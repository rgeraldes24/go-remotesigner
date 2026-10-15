// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/types"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
)

// The end-to-end network: GENESIS_FORK_VERSION 0x000000fd, 10 s slots,
// 6-slot epochs, minimal preset (16-bit sync subcommittees, one subnet).
const genesis = 1_760_000_000

var (
	gvr      = [32]byte{0x7a, 0x1e, 0x2c}
	otherGVR = [32]byte{0x01}
	e2eFork  = signingroot.Version{0, 0, 0, 0xfd}
)

func e2e(t *testing.T, withGVR, withGenesis bool) *network.Network {
	t.Helper()
	src := network.Sources{Network: "e2e"}
	if withGVR {
		g := gvr
		src.GenesisValidatorsRoot = &g
	}
	if withGenesis {
		gt := uint64(genesis)
		src.GenesisTime = &gt
	}
	n, err := network.Load(src)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// at returns a clock fixed at slot s plus extra seconds.
func at(slot int64, extra int64) func() time.Time {
	return func() time.Time { return time.Unix(genesis+10*slot+extra, 0) }
}

func newPolicy(t *testing.T, cfg Config) *Policy {
	t.Helper()
	if cfg.Network == nil {
		cfg.Network = e2e(t, true, true)
	}
	if cfg.Now == nil {
		cfg.Now = at(100, 5) // now_slot 100, now_epoch 16
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func forkInfo() *types.ForkInfo {
	return &types.ForkInfo{Fork: signingroot.Fork{PreviousVersion: e2eFork, CurrentVersion: e2eFork}, GenesisValidatorsRoot: gvr}
}

func sign(pl types.Payload) *types.SignRequest {
	r := &types.SignRequest{Payload: pl}
	if pl.ArtifactType() != signingroot.ValidatorRegistration {
		r.ForkInfo = forkInfo()
	}
	return r
}

var testPubkey = func() *types.Pubkey {
	var pk types.Pubkey
	for i := range pk {
		pk[i] = byte(i)
	}
	return &pk
}()

var testKeyID = types.KeyID(testPubkey)

func registration(fee byte, ts uint64) *types.SignRequest {
	r := &types.ValidatorRegistrationV1{GasLimit: 30_000_000, Timestamp: ts, Pubkey: *testPubkey}
	for i := range r.FeeRecipient {
		r.FeeRecipient[i] = fee
	}
	return sign(r)
}

func aggregate(bits []byte, n int) *types.SignRequest {
	p := &types.AggregateAttestationAndProof{}
	p.Aggregate.AggregationBits = bits
	p.Aggregate.Signatures = make([]types.Signature, n)
	return sign(p)
}

func contribution(sub uint64, bits []byte, n int) *types.SignRequest {
	c := &types.ContributionAndProof{}
	c.Contribution.SubcommitteeIndex = sub
	c.Contribution.AggregationBits = bits
	c.Contribution.Signatures = make([]types.Signature, n)
	return sign(c)
}

// one request of every type, all inside their bounds at slot 100.
func everyType() []*types.SignRequest {
	return []*types.SignRequest{
		sign(&types.BlockV2{Header: types.BeaconBlockHeader{Slot: 100}}),
		sign(&types.AttestationData{Slot: 100, Source: types.Checkpoint{Epoch: 15}, Target: types.Checkpoint{Epoch: 16}}),
		sign(&types.AggregationSlot{Slot: 100}),
		aggregate([]byte{0x07}, 2),
		sign(&types.VoluntaryExit{Epoch: 16}),
		sign(&types.SyncCommitteeMessage{Slot: 100}),
		sign(&types.SyncAggregatorSelectionData{Slot: 100}),
		contribution(0, []byte{0x03, 0x00}, 2),
		registration(1, genesis+1000),
	}
}

func reason(t *testing.T, err error) apierr.Reason {
	t.Helper()
	if err == nil {
		return ""
	}
	r, ok := apierr.ReasonOf(err)
	if !ok {
		t.Fatalf("error without a reason: %v", err)
	}
	return r
}

func TestNew(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrNoNetwork) {
		t.Errorf("no network: %v", err)
	}
	// A named network without a GVR cannot trust on first use.
	if _, err := New(Config{Network: e2e(t, false, true)}); !errors.Is(err, ErrNoGVR) {
		t.Errorf("named network without GVR: %v", err)
	}
	bad := e2e(t, true, true)
	bad.Config.SecondsPerSlot = 0
	if _, err := New(Config{Network: bad}); !errors.Is(err, ErrInvalidNetwork) {
		t.Errorf("zero slot time: %v", err)
	}
	p := newPolicy(t, Config{})
	if g, ok := p.GenesisValidatorsRoot(); !ok || g != gvr {
		t.Errorf("bound GVR %x, %v", g, ok)
	}
	if got := p.Params().SyncSubcommitteeSize; got != 16 {
		t.Errorf("sync subcommittee size %d", got)
	}
}

func TestEveryTypeAccepted(t *testing.T) {
	p := newPolicy(t, Config{VoluntaryExitsEnabled: true})
	for _, req := range everyType() {
		d, err := p.Check(req, testKeyID)
		if err != nil {
			t.Errorf("%s: %v", req.Type(), err)
			continue
		}
		if d.Type != req.Type() || d.Protection != ProtectionFor(req.Type()) || d.PinGVR {
			t.Errorf("%s: decision %+v", req.Type(), d)
		}
		wantGVR := gvr
		if req.Type() == signingroot.ValidatorRegistration {
			wantGVR = [32]byte{}
		}
		if d.GenesisValidatorsRoot != wantGVR {
			t.Errorf("%s: GVR %x", req.Type(), d.GenesisValidatorsRoot)
		}
	}
}

func TestTypePolicy(t *testing.T) {
	exit := sign(&types.VoluntaryExit{Epoch: 1})
	off := newPolicy(t, Config{})
	if r := reason(t, func() error { _, err := off.Check(exit, testKeyID); return err }()); r != apierr.ArtifactTypeDisabled {
		t.Errorf("exit with exits off: %q", r)
	}
	if slices.Contains(off.EnabledTypes(), signingroot.VoluntaryExit) || len(off.EnabledTypes()) != 8 {
		t.Errorf("enabled types %v", off.EnabledTypes())
	}
	on := newPolicy(t, Config{VoluntaryExitsEnabled: true})
	if !slices.Equal(on.EnabledTypes(), types.ArtifactTypes()) {
		t.Errorf("enabled types with exits on: %v", on.EnabledTypes())
	}
	if on.Enabled("DEPOSIT") || on.Enabled("RANDAO_REVEAL") {
		t.Error("an unknown type is enabled")
	}
}

func TestProtection(t *testing.T) {
	p := newPolicy(t, Config{})
	d, err := p.Check(sign(&types.BlockV2{Header: types.BeaconBlockHeader{Slot: 99}}), testKeyID)
	if err != nil || d.Protection != ProtectionBlock || d.Slot != 99 {
		t.Errorf("block: %+v, %v", d, err)
	}
	d, err = p.Check(sign(&types.AttestationData{Source: types.Checkpoint{Epoch: 3}, Target: types.Checkpoint{Epoch: 7}}), testKeyID)
	if err != nil || d.Protection != ProtectionAttestation || d.SourceEpoch != 3 || d.TargetEpoch != 7 {
		t.Errorf("attestation: %+v, %v", d, err)
	}
	for _, typ := range types.ArtifactTypes() {
		want := ProtectionNone
		switch typ {
		case signingroot.BlockV2:
			want = ProtectionBlock
		case signingroot.Attestation:
			want = ProtectionAttestation
		}
		if got := ProtectionFor(typ); got != want {
			t.Errorf("%s: protection %d", typ, got)
		}
	}
}

func TestInvariants(t *testing.T) {
	var other types.Pubkey
	tests := []struct {
		name string
		req  *types.SignRequest
		r    apierr.Reason
	}{
		{"source after target", sign(&types.AttestationData{Source: types.Checkpoint{Epoch: 5}, Target: types.Checkpoint{Epoch: 4}}),
			apierr.InvariantViolation},
		{"source equals target", sign(&types.AttestationData{Source: types.Checkpoint{Epoch: 4}, Target: types.Checkpoint{Epoch: 4}}), ""},
		{"aggregate popcount high", aggregate([]byte{0x07}, 3), apierr.InvariantViolation},
		{"aggregate popcount low", aggregate([]byte{0x07}, 1), apierr.InvariantViolation},
		{"aggregate empty", aggregate([]byte{0x01}, 0), ""},
		{"aggregate 32 of 32", aggregate([]byte{0xff, 0xff, 0xff, 0xff, 0x01}, 32), ""},
		{"aggregate 33 signatures", aggregate([]byte{0xff, 0xff, 0xff, 0xff, 0x01}, 33), apierr.InvariantViolation},
		{"selection subcommittee 1", sign(&types.SyncAggregatorSelectionData{Slot: 1, SubcommitteeIndex: 1}), apierr.InvariantViolation},
		{"contribution subcommittee 1", contribution(1, []byte{0x01, 0x00}, 1), apierr.InvariantViolation},
		{"contribution no signatures", contribution(0, []byte{0x00, 0x00}, 0), apierr.InvariantViolation},
		{"contribution popcount", contribution(0, []byte{0x01, 0x80}, 1), apierr.InvariantViolation},
		{"contribution all bits", contribution(0, []byte{0xff, 0xff}, 16), ""},
		{"registration pubkey", sign(&types.ValidatorRegistrationV1{Timestamp: genesis, Pubkey: other}), apierr.PubkeyMismatch},
	}
	p := newPolicy(t, Config{})
	for _, tt := range tests {
		_, err := p.Check(tt.req, testKeyID)
		if r := reason(t, err); r != tt.r {
			t.Errorf("%s: reason %q, want %q (%v)", tt.name, r, tt.r, err)
		}
	}
}

func TestSigningRoot(t *testing.T) {
	p := newPolicy(t, Config{})
	req := sign(&types.AggregationSlot{Slot: 61})
	d, err := p.Check(req, testKeyID)
	if err != nil {
		t.Fatal(err)
	}
	chain, _ := signingroot.NewChain(e2eFork, gvr, 6)
	obj, _ := types.Uint64(61).HashTreeRoot()
	want, _ := chain.SigningRoot(signingroot.AggregationSlot, obj, 61)
	if d.SigningRoot != want {
		t.Errorf("root %x, want %x", d.SigningRoot, want)
	}
	req.SigningRoot = &want
	if _, err := p.Check(req, testKeyID); err != nil {
		t.Errorf("matching root refused: %v", err)
	}
	bad := want
	bad[0] ^= 1
	req.SigningRoot = &bad
	if _, err := p.Check(req, testKeyID); reason(t, err) != apierr.SigningRootMismatch {
		t.Errorf("mismatching root: %v", err)
	}
}

// S14: a fork_info that names another network is refused for every type
// that carries one. The domain never depends on it.
func TestForkInfoMismatch(t *testing.T) {
	mutations := []struct {
		name string
		f    func(*types.ForkInfo)
	}{
		{"previous version", func(f *types.ForkInfo) { f.Fork.PreviousVersion = signingroot.Version{0x20, 0, 0, 0x89} }},
		{"current version", func(f *types.ForkInfo) { f.Fork.CurrentVersion = signingroot.Version{0, 0, 0, 0} }},
		{"fork epoch", func(f *types.ForkInfo) { f.Fork.Epoch = 1 }},
		{"genesis validators root", func(f *types.ForkInfo) { f.GenesisValidatorsRoot = otherGVR }},
	}
	p := newPolicy(t, Config{VoluntaryExitsEnabled: true})
	for _, req := range everyType() {
		if req.ForkInfo == nil {
			continue
		}
		for _, m := range mutations {
			m.f(req.ForkInfo)
			if _, err := p.Check(req, testKeyID); reason(t, err) != apierr.ForkInfoMismatch {
				t.Errorf("%s with wrong %s: %v", req.Type(), m.name, err)
			}
			if _, _, err := p.CheckForkInfo(req.ForkInfo); reason(t, err) != apierr.ForkInfoMismatch {
				t.Errorf("CheckForkInfo with wrong %s: %v", m.name, err)
			}
			*req.ForkInfo = *forkInfo()
		}
	}
	// With the client's root present, a wrong GVR fails at step 5, which
	// recomputes the root with the bound GVR.
	req := sign(&types.AggregationSlot{Slot: 61})
	wrong := *forkInfo()
	wrong.GenesisValidatorsRoot = otherGVR
	chain, _ := signingroot.NewChain(e2eFork, otherGVR, 6)
	root, _ := req.SigningRootFor(chain)
	req.ForkInfo, req.SigningRoot = &wrong, &root
	if _, err := p.Check(req, testKeyID); reason(t, err) != apierr.SigningRootMismatch {
		t.Errorf("wrong GVR with its own root: %v", err)
	}
}

func TestTrustOnFirstUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "net.yaml")
	if err := os.WriteFile(path, []byte("PRESET_BASE: 'minimal'\nGENESIS_FORK_VERSION: 0x000000fd\nSECONDS_PER_SLOT: 10\nSLOTS_PER_EPOCH: 6\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := network.Load(network.Sources{Network: path})
	if err != nil {
		t.Fatal(err)
	}
	p := newPolicy(t, Config{Network: n})
	if _, ok := p.GenesisValidatorsRoot(); ok {
		t.Fatal("GVR bound before any request")
	}
	req := sign(&types.AggregationSlot{Slot: 61})
	req.ForkInfo.GenesisValidatorsRoot = otherGVR
	d, err := p.Check(req, testKeyID)
	if err != nil {
		t.Fatal(err)
	}
	chain, _ := signingroot.NewChain(e2eFork, otherGVR, 6)
	want, _ := req.SigningRootFor(chain)
	if !d.PinGVR || d.GenesisValidatorsRoot != otherGVR || d.SigningRoot != want {
		t.Fatalf("pending pin: %+v", d)
	}
	if err := p.PinGenesisValidatorsRoot(otherGVR); err != nil {
		t.Fatal(err)
	}
	if err := p.PinGenesisValidatorsRoot(otherGVR); err != nil {
		t.Errorf("re-pinning the same GVR: %v", err)
	}
	if err := p.PinGenesisValidatorsRoot(gvr); !errors.Is(err, ErrGVRPinned) {
		t.Errorf("pinning another GVR: %v", err)
	}
	if d, err := p.Check(req, testKeyID); err != nil || d.PinGVR {
		t.Errorf("after the pin: %+v, %v", d, err)
	}
	req.ForkInfo.GenesisValidatorsRoot = gvr
	if _, err := p.Check(req, testKeyID); reason(t, err) != apierr.ForkInfoMismatch {
		t.Errorf("other GVR after the pin: %v", err)
	}
	// A pending pin also covers RANDAO requests.
	q := newPolicy(t, Config{Network: n})
	if g, pin, err := q.CheckForkInfo(forkInfo()); err != nil || !pin || g != gvr {
		t.Errorf("CheckForkInfo while pending: %x %v %v", g, pin, err)
	}
}

// The contract examples run through the decoder and the policy. Only the
// AGGREGATION_SLOT example carries a real signing root; the others are
// placeholders and fail at step 5.
func TestContractExamples(t *testing.T) {
	raw, err := os.ReadFile("../../../api/openapi/consensus.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Components struct {
			Examples map[string]struct {
				Value any `yaml:"value"`
			} `yaml:"examples"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	g := [32]byte{0x7a, 0x1e, 0x2c, 0x4d, 0x5b, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
		0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09}
	gt := uint64(1_759_999_000) // slot 61 is at 1,759,999,610
	n, err := network.Load(network.Sources{Network: "e2e", GenesisValidatorsRoot: &g, GenesisTime: &gt})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{Network: n, VoluntaryExitsEnabled: true, Now: func() time.Time { return time.Unix(1_760_000_000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	for name, ex := range spec.Components.Examples {
		body, _ := json.Marshal(ex.Value)
		req, err := types.DecodeSignRequest(body, p.Params())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var keyID [32]byte
		if reg, ok := req.Payload.(*types.ValidatorRegistrationV1); ok {
			keyID = types.KeyID(&reg.Pubkey)
		}
		_, err = p.Check(req, keyID)
		want := apierr.SigningRootMismatch
		if name == "AggregationSlot" {
			want = ""
		}
		if r := reason(t, err); r != want {
			t.Errorf("%s: reason %q, want %q (%v)", name, r, want, err)
		}
	}
}
