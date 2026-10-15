// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package consensus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/policy"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/metrics"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
	"github.com/rgeraldes24/go-remotesigner/internal/signer"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

const fileNetwork = "../../network/embedded/end-to-end.yaml"

// counting counts the signatures a key makes, and corrupts them when
// corrupt is set (fault injection).
type counting struct {
	*mldsa87.Key
	calls   *atomic.Int64
	corrupt bool
}

func (c *counting) Sign(m []byte, mode mldsa87.Mode) (signer.Signature, error) {
	c.calls.Add(1)
	sig, err := c.Key.Sign(m, mode)
	if c.corrupt {
		sig[0] ^= 0xff
	}
	return sig, err
}

// signOptions shape a test signer.
type signOptions struct {
	network      network.Sources // default: the case's named network bound to its GVR
	exits        bool
	noProtection bool
	corrupt      bool
	now          func() time.Time
	pins         *policy.FeeRecipientPins
}

type signFixture struct {
	t      *testing.T
	h      *Sign
	pol    *policy.Policy
	engine *slashing.Engine
	store  *memstore.Store
	m      *metrics.Metrics
	keys   map[signer.ID]*counting
	pks    []mldsa87.PublicKey // by interop index
	calls  atomic.Int64
	log    *logrus.Logger
}

func quietLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

// goldenSources is a fixture network: the named network bound to the
// fixture GVR, genesis time unknown (so no clock bound applies).
func goldenSources(t *testing.T, n vectors.Network) network.Sources {
	t.Helper()
	gvr := vectors.Hex32(t, n.GVR)
	return network.Sources{Network: n.ConfigName, GenesisValidatorsRoot: &gvr}
}

// newSignFixture builds the handler over the interop keys of the golden
// vectors, a memory store and a slashing engine.
func newSignFixture(t *testing.T, o signOptions) *signFixture {
	t.Helper()
	n, err := network.Load(o.network)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.New(policy.Config{Network: n, ClockSkewSlots: policy.DefaultClockSkewSlots,
		VoluntaryExitsEnabled: o.exits, Now: o.now, FeeRecipients: o.pins})
	if err != nil {
		t.Fatal(err)
	}
	m, err := metrics.New(metrics.Config{})
	if err != nil {
		t.Fatal(err)
	}
	f := &signFixture{t: t, pol: pol, m: m, store: memstore.New(), keys: map[signer.ID]*counting{}, log: quietLogger()}
	f.engine = slashing.NewEngine(f.store)
	var pks [][]byte
	for _, k := range vectors.Keys(t) {
		seed := [mldsa87.SeedSize]byte(vectors.Hex(t, k.Seed))
		key, err := mldsa87.FromSeed48(&seed)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Zeroize)
		f.keys[key.ID()] = &counting{Key: key, calls: &f.calls, corrupt: o.corrupt}
		pk := key.PublicKey()
		f.pks = append(f.pks, pk)
		pks = append(pks, pk[:])
	}
	if err := f.engine.RegisterValidators(context.Background(), pks); err != nil {
		t.Fatal(err)
	}
	sig := signer.New(signer.Config{
		Lookup: func(id signer.ID) (signer.Key, bool) {
			k, ok := f.keys[id]
			if !ok {
				return nil, false
			}
			return k, true
		},
		SelectionProofMode: mldsa87.Deterministic,
		Metrics:            m,
		Log:                f.log,
	})
	f.h = &Sign{Policy: pol, Signer: sig, Pinner: f.store, Metrics: m, Log: f.log}
	if !o.noProtection {
		f.h.Protector = f.engine
	}
	return f
}

// ident returns the canonical identifier of interop key i.
func (f *signFixture) ident(i int) string { return "0x" + hex.EncodeToString(f.pks[i][:]) }

// alias returns the sha256 identifier of interop key i.
func (f *signFixture) alias(i int) string {
	id := sha256.Sum256(f.pks[i][:])
	return "0x" + hex.EncodeToString(id[:])
}

func (f *signFixture) post(ident string, body []byte, accept ...string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/consensus/sign/"+ident, bytes.NewReader(body))
	r.SetPathValue("identifier", ident)
	r.Header.Set("Content-Type", "application/json")
	for _, a := range accept {
		r.Header.Add("Accept", a)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, r)
	return rec
}

// signature decodes a 200 JSON response.
func signature(t *testing.T, rec *httptest.ResponseRecorder) []byte {
	t.Helper()
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type %q", ct)
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp) != 1 {
		t.Fatalf("body %.100q: %v", rec.Body.String(), err)
	}
	return vectors.Hex(t, resp["signature"])
}

// reason decodes an error response and checks its status.
func reason(t *testing.T, rec *httptest.ResponseRecorder, status int) apierr.Reason {
	t.Helper()
	var e struct {
		Code    int           `json:"code"`
		Message string        `json:"message"`
		Reason  apierr.Reason `json:"reason"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("error body %.200q: %v", rec.Body.String(), err)
	}
	if rec.Code != status || e.Code != status {
		t.Fatalf("status %d (body %d %s), want %d", rec.Code, e.Code, e.Reason, status)
	}
	return e.Reason
}

func counter(t *testing.T, c prometheus.Metric) float64 {
	t.Helper()
	var m dto.Metric
	if err := c.Write(&m); err != nil {
		t.Fatal(err)
	}
	if g := m.GetGauge(); g != nil {
		return g.GetValue()
	}
	return m.GetCounter().GetValue()
}

func (f *signFixture) requests(typ signingroot.ArtifactType, result string) float64 {
	return counter(f.t, f.m.SigningRequests.WithLabelValues(string(typ), result))
}

// firstCases returns the first minimal-preset golden case of each type.
func firstCases(t *testing.T) []vectors.SignCase {
	t.Helper()
	seen := map[string]bool{}
	var out []vectors.SignCase
	for _, c := range vectors.Signing(t) {
		if c.Preset == "minimal" && !seen[c.Type] {
			seen[c.Type] = true
			out = append(out, c)
		}
	}
	if len(out) != 9 {
		t.Fatalf("golden cases of %d types, want 9", len(out))
	}
	return out
}

// edit decodes a JSON object, applies fn and encodes it again.
func edit(t *testing.T, body []byte, fn func(map[string]any)) []byte {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	fn(v)
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Every golden request is signed: the signature verifies under the key,
// and the deterministic selection proofs are qrysm's bytes.
func TestSignGolden(t *testing.T) {
	cases := vectors.Signing(t)
	if len(cases) < 100 {
		t.Fatalf("only %d golden cases", len(cases))
	}
	for _, c := range cases {
		t.Run(c.ID(), func(t *testing.T) {
			f := newSignFixture(t, signOptions{network: goldenSources(t, c.Network), exits: true})
			sig := signature(t, f.post(f.ident(c.KeyIndex), c.RequestJSON))
			root := vectors.Hex32(t, c.SigningRoot)
			if !mldsa87.Verify(&f.pks[c.KeyIndex], root[:], sig) {
				t.Fatal("signature does not verify")
			}
			if c.DeterministicSignature != "" && !bytes.Equal(sig, vectors.Hex(t, c.DeterministicSignature)) {
				t.Fatal("deterministic signature differs from qrysm's")
			}
			if got := f.requests(signingroot.ArtifactType(c.Type), metrics.ResultOK); got != 1 {
				t.Fatalf("signing_requests_total ok = %v", got)
			}
		})
	}
}

// Every negative fixture gets its status and reason, and nothing is
// signed.
func TestSignGoldenNegative(t *testing.T) {
	checked := 0
	for _, nf := range vectors.Negative(t) {
		for _, c := range nf.Cases {
			t.Run(nf.Preset+"/"+c.Name, func(t *testing.T) {
				exits := true
				if c.Signer != nil && c.Signer.VoluntaryExitsEnabled != nil {
					exits = *c.Signer.VoluntaryExitsEnabled
				}
				f := newSignFixture(t, signOptions{network: goldenSources(t, nf.Network), exits: exits})
				ident := c.Identifier
				if ident == "" {
					ident = f.ident(c.KeyIndex)
				}
				rec := f.post(ident, []byte(c.RequestBody))
				if got := reason(t, rec, c.Expect.Status); string(got) != c.Expect.Reason {
					t.Fatalf("reason %s, want %s", got, c.Expect.Reason)
				}
				if f.calls.Load() != 0 {
					t.Fatal("a refused request reached the key")
				}
			})
			checked++
		}
	}
	if checked < 100 {
		t.Fatalf("checked only %d negative fixtures", checked)
	}
}

// The sha256 alias names the same key as the canonical identifier, and an
// identifier of no loaded key is 404 UNKNOWN_KEY.
func TestSignIdentifierAlias(t *testing.T) {
	var c vectors.SignCase
	for _, sc := range firstCases(t) {
		if sc.Type == string(signingroot.AggregationSlot) {
			c = sc
		}
	}
	f := newSignFixture(t, signOptions{network: goldenSources(t, c.Network)})
	viaAlias := signature(t, f.post(f.alias(c.KeyIndex), c.RequestJSON))
	viaKey := signature(t, f.post(f.ident(c.KeyIndex), c.RequestJSON))
	if !bytes.Equal(viaAlias, viaKey) || !bytes.Equal(viaKey, vectors.Hex(t, c.DeterministicSignature)) {
		t.Fatal("the alias and the canonical identifier sign differently")
	}
	unknown := "0x" + strings.Repeat("ab", 32)
	if r := reason(t, f.post(unknown, c.RequestJSON), 404); r != apierr.UnknownKey {
		t.Fatalf("unknown alias: %s", r)
	}
	if got := counter(t, f.m.MissingIdentifier); got != 1 {
		t.Fatalf("signing_mldsa87_missing_identifier_count_total = %v", got)
	}
	if got := f.requests(signingroot.AggregationSlot, metrics.ResultBadRequest); got != 1 {
		t.Fatalf("signing_requests_total bad_request = %v", got)
	}
}

// G4 S14: a fork_info that does not name the signer's network is 400
// FORK_INFO_MISMATCH for every type that carries one, and registrations
// carry none. Nothing is signed.
func TestSignForkInfoMismatch(t *testing.T) {
	mutations := map[string]func(fi map[string]any){
		"gvr": func(fi map[string]any) {
			fi["genesis_validators_root"] = "0x" + strings.Repeat("11", 32)
		},
		"current_version": func(fi map[string]any) {
			fi["fork"].(map[string]any)["current_version"] = "0x20000089"
		},
		"previous_version": func(fi map[string]any) {
			fi["fork"].(map[string]any)["previous_version"] = "0x20000089"
		},
		"epoch": func(fi map[string]any) { fi["fork"].(map[string]any)["epoch"] = "1" },
	}
	for _, c := range firstCases(t) {
		t.Run(c.Type, func(t *testing.T) {
			f := newSignFixture(t, signOptions{network: goldenSources(t, c.Network), exits: true})
			if c.Type == string(signingroot.ValidatorRegistration) {
				body := edit(t, c.RequestJSON, func(v map[string]any) {
					v["fork_info"] = map[string]any{"fork": map[string]any{}, "genesis_validators_root": c.Network.GVR}
				})
				if r := reason(t, f.post(f.ident(c.KeyIndex), body), 400); r != apierr.UnknownField {
					t.Fatalf("registration with fork_info: %s", r)
				}
				return
			}
			for name, mutate := range mutations {
				body := edit(t, c.RequestJSON, func(v map[string]any) { mutate(v["fork_info"].(map[string]any)) })
				if r := reason(t, f.post(f.ident(c.KeyIndex), body), 400); r != apierr.ForkInfoMismatch {
					t.Errorf("%s: reason %s", name, r)
				}
			}
			if f.calls.Load() != 0 {
				t.Fatal("a fork_info mismatch reached the key")
			}
			if got := f.requests(signingroot.ArtifactType(c.Type), metrics.ResultBadRequest); got != float64(len(mutations)) {
				t.Fatalf("signing_requests_total bad_request = %v", got)
			}
		})
	}
}

// goldenCase returns the minimal case of a type and name.
func goldenCase(t *testing.T, typ signingroot.ArtifactType, name string) vectors.SignCase {
	t.Helper()
	for _, c := range vectors.Signing(t) {
		if c.Preset == "minimal" && c.Type == string(typ) && c.Name == name {
			return c
		}
	}
	t.Fatalf("no golden case %s/%s", typ, name)
	return vectors.SignCase{}
}

// G4 S13: a refused attestation never reaches the key. The refusal is
// counted by reason and the request as refused.
func TestSignRefusedAttestationNeverSigns(t *testing.T) {
	c := goldenCase(t, signingroot.Attestation, "typical")
	f := newSignFixture(t, signOptions{network: goldenSources(t, c.Network)})
	var att struct {
		Attestation struct {
			Source struct{ Epoch string } `json:"source"`
			Target struct{ Epoch string } `json:"target"`
		} `json:"attestation"`
	}
	if err := json.Unmarshal(c.RequestJSON, &att); err != nil {
		t.Fatal(err)
	}
	source, target := vectors.U64(t, att.Attestation.Source.Epoch), vectors.U64(t, att.Attestation.Target.Epoch)
	// Another attestation for the same target is already recorded.
	dec, err := f.engine.CheckAndRecordAttestation(context.Background(), slashing.AttestationRequest{
		PublicKey: f.pks[c.KeyIndex][:], GenesisValidatorsRoot: vectors.Hex32(t, c.Network.GVR),
		SourceEpoch: source, TargetEpoch: target, SigningRoot: slashing.Root{0xee},
	})
	if err != nil || !dec.Allowed {
		t.Fatalf("seed record: %+v %v", dec, err)
	}

	rec := f.post(f.ident(c.KeyIndex), c.RequestJSON)
	if r := reason(t, rec, 412); r != apierr.SlashingDoubleVote {
		t.Fatalf("reason %s", r)
	}
	if f.calls.Load() != 0 {
		t.Fatal("Sign was called for a refused attestation")
	}
	if got := counter(t, f.m.Prevented(slashing.ReasonDoubleVote)); got != 1 {
		t.Fatalf("prevented{slashing_double_vote} = %v", got)
	}
	if got := f.requests(signingroot.Attestation, metrics.ResultRefused); got != 1 {
		t.Fatalf("signing_requests_total refused = %v", got)
	}
}

// Blocks are recorded before they are signed: a second, different block at
// the same slot is refused; the same block again is allowed (a repeat).
func TestSignBlockDoubleProposal(t *testing.T) {
	c := goldenCase(t, signingroot.BlockV2, "typical")
	f := newSignFixture(t, signOptions{network: goldenSources(t, c.Network)})
	ident := f.ident(c.KeyIndex)
	signature(t, f.post(ident, c.RequestJSON))
	signature(t, f.post(ident, c.RequestJSON))
	other := edit(t, c.RequestJSON, func(v map[string]any) {
		delete(v, "signing_root")
		v["beacon_block"].(map[string]any)["block_header"].(map[string]any)["state_root"] = "0x" + strings.Repeat("ee", 32)
	})
	if r := reason(t, f.post(ident, other), 412); r != apierr.SlashingDoubleProposal {
		t.Fatalf("reason %s", r)
	}
	if f.calls.Load() != 2 {
		t.Fatalf("Sign called %d times, want 2", f.calls.Load())
	}
	if got := counter(t, f.m.SlashingPermitted); got != 2 {
		t.Fatalf("permitted = %v", got)
	}
}

// With protection disabled (loopback only), blocks and attestations are
// signed unchecked.
func TestSignProtectionDisabled(t *testing.T) {
	c := goldenCase(t, signingroot.BlockV2, "typical")
	f := newSignFixture(t, signOptions{network: goldenSources(t, c.Network), noProtection: true})
	ident := f.ident(c.KeyIndex)
	signature(t, f.post(ident, c.RequestJSON))
	other := edit(t, c.RequestJSON, func(v map[string]any) {
		delete(v, "signing_root")
		v["beacon_block"].(map[string]any)["block_header"].(map[string]any)["state_root"] = "0x" + strings.Repeat("ee", 32)
	})
	signature(t, f.post(ident, other))
}

// Policy and clock refusals never reach the key: exits are off by default,
// and a request ahead of the wall clock is 412 CLOCK_BOUND.
func TestSignPolicyRefusals(t *testing.T) {
	exit := goldenCase(t, signingroot.VoluntaryExit, "typical")
	f := newSignFixture(t, signOptions{network: goldenSources(t, exit.Network)})
	if r := reason(t, f.post(f.ident(exit.KeyIndex), exit.RequestJSON), 403); r != apierr.ArtifactTypeDisabled {
		t.Fatalf("exit: %s", r)
	}

	// Genesis now: slot 0 is current, slot 1 within the skew, slot 2 ahead.
	genesis := uint64(1_760_000_000)
	src := goldenSources(t, exit.Network)
	src.GenesisTime = &genesis
	f = newSignFixture(t, signOptions{network: src, now: func() time.Time { return time.Unix(int64(genesis), 0) }})
	c := goldenCase(t, signingroot.AggregationSlot, "typical")
	for slot, status := range map[string]int{"0": 200, "1": 200, "2": 412} {
		body := edit(t, c.RequestJSON, func(v map[string]any) {
			delete(v, "signing_root")
			v["aggregation_slot"].(map[string]any)["slot"] = slot
		})
		rec := f.post(f.ident(c.KeyIndex), body)
		if status == 200 {
			signature(t, rec)
		} else if r := reason(t, rec, status); r != apierr.ClockBound {
			t.Fatalf("slot %s: %s", slot, r)
		}
	}
	if f.calls.Load() != 2 {
		t.Fatalf("Sign called %d times, want 2", f.calls.Load())
	}
	if got := f.requests(signingroot.AggregationSlot, metrics.ResultRefused); got != 1 {
		t.Fatalf("refused = %v", got)
	}
}

// A registration for a pinned key must carry its pinned fee recipient.
func TestSignFeeRecipientPin(t *testing.T) {
	c := goldenCase(t, signingroot.ValidatorRegistration, "typical")
	var reg struct {
		Registration struct {
			FeeRecipient string `json:"fee_recipient"`
		} `json:"validator_registration"`
	}
	if err := json.Unmarshal(c.RequestJSON, &reg); err != nil {
		t.Fatal(err)
	}
	pin := func(addr string) *policy.FeeRecipientPins {
		id := sha256.Sum256(vectors.Hex(t, c.Pubkey))
		pins, err := policy.ParseFeeRecipientPins([]byte("- key: 0x" + hex.EncodeToString(id[:]) + "\n  fee_recipient: " + addr + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		return pins
	}
	f := newSignFixture(t, signOptions{network: goldenSources(t, c.Network), pins: pin(reg.Registration.FeeRecipient)})
	signature(t, f.post(f.ident(c.KeyIndex), c.RequestJSON))

	f = newSignFixture(t, signOptions{network: goldenSources(t, c.Network), pins: pin("Q" + strings.Repeat("12", 64))})
	if r := reason(t, f.post(f.ident(c.KeyIndex), c.RequestJSON), 403); r != apierr.ArtifactTypeDisabled {
		t.Fatalf("other fee recipient: %s", r)
	}
	if f.calls.Load() != 0 {
		t.Fatal("a refused registration reached the key")
	}
}

// G4 S17: a corrupted signature is 500 SIGNATURE_FAULT, its bytes are never
// sent, and the key is quarantined (503 KEY_QUARANTINED) until a reload.
func TestSignFaultInjection(t *testing.T) {
	c := goldenCase(t, signingroot.Attestation, "typical")
	f := newSignFixture(t, signOptions{network: goldenSources(t, c.Network), corrupt: true})
	ident := f.ident(c.KeyIndex)

	rec := f.post(ident, c.RequestJSON)
	if r := reason(t, rec, 500); r != apierr.SignatureFault {
		t.Fatalf("reason %s", r)
	}
	if strings.Contains(rec.Body.String(), "signature") || rec.Body.Len() > 200 {
		t.Fatalf("the fault response carries more than the error: %.200q", rec.Body.String())
	}
	if r := reason(t, f.post(ident, c.RequestJSON), 503); r != apierr.KeyQuarantined {
		t.Fatalf("second request: %s", r)
	}
	if f.calls.Load() != 1 {
		t.Fatalf("Sign called %d times, want 1", f.calls.Load())
	}
	if got := counter(t, f.m.VerifyFailures); got != 1 {
		t.Fatalf("signing_verify_failures_total = %v", got)
	}
	if got := counter(t, f.m.KeysQuarantined); got != 1 {
		t.Fatalf("signing_keys_quarantined = %v", got)
	}
	if got := f.requests(signingroot.Attestation, metrics.ResultError); got != 2 {
		t.Fatalf("signing_requests_total error = %v", got)
	}
	// Other keys still sign.
	other := (c.KeyIndex + 1) % len(f.pks)
	f.keys[f.pks[other].ID()].corrupt = false
	sc := goldenCase(t, signingroot.SyncCommitteeMessage, "typical")
	signature(t, f.post(f.ident(other), sc.RequestJSON))
}

// G4 S19 (run with -race): removing a key while requests sign with it
// yields only 200 or 404, and 404 once the removal has completed.
func TestSignDeleteWhileSigning(t *testing.T) {
	c := goldenCase(t, signingroot.SyncCommitteeMessage, "typical")
	f := newSignFixture(t, signOptions{network: goldenSources(t, c.Network)})
	keys := provider.New(f.log)
	load := func() []*mldsa87.Key {
		var out []*mldsa87.Key
		for _, k := range vectors.Keys(t) {
			seed := [mldsa87.SeedSize]byte(vectors.Hex(t, k.Seed))
			key, err := mldsa87.FromSeed48(&seed)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, key)
		}
		return out
	}
	if _, err := keys.Apply([]provider.Batch{{Source: "a", Keys: load()}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keys.Close)
	f.h.Signer = signer.New(signer.Config{
		Lookup: func(id signer.ID) (signer.Key, bool) {
			k, ok := keys.Get(id)
			if !ok {
				return nil, false
			}
			return k, true
		},
		Metrics: f.m, Log: f.log,
	})
	ident := f.ident(c.KeyIndex)

	var (
		wg      sync.WaitGroup
		removed atomic.Bool
		codes   sync.Map // status → count
	)
	stop := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				after := removed.Load()
				rec := f.post(ident, c.RequestJSON)
				if rec.Code != 200 && rec.Code != 404 {
					t.Errorf("status %d: %s", rec.Code, rec.Body.String())
					return
				}
				if after && rec.Code != 404 {
					t.Errorf("status %d after the removal completed", rec.Code)
					return
				}
				n, _ := codes.LoadOrStore(rec.Code, new(atomic.Int64))
				n.(*atomic.Int64).Add(1)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	// Reload without the key's source: it is evicted and zeroized.
	others := load()
	var kept []*mldsa87.Key
	for i, k := range others {
		if i == c.KeyIndex {
			k.Zeroize()
			continue
		}
		kept = append(kept, k)
	}
	if _, err := keys.Apply([]provider.Batch{{Source: "a", Keys: kept}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	removed.Store(true)
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
	for _, code := range []int{200, 404} {
		if n, ok := codes.Load(code); !ok || n.(*atomic.Int64).Load() == 0 {
			t.Errorf("no %d responses", code)
		}
	}
}

// A pending GVR is pinned by the first accepted request, in the store and
// the policy; a later request with another GVR is FORK_INFO_MISMATCH.
func TestSignPinsGVROnFirstUse(t *testing.T) {
	c := goldenCase(t, signingroot.AggregationSlot, "typical")
	f := newSignFixture(t, signOptions{network: network.Sources{Network: fileNetwork}})
	if _, pinned := f.pol.GenesisValidatorsRoot(); pinned {
		t.Fatal("file network starts pinned")
	}
	// An unknown key pins nothing.
	if r := reason(t, f.post("0x"+strings.Repeat("ab", 32), c.RequestJSON), 404); r != apierr.UnknownKey {
		t.Fatalf("unknown key: %s", r)
	}
	if _, pinned := f.pol.GenesisValidatorsRoot(); pinned {
		t.Fatal("a refused request pinned the GVR")
	}
	signature(t, f.post(f.ident(c.KeyIndex), c.RequestJSON))
	want := vectors.Hex32(t, c.Network.GVR)
	if gvr, pinned := f.pol.GenesisValidatorsRoot(); !pinned || gvr != want {
		t.Fatal("the policy was not pinned")
	}
	if gvr, pinned, err := f.store.GenesisValidatorsRoot(context.Background()); err != nil || !pinned || gvr != slashing.Root(want) {
		t.Fatal("the store was not pinned")
	}
	other := edit(t, c.RequestJSON, func(v map[string]any) {
		v["fork_info"].(map[string]any)["genesis_validators_root"] = "0x" + strings.Repeat("22", 32)
		delete(v, "signing_root")
	})
	if r := reason(t, f.post(f.ident(c.KeyIndex), other), 400); r != apierr.ForkInfoMismatch {
		t.Fatalf("other GVR: %s", r)
	}
}

// JSON unless the client lists text/plain and not JSON.
func TestSignContentNegotiation(t *testing.T) {
	c := goldenCase(t, signingroot.AggregationSlot, "typical")
	f := newSignFixture(t, signOptions{network: goldenSources(t, c.Network)})
	want := c.DeterministicSignature
	tests := []struct {
		accept []string
		text   bool
	}{
		{nil, false},
		{[]string{"application/json"}, false},
		{[]string{"*/*"}, false},
		{[]string{"text/plain"}, true},
		{[]string{"text/plain; charset=utf-8"}, true},
		{[]string{"text/plain, application/json"}, false},
		{[]string{"text/plain", "application/json"}, false},
		{[]string{"text/plain, application/json;q=0"}, true},
		{[]string{"text/plain;q=0"}, false},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.accept, "|"), func(t *testing.T) {
			rec := f.post(f.ident(c.KeyIndex), c.RequestJSON, tt.accept...)
			if !tt.text {
				if got := "0x" + hex.EncodeToString(signature(t, rec)); got != want {
					t.Fatal("wrong signature")
				}
				return
			}
			if rec.Code != 200 || rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" || rec.Body.String() != want {
				t.Fatalf("%d %q %.40q", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
			}
		})
	}
}

// A malformed identifier or body is counted as malformed, before the type
// is known.
func TestSignMalformed(t *testing.T) {
	c := goldenCase(t, signingroot.AggregationSlot, "typical")
	f := newSignFixture(t, signOptions{network: goldenSources(t, c.Network)})
	if r := reason(t, f.post("0x1234", c.RequestJSON), 400); r != apierr.BadIdentifier {
		t.Fatalf("identifier: %s", r)
	}
	if r := reason(t, f.post(f.ident(0), []byte("{")), 400); r != apierr.MalformedJSON {
		t.Fatalf("body: %s", r)
	}
	if got := counter(t, f.m.MalformedRequests); got != 2 {
		t.Fatalf("http_mldsa87_malformed_request_count_total = %v", got)
	}
	for _, r := range metrics.RequestResults {
		if got := f.requests(signingroot.AggregationSlot, r); got != 0 {
			t.Fatalf("signing_requests_total{%s} = %v for undecoded requests", r, got)
		}
	}
}
