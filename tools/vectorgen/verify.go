// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	fssz "github.com/prysmaticlabs/fastssz"
	"github.com/theQRL/qrysm/beacon-chain/core/signing"
	"github.com/theQRL/qrysm/config/params"
	"github.com/theQRL/qrysm/consensus-types/primitives"
	"github.com/theQRL/qrysm/crypto/ml_dsa_87"
	"github.com/theQRL/qrysm/crypto/randao"
	qrysmpb "github.com/theQRL/qrysm/proto/qrysm/v1alpha1"
)

// verifier posts the fixtures to a running signer and judges every answer
// with qrysm's own code.
type verifier struct {
	base   string
	token  string
	client *http.Client
	now    func() time.Time
	log    io.Writer

	caps    capabilities
	loaded  map[string]bool // canonical lowercase identifiers
	preset  string
	results verifyResults
}

type verifyResults struct {
	passed, skipped int
	failures        []string
}

func (r *verifyResults) fail(format string, a ...any) {
	r.failures = append(r.failures, fmt.Sprintf(format, a...))
}

// capabilities is the signer's GET …/capabilities body.
type capabilities struct {
	APIVersion         string   `json:"api_version"`
	Types              []string `json:"types"`
	RandaoReveal       bool     `json:"randao_reveal"`
	SelectionProofMode string   `json:"selection_proof_mode"`
	SlashingProtection string   `json:"slashing_protection"`
	Network            struct {
		ConfigName            string  `json:"config_name"`
		GenesisForkVersion    string  `json:"genesis_fork_version"`
		GenesisValidatorsRoot *string `json:"genesis_validators_root"`
		GenesisTime           *string `json:"genesis_time"`
		SecondsPerSlot        string  `json:"seconds_per_slot"`
		SlotsPerEpoch         string  `json:"slots_per_epoch"`
	} `json:"network"`
}

type errorBody struct {
	Code   int    `json:"code"`
	Reason string `json:"reason"`
}

// do sends one request and returns the status and body. A 429 is retried
// once after its Retry-After, as the qrysm client does.
func (v *verifier) do(ctx context.Context, method, path, body string) (int, []byte, error) {
	for attempt := 0; ; attempt++ {
		var rd io.Reader
		if method == http.MethodPost {
			rd = strings.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, v.base+path, rd)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Accept", "application/json")
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}
		if v.token != "" {
			req.Header.Set("Authorization", "Bearer "+v.token)
		}
		resp, err := v.client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		_ = resp.Body.Close()
		if err != nil {
			return 0, nil, err
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt == 0 {
			wait, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
			select {
			case <-time.After(time.Duration(max(wait, 1)) * time.Second):
				continue
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			}
		}
		return resp.StatusCode, b, nil
	}
}

func (v *verifier) getJSON(ctx context.Context, path string, out any) error {
	status, body, err := v.do(ctx, http.MethodGet, path, "")
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("GET %s: status %d: %.200s", path, status, body)
	}
	return json.Unmarshal(body, out)
}

// runVerify checks the signer at base against the fixtures in dir.
func runVerify(ctx context.Context, base, token, dir string, log io.Writer) (verifyResults, error) {
	fx, err := loadFixtures(dir)
	if err != nil {
		return verifyResults{}, err
	}
	v := &verifier{
		base:   strings.TrimSuffix(base, "/"),
		token:  token,
		client: &http.Client{Timeout: 2 * time.Minute},
		now:    time.Now,
		log:    log,
		loaded: map[string]bool{},
	}
	if err := v.handshake(ctx, fx); err != nil {
		return verifyResults{}, err
	}
	v.verifyRandao(ctx, fx)
	for _, f := range fx.signing[v.preset] {
		for i := range f.Cases {
			v.verifySign(ctx, &f.Cases[i])
		}
	}
	v.verifyNegative(ctx, fx)
	return v.results, nil
}

// handshake reads capabilities and publicKeys and picks the fixture preset
// whose network the signer is bound to.
func (v *verifier) handshake(ctx context.Context, fx *fixtures) error {
	if err := v.getJSON(ctx, "/api/v1/consensus/capabilities", &v.caps); err != nil {
		return err
	}
	for preset, files := range fx.signing {
		n := files[0].Cases[0].Network
		if n.GenesisForkVersion != v.caps.Network.GenesisForkVersion {
			continue
		}
		if spe := v.caps.Network.SlotsPerEpoch; spe != n.SlotsPerEpoch {
			return fmt.Errorf("signer has %s slots per epoch, the %s fixtures %s", spe, preset, n.SlotsPerEpoch)
		}
		if g := v.caps.Network.GenesisValidatorsRoot; g != nil && !strings.EqualFold(*g, n.GVR) {
			return fmt.Errorf("signer is bound to GVR %s, the %s fixtures use %s", *g, preset, n.GVR)
		}
		v.preset = preset
	}
	if v.preset == "" {
		return fmt.Errorf("no fixtures for the signer's network %s (%s)", v.caps.Network.ConfigName, v.caps.Network.GenesisForkVersion)
	}
	var keys []string
	if err := v.getJSON(ctx, "/api/v1/consensus/publicKeys", &keys); err != nil {
		return err
	}
	for _, k := range keys {
		v.loaded[strings.ToLower(k)] = true
	}
	_, _ = fmt.Fprintf(v.log, "verify: signer on %s, %s preset fixtures, %d keys loaded, selection proofs %s, protection %s\n",
		v.caps.Network.ConfigName, v.preset, len(keys), v.caps.SelectionProofMode, v.caps.SlashingProtection)
	return nil
}

func (v *verifier) skip(format string, a ...any) {
	v.results.skipped++
	_, _ = fmt.Fprintf(v.log, "skip: "+format+"\n", a...)
}

// verifySign posts one golden request. The signature must verify with
// qrysm's ml_dsa_87.VerifySignature over the signing root qrysm computes
// from object_ssz_hex, and deterministic signatures must match byte for
// byte.
func (v *verifier) verifySign(ctx context.Context, c *fxSignCase) {
	id := c.Preset + "/" + c.Type + "/" + c.Name
	if !v.loaded[strings.ToLower(c.Pubkey)] {
		v.skip("%s: key %d is not loaded", id, c.KeyIndex)
		return
	}
	root, err := qrysmSigningRoot(c)
	if err != nil {
		v.results.fail("%s: %v", id, err)
		return
	}
	status, body, err := v.do(ctx, http.MethodPost, "/api/v1/consensus/sign/"+c.Pubkey, string(c.RequestJSON))
	if err != nil {
		v.results.fail("%s: %v", id, err)
		return
	}
	enabled := slices.Contains(v.caps.Types, c.Type)
	if !enabled {
		v.expectError(id, status, body, fxExpect{Status: 403, Reason: "ARTIFACT_TYPE_DISABLED"})
		return
	}
	if status != http.StatusOK {
		var e errorBody
		_ = json.Unmarshal(body, &e)
		switch {
		case status == 412 && e.Reason == "CLOCK_BOUND":
			v.skip("%s: refused by the signer's clock bound", id)
		case status == 412 && strings.HasPrefix(e.Reason, "SLASHING_") && v.caps.SlashingProtection != "disabled":
			v.skip("%s: refused by slashing protection (%s)", id, e.Reason)
		default:
			v.results.fail("%s: status %d %s, want 200", id, status, e.Reason)
		}
		return
	}
	var resp struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		v.results.fail("%s: response: %v", id, err)
		return
	}
	sig, err := unhex(resp.Signature)
	if err != nil {
		v.results.fail("%s: signature: %v", id, err)
		return
	}
	if err := verifySignature(c.Pubkey, sig, root); err != nil {
		v.results.fail("%s: %v", id, err)
		return
	}
	if c.DeterministicSignature != "" && v.caps.SelectionProofMode == "deterministic" && !strings.EqualFold(resp.Signature, c.DeterministicSignature) {
		v.results.fail("%s: deterministic signature differs from qrysm's", id)
		return
	}
	v.results.passed++
}

// verifySignature checks sig over root with qrysm's verifier.
func verifySignature(pubkey string, sig []byte, root [32]byte) error {
	pkb, err := unhex(pubkey)
	if err != nil {
		return err
	}
	pk, err := ml_dsa_87.PublicKeyFromBytes(pkb)
	if err != nil {
		return err
	}
	ok, err := ml_dsa_87.VerifySignature(sig, root, pk)
	if err != nil {
		return fmt.Errorf("qrysm's verifier: %w", err)
	}
	if !ok {
		return errors.New("qrysm's verifier rejects the signature")
	}
	return nil
}

// qrysmSigningRoot decodes the fixture's object with qrysm's UnmarshalSSZ
// and recomputes its signing root with qrysm's signing package from the
// fixture network, and checks it against the recorded root.
func qrysmSigningRoot(c *fxSignCase) ([32]byte, error) {
	b, err := unhex(c.ObjectSSZHex)
	if err != nil {
		return [32]byte{}, err
	}
	root, at, bySlot, err := decodeObject(c.Type, b, c.RequestJSON)
	if err != nil {
		return [32]byte{}, err
	}
	version, err := unhex(c.Network.GenesisForkVersion)
	if err != nil {
		return [32]byte{}, err
	}
	gvr, err := unhex(c.Network.GVR)
	if err != nil {
		return [32]byte{}, err
	}
	spe, err := parseU64(c.Network.SlotsPerEpoch)
	if err != nil {
		return [32]byte{}, err
	}
	dt := domainTypeOf(c.Type)
	var d []byte
	if c.Type == tRegistration {
		d, err = signing.ComputeDomain(dt, version, make([]byte, 32))
	} else {
		epoch := at
		if bySlot {
			epoch = at / spe
		}
		fork := &qrysmpb.Fork{PreviousVersion: version, CurrentVersion: version}
		d, err = signing.Domain(fork, primitives.Epoch(epoch), dt, gvr)
	}
	if err != nil {
		return [32]byte{}, err
	}
	sr, err := signing.ComputeSigningRoot(root, d)
	if err != nil {
		return [32]byte{}, err
	}
	if hx(sr[:]) != c.SigningRoot {
		return [32]byte{}, fmt.Errorf("qrysm recomputes signing root %s, the fixture records %s", hx(sr[:]), c.SigningRoot)
	}
	return sr, nil
}

// decodeObject decodes a fixture object with qrysm's UnmarshalSSZ and
// returns it with the slot (bySlot) or epoch its domain is selected by.
func decodeObject(t string, b []byte, request json.RawMessage) (root fssz.HashRoot, at uint64, bySlot bool, err error) {
	type sszObject interface {
		fssz.HashRoot
		UnmarshalSSZ([]byte) error
	}
	decode := func(o sszObject) error {
		root = o
		return o.UnmarshalSSZ(b)
	}
	bySlot = true
	switch t {
	case tBlock:
		h := new(qrysmpb.BeaconBlockHeader)
		err = decode(h)
		at = uint64(h.Slot)
	case tAttestation:
		d := new(qrysmpb.AttestationData)
		if err = decode(d); err == nil {
			at, bySlot = uint64(d.Target.Epoch), false
		}
	case tAggSlot:
		s := new(primitives.SSZUint64)
		err = decode(s)
		at = uint64(*s)
	case tAggAndProof:
		p := new(qrysmpb.AggregateAttestationAndProof)
		if err = decode(p); err == nil {
			at = uint64(p.Aggregate.Data.Slot)
		}
	case tExit:
		e := new(qrysmpb.VoluntaryExit)
		err = decode(e)
		at, bySlot = uint64(e.Epoch), false
	case tSyncMessage:
		// The object is the bare root; the slot only selects the domain
		// and travels in the request.
		if len(b) != 32 {
			return nil, 0, false, fmt.Errorf("sync committee root of %d bytes", len(b))
		}
		r := primitives.SSZBytes(b)
		root = &r
		var req struct {
			Msg struct {
				Slot string `json:"slot"`
			} `json:"sync_committee_message"`
		}
		if err = json.Unmarshal(request, &req); err == nil {
			at, err = parseU64(req.Msg.Slot)
		}
	case tSyncSelect:
		d := new(qrysmpb.SyncAggregatorSelectionData)
		err = decode(d)
		at = uint64(d.Slot)
	case tContribution:
		p := new(qrysmpb.ContributionAndProof)
		if err = decode(p); err == nil {
			at = uint64(p.Contribution.Slot)
		}
	case tRegistration:
		err = decode(new(qrysmpb.ValidatorRegistrationV1))
	default:
		err = fmt.Errorf("unknown type %s", t)
	}
	if err != nil {
		return nil, 0, false, fmt.Errorf("qrysm cannot decode object_ssz_hex: %w", err)
	}
	return root, at, bySlot, nil
}

// domainTypeOf is domainType with the domain values of qrysm's mainnet
// configuration, which every preset shares.
func domainTypeOf(t string) [4]byte {
	r, _ := withConfig(params.MainnetConfig(), func() ([4]byte, error) { return domainType(t), nil })
	return r
}

func (v *verifier) expectError(id string, status int, body []byte, want fxExpect) {
	var e errorBody
	_ = json.Unmarshal(body, &e)
	if status != want.Status || e.Reason != want.Reason {
		v.results.fail("%s: got %d %s, want %d %s", id, status, e.Reason, want.Status, want.Reason)
		return
	}
	v.results.passed++
}

// verifyNegative posts the negative fixtures and checks status and reason.
func (v *verifier) verifyNegative(ctx context.Context, fx *fixtures) {
	nf := fx.negative[v.preset]
	exitsEnabled := slices.Contains(v.caps.Types, tExit)
	for _, c := range nf.Cases {
		id := v.preset + "/negative/" + c.Name
		if c.Signer != nil && c.Signer.VoluntaryExitsEnabled != nil && *c.Signer.VoluntaryExitsEnabled != exitsEnabled {
			v.skip("%s: needs voluntary exits enabled=%v", id, *c.Signer.VoluntaryExitsEnabled)
			continue
		}
		ident := c.Identifier
		if ident == "" {
			k := fx.keys[c.KeyIndex]
			if !v.loaded[strings.ToLower(k.Pubkey)] {
				v.skip("%s: key %d is not loaded", id, c.KeyIndex)
				continue
			}
			ident = k.Pubkey
		}
		status, body, err := v.do(ctx, http.MethodPost, "/api/v1/consensus/sign/"+ident, c.RequestBody)
		if err != nil {
			v.results.fail("%s: %v", id, err)
			continue
		}
		v.expectError(id, status, body, c.Expect)
	}
}

// verifyRandao runs V5 and then a first reveal per loaded key whose
// commitment is in keys/interop.json, checked with qrysm's randao.Verify.
// It needs the signer to know its genesis time.
func (v *verifier) verifyRandao(ctx context.Context, fx *fixtures) {
	if !v.caps.RandaoReveal || v.caps.Network.GenesisTime == nil {
		v.skip("RANDAO: the signer reports randao_reveal false or no genesis time")
		return
	}
	genesis, err1 := parseU64(*v.caps.Network.GenesisTime)
	sps, err2 := parseU64(v.caps.Network.SecondsPerSlot)
	if err := errors.Join(err1, err2); err != nil || sps == 0 {
		v.results.fail("RANDAO: capabilities network timing: %v", err)
		return
	}
	nowSlot := func() uint64 {
		t := uint64(v.now().Unix())
		if t < genesis {
			return 0
		}
		return (t - genesis) / sps
	}
	body := func(slot uint64, commitment string, forkInfo json.RawMessage) string {
		return compact(obj{}.set("slot", u64s(slot)).set("randao_commitment", commitment).set("fork_info", forkInfo))
	}
	for _, c := range fx.randao {
		if c.Preset != v.preset {
			continue
		}
		k := fx.keys[c.KeyIndex]
		if !v.loaded[strings.ToLower(k.Pubkey)] {
			v.skip("randao/%s: key %d is not loaded", c.Name, c.KeyIndex)
			continue
		}
		slot := uint64(int64(nowSlot()) + c.SlotOffset)
		status, b, err := v.do(ctx, http.MethodPost, "/api/v1/consensus/randao_reveal/"+k.Pubkey, body(slot, c.RandaoCommitment, c.ForkInfo))
		if err != nil {
			v.results.fail("randao/%s: %v", c.Name, err)
			continue
		}
		v.expectError("randao/"+c.Name, status, b, c.Expect)
	}
	forkInfo := fx.negativeForkInfo(v.preset)
	for _, k := range fx.keys[:2] {
		id := fmt.Sprintf("randao/%s/first_reveal_key_%d", v.preset, k.Index)
		if !v.loaded[strings.ToLower(k.Pubkey)] {
			v.skip("%s: key not loaded", id)
			continue
		}
		status, b, err := v.do(ctx, http.MethodPost, "/api/v1/consensus/randao_reveal/"+k.Pubkey, body(nowSlot(), k.RandaoCommitment, forkInfo))
		if err != nil {
			v.results.fail("%s: %v", id, err)
			continue
		}
		if status != http.StatusOK {
			v.results.fail("%s: status %d: %.200s", id, status, b)
			continue
		}
		var resp struct {
			Reveal string `json:"randao_reveal"`
		}
		if err := json.Unmarshal(b, &resp); err != nil {
			v.results.fail("%s: %v", id, err)
			continue
		}
		r, err1 := unhex(resp.Reveal)
		c, err2 := unhex(k.RandaoCommitment)
		if err := errors.Join(err1, err2); err != nil || len(r) != 32 || len(c) != 32 {
			v.results.fail("%s: malformed reveal %.80q: %v", id, resp.Reveal, err)
			continue
		}
		if !randao.Verify([32]byte(r), [32]byte(c)) {
			v.results.fail("%s: qrysm's randao.Verify rejects the reveal", id)
			continue
		}
		if !strings.EqualFold(resp.Reveal, k.RandaoFirstReveal) {
			v.results.fail("%s: reveal %s, want the first reveal %s", id, resp.Reveal, k.RandaoFirstReveal)
			continue
		}
		v.results.passed++
	}
}

// negativeForkInfo returns the fork_info of the preset's RANDAO requests.
func (fx *fixtures) negativeForkInfo(preset string) json.RawMessage {
	for _, c := range fx.randao {
		if c.Preset == preset {
			return c.ForkInfo
		}
	}
	return nil
}
