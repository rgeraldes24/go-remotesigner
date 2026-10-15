// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/theQRL/qrysm/crypto/ml_dsa_87"
)

// fakeSigner answers verify's requests from the fixtures themselves,
// signing with qrysm's keys. Its faults make it wrong in one way each, to
// show that verify catches it.
type fakeSigner struct {
	t      *testing.T
	fx     *fixtures
	preset string
	keys   map[string]ml_dsa_87.MLDSA87Key // by lowercase pubkey
	sign   map[string]*fxSignCase          // by compact request body
	neg    map[string]fxExpect             // by identifier + body
	token  string

	signObjectRoot bool // sign the object root instead of the signing root
	hedgedOnly     bool // never sign deterministically
}

func newFakeSigner(t *testing.T, dir, preset string) *fakeSigner {
	t.Helper()
	fx, err := loadFixtures(dir)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSigner{t: t, fx: fx, preset: preset, keys: map[string]ml_dsa_87.MLDSA87Key{},
		sign: map[string]*fxSignCase{}, neg: map[string]fxExpect{}, token: "0x" + strings.Repeat("ab", 32)}
	for _, k := range fx.keys {
		seed, err := unhex(k.Seed)
		if err != nil {
			t.Fatal(err)
		}
		key, err := ml_dsa_87.SecretKeyFromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		f.keys[strings.ToLower(k.Pubkey)] = key
	}
	for _, file := range fx.signing[preset] {
		for i := range file.Cases {
			c := &file.Cases[i]
			f.sign[compactBody(t, c.RequestJSON)] = c
		}
	}
	for _, c := range fx.negative[preset].Cases {
		id := c.Identifier
		if id == "" {
			id = fx.keys[c.KeyIndex].Pubkey
		}
		f.neg[id+" "+c.RequestBody] = c.Expect
	}
	return f
}

func compactBody(t *testing.T, b []byte) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		return string(b)
	}
	return buf.String()
}

func (f *fakeSigner) fail(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": status, "message": "refused", "reason": reason})
}

func (f *fakeSigner) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		f.fail(w, 401, "UNAUTHENTICATED")
		return
	}
	n := f.fx.signing[f.preset][0].Cases[0].Network
	switch {
	case r.URL.Path == "/api/v1/consensus/capabilities":
		genesis := u64s(uint64(time.Now().Unix()) - 1000*10)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"api_version": "1.0.0",
			"types": []string{tBlock, tAttestation, tAggSlot, tAggAndProof, tSyncMessage, tSyncSelect,
				tContribution, tRegistration},
			"randao_reveal":        true,
			"selection_proof_mode": "deterministic",
			"slashing_protection":  "disabled",
			"network": map[string]any{
				"config_name": n.ConfigName, "genesis_fork_version": n.GenesisForkVersion,
				"genesis_validators_root": n.GVR, "genesis_time": genesis,
				"seconds_per_slot": "10", "slots_per_epoch": n.SlotsPerEpoch,
			},
		})
	case r.URL.Path == "/api/v1/consensus/publicKeys":
		var keys []string
		for _, k := range f.fx.keys {
			keys = append(keys, k.Pubkey)
		}
		_ = json.NewEncoder(w).Encode(keys)
	case strings.HasPrefix(r.URL.Path, "/api/v1/consensus/sign/"):
		f.serveSign(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/v1/consensus/randao_reveal/"):
		f.serveRandao(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeSigner) serveSign(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/consensus/sign/")
	body, _ := io.ReadAll(r.Body)
	if e, ok := f.neg[id+" "+string(body)]; ok {
		f.fail(w, e.Status, e.Reason)
		return
	}
	c, ok := f.sign[compactBody(f.t, body)]
	if !ok {
		f.fail(w, 400, "BAD_FIELD")
		return
	}
	if c.Type == tExit {
		f.fail(w, 403, "ARTIFACT_TYPE_DISABLED")
		return
	}
	key := f.keys[strings.ToLower(id)]
	root := c.SigningRoot
	if f.signObjectRoot {
		root = c.ObjectRoot
	}
	msg, _ := unhex(root)
	sign := key.Sign
	if deterministicTypes[c.Type] && !f.hedgedOnly {
		sign = key.SignDeterministic
	}
	sig, err := sign(msg)
	if err != nil {
		f.fail(w, 500, "INTERNAL")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"signature": hx(sig.Marshal())})
}

func (f *fakeSigner) serveRandao(w http.ResponseWriter, r *http.Request) {
	id := strings.ToLower(strings.TrimPrefix(r.URL.Path, "/api/v1/consensus/randao_reveal/"))
	var req struct {
		Commitment string `json:"randao_commitment"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	for _, c := range f.fx.randao {
		if c.Preset == f.preset && strings.ToLower(f.fx.keys[c.KeyIndex].Pubkey) == id && c.RandaoCommitment == req.Commitment {
			f.fail(w, c.Expect.Status, c.Expect.Reason)
			return
		}
	}
	for _, k := range f.fx.keys {
		if strings.ToLower(k.Pubkey) == id && k.RandaoCommitment == req.Commitment {
			_ = json.NewEncoder(w).Encode(map[string]string{"randao_reveal": k.RandaoFirstReveal})
			return
		}
	}
	f.fail(w, 422, "RANDAO_UNKNOWN_COMMITMENT")
}

func vectorsDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../../testdata/vectors")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func runAgainst(t *testing.T, f *fakeSigner) verifyResults {
	t.Helper()
	srv := httptest.NewServer(f)
	defer srv.Close()
	res, err := runVerify(context.Background(), srv.URL, f.token, vectorsDir(t), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestVerifyAcceptsACorrectSigner runs verify against a signer that answers
// every fixture correctly: everything passes, and only the exit fixtures
// that need exits enabled are skipped.
func TestVerifyAcceptsACorrectSigner(t *testing.T) {
	for _, preset := range []string{"minimal", "mainnet"} {
		t.Run(preset, func(t *testing.T) {
			res := runAgainst(t, newFakeSigner(t, vectorsDir(t), preset))
			for _, f := range res.failures {
				t.Error(f)
			}
			if res.passed < 100 {
				t.Errorf("only %d checks passed", res.passed)
			}
		})
	}
}

// TestVerifyCatchesWrongRoots runs verify against a signer that signs the
// object root instead of the signing root: every signature must fail
// qrysm's verifier.
func TestVerifyCatchesWrongRoots(t *testing.T) {
	f := newFakeSigner(t, vectorsDir(t), "minimal")
	f.signObjectRoot = true
	res := runAgainst(t, f)
	signed := 0
	for _, file := range f.fx.signing["minimal"] {
		for _, c := range file.Cases {
			if c.Type != tExit {
				signed++
			}
		}
	}
	if len(res.failures) != signed {
		t.Fatalf("%d failures, want one per signed fixture (%d)", len(res.failures), signed)
	}
	for _, msg := range res.failures {
		if !strings.Contains(msg, "rejects the signature") {
			t.Fatalf("unexpected failure %q", msg)
		}
	}
}

// TestVerifyCatchesHedgedSelectionProofs runs verify against a signer that
// signs selection proofs in hedged mode while claiming deterministic: the
// signatures verify but differ from qrysm's bytes.
func TestVerifyCatchesHedgedSelectionProofs(t *testing.T) {
	f := newFakeSigner(t, vectorsDir(t), "minimal")
	f.hedgedOnly = true
	res := runAgainst(t, f)
	if len(res.failures) == 0 {
		t.Fatal("no failures")
	}
	for _, msg := range res.failures {
		if !strings.Contains(msg, "deterministic signature differs") {
			t.Fatalf("unexpected failure %q", msg)
		}
	}
}

func TestVerifyRequiresTheToken(t *testing.T) {
	f := newFakeSigner(t, vectorsDir(t), "minimal")
	srv := httptest.NewServer(f)
	defer srv.Close()
	if _, err := runVerify(context.Background(), srv.URL, "wrong", vectorsDir(t), io.Discard); err == nil {
		t.Fatal("verify ran without the signer's token")
	}
}
