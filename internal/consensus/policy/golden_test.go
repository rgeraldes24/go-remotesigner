// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/types"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// goldenPolicy is the policy of a fixture network: the named network bound
// to the fixture GVR, genesis time unknown (so no clock bound applies).
func goldenPolicy(t *testing.T, n vectors.Network, exits bool) *Policy {
	t.Helper()
	gvr := vectors.Hex32(t, n.GVR)
	nw, err := network.Load(network.Sources{Network: n.ConfigName, GenesisValidatorsRoot: &gvr})
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{Network: nw, ClockSkewSlots: DefaultClockSkewSlots, VoluntaryExitsEnabled: exits})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func keyID(t *testing.T, hexPubkey string) [32]byte {
	t.Helper()
	pk := types.Pubkey(vectors.Hex(t, hexPubkey))
	return types.KeyID(&pk)
}

// TestGoldenRequestsPass checks that every golden request passes steps 3 to
// 7 on its own network and that the policy's signing root is qrysm's.
func TestGoldenRequestsPass(t *testing.T) {
	policies := map[string]*Policy{}
	for _, c := range vectors.Signing(t) {
		t.Run(c.ID(), func(t *testing.T) {
			p, ok := policies[c.Preset]
			if !ok {
				p = goldenPolicy(t, c.Network, true)
				policies[c.Preset] = p
			}
			req, err := types.DecodeSignRequest(c.RequestJSON, p.Params())
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			d, err := p.Check(req, keyID(t, c.Pubkey))
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if d.SigningRoot != vectors.Hex32(t, c.SigningRoot) {
				t.Errorf("signing root %#x, want %s", d.SigningRoot, c.SigningRoot)
			}
		})
	}
}

// TestGoldenNegativePolicy runs the policy-stage negative fixtures (the
// decoder's own reasons are covered in internal/consensus/types) through
// Check and compares the status and reason.
func TestGoldenNegativePolicy(t *testing.T) {
	keys := vectors.Keys(t)
	decodeStage := map[string]bool{"BAD_IDENTIFIER": true, "MALFORMED_JSON": true, "UNKNOWN_FIELD": true,
		"BAD_FIELD": true, "UNKNOWN_TYPE": true, "MISSING_FORK_INFO": true}
	checked := 0
	for _, f := range vectors.Negative(t) {
		for _, c := range f.Cases {
			if decodeStage[c.Expect.Reason] {
				continue
			}
			t.Run(f.Preset+"/"+c.Name, func(t *testing.T) {
				exits := true
				if c.Signer != nil && c.Signer.VoluntaryExitsEnabled != nil {
					exits = *c.Signer.VoluntaryExitsEnabled
				}
				p := goldenPolicy(t, f.Network, exits)
				req, err := types.DecodeSignRequest([]byte(c.RequestBody), p.Params())
				if err != nil {
					t.Fatalf("decode: %v", err)
				}
				_, err = p.Check(req, keyID(t, keys[c.KeyIndex].Pubkey))
				var e *apierr.Error
				if !errors.As(err, &e) {
					t.Fatalf("got %v, want %d %s", err, c.Expect.Status, c.Expect.Reason)
				}
				if string(e.Reason) != c.Expect.Reason || e.Status() != c.Expect.Status {
					t.Errorf("got %d %s (%v), want %d %s", e.Status(), e.Reason, e, c.Expect.Status, c.Expect.Reason)
				}
			})
			checked++
		}
	}
	if checked < 20 {
		t.Fatalf("checked only %d policy-stage fixtures", checked)
	}
}
