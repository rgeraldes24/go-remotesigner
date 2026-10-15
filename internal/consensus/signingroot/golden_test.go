// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package signingroot_test

import (
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/types"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// TestGoldenDomainsAndSigningRoots checks the domain and the signing root of
// every golden sign request against qrysm's (testdata/vectors). The request
// is decoded only to learn the slot or epoch the type's rule reads.
func TestGoldenDomainsAndSigningRoots(t *testing.T) {
	for _, c := range vectors.Signing(t) {
		t.Run(c.ID(), func(t *testing.T) {
			n := c.Network
			chain, err := signingroot.NewChain(signingroot.Version(vectors.Hex(t, n.GenesisForkVersion)),
				vectors.Hex32(t, n.GVR), vectors.U64(t, n.SlotsPerEpoch))
			if err != nil {
				t.Fatal(err)
			}
			req, err := types.DecodeSignRequest(c.RequestJSON, types.Params{SyncSubcommitteeSize: syncBits(c.Preset)})
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			typ := signingroot.ArtifactType(c.Type)
			d, err := chain.DomainFor(typ, req.Payload.DomainAt())
			if err != nil {
				t.Fatal(err)
			}
			if want := signingroot.Domain(vectors.Hex32(t, c.Domain)); d != want {
				t.Errorf("domain %#x, want %#x", d, want)
			}
			rule, _ := signingroot.RuleFor(typ)
			if [4]byte(d[:4]) != rule.DomainType {
				t.Errorf("domain type %#x, want %#x", d[:4], rule.DomainType)
			}
			sr := signingroot.ComputeSigningRoot(vectors.Hex32(t, c.ObjectRoot), d)
			if want := vectors.Hex32(t, c.SigningRoot); sr != want {
				t.Errorf("signing root %#x, want %#x", sr, want)
			}
		})
	}
}

// TestGoldenRegistrationDomain checks the builder rule on the golden
// registrations: qrysm's domain is compute_domain(DOMAIN_APPLICATION_BUILDER,
// genesis version, zero root), whatever the network's GVR.
func TestGoldenRegistrationDomain(t *testing.T) {
	checked := 0
	for _, c := range vectors.Signing(t) {
		if c.Type != string(signingroot.ValidatorRegistration) {
			continue
		}
		version := signingroot.Version(vectors.Hex(t, c.Network.GenesisForkVersion))
		want := signingroot.ComputeDomain(signingroot.DomainApplicationBuilder, version, [32]byte{})
		if got := signingroot.Domain(vectors.Hex32(t, c.Domain)); got != want {
			t.Errorf("%s: golden domain %#x, want %#x", c.ID(), got, want)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no golden registrations")
	}
}

func syncBits(preset string) uint64 {
	if preset == "minimal" {
		return 16
	}
	return 128
}
