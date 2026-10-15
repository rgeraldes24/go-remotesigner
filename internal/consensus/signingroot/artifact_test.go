// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package signingroot

import (
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"
)

func TestRules(t *testing.T) {
	tests := []struct {
		typ    ArtifactType
		domain DomainType
		epoch  EpochRule
	}{
		{BlockV2, DomainBeaconProposer, EpochOfSlot},
		{Attestation, DomainBeaconAttester, EpochAsGiven},
		{AggregationSlot, DomainSelectionProof, EpochOfSlot},
		{AggregateAndProof, DomainAggregateAndProof, EpochOfSlot},
		{VoluntaryExit, DomainVoluntaryExit, EpochAsGiven},
		{SyncCommitteeMessage, DomainSyncCommittee, EpochOfSlot},
		{SyncCommitteeSelectionProof, DomainSyncCommitteeSelectionProof, EpochOfSlot},
		{SyncCommitteeContributionAndProof, DomainContributionAndProof, EpochOfSlot},
		{ValidatorRegistration, DomainApplicationBuilder, GenesisFork},
	}
	if len(tests) != len(rules) {
		t.Fatalf("rules has %d types, the table %d", len(rules), len(tests))
	}
	for _, tt := range tests {
		r, ok := RuleFor(tt.typ)
		if !ok {
			t.Errorf("RuleFor(%s): unknown", tt.typ)
			continue
		}
		if r.DomainType != tt.domain || r.Epoch != tt.epoch {
			t.Errorf("RuleFor(%s) = %+v, want {%x %d}", tt.typ, r, tt.domain, tt.epoch)
		}
	}
	for _, typ := range []ArtifactType{"", "block_v2", "BLOCK", "RANDAO_REVEAL", "DEPOSIT", "AGGREGATE_AND_PROOF_V2"} {
		if _, ok := RuleFor(typ); ok {
			t.Errorf("RuleFor(%q) is known", typ)
		}
	}
}

func TestChainErrors(t *testing.T) {
	if _, err := NewChain(Version{}, [32]byte{}, 0); !errors.Is(err, ErrSlotsPerEpoch) {
		t.Errorf("NewChain with 0 slots per epoch: err = %v, want ErrSlotsPerEpoch", err)
	}
	c, err := NewChain(Version{0, 0, 0, 0xfd}, [32]byte{1}, 6)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.DomainFor("UNKNOWN", 1); !errors.Is(err, ErrUnknownArtifactType) {
		t.Errorf("DomainFor(UNKNOWN): err = %v, want ErrUnknownArtifactType", err)
	}
	if _, err := c.SigningRoot(ArtifactType("RANDAO_REVEAL"), [32]byte{}, 1); !errors.Is(err, ErrUnknownArtifactType) {
		t.Errorf("SigningRoot(RANDAO_REVEAL): err = %v, want ErrUnknownArtifactType", err)
	}

	// A zero Chain cannot pick an epoch from a slot, but types that need no
	// slot division still work.
	var zero Chain
	if _, err := zero.DomainFor(BlockV2, 1); !errors.Is(err, ErrSlotsPerEpoch) {
		t.Errorf("zero Chain, BLOCK_V2: err = %v, want ErrSlotsPerEpoch", err)
	}
	if _, err := zero.DomainFor(Attestation, 1); err != nil {
		t.Errorf("zero Chain, ATTESTATION: %v", err)
	}
}

func TestNewChainIsSingleFork(t *testing.T) {
	g := Version{0, 0, 0, 0xfd}
	gvr := [32]byte{7}
	c, err := NewChain(g, gvr, 6)
	if err != nil {
		t.Fatal(err)
	}
	if c.Fork != (Fork{PreviousVersion: g, CurrentVersion: g}) {
		t.Fatalf("Fork = %+v, want {genesis, genesis, 0}", c.Fork)
	}
	for _, at := range []uint64{0, 6, 1 << 40, ^uint64(0)} {
		got, err := c.DomainFor(BlockV2, at)
		if err != nil {
			t.Fatal(err)
		}
		if want := ComputeDomain(DomainBeaconProposer, g, gvr); got != want {
			t.Errorf("DomainFor(BLOCK_V2, %d) = %x, want the genesis-version domain %x", at, got, want)
		}
	}
}

// The validator registration domain depends only on the genesis fork version:
// not on the fork schedule, the genesis validators root or the slot.
func TestRegistrationDomainIgnoresForkAndRoot(t *testing.T) {
	g := Version{0, 0, 0, 0xfd}
	a := Chain{GenesisForkVersion: g, GenesisValidatorsRoot: [32]byte{1}, SlotsPerEpoch: 6,
		Fork: Fork{PreviousVersion: g, CurrentVersion: Version{9, 9, 9, 9}, Epoch: 1}}
	b := Chain{GenesisForkVersion: g}
	da, err := a.DomainFor(ValidatorRegistration, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	db, err := b.DomainFor(ValidatorRegistration, 0)
	if err != nil {
		t.Fatal(err)
	}
	if da != db || da != ComputeDomain(DomainApplicationBuilder, g, [32]byte{}) {
		t.Fatalf("registration domains %x and %x, want both %x", da, db,
			ComputeDomain(DomainApplicationBuilder, g, [32]byte{}))
	}
	if _, ok, err := a.SigningEpoch(ValidatorRegistration, 5); ok || err != nil {
		t.Fatalf("SigningEpoch(VALIDATOR_REGISTRATION) = ok %v, err %v; want no epoch", ok, err)
	}
}

// signingFixture is one case of ../testdata/signing.json, written by
// gen_fixtures.py.
type signingFixture struct {
	Name    string `json:"name"`
	Network struct {
		GenesisForkVersion    string `json:"genesis_fork_version"`
		GenesisValidatorsRoot string `json:"genesis_validators_root"`
		SlotsPerEpoch         string `json:"slots_per_epoch"`
	} `json:"network"`
	Fork struct {
		PreviousVersion string `json:"previous_version"`
		CurrentVersion  string `json:"current_version"`
		Epoch           string `json:"epoch"`
	} `json:"fork"`
	Type        ArtifactType `json:"type"`
	At          string       `json:"at"`
	ObjectRoot  string       `json:"object_root"`
	Epoch       *string      `json:"epoch"`
	Domain      string       `json:"domain"`
	SigningRoot string       `json:"signing_root"`
}

func parseUint(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("bad uint64 %q", s)
	}
	return v
}

func TestSigningRootFixtures(t *testing.T) {
	raw, err := os.ReadFile("../testdata/signing.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []signingFixture `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Cases) == 0 {
		t.Fatal("no cases")
	}
	seen := map[ArtifactType]bool{}
	for _, fx := range doc.Cases {
		t.Run(fx.Name, func(t *testing.T) {
			seen[fx.Type] = true
			c := Chain{
				GenesisForkVersion:    version(t, fx.Network.GenesisForkVersion),
				GenesisValidatorsRoot: root32(t, fx.Network.GenesisValidatorsRoot),
				SlotsPerEpoch:         parseUint(t, fx.Network.SlotsPerEpoch),
				Fork: Fork{
					PreviousVersion: version(t, fx.Fork.PreviousVersion),
					CurrentVersion:  version(t, fx.Fork.CurrentVersion),
					Epoch:           parseUint(t, fx.Fork.Epoch),
				},
			}
			at := parseUint(t, fx.At)

			epoch, ok, err := c.SigningEpoch(fx.Type, at)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case fx.Epoch == nil && ok:
				t.Errorf("SigningEpoch = %d, want none", epoch)
			case fx.Epoch != nil && (!ok || epoch != parseUint(t, *fx.Epoch)):
				t.Errorf("SigningEpoch = %d (ok %v), want %s", epoch, ok, *fx.Epoch)
			}

			d, err := c.DomainFor(fx.Type, at)
			if err != nil {
				t.Fatal(err)
			}
			if d != domainHex(t, fx.Domain) {
				t.Errorf("domain = %x, want %s", d, fx.Domain)
			}
			sr, err := c.SigningRoot(fx.Type, root32(t, fx.ObjectRoot), at)
			if err != nil {
				t.Fatal(err)
			}
			if sr != root32(t, fx.SigningRoot) {
				t.Errorf("signing root = %x, want %s", sr, fx.SigningRoot)
			}
		})
	}
	for typ := range rules {
		if !seen[typ] {
			t.Errorf("no fixture for %s", typ)
		}
	}
}
