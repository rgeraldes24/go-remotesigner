// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/ssz"
)

// hasher is what every container implements.
type hasher interface {
	HashTreeRoot() ([32]byte, error)
}

var (
	_ hasher = Uint64(0)
	_ hasher = Bytes32{}
	_ hasher = BeaconBlockHeader{}
	_ hasher = Checkpoint{}
	_ hasher = AttestationData{}
	_ hasher = (*Attestation)(nil)
	_ hasher = (*AggregateAttestationAndProof)(nil)
	_ hasher = VoluntaryExit{}
	_ hasher = SyncAggregatorSelectionData{}
	_ hasher = (*SyncCommitteeContribution)(nil)
	_ hasher = (*ContributionAndProof)(nil)
	_ hasher = (*ValidatorRegistrationV1)(nil)
)

// fixturePattern mirrors pattern() in ../testdata/gen_fixtures.py.
func fixturePattern(seed, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(seed*37 + i*11 + (i/256)*3)
	}
	return b
}

// fixtureBytes decodes a fixture byte string: "0x<hex>" of exactly n bytes,
// or "pattern:<seed>".
func fixtureBytes(t *testing.T, s string, n int) []byte {
	t.Helper()
	if seed, ok := strings.CutPrefix(s, "pattern:"); ok {
		v, err := strconv.Atoi(seed)
		if err != nil {
			t.Fatalf("bad pattern %q", s)
		}
		return fixturePattern(v, n)
	}
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || !strings.HasPrefix(s, "0x") || (n >= 0 && len(b) != n) {
		t.Fatalf("bad %d-byte hex %q", n, s)
	}
	return b
}

func fxRoot(t *testing.T, s string) [32]byte { t.Helper(); return [32]byte(fixtureBytes(t, s, 32)) }

func fxUint(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("bad uint64 %q", s)
	}
	return v
}

func fxSignatures(t *testing.T, in []string) []Signature {
	t.Helper()
	out := make([]Signature, len(in))
	for i, s := range in {
		out[i] = Signature(fixtureBytes(t, s, SignatureLength))
	}
	return out
}

// Fixture value shapes, with the JSON field names of the signing API.
type (
	fxCheckpoint struct {
		Epoch string `json:"epoch"`
		Root  string `json:"root"`
	}
	fxHeader struct {
		Slot          string `json:"slot"`
		ProposerIndex string `json:"proposer_index"`
		ParentRoot    string `json:"parent_root"`
		StateRoot     string `json:"state_root"`
		BodyRoot      string `json:"body_root"`
	}
	fxData struct {
		Slot            string       `json:"slot"`
		Index           string       `json:"index"`
		BeaconBlockRoot string       `json:"beacon_block_root"`
		Source          fxCheckpoint `json:"source"`
		Target          fxCheckpoint `json:"target"`
	}
	fxAttestation struct {
		AggregationBits string   `json:"aggregation_bits"`
		Data            fxData   `json:"data"`
		Signatures      []string `json:"signatures"`
	}
	fxAggregateAndProof struct {
		AggregatorIndex string        `json:"aggregator_index"`
		Aggregate       fxAttestation `json:"aggregate"`
		SelectionProof  string        `json:"selection_proof"`
	}
	fxExit struct {
		Epoch          string `json:"epoch"`
		ValidatorIndex string `json:"validator_index"`
	}
	fxSelection struct {
		Slot              string `json:"slot"`
		SubcommitteeIndex string `json:"subcommittee_index"`
	}
	fxContribution struct {
		Slot              string   `json:"slot"`
		BeaconBlockRoot   string   `json:"beacon_block_root"`
		SubcommitteeIndex string   `json:"subcommittee_index"`
		AggregationBits   string   `json:"aggregation_bits"`
		Signatures        []string `json:"signatures"`
	}
	fxContributionAndProof struct {
		AggregatorIndex string         `json:"aggregator_index"`
		Contribution    fxContribution `json:"contribution"`
		SelectionProof  string         `json:"selection_proof"`
	}
	fxRegistration struct {
		FeeRecipient string `json:"fee_recipient"`
		GasLimit     string `json:"gas_limit"`
		Timestamp    string `json:"timestamp"`
		Pubkey       string `json:"pubkey"`
	}
)

func (f fxCheckpoint) build(t *testing.T) Checkpoint {
	return Checkpoint{Epoch: fxUint(t, f.Epoch), Root: fxRoot(t, f.Root)}
}

func (f fxData) build(t *testing.T) AttestationData {
	return AttestationData{
		Slot: fxUint(t, f.Slot), Index: fxUint(t, f.Index), BeaconBlockRoot: fxRoot(t, f.BeaconBlockRoot),
		Source: f.Source.build(t), Target: f.Target.build(t),
	}
}

func (f fxAttestation) build(t *testing.T) Attestation {
	return Attestation{
		AggregationBits: fixtureBytes(t, f.AggregationBits, -1),
		Data:            f.Data.build(t),
		Signatures:      fxSignatures(t, f.Signatures),
	}
}

func (f fxContribution) build(t *testing.T) SyncCommitteeContribution {
	return SyncCommitteeContribution{
		Slot: fxUint(t, f.Slot), BeaconBlockRoot: fxRoot(t, f.BeaconBlockRoot),
		SubcommitteeIndex: fxUint(t, f.SubcommitteeIndex),
		AggregationBits:   fixtureBytes(t, f.AggregationBits, -1),
		Signatures:        fxSignatures(t, f.Signatures),
	}
}

// buildFixture decodes a fixture value of the named type.
func buildFixture(t *testing.T, typ string, raw json.RawMessage) hasher {
	t.Helper()
	decode := func(v any) {
		t.Helper()
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			t.Fatalf("decode %s: %v", typ, err)
		}
	}
	switch typ {
	case "Uint64":
		var s string
		decode(&s)
		return Uint64(fxUint(t, s))
	case "Bytes32":
		var s string
		decode(&s)
		return Bytes32(fxRoot(t, s))
	case "BeaconBlockHeader":
		var f fxHeader
		decode(&f)
		return BeaconBlockHeader{
			Slot: fxUint(t, f.Slot), ProposerIndex: fxUint(t, f.ProposerIndex),
			ParentRoot: fxRoot(t, f.ParentRoot), StateRoot: fxRoot(t, f.StateRoot), BodyRoot: fxRoot(t, f.BodyRoot),
		}
	case "Checkpoint":
		var f fxCheckpoint
		decode(&f)
		return f.build(t)
	case "AttestationData":
		var f fxData
		decode(&f)
		return f.build(t)
	case "Attestation":
		var f fxAttestation
		decode(&f)
		a := f.build(t)
		return &a
	case "AggregateAttestationAndProof":
		var f fxAggregateAndProof
		decode(&f)
		return &AggregateAttestationAndProof{
			AggregatorIndex: fxUint(t, f.AggregatorIndex),
			Aggregate:       f.Aggregate.build(t),
			SelectionProof:  Signature(fixtureBytes(t, f.SelectionProof, SignatureLength)),
		}
	case "VoluntaryExit":
		var f fxExit
		decode(&f)
		return VoluntaryExit{Epoch: fxUint(t, f.Epoch), ValidatorIndex: fxUint(t, f.ValidatorIndex)}
	case "SyncAggregatorSelectionData":
		var f fxSelection
		decode(&f)
		return SyncAggregatorSelectionData{Slot: fxUint(t, f.Slot), SubcommitteeIndex: fxUint(t, f.SubcommitteeIndex)}
	case "SyncCommitteeContribution":
		var f fxContribution
		decode(&f)
		c := f.build(t)
		return &c
	case "ContributionAndProof":
		var f fxContributionAndProof
		decode(&f)
		return &ContributionAndProof{
			AggregatorIndex: fxUint(t, f.AggregatorIndex),
			Contribution:    f.Contribution.build(t),
			SelectionProof:  Signature(fixtureBytes(t, f.SelectionProof, SignatureLength)),
		}
	case "ValidatorRegistrationV1":
		var f fxRegistration
		decode(&f)
		return &ValidatorRegistrationV1{
			FeeRecipient: Address(fixtureBytes(t, f.FeeRecipient, AddressLength)),
			GasLimit:     fxUint(t, f.GasLimit),
			Timestamp:    fxUint(t, f.Timestamp),
			Pubkey:       Pubkey(fixtureBytes(t, f.Pubkey, PubkeyLength)),
		}
	}
	t.Fatalf("unknown fixture type %q", typ)
	return nil
}

// TestContainerFixtures checks every container against the roots computed by
// ../testdata/gen_fixtures.py, an independent implementation.
func TestContainerFixtures(t *testing.T) {
	raw, err := os.ReadFile("../testdata/containers.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Type  string          `json:"type"`
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
			Root  string          `json:"root"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	types := map[string]int{}
	for _, c := range doc.Cases {
		t.Run(c.Type+"/"+c.Name, func(t *testing.T) {
			types[c.Type]++
			got, err := buildFixture(t, c.Type, c.Value).HashTreeRoot()
			if err != nil {
				t.Fatal(err)
			}
			if want := fxRoot(t, c.Root); got != want {
				t.Fatalf("root = %x, want %x", got, want)
			}
		})
	}
	if len(types) != 12 {
		t.Errorf("fixtures cover %d types, want 12: %v", len(types), types)
	}
}

// The contribution root is the same at both presets for the same set bits.
func TestContributionRootIsPresetIndependent(t *testing.T) {
	minimal := SyncCommitteeContribution{Slot: 5, AggregationBits: []byte{0x05, 0x00},
		Signatures: make([]Signature, 2)}
	mainnet := minimal
	mainnet.AggregationBits = make([]byte, 16)
	mainnet.AggregationBits[0] = 0x05
	a, err := minimal.HashTreeRoot()
	if err != nil {
		t.Fatal(err)
	}
	b, err := mainnet.HashTreeRoot()
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("minimal root %x != mainnet root %x", a, b)
	}
}

func TestHashTreeRootErrors(t *testing.T) {
	tests := []struct {
		name string
		obj  hasher
		want error
	}{
		{"attestation without delimiter", &Attestation{AggregationBits: []byte{0xff, 0x00}}, ssz.ErrBitlistDelimiter},
		{"attestation with nil bits", &Attestation{}, ssz.ErrBitlistDelimiter},
		{"attestation with 33 bits", &Attestation{AggregationBits: []byte{0xff, 0xff, 0xff, 0xff, 0x03}}, ssz.ErrLimit},
		{"attestation with 33 signatures",
			&Attestation{AggregationBits: []byte{0x01}, Signatures: make([]Signature, 33)}, ssz.ErrLimit},
		{"aggregate with an invalid attestation",
			&AggregateAttestationAndProof{Aggregate: Attestation{AggregationBits: []byte{0}}}, ssz.ErrBitlistDelimiter},
		{"contribution with no bits", &SyncCommitteeContribution{}, ssz.ErrEmptyVector},
		{"contribution with 129 signatures",
			&SyncCommitteeContribution{AggregationBits: make([]byte, 16), Signatures: make([]Signature, 129)}, ssz.ErrLimit},
		{"contribution and proof with an invalid contribution", &ContributionAndProof{}, ssz.ErrEmptyVector},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.obj.HashTreeRoot(); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// The signature lists accept their exact limits.
func TestSignatureListLimits(t *testing.T) {
	att := Attestation{AggregationBits: []byte{0xff, 0xff, 0xff, 0xff, 0x01}, Signatures: make([]Signature, 32)}
	if _, err := att.HashTreeRoot(); err != nil {
		t.Errorf("32 attestation signatures: %v", err)
	}
	c := SyncCommitteeContribution{AggregationBits: make([]byte, 16), Signatures: make([]Signature, 128)}
	if _, err := c.HashTreeRoot(); err != nil {
		t.Errorf("128 contribution signatures: %v", err)
	}
}
