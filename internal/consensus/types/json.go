// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"bytes"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/api/jsonutil"
)

// The JSON shapes of the containers, as docs/contract.md section 8 and
// api/openapi/consensus.yaml define them. Each fields method lists a
// container's keys with views of its fields; the same list decodes and
// encodes, so the two directions cannot drift. JSON key order is free on
// input; SSZ order is the declaration order in containers.go.

// object adapts a field list to jsonutil.Value.
type object []jsonutil.Field

func (o object) UnmarshalJSON(b []byte) error { return jsonutil.DecodeObject(b, o...) }
func (o object) MarshalJSON() ([]byte, error) { return jsonutil.EncodeObject(o...) }

func u64(v *uint64) *jsonutil.Uint64String { return (*jsonutil.Uint64String)(v) }

func (h *BeaconBlockHeader) fields() []jsonutil.Field {
	return []jsonutil.Field{
		{Name: "slot", Value: u64(&h.Slot)},
		{Name: "proposer_index", Value: u64(&h.ProposerIndex)},
		{Name: "parent_root", Value: jsonutil.HexBytesN(h.ParentRoot[:])},
		{Name: "state_root", Value: jsonutil.HexBytesN(h.StateRoot[:])},
		{Name: "body_root", Value: jsonutil.HexBytesN(h.BodyRoot[:])},
	}
}

func (c *Checkpoint) fields() []jsonutil.Field {
	return []jsonutil.Field{
		{Name: "epoch", Value: u64(&c.Epoch)},
		{Name: "root", Value: jsonutil.HexBytesN(c.Root[:])},
	}
}

// fields of AttestationData. The proto field committee_index is `index`.
func (d *AttestationData) fields(*Params) []jsonutil.Field {
	return []jsonutil.Field{
		{Name: "slot", Value: u64(&d.Slot)},
		{Name: "index", Value: u64(&d.Index)},
		{Name: "beacon_block_root", Value: jsonutil.HexBytesN(d.BeaconBlockRoot[:])},
		{Name: "source", Value: object(d.Source.fields())},
		{Name: "target", Value: object(d.Target.fields())},
	}
}

func (a *Attestation) fields() []jsonutil.Field {
	return []jsonutil.Field{
		{Name: "aggregation_bits", Value: (*jsonutil.Bitlist32)(&a.AggregationBits)},
		{Name: "data", Value: object(a.Data.fields(nil))},
		{Name: "signatures", Value: signatureList{&a.Signatures}},
	}
}

func (p *AggregateAttestationAndProof) fields(*Params) []jsonutil.Field {
	return []jsonutil.Field{
		{Name: "aggregator_index", Value: u64(&p.AggregatorIndex)},
		{Name: "aggregate", Value: object(p.Aggregate.fields())},
		{Name: "selection_proof", Value: jsonutil.HexBytesN(p.SelectionProof[:])},
	}
}

func (e *VoluntaryExit) fields(*Params) []jsonutil.Field {
	return []jsonutil.Field{
		{Name: "epoch", Value: u64(&e.Epoch)},
		{Name: "validator_index", Value: u64(&e.ValidatorIndex)},
	}
}

func (s *SyncAggregatorSelectionData) fields(*Params) []jsonutil.Field {
	return []jsonutil.Field{
		{Name: "slot", Value: u64(&s.Slot)},
		{Name: "subcommittee_index", Value: u64(&s.SubcommitteeIndex)},
	}
}

// fields of SyncCommitteeContribution. The proto field block_root is
// `beacon_block_root`. The bitvector length comes from p; p is nil when
// encoding.
func (c *SyncCommitteeContribution) fields(p *Params) []jsonutil.Field {
	var n uint64
	if p != nil {
		n = p.SyncSubcommitteeSize
	}
	return []jsonutil.Field{
		{Name: "slot", Value: u64(&c.Slot)},
		{Name: "beacon_block_root", Value: jsonutil.HexBytesN(c.BeaconBlockRoot[:])},
		{Name: "subcommittee_index", Value: u64(&c.SubcommitteeIndex)},
		{Name: "aggregation_bits", Value: jsonutil.BitvectorN{Bits: &c.AggregationBits, N: n}},
		{Name: "signatures", Value: signatureList{&c.Signatures}},
	}
}

func (p *ContributionAndProof) fields(params *Params) []jsonutil.Field {
	return []jsonutil.Field{
		{Name: "aggregator_index", Value: u64(&p.AggregatorIndex)},
		{Name: "selection_proof", Value: jsonutil.HexBytesN(p.SelectionProof[:])},
		{Name: "contribution", Value: object(p.Contribution.fields(params))},
	}
}

func (r *ValidatorRegistrationV1) fields(*Params) []jsonutil.Field {
	return []jsonutil.Field{
		{Name: "fee_recipient", Value: (*jsonutil.QAddress)(&r.FeeRecipient)},
		{Name: "gas_limit", Value: u64(&r.GasLimit)},
		{Name: "timestamp", Value: u64(&r.Timestamp)},
		{Name: "pubkey", Value: jsonutil.HexBytesN(r.Pubkey[:])},
	}
}

// signatureList is the `signatures` array: per-participant signatures where
// Ethereum has one aggregate. Its length is a request invariant, checked by
// the policy, not here.
type signatureList struct{ list *[]Signature }

// UnmarshalJSON counts the elements first, so the list is allocated once.
func (l signatureList) UnmarshalJSON(b []byte) error {
	n, err := jsonutil.DecodeArray(b, nil)
	if err != nil {
		return err
	}
	sigs := make([]Signature, n)
	if _, err := jsonutil.DecodeArray(b, func(i int, raw []byte) error {
		return jsonutil.HexBytesN(sigs[i][:]).UnmarshalJSON(raw)
	}); err != nil {
		return err
	}
	*l.list = sigs
	return nil
}

// MarshalJSON writes an array, `[]` when the list is empty.
func (l signatureList) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.Grow(2 + len(*l.list)*(2*SignatureLength+5))
	buf.WriteByte('[')
	for i := range *l.list {
		if i > 0 {
			buf.WriteByte(',')
		}
		v, _ := jsonutil.HexBytesN((*l.list)[i][:]).MarshalJSON()
		buf.Write(v)
	}
	buf.WriteByte(']')
	return buf.Bytes(), nil
}

// zondVersion is BLOCK_V2's `version`, which must be "ZOND": QRL has a
// single fork.
type zondVersion struct{}

const blockVersion = "ZOND"

func (zondVersion) UnmarshalJSON(b []byte) error {
	var s jsonutil.String
	if err := s.UnmarshalJSON(b); err != nil {
		return err
	}
	if s != blockVersion {
		return apierr.New(apierr.BadField, `version must be "ZOND"`)
	}
	return nil
}

func (zondVersion) MarshalJSON() ([]byte, error) { return []byte(`"` + blockVersion + `"`), nil }
