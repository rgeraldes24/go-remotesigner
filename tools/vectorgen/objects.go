// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	fssz "github.com/prysmaticlabs/fastssz"
	"github.com/theQRL/qrysm/beacon-chain/core/signing"
	"github.com/theQRL/qrysm/config/params"
	"github.com/theQRL/qrysm/consensus-types/primitives"
	qrysmpb "github.com/theQRL/qrysm/proto/qrysm/v1alpha1"
	"github.com/theQRL/qrysm/time/slots"
)

// The nine artifact types of the contract, in contract order.
const (
	tBlock        = "BLOCK_V2"
	tAttestation  = "ATTESTATION"
	tAggSlot      = "AGGREGATION_SLOT"
	tAggAndProof  = "AGGREGATE_AND_PROOF"
	tExit         = "VOLUNTARY_EXIT"
	tSyncMessage  = "SYNC_COMMITTEE_MESSAGE"
	tSyncSelect   = "SYNC_COMMITTEE_SELECTION_PROOF"
	tContribution = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
	tRegistration = "VALIDATOR_REGISTRATION"
)

var artifactTypes = []string{tBlock, tAttestation, tAggSlot, tAggAndProof, tExit, tSyncMessage, tSyncSelect,
	tContribution, tRegistration}

// payloadKeys are the request keys of the payloads.
var payloadKeys = map[string]string{
	tBlock:        "beacon_block",
	tAttestation:  "attestation",
	tAggSlot:      "aggregation_slot",
	tAggAndProof:  "aggregate_and_proof",
	tExit:         "voluntary_exit",
	tSyncMessage:  "sync_committee_message",
	tSyncSelect:   "sync_aggregator_selection_data",
	tContribution: "contribution_and_proof",
	tRegistration: "validator_registration",
}

// deterministicTypes are signed with SignDeterministic by qrysm's local
// keymanager, so their fixtures carry the signature itself.
var deterministicTypes = map[string]bool{tAggSlot: true, tSyncSelect: true}

// object is a signed object as qrysm's validator client holds it, with the
// slot or epoch its domain is selected by and its request payload.
type object struct {
	typ  string
	root fssz.HashRoot
	ssz  []byte
	// slot is set for types whose fork version comes from epoch(slot), epoch
	// for types that give the epoch; registrations use neither.
	slot, epoch *uint64
	payload     obj
	// padded is set when the root was computed with qrysm's mainnet SSZ code
	// over a minimal-preset bitvector padded to 16 bytes (the padding fallback).
	padded bool
}

// domainType returns the domain type of t.
func domainType(t string) [4]byte {
	c := params.BeaconConfig()
	switch t {
	case tBlock:
		return c.DomainBeaconProposer
	case tAttestation:
		return c.DomainBeaconAttester
	case tAggSlot:
		return c.DomainSelectionProof
	case tAggAndProof:
		return c.DomainAggregateAndProof
	case tExit:
		return c.DomainVoluntaryExit
	case tSyncMessage:
		return c.DomainSyncCommittee
	case tSyncSelect:
		return c.DomainSyncCommitteeSelectionProof
	case tContribution:
		return c.DomainContributionAndProof
	case tRegistration:
		return c.DomainApplicationBuilder
	}
	panic("unknown type " + t)
}

// roots computes the object root, domain and signing root of o on chain c
// the way qrysm's validator client does: get_domain over the single fork for
// the type's epoch, compute_domain with the genesis version and a zero GVR
// for registrations, then ComputeSigningRoot.
func (c *chain) roots(o *object) (objectRoot, domain, signingRoot [32]byte, err error) {
	type result struct{ obj, dom, sig [32]byte }
	r, err := withConfig(c.cfg, func() (result, error) {
		var res result
		var d []byte
		var err error
		switch {
		case o.typ == tRegistration:
			d, err = signing.ComputeDomain(domainType(o.typ), nil, nil)
		case o.slot != nil:
			d, err = signing.Domain(c.fork(), slots.ToEpoch(primitives.Slot(*o.slot)), domainType(o.typ), c.gvr[:])
		case o.epoch != nil:
			d, err = signing.Domain(c.fork(), primitives.Epoch(*o.epoch), domainType(o.typ), c.gvr[:])
		default:
			err = fmt.Errorf("%s object has no slot or epoch", o.typ)
		}
		if err != nil {
			return res, err
		}
		if res.obj, err = o.root.HashTreeRoot(); err != nil {
			return res, err
		}
		if res.sig, err = signing.ComputeSigningRoot(o.root, d); err != nil {
			return res, err
		}
		copy(res.dom[:], d)
		return res, nil
	})
	return r.obj, r.dom, r.sig, err
}

func ptr(v uint64) *uint64 { return &v }

// marshal returns the SSZ encoding of m or panics; every object here is
// well formed by construction.
func marshal(m interface{ MarshalSSZ() ([]byte, error) }) []byte {
	b, err := m.MarshalSSZ()
	if err != nil {
		panic(err)
	}
	return b
}

// The constructors below build each type's object from qrysm's proto types
// and map it to its request payload as docs/contract.md section 19 says the
// qrysm client does.

func checkpointJSON(c *qrysmpb.Checkpoint) obj {
	return obj{}.set("epoch", u64s(uint64(c.Epoch))).set("root", hx(c.Root))
}

func attestationDataJSON(d *qrysmpb.AttestationData) obj {
	return obj{}.
		set("slot", u64s(uint64(d.Slot))).
		set("index", u64s(uint64(d.CommitteeIndex))).
		set("beacon_block_root", hx(d.BeaconBlockRoot)).
		set("source", checkpointJSON(d.Source)).
		set("target", checkpointJSON(d.Target))
}

func sigsJSON(sigs [][]byte) []string {
	out := make([]string, len(sigs))
	for i, s := range sigs {
		out[i] = hx(s)
	}
	return out
}

func blockObject(h *qrysmpb.BeaconBlockHeader) *object {
	return &object{
		typ: tBlock, root: h, ssz: marshal(h), slot: ptr(uint64(h.Slot)),
		payload: obj{}.set("version", "ZOND").set("block_header", obj{}.
			set("slot", u64s(uint64(h.Slot))).
			set("proposer_index", u64s(uint64(h.ProposerIndex))).
			set("parent_root", hx(h.ParentRoot)).
			set("state_root", hx(h.StateRoot)).
			set("body_root", hx(h.BodyRoot))),
	}
}

func attestationObject(d *qrysmpb.AttestationData) *object {
	return &object{
		typ: tAttestation, root: d, ssz: marshal(d), epoch: ptr(uint64(d.Target.Epoch)),
		payload: attestationDataJSON(d),
	}
}

func aggSlotObject(slot uint64) *object {
	s := primitives.SSZUint64(slot)
	return &object{
		typ: tAggSlot, root: &s, ssz: marshal(&s), slot: ptr(slot),
		payload: obj{}.set("slot", u64s(slot)),
	}
}

func aggAndProofObject(p *qrysmpb.AggregateAttestationAndProof) *object {
	return &object{
		typ: tAggAndProof, root: p, ssz: marshal(p), slot: ptr(uint64(p.Aggregate.Data.Slot)),
		payload: obj{}.
			set("aggregator_index", u64s(uint64(p.AggregatorIndex))).
			set("aggregate", obj{}.
				set("aggregation_bits", hx(p.Aggregate.AggregationBits)).
				set("data", attestationDataJSON(p.Aggregate.Data)).
				set("signatures", sigsJSON(p.Aggregate.Signatures))).
			set("selection_proof", hx(p.SelectionProof)),
	}
}

func exitObject(e *qrysmpb.VoluntaryExit) *object {
	return &object{
		typ: tExit, root: e, ssz: marshal(e), epoch: ptr(uint64(e.Epoch)),
		payload: obj{}.set("epoch", u64s(uint64(e.Epoch))).set("validator_index", u64s(uint64(e.ValidatorIndex))),
	}
}

// syncMessageObject is the block root the client signs; slot is the signing
// slot it sends alongside (contract section 19).
func syncMessageObject(root []byte, slot uint64) *object {
	b := primitives.SSZBytes(root)
	return &object{
		typ: tSyncMessage, root: &b, ssz: append([]byte(nil), root...), slot: ptr(slot),
		payload: obj{}.set("beacon_block_root", hx(root)).set("slot", u64s(slot)),
	}
}

func syncSelectObject(d *qrysmpb.SyncAggregatorSelectionData) *object {
	return &object{
		typ: tSyncSelect, root: d, ssz: marshal(d), slot: ptr(uint64(d.Slot)),
		payload: obj{}.set("slot", u64s(uint64(d.Slot))).set("subcommittee_index", u64s(d.SubcommitteeIndex)),
	}
}

// contributionObject builds the object for bits of the chain's subcommittee
// size. qrysm's generated SSZ code is the mainnet one, with a 16-byte
// bitvector; minimal-preset bits are hashed padded to 16 bytes, which gives
// the same root because both fit one chunk, and the object is
// flagged as computed by that fallback.
func contributionObject(aggregator uint64, c *qrysmpb.SyncCommitteeContribution, bits []byte, selectionProof []byte) *object {
	padded := make([]byte, 16)
	copy(padded, bits)
	cc := &qrysmpb.SyncCommitteeContribution{
		Slot:              c.Slot,
		BlockRoot:         c.BlockRoot,
		SubcommitteeIndex: c.SubcommitteeIndex,
		AggregationBits:   padded,
		Signatures:        c.Signatures,
	}
	p := &qrysmpb.ContributionAndProof{
		AggregatorIndex: primitives.ValidatorIndex(aggregator),
		Contribution:    cc,
		SelectionProof:  selectionProof,
	}
	return &object{
		typ: tContribution, root: p, ssz: marshal(p), slot: ptr(uint64(c.Slot)), padded: len(bits) != 16,
		payload: obj{}.
			set("aggregator_index", u64s(aggregator)).
			set("selection_proof", hx(selectionProof)).
			set("contribution", obj{}.
				set("slot", u64s(uint64(c.Slot))).
				set("beacon_block_root", hx(c.BlockRoot)).
				set("subcommittee_index", u64s(c.SubcommitteeIndex)).
				set("aggregation_bits", hx(bits)).
				set("signatures", sigsJSON(c.Signatures))),
	}
}

func registrationObject(r *qrysmpb.ValidatorRegistrationV1) *object {
	return &object{
		typ: tRegistration, root: r, ssz: marshal(r),
		payload: obj{}.
			set("fee_recipient", qaddr(r.FeeRecipient)).
			set("gas_limit", u64s(r.GasLimit)).
			set("timestamp", u64s(r.Timestamp)).
			set("pubkey", hx(r.Pubkey)),
	}
}

// requestJSON is the canonical request body: type, fork_info (absent for
// registrations), signing_root and the payload.
func (c *chain) requestJSON(o *object, signingRoot [32]byte) obj {
	r := obj{}.set("type", o.typ)
	if o.typ != tRegistration {
		r = r.set("fork_info", c.forkInfo())
	}
	return r.set("signing_root", hx(signingRoot[:])).set(payloadKeys[o.typ], o.payload)
}
