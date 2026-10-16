// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/theQRL/qrysm/consensus-types/primitives"
	qrysmpb "github.com/theQRL/qrysm/proto/qrysm/v1alpha1"
)

// signCase is one curated golden sign request.
type signCase struct {
	name string
	key  int
	o    *object
	// block holds the full and blinded block a BLOCK_V2 header comes from.
	block obj
}

const maxU64 = math.MaxUint64

// sigFill is a 4,627-byte filler for signatures inside aggregates.
func sigFill(label string) []byte { return fill("sig:"+label, 4627) }

func sigFills(label string, n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = sigFill(fmt.Sprintf("%s:%d", label, i))
	}
	return out
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		panic(err)
	}
	return b
}

func checkpoint(epoch uint64, root []byte) *qrysmpb.Checkpoint {
	return &qrysmpb.Checkpoint{Epoch: primitives.Epoch(epoch), Root: root}
}

func attData(slot, index uint64, root []byte, src, tgt *qrysmpb.Checkpoint) *qrysmpb.AttestationData {
	return &qrysmpb.AttestationData{
		Slot: primitives.Slot(slot), CommitteeIndex: primitives.CommitteeIndex(index),
		BeaconBlockRoot: root, Source: src, Target: tgt,
	}
}

// typicalData is the attestation data of the contract's worked examples.
func typicalData() *qrysmpb.AttestationData {
	return attData(61, 0, mustHex(specBlockRoot),
		checkpoint(8, mustHex("55ee66ff778899001122334455667788990011aabbccddeeff00112233445555")),
		checkpoint(10, mustHex("66ff778899001122334455667788990011aabbccddeeff0011223344556666ff")))
}

func zeroData() *qrysmpb.AttestationData {
	z := make([]byte, 32)
	return attData(0, 0, z, checkpoint(0, z), checkpoint(0, z))
}

func maxData() *qrysmpb.AttestationData {
	f := fill32("max")
	return attData(maxU64, maxU64, f, checkpoint(maxU64, f), checkpoint(maxU64, f))
}

// Values of the spec examples in api/openapi/consensus.yaml, which are the
// spec_example cases of the minimal preset.
const (
	specBlockRoot    = "44dd55ee66ff778899001122334455667788990011aabbccddeeff0011223344"
	specFeeRecipient = "2b3f5c7d9e1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4"
)

// bitlist returns a Bitlist[32] of n bits with the given bits set.
func bitlist(n int, set ...int) []byte {
	b := make([]byte, n/8+1)
	for _, i := range set {
		b[i/8] |= 1 << (i % 8)
	}
	b[n/8] |= 1 << (n % 8)
	return b
}

func aggregate(label string, bits []byte, d *qrysmpb.AttestationData, aggregator uint64) *object {
	return aggAndProofObject(&qrysmpb.AggregateAttestationAndProof{
		AggregatorIndex: primitives.ValidatorIndex(aggregator),
		Aggregate: &qrysmpb.Attestation{
			AggregationBits: bits,
			Data:            d,
			Signatures:      sigFills(label, popcount(bits)-1),
		},
		SelectionProof: sigFill(label + ":selection"),
	})
}

// bitvector returns n/8 bytes with the given bits set.
func bitvector(n int, set ...int) []byte {
	b := make([]byte, n/8)
	for _, i := range set {
		b[i/8] |= 1 << (i % 8)
	}
	return b
}

func contribution(label string, bits []byte, slot, aggregator uint64, root []byte) *object {
	return contributionObject(aggregator, &qrysmpb.SyncCommitteeContribution{
		Slot: primitives.Slot(slot), BlockRoot: root, SubcommitteeIndex: 0,
		Signatures: sigFills(label, popcount(bits)),
	}, bits, sigFill(label+":selection"))
}

func registration(fee []byte, gas, ts uint64, pub []byte) *object {
	return registrationObject(&qrysmpb.ValidatorRegistrationV1{FeeRecipient: fee, GasLimit: gas, Timestamp: ts, Pubkey: pub})
}

func header(slot, proposer uint64, parent, state, body []byte) *object {
	return blockObject(&qrysmpb.BeaconBlockHeader{
		Slot: primitives.Slot(slot), ProposerIndex: primitives.ValidatorIndex(proposer),
		ParentRoot: parent, StateRoot: state, BodyRoot: body,
	})
}

func seq(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

// curatedCases returns the curated cases of type t on chain c: zero and
// maximum values, edge sizes and the spec examples.
func (g *generator) curatedCases(c *chain, t string) ([]signCase, error) {
	z := make([]byte, 32)
	ff := fill32("max")
	minimal := c.preset == "minimal"
	n := int(c.subcommitteeBits)
	spe := uint64(c.cfg.SlotsPerEpoch)
	var cs []signCase
	add := func(name string, key int, o *object) { cs = append(cs, signCase{name: name, key: key, o: o}) }

	switch t {
	case tBlock:
		add("typical", 0, header(62, 17, mustHex("11aa22bb33cc44dd55ee66ff778899001122334455667788990011aabbccddee"),
			mustHex("22bb33cc44dd55ee66ff778899001122334455667788990011aabbccddeeff00"),
			mustHex("33cc44dd55ee66ff778899001122334455667788990011aabbccddeeff001122")))
		add("zero", 1, header(0, 0, z, z, z))
		add("max", 2, header(maxU64, maxU64, ff, ff, ff))
		add("epoch_boundary_last", 3, header(spe-1, 5, fill32("b1"), fill32("b2"), fill32("b3")))
		add("epoch_boundary_first", 3, header(spe, 5, fill32("b1"), fill32("b2"), fill32("b3")))
		if !minimal {
			rb, err := g.realBlockCase()
			if err != nil {
				return nil, err
			}
			cs = append(cs, rb)
		}
	case tAttestation:
		add("typical", 0, attestationObject(typicalData()))
		add("zero", 1, attestationObject(zeroData()))
		add("max", 2, attestationObject(maxData()))
		add("source_equals_target", 3, attestationObject(attData(spe*4, 3, fill32("a1"),
			checkpoint(4, fill32("a2")), checkpoint(4, fill32("a2")))))
	case tAggSlot:
		add("typical", 0, aggSlotObject(61))
		add("zero", 1, aggSlotObject(0))
		add("max", 2, aggSlotObject(maxU64))
		add("epoch_boundary_last", 3, aggSlotObject(spe-1))
		add("epoch_boundary_first", 3, aggSlotObject(spe))
	case tAggAndProof:
		// Bitlists of every length 0-32 on the minimal preset with no
		// participant, so the delimiter alone moves; one set bit, the
		// highest, at the byte edges on both presets.
		if minimal {
			for l := range 33 {
				add(fmt.Sprintf("bitlist_len_%d_empty", l), l%4, aggregate(fmt.Sprintf("agg:%s:len%d", c.preset, l), bitlist(l), typicalData(), 17))
			}
		}
		for _, l := range []int{1, 8, 9, 32} {
			add(fmt.Sprintf("bitlist_len_%d_high_bit", l), l%4, aggregate(fmt.Sprintf("agg:%s:high%d", c.preset, l), bitlist(l, l-1), typicalData(), 17))
		}
		if minimal {
			add("signatures_31", 1, aggregate("agg:"+c.preset+":31", bitlist(32, seq(31)...), typicalData(), 17))
		}
		add("signatures_32", 2, aggregate("agg:"+c.preset+":32", bitlist(32, seq(32)...), typicalData(), 17))
		add("zero", 3, aggregate("agg:"+c.preset+":zero", bitlist(1, 0), zeroData(), 0))
		add("max", 0, aggregate("agg:"+c.preset+":max", bitlist(1, 0), maxData(), maxU64))
	case tExit:
		add("typical", 0, exitObject(&qrysmpb.VoluntaryExit{Epoch: 10, ValidatorIndex: 42}))
		add("epoch_zero", 1, exitObject(&qrysmpb.VoluntaryExit{Epoch: 0, ValidatorIndex: 0}))
		add("epoch_max", 2, exitObject(&qrysmpb.VoluntaryExit{Epoch: maxU64, ValidatorIndex: maxU64}))
		add("epoch_huge", 3, exitObject(&qrysmpb.VoluntaryExit{Epoch: 1 << 40, ValidatorIndex: 255}))
	case tSyncMessage:
		add("typical", 0, syncMessageObject(mustHex(specBlockRoot), 61))
		add("zero", 1, syncMessageObject(z, 0))
		add("max", 2, syncMessageObject(ff, maxU64))
	case tSyncSelect:
		add("typical", 0, syncSelectObject(&qrysmpb.SyncAggregatorSelectionData{Slot: 61}))
		add("zero", 1, syncSelectObject(&qrysmpb.SyncAggregatorSelectionData{}))
		add("max_slot", 2, syncSelectObject(&qrysmpb.SyncAggregatorSelectionData{Slot: maxU64}))
		add("epoch_boundary_first", 3, syncSelectObject(&qrysmpb.SyncAggregatorSelectionData{Slot: primitives.Slot(spe)}))
	case tContribution:
		label := "contrib:" + c.preset
		add("single_bit_first", 0, contribution(label+":first", bitvector(n, 0), 61, 7, fill32("c1")))
		add("single_bit_last", 1, contribution(label+":last", bitvector(n, n-1), 61, 7, fill32("c1")))
		add("signatures_16", 2, contribution(label+":16", bitvector(n, seq(16)...), 61, 7, fill32("c1")))
		if !minimal {
			add("signatures_128", 3, contribution(label+":128", bitvector(n, seq(128)...), 61, 7, fill32("c1")))
		}
		add("zero", 0, contribution(label+":zero", bitvector(n, 0), 0, 0, z))
		add("max", 1, contribution(label+":max", bitvector(n, n-1), maxU64, maxU64, ff))
	case tRegistration:
		add("typical", 0, registration(mustHex(specFeeRecipient), 30000000, genesisTime, g.keys[0].pub))
		add("zero", 1, registration(make([]byte, 64), 0, 0, g.keys[1].pub))
		add("max", 2, registration(fill("fee:max", 64), maxU64, maxU64, g.keys[2].pub))
	default:
		return nil, fmt.Errorf("unknown type %s", t)
	}
	if minimal {
		ex, err := g.specExample(t)
		if err != nil {
			return nil, err
		}
		cs = append(cs, signCase{name: "spec_example", key: 0, o: ex})
	}
	return cs, nil
}

// specSignature is the deterministic signature of the AGGREGATION_SLOT spec
// example. The other spec examples use it as the bytes of their selection
// proofs and participant signatures, as the hand-written examples used one
// repeated pattern.
func (g *generator) specSignature() ([]byte, error) {
	if g.specSig != nil {
		return g.specSig, nil
	}
	_, _, root, err := g.minimal.roots(aggSlotObject(61))
	if err != nil {
		return nil, err
	}
	sig, err := g.keys[0].signDeterministic(root)
	if err != nil {
		return nil, err
	}
	g.specSig = sig
	return sig, nil
}

// specExample builds the spec example of type t: the values of the
// examples in api/openapi/consensus.yaml, all for interop key 0 on the
// end-to-end network.
func (g *generator) specExample(t string) (*object, error) {
	sig, err := g.specSignature()
	if err != nil {
		return nil, err
	}
	switch t {
	case tBlock:
		return header(62, 17, mustHex("11aa22bb33cc44dd55ee66ff778899001122334455667788990011aabbccddee"),
			mustHex("22bb33cc44dd55ee66ff778899001122334455667788990011aabbccddeeff00"),
			mustHex("33cc44dd55ee66ff778899001122334455667788990011aabbccddeeff001122")), nil
	case tAttestation:
		return attestationObject(typicalData()), nil
	case tAggSlot:
		return aggSlotObject(61), nil
	case tAggAndProof:
		return aggAndProofObject(&qrysmpb.AggregateAttestationAndProof{
			AggregatorIndex: 17,
			Aggregate: &qrysmpb.Attestation{
				AggregationBits: []byte{0x1f},
				Data:            typicalData(),
				Signatures:      [][]byte{sig, sig, sig, sig},
			},
			SelectionProof: sig,
		}), nil
	case tExit:
		return exitObject(&qrysmpb.VoluntaryExit{Epoch: 10, ValidatorIndex: 42}), nil
	case tSyncMessage:
		return syncMessageObject(mustHex(specBlockRoot), 61), nil
	case tSyncSelect:
		return syncSelectObject(&qrysmpb.SyncAggregatorSelectionData{Slot: 61, SubcommitteeIndex: 0}), nil
	case tContribution:
		return contributionObject(7, &qrysmpb.SyncCommitteeContribution{
			Slot: 61, BlockRoot: mustHex(specBlockRoot), SubcommitteeIndex: 0,
			Signatures: [][]byte{sig, sig},
		}, []byte{0x05, 0x00}, sig), nil
	case tRegistration:
		return registration(mustHex(specFeeRecipient), 30000000, genesisTime, g.keys[0].pub), nil
	}
	return nil, fmt.Errorf("unknown type %s", t)
}

// signRecord turns a case into its fixture record.
func (g *generator) signRecord(c *chain, sc signCase) (obj, error) {
	o := sc.o
	objectRoot, domain, signingRoot, err := c.roots(o)
	if err != nil {
		return nil, fmt.Errorf("%s/%s/%s: %w", c.preset, o.typ, sc.name, err)
	}
	k := &g.keys[sc.key]
	r := obj{}.
		set("name", sc.name).
		set("type", o.typ).
		set("preset", c.preset).
		set("network", c.recordNetwork()).
		set("key_index", sc.key).
		set("pubkey", hx(k.pub)).
		set("object_ssz_hex", hx(o.ssz)).
		set("object_root", hx(objectRoot[:])).
		set("domain", hx(domain[:])).
		set("signing_root", hx(signingRoot[:])).
		set("request_json", c.requestJSON(o, signingRoot))
	if deterministicTypes[o.typ] {
		sig, err := k.signDeterministic(signingRoot)
		if err != nil {
			return nil, err
		}
		r = r.set("deterministic_signature", hx(sig))
	}
	if sc.block != nil {
		r = r.set("block", sc.block)
	}
	if o.padded {
		r = r.set("authoritative", false).set("notes", paddedNote)
	}
	return r.set("expect", obj{}.set("status", 200)), nil
}

// paddedNote explains the minimal-preset contribution fallback.
const paddedNote = "Computed with qrysm's mainnet SSZ code over the 2-byte minimal bitvector padded to 16 bytes " +
	"(qrysm has no minimal-preset SSZ code outside Bazel's --config=minimal). Both bitvectors fit one chunk, so the " +
	"roots are equal, but this record is not authoritative. object_ssz_hex is the padded mainnet encoding."

// genSigning writes signing/<preset>/<type>.json.
func genSigning(g *generator) error {
	for _, c := range g.chains() {
		for _, t := range artifactTypes {
			cases, err := g.curatedCases(c, t)
			if err != nil {
				return err
			}
			recs := make([]obj, 0, len(cases))
			for _, sc := range cases {
				r, err := g.signRecord(c, sc)
				if err != nil {
					return err
				}
				recs = append(recs, r)
			}
			if err := writeJSON(g.vectors, "signing/"+c.preset+"/"+strings.ToLower(t)+".json", obj{}.
				set("description", g.description("Golden "+t+" sign requests on the "+c.def.name+" network ("+
					c.preset+" preset). Every root was computed by qrysm's own code; request_json is the canonical "+
					"body of docs/contract.md section 8.")).
				set("generator", g.info).
				set("type", t).
				set("preset", c.preset).
				set("cases", recs)); err != nil {
				return err
			}
		}
	}
	return nil
}
