// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"

	"github.com/theQRL/qrysm/consensus-types/primitives"
	qrysmpb "github.com/theQRL/qrysm/proto/qrysm/v1alpha1"
)

// seedsPerPreset is the number of random containers per type and preset:
// about 1,000 per container across the two presets (DESIGN §7.2).
const seedsPerPreset = 512

// randomObject expands seed into an object of type t, field by field in SSZ
// declaration order, as testdata/vectors/README.md ("Seed expansion")
// specifies. subcommitteeBits is the contribution bitvector length.
func randomObject(t string, seed uint64, subcommitteeBits int) *object {
	s := newStream(seed)
	data := func() *qrysmpb.AttestationData {
		slot, index, root := s.u64(), s.u64(), s.bytes(32)
		src := checkpoint(s.u64(), s.bytes(32))
		tgt := checkpoint(s.u64(), s.bytes(32))
		return attData(slot, index, root, src, tgt)
	}
	sigs := func(n int) [][]byte {
		out := make([][]byte, n)
		for i := range out {
			out[i] = s.bytes(4627)
		}
		return out
	}
	switch t {
	case tBlock:
		slot, proposer := s.u64(), s.u64()
		return header(slot, proposer, s.bytes(32), s.bytes(32), s.bytes(32))
	case tAttestation:
		return attestationObject(data())
	case tAggSlot:
		return aggSlotObject(s.u64())
	case tAggAndProof:
		aggregator := s.u64()
		bits := s.bitlist32()
		d := data()
		atts := sigs(popcount(bits) - 1)
		return aggAndProofObject(&qrysmpb.AggregateAttestationAndProof{
			AggregatorIndex: primitives.ValidatorIndex(aggregator),
			Aggregate:       &qrysmpb.Attestation{AggregationBits: bits, Data: d, Signatures: atts},
			SelectionProof:  s.bytes(4627),
		})
	case tExit:
		epoch, index := s.u64(), s.u64()
		return exitObject(&qrysmpb.VoluntaryExit{Epoch: primitives.Epoch(epoch), ValidatorIndex: primitives.ValidatorIndex(index)})
	case tSyncMessage:
		root := s.bytes(32)
		return syncMessageObject(root, s.u64())
	case tSyncSelect:
		slot, sub := s.u64(), s.u64()
		return syncSelectObject(&qrysmpb.SyncAggregatorSelectionData{Slot: primitives.Slot(slot), SubcommitteeIndex: sub})
	case tContribution:
		aggregator := s.u64()
		slot, root, sub := s.u64(), s.bytes(32), s.u64()
		bits := s.bitvector(subcommitteeBits)
		cs := sigs(popcount(bits))
		return contributionObject(aggregator, &qrysmpb.SyncCommitteeContribution{
			Slot: primitives.Slot(slot), BlockRoot: root, SubcommitteeIndex: sub, Signatures: cs,
		}, bits, s.bytes(4627))
	case tRegistration:
		fee := s.bytes(64)
		gas, ts := s.u64(), s.u64()
		return registration(fee, gas, ts, s.bytes(2592))
	}
	panic("unknown type " + t)
}

// genRoots writes roots/<preset>/<type>.json: the roots of seed-expanded
// random containers.
func genRoots(g *generator) error {
	for _, c := range g.chains() {
		for _, t := range artifactTypes {
			recs := make([]obj, 0, seedsPerPreset)
			padded := false
			for seed := uint64(0); seed < seedsPerPreset; seed++ {
				o := randomObject(t, seed, int(c.subcommitteeBits))
				padded = padded || o.padded
				objectRoot, domain, signingRoot, err := c.roots(o)
				if err != nil {
					return err
				}
				recs = append(recs, obj{}.
					set("seed", seed).
					set("object_root", hx(objectRoot[:])).
					set("domain", hx(domain[:])).
					set("signing_root", hx(signingRoot[:])))
			}
			f := obj{}.
				set("description", g.description("Roots of "+t+" objects expanded from seeds 0-"+u64s(seedsPerPreset-1)+
					" as testdata/vectors/README.md (\"Seed expansion\") specifies, on the "+c.def.name+" network, "+
					"computed by qrysm's own code.")).
				set("generator", g.info).
				set("type", t).
				set("preset", c.preset).
				set("network", c.recordNetwork()).
				set("sync_subcommittee_bits", c.subcommitteeBits)
			if padded {
				f = f.set("authoritative", false).set("notes", paddedNote)
			}
			if err := writeJSON(g.vectors, "roots/"+c.preset+"/"+strings.ToLower(t)+".json", f.set("cases", recs)); err != nil {
				return err
			}
		}
	}
	return nil
}
