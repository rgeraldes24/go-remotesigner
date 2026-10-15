// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package slashingtest

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// The scenarios below are authored from the conditions of EIP-3076 (CC0-1.0), not copied from any test-vector
// repository. In the EIP's terms a signer must refuse:
//
//  1. a block that is slashable against the recorded blocks (same slot, different signing root);
//  2. an attestation that is slashable against the recorded attestations (double or surround vote);
//  3. a block with slot <= the minimum recorded slot, unless it repeats a recorded block;
//  4. an attestation with source epoch < the minimum recorded source epoch;
//  5. an attestation with target epoch <= the minimum recorded target epoch, unless it repeats a recorded one.
//
// A recorded message with an unknown signing root never counts as a repeat. The minima are the stores' low
// watermarks: set by the first signing, by an import, or raised by a watermark repair (which may leave no record at
// the watermark, the case where the literal conditions differ from Web3Signer, deviation X8).

type opKind int

const (
	opBlock opKind = iota
	opAttestation
	opImportBlocks
	opImportAttestations
	opRepairWatermark
	opSetEnabled
	opSetHighWatermark
)

type outcome struct {
	allowed bool
	repeat  bool
	reason  slashing.Reason
	err     error // a rejection the server maps to 400, not a 412 refusal
}

var (
	allowed  = outcome{allowed: true}
	repeated = outcome{allowed: true, repeat: true}
)

func refused(r slashing.Reason) outcome { return outcome{reason: r} }

func rejected(err error) outcome { return outcome{err: err} }

type step struct {
	op             opKind
	key            int
	slot           uint64
	source, target uint64
	root           uint64
	gvr            *slashing.Root
	blocks         []slashing.SignedBlock
	atts           []slashing.SignedAttestation
	low            slashing.LowWatermark
	high           slashing.HighWatermark
	enabled        bool
	want           outcome
}

func block(key int, slot, root uint64, want outcome) step {
	return step{op: opBlock, key: key, slot: slot, root: root, want: want}
}

func blockUnder(gvr slashing.Root, key int, slot, root uint64, want outcome) step {
	s := block(key, slot, root, want)
	s.gvr = &gvr
	return s
}

func att(key int, source, target, root uint64, want outcome) step {
	return step{op: opAttestation, key: key, source: source, target: target, root: root, want: want}
}

func importBlocks(key int, blocks ...slashing.SignedBlock) step {
	return step{op: opImportBlocks, key: key, blocks: blocks}
}

func importAtts(key int, atts ...slashing.SignedAttestation) step {
	return step{op: opImportAttestations, key: key, atts: atts}
}

// repair raises a validator's low watermarks without writing any record, as a watermark repair does.
func repair(key int, low slashing.LowWatermark) step {
	return step{op: opRepairWatermark, key: key, low: low}
}

func setEnabled(key int, enabled bool) step {
	return step{op: opSetEnabled, key: key, enabled: enabled}
}

func setHigh(h slashing.HighWatermark) step { return step{op: opSetHighWatermark, high: h} }

func sb(slot uint64, root *slashing.Root) slashing.SignedBlock {
	return slashing.SignedBlock{Slot: slot, SigningRoot: root}
}

func sa(source, target uint64, root *slashing.Root) slashing.SignedAttestation {
	return slashing.SignedAttestation{SourceEpoch: source, TargetEpoch: target, SigningRoot: root}
}

type scenario struct {
	name  string
	steps []step
}

var otherGVR = slashing.Root{0x01}

var eip3076Scenarios = []scenario{
	// Blocks.
	{"block: first signing sets the minimum slot", []step{
		block(0, 10, 1, allowed),
		block(0, 9, 2, refused(slashing.ReasonBelowWatermark)),
		block(0, 0, 2, refused(slashing.ReasonBelowWatermark)),
	}},
	{"block: identical repeat is allowed", []step{
		block(0, 10, 1, allowed),
		block(0, 10, 1, repeated),
		block(0, 10, 1, repeated),
	}},
	{"block: double proposal", []step{
		block(0, 10, 1, allowed),
		block(0, 10, 2, refused(slashing.ReasonDoubleProposal)),
		block(0, 11, 2, allowed),
		block(0, 11, 1, refused(slashing.ReasonDoubleProposal)),
	}},
	{"block: gaps above the minimum may be filled", []step{
		block(0, 10, 1, allowed),
		block(0, 14, 1, allowed),
		block(0, 12, 1, allowed),
		block(0, 12, 2, refused(slashing.ReasonDoubleProposal)),
	}},
	{"block: slot zero", []step{
		block(0, 0, 1, allowed),
		block(0, 0, 1, repeated),
		block(0, 0, 2, refused(slashing.ReasonDoubleProposal)),
		block(0, 1, 2, allowed),
	}},
	{"block: validators are independent", []step{
		block(0, 10, 1, allowed),
		block(1, 10, 2, allowed),
		block(1, 10, 1, refused(slashing.ReasonDoubleProposal)),
		block(0, 10, 1, repeated),
		block(2, 5, 3, allowed),
	}},
	{"block: imported record with unknown root conflicts", []step{
		importBlocks(0, sb(10, nil), sb(12, RootPtr(5))),
		block(0, 10, 5, refused(slashing.ReasonDoubleProposal)),
		block(0, 12, 5, repeated),
		block(0, 12, 6, refused(slashing.ReasonDoubleProposal)),
		block(0, 11, 1, allowed),
		block(0, 9, 1, refused(slashing.ReasonBelowWatermark)),
	}},
	{"block: repeat at the imported minimum", []step{
		importBlocks(0, sb(10, RootPtr(1)), sb(15, RootPtr(2))),
		block(0, 10, 1, repeated),
		block(0, 10, 2, refused(slashing.ReasonDoubleProposal)),
		block(0, 9, 1, refused(slashing.ReasonBelowWatermark)),
		block(0, 15, 2, repeated),
		block(0, 16, 3, allowed),
	}},
	{"block: watermark without a record refuses its own slot (X8)", []step{
		repair(0, slashing.LowWatermark{Slot: U64(20)}),
		block(0, 20, 1, refused(slashing.ReasonBelowWatermark)),
		block(0, 19, 1, refused(slashing.ReasonBelowWatermark)),
		block(0, 21, 1, allowed),
		block(0, 20, 1, refused(slashing.ReasonBelowWatermark)),
	}},
	{"block: a later interchange raises the minimum", []step{
		importBlocks(0, sb(10, RootPtr(1))),
		importBlocks(0, sb(20, RootPtr(2))),
		block(0, 15, 3, refused(slashing.ReasonBelowWatermark)),
		block(0, 10, 1, refused(slashing.ReasonBelowWatermark)),
		block(0, 20, 2, repeated),
		block(0, 21, 3, allowed),
	}},
	{"block: an earlier interchange does not lower the minimum", []step{
		importBlocks(0, sb(20, RootPtr(2))),
		importBlocks(0, sb(10, RootPtr(1))),
		block(0, 10, 1, refused(slashing.ReasonBelowWatermark)),
		block(0, 20, 2, repeated),
	}},
	{"block: high watermark", []step{
		block(0, 10, 1, allowed),
		setHigh(slashing.HighWatermark{Epoch: U64(100), Slot: U64(50)}),
		block(0, 50, 1, refused(slashing.ReasonAboveHighWatermark)),
		block(0, 51, 1, refused(slashing.ReasonAboveHighWatermark)),
		block(0, 49, 1, allowed),
		setHigh(slashing.HighWatermark{}),
		block(0, 51, 1, allowed),
	}},
	{"block: disabled validator", []step{
		setEnabled(0, false),
		block(0, 10, 1, refused(slashing.ReasonValidatorDisabled)),
		block(1, 10, 1, allowed),
		setEnabled(0, true),
		block(0, 10, 1, allowed),
	}},
	{"block: genesis validators root is pinned by the first request", []step{
		block(0, 10, 1, allowed),
		blockUnder(otherGVR, 0, 11, 1, rejected(slashing.ErrGenesisValidatorsRootMismatch)),
		blockUnder(otherGVR, 1, 11, 1, rejected(slashing.ErrGenesisValidatorsRootMismatch)),
		block(0, 11, 1, allowed),
	}},

	// Attestations.
	{"attestation: first signing sets the minimum epochs", []step{
		att(0, 5, 6, 1, allowed),
		att(0, 4, 7, 1, refused(slashing.ReasonBelowWatermark)),
		att(0, 5, 5, 1, refused(slashing.ReasonBelowWatermark)),
		att(0, 5, 7, 1, allowed),
	}},
	{"attestation: identical repeat is allowed", []step{
		att(0, 5, 6, 1, allowed),
		att(0, 5, 6, 1, repeated),
	}},
	{"attestation: double vote", []step{
		att(0, 5, 6, 1, allowed),
		att(0, 5, 6, 2, refused(slashing.ReasonDoubleVote)),
		att(0, 6, 6, 2, refused(slashing.ReasonDoubleVote)),
	}},
	{"attestation: epoch zero", []step{
		att(0, 0, 0, 1, allowed),
		att(0, 0, 0, 1, repeated),
		att(0, 0, 0, 2, refused(slashing.ReasonDoubleVote)),
		att(0, 0, 1, 2, allowed),
	}},
	{"attestation: a recorded vote surrounds the request", []step{
		att(0, 2, 3, 1, allowed),
		att(0, 3, 10, 1, allowed),
		att(0, 4, 7, 1, refused(slashing.ReasonSurroundingVote)),
		att(0, 4, 9, 1, refused(slashing.ReasonSurroundingVote)),
		att(0, 4, 11, 1, allowed),
	}},
	{"attestation: the request surrounds a recorded vote", []step{
		att(0, 2, 3, 1, allowed),
		att(0, 4, 5, 1, allowed),
		att(0, 3, 6, 1, refused(slashing.ReasonSurroundedVote)),
		att(0, 2, 9, 1, refused(slashing.ReasonSurroundedVote)),
		att(0, 4, 6, 1, allowed),
	}},
	{"attestation: surround needs strict inequality on both epochs", []step{
		att(0, 2, 3, 1, allowed),
		att(0, 3, 10, 1, allowed),
		att(0, 3, 9, 1, allowed),
		att(0, 3, 11, 1, allowed),
		att(0, 4, 10, 2, refused(slashing.ReasonDoubleVote)),
		att(0, 2, 12, 1, refused(slashing.ReasonSurroundedVote)),
	}},
	{"attestation: source after target", []step{
		att(0, 6, 5, 1, rejected(slashing.ErrSourceAfterTarget)),
		att(0, 5, 6, 1, allowed),
	}},
	{"attestation: validators are independent", []step{
		att(0, 2, 3, 1, allowed),
		att(1, 1, 4, 2, allowed),
		att(0, 1, 4, 2, refused(slashing.ReasonBelowWatermark)),
		att(1, 2, 3, 1, refused(slashing.ReasonBelowWatermark)),
		att(0, 3, 4, 2, allowed),
	}},
	{"attestation: imported record with unknown root conflicts", []step{
		importAtts(0, sa(5, 10, nil)),
		att(0, 5, 10, 1, refused(slashing.ReasonDoubleVote)),
		att(0, 6, 10, 1, refused(slashing.ReasonDoubleVote)),
		att(0, 6, 11, 1, allowed),
	}},
	{"attestation: imported minima", []step{
		importAtts(0, sa(5, 10, RootPtr(1)), sa(6, 12, RootPtr(2))),
		att(0, 4, 13, 1, refused(slashing.ReasonBelowWatermark)),
		att(0, 5, 9, 1, refused(slashing.ReasonBelowWatermark)),
		att(0, 5, 10, 1, repeated),
		att(0, 5, 10, 2, refused(slashing.ReasonDoubleVote)),
		att(0, 7, 11, 1, refused(slashing.ReasonSurroundingVote)),
		att(0, 6, 13, 1, allowed),
	}},
	{"attestation: a repeat surrounded by imported history is refused", []step{
		importAtts(0, sa(3, 4, RootPtr(1)), sa(2, 5, RootPtr(2))),
		att(0, 3, 4, 1, refused(slashing.ReasonSurroundingVote)),
		att(0, 2, 5, 2, refused(slashing.ReasonSurroundedVote)),
	}},
	{"attestation: watermark without a record refuses its own target (X8)", []step{
		repair(0, slashing.LowWatermark{SourceEpoch: U64(5), TargetEpoch: U64(10)}),
		att(0, 5, 10, 1, refused(slashing.ReasonBelowWatermark)),
		att(0, 4, 11, 1, refused(slashing.ReasonBelowWatermark)),
		att(0, 6, 9, 1, refused(slashing.ReasonBelowWatermark)),
		att(0, 5, 11, 1, allowed),
	}},
	{"attestation: high watermark", []step{
		att(0, 1, 2, 1, allowed),
		setHigh(slashing.HighWatermark{Epoch: U64(10), Slot: U64(1000)}),
		att(0, 9, 10, 1, refused(slashing.ReasonAboveHighWatermark)),
		att(0, 10, 10, 1, refused(slashing.ReasonAboveHighWatermark)),
		att(0, 8, 9, 1, allowed),
	}},
	{"attestation: disabled validator", []step{
		setEnabled(0, false),
		att(0, 1, 2, 1, refused(slashing.ReasonValidatorDisabled)),
		setEnabled(0, true),
		att(0, 1, 2, 1, allowed),
	}},

	// Both kinds.
	{"blocks and attestations of one validator are independent", []step{
		block(0, 64, 1, allowed),
		att(0, 0, 1, 1, allowed),
		block(0, 65, 2, allowed),
		att(0, 1, 2, 2, allowed),
		setEnabled(0, false),
		block(0, 66, 3, refused(slashing.ReasonValidatorDisabled)),
		att(0, 2, 3, 3, refused(slashing.ReasonValidatorDisabled)),
	}},
}

// RunEIP3076 runs the EIP-3076 scenarios through slashing.Engine against stores from newStore.
func RunEIP3076(t *testing.T, newStore Factory) {
	for _, sc := range eip3076Scenarios {
		t.Run(sc.name, func(t *testing.T) {
			s := open(t, newStore)
			e := slashing.NewEngine(s)
			ctx := context.Background()
			must(t, e.RegisterValidators(ctx, [][]byte{Key(0), Key(1), Key(2)}))
			for i, st := range sc.steps {
				if err := runStep(ctx, s, e, st); err != nil {
					t.Fatalf("step %d: %v", i, err)
				}
			}
		})
	}
}

func runStep(ctx context.Context, s slashing.Store, e *slashing.Engine, st step) error {
	gvr := GVR
	if st.gvr != nil {
		gvr = *st.gvr
	}
	switch st.op {
	case opBlock:
		before, err := blockAt(ctx, s, st.key, st.slot)
		if err != nil {
			return err
		}
		d, err := e.CheckAndRecordBlock(ctx, slashing.BlockRequest{
			PublicKey: Key(st.key), GenesisValidatorsRoot: gvr, Slot: st.slot, SigningRoot: RootOf(st.root),
		})
		if err := checkOutcome(d, err, st.want); err != nil {
			return fmt.Errorf("block(key %d, slot %d, root %d): %w", st.key, st.slot, st.root, err)
		}
		after, err := blockAt(ctx, s, st.key, st.slot)
		if err != nil {
			return err
		}
		return checkRecorded(d, before, after, RootOf(st.root))
	case opAttestation:
		before, err := attestationAt(ctx, s, st.key, st.target)
		if err != nil {
			return err
		}
		d, err := e.CheckAndRecordAttestation(ctx, slashing.AttestationRequest{
			PublicKey: Key(st.key), GenesisValidatorsRoot: gvr,
			SourceEpoch: st.source, TargetEpoch: st.target, SigningRoot: RootOf(st.root),
		})
		if err := checkOutcome(d, err, st.want); err != nil {
			return fmt.Errorf("attestation(key %d, %d→%d, root %d): %w", st.key, st.source, st.target, st.root, err)
		}
		after, err := attestationAt(ctx, s, st.key, st.target)
		if err != nil {
			return err
		}
		return checkRecorded(d, before, after, RootOf(st.root))
	case opImportBlocks:
		return ImportBlocks(ctx, s, id(st.key), st.blocks...)
	case opImportAttestations:
		return ImportAttestations(ctx, s, id(st.key), st.atts...)
	case opRepairWatermark:
		if st.low.Slot != nil {
			if err := s.UpdateBlocks(ctx, id(st.key), func(tx slashing.BlockTx) error {
				return tx.RaiseSlotLowWatermark(*st.low.Slot)
			}); err != nil {
				return err
			}
		}
		if st.low.SourceEpoch != nil {
			return s.UpdateAttestations(ctx, id(st.key), func(tx slashing.AttestationTx) error {
				return tx.RaiseEpochLowWatermarks(*st.low.SourceEpoch, *st.low.TargetEpoch)
			})
		}
		return nil
	case opSetEnabled:
		return e.SetValidatorEnabled(ctx, Key(st.key), st.enabled)
	case opSetHighWatermark:
		return s.SetHighWatermark(ctx, st.high)
	}
	return fmt.Errorf("unknown step kind %d", st.op)
}

// checkOutcome compares a check-and-record result with want. An error matches only a want.err it wraps, and then
// the decision must be the zero value.
func checkOutcome(d slashing.Decision, err error, want outcome) error {
	if err != nil || want.err != nil {
		if want.err == nil || !errors.Is(err, want.err) || d != (slashing.Decision{}) {
			return fmt.Errorf("decision %+v, error %v; want %+v", d, err, want)
		}
		return nil
	}
	got := outcome{allowed: d.Allowed, repeat: d.Repeat, reason: d.Reason}
	if got != want {
		return fmt.Errorf("decision %+v, want %+v", got, want)
	}
	return nil
}

// record is a recorded message's signing root, or absence.
type record struct {
	found bool
	root  *slashing.Root
}

// checkRecorded verifies that a new allowed message was recorded with its root and that anything else left the
// record unchanged.
func checkRecorded(d slashing.Decision, before, after record, root slashing.Root) error {
	if d.Allowed && !d.Repeat {
		if before.found || !after.found || after.root == nil || *after.root != root {
			return fmt.Errorf("allowed message not recorded: before %+v, after %+v", before, after)
		}
		return nil
	}
	if before.found != after.found || (before.root == nil) != (after.root == nil) ||
		(before.root != nil && *before.root != *after.root) {
		return fmt.Errorf("refused or repeated message changed the record: before %+v, after %+v", before, after)
	}
	return nil
}

func blockAt(ctx context.Context, s slashing.Store, key int, slot uint64) (record, error) {
	var r record
	err := s.UpdateBlocks(ctx, id(key), func(tx slashing.BlockTx) error {
		b, ok, err := tx.BlockAt(slot)
		r = record{found: ok, root: b.SigningRoot}
		return err
	})
	return r, err
}

func attestationAt(ctx context.Context, s slashing.Store, key int, target uint64) (record, error) {
	var r record
	err := s.UpdateAttestations(ctx, id(key), func(tx slashing.AttestationTx) error {
		a, ok, err := tx.AttestationAt(target)
		r = record{found: ok, root: a.SigningRoot}
		return err
	})
	return r, err
}
