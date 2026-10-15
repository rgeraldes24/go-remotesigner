// Copyright 2020 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/DbSlashingProtectionTest.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package slashing_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// These tests port Web3Signer's DbSlashingProtectionTest. Web3Signer mocks its DAOs; here the history is real
// (seeded into a memory store) and a spy counts inserts and attestation queries. Where the QRL rules differ from
// Web3Signer the test asserts deviation X8 (literal EIP-3076 conditions at the low watermark).

const (
	slot        = 2
	sourceEpoch = 10
	targetEpoch = 20
)

var (
	signingRoot = slashingtest.RootOf(3)
	ctx         = context.Background()
)

type fixture struct {
	t      *testing.T
	mem    *memstore.Store
	spy    *spyStore
	engine *slashing.Engine
}

// newFixture returns an engine over a spied memory store with Key(0) registered and the store pinned to
// slashingtest.GVR.
func newFixture(t *testing.T) *fixture {
	f := newUnpinnedFixture(t)
	if _, err := f.mem.PinGenesisValidatorsRoot(ctx, slashingtest.GVR); err != nil {
		t.Fatal(err)
	}
	return f
}

func newUnpinnedFixture(t *testing.T) *fixture {
	mem := memstore.New()
	spy := &spyStore{Store: mem}
	f := &fixture{t: t, mem: mem, spy: spy, engine: slashing.NewEngine(spy)}
	if err := f.engine.RegisterValidators(ctx, [][]byte{slashingtest.Key(0)}); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) id() slashing.KeyID { return slashing.KeyIDOf(slashingtest.Key(0)) }

func (f *fixture) importBlocks(blocks ...slashing.SignedBlock) {
	f.t.Helper()
	if err := slashingtest.ImportBlocks(ctx, f.mem, f.id(), blocks...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) importAttestations(atts ...slashing.SignedAttestation) {
	f.t.Helper()
	if err := slashingtest.ImportAttestations(ctx, f.mem, f.id(), atts...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) slotWatermark(s uint64) {
	f.t.Helper()
	if err := f.mem.UpdateBlocks(ctx, f.id(), func(tx slashing.BlockTx) error { return tx.RaiseSlotLowWatermark(s) }); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) epochWatermarks(source, target uint64) {
	f.t.Helper()
	if err := f.mem.UpdateAttestations(ctx, f.id(), func(tx slashing.AttestationTx) error {
		return tx.RaiseEpochLowWatermarks(source, target)
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) highWatermark(h slashing.HighWatermark) {
	f.t.Helper()
	if err := f.mem.SetHighWatermark(ctx, h); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) disable() {
	f.t.Helper()
	if err := f.engine.SetValidatorEnabled(ctx, slashingtest.Key(0), false); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) block(s uint64) slashing.Decision {
	f.t.Helper()
	d, err := f.tryBlock(s)
	if err != nil {
		f.t.Fatal(err)
	}
	return d
}

func (f *fixture) tryBlock(s uint64) (slashing.Decision, error) {
	return f.engine.CheckAndRecordBlock(ctx, slashing.BlockRequest{
		PublicKey: slashingtest.Key(0), GenesisValidatorsRoot: slashingtest.GVR, Slot: s, SigningRoot: signingRoot,
	})
}

func (f *fixture) attestation(source, target uint64) slashing.Decision {
	f.t.Helper()
	d, err := f.tryAttestation(source, target)
	if err != nil {
		f.t.Fatal(err)
	}
	return d
}

func (f *fixture) tryAttestation(source, target uint64) (slashing.Decision, error) {
	return f.engine.CheckAndRecordAttestation(ctx, slashing.AttestationRequest{
		PublicKey: slashingtest.Key(0), GenesisValidatorsRoot: slashingtest.GVR,
		SourceEpoch: source, TargetEpoch: target, SigningRoot: signingRoot,
	})
}

func (f *fixture) wantInserts(blocks, atts int) {
	f.t.Helper()
	if f.spy.blockInserts != blocks || f.spy.attInserts != atts {
		f.t.Errorf("inserts: %d blocks, %d attestations; want %d and %d", f.spy.blockInserts, f.spy.attInserts, blocks, atts)
	}
}

func want(t *testing.T, got slashing.Decision, wantAllowed bool, wantReason slashing.Reason) {
	t.Helper()
	if got.Allowed != wantAllowed || got.Reason != wantReason {
		t.Errorf("decision %+v, want allowed %v reason %q", got, wantAllowed, wantReason)
	}
}

// wantErr checks that a request was rejected with err rather than refused with a 412 reason.
func wantErr(t *testing.T, d slashing.Decision, got, err error) {
	t.Helper()
	if !errors.Is(got, err) || d != (slashing.Decision{}) {
		t.Errorf("decision %+v, error %v; want the zero decision and %v", d, got, err)
	}
}

func TestBlockCanSignWhenNoMatchForValidator(t *testing.T) {
	f := newFixture(t)
	want(t, f.block(slot), true, "")
	f.wantInserts(1, 0)
}

func TestBlockCanSignButNotInsertWhenExactlyMatchesBlockAndIsAboveWatermark(t *testing.T) {
	f := newFixture(t)
	f.slotWatermark(slot - 1)
	f.importBlocks(slashing.SignedBlock{Slot: slot, SigningRoot: &signingRoot})
	d := f.block(slot)
	want(t, d, true, "")
	if !d.Repeat {
		t.Error("an exact match was not reported as a repeat")
	}
	f.wantInserts(0, 0)
}

func TestBlockCannotBeSignedIfMatchesBlockBelowWatermark(t *testing.T) {
	f := newFixture(t)
	f.importBlocks(slashing.SignedBlock{Slot: slot, SigningRoot: &signingRoot})
	f.slotWatermark(slot + 1)
	want(t, f.block(slot), false, slashing.ReasonBelowWatermark)
	f.wantInserts(0, 0)
}

func TestBlockCannotSignWhenSamePublicKeyAndSlotButDifferentSigningRootAboveWatermark(t *testing.T) {
	f := newFixture(t)
	f.slotWatermark(slot - 1)
	f.importBlocks(slashing.SignedBlock{Slot: slot, SigningRoot: slashingtest.RootPtr(4)})
	want(t, f.block(slot), false, slashing.ReasonDoubleProposal)
	f.wantInserts(0, 0)
}

func TestBlockCannotSignWhenSlotIsAtOrBeyondHighWatermark(t *testing.T) {
	f := newFixture(t)
	f.highWatermark(slashing.HighWatermark{Slot: slashingtest.U64(slot)}) // at
	want(t, f.block(slot), false, slashing.ReasonAboveHighWatermark)
	f.highWatermark(slashing.HighWatermark{Slot: slashingtest.U64(slot - 1)}) // beyond
	want(t, f.block(slot), false, slashing.ReasonAboveHighWatermark)
	f.wantInserts(0, 0)
}

func TestBlockCanSignWhenSlotIsBelowHighWatermark(t *testing.T) {
	f := newFixture(t)
	f.highWatermark(slashing.HighWatermark{Slot: slashingtest.U64(slot + 1)})
	want(t, f.block(slot), true, "")
	f.wantInserts(1, 0)
}

func TestBlockCannotSignWhenNoRegisteredValidator(t *testing.T) {
	f := newFixture(t)
	_, err := f.engine.CheckAndRecordBlock(ctx, slashing.BlockRequest{
		PublicKey: slashingtest.Key(1), GenesisValidatorsRoot: slashingtest.GVR, Slot: slot, SigningRoot: signingRoot,
	})
	if !errors.Is(err, slashing.ErrValidatorNotRegistered) {
		t.Fatalf("error %v, want ErrValidatorNotRegistered", err)
	}
	f.wantInserts(0, 0)
}

func TestBlockCannotBeSignedIfValidatorDisabled(t *testing.T) {
	f := newFixture(t)
	f.disable()
	want(t, f.block(slot), false, slashing.ReasonValidatorDisabled)
	f.wantInserts(0, 0)
}

func TestAttestationCanSignWhenExactlyMatchesExistingAttestationAndIsAboveWatermark(t *testing.T) {
	f := newFixture(t)
	f.epochWatermarks(1, 2)
	f.importAttestations(slashing.SignedAttestation{SourceEpoch: sourceEpoch, TargetEpoch: targetEpoch, SigningRoot: &signingRoot})
	d := f.attestation(sourceEpoch, targetEpoch)
	want(t, d, true, "")
	if !d.Repeat {
		t.Error("an exact match was not reported as a repeat")
	}
	f.wantInserts(0, 0)
}

func TestCannotSignAttestationWhichWasPreviouslySignedButBelowSourceWatermark(t *testing.T) {
	f := newFixture(t)
	f.importAttestations(slashing.SignedAttestation{SourceEpoch: sourceEpoch, TargetEpoch: targetEpoch, SigningRoot: &signingRoot})
	f.epochWatermarks(sourceEpoch+1, targetEpoch)
	want(t, f.attestation(sourceEpoch, targetEpoch), false, slashing.ReasonBelowWatermark)
	f.wantInserts(0, 0)
}

func TestCannotSignAttestationWhichWasPreviouslySignedButBelowTargetWatermark(t *testing.T) {
	f := newFixture(t)
	f.importAttestations(slashing.SignedAttestation{SourceEpoch: sourceEpoch, TargetEpoch: targetEpoch, SigningRoot: &signingRoot})
	f.epochWatermarks(sourceEpoch, targetEpoch+1)
	want(t, f.attestation(sourceEpoch, targetEpoch), false, slashing.ReasonBelowWatermark)
	f.wantInserts(0, 0)
}

func TestCannotSignAttestationWhenSourceIsAtOrBeyondHighWatermark(t *testing.T) {
	f := newFixture(t)
	f.highWatermark(slashing.HighWatermark{Epoch: slashingtest.U64(sourceEpoch)}) // at
	want(t, f.attestation(sourceEpoch, sourceEpoch), false, slashing.ReasonAboveHighWatermark)
	f.highWatermark(slashing.HighWatermark{Epoch: slashingtest.U64(sourceEpoch - 1)}) // beyond
	want(t, f.attestation(sourceEpoch, sourceEpoch), false, slashing.ReasonAboveHighWatermark)
	f.wantInserts(0, 0)
}

func TestCannotSignAttestationWhenTargetIsAtOrBeyondHighWatermark(t *testing.T) {
	f := newFixture(t)
	f.highWatermark(slashing.HighWatermark{Epoch: slashingtest.U64(targetEpoch)}) // at
	want(t, f.attestation(sourceEpoch, targetEpoch), false, slashing.ReasonAboveHighWatermark)
	f.highWatermark(slashing.HighWatermark{Epoch: slashingtest.U64(targetEpoch - 1)}) // beyond
	want(t, f.attestation(sourceEpoch, targetEpoch), false, slashing.ReasonAboveHighWatermark)
	f.wantInserts(0, 0)
}

func TestAttestationCanSignWhenSourceIsBelowHighWatermark(t *testing.T) {
	f := newFixture(t)
	f.highWatermark(slashing.HighWatermark{Epoch: slashingtest.U64(sourceEpoch + 1)})
	want(t, f.attestation(sourceEpoch, sourceEpoch), true, "")
	f.wantInserts(0, 1)
}

func TestAttestationCanSignWhenTargetIsBelowHighWatermark(t *testing.T) {
	f := newFixture(t)
	f.highWatermark(slashing.HighWatermark{Epoch: slashingtest.U64(targetEpoch + 1)})
	want(t, f.attestation(sourceEpoch, targetEpoch), true, "")
	f.wantInserts(0, 1)
}

func TestAttestationCannotSignWhenPreviousIsSurroundingAttestation(t *testing.T) {
	f := newFixture(t)
	f.importAttestations(
		slashing.SignedAttestation{SourceEpoch: 1, TargetEpoch: 2, SigningRoot: &signingRoot},
		slashing.SignedAttestation{SourceEpoch: sourceEpoch - 1, TargetEpoch: targetEpoch + 1, SigningRoot: &signingRoot},
	)
	want(t, f.attestation(sourceEpoch, targetEpoch), false, slashing.ReasonSurroundingVote)
	f.wantInserts(0, 0)
}

func TestAttestationCannotSignWhenPreviousIsSurroundedByAttestation(t *testing.T) {
	f := newFixture(t)
	f.importAttestations(
		slashing.SignedAttestation{SourceEpoch: 1, TargetEpoch: 2, SigningRoot: &signingRoot},
		slashing.SignedAttestation{SourceEpoch: sourceEpoch + 1, TargetEpoch: targetEpoch - 1, SigningRoot: &signingRoot},
	)
	want(t, f.attestation(sourceEpoch, targetEpoch), false, slashing.ReasonSurroundedVote)
	f.wantInserts(0, 0)
}

func TestAttestationCanSignWhenNoSurroundingOrSurroundedByAttestation(t *testing.T) {
	f := newFixture(t)
	f.importAttestations(slashing.SignedAttestation{SourceEpoch: 1, TargetEpoch: 2, SigningRoot: &signingRoot})
	want(t, f.attestation(sourceEpoch, targetEpoch), true, "")
	f.wantInserts(0, 1)
}

func TestAttestationCannotSignWhenNoRegisteredValidator(t *testing.T) {
	f := newFixture(t)
	_, err := f.engine.CheckAndRecordAttestation(ctx, slashing.AttestationRequest{
		PublicKey: slashingtest.Key(1), GenesisValidatorsRoot: slashingtest.GVR,
		SourceEpoch: sourceEpoch, TargetEpoch: targetEpoch, SigningRoot: signingRoot,
	})
	if !errors.Is(err, slashing.ErrValidatorNotRegistered) {
		t.Fatalf("error %v, want ErrValidatorNotRegistered", err)
	}
	f.wantInserts(0, 0)
}

func TestAttestationCannotSignWhenSourceEpochGreaterThanTargetEpoch(t *testing.T) {
	f := newFixture(t)
	d, err := f.tryAttestation(targetEpoch+1, targetEpoch)
	wantErr(t, d, err, slashing.ErrSourceAfterTarget)
	if f.spy.attQueries != 0 {
		t.Errorf("%d attestation-history queries, want none", f.spy.attQueries)
	}
	f.wantInserts(0, 0)
}

func TestSlashingProtectionEnactedIfAttestationWithNullSigningRootExists(t *testing.T) {
	f := newFixture(t)
	f.importAttestations(slashing.SignedAttestation{SourceEpoch: 1, TargetEpoch: targetEpoch})
	want(t, f.attestation(sourceEpoch, targetEpoch), false, slashing.ReasonDoubleVote)
}

func TestSlashingProtectionEnactedIfBlockWithNullSigningRootExists(t *testing.T) {
	f := newFixture(t)
	f.importBlocks(slashing.SignedBlock{Slot: slot})
	want(t, f.block(slot), false, slashing.ReasonDoubleProposal)
}

func TestSlashingProtectionEnactedIfBlockWithSlotLessThanMinSlot(t *testing.T) {
	f := newFixture(t)
	f.slotWatermark(2)
	want(t, f.block(1), false, slashing.ReasonBelowWatermark)
	f.wantInserts(0, 0)
}

// Web3Signer allows a new block at the minimum slot when no block is recorded there. The literal EIP-3076
// condition refuses it unless it repeats a recorded block (deviation X8).
func TestBlockCannotBeSignedIfSlotEqualToMinSlotX8(t *testing.T) {
	f := newFixture(t)
	f.slotWatermark(slot)
	want(t, f.block(slot), false, slashing.ReasonBelowWatermark)
	f.wantInserts(0, 0)

	f.importBlocks(slashing.SignedBlock{Slot: slot, SigningRoot: &signingRoot})
	d := f.block(slot)
	want(t, d, true, "")
	if !d.Repeat {
		t.Error("a repeat at the minimum slot was not reported as a repeat")
	}
}

func TestSlashingProtectionEnactedIfAttestationWithSourceEpochLessThanMin(t *testing.T) {
	f := newFixture(t)
	f.epochWatermarks(2, 3)
	want(t, f.attestation(0, 0), false, slashing.ReasonBelowWatermark)
	f.wantInserts(0, 0)
}

func TestAttestationCanBeSignedWithSourceEpochEqualToMin(t *testing.T) {
	f := newFixture(t)
	f.epochWatermarks(sourceEpoch, 3)
	want(t, f.attestation(sourceEpoch, targetEpoch), true, "")
	f.wantInserts(0, 1)
}

func TestSlashingProtectionEnactedIfAttestationWithTargetEpochLessThanMin(t *testing.T) {
	f := newFixture(t)
	f.epochWatermarks(1, 5)
	want(t, f.attestation(3, 4), false, slashing.ReasonBelowWatermark)
	f.wantInserts(0, 0)
}

// Web3Signer allows a new attestation at the minimum target epoch when none is recorded there. The literal
// EIP-3076 condition refuses it unless it repeats a recorded attestation (deviation X8).
func TestAttestationCannotBeSignedIfTargetEpochEqualToMinX8(t *testing.T) {
	f := newFixture(t)
	f.epochWatermarks(2, 4)
	want(t, f.attestation(3, 4), false, slashing.ReasonBelowWatermark)
	f.wantInserts(0, 0)
}

func TestCannotSignMatchingAttestationWhichIsSurroundedEvenIfMatchesExisting(t *testing.T) {
	// Only possible with imported history.
	f := newFixture(t)
	f.importAttestations(
		slashing.SignedAttestation{SourceEpoch: 3, TargetEpoch: 4, SigningRoot: &signingRoot},
		slashing.SignedAttestation{SourceEpoch: 2, TargetEpoch: 5, SigningRoot: slashingtest.RootPtr(11)},
	)
	want(t, f.attestation(3, 4), false, slashing.ReasonSurroundingVote)
	f.wantInserts(0, 0)
}

func TestCannotSignMatchingAttestationWhichIsSurroundingEvenIfMatchesExisting(t *testing.T) {
	// Only possible with imported history.
	f := newFixture(t)
	f.importAttestations(
		slashing.SignedAttestation{SourceEpoch: 3, TargetEpoch: 4, SigningRoot: slashingtest.RootPtr(11)},
		slashing.SignedAttestation{SourceEpoch: 2, TargetEpoch: 5, SigningRoot: &signingRoot},
	)
	want(t, f.attestation(2, 5), false, slashing.ReasonSurroundedVote)
	f.wantInserts(0, 0)
}

func TestAttestationCannotBeSignedIfValidatorDisabled(t *testing.T) {
	f := newFixture(t)
	f.disable()
	want(t, f.attestation(sourceEpoch, targetEpoch), false, slashing.ReasonValidatorDisabled)
	f.wantInserts(0, 0)
}

func TestSlashingProtectionEnactedIfAttestationWithInvalidGvr(t *testing.T) {
	f := newUnpinnedFixture(t)
	other := slashing.Root{31: 1}
	if _, err := f.mem.PinGenesisValidatorsRoot(ctx, other); err != nil {
		t.Fatal(err)
	}
	d, err := f.tryAttestation(sourceEpoch, targetEpoch)
	wantErr(t, d, err, slashing.ErrGenesisValidatorsRootMismatch)
	f.wantInserts(0, 0)
	wantPinned(t, f.mem, other)
}

func TestSlashingProtectionEnactedIfBlockWithInvalidGvr(t *testing.T) {
	f := newUnpinnedFixture(t)
	other := slashing.Root{31: 1}
	if _, err := f.mem.PinGenesisValidatorsRoot(ctx, other); err != nil {
		t.Fatal(err)
	}
	d, err := f.tryBlock(slot)
	wantErr(t, d, err, slashing.ErrGenesisValidatorsRootMismatch)
	f.wantInserts(0, 0)
	wantPinned(t, f.mem, other)
}

func TestRegistersGVRForBlockIfItDoesNotExist(t *testing.T) {
	f := newUnpinnedFixture(t)
	want(t, f.block(slot), true, "")
	wantPinned(t, f.mem, slashingtest.GVR)
}

func TestRegistersGVRForAttestationIfItDoesNotExist(t *testing.T) {
	f := newUnpinnedFixture(t)
	want(t, f.attestation(sourceEpoch, targetEpoch), true, "")
	wantPinned(t, f.mem, slashingtest.GVR)
}

func wantPinned(t *testing.T, s slashing.Store, gvr slashing.Root) {
	t.Helper()
	got, ok, err := s.GenesisValidatorsRoot(ctx)
	if err != nil || !ok || got != gvr {
		t.Fatalf("pinned root %x (present %v, err %v), want %x", got, ok, err, gvr)
	}
}

// spyStore counts history inserts and attestation-history queries made through it.
type spyStore struct {
	slashing.Store
	blockInserts, attInserts, attQueries int
}

func (s *spyStore) UpdateBlocks(ctx context.Context, id slashing.KeyID, fn func(slashing.BlockTx) error) error {
	return s.Store.UpdateBlocks(ctx, id, func(tx slashing.BlockTx) error { return fn(spyBlockTx{tx, s}) })
}

func (s *spyStore) UpdateAttestations(ctx context.Context, id slashing.KeyID, fn func(slashing.AttestationTx) error) error {
	return s.Store.UpdateAttestations(ctx, id, func(tx slashing.AttestationTx) error { return fn(spyAttTx{tx, s}) })
}

type spyBlockTx struct {
	slashing.BlockTx
	s *spyStore
}

func (t spyBlockTx) InsertBlock(b slashing.SignedBlock) error {
	t.s.blockInserts++
	return t.BlockTx.InsertBlock(b)
}

type spyAttTx struct {
	slashing.AttestationTx
	s *spyStore
}

func (t spyAttTx) AttestationAt(target uint64) (slashing.SignedAttestation, bool, error) {
	t.s.attQueries++
	return t.AttestationTx.AttestationAt(target)
}

func (t spyAttTx) SurroundingAttestation(source, target uint64) (slashing.SignedAttestation, bool, error) {
	t.s.attQueries++
	return t.AttestationTx.SurroundingAttestation(source, target)
}

func (t spyAttTx) SurroundedAttestation(source, target uint64) (slashing.SignedAttestation, bool, error) {
	t.s.attQueries++
	return t.AttestationTx.SurroundedAttestation(source, target)
}

func (t spyAttTx) InsertAttestation(a slashing.SignedAttestation) error {
	t.s.attInserts++
	return t.AttestationTx.InsertAttestation(a)
}
