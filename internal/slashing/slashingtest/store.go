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
// slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/dao/SignedBlocksDaoTest.java,
// slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/dao/SignedAttestationsDaoTest.java,
// slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/dao/LowWatermarkDaoTest.java,
// slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/dao/MetadataDaoTest.java and
// slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/dao/ValidatorsDaoTest.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package slashingtest

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// RunStoreContract checks the Store and transaction methods directly: the queries the rule engine relies on, the
// watermark rules and the metadata. The tests are ported from Web3Signer's DAO tests; where the QRL store differs
// (a high watermark set before a genesis validators root is pinned is an error, not a silent no-op), the test says
// so.
func RunStoreContract(t *testing.T, newStore Factory) {
	t.Run("blocks", func(t *testing.T) { runBlockContract(t, newStore) })
	t.Run("attestations", func(t *testing.T) { runAttestationContract(t, newStore) })
	t.Run("low watermarks", func(t *testing.T) { runLowWatermarkContract(t, newStore) })
	t.Run("metadata", func(t *testing.T) { runMetadataContract(t, newStore) })
	t.Run("validators", func(t *testing.T) { runValidatorContract(t, newStore) })
	t.Run("transactions", func(t *testing.T) { runTransactionContract(t, newStore) })
}

// bg is the context of the store-contract tests.
var bg = context.Background()

func runBlockContract(t *testing.T, newStore Factory) {
	t.Run("finds the block at a slot", func(t *testing.T) {
		s := openWithKeys(t, newStore, 2)
		must(t, ImportBlocks(bg, s, id(0), sb(2, RootPtr(3))))
		wantBlock(t, s, 0, 2, &slashing.SignedBlock{Slot: 2, SigningRoot: RootPtr(3)})
		wantBlock(t, s, 0, 3, nil)
		wantBlock(t, s, 1, 2, nil)
	})
	t.Run("stores blocks per validator, including slot zero", func(t *testing.T) {
		s := openWithKeys(t, newStore, 3)
		must(t, ImportBlocks(bg, s, id(1), sb(100, RootPtr(100)), sb(1<<62, RootPtr(101))))
		must(t, ImportBlocks(bg, s, id(2), sb(0, RootPtr(102))))
		wantBlock(t, s, 1, 100, &slashing.SignedBlock{Slot: 100, SigningRoot: RootPtr(100)})
		wantBlock(t, s, 1, 1<<62, &slashing.SignedBlock{Slot: 1 << 62, SigningRoot: RootPtr(101)})
		wantBlock(t, s, 2, 0, &slashing.SignedBlock{Slot: 0, SigningRoot: RootPtr(102)})
		wantBlock(t, s, 0, 100, nil)
	})
	t.Run("stores a block without a signing root", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		must(t, ImportBlocks(bg, s, id(0), sb(2, nil)))
		wantBlock(t, s, 0, 2, &slashing.SignedBlock{Slot: 2})
	})
	t.Run("refuses a second block at a slot", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		must(t, ImportBlocks(bg, s, id(0), sb(2, RootPtr(1))))
		for _, root := range []*slashing.Root{RootPtr(1), RootPtr(2), nil} {
			if err := ImportBlocks(bg, s, id(0), sb(2, root)); !errors.Is(err, slashing.ErrDuplicateRecord) {
				t.Fatalf("second insert at slot 2: %v, want ErrDuplicateRecord", err)
			}
		}
		wantBlock(t, s, 0, 2, &slashing.SignedBlock{Slot: 2, SigningRoot: RootPtr(1)})
	})
}

func runAttestationContract(t *testing.T, newStore Factory) {
	t.Run("finds the attestation at a target", func(t *testing.T) {
		s := openWithKeys(t, newStore, 2)
		must(t, ImportAttestations(bg, s, id(0), sa(3, 4, RootPtr(2))))
		wantAttestation(t, s, 0, 4, &slashing.SignedAttestation{SourceEpoch: 3, TargetEpoch: 4, SigningRoot: RootPtr(2)})
		wantAttestation(t, s, 0, 3, nil)
		wantAttestation(t, s, 1, 4, nil)
	})
	t.Run("stores an attestation without a signing root", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		must(t, ImportAttestations(bg, s, id(0), sa(3, 4, nil)))
		wantAttestation(t, s, 0, 4, &slashing.SignedAttestation{SourceEpoch: 3, TargetEpoch: 4})
	})
	t.Run("refuses a second attestation at a target", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		must(t, ImportAttestations(bg, s, id(0), sa(3, 4, RootPtr(1))))
		if err := ImportAttestations(bg, s, id(0), sa(2, 4, RootPtr(1))); !errors.Is(err, slashing.ErrDuplicateRecord) {
			t.Fatalf("second insert at target 4: %v, want ErrDuplicateRecord", err)
		}
	})
	t.Run("finds a surrounding attestation", func(t *testing.T) {
		s := openWithKeys(t, newStore, 2)
		must(t, ImportAttestations(bg, s, id(0), sa(2, 9, RootPtr(2)), sa(1, 10, RootPtr(2))))
		// Both surround (3, 7); the one with the highest target epoch is returned.
		want := sa(1, 10, RootPtr(2))
		wantSurround(t, s, 0, true, 3, 7, &want)
		wantSurround(t, s, 0, true, 3, 10, nil) // target outside
		wantSurround(t, s, 0, true, 1, 7, nil)  // source outside
		wantSurround(t, s, 0, true, 1, 10, nil) // both outside
		wantSurround(t, s, 1, true, 3, 7, nil)  // another validator
	})
	t.Run("returns the match with the highest target, whatever its source or insertion order", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		// Inserted highest target first; the highest target has the higher source in both pairs.
		must(t, ImportAttestations(bg, s, id(0), sa(2, 10, RootPtr(1)), sa(1, 9, RootPtr(2))))
		must(t, ImportAttestations(bg, s, id(0), sa(13, 15, RootPtr(3)), sa(12, 14, RootPtr(4))))
		surrounding := sa(2, 10, RootPtr(1))
		wantSurround(t, s, 0, true, 3, 7, &surrounding)
		surrounded := sa(13, 15, RootPtr(3))
		wantSurround(t, s, 0, false, 11, 16, &surrounded)
	})
	t.Run("finds a surrounded attestation", func(t *testing.T) {
		s := openWithKeys(t, newStore, 2)
		must(t, ImportAttestations(bg, s, id(0), sa(3, 4, RootPtr(2)), sa(2, 5, RootPtr(2))))
		// (1, 7) surrounds both; the one with the highest target epoch is returned.
		want := sa(2, 5, RootPtr(2))
		wantSurround(t, s, 0, false, 1, 7, &want)
		// Neither recorded attestation surrounds these.
		wantSurround(t, s, 0, true, 1, 5, nil)
		wantSurround(t, s, 0, true, 2, 7, nil)
		wantSurround(t, s, 0, true, 2, 5, nil)
		// Surround is strict on both epochs.
		wantSurround(t, s, 0, false, 3, 5, nil)
		wantSurround(t, s, 0, false, 2, 4, nil)
		wantSurround(t, s, 1, false, 1, 7, nil) // another validator
	})
}

func runLowWatermarkContract(t *testing.T, newStore Factory) {
	t.Run("empty", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		wantLow(t, s, 0, slashing.LowWatermark{})
	})
	t.Run("sets and raises the attestation watermark", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		raiseEpochs(t, s, 0, 2, 3, nil)
		wantLow(t, s, 0, slashing.LowWatermark{SourceEpoch: U64(2), TargetEpoch: U64(3)})
		raiseEpochs(t, s, 0, 4, 5, nil)
		wantLow(t, s, 0, slashing.LowWatermark{SourceEpoch: U64(4), TargetEpoch: U64(5)})
	})
	t.Run("sets the slot alone", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		raiseSlot(t, s, 0, 3, nil)
		wantLow(t, s, 0, slashing.LowWatermark{Slot: U64(3)})
	})
	t.Run("slot and epochs are independent", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		raiseEpochs(t, s, 0, 2, 3, nil)
		raiseSlot(t, s, 0, 5, nil)
		wantLow(t, s, 0, slashing.LowWatermark{Slot: U64(5), SourceEpoch: U64(2), TargetEpoch: U64(3)})
		raiseEpochs(t, s, 0, 4, 5, nil)
		wantLow(t, s, 0, slashing.LowWatermark{Slot: U64(5), SourceEpoch: U64(4), TargetEpoch: U64(5)})
	})
	t.Run("validators have separate watermarks", func(t *testing.T) {
		s := openWithKeys(t, newStore, 2)
		raiseEpochs(t, s, 0, 2, 3, nil)
		raiseSlot(t, s, 0, 4, nil)
		raiseEpochs(t, s, 1, 5, 6, nil)
		raiseSlot(t, s, 1, 7, nil)
		wantLow(t, s, 0, slashing.LowWatermark{Slot: U64(4), SourceEpoch: U64(2), TargetEpoch: U64(3)})
		wantLow(t, s, 1, slashing.LowWatermark{Slot: U64(7), SourceEpoch: U64(5), TargetEpoch: U64(6)})
	})
	t.Run("the attestation watermark never moves down", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		raiseEpochs(t, s, 0, 2, 3, nil)
		raiseEpochs(t, s, 0, 1, 2, nil)
		wantLow(t, s, 0, slashing.LowWatermark{SourceEpoch: U64(2), TargetEpoch: U64(3)})
		raiseEpochs(t, s, 0, 1, 4, nil) // source would move down: both stay
		wantLow(t, s, 0, slashing.LowWatermark{SourceEpoch: U64(2), TargetEpoch: U64(3)})
		raiseEpochs(t, s, 0, 3, 4, nil)
		wantLow(t, s, 0, slashing.LowWatermark{SourceEpoch: U64(3), TargetEpoch: U64(4)})
	})
	t.Run("the block watermark never moves down", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		raiseSlot(t, s, 0, 3, nil)
		raiseSlot(t, s, 0, 1, nil)
		wantLow(t, s, 0, slashing.LowWatermark{Slot: U64(3)})
		raiseSlot(t, s, 0, 4, nil)
		wantLow(t, s, 0, slashing.LowWatermark{Slot: U64(4)})
	})
	t.Run("may reach the high watermark", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		pin(t, s)
		must(t, s.SetHighWatermark(bg, slashing.HighWatermark{Epoch: U64(3), Slot: U64(2)}))
		raiseSlot(t, s, 0, 2, nil)
		raiseEpochs(t, s, 0, 2, 3, nil)
		wantLow(t, s, 0, slashing.LowWatermark{Slot: U64(2), SourceEpoch: U64(2), TargetEpoch: U64(3)})
	})
	t.Run("may not pass the high watermark", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		pin(t, s)
		must(t, s.SetHighWatermark(bg, slashing.HighWatermark{Epoch: U64(2), Slot: U64(2)}))
		raiseSlot(t, s, 0, 3, slashing.ErrWatermarkConflict)
		raiseEpochs(t, s, 0, 3, 3, slashing.ErrWatermarkConflict)
		raiseEpochs(t, s, 0, 2, 3, slashing.ErrWatermarkConflict)
		wantLow(t, s, 0, slashing.LowWatermark{})
	})
	t.Run("a slot-only high watermark leaves the epochs free", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		pin(t, s)
		must(t, s.SetHighWatermark(bg, slashing.HighWatermark{Slot: U64(5)}))
		raiseEpochs(t, s, 0, 100, 200, nil)
		raiseSlot(t, s, 0, 6, slashing.ErrWatermarkConflict)
		wantLow(t, s, 0, slashing.LowWatermark{SourceEpoch: U64(100), TargetEpoch: U64(200)})
	})
	t.Run("an epoch-only high watermark leaves the slot free", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		pin(t, s)
		must(t, s.SetHighWatermark(bg, slashing.HighWatermark{Epoch: U64(5)}))
		raiseSlot(t, s, 0, 100, nil)
		raiseEpochs(t, s, 0, 6, 6, slashing.ErrWatermarkConflict)
		wantLow(t, s, 0, slashing.LowWatermark{Slot: U64(100)})
	})
	t.Run("zero is a value, not unset", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		pin(t, s)
		zero := slashing.HighWatermark{Epoch: U64(0), Slot: U64(0)}
		must(t, s.SetHighWatermark(bg, zero))
		wantHigh(t, s, zero)
		raiseSlot(t, s, 0, 0, nil)
		raiseEpochs(t, s, 0, 0, 0, nil)
		raiseSlot(t, s, 0, 1, slashing.ErrWatermarkConflict)
		wantLow(t, s, 0, slashing.LowWatermark{Slot: U64(0), SourceEpoch: U64(0), TargetEpoch: U64(0)})
		for _, h := range []slashing.HighWatermark{{Slot: U64(0)}, {Epoch: U64(0)}} {
			if err := s.SetHighWatermark(bg, h); !errors.Is(err, slashing.ErrWatermarkConflict) {
				t.Errorf("SetHighWatermark(%s) over zero low watermarks: %v, want ErrWatermarkConflict", fmtHigh(h), err)
			}
		}
	})
}

func runMetadataContract(t *testing.T, newStore Factory) {
	t.Run("genesis validators root", func(t *testing.T) {
		s := open(t, newStore)
		if _, ok, err := s.GenesisValidatorsRoot(bg); err != nil || ok {
			t.Fatalf("new store: root present %v, err %v", ok, err)
		}
		got, err := s.PinGenesisValidatorsRoot(bg, GVR)
		if err != nil || got != GVR {
			t.Fatalf("pin: %x, %v", got, err)
		}
		got, err = s.PinGenesisValidatorsRoot(bg, otherGVR)
		if err != nil || got != GVR {
			t.Fatalf("second pin with another root: %x, %v; want the first root", got, err)
		}
		if got, ok, err := s.GenesisValidatorsRoot(bg); err != nil || !ok || got != GVR {
			t.Fatalf("pinned root: %x, %v, %v", got, ok, err)
		}
	})
	t.Run("high watermark", func(t *testing.T) {
		s := open(t, newStore)
		wantHigh(t, s, slashing.HighWatermark{})
		pin(t, s)
		wantHigh(t, s, slashing.HighWatermark{})
		for _, h := range []slashing.HighWatermark{
			{Epoch: U64(1), Slot: U64(2)},
			{Epoch: U64(1)},
			{Slot: U64(2)},
			{Epoch: U64(3), Slot: U64(4)},
		} {
			must(t, s.SetHighWatermark(bg, h))
			wantHigh(t, s, h)
		}
		must(t, s.SetHighWatermark(bg, slashing.HighWatermark{}))
		wantHigh(t, s, slashing.HighWatermark{})
		if got, ok, err := s.GenesisValidatorsRoot(bg); err != nil || !ok || got != GVR {
			t.Fatalf("root after high-watermark updates: %x, %v, %v", got, ok, err)
		}
	})
	t.Run("concurrent pins agree on one root", func(t *testing.T) {
		s := open(t, newStore)
		const n = 16
		var (
			wg   sync.WaitGroup
			got  [n]slashing.Root
			errs [n]error
		)
		start := make(chan struct{})
		for i := range n {
			wg.Go(func() {
				<-start
				got[i], errs[i] = s.PinGenesisValidatorsRoot(bg, RootOf(uint64(i)))
			})
		}
		close(start)
		wg.Wait()
		pinned, ok, err := s.GenesisValidatorsRoot(bg)
		if err != nil || !ok {
			t.Fatalf("root after concurrent pins: present %v, err %v", ok, err)
		}
		for i := range n {
			if errs[i] != nil || got[i] != pinned {
				t.Errorf("pin %d returned %x, %v; want the pinned root %x", i, got[i], errs[i], pinned)
			}
		}
	})
	t.Run("high watermark needs a genesis validators root", func(t *testing.T) {
		// Web3Signer's UPDATE silently changes nothing here; the QRL store refuses.
		s := open(t, newStore)
		err := s.SetHighWatermark(bg, slashing.HighWatermark{Epoch: U64(1), Slot: U64(2)})
		if !errors.Is(err, slashing.ErrNoGenesisValidatorsRoot) {
			t.Fatalf("SetHighWatermark before a pin: %v, want ErrNoGenesisValidatorsRoot", err)
		}
		wantHigh(t, s, slashing.HighWatermark{})
		// Removing a high watermark that was never set needs no root.
		must(t, s.SetHighWatermark(bg, slashing.HighWatermark{}))
	})
	t.Run("high watermark must exceed every low watermark", func(t *testing.T) {
		s := openWithKeys(t, newStore, 2)
		pin(t, s)
		raiseSlot(t, s, 0, 3, nil)
		raiseEpochs(t, s, 0, 4, 5, nil)
		raiseSlot(t, s, 1, 6, nil)
		raiseEpochs(t, s, 1, 7, 8, nil)
		for _, h := range []slashing.HighWatermark{
			{Slot: U64(6)},
			{Slot: U64(5)},
			{Epoch: U64(8)},
			{Epoch: U64(7)},
			{Epoch: U64(100), Slot: U64(6)},
		} {
			if err := s.SetHighWatermark(bg, h); !errors.Is(err, slashing.ErrWatermarkConflict) {
				t.Fatalf("SetHighWatermark(%s): %v, want ErrWatermarkConflict", fmtHigh(h), err)
			}
		}
		wantHigh(t, s, slashing.HighWatermark{})
		h := slashing.HighWatermark{Epoch: U64(9), Slot: U64(7)}
		must(t, s.SetHighWatermark(bg, h))
		wantHigh(t, s, h)
	})
	t.Run("a partial high watermark is checked on its own field only", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			slot        uint64
			source, tgt uint64
			high        slashing.HighWatermark
		}{
			{"slot only, below the epochs", 1, 9, 10, slashing.HighWatermark{Slot: U64(2)}},
			{"epoch only, below the slot", 10, 1, 2, slashing.HighWatermark{Epoch: U64(3)}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				s := openWithKeys(t, newStore, 1)
				pin(t, s)
				raiseSlot(t, s, 0, tc.slot, nil)
				raiseEpochs(t, s, 0, tc.source, tc.tgt, nil)
				must(t, s.SetHighWatermark(bg, tc.high))
				wantHigh(t, s, tc.high)
			})
		}
	})
	t.Run("transactions read the high watermark", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		pin(t, s)
		h := slashing.HighWatermark{Epoch: U64(4), Slot: U64(40)}
		must(t, s.SetHighWatermark(bg, h))
		must(t, s.UpdateBlocks(bg, id(0), func(tx slashing.BlockTx) error {
			got, err := tx.HighWatermark()
			if err == nil && !reflect.DeepEqual(got, h) {
				t.Errorf("BlockTx.HighWatermark = %s, want %s", fmtHigh(got), fmtHigh(h))
			}
			return err
		}))
		must(t, s.UpdateAttestations(bg, id(0), func(tx slashing.AttestationTx) error {
			got, err := tx.HighWatermark()
			if err == nil && !reflect.DeepEqual(got, h) {
				t.Errorf("AttestationTx.HighWatermark = %s, want %s", fmtHigh(got), fmtHigh(h))
			}
			return err
		}))
	})
}

func runValidatorContract(t *testing.T, newStore Factory) {
	t.Run("registration and enabled flag", func(t *testing.T) {
		s := open(t, newStore)
		wantStatus(t, s, 0, slashing.ValidatorStatus{})
		register(t, s, 2)
		wantStatus(t, s, 0, slashing.ValidatorStatus{Registered: true, Enabled: true})
		wantStatus(t, s, 1, slashing.ValidatorStatus{Registered: true, Enabled: true})
		wantStatus(t, s, 2, slashing.ValidatorStatus{})

		must(t, s.SetValidatorEnabled(bg, id(0), false))
		wantStatus(t, s, 0, slashing.ValidatorStatus{Registered: true})
		wantStatus(t, s, 1, slashing.ValidatorStatus{Registered: true, Enabled: true})

		// Registering again never re-enables a key; new keys in the same call are registered enabled.
		register(t, s, 3)
		wantStatus(t, s, 0, slashing.ValidatorStatus{Registered: true})
		wantStatus(t, s, 2, slashing.ValidatorStatus{Registered: true, Enabled: true})

		must(t, s.SetValidatorEnabled(bg, id(0), true))
		wantStatus(t, s, 0, slashing.ValidatorStatus{Registered: true, Enabled: true})
	})
	t.Run("registration as disabled", func(t *testing.T) {
		s := openWithKeys(t, newStore, 2)
		must(t, s.SetValidatorEnabled(bg, id(1), false))
		// New keys are registered disabled; known keys keep their flag, whichever it is.
		must(t, s.RegisterValidatorsDisabled(bg, [][]byte{Key(0), Key(1), Key(2)}))
		wantStatus(t, s, 0, slashing.ValidatorStatus{Registered: true, Enabled: true})
		wantStatus(t, s, 1, slashing.ValidatorStatus{Registered: true})
		wantStatus(t, s, 2, slashing.ValidatorStatus{Registered: true})
		// A key registered disabled is a full registration: it has a history, and RegisterValidators keeps its flag.
		must(t, s.UpdateHistory(bg, []slashing.KeyID{id(2)}, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
			return tx.InsertBlock(slashing.SignedBlock{Slot: 1})
		}))
		register(t, s, 3)
		wantStatus(t, s, 2, slashing.ValidatorStatus{Registered: true})
		for _, n := range []int{0, slashing.PublicKeyLength + 1} {
			if err := s.RegisterValidatorsDisabled(bg, [][]byte{Key(3), make([]byte, n)}); !errors.Is(err, slashing.ErrInvalidPublicKey) {
				t.Errorf("RegisterValidatorsDisabled(%d bytes): %v, want ErrInvalidPublicKey", n, err)
			}
		}
		wantStatus(t, s, 3, slashing.ValidatorStatus{})
	})
	t.Run("unregistered keys", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		if err := s.SetValidatorEnabled(bg, id(1), false); !errors.Is(err, slashing.ErrValidatorNotRegistered) {
			t.Errorf("SetValidatorEnabled: %v, want ErrValidatorNotRegistered", err)
		}
		called := false
		err := s.UpdateBlocks(bg, id(1), func(slashing.BlockTx) error { called = true; return nil })
		if !errors.Is(err, slashing.ErrValidatorNotRegistered) || called {
			t.Errorf("UpdateBlocks: %v (fn called %v), want ErrValidatorNotRegistered", err, called)
		}
		err = s.UpdateAttestations(bg, id(1), func(slashing.AttestationTx) error { called = true; return nil })
		if !errors.Is(err, slashing.ErrValidatorNotRegistered) || called {
			t.Errorf("UpdateAttestations: %v (fn called %v), want ErrValidatorNotRegistered", err, called)
		}
	})
	t.Run("public key length", func(t *testing.T) {
		s := open(t, newStore)
		for _, n := range []int{0, 48, slashing.PublicKeyLength - 1, slashing.PublicKeyLength + 1} {
			if err := s.RegisterValidators(bg, [][]byte{make([]byte, n)}); !errors.Is(err, slashing.ErrInvalidPublicKey) {
				t.Errorf("RegisterValidators(%d bytes): %v, want ErrInvalidPublicKey", n, err)
			}
		}
	})
	t.Run("enabled flag inside transactions", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		must(t, s.SetValidatorEnabled(bg, id(0), false))
		must(t, s.UpdateBlocks(bg, id(0), func(tx slashing.BlockTx) error {
			if enabled, err := tx.Enabled(); err != nil || enabled {
				t.Errorf("BlockTx.Enabled: %v, %v; want false", enabled, err)
			}
			return nil
		}))
		must(t, s.SetValidatorEnabled(bg, id(0), true))
		must(t, s.UpdateAttestations(bg, id(0), func(tx slashing.AttestationTx) error {
			if enabled, err := tx.Enabled(); err != nil || !enabled {
				t.Errorf("AttestationTx.Enabled: %v, %v; want true", enabled, err)
			}
			return nil
		}))
	})
	t.Run("enabled flag is serialised with transactions", func(t *testing.T) { runEnabledSerialisation(t, newStore) })
}

func runTransactionContract(t *testing.T, newStore Factory) {
	errAbort := errors.New("abort")
	t.Run("a failed block transaction leaves no trace", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		err := s.UpdateBlocks(bg, id(0), func(tx slashing.BlockTx) error {
			must(t, tx.InsertBlock(sb(5, RootPtr(1))))
			must(t, tx.RaiseSlotLowWatermark(5))
			return errAbort
		})
		if !errors.Is(err, errAbort) {
			t.Fatalf("UpdateBlocks: %v, want the function's error", err)
		}
		wantBlock(t, s, 0, 5, nil)
		wantLow(t, s, 0, slashing.LowWatermark{})
	})
	t.Run("a failed attestation transaction leaves no trace", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		must(t, ImportAttestations(bg, s, id(0), sa(1, 2, RootPtr(1))))
		err := s.UpdateAttestations(bg, id(0), func(tx slashing.AttestationTx) error {
			must(t, tx.InsertAttestation(sa(3, 4, RootPtr(2))))
			must(t, tx.RaiseEpochLowWatermarks(3, 4))
			return tx.InsertAttestation(sa(1, 2, RootPtr(3))) // duplicate
		})
		if !errors.Is(err, slashing.ErrDuplicateRecord) {
			t.Fatalf("UpdateAttestations: %v, want ErrDuplicateRecord", err)
		}
		wantAttestation(t, s, 0, 4, nil)
		wantAttestation(t, s, 0, 2, &slashing.SignedAttestation{SourceEpoch: 1, TargetEpoch: 2, SigningRoot: RootPtr(1)})
		wantLow(t, s, 0, slashing.LowWatermark{SourceEpoch: U64(1), TargetEpoch: U64(2)})
	})
	t.Run("a block transaction sees its own writes", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		must(t, s.UpdateBlocks(bg, id(0), func(tx slashing.BlockTx) error {
			must(t, tx.InsertBlock(sb(5, RootPtr(1))))
			if got, ok, err := tx.BlockAt(5); err != nil || !ok || !reflect.DeepEqual(got, sb(5, RootPtr(1))) {
				t.Errorf("BlockAt after insert: %+v, %v, %v", got, ok, err)
			}
			must(t, tx.RaiseSlotLowWatermark(5))
			if low, err := tx.LowWatermark(); err != nil || !reflect.DeepEqual(low, slashing.LowWatermark{Slot: U64(5)}) {
				t.Errorf("LowWatermark after raise: %s, %v", fmtLow(low), err)
			}
			return nil
		}))
	})
	t.Run("an attestation transaction sees its own writes", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		must(t, s.UpdateAttestations(bg, id(0), func(tx slashing.AttestationTx) error {
			must(t, tx.InsertAttestation(sa(3, 8, RootPtr(1))))
			if _, ok, err := tx.AttestationAt(8); err != nil || !ok {
				t.Errorf("AttestationAt after insert: %v, %v", ok, err)
			}
			if _, ok, err := tx.SurroundingAttestation(4, 7); err != nil || !ok {
				t.Errorf("SurroundingAttestation after insert: %v, %v", ok, err)
			}
			if _, ok, err := tx.SurroundedAttestation(2, 9); err != nil || !ok {
				t.Errorf("SurroundedAttestation after insert: %v, %v", ok, err)
			}
			must(t, tx.RaiseEpochLowWatermarks(3, 8))
			want := slashing.LowWatermark{SourceEpoch: U64(3), TargetEpoch: U64(8)}
			if low, err := tx.LowWatermark(); err != nil || !reflect.DeepEqual(low, want) {
				t.Errorf("LowWatermark after raise: %s, %v", fmtLow(low), err)
			}
			return nil
		}))
	})
}

func pin(t *testing.T, s slashing.Store) {
	t.Helper()
	_, err := s.PinGenesisValidatorsRoot(bg, GVR)
	must(t, err)
}

func raiseSlot(t *testing.T, s slashing.Store, key int, slot uint64, want error) {
	t.Helper()
	err := s.UpdateBlocks(bg, id(key), func(tx slashing.BlockTx) error { return tx.RaiseSlotLowWatermark(slot) })
	if !errors.Is(err, want) {
		t.Fatalf("RaiseSlotLowWatermark(%d): %v, want %v", slot, err, want)
	}
}

func raiseEpochs(t *testing.T, s slashing.Store, key int, source, target uint64, want error) {
	t.Helper()
	err := s.UpdateAttestations(bg, id(key), func(tx slashing.AttestationTx) error {
		return tx.RaiseEpochLowWatermarks(source, target)
	})
	if !errors.Is(err, want) {
		t.Fatalf("RaiseEpochLowWatermarks(%d, %d): %v, want %v", source, target, err, want)
	}
}

func wantBlock(t *testing.T, s slashing.Store, key int, slot uint64, want *slashing.SignedBlock) {
	t.Helper()
	must(t, s.UpdateBlocks(bg, id(key), func(tx slashing.BlockTx) error {
		got, ok, err := tx.BlockAt(slot)
		if err != nil {
			return err
		}
		if (want == nil && ok) || (want != nil && (!ok || !reflect.DeepEqual(got, *want))) {
			t.Errorf("key %d BlockAt(%d) = %+v (found %v), want %+v", key, slot, got, ok, want)
		}
		return nil
	}))
}

func wantAttestation(t *testing.T, s slashing.Store, key int, target uint64, want *slashing.SignedAttestation) {
	t.Helper()
	must(t, s.UpdateAttestations(bg, id(key), func(tx slashing.AttestationTx) error {
		got, ok, err := tx.AttestationAt(target)
		if err != nil {
			return err
		}
		if (want == nil && ok) || (want != nil && (!ok || !reflect.DeepEqual(got, *want))) {
			t.Errorf("key %d AttestationAt(%d) = %+v (found %v), want %+v", key, target, got, ok, want)
		}
		return nil
	}))
}

func wantSurround(t *testing.T, s slashing.Store, key int, surrounding bool, source, target uint64, want *slashing.SignedAttestation) {
	t.Helper()
	must(t, s.UpdateAttestations(bg, id(key), func(tx slashing.AttestationTx) error {
		query, name := tx.SurroundedAttestation, "SurroundedAttestation"
		if surrounding {
			query, name = tx.SurroundingAttestation, "SurroundingAttestation"
		}
		got, ok, err := query(source, target)
		if err != nil {
			return err
		}
		if (want == nil && ok) || (want != nil && (!ok || !reflect.DeepEqual(got, *want))) {
			t.Errorf("key %d %s(%d, %d) = %+v (found %v), want %+v", key, name, source, target, got, ok, want)
		}
		return nil
	}))
}

func wantLow(t *testing.T, s slashing.Store, key int, want slashing.LowWatermark) {
	t.Helper()
	must(t, s.UpdateBlocks(bg, id(key), func(tx slashing.BlockTx) error {
		got, err := tx.LowWatermark()
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("key %d low watermark = %s, want %s", key, fmtLow(got), fmtLow(want))
		}
		return nil
	}))
}

func wantHigh(t *testing.T, s slashing.Store, want slashing.HighWatermark) {
	t.Helper()
	got, err := s.HighWatermark(bg)
	must(t, err)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("high watermark = %s, want %s", fmtHigh(got), fmtHigh(want))
	}
}

func wantStatus(t *testing.T, s slashing.Store, key int, want slashing.ValidatorStatus) {
	t.Helper()
	got, err := s.ValidatorStatus(bg, id(key))
	must(t, err)
	if got != want {
		t.Errorf("key %d status = %+v, want %+v", key, got, want)
	}
}
