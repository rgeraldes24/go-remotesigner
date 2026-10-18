// Copyright 2021 ConsenSys AG.
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
// slashing-protection/src/integration-test/java/tech/pegasys/web3signer/slashingprotection/PruningIntegrationTest.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package slashing_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// These tests port Web3Signer's PruningIntegrationTest, run against both stores. Where go-remotesigner differs
// (every validator in the store is pruned, not only registered ones; a watermark above every record no longer
// crashes the run) the test says so.

var bg = context.Background()

// stores are the backends the maintenance tests run on.
var stores = []struct {
	name string
	open func(t *testing.T) slashing.Store
}{
	{"memstore", func(*testing.T) slashing.Store { return memstore.New() }},
	{"boltstore", func(t *testing.T) slashing.Store {
		s, err := boltstore.Open(filepath.Join(t.TempDir(), "sp.db"), boltstore.Options{})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}},
}

func forEachStore(t *testing.T, test func(t *testing.T, s slashing.Store)) {
	for _, st := range stores {
		t.Run(st.name, func(t *testing.T) {
			s := st.open(t)
			t.Cleanup(func() { _ = s.Close() })
			test(t, s)
		})
	}
}

type history struct {
	blocks []slashing.SignedBlock
	atts   []slashing.SignedAttestation
	low    slashing.LowWatermark
}

// seed registers key i and writes its history as Web3Signer's tests insert rows: records first, then the given
// watermark.
func seed(t *testing.T, s slashing.Store, i int, h history) {
	t.Helper()
	must(t, s.RegisterValidators(bg, [][]byte{slashingtest.Key(i)}))
	must(t, s.UpdateHistory(bg, []slashing.KeyID{keyID(i)}, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
		for _, b := range h.blocks {
			if err := tx.InsertBlock(b); err != nil {
				return err
			}
		}
		for _, a := range h.atts {
			if err := tx.InsertAttestation(a); err != nil {
				return err
			}
		}
		if h.low.Slot != nil {
			if err := tx.RaiseSlotLowWatermark(*h.low.Slot); err != nil {
				return err
			}
		}
		if h.low.SourceEpoch != nil {
			return tx.RaiseEpochLowWatermarks(*h.low.SourceEpoch, *h.low.TargetEpoch)
		}
		return nil
	}))
}

// read returns key i's history.
func read(t *testing.T, s slashing.Store, i int) history {
	t.Helper()
	var h history
	must(t, s.ViewHistory(bg, func(v slashing.HistoryView) error {
		var err error
		if h.low, err = v.LowWatermark(keyID(i)); err != nil {
			return err
		}
		if err := v.Blocks(keyID(i), func(b slashing.SignedBlock) error { h.blocks = append(h.blocks, b); return nil }); err != nil {
			return err
		}
		return v.Attestations(keyID(i), func(a slashing.SignedAttestation) error { h.atts = append(h.atts, a); return nil })
	}))
	return h
}

func keyID(i int) slashing.KeyID { return slashing.KeyIDOf(slashingtest.Key(i)) }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func low(slot, source, target uint64) slashing.LowWatermark {
	return slashing.LowWatermark{Slot: &slot, SourceEpoch: &source, TargetEpoch: &target}
}

// ladder is Web3Signer's createSlashingData: blocks at slots 0..n-1 and attestations (i, i), with watermark 0.
func ladder(n int) history {
	h := history{low: low(0, 0, 0)}
	for i := range n {
		h.blocks = append(h.blocks, slashing.SignedBlock{Slot: uint64(i), SigningRoot: slashingtest.RootPtr(100)})
		h.atts = append(h.atts, slashing.SignedAttestation{SourceEpoch: uint64(i), TargetEpoch: uint64(i),
			SigningRoot: slashingtest.RootPtr(100)})
	}
	return h
}

func TestPrunesDataForRegisteredValidator(t *testing.T) {
	for _, tc := range []struct {
		keep, slotsPerEpoch         uint64
		lowestEpoch, lowestSlotKept int
	}{
		{1, 1, 9, 9},
		{5, 1, 5, 5},
		{9, 1, 1, 1},
		{10, 1, 0, 0},
		{20, 1, 0, 0},
		{1, 2, 9, 8},
		{3, 2, 7, 4},
	} {
		t.Run(fmt.Sprintf("keep %d of %d slots", tc.keep, tc.slotsPerEpoch), func(t *testing.T) {
			testPrune(t, tc.keep, tc.slotsPerEpoch, tc.lowestEpoch, tc.lowestSlotKept)
		})
	}
}

func testPrune(t *testing.T, keep, slotsPerEpoch uint64, lowestEpoch, lowestSlotKept int) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		all := ladder(10)
		seed(t, s, 1, all)
		res, err := slashing.Prune(bg, s, slashing.PruneConfig{EpochsToKeep: keep, SlotsPerEpoch: slotsPerEpoch})
		must(t, err)
		got := read(t, s, 1)
		want := history{
			blocks: all.blocks[lowestSlotKept:],
			atts:   all.atts[lowestEpoch:],
			low:    low(uint64(lowestSlotKept), uint64(lowestEpoch), uint64(lowestEpoch)),
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
		if res.Validators != 1 || res.Blocks != lowestSlotKept || res.Attestations != lowestEpoch {
			t.Fatalf("result %+v", res)
		}
	})
}

// Web3Signer prunes only the validators registered in the running process. go-remotesigner prunes every validator
// in the store, which also lets it prune at startup, before any key is loaded.
func TestPrunesEveryValidatorInTheStore(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		seed(t, s, 1, ladder(2))
		seed(t, s, 2, ladder(2))
		res, err := slashing.Prune(bg, s, slashing.PruneConfig{EpochsToKeep: 1, SlotsPerEpoch: 1})
		must(t, err)
		for i := 1; i <= 2; i++ {
			if h := read(t, s, i); len(h.atts) != 1 || len(h.blocks) != 1 {
				t.Fatalf("validator %d: %+v", i, h)
			}
		}
		if res.Validators != 2 {
			t.Fatalf("result %+v", res)
		}
	})
}

func TestWatermarkIsNotMovedLower(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		h := ladder(10)
		h.low = low(8, 8, 8)
		seed(t, s, 1, h)
		_, err := slashing.Prune(bg, s, slashing.PruneConfig{EpochsToKeep: 5, SlotsPerEpoch: 1})
		must(t, err)
		// Only two entries can go because the watermark is at 8.
		got := read(t, s, 1)
		if len(got.atts) != 2 || len(got.blocks) != 2 || !reflect.DeepEqual(got.low, low(8, 8, 8)) {
			t.Fatalf("got %+v", got)
		}
	})
}

func TestLowWatermarkCanMoveToEqualHighWatermark(t *testing.T) {
	// In the extreme case where only one epoch is kept, the low watermark may move up to the high watermark.
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		h := ladder(10)
		h.low = low(8, 8, 8)
		seed(t, s, 1, h)
		_, err := s.PinGenesisValidatorsRoot(bg, slashingtest.GVR)
		must(t, err)
		must(t, s.SetHighWatermark(bg, slashing.HighWatermark{Epoch: slashingtest.U64(9), Slot: slashingtest.U64(9)}))
		_, err = slashing.Prune(bg, s, slashing.PruneConfig{EpochsToKeep: 1, SlotsPerEpoch: 1})
		must(t, err)
		got := read(t, s, 1)
		if len(got.atts) != 1 || len(got.blocks) != 1 || !reflect.DeepEqual(got.low, low(9, 9, 9)) {
			t.Fatalf("got %+v", got)
		}
	})
}

func TestNoPruningOccursWhenThereIsNoWatermark(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		h := ladder(5)
		h.low = slashing.LowWatermark{}
		seed(t, s, 1, h)
		_, err := slashing.Prune(bg, s, slashing.PruneConfig{EpochsToKeep: 1, SlotsPerEpoch: 1})
		must(t, err)
		if got := read(t, s, 1); len(got.atts) != 5 || len(got.blocks) != 5 {
			t.Fatalf("got %+v", got)
		}
	})
}

func TestPrunesForDataWithGaps(t *testing.T) {
	for _, tc := range []struct {
		name    string
		indexes []uint64
		kept    int
		low     slashing.LowWatermark
	}{
		{"gaps", []uint64{0, 1, 8, 9}, 2, low(8, 8, 9)},
		{"gaps and does not delete all data", []uint64{0, 1, 9}, 1, low(9, 9, 10)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forEachStore(t, func(t *testing.T, s slashing.Store) {
				h := history{low: low(0, 0, 0)}
				for _, i := range tc.indexes {
					h.atts = append(h.atts, slashing.SignedAttestation{SourceEpoch: i, TargetEpoch: i + 1})
					h.blocks = append(h.blocks, slashing.SignedBlock{Slot: i})
				}
				seed(t, s, 1, h)
				_, err := slashing.Prune(bg, s, slashing.PruneConfig{EpochsToKeep: 5, SlotsPerEpoch: 1})
				must(t, err)
				got := read(t, s, 1)
				if len(got.atts) != tc.kept || len(got.blocks) != tc.kept || !reflect.DeepEqual(got.low, tc.low) {
					t.Fatalf("got %+v", got)
				}
			})
		})
	}
}

// Web3Signer's pruner crashes when the target watermark lies above every attestation, for example after a
// watermark repair to a future epoch (Optional.get on an empty nearest attestation), and the exception aborts the
// whole run. Here the watermark stays, the records below it go, and the other validators are pruned.
func TestWatermarkAboveEveryRecord(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		repaired := ladder(10)
		repaired.low = low(50, 50, 50)
		seed(t, s, 1, repaired)
		seed(t, s, 2, ladder(10))
		_, err := slashing.Prune(bg, s, slashing.PruneConfig{EpochsToKeep: 5, SlotsPerEpoch: 1})
		must(t, err)
		if got := read(t, s, 1); len(got.atts) != 0 || len(got.blocks) != 0 || !reflect.DeepEqual(got.low, low(50, 50, 50)) {
			t.Fatalf("repaired validator: %+v", got)
		}
		if got := read(t, s, 2); len(got.atts) != 5 || len(got.blocks) != 5 {
			t.Fatalf("other validator: %+v", got)
		}
	})
}

// The source watermark moves to the kept attestation's source only when that is higher: it is never lowered.
func TestSourceWatermarkIsNotLowered(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		seed(t, s, 1, history{
			atts: []slashing.SignedAttestation{{SourceEpoch: 1, TargetEpoch: 2}, {SourceEpoch: 2, TargetEpoch: 9}},
			low:  slashing.LowWatermark{SourceEpoch: slashingtest.U64(5), TargetEpoch: slashingtest.U64(2)},
		})
		_, err := slashing.Prune(bg, s, slashing.PruneConfig{EpochsToKeep: 1, SlotsPerEpoch: 1})
		must(t, err)
		got := read(t, s, 1)
		want := slashing.LowWatermark{SourceEpoch: slashingtest.U64(5), TargetEpoch: slashingtest.U64(9)}
		if len(got.atts) != 1 || !reflect.DeepEqual(got.low, want) {
			t.Fatalf("got %+v", got)
		}
	})
}

func TestPruneBatchesAndArguments(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		for i := range 7 {
			seed(t, s, i, ladder(4))
		}
		res, err := slashing.Prune(bg, s, slashing.PruneConfig{EpochsToKeep: 2, SlotsPerEpoch: 1, Batch: 3})
		must(t, err)
		if res != (slashing.PruneResult{Validators: 7, Blocks: 14, Attestations: 14}) {
			t.Fatalf("result %+v", res)
		}
		// Huge windows do not overflow: nothing is pruned.
		res, err = slashing.Prune(bg, s, slashing.PruneConfig{EpochsToKeep: 1 << 63, SlotsPerEpoch: 128})
		must(t, err)
		if res.Blocks != 0 || res.Attestations != 0 {
			t.Fatalf("overflowing window pruned %+v", res)
		}
		for _, cfg := range []slashing.PruneConfig{{SlotsPerEpoch: 1}, {EpochsToKeep: 1}} {
			if _, err := slashing.Prune(bg, s, cfg); err == nil {
				t.Fatalf("%+v accepted", cfg)
			}
		}
		ctx, cancel := context.WithCancel(bg)
		cancel()
		if _, err := slashing.Prune(ctx, s, slashing.PruneConfig{EpochsToKeep: 1, SlotsPerEpoch: 1}); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled prune: %v", err)
		}
	})
}
