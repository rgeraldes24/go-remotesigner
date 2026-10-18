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
// slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/dao/SignedBlocksDaoTest.java and
// slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/dao/SignedAttestationsDaoTest.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package slashingtest

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// RunHistory checks the methods the interchange import and export, the pruner and the watermark commands use:
// UpdateHistory, ViewHistory and the pruning queries of the block and attestation transactions. The pruning-query
// cases port the delete, max and nearest tests of Web3Signer's SignedBlocksDaoTest and SignedAttestationsDaoTest.
func RunHistory(t *testing.T, newStore Factory) {
	t.Run("update history", func(t *testing.T) { runUpdateHistory(t, newStore) })
	t.Run("pruning queries", func(t *testing.T) { runPruningQueries(t, newStore) })
	t.Run("view history", func(t *testing.T) { runViewHistory(t, newStore) })
	t.Run("concurrent history updates", func(t *testing.T) { runConcurrentHistory(t, newStore) })
}

// hctx is the context of the history tests.
var hctx = context.Background()

func runUpdateHistory(t *testing.T, newStore Factory) {
	t.Run("refuses an unregistered key without calling fn", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		called := false
		err := s.UpdateHistory(hctx, []slashing.KeyID{id(0), id(1)}, func(slashing.KeyID, slashing.HistoryTx) error {
			called = true
			return nil
		})
		if !errors.Is(err, slashing.ErrValidatorNotRegistered) || called {
			t.Fatalf("UpdateHistory with an unregistered key: %v, fn called %v", err, called)
		}
	})
	t.Run("commits every validator together", func(t *testing.T) {
		s := openWithKeys(t, newStore, 3)
		var order []slashing.KeyID
		ids := []slashing.KeyID{id(2), id(0), id(2)}
		err := s.UpdateHistory(hctx, ids, func(k slashing.KeyID, tx slashing.HistoryTx) error {
			order = append(order, k)
			if _, found, err := tx.BlockAt(uint64(len(order))); err != nil || found {
				return errors.Join(err, errors.New("unexpected block"))
			}
			if err := tx.InsertBlock(sb(uint64(len(order)), RootPtr(1))); err != nil {
				return err
			}
			if err := tx.InsertAttestation(sa(1, uint64(len(order)), RootPtr(2))); err != nil {
				return err
			}
			if err := tx.RaiseSlotLowWatermark(1); err != nil {
				return err
			}
			return tx.RaiseEpochLowWatermarks(1, 1)
		})
		must(t, err)
		if !reflect.DeepEqual(order, ids) {
			t.Fatalf("fn order %v, want %v", order, ids)
		}
		wantHistBlocks(t, s, 2, sb(1, RootPtr(1)), sb(3, RootPtr(1)))
		wantHistBlocks(t, s, 0, sb(2, RootPtr(1)))
		wantHistBlocks(t, s, 1)
		wantHistLow(t, s, 2, slashing.LowWatermark{Slot: U64(1), SourceEpoch: U64(1), TargetEpoch: U64(1)})
	})
	t.Run("an error keeps nothing for any validator", func(t *testing.T) {
		s := openWithKeys(t, newStore, 2)
		must(t, ImportBlocks(hctx, s, id(0), sb(5, RootPtr(5))))
		must(t, ImportAttestations(hctx, s, id(0), sa(4, 5, RootPtr(5))))
		before := histSnapshot(t, s)
		boom := errors.New("boom")
		err := s.UpdateHistory(hctx, []slashing.KeyID{id(1), id(0)}, func(k slashing.KeyID, tx slashing.HistoryTx) error {
			must(t, tx.InsertBlock(sb(9, nil)))
			must(t, tx.InsertAttestation(sa(8, 9, nil)))
			must(t, tx.RaiseSlotLowWatermark(9))
			must(t, tx.RaiseEpochLowWatermarks(8, 9))
			must(t, tx.SetEnabled(false))
			if _, err := tx.PruneBlocks(); err != nil {
				return err
			}
			if _, err := tx.PruneAttestations(); err != nil {
				return err
			}
			if k == id(0) {
				return boom
			}
			return nil
		})
		if !errors.Is(err, boom) {
			t.Fatalf("UpdateHistory: %v, want the function's error", err)
		}
		if after := histSnapshot(t, s); !reflect.DeepEqual(after, before) {
			t.Fatalf("a failed UpdateHistory changed the store:\nbefore %+v\nafter  %+v", before, after)
		}
		for i := range 2 {
			if st, err := s.ValidatorStatus(hctx, id(i)); err != nil || !st.Enabled {
				t.Fatalf("key %d after the failed transaction: %+v %v, want enabled", i, st, err)
			}
		}
	})
	t.Run("sets the enabled flag", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		for _, enabled := range []bool{false, true, false} {
			must(t, s.UpdateHistory(hctx, []slashing.KeyID{id(0)}, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
				return tx.SetEnabled(enabled)
			}))
			st, err := s.ValidatorStatus(hctx, id(0))
			if err != nil || st.Enabled != enabled {
				t.Fatalf("after SetEnabled(%v): %+v %v", enabled, st, err)
			}
			err = s.UpdateHistory(hctx, []slashing.KeyID{id(0)}, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
				got, err := tx.Enabled()
				if err == nil && got != enabled {
					err = errors.New("the Enabled flag disagrees with SetEnabled")
				}
				return err
			})
			must(t, err)
		}
	})
}

func runPruningQueries(t *testing.T, newStore Factory) {
	type result struct {
		last, nearest   any
		pruned          int
		blocks          []slashing.SignedBlock
		attestations    []slashing.SignedAttestation
		lastOK, nearOK  bool
		lowAfterPruning slashing.LowWatermark
	}
	run := func(t *testing.T, s slashing.Store, nearest uint64) result {
		var r result
		must(t, s.UpdateHistory(hctx, []slashing.KeyID{id(0)}, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
			lb, lok, err := tx.LastBlock()
			if err != nil {
				return err
			}
			nb, nok, err := tx.NearestBlock(nearest)
			if err != nil {
				return err
			}
			la, laok, err := tx.LastAttestation()
			if err != nil {
				return err
			}
			na, naok, err := tx.NearestAttestation(nearest)
			if err != nil {
				return err
			}
			if lok != laok || nok != naok {
				return errors.New("the scenario keeps blocks and attestations in step")
			}
			r.last, r.nearest, r.lastOK, r.nearOK = [2]any{lb, la}, [2]any{nb, na}, lok, nok
			pb, err := tx.PruneBlocks()
			if err != nil {
				return err
			}
			pa, err := tx.PruneAttestations()
			r.pruned = pb + pa
			return err
		}))
		r.blocks, r.attestations = histOf(t, s, 0)
		r.lowAfterPruning = histLow(t, s, 0)
		return r
	}

	t.Run("no history", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		if r := run(t, s, 0); r.lastOK || r.nearOK || r.pruned != 0 {
			t.Fatalf("empty history: %+v", r)
		}
	})
	t.Run("last, nearest and pruning below the watermark", func(t *testing.T) {
		s := openWithKeys(t, newStore, 2)
		// Key 1's history must not be touched.
		must(t, ImportBlocks(hctx, s, id(1), sb(0, RootPtr(0))))
		must(t, ImportAttestations(hctx, s, id(1), sa(0, 0, RootPtr(0))))
		must(t, ImportBlocks(hctx, s, id(0), sb(2, RootPtr(2)), sb(4, nil), sb(7, RootPtr(7)), sb(1<<62, RootPtr(9))))
		must(t, ImportAttestations(hctx, s, id(0), sa(1, 2, RootPtr(2)), sa(3, 4, nil), sa(6, 7, RootPtr(7)), sa(8, 1<<62, RootPtr(9))))
		// Raise the watermarks to slot 4 and epochs (3, 4): the records at 2 go.
		must(t, s.UpdateHistory(hctx, []slashing.KeyID{id(0)}, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
			return errors.Join(tx.RaiseSlotLowWatermark(4), tx.RaiseEpochLowWatermarks(3, 4))
		}))
		r := run(t, s, 5)
		wantLast := [2]any{sb(1<<62, RootPtr(9)), sa(8, 1<<62, RootPtr(9))}
		wantNearest := [2]any{sb(7, RootPtr(7)), sa(6, 7, RootPtr(7))}
		if !r.lastOK || !reflect.DeepEqual(r.last, wantLast) || !r.nearOK || !reflect.DeepEqual(r.nearest, wantNearest) {
			t.Fatalf("last %+v, nearest %+v; want %+v, %+v", r.last, r.nearest, wantLast, wantNearest)
		}
		if r.pruned != 2 {
			t.Fatalf("pruned %d records, want 2", r.pruned)
		}
		wantHistBlocksEqual(t, r.blocks, sb(4, nil), sb(7, RootPtr(7)), sb(1<<62, RootPtr(9)))
		wantAttsEqual(t, r.attestations, sa(3, 4, nil), sa(6, 7, RootPtr(7)), sa(8, 1<<62, RootPtr(9)))
		wantLowEqual(t, r.lowAfterPruning, slashing.LowWatermark{Slot: U64(4), SourceEpoch: U64(3), TargetEpoch: U64(4)})
		wantHistBlocks(t, s, 1, sb(0, RootPtr(0)))
		// Nearest at an exact record, and past the last one.
		r = run(t, s, 7)
		if !reflect.DeepEqual(r.nearest, wantNearest) || r.pruned != 0 {
			t.Fatalf("nearest at 7: %+v, pruned %d", r.nearest, r.pruned)
		}
		if r = run(t, s, 1<<62+1); r.nearOK {
			t.Fatalf("nearest past the last record: %+v", r.nearest)
		}
	})
	t.Run("nothing is pruned without a watermark", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		must(t, s.UpdateHistory(hctx, []slashing.KeyID{id(0)}, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
			return errors.Join(tx.InsertBlock(sb(3, nil)), tx.InsertAttestation(sa(1, 3, nil)))
		}))
		if r := run(t, s, 0); r.pruned != 0 || len(r.blocks) != 1 || len(r.attestations) != 1 {
			t.Fatalf("pruned without a watermark: %+v", r)
		}
	})
}

func runViewHistory(t *testing.T, newStore Factory) {
	t.Run("empty store", func(t *testing.T) {
		s := open(t, newStore)
		must(t, s.ViewHistory(hctx, func(v slashing.HistoryView) error {
			if _, ok, err := v.GenesisValidatorsRoot(); ok || err != nil {
				t.Errorf("GVR of an empty store: %v %v", ok, err)
			}
			return v.Validators(func(slashing.KeyID, []byte) error { return errors.New("no validator expected") })
		}))
	})
	t.Run("snapshot of every validator", func(t *testing.T) {
		s := openWithKeys(t, newStore, 5)
		_, err := s.PinGenesisValidatorsRoot(hctx, GVR)
		must(t, err)
		must(t, ImportBlocks(hctx, s, id(3), sb(9, RootPtr(9)), sb(2, nil)))
		must(t, ImportAttestations(hctx, s, id(3), sa(5, 8, nil), sa(1, 2, RootPtr(2))))
		var (
			ids    []slashing.KeyID
			blocks []slashing.SignedBlock
			atts   []slashing.SignedAttestation
			low    slashing.LowWatermark
		)
		must(t, s.ViewHistory(hctx, func(v slashing.HistoryView) error {
			gvr, ok, err := v.GenesisValidatorsRoot()
			if err != nil || !ok || gvr != GVR {
				t.Errorf("GVR %x %v %v", gvr, ok, err)
			}
			err = v.Validators(func(k slashing.KeyID, pk []byte) error {
				if slashing.KeyIDOf(pk) != k {
					t.Errorf("validator %s has another key's public key", k)
				}
				ids = append(ids, k)
				return nil
			})
			if err != nil {
				return err
			}
			if low, err = v.LowWatermark(id(3)); err != nil {
				return err
			}
			if err := v.Blocks(id(3), func(b slashing.SignedBlock) error { blocks = append(blocks, b); return nil }); err != nil {
				return err
			}
			return v.Attestations(id(3), func(a slashing.SignedAttestation) error { atts = append(atts, a); return nil })
		}))
		if len(ids) != 5 {
			t.Fatalf("%d validators, want 5", len(ids))
		}
		for i := 1; i < len(ids); i++ {
			if bytes.Compare(ids[i-1][:], ids[i][:]) >= 0 {
				t.Fatalf("validators not in KeyID order: %v", ids)
			}
		}
		wantHistBlocksEqual(t, blocks, sb(2, nil), sb(9, RootPtr(9)))
		wantAttsEqual(t, atts, sa(1, 2, RootPtr(2)), sa(5, 8, nil))
		wantLowEqual(t, low, slashing.LowWatermark{Slot: U64(2), SourceEpoch: U64(1), TargetEpoch: U64(2)})
	})
	t.Run("stops at the first error and refuses unregistered keys", func(t *testing.T) {
		s := openWithKeys(t, newStore, 3)
		stop := errors.New("stop")
		calls := 0
		err := s.ViewHistory(hctx, func(v slashing.HistoryView) error {
			return v.Validators(func(slashing.KeyID, []byte) error { calls++; return stop })
		})
		if !errors.Is(err, stop) || calls != 1 {
			t.Fatalf("Validators did not stop at the first error: %v after %d calls", err, calls)
		}
		err = s.ViewHistory(hctx, func(v slashing.HistoryView) error {
			_, err := v.LowWatermark(id(7))
			return errors.Join(err, v.Blocks(id(7), func(slashing.SignedBlock) error { return nil }),
				v.Attestations(id(7), func(slashing.SignedAttestation) error { return nil }))
		})
		if !errors.Is(err, slashing.ErrValidatorNotRegistered) {
			t.Fatalf("view of an unregistered key: %v", err)
		}
	})
}

// runConcurrentHistory runs overlapping UpdateHistory batches, in opposite orders, against signing and
// SetValidatorEnabled on the same keys: the fixed lock order must keep them from deadlocking.
func runConcurrentHistory(t *testing.T, newStore Factory) {
	s := openWithKeys(t, newStore, 4)
	e := slashing.NewEngine(s)
	keys := [][]byte{Key(0), Key(1), Key(2), Key(3)}
	must(t, e.RegisterValidators(hctx, keys))
	forward := []slashing.KeyID{id(0), id(1), id(2), id(3)}
	backward := []slashing.KeyID{id(3), id(2), id(1), id(0)}
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := range 4 {
		wg.Go(func() {
			ids := forward
			if g%2 == 1 {
				ids = backward
			}
			for range 10 {
				errs <- s.UpdateHistory(hctx, ids, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
					_, err := tx.PruneBlocks()
					return err
				})
			}
		})
	}
	for k := range 4 {
		wg.Go(func() {
			for i := range 5 {
				_, err := e.CheckAndRecordBlock(hctx, slashing.BlockRequest{PublicKey: keys[k], GenesisValidatorsRoot: GVR,
					Slot: uint64(10 + i), SigningRoot: RootOf(1)})
				errs <- errors.Join(err, s.SetValidatorEnabled(hctx, id(k), true))
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		must(t, err)
	}
}

// storeState is a store's observable history, for before/after comparisons.
type storeState map[slashing.KeyID]struct {
	Blocks       []slashing.SignedBlock
	Attestations []slashing.SignedAttestation
	Low          slashing.LowWatermark
}

func histSnapshot(t *testing.T, s slashing.Store) storeState {
	t.Helper()
	st := storeState{}
	must(t, s.ViewHistory(hctx, func(v slashing.HistoryView) error {
		return v.Validators(func(k slashing.KeyID, _ []byte) error {
			e := st[k]
			var err error
			if e.Low, err = v.LowWatermark(k); err != nil {
				return err
			}
			if err := v.Blocks(k, func(b slashing.SignedBlock) error { e.Blocks = append(e.Blocks, b); return nil }); err != nil {
				return err
			}
			err = v.Attestations(k, func(a slashing.SignedAttestation) error { e.Attestations = append(e.Attestations, a); return nil })
			st[k] = e
			return err
		})
	}))
	return st
}

func histOf(t *testing.T, s slashing.Store, key int) ([]slashing.SignedBlock, []slashing.SignedAttestation) {
	t.Helper()
	e := histSnapshot(t, s)[id(key)]
	return e.Blocks, e.Attestations
}

func histLow(t *testing.T, s slashing.Store, key int) slashing.LowWatermark {
	t.Helper()
	return histSnapshot(t, s)[id(key)].Low
}

func wantHistBlocks(t *testing.T, s slashing.Store, key int, want ...slashing.SignedBlock) {
	t.Helper()
	got, _ := histOf(t, s, key)
	wantHistBlocksEqual(t, got, want...)
}

func wantHistLow(t *testing.T, s slashing.Store, key int, want slashing.LowWatermark) {
	t.Helper()
	wantLowEqual(t, histLow(t, s, key), want)
}

func wantHistBlocksEqual(t *testing.T, got []slashing.SignedBlock, want ...slashing.SignedBlock) {
	t.Helper()
	if len(got) != len(want) || (len(want) > 0 && !reflect.DeepEqual(got, want)) {
		t.Fatalf("blocks %+v, want %+v", got, want)
	}
}

func wantAttsEqual(t *testing.T, got []slashing.SignedAttestation, want ...slashing.SignedAttestation) {
	t.Helper()
	if len(got) != len(want) || (len(want) > 0 && !reflect.DeepEqual(got, want)) {
		t.Fatalf("attestations %+v, want %+v", got, want)
	}
}

func wantLowEqual(t *testing.T, got, want slashing.LowWatermark) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("low watermark %+v, want %+v", got, want)
	}
}
