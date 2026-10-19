// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package slashing_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// A backend may run an UpdateHistory function again when it retries the transaction, as a Postgres store does. The
// counts of a pruning run, and what it deletes, are then the same as without the retry.
func TestPruneThroughARetriedTransaction(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		keys := [][]byte{slashingtest.Key(0), slashingtest.Key(1), slashingtest.Key(2)}
		must(t, s.RegisterValidators(bg, keys))
		for _, k := range keys {
			var blocks []slashing.SignedBlock
			var atts []slashing.SignedAttestation
			for i := range uint64(20) {
				blocks = append(blocks, slashing.SignedBlock{Slot: i, SigningRoot: slashingtest.RootPtr(i)})
				atts = append(atts, slashing.SignedAttestation{SourceEpoch: i, TargetEpoch: i + 1, SigningRoot: slashingtest.RootPtr(i)})
			}
			must(t, slashingtest.ImportBlocks(bg, s, slashing.KeyIDOf(k), blocks...))
			must(t, slashingtest.ImportAttestations(bg, s, slashing.KeyIDOf(k), atts...))
		}
		// Five epochs of one slot are kept below each newest record: 15 blocks and 15 attestations go per validator.
		res, err := slashing.Prune(bg, slashingtest.Retrying(s), slashing.PruneConfig{EpochsToKeep: 5, SlotsPerEpoch: 1, Batch: 2})
		must(t, err)
		if want := (slashing.PruneResult{Validators: 3, Blocks: 45, Attestations: 45}); res != want {
			t.Fatalf("prune through a retried transaction: %+v, want %+v", res, want)
		}
		if res, err = slashing.Prune(bg, s, slashing.PruneConfig{EpochsToKeep: 5, SlotsPerEpoch: 1}); err != nil || res.Blocks+res.Attestations != 0 {
			t.Fatalf("a second run: %+v, %v", res, err)
		}
	})
}

// slowHistory is a store whose history transactions take at least d each.
type slowHistory struct {
	slashing.Store
	d     time.Duration
	calls int
}

func (s *slowHistory) UpdateHistory(ctx context.Context, ids []slashing.KeyID,
	fn func(slashing.KeyID, slashing.HistoryTx) error) error {
	s.calls++
	time.Sleep(s.d)
	return s.Store.UpdateHistory(ctx, ids, fn)
}

// With a pace, a pruning run rests after each transaction for that many times as long as the transaction took, and
// ends early, between transactions, when its context ends.
func TestPrunePace(t *testing.T) {
	s := memstore.New()
	keys := [][]byte{slashingtest.Key(0), slashingtest.Key(1), slashingtest.Key(2)}
	must(t, s.RegisterValidators(bg, keys))
	slow := &slowHistory{Store: s, d: 20 * time.Millisecond}
	began := time.Now()
	res, err := slashing.Prune(bg, slow, slashing.PruneConfig{EpochsToKeep: 5, SlotsPerEpoch: 1, Batch: 1, Pace: 2})
	took := time.Since(began)
	must(t, err)
	// Three transactions of at least 20 ms, and two rests of at least 40 ms between them.
	if res.Validators != 3 || took < 140*time.Millisecond {
		t.Fatalf("paced run: %+v in %v, want 3 validators in at least 140ms", res, took)
	}

	ctx, cancel := context.WithCancel(bg)
	slow.calls = 0
	slow.d = 50 * time.Millisecond
	time.AfterFunc(250*time.Millisecond, cancel)
	res, err = slashing.Prune(ctx, slow, slashing.PruneConfig{EpochsToKeep: 5, SlotsPerEpoch: 1, Batch: 1, Pace: 100})
	if !errors.Is(err, context.Canceled) || res.Validators != 1 || slow.calls != 1 {
		t.Fatalf("a run cancelled while it rests: %+v, %v after %d transactions; want one validator and Canceled", res,
			err, slow.calls)
	}
}
