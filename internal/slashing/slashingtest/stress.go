// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package slashingtest

import (
	"context"
	"sync"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// StressCalls is the number of concurrent check-and-record calls in each stress test.
const StressCalls = 1000

// RunStress fires StressCalls concurrent check-and-record calls at one key and checks that exactly one message
// is accepted per slot or target epoch, and that it is the one recorded. Run it with -race.
func RunStress(t *testing.T, newStore Factory) {
	t.Run("blocks at one slot", func(t *testing.T) {
		got := stress(t, newStore, func(e *slashing.Engine, i int) (slashing.Decision, error) {
			return e.CheckAndRecordBlock(context.Background(), blockReq(7, uint64(i)))
		})
		checkSingleWinner(t, got, func(s slashing.Store) record { return mustBlockAt(t, s, 0, 7) })
	})
	t.Run("attestations at one target", func(t *testing.T) {
		got := stress(t, newStore, func(e *slashing.Engine, i int) (slashing.Decision, error) {
			return e.CheckAndRecordAttestation(context.Background(), attReq(3, 9, uint64(i)))
		})
		checkSingleWinner(t, got, func(s slashing.Store) record { return mustAttestationAt(t, s, 0, 9) })
	})
	t.Run("few distinct roots", func(t *testing.T) {
		// Callers share 8 roots: every accepted call must carry the winner's root, and exactly one is not a repeat.
		got := stress(t, newStore, func(e *slashing.Engine, i int) (slashing.Decision, error) {
			return e.CheckAndRecordBlock(context.Background(), blockReq(7, uint64(i%8)))
		})
		var winners int
		roots := map[uint64]bool{}
		for _, r := range got.results {
			if r.d.Allowed {
				roots[uint64(r.i%8)] = true
				if !r.d.Repeat {
					winners++
				}
			}
		}
		if winners != 1 || len(roots) != 1 {
			t.Fatalf("%d non-repeat acceptances over %d distinct roots, want 1 and 1", winners, len(roots))
		}
		rec := mustBlockAt(t, got.store, 0, 7)
		for root := range roots {
			if rec.root == nil || *rec.root != RootOf(root) {
				t.Fatalf("recorded root %v, want the accepted root %d", rec.root, root)
			}
		}
	})
	t.Run("blocks over ten slots", func(t *testing.T) {
		got := stress(t, newStore, func(e *slashing.Engine, i int) (slashing.Decision, error) {
			return e.CheckAndRecordBlock(context.Background(), blockReq(100+uint64(i%10), uint64(i)))
		})
		perSlot := map[uint64][]int{}
		for _, r := range got.results {
			if r.d.Allowed {
				perSlot[100+uint64(r.i%10)] = append(perSlot[100+uint64(r.i%10)], r.i)
			}
		}
		if len(perSlot) == 0 {
			t.Fatal("no block accepted")
		}
		for slot, winners := range perSlot {
			if len(winners) != 1 {
				t.Fatalf("slot %d: %d acceptances, want 1", slot, len(winners))
			}
			rec := mustBlockAt(t, got.store, 0, slot)
			if rec.root == nil || *rec.root != RootOf(uint64(winners[0])) {
				t.Fatalf("slot %d: recorded root %v, want the accepted root %d", slot, rec.root, winners[0])
			}
		}
	})
}

type stressResult struct {
	i int
	d slashing.Decision
}

type stressRun struct {
	store   slashing.Store
	results []stressResult
}

// stress runs call StressCalls times concurrently for key 0, releasing all goroutines at once.
func stress(t *testing.T, newStore Factory, call func(*slashing.Engine, int) (slashing.Decision, error)) stressRun {
	t.Helper()
	s := open(t, newStore)
	e := slashing.NewEngine(s)
	must(t, e.RegisterValidators(context.Background(), [][]byte{Key(0)}))

	results := make([]stressResult, StressCalls)
	errs := make([]error, StressCalls)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range StressCalls {
		wg.Go(func() {
			<-start
			d, err := call(e, i)
			results[i], errs[i] = stressResult{i: i, d: d}, err
		})
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	return stressRun{store: s, results: results}
}

// checkSingleWinner checks that exactly one call with a distinct root was accepted and that its root is recorded.
func checkSingleWinner(t *testing.T, run stressRun, recorded func(slashing.Store) record) {
	t.Helper()
	var winners []int
	for _, r := range run.results {
		if r.d.Allowed {
			winners = append(winners, r.i)
		}
	}
	if len(winners) != 1 {
		t.Fatalf("%d calls accepted, want exactly 1", len(winners))
	}
	rec := recorded(run.store)
	if rec.root == nil || *rec.root != RootOf(uint64(winners[0])) {
		t.Fatalf("recorded root %v, want the accepted root %d", rec.root, winners[0])
	}
}

func blockReq(slot, root uint64) slashing.BlockRequest {
	return slashing.BlockRequest{PublicKey: Key(0), GenesisValidatorsRoot: GVR, Slot: slot, SigningRoot: RootOf(root)}
}

func attReq(source, target, root uint64) slashing.AttestationRequest {
	return slashing.AttestationRequest{
		PublicKey: Key(0), GenesisValidatorsRoot: GVR, SourceEpoch: source, TargetEpoch: target, SigningRoot: RootOf(root),
	}
}

func mustBlockAt(t *testing.T, s slashing.Store, key int, slot uint64) record {
	t.Helper()
	r, err := blockAt(context.Background(), s, key, slot)
	must(t, err)
	return r
}

func mustAttestationAt(t *testing.T, s slashing.Store, key int, target uint64) record {
	t.Helper()
	r, err := attestationAt(context.Background(), s, key, target)
	must(t, err)
	return r
}
