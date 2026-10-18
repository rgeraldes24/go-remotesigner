// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package boltstore_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// B14 (bbolt variant): one pruning run over 4,096 validators that each keep 512 epochs, one attestation per epoch and
// one block every 32 epochs, on the mainnet preset's 128 slots per epoch. The run must take at most 5 minutes, and
// attestation signing during it must keep its p99 within twice the p99 without it. Two histories are pruned:
//
//   - the steady state: 512 epochs plus the six that a 12 h interval adds (12 h is 5.6 QRL epochs), so the run
//     deletes six attestations per validator;
//   - the first run on a history twice the window (1,024 epochs), which deletes 512 attestations per validator.
//
// Signing is the e2e duty shape scaled to 4,096 keys: a burst of 32 concurrent attestations (4,096 keys / 128 slots)
// from 32 distinct keys, four times a second, 240 times the duty rate of 60 s slots.
//
// Timing depends on the machine, so it runs only with REMOTESIGNER_BENCH=1 (make bench-b14).
const (
	b14Validators   = 4096
	b14Kept         = 512
	b14SlotsPer     = 128
	b14BlockEvery   = 32 // epochs between two blocks of one validator
	b14Burst        = 32
	b14BurstEvery   = 250 * time.Millisecond
	b14SeedBatch    = 128
	b14BaselineRuns = 40
)

func TestB14PruningBolt(t *testing.T) {
	if os.Getenv("REMOTESIGNER_BENCH") == "" {
		t.Skip("set REMOTESIGNER_BENCH=1 to run benchmark B14 (make bench-b14)")
	}
	for _, tc := range []struct {
		name  string
		extra int // epochs above the window
	}{
		{"steady state", 6},
		{"first run on twice the window", b14Kept},
	} {
		t.Run(tc.name, func(t *testing.T) { testB14(t, tc.extra) })
	}
}

func testB14(t *testing.T, extra int) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "b14.db")
	s, err := boltstore.Open(path, boltstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	start := time.Now()
	keys, epochs := b14Seed(t, s, b14Kept+extra)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("seeded %d validators x %d epochs (%d attestations, %d blocks) in %s; file %d MiB", b14Validators, epochs,
		b14Validators*epochs, b14Validators*((epochs-1)/b14BlockEvery+1), time.Since(start).Round(time.Second),
		info.Size()>>20)

	e := slashing.NewEngine(s)
	if err := e.RegisterValidators(ctx, keys); err != nil {
		t.Fatal(err)
	}
	// The duties attest the epoch after the history; a key that signs before the pruner reaches it has one more
	// epoch to prune.
	signer := &b14Signer{engine: e, keys: keys, target: uint64(epochs)}

	baseline := signer.bursts(t, b14BaselineRuns, nil)

	done := make(chan struct{})
	var (
		res     slashing.PruneResult
		pruneD  time.Duration
		pruneEr error
	)
	go func() {
		defer close(done)
		t0 := time.Now()
		res, pruneEr = slashing.Prune(ctx, s, slashing.PruneConfig{EpochsToKeep: b14Kept, SlotsPerEpoch: b14SlotsPer})
		pruneD = time.Since(t0)
	}()
	during := signer.bursts(t, 0, done)
	if pruneEr != nil {
		t.Fatal(pruneEr)
	}
	wantAtts := b14Validators * extra
	wantBlocks := b14Validators * b14PrunedBlocks(epochs)
	if res.Validators != b14Validators || res.Blocks != wantBlocks || res.Attestations < wantAtts ||
		res.Attestations > wantAtts+len(baseline)+len(during) {
		t.Fatalf("prune result %+v, want %d validators, %d blocks and %d attestations (plus one per key that signed) "+
			"deleted", res, b14Validators, wantBlocks, wantAtts)
	}
	b50, b99 := percentiles(baseline)
	d50, d99 := percentiles(during)
	t.Logf("B14 prune: %s for %d validators, %d attestations and %d blocks deleted", pruneD.Round(time.Millisecond),
		res.Validators, res.Attestations, res.Blocks)
	t.Logf("B14 signing baseline: %d attestations, p50 %s, p99 %s", len(baseline), b50, b99)
	t.Logf("B14 signing during the prune: %d attestations, p50 %s, p99 %s (%.2fx the baseline p99)", len(during), d50, d99,
		float64(d99)/float64(b99))
	if pruneD > 5*time.Minute {
		t.Errorf("the prune took %s, threshold 5 min", pruneD)
	}
	if d99 > 2*b99 {
		t.Errorf("signing p99 during the prune %s is above twice the baseline p99 %s", d99, b99)
	}
}

// b14PrunedBlocks is how many of one validator's blocks a prune deletes: those more than 512 epochs of slots below
// its newest block.
func b14PrunedBlocks(epochs int) int {
	slot := func(epoch int) int { return epoch*b14SlotsPer + 7 }
	point := slot((epochs-1)/b14BlockEvery*b14BlockEvery) - b14Kept*b14SlotsPer + 1
	n := 0
	for e := 0; e < epochs; e += b14BlockEvery {
		if slot(e) < point {
			n++
		}
	}
	return n
}

// b14Seed writes epochs of history for every validator and returns the keys and epochs.
func b14Seed(t *testing.T, s slashing.Store, epochs int) ([][]byte, int) {
	t.Helper()
	ctx := context.Background()
	keys := make([][]byte, b14Validators)
	ids := make([]slashing.KeyID, b14Validators)
	for i := range keys {
		keys[i] = slashingtest.Key(i)
		ids[i] = slashing.KeyIDOf(keys[i])
	}
	if err := s.RegisterValidators(ctx, keys); err != nil {
		t.Fatal(err)
	}
	for start := 0; start < len(ids); start += b14SeedBatch {
		err := s.UpdateHistory(ctx, ids[start:min(start+b14SeedBatch, len(ids))], func(_ slashing.KeyID, tx slashing.HistoryTx) error {
			for ep := range uint64(epochs) {
				root := slashingtest.RootOf(ep)
				if err := tx.InsertAttestation(slashing.SignedAttestation{SourceEpoch: max(ep, 1) - 1, TargetEpoch: ep,
					SigningRoot: &root}); err != nil {
					return err
				}
				if ep%b14BlockEvery == 0 {
					if err := tx.InsertBlock(slashing.SignedBlock{Slot: ep*b14SlotsPer + 7, SigningRoot: &root}); err != nil {
						return err
					}
				}
			}
			if err := tx.RaiseSlotLowWatermark(7); err != nil {
				return err
			}
			return tx.RaiseEpochLowWatermarks(0, 0)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return keys, epochs
}

// b14Signer signs bursts of attestations, each burst from the next b14Burst keys at the next target epoch.
type b14Signer struct {
	engine *slashing.Engine
	keys   [][]byte
	next   int
	target uint64
}

// bursts runs n bursts, one every b14BurstEvery, or, with n zero, bursts until done is closed, and returns the
// latencies.
func (b *b14Signer) bursts(t *testing.T, n int, done <-chan struct{}) []time.Duration {
	t.Helper()
	var lat []time.Duration
	tick := time.NewTicker(b14BurstEvery)
	defer tick.Stop()
	for i := 0; n == 0 || i < n; i++ {
		lat = append(lat, b.burst(t)...)
		select {
		case <-done:
			return lat
		case <-tick.C:
		}
	}
	return lat
}

func (b *b14Signer) burst(t *testing.T) []time.Duration {
	t.Helper()
	ctx := context.Background()
	lat := make([]time.Duration, b14Burst)
	var wg sync.WaitGroup
	for i := range b14Burst {
		key := b.keys[(b.next+i)%len(b.keys)]
		req := slashing.AttestationRequest{PublicKey: key, GenesisValidatorsRoot: slashingtest.GVR,
			SourceEpoch: b.target - 1, TargetEpoch: b.target, SigningRoot: slashingtest.RootOf(b.target)}
		wg.Go(func() {
			t0 := time.Now()
			d, err := b.engine.CheckAndRecordAttestation(ctx, req)
			lat[i] = time.Since(t0)
			if err != nil || !d.Allowed {
				t.Errorf("attestation refused: %+v %v", d, err)
			}
		})
	}
	wg.Wait()
	b.next += b14Burst
	if b.next >= len(b.keys) {
		b.next, b.target = 0, b.target+1
	}
	return lat
}

func percentiles(ds []time.Duration) (p50, p99 time.Duration) {
	s := slices.Clone(ds)
	slices.Sort(s)
	at := func(p float64) time.Duration { return s[min(len(s)-1, int(p*float64(len(s))))] }
	return at(0.50).Round(10 * time.Microsecond), at(0.99).Round(10 * time.Microsecond)
}
