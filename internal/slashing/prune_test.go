// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package slashing_test

import (
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
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
