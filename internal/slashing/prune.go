// Copyright 2021 ConsenSys AG.
// Copyright 2023 ConsenSys AG.
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
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbPruner.java and
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DBSlashingProtectionPruner.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package slashing

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"
)

// DefaultPruneBatch is how many validators one pruning transaction covers.
const DefaultPruneBatch = 16

// PruneConfig configures a pruning run.
type PruneConfig struct {
	// EpochsToKeep is how many epochs of attestations, and of blocks, are kept below each validator's newest
	// record. It must be positive.
	EpochsToKeep uint64
	// SlotsPerEpoch is the network's SLOTS_PER_EPOCH. It must be positive.
	SlotsPerEpoch uint64
	// Batch is how many validators share one transaction; zero means DefaultPruneBatch.
	Batch int
	// Pace, when positive, makes the run rest after each transaction for Pace times as long as the transaction
	// took, so that a database the signers share spends at most 1/(1+Pace) of its time on pruning.
	Pace float64
}

// PruneResult counts what a pruning run did.
type PruneResult struct {
	Validators   int // validators visited
	Blocks       int // blocks deleted
	Attestations int // attestations deleted
}

// Prune prunes every validator in the store, not only the keys this process has loaded: at startup no key is
// loaded yet, and a key that is no longer loaded keeps its history bounded too.
//
// For each validator, in one transaction holding its block and attestation locks: the low watermark is first raised
// to the oldest record that is kept, never lowered, and the records below the watermark are then deleted. A
// validator without a low watermark, or without records, is left alone. The watermark only moves to a record that
// exists; when none is at or above the computed point (after a watermark repair beyond every record), the watermark
// stays where it is and the records below it go.
func Prune(ctx context.Context, s Store, cfg PruneConfig) (PruneResult, error) {
	if cfg.EpochsToKeep == 0 || cfg.SlotsPerEpoch == 0 {
		return PruneResult{}, fmt.Errorf("slashing: prune needs positive epochs to keep and slots per epoch, got %d and %d",
			cfg.EpochsToKeep, cfg.SlotsPerEpoch)
	}
	batch := cfg.Batch
	if batch <= 0 {
		batch = DefaultPruneBatch
	}
	slotsToKeep := uint64(math.MaxUint64)
	if cfg.EpochsToKeep <= math.MaxUint64/cfg.SlotsPerEpoch {
		slotsToKeep = cfg.EpochsToKeep * cfg.SlotsPerEpoch
	}
	ids, err := validatorIDs(ctx, s)
	if err != nil {
		return PruneResult{}, err
	}
	var (
		res  PruneResult
		took time.Duration // the last transaction's
	)
	for start := 0; start < len(ids); start += batch {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if start > 0 && cfg.Pace > 0 {
			if err := rest(ctx, time.Duration(cfg.Pace*float64(took))); err != nil {
				return res, err
			}
		}
		chunk := ids[start:min(start+batch, len(ids))]
		began := time.Now()
		// The counts are kept per validator and set, not added, so a retried transaction does not count twice.
		deleted := make(map[KeyID][2]int, len(chunk))
		err := s.UpdateHistory(ctx, chunk, func(id KeyID, tx HistoryTx) error {
			b, err := pruneBlocks(tx, slotsToKeep)
			if err != nil {
				return err
			}
			a, err := pruneAttestations(tx, cfg.EpochsToKeep)
			deleted[id] = [2]int{b, a}
			return err
		})
		if err != nil {
			return res, fmt.Errorf("prune slashing-protection history: %w", err)
		}
		took = time.Since(began)
		res.Validators += len(chunk)
		for _, d := range deleted {
			res.Blocks += d[0]
			res.Attestations += d[1]
		}
	}
	return res, nil
}

// rest waits for d, or until ctx ends.
func rest(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// pruneBlocks moves the slot watermark up to the oldest kept block and deletes the blocks below it.
func pruneBlocks(tx HistoryTx, slotsToKeep uint64) (int, error) {
	low, err := tx.LowWatermark()
	if err != nil || low.Slot == nil {
		return 0, err
	}
	last, found, err := tx.LastBlock()
	if err != nil || !found {
		return 0, err
	}
	nearest, found, err := tx.NearestBlock(pruningPoint(slotsToKeep, last.Slot, *low.Slot))
	if err != nil {
		return 0, err
	}
	if found {
		if err := keepConflict(tx.RaiseSlotLowWatermark(nearest.Slot)); err != nil {
			return 0, err
		}
	}
	return tx.PruneBlocks()
}

// pruneAttestations moves the epoch watermarks up to the oldest kept attestation and deletes the attestations below
// the target watermark. The source watermark takes that attestation's source epoch unless it is already higher, so
// neither epoch is ever lowered.
func pruneAttestations(tx HistoryTx, epochsToKeep uint64) (int, error) {
	low, err := tx.LowWatermark()
	if err != nil || low.TargetEpoch == nil {
		return 0, err
	}
	last, found, err := tx.LastAttestation()
	if err != nil || !found {
		return 0, err
	}
	nearest, found, err := tx.NearestAttestation(pruningPoint(epochsToKeep, last.TargetEpoch, *low.TargetEpoch))
	if err != nil {
		return 0, err
	}
	if found {
		source := max(nearest.SourceEpoch, *low.SourceEpoch)
		if err := keepConflict(tx.RaiseEpochLowWatermarks(source, nearest.TargetEpoch)); err != nil {
			return 0, err
		}
	}
	return tx.PruneAttestations()
}

// pruningPoint is the lowest slot or epoch to keep: keep values up to and including newest, but never below the
// current watermark.
func pruningPoint(keep, newest, watermark uint64) uint64 {
	point := uint64(0)
	if newest >= keep {
		point = newest - keep + 1
	}
	return max(point, watermark)
}

// keepConflict turns a watermark raise refused by the high watermark into no raise: pruning then deletes only
// below the current watermark.
func keepConflict(err error) error {
	if errors.Is(err, ErrWatermarkConflict) {
		return nil
	}
	return err
}

// validatorIDs lists the store's validators in KeyID order.
func validatorIDs(ctx context.Context, s Store) ([]KeyID, error) {
	var ids []KeyID
	err := s.ViewHistory(ctx, func(v HistoryView) error {
		return v.Validators(func(id KeyID, _ []byte) error {
			ids = append(ids, id)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("list slashing-protection validators: %w", err)
	}
	return ids, nil
}
