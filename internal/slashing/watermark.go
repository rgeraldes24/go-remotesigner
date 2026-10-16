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
// commandline/src/main/java/tech/pegasys/web3signer/commandline/subcommands/Eth2WatermarkRepairSubCommand.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package slashing

import (
	"context"
	"errors"
	"fmt"
)

// DefaultRepairBatch is how many validators one watermark-repair transaction covers.
const DefaultRepairBatch = 64

// ErrLowerWatermark: a watermark repair would lower a validator's low watermark.
var ErrLowerWatermark = errors.New("slashing: a low watermark can only be raised")

// LowerWatermarkError reports the validators whose low watermark is above a requested repair.
type LowerWatermarkError struct {
	// Validators is how many validators the repair would lower.
	Validators int
	// Example is one of them, and Low its low watermark.
	Example KeyID
	Low     LowWatermark
}

func (e *LowerWatermarkError) Error() string {
	return fmt.Sprintf("the repair would lower the low watermark of %d validator(s), for example %s at slot %s, "+
		"source epoch %s and target epoch %s; low watermarks can only be raised",
		e.Validators, e.Example, optional(e.Low.Slot), optional(e.Low.SourceEpoch), optional(e.Low.TargetEpoch))
}

// Is makes errors.Is(err, ErrLowerWatermark) hold.
func (e *LowerWatermarkError) Is(target error) bool { return target == ErrLowerWatermark }

func optional(v *uint64) string {
	if v == nil {
		return "unset"
	}
	return fmt.Sprint(*v)
}

// RepairLowWatermarks raises the low watermark of every registered validator to slot and to source = target =
// epoch, so that no block at or below slot and no attestation with a source below epoch or a target at or below it
// is signed: the fallback when no slashing-protection history can be imported. It returns how many validators it
// updated.
//
// It changes nothing, and returns a *LowerWatermarkError, when it would lower any validator's watermark; and it
// returns ErrWatermarkConflict when slot or epoch is above the high watermark. Validators are updated in batches,
// each in one transaction; each transaction checks again, so a watermark that moved concurrently is never lowered.
func RepairLowWatermarks(ctx context.Context, s Store, slot, epoch uint64) (int, error) {
	high, err := s.HighWatermark(ctx)
	if err != nil {
		return 0, err
	}
	if (high.Slot != nil && slot > *high.Slot) || (high.Epoch != nil && epoch > *high.Epoch) {
		return 0, fmt.Errorf("%w: slot %d and epoch %d must not exceed the high watermark (slot %s, epoch %s)",
			ErrWatermarkConflict, slot, epoch, optional(high.Slot), optional(high.Epoch))
	}
	var (
		ids      []KeyID
		lowering *LowerWatermarkError
	)
	err = s.ViewHistory(ctx, func(v HistoryView) error {
		return v.Validators(func(id KeyID, _ []byte) error {
			low, err := v.LowWatermark(id)
			if err != nil {
				return err
			}
			if lowers(low, slot, epoch) {
				if lowering == nil {
					lowering = &LowerWatermarkError{Example: id, Low: low}
				}
				lowering.Validators++
			}
			ids = append(ids, id)
			return nil
		})
	})
	if err != nil {
		return 0, err
	}
	if lowering != nil {
		return 0, lowering
	}
	for start := 0; start < len(ids); start += DefaultRepairBatch {
		chunk := ids[start:min(start+DefaultRepairBatch, len(ids))]
		err := s.UpdateHistory(ctx, chunk, func(id KeyID, tx HistoryTx) error {
			low, err := tx.LowWatermark()
			if err != nil {
				return err
			}
			if lowers(low, slot, epoch) {
				return &LowerWatermarkError{Validators: 1, Example: id, Low: low}
			}
			if err := tx.RaiseSlotLowWatermark(slot); err != nil {
				return err
			}
			return tx.RaiseEpochLowWatermarks(epoch, epoch)
		})
		if err != nil {
			return start, err
		}
	}
	return len(ids), nil
}

// lowers reports whether setting slot and source = target = epoch would lower any part of low.
func lowers(low LowWatermark, slot, epoch uint64) bool {
	return (low.Slot != nil && *low.Slot > slot) ||
		(low.SourceEpoch != nil && *low.SourceEpoch > epoch) ||
		(low.TargetEpoch != nil && *low.TargetEpoch > epoch)
}
