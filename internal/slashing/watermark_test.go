// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package slashing_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

func TestRepairLowWatermarks(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		seed(t, s, 0, history{}) // no watermark yet
		seed(t, s, 1, history{low: low(10, 3, 4)})
		seed(t, s, 2, history{low: slashing.LowWatermark{Slot: slashingtest.U64(20)}})
		n, err := slashing.RepairLowWatermarks(bg, s, 20, 4)
		must(t, err)
		if n != 3 {
			t.Fatalf("repaired %d validators, want 3", n)
		}
		for i := range 3 {
			if got := read(t, s, i).low; !reflect.DeepEqual(got, low(20, 4, 4)) {
				t.Fatalf("validator %d: %+v", i, got)
			}
		}
		// Repeating the same repair is not lowering.
		_, err = slashing.RepairLowWatermarks(bg, s, 20, 4)
		must(t, err)
	})
}

func TestRepairRefusesToLower(t *testing.T) {
	for _, tc := range []struct {
		name        string
		slot, epoch uint64
	}{
		{"slot", 9, 100},
		{"target epoch", 100, 6},
		{"source epoch", 100, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forEachStore(t, func(t *testing.T, s slashing.Store) {
				seed(t, s, 0, history{low: low(1, 1, 1)})
				seed(t, s, 1, history{low: low(10, 5, 7)})
				_, err := slashing.RepairLowWatermarks(bg, s, tc.slot, tc.epoch)
				var lerr *slashing.LowerWatermarkError
				if !errors.Is(err, slashing.ErrLowerWatermark) || !errors.As(err, &lerr) || lerr.Validators != 1 ||
					lerr.Example != keyID(1) {
					t.Fatalf("lowering repair: %v", err)
				}
				// Nothing changed, not even for the validator the repair would have raised.
				if got := read(t, s, 0).low; !reflect.DeepEqual(got, low(1, 1, 1)) {
					t.Fatalf("validator 0 changed: %+v", got)
				}
			})
		})
	}
}

func TestRepairRespectsTheHighWatermark(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		seed(t, s, 0, history{low: low(1, 1, 1)})
		_, err := s.PinGenesisValidatorsRoot(bg, slashingtest.GVR)
		must(t, err)
		must(t, s.SetHighWatermark(bg, slashing.HighWatermark{Epoch: slashingtest.U64(10), Slot: slashingtest.U64(100)}))
		for _, tc := range [][2]uint64{{101, 5}, {50, 11}} {
			if _, err := slashing.RepairLowWatermarks(bg, s, tc[0], tc[1]); !errors.Is(err, slashing.ErrWatermarkConflict) {
				t.Fatalf("repair to slot %d, epoch %d above the high watermark: %v", tc[0], tc[1], err)
			}
		}
		_, err = slashing.RepairLowWatermarks(bg, s, 100, 10)
		must(t, err)
		if got := read(t, s, 0).low; !reflect.DeepEqual(got, low(100, 10, 10)) {
			t.Fatalf("repair at the high watermark: %+v", got)
		}
	})
}

func TestRepairEmptyStore(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		if n, err := slashing.RepairLowWatermarks(bg, s, 1, 1); n != 0 || err != nil {
			t.Fatalf("empty store: %d %v", n, err)
		}
	})
}
