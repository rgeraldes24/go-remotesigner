// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package slashingtest_test

import (
	"context"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// TestImportAttestationsRaisesEpochsIndependently checks that the import helper raises each low-watermark epoch to
// max(current, imported minimum) on its own, as an EIP-3076 import does.
func TestImportAttestationsRaisesEpochsIndependently(t *testing.T) {
	tests := []struct {
		name               string
		current            *[2]uint64 // source, target; nil means no watermark
		atts               []slashing.SignedAttestation
		wantSource, wantTo uint64
	}{
		{"no watermark", nil, []slashing.SignedAttestation{att(4, 9), att(6, 8)}, 4, 8},
		{"both above", &[2]uint64{2, 3}, []slashing.SignedAttestation{att(4, 9)}, 4, 9},
		{"both below", &[2]uint64{5, 10}, []slashing.SignedAttestation{att(1, 2)}, 5, 10},
		{"source above, target below", &[2]uint64{5, 10}, []slashing.SignedAttestation{att(6, 8)}, 6, 10},
		{"source below, target above", &[2]uint64{5, 10}, []slashing.SignedAttestation{att(4, 12)}, 5, 12},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			s := memstore.New()
			t.Cleanup(func() { _ = s.Close() })
			if err := s.RegisterValidators(ctx, [][]byte{slashingtest.Key(0)}); err != nil {
				t.Fatal(err)
			}
			id := slashing.KeyIDOf(slashingtest.Key(0))
			if tc.current != nil {
				if err := s.UpdateAttestations(ctx, id, func(tx slashing.AttestationTx) error {
					return tx.RaiseEpochLowWatermarks(tc.current[0], tc.current[1])
				}); err != nil {
					t.Fatal(err)
				}
			}
			if err := slashingtest.ImportAttestations(ctx, s, id, tc.atts...); err != nil {
				t.Fatal(err)
			}
			var low slashing.LowWatermark
			if err := s.UpdateAttestations(ctx, id, func(tx slashing.AttestationTx) error {
				var err error
				low, err = tx.LowWatermark()
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if low.SourceEpoch == nil || low.TargetEpoch == nil {
				t.Fatalf("low-watermark epochs unset, want %d %d", tc.wantSource, tc.wantTo)
			}
			if *low.SourceEpoch != tc.wantSource || *low.TargetEpoch != tc.wantTo {
				t.Errorf("low watermark source %d target %d, want %d %d",
					*low.SourceEpoch, *low.TargetEpoch, tc.wantSource, tc.wantTo)
			}
		})
	}
}

func att(source, target uint64) slashing.SignedAttestation {
	return slashing.SignedAttestation{SourceEpoch: source, TargetEpoch: target, SigningRoot: slashingtest.RootPtr(target)}
}
