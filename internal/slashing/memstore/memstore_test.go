// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package memstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

func TestConformance(t *testing.T) {
	slashingtest.Run(t, func(*testing.T) slashing.Store { return memstore.New() })
}

func TestClosed(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	if err := s.RegisterValidators(ctx, [][]byte{slashingtest.Key(0)}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	id := slashing.KeyIDOf(slashingtest.Key(0))
	for name, err := range map[string]error{
		"SchemaVersion":             second(s.SchemaVersion(ctx)),
		"PinGenesisValidatorsRoot":  second(s.PinGenesisValidatorsRoot(ctx, slashingtest.GVR)),
		"HighWatermark":             second(s.HighWatermark(ctx)),
		"RegisterValidators":        s.RegisterValidators(ctx, [][]byte{slashingtest.Key(1)}),
		"ValidatorStatus":           second(s.ValidatorStatus(ctx, id)),
		"UpdateBlocks":              s.UpdateBlocks(ctx, id, func(slashing.BlockTx) error { return nil }),
		"CompareAndSwapRandaoState": second(s.CompareAndSwapRandaoState(ctx, id, nil, slashing.RandaoState{})),
	} {
		if !errors.Is(err, memstore.ErrClosed) {
			t.Errorf("%s after Close: %v, want ErrClosed", name, err)
		}
	}
}

func TestCanceledContext(t *testing.T) {
	s := memstore.New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.RegisterValidators(ctx, [][]byte{slashingtest.Key(0)}); !errors.Is(err, context.Canceled) {
		t.Fatalf("RegisterValidators with a canceled context: %v, want context.Canceled", err)
	}
}

func second[T any](_ T, err error) error { return err }
