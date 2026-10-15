// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package slashingtest

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// RunRandao checks the RandaoStore contract: per-validator frontiers with compare-and-swap semantics.
func RunRandao(t *testing.T, newStore Factory) {
	ctx := context.Background()
	s1 := slashing.RandaoState{Index: 1 << 20, Reveal: RootOf(1), LastSlot: 10}
	s2 := slashing.RandaoState{Index: 1<<20 - 1, Reveal: RootOf(2), LastSlot: 11}
	s3 := slashing.RandaoState{Index: 7, Reveal: RootOf(3), LastSlot: 12}

	t.Run("unregistered key", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		if _, _, err := s.RandaoState(ctx, id(1)); !errors.Is(err, slashing.ErrValidatorNotRegistered) {
			t.Errorf("RandaoState: %v, want ErrValidatorNotRegistered", err)
		}
		if _, err := s.CompareAndSwapRandaoState(ctx, id(1), nil, s1); !errors.Is(err, slashing.ErrValidatorNotRegistered) {
			t.Errorf("CompareAndSwapRandaoState: %v, want ErrValidatorNotRegistered", err)
		}
		if err := s.DeleteRandaoState(ctx, id(1)); !errors.Is(err, slashing.ErrValidatorNotRegistered) {
			t.Errorf("DeleteRandaoState: %v, want ErrValidatorNotRegistered", err)
		}
	})

	t.Run("compare and swap", func(t *testing.T) {
		s := openWithKeys(t, newStore, 2)
		wantState(t, s, 0, nil)
		steps := []struct {
			old, next *slashing.RandaoState
			swapped   bool
			after     *slashing.RandaoState
		}{
			{nil, &s1, true, &s1},  // first use
			{nil, &s2, false, &s1}, // a state exists
			{&s2, &s3, false, &s1}, // stale old
			{&s1, &s2, true, &s2},  // frontier moves one layer
			{&s1, &s3, false, &s2}, // lost race
			{&s2, &s2, true, &s2},  // idempotent rewrite
		}
		for i, st := range steps {
			swapped, err := s.CompareAndSwapRandaoState(ctx, id(0), st.old, *st.next)
			must(t, err)
			if swapped != st.swapped {
				t.Fatalf("step %d: swapped %v, want %v", i, swapped, st.swapped)
			}
			wantState(t, s, 0, st.after)
		}
		wantState(t, s, 1, nil)
	})

	t.Run("delete", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		must(t, s.DeleteRandaoState(ctx, id(0)))
		if _, err := s.CompareAndSwapRandaoState(ctx, id(0), nil, s1); err != nil {
			t.Fatal(err)
		}
		must(t, s.DeleteRandaoState(ctx, id(0)))
		wantState(t, s, 0, nil)
		swapped, err := s.CompareAndSwapRandaoState(ctx, id(0), nil, s3)
		must(t, err)
		if !swapped {
			t.Fatal("first use after a reset did not swap")
		}
		wantState(t, s, 0, &s3)
	})

	t.Run("concurrent swaps from one state", func(t *testing.T) {
		s := openWithKeys(t, newStore, 1)
		if _, err := s.CompareAndSwapRandaoState(ctx, id(0), nil, s1); err != nil {
			t.Fatal(err)
		}
		var wins atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := range 100 {
			wg.Go(func() {
				<-start
				next := slashing.RandaoState{Index: s1.Index - 1, Reveal: RootOf(uint64(i)), LastSlot: s1.LastSlot + 1}
				swapped, err := s.CompareAndSwapRandaoState(ctx, id(0), &s1, next)
				if err != nil {
					t.Error(err)
				}
				if swapped {
					wins.Add(1)
				}
			})
		}
		close(start)
		wg.Wait()
		if n := wins.Load(); n != 1 {
			t.Fatalf("%d swaps succeeded, want exactly 1", n)
		}
	})
}

func wantState(t *testing.T, s slashing.Store, key int, want *slashing.RandaoState) {
	t.Helper()
	got, ok, err := s.RandaoState(context.Background(), id(key))
	must(t, err)
	switch {
	case want == nil && ok:
		t.Fatalf("key %d: state %+v, want none", key, got)
	case want != nil && (!ok || got != *want):
		t.Fatalf("key %d: state %+v (present %v), want %+v", key, got, ok, *want)
	}
}
