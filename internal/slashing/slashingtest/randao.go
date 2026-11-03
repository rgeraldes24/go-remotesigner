// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package slashingtest

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// RunRandao checks the RandaoStore contract: per-validator frontiers with compare-and-swap semantics, which never
// move for a disabled validator.
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

	t.Run("a disabled validator's frontier does not move", func(t *testing.T) { runRandaoDisabled(t, newStore) })
	t.Run("disabling is serialised with the frontier commit", func(t *testing.T) { runRandaoDisableRace(t, newStore) })
}

// runRandaoDisabled checks that a compare-and-set for a key disabled on purpose or by an import fails with
// ErrValidatorDisabled and stores nothing, whether a frontier is stored or not, and that it stores again once the
// key is enabled.
func runRandaoDisabled(t *testing.T, newStore Factory) {
	s := openWithKeys(t, newStore, 2)
	must(t, s.RegisterValidatorsDisabled(bg, [][]byte{Key(2)}))
	s1 := slashing.RandaoState{Index: 1 << 20, Reveal: RootOf(1), LastSlot: 10}
	s2 := nextFrontier(s1)
	swapped, err := s.CompareAndSwapRandaoState(bg, id(0), nil, s1)
	if err != nil || !swapped {
		t.Fatalf("first use: swapped %v, %v", swapped, err)
	}
	must(t, s.SetValidatorEnabled(bg, id(0), false))
	must(t, s.SetValidatorEnabled(bg, id(1), false))
	for _, c := range []struct {
		key int
		old *slashing.RandaoState
	}{{0, &s1}, {0, nil}, {1, nil}, {2, nil}} {
		wantDisabled(t, s, c.key, c.old, s2)
	}
	wantState(t, s, 0, &s1)
	wantState(t, s, 1, nil)
	wantState(t, s, 2, nil)

	must(t, s.SetValidatorEnabled(bg, id(0), true))
	if swapped, err := s.CompareAndSwapRandaoState(bg, id(0), &s1, s2); err != nil || !swapped {
		t.Fatalf("after enabling the key again: swapped %v, %v; want stored", swapped, err)
	}
	wantState(t, s, 0, &s2)
}

// randaoDisables are the ways a validator is disabled: on purpose by SetValidatorEnabled (consensus
// disable-validator) or by a history transaction's SetEnabled (a keymanager DELETE), and by an import whose element
// failed (DisableForImport). The history transactions cover a second validator too, named first, and call during
// once the key is disabled: what during returns is what their function returns.
var randaoDisables = []struct {
	name    string
	history bool // a history transaction, which the suite can hold open
	disable func(s slashing.Store, during func() error) error
}{
	{"SetValidatorEnabled", false, func(s slashing.Store, _ func() error) error {
		return s.SetValidatorEnabled(bg, id(0), false)
	}},
	{"history SetEnabled", true, func(s slashing.Store, during func() error) error {
		return historyDisable(s, during, func(tx slashing.HistoryTx) error { return tx.SetEnabled(false) })
	}},
	{"history DisableForImport", true, func(s slashing.Store, during func() error) error {
		return historyDisable(s, during, func(tx slashing.HistoryTx) error { return tx.DisableForImport() })
	}},
}

// historyDisable disables key 0 with disable in a history transaction over keys 1 and 0, and then calls during.
func historyDisable(s slashing.Store, during func() error, disable func(slashing.HistoryTx) error) error {
	return s.UpdateHistory(bg, []slashing.KeyID{id(1), id(0)}, func(k slashing.KeyID, tx slashing.HistoryTx) error {
		if k != id(0) {
			return nil
		}
		if err := disable(tx); err != nil {
			return err
		}
		if during != nil {
			return during()
		}
		return nil
	})
}

// runRandaoDisableRace checks that every way of disabling a validator is serialised with the commit of its RANDAO
// frontier, as SetValidatorEnabled is with its block and attestation transactions (runEnabledSerialisation), so that
// the reveal service's condition 5 holds when the frontier moves, not only when it was checked:
//   - a reveal that read the key enabled commits its frontier after the key was disabled: the compare-and-set refuses
//     with ErrValidatorDisabled, which the service answers with 412 VALIDATOR_DISABLED;
//   - a compare-and-set does not return while a history transaction that disables the key is open, then refuses once
//     it commits, and stores once one that rolls back has ended;
//   - compare-and-sets racing a disable: once the disable has returned, the frontier no longer moves.
func runRandaoDisableRace(t *testing.T, newStore Factory) {
	for _, d := range randaoDisables {
		t.Run(d.name, func(t *testing.T) {
			s := openWithKeys(t, newStore, 2)
			first := slashing.RandaoState{Index: 1 << 20, Reveal: RootOf(1), LastSlot: 10}
			if swapped, err := s.CompareAndSwapRandaoState(bg, id(0), nil, first); err != nil || !swapped {
				t.Fatalf("first use: swapped %v, %v", swapped, err)
			}
			t.Run("disabled after the status was read", func(t *testing.T) {
				st, err := s.ValidatorStatus(bg, id(0))
				must(t, err)
				if !st.Enabled {
					t.Fatal("the key is not enabled")
				}
				cur := currentFrontier(t, s)
				must(t, d.disable(s, nil))
				wantDisabled(t, s, 0, &cur, nextFrontier(cur))
				wantState(t, s, 0, &cur)
			})
			if d.history {
				for _, tc := range []struct {
					name   string
					commit bool
				}{{"open disable commits", true}, {"open disable rolls back", false}} {
					t.Run(tc.name, func(t *testing.T) {
						must(t, s.SetValidatorEnabled(bg, id(0), true))
						disableHeldOpen(t, s, d.disable, tc.commit)
					})
				}
			}
			t.Run("compare-and-sets racing the disable", func(t *testing.T) {
				must(t, s.SetValidatorEnabled(bg, id(0), true))
				disableRacing(t, s, d.disable)
			})
		})
	}
}

// disableHeldOpen holds a history transaction that disabled key 0 open while a compare-and-set of the key's frontier
// starts, and then commits it or rolls it back.
func disableHeldOpen(t *testing.T, s slashing.Store, disable func(slashing.Store, func() error) error, commit bool) {
	cur := currentFrontier(t, s)
	errAbort := errors.New("abort")
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	disableDone := make(chan error, 1)
	go func() {
		disableDone <- disable(s, func() error {
			once.Do(func() { close(entered) })
			<-release
			if !commit {
				return errAbort
			}
			return nil
		})
	}()
	select {
	case <-entered:
	case err := <-disableDone:
		t.Fatalf("the disable returned without calling its function: %v", err)
	}

	type result struct {
		swapped bool
		err     error
	}
	swapDone := make(chan result, 1)
	go func() {
		swapped, err := s.CompareAndSwapRandaoState(bg, id(0), &cur, nextFrontier(cur))
		swapDone <- result{swapped, err}
	}()
	select {
	case r := <-swapDone:
		t.Errorf("CompareAndSwapRandaoState returned (swapped %v, %v) while a disable was open", r.swapped, r.err)
		swapDone <- r
	case <-time.After(enabledWait):
	}
	close(release)

	err := <-disableDone
	r := <-swapDone
	if commit {
		must(t, err)
		if !errors.Is(r.err, slashing.ErrValidatorDisabled) || r.swapped {
			t.Errorf("compare-and-set after the disable committed: swapped %v, %v; want ErrValidatorDisabled",
				r.swapped, r.err)
		}
		wantState(t, s, 0, &cur)
		return
	}
	if !errors.Is(err, errAbort) {
		t.Fatalf("the rolled-back disable returned %v", err)
	}
	if r.err != nil || !r.swapped {
		t.Errorf("compare-and-set after the disable rolled back: swapped %v, %v; want stored", r.swapped, r.err)
	}
	next := nextFrontier(cur)
	wantState(t, s, 0, &next)
}

// disableRacing runs compare-and-sets of key 0's frontier from several goroutines, each from the frontier it has
// just read, disables the key once they have moved it, and lets each try a few more times: the frontier read when
// the disable returned is the last one.
func disableRacing(t *testing.T, s slashing.Store, disable func(slashing.Store, func() error) error) {
	const (
		workers = 4
		after   = 3 // attempts each worker makes once the disable has returned
	)
	disabled := make(chan struct{})
	var (
		moves atomic.Int32
		wg    sync.WaitGroup
	)
	for range workers {
		wg.Go(func() {
			for n := 0; ; {
				select {
				case <-disabled:
					if n++; n > after {
						return
					}
				default:
				}
				st, ok, err := s.RandaoState(bg, id(0))
				if err != nil || !ok {
					t.Errorf("RandaoState: %+v, %v, %v", st, ok, err)
					return
				}
				swapped, err := s.CompareAndSwapRandaoState(bg, id(0), &st, nextFrontier(st))
				switch {
				case errors.Is(err, slashing.ErrValidatorDisabled):
					return
				case err != nil:
					t.Errorf("CompareAndSwapRandaoState: %v", err)
					return
				case swapped:
					moves.Add(1)
				}
			}
		})
	}
	for deadline := time.Now().Add(10 * time.Second); moves.Load() < workers && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	err := disable(s, nil)
	last, ok, lerr := s.RandaoState(bg, id(0))
	close(disabled)
	wg.Wait()
	must(t, err)
	must(t, lerr)
	if !ok {
		t.Fatal("no frontier is stored")
	}
	if n := moves.Load(); n < workers {
		t.Fatalf("only %d frontier moves before the disable", n)
	}
	wantState(t, s, 0, &last)
}

// currentFrontier returns key 0's stored frontier.
func currentFrontier(t *testing.T, s slashing.Store) slashing.RandaoState {
	t.Helper()
	st, ok, err := s.RandaoState(bg, id(0))
	must(t, err)
	if !ok {
		t.Fatal("no frontier is stored")
	}
	return st
}

// nextFrontier is the frontier one layer deeper than st, released one slot later.
func nextFrontier(st slashing.RandaoState) slashing.RandaoState {
	return slashing.RandaoState{Index: st.Index - 1, Reveal: RootOf(st.Index - 1), LastSlot: st.LastSlot + 1}
}

// wantDisabled checks that a compare-and-set of key's frontier fails with ErrValidatorDisabled without storing.
func wantDisabled(t *testing.T, s slashing.Store, key int, old *slashing.RandaoState, next slashing.RandaoState) {
	t.Helper()
	swapped, err := s.CompareAndSwapRandaoState(bg, id(key), old, next)
	if !errors.Is(err, slashing.ErrValidatorDisabled) || swapped {
		t.Errorf("key %d: compare-and-set from %+v while disabled: swapped %v, %v; want ErrValidatorDisabled",
			key, old, swapped, err)
	}
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
