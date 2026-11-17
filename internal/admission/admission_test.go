// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package admission_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/admission"
)

func TestNewRefusesBadLimits(t *testing.T) {
	tests := []struct {
		concurrent, queued int
		ok                 bool
	}{
		{1, 0, true},
		{32, 512, true},
		{0, 512, false},
		{-1, 0, false},
		{32, -1, false},
	}
	for _, tt := range tests {
		g, err := admission.New(tt.concurrent, tt.queued)
		if (err == nil) != tt.ok {
			t.Errorf("New(%d, %d): %v, want ok %v", tt.concurrent, tt.queued, err, tt.ok)
		}
		if err == nil {
			if c, q := g.Limits(); c != tt.concurrent || q != tt.queued {
				t.Errorf("New(%d, %d).Limits() = %d, %d", tt.concurrent, tt.queued, c, q)
			}
		}
	}
}

// waitFor polls cond until it holds or a second has passed.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestBounds saturates a gate: the holders beyond its slots wait, the
// callers beyond its queue are refused at once, and each release lets one
// waiter in.
func TestBounds(t *testing.T) {
	tests := []struct{ concurrent, queued int }{{1, 0}, {1, 1}, {2, 3}, {32, 512}}
	for _, tt := range tests {
		g, err := admission.New(tt.concurrent, tt.queued)
		if err != nil {
			t.Fatal(err)
		}
		bg := context.Background()
		var held []func()
		for range tt.concurrent {
			release, err := g.Acquire(bg)
			if err != nil {
				t.Fatalf("%+v: a free slot: %v", tt, err)
			}
			held = append(held, release)
		}
		var (
			admitted atomic.Int64
			wg       sync.WaitGroup
			releases = make(chan func(), tt.queued)
		)
		for range tt.queued {
			wg.Add(1)
			go func() {
				defer wg.Done()
				release, err := g.Acquire(bg)
				if err != nil {
					t.Errorf("%+v: a queued caller: %v", tt, err)
					return
				}
				admitted.Add(1)
				releases <- release
			}()
		}
		waitFor(t, "the queue to fill", func() bool { return g.Queued() == tt.queued })
		if _, err := g.Acquire(bg); !errors.Is(err, admission.ErrOverloaded) {
			t.Fatalf("%+v: with the queue full: %v, want ErrOverloaded", tt, err)
		}
		if g.InFlight() != tt.concurrent || admitted.Load() != 0 {
			t.Fatalf("%+v: %d in flight and %d admitted from the queue", tt, g.InFlight(), admitted.Load())
		}
		// Each release lets exactly one waiter in, until the queue is empty.
		for i := range tt.queued {
			if i < len(held) {
				held[i]()
			} else {
				(<-releases)()
			}
			waitFor(t, "a waiter to take the freed slot", func() bool { return admitted.Load() == int64(i+1) })
			if g.InFlight() != tt.concurrent {
				t.Fatalf("%+v: %d in flight after %d releases", tt, g.InFlight(), i+1)
			}
		}
		for _, release := range held[min(tt.queued, len(held)):] {
			release()
		}
		wg.Wait()
		close(releases)
		for release := range releases {
			release()
		}
		if g.InFlight() != 0 || g.Queued() != 0 {
			t.Errorf("%+v: %d in flight and %d queued at the end", tt, g.InFlight(), g.Queued())
		}
	}
}

// TestNeverMoreThanConcurrent runs many callers through a small gate and
// checks the number running at once.
func TestNeverMoreThanConcurrent(t *testing.T) {
	const concurrent, callers = 4, 200
	g, err := admission.New(concurrent, callers)
	if err != nil {
		t.Fatal(err)
	}
	var running, peak atomic.Int64
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := g.Acquire(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			defer release()
			n := running.Add(1)
			for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
			}
			time.Sleep(100 * time.Microsecond)
			running.Add(-1)
		}()
	}
	wg.Wait()
	if p := peak.Load(); p > concurrent || p == 0 {
		t.Errorf("peak %d running, want 1 to %d", p, concurrent)
	}
}

// TestContextEndsWhileQueued: a caller whose context ends gives up its place
// in the queue.
func TestContextEndsWhileQueued(t *testing.T) {
	g, err := admission.New(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	release, err := g.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := g.Acquire(ctx)
		done <- err
	}()
	waitFor(t, "the caller to queue", func() bool { return g.Queued() == 1 })
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire after cancel: %v, want context.Canceled", err)
	}
	if g.Queued() != 0 {
		t.Fatalf("%d queued after the caller gave up", g.Queued())
	}
	release()
	if release, err := g.Acquire(context.Background()); err != nil {
		t.Fatalf("a slot after the release: %v", err)
	} else {
		release()
	}
}
