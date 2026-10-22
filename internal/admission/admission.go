// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package admission bounds the signing work a signer accepts at once: a
// Gate lets a fixed number of holders run, queues a fixed number more, and
// refuses the rest at once, so that a burst beyond what the signer can serve
// fails fast with 503 OVERLOADED instead of piling up goroutines and request
// bodies (docs/contract.md section 13: 32 in flight, 512 queued, by
// default --max-concurrent-signing-requests and
// --max-queued-signing-requests).
//
// The gate knows nothing of HTTP or of what is signed: consensus mode holds
// a slot around the slashing check-and-record, the signature and its
// verification, and any other signing path can hold one the same way.
package admission

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
)

// Defaults of --max-concurrent-signing-requests and
// --max-queued-signing-requests.
const (
	DefaultConcurrent = 32
	DefaultQueued     = 512
)

// ErrOverloaded is returned by Acquire when every slot is taken and the
// queue is full.
var ErrOverloaded = errors.New("admission: every slot is taken and the queue is full")

// Gate admits at most Concurrent holders at once and lets at most Queued
// more wait for a slot. It is safe for concurrent use.
type Gate struct {
	slots     chan struct{}
	maxQueued int64
	queued    atomic.Int64
}

// New returns a gate of concurrent slots and a queue of queued waiters.
// concurrent must be at least 1 and queued at least 0.
func New(concurrent, queued int) (*Gate, error) {
	if concurrent < 1 {
		return nil, fmt.Errorf("admission: %d concurrent slots: want at least 1", concurrent)
	}
	if queued < 0 {
		return nil, fmt.Errorf("admission: a queue of %d: want at least 0", queued)
	}
	return &Gate{slots: make(chan struct{}, concurrent), maxQueued: int64(queued)}, nil
}

// Acquire takes a slot. When every slot is taken it waits in the queue,
// unless the queue is full, in which case it returns ErrOverloaded at once.
// It returns ctx's error when ctx ends while it waits. On success the
// caller must call release exactly once, when its work is done.
//
// Waiters are not served in strict arrival order: a slot freed while a
// caller arrives may go to that caller first. The bounds hold regardless.
func (g *Gate) Acquire(ctx context.Context) (release func(), err error) {
	select {
	case g.slots <- struct{}{}:
		return g.release, nil
	default:
	}
	if !g.enqueue() {
		return nil, ErrOverloaded
	}
	defer g.queued.Add(-1)
	select {
	case g.slots <- struct{}{}:
		return g.release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// enqueue takes a place in the queue, and reports false when it is full.
func (g *Gate) enqueue() bool {
	for {
		n := g.queued.Load()
		if n >= g.maxQueued {
			return false
		}
		if g.queued.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

func (g *Gate) release() { <-g.slots }

// InFlight returns the number of slots taken.
func (g *Gate) InFlight() int { return len(g.slots) }

// Queued returns the number of callers waiting for a slot.
func (g *Gate) Queued() int { return int(g.queued.Load()) }

// Limits returns the gate's concurrent slots and queue size.
func (g *Gate) Limits() (concurrent, queued int) { return cap(g.slots), int(g.maxQueued) }
