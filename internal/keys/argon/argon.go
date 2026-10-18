// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package argon bounds the Argon2id runs of keystore decryption. Every
// keystore the signer decrypts, at startup, on reload or in an offline
// check, goes through one process-wide Semaphore, so that concurrent loads
// can never hold more Argon2id memory than the budget allows.
//
// A decrypt of a keystore with memory parameter m KiB is weighed at 2 × m
// KiB: Go frees an Argon2id block only at the next garbage collection, so
// a decrypt slot can hold its own block and the previous run's. A
// standard keystore (m = 256 MiB) therefore weighs SlotSize (512 MiB) and a
// light one (m = 4 MiB) 8 MiB. The semaphore admits a decrypt while fewer
// than Procs run and the running weights fit the budget; one decrypt always
// runs, however small the budget. Waiters are served in arrival order, so
// a standard keystore is not starved by light ones.
package argon

import (
	"container/list"
	"context"
	"fmt"
	"math"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystore/qrlv1"
)

// Sizing constants.
const (
	// SlotSize is the weight of a standard-KDF decrypt: two 256 MiB
	// Argon2id blocks.
	SlotSize = 512 << 20
	// Reserve is the memory left out of the budget for the rest of the
	// process: the runtime, the loaded keys and the requests in flight.
	Reserve = 512 << 20
	// MaxProcs caps concurrent decrypts. Argon2id runs are bound by memory
	// bandwidth well before 16 of them run at once.
	MaxProcs = 16
)

// Weight is the weight of one decrypt of a keystore with kdf.
func Weight(kdf qrlv1.KDF) int64 {
	return 2 * int64(kdf.M) << 10
}

// Semaphore admits Argon2id runs. It is safe for concurrent use.
type Semaphore struct {
	procs  int
	budget int64

	mu      sync.Mutex
	running int
	used    int64
	waiters list.List // of *waiter, in arrival order

	decrypts atomic.Int64 // decrypts run, for Stats
	busy     atomic.Int64 // their total duration in nanoseconds
}

type waiter struct {
	weight int64
	ready  chan struct{} // closed when admitted
}

// New returns a semaphore that admits at most procs decrypts, of total
// weight at most budget bytes. procs below 1 is taken as 1.
func New(procs int, budget int64) *Semaphore {
	return &Semaphore{procs: max(procs, 1), budget: max(budget, 0)}
}

// Procs is the most decrypts that run at once.
func (s *Semaphore) Procs() int { return s.procs }

// Budget is the total weight of the decrypts that run at once, in bytes.
func (s *Semaphore) Budget() int64 { return s.budget }

// Standard is the number of standard-KDF decrypts that run at once:
// min(Procs, Budget / SlotSize), at least 1.
func (s *Semaphore) Standard() int {
	return int(max(1, min(int64(s.procs), s.budget/SlotSize)))
}

// fits reports whether a decrypt of weight w may start now. It needs s.mu.
func (s *Semaphore) fits(w int64) bool {
	return s.running < s.procs && (s.running == 0 || s.used+w <= s.budget)
}

// Acquire waits until a decrypt of weight w may run, or ctx ends. On
// success the caller calls Release(w) when the decrypt is done.
func (s *Semaphore) Acquire(ctx context.Context, w int64) error {
	s.mu.Lock()
	if s.waiters.Len() == 0 && s.fits(w) {
		s.running++
		s.used += w
		s.mu.Unlock()
		return nil
	}
	wt := &waiter{weight: w, ready: make(chan struct{})}
	el := s.waiters.PushBack(wt)
	s.mu.Unlock()

	select {
	case <-wt.ready:
		return nil
	case <-ctx.Done():
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-wt.ready:
		// Admitted while ctx ended: give the slot back.
		s.running--
		s.used -= w
	default:
		s.waiters.Remove(el)
	}
	s.admit()
	return ctx.Err()
}

// Release ends a decrypt of weight w.
func (s *Semaphore) Release(w int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running--
	s.used -= w
	if s.running < 0 || s.used < 0 {
		panic("argon: Release without Acquire")
	}
	s.admit()
}

// admit starts the waiters at the front that fit. It needs s.mu.
func (s *Semaphore) admit() {
	for {
		front := s.waiters.Front()
		if front == nil {
			return
		}
		wt := front.Value.(*waiter)
		if !s.fits(wt.weight) {
			return
		}
		s.running++
		s.used += wt.weight
		s.waiters.Remove(front)
		close(wt.ready)
	}
}

// Decrypt decrypts ks with pw once the semaphore admits it.
func (s *Semaphore) Decrypt(ctx context.Context, ks *qrlv1.Keystore, pw *qrlv1.Password) (*mldsa87.Key, error) {
	w := Weight(ks.KDF)
	if err := s.Acquire(ctx, w); err != nil {
		return nil, err
	}
	defer s.Release(w)
	start := time.Now()
	defer func() {
		s.decrypts.Add(1)
		s.busy.Add(int64(time.Since(start)))
	}()
	return ks.Decrypt(pw)
}

// Stats returns the number of decrypts Decrypt has run and their total
// duration, from admission to return. A load that compares them before and
// after knows how long its decrypts took at the concurrency they ran at.
func (s *Semaphore) Stats() (decrypts int64, total time.Duration) {
	return s.decrypts.Load(), time.Duration(s.busy.Load())
}

// Budget sources, as Sizing reports them.
const (
	SourceGOMEMLIMIT  = "GOMEMLIMIT"
	SourceCgroup      = "cgroup memory limit"
	SourceRAM         = "50% of RAM"
	SourceUnknown     = "unknown (no memory limit or RAM size found)"
	SourceParallelism = "--signer-load-parallelism"
)

// Memory is the memory the process may use, and where that figure comes
// from.
type Memory struct {
	Bytes  int64
	Source string
}

// DetectMemory returns the memory limit of the process: GOMEMLIMIT, else
// the cgroup memory limit (Linux), else half of the RAM. Bytes is 0 when
// none of them is known.
func DetectMemory() Memory {
	if lim := debug.SetMemoryLimit(-1); lim != math.MaxInt64 {
		return Memory{Bytes: lim, Source: SourceGOMEMLIMIT}
	}
	if lim, ok := cgroupLimit(); ok {
		return Memory{Bytes: lim, Source: SourceCgroup}
	}
	if ram, ok := totalRAM(); ok && ram <= math.MaxInt64 {
		return Memory{Bytes: int64(ram / 2), Source: SourceRAM}
	}
	return Memory{Source: SourceUnknown}
}

// Sizing is a semaphore's size and how it was chosen.
type Sizing struct {
	Procs  int
	Budget int64 // bytes
	Source string
}

// Size chooses the semaphore's size. A parallelism above 0 fixes it at
// that many standard-KDF decrypts. Otherwise it follows mem: the budget is
// mem minus Reserve, and at most min(gomaxprocs, MaxProcs) decrypts run, so
// that min(gomaxprocs, (mem - Reserve) / SlotSize, MaxProcs), at least 1,
// standard-KDF decrypts run at once.
func Size(parallelism int, mem Memory, gomaxprocs int) Sizing {
	if parallelism > 0 {
		return Sizing{Procs: parallelism, Budget: int64(parallelism) * SlotSize, Source: SourceParallelism}
	}
	return Sizing{
		Procs:  max(1, min(gomaxprocs, MaxProcs)),
		Budget: max(0, mem.Bytes-Reserve),
		Source: mem.Source,
	}
}

// Auto returns the semaphore for --signer-load-parallelism (0 sizes it
// from the memory limit) and its sizing.
func Auto(parallelism int) (*Semaphore, Sizing) {
	sz := Size(parallelism, DetectMemory(), runtime.GOMAXPROCS(0))
	return New(sz.Procs, sz.Budget), sz
}

// String describes the sizing for the startup log.
func (sz Sizing) String() string {
	s := New(sz.Procs, sz.Budget)
	return fmt.Sprintf("at most %d keystore decrypts at once, %d with the standard KDF (Argon2id budget %d MiB, from %s)",
		s.Procs(), s.Standard(), sz.Budget>>20, sz.Source)
}
