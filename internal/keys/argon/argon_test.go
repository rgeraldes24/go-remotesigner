// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package argon

import (
	"context"
	"errors"
	"math"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystore/qrlv1"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
)

const (
	mib      = 1 << 20
	standard = SlotSize // a standard-KDF decrypt
	light    = 8 * mib  // a light-KDF decrypt
)

func TestWeight(t *testing.T) {
	if w := Weight(qrlv1.KDF{T: 8, M: 262144, P: 1}); w != SlotSize {
		t.Errorf("standard KDF weighs %d, want %d", w, SlotSize)
	}
	if w := Weight(qrlv1.KDF{T: 8, M: 4096, P: 1}); w != light {
		t.Errorf("light KDF weighs %d, want %d", w, light)
	}
}

// The sizing rule for standard keystores: min(GOMAXPROCS,
// (mem - 512 MiB) / 512 MiB, 16), at least 1; light keystores are bounded
// by the procs only.
func TestSize(t *testing.T) {
	gib := int64(1 << 30)
	for _, tt := range []struct {
		name         string
		parallelism  int
		mem          int64
		gomaxprocs   int
		procs, std   int
		budgetSource string
	}{
		{"16 GiB RAM, 8 CPUs", 0, 8 * gib, 8, 8, 8, SourceRAM},
		{"4 GiB limit, 8 CPUs", 0, 4 * gib, 8, 8, 7, SourceGOMEMLIMIT},
		{"2 GiB limit", 0, 2 * gib, 8, 8, 3, SourceGOMEMLIMIT},
		{"768 MiB limit", 0, 768 * mib, 8, 8, 1, SourceGOMEMLIMIT},
		{"limit below the reserve", 0, 256 * mib, 8, 8, 1, SourceGOMEMLIMIT},
		{"unknown memory", 0, 0, 4, 4, 1, SourceUnknown},
		{"64 CPUs, 64 GiB", 0, 64 * gib, 64, MaxProcs, MaxProcs, SourceCgroup},
		{"one CPU", 0, 8 * gib, 1, 1, 1, SourceRAM},
		{"fixed parallelism", 3, 1 * gib, 8, 3, 3, SourceParallelism},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := tt.budgetSource
			if src == SourceParallelism {
				src = SourceRAM
			}
			sz := Size(tt.parallelism, Memory{Bytes: tt.mem, Source: src}, tt.gomaxprocs)
			s := New(sz.Procs, sz.Budget)
			if s.Procs() != tt.procs || s.Standard() != tt.std || sz.Source != tt.budgetSource {
				t.Fatalf("Size = %+v: procs %d, standard %d; want %d, %d, %s", sz, s.Procs(), s.Standard(), tt.procs,
					tt.std, tt.budgetSource)
			}
		})
	}
}

// load runs n decrypts of weight w at once on s and returns the most that
// ran together.
func load(t *testing.T, s *Semaphore, ws ...int64) int {
	t.Helper()
	var running, peak atomic.Int64
	var wg sync.WaitGroup
	for _, w := range ws {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Acquire(context.Background(), w); err != nil {
				t.Error(err)
				return
			}
			n := running.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			running.Add(-1)
			s.Release(w)
		}()
	}
	wg.Wait()
	return int(peak.Load())
}

func repeat(w int64, n int) []int64 {
	out := make([]int64, n)
	for i := range out {
		out[i] = w
	}
	return out
}

func TestSemaphoreBounds(t *testing.T) {
	// 4 procs, room for 2 standard decrypts.
	if got := load(t, New(4, 2*SlotSize), repeat(standard, 8)...); got != 2 {
		t.Errorf("standard decrypts at once: %d, want 2", got)
	}
	if got := load(t, New(4, 2*SlotSize), repeat(light, 16)...); got != 4 {
		t.Errorf("light decrypts at once: %d, want 4 (the procs)", got)
	}
	// A budget too small for one standard decrypt still runs one at a time.
	if got := load(t, New(4, 0), repeat(standard, 3)...); got != 1 {
		t.Errorf("standard decrypts with no budget: %d, want 1", got)
	}
}

// Waiters run in arrival order: light decrypts that arrive after a
// standard one wait for it even when they would fit.
func TestSemaphoreFIFO(t *testing.T) {
	s := New(4, SlotSize)
	if err := s.Acquire(context.Background(), light); err != nil {
		t.Fatal(err)
	}
	heavy := make(chan struct{})
	go func() {
		if err := s.Acquire(context.Background(), standard); err != nil {
			t.Error(err)
		}
		close(heavy)
	}()
	waitFor(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.waiters.Len() == 1 })
	lightDone := make(chan struct{})
	go func() {
		if err := s.Acquire(context.Background(), light); err != nil {
			t.Error(err)
		}
		close(lightDone)
	}()
	waitFor(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.waiters.Len() == 2 })
	select {
	case <-lightDone:
		t.Fatal("a light decrypt overtook the waiting standard one")
	case <-time.After(20 * time.Millisecond):
	}
	s.Release(light)
	<-heavy
	s.Release(standard)
	<-lightDone
	s.Release(light)
}

func TestSemaphoreCancel(t *testing.T) {
	s := New(1, SlotSize)
	if err := s.Acquire(context.Background(), standard); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.Acquire(ctx, light); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire = %v, want the deadline", err)
	}
	s.Release(standard)
	// The cancelled waiter left no trace: the semaphore is free.
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := s.Acquire(ctx2, standard); err != nil {
		t.Fatalf("Acquire after a cancel = %v", err)
	}
	s.Release(standard)
	defer func() {
		if recover() == nil {
			t.Error("Release without Acquire did not panic")
		}
	}()
	s.Release(light)
}

// Decrypt goes through the semaphore and counts each decrypt it runs,
// failed ones included, with its duration.
func TestDecryptStats(t *testing.T) {
	sealer, err := keystoretest.NewSealer("pw", keystoretest.Cheapest)
	if err != nil {
		t.Fatal(err)
	}
	data, err := sealer.DepositCLI(keystoretest.Seed(t.Name(), 0), 0, true)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := qrlv1.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	s := New(2, 2*SlotSize)
	for _, password := range []string{"pw", "wrong"} {
		pw := qrlv1.NewPassword([]byte(password))
		k, err := s.Decrypt(context.Background(), ks, pw)
		pw.Wipe()
		if (err == nil) != (password == "pw") {
			t.Fatalf("password %q: %v", password, err)
		}
		if k != nil {
			k.Zeroize()
		}
	}
	if n, total := s.Stats(); n != 2 || total <= 0 {
		t.Fatalf("Stats = %d, %v; want 2 decrypts and their time", n, total)
	}
	// A decrypt the context refuses before admission is not counted.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Acquire(context.Background(), standard); err != nil {
		t.Fatal(err)
	}
	if err := s.Acquire(context.Background(), standard); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decrypt(ctx, ks, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Decrypt with a full semaphore and a cancelled context: %v", err)
	}
	s.Release(standard)
	s.Release(standard)
	if n, _ := s.Stats(); n != 2 {
		t.Fatalf("Stats counted %d decrypts, want 2", n)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition never held")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDetectMemoryGOMEMLIMIT(t *testing.T) {
	old := debug.SetMemoryLimit(768 * mib)
	defer debug.SetMemoryLimit(old)
	if m := DetectMemory(); m.Bytes != 768*mib || m.Source != SourceGOMEMLIMIT {
		t.Fatalf("DetectMemory = %+v", m)
	}
	debug.SetMemoryLimit(math.MaxInt64)
	if m := DetectMemory(); m.Source == SourceGOMEMLIMIT {
		t.Fatalf("DetectMemory without a limit = %+v", m)
	}
}

func TestCgroupLimit(t *testing.T) {
	for _, tt := range []struct {
		name  string
		files map[string]string
		want  int64
		ok    bool
	}{
		{"v2 own group", map[string]string{
			"proc/self/cgroup": "0::/system.slice/signer.service\n",
			"sys/fs/cgroup/system.slice/signer.service/memory.max": "2147483648\n",
			"sys/fs/cgroup/memory.max":                             "max\n",
		}, 2 << 30, true},
		{"v2 container root", map[string]string{
			"proc/self/cgroup":         "0::/\n",
			"sys/fs/cgroup/memory.max": "1073741824\n",
		}, 1 << 30, true},
		{"v2 unlimited", map[string]string{
			"proc/self/cgroup":         "0::/\n",
			"sys/fs/cgroup/memory.max": "max\n",
		}, 0, false},
		{"v1 limited", map[string]string{
			"sys/fs/cgroup/memory/memory.limit_in_bytes": "536870912\n",
		}, 512 << 20, true},
		{"v1 unlimited", map[string]string{
			"sys/fs/cgroup/memory/memory.limit_in_bytes": "9223372036854771712\n",
		}, 0, false},
		{"garbage", map[string]string{"sys/fs/cgroup/memory.max": "lots\n"}, 0, false},
		{"none", map[string]string{}, 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for name, data := range tt.files {
				fsys[name] = &fstest.MapFile{Data: []byte(data)}
			}
			got, ok := cgroupLimitIn(fsys)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("cgroupLimitIn = %d, %v; want %d, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}
