// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package mldsa87

// Benchmarks B1-B4 (signing latency, key derivation, parallel signing).
// Signing uses random 32-byte roots, never one fixed message: the rejection
// loop's cost depends on the message. Besides ns/op, the latency benchmarks
// report p50, p99 and p99.99 in milliseconds. docs/benchmarks.md has the
// commands, including the -cpu 4 run of B4 and the -race run.

import (
	"crypto/rand"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

const benchRoots = 1024

func randomRoots(b *testing.B) [][32]byte {
	b.Helper()
	roots := make([][32]byte, benchRoots)
	for i := range roots {
		if _, err := rand.Read(roots[i][:]); err != nil {
			b.Fatal(err)
		}
	}
	return roots
}

func reportLatency(b *testing.B, lat []time.Duration) {
	b.Helper()
	if len(lat) == 0 {
		return
	}
	slices.Sort(lat)
	q := func(p float64) float64 {
		i := int(p * float64(len(lat)-1))
		return float64(lat[i]) / float64(time.Millisecond)
	}
	b.ReportMetric(q(0.50), "p50-ms")
	b.ReportMetric(q(0.99), "p99-ms")
	b.ReportMetric(q(0.9999), "p99.99-ms")
}

func benchmarkSign(b *testing.B, mode Mode) {
	k := newTestKey(b, 0x40)
	roots := randomRoots(b)
	lat := make([]time.Duration, 0, b.N)
	var first [benchRoots]*[SignatureSize]byte
	i := 0
	for b.Loop() {
		r := i % benchRoots
		start := time.Now()
		sig, err := k.Sign(roots[r][:], mode)
		lat = append(lat, time.Since(start))
		if err != nil {
			b.Fatal(err)
		}
		if mode == Deterministic {
			// B2: repeated roots must give byte-identical signatures.
			if first[r] == nil {
				first[r] = &sig
			} else if *first[r] != sig {
				b.Fatalf("root %d: deterministic signature changed", r)
			}
		}
		i++
	}
	reportLatency(b, lat)
}

// BenchmarkSignHedged is B1: Wallet.Sign, random roots, one goroutine.
func BenchmarkSignHedged(b *testing.B) { benchmarkSign(b, Hedged) }

// BenchmarkSignDeterministic is B2: Wallet.SignDeterministic, random roots,
// plus byte-identical output for repeated roots.
func BenchmarkSignDeterministic(b *testing.B) { benchmarkSign(b, Deterministic) }

// BenchmarkKeyFromSeed is B3: NewWalletFromSeed plus the weak-key check.
func BenchmarkKeyFromSeed(b *testing.B) {
	var seed [SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		b.Fatal(err)
	}
	for b.Loop() {
		k, err := FromSeed48(&seed)
		if err != nil {
			b.Fatal(err)
		}
		k.Zeroize()
	}
}

// BenchmarkSignParallel is B4: GOMAXPROCS goroutines signing with distinct
// keys, and with one shared key. It reports signatures per second.
func BenchmarkSignParallel(b *testing.B) {
	roots := randomRoots(b)
	procs := runtime.GOMAXPROCS(0)

	b.Run("distinct-keys", func(b *testing.B) {
		keys := make([]*Key, procs)
		for i := range keys {
			keys[i] = newTestKey(b, byte(0x50+i))
		}
		var next atomic.Int64
		start := time.Now()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			k := keys[int(next.Add(1)-1)%len(keys)]
			i := 0
			for pb.Next() {
				if _, err := k.Sign(roots[i%benchRoots][:], Hedged); err != nil {
					b.Error(err)
					return
				}
				i++
			}
		})
		b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "sigs/s")
	})

	b.Run("shared-key", func(b *testing.B) {
		k := newTestKey(b, 0x4f)
		start := time.Now()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				if _, err := k.Sign(roots[i%benchRoots][:], Hedged); err != nil {
					b.Error(err)
					return
				}
				i++
			}
		})
		b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "sigs/s")
	})
}
