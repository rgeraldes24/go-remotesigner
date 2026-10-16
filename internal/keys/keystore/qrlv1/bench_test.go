// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package qrlv1

import (
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// BenchmarkB10Argon2idDecrypt is benchmark B10 (docs/benchmarks.md): decrypting
// the standard-KDF keystore (t=8, m=256 MiB, p=1) with P decrypts running
// at once, P = 1, 2, 4, 8 and 16. One op is a round of P concurrent
// decrypts. It reports the throughput (decrypts/s) and the per-decrypt
// latency (mean and slowest), whose growth with P shows the scaling knee.
// Peak memory is P × 256 MiB plus the process; measure RSS per P with
// /usr/bin/time (docs/benchmarks.md).
func BenchmarkB10Argon2idDecrypt(b *testing.B) {
	benchDecrypt(b, "keystores/qrl-v1-standard.json", []int{1, 2, 4, 8, 16})
}

// BenchmarkDecryptLightKDF is the same for the light KDF (t=8, m=4 MiB),
// the deposit CLI's --lightkdf, for reference.
func BenchmarkDecryptLightKDF(b *testing.B) {
	benchDecrypt(b, "keystores/qrl-v1-light.json", []int{1, 8})
}

func benchDecrypt(b *testing.B, file string, ps []int) {
	ks, err := Parse(vectors.Raw(b, file))
	if err != nil {
		b.Fatal(err)
	}
	pw := NewPassword([]byte("testpassword"))
	for _, p := range ps {
		b.Run(fmt.Sprintf("P=%d", p), func(b *testing.B) {
			var (
				mu   sync.Mutex
				lats []time.Duration
			)
			for b.Loop() {
				var wg sync.WaitGroup
				for range p {
					wg.Go(func() {
						start := time.Now()
						key, err := ks.Decrypt(pw)
						d := time.Since(start)
						if err != nil {
							b.Error(err)
							return
						}
						key.Zeroize()
						mu.Lock()
						lats = append(lats, d)
						mu.Unlock()
					})
				}
				wg.Wait()
			}
			if len(lats) == 0 {
				return
			}
			var sum time.Duration
			for _, d := range lats {
				sum += d
			}
			b.ReportMetric(float64(len(lats))/b.Elapsed().Seconds(), "decrypts/s")
			b.ReportMetric((sum / time.Duration(len(lats))).Seconds(), "s/decrypt")
			b.ReportMetric(slices.Max(lats).Seconds(), "max-s/decrypt")
		})
	}
}
