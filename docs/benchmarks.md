# Benchmarks

Each benchmark is first required by the milestone that delivers its component, then re-run weekly and before every
release. The thresholds were set for the reference hardware: a 4-vCPU x86-64 cloud VM and a 4-vCPU Graviton-class
arm64 VM, reporting p50, p99 and p99.9 with `benchstat` over at least 10 runs. Rows measured elsewhere say so and
must be re-run on the reference VMs before v1.0.

## ML-DSA-87 (B1-B4, `internal/crypto/mldsa87`)

```
go test -run '^$' -bench . -benchtime 20000x ./internal/crypto/mldsa87/
CGO_ENABLED=1 go test -race -run '^$' -bench SignParallel -benchtime 200x ./internal/crypto/mldsa87/
```

Signing uses 1,024 random 32-byte roots, never one fixed message. Latency percentiles come from per-call timings
(`p50-ms`, `p99-ms`, `p99.99-ms`).

| ID | Benchmark | Threshold | Result | Verdict |
|---|---|---|---|---|
| B1 | `BenchmarkSignHedged` | mean ≤ 2 ms; p99 ≤ 6 ms; p99.99 ≤ 12 ms (amd64) | mean 0.67 ms; p50 0.53 ms; p99 2.27 ms; p99.99 13.9 ms | mean and p99 met; p99.99 to re-measure on reference hardware (see note) |
| B2 | `BenchmarkSignDeterministic` | as B1, and byte-identical output for repeated roots | mean 0.60 ms; p50 0.48 ms; p99 2.10 ms; p99.99 16.0 ms; every repeated root gave identical bytes | as B1 |
| B3 | `BenchmarkKeyFromSeed` (`NewWalletFromSeed` plus the weak-key check) | mean ≤ 1 ms | 0.18 ms | met |
| B4 | `BenchmarkSignParallel` (GOMAXPROCS = 8 goroutines) | ≥ 1,000 signatures/s on 4 vCPU; no data races | distinct keys 5,620/s; one shared key 1,690/s (serialised by the per-key lock); no race reported under `-race` | met (on 8 cores, not 4 vCPU) |

Measured 2026-10-15 on an Apple M2 (8 cores, darwin/arm64, Go 1.26.9, go-qrllib v0.11.0), one run of 20,000
operations per benchmark, on a shared development machine with a load average of 11-20 during the run. A p99.99 over
20,000 samples is the third-slowest call, so it is dominated by scheduler pauses from the other load; an earlier
run under heavier load gave p99.99 of 56-58 ms with p99 of 2.9-4.6 ms. The amd64 p99.99 threshold needs the
reference VM.
