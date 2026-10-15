# Benchmarks

Each benchmark is first required by the milestone that delivers its component, then re-run weekly and before every
release. The thresholds were set for the reference hardware: a 4-vCPU x86-64 cloud VM and a 4-vCPU Graviton-class
arm64 VM, reporting p50, p99 and p99.9 with `benchstat` over at least 10 runs. Rows measured elsewhere say so and
must be re-run on the reference VMs before v1.0.

## ML-DSA-87 (B1-B4, `internal/crypto/mldsa87`)

**Status: open.** The S2c acceptance criterion "B1-B4 meet their thresholds" is not yet confirmed. The only
measurements so far come from a shared, heavily loaded development machine, which cannot confirm or refute a
latency bound. This stays a tracked gate until the rows below are re-run on a quiet machine or the reference VMs.

```
go test -run '^$' -bench 'SignHedged|SignDeterministic|KeyFromSeed' -benchtime 20000x -count 10 \
    ./internal/crypto/mldsa87/ | tee b1-b3.txt && benchstat b1-b3.txt
go test -run '^$' -bench SignParallel -cpu 4 -benchtime 5000x -count 10 \
    ./internal/crypto/mldsa87/ | tee b4.txt && benchstat b4.txt
CGO_ENABLED=1 go test -race -run '^$' -bench SignParallel -benchtime 200x ./internal/crypto/mldsa87/
```

Signing uses 1,024 random 32-byte roots, never one fixed message. Latency percentiles come from per-call timings
(`p50-ms`, `p99-ms`, `p99.99-ms`). B4 runs with `-cpu 4` so that it uses four procs, as on the reference VMs.

| ID | Benchmark | Threshold | Development-machine results | Verdict |
|---|---|---|---|---|
| B1 | `BenchmarkSignHedged` | mean ≤ 2 ms; p99 ≤ 6 ms; p99.99 ≤ 12 ms (amd64) | run A: mean 0.67 ms, p50 0.53 ms, p99 2.27 ms, p99.99 13.9 ms; run B: mean 2.52 ms, p99 24.8 ms, p99.99 161.6 ms | pending: re-run on reference hardware |
| B2 | `BenchmarkSignDeterministic` | as B1, and byte-identical output for repeated roots | run A: mean 0.60 ms, p50 0.48 ms, p99 2.10 ms, p99.99 16.0 ms; run B: mean 1.92 ms, p99 12.75 ms, p99.99 103.7 ms; every repeated root gave identical bytes | pending: re-run on reference hardware |
| B3 | `BenchmarkKeyFromSeed` (`NewWalletFromSeed` plus the weak-key check) | mean ≤ 1 ms | run A: 0.18 ms | pending: re-run on reference hardware |
| B4 | `BenchmarkSignParallel` | ≥ 1,000 signatures/s on 4 vCPU; no data races | run A (8 procs): distinct keys 5,620/s, shared key 1,690/s; run B (8 procs): shared key 721/s; run C (`-cpu 4`, 10 runs): distinct keys 2,192/s ± 15%, shared key 835/s ± 9%; no race reported under `-race` | pending: re-run on reference hardware |

All runs were on an Apple M2 (8 cores, darwin/arm64, go-qrllib v0.11.0) shared with other work:

- Run A, 2026-10-15, Go 1.26.9: one run of 20,000 operations per benchmark, load average 11-20.
- Run B, 2026-10-15, review re-run of the same command, load average 16-20.
- Run C, 2026-10-15, Go 1.26.5: B4 with `-cpu 4 -benchtime 5000x -count 10`, summarised with `benchstat`, load
  average 8-14.

A p99.99 over 20,000 samples is the third-slowest call, so on a loaded machine it measures scheduler pauses from the
other load rather than signing. The shared-key B4 figure is bounded by the per-key lock (one signature at a time per
key), so it tracks single-call latency and falls with load; the distinct-keys figure is the parallel throughput.

## Hash-tree-root and strict decoding (B5, B6, `internal/consensus/types`)

**Status: met on the development machine, with wide margins** (at least 4x below every threshold). Still to be
re-run on the reference VMs before v1.0, like every row measured elsewhere.

```
go test -run '^$' -bench 'SigningRoot|DecodeContribution' -benchtime 2s -count 10 \
    ./internal/consensus/types/ | tee b5-b6.txt && benchstat b5-b6.txt
```

B5 measures the object's hash-tree-root plus the signing root, the work step 5 of the validation pipeline does per
request. B6 decodes the largest valid sign request through `DecodeSignRequest`, including the JSON validity and
duplicate-key pre-scan: a mainnet-preset contribution with 128 signatures, 1,194,934 bytes, within 100 bytes of the
1,195,027-byte maximum in `docs/contract.md` section 13.

| ID | Benchmark | Threshold | Development-machine results | Verdict |
|---|---|---|---|---|
| B5 | `BenchmarkSigningRootContributionAndProof` (128 signatures) | ≤ 10 ms | 1.65-1.85 ms, 0.98 MB and 262 allocations per op | met on dev machine |
| B5 | `BenchmarkSigningRootAggregateAndProof` (32 signatures) | ≤ 3 ms | 0.42-0.59 ms, 0.25 MB per op | met on dev machine |
| B5 | `BenchmarkSigningRootAttestationData` | ≤ 50 µs | 1.06-1.09 µs, one allocation | met on dev machine |
| B6 | `BenchmarkDecodeContribution` (1.2 MB) | ≤ 20 ms; ≤ 6 MB allocated | 3.5-3.9 ms (306-339 MB/s), 0.61 MB and 59 allocations per op | met on dev machine |

Run D, 2026-10-15, Go 1.26.9, Apple M2 (8 cores, darwin/arm64), three runs of 2 s per benchmark, load average 7-9
from other work. The decoder reads the body in place: besides the decoded signatures (128 x 4,627 bytes) it
allocates only small bookkeeping, which is why B6 stays far under its memory bound.

## Public keys and idle connections (B15, B19, the API server)

**B15: met on the development machine.** **B19: implemented as a nightly job; no 1 h run recorded yet** (a 40 s
smoke run and a 5 min run passed with 0 errors). B19 is met only once a 1 h run, nightly or local, is recorded
below.

```
go test -run '^$' -bench PublicKeys10k -benchtime 10x -count 10 ./internal/api/consensus/ | tee b15.txt && benchstat b15.txt
make b19 B19_DURATION=1h     # nightly: .github/workflows/nightly.yml
```

B15 serves `GET /api/v1/consensus/publicKeys` for 10,000 random 2,592-byte keys through the handler, writing to a
discarding response writer, so it measures rendering and compression, not the network. The handler streams key by
key through a 64 KiB buffer and never holds the 51.9 MB array; gzip uses `BestSpeed`, since hex public keys compress
about 2:1 at any level. B19 runs the built binary and two clients with Go's default transport (90 s
`IdleConnTimeout`), one POSTing every 25-35 s and one every 85-95 s, and counts transport errors.

| ID | Benchmark | Threshold | Development-machine results | Verdict |
|---|---|---|---|---|
| B15 | `BenchmarkPublicKeys10k/plain` | ≤ 2 s on a LAN; transient allocation ≤ 64 MB | 20.7-21.0 ms, 71.6 KB and 12 allocations per request | met on dev machine |
| B15 | `BenchmarkPublicKeys10k/gzip` | as above | 526-551 ms, 1.28 MB and 32 allocations per request | met on dev machine |
| B19 | `TestB19IdleConnectionRace` (`make b19`) | 0 "server closed idle connection" or EOF errors over 1 h with `IdleTimeout` 120 s | 40 s smoke run: 0 errors; 5 min run (2026-10-15): 14 POSTs, 0 errors | pending: first 1 h run |

Run E, 2026-10-15, Go 1.26.9, Apple M2 (8 cores, darwin/arm64), 10 runs of 10 requests each, load average 4-5 from
other work.
