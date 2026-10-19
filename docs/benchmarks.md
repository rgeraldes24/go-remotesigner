# Benchmarks

Each benchmark is first run when its component lands, then re-run weekly and before every release. The thresholds
were set for the reference hardware: a 4-vCPU x86-64 cloud VM and a 4-vCPU Graviton-class arm64 VM, reporting p50,
p99 and p99.9 with `benchstat` over at least 10 runs. Rows measured elsewhere say so and must be re-run on the
reference VMs before v1.0.

The first section is the run for the 1.0.0 release; the sections after it describe each benchmark and keep the runs
made when its component landed.

## v1.0 release run (dev machine)

**These are development-machine numbers, not the release gate.** v1.0 needs every benchmark below within its threshold
on the reference VMs, and B16, which no machine here can run; both are open items of the
[release checklist](operations/release.md#62-open-gates-this-repository-cannot-meet-today). Run V re-ran every
benchmark that runs on this machine, on the code of the 1.0.0 candidate, with the commands of the sections below.

Run V, 2026-10-20, Go 1.26.9, Apple M2 (4 performance and 4 efficiency cores, 16 GiB, darwin/arm64), PostgreSQL 17
(`postgres:17-alpine`) in Docker Desktop for B13 and B14. The machine was shared with other work throughout; the
load average of each run is in the table, and it moved within runs (a build by other work pushed it from 5 to 32
between B10 and B11).

| ID | Threshold | Run V | Load average | Verdict (dev machine) |
|---|---|---|---|---|
| B1 | mean ≤ 2 ms; p99 ≤ 6 ms; p99.99 ≤ 12 ms (amd64) | 10 runs of 20,000: mean 0.439 ms ± 3 %, p50 0.353 ms, p99 1.39 ms, p99.99 13.9 ms ± 32 % (2.6-28.6 ms; above 12 ms in 7 of 10) | 1.8-3.5 | mean and p99 met; p99.99 not met (scheduler pauses of the shared machine) |
| B2 | as B1; identical bytes for repeated roots | mean 0.432 ms ± 3 %, p50 0.351 ms, p99 1.30 ms, p99.99 8.0 ms ± 82 % (2.8-20.0 ms; above 12 ms in 3 of 10); every repeated root gave identical bytes | 1.8-3.5 | mean and p99 met; p99.99 not met in 3 of 10 |
| B3 | mean ≤ 1 ms | 0.145 ms ± 9 % | 1.8-3.5 | met |
| B4 | ≥ 1,000 signatures/s on 4 vCPU; no data races | `-cpu 4`, 10 runs: distinct keys 8,178/s ± 6 %, shared key 2,228/s ± 3 %; no race under `-race` | 3.1-3.4 | met |
| B5 | ≤ 10 ms / ≤ 3 ms / ≤ 50 µs | contribution (128 signatures) 1.66 ms, aggregate (32) 0.429 ms, attestation data 1.04 µs (10 runs each) | 3.3-3.4 | met |
| B6 | ≤ 20 ms; ≤ 6 MB allocated | 3.40 ms ± 3 % (335 MiB/s), 592 KiB and 59 allocations | 3.3-3.4 | met |
| B7 | last ≤ 1 s, p99 ≤ 500 ms, 0 errors | 5 runs: last 293-542 ms, p50 25-51 ms, p99 288-537 ms, 0 errors; p99 over 500 ms in one run (537 ms), and in a sixth run at 12:51 (570 ms) | 5.7-8.1 (sixth: 4.0) | met in 4 of 6 |
| B8 | each ≤ 250 ms; RSS + ≤ 128 MiB | slowest 26.9-30.0 ms; RSS +26-35 MiB | 5.7-8.1 | met |
| B9 | reveal p99 ≤ 0.5 s; unknown ≤ 0.6 s, cached on retry; signing p99 ≤ 500 ms alongside | 4 first reveals p99 198-299 ms; unknown 57-140 ms, retry 0.22-0.26 ms; signing p99 alongside 145-260 ms | 5.7-8.1 | met |
| B10 | single ≤ 3 s (amd64) / ≤ 5 s (arm64); the knee; RSS ≤ base + P × 320 MiB | P = 1: 1.48-1.54 s; throughput P=1 0.65-0.68/s, P=2 1.17-1.29/s, P=4 2.16-2.22/s, P=8 2.45-2.86/s, P=16 1.04-2.00/s; peak RSS P=1 521, P=2 1,034, P=4 2,060, P=8 2,830, P=16 5,606 MiB | 5-21 | single met; knee at P = 4-8; RSS not met at any P (bound open, see [B10](#argon2id-keystore-decryption-b10-internalkeyskeystoreqrlv1)) |
| B11 | 10k raw: ready ≤ 30 s, `publicKeys` ≤ 5 s | ready 4.04 s, `publicKeys` 955 ms, peak RSS 625 MiB | 18-19 | met |
| B11 | keystores: ready ≤ 1.2 × N × t_B10 / P | 100: P = 8, t_B10 = 9.06 s: ready 2 min 10 s, bound 2 min 16 s, peak RSS 4,195 MiB. 1,000: t_B10 = 9.71 s before the load and 3.66 s after it: ready 12 min 14 s, bound 24 min 17 s, peak RSS 4,639 MiB | 14-32 | met under the threshold's rule (the larger t_B10); the load fell during the 1,000-keystore run, and against the t_B10 measured after it (bound 9 min 9 s) it would have missed |
| B12 | B7 p99 during the reload ≤ 2 × without | 3 runs, every burst signed (B12 now sends new signing roots per burst): B7 p99 114-137 ms without a reload, 250-471 ms during a reload of 100 standard-KDF keystores (2.2-3.4 ×); the reload took 58-62 s at 4.0-4.3 s per decrypt | 5.7-9.4 | not met (3 of 3); the burst still met B7's own bound (p99 ≤ 500 ms) |
| B13 | p50 ≤ 5 ms, p99 ≤ 20 ms; burst ≤ 100 ms; stalled DB fails in ≤ 5 s | attestation p50 1.37 ms, p99 1.81 ms; block p50 1.08 ms, p99 1.44 ms; burst of 33 wall p50 27.4 ms, p99 46.6 ms; stalled database 4.50 s | 8-12 | met |
| B14 | run ≤ 5 min; signing p99 during ≤ 2 × baseline | bbolt: steady state 10.9 s, 1.64 ×; first run on twice the window 7.2 s, 0.52 ×. Postgres: 34.1 s, 0.90 ×; 44.4 s, 0.52 × | 3.9-5.0 (bbolt), 8-12 (Postgres) | met |
| B15 | ≤ 2 s on a LAN; transient allocation ≤ 64 MB | plain 19.4 ms ± 1 %, 70 KiB; gzip 507 ms ± 6 %, 1.2 MiB (10 runs each) | 3.3-4.0 | met |
| B16 | 24 h with 4,096 keys: 0 failed duties; RSS flat within ± 10 %; no goroutine growth | not run: it needs a time-compressed driver of the mainnet duty schedule, which does not exist yet, and a reference VM for 24 h | — | open (release checklist) |
| B18 | ≤ 100 × t_B10 / P + 10 s; no write-deadline error | P = 8, t_B10 = 3.06 s: 46.1 s (28.9 s for 64, 17.3 s for 36) against 48 s; peak RSS 4,891 MiB | 12-14 | met |
| B19 | 0 idle-connection errors over 1 h with `IdleTimeout` 120 s | 1 h run (`make b19 B19_DURATION=1h`, alongside the other runs): 162 POSTs, 0 connection errors | 2-32 over the hour | met (the first 1 h run) |
| B20 | p99 handshake ≤ 200 ms on 4 vCPU | 5 runs: P-256 p99 22.0-25.1 ms (max 25.4 ms), RSA-2048 p99 42.8-106.2 ms (max 106.2 ms). B7 over TLS on HTTP/1.1: P-256 p99 325-371 ms, RSA-2048 211-382 ms; on h2: P-256 200-645 ms (over 500 ms in one run), RSA-2048 165-433 ms; 0 errors | 5.7-8.1 | storm met; B7 over TLS met in 19 of the 20 measurements (and missed once more in the sixth run: RSA-2048 on HTTP/1.1, p99 792 ms) |

The AWS KMS benchmark belongs to v2 and is not listed. Every B7-type latency here includes the loopback round trip
and a Go client on the same shared machine; the B7 misses are single runs next to passing ones, so the reference VMs
decide. The raw logs of Run V are not kept in the repository.

## ML-DSA-87 (B1-B4, `internal/crypto/mldsa87`)

**Status: open.** The criterion "B1-B4 meet their thresholds" is not yet confirmed. The only
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

**B15: met on the development machine.** **B19: met on the development machine** in its first 1 h run (Run V,
2026-10-20: 162 POSTs, 0 errors); the nightly job runs it every night.

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
| B19 | `TestB19IdleConnectionRace` (`make b19`) | 0 "server closed idle connection" or EOF errors over 1 h with `IdleTimeout` 120 s | 1 h run (Run V, 2026-10-20): 162 POSTs, 0 errors; earlier a 40 s smoke run (0 errors) and a 5 min run (2026-10-15: 14 POSTs, 0 errors) | met on dev machine |

Run E, 2026-10-15, Go 1.26.9, Apple M2 (8 cores, darwin/arm64), 10 runs of 10 requests each, load average 4-5 from
other work.

## End-to-end bursts and RANDAO reveals (B7-B9, the built binary)

**B7, B8 and B9: met on the development machine in Run F**, pending the reference VMs. Run H, on the same
machine under a much heavier load, missed the B7 and B9 latency bounds; see below.

```
make bench-e2e     # REMOTESIGNER_BENCH=1 go test -run '^TestB([789]|20)' ./test/acceptance/
```

Each test starts the built binary on loopback with token auth and bbolt slashing protection, and drives it with a Go
client on `http.DefaultTransport`; latencies are measured by the client, so they include the loopback round trip.
B7 sends the t = 20 s burst of the e2e network at once: 32 `ATTESTATION` requests, each recorded in the store, and
126 `SYNC_COMMITTEE_MESSAGE` requests. Every request is for a key of its own (158 keys): with the response cache, a
repeat of a key and signing root would be answered without signing, and the burst would no longer measure 158
signatures; before the response cache, the 126 messages shared the attestations' 32 keys. B8 sends 16 copies of the
mainnet-preset 128-signature contribution (1,197,210 bytes) at once, so eight wait for a large-body slot, and reads
the process RSS with `ps` before and after. B9 sends four concurrent first reveals (each a scan of up to 2^20
layers) while the B7 burst runs, then an unknown commitment twice: the second answer must come from the negative
cache. B7 runs over plaintext HTTP here; its TLS variants are part of B20 below.

| ID | Test | Threshold | Development-machine results (5 runs) | Verdict |
|---|---|---|---|---|
| B7 | `TestB7AttestationBurst` | last response ≤ 1 s, p99 ≤ 500 ms, 0 errors | last 203-331 ms, p50 26-38 ms, p99 200-328 ms, 0 errors | met on dev machine |
| B8 | `TestB8ContributionBurst` | each ≤ 250 ms; RSS increase ≤ 128 MiB | slowest 31-33 ms; RSS +28-33 MiB | met on dev machine |
| B9 | `TestB9RandaoReveal` | reveal p99 ≤ 0.5 s; unknown ≤ 0.6 s and cached on retry; B7 signing p99 unaffected (≤ 500 ms) | 4 concurrent first reveals p99 203-224 ms; unknown 54-115 ms, retry 0.21-0.30 ms; signing p99 alongside 159-259 ms | met on dev machine |

Run F, 2026-10-15, Go 1.26.9, Apple M2 (8 cores, darwin/arm64), load average 2.6-3.4 from other work, with the
earlier 32-key B7, before the response cache.

Run H, 2026-10-16, Go 1.26.9, the same machine under a load average of 9-20 from other work (the machine is shared,
and no quieter window came), with the 158-key B7 and the response cache (B7 five runs, B8 and B9
three): B7 last response 526-1,491 ms, p99 520-1,480 ms, 0 errors; B8 slowest 40-78 ms, RSS +32-35 MiB; B9 first
reveals p99 542-635 ms, unknown 69-99 ms, retry 0.36-0.51 ms, signing p99 alongside 461-821 ms. B7 and B9 miss their
latency bounds in Run H, by an amount that tracks the load; they are re-measured on a quiet machine or the reference
VMs before v1.0, together with B20's TLS variants.

## Argon2id keystore decryption (B10, `internal/keys/keystore/qrlv1`)

**Single-decrypt latency: met on the development machine. Scaling knee: recorded below. RSS bound: not met**; the
reason is the Go runtime rather than the decryptor (see "Memory" below). Concurrent keystore loading must therefore
budget 512 MiB per running decrypt. All rows are still to be re-run on the reference VMs.

```
go test -c -o qrlv1.test ./internal/keys/keystore/qrlv1/ && cd internal/keys/keystore/qrlv1
../../../../qrlv1.test -test.run '^$' -test.bench B10 -test.benchtime 5x -test.count 3
for p in 1 2 4 8 16; do GOMEMLIMIT=$((p*320+64))MiB /usr/bin/time -l ../../../../qrlv1.test -test.run '^$' \
    -test.bench "B10Argon2idDecrypt/P=$p\$" -test.benchtime 2x; done    # Linux: /usr/bin/time -v
```

`BenchmarkB10Argon2idDecrypt` decrypts the standard-KDF golden keystore (`qrl-v1-standard.json`: Argon2id `t=8`,
`m=262144` KiB, `p=1`) through `Keystore.Decrypt`, the path every keystore takes, including key derivation and the
public-key comparison. One op is a round of P decrypts started together; the benchmark reports the throughput
(`decrypts/s`) and the per-decrypt latency (`s/decrypt`, `max-s/decrypt`). RSS is the process's peak resident set
from `/usr/bin/time`, with `GOMEMLIMIT` set to P × 320 MiB + 64 MiB; the test binary alone peaks at 6 MiB.

| ID | Measure | Threshold | Development-machine results | Verdict |
|---|---|---|---|---|
| B10 | single decrypt (P = 1) | ≤ 3 s (amd64), ≤ 5 s (arm64) | 1.46-1.49 s per decrypt | met on dev machine (arm64) |
| B10 | throughput by P | report the scaling knee | P=1: 0.68/s; P=2: 1.22-1.30/s; P=4: 2.12-2.19/s; P=8: 1.88-2.62/s; P=16: 0.96-1.54/s | knee at P = 4 |
| B10 | per-decrypt latency by P | none (informational) | P=2: 1.54-1.64 s; P=4: 1.82-1.87 s; P=8: 2.97-4.16 s (slowest 7.2 s); P=16: 10.2-16.2 s (slowest 27.6 s) | |
| B10 | peak RSS by P, `GOMEMLIMIT` set | ≤ base + P × 320 MiB | P=1: 521 MiB; P=2: 1,034 MiB; P=4: 1,547 MiB; P=8: 4,111 MiB; P=16: 6,163 MiB | not met: up to base + P × 512 MiB |
| B10 | `BenchmarkDecryptLightKDF` (`m=4096` KiB), for reference | none | P=1: 21 ms per decrypt (47/s); P=8: 40-45 ms per decrypt (139-153/s) | |

Run G, 2026-10-16, Go 1.26.9, Apple M2 (4 performance and 4 efficiency cores, 16 GiB, darwin/arm64). On arm64
`x/crypto/argon2` runs its generic Go code; it has assembly for amd64 only. Throughput and latency: three runs of
five rounds per P at load average 16-25 from other work. RSS: one run of two rounds per P at load average 25-32.

- **Knee.** Throughput grows almost linearly up to P = 4, the number of performance cores, and stops there: P = 8
  adds 0-20 % at about twice the latency, and P = 16 loses throughput, with the slowest decrypt of a round taking
  over 20 s. Each run makes about eight passes over its 256 MiB block, so beyond the fast cores the runs also
  compete for memory bandwidth. The heavy background load lowers the absolute numbers at P ≥ 8, so on a quiet
  machine the knee may sit somewhat higher, but not near 16. The amd64 assembly path may move it; the reference VMs
  decide the default concurrency cap.
- **Memory.** Every decrypt allocates one 256 MiB Argon2id block. The block becomes garbage when its decrypt returns,
  but the next decrypt allocates its own block before a garbage collection has reclaimed the old one, so a decrypt
  slot holds up to two blocks at its peak. With all P decrypts of a round starting together, peak RSS comes close to
  base + P × 512 MiB. `GOMEMLIMIT` lowered it only at P = 4 (1,547 MiB against 2,059 MiB without it); at P = 1, 2
  and 8 the peaks were equal, and at P = 16 it was 6,163 MiB against 5,906 MiB. The 320 MiB-per-decrypt bound is
  therefore not reached, and a loader that runs decrypts concurrently has to count 512 MiB for each.
- **Open before v1.0: a decision for the maintainers.** B10 gates v1.0, and its RSS bound was not met in any run
  (Run G, and Run V in [the v1.0 table](#v10-release-run-dev-machine)). Either the bound is revised to what the
  keystore loader's Argon2id semaphore budgets, 512 MiB for the process plus 512 MiB per standard-KDF decrypt (every
  run so far meets it: Run V peaked at 521, 1,034, 2,060, 2,830 and 5,606 MiB for P = 1, 2, 4, 8 and 16, against
  1,024 to 8,704 MiB), or a mitigation is added in the loader and B10's RSS rows are measured again with it. The
  loader already counts 512 MiB for each standard-KDF decrypt it admits
  ([`operations/reload.md`](operations/reload.md#6-memory-for-keystore-decryption)), so its memory stays within the
  budget either way. For Run V a garbage collection after each decrypt, inside its slot, was tried in a throw-away
  copy of the benchmark (not in the code): peak RSS 265, 777, 1,289 and 2,157 MiB for P = 1, 2, 4 and 8, which meets
  320 MiB per decrypt at P = 1 and 8 but not at P = 2 (388 MiB per decrypt) and only just misses it at P = 4, so that
  mitigation alone would not make the 320 MiB bound hold.

## TLS handshake storm (B20, the built binary)

**B20: met on the development machine** (the storm, under load), pending the reference VMs. The B7-over-TLS
variants are recorded alongside; they miss B7's bounds in the same runs as plaintext B7 does.

```
make bench-e2e     # or: REMOTESIGNER_BENCH=1 go test -run '^TestB20' -v ./test/acceptance/
```

`TestB20TLSHandshakeStorm` starts the built binary with token auth over TLS 1.3, once with an ECDSA P-256 and once
with an RSA-2048 certificate (PEM files), and opens 160 connections at once, each a full handshake (no session
cache, so nothing resumes), timing dial plus handshake at the client and keeping every connection open until all
are done. It then replays the B7 burst over TLS against a fresh signer twice: on HTTP/1.1, where a client with its
own TLS configuration (as qrysm's is) opens a connection, and so a handshake, per concurrent request, and on h2
(Go's default transport), which multiplexes the burst over one connection.

| ID | Test | Threshold | Development-machine results (5 runs) | Verdict |
|---|---|---|---|---|
| B20 | storm, P-256 | p99 handshake ≤ 200 ms on 4 vCPU | p50 15.7-32.5 ms, p99 24.2-47.0 ms, max 49.4 ms | met on dev machine |
| B20 | storm, RSA-2048 | as above | p50 33.8-54.8 ms, p99 63.3-103.8 ms, max 104.1 ms | met on dev machine |
| B20 | B7 over TLS, HTTP/1.1, P-256 / RSA-2048 | B7's: last ≤ 1 s, p99 ≤ 500 ms, 0 errors | P-256 last 404-915 ms, p99 398-904 ms; RSA-2048 last 360-1,083 ms, p99 353-1,072 ms; 0 errors | pending: plaintext B7 misses in the same runs |
| B20 | B7 over TLS, h2, P-256 / RSA-2048 | as above | P-256 last 232-1,228 ms, p99 226-1,211 ms; RSA-2048 last 361-2,066 ms, p99 354-2,056 ms; 0 errors | pending: plaintext B7 misses in the same runs |

Run H as above (load average 9-20). The handshake itself is cheap: even RSA-2048, whose server-side signature is
the expensive part, stays at half the bound with every core busy elsewhere. The TLS bursts are as fast as the
plaintext one in the same runs, within the noise, so TLS adds no measurable cost to B7 here; the HTTP/1.1 variant's
160 handshakes cost less than the scheduling delays of the loaded machine.

## Slashing-protection pruning (B14, bbolt variant, `internal/slashing`)

**B14 (bbolt): met on the development machine**, pending the reference VMs. The Postgres variant is in
[the next section](#postgres-slashing-protection-b13-b14-internalslashingpgstore).

```
make bench-b14     # REMOTESIGNER_BENCH=1 go test -run '^TestB14' ./internal/slashing/boltstore/
```

`TestB14PruningBolt` builds a bbolt store with 4,096 validators that each keep 512 epochs: one attestation per epoch,
one block every 32 epochs, with the mainnet preset's 128 slots per epoch. It prunes two histories with
`slashing.Prune` (512 epochs kept): the steady state, 512 epochs plus the six a 12 h interval adds (2.1 million
attestations, 403 MiB), and the first run on twice the window, 1,024 epochs (4.2 million attestations, 659 MiB),
which deletes half of them. Attestation signing through `slashing.Engine` runs before and during each prune: a burst
of 32 concurrent attestations from 32 distinct keys (4,096 keys over 128 slots) every 250 ms, 240 times the duty
rate of 60 s slots; every call is a synced bbolt transaction. The pruner writes 16 validators per transaction.

| ID | Test | Threshold | Development-machine results (3 runs) | Verdict |
|---|---|---|---|---|
| B14 | `TestB14PruningBolt/steady_state` | run ≤ 5 min; signing p99 during the run ≤ 2 × baseline | run 2.4-9.7 s (4,096 validators, about 26,000 attestations and 4,096 blocks deleted); signing p99 baseline 284-300 ms, during 122-235 ms (0.43-0.82 ×) | met on dev machine |
| B14 | `TestB14PruningBolt/first_run_on_twice_the_window` | as above | run 6.2-14.0 s (2.1 million attestations and 65,536 blocks deleted); signing p99 baseline 238-329 ms, during 225-237 ms (0.68-0.95 ×) | met on dev machine |

Run I, 2026-10-16, Go 1.26.9, Apple M2 (8 cores, darwin/arm64), APFS, load average 6-15 from other work. Signing
latency is bounded by bbolt's single writer: each attestation is its own fsynced commit, so a burst of 32 queues on
the write lock, and the baseline p99 is the last of those commits. A prune transaction takes the write lock as often
as one more signer would, so signing during the run stays near its baseline (in all six measurements the baseline
p99 was the higher one, within the noise of a loaded machine). Batching signing commits (`db.Batch`) was left out:
the threshold is met without it.

## Postgres slashing protection (B13, B14, `internal/slashing/pgstore`)

**B13 and B14 (Postgres): met on the development machine in 5 of 6 and 3 of 3 runs of the final code**, pending the
reference VMs with the database on its own host on the same LAN.

```
make bench-postgres   # REMOTESIGNER_BENCH=1 go test -run '^TestB1[34]' ./internal/slashing/pgstore/, against
                      # the server REMOTESIGNER_TEST_POSTGRES names
```

`TestB13Postgres` runs check-and-records through `slashing.Engine` on a store with the signing profile (a pool of 16,
2 kept open, 4.5 s per call), reached through a TCP proxy: 1,000 single attestations and 1,000 single blocks one
after another over 64 keys, then 200 bursts of 33 concurrent attestations from 33 keys, 100 ms apart. It then stops
the proxy forwarding while the connections stay open, as a database stopped with `SIGSTOP` looks to its clients, and
times one more attestation. `TestB14PruningPostgres` is the bbolt variant's B14 on Postgres: the same histories,
written in SQL (358 MB for the steady state, 696 MB for the first run on twice the window), and the same signing load,
pruned as the signer prunes a Postgres store: a pool of one connection, one validator per transaction, and a rest
after each transaction as long as it took (`PruneConfig.Pace` 1).

| ID | Test | Threshold | Development-machine results | Verdict |
|---|---|---|---|---|
| B13 | `TestB13Postgres`, single attestation | p50 ≤ 5 ms, p99 ≤ 20 ms | p50 1.37-3.82 ms, p99 2.94-14.6 ms in 5 runs; 3.64 and 49.6 ms in the sixth | met on dev machine (5 of 6) |
| B13 | `TestB13Postgres`, single block | as above | p50 1.11-3.56 ms, p99 1.47-9.28 ms in 5 runs; 64.6 ms in the sixth | met on dev machine (5 of 6) |
| B13 | `TestB13Postgres`, burst of 33 | burst ≤ 100 ms (p99 of the bursts' wall times) | wall p50 19.5-26.4 ms, p99 35.4-91.6 ms in 5 runs; 178 ms in the sixth | met on dev machine (5 of 6) |
| B13 | `TestB13Postgres`, stalled database | fails in ≤ 5 s | 4.50 s in every run, with the call's deadline; through the built signer 500 `STORE_UNAVAILABLE` after 4.51 s (`TestRunPostgres`) | met |
| B14 | `TestB14PruningPostgres/steady_state` | run ≤ 5 min; signing p99 during the run ≤ 2 × baseline | run 34.9-35.4 s (4,096 validators, about 28,000 attestations and 4,096 blocks deleted); signing p99 baseline 55-81 ms, during 24-37 ms (0.44-0.50 ×) | met on dev machine |
| B14 | `TestB14PruningPostgres/first_run_on_twice_the_window` | as above | run 44.8 s-1 min 58 s (2.1 million attestations and 65,536 blocks deleted); signing p99 baseline 228-302 ms, during 97-136 ms (0.32-0.59 ×) | met on dev machine |

Runs Q (unpaced pruning, three check-and-record round trips more) and R (the final code), 2026-10-19, Go 1.26.9,
Apple M2 (8 cores, darwin/arm64), PostgreSQL 17.11 (`postgres:17-alpine`, default settings) in Docker Desktop on the
same machine, reached through its port forwarding; load average 2-44 from other work, which moved by a factor of ten
within single runs. The numbers are dominated by the round trip through Docker's port forwarding, which was 0.18 ms at
the median on a quiet machine and 0.5 ms, with a p99 of 4.5 ms, at a load average of 23:

- **B13.** In run Q an attestation took eight round trips and a block six; at the median both cost 5 ms
  (attestation p50 4.96-5.09 ms, p99 14.4-28.3 ms over 3 runs), missing the threshold. The final code sends `BEGIN`,
  the validator's lock and the read of its flag and watermarks in one pipeline, and reads both surround candidates in
  one statement, so an attestation is five round trips and a block four. The run that missed (p99 49.6 ms) ran while
  the load average rose from 7 to 14. The stalled-database bound is the store's 4.5 s per call, which leaves the
  response time inside the API's 5 s write deadline.
- **B14.** Unpaced, the prune ran in 12.7-72 s, and in one of three runs signing p99 during the steady-state prune was
  2.46 × its baseline: the pruner's one connection kept the database busy between the signers' transactions. Paced,
  the run takes about twice as long and signing during it stays below its baseline. As with bbolt, the baseline p99
  was the higher one in every paced run: the baseline's 40 bursts are the first after the history was written, while
  the bursts during the run are steadier load that the machine schedules on its faster cores.

## Key loading and reload (B11, B12, the built binary)

**B11: met on the development machine**, pending the reference VMs. **B12: not met on the development machine** in
Run V, the first run in which B12 measured signing (see below). The keystore rows of B11 are met in runs L and V,
measured against the threshold's bound; run K's 1,000-keystore load, on a machine loaded by other work, did not meet
that bound. Every run shared the machine with other work, so the absolute times say much about that load.

```
make bench-loading     # REMOTESIGNER_BENCH=1 go test -run '^TestB1[12]' ./test/acceptance/
```

B11 starts the built binary and measures, from process start, the time to `/upcheck` 200: once with 10,000 `file-raw`
keys (then the full `GET /api/v1/consensus/publicKeys`, 51.9 MB), and once each with 100 and 1,000 standard-KDF
deposit CLI keystores (Argon2id `t=8`, `m=262144` KiB) in `--keystores-path` with one password file. The keystore
bound is the threshold's 1.2 × N × t_B10 / P. P is the number of standard-KDF decrypts the signer's semaphore runs at once,
from its startup log (the test checks it against the sizing it computes from the same environment). t_B10 is the
mean time of one decrypt when P run together, the B10 measure, taken in the test process apart from the load: once
before the signer starts and once after it stops, and the larger of the two counts. The mean decrypt time the signer
measured during the load ("Keys loaded": `decrypt-time` / `decrypts`) is logged beside it, with the share of the P
decrypt slots the load kept busy. It is not the threshold: a bound built from the load's own decrypt time only
checks that share and cannot catch a load whose decrypts are slow. B12 starts with B7's 158 `file-raw` keys, runs the
B7 burst four times (the first warms up; the median p99 of the other three is the baseline), adds 100 standard-KDF
keystores, posts `/reload`, waits 2 s and runs the burst again while the reload decrypts. Each burst has signing
roots of its own (the attestations' epochs rise by one per burst, the sync committee messages name another block
root), so that every request is signed. Before the v1.0 run B12 sent one burst over 32 keys four times, so from the
second burst on the response cache answered every request: its earlier rows compare cache hits, not signing. Peak
RSS is sampled with `ps` every 100 ms.

| ID | Test | Threshold | Development-machine results | Verdict |
|---|---|---|---|---|
| B11 | `TestB11StartupFileRaw` (10,000 keys) | ready ≤ 30 s; `publicKeys` ≤ 5 s | ready 1.09 s, `publicKeys` 554 ms, peak RSS 635 MiB (run K); ready 2.13 s, 813 ms, 617 MiB (run J) | met on dev machine |
| B11 | `TestB11StartupKeystores/100` | ready ≤ 1.2 × N × t_B10 / P | run L: P = 8, t_B10 = 3.33 s (2.88 s before the load, 3.33 s after it): ready 46 s, bound 50 s; 3.56 s per decrypt during the load, slots 97 % busy; peak RSS 4,375 MiB. Run K: ready 35 s; t_B10 not measured before the load, B10's 2.97-4.16 s gives a bound of 45-62 s | met on dev machine |
| B11 | `TestB11StartupKeystores/1000` | as above | run L: P = 8, t_B10 = 3.55 s (2.93 s before, 3.55 s after): ready 6 min 49 s, bound 8 min 52 s; 3.26 s per decrypt during the load, slots 100 % busy; peak RSS 5,138 MiB. Run K: ready 20 min 3 s against 10 min 14 s (t = 4.09 s, measured after the load; 9.61 s per decrypt during it) | met on dev machine in run L; run K not met under heavy load; re-run on the reference VMs |
| B12 | `TestB12ReloadDuringBurst` | B7 p99 during the reload ≤ 2 × B7 p99 without | Run V (every burst signed): p99 114-137 ms without, 250-471 ms during the reload (2.2-3.4 ×), 3 runs. Run K, cache hits (see above): p99 256 ms without (median of 181, 256 and 278 ms), 322 ms during a reload of 100 standard-KDF keystores; the reload took 59 s at 4.0 s per decrypt | not met on dev machine (Run V); run K did not measure signing |

Run L, 2026-10-18, Go 1.26.9, Apple M2 (4 performance and 4 efficiency cores, 16 GiB, darwin/arm64): the keystore
rows of B11 only, load average 2.4 at the start and 9-16 during the loads, which ran eight Argon2id decrypts at once
themselves. Run K, the same day and machine: load average 5 at the start, 30-37 from other work during the
1,000-keystore load and B12. It compared the ready time with a bound built from the decrypt time the signer
measured during the load, which is not the threshold's bound; against t measured after the load its 1,000-keystore load
missed by about 2x, while the in-load decrypt time (9.61 s) shows that the other work slowed every decrypt. In both
runs the signer sized its semaphore from half the RAM (7.5 GiB budget, P = 8, the CPU count). Run J, earlier the same
day, is the `file-raw` row of an attempt at load average 50-60 whose keystore rows missed the bound (100 keystores:
4 min 53 s against 3 min 20 s, while the load average moved between 20 and 60).

- **Memory.** The keystore runs peaked at about 8 × 512 MiB, the semaphore's budget for eight standard-KDF decrypts,
  plus the process, as B10's memory note predicts; run L's 1,000-keystore load reached 5,138 MiB, still well within
  the 8 GiB limit the budget was sized from. The 10,000 `file-raw` keys took about 620 MiB, about 60 KiB per
  key ([`operations/reload.md`](operations/reload.md#6-memory-for-keystore-decryption)).
- **Reload isolation.** A reload loads at most `GOMAXPROCS − 1` sources at once, so one CPU stays free for signing.
  With every burst signed (Run V), B12's p99 rose 2.2-3.4 times during a reload that kept seven Argon2id runs busy on
  this machine's eight cores, four of them efficiency cores; the burst stayed within B7's 500 ms. Whether one free
  CPU is enough on the 4-vCPU reference VMs, or a reload must leave more, is for their run to show.

## Keymanager import (B18, the built binary)

**B18: met on the development machine**, pending the reference VMs.

```
make bench-keymanager     # REMOTESIGNER_BENCH=1 go test -run '^TestB18' ./test/acceptance/
```

B18 starts the built binary with `--key-manager-api-enabled` and imports 100 standard-KDF deposit CLI keystores
(Argon2id `t=8`, `m=262144` KiB, each declaring its pubkey) through `POST /qrl/v1/keystores`. An import takes at most
64 keystores, so the threshold's single request of 100 is sent as two, 64 and then 36, and the time runs from the
first request to the second response. The bound is the threshold's 100 × t_B10 / P + 10 s, with P and t_B10 measured
as for B11 (above): P from the signer's startup log, t_B10 in the test process before the signer starts and after it
stops, the larger of the two. Both responses must be 200 with every keystore imported, which a write-deadline error
(10 minutes) would cut short. Peak RSS is sampled with `ps` every 100 ms.

| ID | Test | Threshold | Development-machine results | Verdict |
|---|---|---|---|---|
| B18 | `TestB18KeymanagerImport` | ≤ 100 × t_B10 / P + 10 s; no write-deadline error | run O: P = 8, t_B10 = 2.59 s (2.59 s before, 2.54 s after): imported in 35.9 s (23.3 s for the 64, 12.6 s for the 36), bound 42 s; peak RSS 4,448 MiB. Run M: t_B10 = 5.05 s: 60.7 s against 73 s; peak RSS 4,392 MiB. Run N: t_B10 = 2.86 s: 47.6 s against 45.7 s, missed. Run P (2026-10-19, the final code): t_B10 = 2.66 s (2.59 s before, 2.66 s after): 43.0 s (29.4 s and 13.6 s) against 43.2 s; peak RSS 4,379 MiB | met on dev machine in runs M, O and P |

Runs M, N and O on 2026-10-18 and run P on 2026-10-19, Go 1.26.9, Apple M2 (4 performance and 4 efficiency cores,
16 GiB, darwin/arm64), on a machine shared with other work: load average 9.4 at the start of run M and 18 at its end,
10.6 to 14.6 during run N, 4.9 to 7.2 during run O, and 6.8 at the start of run P and 14.7 at its end. Runs M and N
committed each imported key on its own (two synced store transactions and a directory sync per key, about 30 ms per
key here); run N missed by 1.9 s. Runs O and P are the code as it stands: the keys' files are written in parallel and
the keys registered and enabled in one transaction each, which commits 64 keys in about 0.7 s instead of 2 s. Run P
met the bound by only 0.2 s, at a higher load than run O. The 64 keystores of the first request take eight rounds of
P = 8 decrypts and the 36 of the second five, thirteen rounds in all, as one request of 100 would; the bound allows
12.5, so the 10 s also covers that last partial round.

## Binary size with the secret stores (no benchmark ID)

No benchmark is assigned to the secret stores. Their SDKs are linked by the default flavour only, and the release
binaries were measured before and after they landed, built as the release builds them (`CGO_ENABLED=0 -trimpath
-ldflags '-s -w'`), on the development machine (Apple M2, Go 1.26.9). These are dev-machine numbers (MB is 10^6
bytes). The "after" sizes were measured on 2026-10-19 at load average 13-25, from other work, which does not change a
size, with every secret store in: smithy-go a direct requirement, and the later fixes (each GCP page under its own
timeout, the reference-counted client cache, unsized response bodies read into a growing buffer).

| Target | `remotesigner` before | `remotesigner` after | `remotesigner-consensus` before | `remotesigner-consensus` after |
|---|---|---|---|---|
| linux/amd64 | 13.99 MB | 26.70 MB | 13.99 MB | 14.60 MB |
| linux/arm64 | 12.98 MB | 24.71 MB | 12.98 MB | 13.57 MB |
| darwin/arm64 | 13.32 MB | 25.63 MB | 13.32 MB | 13.92 MB |

- **Default flavour: +12.7 MB** (linux/amd64), from aws-sdk-go-v2, cloud.google.com/go/secretmanager with gRPC,
  OpenTelemetry and the Google auth libraries, and azure-sdk-for-go with MSAL.
- **Consensus flavour: +0.61 MB**, which links no cloud SDK (`TestCloudSDKsInDefaultFlavourOnly`). The upgrades of
  `google.golang.org/protobuf` and `golang.org/x/*` that the SDKs required account for 0.02 MB of it (the base rebuilt
  with only those upgrades: 14.01 MB). The rest is the HashiCorp Vault client, which works in both flavours, and the
  part of `net/http` it is the first to use: the HTTP client, its transport and its HTTP/2 client.
