# Benchmarks

Each benchmark is first run when its component lands, then re-run weekly and before every release. The thresholds
were set for the reference hardware: a 4-vCPU x86-64 cloud VM and a 4-vCPU Graviton-class arm64 VM, reporting p50,
p99 and p99.9 with `benchstat` over at least 10 runs. Rows measured elsewhere say so and must be re-run on the
reference VMs before v1.0.

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

## End-to-end bursts and RANDAO reveals (B7-B9, the built binary)

**B7, B8 and B9: met on the development machine in Run F**, pending the reference VMs. Run H (S7), on the same
machine under a much heavier load, missed the B7 and B9 latency bounds; see below.

```
make bench-e2e     # REMOTESIGNER_BENCH=1 go test -run '^TestB([789]|20)' ./test/acceptance/
```

Each test starts the built binary on loopback with token auth and bbolt slashing protection, and drives it with a Go
client on `http.DefaultTransport`; latencies are measured by the client, so they include the loopback round trip.
B7 sends the t = 20 s burst of the e2e network at once: 32 `ATTESTATION` requests, each recorded in the store, and
126 `SYNC_COMMITTEE_MESSAGE` requests. Since S7 every request is for a key of its own (158 keys): with the response
cache, a repeat of a key and signing root would be answered without signing, and the burst would no longer measure
158 signatures; until S7 the 126 messages shared the attestations' 32 keys. B8 sends 16 copies of the
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
32-key B7 of S5b.

Run H, 2026-10-16, Go 1.26.9, the same machine under a load average of 9-20 from other work (the machine is shared,
and no quieter window came during the milestone), with the 158-key B7 and the response cache (B7 five runs, B8 and B9
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
- **Open before v1.0.** B10 gates v1.0. Either the RSS bound is revised to 512 MiB per decrypt, the slot size of the
  keystore loader's Argon2id semaphore, or a mitigation (such as a garbage collection after each run, inside the
  semaphore slot) is added in the keystore loader and B10's RSS rows are measured again with it.

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
