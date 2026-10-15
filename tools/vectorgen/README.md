# vectorgen

> **Warning: the built tool is a GPL-3.0 combined work. Never distribute it.**
>
> `vectorgen` links qrysm (`github.com/theQRL/qrysm`, GPL-3.0). Its source files here are Apache-2.0, like the rest
> of the repository, but any binary built from this module combines them with GPL code, so it may only be
> distributed under the GPL. It is a development tool: it is never part of a release, an image or any other shipped
> artefact, and the signer module never imports it. Run it with `go run`; do not publish a binary.

`vectorgen` is a separate Go module (its own `go.mod`), so qrysm, its dependency graph and its `replace` directives
stay out of the signer's module. It has two jobs:

- **`gen`** writes the golden vectors under `testdata/vectors/` and the embedded network YAMLs under
  `internal/network/embedded/`, using qrysm's own code as the oracle. The output is data, dedicated to the public
  domain under CC0-1.0 (see `testdata/vectors/README.md` for the layout and the licence statement).
- **`verify`** posts every fixture to a running signer and checks the answers with qrysm's own verifier.

## Pins

`go.mod` pins qrysm to `cyyber/qrysm` `0b9cdf25` (identical to `rgeraldes24/qrysm` main) and repeats qrysm's own
`replace` directives, because replaces apply only in the main module:

| Module | Replaced by | Why |
|---|---|---|
| `github.com/theQRL/qrysm` | `github.com/cyyber/qrysm v0.2.1-0.20261012085230-0b9cdf251d1f` | The target consensus (hash-onion RANDAO, 64-byte addresses) is on no theQRL tag or branch |
| `github.com/theQRL/go-qrl` | `github.com/cyyber/go-qrl v0.3.2-0.20260918165407-a9f196d809aa` | qrysm's own replace; a test checks the two stay equal |
| `github.com/grpc-ecosystem/grpc-gateway/v2` | `github.com/theQRL/grpc-gateway/v2 v2.0.0-20250214142603-49067762c97f` | qrysm's own replace (its protos need the fork) |
| `github.com/json-iterator/go` | `github.com/prestonvanloon/go v1.1.7-0.20190722034630-4f2e55fcf87b` | qrysm's own replace, kept for parity |

`TestReplacesMirrorQrysm` fails when a replace differs from qrysm's `go.mod` at the pinned commit. Every fixture file
records the module versions it was generated with.

## Regenerating

```sh
make vectors            # = cd tools/vectorgen && go run . gen
git diff --exit-code    # CI does the same and fails on any difference
```

Generation takes about a minute: it builds qrysm's 256-validator interop genesis (one 2^20-layer RANDAO onion per
key), a real block, the random-root sets and two standard-KDF keystores. Two runs give byte-identical files; every
random choice is a fixed seed, and qrysm's block generator signs in deterministic mode here.

The build must not use the `minimal` tag. qrysm has minimal-preset SSZ code only under Bazel's `--config=minimal`, so
the minimal-preset contribution roots are computed with the mainnet code over the bitvector padded to 16 bytes (the
roots are equal because both fit one chunk); those records are flagged `"authoritative": false` (G2 §8.3).

## Verifying a running signer

```sh
cd tools/vectorgen
go run . verify -signer http://127.0.0.1:9000 -token-file <data-path>/auth-token
```

`verify` reads `GET /api/v1/consensus/capabilities` and picks the fixtures of the signer's network (the `end-to-end`
or `end-to-end-mainnet` fork version). Run the signer with the interop keys of `testdata/vectors/keys/interop.json`
loaded, on that network, bound to the fixture GVR (or with a pending trust-on-first-use pin). Then for each fixture:

- **Sign requests** (`signing/`): `POST /api/v1/consensus/sign/{pubkey}` with `request_json`. qrysm decodes
  `object_ssz_hex` and recomputes the signing root with `signing.ComputeSigningRoot`; the returned signature must pass
  qrysm's `ml_dsa_87.VerifySignature`, and selection proofs must equal the deterministic signature byte for byte when
  the signer reports `selection_proof_mode: deterministic`. A type the signer has disabled must answer 403
  `ARTIFACT_TYPE_DISABLED`. A 412 `CLOCK_BOUND`, or a 412 `SLASHING_*` with slashing protection on, is reported as
  skipped: run the signer without genesis time and with protection disabled (loopback only) to check every fixture.
- **Negative fixtures** (`negative/`): the status and `reason` must match.
- **RANDAO** (only when the signer knows its genesis time): the V5 refusals of `randao/requests.json`, then a first
  reveal for keys 0 and 1 at the current slot, which must pass qrysm's `randao.Verify` and equal the key's first
  reveal. A 429 is retried once after its `Retry-After`.

`make vectors-verify-binary` does all of this against the built binary: it runs the signer with the interop keys on
both end-to-end networks, once without genesis time (so the fixtures at the slot and epoch limits pass the clock
bounds) and once with genesis time and exits disabled (the RANDAO fixtures and the exits-disabled fixture), with
protection disabled, and fails on any failure or on a skip the other run does not cover.

`verify` exits 1 if any check fails. Its tests run it against a fake signer that answers from the fixtures, and
against fakes that sign the wrong root or sign selection proofs in hedged mode, which it must catch.
