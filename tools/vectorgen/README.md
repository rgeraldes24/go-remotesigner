# vectorgen

> **Warning: the built tool is a GPL-3.0 combined work. Never distribute it.**
>
> `vectorgen` links qrysm (`github.com/theQRL/qrysm`, GPL-3.0). Its source files here are Apache-2.0, like the rest
> of the repository, but any binary built from this module combines them with GPL code, so it may only be
> distributed under the GPL. It is a development tool: it is never part of a release, an image or any other shipped
> artefact, and the signer module never imports it. Run it with `go run`; do not publish a binary.

`vectorgen` is a separate Go module (its own `go.mod`), so qrysm, its dependency graph and its `replace` directives
stay out of the signer's module. It has four jobs:

- **`gen`** writes the golden vectors under `testdata/vectors/` and the embedded network YAMLs under
  `internal/network/embedded/`, using qrysm's own code as the oracle. The output is data, dedicated to the public
  domain under CC0-1.0 (see `testdata/vectors/README.md` for the layout and the licence statement).
- **`verify`** posts every fixture to a running signer and checks the answers with qrysm's own verifier.
- **contract mode** drives a running signer with qrysm's own `remote-web3signer` keymanager, the client the qrysm
  validator signs through. It needs another qrysm commit than the golden vectors, so it is a second nested module,
  [`contract/`](#contract-mode), with its own pin; the same warning applies to it.
- **`interchange-check`** imports an EIP-3076 file, the signer's export, into a new qrysm validator database and
  checks it against the interchange fixture (section "Interchange round trip").

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
roots are equal because both fit one chunk); those records are flagged `"authoritative": false`.

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
both end-to-end networks, once with protection disabled and without genesis time (so no fixture is refused as a
repeat and the fixtures at the slot and epoch limits pass the clock bounds), and once with protection on (bbolt),
genesis time set and exits disabled (the RANDAO fixtures and the exits-disabled fixture), and fails on any failure or
on a skip the other run does not cover. It builds the binary itself unless `REMOTESIGNER_BINARY` names one; CI's
`vectors-verify` job passes the `make build` output.

`verify` exits 1 if any check fails. Its tests run it against a fake signer that answers from the fixtures, and
against fakes that sign the wrong root or sign selection proofs in hedged mode, which it must catch.

## Contract mode

`contract/` checks that the signer and the qrysm client it serves still speak the same JSON. It imports qrysm's
revived `remote-web3signer` keymanager and, against a running signer:

- calls `CheckCapabilities` with qrysm's configuration of the network, the interop genesis validators root and the
  genesis time;
- fetches the keys through the signer's `publicKeys` URL and looks for interop key 0;
- signs one `SignRequest` per signing oneof (`block_zond`, `blinded_block_zond`, `attestation_data`,
  `aggregate_attestation_and_proof`, `slot`, `exit`, `sync_message_block_root`, `sync_aggregator_selection_data`,
  `contribution_and_proof`, `registration`: the nine artifact types) with key 0, over signing roots qrysm computes,
  and checks each signature with qrysm's `ml_dsa_87.VerifySignature`; the keymanager verifies it too. The `epoch`
  oneof must be refused by the client (RANDAO is a reveal, not a signature);
- asks for one `RandaoReveal` at the current slot, which must pass qrysm's `randao.Verify` and, on a fresh signer,
  equal key 0's first reveal.

Both sides decode strictly (the signer refuses an unknown request field, the client an unknown response field), so a
field renamed on one side alone fails here, even when that side's own tests were updated to match.

```sh
make vectors-contract   # builds the signer and runs everything below, as CI's vectors-contract job does
```

`make vectors-contract` runs `TestVectorgenContract` and `TestVectorgenContractCatchesDTORenames` in
`test/acceptance`. The first starts the binary with the interop keys on each end-to-end network, bound to the
interop GVR, with `--network-genesis-time=1760000000`, bbolt slashing protection and voluntary exits enabled, and
requires all 14 checks to pass. The second shows that the run catches a deliberate DTO rename on either side,
without a broken branch: it builds a signer whose `AGGREGATION_SLOT` payload key and reveal response key are renamed
(`go build -overlay`), and a contract tool over a renamed copy of the pinned qrysm (`go build -modfile`) whose
`VOLUNTARY_EXIT` payload key and capabilities `selection_proof_mode` field are renamed, and requires each mutant to
fail exactly those two checks.

The module's own tests (`make vectors-test`) run the tool against a fake signer that answers from the golden
vectors. They check that the types qrysm's client puts on the wire are the nine artifact types, that every signing
oneof of `SignRequest` is driven, that a wrong signing root, a renamed reveal key or another genesis time each fail
exactly their check, and that the tool stops when `networks.json` disagrees with the pinned qrysm or interop key 0
is missing or malformed in `keys/interop.json`.

Against a signer you started yourself (keys from `testdata/vectors/keys/interop.json`, genesis time set, exits
enabled, on a fresh store so the reveal is a first use):

```sh
cd tools/vectorgen/contract
go run . -signer http://127.0.0.1:9000 -token-file <data-path>/auth-token -network end-to-end -genesis-time 1760000000
```

### Contract pin

The revived keymanager is on no theQRL or cyyber branch yet, and the v1.0 release waits for it: the merge of #60-#62
and the move of this pin to the merged commit are an open gate of the release checklist
([`docs/operations/release.md`](../../docs/operations/release.md#62-open-gates-this-repository-cannot-meet-today)
section 6.2). The pin is the tip of a stack of three qrysm PRs on `cyyber/qrysm` `0b9cdf25`, the commit the golden
vectors pin: rgeraldes24/qrysm#60 (branch `remote-signer/q1-randao-slot`, `8fc55fff`), which passes the proposal
slot to `RandaoRevealer` (the tool's RANDAO check calls `RandaoReveal` with it), then #61
(`remote-signer/q2-remote-keymanager`, `2e957846`), the revived keymanager, then #62 (`remote-signer/q3-vc-wiring`,
`eefefe92`), its validator wiring. One module cannot hold two qrysm versions, and moving the golden-vector pin would
change every fixture's generator record, so `contract/go.mod` pins qrysm on its own:

| Module | Replaced by | Why |
|---|---|---|
| `github.com/theQRL/qrysm` | `github.com/rgeraldes24/qrysm v0.0.0-20261015164126-eefefe9230e1` | The tip of #62: the RANDAO slot (#60) and the revived keymanager (#61) with the validator wiring on top, as the qrysm e2e runs it. A public fork, so CI fetches it through the module proxy |
| `github.com/theQRL/go-qrl` | `github.com/cyyber/go-qrl v0.3.2-0.20260918165407-a9f196d809aa` | qrysm's own replace |
| `github.com/grpc-ecosystem/grpc-gateway/v2` | `github.com/theQRL/grpc-gateway/v2 v2.0.0-20250214142603-49067762c97f` | qrysm's own replace |
| `github.com/json-iterator/go` | `github.com/prestonvanloon/go v1.1.7-0.20190722034630-4f2e55fcf87b` | qrysm's own replace |

`contract`'s `TestReplacesMirrorQrysm` fails when a replace differs from qrysm's `go.mod` at the pinned commit, and
the tool checks at start that `testdata/vectors/networks.json` agrees with the pinned qrysm on the selected network's
fork version and slot timing (`make vectors-contract` runs both networks). It prints the qrysm module it was built
with.

To bump the pin, for example to a new tip of #62 or, once #60-#62 merge, to the `theQRL` or `cyyber` commit that
carries them:

1. In `tools/vectorgen/contract`, point the replace at the full commit hash; `go mod tidy` rewrites it as a
   pseudo-version:

   ```sh
   go mod edit -replace=github.com/theQRL/qrysm=github.com/rgeraldes24/qrysm@<commit>
   go mod tidy
   go mod edit -require=github.com/theQRL/qrysm@<that pseudo-version>   # a placeholder; keep it equal to the pin
   ```

   The commit must be in a public repository, so that the module proxy, and CI, can fetch it.
2. Copy qrysm's own `replace` directives from its `go.mod` at that commit; `go test ./...` (`TestReplacesMirrorQrysm`)
   names any that differ.
3. Run `make vectors-test` and `make vectors-contract`. A failure is contract drift between the signer and that qrysm
   commit: fix the side that broke the contract (`docs/contract.md` section 20) rather than the check.
4. Update the table above and the contract row of `PROVENANCE.md` ("Golden vectors").

## Interchange round trip

`gen` also writes `testdata/vectors/interchange/qrysm-export.json`: the file qrysm's validator writes
(`ExportStandardProtectionJSON`, tab-indented as its CLI does) from a validator database holding a fixed history of
interop keys 0-3, and `interchange/index.json`, which lists that history.

```sh
cd tools/vectorgen
go run . interchange-check -file <export.json>
```

`interchange-check` imports the file into a new qrysm validator database with `ImportStandardProtectionJSON`, fails
if qrysm refuses it or marks any key slashable, exports the database again and requires that export to equal
`qrysm-export.json` byte for byte. Given the signer's export of the fixture, that proves the round trip: qrysm's
history survives the signer's import and export unchanged. `make vectors-verify-binary` runs it on the built
binary's `consensus import` and `consensus export` (`TestQrysmInterchangeRoundTrip` in `test/acceptance`); the
signer's own tests import the fixture without qrysm.
