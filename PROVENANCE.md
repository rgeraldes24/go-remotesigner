# Provenance

go-remotesigner is a Go port of Consensys Web3Signer for the QRL stack. This file records where every piece of
the repository comes from, so that the Apache-2.0 obligations (§4(b) modification notices, §4(c) retained notices)
can be checked and future upstream changes can be followed. `tools/headercheck` reads the file table below and fails
CI when a header does not match its class (see "Header classes").

## Upstream baseline

| Item | Value |
|---|---|
| Upstream project | Consensys Web3Signer, Apache-2.0 |
| Repository | https://github.com/Consensys/web3signer (redirects to `Consensys-Incorporated/web3signer`) |
| Commit | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| Version | `26.9.0-4-g30af06dc` (latest tag `26.9.0`) |
| Commit date | 2026-10-15 |
| Retrieved | 2026-10-15 |

Web3Signer files carry the notice `Copyright <year> ConsenSys AG.` (2018-2026). Every go-remotesigner file
translated or adapted from a Web3Signer file keeps that line verbatim and adds a modification notice.

Web3Signer's OpenAPI files (`openapi-specs/**`) carry no per-file notice; their only licence statement is the
Apache-2.0 block in `info.license`. `api/openapi/consensus.yaml`, which adapts them, keeps that block and names
ConsenSys AG, the upstream project's copyright holder, in a `Copyright 2020 ConsenSys AG.` header line (2020 is the
year on the notices of Web3Signer's eth2 signing, public-key and upcheck handlers, which serve these paths), so that
the attribution survives and `headercheck` can check the file as `w3s-derived`. Its signing schemas also follow
`ethereum/remote-signing-api` v1.4.0 (CC0-1.0), which Web3Signer's signing schemas reproduce.

## QRL code

No GPL code from qrysm (`github.com/theQRL/qrysm`, GPL-3.0) is copied into or imported by this module. `depguard`
denies every `github.com/theQRL/qrysm/**` import, `make nogpl` checks that `go list -deps` of the module (both
flavours) contains no qrysm package, and `go-licenses check` gates the dependency graph. Only the nested,
never-shipped modules `tools/vectorgen` and `tools/vectorgen/contract` may link qrysm, to generate test data and to
check the contract against qrysm's own client (see "Golden vectors").

The only qrysm content in the repository is its keystore v1 implementation, an island with its own MIT `LICENSE`
("Copyright (c) 2023 The Quantum Resistant Ledger"). That code is itself derived from Weald Technology's Apache-2.0
keystore v4 encryptor, whose copyright and licence notices were removed in the QRL copy: `norm.go` matches Weald's
`norm.go` line for line apart from the removed header, the package name and one added error check, and `encryptor.go`
and `decrypt.go` keep Weald's structure, function names, error strings and doc comments with "V4" renamed to "V1".
The QRL origin repository, `go-zond-wallet-encryptor-keystore` (history read from the `rgeraldes24` fork), was MIT
from its first commit (`5448561`, 2023-08-24); the implementation arrived in `a3587b0` (2023-08-29) without a Weald
notice.

| Item | Value |
|---|---|
| Upstream path | `pkg/go-qrl-wallet-encryptor-keystore` |
| Source commit | `cyyber/qrysm` `0b9cdf251d1f022957d35c4edeb6dd3ce42a617d` (2026-10-12), identical to `rgeraldes24/qrysm` main |
| Tree id | `6c97bfffa7d145c2be452fa4435c81b6c7532554` (the same tree in `theQRL/qrysm` main `e07a6007`) |
| Copy | `third_party/qrl-keystore/go-qrl-wallet-encryptor-keystore/`, pristine; `headercheck` verifies the tree id |
| Upstream of upstream | `wealdtech/go-eth2-wallet-encryptor-keystorev4` (https://github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4), Apache-2.0, "Copyright © 2019 - 2023 Weald Technology Trading" (per-file years 2019-2023); compared against `v1.4.1` (`1067d369`, 2023-07-29), released a month before the QRL copy. Notices stripped in the QRL copy. |

The copy under `third_party/` stays pristine, so the Weald lineage is recorded here, in `NOTICE` and in
`third_party/qrl-keystore/README.md` instead of in its files.

The hardened copy that is compiled into the signer is `internal/keys/keystore/qrlv1/`. Two of its files are copies,
recorded as `mit-derived`: `decrypt.go` (from upstream `decrypt.go`, the keystore types of `encryptor.go` and the
algorithm, cipher and IV size constants of `encrypt.go`) and `norm.go` (from `norm.go`, unchanged apart from the
package name). Because they modify Apache-2.0 code, their headers restore Weald's per-file copyright line from
`v1.4.1` ("Copyright © 2019 - 2023 Weald Technology Trading." for `decrypt.go`, `encryptor.go` and `encrypt.go`,
"Copyright © 2020, 2021 Weald Technology Trading" for `norm.go`) and the Apache notice next to the QRL MIT line,
under `SPDX-License-Identifier: MIT AND Apache-2.0` (Apache-2.0 §4(c)); `LICENSES/Apache-2.0.txt` and
`LICENSES/MIT.txt` hold the texts. `headercheck` requires this header of every `mit-derived` row whose upstream path
is in the QRL keystore. Of upstream `encrypt.go` only the constants `algoArgon2id`, `cipherAes256Gcm` and `ivSize`
are taken, with their comments; its encryption code is not copied, because the signer never writes keystores. The
package's other files (the keystore format, the password candidates and the tests) were written for this project and
are classed `new`. `headercheck` lists them by name and refuses any class but `mit-derived` for any other file under
`qrlv1/`, so that a file copied from upstream later cannot be recorded as `new`.

qrysm's keystore package imports neither `pkg/go-qrl-wallet-types` (tree `19f25ac100399096af79b50e65ded092a8078ae3`)
nor `pkg/go-qrl-types` (tree `fc5b262a3483358cbd4ce6f7bd7ea0ce20306dfd`) at `0b9cdf25`. Only its test
`encryptor_test.go` imports the former, to assert that the encryptor implements the wallet `Encryptor` interface, and
the latter reaches the keystore only as a dependency of the former. The hardened copy decrypts only and implements no
wallet interface, so neither package is vendored or copied.

## go-qrl

The default flavour links go-qrl (`github.com/theQRL/go-qrl`, LGPL-3.0-or-later) at `theQRL/go-qrl` `b92884a3a1d5`
(`v0.3.4-0.20260608175446-b92884a3a1d5`, no `replace`), unmodified, as a library: `internal/execution` imports its
`common`, `common/hexutil`, `core/types` and `crypto/pqcrypto/wallet` packages to build, encode and sign
transactions (`types.DynamicFeeTx`, `types.SignTx`, `types.NewZondSigner`, `types.Sender`) and to read and write
gqrl's JSON encodings. depguard allows go-qrl nowhere else and never its `cmd/**` or `internal/**`, the consensus
flavour (`-tags noexecution`) links none of it, and `test/repo` checks that every linked go-qrl file is LGPL
(`TestLinkedGoQRLIsLGPL`). No go-qrl code is copied into this repository: the `pqcrypto/wallet.Wallet` adapter of
`internal/execution/wallet.go` implements go-qrl's interface over this project's key, and the transaction methods'
behaviour (gqrl's required members, the `{raw, tx}` result, `qrl_fillTransaction`'s defaults, the transaction-pool
messages the retry matches) is written from facts about gqrl at that commit (`internal/qrlapi/api.go` and
`transaction_args.go`, `core/txpool`), not from its code. `NOTICE.execution` and `docs/operations/release.md` record
what the LGPL asks of the default flavour and how a release provides it.

The fill-sign-send flow of `qrl_sendTransaction`, its nonce retry loop and the signer's own downstream calls are
classed `w3s-derived` (Web3Signer's `SendTransactionHandler`, `TransactionTransmitter`, `RetryingTransactionTransmitter`,
`NonceTooLowRetryMechanism`, `RetryMechanism`, `VertxNonceRequestTransmitter` and `EthNonceProvider`), as is
`qrl_signTransaction` (`EthSignTransactionResultProvider`, `EthSendTransactionJsonParameters`,
`TransactionSerializer`). The parts with no Web3Signer counterpart (the wallet adapter, the payload check, the
policy file, the audit log, the chain-ID check, the per-sender locks) are classed `new`.

No go-qrl code is copied into the signer module. The execution-mode key code outside `internal/execution` (the account keystore of
`internal/keys/keystore/qrlv1/account.go` and its sealing helper in `internal/keys/keystoretest`, and the extended
seed of `internal/crypto/mldsa87/extended.go`) and `TextHash` in `internal/execution/methods.go` are written from
facts about go-qrl at `theQRL/go-qrl` `b92884a3a1d5`: the account keystore JSON that `accounts/keystore` writes (a
flat `crypto` section, a `Q` address, an id and version 1; Argon2id and AES-256-GCM over the 51-byte extended seed;
its light and standard Argon2id parameters), the extended seed (the descriptor `01 00 00`, then the 48-byte seed)
and `accounts.TextHash` (Keccak-256 of `"\x19QRL Signed Message:\n"`, the data's length in decimal, and the data).
The address and its QIP-55 form are go-qrllib's (MIT), which the signer calls. The keystore that go-qrl itself wrote,
used as a test fixture, is described under "Golden vectors".

## Written from facts

These components are written from specifications and facts, not from qrysm code. Their implementers do not open
qrysm's Go source while writing them. The facts, with their sources, are recorded in the notes under `docs/spec/`
(see `docs/spec/README.md`); implementers work from those notes and the sources they cite.

| Component | Fact note | Fact sources |
|---|---|---|
| SSZ hash-tree-root (`internal/ssz`) | `docs/spec/ssz-containers.md` | Ethereum consensus specs v1.5.0 (CC0-1.0): `ssz/simple-serialize.md`, merkleization rules |
| Consensus containers (`internal/consensus/types`) | `docs/spec/ssz-containers.md` | Ethereum consensus specs v1.5.0 and builder specs (CC0-1.0) for shapes; QRL sizes, limits and field order from the Apache-2.0-headed qrysm protos (`proto/qrysm/v1alpha1/attestation.proto`, `beacon_block.proto`, `sync_committee.proto`, `proto/qrl/v1/*.proto`); ML-DSA-87 sizes from FIPS 204; preset numbers re-declared as constants. The header-less (GPL) `beacon_state.proto` is not used. |
| Signing roots and domains (`internal/consensus/signingroot`) | `docs/spec/signing-roots.md` | Ethereum consensus specs v1.5.0 (CC0-1.0): `compute_fork_data_root`, `compute_domain`, `compute_signing_root`, `get_domain`, domain constants; the per-type domain and epoch rules from the remote-signing-api (CC0-1.0) and the builder specs (CC0-1.0, validator registration domain) |
| Hand-derived SSZ fixtures (`internal/consensus/testdata`) | `docs/spec/ssz-containers.md`, `docs/spec/signing-roots.md` | Computed by `gen_fixtures.py`, a second, independent Python implementation of the same CC0 specs with the QRL sizes above. It stays as an independent cross-check next to the golden vectors of `tools/vectorgen` (see "Golden vectors"). Its output is data. |
| Wire JSON (`api/openapi/consensus.yaml`, `docs/contract.md`), its strict codec (`internal/api/jsonutil`, the request codecs in `internal/consensus/types`) and the request policy (`internal/consensus/policy`) | `docs/contract.md` | `ethereum/remote-signing-api` v1.4.0 (CC0-1.0) and the Web3Signer OpenAPI files listed in the file table, with the QRL deltas documented in `docs/contract.md` |
| Network loader (`internal/network`) | `docs/spec/network-config.md` | qrysm config YAML key names and values as data: the values of qrysm's `config/params` mainnet, minimal, end-to-end and interop configurations at the pinned commit (`cyyber/qrysm` `0b9cdf25`, GPL-3.0), taken as data only with no code copied (for example mainnet `SECONDS_PER_SLOT` 60, `SLOTS_PER_EPOCH` 128, `SYNC_COMMITTEE_SIZE` 128, and the fork versions). The embedded YAMLs are generated by `tools/vectorgen` with qrysm's `ConfigToYaml` at that commit (program output, data only; see "Golden vectors"); the `genesis.ssz` prefix layout (genesis_time bytes 0-8, genesis_validators_root 8-40, slot 40-48, fork 48-64) from the consensus spec `BeaconState` field order, independently re-derived, not from the GPL proto; the genesis fork `{GENESIS_FORK_VERSION, GENESIS_FORK_VERSION, 0}` from the consensus spec's genesis initialisation |
| EIP-3076 conformance scenarios (`internal/slashing/slashingtest/eip3076.go`) | — | The conditions of EIP-3076 (CC0-1.0), authored as QRL scenarios with 2,592-byte keys. The `eth-clients/slashing-protection-interchange-tests` vectors are not used: that repository has no licence. |
| RANDAO reveal service (`internal/randao`, `internal/api/consensus/randao.go`) | `docs/contract.md` section 14 | The frontier rule (state `(m, R, last)`, the classes, the two-sided window, the new-layer conditions and their order, the per-key bucket, the slow-path budget and negative cache) is this project's own design, specified in `docs/contract.md` section 14, not taken from any implementation: qrysm keeps no reveal state and Web3Signer has no hash onion. The layers come from `internal/randao/onion`; the expected behaviour is checked against vectors V5 and V6, whose layer values qrysm's `crypto/randao` computed in `tools/vectorgen`. |
| RANDAO hash onion (`internal/randao/onion`) | `docs/spec/randao-onion.md` | The package is written from the facts and vectors V1-V3 of that note only; the golden vectors of `tools/vectorgen` later confirmed V1-V4 against qrysm's `crypto/randao`. The note records honestly that the construction (domain tag `qrl-randao-onion-v1`, `x_0 = SHA-256(tag ‖ seed48)`, `x_{j+1} = SHA-256(x_j)`, commitment `x_L`, default `L = 2^20`, reveal check `SHA-256(reveal) = commitment`) was **learned by reading qrysm's GPL `crypto/randao/onion.go`**; only these facts were taken. The package was written from the note without opening `onion.go`, and its vectors were computed independently with Python `hashlib`; vector V2 reuses the seed and length of qrysm's own onion test. The Go API uses its own names (`Base`, `Step`, `Top`, `Find`, `Advance`, `DefaultLength`); a test asserts that it exports none of qrysm's names `Origin`, `Next`, `Verify`, `Commitment`, `DefaultLayers`. The first draft did reuse two qrysm identifiers (`DefaultLayers`, which the design had named after qrysm's constant, and the unexported `domainTag`) and two doc-comment phrasings close to qrysm's; review caught these and they were renamed and reworded. The body of `Base` is the one idiomatic Go form of `SHA-256(tag ‖ seed)` and resembles qrysm's for that reason. The note's "Signer-level additions" (added with the contract, not package input) record two further GPL sources: the interop seed derivation behind vector V4, **learned by reading qrysm's GPL `runtime/interop`**, and the onion lengths used by qrysm's deposit tooling, interop genesis and unit-test helpers. Only facts were taken there too, and the V4 and V5 values were computed independently. |

## Golden vectors

`testdata/vectors/` holds golden vectors, and `internal/network/embedded/*.yaml` the named networks, both written by
`tools/vectorgen`. That nested module links qrysm at the pinned commit (`cyyber/qrysm` `0b9cdf25`) and
uses its code as the oracle: hash-tree-roots, domains and signing roots, deterministic ML-DSA-87 signatures, the
RANDAO onion, the interop genesis, `ConfigToYaml`, the keystore encoders, and its validator's EIP-3076
slashing-protection export and import (`validator/slashing-protection-history`), which give the interchange fixture
and the round-trip check `vectorgen interchange-check`.

- **The tool.** Its source files are this project's (class `new`, Apache-2.0). A binary built from it is a GPL-3.0
  combined work, so it is a development tool that is never built into a shipped artefact; `tools/vectorgen/README.md`
  says so. It has its own `go.mod`, so qrysm and its `replace` directives never enter the signer module's graph.
- **Its output.** The generated files are program output, not program text (GPL FAQ, "Is there some way that I can
  GPL the output people get from use of my program?"), and none reproduces qrysm source. They are dedicated to the
  public domain under CC0-1.0, as `testdata/vectors/README.md` and every file's `description` state, and each file
  records the module versions that generated it in its `generator` object. The exceptions are the keystore files of
  `testdata/vectors/keystores/` and `testdata/vectors/interchange/qrysm-export.json`, which keep their native
  formats (a keystore; the EIP-3076 file qrysm's validator writes); `keystores/index.json`, `interchange/index.json`
  and the README carry their CC0 dedication and generator record. JSON files outside `deploy/` carry no header row; the generated
  YAMLs carry the class `new` header.
- **Contract mode.** `tools/vectorgen/contract` is a second nested module of the same kind: class `new` sources, a
  GPL-3.0 combined work when built, never shipped, never imported by the signer module. It links qrysm at
  `rgeraldes24/qrysm` `eefefe9230e10a1ce0c9b05c04bd40556da29684` (2026-10-15, the tip of a stack of three PRs on
  `cyyber/qrysm` `0b9cdf25`: rgeraldes24/qrysm#60 `remote-signer/q1-randao-slot` `8fc55fff`, which passes the proposal
  slot to `RandaoRevealer`; #61 `remote-signer/q2-remote-keymanager` `2e957846`, the revived `remote-web3signer`
  keymanager; and #62 `remote-signer/q3-vc-wiring`, its validator wiring), because one module cannot hold the golden
  vectors' qrysm and this one. It writes no files: it drives a running signer with qrysm's
  keymanager and checks the answers with qrysm's verifiers.
  `test/acceptance` builds and runs it in a temporary directory (`make vectors-contract`); its DTO-rename test
  copies the qrysm packages the tool links into a temporary directory and renames two JSON field names in the
  copy, so no qrysm file ever enters the repository. `tools/vectorgen/README.md` records the pin and how to bump it.
- **The transaction vectors.** `testdata/vectors/transactions/signing.json` holds transactions signed by go-qrl's own
  `types.SignTx` at the go-qrl commit qrysm pins (`cyyber/go-qrl` `a9f196d809aa`), in deterministic mode, with
  their signing hashes; `vectorgen` writes them, and `internal/execution/golden_test.go` requires the signer's
  `qrl_signTransaction`, built on `theQRL/go-qrl` `b92884a3a1d5`, to reproduce them byte for byte.
  `testdata/vectors/transactions/text_hash.json` holds go-qrl's `accounts.TextHash` of messages at the same commit,
  which the signer's own `TextHash` and the message `qrl_sign` signs must equal. Program output, data only, like the
  other vectors.
- **The go-qrl keystore.** `gqrlKeystore` in `internal/keys/keystore/qrlv1/account_test.go` is an account keystore
  written by go-qrl's own `accounts/keystore.EncryptKey` at `b92884a3a1d5`, with its light Argon2id parameters, for
  the extended seed and password the test names. It is program output, data only. It was generated once by a
  throwaway program outside the repository, which was not kept: a program that links go-qrl cannot live in the
  signer module, and `EncryptKey` draws the salt and IV from `crypto/rand`, so no generator could reproduce the bytes
  for `make vectors` to compare. It was checked again with go-qrl at that commit, from a scratch module requiring
  `github.com/theQRL/go-qrl v0.3.4-0.20260608175446-b92884a3a1d5`: `keystore.DecryptKey` opens it with the password
  and returns the extended seed, `Key.Address.Hex()` is the test's `gqrlAddress`, and `EncryptKey` of the same
  key (a `keystore.Key` over `wallet.RestoreFromSeedHex` of the seed) writes the same layout and KDF parameters.
- **The consumers.** The signer's `golden_test.go` files and `internal/vectors` read the data only. The seed
  expansion of the random-root sets is implemented twice, independently, from its description in
  `testdata/vectors/README.md`: once over qrysm's types in `tools/vectorgen`, once over the signer's types in
  `internal/consensus/types/golden_test.go`.

## Generated test code

`internal/consensus/types/fastssz_mirror_htr_test.go` is output of the `sszgen` code generator of fastssz v1.0.0
(`github.com/ferranbt/fastssz`, MIT), run over this project's own mirror structs in `fastssz_mirror_test.go` and
reduced to the hash-tree-root methods (the regeneration steps are in that file). It is the test-only oracle of the
differential fuzz in `fastssz_test.go`. fastssz is a test-only dependency: no package that ships imports it, so it is
in no binary and outside `go-licenses check`. The generated file is classed `new`: it is generator output over our
declarations, not fastssz source. Its method bodies and doc comments are instantiated from fastssz's MIT-licensed
templates, so the file carries fastssz's notice, "Copyright (c) 2020 Ferran Borreguero" under the MIT License, in an
attribution line below our header.

## Header classes

| Class | Files | Required header |
|---|---|---|
| `new` | Written for this project | `Copyright <year> The go-remotesigner Authors.` and `SPDX-License-Identifier: Apache-2.0`; no ConsenSys line |
| `w3s-derived` | Written while consulting a specific Web3Signer file, including ported tests | The original `Copyright <year> ConsenSys AG.` line(s), our copyright line, the Apache short notice, `SPDX-License-Identifier: Apache-2.0`, and "Modified by The go-remotesigner Authors, <year>: translated from Java to Go and adapted for QRL. Derived from `<upstream path>` at commit `<commit>`." |
| `mit-derived` | Modified copies of MIT code | The original MIT copyright line, `SPDX-License-Identifier: MIT` (or `MIT AND Apache-2.0` together with the Apache notice), and a "Modified by" line; copies of the QRL keystore must carry Weald's copyright line, the Apache notice and `MIT AND Apache-2.0` (see "QRL code"); every file under `internal/keys/keystore/qrlv1/` is `mit-derived` except those `headercheck` lists as written for this project |
| `vendored` | Pristine upstream trees under `third_party/` | No added header; the directory must hash to the recorded git tree id |

`headercheck` checks `.go`, `.sql`, `.yaml`/`.yml`, `.sh`, `.py`, `.service` (systemd units), `Dockerfile*` and
`deploy/**/*.json` files (JSON files carry the notice in a top-level `description` field). Every such file needs a
row, as does every file under `third_party/` and every derived file of any type. Markdown, the Makefile,
`go.mod`/`go.sum`, `renovate.json`, `.gitignore`, the licence texts, `NOTICE` and `NOTICE.execution` are project
files that need no row unless they are derived from upstream or live under `third_party/`, and the generated files
under `testdata/vectors/` are covered as a whole by "Golden vectors"; every other tracked file needs a row
(`test/repo` checks this). For a row of a kind `headercheck` does not read (such as Markdown), the row records origin
only and no header is required.

`headercheck` checks only that a `w3s-derived` header has a ConsenSys line, since CI has no Web3Signer checkout.
That each one carries exactly the ConsenSys lines of the upstream files its row names is checked against a checkout
at the recorded commit:

```
REMOTESIGNER_WEB3SIGNER_DIR=<web3signer checkout> go test -count=1 -run ConsenSysLinesMatchUpstream ./tools/headercheck/
```

Every file under `third_party/` outside a vendored tree records `sha256 <hex>` of its content as its revision, and
`headercheck` verifies it, so nothing under `third_party/` changes without a reviewed `PROVENANCE.md` update. Editor
and OS files that `.gitignore` excludes (`.DS_Store`, `*.swp`, `.idea/`, `.vscode/`) are ignored everywhere,
including when a vendored tree id is computed.

## File table

Columns: path (directories end in `/`), class, upstream repository, upstream path(s) separated by `<br>`, and
revision: the upstream commit (7-40 hex digits, required for derived rows), `tree <id>` for vendored directories, or
`sha256 <hex>` pinning a file's content (required for files under `third_party/` outside a vendored tree).

<!-- headercheck:begin -->
| Path | Class | Upstream repository | Upstream path(s) | Revision |
|---|---|---|---|---|
| `.github/workflows/bench.yml` | new | | | |
| `.github/workflows/ci.yml` | new | | | |
| `.github/workflows/nightly.yml` | new | | | |
| `.github/workflows/release.yml` | new | | | |
| `.golangci.yml` | new | | | |
| `.goreleaser.yaml` | new | | | |
| `api/openapi/consensus.yaml` | w3s-derived | `Consensys/web3signer` | `openapi-specs/eth2/web3signer.yaml`<br>`openapi-specs/eth2/signing/schemas.yaml`<br>`openapi-specs/eth2/signing/paths/sign.yaml`<br>`openapi-specs/eth2/signing/paths/public_keys.yaml`<br>`openapi-specs/eth2/signing/paths/high_watermark.yaml`<br>`openapi-specs/eth2/signing/paths/upcheck.yaml`<br>`openapi-specs/eth2/signing/paths/healthcheck.yaml`<br>`openapi-specs/eth2/signing/paths/reload.yaml`<br>`openapi-specs/eth2/keymanager/schemas.yaml`<br>`openapi-specs/eth2/keymanager/paths/keystores.yaml` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `api/openapi/docs_test.go` | new | | | |
| `api/openapi/encoding_test.go` | new | | | |
| `api/openapi/examples_test.go` | new | | | |
| `api/openapi/golden_test.go` | new | | | |
| `api/openapi/spec_test.go` | new | | | |
| `cmd/remotesigner/consensus.go` | new | | | |
| `cmd/remotesigner/consensus_test.go` | new | | | |
| `cmd/remotesigner/deploy_test.go` | new | | | |
| `cmd/remotesigner/execution.go` | new | | | |
| `cmd/remotesigner/execution_test.go` | new | | | |
| `cmd/remotesigner/flags/execution.go` | w3s-derived | Web3Signer | `commandline/src/main/java/tech/pegasys/web3signer/commandline/subcommands/Eth1SubCommand.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `cmd/remotesigner/flags/flags.go` | new | | | |
| `cmd/remotesigner/flags/flags_test.go` | new | | | |
| `cmd/remotesigner/flavour_consensus.go` | new | | | |
| `cmd/remotesigner/flavour_consensus_test.go` | new | | | |
| `cmd/remotesigner/flavour_full.go` | new | | | |
| `cmd/remotesigner/gate_test.go` | new | | | |
| `cmd/remotesigner/interchange.go` | new | | | |
| `cmd/remotesigner/interchange_test.go` | new | | | |
| `cmd/remotesigner/keys_test.go` | new | | | |
| `cmd/remotesigner/keystore.go` | new | | | |
| `cmd/remotesigner/keystore_test.go` | new | | | |
| `cmd/remotesigner/main.go` | new | | | |
| `cmd/remotesigner/main_test.go` | new | | | |
| `cmd/remotesigner/offline.go` | new | | | |
| `cmd/remotesigner/offline_test.go` | new | | | |
| `cmd/remotesigner/secrets.go` | w3s-derived | Web3Signer | `commandline/src/main/java/tech/pegasys/web3signer/commandline/subcommands/Eth2SubCommand.java`<br>`commandline/src/main/java/tech/pegasys/web3signer/commandline/PicoCliAwsSecretsManagerParameters.java`<br>`commandline/src/main/java/tech/pegasys/web3signer/commandline/PicoCliGcpSecretManagerParameters.java`<br>`commandline/src/main/java/tech/pegasys/web3signer/commandline/PicoCliAzureKeyVaultParameters.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `cmd/remotesigner/secrets_test.go` | new | | | |
| `cmd/remotesigner/store.go` | new | | | |
| `cmd/remotesigner/store_test.go` | new | | | |
| `cmd/remotesigner/xhelp.go` | w3s-derived | Web3Signer | `commandline/src/main/java/tech/pegasys/web3signer/commandline/subcommands/XHelpSubCommand.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `cmd/remotesigner/xhelp_test.go` | w3s-derived | Web3Signer | `commandline/src/test/java/tech/pegasys/web3signer/commandline/XHelpSubCommandTest.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `deploy/config/postgres-ha.yaml` | new | | | |
| `deploy/config/single-host.yaml` | new | | | |
| `deploy/docker/Dockerfile` | new | | | |
| `deploy/docker/compose.yaml` | new | | | |
| `deploy/grafana/remotesigner.json` | w3s-derived | Web3Signer | `dashboard/web3signer-eth2-dashboard-grafana.json` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `deploy/prometheus/alerts.yml` | new | | | |
| `deploy/systemd/remotesigner.service` | new | | | |
| `internal/admission/admission.go` | new | | | |
| `internal/admission/admission_test.go` | new | | | |
| `internal/api/apierr/apierr.go` | new | | | |
| `internal/api/apierr/apierr_test.go` | new | | | |
| `internal/api/apierr/messages.go` | new | | | |
| `internal/api/consensus/capabilities.go` | new | | | |
| `internal/api/consensus/consensus_test.go` | new | | | |
| `internal/api/consensus/highwatermark.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/HighWatermarkHandler.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/api/consensus/highwatermark_test.go` | new | | | |
| `internal/api/consensus/identifier.go` | new | | | |
| `internal/api/consensus/publickeys.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/PublicKeysListHandler.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/api/consensus/randao.go` | new | | | |
| `internal/api/consensus/randao_test.go` | new | | | |
| `internal/api/consensus/sign.go` | new | | | |
| `internal/api/consensus/sign_gate_test.go` | new | | | |
| `internal/api/consensus/sign_test.go` | new | | | |
| `internal/api/jsonutil/jsonutil_test.go` | new | | | |
| `internal/api/jsonutil/object.go` | new | | | |
| `internal/api/jsonutil/scan.go` | new | | | |
| `internal/api/jsonutil/values.go` | new | | | |
| `internal/api/keymanager/keymanager.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/list/ListKeystoresHandler.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/list/KeystoreInfo.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/imports/ImportKeystoresHandler.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/imports/ImportKeystoresRequestBody.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/imports/ImportKeystoreResult.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/delete/DeleteKeystoresHandler.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/delete/DeleteKeystoresRequestBody.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/delete/DeleteKeystoresResponse.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/api/keymanager/keymanager_test.go` | new | | | |
| `internal/api/ops/healthcheck.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/Runner.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/config/HealthCheckNames.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/api/ops/ops_test.go` | new | | | |
| `internal/api/ops/reload.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/ReloadHandler.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/api/ops/upcheck.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/UpcheckHandler.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/config/config.go` | new | | | |
| `internal/config/config_test.go` | new | | | |
| `internal/config/env.go` | w3s-derived | Web3Signer | `commandline/src/main/java/tech/pegasys/web3signer/commandline/valueprovider/EnvironmentVariableDefaultProvider.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/config/execution_test.go` | new | | | |
| `internal/config/yaml.go` | w3s-derived | Web3Signer | `commandline/src/main/java/tech/pegasys/web3signer/commandline/valueprovider/YamlConfigFileDefaultProvider.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/consensus/policy/clock.go` | new | | | |
| `internal/consensus/policy/clock_test.go` | new | | | |
| `internal/consensus/policy/golden_test.go` | new | | | |
| `internal/consensus/policy/pins.go` | new | | | |
| `internal/consensus/policy/pins_test.go` | new | | | |
| `internal/consensus/policy/policy.go` | new | | | |
| `internal/consensus/policy/policy_test.go` | new | | | |
| `internal/consensus/signingroot/artifact.go` | new | | | |
| `internal/consensus/signingroot/artifact_test.go` | new | | | |
| `internal/consensus/signingroot/domain.go` | new | | | |
| `internal/consensus/signingroot/domain_test.go` | new | | | |
| `internal/consensus/signingroot/golden_test.go` | new | | | |
| `internal/consensus/testdata/containers.json` | new | | | |
| `internal/consensus/testdata/gen_fixtures.py` | new | | | |
| `internal/consensus/testdata/signing.json` | new | | | |
| `internal/consensus/types/bench_test.go` | new | | | |
| `internal/consensus/types/containers.go` | new | | | |
| `internal/consensus/types/containers_test.go` | new | | | |
| `internal/consensus/types/decode_fuzz_test.go` | new | | | |
| `internal/consensus/types/fastssz_mirror_htr_test.go` | new | | | |
| `internal/consensus/types/fastssz_mirror_test.go` | new | | | |
| `internal/consensus/types/fastssz_test.go` | new | | | |
| `internal/consensus/types/golden_test.go` | new | | | |
| `internal/consensus/types/json.go` | new | | | |
| `internal/consensus/types/randao.go` | new | | | |
| `internal/consensus/types/request.go` | new | | | |
| `internal/consensus/types/request_test.go` | new | | | |
| `internal/crypto/mldsa87/bench_test.go` | new | | | |
| `internal/crypto/mldsa87/extended.go` | new | | | |
| `internal/crypto/mldsa87/extended_test.go` | new | | | |
| `internal/crypto/mldsa87/golden_test.go` | new | | | |
| `internal/crypto/mldsa87/key.go` | new | | | |
| `internal/crypto/mldsa87/mldsa87.go` | new | | | |
| `internal/crypto/mldsa87/mldsa87_test.go` | new | | | |
| `internal/crypto/mldsa87/selftest.go` | new | | | |
| `internal/execution/accounts.go` | w3s-derived | Web3Signer | `signing/src/main/java/tech/pegasys/web3signer/signing/config/SecpArtifactSignerProviderAdapter.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/execution/accounts_w3s_test.go` | w3s-derived | Web3Signer | `signing/src/test/java/tech/pegasys/web3signer/signing/config/SecpArtifactSignerProviderAdapterTest.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/execution/allowlist.go` | new | | | |
| `internal/execution/allowlist_test.go` | new | | | |
| `internal/execution/audit.go` | new | | | |
| `internal/execution/audit_test.go` | new | | | |
| `internal/execution/call.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/sendtransaction/transaction/VertxNonceRequestTransmitter.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/sendtransaction/transaction/EthNonceProvider.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/execution/chainid.go` | new | | | |
| `internal/execution/chainid_test.go` | new | | | |
| `internal/execution/doc.go` | new | | | |
| `internal/execution/downstream.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/WebClientOptionsFactory.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/DownstreamPathCalculator.java`<br>`commandline/src/main/java/tech/pegasys/web3signer/commandline/subcommands/Eth1SubCommand.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/execution/fakegqrl_test.go` | new | | | |
| `internal/execution/golden_test.go` | new | | | |
| `internal/execution/gqrl_test.go` | new | | | |
| `internal/execution/handler.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/JsonRpcHandler.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/RequestMapper.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/internalresponse/InternalResponseHandler.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/JsonRpcErrorHandler.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/HttpResponseFactory.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/util/ResponseCodeSelector.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/execution/handler_test.go` | new | | | |
| `internal/execution/helpers_test.go` | new | | | |
| `internal/execution/jsonrpc.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/JsonRpcRequest.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/JsonRpcRequestId.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/response/JsonRpcError.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/response/JsonRpcErrorResponse.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/response/JsonRpcSuccessResponse.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/execution/jsonrpc_test.go` | new | | | |
| `internal/execution/methods.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/routes/eth1/JsonRpcRoute.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/Eth1AccountsHandler.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/internalresponse/EthSignResultProvider.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/util/EthMessageUtil.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/execution/methods_w3s_test.go` | w3s-derived | Web3Signer | `core/src/integrationTest/java/tech/pegasys/web3signer/core/jsonrpcproxy/EthAccountsIntegrationTest.java`<br>`core/src/integrationTest/java/tech/pegasys/web3signer/core/jsonrpcproxy/EthSignIntegrationTest.java`<br>`core/src/test/java/tech/pegasys/web3signer/core/service/jsonrpc/EthSignResultProviderTest.java`<br>`core/src/test/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/RequestMapperTest.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/execution/payload.go` | new | | | |
| `internal/execution/policy.go` | new | | | |
| `internal/execution/policy_test.go` | new | | | |
| `internal/execution/proxy.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/PassThroughHandler.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/HeaderHelpers.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/VertxRequestTransmitter.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/ForwardedMessageResponder.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/execution/proxy_test.go` | new | | | |
| `internal/execution/proxy_w3s_test.go` | w3s-derived | Web3Signer | `core/src/integrationTest/java/tech/pegasys/web3signer/core/jsonrpcproxy/ProxyIntegrationTest.java`<br>`core/src/integrationTest/java/tech/pegasys/web3signer/core/jsonrpcproxy/FailedConnectionIntegrationTest.java`<br>`core/src/integrationTest/java/tech/pegasys/web3signer/core/jsonrpcproxy/TimeoutTest.java`<br>`core/src/test/java/tech/pegasys/web3signer/core/service/DownstreamPathCalculatorTest.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/execution/publickeys.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/PublicKeysListHandler.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/execution/run.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/Eth1Runner.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/execution/run_test.go` | new | | | |
| `internal/execution/scan.go` | new | | | |
| `internal/execution/scan_test.go` | new | | | |
| `internal/execution/senderlock.go` | new | | | |
| `internal/execution/sendtx.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/sendtransaction/SendTransactionHandler.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/sendtransaction/TransactionTransmitter.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/sendtransaction/RetryingTransactionTransmitter.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/sendtransaction/NonceTooLowRetryMechanism.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/sendtransaction/RetryMechanism.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/execution/sendtx_test.go` | new | | | |
| `internal/execution/sendtx_w3s_test.go` | w3s-derived | Web3Signer | `core/src/integrationTest/java/tech/pegasys/web3signer/core/jsonrpcproxy/SigningEthSendTransactionIntegrationTest.java`<br>`core/src/test/java/tech/pegasys/web3signer/core/service/jsonrpc/sendtransaction/NonceTooLowRetryMechanismTest.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/execution/transaction.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/internalresponse/EthSignTransactionResultProvider.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/EthSendTransactionJsonParameters.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/signing/TransactionSerializer.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/execution/transaction_test.go` | new | | | |
| `internal/execution/wallet.go` | new | | | |
| `internal/hygiene/hygiene.go` | new | | | |
| `internal/hygiene/hygiene_linux.go` | new | | | |
| `internal/hygiene/hygiene_other.go` | new | | | |
| `internal/hygiene/hygiene_test.go` | new | | | |
| `internal/keymanager/files.go` | w3s-derived | Web3Signer | `signing/src/main/java/tech/pegasys/web3signer/signing/KeystoreFileManager.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/KeystoreFileRecord.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/keymanager/helpers_test.go` | new | | | |
| `internal/keymanager/keymanager.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/imports/ImportKeystoresHandler.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/delete/DeleteKeystoresProcessor.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/list/ListKeystoresHandler.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/DefaultValidatorManager.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbValidatorManager.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/keymanager/keymanager_test.go` | new | | | |
| `internal/keys/argon/argon.go` | new | | | |
| `internal/keys/argon/argon_test.go` | new | | | |
| `internal/keys/argon/cgroup.go` | new | | | |
| `internal/keys/argon/memory_darwin.go` | new | | | |
| `internal/keys/argon/memory_linux.go` | new | | | |
| `internal/keys/argon/memory_other.go` | new | | | |
| `internal/keys/keyconfig/execution_test.go` | new | | | |
| `internal/keys/keyconfig/keyconfig.go` | w3s-derived | Web3Signer | `signing/src/main/java/tech/pegasys/web3signer/signing/config/SignerLoader.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/parser/YamlSignerParser.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/FileRawSigningMetadata.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/FileKeyStoreMetadata.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/AbstractArtifactSignerFactory.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/keys/keyconfig/keyconfig_test.go` | new | | | |
| `internal/keys/keyconfig/remote.go` | w3s-derived | Web3Signer | `signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/HashicorpSigningMetadata.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/AwsKeySigningMetadataDeserializer.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/AzureSecretSigningMetadataDeserializer.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/AbstractArtifactSignerFactory.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/keys/keyconfig/remote_test.go` | new | | | |
| `internal/keys/keystore/qrlv1/account.go` | new | | | |
| `internal/keys/keystore/qrlv1/account_test.go` | new | | | |
| `internal/keys/keystore/qrlv1/bench_test.go` | new | | | |
| `internal/keys/keystore/qrlv1/decrypt.go` | mit-derived | `cyyber/qrysm` (MIT), from `wealdtech/go-eth2-wallet-encryptor-keystorev4` `v1.4.1` (Apache-2.0) | `pkg/go-qrl-wallet-encryptor-keystore/decrypt.go`<br>`pkg/go-qrl-wallet-encryptor-keystore/encryptor.go`<br>`pkg/go-qrl-wallet-encryptor-keystore/encrypt.go` | `0b9cdf251d1f022957d35c4edeb6dd3ce42a617d` |
| `internal/keys/keystore/qrlv1/fuzz_test.go` | new | | | |
| `internal/keys/keystore/qrlv1/golden_test.go` | new | | | |
| `internal/keys/keystore/qrlv1/helpers_test.go` | new | | | |
| `internal/keys/keystore/qrlv1/keystore.go` | new | | | |
| `internal/keys/keystore/qrlv1/keystore_test.go` | new | | | |
| `internal/keys/keystore/qrlv1/norm.go` | mit-derived | `cyyber/qrysm` (MIT), from `wealdtech/go-eth2-wallet-encryptor-keystorev4` `v1.4.1` (Apache-2.0) | `pkg/go-qrl-wallet-encryptor-keystore/norm.go` | `0b9cdf251d1f022957d35c4edeb6dd3ce42a617d` |
| `internal/keys/keystore/qrlv1/norm_test.go` | new | | | |
| `internal/keys/keystore/qrlv1/password.go` | new | | | |
| `internal/keys/keystores/execution_test.go` | new | | | |
| `internal/keys/keystores/keystores.go` | w3s-derived | Web3Signer | `signing/src/main/java/tech/pegasys/web3signer/signing/bulkloading/BlsKeystoreBulkLoader.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/bulkloading/SecpV3KeystoresBulkLoader.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/secp256k1/util/JsonFilesUtil.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/keys/keystores/keystores_test.go` | new | | | |
| `internal/keys/keystores/keystores_w3s_test.go` | w3s-derived | Web3Signer | `signing/src/test/java/tech/pegasys/web3signer/signing/bulkloading/BlsKeystoreBulkLoaderTest.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/keys/keystoretest/keystoretest.go` | new | | | |
| `internal/keys/secretfile/secretfile.go` | new | | | |
| `internal/keys/secretfile/secretfile_test.go` | new | | | |
| `internal/keys/secretfile/secretfile_unix_test.go` | new | | | |
| `internal/keys/secrets/awssm/awssm.go` | w3s-derived | Web3Signer | `keystorage/src/main/java/tech/pegasys/web3signer/keystorage/aws/AwsSecretsManager.java`<br>`keystorage/src/main/java/tech/pegasys/web3signer/keystorage/aws/AwsSecretsManagerProvider.java`<br>`keystorage/src/main/java/tech/pegasys/web3signer/keystorage/aws/AwsKeyIdentifier.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/config/AwsSecretsManagerFactory.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/keys/secrets/awssm/awssm_test.go` | new | | | |
| `internal/keys/secrets/awssm/localstack_test.go` | new | | | |
| `internal/keys/secrets/azurekv/azurekv.go` | w3s-derived | Web3Signer | `keystorage/src/main/java/tech/pegasys/web3signer/keystorage/azure/AzureKeyVault.java`<br>`keystorage/src/main/java/tech/pegasys/web3signer/keystorage/azure/AzureOverrides.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/config/AzureKeyVaultFactory.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/keys/secrets/azurekv/azurekv_test.go` | new | | | |
| `internal/keys/secrets/bulk.go` | w3s-derived | Web3Signer | `keystorage/src/main/java/tech/pegasys/web3signer/keystorage/common/SecretValueMapperUtil.java`<br>`keystorage/src/main/java/tech/pegasys/web3signer/keystorage/common/MappedResults.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/bulkloading/BlsAwsBulkLoader.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/bulkloading/BlsGcpBulkLoader.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/Eth2Runner.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/keys/secrets/cache.go` | new | | | |
| `internal/keys/secrets/gcpsm/gcpsm.go` | w3s-derived | Web3Signer | `keystorage/src/main/java/tech/pegasys/web3signer/keystorage/gcp/GcpSecretManager.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/keys/secrets/gcpsm/gcpsm_test.go` | new | | | |
| `internal/keys/secrets/hashicorp/devserver_test.go` | new | | | |
| `internal/keys/secrets/hashicorp/hashicorp.go` | w3s-derived | Web3Signer | `keystorage/src/main/java/tech/pegasys/web3signer/keystorage/hashicorp/HashicorpConnection.java`<br>`keystorage/src/main/java/tech/pegasys/web3signer/keystorage/hashicorp/HashicorpConnectionFactory.java`<br>`keystorage/src/main/java/tech/pegasys/web3signer/keystorage/hashicorp/HashicorpKVResponseMapper.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/AbstractArtifactSignerFactory.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/keys/secrets/hashicorp/hashicorp_test.go` | new | | | |
| `internal/keys/secrets/hashicorp/knownservers.go` | new | | | |
| `internal/keys/secrets/http.go` | new | | | |
| `internal/keys/secrets/secrets.go` | new | | | |
| `internal/keys/secrets/secrets_test.go` | new | | | |
| `internal/keys/secrets/secretstest/aws.go` | new | | | |
| `internal/keys/secrets/secretstest/azure.go` | new | | | |
| `internal/keys/secrets/secretstest/cloud.go` | new | | | |
| `internal/keys/secrets/secretstest/gcp.go` | new | | | |
| `internal/keys/secrets/secretstest/stderr.go` | new | | | |
| `internal/keys/secrets/secretstest/vault.go` | new | | | |
| `internal/keys/secrets/seed.go` | new | | | |
| `internal/keys/secrets/seed_test.go` | new | | | |
| `internal/keys/secrets/spec.go` | w3s-derived | Web3Signer | `signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/HashicorpSigningMetadata.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/AwsKeySigningMetadataDeserializer.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/AzureSecretSigningMetadataDeserializer.java`<br>`keystorage/src/main/java/tech/pegasys/web3signer/keystorage/hashicorp/config/ConnectionParameters.java`<br>`keystorage/src/main/java/tech/pegasys/web3signer/keystorage/hashicorp/config/KubernetesAuthOptions.java`<br>`keystorage/src/main/java/tech/pegasys/web3signer/keystorage/azure/AzureOverrides.java`<br>`common/src/main/java/tech/pegasys/web3signer/common/config/AwsAuthenticationMode.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/config/AzureAuthenticationMode.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/keys/source/identity_bsd.go` | new | | | |
| `internal/keys/source/identity_linux.go` | new | | | |
| `internal/keys/source/identity_other.go` | new | | | |
| `internal/keys/source/source.go` | new | | | |
| `internal/keys/source/source_test.go` | new | | | |
| `internal/logging/logging.go` | new | | | |
| `internal/logging/logging_test.go` | new | | | |
| `internal/logging/secret.go` | new | | | |
| `internal/metrics/dashboard_test.go` | new | | | |
| `internal/metrics/listener.go` | new | | | |
| `internal/metrics/listener_test.go` | new | | | |
| `internal/metrics/metrics.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/http/metrics/HttpApiMetrics.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/metrics/SlashingProtectionMetrics.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/metrics/metrics_test.go` | new | | | |
| `internal/network/config.go` | new | | | |
| `internal/network/config_test.go` | new | | | |
| `internal/network/embedded/end-to-end-mainnet.yaml` | new | | | |
| `internal/network/embedded/end-to-end.yaml` | new | | | |
| `internal/network/embedded/interop.yaml` | new | | | |
| `internal/network/embedded/minimal.yaml` | new | | | |
| `internal/network/genesis.go` | new | | | |
| `internal/network/golden_test.go` | new | | | |
| `internal/network/network.go` | new | | | |
| `internal/network/network_test.go` | new | | | |
| `internal/network/registry.go` | new | | | |
| `internal/randao/limits.go` | new | | | |
| `internal/randao/onion/golden_test.go` | new | | | |
| `internal/randao/onion/onion.go` | new | | | |
| `internal/randao/onion/onion_test.go` | new | | | |
| `internal/randao/service.go` | new | | | |
| `internal/randao/service_test.go` | new | | | |
| `internal/runner/credentials.go` | new | | | |
| `internal/runner/credentials_test.go` | new | | | |
| `internal/runner/files.go` | new | | | |
| `internal/runner/keymanager_test.go` | new | | | |
| `internal/runner/keys.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/Eth2Runner.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/runner/postgres_test.go` | new | | | |
| `internal/runner/prune.go` | w3s-derived | Web3Signer | `slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbPrunerRunner.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/runner/prune_test.go` | new | | | |
| `internal/runner/randao_test.go` | new | | | |
| `internal/runner/reload_test.go` | new | | | |
| `internal/runner/runner.go` | new | | | |
| `internal/runner/runner_test.go` | new | | | |
| `internal/runner/secrets_consensus_test.go` | new | | | |
| `internal/runner/secrets_test.go` | new | | | |
| `internal/runner/sign_test.go` | new | | | |
| `internal/runner/store.go` | w3s-derived | Web3Signer | `slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbHealthCheck.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/Eth2Runner.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/runner/stores.go` | new | | | |
| `internal/runner/stores_consensus.go` | new | | | |
| `internal/runner/stores_full.go` | new | | | |
| `internal/runner/tls_test.go` | new | | | |
| `internal/server/auth/auth.go` | new | | | |
| `internal/server/auth/auth_test.go` | new | | | |
| `internal/server/auth/files_test.go` | new | | | |
| `internal/server/body.go` | new | | | |
| `internal/server/errors.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/JsonErrorHandler.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/server/hostallow.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/http/HostAllowListHandler.java`<br>`commandline/src/main/java/tech/pegasys/web3signer/commandline/config/AllowListHostsProperty.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/server/listener.go` | new | | | |
| `internal/server/metrics.go` | new | | | |
| `internal/server/middleware.go` | new | | | |
| `internal/server/ports.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/Runner.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/server/router.go` | new | | | |
| `internal/server/server.go` | new | | | |
| `internal/server/server_test.go` | new | | | |
| `internal/server/tls_test.go` | new | | | |
| `internal/server/tlsconf/config.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/Runner.java`<br>`commandline/src/main/java/tech/pegasys/web3signer/commandline/config/PicoCliTlsServerOptionsValidator.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/server/tlsconf/files_test.go` | new | | | |
| `internal/server/tlsconf/selfsigned.go` | new | | | |
| `internal/server/tlsconf/selfsigned_other.go` | new | | | |
| `internal/server/tlsconf/selfsigned_unix.go` | new | | | |
| `internal/server/tlsconf/testcerts_test.go` | new | | | |
| `internal/server/tlsconf/tlsconf.go` | new | | | |
| `internal/server/tlsconf/tlsconf_test.go` | new | | | |
| `internal/signer/cache.go` | new | | | |
| `internal/signer/cache_test.go` | new | | | |
| `internal/signer/provider/change_test.go` | new | | | |
| `internal/signer/provider/provider.go` | w3s-derived | Web3Signer | `signing/src/main/java/tech/pegasys/web3signer/signing/config/DefaultArtifactSignerProvider.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/signer/provider/provider_test.go` | new | | | |
| `internal/signer/signer.go` | new | | | |
| `internal/signer/signer_test.go` | new | | | |
| `internal/slashing/boltstore/b14_test.go` | new | | | |
| `internal/slashing/boltstore/boltstore.go` | new | | | |
| `internal/slashing/boltstore/boltstore_test.go` | new | | | |
| `internal/slashing/boltstore/encoding.go` | new | | | |
| `internal/slashing/boltstore/encoding_test.go` | new | | | |
| `internal/slashing/boltstore/history.go` | new | | | |
| `internal/slashing/boltstore/migrate.go` | new | | | |
| `internal/slashing/boltstore/migrate_test.go` | new | | | |
| `internal/slashing/boltstore/migrate_testmigration.go` | new | | | |
| `internal/slashing/boltstore/process_test.go` | new | | | |
| `internal/slashing/boltstore/tx.go` | new | | | |
| `internal/slashing/engine.go` | w3s-derived | Web3Signer | `slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbSlashingProtection.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/RegisteredValidators.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/validator/BlockValidator.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/validator/AttestationValidator.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/validator/GenesisValidatorRootValidator.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/engine_test.go` | new |  |  |  |
| `internal/slashing/engine_w3s_test.go` | w3s-derived | Web3Signer | `slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/DbSlashingProtectionTest.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/interchange/decode.go` | w3s-derived | Web3Signer | `slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/model/Metadata.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/model/SignedBlock.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/model/SignedAttestation.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/InterchangeJsonProvider.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/interchange/decode_test.go` | new | | | |
| `internal/slashing/interchange/export.go` | w3s-derived | Web3Signer | `slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/InterchangeV5Exporter.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/EmptyDataIncrementalInterchangeV5Exporter.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/interchange/export_test.go` | new | | | |
| `internal/slashing/interchange/export_w3s_test.go` | w3s-derived | Web3Signer | `slashing-protection/src/integration-test/java/tech/pegasys/web3signer/slashingprotection/InterchangeExportIntegrationTestBase.java`<br>`slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/interchange/InterchangeV5ExporterTest.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/interchange/filter_test.go` | new | | | |
| `internal/slashing/interchange/fuzz_test.go` | new | | | |
| `internal/slashing/interchange/helpers_test.go` | new | | | |
| `internal/slashing/interchange/import.go` | w3s-derived | Web3Signer | `slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/InterchangeV5Importer.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/BlockImporter.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/AttestationImporter.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/OptionalMinValueTracker.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/interchange/import_test.go` | new | | | |
| `internal/slashing/interchange/import_w3s_test.go` | w3s-derived | Web3Signer | `slashing-protection/src/integration-test/java/tech/pegasys/web3signer/slashingprotection/InterchangeImportConflictsIntegrationTestBase.java`<br>`slashing-protection/src/integration-test/java/tech/pegasys/web3signer/slashingprotection/InterchangeImportBadJsonFormattingIntegrationTestBase.java`<br>`slashing-protection/src/integration-test/java/tech/pegasys/web3signer/slashingprotection/InterchangeImportBadLogicalContentIntegrationTestBase.java`<br>`slashing-protection/src/integration-test/java/tech/pegasys/web3signer/slashingprotection/WatermarkImportingIntegrationTestBase.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/interchange/qrysm_test.go` | new | | | |
| `internal/slashing/interchange/reenable_test.go` | new | | | |
| `internal/slashing/interchange/safety_test.go` | new | | | |
| `internal/slashing/memstore/memstore.go` | new |  |  |  |
| `internal/slashing/memstore/memstore_test.go` | new |  |  |  |
| `internal/slashing/pgstore/bench_test.go` | new | | | |
| `internal/slashing/pgstore/concurrency_test.go` | new | | | |
| `internal/slashing/pgstore/export_test.go` | new | | | |
| `internal/slashing/pgstore/highwatermark_test.go` | new | | | |
| `internal/slashing/pgstore/history.go` | new | | | |
| `internal/slashing/pgstore/migrate.go` | new | | | |
| `internal/slashing/pgstore/pgstore.go` | w3s-derived | Web3Signer | `slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbLocker.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbConnection.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/pgstore/pgstore_test.go` | new | | | |
| `internal/slashing/pgstore/pgtest/pgtest.go` | new | | | |
| `internal/slashing/pgstore/randao.go` | new | | | |
| `internal/slashing/pgstore/roles_test.go` | new | | | |
| `internal/slashing/pgstore/sql/0001.sql` | w3s-derived | Web3Signer | `slashing-protection/src/main/resources/migrations/postgresql/V00001__initial.sql`<br>`slashing-protection/src/main/resources/migrations/postgresql/V00002__removeUniqueConstraints.sql`<br>`slashing-protection/src/main/resources/migrations/postgresql/V00003__addLowWatermark.sql`<br>`slashing-protection/src/main/resources/migrations/postgresql/V00004__addGenesisValidatorsRoot.sql`<br>`slashing-protection/src/main/resources/migrations/postgresql/V00005__xnor_source_target_low_watermark.sql`<br>`slashing-protection/src/main/resources/migrations/postgresql/V00006__signed_data_indexes.sql`<br>`slashing-protection/src/main/resources/migrations/postgresql/V00007__add_db_version.sql`<br>`slashing-protection/src/main/resources/migrations/postgresql/V00008__signed_data_unique_constraints.sql`<br>`slashing-protection/src/main/resources/migrations/postgresql/V00009__upsert_validators.sql`<br>`slashing-protection/src/main/resources/migrations/postgresql/V00010__validator_enabled_status.sql`<br>`slashing-protection/src/main/resources/migrations/postgresql/V00011__bigint_indexes.sql`<br>`slashing-protection/src/main/resources/migrations/postgresql/V00012__add_highwatermark_metadata.sql` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/pgstore/store.go` | w3s-derived | Web3Signer | `slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/MetadataDao.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/ValidatorsDao.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbSlashingProtection.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbValidatorManager.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/pgstore/tx.go` | w3s-derived | Web3Signer | `slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/SignedBlocksDao.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/SignedAttestationsDao.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/LowWatermarkDao.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/ValidatorsDao.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/prune.go` | w3s-derived | Web3Signer | `slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbPruner.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DBSlashingProtectionPruner.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/prune_test.go` | new | | | |
| `internal/slashing/prune_w3s_test.go` | w3s-derived | Web3Signer | `slashing-protection/src/integration-test/java/tech/pegasys/web3signer/slashingprotection/PruningIntegrationTest.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/randao.go` | new |  |  |  |
| `internal/slashing/schema.go` | new |  |  |  |
| `internal/slashing/slashing.go` | w3s-derived | Web3Signer | `slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/SlashingProtection.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/slashingtest/eip3076.go` | new |  |  |  |
| `internal/slashing/slashingtest/enabled.go` | new |  |  |  |
| `internal/slashing/slashingtest/history.go` | w3s-derived | Web3Signer | `slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/dao/SignedBlocksDaoTest.java`<br>`slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/dao/SignedAttestationsDaoTest.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/slashingtest/randao.go` | new |  |  |  |
| `internal/slashing/slashingtest/retry.go` | new | | | |
| `internal/slashing/slashingtest/slashingtest.go` | new |  |  |  |
| `internal/slashing/slashingtest/slashingtest_test.go` | new |  |  |  |
| `internal/slashing/slashingtest/store.go` | w3s-derived | Web3Signer | `slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/dao/SignedBlocksDaoTest.java`<br>`slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/dao/SignedAttestationsDaoTest.java`<br>`slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/dao/LowWatermarkDaoTest.java`<br>`slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/dao/MetadataDaoTest.java`<br>`slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/dao/ValidatorsDaoTest.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/slashingtest/stress.go` | new |  |  |  |
| `internal/slashing/store.go` | w3s-derived | Web3Signer | `slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/SignedBlocksDao.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/SignedAttestationsDao.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/LowWatermarkDao.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/MetadataDao.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/ValidatorsDao.java`<br>`slashing-protection/src/main/resources/migrations/postgresql/V00012__add_highwatermark_metadata.sql` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/watermark.go` | w3s-derived | Web3Signer | `commandline/src/main/java/tech/pegasys/web3signer/commandline/subcommands/Eth2WatermarkRepairSubCommand.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/watermark_test.go` | new | | | |
| `internal/ssz/merkleize.go` | new | | | |
| `internal/ssz/merkleize_test.go` | new | | | |
| `internal/ssz/types.go` | new | | | |
| `internal/ssz/types_test.go` | new | | | |
| `internal/vectors/vectors.go` | new | | | |
| `test/acceptance/b16_test.go` | new | | | |
| `test/acceptance/b18_test.go` | new | | | |
| `test/acceptance/b19_test.go` | new | | | |
| `test/acceptance/b20_test.go` | new | | | |
| `test/acceptance/bursts_test.go` | new | | | |
| `test/acceptance/contract_test.go` | new | | | |
| `test/acceptance/e2e_test.go` | new | | | |
| `test/acceptance/execution_files_test.go` | new | | | |
| `test/acceptance/execution_test.go` | new | | | |
| `test/acceptance/execution_w3s_test.go` | w3s-derived | Web3Signer | `acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/eth1rpc/PassThroughAcceptanceTest.java`<br>`acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/eth1rpc/AccountManagementAcceptanceTest.java`<br>`acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/eth1rpc/Eth1RpcReloadKeysTest.java`<br>`acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/bulkloading/SecpV3KeystoresBulkLoadAcceptanceTest.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `test/acceptance/files_test.go` | new | | | |
| `test/acceptance/gate_test.go` | new | | | |
| `test/acceptance/harness_test.go` | new | | | |
| `test/acceptance/health_test.go` | new | | | |
| `test/acceptance/hygiene_linux_test.go` | new | | | |
| `test/acceptance/interchange_test.go` | new | | | |
| `test/acceptance/keymanager_test.go` | new | | | |
| `test/acceptance/keymanager_w3s_test.go` | w3s-derived | Web3Signer | `acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/keymanager/ListKeysAcceptanceTest.java`<br>`acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/keymanager/ImportKeystoresAcceptanceTest.java`<br>`acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/keymanager/DeleteKeystoresAcceptanceTest.java`<br>`acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/keymanager/KeyManagerTestBase.java`<br>`acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/keymanager/SlashingProtectionDataChoice.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `test/acceptance/keystores_test.go` | new | | | |
| `test/acceptance/keystores_w3s_test.go` | w3s-derived | Web3Signer | `acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/bulkloading/KeystoreAcceptanceTest.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `test/acceptance/loading_bench_test.go` | new | | | |
| `test/acceptance/metrics_test.go` | new | | | |
| `test/acceptance/migrate_test.go` | new | | | |
| `test/acceptance/postgres_test.go` | new | | | |
| `test/acceptance/qrlpackage_test.go` | new | | | |
| `test/acceptance/reload_w3s_test.go` | w3s-derived | Web3Signer | `acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/reload/ReloadAcceptanceTest.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `test/acceptance/secrets_test.go` | new | | | |
| `test/acceptance/server_test.go` | new | | | |
| `test/acceptance/tls_test.go` | new | | | |
| `test/acceptance/tls_w3s_test.go` | w3s-derived | Web3Signer | `acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/tls/ServerSideTlsAcceptanceTest.java`<br>`acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/tls/ServerSideTlsCaClientAcceptanceTest.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `test/release/checks_test.go` | new | | | |
| `test/release/helpers_test.go` | new | | | |
| `test/release/release_test.go` | new | | | |
| `test/release/smoke_test.go` | new | | | |
| `test/release/smokeclient/main.go` | new | | | |
| `test/release/smokeclient/owner_other.go` | new | | | |
| `test/release/smokeclient/owner_unix.go` | new | | | |
| `test/release/source_test.go` | new | | | |
| `test/release/systemd_test.go` | new | | | |
| `test/release/version_test.go` | new | | | |
| `test/repo/deploy_test.go` | new | | | |
| `test/repo/deps_test.go` | new | | | |
| `test/repo/docs_test.go` | new | | | |
| `test/repo/flavour_test.go` | new | | | |
| `test/repo/links_test.go` | new | | | |
| `test/repo/notice_test.go` | new | | | |
| `test/repo/provenance_test.go` | new | | | |
| `test/repo/public_test.go` | new | | | |
| `test/repo/repo_test.go` | new | | | |
| `test/repo/workflows_test.go` | new | | | |
| `third_party/qrl-keystore/README.md` | new | | | sha256 `b62799d6df0bdbbb39c3110d2f4ffe98e9e4508cc6f45ea618f943d29184b19c` |
| `third_party/qrl-keystore/go-qrl-wallet-encryptor-keystore/` | vendored | `cyyber/qrysm` (= `theQRL/qrysm` `e07a6007`) | `pkg/go-qrl-wallet-encryptor-keystore` | tree `6c97bfffa7d145c2be452fa4435c81b6c7532554` |
| `third_party/qrl-keystore/go.mod` | new | | | sha256 `8794f04b43301ccdaa0e3a1b5bb6a68affe585340a058657f12e7b6a28375d47` |
| `tools/flagdoc/main.go` | new | | | |
| `tools/flagdoc/main_test.go` | new | | | |
| `tools/headercheck/check.go` | new | | | |
| `tools/headercheck/check_test.go` | new | | | |
| `tools/headercheck/gittree.go` | new | | | |
| `tools/headercheck/gittree_test.go` | new | | | |
| `tools/headercheck/main.go` | new | | | |
| `tools/headercheck/provenance.go` | new | | | |
| `tools/headercheck/provenance_test.go` | new | | | |
| `tools/headercheck/upstream_test.go` | new | | | |
| `tools/releasedocs/main.go` | new | | | |
| `tools/releasedocs/main_test.go` | new | | | |
| `tools/releasedocs/notes.go` | new | | | |
| `tools/releasedocs/notes_test.go` | new | | | |
| `tools/vectorgen/blocks.go` | new | | | |
| `tools/vectorgen/capabilities.go` | new | | | |
| `tools/vectorgen/contract/contract.go` | new | | | |
| `tools/vectorgen/contract/contract_test.go` | new | | | |
| `tools/vectorgen/contract/main.go` | new | | | |
| `tools/vectorgen/contract/requests.go` | new | | | |
| `tools/vectorgen/contract/vectors.go` | new | | | |
| `tools/vectorgen/fixtures.go` | new | | | |
| `tools/vectorgen/gen.go` | new | | | |
| `tools/vectorgen/interchange.go` | new | | | |
| `tools/vectorgen/interchange_test.go` | new | | | |
| `tools/vectorgen/jsonout.go` | new | | | |
| `tools/vectorgen/keys.go` | new | | | |
| `tools/vectorgen/keystore.go` | new | | | |
| `tools/vectorgen/main.go` | new | | | |
| `tools/vectorgen/negative.go` | new | | | |
| `tools/vectorgen/networks.go` | new | | | |
| `tools/vectorgen/norace_test.go` | new | | | |
| `tools/vectorgen/objects.go` | new | | | |
| `tools/vectorgen/race_test.go` | new | | | |
| `tools/vectorgen/randao.go` | new | | | |
| `tools/vectorgen/readme.go` | new | | | |
| `tools/vectorgen/roots.go` | new | | | |
| `tools/vectorgen/signing.go` | new | | | |
| `tools/vectorgen/stream.go` | new | | | |
| `tools/vectorgen/transactions.go` | new | | | |
| `tools/vectorgen/vectorgen_test.go` | new | | | |
| `tools/vectorgen/verify.go` | new | | | |
| `tools/vectorgen/verify_test.go` | new | | | |
<!-- headercheck:end -->
