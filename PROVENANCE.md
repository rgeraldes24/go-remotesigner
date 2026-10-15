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
never-shipped module `tools/vectorgen` may link qrysm, to generate test data (see "Golden vectors").

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

The hardened copy that is compiled into the signer will live in `internal/keys/keystore/qrlv1/` and is recorded as
`mit-derived`. Because it modifies Apache-2.0 code, its headers must restore Weald's copyright line and the Apache
notice next to the QRL MIT line (Apache-2.0 §4(c)), and `LICENSES/Apache-2.0.txt` covers that part.

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
| RANDAO reveal service (`internal/randao`, `internal/api/consensus/randao.go`) | `docs/contract.md` section 14 | The frontier rule (state `(m, R, last)`, the classes, the two-sided window, the new-layer conditions and their order, the per-key bucket, the slow-path budget and negative cache) is this project's own design (DESIGN §2.11, from the G1 analysis), not taken from any implementation: qrysm keeps no reveal state and Web3Signer has no hash onion. The layers come from `internal/randao/onion`; the expected behaviour is checked against vectors V5 and V6, whose layer values qrysm's `crypto/randao` computed in `tools/vectorgen`. |
| RANDAO hash onion (`internal/randao/onion`) | `docs/spec/randao-onion.md` | The package is written from the facts and vectors V1-V3 of that note only; the golden vectors of `tools/vectorgen` later confirmed V1-V4 against qrysm's `crypto/randao`. The note records honestly that the construction (domain tag `qrl-randao-onion-v1`, `x_0 = SHA-256(tag ‖ seed48)`, `x_{j+1} = SHA-256(x_j)`, commitment `x_L`, default `L = 2^20`, reveal check `SHA-256(reveal) = commitment`) was **learned by reading qrysm's GPL `crypto/randao/onion.go`**; only these facts were taken. The package was written from the note without opening `onion.go`, and its vectors were computed independently with Python `hashlib`; vector V2 reuses the seed and length of qrysm's own onion test. The Go API uses its own names (`Base`, `Step`, `Top`, `Find`, `Advance`, `DefaultLength`); a test asserts that it exports none of qrysm's names `Origin`, `Next`, `Verify`, `Commitment`, `DefaultLayers`. The first draft did reuse two qrysm identifiers (`DefaultLayers`, which the design had named after qrysm's constant, and the unexported `domainTag`) and two doc-comment phrasings close to qrysm's; review caught these and they were renamed and reworded. The body of `Base` is the one idiomatic Go form of `SHA-256(tag ‖ seed)` and resembles qrysm's for that reason. The note's "Signer-level additions" (added with the contract, not package input) record two further GPL sources: the interop seed derivation behind vector V4, **learned by reading qrysm's GPL `runtime/interop`**, and the onion lengths used by qrysm's deposit tooling, interop genesis and unit-test helpers. Only facts were taken there too, and the V4 and V5 values were computed independently. |

## Golden vectors

`testdata/vectors/` holds golden vectors, and `internal/network/embedded/*.yaml` the named networks, both written by
`tools/vectorgen` (milestone S3). That nested module links qrysm at the pinned commit (`cyyber/qrysm` `0b9cdf25`) and
uses its code as the oracle: hash-tree-roots, domains and signing roots, deterministic ML-DSA-87 signatures, the
RANDAO onion, the interop genesis, `ConfigToYaml`, and the keystore encoders.

- **The tool.** Its source files are this project's (class `new`, Apache-2.0). A binary built from it is a GPL-3.0
  combined work, so it is a development tool that is never built into a shipped artefact; `tools/vectorgen/README.md`
  says so. It has its own `go.mod`, so qrysm and its `replace` directives never enter the signer module's graph.
- **Its output.** The generated files are program output, not program text (GPL FAQ, "Is there some way that I can
  GPL the output people get from use of my program?"), and none reproduces qrysm source. They are dedicated to the
  public domain under CC0-1.0, as `testdata/vectors/README.md` and every file's `description` state, and each file
  records the module versions that generated it in its `generator` object. The exception is the keystore files of
  `testdata/vectors/keystores/`, which keep their native keystore format; `keystores/index.json` and the README carry
  their CC0 dedication and generator record. JSON files outside `deploy/` carry no header row; the generated
  YAMLs carry the class `new` header.
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
| `mit-derived` | Modified copies of MIT code | The original MIT copyright line, `SPDX-License-Identifier: MIT`, and a "Modified by" line; for the keystore, also Weald's copyright line and the Apache notice (see "QRL code") |
| `vendored` | Pristine upstream trees under `third_party/` | No added header; the directory must hash to the recorded git tree id |

`headercheck` checks `.go`, `.sql`, `.yaml`/`.yml`, `.sh`, `Dockerfile*` and `deploy/**/*.json` files (JSON files carry
the notice in a top-level `description` field). Every such file needs a row, as does every file under
`third_party/` and every derived file of any type. Markdown, the Makefile, `go.mod`/`go.sum`, `renovate.json` and
the licence texts are project files that need no row unless they are derived from upstream or live under
`third_party/`. For a row of a kind `headercheck` does not read (such as Markdown), the row records origin only and
no header is required.

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
| `.github/workflows/ci.yml` | new | | | |
| `.github/workflows/nightly.yml` | new | | | |
| `.golangci.yml` | new | | | |
| `api/openapi/consensus.yaml` | w3s-derived | `Consensys/web3signer` | `openapi-specs/eth2/web3signer.yaml`<br>`openapi-specs/eth2/signing/schemas.yaml`<br>`openapi-specs/eth2/signing/paths/sign.yaml`<br>`openapi-specs/eth2/signing/paths/public_keys.yaml`<br>`openapi-specs/eth2/signing/paths/high_watermark.yaml`<br>`openapi-specs/eth2/signing/paths/upcheck.yaml`<br>`openapi-specs/eth2/signing/paths/healthcheck.yaml`<br>`openapi-specs/eth2/signing/paths/reload.yaml`<br>`openapi-specs/eth2/keymanager/schemas.yaml`<br>`openapi-specs/eth2/keymanager/paths/keystores.yaml` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `api/openapi/docs_test.go` | new | | | |
| `api/openapi/encoding_test.go` | new | | | |
| `api/openapi/examples_test.go` | new | | | |
| `api/openapi/golden_test.go` | new | | | |
| `api/openapi/spec_test.go` | new | | | |
| `cmd/remotesigner/consensus.go` | new | | | |
| `cmd/remotesigner/consensus_test.go` | new | | | |
| `cmd/remotesigner/flags/flags.go` | new | | | |
| `cmd/remotesigner/flags/flags_test.go` | new | | | |
| `cmd/remotesigner/flavour_consensus.go` | new | | | |
| `cmd/remotesigner/flavour_full.go` | new | | | |
| `cmd/remotesigner/main.go` | new | | | |
| `cmd/remotesigner/main_test.go` | new | | | |
| `cmd/remotesigner/offline.go` | new | | | |
| `cmd/remotesigner/offline_test.go` | new | | | |
| `deploy/prometheus/alerts.yml` | new | | | |
| `internal/api/apierr/apierr.go` | new | | | |
| `internal/api/apierr/apierr_test.go` | new | | | |
| `internal/api/apierr/messages.go` | new | | | |
| `internal/api/consensus/capabilities.go` | new | | | |
| `internal/api/consensus/consensus_test.go` | new | | | |
| `internal/api/consensus/identifier.go` | new | | | |
| `internal/api/consensus/publickeys.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/PublicKeysListHandler.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/api/consensus/randao.go` | new | | | |
| `internal/api/consensus/randao_test.go` | new | | | |
| `internal/api/consensus/sign.go` | new | | | |
| `internal/api/consensus/sign_test.go` | new | | | |
| `internal/api/jsonutil/jsonutil_test.go` | new | | | |
| `internal/api/jsonutil/object.go` | new | | | |
| `internal/api/jsonutil/scan.go` | new | | | |
| `internal/api/jsonutil/values.go` | new | | | |
| `internal/api/ops/healthcheck.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/Runner.java`<br>`core/src/main/java/tech/pegasys/web3signer/core/config/HealthCheckNames.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/api/ops/ops_test.go` | new | | | |
| `internal/api/ops/reload.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/ReloadHandler.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/api/ops/upcheck.go` | w3s-derived | Web3Signer | `core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/UpcheckHandler.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/config/config.go` | new | | | |
| `internal/config/config_test.go` | new | | | |
| `internal/config/env.go` | w3s-derived | Web3Signer | `commandline/src/main/java/tech/pegasys/web3signer/commandline/valueprovider/EnvironmentVariableDefaultProvider.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
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
| `internal/crypto/mldsa87/golden_test.go` | new | | | |
| `internal/crypto/mldsa87/key.go` | new | | | |
| `internal/crypto/mldsa87/mldsa87.go` | new | | | |
| `internal/crypto/mldsa87/mldsa87_test.go` | new | | | |
| `internal/crypto/mldsa87/selftest.go` | new | | | |
| `internal/keys/keyconfig/keyconfig.go` | w3s-derived | Web3Signer | `signing/src/main/java/tech/pegasys/web3signer/signing/config/SignerLoader.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/parser/YamlSignerParser.java`<br>`signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/FileRawSigningMetadata.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/keys/keyconfig/keyconfig_test.go` | new | | | |
| `internal/logging/logging.go` | new | | | |
| `internal/logging/logging_test.go` | new | | | |
| `internal/logging/secret.go` | new | | | |
| `internal/metrics/listener.go` | new | | | |
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
| `internal/runner/randao_test.go` | new | | | |
| `internal/runner/runner.go` | new | | | |
| `internal/runner/runner_test.go` | new | | | |
| `internal/runner/sign_test.go` | new | | | |
| `internal/server/auth/auth.go` | new | | | |
| `internal/server/auth/auth_test.go` | new | | | |
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
| `internal/signer/provider/provider.go` | w3s-derived | Web3Signer | `signing/src/main/java/tech/pegasys/web3signer/signing/config/DefaultArtifactSignerProvider.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/signer/provider/provider_test.go` | new | | | |
| `internal/signer/signer.go` | new | | | |
| `internal/signer/signer_test.go` | new | | | |
| `internal/slashing/boltstore/boltstore.go` | new | | | |
| `internal/slashing/boltstore/boltstore_test.go` | new | | | |
| `internal/slashing/boltstore/encoding.go` | new | | | |
| `internal/slashing/boltstore/encoding_test.go` | new | | | |
| `internal/slashing/boltstore/migrate.go` | new | | | |
| `internal/slashing/boltstore/migrate_test.go` | new | | | |
| `internal/slashing/boltstore/process_test.go` | new | | | |
| `internal/slashing/boltstore/tx.go` | new | | | |
| `internal/slashing/engine.go` | w3s-derived | Web3Signer | `slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbSlashingProtection.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/RegisteredValidators.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/validator/BlockValidator.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/validator/AttestationValidator.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/validator/GenesisValidatorRootValidator.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/engine_test.go` | new |  |  |  |
| `internal/slashing/engine_w3s_test.go` | w3s-derived | Web3Signer | `slashing-protection/src/test/java/tech/pegasys/web3signer/slashingprotection/DbSlashingProtectionTest.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/memstore/memstore.go` | new |  |  |  |
| `internal/slashing/memstore/memstore_test.go` | new |  |  |  |
| `internal/slashing/randao.go` | new |  |  |  |
| `internal/slashing/schema.go` | new |  |  |  |
| `internal/slashing/slashing.go` | w3s-derived | Web3Signer | `slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/SlashingProtection.java` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/slashing/slashingtest/eip3076.go` | new |  |  |  |
| `internal/slashing/slashingtest/randao.go` | new |  |  |  |
| `internal/slashing/slashingtest/slashingtest.go` | new |  |  |  |
| `internal/slashing/slashingtest/slashingtest_test.go` | new |  |  |  |
| `internal/slashing/slashingtest/stress.go` | new |  |  |  |
| `internal/slashing/store.go` | w3s-derived | Web3Signer | `slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/SignedBlocksDao.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/SignedAttestationsDao.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/LowWatermarkDao.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/MetadataDao.java`<br>`slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/ValidatorsDao.java`<br>`slashing-protection/src/main/resources/migrations/postgresql/V00012__add_highwatermark_metadata.sql` | `30af06dc975ba5b8ed0e17e53cba8683ca50ec02` |
| `internal/ssz/merkleize.go` | new | | | |
| `internal/ssz/merkleize_test.go` | new | | | |
| `internal/ssz/types.go` | new | | | |
| `internal/ssz/types_test.go` | new | | | |
| `internal/vectors/vectors.go` | new | | | |
| `test/acceptance/b19_test.go` | new | | | |
| `test/acceptance/harness_test.go` | new | | | |
| `test/acceptance/metrics_test.go` | new | | | |
| `test/acceptance/server_test.go` | new | | | |
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
| `tools/vectorgen/blocks.go` | new | | | |
| `tools/vectorgen/capabilities.go` | new | | | |
| `tools/vectorgen/fixtures.go` | new | | | |
| `tools/vectorgen/gen.go` | new | | | |
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
| `tools/vectorgen/vectorgen_test.go` | new | | | |
| `tools/vectorgen/verify.go` | new | | | |
| `tools/vectorgen/verify_test.go` | new | | | |
<!-- headercheck:end -->
