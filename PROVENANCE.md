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

## QRL code

No GPL code from qrysm (`github.com/theQRL/qrysm`, GPL-3.0) is copied into or imported by this module. `depguard`
denies every `github.com/theQRL/qrysm/**` import, and `go-licenses check` gates the dependency graph. Only the nested,
never-shipped module `tools/vectorgen` may link qrysm, to generate test data.

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
qrysm's Go source while writing them.

| Component | Fact sources |
|---|---|
| SSZ hash-tree-root (`internal/ssz`) | Ethereum consensus specs v1.5.0 (CC0-1.0): `ssz/simple-serialize.md`, merkleization rules |
| Consensus containers (`internal/consensus/types`) | Ethereum consensus specs v1.5.0 and builder specs (CC0-1.0) for shapes; QRL sizes, limits and field order from the Apache-2.0-headed qrysm protos (`proto/qrysm/v1alpha1/attestation.proto`, `beacon_block.proto`, `sync_committee.proto`, `proto/qrl/v1/*.proto`); preset numbers re-declared as constants. The header-less (GPL) `beacon_state.proto` is not used. |
| Signing roots and domains (`internal/consensus/signingroot`) | Ethereum consensus specs v1.5.0 (CC0-1.0): `compute_fork_data_root`, `compute_domain`, `compute_signing_root`, domain constants |
| Wire JSON | `ethereum/remote-signing-api` v1.4.0 (CC0-1.0), with the QRL deltas documented in `api/openapi/` |
| Network loader (`internal/network`) | qrysm config YAML key names and values as data; the `genesis.ssz` prefix layout (genesis_time bytes 0-8, genesis_validators_root 8-40, slot 40-48, fork 48-64) from the consensus spec `BeaconState` field order, independently re-derived, not from the GPL proto |
| RANDAO hash onion (`internal/randao/onion`) | `docs/spec/randao-onion.md` and its vectors only. That note records honestly that the construction (domain tag `qrl-randao-onion-v1`, `x_0 = SHA-256(tag ‖ seed48)`, `x_{j+1} = SHA-256(x_j)`, commitment `x_L`) was **learned by reading qrysm's GPL `crypto/randao/onion.go`**; only these facts were taken and no expression was copied. The Go API deliberately differs (`Base`, `Step`, `Top`, `Find`, `Advance`). |

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
| `.golangci.yml` | new | | | |
| `cmd/remotesigner/flavour_consensus.go` | new | | | |
| `cmd/remotesigner/flavour_full.go` | new | | | |
| `cmd/remotesigner/main.go` | new | | | |
| `cmd/remotesigner/main_test.go` | new | | | |
| `third_party/qrl-keystore/README.md` | new | | | sha256 `b62799d6df0bdbbb39c3110d2f4ffe98e9e4508cc6f45ea618f943d29184b19c` |
| `third_party/qrl-keystore/go.mod` | new | | | sha256 `8794f04b43301ccdaa0e3a1b5bb6a68affe585340a058657f12e7b6a28375d47` |
| `third_party/qrl-keystore/go-qrl-wallet-encryptor-keystore/` | vendored | `cyyber/qrysm` (= `theQRL/qrysm` `e07a6007`) | `pkg/go-qrl-wallet-encryptor-keystore` | tree `6c97bfffa7d145c2be452fa4435c81b6c7532554` |
| `tools/headercheck/check.go` | new | | | |
| `tools/headercheck/check_test.go` | new | | | |
| `tools/headercheck/gittree.go` | new | | | |
| `tools/headercheck/gittree_test.go` | new | | | |
| `tools/headercheck/main.go` | new | | | |
| `tools/headercheck/provenance.go` | new | | | |
| `tools/headercheck/provenance_test.go` | new | | | |
<!-- headercheck:end -->
