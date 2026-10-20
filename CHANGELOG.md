# Changelog

All notable changes to go-remotesigner are recorded in this file. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and releases follow
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). The HTTP contract with the qrysm validator client
has a version of its own, `info.version` in [`api/openapi/consensus.yaml`](api/openapi/consensus.yaml), which
changes only as [`docs/contract.md`](docs/contract.md#20-versioning-and-change-control) section 20 says.

A version's heading carries the date of its tag. Until the tag is pushed, the heading says `Unreleased`, and the
release workflow refuses to publish a version whose entry is missing or undated
([`docs/operations/release.md`](docs/operations/release.md#5-publishing)). Pre-releases have no entries of their
own: a tag such as `v1.0.0-rc.1` publishes the notes of its version's entry, dated or not.

## [Unreleased]

## [1.0.0] - Unreleased

The first release: a remote signer for the ML-DSA-87 validator keys of qrysm validator clients on Testnet V3, ported
from Consensys Web3Signer and, like it, licensed under the Apache License 2.0 ([`LICENSE`](LICENSE),
[`NOTICE`](NOTICE)). Every behaviour that differs from Web3Signer is listed in [`DEVIATIONS.md`](DEVIATIONS.md)
(rows X1-X75); the ones about execution mode (X25, X26, X28) describe a later release. The validator client needs
qrysm's remote-signer keymanager, and
[`docs/operations/requirements.md`](docs/operations/requirements.md#5-a-qrysm-validator-client-with-the-remote-signer-keymanager)
section 5 names the qrysm build that has it.

### Added

- **Consensus signing.** `remotesigner consensus` signs the nine artifact types the qrysm validator client sends:
  `BLOCK_V2`, `ATTESTATION`, `AGGREGATION_SLOT`, `AGGREGATE_AND_PROOF`, `VOLUNTARY_EXIT`,
  `SYNC_COMMITTEE_MESSAGE`, `SYNC_COMMITTEE_SELECTION_PROOF`, `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` and
  `VALIDATOR_REGISTRATION`, at `POST /api/v1/consensus/sign/{identifier}`, where the identifier is the 2,592-byte
  public key or its SHA-256. Signatures are ML-DSA-87 through the go-qrllib wallet, which qrysm verifies; selection
  proofs are deterministic and everything else is hedged (`--selection-proof-signing`).
- **Request validation.** The signer recomputes every object root, domain and signing root from its own network
  configuration and refuses a request whose `signing_root` or `fork_info` differs. Request bodies are decoded
  strictly: unknown and duplicate fields, JSON numbers for 64-bit values, non-canonical decimals and hex of the wrong
  length are refused, each with a machine-readable `reason`. Requests too far ahead of the wall clock are refused
  (`CLOCK_BOUND`, with `--signing-clock-skew-slots`), exits are signed only with `--voluntary-exit-signing-enabled`, and
  `--registration-fee-recipient-file` pins the fee recipient of a key's validator registrations.
- **Safe signing order.** Each request is checked and its slashing record committed before the key signs, and every
  signature is verified before it is released; a key whose signature fails that check is quarantined until the next
  reload. A repeated request is answered from a bounded response cache with the same signature.
- **Slashing protection, on by default.** EIP-3076 block and attestation rules, with the inclusive low-watermark
  conditions. The history lives in an embedded bbolt file (the default, `bolt:///` URLs) or, for replicas that serve
  the same keys, a shared PostgreSQL database (`postgres://` URLs) with a squashed schema that the signer creates and
  upgrades itself (`consensus migrate`, `--slashing-protection-db-migrate`), advisory locks, a fixed pool and timeout
  profile, and credentials only from a password file or `PGPASSFILE`. Disabling protection is allowed only when every
  listener is on loopback. Both stores pass the store tests ported from Web3Signer's slashing-protection suite and
  scenarios written from the conditions of EIP-3076.
- **Slashing-protection history commands.** `consensus import` and `consensus export` stream EIP-3076 v5 interchange
  files with 2,592-byte keys, `consensus watermark-repair` raises low watermarks, `consensus set-high-watermark` sets
  or removes the high-watermark fence (served at `GET /api/v1/consensus/highWatermark`), and
  `consensus disable-validator` disables a key. With bbolt they run on a stopped signer, with Postgres online. The
  history is pruned every `--slashing-protection-pruning-interval` (512 epochs kept by default): with bbolt also at
  startup; with Postgres, paced so that a run takes at most half of the database's time.
- **RANDAO reveals.** `POST /api/v1/consensus/randao_reveal/{identifier}` releases hash-onion layers under the frontier
  rule: a two-sided slot window, a per-key new-layer token bucket, a rate-limited slow-path scan and persistent state
  per key, which an admin can reset online (`DELETE /api/v1/consensus/randao_state/{identifier}`) or offline
  (`consensus randao-state reset`). Replicas on one Postgres database serve a slot's reveal consistently.
- **Key sources.** `file-raw` key-config files with 48-byte seeds, `file-keystore` key-config files, and keystore
  directories (`--keystores-path` with `--keystores-password-file` or `--keystores-passwords-path`), for qrysm's
  keystore v1 and the deposit CLI's keystores. Keystores are opened by a hardened decryptor that bounds the KDF
  parameters before any work, compares the derived key with the declared one, and runs Argon2id under one
  memory-sized semaphore (`--signer-load-parallelism`). Password and seed files that other users can read are
  refused (`--strict-file-permissions`). `consensus keystore verify` checks keystores and password files offline.
- **Reload.** `POST /reload` loads only the sources that changed, never disables a key, keeps the previous keys of a
  source that fails, and is bounded by `--reload-timeout`. The startup load, which runs while the API already
  listens, is not bounded. `GET /reload` reports the status of either.
- **Keymanager API.** With `--key-manager-api-enabled`, `GET`, `POST` and `DELETE /qrl/v1/keystores` list, import
  (with their slashing-protection history) and delete keys while the signer runs, behind the admin token.
- **Authentication and TLS.** Bearer tokens for a `sign` and an `admin` scope, generated on first start and rotated
  with `SIGHUP`; TLS 1.3 on the API listener from PEM files, a PKCS#12 keystore or a certificate generated on first
  start (`--tls-generate-self-signed`), its fingerprint logged for pinning; client certificates in
  `--http-auth-mode=mtls` and `token+mtls`, trusted by fingerprint or by a client CA, never by the system roots.
- **Request guards.** Host allowlist, refusal of any `Origin` header, `Content-Type` checks, per-route body limits,
  timeouts and a connection cap, and startup refusals on a non-loopback listener for anything that would weaken them
  unless an explicit `--X…` override says so (each override is explained in
  [`docs/reference/flags.md`](docs/reference/flags.md#override-flags)).
- **Process hygiene on Linux.** Core dumps off and the process not dumpable (`--disable-core-dumps`, on by default),
  and optional `--mlock-all`.
- **Operations endpoints and metrics.** `GET /api/v1/consensus/publicKeys` (sorted, streamed, gzip on request),
  `GET /api/v1/consensus/capabilities` for the validator client's startup handshake, `/upcheck` and `/healthcheck`
  in Web3Signer's shape. A separate Prometheus listener (`--metrics-enabled`) with its own host allowlist and an
  optional token serves the signing, slashing-protection, RANDAO, loaded-key and HTTP metrics; no metric carries a
  key as a label. Prometheus alert rules and a Grafana dashboard are in [`deploy/`](deploy).
- **Networks.** `--network` is required: the built-in `minimal`, `end-to-end` (alias `e2e`), `end-to-end-mainnet` and
  `interop`, or a qrysm configuration file with the genesis time and validators root from flags or a genesis state.
- **Configuration.** Every global and `consensus` flag also reads a `REMOTESIGNER_` environment variable and a YAML
  `--config-file`, while the subcommands' own flags read the environment at most; the flag reference, generated
  from the flag definitions, lists what each flag reads. Booleans take `--flag=false`, never `--flag false`. Logs
  are text or JSON (`--logging-format`), with Web3Signer's levels (`--logging`).
- **Container image and deployment examples.** A distroless, non-root image per flavour that runs with a read-only
  root file system and a TLS-first entrypoint, a docker-compose example with a validator client, a hardened systemd
  unit, and example configurations for a single host (bbolt) and Postgres replicas.
- **Release artefacts.** Two flavours, `remotesigner` and `remotesigner-consensus` (built with `noexecution`, which
  never links go-qrl or any GPL or LGPL code), for linux and darwin on amd64 and arm64. Each archive and image carries
  `LICENSE`, its flavour's `NOTICE`, `LICENSES/` and the licence files of every linked module
  (`third_party_licenses/`). Archives have SPDX SBOMs and a build provenance attestation, `checksums.txt` a
  keyless cosign signature, and the images an SBOM, a provenance attestation and a cosign signature. `--version`
  prints the release version (`1.0.0` for the `v1.0.0` tag) and commit.
- **HTTP contract 1.0.0.** [`api/openapi/consensus.yaml`](api/openapi/consensus.yaml) and
  [`docs/contract.md`](docs/contract.md) specify every route, field, status code and reason with the qrysm validator
  client. CC0 golden vectors generated with qrysm's own code ([`testdata/vectors`](testdata/vectors/README.md)) and
  qrysm's own remote-signer client check the signer on every change.
- **Operator documentation.** Requirements and limits, a quickstart, Docker and systemd deployment, Postgres, TLS and
  rotation, keystores, reload and memory sizing, the keymanager, migration from a validator client, bbolt backup,
  RANDAO operations, the metrics catalogue with alert runbooks, upgrades and releases, all indexed from the
  [README](README.md#documentation), with dev-machine benchmark results in [`docs/benchmarks.md`](docs/benchmarks.md).

[Unreleased]: https://github.com/rgeraldes24/go-remotesigner/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/rgeraldes24/go-remotesigner/releases/tag/v1.0.0
