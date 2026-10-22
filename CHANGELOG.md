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

## [1.1.0] - Unreleased

Execution mode, which holds QRL account keys in front of a gqrl node, and validator seeds read from secret stores.
The HTTP contract with the qrysm validator client stays at 1.0.0: its one addition, the secret stores' health checks,
is a clarification that [`docs/contract.md`](docs/contract.md#20-versioning-and-change-control) section 20 lists. The
slashing-protection schema is unchanged and no flag was removed or renamed, so a 1.0.0 signer upgrades in place with
its configuration ([`docs/operations/upgrade.md`](docs/operations/upgrade.md)). The behaviours that differ from
Web3Signer are rows X25, X26, X28 and X76-X106 of [`DEVIATIONS.md`](DEVIATIONS.md).

### Added

- **Execution mode.** `remotesigner execution`, in the default flavour only and in a process of its own, holds QRL
  account keys for wallets and tools that speak JSON-RPC, so that the gqrl node behind it holds none: 51-byte
  extended seeds in `file-raw` key-config files, and go-qrl account keystores in `file-keystore` documents or a
  `--keystores-path` directory. At `POST /` it answers `qrl_accounts`, `qrl_sign` (a hedged ML-DSA-87 signature of
  go-qrl's text hash, verified before it is returned) and `health_status`, and splits batches of up to 1,000
  requests. `GET /api/v1/execution/publicKeys` lists each account's address with its public key, which a verifier of
  `qrl_sign` needs. Clients authenticate with the sign token in an `Authorization: Bearer` header, a client
  certificate or both; Basic authentication and a token in the URL are refused. See
  [`docs/operations/execution.md`](docs/operations/execution.md).
- **Transaction signing and sending.** `qrl_signTransaction` signs go-qrl's type-0x2 transactions for `--chain-id`
  and answers gqrl's `{raw, tx}`; the signer compares that chain ID with the node's at startup and every 10 minutes,
  and refuses transactions while they differ. `qrl_sendTransaction` asks the node's `qrl_fillTransaction` for what a
  request lacks, takes only the nonce, gas and fees from its answer after checking that the rest is the request's,
  refuses a filled nonce more than 64 above the account's pending one (`--execution-nonce-crosscheck`, on by
  default), then signs and sends, one transaction per account at a time. When the request left the nonce to the
  node, it tries again up to 10 times if the node reports that another transaction took the nonce.
  Every transaction stays within a fee cap of 1 quanta, unless the policy sets another, and within the per-account
  policy of `--execution-policy-file` (recipients, value, fee, contract creation, input size, transactions per
  hour), which a listener beyond loopback requires. `--execution-audit-log-file` records every signature, every send
  and every refusal.
- **Proxy to the node.** Requests for the methods `--execution-proxy-allowed-methods` allows (`qrl_*`, `net_*` and
  `web3_*` by default) are re-encoded and forwarded to the node without the client's `Authorization`, cookies or
  forwarding headers, with the node's own credential from `--downstream-http-auth-header-file`, and, if asked, over
  TLS (`--downstream-http-tls-enabled`) and through an HTTP proxy (`--downstream-http-proxy-host` and
  `--downstream-http-proxy-port`); no redirect is followed, and responses stop at 25 MB. `qrl_signTypedData` is never
  offered or forwarded, and methods outside the allowlist (by default `admin_*`, `debug_*`, `personal_*` and every
  other namespace but those three) are refused.
- **Secret stores.** `remotesigner consensus` reads validator seeds from HashiCorp Vault's KV version 2 engine
  (`hashicorp` key-config documents, through Vault's HTTP API with token or Kubernetes authentication, in both
  flavours) and, in the default flavour only, from AWS Secrets Manager, GCP Secret Manager and Azure Key Vault
  secrets: one secret per `aws-secret`, `gcp-secret` or `azure-secret` key-config document, or in bulk with
  `--aws-secrets-enabled`, `--gcp-secrets-enabled` and `--azure-vault-enabled`, one seed per line of each secret.
  A secret that fails to load keeps the keys it had, no store client follows a redirect, and a key-config file that
  holds a store credential is a secret file under `--strict-file-permissions`. `remotesigner-consensus` refuses the
  AWS, GCP and Azure stores, and execution mode reads none. See
  [`docs/operations/reload.md`](docs/operations/reload.md#1-key-sources) and the page of each store it lists.
- **The source of each release.** Every release attaches `remotesigner-<version>-src-vendored.tar.gz`: the tagged
  source with every module the binaries link in `vendor/`, go-qrl included, which rebuilds the default flavour
  offline with Go 1.26.5 or later ([`docs/operations/release.md`](docs/operations/release.md#3-verifying-a-release)).

### Changed

- **The default flavour links LGPL code.** `remotesigner` now links the go-qrl library (LGPL-3.0-or-later),
  unmodified, for execution mode, which makes it a combined work: its archives and image append
  [`NOTICE.execution`](NOTICE.execution) to the NOTICE and add the LGPL and GPL texts to `LICENSES/`, its image's
  licence label names `LGPL-3.0-or-later`, and `--version` prints go-qrl's notice. With go-qrl and the AWS, GCP and
  Azure SDKs, which it links too, it is about 13 MB larger than `remotesigner-consensus`
  ([`docs/benchmarks.md`](docs/benchmarks.md#binary-size-with-the-secret-stores-no-benchmark-id)).
  `remotesigner-consensus` links none of them and stays under permissive licences only: run it to sign consensus
  duties without LGPL code ([`docs/operations/release.md`](docs/operations/release.md#2-notice-and-licence-texts-per-flavour)).
- **`/healthcheck`** also lists `keys-check/aws-bulk-loading`, `keys-check/gcp-bulk-loading` and
  `keys-check/azure-bulk-loading`, each while its bulk loader is enabled, with the data of the other key checks.

## [1.0.0] - Unreleased

The first release: a remote signer for the ML-DSA-87 validator keys of qrysm validator clients on Testnet V3, ported
from Consensys Web3Signer and, like it, licensed under the Apache License 2.0 ([`LICENSE`](LICENSE),
[`NOTICE`](NOTICE)). Every behaviour that differs from Web3Signer is listed in [`DEVIATIONS.md`](DEVIATIONS.md)
(rows X1-X75); the ones about execution mode (X25, X26, X28) describe what 1.1.0 adds. The validator client needs
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
  `consensus disable-validator` disables a key, which an import enables again only when `--enable-keys` names it.
  With bbolt they run on a stopped signer, with Postgres online. The
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
  refused (`--strict-file-permissions`), as are token files and TLS private keys. `consensus keystore verify` checks
  keystores and password files offline.
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
  timeouts, a connection cap, a signing gate that admits 32 sign requests at once, queues 512 more and answers the
  rest 503 `OVERLOADED` (`--max-concurrent-signing-requests`, `--max-queued-signing-requests`), and startup refusals
  on a non-loopback listener for anything that would weaken them unless an explicit `--X…` override says so (each
  override is explained in [`docs/reference/flags.md`](docs/reference/flags.md#override-flags)).
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

[Unreleased]: https://github.com/rgeraldes24/go-remotesigner/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/rgeraldes24/go-remotesigner/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/rgeraldes24/go-remotesigner/releases/tag/v1.0.0
