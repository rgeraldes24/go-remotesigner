# go-remotesigner

go-remotesigner is a remote signing service for QRL validators. It keeps ML-DSA-87 validator keys out of the
validator client, recomputes every signing root itself, and applies slashing protection before it signs. It is a Go
port of [Consensys Web3Signer](https://github.com/Consensys/web3signer) for the QRL stack, built to work with the
remote-signer client of the qrysm validator client.

go-remotesigner is an independent, non-affiliated port: it is not affiliated with, endorsed by or sponsored by
Consensys.

## Status

[`CHANGELOG.md`](CHANGELOG.md) lists what each version contains. A version whose heading there still says
`Unreleased` has not been tagged: it is tagged once it meets its release checklist in
[`docs/operations/release.md`](docs/operations/release.md) (for
[v1.0](docs/operations/release.md#6-the-v10-release-checklist) and
[v1.1](docs/operations/release.md#7-the-v11-release-checklist)). The HTTP contract with the qrysm
validator client is [`docs/contract.md`](docs/contract.md) and
[`api/openapi/consensus.yaml`](api/openapi/consensus.yaml), with the protocol facts it relies on in
[`docs/spec/`](docs/spec/README.md). `remotesigner consensus` signs all nine artifact types behind slashing protection
in a bbolt file or, for replicas serving the same keys, a shared Postgres database, releases RANDAO reveals under the
frontier rule, and serves `publicKeys`, `capabilities`, `/upcheck`, `/healthcheck`, `/reload` and a Prometheus metrics
listener, with token and client-certificate authentication over TLS, the request guards and limits, and key loading
from `file-raw` and `file-keystore` key files, from keystore directories and from secret stores, with reloads that
never disable a key ([`docs/operations/reload.md`](docs/operations/reload.md)), and the keymanager API to list, import
and delete keys while it runs ([`docs/operations/keymanager.md`](docs/operations/keymanager.md)). The secret stores
hold seeds only: HashiCorp Vault's KV version 2 engine, read over plain HTTP in both flavours
([`docs/operations/hashicorp-vault.md`](docs/operations/hashicorp-vault.md)), and, in the default flavour,
AWS Secrets Manager, GCP Secret Manager and Azure Key Vault secrets, each one secret per key file or in bulk
([`aws-secrets-manager.md`](docs/operations/aws-secrets-manager.md),
[`gcp-secret-manager.md`](docs/operations/gcp-secret-manager.md),
[`azure-key-vault.md`](docs/operations/azure-key-vault.md)). `remotesigner consensus keystore
verify` checks qrysm and deposit CLI keystores and their password files offline
([`docs/operations/keystores.md`](docs/operations/keystores.md)). In the default flavour, `remotesigner execution`
holds QRL account keys for JSON-RPC clients in front of a gqrl node: it answers `qrl_accounts`, `qrl_sign`,
`qrl_signTransaction` and `qrl_sendTransaction` under a chain ID, a fee cap, a per-account policy and an audit log,
and forwards an allowlist of methods to the node, without the client's credentials
([`docs/operations/execution.md`](docs/operations/execution.md)). To try the signer, see
[`docs/operations/quickstart.md`](docs/operations/quickstart.md); every flag is in
[`docs/reference/flags.md`](docs/reference/flags.md).

## Documentation

Operators start with [`requirements.md`](docs/operations/requirements.md), then deploy with the Docker or the systemd
guide; each brings up a signer on its own. [`deploy/`](deploy) holds the Dockerfile, the compose example, the systemd
unit, example configuration files, the Grafana dashboard and the Prometheus alert rules.

| Page | Content |
|---|---|
| [`docs/operations/requirements.md`](docs/operations/requirements.md) | rules every deployment follows: Testnet V3 only, one seed per role, `--flag=false`, signers next to their validator clients, the qrysm validator client to use |
| [`docs/operations/quickstart.md`](docs/operations/quickstart.md) | a first signer on one host: key files, network, tokens, signing, metrics |
| [`docs/operations/deploy-docker.md`](docs/operations/deploy-docker.md) | the container image, its entrypoint, keys and volumes, pinning its generated certificate, the compose example, orchestrators |
| [`docs/operations/deploy-systemd.md`](docs/operations/deploy-systemd.md) | the hardened systemd unit with the example configuration |
| [`docs/operations/postgres.md`](docs/operations/postgres.md) | the Postgres slashing-protection store for replicas: roles, `consensus migrate`, the pool and timeout profile |
| [`docs/operations/tls.md`](docs/operations/tls.md) | TLS, client certificates, scopes, token and certificate rotation with SIGHUP, process hygiene |
| [`docs/operations/keystores.md`](docs/operations/keystores.md) | keystore formats, the keystore policy, password files, `consensus keystore verify` |
| [`docs/operations/reload.md`](docs/operations/reload.md) | key sources, loading and reloading, disabling and enabling a key, memory for keystore decryption |
| [`docs/operations/keymanager.md`](docs/operations/keymanager.md) | the keymanager API: listing, importing and deleting keys while the signer runs |
| [`docs/operations/hashicorp-vault.md`](docs/operations/hashicorp-vault.md) | seeds in HashiCorp Vault's KV version 2 engine: the `hashicorp` document, token and Kubernetes authentication, TLS and pinned servers |
| [`docs/operations/aws-secrets-manager.md`](docs/operations/aws-secrets-manager.md) | seeds in AWS Secrets Manager (default flavour): the `aws-secret` document, the bulk loader, credentials |
| [`docs/operations/gcp-secret-manager.md`](docs/operations/gcp-secret-manager.md) | seeds in GCP Secret Manager (default flavour): the bulk loader, the `gcp-secret` document, credentials |
| [`docs/operations/azure-key-vault.md`](docs/operations/azure-key-vault.md) | seeds in Azure Key Vault secrets (default flavour): authentication, the `azure-secret` document, the bulk loader, the overrides |
| [`docs/operations/migration.md`](docs/operations/migration.md) | moving validators to the signer: importing their slashing-protection history, the high watermark, exporting |
| [`docs/operations/backup.md`](docs/operations/backup.md) | backing up and restoring the bbolt store |
| [`docs/operations/randao.md`](docs/operations/randao.md) | RANDAO reveals: the frontier rule, gap advances, sizing the bucket, resetting a key, the alerts |
| [`docs/operations/metrics.md`](docs/operations/metrics.md) | the metrics catalogue, the alert rules and their runbooks, the Grafana dashboard |
| [`docs/operations/execution.md`](docs/operations/execution.md) | execution mode: account keys, the JSON-RPC methods, transaction signing, the policy file, the proxy to gqrl and the LGPL notes |
| [`docs/operations/upgrade.md`](docs/operations/upgrade.md) | upgrading and going back: the schema-version rule, one signer, Postgres replicas |
| [`docs/operations/release.md`](docs/operations/release.md) | what a release contains, how to verify it, the release dry run, and the v1.0 and v1.1 release checklists |
| [`docs/reference/flags.md`](docs/reference/flags.md) | every flag with its environment variable, config-file key and default, and every `--X…` override explained (generated) |
| [`docs/reference/registration-fee-recipient-file.md`](docs/reference/registration-fee-recipient-file.md) | the per-key fee-recipient file |
| [`docs/contract.md`](docs/contract.md) | the HTTP contract with the qrysm validator client |
| [`docs/spec/README.md`](docs/spec/README.md) | the protocol facts the signer relies on: SSZ containers, signing roots, the RANDAO onion, network configuration |
| [`docs/benchmarks.md`](docs/benchmarks.md) | benchmark results, measured on a development machine |
| [`DEVIATIONS.md`](DEVIATIONS.md) | every behaviour that differs from Web3Signer |
| [`CHANGELOG.md`](CHANGELOG.md) | what each release adds, changes and fixes |

## Building

Go 1.26.5 or later is required (the module's toolchain line selects go1.26.9).

```
make build             # bin/remotesigner, the default flavour
make build-consensus   # bin/remotesigner-consensus, consensus only (-tags noexecution)
make test              # go test -race, both flavours
make test-cloud        # the secret-store tests against a Vault dev server and LocalStack (Docker)
make contract          # OpenAPI lint, example validation, docs/contract.md consistency
make lint              # go vet, golangci-lint, headercheck, LICENSE hash
make docs              # regenerate docs/reference/flags.md from the flag definitions
make image             # the container image of FLAVOUR for this machine's Docker
make release-snapshot  # the release dry run (goreleaser); make release-check checks its output
```

Both flavours are static (`CGO_ENABLED=0`). The consensus-only flavour, `remotesigner-consensus`, never links go-qrl
or any other GPL or LGPL code, nor the AWS, Azure and GCP SDKs of the cloud secret stores.

```
$ bin/remotesigner-consensus --version
remotesigner-consensus version 1.1.0 (commit ..., go1.26.9, linux/amd64)
```

The default flavour, `bin/remotesigner`, prints the same line with its own name, followed by the notice of the go-qrl
library it links (LGPL-3.0-or-later). The version is the tag's without its `v` (`1.1.0` for `v1.1.0`), as in the
release binaries and in a binary that `go install github.com/rgeraldes24/go-remotesigner/cmd/remotesigner@v1.1.0`
builds; between tags it is `git describe`'s.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Commits need a DCO sign-off, and no GPL code may be copied or imported.

## License

go-remotesigner is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)). It is a derivative of Consensys
Web3Signer (Apache-2.0); see [NOTICE](NOTICE) and [PROVENANCE.md](PROVENANCE.md). Behaviour that differs from
Web3Signer is listed in [DEVIATIONS.md](DEVIATIONS.md).

Both binaries link this project's Apache-2.0 code and dependencies under Apache-2.0, MIT, BSD-2-Clause and
BSD-3-Clause; [NOTICE](NOTICE) lists each one with its copyright notice, and new dependencies must carry a licence
from the allowlist in [CONTRIBUTING.md](CONTRIBUTING.md). The generic licence texts are in [LICENSES/](LICENSES).
The consensus-only binary, `remotesigner-consensus`, links nothing else. The default binary, `remotesigner`, also
links the go-qrl library (LGPL-3.0-or-later), unmodified, for execution mode, with two more modules under
BSD-3-Clause and ISC; its release appends [NOTICE.execution](NOTICE.execution) to its NOTICE and ships the LGPL and
GPL texts in `LICENSES/`, and every release attaches `remotesigner-<version>-src-vendored.tar.gz`, the source with
every dependency vendored. Release archives and images ship `LICENSE`, their flavour's `NOTICE`, `LICENSES/` and a
`third_party_licenses/` directory with each linked module's own licence file, with this README and the systemd unit
and example configuration files of [`deploy/`](deploy) ([`docs/operations/release.md`](docs/operations/release.md)).
Neither binary copies or links any GPL code, and no go-qrl code is copied into this repository. The development tool
[`tools/vectorgen`](tools/vectorgen/README.md), a separate module that generates the golden test vectors, links qrysm
(GPL-3.0) and is never built into a release.

## Trademarks

Web3Signer and Consensys are product names or trademarks of Consensys. This project is not affiliated with or
endorsed by Consensys. References to them are for identification only.
