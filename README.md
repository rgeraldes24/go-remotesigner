# go-remotesigner

go-remotesigner is a remote signing service for QRL validators. It keeps ML-DSA-87 validator keys out of the
validator client, recomputes every signing root itself, and applies slashing protection before it signs. It is a Go
port of [Consensys Web3Signer](https://github.com/Consensys/web3signer) for the QRL stack, built to work with the
remote-signer client of the qrysm validator client.

go-remotesigner is an independent, non-affiliated port: it is not affiliated with, endorsed by or sponsored by
Consensys.

## Status

Pre-release. The HTTP contract with the qrysm validator client is [`docs/contract.md`](docs/contract.md) and
[`api/openapi/consensus.yaml`](api/openapi/consensus.yaml), with the protocol facts it relies on in
[`docs/spec/`](docs/spec/README.md). `remotesigner consensus` signs all nine artifact types behind slashing protection
in a bbolt file or, for replicas serving the same keys, a shared Postgres database, releases RANDAO reveals under the
frontier rule, and serves `publicKeys`, `capabilities`, `/upcheck`, `/healthcheck`, `/reload` and a Prometheus metrics
listener, with token authentication, the request guards and limits, and key loading from `file-raw` and `file-keystore`
key files and from keystore directories, with reloads that never disable a key
([`docs/operations/reload.md`](docs/operations/reload.md)), and the keymanager API to list, import and delete keys
while it runs ([`docs/operations/keymanager.md`](docs/operations/keymanager.md)). `remotesigner consensus keystore
verify` checks qrysm and deposit CLI keystores and their password files offline
([`docs/operations/keystores.md`](docs/operations/keystores.md)). To try the signer, see
[`docs/operations/quickstart.md`](docs/operations/quickstart.md); every flag is in
[`docs/reference/flags.md`](docs/reference/flags.md).

## Deployment

| Page | Content |
|---|---|
| [`docs/operations/deploy-docker.md`](docs/operations/deploy-docker.md) | the container image, its entrypoint, pinning its generated certificate, and the compose example |
| [`docs/operations/deploy-systemd.md`](docs/operations/deploy-systemd.md) | the hardened systemd unit with the example configuration |
| [`docs/operations/postgres.md`](docs/operations/postgres.md) | the Postgres slashing-protection store: roles, `consensus migrate`, the pool and timeout profile, replicas |
| [`docs/operations/tls.md`](docs/operations/tls.md) | TLS, client certificates, token and certificate rotation, process hygiene |
| [`docs/operations/metrics.md`](docs/operations/metrics.md) | the metrics, the alert rules and the Grafana dashboard |
| [`docs/operations/randao.md`](docs/operations/randao.md) | RANDAO reveals: the frontier rule, its flags and alerts |
| [`docs/operations/release.md`](docs/operations/release.md) | what a release contains, how to verify it, and the release dry run |

[`deploy/`](deploy) holds the Dockerfile, the compose example, the systemd unit, example configuration files, the
Grafana dashboard and the Prometheus alert rules.

## Building

Go 1.26.5 or later is required (the module's toolchain line selects go1.26.9).

```
make build             # bin/remotesigner, the default flavour
make build-consensus   # bin/remotesigner-consensus, consensus only (-tags noexecution)
make test              # go test -race, both flavours
make contract          # OpenAPI lint, example validation, docs/contract.md consistency
make lint              # go vet, golangci-lint, headercheck, LICENSE hash
make docs              # regenerate docs/reference/flags.md from the flag definitions
make image             # the container image of FLAVOUR for this machine's Docker
make release-snapshot  # the release dry run (goreleaser); make release-check checks its output
```

Both flavours are static (`CGO_ENABLED=0`). The consensus-only flavour, `remotesigner-consensus`, never links go-qrl
or any other GPL or LGPL code.

```
$ bin/remotesigner --version
remotesigner version v0.0.0-... (commit ..., go1.26.9, linux/amd64)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Commits need a DCO sign-off, and no GPL code may be copied or imported.

## License

go-remotesigner is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)). It is a derivative of Consensys
Web3Signer (Apache-2.0); see [NOTICE](NOTICE) and [PROVENANCE.md](PROVENANCE.md). Behaviour that differs from
Web3Signer is listed in [DEVIATIONS.md](DEVIATIONS.md).

Both binaries link this project's Apache-2.0 code and dependencies under Apache-2.0, MIT, BSD-2-Clause and
BSD-3-Clause; [NOTICE](NOTICE) lists each one with its copyright notice, and new dependencies must carry a licence
from the allowlist in [CONTRIBUTING.md](CONTRIBUTING.md). The generic licence texts are in [LICENSES/](LICENSES).
Release archives and images ship `LICENSE`, their flavour's `NOTICE`, `LICENSES/` and a `third_party_licenses/`
directory with each linked module's own licence file ([`docs/operations/release.md`](docs/operations/release.md)). Current
builds neither copy nor link any GPL or LGPL code. The development tool [`tools/vectorgen`](tools/vectorgen/README.md),
a separate module that generates the golden test vectors, links qrysm (GPL-3.0) and is never built into a release.

## Trademarks

Web3Signer and Consensys are product names or trademarks of Consensys. This project is not affiliated with or
endorsed by Consensys. References to them are for identification only.
