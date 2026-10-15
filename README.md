# go-remotesigner

go-remotesigner is a remote signing service for QRL validators. It keeps ML-DSA-87 validator keys out of the
validator client, recomputes every signing root itself, and applies slashing protection before it signs. It is a Go
port of [Consensys Web3Signer](https://github.com/Consensys/web3signer) for the QRL stack, built to work with the
remote-signer client of the qrysm validator client.

go-remotesigner is an independent, non-affiliated port: it is not affiliated with, endorsed by or sponsored by
Consensys.

## Status

Pre-release. This tree holds the project bootstrap (licence and provenance files, CI, and a `remotesigner` binary
that only reports its version) and the HTTP contract with the qrysm validator client:
[`docs/contract.md`](docs/contract.md) and [`api/openapi/consensus.yaml`](api/openapi/consensus.yaml), with the
protocol facts it relies on in [`docs/spec/`](docs/spec/README.md). The signing API, slashing protection and key
loading follow in later milestones.

## Building

Go 1.26.5 or later is required (the module's toolchain line selects go1.26.9).

```
make build             # bin/remotesigner, the default flavour
make build-consensus   # bin/remotesigner-consensus, consensus only (-tags noexecution)
make test              # go test -race, both flavours
make contract          # OpenAPI lint, example validation, docs/contract.md consistency
make lint              # go vet, golangci-lint, headercheck, LICENSE hash
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
Web3Signer is listed in [DEVIATIONS.md](DEVIATIONS.md). Current builds link this project's Apache-2.0 code and
dependencies under Apache-2.0, MIT and BSD-2-Clause (see [NOTICE](NOTICE)); new dependencies must carry a licence
from the allowlist in [CONTRIBUTING.md](CONTRIBUTING.md). The licence texts are in [LICENSES/](LICENSES), and release
archives will also ship a `third_party_licenses/` directory.

## Trademarks

Web3Signer and Consensys are product names or trademarks of Consensys. This project is not affiliated with or
endorsed by Consensys. References to them are for identification only.
