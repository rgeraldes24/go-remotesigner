# Deviations from Web3Signer

go-remotesigner follows Consensys Web3Signer (commit `30af06dc975ba5b8ed0e17e53cba8683ca50ec02`, see
`PROVENANCE.md`) wherever Web3Signer has the behaviour. This register lists every behaviour that differs on purpose;
anything not listed behaves like Web3Signer. Tests ported from Web3Signer assert this register, not Web3Signer
quirks. Every PR that introduces a new difference adds a row here.

Classes: **Fix** (a Web3Signer weakness closed), **Stricter** (narrower acceptance), **QRL-forced** (required by
ML-DSA-87, QRL sizes or the qrysm client), **QRL-sized** / **QRL time** (limits and timings re-derived for QRL),
**Policy** (a safer default), **Simplification**, **Go client** / **Go-native** (follows the Go ecosystem),
**NAME_MAX** (file-system limits), **QRL client** (follows gqrl's API).

Rows that show on the HTTP API are specified in [`docs/contract.md`](docs/contract.md), whose section 21 maps each of
them to the contract section that states the behaviour. The "go-remotesigner" column links the page that specifies
the behaviour where one exists; rows without a link describe features whose documentation lands with them.

| # | Area | Web3Signer | go-remotesigner | Class |
|---|---|---|---|---|
| X1 | Sign order | Signs, then checks `maySign` | Check and record, then sign, verify, release ([contract §7](docs/contract.md#7-request-envelope-and-validation-pipeline)) | Fix |
| X2 | Signing mode | BLS is deterministic | Deterministic selection proofs; hedged for everything else ([contract §15](docs/contract.md#15-selection-proofs-and-signing-modes)) | QRL-forced |
| X3 | Verify before release | none | Always on; 500 and quarantine on failure ([contract §7](docs/contract.md#7-request-envelope-and-validation-pipeline)) | Fix |
| X4 | Missing `fork_info` | NPE, then 500 | 400 `MISSING_FORK_INFO` ([contract §7](docs/contract.md#7-request-envelope-and-validation-pipeline)) | Fix |
| X5 | `fork_info` validation | Trusted; GVR pinned for blocks and attestations only | Must match the configured network for every type; domain from config ([contract §7](docs/contract.md#7-request-envelope-and-validation-pipeline)) | Fix |
| X6 | Authentication | None | Bearer token by default, `admin` scope, optional mTLS ([contract §6](docs/contract.md#6-authentication-and-scopes)) | Fix (user request) |
| X7 | Content type and `Origin` | Not enforced | 415 for non-JSON POST; 403 for any `Origin` ([contract §6](docs/contract.md#6-authentication-and-scopes)) | Fix |
| X8 | Low-watermark conditions | `<` plus a double-vote check | Literal EIP-3076 (`≤`) | Stricter |
| X9 | Body limits | 10 MiB everywhere | Per route ([contract §13](docs/contract.md#13-size-limits-and-timeouts)) | QRL-sized |
| X10 | Idle timeout | 30 s | 120 s ([contract §13](docs/contract.md#13-size-limits-and-timeouts)) | Go client |
| X11 | JSON strictness | Unknown fields ignored, numbers accepted, case-insensitive `type` | Strict ([contract §4](docs/contract.md#4-encoding-rules)) | Fix |
| X12 | Response default | `text/plain` without `Accept` | JSON unless `Accept` lists `text/plain` and not `application/json` ([contract §10](docs/contract.md#10-responses-and-content-negotiation)) | Simplification |
| X13 | Signer load | batch 500 on virtual threads | Memory-sized Argon2id semaphore | QRL-forced |
| X14 | Keystores | EIP-2335 | QRL v1 + deposit-cli, KDF bounds, derive and compare | QRL-forced + fix |
| X15 | Keymanager file names | `<pubkey>.*` | `<sha256(pk)>.*`, 0600 | NAME_MAX |
| X16 | Interchange import | Per-validator errors swallowed, no locks | Errors surface, key inactive, locks, GVR always exported | Fix |
| X17 | Pruning | 250 epochs, 32 slots per epoch | 512 epochs, slots per epoch from the network | QRL time |
| X18 | Secret logging | Import body at INFO on parse error | Redaction; bodies never logged | Fix |
| X19 | Embedded store | none (protection off without Postgres) | bbolt by default | Fix |
| X20 | Exits | Always signed | Off by default ([contract §8](docs/contract.md#8-artifact-types)) | Policy |
| X21 | Clock bounds | none | Per type when genesis time is known; RANDAO always ([contract §12](docs/contract.md#12-wall-clock-bounds)) | Fix |
| X22 | RANDAO | BLS signature of the epoch on `/sign` | Dedicated reveal endpoint with the frontier rule ([contract §14](docs/contract.md#14-randao-reveal)) | QRL-forced |
| X23 | Metric names | `signing_bls_*`, `eth2_*`, summaries | `signing_mldsa87_*`, `consensus_*`, histograms ([contract §18](docs/contract.md#18-metric-label-values), [docs/operations/metrics.md](docs/operations/metrics.md)) | QRL-forced |
| X24 | `DEPOSIT` | Always enabled | Not in v1; v2 off by default with the commitment guard ([contract §8](docs/contract.md#8-artifact-types)) | QRL-forced |
| X25 | eth1 nonce retry | Exact Besu `(code, message)` pairs | Code -32000 plus gqrl message substrings, per-sender lock | QRL-forced |
| X26 | `qrl_signTransaction` result | raw hex | gqrl `{raw, tx}` | QRL client |
| X27 | eth1 REST sign, `/ext/sign`, Commit-Boost | present | removed ([contract §8](docs/contract.md#8-artifact-types)) | Fix |
| X28 | Execution proxy | Forwards every header and method | Header and method allowlists, `Host` rewritten, no redirects | Fix |
| X29 | Reload delta | Removed keys (including ones that failed to load) are disabled in slashing protection | Reload only evicts from memory; `enabled=false` only on keymanager DELETE or `consensus disable-validator`; a failed source keeps its previous signers ([contract §17](docs/contract.md#17-supporting-endpoints)) | Fix |
| X30 | `--network` default | `mainnet` | Required, no default ([docs/spec/network-config.md](docs/spec/network-config.md)) | QRL (no published mainnet) |
| X31 | Disabling slashing protection | Allowed anywhere | Allowed only when every listener is loopback, no override ([docs/operations/quickstart.md](docs/operations/quickstart.md#10-listening-beyond-loopback)) | Fix |
| X32 | Connection limits | none | `--http-max-connections` 1024; unknown-length bodies count as large ([contract §13](docs/contract.md#13-size-limits-and-timeouts)) | Fix |
| X33 | Text log format | log4j pattern | logrus `TextFormatter` ([docs/reference/flags.md](docs/reference/flags.md)) | Go-native |
| X34 | High watermark before the network is pinned | `UPDATE metadata` silently changes nothing when no genesis validators root is stored | Refused with an error (`ErrNoGenesisValidatorsRoot`) | Fix |
| X35 | Validator registrations | Signed for the key the path names, whatever `pubkey` and `fee_recipient` say | `pubkey` must be the identified key (400 `PUBKEY_MISMATCH`, [contract §8](docs/contract.md#8-artifact-types)); an optional per-key fee-recipient pin refuses any other `fee_recipient` (403 `ARTIFACT_TYPE_DISABLED`, [docs/reference/registration-fee-recipient-file.md](docs/reference/registration-fee-recipient-file.md)) | Fix |
| X36 | Startup and `/upcheck` | Loads every key before it listens | Listens at once; `/upcheck` answers 503 `LOADING`, and `publicKeys` and `capabilities` 503 `NOT_READY`, until the first key load and the store open finish ([contract §17](docs/contract.md#17-supporting-endpoints)) | Fix |
| X37 | `/healthcheck` detail | Every caller sees every check | Without the sign scope a caller sees only `status` and `outcome` ([contract §17](docs/contract.md#17-supporting-endpoints)) | Fix |
| X38 | Startup fail-safes on a non-loopback listener | None | Refused: `--http-auth-mode=none`, plaintext token auth without `--Xallow-plaintext-token-auth`, a host allowlist of loopback names only, a GVR pinned on first use without `--Xallow-gvr-tofu`, an unknown genesis time without `--Xallow-unknown-genesis-time`; all applicable refusals are reported together ([docs/operations/quickstart.md](docs/operations/quickstart.md#10-listening-beyond-loopback)) | Fix |
| X39 | `--http-host-allowlist` default | `localhost,127.0.0.1` | `localhost,127.0.0.1,::1` ([docs/reference/flags.md](docs/reference/flags.md)) | Simplification |
| X40 | Configuration sources | `WEB3SIGNER_` environment prefix; YAML keys dotted by subcommand (`eth2.network`) | `REMOTESIGNER_` prefix (`REMOTESIGNER_CONSENSUS_NETWORK`); YAML takes bare flag names, consensus flags at the top level or in a `consensus:` section ([docs/reference/flags.md](docs/reference/flags.md)) | Go-native |
| X41 | `--key-config-path` default | `./` (the working directory) | Unset: no key-config source, with a WARN ([docs/reference/flags.md](docs/reference/flags.md)) | Policy |
| X42 | `--logging-format` | `PLAIN`, `ECS`, `GCP`, `GELF`, `LOGSTASH` | `text` (logrus `TextFormatter`, alias `--log-format`) or `json` ([docs/reference/flags.md](docs/reference/flags.md)) | Go-native |
| X43 | Ports file | `web3signer.ports` with `http-port` and `metrics-port` | `remotesigner.ports` with `http-port`, and `metrics-port` when `--metrics-enabled` starts the metrics listener ([docs/reference/flags.md](docs/reference/flags.md)) | Go-native |
| X44 | `/reload` messages | 202 message and `lastError` carry free text and exception messages | Fixed strings: `reload started`; `reload completed with N key loading error(s)` or `reload failed; see the signer log` ([contract §17](docs/contract.md#17-supporting-endpoints)) | Fix |
| X45 | `POST` without a body | Accepted with any or no `Content-Type` | Every POST, `/reload` included, needs `Content-Type: application/json` (415 otherwise) ([contract §6](docs/contract.md#6-authentication-and-scopes)) | Stricter |
| X46 | Metrics listener on a non-loopback host | Starts with any `--metrics-host-allowlist`, so the default (`localhost,127.0.0.1`) silently refuses every remote scraper | Startup is refused when the allowlist names only loopback hosts, as for the API listener ([docs/operations/metrics.md](docs/operations/metrics.md#1-the-metrics-listener)) | Fix |
