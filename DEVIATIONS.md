# Deviations from Web3Signer

go-remotesigner follows Consensys Web3Signer (commit `30af06dc975ba5b8ed0e17e53cba8683ca50ec02`, see
`PROVENANCE.md`) wherever Web3Signer has the behaviour. This register lists every behaviour that differs on purpose;
anything not listed behaves like Web3Signer. Tests ported from Web3Signer assert this register, not Web3Signer
quirks. Every PR that introduces a new difference adds a row here.

Classes: **Fix** (a Web3Signer weakness closed), **Stricter** (narrower acceptance), **QRL-forced** (required by
ML-DSA-87, QRL sizes or the qrysm client), **QRL-sized** / **QRL time** (limits and timings re-derived for QRL),
**Policy** (a safer default), **Simplification**, **Go client** / **Go-native** (follows the Go ecosystem),
**NAME_MAX** (file-system limits), **QRL client** (follows gqrl's API).

The source column cites the evidence notes (component maps and gap reports) written while planning the port, which
are not in this repository. Rows that show on the HTTP API are specified in [`docs/contract.md`](docs/contract.md),
whose section 21 maps each of them to the contract section that states the behaviour; the "go-remotesigner" column
links that section where one exists.

| # | Area | Web3Signer | go-remotesigner | Class | Source |
|---|---|---|---|---|---|
| X1 | Sign order | Signs, then checks `maySign` | Check and record, then sign, verify, release | Fix | CH §6.2; G4 C9 |
| X2 | Signing mode | BLS is deterministic | Deterministic selection proofs; hedged for everything else | QRL-forced | QI §7 |
| X3 | Verify before release | none | Always on; 500 and quarantine on failure | Fix | G4 C11 |
| X4 | Missing `fork_info` | NPE, then 500 | 400 `MISSING_FORK_INFO` ([contract §7](docs/contract.md#7-request-envelope-and-validation-pipeline)) | Fix | CH §6.1 |
| X5 | `fork_info` validation | Trusted; GVR pinned for blocks and attestations only | Must match the configured network for every type; domain from config | Fix | G4 C10 |
| X6 | Authentication | None | Bearer token by default, `admin` scope, optional mTLS | Fix (user request) | CH §10; G4 C1 |
| X7 | Content type and `Origin` | Not enforced | 415 for non-JSON POST; 403 for any `Origin` | Fix | G4 C4 |
| X8 | Low-watermark conditions | `<` plus a double-vote check | Literal EIP-3076 (`≤`) | Stricter | SP §5.2 |
| X9 | Body limits | 10 MiB everywhere | Per route ([contract §13](docs/contract.md#13-size-limits-and-timeouts)) | QRL-sized | G6 §7.1 |
| X10 | Idle timeout | 30 s | 120 s | Go client | G6 §7.2 |
| X11 | JSON strictness | Unknown fields ignored, numbers accepted, case-insensitive `type` | Strict ([contract §4](docs/contract.md#4-encoding-rules)) | Fix | G2 §6.1 |
| X12 | Response default | `text/plain` without `Accept` | JSON unless `text/plain` is explicitly preferred ([contract §10](docs/contract.md#10-responses-and-content-negotiation)) | Simplification | CH §6.2 |
| X13 | Signer load | batch 500 on virtual threads | Memory-sized Argon2id semaphore | QRL-forced | G6 §7.4 |
| X14 | Keystores | EIP-2335 | QRL v1 + deposit-cli, KDF bounds, derive and compare | QRL-forced + fix | G3 §A.2; G4 C7, C8 |
| X15 | Keymanager file names | `<pubkey>.*` | `<sha256(pk)>.*`, 0600 | NAME_MAX | G3 §B.7 |
| X16 | Interchange import | Per-validator errors swallowed, no locks | Errors surface, key inactive, locks, GVR always exported | Fix | SP §18.2 |
| X17 | Pruning | 250 epochs, 32 slots per epoch | 512 epochs, slots per epoch from the network | QRL time | SP §17.3 |
| X18 | Secret logging | Import body at INFO on parse error | Redaction; bodies never logged | Fix | G4 N1, C15 |
| X19 | Embedded store | none (protection off without Postgres) | bbolt by default | Fix | G4 T26 |
| X20 | Exits | Always signed | Off by default | Policy | G4 C13 |
| X21 | Clock bounds | none | Per type when genesis time is known; RANDAO always ([contract §12](docs/contract.md#12-wall-clock-bounds)) | Fix | G4 C12 |
| X22 | RANDAO | BLS signature of the epoch on `/sign` | Dedicated reveal endpoint with the frontier rule ([contract §14](docs/contract.md#14-randao-reveal)) | QRL-forced | G1 §7 |
| X23 | Metric names | `signing_bls_*`, `eth2_*`, summaries | `signing_mldsa87_*`, `consensus_*`, histograms | QRL-forced | OF §5.3 |
| X24 | `DEPOSIT` | Always enabled | Not in v1; v2 off by default with the commitment guard | QRL-forced | G1 §6.3 |
| X25 | eth1 nonce retry | Exact Besu `(code, message)` pairs | Code -32000 plus gqrl message substrings, per-sender lock | QRL-forced | E1 §1.7 |
| X26 | `qrl_signTransaction` result | raw hex | gqrl `{raw, tx}` | QRL client | E1 §1.6 |
| X27 | eth1 REST sign, `/ext/sign`, Commit-Boost | present | removed | Fix | G4 T17 |
| X28 | Execution proxy | Forwards every header and method | Header and method allowlists, `Host` rewritten, no redirects | Fix | G4 C18 |
| X29 | Reload delta | Removed keys (including ones that failed to load) are disabled in slashing protection | Reload only evicts from memory; `enabled=false` only on keymanager DELETE or `consensus disable-validator`; a failed source keeps its previous signers | Fix | [contract §17](docs/contract.md#17-supporting-endpoints) |
| X30 | `--network` default | `mainnet` | Required, no default | QRL (no published mainnet) | [docs/spec/network-config.md](docs/spec/network-config.md) |
| X31 | Disabling slashing protection | Allowed anywhere | Allowed only when every listener is loopback, no override | Fix | G4 C3, T26 |
| X32 | Connection limits | none | `--http-max-connections` 1024; unknown-length bodies count as large | Fix | G4 C6 |
| X33 | Text log format | log4j pattern | logrus `TextFormatter` | Go-native | CO §7 |
