# Quickstart

This page runs `remotesigner consensus` on one host, next to the qrysm validator client, with `file-raw` keys,
generated bearer tokens and a file network. Every flag is listed in [`../reference/flags.md`](../reference/flags.md);
the HTTP API is [`../contract.md`](../contract.md).

> This release signs all nine artifact types behind slashing protection, releases RANDAO reveals under the frontier
> rule ([`randao.md`](randao.md)), and serves the operational API (`publicKeys`, `capabilities`, `/upcheck`,
> `/healthcheck`, `/reload`) and the metrics listener.

## 1. Build

```
make build-consensus      # bin/remotesigner-consensus: consensus only, permissive licences only
```

`make build` produces `bin/remotesigner`, the default flavour; both behave the same for everything on this page.

## 2. Key files

A key is the validator's **48-byte ML-DSA-87 wallet seed**, the same seed qrysm derives the key pair from. Put one
YAML document per key into a directory; every non-hidden `*.yaml` or `*.yml` file directly in it is read, and a file
may hold several documents separated by `---`:

```yaml
type: file-raw
keyType: ML_DSA_87
privateKey: "0x<96 hex characters>"
```

- `keyType` may be left out; `ML_DSA_87` is the only value.
- 32-byte keys, 51-byte extended seeds (execution mode) and 4,896-byte raw ML-DSA secret keys are refused with a
  message that says which one was found.
- File names are free. Keys are identified by their public key, never by the file name.
- Keep the directory readable by the signer's user only (`chmod 700`, files `0600`): the seed is the key.

A file that fails to load is logged at ERROR and counted in the `keys-check/config-files-loading` health check; the
other files still load. On `POST /reload`, a file that now fails keeps the keys it had.

## 3. Network

`--network` is required. It is either a built-in name (`minimal`, `end-to-end` or `e2e`, `end-to-end-mainnet`,
`interop`) or a qrysm-format chain config YAML, such as the one a qrysm e2e run writes.

The signer also needs the chain's genesis validators root (GVR) and genesis time:

| Value | Sources, in precedence order |
|---|---|
| GVR | `--network-genesis-validators-root`, the first bytes of `--network-genesis-state`, or pinned on first use (file networks on a loopback listener only) |
| Genesis time | `--network-genesis-time`, or the first bytes of `--network-genesis-state` |

When two sources give a value they must agree, or the signer refuses to start. Without a genesis time the signer
starts on loopback with a WARN, but `capabilities` reports `randao_reveal: false` and the qrysm client will refuse to
use it, so always pass one.

## 4. Start

```
bin/remotesigner-consensus \
  --data-path=/var/lib/remotesigner \
  --key-store-path=/var/lib/remotesigner/keys \
  --http-listen-port=9000 \
  consensus \
  --network=/etc/remotesigner/config.yaml \
  --network-genesis-time=1760000000
```

On first start the signer creates, under `--data-path`:

| File | Content |
|---|---|
| `auth-token` | the **sign** token (mode `0600`): duty routes, `publicKeys`, `capabilities`, `GET /reload`, healthcheck detail |
| `admin-token` | the **admin** token (mode `0600`): `POST /reload`, `DELETE /api/v1/consensus/randao_state/{identifier}` |
| `slashing-protection.db` | the bbolt slashing-protection store, locked while the signer runs |
| `remotesigner.ports` | `http-port=<port>` (and `metrics-port=<port>` with `--metrics-enabled`), written once listening and removed at shutdown; useful with `--http-listen-port=0` |

Neither token implies the other. Give the validator client the sign token only
(`--validators-external-signer-auth-token-file=/var/lib/remotesigner/auth-token`); keep the admin token for
operators. Use `--http-auth-token-file` and `--http-admin-token-file` to place them elsewhere. The two tokens must
differ: the signer refuses to start, and a SIGHUP reload keeps the previous tokens, when they are the same.

The signer listens at once and loads keys in the background; `/upcheck` answers `503 LOADING` until the keys are
loaded and the store is open, then `200 OK`.

## 5. Check it

```
TOKEN=$(cat /var/lib/remotesigner/auth-token)
curl -s localhost:9000/upcheck
curl -s -H "Authorization: Bearer $TOKEN" localhost:9000/api/v1/consensus/publicKeys
curl -s -H "Authorization: Bearer $TOKEN" localhost:9000/api/v1/consensus/capabilities
curl -s -H "Authorization: Bearer $TOKEN" localhost:9000/healthcheck
```

Without the token, `/healthcheck` shows only `status` and `outcome`.

After adding or removing key files, reload with the admin token. Every POST needs `Content-Type: application/json`,
even without a body:

```
ADMIN=$(cat /var/lib/remotesigner/admin-token)
curl -s -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' localhost:9000/reload
curl -s -H "Authorization: Bearer $TOKEN" localhost:9000/reload        # idle, running, completed, ...
```

Keys removed from the directory are dropped from memory; their slashing-protection history stays in the store.

## 6. Sign

The validator client signs through `POST /api/v1/consensus/sign/{identifier}` with the sign token; the request
bodies are in [`../contract.md`](../contract.md#8-artifact-types). The identifier is the canonical public key (`0x`
and 5,184 hex characters) or its short alias, `0x` and the 64 hex characters of `sha256(pubkey)`, which is easier to
type:

```
ALIAS=0x$(curl -s -H "Authorization: Bearer $TOKEN" localhost:9000/api/v1/consensus/publicKeys |
  jq -r '.[0][2:]' | xxd -r -p | sha256sum | cut -d' ' -f1)
curl -s -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d @aggregation-slot.json localhost:9000/api/v1/consensus/sign/$ALIAS
```

Every request is checked before anything is signed: its network (`fork_info`), its signing root, the wall clock
(when genesis time is known), and, for blocks and attestations, slashing protection, which records the message in
the store before the signature is computed. Every signature is verified before it is released; a key whose signature
fails is quarantined until the next reload (see [`metrics.md`](metrics.md#signaturefault)).

| Flag | Default | Effect |
|---|---|---|
| `--voluntary-exit-signing-enabled` | `false` | `VOLUNTARY_EXIT` is refused with 403 `ARTIFACT_TYPE_DISABLED` unless set. The qrysm e2e needs no exits through the signer. |
| `--registration-fee-recipient-file` | unset | Pins fee recipients per key ([`../reference/registration-fee-recipient-file.md`](../reference/registration-fee-recipient-file.md)) |
| `--signing-clock-skew-slots` | `1` | How far ahead of the wall clock a slot-scoped request may be |
| `--selection-proof-signing` | `deterministic` | `AGGREGATION_SLOT` and `SYNC_COMMITTEE_SELECTION_PROOF` are signed deterministically, as qrysm's local keymanager does; `hedged` changes that. Every other type is always hedged. |

### RANDAO

The validator client asks for its RANDAO reveal through `POST /api/v1/consensus/randao_reveal/{identifier}` with the
sign token, sending the proposal slot, the commitment it read from its beacon node and `fork_info`. The signer
releases a new onion layer only for a slot next to the wall clock and after the key's last one, within a small
per-key budget, and records it in the store before answering. A small network (fewer than about `4 × SLOTS_PER_EPOCH` validators) should raise
`--randao-new-layer-burst` or turn the bucket off with `--randao-new-layer-refill-epochs=0`. The rule, the flags,
the reset of a key's state and the store upgrade (`consensus migrate`) are in [`randao.md`](randao.md).

## 7. Metrics

`--metrics-enabled` starts the Prometheus listener on `127.0.0.1:9001`. The metric catalogue, the alert rules in
`deploy/prometheus/alerts.yml` and their runbooks are in [`metrics.md`](metrics.md).

## 8. Rotate tokens, stop

- **Rotate a token:** write a new one (`0x` and at least 64 hex characters) into its file, or delete the file to have
  a new one generated, then `kill -HUP <pid>`. If the new file is invalid, the old token stays in force and an ERROR
  is logged.
- **Stop:** `SIGTERM` (or `SIGINT`). The signer stops accepting connections, lets in-flight requests finish for up to
  10 s, closes the store, wipes the keys from memory, removes the ports file and exits 0.

## 9. Configuration file and environment

Every flag can also come from the environment or from `--config-file` (precedence: command line, environment,
config file, default):

```yaml
# /etc/remotesigner/signer.yaml
data-path: /var/lib/remotesigner
key-store-path: /var/lib/remotesigner/keys
consensus:
  network: /etc/remotesigner/config.yaml
  network-genesis-time: 1760000000
```

```
REMOTESIGNER_HTTP_LISTEN_PORT=9000 bin/remotesigner-consensus --config-file=/etc/remotesigner/signer.yaml consensus
```

Unknown keys in the file are refused (exit code 2), so a typo never silently falls back to a default.

## 10. Listening beyond loopback

The defaults bind `127.0.0.1`. A non-loopback `--http-listen-host` turns on fail-safes, each of which refuses to start
(exit code 1) with a message naming the fix:

| Refused | Fix |
|---|---|
| `--http-auth-mode=none` | use token auth |
| token auth over plaintext HTTP (this release has no TLS) | put the signer behind a TLS terminator on the same host, or accept the risk with `--Xallow-plaintext-token-auth` |
| `--http-host-allowlist` with loopback names only | add the names clients use, for example `--http-host-allowlist=signer.internal` |
| `--slashing-protection-enabled=false` | none: protection can be disabled only when every listener is loopback |
| GVR to be pinned on first use | pass `--network-genesis-validators-root` or `--network-genesis-state` (or `--Xallow-gvr-tofu`) |
| genesis time unknown | pass `--network-genesis-time` or `--network-genesis-state` (or `--Xallow-unknown-genesis-time`) |
| a non-loopback `--metrics-host` with a `--metrics-host-allowlist` of loopback names only | add the name Prometheus scrapes with |

Requests are also refused whatever the listener: any `Origin` header (403), a `Host` outside the allowlist (403), a
POST that is not `application/json` (415), and bodies over the route limit (413). At most
`--http-max-connections` (1,024) connections are open at once; further ones wait.
