# Execution mode

`remotesigner execution` holds QRL account keys for wallets and tools that talk JSON-RPC: it lists the accounts,
signs messages with them, and forwards everything else to a gqrl node, so that the node holds no keys. It is the
execution-layer counterpart of `remotesigner consensus`, and a port of Web3Signer's `eth1` mode. Every flag is in
[`../reference/flags.md`](../reference/flags.md#execution-flags); the differences from Web3Signer are rows X68-X79 of
[`DEVIATIONS.md`](../../DEVIATIONS.md).

This release answers `qrl_accounts`, `qrl_sign` and `health_status`. Transaction signing (`qrl_signTransaction`,
`qrl_sendTransaction`) is not part of it: both methods are refused (section 4) and never reach the node.

## 1. The process and the flavours

Execution mode is a process of its own, never a part of the consensus signer: one process serves one mode. Only the
default flavour, `remotesigner`, has the `execution` command. The consensus-only flavour, `remotesigner-consensus`
(built with `-tags noexecution`), has no execution code at all and refuses the command and an `execution:` section
in its config file ([`release.md`](release.md)).

The two modes share the global flags. To run both on one host, give each its own `--data-path` (tokens, the ports
file) and `--http-listen-port`, and its own key directories.

## 2. Start

```
remotesigner --data-path=/var/lib/remotesigner-execution --key-config-path=/etc/remotesigner/accounts \
  --http-listen-port=9100 \
  execution --downstream-http-host=127.0.0.1 --downstream-http-port=8545
```

The signer listens at once, writes `<data-path>/remotesigner.ports` and the sign token (`<data-path>/auth-token`, as
in consensus mode), and loads the account keys. Until that load finishes, `POST /` and `publicKeys` answer 503
`NOT_READY` and `/upcheck` 503, as in consensus mode. Load errors never stop the signer: a key that fails to load is
reported by `/healthcheck` (section 7) and in the log.

## 3. Account keys

Account keys are ML-DSA-87 keys held as go-qrl holds them: a **51-byte extended seed**, the descriptor `01 00 00`
followed by the 48-byte wallet seed. Two sources load them, the same two as in consensus mode:

| Source | Flags | Holds |
|---|---|---|
| Key-config files | `--key-config-path` | `file-raw` documents with the extended seed, and `file-keystore` documents naming a go-qrl account keystore |
| Keystore directory | `--keystores-path` with `--keystores-password-file` or `--keystores-passwords-path` (`<name>.txt` for `<name>.json`) | go-qrl account keystores |

```yaml
type: file-raw
keyType: ML_DSA_87
privateKey: "0x010000<96 hex characters>"   # 102 hex characters; the 0x is optional, as in go-qrl's seed files
---
type: file-keystore
keyType: ML_DSA_87
keystoreFile: accounts/account-0.json      # relative paths are relative to the key-config directory
keystorePasswordFile: accounts/account-0.txt
```

The rules:

- The descriptor must be exactly `01 00 00` (ML-DSA-87 without parameters). go-qrl checks only its first byte; this
  signer refuses any other value.
- A **48-byte seed is refused** in execution mode, with "a 48-byte seed is a consensus validator key", and a 51-byte
  extended seed is refused in consensus mode. Each mode refuses the other's keystores the same way: a validator
  keystore has no `address`, and an account keystore has one.
- **Never let one seed serve as both a validator key and an account key.** Both modes sign under the same ML-DSA
  context, so only the structure of what is signed keeps a consensus signing root and an account message apart. The
  length rule keeps one file from loading in both modes; reusing the 48 seed bytes behind an account's descriptor is
  still possible and must not be done.
- A go-qrl account keystore (`gqrl account new`, `account import`) is opened with the same structure and KDF policy
  as validator keystores ([`keystores.md`](keystores.md#2-what-the-signer-refuses)), with a 51-byte plaintext; its
  password is used as raw bytes, as go-qrl does (trailing line breaks of the password file are dropped). After
  decryption the signer derives the address from the key and **compares it with the keystore's `address`**, which
  go-qrl's own decryptor does not: a keystore whose address belongs to another key is refused.
- gqrl names its keystore files `UTC--<time>--Q<address>`, with no extension. `--keystores-path` loads only
  `*.json` files, as Web3Signer's keystore directories do, so copy each keystore under a `<name>.json` name (its
  password file is then `<name>.txt` with `--keystores-passwords-path`), or name it in a `file-keystore` document,
  which takes any file name.
- Seed files and password files are secret files under `--strict-file-permissions`, and reloads work as in consensus
  mode ([`reload.md`](reload.md)): `POST /reload` with the admin token, a failed source keeps its previous keys.

An account's address is `SHAKE-256(01 00 00 ‖ public key)`, the first 64 bytes, written `Q` and 128 hex characters.
The signer reads an address in either case after the `Q` and does not check its QIP-55 checksum, as gqrl does; the
`Q` itself must be upper case.

## 4. The JSON-RPC endpoint

`POST /` speaks JSON-RPC 2.0 behind the sign token. Other paths are 404 once the caller has a credential, and `GET /`
is 405. Web3Signer's REST paths (`/api/v1/eth1/sign/…`, `/api/v1/eth1/publicKeys`), its signing extension and
Commit-Boost do not exist.

| Method | Answer |
|---|---|
| `qrl_accounts` | The loaded addresses in QIP-55 form, sorted by address. Its `params` must be absent, `null` or `[]` (-32602 otherwise). |
| `qrl_sign` | `params: [address, data]`, as gqrl's: `data` is `0x` hex (text is refused with -32602). The signer signs `keccak256("\x19QRL Signed Message:\n" + len(data) + data)`, go-qrl's `accounts.TextHash`, with hedged ML-DSA-87, verifies the signature, and returns the raw 4,627-byte signature in `0x` hex: no public key, no recovery byte. An address that is not loaded is -32000. |
| `health_status` | `"OK"` |
| `qrl_signTransaction`, `qrl_sendTransaction` | -32604 "Method not enabled": not available in this release. Never forwarded, so the node never signs with keys of its own. |
| `qrl_signTypedData` | -32601: typed-data signing is not offered. Never forwarded. |
| anything else | Forwarded to the node when `--execution-proxy-allowed-methods` allows it (section 6), otherwise -32601 "Method not found". |

The errors the signer itself returns:

| Code | Message | HTTP status of a single request |
|---|---|---|
| -32700 | Parse error | 400 |
| -32600 | Invalid Request (not an object, `jsonrpc` not `"2.0"`, no `method`, an `id` that is not a string, number or null, an empty or oversized batch) | 400 |
| -32601 | Method not found | 200 |
| -32602 | Invalid params | 400 |
| -32603 | Internal error | 500 |
| -32604 | Method not enabled | 200 |
| -32000 | No unlocked account matches the Sender (`qrl_sign` for an address that is not loaded) | 200 |
| -32000 | Failed to connect to downstream node / Connection to downstream node timed out / Invalid response from downstream node | 504, 504 and 502 (section 6) |

An error may carry a `data` string that says more. A request without an `id` is a notification: a notification of
a local or refused method runs nothing and gets an empty 200 response.

**Batches.** A JSON array of 1 to 1,000 requests, gqrl's own limit, is answered element by element, in request
order, with HTTP 200:

- the local methods are answered by the signer;
- a method the allowlist refuses gets -32601 and never reaches the node;
- the forwarded requests go to the node as one batch, each carrying its position in the client's batch as its
  `id`; the node's answers are matched by that id and returned under the client's own ids, so repeated or `null` ids
  are answered correctly. A forwarded call the node does not answer, or a node failure, gets the -32000 error of
  section 6 in its place, while the local answers still arrive;
- notifications get no element.

An empty batch and a batch of more than 1,000 requests are refused with one -32600 object and 400. The request body
is limited to 5 MiB, gqrl's own limit (413 `BODY_TOO_LARGE`).

## 5. Public keys and verifying a signature

ML-DSA signatures cannot be recovered to a key, so a verifier needs the public key:

```
curl -H "Authorization: Bearer $(cat /var/lib/remotesigner-execution/auth-token)" \
  http://127.0.0.1:9100/api/v1/execution/publicKeys
[{"address":"Q…","public_key":"0x…"}]
```

The array lists every loaded account, sorted by address as `qrl_accounts` is, with the 2,592-byte public key. A
`qrl_sign` signature verifies with go-qrllib's `wallet/ml_dsa_87.Verify(TextHash(data), signature, publicKey,
descriptor 01 00 00)`, which applies the context `"ZOND" ‖ 01 ‖ 01 00 00`.

## 6. The proxy

Requests the signer does not answer go to `http://<--downstream-http-host>:<--downstream-http-port><--downstream-http-path>`
(default `http://127.0.0.1:8545/`) through Go's `httputil.ReverseProxy`. The node is trusted to answer, never to
receive the client's credentials:

- **Methods.** `--execution-proxy-allowed-methods` lists method names, prefixes ending in `*`, or `*` for every
  method. The default, `qrl_*,net_*,web3_*`, forwards the chain, network and client namespaces; `admin_*`,
  `debug_*`, `personal_*`, `miner_*`, `txpool_*`, `eth_*` and clef's `account_*` are refused with -32601. Names are
  case-sensitive. The list applies to every element of a batch. An empty value forwards nothing.
- **Request bodies.** The node never gets the client's bytes: each forwarded request is re-encoded from what the
  signer decoded, its `jsonrpc`, `id`, `method` and `params`, and any other member is dropped. gqrl decodes member
  names without regard to case, the last one winning, so a body with both `method` and `METHOD` would otherwise run
  the second, which the allowlist never checked.
- **Request headers.** Only `Content-Type`, `Accept` and `User-Agent` are forwarded. The client's `Authorization`
  (the signer's own token), `Cookie`, `Proxy-*`, `Forwarded`, `X-Forwarded-*` and every other header stay with the
  signer. `Host` is the node's. The node's own credential, when it needs one, comes from
  `--downstream-http-auth-header-file`: the file's first line is sent as `Authorization` (for example
  `Bearer <token>`). It is a secret file, read at startup.
- **Responses.** The node's status, headers and body are passed back, except `Set-Cookie` and every
  `Access-Control-*` header. Its trailers and its 1xx interim responses (such as 103 Early Hints) are not passed
  back at all, as in Web3Signer. A response over 25 MB is refused with 502 when its length is announced and cut off
  otherwise.
- **No redirects.** A redirect from the node is passed back as it is; the signer never follows it. In a batch it
  is an "Invalid response from downstream node" error.
- **Timeouts and failures.** `--downstream-http-request-timeout` (milliseconds, default 5000) bounds the connection,
  the TLS handshake and the wait for the node's response headers. A node that cannot be reached gets 504 "Failed to
  connect to downstream node", one that does not answer in time 504 "Connection to downstream node timed out", a TLS
  failure 502.
- **TLS and HTTP proxies.** `--downstream-http-tls-enabled` connects with https, checking the node's certificate
  against the system roots or the PEM CAs of `--downstream-http-tls-ca-file`. `--downstream-http-proxy-host` and
  `--downstream-http-proxy-port` route requests through an HTTP proxy; the proxy environment variables are never
  read.

## 7. Guards, health and metrics

Execution mode runs behind the same server as consensus mode ([`tls.md`](tls.md)):

- **Authentication.** Bearer tokens only, in the `Authorization: Bearer` header, with the sign token
  (`--http-auth-mode=token`, the default), a client certificate (`mtls`) or both. Basic authentication, and a token
  in the URL, are refused with 401: gqrl logs the URL of its signer, so a token there would leak.
- **The rest.** The host allowlist (403 `HOST_NOT_ALLOWED`), the `Origin` refusal (403 `ORIGIN_NOT_ALLOWED`: there
  is no CORS), `Content-Type: application/json` (415), the connection cap `--http-max-connections`, the large-body
  gate, TLS 1.3, and the startup fail-safes of a non-loopback listener: no `--http-auth-mode=none`, no token over
  plaintext HTTP without `--Xallow-plaintext-token-auth`, no host allowlist of loopback names only.
- **Health.** `/upcheck` and `/healthcheck` as in consensus mode, with the checks `default-check`,
  `keys-check/config-files-loading` and, with a keystore directory, `keys-check/keystores-bulk-loading`.
  `GET /reload` reports the last load, `POST /reload` (admin token) starts one.
- **Metrics.** With `--metrics-enabled`, the metrics listener serves the Go and process metrics, `process_release`,
  `signing_signers_loaded_count` and the HTTP metrics of the API listener ([`metrics.md`](metrics.md)).
