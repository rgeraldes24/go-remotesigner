# Execution mode

`remotesigner execution` holds QRL account keys for wallets and tools that talk JSON-RPC: it lists the accounts, signs
messages and transactions with them, sends transactions through a gqrl node, and forwards everything else to that
node, so that the node holds no keys. It is the execution-layer counterpart of `remotesigner consensus`, and a port of
Web3Signer's `eth1` mode. Every flag is in [`../reference/flags.md`](../reference/flags.md#execution-flags); the
differences from Web3Signer are rows X25, X26, X28, X76-X87 and X102-X106 of [`DEVIATIONS.md`](../../DEVIATIONS.md).

It answers `qrl_accounts`, `qrl_sign`, `qrl_signTransaction`, `qrl_sendTransaction` and `health_status`
(section 4). Transactions are signed for one chain, `--chain-id`, under a fee cap and a per-account policy, and
recorded in an audit log (sections 8 to 10). The default flavour links the go-qrl library (LGPL-3.0-or-later) to
build and sign them (section 11).

## 1. The process and the flavours

Execution mode is a process of its own, never a part of the consensus signer: one process serves one mode. Only the
default flavour, `remotesigner`, has the `execution` command. The consensus-only flavour, `remotesigner-consensus`
(built with `-tags noexecution`), has no `execution` command, JSON-RPC endpoint or proxy (its build leaves out
`internal/execution`) and links no go-qrl; it refuses the command and an `execution:` section in its config file
([`release.md`](release.md)). The account-key parsing that execution mode shares with the key loaders is built into
both flavours.

The two modes share the global flags. To run both on one host, give each its own `--data-path` (tokens, the ports
file) and `--http-listen-port`, and its own key directories.

## 2. Start

```
remotesigner --data-path=/var/lib/remotesigner-execution --key-config-path=/etc/remotesigner/accounts \
  --http-listen-port=9100 \
  execution --chain-id=1337 --downstream-http-host=127.0.0.1 --downstream-http-port=8545 \
  --execution-audit-log-file=/var/lib/remotesigner-execution/audit.jsonl
```

`--chain-id` is required: it is the chain every transaction is signed for (section 8). On a listener that is not
loopback, `--execution-policy-file` is required too (section 9).

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
  mode ([`reload.md`](reload.md)): `POST /reload` with the admin token, a failed source keeps its previous keys. The
  token files and the TLS private key, keystore and its password file are secret files too, as in consensus mode
  ([`tls.md`](tls.md#1-tls-on-the-api-listener)).
- The secret-store documents (`hashicorp`, `aws-secret`, `azure-secret`, `gcp-secret`) hold validator seeds and are
  read in consensus mode only: in execution mode a key-config file with one of them fails to load, saying so, and
  nothing is fetched. Web3Signer's `eth1` mode reads `hashicorp` and `azure-secret` documents
  ([`../../DEVIATIONS.md`](../../DEVIATIONS.md), X102).

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
| `qrl_signTransaction` | `params: [transaction]`, as gqrl's: `from`, `nonce`, `gas`, `maxFeePerGas` and `maxPriorityFeePerGas` are required. The signer signs the type-0x2 transaction and returns `{"raw": "0x02…", "tx": {…}}` (section 8). It never asks the node. |
| `qrl_sendTransaction` | `params: [transaction]`. The signer completes the transaction with the node's `qrl_fillTransaction` when it lacks a nonce, gas, a fee cap or a chain ID, checks the node's answer, signs, and sends it with `qrl_sendRawTransaction` under the client's `id`; the result is the transaction hash, or the node's error (section 8). |
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
| -32603 | Internal error (the node refused a send's nonce 11 times, section 8) | 400 |
| -32603 | Internal error (waiting for the account's earlier transactions until the request ended) | 503 |
| -32003 | Transaction rejected: the chain ID, the fee cap, the account's policy or the node's fill answer (sections 8 and 9); `data` says why | 200 |
| -32000 | No unlocked account matches the Sender (`qrl_sign` or a transaction method for an address that is not loaded) | 200 |
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
  case-sensitive. The list applies to every element of a batch. An empty value forwards nothing. The signer's own
  methods are never forwarded, whatever the list says. The list governs only what clients send: the signer's own
  calls for transactions (`qrl_chainId`, `qrl_fillTransaction`, `qrl_getTransactionCount`, `qrl_sendRawTransaction`)
  go to the node whatever it allows, so a list that leaves out `qrl_*` still lets `qrl_sendTransaction` work, while
  clients can no longer call those methods themselves. With the default list a client may also send a transaction it
  signed itself with `qrl_sendRawTransaction`, or ask the node for `qrl_fillTransaction`; neither involves the
  signer's keys.
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
  the TLS handshake, the wait for the node's response headers and each wait for more of its response body. A whole
  request ends at the endpoint's write timeout, the downstream timeout plus 30 seconds, however slowly the node
  answers. A node that cannot be reached gets 504 "Failed to connect to downstream node", one that does not answer in
  time 504 "Connection to downstream node timed out" (in a batch, in place of each forwarded answer; a single
  response the node stops sending is cut off), a TLS failure 502.
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
  plaintext HTTP without `--Xallow-plaintext-token-auth`, no host allowlist of loopback names only, and no start
  without `--execution-policy-file` (section 9).
- **Health.** `/upcheck` and `/healthcheck` as in consensus mode, with the checks `default-check`,
  `keys-check/config-files-loading` and, with a keystore directory, `keys-check/keystores-bulk-loading`.
  `GET /reload` reports the last load, `POST /reload` (admin token) starts one.
- **Metrics.** With `--metrics-enabled`, the metrics listener serves the Go and process metrics, `process_release`,
  `signing_signers_loaded_count` and the HTTP metrics of the API listener ([`metrics.md`](metrics.md)). As in
  consensus mode, a metrics token on a non-loopback `--metrics-host` brings a startup warning that scrapes send it in
  clear ([`tls.md`](tls.md#7-the-metrics-token)).

## 8. Transactions

Transactions are go-qrl's own: a type-0x2 (dynamic fee) `DynamicFeeTx`, the only type QRL has, signed with go-qrl's
`types.SignTx` and `types.NewZondSigner(--chain-id)`. The signer passes go-qrl a `pqcrypto/wallet.Wallet` over the
loaded key, which signs and verifies but never gives out the seed. The signing hash is
`keccak256(0x02 ‖ rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gas, to, value, input, accessList,
descriptor, extraParams]))` with the descriptor `01 00 00` and empty `extraParams`. Signatures are hedged ML-DSA-87,
so signing the same transaction twice gives two hashes. Each signature is verified, and the sender recovered from the
signed transaction must be `from`, before it leaves the signer.

**The transaction object.** Both methods take one object with gqrl's member names and encodings (`Q` addresses, `0x`
quantities without leading zeros, `0x` data):

| Member | |
|---|---|
| `from` | required: a loaded account, else -32000 |
| `to` | the recipient; absent creates a contract, which needs `input` |
| `value` | Planck (10^18 Planck = 1 quanta); absent is 0 |
| `gas`, `maxFeePerGas`, `maxPriorityFeePerGas`, `nonce` | required by `qrl_signTransaction`; `qrl_sendTransaction` asks the node for those it lacks. `maxFeePerGas` may not be below `maxPriorityFeePerGas` |
| `input` (or `data`) | call data; when both are given they must be equal |
| `accessList` | signed as given; absent is empty |
| `chainId` | must be `--chain-id`; absent is `--chain-id` |
| `type` | optional; must be `0x2`, else -32602, and the refusal is written to the audit log (section 10) |

Other members are ignored, as gqrl ignores them. A member that does not decode is -32602, with the member's name and
go-qrl's reason in `data`.

**`qrl_signTransaction`** returns gqrl's result:

```json
{"raw": "0x02f91c…", "tx": {"type": "0x2", "chainId": "0x539", "nonce": "0x0", "to": "Q…", "gas": "0x5208",
  "maxPriorityFeePerGas": "0x3b9aca00", "maxFeePerGas": "0x2e90edd001", "value": "0x1", "input": "0x",
  "accessList": [], "descriptor": "0x010000", "extraParams": "0x", "signature": "0x…", "publicKey": "0x…",
  "hash": "0x…"}}
```

`raw` is what `qrl_sendRawTransaction` takes. A signed transaction is about 7.3 KB: the 4,627-byte signature and the
2,592-byte public key travel with it.

**`qrl_sendTransaction`** holds a lock for `from` from the first step to the node's answer, so that two calls for one
account never take the same nonce:

1. If the request lacks a nonce, gas, a fee cap or a chain ID, the signer calls the node's `qrl_fillTransaction` with
   its own encoding of the request, which runs gqrl's defaults (the pool nonce, a gas estimate, the suggested tip and
   twice the base fee).
2. It checks the answer (the payload check): the answer must be a type-0x2 transaction whose `to`, `value`, `input`,
   `accessList` and `chainId` are the request's, an absent `accessList` counting as empty and an absent `chainId` as
   `--chain-id`. `from` is never the node's to choose: it comes from the request and selects the key. Of the answer
   the signer takes only the nonce, gas and fee caps the request lacked, and builds the transaction again from the
   request and those values. A node that changes anything else gets -32003 "the node's qrl_fillTransaction answer
   changed the transaction's to" (or `value`, `input`, `accessList`, `chainId`), and nothing is signed.
3. With `--execution-nonce-crosscheck` (the default), a nonce the node filled in is compared with the node's
   `qrl_getTransactionCount(from, "pending")`; more than 64 above it is refused (-32003), because the transaction
   would wait in the pool behind a gap. A nonce the client chose is not checked.
4. The chain ID, the fee cap and the account's policy apply (below and section 9).
5. The signer signs, writes the audit entry (section 10) and sends `qrl_sendRawTransaction([raw])` under the
   client's `id`. The node's answer is returned: the transaction hash, or the node's own error with HTTP 200.
6. If the client did not choose the nonce and the node answers -32000 with a message containing `nonce too low`,
   `already known` or `replacement transaction underpriced`, another transaction holds that nonce: the signer goes back
   to step 1, up to 10 times, and then gives up with -32603 and HTTP 400. With hedged signatures a resent nonce gives
   "replacement transaction underpriced" rather than "already known". A nonce the client chose is never retried.

The lock is per process. Several signers in front of one node, or a client that also signs elsewhere, rely on the
retries, as Web3Signer does. The signer's own calls to the node carry none of the client's headers, only the
`--downstream-http-auth-header-file` credential, and are bounded like forwarded calls (section 6): a node that cannot
be reached is 504, a malformed or non-200 answer is -32000 "Invalid response from downstream node" with 502.

**The chain ID.** `--chain-id` is the chain every transaction is signed for. A request with another `chainId` is
refused (-32003). At startup and every 10 minutes the signer also asks the node for `qrl_chainId`: while the node's
answer differs from `--chain-id`, both transaction methods refuse every transaction, with "the downstream node's chain
ID is …, not --chain-id …", and an ERROR line is logged at each check. A check the node does not answer keeps the
last verdict. Until the node has answered once, the signer asks again every 15 seconds rather than every 10 minutes,
and signs transactions meanwhile: there is no mismatch to refuse yet. `qrl_sign` signs no transaction and is not affected.

**The fee cap.** A transaction's fee, `gas × maxFeePerGas`, the most it can pay, may be at most 1 quanta
(10^18 Planck), gqrl's own default `--rpc.txfeecap`, unless the account's policy sets another `max-fee`. It applies to
both methods, and in `qrl_sendTransaction` to the fees the node filled in.

## 9. The policy file

`--execution-policy-file` names a YAML file of per-account policies. It is read at startup; a file that does not
parse stops the signer. A non-loopback listener refuses to start without one. Without a file (loopback only), every
loaded account may sign any transaction within the fee cap.

```yaml
# Accounts the file does not name get the default section, or may sign nothing when it is absent.
default:
  max-fee: 100000000000000000          # 0.1 quanta
  contract-creation: false
accounts:
  Q2a5b…:                              # Q and 128 hex characters, either case after the Q
    allowed-recipients:
      - Q9f0e…
      - Q11c4…
    max-value: 5000000000000000000     # 5 quanta, in Planck
    max-fee: 1000000000000000000       # gas × maxFeePerGas, in Planck
    contract-creation: false
    max-data-bytes: 0                  # plain transfers only
    max-transactions-per-hour: 30
```

| Key | Meaning | When absent |
|---|---|---|
| `allowed-recipients` | the only `to` addresses the account may send to; a contract creation has none and is governed by `contract-creation` | any recipient |
| `max-value` | the largest `value`, in Planck | no limit |
| `max-fee` | the largest `gas × maxFeePerGas`, in Planck | 1 quanta |
| `contract-creation` | whether a transaction without `to` may be signed | `false` |
| `max-data-bytes` | the longest `input` | no limit |
| `max-transactions-per-hour` | the most transactions signed in any hour (0 to 100,000) | no limit |

Amounts are decimal integers of Planck (YAML integers or strings, `_` allowed as a separator). Unknown keys, an
address that is not `Q` and 128 hex characters, an account named twice (in any spelling) and a file that names no
account and has no default are refused.

A key without a value is refused too, wherever it is: `max-value:` with nothing after it, `~` or `null`, an
`allowed-recipients:` whose entries are all commented out, an empty list entry, or an account named with no section.
YAML reads each of these as null, and taking null for an absent key would lift the limit: `allowed-recipients:` alone
would allow every recipient. Write `allowed-recipients: []` to allow none, `Q…: {}` for an account that gets only the
defaults, or remove the key to get the "When absent" column. The file is one YAML document: a second one, after
`---`, is refused rather than ignored. The hourly count is kept in memory, per process: a restart resets it, and
each signer in front of one node counts only its own transactions. A `qrl_sendTransaction` counts once however often
it retries. A refusal is -32003 "Transaction rejected" with the reason in `data`, which names no address.

## 10. The audit log

`--execution-audit-log-file` names an append-only [JSON Lines](https://jsonlines.org/) file, created with mode 0600.
It records, one object per line:

| `outcome` | Written when |
|---|---|
| `signed` | a transaction was signed, before it leaves the signer (returned by `qrl_signTransaction` or sent by `qrl_sendTransaction`) |
| `sent` | the node accepted a sent transaction |
| `node-refused` | the node refused a sent transaction; `reason` is its message (a retry follows when step 6 of section 8 applies) |
| `refused` | the signer refused a transaction: an unknown account, a `type` other than `0x2` (answered with -32602, as gqrl does), the chain ID, the fee cap, the policy or the node's fill answer; `reason` says which |

```json
{"time":"2026-10-20T08:15:02.731Z","method":"qrl_sendTransaction","outcome":"signed","hash":"0x5bfe…","from":"Q45F3…","to":"Q1111…","nonce":"0x7","value":"0xde0b6b3a7640000","fee":"0xeebe0b40ed208","chainId":"0x539"}
```

`fee` is `gas × maxFeePerGas`. The fields a refusal had no value for are absent. Each line is written and synced
before the request goes on; if the log cannot be written, the signature is discarded and the request fails with
-32603, so no signature leaves the signer without its line. On SIGHUP the signer opens the path again, so a log
rotator can move the file away and signal the signer.

## 11. go-qrl and the LGPL

The default flavour builds and signs transactions with the go-qrl library (`github.com/theQRL/go-qrl`, licensed
under the GNU Lesser General Public License v3.0 or later), at the commit `go.mod` requires, unmodified. Only
`internal/execution` imports it, and only its library packages, never `cmd/**` or `internal/**`; a lint rule and the
release checks enforce both. The consensus flavour, `remotesigner-consensus`, links none of it.

The default flavour is therefore an LGPL combined work: go-remotesigner's code stays Apache-2.0 and go-qrl stays LGPL.
Its releases carry what the LGPL asks ([`release.md`](release.md#2-notice-and-licence-texts-per-flavour)): the NOTICE
appends [`NOTICE.execution`](../../NOTICE.execution), which says that go-qrl is used and under the LGPL; `LICENSES/`
holds the LGPL and GPL texts; `--version` prints go-qrl's notice with where to find them and the version's source; and
each release attaches `remotesigner-<version>-src-vendored.tar.gz`, the source with every dependency vendored, from
which the binary can be rebuilt with a modified go-qrl. Anyone who needs a permissively licensed binary uses `remotesigner-consensus`, which
has no execution mode.
