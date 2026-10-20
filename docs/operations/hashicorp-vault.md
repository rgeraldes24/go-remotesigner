# HashiCorp Vault

The signer reads validator seeds from HashiCorp Vault's KV version 2 secrets engine with `type: hashicorp`
key-config documents, as Web3Signer does. It talks to Vault's HTTP API directly: no Vault SDK is linked into either
binary, and this store works in both `remotesigner` and `remotesigner-consensus`. Vault holds the seed only; every
signature is made in the signer's own memory. Web3Signer has no Vault bulk loader, and neither has this signer: each
secret is named by one document.

How key-config files are found, loaded and reloaded is in [`reload.md`](reload.md); the other stores are
[AWS Secrets Manager](aws-secrets-manager.md), [GCP Secret Manager](gcp-secret-manager.md) and
[Azure Key Vault](azure-key-vault.md).

## 1. The secret

Store the validator's 48-byte wallet seed as one key of a KV version 2 secret, in hex, with or without `0x`:

```
vault kv put -mount=secret validators/validator-0 value=0x<96 hex characters>
```

The value is one seed. Whitespace around it (a trailing line feed) is ignored. A 51-byte extended seed (it belongs to
execution mode), a 32-byte value (a FIPS 204 ξ or a BLS key) and a 4,896-byte expanded secret key are refused with a
message that says what they are; no error message or log line ever contains the value.

## 2. The key-config document

```yaml
type: hashicorp
keyType: ML_DSA_87                          # optional; the only value
serverHost: vault.example.internal
serverPort: 8200                            # default 8200
keyPath: /v1/secret/data/validators/validator-0
keyName: value                              # default "value"
token: "hvs.…"                              # the TOKEN method's Vault token
tlsEnabled: true
tlsKnownServersPath: known_servers          # optional, relative to the key-config directory
timeout: 10000                              # milliseconds, default 10000
httpProtocolVersion: HTTP_2                 # HTTP_1_1 or HTTP_2 (default)
```

| Field | Required | Meaning |
|---|---|---|
| `serverHost`, `keyPath` | yes | The server and the secret's read path: `/v1/<mount>/data/<path>`, optionally with `?version=N`. The path must be a path on the server: an absolute URL is refused, and `.` and `..` segments are resolved. |
| `serverPort` | no | 1 to 65535; default 8200. |
| `keyName` | no | The key of the secret's data that holds the seed; default `value`. The signer reads `data.data[keyName]` of the response, which must be a string. |
| `authMethod` | no | `TOKEN` (default) or `KUBERNETES`, in any case. |
| `token` | for `TOKEN` | The Vault token, sent as `X-Vault-Token`. |
| `kubernetesRole` | for `KUBERNETES` | The Vault role bound to the pod's service account. |
| `kubernetesServiceAccountTokenPath` | no | The service-account token file; default `/var/run/secrets/kubernetes.io/serviceaccount/token`. |
| `kubernetesAuthPath` | no | The auth method's mount path; default `kubernetes`. Surrounding slashes are dropped; an empty, `.` or `..` segment is refused. |
| `tlsEnabled` | no | `true` connects over HTTPS; default `false`, as in Web3Signer. Without it the token and the seed cross the network unencrypted: keep `false` for a Vault on the same host or a dev server only. |
| `tlsKnownServersPath` | no | With `tlsEnabled`, a file of trusted server certificates (section 4). |
| `timeout` | no | Milliseconds each request may take, from connecting to reading the response; default 10000. |
| `httpProtocolVersion` | no | `HTTP_2` (default) or `HTTP_1_1`. Over plain HTTP the signer always speaks HTTP/1.1. |

Unknown fields are refused, as in every key-config document. A file may hold several documents, of any types; it
loads as a whole or fails as a whole.

**A file with a `token` is a secret file**: under `--strict-file-permissions` (the default) it is refused when its
group or other users can read it, so keep it at `0600` ([`reload.md`](reload.md#secret-files)).

## 3. Authentication

- **TOKEN**: the `token` field. Use a token with a policy that can read only the validators' secrets, for example:

  ```hcl
  path "secret/data/validators/*" {
    capabilities = ["read"]
  }
  ```

- **KUBERNETES**: on every fetch the signer reads the pod's service-account token and logs in with
  `POST /v1/auth/<kubernetesAuthPath>/login` (`{"role", "jwt"}`), then reads the secret with the client token it
  gets. Neither token is cached or logged. The service-account token file is not a secret file in the sense of
  `--strict-file-permissions`: Kubernetes mounts it readable by the pod's user and group (mode `0644` by default),
  and its access is the pod's.

## 4. TLS

With `tlsEnabled: true` the server certificate must chain to the system roots, with the server name `serverHost`.
With `tlsKnownServersPath`, a certificate is also accepted when its SHA-256 fingerprint is listed for the server,
Web3Signer's allowlist format:

```
# <host>:<port> <SHA-256 fingerprint of the server certificate>
vault.example.internal:8200 <32 hex bytes, as openssl prints them>
```

The host is matched without case and must be the document's `serverHost:serverPort` (an IPv6 host in brackets);
colons in the fingerprint are optional. `openssl x509 -in vault.crt -noout -fingerprint -sha256` prints one. A
missing or malformed file fails the document.

The file is read again on every load, as Web3Signer does: the HTTP clients of the documents last one load (the
documents of one server share one within it). To rotate a pinned certificate, add the new fingerprint, then touch
the documents and `POST /reload` (an unchanged document is not fetched again, section 6); removing a fingerprint
applies the same way.

## 5. Requests and limits

- Every request has the document's `timeout`; a reload as a whole is bounded by `--reload-timeout`.
- A response is read up to 4 MiB and a value up to 64 KiB; anything larger fails the document.
- **No redirect is followed** ([`DEVIATIONS.md`](../../DEVIATIONS.md), X90): a Vault standby node answers with a
  redirect to the active node, and following it would send the token to another address. Point `serverHost` at the
  active node or at a load balancer that forwards to it.
- HTTP 404 means the secret or its `keyName` does not exist; 403 a token without access. Vault's error messages are
  quoted in the log, bounded; the token and the value never are.
- Proxies are taken from `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, as in every Go program.

## 6. Reload and health

A document is fetched when its file is new or has changed. As in Web3Signer, **an unchanged file is not fetched
again** on `POST /reload`: after rotating a seed in Vault (which makes it a different validator key), touch or
rewrite the file. A fetch that fails (Vault down, 403, a bad value) fails the file, which keeps the keys it had, and
`keys-check/config-files-loading` reports the error until a reload succeeds; nothing is disabled
([`reload.md`](reload.md#3-reload)).

## 7. Testing against a Vault dev server

`make test-cloud` runs the client's and the built binary's tests against a real Vault: it starts the pinned
`hashicorp/vault` image as a dev server in Docker (or uses `REMOTESIGNER_TEST_VAULT_ADDR` and
`REMOTESIGNER_TEST_VAULT_TOKEN` when they are set, as the CI job `cloud-secrets` does). It fails unless each of its
three server tests ran and passed; `make test` skips them. A dev server is for tests only: it keeps everything in
memory and starts unsealed with a root token.
