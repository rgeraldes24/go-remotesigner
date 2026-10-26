# TLS, mTLS and process hygiene

This page covers serving the API over TLS, authenticating validator clients with certificates, pinning the
certificate the signer generates, rotating tokens and certificates with SIGHUP, the metrics token, and the process
hardening the signer applies on Linux. Every flag is listed in [`../reference/flags.md`](../reference/flags.md);
the authentication scopes are specified in [`../contract.md`](../contract.md#6-authentication-and-scopes).

## 1. TLS on the API listener

TLS is on when a certificate is configured or `--tls-generate-self-signed` is set. The listener then speaks
**TLS 1.3 only**: a TLS 1.2 or older client is refused during the handshake. The key exchange is Go's default, so the
hybrid post-quantum `X25519MLKEM768` comes first for clients that offer it (Go 1.24 and later do), and the API is
served over h2 and HTTP/1.1. Plaintext HTTP on the TLS port gets no API.

The certificate comes from one of three sources:

| Source | Flags | Notes |
|---|---|---|
| PEM | `--tls-cert-file`, `--tls-key-file` | The certificate file may hold the chain after the leaf. The key is PKCS#8, PKCS#1 or SEC 1, unencrypted. |
| PKCS#12 | `--tls-keystore-file`, `--tls-keystore-password-file` | Web3Signer's options. Only the first line of the password file is the password. Modern (AES, PBKDF2) and legacy (3DES, RC2) keystores load. |
| Generated | `--tls-generate-self-signed` | Section 2. A PEM or PKCS#12 certificate, when configured, takes precedence, and nothing is generated. |

Each flag of a pair needs the other, and PEM and PKCS#12 cannot both be given; these are usage errors (exit code 2). A
file that cannot be read, a wrong password, or a key that does not match its certificate refuses the start (exit code
1). The private key, the PKCS#12 keystore and its password file are secret files, like the token files (section 5): with
`--strict-file-permissions` (the default) one that its group or other users can read refuses the start, and the log
names the file and its mode; with `--strict-file-permissions=false` it is loaded with a WARN. Keep them at `0600` or
`0400`. The certificate file is public and is not checked. At startup the signer logs the certificate's source, path,
SHA-256 fingerprint and expiry:

```
level=info msg="TLS enabled" certificate=/etc/remotesigner/tls/signer.crt client-auth=none
  not-after="2027-10-16T00:00:00Z" sha256-fingerprint="80:F9:0F:…:27:79" source=pem
```

The validator client verifies the signer's certificate against the CA file it is given
(`--validators-external-signer-tls-ca-file`), or against the system roots when it is given none:

```
validator … \
  --validators-external-signer-url=https://signer.internal:9000 \
  --validators-external-signer-tls-ca-file=/etc/qrysm/signer-ca.pem \
  --validators-external-signer-auth-token-file=/etc/qrysm/signer-auth-token
```

TLS makes token auth safe on a non-loopback listener: with TLS on, the plaintext-token refusal of the fail-safes
(section 6) no longer applies.

## 2. The generated certificate, and pinning it

With `--tls-generate-self-signed` and no configured certificate, the first start writes an ECDSA P-256 key and a
self-signed certificate to `<data-path>/tls/`:

| File | Mode | Content |
|---|---|---|
| `<data-path>/tls/` | `0700` | |
| `key.pem` | `0600` | the PKCS#8 private key |
| `cert.pem` | `0600` | the certificate, valid for 10 years, for every name and address in `--http-host-allowlist` |

The signer logs where it wrote the certificate and its SHA-256 fingerprint:

```
level=info msg="Generated a self-signed TLS certificate: give its file to the validator client
  (--validators-external-signer-tls-ca-file) and compare the fingerprint" certificate=/var/lib/remotesigner/tls/cert.pem
  sha256-fingerprint="3A:1F:…:C2" source=self-signed
```

Later starts reuse the two files; they are never regenerated while `cert.pem` exists. A reused `key.pem` is a secret
file (section 1): one that its group or other users can read refuses the start under `--strict-file-permissions`. A
`cert.pem` whose `key.pem` is gone refuses the start rather than being replaced, because clients have pinned it. If
`<data-path>/tls/` already exists and its group or other users can write it (a volume mounted with loose permissions,
say), the start is refused on Linux and macOS: they could replace the key the signer serves. `chmod 0700` the directory
and check its files. Generation runs under a lock on the directory, so two signers started at once on the same data path
end up with the same certificate.

The certificate's names come from `--http-host-allowlist`, so set the allowlist to the names validator clients
connect with before the first start, for example `--http-host-allowlist=signer.internal,10.0.0.5`. A wildcard
allowlist (`*` or `all`) names no host, and the start is refused. If the allowlist later gains a name the certificate
does not cover, the signer logs a WARN naming it: clients connecting by that name fail hostname verification.

**Pin it in the validator client.** Copy `cert.pem` to the validator client's host over a channel you trust, check
that its fingerprint is the one the signer logged, and give it to the client as its CA file:

```
openssl x509 -in cert.pem -noout -fingerprint -sha256     # must match sha256-fingerprint in the signer's log
validator … --validators-external-signer-tls-ca-file=/etc/qrysm/signer-cert.pem
```

The client then accepts only this certificate. Never turn verification off instead: the token would go to whoever
answers on the signer's address.

**Rotate it.** Delete both files, then restart the signer or send it SIGHUP (section 5): it generates a new pair and
logs the new fingerprint. Pin the new certificate in every client; clients that still pin the old one fail to connect
until they are updated. The container image has no shell to delete them with: copy a new pair into the volume
instead ([`deploy-docker.md`](deploy-docker.md#6-running-it)).

## 3. Client certificates (mTLS)

`--http-auth-mode=mtls` and `--http-auth-mode=token+mtls` authenticate validator clients with a certificate. They need
TLS (section 1) and at least one way to check client certificates; without them the start is refused as a usage
error. Every connection must then present an accepted certificate during the handshake, for every route, `/upcheck`
and `/healthcheck` included, so health probes need a client certificate too.

| Check | Flag | Accepts |
|---|---|---|
| Fingerprint | `--tls-known-clients-file` | a certificate whose SHA-256 fingerprint the file lists |
| CA | `--tls-client-ca-file` | a certificate that chains to one of the PEM CAs in the file and allows client authentication |

The known-clients file has Web3Signer's format: one `<label> <fingerprint>` per line, where the label is free text for
the operator (Web3Signer writes the client's host) and the fingerprint is the SHA-256 of the DER certificate in hex,
with or without colons, in either case. Blank lines and lines starting with `#` are skipped.

```
# /etc/remotesigner/known-clients
vc-1 DF:65:B8:02:08:5E:91:82:0F:91:F5:1C:96:56:92:C4:1A:F6:C6:27:FD:6C:FC:31:F2:BB:90:17:22:59:5B:50
vc-2 a8:90:93:1c:1d:5b:d8:51:7c:18:24:1b:77:61:68:7e:a0:13:3d:92:f0:5f:6e:25:4f:70:17:76:c8:a6:4e:2b
```

```
openssl x509 -in vc-1.crt -noout -fingerprint -sha256      # the fingerprint to list
```

A fingerprint pins the exact certificate: its dates and issuer are not checked, so replacing an expired client
certificate means listing the new fingerprint. In CA mode the certificate's chain, dates and client-authentication
usage are checked against `--tls-client-ca-file` **only**: the system roots never vouch for a client, so a
certificate from a public CA is refused unless that CA is in the file. When both files are given, either check is
enough.

The client check runs on every handshake, a resumed TLS session included, and again on every request against the trust
in force at that moment. A client removed from either file by a reload (section 5) can neither open a new connection
nor resume its session, and its open connections get 401 `UNAUTHENTICATED` from their next request, on every route,
`/upcheck` and `/healthcheck` included, and that 401 closes the connection. This holds for the last client too: a
reload of a known-clients file that lists nobody, or of a CA file without a certificate, trusts nobody. At startup
such a file refuses the start instead, as a mistake.

The validator client presents its certificate with `--validators-external-signer-tls-client-cert-file` and
`--validators-external-signer-tls-client-key-file`.

## 4. Scopes in the mTLS modes

A client certificate grants the **sign** scope only, never **admin**. Admin routes (`POST /reload`,
`DELETE …/randao_state/…`, the keymanager) need the admin token in every mode:

| `--http-auth-mode` | Sign routes | Admin routes |
|---|---|---|
| `token` (default) | sign token | admin token |
| `mtls` | client certificate | client certificate and admin token; the certificate alone gets 403 `FORBIDDEN_SCOPE` |
| `token+mtls` | client certificate **and** sign token | client certificate **and** admin token; the sign token gets 403 `FORBIDDEN_SCOPE` |
| `none` (loopback only) | open | admin token |

In `mtls` no sign token exists and none is generated; the admin token is still generated into `<data-path>` when
missing. A validator client in `token+mtls` gets both the certificate flags and
`--validators-external-signer-auth-token-file`.

## 5. Rotating tokens and certificates with SIGHUP

`kill -HUP <pid>` re-reads, without dropping connections:

- the sign, admin and metrics token files; a missing file is generated again (`0600`);
- the certificate (PEM files or the PKCS#12 keystore and its password file), or, with `--tls-generate-self-signed`,
  `<data-path>/tls/`, generating a new pair when both files were deleted;
- the known-clients file and the client CA file.

The tokens, the certificate and the client trust reload independently, and fail differently:

- **Tokens and the certificate keep the previous set.** An invalid token, two equal tokens, a broken key, or a token
  or key file that its group or other users can read under `--strict-file-permissions` is logged as an ERROR, and the
  previous tokens or certificate stay in force, so a mistake never leaves the signer without credentials. The token
  files are secret files at startup too: under the strict policy one that others can read refuses the start, and
  with `--strict-file-permissions=false` it is loaded with a WARN that names it.
- **The client trust fails closed.** If the known-clients file or the client CA file cannot be read or does not parse
  (deleted, a line that is not `<label> <fingerprint>`, a broken certificate), the signer logs an ERROR and refuses
  every client certificate, on new handshakes and on open connections, until a reload succeeds. Keeping the previous
  trust would keep the client the edit was meant to revoke. Fix the file and send SIGHUP again.

Handshakes that start after a reload use the new certificate and client trust; established connections keep the
certificate they negotiated, and their requests are checked against the new trust. The log confirms each reload with
the new fingerprint, or names what failed:

```
level=info msg="Token files reloaded"
level=info msg="TLS files reloaded" client-auth=known-clients known-clients=2 sha256-fingerprint="…" source=pem
level=error msg="Reloading the TLS client trust failed; every client certificate is refused, on open connections too,
  until a reload succeeds" client-auth=refused error="--tls-known-clients-file: open …: no such file or directory" …
```

To revoke a client, remove its line from the known-clients file (or its CA from the CA file) and send SIGHUP; this
works for the last client too, which leaves a trust that accepts nobody and logs a WARN saying so.

To rotate a token, write a new one (`0x` and at least 64 hex characters) into its file, or delete the file, and send
SIGHUP; then give the new sign token to the validator clients. The old token stops working at once, so update the
clients right after the reload. To rotate a certificate, replace the files in place (write the new ones next to them
and rename them over the old ones) and send SIGHUP. With the container image, the files in `/data` are replaced with
`docker cp`, owned by the image's user ([`deploy-docker.md`](deploy-docker.md#6-running-it)).

## 6. Listening beyond loopback

A non-loopback `--http-listen-host` refuses to start (exit code 1) when:

| Refused | Fix |
|---|---|
| `--http-auth-mode=none` | use `token`, `mtls` or `token+mtls` |
| `--http-auth-mode=token` over plaintext HTTP | configure TLS (section 1); `--Xallow-plaintext-token-auth` accepts the risk instead and is never set by the shipped image |
| `--http-host-allowlist` with loopback names only | add the names clients use |
| `--slashing-protection-enabled=false` | none: protection can be disabled only when every listener is loopback |
| GVR to be pinned on first use, genesis time unknown | pass them, or accept the risk with the matching `--Xallow-…` flag ([`../reference/flags.md`](../reference/flags.md#what-each-override-accepts)) |
| a non-loopback metrics listener with a loopback-only `--metrics-host-allowlist` | add the name Prometheus scrapes with |

TLS lifts only the plaintext-token refusal; every other one still applies. All applicable refusals are reported
together.

## 7. The metrics token

`--metrics-auth-token-file` makes the metrics listener require `Authorization: Bearer <token>` on `GET /metrics`; a
scrape without it, or with another token, gets 401 `UNAUTHENTICATED`. The file is generated (`0600`) when missing and
re-read on SIGHUP, like the API tokens, and its token must differ from the sign and admin tokens, which never grant
access to the metrics. Without the flag `/metrics` is open to any client that passes the host allowlist.

The metrics listener has no TLS, so the token crosses the network in clear when `--metrics-host` is not loopback.
The signer starts all the same, since the token grants nothing but `GET /metrics`, and logs a warning:

```
level=warning msg="The metrics listener has no TLS, so every scrape sends the metrics token in clear on a non-loopback --metrics-host; keep the listener on a network only Prometheus can reach" metrics-host=0.0.0.0
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: remotesigner
    authorization:
      credentials_file: /etc/prometheus/remotesigner-metrics-token
    static_configs:
      - targets: ["signer.internal:9001"]
```

The metrics listener has no TLS, so the token travels in clear: keep the listener on loopback or on a network only
Prometheus can reach.

## 8. Process hygiene (Linux)

At startup, before any key or token is read, the signer hardens its process. These controls act on Linux only; on
other platforms the flags have no effect (`--mlock-all` logs a WARN there).

| Flag | Default | Effect |
|---|---|---|
| `--disable-core-dumps` | `true` | `prctl(PR_SET_DUMPABLE, 0)`: no core dumps, and other processes of the same user can neither attach a debugger nor read the signer's memory through `/proc`. `RLIMIT_CORE` is set to 0, soft and hard. |
| `--mlock-all` | `false` | `mlockall(MCL_CURRENT \| MCL_FUTURE)`: no page of the process, keys included, is ever written to swap. Needs `CAP_IPC_LOCK` or an unlimited `RLIMIT_MEMLOCK`; with neither, or when the call fails, the start is refused. |

A finite `RLIMIT_MEMLOCK` is refused even when it is larger than the process at startup: `MCL_FUTURE` locks every
later allocation too, so the limit would run out once the heap grows (a burst of requests, a keystore reload) and the
process would die with a Go runtime `out of memory` error. Either lift the limit (`docker run --ulimit memlock=-1`,
`LimitMEMLOCK=infinity` in systemd), or grant the capability: `AmbientCapabilities=CAP_IPC_LOCK` in systemd, or
`docker run --cap-add IPC_LOCK` for a container that runs as root (a non-root container user does not get the added
capability in its effective set). In a rootless container the kernel does not let the capability lift the limit, so
lift the limit there.

The startup log records the result:

```
level=info msg="Process hygiene applied" core-dumps-disabled=true core-limit=0 dumpable=false memory-locked=false
```

A non-dumpable process's `/proc/<pid>` files belong to root, so tools that read them as the signer's user (some
process exporters) see less. Run with `--disable-core-dumps=false` only to debug the signer itself.
