# Deploying with systemd

This page installs remotesigner on a Linux host as a hardened systemd service, with the unit in
[`deploy/systemd/remotesigner.service`](../../deploy/systemd/remotesigner.service) and the configuration in
[`deploy/config/single-host.yaml`](../../deploy/config/single-host.yaml): one signer with its bbolt
slashing-protection store, serving validator clients on the local network over TLS. Every flag is in
[`../reference/flags.md`](../reference/flags.md); to run the container image instead, see
[`deploy-docker.md`](deploy-docker.md).

## 1. Install the binary

Download the archive for your platform from the release page, check it ([`release.md`](release.md#3-verifying-a-release)),
and install its binary. `remotesigner-consensus` is the consensus-only flavour; `remotesigner` behaves the same for
everything on this page. The unit runs `/usr/local/bin/remotesigner`, so install the flavour you chose under that name:

```
tar -xzf remotesigner-consensus_<version>_linux_amd64.tar.gz
sudo install -m 0755 remotesigner-consensus_<version>_linux_amd64/remotesigner-consensus /usr/local/bin/remotesigner
remotesigner --version
```

The archive also holds `LICENSE`, the flavour's `NOTICE`, `LICENSES/` and `third_party_licenses/`. To build from
source instead: `make build-consensus` and install `bin/remotesigner-consensus`.

## 2. User, directories and keys

The service runs as its own system user, which owns the state directory and nothing else:

```
sudo useradd --system --no-create-home --shell /usr/sbin/nologin remotesigner
sudo install -d -m 0700 -o remotesigner -g remotesigner /var/lib/remotesigner /var/lib/remotesigner/keys
sudo install -m 0600 -o remotesigner -g remotesigner key-0.yaml /var/lib/remotesigner/keys/
```

| Path | Owner, mode | Content |
|---|---|---|
| `/etc/remotesigner/remotesigner.yaml` | root, `0644` | the configuration (section 3) |
| `/etc/remotesigner/network.yaml` | root, `0644` | the chain's qrysm-format config |
| `/var/lib/remotesigner/` | remotesigner, `0700` | written by the signer: `auth-token`, `admin-token`, `tls/`, `slashing-protection.db`, `remotesigner.ports` |
| `/var/lib/remotesigner/keys/` | remotesigner, `0700`, files `0600` | one `file-raw` key-config file per key ([`quickstart.md`](quickstart.md#2-key-files)) |

The key files hold the seeds: keep them readable by the service user only. Back up `/var/lib/remotesigner`;
losing `slashing-protection.db` loses the slashing-protection history.

## 3. Configuration

```
sudo install -d -m 0755 /etc/remotesigner
sudo install -m 0644 deploy/config/single-host.yaml /etc/remotesigner/remotesigner.yaml
sudo install -m 0644 config.yaml /etc/remotesigner/network.yaml
```

Edit `/etc/remotesigner/remotesigner.yaml` before the first start:

| Key | Set it to |
|---|---|
| `http-host-allowlist` | the names and addresses validator clients connect with. The generated certificate is valid for exactly these, so set them first. |
| `consensus.network-genesis-time`, `consensus.network-genesis-validators-root` | your chain's values. A non-loopback listener refuses to start without them. |
| `metrics-*` | where Prometheus scrapes; the example keeps the listener on `127.0.0.1:9001`. |

The file binds the API to every interface over TLS 1.3, with a certificate generated into
`/var/lib/remotesigner/tls/` on first start. To serve your own certificate, set `tls-cert-file` and `tls-key-file`
(files the service user can read) and drop `tls-generate-self-signed`. Unknown keys are refused, so a typo fails the
start (exit code 2) instead of falling back to a default. The file never sets `Xallow-*` overrides; do not add
them.

## 4. Start

```
sudo install -m 0644 deploy/systemd/remotesigner.service /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/remotesigner.service
sudo systemctl daemon-reload
sudo systemctl enable --now remotesigner
journalctl -u remotesigner -f
```

The first start generates the tokens and the certificate and logs the certificate's fingerprint:

```
journalctl -u remotesigner | grep -o 'sha256-fingerprint="[^"]*"'
```

Check it from the host, by one of the allowlist names (the files are readable by root and the service user only):

```
sudo curl --cacert /var/lib/remotesigner/tls/cert.pem https://signer.internal:9000/upcheck
sudo sh -c 'curl -s --cacert /var/lib/remotesigner/tls/cert.pem \
  -H "Authorization: Bearer $(cat /var/lib/remotesigner/auth-token)" \
  https://signer.internal:9000/api/v1/consensus/publicKeys'
```

## 5. Connect the validator client

Copy `/var/lib/remotesigner/tls/cert.pem` and `/var/lib/remotesigner/auth-token` to the validator client's host over a
channel you trust, check the certificate's fingerprint against the log (`openssl x509 -in cert.pem -noout
-fingerprint -sha256`), and start the client with:

```
validator … \
  --validators-external-signer-url=https://signer.internal:9000 \
  --validators-external-signer-tls-ca-file=/etc/qrysm/signer-cert.pem \
  --validators-external-signer-auth-token-file=/etc/qrysm/signer-auth-token \
  --validators-external-signer-key-file=/etc/qrysm/remote-keys.txt
```

`remote-keys.txt` lists the validator public keys this client validates with, one `0x` key per line. Never give a
validator client the admin token. Deploy the signer on the same local network as its validator clients.

## 6. Operations

| Task | Command |
|---|---|
| Reload the tokens, the TLS certificate and the client trust files (SIGHUP) | `sudo systemctl reload remotesigner` |
| Reload the key-config files | `POST /reload` with the admin token ([`quickstart.md`](quickstart.md#5-check-it)) |
| Rotate a token | write the new token into its file (or delete it to have one generated), then reload ([`tls.md`](tls.md#5-rotating-tokens-and-certificates-with-sighup)) |
| Stop | `sudo systemctl stop remotesigner`: SIGTERM; in-flight requests finish within 10 s, the store is closed and the keys wiped; the unit allows 30 s |
| Back up the store | stop the service, then copy `/var/lib/remotesigner` |
| Upgrade | install the new binary, then `sudo systemctl restart remotesigner` |
| Change a setting without editing the unit | `sudo systemctl edit remotesigner` (a drop-in); for example `LimitMEMLOCK=infinity` for `--mlock-all` |

The unit restarts the signer after a failure, except after exit code 2 (a usage error: a bad flag or config file),
which a restart does not fix. Exit code 1 is a startup refusal or a failure; its log line names the cause.

## 7. What the unit restricts

The signer needs no privileges: it reads its configuration and keys, writes its state directory, and listens on TCP.
The unit takes everything else away; `systemd-analyze security remotesigner` rates it about 1.4 ("OK").

| Directives | Effect |
|---|---|
| `User=remotesigner`, `NoNewPrivileges`, empty `CapabilityBoundingSet` and `AmbientCapabilities` | an unprivileged process that cannot gain privileges or capabilities |
| `StateDirectory=remotesigner`, `StateDirectoryMode=0700`, `UMask=0077` | `/var/lib/remotesigner` is created owned by the service user and closed to others, and every file the signer writes is too |
| `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices` | the file system is read-only except the state directory; no home directories, no shared `/tmp`, no devices. A token or certificate file configured outside `/var/lib/remotesigner` must therefore exist before the start: the signer cannot generate it there. |
| `LimitCORE=0` | no core dumps (the signer also makes itself non-dumpable, [`tls.md`](tls.md#8-process-hygiene-linux)) |
| `ProtectKernel*`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible`, `KeyringMode=private` | no access to kernel settings, other processes or the host's identity |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`, `RemoveIPC` | IP and Unix sockets only; no namespaces, real-time scheduling, set-id files or writable executable memory |
| `SystemCallArchitectures=native`, `SystemCallFilter=@system-service` and `~@privileged` | only the system calls of an ordinary service |

`make systemd-smoke` runs this page's installation in a container that runs systemd, and checks that the unit serves
TLS, `/upcheck` and `publicKeys`, writes its files `0600`/`0700` as the service user, reloads, and stops with exit
code 0. CI runs it on every pull request.

## 8. More than one signer: Postgres

[`deploy/config/postgres-ha.yaml`](../../deploy/config/postgres-ha.yaml) is the configuration for two or more signers
that serve the same keys behind one name and share a Postgres slashing-protection database, each replica with the same
file, keys, token files and certificate. [`postgres.md`](postgres.md) sets up the database and its roles, creates the
schema with `consensus migrate`, and describes the connection profile and what replicas share. Without Postgres, run
exactly one signer per set of keys.
