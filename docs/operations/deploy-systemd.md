# Deploying with systemd

This page installs remotesigner on a Linux host as a hardened systemd service, with the unit in
[`deploy/systemd/remotesigner.service`](../../deploy/systemd/remotesigner.service) and the configuration in
[`deploy/config/single-host.yaml`](../../deploy/config/single-host.yaml): one signer with its bbolt
slashing-protection store, serving validator clients on the local network over TLS. Every flag is in
[`../reference/flags.md`](../reference/flags.md); to run the container image instead, see
[`deploy-docker.md`](deploy-docker.md).

## 1. Install the binary

Download the archive for your platform from the release page and check it
([`release.md`](release.md#3-verifying-a-release)). `remotesigner-consensus` is the consensus-only flavour;
`remotesigner` behaves the same for everything on this page. Besides the binary, the archive holds this release's
unit and example configuration, `deploy/systemd/remotesigner.service` and `deploy/config/single-host.yaml`, which
sections 3 and 4 install, and `README.md`, `LICENSE`, the flavour's `NOTICE`, `LICENSES/` and
`third_party_licenses/`. Extract it and work in its directory. The unit runs `/usr/local/bin/remotesigner`, so install
the flavour you chose under that name:

<!-- systemd-smoke:archive -->
```
tar -xzf remotesigner-consensus_<version>_linux_amd64.tar.gz
cd remotesigner-consensus_<version>_linux_amd64
sudo install -m 0755 remotesigner-consensus /usr/local/bin/remotesigner
remotesigner --version
```

The commands of sections 2 to 4 run in this directory. Put the files they install there, next to `deploy/`: the key
files of section 2 (`key-0.yaml`, or the deposit CLI's `validator_keys/` and `keystores-password.txt`) and the
chain's `config.yaml` (section 3). Install the unit and the configuration of the release whose binary you install:
the binary refuses a configuration key it does not know, and a newer release's example may have one.

To build from source instead, check out the release's tag (`git clone --branch v<version>
https://github.com/rgeraldes24/go-remotesigner`), run `make build-consensus`, install `bin/remotesigner-consensus` as
`/usr/local/bin/remotesigner`, and run sections 2 to 4 in the checkout, which has the same `deploy/` files.

## 2. User, directories and keys

The service runs as its own system user, which owns the state directory and nothing else. A key is the validator's
48-byte ML-DSA-87 wallet seed, the one qrysm derives its key pair from; give the signer each key as a key-config file
in `/var/lib/remotesigner/keys/` (every non-hidden `*.yaml` or `*.yml` file there is loaded, and a file may hold
several documents separated by `---`):

```yaml
# key-0.yaml: one validator's seed, in the clear; readable by the service user only
type: file-raw
keyType: ML_DSA_87
privateKey: "0x<96 hex characters>"
```

Create the user and the directories, and install the key files:

<!-- systemd-smoke -->
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
| `/var/lib/remotesigner/keys/` | remotesigner, `0700`, files `0600` | one key-config file per key |
| `/var/lib/remotesigner/keystores/`, `keystores-password.txt` | remotesigner, `0700`, files `0600` | keystores and their password, instead of key-config files or next to them (below) |

A key-config file with a seed, and a password file, that its group or other users can read is refused
(`--strict-file-permissions`, [`reload.md`](reload.md#secret-files)). Back up `/var/lib/remotesigner`; losing
`slashing-protection.db` loses the slashing-protection history.

**Keystores, instead of seeds or next to them.** Keystores from the deposit CLI or qrysm's `validator accounts
backup` go into a keystore directory of their own (copy the `keystore-*.json` files, and only them: every `*.json`
file there is loaded), with the password they were created with in a file next to it:

<!-- systemd-smoke -->
```
sudo install -d -m 0700 -o remotesigner -g remotesigner /var/lib/remotesigner/keystores
sudo install -m 0600 -o remotesigner -g remotesigner validator_keys/keystore-*.json /var/lib/remotesigner/keystores/
sudo install -m 0600 -o remotesigner -g remotesigner keystores-password.txt /var/lib/remotesigner/
sudo -u remotesigner remotesigner consensus keystore verify --keystores-path=/var/lib/remotesigner/keystores \
  --keystores-password-file=/var/lib/remotesigner/keystores-password.txt
```

The last command decrypts every keystore as the signer will and prints each key's identifier
([`keystores.md`](keystores.md#4-checking-keystores)). Section 3 adds the directory to the configuration.

A key-config file can also name one keystore and its password file (`type: file-keystore`,
[`reload.md`](reload.md#1-key-sources)). Decrypting a standard-KDF keystore takes about 1.5 s of one core and up to
512 MiB; the signer runs as many at once as the memory limit allows, which is half of the RAM unless the unit sets
one (`MemoryMax=` in a drop-in, section 6; [`reload.md`](reload.md#6-memory-for-keystore-decryption)).

## 3. Configuration

<!-- systemd-smoke -->
```
sudo install -d -m 0755 /etc/remotesigner
sudo install -m 0644 deploy/config/single-host.yaml /etc/remotesigner/remotesigner.yaml
sudo install -m 0644 config.yaml /etc/remotesigner/network.yaml
```

`config.yaml` is the chain's qrysm-format config file, which the network publishes with its genesis time and genesis
validators root. Only Testnet V3 and test networks of the same stack are supported
([`requirements.md`](requirements.md#1-testnet-v3-only-testnet-v2-is-unsupported)). Edit
`/etc/remotesigner/remotesigner.yaml` before the first start:

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

With keystores (section 2), add their directory to the `consensus:` section, which ends the example file:

<!-- systemd-smoke -->
```
sudo tee -a /etc/remotesigner/remotesigner.yaml >/dev/null <<'EOF'
  keystores-path: /var/lib/remotesigner/keystores
  keystores-password-file: /var/lib/remotesigner/keystores-password.txt
EOF
```

The signer loads the key-config files of `key-config-path` and the keystores together; with keystores only, leave
`/var/lib/remotesigner/keys/` empty.

## 4. Start

<!-- systemd-smoke -->
```
sudo install -m 0644 deploy/systemd/remotesigner.service /etc/systemd/system/
sudo systemd-analyze verify /etc/systemd/system/remotesigner.service
sudo systemctl daemon-reload
sudo systemctl enable --now remotesigner
```

Follow the log with `sudo journalctl -u remotesigner -f` (without `sudo`, only members of the `adm` or
`systemd-journal` group see the service's log). The first start generates the tokens and the certificate and logs
the certificate's fingerprint:

<!-- systemd-smoke:fingerprint -->
```
sudo journalctl -u remotesigner | grep -o 'sha256-fingerprint="[^"]*"'
```

The signer listens at once and loads the keys in the background: `/upcheck` answers `503` until they are loaded and
the store is open, then `200 OK`. Check it from the host. The certificate is valid for the allowlist names only, so
connect by one of them; `--resolve` points the name at this host, whether or not it resolves here. The files are
readable by root and the service user only:

<!-- systemd-smoke:check -->
```
sudo curl --resolve signer.internal:9000:127.0.0.1 --cacert /var/lib/remotesigner/tls/cert.pem \
  https://signer.internal:9000/upcheck
sudo sh -c 'curl -s --resolve signer.internal:9000:127.0.0.1 --cacert /var/lib/remotesigner/tls/cert.pem \
  -H "Authorization: Bearer $(cat /var/lib/remotesigner/auth-token)" \
  https://signer.internal:9000/api/v1/consensus/publicKeys'
```

The first prints `OK`, the second the loaded public keys. `make systemd-smoke` runs the commands of sections 1 to 4
and 6 as they are written here (section 7).

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
validator client the admin token. Deploy the signer on the same local network as its validator clients
([`requirements.md`](requirements.md#4-deploy-signers-next-to-their-validator-clients)).

## 6. Operations

| Task | Command |
|---|---|
| Reload the tokens, the TLS certificate and the client trust files (SIGHUP) | `sudo systemctl reload remotesigner` |
| Reload the key-config files and keystores | `POST /reload` with the admin token (below; [`reload.md`](reload.md#3-reload)) |
| Rotate a token | write the new token into its file (or delete it to have one generated), then reload ([`tls.md`](tls.md#5-rotating-tokens-and-certificates-with-sighup)) |
| Stop | `sudo systemctl stop remotesigner`: SIGTERM; in-flight requests finish within 10 s, the store is closed and the keys wiped; the unit allows 30 s |
| Back up the store | stop the service, then copy `/var/lib/remotesigner` |
| Upgrade | install the new binary, stop the service, run the new binary's `consensus migrate` as the service user, start the service ([`upgrade.md`](upgrade.md#3-one-signer)) |
| Change a setting without editing the unit | `sudo systemctl edit remotesigner` (a drop-in); for example `LimitMEMLOCK=infinity` for `--mlock-all`, or `MemoryMax=4G` to size keystore decryption |

After adding or removing key files or keystores, reload them, by an allowlist name as in section 4 and with the
admin token. It answers `202 {"code":202,"message":"reload started"}`; `GET /reload` with the sign token reports
its progress:

<!-- systemd-smoke:reload -->
```
sudo sh -c 'curl -s --resolve signer.internal:9000:127.0.0.1 --cacert /var/lib/remotesigner/tls/cert.pem -X POST \
  -H "Authorization: Bearer $(cat /var/lib/remotesigner/admin-token)" -H "Content-Type: application/json" \
  https://signer.internal:9000/reload'
```

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

`make systemd-smoke` runs this page's installation in a container that runs systemd, as an unprivileged user with
`sudo` rights and no access to the journal of its own: a release archive laid out as the release's (the binary and
the repository's `deploy/` files), a key file, a deposit CLI keystore with its password file and a network file are
put in place, and then the commands of sections 1 to 4 run exactly as written (the blocks marked for it in this
page's source), from extracting the archive on. The host name `signer.internal` resolves nowhere in the container.
It checks that the unit serves TLS, `/upcheck` and `publicKeys` with both keys, writes its files `0600`/`0700` as the
service user, logs the fingerprint section 4 reads, reloads its TLS files and, with section 6's command, its keys,
runs the upgrade steps of [`upgrade.md`](upgrade.md#3-one-signer) as written there, and stops with exit code 0. CI
runs it on every pull request.

## 8. More than one signer: Postgres

[`deploy/config/postgres-ha.yaml`](../../deploy/config/postgres-ha.yaml) is the configuration for two or more signers
that serve the same keys behind one name and share a Postgres slashing-protection database, each replica with the same
file, keys, token files and certificate. [`postgres.md`](postgres.md) sets up the database and its roles, creates the
schema with `consensus migrate`, and describes the connection profile and what replicas share. Without Postgres, run
exactly one signer per set of keys.
