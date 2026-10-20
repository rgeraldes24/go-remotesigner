# Deploying with Docker

This page runs remotesigner from its container image: what the image contains, what its entrypoint sets and what it
leaves to you, the first start and pinning the generated certificate, and the compose example with a qrysm validator
client. Every flag is in [`../reference/flags.md`](../reference/flags.md); TLS and tokens are covered in depth in
[`tls.md`](tls.md). To run the binary directly under systemd instead, see [`deploy-systemd.md`](deploy-systemd.md).

## 1. The images

| Image | Flavour |
|---|---|
| `ghcr.io/rgeraldes24/remotesigner-consensus` | Consensus only (`-tags noexecution`); links permissively licensed code only. Use this one unless you need execution mode. |
| `ghcr.io/rgeraldes24/remotesigner` | The default flavour, with execution mode, which links the go-qrl library (LGPL-3.0-or-later; [`execution.md`](execution.md#11-go-qrl-and-the-lgpl)). It behaves the same for everything on this page. |

Each release is tagged with its version (`1.0.0`, without the `v`) and, unless it is a pre-release, `latest`, for
`linux/amd64` and `linux/arm64`. Pin a version, or better its digest, in production. How to check an image's
signature, SBOM and provenance is in [`release.md`](release.md#3-verifying-a-release).

| Path | Content |
|---|---|
| `/usr/local/bin/remotesigner` | the static binary, the image's only program: there is no shell |
| `/usr/share/doc/remotesigner/` | `LICENSE`, the flavour's `NOTICE`, `LICENSES/`, `third_party_licenses/`, `README.md`, and the example configuration files and systemd unit in `deploy/`, as in the release archives ([`release.md`](release.md#1-what-a-release-contains)) |
| `/data` | empty, owned by `65532:65532`, mode `0700`: mount a volume here |

The base is distroless `static-debian13:nonroot`, pinned by digest. The image runs as its `nonroot` user
(`65532:65532`), and the only path it writes is `/data`, so it runs with a read-only root file system and no
capabilities. The OCI labels name the flavour (`org.opencontainers.image.title`), the licences its binary links
(`org.opencontainers.image.licenses`), the version and the source revision.

## 2. The entrypoint

```
ENTRYPOINT ["/usr/local/bin/remotesigner", "--data-path=/data", "--http-listen-host=0.0.0.0", "--tls-generate-self-signed"]
CMD ["consensus"]
```

| Set by the image | Effect |
|---|---|
| `--data-path=/data` | The sign and admin tokens are generated into `/data/auth-token` and `/data/admin-token` (mode `0600`) on first start; the bbolt slashing-protection store is `/data/slashing-protection.db`. |
| `--http-listen-host=0.0.0.0` | The API listens on every interface of the container, port 9000. Every non-loopback fail-safe applies. |
| `--tls-generate-self-signed` | The API serves TLS 1.3. Without a configured certificate the first start writes one to `/data/tls/` for the `--http-host-allowlist` names and logs its fingerprint (section 4). |

The image never sets `--Xallow-plaintext-token-auth`, so the sign token never travels over plaintext HTTP. The
metrics listener stays off unless you enable it (section 7).

**What you pass.** Arguments to `docker run` (or a compose `command`) replace `CMD`, so they name the `consensus`
subcommand themselves. Global flags, such as the host allowlist, go before `consensus`; consensus flags, such as the
network and the keystore directory, after it:

```
--http-host-allowlist=signer \
  consensus --network=/network/config.yaml --network-genesis-time=<unix seconds> --network-genesis-validators-root=0x<64 hex> \
  --keystores-path=/keys/keystores --keystores-password-file=/keys/password.txt
```

| You must pass | Without it |
|---|---|
| `--http-host-allowlist` with the names clients connect with (a compose service name, a DNS name, an address) | exit 1: a non-loopback listener with the default, loopback-only allowlist is refused |
| `consensus --network=…` | exit 2: `--network` has no default |
| `--network-genesis-time` and `--network-genesis-validators-root`, or `--network-genesis-state` | exit 1: a non-loopback listener refuses an unknown genesis time and a validators root pinned on first use |

The allowlist names are also the names the generated certificate is valid for, so set them before the first start.
A wildcard allowlist (`*`) names no host and is refused. Running the image with no arguments at all prints the
`--network` usage error and exits 2.

To override something the entrypoint sets, pass the flag again: the last value wins. `--tls-generate-self-signed=false`
with no certificate configured makes the signer refuse to start (exit 1), because token authentication would then run
over plaintext.

## 3. Volumes and keys

| Mount | Mode | Content |
|---|---|---|
| a named volume at `/data` | read-write | tokens, the TLS certificate and key, the slashing-protection store, the ports file. Keep it and back it up: losing the store loses the slashing-protection history. |
| your keys at, for example, `/keys` | read-only | a keystore directory and its password file (below), given after `consensus` with `--keystores-path=/keys/keystores --keystores-password-file=/keys/password.txt`; or key-config files (`file-raw` seeds, `file-keystore` documents, [`reload.md`](reload.md#1-key-sources)), given before `consensus` with `--key-config-path=/keys` |
| the network config at, for example, `/network` | read-only | the chain's qrysm-format config YAML |

**Prepare the keys.** The deposit CLI writes one keystore per validator, `keystore-m_12381_238_<i>_0-<time>.json`, all
under the password you gave it; qrysm's `validator accounts backup` writes keystores too
([`keystores.md`](keystores.md#5-from-a-qrysm-wallet)). Copy the keystores, and only them, into `keys/keystores/`
(every `*.json` file there is loaded, and a `deposit_data-*.json` would fail), and write the password into
`keys/password.txt`. The container runs as uid 65532, which must be able to read the files, and only it: a password
file that its group or other users can read is refused (`--strict-file-permissions`,
[`reload.md`](reload.md#secret-files)). On Linux:

```
mkdir -p keys/keystores network
cp validator_keys/keystore-*.json keys/keystores/
$EDITOR keys/password.txt                       # the keystores' password, on one line
cp config.yaml network/config.yaml              # the chain's qrysm-format config
chmod 0700 keys keys/keystores && chmod 0600 keys/password.txt keys/keystores/*
sudo chown -R 65532:65532 keys
```

**The chain.** The signer needs the chain's qrysm-format config file, its genesis time and its genesis validators
root, which the network publishes; its `genesis.ssz` gives the last two (`--network-genesis-state=/network/genesis.ssz`
in place of the two flags). Only Testnet V3 and test networks of the same stack are supported
([`requirements.md`](requirements.md#1-testnet-v3-only-testnet-v2-is-unsupported)).

Check the keys with the image before the first start; it decrypts every keystore as the signer will and prints each
key's identifier ([`keystores.md`](keystores.md#4-checking-keystores)):

```
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges -v "$PWD/keys:/keys:ro" \
  ghcr.io/rgeraldes24/remotesigner-consensus:<version> \
  consensus keystore verify --keystores-path=/keys/keystores --keystores-password-file=/keys/password.txt
```

It ends with a summary such as `4 keystores: 4 OK, 0 refused`, and exits 1 naming each refusal otherwise. A
standard-KDF keystore takes about 1.5 s of one core and up to 512 MiB of memory to decrypt; the signer runs as many
at once as its memory limit allows ([`reload.md`](reload.md#6-memory-for-keystore-decryption)), so give the container
a memory limit (`--memory`, compose `mem_limit`).

A new named volume mounted at `/data` takes the image's owner and mode (`65532:65532`, `0700`). A bind mount does not:
make the host directory owned by `65532:65532` with mode `0700` yourself, or the signer cannot write its files.
Never mount one `/data` volume into two running signers: the bbolt store allows one process.

Run it hardened, on a user-defined network that the validator client's container joins to reach
`https://signer:9000`:

<!-- docker-smoke:run -->
```
docker network create signer-net
docker volume create signer-data
docker run -d --name signer --network signer-net --network-alias signer \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges --memory=2g --stop-timeout=30 \
  -v signer-data:/data -v "$PWD/keys:/keys:ro" -v "$PWD/network:/network:ro" \
  ghcr.io/rgeraldes24/remotesigner-consensus:<version> \
  --http-host-allowlist=signer \
  consensus --network=/network/config.yaml \
  --network-genesis-time=1760000000 \
  --network-genesis-validators-root=0x9471e8fb19e0faae953e9d46889f207192bcec9b14293d7ba418ae4dc5e3ac8f \
  --keystores-path=/keys/keystores --keystores-password-file=/keys/password.txt
docker logs -f signer
```

`make docker-smoke` runs this command, with the same mounts, flags and key layout, on every pull request (section 8).
`/upcheck` answers `503` while the keys load, then `200 OK`; the log line `Keys loaded` then reports the keys loaded
(`loaded=`) and the sources that failed (`errors=`), each failure logged at ERROR before it. Publish the API port (`-p 9000:9000`) only if validator clients outside Docker connect to it, and
then add the name or address they use to `--http-host-allowlist`.

**With the keymanager API** (`--key-manager-api-enabled`, [`keymanager.md`](keymanager.md)), the signer writes the
keys it imports to `--key-config-path`, which must then be writable: give `--key-config-path=/data/keys` before
`consensus`, and the signer creates the directory, mode `0700`, in its data volume.

## 4. First start: pin the certificate

On first start the signer writes `/data/tls/cert.pem` and `key.pem` and logs the certificate's SHA-256 fingerprint:

```
docker logs signer 2>&1 | grep -o 'sha256-fingerprint="[^"]*"'
```

Later starts reuse the pair; it is never regenerated while `cert.pem` exists. Give the validator client the
certificate as its CA file, and the sign token, after checking the fingerprint:

```
mkdir -p validator
docker cp signer:/data/tls/cert.pem validator/signer-cert.pem
docker cp signer:/data/auth-token validator/signer-auth-token
openssl x509 -in validator/signer-cert.pem -noout -fingerprint -sha256    # must match the logged fingerprint
```

The validator client then accepts only this certificate, for the names in the allowlist. Never give it the admin
token, and never mount the signer's `/data` volume into another container: it holds the admin token and the TLS
private key. [`tls.md`](tls.md#2-the-generated-certificate-and-pinning-it) has the details; section 6 rotates the
certificate and the tokens.

Check the signer as a validator client reaches it: from a client container on the signer's network, by its name and
with the copied certificate. `docker cp` wrote the two files with mode `0600`, owned by you, so the client runs as
your user:

<!-- docker-guide:check -->
```
docker run --rm --network signer-net --user "$(id -u):$(id -g)" -v "$PWD/validator:/v:ro" curlimages/curl:8.11.1 \
  -sS --cacert /v/signer-cert.pem https://signer:9000/upcheck
docker run --rm --network signer-net --user "$(id -u):$(id -g)" -v "$PWD/validator:/v:ro" curlimages/curl:8.11.1 \
  -sS --cacert /v/signer-cert.pem -H "Authorization: Bearer $(cat validator/signer-auth-token)" \
  https://signer:9000/api/v1/consensus/publicKeys
```

The first prints `OK` once the keys are loaded (`503` before), the second the loaded public keys.

**Your own certificate.** Put the certificate and its key in a directory of their own that the container's user
(65532) can read, the key readable by it alone, then mount the directory read-only and name the files; a configured
certificate takes precedence and nothing is generated. A key file that 65532 cannot read refuses the start
(`open /tls/signer.key: permission denied`). On Linux:

<!-- docker-guide:own-certificate -->
```
mkdir -p tls && cp signer.crt signer.key tls/
chmod 0700 tls && chmod 0644 tls/signer.crt && chmod 0600 tls/signer.key
sudo chown -R 65532:65532 tls
```

```
-v "$PWD/tls:/tls:ro" … --tls-cert-file=/tls/signer.crt --tls-key-file=/tls/signer.key --http-host-allowlist=signer.example.org …
```

## 5. The compose example

[`deploy/docker/compose.yaml`](../../deploy/docker/compose.yaml) runs one signer and the qrysm validator client that
signs through it. The validator client reaches the signer by its service name, `https://signer:9000`. The signer is
on an internal network only: nothing outside the project can reach it, and it has no route out; the validator client
is also on the default network, to reach its beacon node.

```
deploy/docker/
  compose.yaml
  .env                  GENESIS_TIME, GENESIS_VALIDATORS_ROOT, QRYSM_VALIDATOR_IMAGE, BEACON_RPC_PROVIDER
                        (and REMOTESIGNER_IMAGE to pin a version)
  keys/keystores/       the signer's keystores, prepared as in section 3
  keys/password.txt     their password
  network/config.yaml   the chain's config, read by both containers
  validator/            filled in step 2
```

1. Prepare `keys/` and `network/` as in section 3, then start the signer alone and wait for it to log its
   fingerprint:

   ```
   docker compose up -d signer
   docker compose logs signer | grep -o 'sha256-fingerprint="[^"]*"'
   ```

2. Copy its certificate and sign token for the validator client, compare the fingerprint, and list the validator
   keys the client should use, one `0x` public key per line, for example from your deposit data:

   <!-- docker-guide:compose-copy -->
   ```
   mkdir -p validator
   docker compose cp signer:/data/tls/cert.pem validator/signer-cert.pem
   docker compose cp signer:/data/auth-token validator/signer-auth-token
   openssl x509 -in validator/signer-cert.pem -noout -fingerprint -sha256
   $EDITOR validator/remote-keys.txt
   ```

3. Start the validator client:

   ```
   docker compose up -d validator
   ```

The validator client runs with `--validators-external-signer-url=https://signer:9000`,
`--validators-external-signer-tls-ca-file`, `--validators-external-signer-auth-token-file` and
`--validators-external-signer-key-file` pointing at the files of step 2. A validator key must be listed for exactly one
validator client: two clients signing for the same validator can be slashed. `QRYSM_VALIDATOR_IMAGE` must be a
validator client with these flags, which no qrysm release has yet: build it from the branch
[`requirements.md`](requirements.md#5-a-qrysm-validator-client-with-the-remote-signer-keymanager) names. An image
without them stops with `flag provided but not defined: -validators-external-signer-url`.

## 6. Running it

| Task | Command |
|---|---|
| Logs | `docker logs signer` (text; add `--logging-format=json` before `consensus` for JSON) |
| Reload tokens, the certificate and client trust (SIGHUP) | `docker kill --signal=HUP signer` |
| Reload the keys after adding or removing keystores | `POST /reload` with the admin token, from a client container (below) |
| Rotate the sign or the admin token | copy the new token into `/data`, then SIGHUP (below) |
| Rotate the generated certificate | copy a new pair into `/data/tls`, then SIGHUP, and pin it in every client (below) |
| Stop | `docker stop signer`: SIGTERM; in-flight requests finish within 10 s, then the store is closed and the keys wiped. Allow 30 s (`--stop-timeout=30`, compose `stop_grace_period`). |
| Back up the store | stop the signer, then copy `/data` out with `docker cp` (below) |
| Upgrade | stop the old container, run the new image's `consensus migrate` on the `/data` volume, start the new image with the same volume and arguments ([`upgrade.md`](upgrade.md#3-one-signer)) |

`/upcheck` answers `200 OK` once the keys are loaded and the store is open. The image has no shell, so it has no
Docker `HEALTHCHECK`; probe `/upcheck` from outside, over TLS and pinning the certificate, as section 4's check does.

**Reloading the keys.** The admin token stays in the volume: the command reads it from the container for this one
request (`docker cp … -` writes a tar stream, and `tar -xO` prints its file), and a client container on the signer's
network sends the request with the certificate of section 4. The signer answers `{"code":202,"message":"reload
started"}`, and `GET /reload` with the sign token reports the progress ([`reload.md`](reload.md#3-reload)):

<!-- docker-guide:reload -->
```
docker run --rm --network signer-net --user "$(id -u):$(id -g)" -v "$PWD/validator:/v:ro" curlimages/curl:8.11.1 \
  -sS -X POST --cacert /v/signer-cert.pem -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $(docker cp signer:/data/admin-token - | tar -xOf -)" https://signer:9000/reload
```

**Files in `/data`.** The image has no shell and `/data` is never mounted into another container, so `docker cp`
moves files in and out of the volume. A file copied out keeps its mode, `0600`, and belongs to you. A file copied in
must end up as the signer writes its own, owned by 65532 with mode `0600`: a plain `docker cp` of a file makes root
its owner and keeps its mode on the host, so copy in a tar stream that sets both, with `docker cp --archive`. The
commands use GNU tar, as on Linux:

- **Rotate the sign token.** Write a new one (`0x` and 64 hex characters) as the validator clients' copy, copy it
  into the volume as `auth-token`, and reload. The old token stops working at once, so give the clients the new copy
  right away ([`tls.md`](tls.md#5-rotating-tokens-and-certificates-with-sighup)):

  <!-- docker-guide:rotate-token -->
  ```
  (umask 077; printf '0x%s\n' "$(openssl rand -hex 32)" > validator/signer-auth-token)
  tar -C validator -cf - --owner=65532 --group=65532 --mode=0600 --transform='s/.*/auth-token/' signer-auth-token \
    | docker cp --archive - signer:/data
  docker kill --signal=HUP signer
  ```

  The admin token works the same way, as `admin-token`; keep its copy away from the validator clients. The log line
  `Token files reloaded` confirms the reload.

- **Rotate the generated certificate.** Make a new pair valid for every allowlist name (`DNS:<name>`, or
  `IP:<address>` for an address), copy it over `/data/tls/cert.pem` and `key.pem`, reload, and pin the new
  certificate in every client; clients that still pin the old one fail to connect until they have it. The log line
  `TLS files reloaded` gives the new fingerprint:

  <!-- docker-guide:rotate-certificate -->
  ```
  mkdir -p newtls
  (umask 077; openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj /CN=remotesigner \
    -addext subjectAltName=DNS:signer -keyout newtls/key.pem -out newtls/cert.pem)
  tar -C newtls -cf - --owner=65532 --group=65532 --mode=0600 key.pem cert.pem | docker cp --archive - signer:/data/tls
  docker kill --signal=HUP signer
  cp newtls/cert.pem validator/signer-cert.pem && rm -r newtls
  ```

- **Back up the store.** Stop the signer, copy `/data` out as a tar stream, which keeps every file's owner and mode,
  and start it again. The archive holds the admin token and the TLS key as well as the store: keep it as you keep the
  keys.

  <!-- docker-guide:backup -->
  ```
  docker stop signer
  (umask 077; docker cp signer:/data - > signer-data-$(date +%Y%m%d).tar)
  docker start signer
  ```

  To restore it into a new volume, copy it into a container that is created and never started, then start the
  signer on that volume. Before it signs, close the gap since the backup
  ([`backup.md`](backup.md#3-the-gap-after-an-old-backup)):

  ```
  docker volume create signer-data-restored
  docker create --name signer-restore -v signer-data-restored:/data ghcr.io/rgeraldes24/remotesigner-consensus:<version>
  docker cp --archive - signer-restore:/ < signer-data-<date>.tar
  docker rm signer-restore
  ```

## 7. Metrics and the dashboard

The metrics listener is off by default. To let a Prometheus container on the signer's network scrape it, add before
`consensus`:

```
--metrics-enabled --metrics-host=0.0.0.0 --metrics-host-allowlist=signer --metrics-auth-token-file=/data/metrics-token
```

The metrics listener has no TLS: keep it on an internal network, and use the metrics token
([`tls.md`](tls.md#7-the-metrics-token)). The Grafana dashboard and the alert rules are in
[`deploy/grafana/`](../../deploy/grafana/remotesigner.json) and [`deploy/prometheus/`](../../deploy/prometheus/alerts.yml);
[`metrics.md`](metrics.md#5-the-grafana-dashboard) describes them.

## 8. Building the image

`make image` needs Go (the module's toolchain line selects the release), go-licenses v2.0.1, which writes the licence
files the image ships (`go install github.com/google/go-licenses/v2@v2.0.1`, then pass
`GO_LICENSES="$(go env GOPATH)/bin/go-licenses"` unless it is on `PATH`), and Docker with buildx:

```
make image FLAVOUR=remotesigner-consensus      # local/remotesigner-consensus:dev, for this machine's Docker
make docker-smoke FLAVOUR=remotesigner-consensus
```

To run the image you built, use `local/remotesigner-consensus:dev` wherever this page names
`ghcr.io/rgeraldes24/remotesigner-consensus:<version>`, and for the compose example set
`REMOTESIGNER_IMAGE=local/remotesigner-consensus:dev` in `.env`.

`make docker-smoke` builds the image and runs its real entrypoint in Docker, as section 3 does: `keystore verify` on the
key volume, then the signer with a file network, its genesis time and validators root, and one keystore from a
keystore directory with its password file; a client container that reaches `https://signer:9000` by name, pins the
generated certificate by its logged fingerprint, and calls `/upcheck` and `publicKeys`; `consensus migrate` on the
stopped signer's data volume, as an upgrade runs it ([`upgrade.md`](upgrade.md#3-one-signer)); the refusals without a
certificate, a host allowlist or a network; and the compose file's configuration. Tests that need no Docker check
that section 3's `docker run` command, the smoke test and the compose example's signer use the same mounts,
hardening and arguments. CI runs it for both flavours, and
`make release-check` runs the same test on the release dry run's images ([`release.md`](release.md#4-the-release-dry-run)).

## 9. Orchestrators

An orchestrator such as Kurtosis or Kubernetes runs the image the same way: its command (Kurtosis `cmd`, Kubernetes
`args`) replaces `CMD` and comes after the entrypoint's flags. For a flag that takes one value, the last one given
wins, so an orchestrator can move what the entrypoint sets: `--data-path` to a mounted directory, or the port with
`--http-listen-port`. List flags, such as `--http-host-allowlist`, add up instead.

- **Names.** The generated certificate covers the allowlist names, and a wildcard allowlist is refused with it. List
  the names clients use (the service name, for example `signer-1`), or mount a certificate that covers what they
  dial. A readiness probe must speak HTTPS to `/upcheck` with a `Host` from the allowlist.
- **File owners.** Files an orchestrator mounts are often owned by root with mode `0600`, which the image's user
  (65532) cannot read. Make them readable by 65532 and keep the non-root user: with Kurtosis, `chown 65532:65532`
  the files in the step that writes them (for example a `plan.run_sh`) before it stores them as a files artifact; in
  Kubernetes, give the Secret or ConfigMap volume a `defaultMode` that lets 65532 read them (`0440` with the pod's
  `fsGroup: 65532`, or `0444`). With `fsGroup`, also set `fsGroupChangePolicy: OnRootMismatch`: otherwise the
  kubelet makes the `/data` volume group-writable at every mount, and the signer refuses a `/data/tls` its group can
  write. Those modes suit the configuration and certificates only: the kubelet cannot give a Secret file to 65532
  alone, so a `file-raw` key-config file or a password file mounted that way is refused. Copy those into an
  `emptyDir` with mode `0600` in an init container that runs as 65532, or set `--strict-file-permissions=false`,
  which loads them with a WARN. Do not run the container as root instead: without capabilities (`--cap-drop=ALL`, as
  in section 3 and the compose example) root cannot write the `/data` the image creates for 65532, so the signer
  exits 1, and with them it writes root-owned files into `/data`.
- **Overrides.** The `--X…` overrides work the same way when appended, for example `--Xallow-plaintext-token-auth`
  together with `--tls-generate-self-signed=false` on a throwaway test network where TLS is impractical. The token
  then crosses the network in clear text: never do this where real validator keys are at stake.
