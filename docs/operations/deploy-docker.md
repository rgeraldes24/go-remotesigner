# Deploying with Docker

This page runs remotesigner from its container image: what the image contains, what its entrypoint sets and what it
leaves to you, the first start and pinning the generated certificate, and the compose example with a qrysm validator
client. Every flag is in [`../reference/flags.md`](../reference/flags.md); TLS and tokens are covered in depth in
[`tls.md`](tls.md). To run the binary directly under systemd instead, see [`deploy-systemd.md`](deploy-systemd.md).

## 1. The images

| Image | Flavour |
|---|---|
| `ghcr.io/rgeraldes24/remotesigner-consensus` | Consensus only (`-tags noexecution`); links permissively licensed code only. Use this one unless you need execution mode. |
| `ghcr.io/rgeraldes24/remotesigner` | The default flavour. It behaves the same for everything on this page. |

Each release is tagged with its version (`1.0.0`, without the `v`) and, unless it is a pre-release, `latest`, for
`linux/amd64` and `linux/arm64`. Pin a version, or better its digest, in production. How to check an image's
signature, SBOM and provenance is in [`release.md`](release.md#3-verifying-a-release).

| Path | Content |
|---|---|
| `/usr/local/bin/remotesigner` | the static binary, the image's only program: there is no shell |
| `/usr/share/doc/remotesigner/` | `LICENSE`, the flavour's `NOTICE`, `LICENSES/` and `third_party_licenses/` |
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
subcommand themselves. Global flags, such as the host allowlist and the key directory, go before `consensus`;
consensus flags, such as the network, after it:

```
--http-host-allowlist=signer --key-config-path=/keys \
  consensus --network=/network/config.yaml --network-genesis-time=<unix seconds> --network-genesis-validators-root=0x<64 hex>
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
| key-config files at, for example, `/keys` | read-only | one `file-raw` key-config file per key ([`quickstart.md`](quickstart.md#2-key-files)), given with `--key-config-path=/keys` |
| the network config at, for example, `/network` | read-only | the chain's qrysm-format config YAML |

A new named volume mounted at `/data` takes the image's owner and mode (`65532:65532`, `0700`). A bind mount does not:
make the host directory owned by `65532:65532` with mode `0700` yourself, or the signer cannot write its files.
The key files must be readable by uid 65532, and by it alone: on Linux, `chown -R 65532:65532 keys && chmod 0700 keys
&& chmod 0600 keys/*`. A `file-raw` key-config file or a keystore password file that its group or other users can
read is refused (`--strict-file-permissions`, [`reload.md`](reload.md#secret-files)). Never mount one `/data` volume
into two running signers: the bbolt store allows one process.

Run it hardened, on a user-defined network that the validator client's container joins to reach
`https://signer:9000`:

```
docker network create signer-net
docker volume create signer-data
docker run -d --name signer --network signer-net --network-alias signer \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges --stop-timeout=30 \
  -v signer-data:/data -v "$PWD/keys:/keys:ro" -v "$PWD/network:/network:ro" \
  ghcr.io/rgeraldes24/remotesigner-consensus:<version> \
  --http-host-allowlist=signer --key-config-path=/keys \
  consensus --network=/network/config.yaml \
  --network-genesis-time=1760000000 \
  --network-genesis-validators-root=0x9471e8fb19e0faae953e9d46889f207192bcec9b14293d7ba418ae4dc5e3ac8f
```

Publish the API port (`-p 9000:9000`) only if validator clients outside Docker connect to it, and then add the name
or address they use to `--http-host-allowlist`.

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
private key. [`tls.md`](tls.md#2-the-generated-certificate-and-pinning-it) has the details, including rotating
the certificate.

**Your own certificate.** Mount it read-only and name it; a configured certificate takes precedence and nothing is
generated:

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
  keys/                 the signer's key-config files
  network/config.yaml   the chain's config, read by both containers
  validator/            filled in step 2
```

1. Start the signer alone and wait for it to log its fingerprint:

   ```
   docker compose up -d signer
   docker compose logs signer | grep -o 'sha256-fingerprint="[^"]*"'
   ```

2. Copy its certificate and sign token for the validator client, compare the fingerprint, and list the validator
   keys the client should use, one `0x` public key per line, for example from your deposit data:

   ```
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
validator client: two clients signing for the same validator can be slashed.

## 6. Running it

| Task | Command |
|---|---|
| Logs | `docker logs signer` (text; add `--logging-format=json` before `consensus` for JSON) |
| Reload tokens, the certificate and client trust (SIGHUP) | `docker kill --signal=HUP signer` |
| Reload the key-config files | `POST /reload` with the admin token, from a client on the signer's network ([`quickstart.md`](quickstart.md#5-check-it)) |
| Stop | `docker stop signer`: SIGTERM; in-flight requests finish within 10 s, then the store is closed and the keys wiped. Allow 30 s (`--stop-timeout=30`, compose `stop_grace_period`). |
| Back up the store | stop the signer, then copy the `/data` volume |
| Upgrade | stop the old container, start the new image with the same `/data` volume and arguments |

`/upcheck` answers `200 OK` once the keys are loaded and the store is open. The image has no shell, so it has no
Docker `HEALTHCHECK`; probe `/upcheck` from outside (over TLS, pinning the certificate).

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

```
make image FLAVOUR=remotesigner-consensus      # local/remotesigner-consensus:dev, for this machine's Docker
make docker-smoke FLAVOUR=remotesigner-consensus
```

`make docker-smoke` builds the image and runs its real entrypoint in Docker: the signer with a file network, its
genesis time and validators root, and one key; a client container that reaches `https://signer:9000` by name, pins
the generated certificate by its logged fingerprint, and calls `/upcheck` and `publicKeys`; the refusals without a
certificate, a host allowlist or a network; and the compose file's configuration. CI runs it for both flavours, and
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
