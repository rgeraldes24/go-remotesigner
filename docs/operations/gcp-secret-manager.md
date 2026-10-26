# GCP Secret Manager

The signer reads validator seeds from GCP Secret Manager in two ways: the bulk loader (`--gcp-secrets-enabled`),
Web3Signer's, loads the latest version of every secret of a project that a list filter selects, and a `gcp-secret`
key-config document, which Web3Signer lacks, names one secret ([`DEVIATIONS.md`](../../DEVIATIONS.md), X93). Secret
Manager holds the seeds only; every signature is made in the signer's own memory. The client is
`cloud.google.com/go/secretmanager` over gRPC, the SDK's default transport, linked by the default flavour,
`remotesigner`, only: `remotesigner-consensus` refuses the bulk flags (exit 2) and fails `gcp-secret` documents with a
hint (X96).

How sources are loaded and reloaded is in [`reload.md`](reload.md); the other stores are
[HashiCorp Vault](hashicorp-vault.md), [AWS Secrets Manager](aws-secrets-manager.md) and
[Azure Key Vault](azure-key-vault.md).

## 1. The secrets

The signer reads the payload of the secret's `latest` version: hex seeds, with or without `0x`. The secret of a
`gcp-secret` document holds one seed (whitespace around it is ignored); a secret the bulk loader reads holds one seed
per line (`\n` or `\r\n`; blank lines are skipped), up to the 64 KiB a version can hold.

```
gcloud secrets create validators-batch-0 --labels=role=validator --data-file=seeds-batch-0.txt
```

A 51-byte extended seed, a 32-byte value and a 4,896-byte expanded secret key are refused with a hint; no error or
log line contains a value. A bulk secret loads as a whole or fails (X88). A secret with no enabled version fails as
not found.

## 2. The bulk loader

```
remotesigner consensus --network=… \
  --gcp-secrets-enabled --gcp-project-id=validators-prod \
  --gcp-secrets-filter='labels.role=validator'
```

| Flag | Default | Meaning |
|---|---|---|
| `--gcp-secrets-enabled` | `false` | Turn the loader on. |
| `--gcp-project-id` | unset | Required: the project whose secrets are listed. |
| `--gcp-secrets-filter` | unset | A [list filter](https://cloud.google.com/secret-manager/docs/filtering), such as `labels.role=validator` or `name:validator`; unset lists every secret of the project. |

Every listed secret is one source, `gcp-bulk:projects/<project>/secrets/<name>`. A missing `--gcp-project-id` is a
usage error.

## 3. The `gcp-secret` document

```yaml
type: gcp-secret
keyType: ML_DSA_87          # optional; the only value
projectId: validators-prod
secretName: validator-0
```

| Field | Required | Meaning |
|---|---|---|
| `projectId`, `secretName` | yes | The secret `projects/<projectId>/secrets/<secretName>`; its `latest` version is read. |
| `endpointOverride` | no | As `--Xgcp-endpoint-override` below. |

The document holds no credential, so it is not a secret file.

## 4. Credentials

Application Default Credentials, as Web3Signer's client uses them: the service-account key file that
`GOOGLE_APPLICATION_CREDENTIALS` names, the user credentials of `gcloud auth application-default login`, or, on
Compute Engine, GKE (with Workload Identity) and Cloud Run, the attached service account from the metadata server.
The service account needs `roles/secretmanager.secretAccessor` on the secrets, and for the bulk loader
`secretmanager.secrets.list` on the project (for example `roles/secretmanager.viewer`).

The SDK's logger is replaced by one that discards everything, so `GOOGLE_SDK_GO_LOGGING_LEVEL=debug`, which would
otherwise log request and response payloads, has no effect, and so is gRPC's, which `GRPC_GO_LOG_SEVERITY_LEVEL`
would otherwise turn on (X101).

## 5. Requests and limits

Each call (one page of the listing, one access of a version) may take 30 seconds, the SDK's retries included, and
each gRPC message is read up to 4 MiB: a larger one fails at once, without the retries the SDK makes when the service
answers that it is out of quota. A payload larger than 64 KiB fails its secret (X98).

The hidden `--Xgcp-endpoint-override` (and a document's `endpointOverride`) replaces Google's endpoint, which
Web3Signer cannot do: `host:port` (or `https://host:port`) keeps TLS and Application Default Credentials, for a
regional or Private Service Connect endpoint; **`http://host:port` is an emulator or a test fake**, reached without
TLS and without credentials. Never point an `http://` override at anything but a local emulator.

## 6. Reload and health

On `POST /reload` the bulk loader lists the secrets again and loads every one; a `gcp-secret` document is fetched
again only when its file changed. A secret that fails keeps its keys; a listing that fails keeps every key of the
loader and counts one error; a secret that is no longer listed is evicted from memory and never disabled in
slashing protection. `/healthcheck` has `keys-check/gcp-bulk-loading` while the loader is on
([`reload.md`](reload.md#4-health-checks)). Sources load in Web3Signer's order (key-config files, Azure, keystores,
AWS, GCP), and a key that an earlier source also provides is loaded from the earlier one, with a WARN.

## 7. Testing

Google publishes no Secret Manager emulator. `make test-cloud` runs the client's and the built binary's tests against
[floci-gcp](https://github.com/floci-io/floci-gcp) (MIT), an open-source emulator of Google Cloud APIs: it starts the
pinned image in Docker on a free loopback port and points `--Xgcp-endpoint-override=http://…` at it, which reaches it
without TLS or credentials (the CI job `cloud-secrets` runs it as a service container). The tests read a secret's
latest version, a missing secret, and a project's secrets in bulk, through a `gcp-secret` document and the bulk
loader. floci-gcp ignores the `ListSecrets` filter, so `make test` covers the label filters, paging and the error paths
against an in-process fake that implements the SDK's own generated gRPC service (`ListSecrets` with paging and label
filters, `AccessSecretVersion`). Neither replaces a run against Google's service, with Application Default
Credentials, which the release checklist requires ([`release.md`](release.md#72-open-gates-this-repository-cannot-meet-today)).
