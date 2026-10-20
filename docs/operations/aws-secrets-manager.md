# AWS Secrets Manager

The signer reads validator seeds from AWS Secrets Manager in two ways, with Web3Signer's names: an `aws-secret`
key-config document names one secret, and the bulk loader (`--aws-secrets-enabled`) loads every secret its name and
tag filters select. Secrets Manager holds the seeds only; every signature is made in the signer's own memory. The
client is aws-sdk-go-v2, linked by the default flavour, `remotesigner`, only: `remotesigner-consensus` refuses the
bulk flags (exit 2) and fails `aws-secret` documents with a hint ([`DEVIATIONS.md`](../../DEVIATIONS.md), X96).

How sources are loaded and reloaded is in [`reload.md`](reload.md); the other stores are
[HashiCorp Vault](hashicorp-vault.md), [GCP Secret Manager](gcp-secret-manager.md) and
[Azure Key Vault](azure-key-vault.md).

## 1. The secrets

Store each seed as the secret's string value (`SecretString`), in hex with or without `0x`. A secret of an
`aws-secret` document holds one seed; whitespace around it is ignored. A secret the bulk loader reads holds one seed
per line (`\n` or `\r\n`; blank lines are skipped), up to the 64 KiB a secret can hold (661 seeds).

```
aws secretsmanager create-secret --name validators/batch-0 \
  --secret-string "$(cat seeds-batch-0.txt)" --tags Key=role,Value=validator
```

A 51-byte extended seed (execution mode's format), a 32-byte value and a 4,896-byte expanded secret key are refused
with a hint; a binary secret (`SecretBinary`) is refused too. No error or log line contains a value. **A bulk secret
loads as a whole or fails**: one bad line fails that secret, which keeps the keys it had, and the log names the line
by its number (X88).

## 2. The `aws-secret` document

```yaml
type: aws-secret
authenticationMode: SPECIFIED          # SPECIFIED (default) or ENVIRONMENT
region: us-east-1
secretName: validators/validator-0
accessKeyId: AKIA…
secretAccessKey: "…"
endpointOverride: https://vpce-….secretsmanager.us-east-1.vpce.amazonaws.com   # optional
```

| Field | Required | Meaning |
|---|---|---|
| `region`, `secretName` | yes | The secret's region and name (or ARN). |
| `authenticationMode` | no | `SPECIFIED` uses `accessKeyId` and `secretAccessKey`; `ENVIRONMENT` uses the SDK's default credential chain (section 4). |
| `accessKeyId`, `secretAccessKey` | for `SPECIFIED` | The access key. |
| `endpointOverride` | no | An `http://` or `https://` URL replacing the service endpoint: a VPC endpoint, LocalStack. |
| `keyType` | no | `ML_DSA_87`, the only value (Web3Signer's `aws-secret` has no `keyType`). |

**A file with a `secretAccessKey` is a secret file** under `--strict-file-permissions`: keep it at `0600`
([`reload.md`](reload.md#secret-files)). Up to `--aws-connection-cache-size` SDK clients (default 1) are kept for the
documents during a load, by credentials, region and endpoint, as Web3Signer's cache does (X92); each load builds them
again.

## 3. The bulk loader

```
remotesigner consensus --network=… \
  --aws-secrets-enabled \
  --aws-secrets-auth-mode=ENVIRONMENT --aws-secrets-region=us-east-1 \
  --aws-secrets-prefixes-filter=validators/ \
  --aws-secrets-tag=role=validator
```

| Flag | Default | Meaning |
|---|---|---|
| `--aws-secrets-enabled` | `false` | Turn the loader on. |
| `--aws-secrets-auth-mode` | `SPECIFIED` | `SPECIFIED` or `ENVIRONMENT`, as for the document. |
| `--aws-secrets-access-key-id`, `--aws-secrets-secret-access-key` | unset | The access key; both required for `SPECIFIED`. |
| `--aws-secrets-region` | unset | Required for `SPECIFIED`; with `ENVIRONMENT` the configured region is used when set, else the SDK's (X92). |
| `--aws-endpoint-override` | unset | The service endpoint URL, as above. |
| `--aws-secrets-prefixes-filter` | none | Comma-separated name prefixes; a secret matches any. |
| `--aws-secrets-tag` | none | `TAG_NAME=TAG_VALUE`, repeated or separated by `\|`; a name given twice keeps its last value, as in Web3Signer; a value cannot contain a comma (X95). |

The filters are Web3Signer's: one `name` filter with every prefix, one `tag-key` filter with every tag name, and one
`tag-value` filter with every non-empty value. AWS matches any value within a filter and requires every filter, and
matches by prefix, so `--aws-secrets-tag=role=validator --aws-secrets-tag=team=blue` selects the secrets with a tag
named `role` or `team` and a tag value starting with `validator` or `blue`. A missing required flag is a usage error
that names it.

Every listed secret is one source, `aws-bulk:<name>`. The credentials should not be on the command line, where other
users can read them in the process list: set `REMOTESIGNER_CONSENSUS_AWS_SECRETS_SECRET_ACCESS_KEY`, or use
`ENVIRONMENT` authentication. The `--config-file` is not a secret file: its permissions are not checked, even under
`--strict-file-permissions`, so a key put there is only as private as the mode you give the file.

## 4. Credentials

`ENVIRONMENT` is the SDK's default chain: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (and
`AWS_SESSION_TOKEN`), the shared credentials and config files (`AWS_PROFILE`, `AWS_SHARED_CREDENTIALS_FILE`,
`AWS_CONFIG_FILE`), web identity (`AWS_WEB_IDENTITY_TOKEN_FILE`, as EKS's IRSA sets it), and the ECS task role and
EC2 instance profile. The IAM policy needs `secretsmanager:GetSecretValue` on the validators' secrets, and for the
bulk loader `secretsmanager:ListSecrets`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": "secretsmanager:ListSecrets", "Resource": "*"},
    {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue",
     "Resource": "arn:aws:secretsmanager:us-east-1:111122223333:secret:validators/*"}
  ]
}
```

The SDK logs nothing: its logger, which by default writes warnings to stderr in its own format, is replaced by a
no-op, and no request or response logging is turned on (X101).

## 5. Requests and limits

Each call (a `GetSecretValue`, one page of `ListSecrets`) may take 30 seconds, the SDK's retries included, and each
response is read up to 4 MiB; a value larger than 64 KiB fails its secret. No redirect is followed (X90, X98).
Proxies are taken from `HTTPS_PROXY` and `NO_PROXY`. A secret scheduled for deletion is not listed.

**`AWS_CA_BUNDLE` and the shared config's `ca_bundle` are not supported**: the SDK can add a CA bundle only to its
own HTTP client, and the signer sends every request through its bounded one, so with either set every `aws-secret`
document and the bulk loader fail with a configuration error. To trust a private CA (a TLS-inspecting proxy, a VPC
endpoint behind one, LocalStack over TLS), set `SSL_CERT_FILE` (or `SSL_CERT_DIR`) on Linux; it replaces the system
roots, so the file must also hold the public CAs that AWS's endpoints chain to when the signer reaches them.

## 6. Reload and health

On `POST /reload` the bulk loader lists the secrets again and loads every one; an `aws-secret` document is fetched
again only when its file changed, as in Web3Signer.

| Event | What happens |
|---|---|
| a secret fails (bad line, access denied, timeout) | it keeps its keys; `error-count` counts it |
| the listing fails | every secret of the loader keeps its keys; `error-count` is 1 |
| a secret is no longer listed (deleted, untagged, renamed) | its keys are evicted from memory, never disabled in slashing protection |
| a key is in a key-config file too | the key-config file wins, with a WARN: sources load in Web3Signer's order (key-config files, Azure, keystores, AWS, GCP) |

`/healthcheck` has `keys-check/aws-bulk-loading` while the loader is on, with `keys-loaded` and `error-count`; it is
`DOWN` while a secret fails ([`reload.md`](reload.md#4-health-checks)).

## 7. Testing against LocalStack

`make test-cloud` runs the client's and the built binary's tests against LocalStack's Secrets Manager: it starts
the pinned `localstack/localstack` image in Docker, or uses `REMOTESIGNER_TEST_AWS_ENDPOINT` when it is set (the CI
job `cloud-secrets` runs LocalStack as a service container). LocalStack 4.14.0 is the last release that serves
Secrets Manager without an auth token. `make test` runs the same client against an in-process fake of the AWS JSON
protocol.
