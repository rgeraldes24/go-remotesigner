# Azure Key Vault

The signer reads validator seeds from Azure Key Vault **secrets** in two ways, with Web3Signer's names: an
`azure-secret` key-config document names one secret, and the bulk loader (`--azure-vault-enabled`) loads every secret
of a vault that carries the configured tags. Key Vault holds the seeds only; every signature is made in the signer's
own memory. Key Vault *keys* are not used: Azure has no ML-DSA key type, so Web3Signer's `azure-key` signer has no QRL
counterpart. The client is azure-sdk-for-go (`azsecrets`, `azidentity`), linked by the default flavour,
`remotesigner`, only: `remotesigner-consensus` refuses the bulk flags (exit 2) and fails `azure-secret` documents with
a hint ([`DEVIATIONS.md`](../../DEVIATIONS.md), X96).

How sources are loaded and reloaded is in [`reload.md`](reload.md); the other stores are
[HashiCorp Vault](hashicorp-vault.md), [AWS Secrets Manager](aws-secrets-manager.md) and
[GCP Secret Manager](gcp-secret-manager.md).

## 1. The secrets

The signer reads the secret's latest version: hex seeds, with or without `0x`. The secret of an `azure-secret`
document holds one seed (whitespace around it is ignored); a secret the bulk loader reads holds one seed per line
(`\n` or `\r\n`; blank lines are skipped). Key Vault stores at most 25 KB per secret, so keep at most about 250 seeds
in one, or 200 as Web3Signer advises.

```
az keyvault secret set --vault-name validators-prod --name batch-0 --file seeds-batch-0.txt --tags role=validator
```

A 51-byte extended seed, a 32-byte value and a 4,896-byte expanded secret key are refused with a hint; no error or
log line contains a value. A bulk secret loads as a whole or fails (X88). As in Web3Signer, a disabled secret is
listed and fails to load.

## 2. Authentication

| Mode | Needs | Credential |
|---|---|---|
| `CLIENT_SECRET` (default) | client id, client secret, tenant id | a Microsoft Entra ID application's client secret |
| `USER_ASSIGNED_MANAGED_IDENTITY` | client id | the user-assigned managed identity with that client id |
| `SYSTEM_ASSIGNED_MANAGED_IDENTITY` | nothing (a client id, when given, selects that identity) | the resource's system-assigned identity |

The managed identities are read from the host's identity endpoint (the Azure Instance Metadata Service, or App
Service's `IDENTITY_ENDPOINT`). The identity needs the **Key Vault Secrets User** role on the vault (or a `get` and,
for the bulk loader, `list` secret access policy).

The SDK's log listener is removed, so `AZURE_SDK_GO_LOGGING=all` has no effect (X101).

## 3. The `azure-secret` document

```yaml
type: azure-secret
keyType: ML_DSA_87                      # optional; the only value
vaultName: validators-prod
secretName: validator-0
authenticationMode: CLIENT_SECRET
clientId: 00000000-0000-0000-0000-000000000000
clientSecret: "…"
tenantId: 00000000-0000-0000-0000-000000000000
timeout: 60                             # seconds, default 60
```

| Field | Required | Meaning |
|---|---|---|
| `vaultName`, `secretName` | yes | The vault (`https://<vaultName>.vault.azure.net`) and the secret. A vault name is letters, digits and hyphens. |
| `authenticationMode` | no | As in section 2; `CLIENT_SECRET` needs `clientId`, `clientSecret` and `tenantId`, `USER_ASSIGNED_MANAGED_IDENTITY` needs `clientId`. |
| `timeout` | no | Seconds each request, and each call with its retries, may take; default 60. |
| `endpointOverride`, `authorityHostOverride`, `trustCertificateOverride` | no | Web3Signer's overrides (section 5); a relative `trustCertificateOverride` is relative to the key-config directory. |

**A file with a `clientSecret` is a secret file** under `--strict-file-permissions`: keep it at `0600`
([`reload.md`](reload.md#secret-files)). Up to 10 SDK clients are kept for the documents during a load, by
credentials, vault and overrides, as Web3Signer's `AzureKeyVaultFactory` does, so a vault's token is fetched once per
load, not once per document. Each load builds them again, so a replaced `trustCertificateOverride` file applies to
the next reload that fetches the document.

## 4. The bulk loader

```
remotesigner consensus --network=… \
  --azure-vault-enabled --azure-vault-name=validators-prod \
  --azure-vault-auth-mode=SYSTEM_ASSIGNED_MANAGED_IDENTITY \
  --azure-tags=role=validator
```

| Flag | Default | Meaning |
|---|---|---|
| `--azure-vault-enabled` | `false` | Turn the loader on. |
| `--azure-vault-name` | unset | Required. |
| `--azure-vault-auth-mode` | `CLIENT_SECRET` | As in section 2. |
| `--azure-client-id`, `--azure-tenant-id`, `--azure-client-secret-file` | unset | As the mode needs; `CLIENT_SECRET` needs all three (Web3Signer does not check the client id at startup, X94). The file's first line is the client secret. |
| `--azure-client-secret` | unset | Deprecated: the client secret itself, instead of the file (Web3Signer's flag). Not with `--azure-client-secret-file`. |
| `--azure-response-timeout` | `60` | Seconds, as the document's `timeout`. |
| `--azure-tags` | none | `TAG_NAME=TAG_VALUE`, repeated or separated by `\|`: a secret must carry every one with that exact value (an empty value matches an empty tag value). A name given twice keeps its last value, as in Web3Signer; a value cannot contain a comma (X95). |

Every selected secret is one source, `azure-bulk:<name>`.

**Give the client secret in a file.** `--azure-client-secret-file` names a secret file, read once at startup: its
first line is the secret (a trailing `\r` is dropped), and under `--strict-file-permissions` (the default) the signer
refuses to start (exit 1) when its group or other users can read it, as for every secret file
([`reload.md`](reload.md#secret-files)). Keep it at `0600`, owned by the signer's user; a new secret needs a restart.
Web3Signer's plain `--azure-client-secret` is still accepted, from the command line, the environment
(`REMOTESIGNER_CONSENSUS_AZURE_CLIENT_SECRET`) or the config file, but it is deprecated, and the signer logs a WARN at
startup that names the `-file` flag to use instead. On the command line the secret can be read by every local user in
the process list, which a second WARN says. A `--config-file` that sets it is a secret file: under
`--strict-file-permissions` one that its group or other users can read refuses the start. Setting both flags is a
usage error (exit 2). The managed-identity modes need neither.

## 5. Overrides

The hidden `--Xazure-endpoint-override`, `--Xazure-authority-host-override` and `--Xazure-trust-certificate-override`
(and the document fields of the same meaning) are Web3Signer's unstable Azure options, for sovereign clouds, private
endpoints and emulators:

- the endpoint override replaces `https://<vault>.vault.azure.net`, and turns off the SDK's check that the vault's
  authentication challenge names a `vault.azure.net` resource;
- the authority host override replaces `https://login.microsoftonline.com/` for `CLIENT_SECRET` tokens (and skips the
  authority's instance discovery);
- the trust certificate override, a PEM or DER certificate file, is trusted for the vault and authority connections
  **instead of** the system roots.

## 6. Requests and limits

The timeout bounds each request and each call, the SDK's retries included. A response is read up to 4 MiB (a larger
one fails at once: the SDK does not retry it, as it retries a body it could not read) and a value up to 64 KiB. No
redirect is followed (X90, X98). Proxies are taken from `HTTPS_PROXY` and `NO_PROXY`.

## 7. Reload and health

On `POST /reload` the bulk loader lists the vault again and loads every selected secret; an `azure-secret` document
is fetched again only when its file changed, as in Web3Signer. A secret that fails keeps its keys; a listing that
fails keeps every key of the loader and counts one error; a secret that is no longer selected is evicted from memory
and never disabled in slashing protection. `/healthcheck` has `keys-check/azure-bulk-loading` while the loader is on
([`reload.md`](reload.md#4-health-checks)). The Azure loader runs right after the key-config files, before the
keystores, as in Web3Signer; a key that an earlier source also provides is loaded from the earlier one, with a WARN.

## 8. Testing

`make test` runs the client, and the built binary through the three overrides, against an in-process fake of Key
Vault and Microsoft Entra ID on one TLS server: Key Vault's authentication challenge, Entra ID's OpenID configuration
and client-credentials token endpoint, App Service's managed identity endpoint, and the secret listing with paging and
the secret read. Web3Signer's acceptance tests use a Key Vault emulator image with a mock authority in the same way.
