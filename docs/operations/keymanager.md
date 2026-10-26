# Keymanager API

The keymanager API lists, imports and deletes validator keys while the signer runs: `GET`, `POST` and `DELETE
/qrl/v1/keystores`, the path of the qrysm validator client's own keymanager API. It is the Web3Signer keymanager API
for QRL keystores and ML-DSA-87 keys, with the differences listed in section 7. The request and response shapes are
in [`../contract.md`](../contract.md#17-supporting-endpoints) and `api/openapi/consensus.yaml`; keystore formats and
the keystore policy are in [`keystores.md`](keystores.md); how keys load and reload is in [`reload.md`](reload.md).

The qrysm validator client never calls this API; the signer's keys for it come from the key sources of
[`reload.md`](reload.md). The API is for moving keys between signers and for adding keys without a restart.

## 1. Enabling it

```
remotesigner --key-config-path=/var/lib/remotesigner/keys --data-path=/var/lib/remotesigner \
  consensus --network=… --key-manager-api-enabled
```

`--enable-key-manager-api`, Web3Signer's alias, does the same. Web3Signer's hidden
`--Xkey-manager-skip-keystore-storage`, which keeps imported keys in memory only, is not accepted: imported keys are
always written to the key-config directory (DEVIATIONS X112).

- **Admin token.** Every route takes the admin token (`--http-admin-token-file`, default
  `<data-path>/admin-token`), in every `--http-auth-mode`; the sign token and a client certificate get `403
  FORBIDDEN_SCOPE`. Without an admin token the signer refuses to start.
- **Key-config directory.** Imported keys are written to `--key-config-path`, which the startup load and every reload
  read, so they load again after a restart. The flag is required: without it the signer refuses to start. A missing
  directory is created with mode `0700`. An existing one that its group or other users can access (`0755`, for
  example, as `mkdir` makes it under the usual umask) is refused at startup under `--strict-file-permissions` (the
  default): `chmod 0700` it. With `--strict-file-permissions=false` the signer starts and logs a WARN naming the
  directory and its mode. On Windows the directory's ACL governs access and no mode is checked. The signer must be
  able to write there, so a read-only mount makes every import an `error`: in the container image use
  `--key-config-path=/data/keys`, which the signer creates in its data volume
  ([`deploy-docker.md`](deploy-docker.md#3-volumes-and-keys)).
- **Without the flag** the routes do not exist: they answer `404` once the caller has presented a token.

The routes answer during the startup load as well, while `/upcheck` is still `503`. An import or a delete then changes
its key at once, and the load that is running cannot undo it: it neither loads a key deleted meanwhile, even when it
had already read its files, nor drops a key imported meanwhile. A list during the startup load shows the keys loaded
so far: the startup load applies its keys when it ends, so that is the keys imported since the signer started.

Limits: at most 64 keystores per import, a body of at most 32 MiB (`413 BODY_TOO_LARGE` above it), and a write
deadline of 10 minutes for the response, enough for 64 standard-KDF keystores on a small machine (section 3). The
`POST` and `DELETE` bodies need `Content-Type: application/json` (`415 UNSUPPORTED_MEDIA_TYPE` otherwise).
Imports and deletes run one at a time; the keystores of an import are decrypted before it waits for the one before
it.

## 2. Listing keys

`GET /qrl/v1/keystores` returns every loaded key, sorted:

```json
{"data":[{"validating_pubkey":"0x<5184 hex>","derivation_path":"m/12381/238/0/0","readonly":false}, …]}
```

- `derivation_path` is the path the key's keystore records (the deposit CLI writes one; qrysm's keystore v1 an empty
  one), and empty for a raw seed.
- `readonly` is `false` only for a key loaded from the key-config file the keymanager writes for it,
  `<sha256 of the public key>.yaml` in `--key-config-path`, holding that key alone, out of a keystore. Every other key
  (a `file-raw` seed, a seed from a secret store, a key-config file of another name, a key of `--keystores-path`) is
  read-only: a delete of it is an error.

## 3. Importing keys

```json
POST /qrl/v1/keystores
{"keystores": ["<keystore JSON>", …], "passwords": ["<password>", …], "slashing_protection": "<EIP-3076 JSON>"}
```

`keystores` and `passwords` go index by index and must be equally long (`400 INVARIANT_VIOLATION` otherwise, and for
more than 64); `slashing_protection` is optional. Unknown fields and duplicate keys are refused with `400`, as on
every route. The response has one result per keystore, in request order:

| `status` | Meaning |
|---|---|
| `imported` | The key is loaded and enabled: the import wrote its files to `--key-config-path` and loaded it, or the key was loaded already but disabled in slashing protection, and the import enabled it (step 4) |
| `duplicate` | The key is loaded and enabled already, or an earlier keystore of the request has it and was imported |
| `error` | The keystore was not imported; `message` says why. Nothing of it is left: no file, no loaded key (a key whose files an earlier import wrote keeps them, step 7) |

Each keystore goes through these steps, in order; a step that fails makes it an `error`:

1. **Password.** A password longer than 65,536 bytes is refused (no password file the signer reads may be longer).
   Trailing carriage returns and line feeds are dropped, as when the password file written for the key is read back.
2. **Keystore.** A QRL keystore v1 (`version: 1`) or a deposit CLI keystore (`version: 0`) that passes the keystore
   policy of [`keystores.md`](keystores.md#2-what-the-signer-refuses): the KDF and its parameters, the salt, IV and
   ciphertext are checked before Argon2id runs, so a keystore with an oversized KDF costs nothing. The keystore must
   declare its `pubkey`: the keymanager imports only keystores that name their key, so that the files it writes hold
   the full key.
3. **Decryption and comparison.** The keystore is decrypted through the same Argon2id semaphore as the startup load
   and every reload, so an import never holds more Argon2id memory than they may. The public key the seed derives
   must equal the declared one: a keystore that declares another key's pubkey (someone else's validator) is an
   `error`, and nothing is written for either key.
4. **Duplicates.** A key that is loaded and enabled already is a `duplicate`, and nothing changes for it, its history
   included. A key that is loaded but disabled goes on to step 5 and is enabled at step 7, without any file written
   or changed: a key that `consensus disable-validator` disabled (its files stay, so it loads again after the
   restart), and one that a `DELETE` disabled before a load brought it in, from any source (the startup load still
   running, for example). Of two keystores of one key in a request, the first that opens is imported and a later one
   is a `duplicate`; if the first fails after it opened, the later ones are an `error` naming it.
5. **History.** When the request carries `slashing_protection` and slashing protection is enabled, the history of the
   keys about to be imported or enabled is imported, and nothing of any other key in the file: no record, no
   registration. The whole file is read before any keystore is decrypted: a file that is not EIP-3076 version 5 to
   its end, or that names a genesis validators root other than the signer's, refuses the request with `400
   BAD_FIELD` and nothing is written; a store that cannot be read for this check fails it with `500
   STORE_UNAVAILABLE`. A data element of such a key that fails (an invalid record, a watermark beyond the high
   watermark) makes that key an `error`, whose `message` quotes at most 160 printable characters of the element's
   error; the key is disabled in slashing protection, and not loaded when it was not. The import leaves the enabled
   flag of the other keys alone at this step. A store not bound to a network yet is bound to the file's root. With
   slashing protection disabled the history is ignored, with a WARN.
6. **Files.** For a key that is not loaded, three files are written in `--key-config-path`, named by the hex SHA-256
   of the public key (a public key in hex is longer than a file name may be): `<sha256>.password` (the password as
   given), `<sha256>.json` (the keystore as given) and `<sha256>.yaml`:

   ```yaml
   type: file-keystore
   keyType: ML_DSA_87
   keystoreFile: <sha256>.json
   keystorePasswordFile: <sha256>.password
   ```

   Each is written to a new temporary file (`O_EXCL`, mode `0600`, synced); once all three are, they are renamed over
   their names, the key-config file last: a file or a symlink found at a name is replaced, never written through, and
   a load never sees half a file or a key-config file without its keystore. A write that fails before the renames (a
   full disk, for example) leaves the names as they were.
7. **Load and enable.** The keys of the request are registered in slashing protection, loaded from their files and
   then enabled, together with the loaded keys that step 4 found disabled: a key that a delete or `consensus
   disable-validator` disabled is enabled again by its import, whether it is loaded or not, since the import proved
   that the caller holds it. If this step fails for a key, its files are removed, it is evicted and its enabled flag
   is left as it was: a key the store did not know stays registered, enabled, as any load of it would register it,
   unless step 5 wrote its history, which registers a new key disabled. A loaded key that cannot be enabled stays
   loaded and disabled. A key whose files were in `--key-config-path` before the import (written by an earlier
   import, and not loaded yet because the startup load is still running or their load failed) keeps them whatever
   step fails, rewritten by this import, or as they were when the write failed before its renames, and the loads
   load it from them as they would have.

An import that fails after step 5 leaves the history it wrote (history only adds protection), but it never enables a
key that was disabled; a key new to the store whose history it wrote stays registered disabled until an import of it
succeeds. The first reload after an import decrypts each imported key once more: files that were written
less than two seconds before a load starts are always read again (see [`reload.md`](reload.md)); later reloads keep
it without decrypting.

## 4. Deleting keys

```json
DELETE /qrl/v1/keystores
{"pubkeys": ["0x<5184 hex>", …]}
```

The response has one result per key, in request order, and the history of the keys it disabled:

```json
{"data":[{"status":"deleted","message":""}], "slashing_protection":"<EIP-3076 JSON>"}
```

| `status` | Meaning |
|---|---|
| `deleted` | The key was loaded from its keymanager files, or was not loaded but had them: it is disabled in slashing protection, its three files are removed and it is evicted |
| `not_active` | The key was not loaded, has no keymanager files, and has history: it is disabled |
| `not_found` | The key was not loaded, has no keymanager files and no history: it is disabled (a key the store never saw is registered disabled) |
| `error` | Nothing changed for the key (it is read-only, or its keystore file at the keymanager's name declares another key), or a step failed after it was disabled, as `message` says |

For each key the signer first persists `enabled=false`, so that from then on it refuses the key's blocks,
attestations and new RANDAO layers with `412 VALIDATOR_DISABLED`, then removes the files and evicts the key. The keys
of a request are disabled together, in two store transactions whatever their number, so the cost of a delete hardly
grows with it: on the development machine (load average 2) 500 keys took 0.07 s and 6,470, as many as a 32 MiB body
holds, 0.75 s. Imports wait while a delete runs. Every key a delete names that the store does not know is
registered there, disabled, and stays: name only keys you mean to delete. A key
that is not loaded is disabled too, so that a load that brings it in later, from any source, cannot make it sign:
the startup load still running, a reload of a source that had failed to load, or the key's file put back. Only an
import of its keystore (section 3), whether the key is loaded by then or not, or a clean offline `consensus import` of
its history ([`migration.md`](migration.md#2-import-the-history)), enables a key again.

`slashing_protection` is an EIP-3076 version 5 interchange of every key the delete disabled that has history: the same
document `consensus export --keys=<the keys>` writes, from one consistent read after the keys were disabled, so no
signature can be missing from it. It always names the genesis validators root: the store's, or the one the network
configuration gives. After a watermark repair it carries the watermark records `export` writes
([`migration.md`](migration.md#7-exporting-and-moving-back)). On a signer that is not bound to a network yet (no root
configured, none pinned) nothing was ever recorded, so it is the empty string; a `POST` takes an empty
`slashing_protection` as none. If the export fails, every result that is not an `error` already becomes one whose
message says that the key is disabled but its history could not be exported: export it with `consensus export` once
the signer is stopped.

With slashing protection disabled (`--slashing-protection-enabled=false`, allowed only when every listener is
loopback) the store is in memory: a delete still disables the key there, removes its files and evicts it, but the
disable does not outlive a restart, and `slashing_protection` is an interchange without data that names the network
(the empty string when none is known).

## 5. Moving a key to another signer

1. `DELETE` the key on the old signer and keep the response's `slashing_protection`. The key is disabled there for
   good: do not import it into the old signer again unless it is moving back.
2. `POST` the keystore, its password and that `slashing_protection` to the new signer. The new signer imports the
   history before it loads the key, so the key never signs there without it.
3. Check the result is `imported`, and that the old signer lists the key no more.

The two signers must never hold the same key enabled at once: slashing protection cannot see across them. A delete
during the old signer's startup load is safe (section 1): the key does not come back when the load ends.

## 6. Logging

Request bodies are never logged, at any level, `TRACE` included: not on success, not when a body does not parse.
The log has, per request, the number of keys per status, and per key its short form (`0x`, the first 10 hex
characters of the key, `…` and the first 8 of its SHA-256) and the status or the reason of an `error`; a failed
request is logged at `DEBUG` with its route and reason code. Nothing of a `slashing_protection` reaches the log
either: a refused one is logged by the kind of refusal (unreadable, another interchange version, another network),
and the reason logged for a key whose history element fails leaves out the part of the `message` that quotes the
element. The `message` of an `error` holds no password, key material or file path; the log line next to it has the
path where a file could not be written.

An import's body is read into one buffer, which is copied and wiped whenever the body outgrows it, and the passwords
and keystores are decoded into buffers of their own; all of them are wiped once the import is done, and what was read
is wiped when the body cannot be read to its end. The read buffers of Go's HTTP and TLS layers are out of the
signer's reach.

## 7. Differences from Web3Signer

| Row | Difference |
|---|---|
| [X15](../../DEVIATIONS.md) | Files named by the SHA-256 of the key, not by the key, mode `0600` |
| [X16](../../DEVIATIONS.md) | Only the imported keys' history is written; a key whose history fails is an `error` and stays disabled; a file that cannot be read refuses the request before any keystore is opened; the export always names the network |
| [X29](../../DEVIATIONS.md) | A reload never writes `enabled=false`: a delete and `consensus disable-validator` write it on purpose, and an import for a key whose history fails |
| [X68](../../DEVIATIONS.md) | `--key-config-path` required, `0700` directory, routes served during the startup load |
| [X69](../../DEVIATIONS.md) | Import: at most 64 keystores, the keystore must declare its pubkey, password rules, keys enabled once their files are written, a loaded key that is disabled is enabled |
| [X70](../../DEVIATIONS.md) | Delete: keys that are not loaded are disabled too; only keymanager-written keys can be deleted; disabled before evicted |
