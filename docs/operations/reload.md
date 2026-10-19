# Key sources and reload

This page describes where the signer loads keys from, what a load and a `POST /reload` do to the keys in memory and
to slashing protection, how to disable a validator, and how the signer sizes keystore decryption to the memory it
may use. Keystore formats and password files are in [`keystores.md`](keystores.md); every flag is in
[`../reference/flags.md`](../reference/flags.md).

## 1. Key sources

| Source | Flags | One source is |
|---|---|---|
| Key-config files | `--key-config-path` (alias `--key-store-path`): every non-hidden `*.yaml` or `*.yml` file directly in the directory | one file, with all its documents |
| Keystore directory | `--keystores-path` with `--keystores-password-file` (one password for every keystore) or `--keystores-passwords-path` (`<name>.txt` for keystore `<name>.json`) | one keystore |

A key-config file holds one or more YAML documents of two types:

```yaml
type: file-raw
keyType: ML_DSA_87
privateKey: "0x<96 hex characters: the 48-byte wallet seed>"
---
type: file-keystore
keyType: ML_DSA_87
keystoreFile: keystores/keystore-0.json        # relative paths are relative to the key-config directory
keystorePasswordFile: keystores/keystore-0.txt
```

A key-config file larger than `--key-store-config-file-max-size` (in bytes; default 104857600, 100 MiB, as in
Web3Signer, which counts code points instead) fails to load before any of it is read.

The keystore directory takes every non-hidden `*.json` file directly in `--keystores-path` (any case of the
extension); entries that are not regular files are skipped. This is the layout the deposit CLI writes: a directory
of `keystore-*.json` files and the password given to the CLI in one file:

```
remotesigner consensus --network=… \
  --keystores-path=/var/lib/remotesigner/keystores \
  --keystores-password-file=/var/lib/remotesigner/password.txt
```

Every `*.json` file in the directory is taken for a keystore, as in Web3Signer, so copy only the `keystore-*.json`
files there: the deposit CLI's `deposit_data-*.json` would fail to load and keep the keystore health check `DOWN`.
The password file the CLI was given can be used as it is (its trailing line feed is not part of the password), once
it is readable by its owner only (see "Secret files" below).

`--keystores-path` needs exactly one of the two password flags, and they need it; any other combination is a usage
error (exit 2). The key-config files are loaded first, then the keystores. A key that two sources provide is loaded
once, from the first, with a WARN. With `--key-manager-api-enabled`, keys imported through the keymanager are
written to the key-config directory as `<sha256 of the public key>.yaml` with its keystore and password file
([`keymanager.md`](keymanager.md#3-importing-keys)), so every later load reads them like any other key-config file; a
load that is running when the keymanager imports or deletes a key does not undo that change.

### Secret files

A password file, and a key-config file with a `file-raw` document (which holds a seed in the clear), is a secret
file. With `--strict-file-permissions` (the default) a secret file that its group or other users can read is
refused: it fails to load like any other error (section 3), and the log names the file and its mode. With
`--strict-file-permissions=false` it is loaded with a WARN. The mode is checked on the opened file, so the file read
is the file checked. Keystores themselves are encrypted and are not checked. Keep secret files at `0600` or `0400`
in `0700` directories. On Windows, whose files have no owner, group and other mode bits, the check is not made
(only a path that is not a regular file is refused): restrict secret files there with their ACLs.

## 2. The startup load

The signer listens at once and loads keys in the background. `/upcheck` answers `503 LOADING`, and the signing
routes `503 NOT_READY`, until the first load and the store open have finished. The startup load has no time bound;
`GET /reload` reports it as the last operation (`running`, then `completed`, `completed_with_errors` or `failed`),
and a `POST /reload` while it runs gets `409 RELOAD_IN_PROGRESS`.

## 3. Reload

`POST /reload` with the **admin** token starts a reload in the background and answers
`202 {"code":202,"message":"reload started"}`, or `409 RELOAD_IN_PROGRESS` while a load runs. The sign token gets
`403 FORBIDDEN_SCOPE`. `GET /reload` with the sign token reports the state:

| `status` | Meaning |
|---|---|
| `idle` | no load has run yet |
| `running` | a load is running |
| `completed` | every source loaded |
| `completed_with_errors` | the load was applied, but some sources failed; `lastError` is `reload completed with N key loading error(s)` |
| `failed` | nothing changed, because the new keys could not be registered in slashing protection; `lastError` is `reload failed; see the signer log` |

```
curl -s -X POST -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' localhost:9000/reload
curl -s -H "Authorization: Bearer $TOKEN" localhost:9000/reload
```

A reload reads every source again and treats each one on its own:

| The source | What the reload does |
|---|---|
| is unchanged | keeps its keys without decrypting anything |
| is new or changed | loads it; a key that is already loaded keeps its object in memory |
| fails to load | **keeps the keys it had**; its health check reports the error (section 4) |
| is gone | **evicts** its keys (section 3.1) |
| lists a quarantined key | derives the key again, which lifts the quarantine ([`metrics.md`](metrics.md#signaturefault)) |

A source is unchanged when the file itself and every keystore and password file it names have the size and
modification time they had when its keys were loaded, and its key files (the key-config file and the keystores) are
still the same files: on Linux, macOS and FreeBSD the signer also compares their device, inode number and
status-change time, so that a keystore renamed or copied over another one with the same size and time (as `tar`,
`unzip` and `cp -p` can leave two keystores) is loaded again instead of keeping the replaced key. A `chmod` of a
keystore therefore decrypts it again at the next load; a `chmod` of a password file does not. A file modified less
than two seconds before a load counts as changed at the next load too, because a file rewritten within the
timestamp granularity of its file system can keep both. Unchanged keystores are the reason a reload of 10,000
keystores with one new keystore costs one Argon2id run, not 10,000.

"Fails to load" covers every error: a file that cannot be read, invalid YAML or JSON, an unknown key, a wrong
password, a keystore the policy refuses, a password file refused by `--strict-file-permissions`, and a source not
reached before `--reload-timeout`. When a whole source kind fails (the key-config or keystore directory cannot be
listed, or the shared `--keystores-password-file` cannot be read or is refused), every key it had stays loaded and it
counts one error.

New keys are registered in slashing protection before they can sign. If that registration fails, the reload changes
nothing and ends `failed`.

A reload loads at most `GOMAXPROCS − 1` sources at once, leaving one CPU to signing, and the Argon2id semaphore
(section 6) bounds the decrypts among them. `--reload-timeout`
(minutes, default 60) bounds it: when it runs out, the sources loaded so far are applied, the others keep their
previous keys and count as errors, and the log says so. The startup load is not bounded.

### 3.1 Evicted keys

A key whose source is gone (its key-config file or keystore was removed, or its document was taken out of the file)
is evicted:

- it leaves the key set at once: `publicKeys` no longer lists it, and signing and RANDAO requests for it answer
  `404 UNKNOWN_KEY`;
- its seed and secret key are zeroized as soon as no request is using them, and its precomputed RANDAO layer is
  wiped;
- **its slashing-protection history and its `enabled` flag are not touched.** Putting its file back loads it again,
  with its history, and no import is needed.

Requests run against the key set they started with, so a reload never blocks signing and never mixes two key sets.
A request that started just before an eviction either finishes with the old key or answers `404 UNKNOWN_KEY`.

A reload never disables a key. A key whose source fails to load stays loaded and signing; only an explicit command
disables a key (section 5). Web3Signer instead disables in slashing protection every key absent from the new load,
including keys that merely failed to load ([`../../DEVIATIONS.md`](../../DEVIATIONS.md), X29).

## 4. Health checks

`/healthcheck` (with the sign token) reports one check per source kind, as Web3Signer does:

| Check | Present | `data` |
|---|---|---|
| `keys-check/config-files-loading` | always | `keys-loaded`: keys from key-config files; `error-count`: files that failed in the last load |
| `keys-check/keystores-bulk-loading` | with `--keystores-path` | `keys-loaded`: keys from the keystore directory; `error-count`: keystores that failed (1 when the whole directory failed) |

A check is `DOWN` before the first load, after a `failed` load, and while its `error-count` is above 0; `/healthcheck`
then answers 503. A failed source keeps its keys, so `keys-loaded` counts them while the check is `DOWN`. Fix the
cause and reload: the check is `UP` again when every source loads.

## 5. Disabling a validator

```
remotesigner --data-path=/var/lib/remotesigner consensus disable-validator --key=0x<public key or its sha256>
```

The command sets the key's `enabled` flag to false in the slashing-protection store. The signer then refuses
the key's blocks, attestations and new RANDAO layers with `412 VALIDATOR_DISABLED`; the other artifact types (such as
selection proofs and sync-committee messages) still sign. Use it for a key that must never sign a block or an
attestation again, for example one that has moved to another signer.

- With bbolt the signer must be stopped: the store is locked while it runs, and the command says so and changes
  nothing. With Postgres it runs online: it waits for the key's open block and attestation transactions on every
  replica, and every replica refuses the key from its next request
  ([`postgres.md`](postgres.md#6-store-commands-online)).
- The key must be registered in the store (loaded at least once); `--slashing-protection-db-url=bolt:///path` names
  another store than `<data-path>/slashing-protection.db`.
- It exits 0 and says so when the key is already disabled.

A keymanager `DELETE` disables a key the same way, with the signer running
([`keymanager.md`](keymanager.md#4-deleting-keys)). These two write `enabled=false` on purpose. The only other write
of it protects a key whose history fails to import: the keymanager `POST` and the offline `consensus import` disable
a key whose element in the file fails, so that it cannot sign without the history the file meant to give it. A
reload never writes it. Two things enable a key again: importing its keystore through the keymanager, whether the
key is loaded or not ([`keymanager.md`](keymanager.md#3-importing-keys)), and an offline `consensus import` of a file
whose element for the key imports cleanly ([`migration.md`](migration.md#2-import-the-history)), even when every
record in it is already covered. So do not import the history of a key that has moved to another signer into this
one.

Removing a key's files only evicts it (section 3.1); it does not disable it.

### 5.1 Enabling a key again

A disabled key stays disabled across restarts, reloads and evictions, on every replica. Enable it again only once no
other signer and no validator client's own keystore can sign for it: the store cannot see their history. Then, in
order of preference:

1. **Import its keystore through the keymanager** (`--key-manager-api-enabled`): `POST /qrl/v1/keystores` with the
   keystore, its password and, when the key signed elsewhere since it was disabled here, that signer's history in
   `slashing_protection` ([`keymanager.md`](keymanager.md#3-importing-keys)). The result is `imported`. This works
   whatever source loads the key: a loaded key is enabled where it is, without any file written, and a key that is
   not loaded is written to `--key-config-path` and loaded. There is no need to `DELETE` it first; a `DELETE`
   disables it again and removes the files the keymanager wrote for it.
2. **Import its history offline**, for a key without a keystore (a `file-raw` seed) or a signer without the
   keymanager: `consensus import` of an EIP-3076 file whose element for the key imports cleanly enables it, even
   when the store already holds every record in it ([`migration.md`](migration.md#2-import-the-history)). The key's
   own history serves:

   ```
   remotesigner --data-path=/var/lib/remotesigner consensus --network=<network> export --keys=<id> --to=key.json
   remotesigner --data-path=/var/lib/remotesigner consensus --network=<network> import --from=key.json
   ```

   With bbolt the signer must be stopped for both; with Postgres both run online. A key that has no history in the
   store is left out of the export (the command says so on stderr); for it, an element with empty
   `signed_blocks` and `signed_attestations` lists, under the store's genesis validators root, does the same.

The keymanager answers `imported` for the key, and the offline import counts it among the validators it imported;
from then on its blocks, attestations and new RANDAO layers no longer get `412 VALIDATOR_DISABLED`.

## 6. Memory for keystore decryption

Every keystore decrypt runs Argon2id. One process-wide semaphore admits the decrypts of the startup load and of
every reload, so that together they never hold more memory than the budget (`consensus keystore verify` sizes its
own the same way):

- **Budget.** `GOMEMLIMIT` when set; else the cgroup memory limit (`memory.max`, or `memory.limit_in_bytes` under
  cgroup v1); else half of the RAM. 512 MiB of it are kept for the rest of the process. The startup log reports the
  result, for example `Keystore decryption: at most 8 keystore decrypts at once, 3 with the standard KDF (Argon2id
  budget 1536 MiB, from GOMEMLIMIT)`.
- **Weight.** A decrypt counts twice its Argon2id memory, because Go reclaims a run's block only at the next garbage
  collection, which may come after the next run has allocated its own ([`../benchmarks.md`](../benchmarks.md), B10):
  512 MiB for the standard KDF (`m` = 256 MiB), 8 MiB for the deposit CLI's light KDF (`m` = 4 MiB).
- **Admission.** A decrypt starts while fewer than `min(GOMAXPROCS, 16)` run and the running weights fit the
  budget; one always runs, however small the budget. Decrypts start in arrival order. With the standard KDF that is
  `min(GOMAXPROCS, ⌊budget / 512 MiB⌋, 16)` at once, at least 1.
- **Override.** `--signer-load-parallelism=N` (1 to 64) admits N standard decrypts at once and sets the budget to
  N × 512 MiB, whatever the memory limit.

| Memory limit | Budget | Standard-KDF decrypts at once (8 CPUs) |
|---|---|---|
| 1 GiB | 512 MiB | 1 |
| 2 GiB | 1.5 GiB | 3 |
| 4 GiB | 3.5 GiB | 7 |
| 8 GiB or more | 7.5 GiB or more | 8 (one per CPU) |

In a container, set the container's memory limit (or `GOMEMLIMIT`, a little below it) rather than relying on half
of the host's RAM.

A standard-KDF decrypt takes about 1.5 s of one core when it runs alone, and longer when several run at once, since
they compete for cores and memory bandwidth. Size a load from the throughput, not from 1.5 s / P: on the 8-core
development machine B10 measured about 2 decrypts per second at P = 4 and at P = 8 (0.7 at P = 1), so 4,096 new
standard keystores take about 30 to 35 minutes there. B11 loaded 1,000 in 7 minutes on that machine when it was quiet,
and in 20 minutes while other work loaded it, a rate at which 4,096 take over 80 minutes
([`../benchmarks.md`](../benchmarks.md), B10 and B11). A reload that adds thousands of standard-KDF keystores can
therefore exceed the 60-minute default of `--reload-timeout`. Set it above the time the new keystores need on the
host; every "Keys loaded" log line reports the decrypts of its load and their time. A reload that runs out of time is
not lost: the keystores it loaded stay loaded and count as unchanged, so the next reload decrypts only the rest.
Light-KDF keystores take about 20 ms each; 4,096 of them load in seconds.

The 512 MiB kept out of the budget hold the loaded keys too, and each key takes about 60 KiB: on the development
machine 4,096 keys peaked at about 210 MiB of RSS and 10,000 keys at about 620 MiB
([`../benchmarks.md`](../benchmarks.md), B11). The automatic sizing does not count the keys, so above about 8,000
keys set `--signer-load-parallelism` to at most (memory limit − 512 MiB − keys × 60 KiB) / 512 MiB, so that the keys
and the running decrypts fit together.
