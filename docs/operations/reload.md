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
once, from the first, with a WARN.

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

The command sets the key's `enabled` flag to false in the bbolt slashing-protection store. The signer then refuses
the key's blocks, attestations and new RANDAO layers with `412 VALIDATOR_DISABLED`; the other artifact types (such as
selection proofs and sync-committee messages) still sign. Use it for a key that must never sign a block or an
attestation again, for example one that has moved to another signer.

- The signer must be stopped: the store is locked while it runs, and the command says so and changes nothing.
- The key must be registered in the store (loaded at least once); `--slashing-protection-db-url=bolt:///path` names
  another store than `<data-path>/slashing-protection.db`.
- It exits 0 and says so when the key is already disabled.
- This release has no command that enables a key again.

Removing a key's files only evicts it (section 3.1); it does not disable it.

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
of the host's RAM. A standard-KDF decrypt takes about 1.5 s of one core (more when several run at once; B10 found
little gain beyond four at once on an 8-core development machine), so loading N new standard keystores takes about
N × 1.5 s / P: 4,096 keystores at P = 4 take about 26 minutes, at P = 8 about 13. Light-KDF keystores take about
20 ms each; 4,096 of them load in seconds. Set `--reload-timeout` above the time a reload of the new keystores
needs.

The 512 MiB kept out of the budget hold the loaded keys too, and each key takes about 60 KiB: on the development
machine 4,096 keys peaked at about 210 MiB of RSS and 10,000 keys at about 620 MiB
([`../benchmarks.md`](../benchmarks.md), B11). The automatic sizing does not count the keys, so above about 8,000
keys set `--signer-load-parallelism` to at most (memory limit − 512 MiB − keys × 60 KiB) / 512 MiB, so that the keys
and the running decrypts fit together.
