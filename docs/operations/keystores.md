# Keystores

A keystore holds a validator's **48-byte ML-DSA-87 wallet seed**, encrypted under a password with Argon2id and
AES-256-GCM. This page describes the two keystore formats the signer reads, the rules it applies before and while
decrypting them, how password files are read, and `remotesigner consensus keystore verify`, which checks a keystore
and its password file offline.

> In this release keystores are checked with `consensus keystore verify` only; the signer itself loads `file-raw`
> keys ([`quickstart.md`](quickstart.md)). Keystore loading at startup and on reload will go through the same
> decryptor and rules.

## 1. Formats

Both formats carry the same `crypto` section. They differ in the fields around it and in how the password becomes the
Argon2id input.

| | qrysm keystore v1 | Deposit CLI keystore |
|---|---|---|
| Written by | `validator accounts backup` (`backup.zip`, entries `keystore-<i>.json`) | `deposit new-seed` and `deposit existing-seed` (`keystore-m_12381_238_<i>_0-<time>.json`) |
| `version` | `1` | `0` |
| `pubkey` | 5,184 hex characters, no `0x` | `0x` and 5,184 hex characters |
| `description`, `path` | `"keystore"`, `""` | `""`, `m/12381/238/<i>/0` |
| Other fields | `uuid` | `uuid`; `crypto.checksum: null` and `crypto.kdf.message: ""`, both ignored |
| Password encoding | NFKD-normalised, control characters removed | raw bytes, as typed |
| KDF | Argon2id `t=8`, `m=262144` KiB (256 MiB), `p=1` | the same, or `m=4096` KiB (4 MiB) with `--lightkdf` |

```json
{
  "crypto": {
    "kdf": {"function": "argon2id", "params": {"dklen": 32, "m": 262144, "p": 1, "salt": "<64 hex>", "t": 8}},
    "cipher": {"function": "aes-256-gcm", "params": {"iv": "<24 hex>"}, "message": "<128 hex>"}
  },
  "uuid": "<uuid>",
  "pubkey": "<5184 hex>",
  "version": 1,
  "description": "keystore",
  "path": ""
}
```

`message` is the 48-byte seed followed by the 16-byte GCM tag. The `pubkey` field is optional to the signer, and
either spelling (with or without `0x`) is accepted for both formats.

Not keystores in this sense:

- qrysm's wallet file `direct/accounts/all-accounts.keystore.json` holds every key of a wallet in one encrypted blob.
  Export per-key keystores with `validator accounts backup` instead (section 5).
- go-qrl execution keystores (an `address` field, a 51-byte extended seed) are execution-layer keys.

## 2. What the signer refuses

The signer reads the keystore, then checks it before any Argon2id run, so that no file can make an Argon2id run
allocate more than 256 MiB (`m ≤ 262144` KiB) or crash the decryptor:

| Rule | Refusal |
|---|---|
| The file is at most 64 KiB of JSON with `version` 0 or 1 | malformed keystore / refused by the keystore policy |
| A KDF is present, and it is `argon2id` | refused by the keystore policy (a keystore without a KDF is never accepted) |
| `1 ≤ t ≤ 16`, `4096 ≤ m ≤ 262144` KiB, `1 ≤ p ≤ 4`, `dklen = 32` | refused by the keystore policy |
| The salt is 16 to 64 bytes of hex | refused by the keystore policy / malformed keystore |
| The cipher is `aes-256-gcm` with an IV of exactly 12 bytes and a 64-byte `message` | refused by the keystore policy / malformed keystore |
| `pubkey`, when present, is a valid 2,592-byte ML-DSA-87 public key | malformed keystore |

Then it decrypts. A wrong password and a modified ciphertext both fail GCM authentication and give the same error,
"wrong password or corrupted ciphertext". After decryption the signer derives the key pair from the seed and compares
the derived public key with `pubkey`: a keystore whose `pubkey` belongs to another key is refused ("pubkey does not
match the decrypted seed"), whatever its file name. The derived key is the one the signer serves.

Every Argon2id run with the standard KDF takes about 1.5 s of one CPU core and allocates 256 MiB; a light keystore
takes about 20 ms and 4 MiB. The memory a run frees is reclaimed only by the next garbage collection, which may come
after the next run has allocated its own block, so the process can hold about 512 MiB per running decrypt
([`../benchmarks.md`](../benchmarks.md), B10). A non-ASCII password that is wrong runs Argon2id up to three times
on the same keystore (section 3). Size memory for 512 MiB per keystore decrypted at once.

## 3. Password files

- A password file holds one password. Trailing line breaks (`\n`, `\r\n`) are removed, as qrysm and the deposit CLI
  remove them; every other character, including leading and trailing spaces, is part of the password.
- The signer tries up to three forms of the password, each once:
  1. NFKD-normalised with the C0 control characters and DEL removed: what qrysm encrypts with;
  2. an older normalisation that qrysm's own decryptor also tries;
  3. the raw bytes: what the deposit CLI encrypts with (tried first for `version: 0` keystores).

  For a printable-ASCII password the three are identical, so a keystore costs one Argon2id run. A non-ASCII password
  that is wrong costs one run per distinct form, up to three.
- Keep password files readable by the signer's user only (`chmod 0400`), next to keystores with the same mode.

## 4. Checking a keystore

```
remotesigner consensus keystore verify --file keystore-0.json --password-file keystore-0.txt
```

The command runs the signer's decryptor and rules from sections 2 and 3 on one keystore. It needs no network, store,
token or running signer. On success it prints what the signer would load and exits 0:

```
keystore-0.json: OK
  format:     qrl-v1 (version 1)
  kdf:        argon2id t=8 m=262144 KiB p=1
  pubkey:     matches the key the seed derives
  public key: 0xe7d441383d…68ab6820
  identifier: 0x68ab6820e01f105e16411b5cbf10c13814002e4bd1fd905a839095138251c9fb (sha256 of the public key)
```

The public key is shown as its first five bytes and the first four bytes of its identifier. A deposit CLI keystore
also prints its derivation `path`. When the keystore has no `pubkey` field, the `pubkey` line says so and the key
derived from the seed is the one reported.

GCM authenticates only the ciphertext: anyone who can edit a keystore file can change its `path`, `uuid` and
`description` without knowing the password. The signer therefore keeps `path` only when it is a derivation path
(`m`, then numeric components such as `m/12381/238/0/0`) and ignores any other value, and it drops control and
format characters from `uuid` and `description`, so that no keystore can write terminal escapes or extra lines into
this output or into a log.

The identifier is the SHA-256 of the public key, which the API accepts wherever it takes a key identifier
([`../contract.md`](../contract.md)), as does `consensus randao-state reset --key`. The output never shows the
password or the full public key.

A refused keystore prints the reason on standard error and exits 1, for example:

```
keystore-0.json: keystore: wrong password or corrupted ciphertext
keystore-0.json: keystore: refused by the keystore policy: KDF m=2147483648 KiB outside [4096, 262144]
keystore-0.json: keystore: pubkey does not match the decrypted seed: declared 0x13694f58d7…a64ba382, derived 0xe7d441383d…68ab6820
```

Missing or extra arguments exit 2. Every flag is in [`../reference/flags.md`](../reference/flags.md).

## 5. From a qrysm wallet

1. Export the keys: `validator accounts backup --wallet-dir <dir> --wallet-password-file <file>
   --backup-dir <out> --backup-password-file <file>`. It writes `<out>/backup.zip` with one keystore v1 per key, all
   under the backup password. With more than 25 keys, choose "All accounts" at the prompt rather than listing keys in
   `--backup-public-keys`, whose argument length is limited.
2. Unzip it. Entry names repeat across backups (`keystore-0.json`, …), so rename them (for example
   `<wallet>-keystore-<i>.json`) before putting several backups in one directory.
3. Write the backup password to a file, make it and the keystores readable by their owner only (`chmod 0400`), and
   check every keystore:

   ```
   for f in keystores/*.json; do
     remotesigner consensus keystore verify --file "$f" --password-file backup.pw || echo "REFUSED: $f"
   done
   ```

   The command checks one keystore per run, about 1.5 s each with the standard KDF, so 4,096 keystores take about
   1 h 40 min.

The wallet's stored public keys are copied into the backup as they are, not re-derived. A keystore that `verify`
refuses with "pubkey does not match" comes from a wallet whose stored key and seed disagree; do not load it.

Deposit CLI keystores are used as written; their password is the one given to the CLI.
