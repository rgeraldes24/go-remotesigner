# Migrating validators to the signer

This page is the signer side of moving keys from a qrysm validator client with a local wallet to go-remotesigner:
import the client's slashing-protection history, fence the store with a high watermark, start the signer, verify,
and lift the fence. The qrysm side (stopping the client, exporting its keystores and history, pointing the client
at the signer) is in qrysm's documentation; the commands it needs are quoted where the order matters.

The examples use `bin/remotesigner-consensus` with `--data-path=/var/lib/remotesigner`, so the store is
`/var/lib/remotesigner/slashing-protection.db`. `--slashing-protection-db-url=bolt:///path/to/file.db` names
another file. Every command on this page except the signer itself runs **offline**: bbolt allows one process per
file, so they fail while a signer holds the store, and say so.

| Exit code | Meaning |
|---|---|
| 0 | Done |
| 1 | Refused or failed; the message says why. For `import`, at least one validator failed (see section 2) |
| 2 | Usage error: a missing or invalid flag; nothing was read or written |

## 1. Before you start

- **The old client must not sign again.** Stop it and remove the keys from its wallet (`validator accounts delete`),
  or remove them with the client's keymanager `DELETE`, which returns their history in the same step. Two signers
  holding the same keys is the one mistake slashing protection cannot repair, because neither sees the other's
  history.
- **Export the history after the last signature.** With the client stopped:
  `validator slashing-protection-history export --datadir=<wallet-dir>/direct --slashing-protection-export-dir=<dir>`
  writes `<dir>/slashing_protection.json`. The file is EIP-3076 version 5 with 2,592-byte keys; it holds every
  record the client kept, so it can be large (about 5 KB per validator plus about 160 bytes per record).
- **Both sides are on one network.** The file names its genesis validators root; the signer refuses a file from
  another network. Pass the same `--network` (and `--network-genesis-validators-root` for a file network) to the
  commands below and to the signer, and the store is pinned to it.

## 2. Import the history

```
bin/remotesigner-consensus --data-path=/var/lib/remotesigner consensus --network=<network> \
    import --from=/secure/sp/slashing_protection.json
```

`import` creates the store when it does not exist. It first reads the whole file: a document that cannot be read as
EIP-3076 version 5 (not JSON, truncated, another `interchange_format_version`, a genesis validators root that is not
32 bytes, an unknown or repeated field outside the data elements) is refused before anything is written. It then
writes the validators in batches, each batch in one transaction:

- each key is registered (a key new to the store is registered disabled, and the transaction that writes its
  history enables it, so a key never signs without its history, even when the import is interrupted), and every
  block and attestation the store does not already hold is recorded;
- a record the store already holds, or one without a signing root where the store holds any record at that slot or
  target epoch, counts as already covered;
- a record that differs from the one the store holds at the same slot or target epoch is not written and is reported
  as a conflict (the stored record keeps refusing anything else there);
- the low watermarks are raised to the lowest newly written slot and epochs, so nothing older than the imported
  history is ever signed. A watermark is never lowered.

```
imported 4096 of 4096 validator(s) into /var/lib/remotesigner/slashing-protection.db: 65536 block(s) and
2097152 attestation(s) written; 0 block(s) and 0 attestation(s) already covered; 0 block(s) and 0 attestation(s)
conflicting, not written
```

**A validator that fails to import makes the command exit 1, and its key is disabled.** An element fails when it is
not a valid entry (a public key that is not 2,592 bytes, a slot or epoch that is not a canonical decimal string, a
root that is not 32 bytes, an unknown field) or when its transaction fails. It is named on stderr by its position in
the file and its key's short id; the other validators are imported. A disabled key is refused with 412
`VALIDATOR_DISABLED` for blocks, attestations and new RANDAO layers, so it cannot sign without the history the file
meant to give it. Fix the element (or export it again from the client) and import that file: a
clean import of the key enables it again. An element without a valid public key cannot be tied to a key; it is
reported and nothing is written for it.

Importing the same file twice is harmless: the second run writes nothing and reports every record as already
covered. Importing several files (for example one per old client) merges them.

## 3. Fence the store with a high watermark

The high watermark is a global fence: no block at or above its slot, and no attestation with a source or target
epoch at or above its epoch, is signed by any key (412 `SLASHING_ABOVE_HIGH_WATERMARK`). Set it to the cut-over
point, so that the first start can be checked without any risk of a duty being signed:

```
bin/remotesigner-consensus --data-path=/var/lib/remotesigner consensus set-high-watermark --epoch=<E> --slot=<S>
```

- Both `--epoch` and `--slot` are required (`--remove` takes neither). A missing one is a usage error (exit 2).
- The fence must be above every low watermark: the slot above every validator's low-watermark slot and the epoch
  above every low-watermark source and target epoch; otherwise it is refused (exit 1). Use the current head epoch
  and slot from the beacon node.
- A store that has never been bound to a network (no import yet, never started) has nothing to fence: the command
  is refused (exit 1) instead of silently doing nothing, unless `--network` names a network with a known genesis
  validators root, which then binds the store as the signer's startup would.

The same fence protects a move **away** from this signer: set it at the epoch and slot from which the next signer
takes over, keep this signer running until then, stop it, and export (section 7).

## 4. Start the signer

Start the signer as usual ([`quickstart.md`](quickstart.md)), with the same network and store. The startup prune
(section 6) runs in the background and never lowers a watermark. Point the qrysm validator client at the signer, and
keep the client's own `validator.db` (`--datadir=<wallet-dir>/direct`): the client checks its local history again
before broadcasting, a second gate behind the signer's.

## 5. Verify

- `GET /api/v1/consensus/publicKeys` (sign token) lists every migrated key, and `/healthcheck` shows no key-loading
  errors.
- `GET /api/v1/consensus/highWatermark` (sign token) returns the fence: `{"epoch":"<E>","slot":"<S>"}`.
- The validator client's duties below the fence sign; duties at or beyond it are refused with
  `SLASHING_ABOVE_HIGH_WATERMARK` and counted in `consensus_slashingprotection_prevented_signings_total`.
- The imported history holds: a request that conflicts with an imported record is refused
  (`SLASHING_DOUBLE_VOTE`, `SLASHING_DOUBLE_PROPOSAL`, `SLASHING_SURROUNDING_VOTE`, `SLASHING_SURROUNDED_VOTE` or
  `SLASHING_BELOW_WATERMARK`).
- `consensus export --keys=<id>` (with the signer stopped) shows what the store holds for one key.

When everything checks out, stop the signer, lift the fence and start it again:

```
bin/remotesigner-consensus --data-path=/var/lib/remotesigner consensus set-high-watermark --remove
```

RANDAO needs nothing here: the reveal frontier is not part of EIP-3076, so each key's first proposal on the signer
is a first use of its onion, under the usual new-layer conditions ([`randao.md`](randao.md)).

## 6. Pruning

The signer prunes every validator in the store at startup and then every `--slashing-protection-pruning-interval`
(12 h). Each validator keeps `--slashing-protection-pruning-epochs-to-keep` (512, about 45.5 days on mainnet-preset
timing) epochs of attestations below its newest one, and as many epochs of slots, in the network's slots per epoch,
below its newest block. The low watermark is first raised to the oldest record that is kept, then older records are
deleted, so pruning never allows anything that was refused before. A large first prune after an import runs
alongside signing; benchmark B14 measures it ([`../benchmarks.md`](../benchmarks.md)).

## 7. Exporting and moving back

```
bin/remotesigner-consensus --data-path=/var/lib/remotesigner consensus --network=<network> \
    export --to=/secure/sp/remotesigner.json [--keys=<id>,<id>,...]
```

- The file always names a genesis validators root, even when the store holds no history: the store's, or, for a
  store never bound to one, the root `--network` gives. qrysm refuses a file without one.
- `--keys` takes public keys or their `0x` sha256 identifiers. qrysm imports everything in a file, so export only the
  keys being moved. A requested key the store has no history for is noted on stderr.
- Blocks are written from each validator's slot watermark up, and attestations from its target watermark up,
  whatever their source epoch; older records are left out, and a validator without a watermark has no history and
  is left out too. A watermark that no signed record sits at (after a watermark repair, section 8) is written as a
  record of its own without a signing root, and noted on stderr: the importing side takes its watermarks from the
  oldest records in the file, so it then refuses everything this signer refuses at and below them. The high
  watermark and the RANDAO frontier are not exported (EIP-3076 has no field for them).
- The file is written next to `--to` and renamed into place when complete, so a failed export leaves no partial
  file.

On the qrysm side: `validator slashing-protection-history import --datadir=<wallet-dir>/direct
--slashing-protection-json-file=<file>`, before the client starts with the keys.

## 8. No history to import

When the client's history is lost, raise the low watermarks instead, before the signer starts:

```
bin/remotesigner-consensus --data-path=/var/lib/remotesigner consensus watermark-repair --epoch=<E> --slot=<S>
```

- Every validator in the store gets the slot watermark `S` and source = target = `E`: no block at or below `S` and no
  attestation with a source below `E` or a target at or below `E` is signed (the first attestation allowed has
  source `E` or above and target above `E`). Only validators already in the store are repaired: register the keys
  first by starting the signer once with no validator client connected (it registers every key it loads), then stop
  it and repair.
- Both flags are required; a missing one is a usage error (exit 2).
- A repair that would **lower** any validator's watermark is refused as a whole (exit 1), naming how many validators
  and one of them; nothing changes. A repair above the high watermark is refused too.
- Pick `E` and `S` at or above the head: the client then misses the duties of the current epoch, which is the price
  of signing nothing the lost history might have covered. Treat this as the last resort; the import is the control.
