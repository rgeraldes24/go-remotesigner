# Backing up and restoring the bbolt store

The signer's state is the bbolt slashing-protection store, `<data-path>/slashing-protection.db` by default (or the
file `--slashing-protection-db-url=bolt:///…` names). It holds, under the network's pinned genesis validators root:

- every validator's signed blocks and attestations and its low watermarks, which slashing protection checks;
- each validator's enabled flag;
- each validator's RANDAO frontier `(m, R, last)` ([`randao.md`](randao.md#5-persistence));
- the global high watermark, and the schema version.

Keys, tokens and configuration live elsewhere and are backed up with them; the store holds no secret. A Postgres
store is backed up with the server's own tools ([`postgres.md`](postgres.md#8-backups)).

## 1. Taking a backup

The file is the backup unit. bbolt is crash-safe: every commit is fsynced, and a file cut at any instant opens to
the last committed transaction. A backup must therefore be **a consistent point-in-time copy**, which a plain copy
of a file that is being written is not.

- **Signer stopped (simplest).** Stop the signer (SIGTERM; it drains requests and closes the store), copy the file,
  start the signer:

  ```
  systemctl stop remotesigner
  install -m 0600 /var/lib/remotesigner/slashing-protection.db /backup/slashing-protection-$(date -u +%Y%m%dT%H%M%SZ).db
  systemctl start remotesigner
  ```

  The signer is down for as long as the copy takes (a 4,096-validator store with 512 epochs of history is about
  400 MiB). Plan it between duties.
- **Signer running.** Take an atomic file-system snapshot (LVM, ZFS, Btrfs, or a cloud volume snapshot) of the
  volume that holds the file, and copy the file out of the snapshot. The snapshot is the state a crash would have
  left, which bbolt recovers from. Do not `cp` or `rsync` the live file: a commit during the copy can mix pages of two
  transactions.
- **Portable history.** `consensus export --to=<file>` (offline) writes the blocks and attestations as EIP-3076
  ([`migration.md`](migration.md#7-exporting-and-moving-back)). It is the format to move history to another signer or
  back to a qrysm validator client, but it is not a full backup: it leaves out the enabled flags, the high watermark,
  the RANDAO frontiers and records below the low watermarks.

`consensus migrate` keeps its own backup, `<file>.v<old>.bak`, before it upgrades the schema.

Keep backups with the same care as the live store, and keep several: a backup is only as useful as it is recent
(section 3).

## 2. Restoring

1. Stop the signer, and make sure no other signer holds the keys.
2. Put the backup in place as the store file, mode 0600, owned by the signer's user:

   ```
   install -m 0600 -o remotesigner /backup/slashing-protection-20261016T120000Z.db \
       /var/lib/remotesigner/slashing-protection.db
   ```

3. **Close the gap since the backup was taken** (section 3), before the signer starts.
4. Start the signer. It refuses a file pinned to another network (a different genesis validators root), a file
   written by a newer release, and an older schema until `consensus migrate` has run.

## 3. The gap after an old backup

A backup does not know what the signer signed after it was taken. A restored store would let a validator sign a
second, different block or attestation for a duty it already signed: a slashable offence. Before the restored
signer signs, give the store that history back, in order of preference:

1. **Import the validator client's history.** The qrysm client keeps its own `validator.db` and checks it before
   broadcasting. Stop the client, export its history (`validator slashing-protection-history export`), and
   `consensus import --from` it into the restored store. The import only adds records and raises low watermarks.
2. **Raise the watermarks to the present.** `consensus watermark-repair --epoch=<E> --slot=<S>` with `E` and `S` at or
   above the chain head refuses everything the gap could hold. It costs the duties of the current epoch
   ([`migration.md`](migration.md#8-no-history-to-import)). It never lowers a watermark, so it is safe to run on a
   backup that turns out to be recent.

Keys that were disabled after the backup (keymanager `DELETE`, `consensus disable-validator`) come back enabled from
an older backup, and an import enables every key whose history it imports cleanly, those disabled before the backup
included ([`migration.md`](migration.md#2-import-the-history)). Disable them again, or remove them from the key
configuration, before starting.

## 4. Why an old backup is safe for RANDAO

The RANDAO reveal needs no repair. The frontier stored with each key, `m` and `R = x_m`, is the deepest onion layer
this signer has released, and layers are released from the top of the onion down. A backup holds an older frontier:
`m_backup` is at or above the true deepest released layer `m`. After the restore:

- The chain's current commitment for the key is `x_m`, deeper than the restored `R`. The signer classifies it as
  `gap_advanced`: it releases `x_{m-1}`, the honest next layer, under the new-layer conditions, and moves the frontier
  there. `RemoteSignerRandaoGapAdvanced` fires once to say so.
- Every layer between `m` and `m_backup` is already public: each was revealed in a block on chain. Serving one of
  them again (to a reorg, or to a beacon node that presents a stale commitment) reveals nothing new.
- No layer below `m` can be obtained more cheaply than before the restore. A new layer still needs a commitment at the
  frontier, a slot in the two-sided window, a slot above `last`, and a token, so the walking bound of
  [`randao.md`](randao.md#3-sizing-the-bucket) holds.

The frontier never moves up, and a restore can only move it up. The worst a restore does to RANDAO is make the next
proposal a scan instead of a cached step. The same argument covers a restore of a store whose frontiers were reset,
and a migration, where the first reveal is a first use.

## 5. Checking a backup

Open a copy, never the live file, with the offline commands, which take the file's lock:

```
cp /backup/slashing-protection-20261016T120000Z.db /tmp/check.db
bin/remotesigner-consensus consensus --slashing-protection-db-url=bolt:///tmp/check.db export --to=/tmp/check.json
```

The export succeeds only on an intact store of this release's schema, and its validators and records show what the
backup holds.
