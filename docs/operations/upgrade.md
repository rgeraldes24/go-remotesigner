# Upgrading

This page covers moving a running signer to a new release: what to check first, the rule that ties a release to
the schema of its slashing-protection store, the steps for one signer (systemd or Docker) and for Postgres replicas,
and going back to an older release. Moving validators to the signer from a qrysm validator client is a different
task, described in [`migration.md`](migration.md).

## 1. Before every upgrade

- **Read the release notes.** They say when a release changes the store's schema (section 2), removes or renames a
  flag, or changes the HTTP contract with the validator client.
- **Check the release** ([`release.md`](release.md#3-verifying-a-release)): its checksums and their signature, or the
  image's signature.
- **Back up the store** ([`backup.md`](backup.md#1-taking-a-backup) for bbolt,
  [`postgres.md`](postgres.md#8-backups) for Postgres). An upgrade that changes the schema keeps its own copy of a
  bbolt file, but a backup of your own is what lets you go back (section 5).
- **Check the configuration.** Unknown keys in the config file, and unknown flags, refuse the start with exit code 2,
  so a flag that a release removes stops the signer instead of being ignored; the systemd unit does not restart after
  exit code 2. `remotesigner --version` prints the release a binary is.

The validator client checks the major of the signer's contract version (`api_version` in `capabilities`) at its
start and refuses one it does not support ([`../contract.md`](../contract.md#16-capabilities-and-api_version)). Releases
with the same contract major work with the same validator clients
([`../contract.md`](../contract.md#20-versioning-and-change-control)); the release notes say when a release needs a
newer qrysm client.

## 2. The schema-version rule

Each release reads and writes exactly one version of the slashing-protection store's schema, and the store records
the version that wrote it: `meta/schema_version` in a bbolt file, the `database_version` table in Postgres. This
release uses version 1, the first schema of both backends. At startup the signer compares the two:

| The store's version | At startup |
|---|---|
| the release's | the signer starts |
| older | refused, exit code 1: `slashing-protection store has schema version <n>, this remotesigner expects <m>: run "remotesigner consensus migrate" to upgrade it`. With `--slashing-protection-db-migrate` the signer migrates first instead. |
| newer | always refused: `… written by a newer remotesigner (this one expects <m>); downgrade is not supported` |

`consensus migrate` brings a store to the release's version, one step per schema version:

- **bbolt** runs offline: the signer holds the file's lock while it runs, so the command refuses ("stop the signer
  first"). Before it changes anything it copies the file to `<file>.v<old version>.bak` (mode `0600`, never over an
  existing backup), and all steps run in one transaction, so a failed migration leaves the file at its old version.
- **Postgres** runs online, under the session lock `pg_advisory_lock(3, 0)`, each step in its own transaction, and
  needs a role that may create and alter tables: the schema owner, not the signers' role
  ([`postgres.md`](postgres.md#3-creating-and-upgrading-the-schema-consensus-migrate)).
- A store already at the release's version is left alone: `… is already at schema version 1; nothing to do`. Running
  it on every upgrade of a stopped signer is therefore safe, and section 3 does; for Postgres replicas, section 4
  says when.
- A store of a newer version is refused, as at startup.

Every schema change in a later release ships its migration and a test that upgrades a store of the version before.
Neither EIP-3076 interchange files nor the HTTP contract depend on the schema version.

## 3. One signer

The signer is down from the stop to the next `200 OK` from `/upcheck`: plan the upgrade between the validators'
duties, as for a backup.

**systemd** ([`deploy-systemd.md`](deploy-systemd.md)): install the new binary over the old one (`install` replaces
the file, which the running process does not notice), stop the service, migrate the store as the service user with
the service's configuration, and start it again:

```
sudo install -m 0755 remotesigner-consensus_<version>_linux_amd64/remotesigner-consensus /usr/local/bin/remotesigner
sudo systemctl stop remotesigner
sudo -u remotesigner remotesigner --config-file=/etc/remotesigner/remotesigner.yaml consensus migrate
sudo systemctl start remotesigner
journalctl -u remotesigner -n 20
```

**Docker** ([`deploy-docker.md`](deploy-docker.md)): stop and remove the old container, run the new image's
`consensus migrate` on the same `/data` volume, and start the new image with the same volume and arguments:

```
docker stop signer && docker rm signer
docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges -v signer-data:/data \
  ghcr.io/rgeraldes24/remotesigner-consensus:<version> consensus migrate
docker run -d --name signer … ghcr.io/rgeraldes24/remotesigner-consensus:<version> …   # as before
```

The tokens, the generated TLS certificate and the store live in the data directory or volume, so the validator
clients need no change: they keep the pinned certificate and the sign token. RANDAO needs nothing either: the
frontiers are in the store, and the per-key new-layer buckets start full after any restart.

## 4. Postgres replicas

Run the new release's `consensus migrate` as the schema owner, never with `--slashing-protection-db-migrate` on the
signers, whose role cannot change the schema ([`postgres.md`](postgres.md#2-setting-up-the-database-and-its-roles)).

- **The schema version stays** (the release notes say so, or a replica of the new release starts cleanly): upgrade
  the replicas one at a time, each as in section 3 without the migration, waiting for `/upcheck` to answer `200 OK`
  before the next. The others keep signing meanwhile, so the validators see no gap.
- **The schema version changes:** a signer checks the version only when it starts, so a replica of the old release
  that is still running would keep using the database after its schema changed. Stop every replica, run
  `consensus migrate` once as the owner, then start the new release on every replica:

  ```
  remotesigner consensus migrate \
      --slashing-protection-db-url=postgres://remotesigner_owner@db.internal:5432/remotesigner?sslmode=verify-full \
      --slashing-protection-db-password-file=/etc/remotesigner/db-owner-password
  ```

  To find out without reading the notes, start one replica of the new release while the others run: if the schema
  changed it refuses to start with the message of section 2, and changes nothing.

## 5. Going back to an older release

Without a schema change, install the older binary or image and restart it; nothing else changes.

After a schema change the older release refuses the store ("downgrade is not supported"). To go back, give it a
store of its own version that holds the history signed since:

1. Stop the signer, or every replica.
2. With the **new** release, export the history: `consensus export --to=<file>`
   ([`migration.md`](migration.md#7-exporting-and-moving-back)).
3. Restore the store taken before the upgrade: for bbolt the backup `consensus migrate` wrote (`<file>.v<old>.bak`)
   or your own; for Postgres the server's backup.
4. With the **old** release, import the file: `consensus import --from=<file>`. The import only adds records and
   raises watermarks, so the restored store again refuses everything the new release signed.
5. Redo what the file does not carry. The import enables every key whose history it imports cleanly, so disable
   again, with `consensus disable-validator`, every key that was disabled when you stopped; and set the high
   watermark again (`consensus set-high-watermark`) if there was one. RANDAO frontiers need nothing
   ([`backup.md`](backup.md#4-why-an-old-backup-is-safe-for-randao)).
6. Start the older release.

Never start an older release on a copy of the store from before the upgrade without step 4: it would not know the
blocks and attestations signed since, and could sign a second, slashable one ([`backup.md`](backup.md#3-the-gap-after-an-old-backup)).
