# Postgres slashing protection

The default store is a bbolt file that one signer process holds. To run two or more signers for the same keys (a
highly available pair behind one name, or replicas that fail over), give them one Postgres database instead:

```
--slashing-protection-db-url=postgres://remotesigner@db.internal:5432/remotesigner?sslmode=verify-full
--slashing-protection-db-password-file=/etc/remotesigner/db-password
```

Every check-and-record then runs in one Postgres transaction under an advisory lock on the validator, so no two
replicas can sign conflicting messages for one key, and the store commands (import, export, watermark repair, high
watermark, RANDAO reset, disabling a key) run online while the replicas sign.
[`deploy/config/postgres-ha.yaml`](../../deploy/config/postgres-ha.yaml) is a complete replica configuration.

## 1. Requirements

- PostgreSQL 13 or later (tested with 17). The database holds nothing but the signer's tables.
- TLS to the server, with `sslmode=verify-full` and the server's CA in `sslrootcert=` or `~/.postgresql/root.crt`.
  The connection carries every signing decision.
- Two roles: an owner that creates the schema, and the role the signers connect as, which may read and write rows
  but not change the schema (section 2).
- Connections: 17 per replica (a pool of 16 for signing and one for pruning) and one per running store command;
  three replicas need 51, well inside the default `max_connections` of 100.

## 2. Setting up the database and its roles

As a superuser, on any database of the server, create the two roles and the database:

<!-- postgres-roles:server -->
```sql
CREATE ROLE remotesigner_owner LOGIN;
CREATE ROLE remotesigner LOGIN;
CREATE DATABASE remotesigner OWNER remotesigner_owner;
REVOKE ALL ON DATABASE remotesigner FROM PUBLIC;
GRANT CONNECT ON DATABASE remotesigner TO remotesigner_owner, remotesigner;
```

Give both roles a password (`\password remotesigner` in `psql`, or your secret manager's provisioning) and keep each
in a file readable by its user only. Then, still as the superuser but connected to the new database
(`\connect remotesigner`), give its schema to the owner and keep everyone else from creating objects in it:

<!-- postgres-roles:database -->
```sql
ALTER SCHEMA public OWNER TO remotesigner_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO remotesigner;
```

Create the schema as the owner (section 3), and then, as the owner, grant the signers' role what it needs and
nothing more:

<!-- postgres-roles:grants -->
```sql
GRANT SELECT, INSERT, UPDATE ON validators, low_watermarks, metadata TO remotesigner;
GRANT SELECT, INSERT, DELETE ON signed_blocks, signed_attestations TO remotesigner;
GRANT SELECT, INSERT, UPDATE, DELETE ON randao_reveal_state TO remotesigner;
GRANT SELECT ON database_version TO remotesigner;
GRANT USAGE ON SEQUENCE validators_id_seq, signed_blocks_id_seq, signed_attestations_id_seq TO remotesigner;
```

The signers' role cannot create, alter or drop anything, cannot change the schema version, and cannot delete a
validator. The store commands of section 6 run as the same role. The tests of `internal/slashing/pgstore` run these
three blocks as written and then sign, import, prune and export as the signers' role.

## 3. Creating and upgrading the schema: `consensus migrate`

```
remotesigner consensus migrate \
    --slashing-protection-db-url=postgres://remotesigner_owner@db.internal:5432/remotesigner?sslmode=verify-full \
    --slashing-protection-db-password-file=/etc/remotesigner/db-owner-password
# Postgres database "remotesigner" on db.internal:5432: slashing-protection schema version 1 created
```

- The schema is versioned in the `database_version` table. A signer refuses to start on a database without the
  schema, or with an older one, with a message that names `consensus migrate`; a database written by a newer
  release is always refused ("downgrade is not supported"). A database with tables this release did not create,
  such as a Web3Signer database, is refused too: export its history with Web3Signer and import the EIP-3076 file
  (section 6).
- `consensus migrate` holds the session lock `pg_advisory_lock(3, 0)` while it reads and upgrades the schema, and
  runs each migration in its own transaction. Running it again is harmless: "already at schema version 1; nothing
  to do".
- Upgrading replicas to a release that changes the schema means stopping all of them before the migration, since a
  signer checks the version only when it starts ([`upgrade.md`](upgrade.md#4-postgres-replicas)).
- `--slashing-protection-db-migrate` on `consensus` migrates at startup instead. Several replicas started together
  then migrate once: the others wait for the lock and find the schema current. It needs a role that may create
  tables, which the signers' role of section 2 is not, so the least-privilege setup runs `consensus migrate` as the
  owner before the upgraded signers start.
- The schema is one squashed QRL schema, not Web3Signer's twelve migrations: validators are keyed by the SHA-256 of
  their 2,592-byte public key (a raw key is too long for a B-tree index), slots and epochs are `BIGINT` with
  `CHECK (>= 0)`, Web3Signer's high-watermark triggers are kept, and `randao_reveal_state` holds the RANDAO
  frontiers. Slots and epochs above 2^63 − 1 do not fit a `BIGINT`: the store refuses them before they reach the
  database, and a signing request for one fails with 500 `STORE_UNAVAILABLE` (with bbolt it would be recorded).

## 4. Connecting

- `--slashing-protection-db-url` takes `postgres://` or `postgresql://` with libpq's parameters
  (`sslmode`, `sslrootcert`, `connect_timeout`, `application_name`, `target_session_attrs`, …). Web3Signer's
  `jdbc:postgresql://host:port/database` is accepted and rewritten to `postgresql://`; JDBC-only parameters are not
  translated.
- `--slashing-protection-db-username` replaces the URL's user name.
- The password comes from `--slashing-protection-db-password-file` (its first line; the file must be readable by its
  owner only unless `--strict-file-permissions=false`), else from libpq's password file (`PGPASSFILE`, by default
  `~/.pgpass`, or the URL's `passfile=`), under the same rule: a password found there in a file that its group or
  other users can read is refused, or used with a warning under `--strict-file-permissions=false` (libpq would
  ignore such a file). The entry is looked up for the user `--slashing-protection-db-username` names, when it is
  set. A password in the URL, `PGPASSWORD` in the environment, and a `password` in the `pg_service.conf` entry of a
  connection service (`service=` or `PGSERVICE`) are refused at startup: they put the password where other
  processes and logs can see it, or in a file nothing checks. There is no `--slashing-protection-db-password` flag.
- Messages name the database as `Postgres database "<name>" on <host>:<port>`, never with credentials.

## 5. Pool and timeout profile

The profile is fixed; a `pool_*` parameter in the URL is refused.

| Setting | Value | Why |
|---|---|---|
| Signing pool | 16 connections, 2 kept open | a 33-transaction burst at the attestation deadline runs in two waves; idle slots do not pay for connection setup |
| Pruning pool | 1 connection | pruning never takes a connection signing needs |
| One store call | 4.5 s, acquiring a connection and every retry included | a stalled database fails the signing request with 500 `STORE_UNAVAILABLE` before the API's 5 s write deadline |
| Store commands (section 6) | 1 connection, 10 min per call | a command makes one call at a time; an online import writes each validator's whole history in one call |
| Connecting | 5 s | |
| `lock_timeout` | 2 s | a check-and-record that waits longer for a validator's lock fails instead of queueing |
| `statement_timeout` | 5 s | |
| `idle_in_transaction_session_timeout` | 10 s | a client that stalls mid-transaction releases its locks |
| Retries | up to 5 runs of a transaction that fails with SQLSTATE 40001 (serialisation failure) or 40P01 (deadlock detected) | |

Advisory locks: `pg_advisory_xact_lock(type, validator_id)` with type 0 for blocks, 1 for attestations and 2 for
RANDAO frontiers, always taken in that order. Disabling a key takes its block and then its attestation lock;
import, pruning and the watermark repair take both for each validator they write, validator by validator in the
order of the SHA-256 of the keys, so no two transactions can wait on each other in a cycle.

A check-and-record is five round trips for an attestation and four for a block (`BEGIN`, the lock and the read of
the validator's flag and watermarks travel together), so the network's round-trip time adds to its latency four or
five times over: keep the database close to the replicas. Benchmark B13 measures it
([`../benchmarks.md`](../benchmarks.md#postgres-slashing-protection-b13-b14-internalslashingpgstore)).

### Health check

`/healthcheck` reports `slashing-protection-db-health-check`, as Web3Signer does: a query bounded by
`--slashing-protection-db-health-check-timeout-milliseconds` (3,000) alone, not by the 4.5 s call bound (a server
that answers still ends a query after `statement_timeout`, 5 s), run at startup and every
`--slashing-protection-db-health-check-interval-milliseconds` (30,000). The check reports the last result, so it
turns `DOWN` at most one interval after the database stops answering, and `UP` again one interval after it is back;
the transitions are logged. Signing does not wait for the check: each request finds the database's state itself.

## 6. Store commands online

With Postgres the store commands run while the replicas sign, under the same locks; they take the same
`--slashing-protection-db-url`, `--slashing-protection-db-username` and `--slashing-protection-db-password-file`.

| Command | With Postgres |
|---|---|
| `consensus import --from=<file>` | One validator per transaction: a validator's locks are held only while its history is written. A key the import adds is registered disabled and enabled by the transaction that writes its history ([`migration.md`](migration.md#2-import-the-history)). Writing a history takes two or three round trips per record, so 10,000 attestations take from a few seconds to tens of seconds depending on the round-trip time, and a signing request for that key that waits longer than `lock_timeout` for its locks meanwhile fails with 500 `STORE_UNAVAILABLE`: import a key's long history while it is not due to sign, or with the replicas stopped. |
| `consensus export --to=<file>` | One consistent snapshot (`REPEATABLE READ`, read only), taken without locks. |
| `consensus watermark-repair --epoch --slot` | Batches of 64 validators per transaction. |
| `consensus set-high-watermark` | Waits for every check-and-record that read the old high watermark, so that once it returns no message decided under the old one is still to be recorded. It locks the `metadata` table first, so check-and-records that start meanwhile wait behind it (for `lock_timeout` at most) and steady signing cannot starve it. When a transaction that read the old high watermark runs longer than `lock_timeout` (an import writing a long history, say), it fails with nothing changed: run it again. |
| `consensus randao-state reset --key` | Online; the next reveal for the key, on any replica, is a first use. |
| `consensus disable-validator --key` | Waits for the key's open block and attestation transactions on every replica; from the next request every replica refuses the key's blocks, attestations and new RANDAO layers with 412 `VALIDATOR_DISABLED`. A replica's response cache can still answer an exact repeat of a signature it released before, for the cache's lifetime (two epochs): that is the same message again, not a new one. |
| `consensus migrate` | Section 3. |

## 7. Running replicas

- **Same everything.** Every replica runs with the same configuration file, key-config files or keystores, token
  files and certificate. Validator clients pin the certificate and send the sign token, whichever replica answers.
- **Reloads never write `enabled`.** A reload, or a replica starting, registers keys it has not seen with
  `INSERT … ON CONFLICT DO NOTHING` and never writes an existing key's row. A replica whose reload fails for a key
  (an unreadable password file, say) keeps its previous keys, and the key stays enabled for every replica; only
  `disable-validator`, a failed import of the key, or the keymanager API disables it.
- **RANDAO.** Every reveal is classified against the key's row, not against anything a replica remembers, and
  every frontier move re-reads the row under the key's RANDAO lock and compares it before it writes. A request two
  replicas serve for the same slot is answered by one as a new layer and by the other as a re-reveal of the same
  layer; a replica that lost the race classifies the request again instead of failing. The loser checks its own
  new-layer bucket before its compare-and-set, though: when it read the row before the winner committed and its
  bucket for the key is empty, it answers 412 `RANDAO_NEW_LAYER_RATE_LIMITED` instead (next point). A replica
  remembers only the next layer it precomputed, for the index it was computed for, and ignores it once the row has
  moved.
- **The new-layer bucket is per replica.** The bucket that bounds frontier moves per key
  (`--randao-new-layer-burst`, `--randao-new-layer-refill-epochs`; [`randao.md`](randao.md#3-sizing-the-bucket))
  lives in each replica's memory, so N replicas allow up to N times the rate when an attacker can reach all of them.
  The one-per-slot rule (`slot > last`) and the two-sided slot window are global, because `last` lives in the
  shared row, so walking stays bounded by one layer per real slot. Lower the burst if that matters for your
  deployment.
- **The slow-path scan budget and the negative cache are per replica too**, and so is the response cache.
- **Pruning.** Each replica prunes every `--slashing-protection-pruning-interval` (12 h), one validator per
  transaction on its one-connection pool, and not at startup: replicas that start together would otherwise all
  prune at once. After each transaction the run rests for as long as the transaction took, so a run takes at most
  half of the database's time from signing (35 s for 4,096 validators in the steady state on the development
  machine, benchmark B14). Pruning is idempotent, so replicas pruning the same database only repeat each other's work.
- **Clocks.** The slot window and the bucket read each replica's clock; keep them synchronised (NTP).
- **Failover** needs nothing from the store: the next request on another replica finds the same rows.
- **PgBouncer** has not been tested. Advisory transaction locks work in its transaction mode; the store also uses
  prepared statements, which need PgBouncer 1.21 or later there.

## 8. Backups

Use the server's own tools: `pg_dump`, or continuous archiving with point-in-time recovery. Restoring a backup
loses every record signed after it, which slashing protection then cannot refuse: before replicas sign from a
restored database, fence it with `consensus set-high-watermark` above the last epoch and slot they may have signed,
or import the history the validator clients kept. RANDAO frontiers need nothing: a restored, older frontier is
healed by the next honest proposal ([`backup.md`](backup.md#4-why-an-old-backup-is-safe-for-randao)).
