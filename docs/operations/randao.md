# RANDAO reveals

On the QRL consensus stack a block's RANDAO contribution is not a signature but a layer of the validator's hash onion
([`../spec/randao-onion.md`](../spec/randao-onion.md)). The signer holds the 48-byte seed the onion is built from and
releases one layer per proposal through `POST /api/v1/consensus/randao_reveal/{identifier}`
([`../contract.md`](../contract.md#14-randao-reveal)). This page explains what the signer allows, how to size the
limits, and how to operate the stored state.

## 1. The frontier rule

From a public commitment `x_j`, one reveal gives `x_{j-1}`, the validator's next contribution; feeding it back would
walk the onion, and a walked onion stays walked for the validator's life. A malicious beacon node behind an honest
validator client controls both the proposer duties and the commitment the client sends, so the signer never trusts
the commitment to be current. Instead it keeps, per key, in the slashing-protection store:

- `m`, the deepest layer it has released (counted from `x_0`), and `R = x_m`;
- `last`, the slot of the last release that moved the frontier.

Each request is classified against that state:

| Commitment `c` | Result (metric label) | Released | Store |
|---|---|---|---|
| no state for the key (first proposal, after a migration, a reset or a memory-store restart) | `first_use` | `x_{j-1}` after a scan from `x_0` | `(j-1, x_{j-1}, slot)` |
| `c == R` | `new_layer` | `x_{m-1}` | `(m-1, x_{m-1}, slot)` |
| `c` within `--randao-reorg-window` layers above `R` (an orphaned block, a missed proposal, a retry) | `re_reveal` | the layer under `c`, already public | unchanged |
| `c` deeper than `R` (`j < m`) | `gap_advanced` | `x_{j-1}` after a scan, with a WARN naming the key, `m` and `j` | `(j-1, x_{j-1}, slot)` |
| `c` further above `R` (a deep reorg) | `re_reveal` | after a scan | unchanged |
| `c` not in the onion | `refused` | 422 `RANDAO_UNKNOWN_COMMITMENT` | unchanged |

Every release that moves the frontier (`first_use`, `new_layer`, `gap_advanced`) must pass the **new-layer
conditions**, in this order:

1. Genesis time is known and `slot` lies in the window `[now_slot - 1, now_slot + --signing-clock-skew-slots]`,
   else 412 `RANDAO_SLOT_OUT_OF_WINDOW`.
2. `slot > last`, else 412 `RANDAO_SLOT_NOT_INCREASING`.
3. The key's new-layer bucket holds a token, else 412 `RANDAO_NEW_LAYER_RATE_LIMITED`.
4. A deeper layer exists (`c` is not `x_0`), else 422 `RANDAO_ONION_EXHAUSTED`.
5. The validator is enabled in slashing protection, else 412 `VALIDATOR_DISABLED`.

The new frontier is then committed (bbolt fsyncs) and only then is the layer returned. A response lost after the
commit is harmless: the retry is a `re_reveal` of the same layer.

**Why the window has two sides.** With only `slot > last`, a key whose last proposal was long ago could be walked by
asking for `last+1, last+2, …, now`. The lower edge allows at most `skew + 2` frontier moves in one real slot (3 with
the default skew), then one per slot.

**Why a deeper commitment advances.** Layers below `m` were never released by this signer, so whoever presents one
has read it on chain or holds a leak; releasing the next one costs a new layer under the same rules. Refusing it
would let a malicious beacon node seed a stale first use (for example with the public deposit commitment `x_L`) and
block every honest proposal afterwards. A migration, an import or a restored backup therefore needs no override: the
next honest proposal advances the frontier and raises the `RemoteSignerRandaoGapAdvanced` alert once.

**Genesis time is required.** Without it the window cannot be evaluated: only re-reveals are served, `capabilities`
reports `randao_reveal: false`, startup logs an ERROR and `keys-check/randao` is DOWN, so the qrysm validator client
refuses to start instead of missing proposals. Pass `--network-genesis-time` or `--network-genesis-state`.

## 2. Flags

| Flag | Default | Meaning |
|---|---|---|
| `--randao-new-layer-burst` | `3` | Tokens per key: frontier moves allowed in a burst |
| `--randao-new-layer-refill-epochs` | `1` | Epochs per token refill; `0` turns the bucket off |
| `--randao-reorg-window` | `1024` | Layers above `R` searched for a re-reveal before a scan |
| `--randao-max-layers` | `1048576` (`2^20`) | Layers a scan from `x_0` covers; interop genesis and qrysm's deposit tooling use `2^20` |
| `--randao-full-scan-min-interval` | `SECONDS_PER_SLOT` | Minimum time between two scans of one key, else 429 `RANDAO_SCAN_RATE_LIMITED` with `Retry-After` |
| `--randao-protection-required` | `false` | Refuse to start when the frontier would live in memory only (`--slashing-protection-enabled=false`) |
| `--signing-clock-skew-slots` | `1` | The window's upper edge |

## 3. Sizing the bucket

Each key has an in-memory token bucket: `--randao-new-layer-burst` tokens, refilled at one token per
`--randao-new-layer-refill-epochs` epochs. `first_use`, `new_layer` and `gap_advanced` take a token; re-reveals are
free. A restart refills the buckets (restarts are logged). Startup logs the effective rate.

With the window and the bucket together, a compromised validator client or beacon node that assigns fake duties to
every key extracts at most the burst plus one layer per refill period per key: about 11 layers per key per day on
the mainnet preset (60 s slots, 128-slot epochs), and every refusal is counted and alerted on.

An honest validator proposes about `SLOTS_PER_EPOCH / active validators` times per epoch, so an honest refusal needs
four or more proposals by one key within about three epochs. That is negligible on real networks, but not on very
small ones: **with fewer than about `4 × SLOTS_PER_EPOCH` active validators, raise `--randao-new-layer-burst` or turn
the bucket off with `--randao-new-layer-refill-epochs=0`.** The window still limits a bucket-less signer to one new
layer per real slot after the first burst.

## 4. Cost

No onion is built at startup, and `/upcheck` does not wait for any. A key's first reveal after a start is a scan
from `x_0` (up to `--randao-max-layers` SHA-256 calls, 0.04-0.26 s at `2^20`). After every frontier move the next
layer is computed in the background and kept in memory, so the next proposal needs no scan; re-reveals cost a few
hashes. At most `max(1, GOMAXPROCS/2)` onion computations run at once. `consensus_randao_reveal_duration_seconds{path}`
separates the fast path (`hot`) from computations from `x_0` (`scan`), and `consensus_randao_slow_path_scans_total`
counts the scans. Commitments a scan did not find are remembered (1,024 entries), so repeating one costs nothing.
A scan does not hold the key's lock: a new layer or a re-reveal for the same key is served while a scan for another
commitment runs, and the scan's result is classified against the frontier as it stands when the scan finishes.

## 5. Persistence

- **bbolt** (default): the frontier `(m, R, last)` sits in the key's record in `slashing-protection.db`, under the
  store's pinned GVR. Only one process opens the file, and every frontier move is fsynced before the reveal is sent.
- **Postgres**: the frontier is the key's row in `randao_reveal_state`, shared by every replica. Each reveal is
  classified against the row; a frontier move takes the key's RANDAO advisory lock, re-reads the row and writes it
  with a compare-and-set, and commits before the reveal is sent. A replica that loses the race to another one
  classifies the request again, usually as a re-reveal of the layer the other released; one whose own new-layer
  bucket for the key is empty refuses the request with 412 `RANDAO_NEW_LAYER_RATE_LIMITED` before it gets that
  far ([`postgres.md`](postgres.md#7-running-replicas)).
- **Protection disabled** (`--slashing-protection-enabled=false`, loopback only): the same rule runs against the
  memory store, so a restart makes every key's next reveal a first use; startup logs a WARN.
  `--randao-protection-required` refuses to start in that case.
- Never stored: the seed and the precomputed next layer, which are future reveals.
- The frontier is not part of EIP-3076 interchange; a key's first reveal on a new signer is a safe first use.

## 6. Resetting a key's state

A reset is operational cleanup only; no correctness path depends on it. The key's next reveal is a first use, still
under the new-layer conditions, and its bucket is not refilled.

Online, with the admin token (the sign token gets 403):

```
ADMIN=$(cat /var/lib/remotesigner/admin-token)
curl -s -X DELETE -H "Authorization: Bearer $ADMIN" localhost:9000/api/v1/consensus/randao_state/$ALIAS
# {"code":200,"message":"randao state cleared"}
```

The identifier is the public key or its sha256 alias. A key unknown to slashing protection gets 404 `UNKNOWN_KEY`;
with protection disabled the route answers 404 `PROTECTION_DISABLED`.

Offline, with the signer stopped:

```
bin/remotesigner-consensus --data-path=/var/lib/remotesigner consensus randao-state reset --key=$ALIAS
```

While a signer holds the bbolt store the command fails and points to the admin endpoint. With Postgres the command
runs online, against the database the replicas share (`--slashing-protection-db-url` and its password file).

## 7. Health and alerts

- `keys-check/randao` in `/healthcheck` is DOWN when genesis time is unknown or a loaded key has fewer than 1,024
  layers left; its detail shows `min-layers-remaining` (once a key has a frontier) and `keys-without-seed`.
- `consensus_randao_min_layers_remaining` is the fewest layers any loaded key has left (NaN until a key has a
  frontier). A key at 0 can no longer propose; the validator must exit.
- `RemoteSignerRandaoNewLayerRateLimited` and `RemoteSignerRandaoGapAdvanced` fire on the bucket and on a deeper
  commitment; their runbooks are in [`metrics.md`](metrics.md#4-alerts).

## 8. Upgrading the store

A store written by an older release refuses to start with a message naming `consensus migrate`. Stop the signer and
run it (a backup `<file>.v<old>.bak` is written first), or start with `--slashing-protection-db-migrate`:

```
bin/remotesigner-consensus --data-path=/var/lib/remotesigner consensus migrate
bin/remotesigner-consensus consensus migrate --slashing-protection-db-url=bolt:///var/lib/remotesigner/slashing-protection.db
```

While a signer holds the store, `consensus migrate` fails with "stop the signer first". A store written by a newer
release is always refused; downgrades are not supported. The upgrade steps, for one signer and for Postgres replicas,
are in [`upgrade.md`](upgrade.md).
