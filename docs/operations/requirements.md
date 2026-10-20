# Requirements and limits

This page collects the rules every deployment must follow because the signer cannot enforce them, or can enforce them
only in part: the networks it signs for, keeping a validator seed out of every other role, writing boolean flags, and
where the signer runs relative to its validator clients. The other pages assume them.

## 1. Testnet V3 only; Testnet V2 is unsupported

The signer signs for the current QRL consensus stack, the one Testnet V3 runs (the network this release targets):
ML-DSA-87 signatures under the 8-byte signing context, 64-byte execution addresses and fee recipients, and RANDAO
reveals that are layers of a hash onion ([`../spec/randao-onion.md`](../spec/randao-onion.md)).

**Testnet V2 (live since 2026-04-01) is not supported, and cannot be.** It runs an older stack whose signing context
is 4 bytes, whose addresses are 20 bytes, whose RANDAO reveal is a signature and whose containers have other shapes.
Its validators derive the same public keys from the same seeds, but no signature this signer makes verifies there,
and the signer cannot make a signature-based RANDAO reveal at all. Do not point the signer at a Testnet V2
configuration: it cannot tell one from a supported configuration, since networks are not identified by their fork
version, which Testnet V1, Testnet V2 and the old betanet share (`0x20000089`). It would start and sign messages
that the network rejects. The networks the signer
knows by name, and how to give it a configuration file, are in [`../spec/network-config.md`](../spec/network-config.md).

## 2. One seed is a validator key or an account key, never both

A validator's 48-byte seed must never also serve as an execution-layer account key: never import it into an
execution wallet, a go-qrl keystore or any signer that signs for accounts, whatever the encoding.

The consensus and execution layers sign with the same ML-DSA-87 signing context, so the two kinds of signature are
told apart only by the bytes being signed. A signer that signs a 32-byte value it is handed for an account (a
transaction hash, or a raw digest, which Web3Signer's execution mode signs) would sign a consensus signing root just
as well, and with a validator's key that signature is a block or an attestation made outside slashing protection.

The signer refuses the encodings it can recognise: in consensus mode a key must be a 48-byte wallet seed, and a
51-byte extended seed, the execution form of a key, is refused with a message saying so
([`quickstart.md`](quickstart.md#2-key-files)). An extended seed is a 3-byte descriptor followed by the 48-byte seed,
though, so this catches mistakes, not a seed deliberately loaded in both roles: that is the operator's to prevent.

## 3. Booleans take `=`: `--flag=false`, never `--flag false`

Write a boolean flag as `--flag` (true), `--flag=true` or `--flag=false`. The command-line parser (urfave/cli) does
not take the next argument as a boolean's value: in `--slashing-protection-enabled false` the `false` is an argument
of its own. Every command refuses a stray argument as a usage error (exit code 2), so the mistake stops the start
instead of leaving the flag on, but a Web3Signer command line, where `--slashing-protection-enabled` and
`--key-manager-api-enabled` take their value as the next argument, must be rewritten with `=`
([`../../DEVIATIONS.md`](../../DEVIATIONS.md), X75). In the environment and in the config file a boolean is a value,
such as `true` or `false`, as for any other flag ([`../reference/flags.md`](../reference/flags.md)).

## 4. Deploy signers next to their validator clients

Run the signer on the same local network as the validator clients it serves, and, with Postgres, the database on the
same local network as the signers. Every duty waits for a round trip to the signer, and some bodies are large:

- **Sync-committee contributions** are up to 1.2 MB of JSON each (128 signatures of 4,627 bytes, hex-encoded), and
  they are all due at once, two thirds into the slot. For 4,096 validators the estimate is about 10 MB at that
  moment, and up to about 18 MB: under 0.2 s on a 1 Gbit/s LAN, 1 to 1.5 s at 100 Mbit/s, and 8 to 15 s over a
  10 Mbit/s WAN link, which misses the deadline. The API's read timeout for one body is a quarter of the slot (15 s on
  60-second slots).
- **Attestations** of every validator with a duty in the slot are due at the same moment, a third into the slot, so
  the round-trip time adds to all of them at once.
- **RANDAO reveals** come before the block is built, so their round trip delays every proposal.
- **Postgres** adds four or five round trips between a signer and the database to every block and attestation
  ([`postgres.md`](postgres.md#5-pool-and-timeout-profile)).

The signer's own work is small by comparison: on the development machine a burst of 158 sign requests at once was
answered within about 0.3 s, and 16 contributions at once within 35 ms each ([`../benchmarks.md`](../benchmarks.md),
B7 and B8). Over a WAN the network, not the signer, decides whether duties are on time. Keep the signer's port off
the internet too: it is meant for the validator clients of one operator, behind TLS and its tokens
([`tls.md`](tls.md)).

## 5. A qrysm validator client with the remote-signer keymanager

The validator client signs through the signer with qrysm's `remote-web3signer` keymanager and its
`--validators-external-signer-*` flags (`-url`, `-key-file`, `-auth-token-file`, `-tls-ca-file`, and the client
certificate flags for mTLS). No qrysm release ships them yet: they are in review as pull requests #60 to #62 of
[`rgeraldes24/qrysm`](https://github.com/rgeraldes24/qrysm/pulls), for qrysm's `main`. Until a release has them,
build the validator client from the branch that holds all three,
[`remote-signer/q3-vc-wiring`](https://github.com/rgeraldes24/qrysm/tree/remote-signer/q3-vc-wiring). A validator
client without them stops at once with `flag provided but not defined: -validators-external-signer-url`. The v1.0
release waits for them to merge: until then this section names the review branch, and the
[release checklist](release.md#62-open-gates-this-repository-cannot-meet-today) keeps the merge as an open gate. The
validator client also checks the signer's contract version when it starts
([`upgrade.md`](upgrade.md#1-before-every-upgrade)).
