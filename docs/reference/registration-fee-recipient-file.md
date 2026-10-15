# Fee-recipient pin file (`--registration-fee-recipient-file`)

A `VALIDATOR_REGISTRATION` names the address that block builders pay. Anyone who can make the signer sign one can
redirect a validator's rewards, so the signer can pin a fee recipient per key: a registration for a pinned key is
signed only when its `fee_recipient` is the pinned address. Keys without a pin are not restricted. The option is off
unless the flag names a file. It is read by `internal/consensus/policy` (`LoadFeeRecipientPins`); the
`consensus` subcommand wires the flag together with the sign endpoint.

## Format

A YAML list (JSON is accepted, as YAML) of entries with exactly two keys:

```yaml
# one entry per pinned key
- key: 0x6a0520f46e95a03d3957eb79b5756ac5c57a29c57c4344c0ba4c2b19dd6fa73c
  fee_recipient: Q2b3f5c7d9e1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4
- key: 0x<5,184 hex characters of the full public key>
  fee_recipient: Q<128 hex characters>
```

| Key | Value |
|---|---|
| `key` | The key identifier, as in API paths: `0x` + 64 hex characters (`sha256` of the public key, the short form) or `0x` + 5,184 hex characters (the public key). Hex digits in either case. |
| `fee_recipient` | The 64-byte address in its `Q` form: `Q` + 128 hex characters, either case. The QIP-55 checksum is not checked. `0x` addresses are refused. |

The file is a list rather than a mapping from key to address because YAML does not allow mapping keys longer than
1,024 characters, and a full public key is 5,186.

Loading fails, so the signer refuses to start, when the file:

- is not YAML, is not a list, or is an empty list (an empty file would pin nothing, which is almost certainly a
  mistake);
- has an entry that is not a mapping, lacks `key` or `fee_recipient`, repeats one, or has any other key;
- has a malformed identifier or address;
- pins the same key twice, in either identifier form.

Errors name the line of the offending entry and never print the values.

## Behaviour

- A registration for a pinned key with a different `fee_recipient` is refused with 403 `ARTIFACT_TYPE_DISABLED`,
  before anything is signed (validation pipeline step 3, `docs/contract.md` section 7).
- The pin does not replace the other registration checks: the `pubkey` must still be the key named in the path (400
  `PUBKEY_MISMATCH`), and the `timestamp` must not be ahead of the wall clock by more than one slot (412
  `CLOCK_BOUND`).
