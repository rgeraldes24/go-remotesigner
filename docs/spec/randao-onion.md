# RANDAO hash onion

## Where these facts come from

There is no CC0 or permissively licensed specification of the QRL RANDAO construction. The facts below were
**learned by reading qrysm's `crypto/randao/onion.go`, which is GPL-3.0**, during the planning of this port (the
interop key derivation in §5 was likewise read from qrysm's GPL `runtime/interop` code). Only facts were taken: a
domain tag, a hash chain, a length and a check. No expression, structure, name or comment was copied, and the
implementation in `internal/randao/onion` is written from this note and its vectors only, by someone who does not
read `onion.go`. Its API deliberately does not mirror qrysm's (§4). `PROVENANCE.md` records the same.

If QRL publishes the construction under CC0 or a permissive licence, this section should cite that document
instead.

## 1. Construction

- **Seed.** The validator's 48-byte ML-DSA-87 wallet seed, the same secret the signer signs with. A 32-byte key
  input (for example `SHA-256(seed)`) is not enough: the onion cannot be derived from it.
- **Domain tag.** The 19 ASCII bytes `qrl-randao-onion-v1`, with no terminator and no length prefix.
- **Base.** `x_0 = SHA-256(tag ‖ seed)`. With a 48-byte seed the hash input is 67 bytes.
- **Chain.** `x_{j+1} = SHA-256(x_j)`. Every value is 32 bytes.
- **Commitment.** `x_L`, the top of an onion of `L` layers. `L` is a validator-side choice, not a consensus constant.
  qrysm's deposit tooling and interop genesis use `L = 2^20` (1,048,576), which is also the signer's default
  `--randao-max-layers`. qrysm's unit-test deposits use 256 layers; such a commitment is still found by a scan,
  because it is `x_256` of the same chain.
- **Reveal check.** A reveal `r` is valid for commitment `c` when `SHA-256(r) == c`: one hash.

## 2. On chain

- A deposit signs `randao_commitment = x_L` as part of the `DepositMessage`, so the commitment is authenticated by
  the validator key. A new validator's `randao_commitment` is set from its deposit.
- A block body carries a 32-byte `randao_reveal`. The beacon node accepts it when `SHA-256(randao_reveal)` equals the
  proposer's current `randao_commitment`, then sets the commitment to the reveal, and XORs the reveal into the
  epoch's RANDAO mix.
- So a validator whose commitment is `x_j` must reveal `x_{j-1}` for its next proposal, then `x_{j-2}`, and so on.
  The values are used from the top of the onion down; `x_0` is the last usable reveal. Once the commitment is `x_0`
  the onion is exhausted and the validator can never propose again. With `L = 2^20` and 60 s slots, one validator
  alone on a network exhausts its onion after about two years; with `N` validators it lasts about `2 × N` years.
- Nothing can rotate a commitment. Any `x_{j-1}` released early is a future contribution of that validator, known
  before its proposal: this is why the signer guards releases with the frontier rule (`docs/contract.md`,
  section 14).

## 3. Cost

- Building the commitment from the seed: `L` hashes (about 0.04-0.26 s for `L = 2^20` on current CPUs).
- Finding `j` for a commitment `c` without stored state: hash forward from `x_0` until `c` appears, keeping the
  predecessor; at most `L` hashes, and an unknown commitment always costs the full scan.
- Re-deriving a value `k` layers above a known `x_m`: `k` hashes.

## 4. API shape for `internal/randao/onion`

The Go API is chosen to differ from qrysm's exported names (the package must export none of `Origin`, `Next`,
`Verify`, `Commitment`):

| Function | Meaning |
|---|---|
| `Base(seed *[48]byte) [32]byte` | `x_0` |
| `Step(x [32]byte) [32]byte` | `SHA-256(x)`, one layer up |
| `Advance(x [32]byte, k uint64) [32]byte` | `Step` applied `k` times |
| `Top(seed *[48]byte, layers uint64) [32]byte` | `x_layers`, the commitment |
| `Find(seed *[48]byte, c [32]byte, maxDepth uint64) (j uint64, prev [32]byte, ok bool)` | the index `j ≤ maxDepth` with `x_j == c`, and `x_{j-1}` when `j ≥ 1` |

The exact signatures are the implementer's to settle; the names and the semantics are fixed here.

## 5. Vectors (independently computed)

Computed with Python's `hashlib` directly from §1. They are preliminary: milestone S3 regenerates them with
`tools/vectorgen` from qrysm's own implementation and checks them byte for byte; where they ever differ, the
generated vectors win and this note is corrected.

**V1, short chain.** seed = bytes `0x00, 0x01, …, 0x2f` (48 bytes), `L = 8`.

| Value | Hex |
|---|---|
| `x_0` | `bad1b225316b32675bd274b5f209449593995f2807dc53020ec640552ef90182` |
| `x_1` | `a7a70e5e8ec3852c1b80d42af6b59c70acaaee13d8b1e8ed257e9d1e80bdb3cf` |
| `x_7` (the reveal for commitment `x_8`) | `2084686c9a18304e24d4e10f977066bc85cc30d85bc9872faacbd7ad6ce29338` |
| `x_8` (commitment) | `e5a508b11f92cf756ee98e55604cfff7712de2d0922369ab24eb74a64e28c1ae` |

**V2, non-48-byte input to the hash construction.** seed = the 6 ASCII bytes `seed-a`, `L = 5` (exercises the
construction only; the signer itself accepts 48-byte seeds only).

| Value | Hex |
|---|---|
| `x_0` | `b44d435b1986360902040fca040b0eb9713b35ab01c8b890cdcc77e604e319a2` |
| `x_5` | `7cc43d4b182dcac4728d997d2dffefd709b5a2f4b752006b228142a2c5ab0e73` |

**V3, default length.** The V1 seed, `L = 2^20`.

| Value | Hex |
|---|---|
| `x_1023` | `7be31017d3ac2ca66321e3c018d4ea47ac3e39fdf0826d755fe12e461884e926` |
| `x_1024` | `f0f017898e20ca070ad07e8c2a72331ec950d7b688adf17b51f1e5b0db6b3c64` |
| `x_{2^20 - 1}` | `f276643d55e51c864effdc5f67588f7ba0bf1b08e7676921038446f44a5b1f2a` |
| `x_{2^20}` (commitment) | `f2f69ca0faa14d5d382ef99d1a77babeea9dabf5e57947e26231a0fe3ceb7dc3` |

**V4, interop genesis keys**, `L = 2^20`. The interop seed of validator `i` is
`SHA-256(le32(i) ‖ 0^28) ‖ 0^16` (32 hash bytes followed by 16 zero bytes). The qrysm e2e genesis gives each
validator this commitment, so the first reveal of each key in the e2e is the value below. The RANDAO example in
`api/openapi/consensus.yaml` uses index 0.

| Index | Seed | Commitment `x_{2^20}` | First reveal `x_{2^20 - 1}` |
|---|---|---|---|
| 0 | `66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925` ‖ `0^16` | `e17fb348371196a90df0e5fb286257f29c006b4527cd838dc9a2eee4e41e1ffe` | `f26304fe9b11cac1b460aef64aaf7bb11df4b1fcdee6ddb00a69fee0a80d97df` |
| 1 | `01d0fabd251fcbbe2b93b4b927b26ad2a1a99077152e45ded1e678afa45dbec5` ‖ `0^16` | `7e6c16f1b49e65ec2d592304d320adb22278e4fa65d5f07a196833aa5e18a606` | `e325859d9461bb73856233671943e8bc393dff35ea2c9c2ff77791fd0e31dab9` |
| 2 | `5778f985db754c6628691f56fadae50c65fddbe8eb2e93039633fefa05d45e31` ‖ `0^16` | `eeba5db397a66aae0998bb8e83c0b5d208b8154adaf744a3cac6d02675140722` | `ed8ea72a061c463d17e78317ad9e67842ba6081dee2cabc4221cd3db391d4465` |
| 3 | `91d3827f052f5a4b44d5fe2bed657c752247365d94f80a33cb09c1436a16b125` ‖ `0^16` | `4d730636e5d64b2de0a1c80076399e6a8529e6a9b18bc7b5ca31739ac6002ee8` | `1304155b5912b795bae0d77cee20bccb92453debc17364cd5a1ce135bad805e5` |

**V5, error cases** (signer responses, `docs/contract.md` section 14):

| Request | Expected |
|---|---|
| commitment `x_0` of the key's onion | 422 `RANDAO_ONION_EXHAUSTED` |
| a commitment from another seed, or the zero value | 422 `RANDAO_UNKNOWN_COMMITMENT` |
| `x_{L_max + 1}` with `L_max = --randao-max-layers` | 422 `RANDAO_UNKNOWN_COMMITMENT` (unless `L_max` is raised) |
| a commitment of 31 or 33 bytes | 400 `BAD_FIELD` |
