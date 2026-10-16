# RANDAO hash onion: facts

This note states the facts that `internal/randao/onion` implements, and nothing else. It is the only input the
implementer of that package works from, together with the vectors below. It is deliberately not a description of
any existing implementation.

## Provenance

- QRL has not published the hash-onion construction as a specification. The facts below were **learned by reading
  qrysm's `crypto/randao/onion.go`** (GPL-3.0) during the design of this project. Only these facts (a domain tag, a
  derivation, a default length and a check) were taken, and the Go package that implements them was written from this
  note without opening that file. Its names are its own. The first draft did not fully achieve that: it reused
  qrysm's `DefaultLayers` (the design had named the default length after qrysm's constant) and the unexported name
  `domainTag`, and two of its doc comments were phrased close to qrysm's. Review found these and they were renamed and
  reworded. The body of `Base` is the one idiomatic Go form of `SHA-256(tag ‖ seed)` and resembles qrysm's for that
  reason.
- The test vectors were computed independently, with Python's `hashlib`, directly from the facts below. They are data,
  not code. V2 reuses the seed and length of qrysm's own onion test, so the cross-check against qrysm also covers
  qrysm's test case; its expected value was still computed here from the facts. The golden vectors later regenerated
  them with `tools/vectorgen` from qrysm's `crypto/randao` at the pinned commit
  (`testdata/vectors/randao/onion.json`), and every value matched; the signer's tests check the package against the
  generated file.
- If QRL publishes the construction under a permissive licence, this note will cite it instead. Whether QRL
  would publish the construction under CC0 or a permissive licence is an open question.

## Notation

- `‖` is byte concatenation. `SHA-256` is FIPS 180-4 SHA-256, output 32 bytes.
- `seed` is the validator's 48-byte wallet seed: the same secret the ML-DSA-87 key is derived from, **not** the
  32-byte `SHA-256(seed)` that the key generator consumes. A key whose 48-byte seed is not held cannot produce reveals.
- All onion values ("layers") are 32 bytes.

## Facts

1. **Domain tag.** `tag` is the 19 ASCII bytes `qrl-randao-onion-v1`
   (hex `71726c2d72616e64616f2d6f6e696f6e2d7631`), with no length prefix and no terminator.
2. **Base layer.** `x_0 = SHA-256(tag ‖ seed)`.
3. **Step.** `x_{j+1} = SHA-256(x_j)` for every `j ≥ 0`. Each step hashes exactly the 32 bytes of the previous layer.
4. **Commitment.** For an onion of length `L`, the commitment is `x_L`. It is fixed at deposit time and stored on
   chain as the validator's `randao_commitment` (32 bytes).
5. **Default length.** `L = 2^20 = 1,048,576`. Interop genesis uses this length.
6. **Reveal.** A block proposal reveals the pre-image of the validator's current commitment: for a current
   commitment `c = x_j` with `j ≥ 1`, the reveal is `r = x_{j−1}`.
7. **Check.** A reveal `r` is valid for a commitment `c` exactly when `SHA-256(r) = c`.
8. **Rotation.** After an accepted reveal, the validator's commitment becomes `r`. The next proposal therefore reveals
   one layer deeper, `x_{j−2}`, and so on.
9. **Exhaustion.** `x_0` has no pre-image inside the onion. A validator whose commitment is `x_0` cannot propose
   with this onion. With `L = 2^20` this takes 2^20 proposals.

## Consequences used by the signer

These follow from the facts; they are stated here so the implementation needs nothing else.

- Layers are indexed from the base: `x_j` is reached from `x_0` with `j` steps. A layer's index is its distance from
  the base, so a deeper layer has a smaller index.
- Walking is one-way. From `x_j`, any higher layer `x_{j+k}` costs `k` steps; a lower layer cannot be computed without
  the seed.
- Locating a commitment `c` in the onion of `seed` means stepping from `x_0` until the value equals `c`. Bounding the
  walk at a maximum length `L_max` bounds the cost at `L_max` steps; a commitment not reached within `L_max` steps is
  treated as not belonging to the onion.
- The reveal for a commitment at index `j` is the value one step before it, so a scan from `x_0` that keeps the
  previous value finds both the index and the reveal in one pass.

## Test vectors

`seed0` is the 48 bytes `0x00, 0x01, …, 0x2f`. All values are hex.

| ID | Inputs | Expected |
|---|---|---|
| V1 | `seed0`, `L = 8` | `x_0 = bad1b225316b32675bd274b5f209449593995f2807dc53020ec640552ef90182`<br>`x_1 = a7a70e5e8ec3852c1b80d42af6b59c70acaaee13d8b1e8ed257e9d1e80bdb3cf`<br>`x_7 = 2084686c9a18304e24d4e10f977066bc85cc30d85bc9872faacbd7ad6ce29338`<br>`x_8 = e5a508b11f92cf756ee98e55604cfff7712de2d0922369ab24eb74a64e28c1ae` (commitment); the reveal for `x_8` is `x_7` |
| V2 | the 6 ASCII bytes `seed-a` as the seed (the derivation does not depend on the seed length), `L = 5` | `x_5 = 7cc43d4b182dcac4728d997d2dffefd709b5a2f4b752006b228142a2c5ab0e73` |
| V3 | `seed0`, `L = 2^20` | `x_1023 = 7be31017d3ac2ca66321e3c018d4ea47ac3e39fdf0826d755fe12e461884e926`<br>`x_1024 = f0f017898e20ca070ad07e8c2a72331ec950d7b688adf17b51f1e5b0db6b3c64`<br>`x_{2^20−1} = f276643d55e51c864effdc5f67588f7ba0bf1b08e7676921038446f44a5b1f2a`<br>`x_{2^20} = f2f69ca0faa14d5d382ef99d1a77babeea9dabf5e57947e26231a0fe3ceb7dc3` (commitment) |

The signer only ever passes 48-byte seeds; V2 exercises the derivation with a shorter input.

## Signer-level additions

The sections below were added with the HTTP contract (`docs/contract.md`). They are **not** inputs to
`internal/randao/onion`, which was written from the sections above only. They record what the signer, its
contract and its tests need around that package.

### Provenance of the additions

- The interop seed derivation (V4) was **learned by reading qrysm's `runtime/interop` key generation** (GPL-3.0).
  The onion lengths used by qrysm's deposit tooling, interop genesis and unit-test helpers (below) were likewise
  read from qrysm's GPL code. Only these facts were taken. The V4 and V5 values were computed independently with
  Python's `hashlib` from the facts in this note.
- The golden vectors later regenerated V4 and V5 with `tools/vectorgen` (`testdata/vectors/randao/interop.json`
  and `requests.json`): the V4 values matched, and each commitment equals the one qrysm's interop genesis stores for
  its validator.

### Onion length in practice

- The protocol checks a single hash per proposal, so the number of layers is never part of the consensus rules:
  each validator picks it when it builds the commitment for its deposit.
- qrysm's deposit tooling and its interop genesis both build `2^20`-layer onions, which is why the signer's
  `--randao-max-layers` defaults to `2^20`. qrysm's unit-test helpers use 256 layers; a scan from `x_0` still
  finds such a commitment, since it is `x_256` of the same chain.
- With `L = 2^20` and 60 s slots, a validator alone on a network uses up its onion after about two years of
  proposing every slot; with `N` validators it lasts about `2 × N` years.
- Cost: building a commitment is `L` hashes (about 0.04-0.26 s for `L = 2^20` on current CPUs). Locating an unknown
  commitment without stored state costs up to `L_max` hashes, and a commitment that is not in the onion always costs
  the full `L_max`.
- A deposit's `DepositMessage` includes `randao_commitment`, so the deposit signature authenticates it. The beacon
  node XORs each accepted reveal into the epoch's RANDAO mix. A layer released before its proposal is therefore a
  future RANDAO contribution known in advance; the signer's frontier rule (`docs/contract.md`, section 14) limits
  such releases.

### Package names

`internal/randao/onion` uses its own names: `Base` (`x_0`), `Step` (one layer up), `Advance` (`k` steps up), `Top`
(the commitment `x_L`) and `Find` (the index `j ≤ L_max` with `x_j = c`, and `x_{j−1}` when `j ≥ 1`). The exact Go
signatures, including whether a seed is passed as a slice or an array, are the implementer's choice. The package
exports none of the names `Origin`, `Next`, `Verify`, `Commitment` or `DefaultLayers`.

### V4, interop genesis keys

The interop seed of validator `i` is `SHA-256(le32(i) ‖ 0^28) ‖ 0^16`: 32 hash bytes followed by 16 zero bytes,
48 bytes in all. The qrysm e2e genesis gives each validator the `L = 2^20` commitment of this seed, so the first
reveal of each key in the e2e is the value below. The RANDAO example in `api/openapi/consensus.yaml` uses index 0.

| Index | First 32 seed bytes | Commitment `x_{2^20}` | First reveal `x_{2^20−1}` |
|---|---|---|---|
| 0 | `66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925` | `e17fb348371196a90df0e5fb286257f29c006b4527cd838dc9a2eee4e41e1ffe` | `f26304fe9b11cac1b460aef64aaf7bb11df4b1fcdee6ddb00a69fee0a80d97df` |
| 1 | `01d0fabd251fcbbe2b93b4b927b26ad2a1a99077152e45ded1e678afa45dbec5` | `7e6c16f1b49e65ec2d592304d320adb22278e4fa65d5f07a196833aa5e18a606` | `e325859d9461bb73856233671943e8bc393dff35ea2c9c2ff77791fd0e31dab9` |
| 2 | `5778f985db754c6628691f56fadae50c65fddbe8eb2e93039633fefa05d45e31` | `eeba5db397a66aae0998bb8e83c0b5d208b8154adaf744a3cac6d02675140722` | `ed8ea72a061c463d17e78317ad9e67842ba6081dee2cabc4221cd3db391d4465` |
| 3 | `91d3827f052f5a4b44d5fe2bed657c752247365d94f80a33cb09c1436a16b125` | `4d730636e5d64b2de0a1c80076399e6a8529e6a9b18bc7b5ca31739ac6002ee8` | `1304155b5912b795bae0d77cee20bccb92453debc17364cd5a1ce135bad805e5` |

### V5, signer error cases

Responses of `POST /api/v1/consensus/randao_reveal/{identifier}` (`docs/contract.md`, section 14):

| Request | Expected |
|---|---|
| commitment `x_0` of the key's onion | 422 `RANDAO_ONION_EXHAUSTED` |
| a commitment from another seed, or the zero value | 422 `RANDAO_UNKNOWN_COMMITMENT` |
| `x_{L_max + 1}` with `L_max = --randao-max-layers` | 422 `RANDAO_UNKNOWN_COMMITMENT` (unless `L_max` is raised) |
| a commitment of 31 or 33 bytes | 400 `BAD_FIELD` |
