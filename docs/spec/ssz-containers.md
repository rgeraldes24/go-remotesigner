# SSZ containers and sizes

The signer never serialises or deserialises SSZ. It needs only `hash_tree_root` (HTR) of the objects it signs, to
recompute every signing root itself. This note lists everything that takes.

Sources:
- **[CS]** Ethereum consensus specifications, tag `v1.5.0` (CC0-1.0): `ssz/simple-serialize.md` (types,
  merkleization, JSON mapping), `specs/phase0/beacon-chain.md`, `specs/phase0/validator.md`,
  `specs/altair/validator.md`. The SSZ document was later moved to `ethereum/ssz-specs` under MIT; cite the CC0 copy
  at `v1.5.0`.
- **[BS]** Ethereum builder specifications, `specs/bellatrix/builder.md` (CC0-1.0): `ValidatorRegistrationV1`.
- **[P]** The Apache-2.0-headed qrysm protos `proto/qrysm/v1alpha1/attestation.proto`, `beacon_block.proto`,
  `sync_committee.proto` and their `proto/qrl/v1/` counterparts: QRL sizes, limits and declaration order. The
  header-less (therefore GPL) `beacon_state.proto` is **not** a source; every container it defines is either
  identical to [CS] or also declared in an Apache-headed file.
- **[F204]** FIPS 204 (ML-DSA), parameter set ML-DSA-87: public key 2,592 bytes, signature 4,627 bytes.
- **[QL]** go-qrllib (MIT): address size 64 bytes.

## 1. Primitives

From [CS] `ssz/simple-serialize.md`. `BytesN` is `Vector[byte, N]`. A *chunk* is 32 bytes.

- `pack(bytes)`: right-pad to a multiple of 32 and split into chunks.
- `merkleize(chunks, limit=None)`: pad the chunk list with zero chunks to `next_pow_of_two(limit or len(chunks))`
  leaves (at least one) and hash pairwise with SHA-256 up to a single root.
- `mix_in_length(root, n) = sha256(root ‖ uint256_le(n))`.
- Basic types and byte vectors: `HTR = merkleize(pack(serialised bytes))`.
- Lists of composite elements: `HTR = mix_in_length(merkleize([HTR(e) for e in list], limit=N), len(list))`, where
  the limit `N` counts **elements**.
- Bitlist `Bitlist[N]`: serialised with a delimiter bit set just after the last data bit. For the HTR the delimiter is
  removed: `HTR = mix_in_length(merkleize(pack(bits without delimiter), limit=(N+255)//256), bit_length)`.
- Bitvector `Bitvector[N]`: `HTR = merkleize(pack(bits), limit=(N+255)//256)`, no length mix-in.
- Container: `HTR = merkleize([HTR(field) for field in declaration order])`.

| SSZ type (QRL use) | Serialised bytes | Chunks | Padded leaves | Depth | Length mix-in |
|---|---|---|---|---|---|
| `uint64` (slot, epoch, indices, gas_limit, timestamp) | 8, little-endian | 1 | 1 | 0 | no |
| `Bytes4` (version, domain type) | 4 | 1 (right-padded) | 1 | 0 | no |
| `Bytes32` (root, domain, RANDAO commitment) | 32 | 1 | 1 | 0 | no |
| `Vector[byte,64]` (QRL address [QL]) | 64 | 2 | 2 | 1 | no |
| `Vector[byte,2592]` (ML-DSA-87 public key [F204]) | 2,592 | 81 | 128 | 7 | no |
| `Vector[byte,4627]` (ML-DSA-87 signature [F204]) | 4,627 | 145 (the last holds 19 data bytes) | 256 | 8 | no |
| `Bitlist[32]` (attestation `aggregation_bits`) | 1-5 (bits + delimiter) | 1 | 1 | 0 | yes (bit length) |
| `Bitvector[128]` (contribution bits, mainnet preset) | 16 | 1 | 1 | 0 | no |
| `Bitvector[16]` (contribution bits, minimal preset) | 2 | 1 | 1 | 0 | no |
| `List[Vector[byte,4627], 32]` (attestation `signatures`) | ≤ 148,064 | 32 | 32 | 5 | yes (count) |
| `List[Vector[byte,4627], 128]` (contribution `signatures`, both presets) | ≤ 592,256 | 128 | 128 | 7 | yes (count) |

## 2. The containers the signer hashes

`#` is the SSZ position, which is the **declaration order**, not the proto field number. "Δ" is the difference from
the Ethereum definition in [CS]/[BS].

### 2.1 `BeaconBlockHeader` (object of `BLOCK_V2`) — [CS] phase0, identical

| # | Field | Type |
|---|---|---|
| 0 | `slot` | uint64 |
| 1 | `proposer_index` | uint64 |
| 2 | `parent_root` | Bytes32 |
| 3 | `state_root` | Bytes32 |
| 4 | `body_root` | Bytes32 |

5 fields, padded to 8 leaves. `HTR(header) == HTR(BeaconBlockZond) == HTR(BlindedBeaconBlockZond)` for the same
block: both blocks have the same five fields with `body` in position 4, a header built from a block sets
`body_root = HTR(body)`, and the blinded body differs from the full body only in carrying the execution payload
header, whose HTR equals the payload's. So the header alone covers both block kinds.

### 2.2 `Checkpoint` — [CS] phase0, identical

| # | Field | Type |
|---|---|---|
| 0 | `epoch` | uint64 |
| 1 | `root` | Bytes32 |

### 2.3 `AttestationData` (object of `ATTESTATION`) — [CS] phase0, identical

| # | Field | Type |
|---|---|---|
| 0 | `slot` | uint64 |
| 1 | `index` (proto name `committee_index`) | uint64 |
| 2 | `beacon_block_root` | Bytes32 |
| 3 | `source` | Checkpoint |
| 4 | `target` | Checkpoint |

### 2.4 `Attestation` (inside `AGGREGATE_AND_PROOF`) — [CS] phase0 shape, [P] sizes

| # | Field | Type | Δ |
|---|---|---|---|
| 0 | `aggregation_bits` | Bitlist[32] | Bitlist[2048] → Bitlist[32] (a literal limit in [P], not a preset value) |
| 1 | `data` | AttestationData | none |
| 2 | `signatures` | List[Vector[byte,4627], 32] | one BLS signature → one ML-DSA signature per participant |

Invariant (not SSZ): `popcount(aggregation_bits) == len(signatures)`.

### 2.5 `AggregateAttestationAndProof` (object of `AGGREGATE_AND_PROOF`) — [CS] phase0 `AggregateAndProof`

| # | Field | Type | Δ |
|---|---|---|---|
| 0 | `aggregator_index` | uint64 | none |
| 1 | `aggregate` | Attestation | via §2.4 |
| 2 | `selection_proof` | Vector[byte,4627] | 96 → 4,627 bytes |

In `proto/qrl/v1/attestation.proto` the proto numbers are `aggregate = 3` and `selection_proof = 2`, declared in
the order above. SSZ follows the declaration order; a generator keyed on proto numbers would get this wrong.

### 2.6 `VoluntaryExit` (object of `VOLUNTARY_EXIT`) — [CS] phase0, identical

| # | Field | Type |
|---|---|---|
| 0 | `epoch` | uint64 |
| 1 | `validator_index` | uint64 |

### 2.7 `uint64` (object of `AGGREGATION_SLOT`) — [CS] phase0 validator, `compute_signing_root(slot, domain)`

HTR is the 8-byte little-endian value right-padded with zeros to 32 bytes.

### 2.8 `Bytes32` (object of `SYNC_COMMITTEE_MESSAGE`) — [CS] altair validator

The signed object is the block root itself; its HTR is the 32 bytes unchanged. Exactly 32 bytes are required: a
shorter input would be padded silently and give a different root. (The `SyncCommitteeMessage` container is not
hashed by the signer.)

### 2.9 `SyncAggregatorSelectionData` (object of `SYNC_COMMITTEE_SELECTION_PROOF`) — [CS] altair, identical

| # | Field | Type |
|---|---|---|
| 0 | `slot` | uint64 |
| 1 | `subcommittee_index` | uint64 |

`subcommittee_index < SYNC_COMMITTEE_SUBNET_COUNT`, which is 1 on every current QRL network, so it is always 0.

### 2.10 `SyncCommitteeContribution` (inside `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF`) — [CS] altair shape, [P] sizes

| # | Field | Type | Δ |
|---|---|---|---|
| 0 | `slot` | uint64 | none |
| 1 | `beacon_block_root` (proto name `block_root`) | Bytes32 | none |
| 2 | `subcommittee_index` | uint64 | none |
| 3 | `aggregation_bits` | Bitvector[SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT]: 128 bits (16 bytes) on the mainnet preset, 16 bits (2 bytes) on minimal | preset-dependent length |
| 4 | `signatures` | List[Vector[byte,4627], 128] (a literal limit in [P], the same in both presets) | per-participant list |

Invariants: `popcount(aggregation_bits) == len(signatures) > 0`; the bitvector has exactly the preset's byte length;
`subcommittee_index < SYNC_COMMITTEE_SUBNET_COUNT`.

### 2.11 `ContributionAndProof` (object of `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF`) — [CS] altair

| # | Field | Type | Δ |
|---|---|---|---|
| 0 | `aggregator_index` | uint64 | none |
| 1 | `contribution` | SyncCommitteeContribution | via §2.10 |
| 2 | `selection_proof` | Vector[byte,4627] | 96 → 4,627 bytes |

### 2.12 `ValidatorRegistrationV1` (object of `VALIDATOR_REGISTRATION`) — [BS] shape, [P] sizes

| # | Field | Type | Δ |
|---|---|---|---|
| 0 | `fee_recipient` | Vector[byte,64] | 20 → 64 bytes |
| 1 | `gas_limit` | uint64 | none |
| 2 | `timestamp` | uint64 | none |
| 3 | `pubkey` | Vector[byte,2592] | 48 → 2,592 bytes |

### 2.13 Containers used only for domains — [CS] phase0, identical

| Container | Fields in order |
|---|---|
| `Fork` (JSON `fork_info.fork`; never hashed for signing) | `previous_version` Bytes4, `current_version` Bytes4, `epoch` uint64 |
| `ForkData` | `current_version` Bytes4, `genesis_validators_root` Bytes32 |
| `SigningData` | `object_root` Bytes32, `domain` Bytes32 |

### 2.14 `DepositMessage` (v2 `DEPOSIT` only; not in v1)

Fields in order: `pubkey` Vector[byte,2592], `withdrawal_recipient` Vector[byte,64], `amount` uint64,
`randao_commitment` Bytes32. Shape from [CS] phase0 with the QRL fields of `Deposit.Data` in the Apache-headed
`beacon_block.proto` (where `randao_commitment = 5` is declared before `signature = 4`; SSZ again follows
declaration order).

## 3. Formulas

`H(a, b) = sha256(a ‖ b)`; `Zd` is the root of a zero subtree of depth `d` (`Z0` = 32 zero bytes,
`Z(d+1) = H(Zd, Zd)`); `u64(x) = le8(x) ‖ 0^24`; `vec(b) = merkleize(pack(b))`.

- `HTR(BeaconBlockHeader) = H(H(H(u64(slot), u64(proposer)), H(parent, state)), H(H(body, Z0), Z1))`
- `HTR(Checkpoint) = H(u64(epoch), root)`
- `HTR(AttestationData) = merkleize([u64(slot), u64(index), beacon_block_root, HTR(source), HTR(target)])`
- `HTR(Bitlist[32] b) = H(chunk, uint256_le(bit_length))`, where `chunk` is the data bits (delimiter cleared,
  trailing zero bytes dropped) right-padded to 32 bytes. The empty bitlist `0x01` gives `H(Z0, Z0) = Z1`.
- `HTR(List[Vector[byte,4627], N] s) = H(merkleize([vec(s_i)], limit=N), uint256_le(len(s)))`; each `vec(s_i)` is a
  depth-8 tree of 145 data chunks and 111 zero chunks; `N = 32` gives depth 5, `N = 128` depth 7.
- `HTR(Attestation) = H(H(HTR(bits), HTR(data)), H(HTR(signatures), Z0))`
- `HTR(AggregateAttestationAndProof) = H(H(u64(aggregator_index), HTR(aggregate)), H(vec(selection_proof), Z0))`
- `HTR(VoluntaryExit) = H(u64(epoch), u64(validator_index))`
- `HTR(SyncAggregatorSelectionData) = H(u64(slot), u64(subcommittee_index))`
- `HTR(SyncCommitteeContribution) = merkleize([u64(slot), root, u64(subcommittee_index), bits_chunk, HTR(signatures)])`,
  where `bits_chunk` is the 2 or 16 bitvector bytes right-padded to 32 (no mix-in)
- `HTR(ContributionAndProof) = H(H(u64(aggregator_index), HTR(contribution)), H(vec(selection_proof), Z0))`
- `HTR(ValidatorRegistrationV1) = H(H(vec64(fee_recipient), u64(gas_limit)), H(u64(timestamp), vec2592(pubkey)))`,
  with `vec64(a) = H(a[0:32], a[32:64])` and `vec2592` a depth-7 tree
- `HTR(ForkData) = H(version ‖ 0^28, genesis_validators_root)`
- `HTR(SigningData) = H(object_root, domain)`

## 4. Pitfalls

- `Vector[byte,4627]` is a vector, not a list: no length mix-in, and it pads to 256 leaves, not 145.
- List limits count elements (32, 128), not bytes or chunks of bytes.
- The bitlist chunk limit is `(N+255)//256` (1 for `N = 32`), with the bit length mixed in. Reject a missing
  delimiter (last byte `0x00`), a bit length above 32, or more than 5 bytes.
- A bitvector of 16 or 128 bits has no padding bits. Reject any byte length other than the preset's.
- SSZ order is declaration order (§2.5, §2.14).
- Every fixed-size field is length-checked exactly, including `Bytes32`.

## 5. Preset dependence

For every container the signer hashes, the HTR is the same on both presets for the same logical content: the
attestation limits and the contribution signature limit are literals in [P], and both contribution bitvector lengths
fit in one chunk (so `Bitvector[16] 0x0500` and `Bitvector[128] 0x0500…00` have the same root). The JSON validation
is preset-dependent: it must accept exactly 2 contribution-bit bytes on minimal and 16 on mainnet, taken from the
network's `PRESET_BASE` ([network-config.md](network-config.md)). `SyncAggregate` and the execution payload, which do
depend on the preset, are inside block bodies and are never hashed by the signer.

## 6. Anchors (independently computed)

| Quantity | Value |
|---|---|
| `Z1` = HTR(64 zero bytes) = HTR(`ForkData{0x00000000, 0}`) = HTR(empty `Bitlist[32]` `0x01`) | `f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b` |
| `Z5` | `9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30` |
| `Z7` = HTR(zero `Vector[byte,2592]`) | `87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c` |
| `Z8` = HTR(zero `Vector[byte,4627]`) | `26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193` |
| HTR(empty `List[sig, 32]`) | `52e2647abc3d0c9d3be0387f3f0d925422c7a4e98cf4489066f0f43281a899f3` |
| HTR(empty `List[sig, 128]`) | `96559674a79656e540871e1f39c9b91e152aa8cddb71493e754827c4cc809d57` |
| HTR(`List[sig, 32]` holding one zero signature) | `34037bca7b0d04fde7c26d17fbb52a5be433c0015e87c7acf672180578e65e36` |
| HTR(`List[sig, 128]` holding one zero signature) | `56c2e976eff8df1702d8483b48db6c7b385d7ae4a4d01af55571af6d15906923` |
| HTR(`Bitlist[32]` `0x14`: 4 bits, bit 2 set) | `3c27186a030991e3d008114becb58b249cf038d500d1323185bc899e500a9a60` |
| HTR(`Bitvector[16]` `0x0500`) = HTR(`Bitvector[128]` `0x0500…00`) | `0500000000000000000000000000000000000000000000000000000000000000` |
| HTR(`uint64` 1234) | `d204000000000000000000000000000000000000000000000000000000000000` |

Domain anchors are in [signing-roots.md](signing-roots.md).
