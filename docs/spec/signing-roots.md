# Signing roots and domains

Sources:
- **[CS]** Ethereum consensus specifications, tag `v1.5.0` (CC0-1.0), `specs/phase0/beacon-chain.md`:
  `compute_fork_data_root`, `compute_domain`, `get_domain`, `compute_signing_root` and the domain constants;
  `specs/phase0/validator.md` and `specs/altair/validator.md` for which object and epoch each duty signs.
- **[BS]** Ethereum builder specifications (CC0-1.0): the builder domain for validator registrations.
- QRL network parameters (genesis fork versions, slots per epoch) are recorded in
  [network-config.md](network-config.md).

## 1. Functions

From [CS], unchanged for QRL:

- `compute_fork_data_root(version, gvr) = HTR(ForkData{current_version: version, genesis_validators_root: gvr})`
  `= sha256(version ‖ 0^28 ‖ gvr)`.
- `compute_domain(domain_type, version, gvr) = domain_type ‖ compute_fork_data_root(version, gvr)[0:28]`
  (32 bytes).
- `get_domain(fork, domain_type, epoch, gvr)`: `version = fork.previous_version if epoch < fork.epoch else
  fork.current_version`, then `compute_domain(domain_type, version, gvr)`.
- `compute_signing_root(object, domain) = HTR(SigningData{object_root: HTR(object), domain})`
  `= sha256(HTR(object) ‖ domain)`.

The signer evaluates `get_domain` over **its own** configured fork schedule, never over client data. QRL networks
have a single fork: the schedule holds only `{previous_version: G, current_version: G, epoch: 0}` with
`G = GENESIS_FORK_VERSION`, so `previous_version` is never selected for any epoch ≥ 0. The generic rule is
implemented anyway, so a future fork needs no new code path.

## 2. Domain types

The values equal Ethereum's ([CS] phase0 and altair, [BS]). They are 4-byte sequences written as hex, so
`0x01000000` is the bytes `01 00 00 00`.

| Constant | Value | Used by |
|---|---|---|
| `DOMAIN_BEACON_PROPOSER` | `0x00000000` | `BLOCK_V2` |
| `DOMAIN_BEACON_ATTESTER` | `0x01000000` | `ATTESTATION` |
| `DOMAIN_RANDAO` | `0x02000000` | nothing: RANDAO is a hash-onion reveal on the target stack ([randao-onion.md](randao-onion.md)) |
| `DOMAIN_DEPOSIT` | `0x03000000` | `DEPOSIT` (v2 only, not in v1) |
| `DOMAIN_VOLUNTARY_EXIT` | `0x04000000` | `VOLUNTARY_EXIT` |
| `DOMAIN_SELECTION_PROOF` | `0x05000000` | `AGGREGATION_SLOT` |
| `DOMAIN_AGGREGATE_AND_PROOF` | `0x06000000` | `AGGREGATE_AND_PROOF` |
| `DOMAIN_SYNC_COMMITTEE` | `0x07000000` | `SYNC_COMMITTEE_MESSAGE` |
| `DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF` | `0x08000000` | `SYNC_COMMITTEE_SELECTION_PROOF` |
| `DOMAIN_CONTRIBUTION_AND_PROOF` | `0x09000000` | `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` |
| `DOMAIN_APPLICATION_BUILDER` | `0x00000001` | `VALIDATOR_REGISTRATION` |

Domain types are constants of the protocol, not network configuration: they do not appear in the network YAML.

## 3. Per type: object, domain and epoch

`epoch(slot) = slot // SLOTS_PER_EPOCH`.

| Type | Object (see [ssz-containers.md](ssz-containers.md)) | Domain | Fork version chosen at | GVR |
|---|---|---|---|---|
| `BLOCK_V2` | `BeaconBlockHeader` | `DOMAIN_BEACON_PROPOSER` | `epoch(header.slot)` | bound GVR |
| `ATTESTATION` | `AttestationData` | `DOMAIN_BEACON_ATTESTER` | `data.target.epoch` | bound GVR |
| `AGGREGATION_SLOT` | `uint64 slot` | `DOMAIN_SELECTION_PROOF` | `epoch(slot)` | bound GVR |
| `AGGREGATE_AND_PROOF` | `AggregateAttestationAndProof` | `DOMAIN_AGGREGATE_AND_PROOF` | `epoch(aggregate.data.slot)` | bound GVR |
| `VOLUNTARY_EXIT` | `VoluntaryExit` | `DOMAIN_VOLUNTARY_EXIT` | `exit.epoch` (plain `get_domain`; no EIP-7044 pin to a fixed fork) | bound GVR |
| `SYNC_COMMITTEE_MESSAGE` | `Bytes32 beacon_block_root` | `DOMAIN_SYNC_COMMITTEE` | `epoch(slot)` | bound GVR |
| `SYNC_COMMITTEE_SELECTION_PROOF` | `SyncAggregatorSelectionData` | `DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF` | `epoch(slot)` | bound GVR |
| `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` | `ContributionAndProof` | `DOMAIN_CONTRIBUTION_AND_PROOF` | `epoch(contribution.slot)` | bound GVR |
| `VALIDATOR_REGISTRATION` | `ValidatorRegistrationV1` | `DOMAIN_APPLICATION_BUILDER` | none: always `GENESIS_FORK_VERSION` | 32 zero bytes |
| (v2) `DEPOSIT` | `DepositMessage` | `DOMAIN_DEPOSIT` | none: `GENESIS_FORK_VERSION` | 32 zero bytes |

The registration and deposit domains depend only on the network's genesis fork version. QRL mainnet's placeholder
`GENESIS_FORK_VERSION` is `0x00000000`, the same as Ethereum mainnet's, so those two domains are byte-identical to
Ethereum mainnet's (harmless across chains because the key types differ, but a reason never to reuse `0x00000000`
for another QRL network).

## 4. Anchors (independently computed)

`compute_fork_data_root(G, 0^32)` and the genesis-only domains for each named network's fork version:

| Network | `GENESIS_FORK_VERSION` | `compute_fork_data_root(G, 0)` | DEPOSIT domain | APPLICATION_BUILDER domain |
|---|---|---|---|---|
| mainnet (placeholder) | `0x00000000` | `f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b` | `03000000f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9` | `00000001f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9` |
| minimal | `0x00000001` | `18ae4ccbda9538839d79bb18ca09e23e24ae8c1550f56cbb3d84b05331fff401` | `0300000018ae4ccbda9538839d79bb18ca09e23e24ae8c1550f56cbb3d84b053` | `0000000118ae4ccbda9538839d79bb18ca09e23e24ae8c1550f56cbb3d84b053` |
| end-to-end | `0x000000fd` | `2c3c06efe6456ca45340ee2bf169ae9fcd41f600b9cd0a54cbe6b47239979645` | `030000002c3c06efe6456ca45340ee2bf169ae9fcd41f600b9cd0a54cbe6b472` | `000000012c3c06efe6456ca45340ee2bf169ae9fcd41f600b9cd0a54cbe6b472` |
| end-to-end-mainnet | `0x000000fe` | `c73bfd082b705da602272cd8ee18fb3bd3caac1a8a80338ce585947ad37b157c` | `03000000c73bfd082b705da602272cd8ee18fb3bd3caac1a8a80338ce585947a` | `00000001c73bfd082b705da602272cd8ee18fb3bd3caac1a8a80338ce585947a` |
| interop | `0x000000eb` | `72b77772929e99a4044717cc4506b0f0d1b45f2a80020ea5eddfbd49bd43948c` | `0300000072b77772929e99a4044717cc4506b0f0d1b45f2a80020ea5eddfbd49` | `0000000172b77772929e99a4044717cc4506b0f0d1b45f2a80020ea5eddfbd49` |

The mainnet DEPOSIT domain `03000000f5a5fd42…31a9` is also Ethereum mainnet's, a well-known value that anchors the
whole chain of functions.

Worked example (end-to-end network, GVR
`0x7a1e2c4d5b6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809` as in the OpenAPI examples), an
`AGGREGATION_SLOT` request for slot 61:

| Step | Value |
|---|---|
| object root `HTR(uint64 61)` | `3d00000000000000000000000000000000000000000000000000000000000000` |
| domain `compute_domain(0x05000000, 0x000000fd, GVR)` | `05000000b8e25631e1df7e6cbf073dcd2459a5baa6a3649d070d4be0de51066e` |
| signing root | `489e15e8bcf803c483b1efdff3bf2832f9ee2dbd4154e0f5257168d2a14b3284` |

The `AGGREGATION_SLOT` example in `api/openapi/consensus.yaml` carries this signing root, and a contract test
recomputes it.

## 5. The signature over the root

The message signed is the 32-byte signing root, unhashed, with ML-DSA-87 through the go-qrllib wallet API, which
applies the FIPS 204 context `"ZOND" ‖ 0x01 ‖ descriptor` (`5a4f4e4401010000` for descriptor `0x010000`). A signature
made with an empty context does not verify in qrysm.
