# Fact notes

These notes record the protocol facts that go-remotesigner re-implements instead of importing qrysm, which is
GPL-3.0. Each note states facts (sizes, field orders, constants, formulas, byte layouts) and where each fact comes
from. None of them contains qrysm code, and none is a substitute for reading the cited specifications.

| Note | Implemented in | Covers |
|---|---|---|
| [ssz-containers.md](ssz-containers.md) | `internal/ssz`, `internal/consensus/types` | SSZ primitives, QRL sizes and limits, the signed containers field by field, merkleization, anchors |
| [signing-roots.md](signing-roots.md) | `internal/consensus/signingroot` | Domain types, fork selection, `compute_domain`, `compute_signing_root`, the epoch each type uses, anchors |
| [randao-onion.md](randao-onion.md) | `internal/randao/onion` | The hash-onion construction, the reveal check, vectors, and how its facts were learned |
| [network-config.md](network-config.md) | `internal/network` | Network YAML keys, presets, the named networks, the `genesis.ssz` prefix, source precedence and agreement |

## Rules for implementers

- Work from these notes and the sources they cite. Do not open qrysm's Go source while writing the code they
  describe (`CONTRIBUTING.md`, "What you may and may not bring in").
- The sources are, by licence:
  - **CC0-1.0**: the Ethereum consensus specifications at tag `v1.5.0` (including `ssz/simple-serialize.md`, which
    later moved out of that repository), the Ethereum builder specifications, and `ethereum/remote-signing-api`
    v1.4.0.
  - **Public standard**: FIPS 204 (ML-DSA), for key and signature sizes.
  - **Apache-2.0**: the Apache-headed qrysm protos (`proto/qrysm/v1alpha1/{attestation,beacon_block,sync_committee}.proto`
    and `proto/qrl/v1/*.proto`), for QRL sizes, limits and field order; Web3Signer for the HTTP shapes.
  - **MIT**: go-qrllib, for the ML-DSA wallet context and the 64-byte address size.
  - **Facts read from GPL code**: a few values exist only in qrysm's GPL Go code (network parameters, the RANDAO
    onion construction, the interop key derivation). Each note says so where it applies. Facts are not protected by
    copyright, but the notes record their origin honestly so that a reviewer can judge it, and `PROVENANCE.md` lists
    them under "Written from facts".
- Values marked *independently computed* were produced from the stated facts with a small script written for these
  notes. The golden vectors that `tools/vectorgen` generates from qrysm itself (milestone S3) confirm or replace
  them; where the two ever differ, the generated vectors win and the note is corrected.
