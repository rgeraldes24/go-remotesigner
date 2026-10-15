# QRL keystore v1 (vendored, pristine)

`go-qrl-wallet-encryptor-keystore/` is an unmodified copy of qrysm's MIT-licensed keystore v1 implementation,
kept as the reference for reviewing the hardened copy that the signer compiles (`internal/keys/keystore/qrlv1/`).

| Item | Value |
|---|---|
| Upstream path | `pkg/go-qrl-wallet-encryptor-keystore` |
| Source | `cyyber/qrysm` commit `0b9cdf251d1f022957d35c4edeb6dd3ce42a617d` (2026-10-12) |
| Git tree id | `6c97bfffa7d145c2be452fa4435c81b6c7532554`, identical in `theQRL/qrysm` main `e07a6007` |
| Licence | MIT, "Copyright (c) 2023 The Quantum Resistant Ledger" (`go-qrl-wallet-encryptor-keystore/LICENSE`) |
| Derived from | `wealdtech/go-eth2-wallet-encryptor-keystorev4` (https://github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4), Apache-2.0, "Copyright © 2019 - 2023 Weald Technology Trading"; compared against `v1.4.1` (`1067d369`) |

The QRL code is derived from Weald Technology's keystore v4 encryptor, and the Weald copyright and Apache-2.0 notices
were removed upstream. The files here are left exactly as upstream has them; the Weald notice is recorded here, in
`NOTICE` and in `PROVENANCE.md`, and any modified copy must restore it (Apache-2.0 §4(c)).

Do not edit anything in that directory: `tools/headercheck` recomputes its git tree id and fails CI on any change.
To update it, replace the directory with a newer upstream tree and record the new commit and tree id here and in
`PROVENANCE.md`.

The `go.mod` next to this file only keeps the copy out of the main module, so it is never compiled, vetted or linted
(its tests import qrysm paths). It is not part of the upstream tree. This README and that `go.mod` are project files;
`PROVENANCE.md` pins their sha256, so they too change only together with their rows there.
