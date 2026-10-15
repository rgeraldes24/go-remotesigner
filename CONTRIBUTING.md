# Contributing to go-remotesigner

Thank you for helping. This file covers the legal side of contributing (licence, sign-off, provenance) and the
checks every change must pass.

## Licence of contributions

go-remotesigner is licensed under the Apache License 2.0 (`LICENSE`). By contributing you agree that your
contribution is licensed under the same terms (Apache-2.0 §5). Copyright stays with the contributors, who are
collectively "The go-remotesigner Authors"; the git history records who they are. There is no contributor licence
agreement. In particular, the Consensys CLA that Web3Signer uses covers contributions to Consensys and does not
apply here.

## Developer Certificate of Origin (DCO)

Every commit must be signed off. The sign-off certifies the Developer Certificate of Origin 1.1
(https://developercertificate.org/):

> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I have the right to submit it under the open
> source license indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best of my knowledge, is covered under an
> appropriate open source license and I have the right under that license to submit that work with modifications,
> whether created in whole or in part by me, under the same open source license (unless I am permitted to submit
> under a different license), as indicated in the file; or
>
> (c) The contribution was provided directly to me by some other person who certified (a), (b) or (c) and I have not
> modified it.
>
> (d) I understand and agree that this project and the contribution are public and that a record of the
> contribution (including all personal information I submit with it, including my sign-off) is maintained
> indefinitely and may be redistributed consistent with this project or the open source license(s) involved.

Sign off by adding a trailer with your real name and an email address you can be reached at:

```
Signed-off-by: Jane Doe <jane@example.org>
```

`git commit -s` adds it for you. To sign off commits you already made on a branch, run
`git rebase --signoff origin/main` and push the branch again.

## What you may and may not bring in

- **Never copy or import GPL code from qrysm** (`github.com/theQRL/qrysm`). `depguard` rejects any qrysm import.
  SSZ, signing roots, the RANDAO onion and the network loader are written from the CC0 specifications, the
  Apache-2.0-headed protos and the facts recorded in `PROVENANCE.md`; do not open qrysm's Go source while working on
  them. Only the nested, never-shipped `tools/vectorgen` module may link qrysm.
- go-qrl (LGPL-3.0) may be imported only under `internal/execution/`, and never its `cmd/` or `internal/` packages.
- New dependencies must carry one of: Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0. CI runs
  `go-licenses check` against that list.
- Do not edit anything under `third_party/`. It holds pristine upstream copies whose git tree ids are verified.

## File headers and PROVENANCE.md

Every new or changed `.go`, `.sql`, `.yaml`/`.yml`, `.sh`, `Dockerfile*` or `deploy/**/*.json` file needs a row in
the file table of `PROVENANCE.md` and the header of its class (see "Header classes" there):

- A file you wrote for this project (class `new`):

  ```go
  // Copyright 2026 The go-remotesigner Authors.
  // SPDX-License-Identifier: Apache-2.0
  ```

- A file written while consulting a Web3Signer source file, including a ported test (class `w3s-derived`): keep the
  original `Copyright <year> ConsenSys AG.` line(s) verbatim, add our copyright line, the Apache short notice,
  `SPDX-License-Identifier: Apache-2.0`, and a line of the form "Modified by The go-remotesigner Authors, 2026:
  translated from Java to Go and adapted for QRL. Derived from `<path in Web3Signer>` at commit
  30af06dc975ba5b8ed0e17e53cba8683ca50ec02."

If your change behaves differently from Web3Signer, add a row to `DEVIATIONS.md`.

## Checks

Run these before opening a pull request; CI runs the same:

```
make build build-consensus   # static builds of both flavours
make test                    # go test -race, both flavours
make lint                    # go vet, golangci-lint (incl. depguard), headercheck, LICENSE hash
make licenses vuln           # go-licenses check, govulncheck
```

Code must be `gofmt`-clean and idiomatic Go, with table-driven tests for new behaviour.
