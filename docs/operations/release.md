# Releases

This page lists what a release contains, how the licence files differ per flavour, how to verify a release, how
maintainers run the release dry run and publish, and what still stands between the repository and `v1.0.0` and
`v1.1.0`. The
configuration is [`.goreleaser.yaml`](../../.goreleaser.yaml) (goreleaser v2) and the workflow
[`.github/workflows/release.yml`](../../.github/workflows/release.yml).

## 1. What a release contains

Two flavours, built from the same commit with `CGO_ENABLED=0 -trimpath`:

| Flavour | Build | Licences linked |
|---|---|---|
| `remotesigner` | default, with [execution mode](execution.md) | permissive, and go-qrl's library (LGPL-3.0-or-later), unmodified, which execution mode signs transactions with: the binary is an LGPL combined work (section 2) |
| `remotesigner-consensus` | `-tags noexecution` | permissive only, always: it never links go-qrl or any GPL or LGPL code |

| File | Content |
|---|---|
| `<flavour>_<version>_<os>_<arch>.tar.gz` | for linux and darwin, amd64 and arm64: a directory with the binary, `LICENSE`, the flavour's `NOTICE`, `LICENSES/`, `third_party_licenses/`, `README.md`, and the release's systemd unit and example configuration files in `deploy/systemd/` and `deploy/config/` ([`deploy-systemd.md`](deploy-systemd.md) installs them from there) |
| `<archive>.sbom.json` | the archive's SPDX SBOM (syft) |
| `remotesigner-<version>-src-vendored.tar.gz` | the source of the release: the tagged tree with every module the binaries link in `vendor/` (`make release-src`), go-qrl included, which rebuilds the default flavour offline with Go 1.26.5 or later (section 3) |
| `checksums.txt` | SHA-256 of every archive, SBOM and the source archive |
| `checksums.txt.sigstore.json` | the keyless cosign signature bundle of `checksums.txt` |
| `ghcr.io/rgeraldes24/<flavour>:<version>` (and `:latest` unless a pre-release) | the multi-platform image ([`deploy-docker.md`](deploy-docker.md)), with an SBOM and a SLSA provenance attestation attached, signed with cosign |

GitHub also stores a build provenance attestation for every file in `checksums.txt`.

`third_party_licenses/` is `go-licenses save` of the flavour's binary: the licence and notice files of every module it
links, under the module's path. `README.md` is the repository's, with each link to a file the archive does not hold
pointing at that file in the repository at the release's tag. The image carries the same files under
`/usr/share/doc/remotesigner/`, and its
`org.opencontainers.image.licenses` label is the SPDX expression of the licences the binary links, generated per
flavour from `go-licenses report` (for example `Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND MIT` for the
consensus flavour, and `Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND ISC AND LGPL-3.0-or-later AND MIT` for the
default one).

**go-qrl and go-licenses.** go-licenses reads go-qrl's `COPYING`, which is the GPL text, and reports go-qrl as
`GPL-3.0`; `save` would then copy the whole go-qrl module (35 MB, its GPL commands included) into every archive and
image, as the source a GPL licence asks for. go-qrl's README licenses all of go-qrl outside `cmd/` under the LGPL, and
the default flavour links only such packages. So the release tooling treats go-qrl apart:

- `third_party_licenses/github.com/theQRL/go-qrl/` holds go-qrl's `COPYING` and `COPYING.LESSER` and none of its
  source; the source goes with the release in `remotesigner-<version>-src-vendored.tar.gz`;
- the licence label names `LGPL-3.0-or-later` for it. `tools/releasedocs` corrects only a go-qrl line that
  go-licenses read from `COPYING`, and fails on go-qrl in the consensus flavour;
- `make licenses` checks the default flavour with go-qrl's packages left out (the prefix `github.com/theQRL/go-qrl/`
  ends in a slash, because go-licenses matches prefixes and the bare module path would also leave out go-qrllib) and
  then runs two tests instead: every go-qrl file the default flavour links, on every target it builds for, carries the
  LGPL notice or no GNU notice and none is under `cmd/` or `internal/`, and `LICENSES/` holds go-qrl's own LGPL and GPL
  texts. The consensus flavour is checked with no exception.

## 2. NOTICE and licence texts per flavour

[`tools/releasedocs`](../../tools/releasedocs/main.go) assembles each flavour's files from the repository
(`make release-docs`, which goreleaser runs first):

- `NOTICE`: the repository's [`NOTICE`](../../NOTICE). For the default flavour,
  [`NOTICE.execution`](../../NOTICE.execution) is appended: the go-qrl paragraph (the binary links the LGPL go-qrl
  library unmodified; where its texts and the release's corresponding source are) and the notices of the three
  modules only execution mode links (go-qrl, `holiman/uint256`, decred's `secp256k1`). The consensus flavour's NOTICE
  is the repository's NOTICE only, which never mentions the LGPL.
- `LICENSES/`: the texts in [`LICENSES/`](../../LICENSES). `GPL-3.0-or-later.txt` and `LGPL-3.0-or-later.txt`
  (go-qrl's own `COPYING` and `COPYING.LESSER`, which a test keeps equal) and `ISC.txt` ship in the default flavour
  only. Any other GNU GPL, LGPL or AGPL text, recognised by `GPL` in its file name or by its GNU title line, makes
  `make release-docs` fail until it is listed as execution-only.

The release checks (section 4) enforce the split on what was built: an archive or image of the consensus flavour
whose NOTICE mentions the LGPL, whose `LICENSES/` holds a GNU GPL, LGPL or AGPL text by either test, whatever its name,
or whose `third_party_licenses/` holds anything of go-qrl fails them, and so does an archive or image of the default
flavour without the go-qrl paragraph, both GNU texts and go-qrl's licence files, or with go-qrl source.

**The LGPL's obligations, and how a release meets them.** The default flavour is a combined work of
go-remotesigner's Apache-2.0 code and the go-qrl library. Its archives and images carry the notice that go-qrl is
used and is under the LGPL (NOTICE), the LGPL and GPL texts (`LICENSES/`), and `--version` prints the go-qrl notice
with where those texts are, in the archive and under `/usr/share/doc/remotesigner/` in the image. The corresponding
source is `remotesigner-<version>-src-vendored.tar.gz`, which builds the binary with a modified go-qrl in `vendor/`.
The image holds no source archive and ghcr.io serves none, so both say where it is: `NOTICE.execution` names the
file and its GitHub release, `https://github.com/rgeraldes24/go-remotesigner/releases/tag/v<version>`, and
`--version` prints both with the binary's own version filled in. go-qrl is never modified or copied into this
repository; if that ever changes, the copy keeps go-qrl's LGPL headers in a directory of its own.

## 3. Verifying a release

**Checksums and their signature.** The signature is keyless: it is valid only for a certificate that Sigstore issued
to this repository's release workflow running for a tag.

```
sha256sum --check --ignore-missing checksums.txt
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/rgeraldes24/go-remotesigner/\.github/workflows/release\.yml@refs/tags/v'
gh attestation verify remotesigner-consensus_<version>_linux_amd64.tar.gz --repo rgeraldes24/go-remotesigner
```

**Images.**

```
cosign verify ghcr.io/rgeraldes24/remotesigner-consensus:<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/rgeraldes24/go-remotesigner/\.github/workflows/release\.yml@refs/tags/v'
docker buildx imagetools inspect ghcr.io/rgeraldes24/remotesigner-consensus:<version> --format '{{ json .Provenance }}'
docker buildx imagetools inspect ghcr.io/rgeraldes24/remotesigner-consensus:<version> --format '{{ json .SBOM }}'
```

**The consensus flavour links no go-qrl.** `go version -m` lists every module a binary links:

```
go version -m remotesigner-consensus | grep -E 'dep\s+github.com/theQRL/go-qrl\s'    # prints nothing
go version -m remotesigner | grep -E 'dep\s+github.com/theQRL/go-qrl\s'              # the go-qrl version
```

**The source archive rebuilds the default flavour.** Offline, with the Go installed, 1.26.5 or later (the `go` line
of `go.mod`):

```
tar -xzf remotesigner-<version>-src-vendored.tar.gz
cd remotesigner-<version>-src-vendored
GOTOOLCHAIN=local CGO_ENABLED=0 GOPROXY=off go build -mod=vendor -trimpath -o remotesigner ./cmd/remotesigner
```

`GOTOOLCHAIN=local` keeps the go command on that Go: without it, a Go older than the `toolchain` line of `go.mod`
(go1.26.9) tries to download that toolchain, which `GOPROXY=off` forbids, and the build fails.

## 4. The release dry run

The dry run builds everything a release would, publishes and signs nothing, and its checks run on every pull
request (the `release-dry-run` job). Locally it needs goreleaser v2 (CI pins the version in
[`ci.yml`](../../.github/workflows/ci.yml)), go-licenses, syft for the SBOMs, and Docker with buildx:

```
make release-snapshot GO_LICENSES="$(go env GOPATH)/bin/go-licenses"     # add RELEASE_SKIP=sign,sbom without syft
make release-check
```

`make release-check` ([`test/release`](../../test/release/release_test.go)) reads `dist/artifacts.json` and checks:

- archives exist for both flavours and every target, and `checksums.txt` matches them;
- every archive holds its binary, `LICENSE`, the flavour's `NOTICE`, exactly the flavour's `LICENSES/` texts,
  `third_party_licenses/` with a licence file of every module that `go version -m` lists for the binary (and the
  module's `NOTICE` where its source has one) and the go-qrl rules of section 2, the repository's `deploy/config/` and
  `deploy/systemd/` files, and a `README.md` whose relative links all name files the archive holds;
- the source archive (`REMOTESIGNER_RELEASE_DOCS`, the `build/release` directory) holds both NOTICE files, the GNU
  texts and every module in `vendor/`, go-qrl at the version `go.mod` requires and no qrysm, holds no AppleDouble
  `._` file and no extended attribute (macOS's tar adds both unless `make release-src` turns them off), is in
  `checksums.txt`, and builds the default flavour offline from `vendor/` into a binary that links that go-qrl;
- every binary is static and trimmed; the consensus binaries are built with `noexecution` and `go version -m` lists
  no go-qrl module;
- every binary built for this machine, and every image of its architecture, reports the version goreleaser derived
  from the tag (`dist/metadata.json`): `<version> (commit <commit>, …)`, where the version is the tag without its `v`,
  and for the dry run that version followed by `-SNAPSHOT-<short commit>`;
- every archive has an SPDX SBOM (unless the dry run skipped them);
- every image (both flavours, amd64 and arm64) runs as `65532:65532` with the documented entrypoint and no
  plaintext-token override, carries its flavour's labels and the same licence and documentation files, holds a
  binary that passes the same build checks, and has `/data` owned by the nonroot user with mode `0700`;
- the images of this machine's architecture, one per flavour, pass the Docker smoke test
  ([`deploy-docker.md`](deploy-docker.md#8-building-the-image)): run hardened, with a read-only root file system and
  no capabilities, as the Docker guide runs them, they check and load a keystore, serve TLS as the nonroot user to a
  client container that pins the generated certificate, migrate a stopped signer's data volume, and refuse to start
  without a certificate, a host allowlist or a network.

`make docker-smoke` runs the same smoke test on an image `make image` builds, and `make systemd-smoke` checks the
systemd unit ([`deploy-systemd.md`](deploy-systemd.md#7-what-the-unit-restricts)).

The version comes from the ldflags of [`.goreleaser.yaml`](../../.goreleaser.yaml), `-X main.version={{ .Version }}`,
which is the tag without its `v`. To see what a tag's release would report without creating the tag:

```
make release-version RELEASE_TAG=v1.1.0 GO_LICENSES="$(go env GOPATH)/bin/go-licenses"
```

It builds every binary as the release would (`goreleaser build` with `GORELEASER_CURRENT_TAG`, into `dist/`; nothing
is tagged, archived or published) and checks that each one of this machine prints
`remotesigner version 1.1.0 (commit …)`, followed in the default flavour by go-qrl's notice (section 2), which the
consensus flavour never prints. `RELEASE_TAG` defaults to the tag of the newest version in `CHANGELOG.md`.
`make build` on a checkout of the tag reports the same version: the Makefile drops the `v` of `git describe` too
(`TestMakeBuildVersion` in `test/repo`).

## 5. Publishing

A release is published only by pushing a version tag, `v<major>.<minor>.<patch>` (with an optional pre-release
suffix, which makes a pre-release without the `latest` tags), on a commit of `main` that CI has passed. The commit
must carry the version's [`CHANGELOG.md`](../../CHANGELOG.md) entry with the tag's date in its heading
(`## [1.0.0] - 2026-11-02`), written in a pull request to `main` before the tag:

```
git tag -s v1.0.0 -m 'v1.0.0'
git push origin v1.0.0
```

The Release workflow then checks the tagged tree before it publishes anything:

1. the tagged commit is on `main` (`git merge-base --is-ancestor`); a tag on any other commit fails the job;
2. the compliance gates of CI: `make license-hash headercheck nogpl licenses` and `go vet` in both flavours;
3. the release notes: `go run ./tools/releasedocs -notes <tag>` prints the body of the tag's `CHANGELOG.md` entry,
   with its relative links pointed at the repository at the tag, and fails when the entry is missing, empty or still
   `Unreleased`; goreleaser publishes it as the release's description (`--release-notes`). `CHANGELOG.md` has entries
   for versions only, so a pre-release tag publishes its version's entry, which may still be `Unreleased`:
   `v1.0.0-rc.1` the 1.0.0 entry;
4. the dry run and its checks (section 4).

Only if they all pass does it run `goreleaser release`. It builds with a cold Go module and build cache, never one
that an earlier workflow run saved. The full test suite, lint and the vectors are not rerun: they ran on the commit
when it reached `main`. Its job is the only one with write access: `contents: write` for the GitHub release,
`packages: write` for ghcr.io, and `id-token: write` with `attestations: write` for the keyless signatures and the
provenance attestation. Every other workflow reads only.

## 6. The v1.0 release checklist

`v1.0.0` is tagged only when every item below holds. The items of section 6.1 are met in this repository: CI checks
those that a test or a make target checks on every pull request, and the others (the reviews, the comparison of the
ConsenSys lines with Web3Signer, the benchmark runs and `make release-version`) are done by hand before the tag. Those of section 6.2 need infrastructure or decisions this
repository does not have; each is recorded where the table says once it is met.

### 6.1 Met in the repository

| Item | Checked by |
|---|---|
| `CHANGELOG.md` has the 1.0.0 entry, in Keep a Changelog form | `TestChangelog` (`tools/releasedocs`) |
| `PROVENANCE.md` records every file, and every header matches its class | `make headercheck`; `TestProvenanceCoversEveryFile` (`test/repo`); by hand, the ConsenSys lines against a Web3Signer checkout (`PROVENANCE.md`, "Header classes") |
| `DEVIATIONS.md` is reviewed against the code, and its rows that show on the API are mapped in the contract | the review for 1.0.0; `make contract` |
| Every archive and image carries `LICENSE`, its flavour's `NOTICE`, `LICENSES/` and `third_party_licenses/` with the licence (and any `NOTICE`) of every module its binary links | `make release-check` (section 4) |
| The binaries of the tag `v1.0.0` report `1.0.0` | `make release-version` (section 4) by hand; in CI, `TestReleaseVersion` checks the dry run's `<version>-SNAPSHOT-<short commit>`, and `TestMakeBuildVersion` (`test/repo`) what `make build` passes for a tag |
| Every operator page exists and is linked from the README; the flag reference is current | `TestOperatorDocs` (`test/repo`); `go run ./tools/flagdoc -check` |
| The benchmarks that run on a development machine are re-run for the release | [`docs/benchmarks.md`](../benchmarks.md#v10-release-run-dev-machine), "v1.0 release run" |
| The contract's known gaps are accepted for 1.0.0: `GET …/highWatermark` and `POST /qrl/v1/keystores` answer 500 `STORE_UNAVAILABLE` when the store cannot be read, and `POST /reload` and `DELETE …/randao_state/{identifier}` answer 415 `UNSUPPORTED_MEDIA_TYPE` without `Content-Type: application/json`, statuses the frozen `1.0.0` OpenAPI does not list for them. Listing them is a contract change, which the next contract version makes together with the matching qrysm client and fixture change ([`docs/contract.md`](../contract.md#20-versioning-and-change-control) section 20) | the maintainers' review for 1.0.0; `make contract` keeps `info.version` at `1.0.0` |

### 6.2 Open: gates this repository cannot meet today

| Gate | What meets it | Recorded in |
|---|---|---|
| qrysm's remote-signer client merged | rgeraldes24/qrysm pull requests #60 to #62 (the proposal slot for RANDAO reveals, the revived `remote-web3signer` keymanager and its validator wiring) merged into qrysm, or a qrysm release that ships them; the pin of `tools/vectorgen/contract` moved to the merged commit, with `make vectors-test` and `make vectors-contract` passing; and [`requirements.md`](requirements.md#5-a-qrysm-validator-client-with-the-remote-signer-keymanager) section 5 naming that release or commit instead of the review branch. The signer's contract checks and the nightly runs above test that unmerged branch, so meeting them does not close this gate | [`tools/vectorgen/README.md`](../../tools/vectorgen/README.md#contract-pin) ("Contract pin") and `requirements.md` section 5 |
| Both nightly end-to-end runs green for 7 consecutive nights | qrysm's remote-signer scenario, `TestEndToEnd_MinimalConfig_Web3Signer`, green on seven consecutive nights against the commit to be tagged, with the qrysm validator client of [`requirements.md`](requirements.md#5-a-qrysm-validator-client-with-the-remote-signer-keymanager), in both places that run it: this repository's nightly job `qrysm-e2e` ([`nightly.yml`](../../.github/workflows/nightly.yml)), which builds the consensus flavour from the commit, runs the scenario from the qrysm ref that the repository variable `QRYSM_E2E_REF` names and uploads the signer log, the validator client logs and a metrics scrape when it fails; and qrysm CI, which runs the scenario and its hardened variant over TLS with the token. Until qrysm has the scenario and `QRYSM_E2E_REF` names it, the job only posts a notice, and scheduled runs start once the workflow is on `main` | the nightly workflow's runs and qrysm CI, linked from the release pull request |
| Benchmark B16 | A 24 h soak with 4,096 keys on a reference VM, within its threshold. It is driven by a time-compressed replay of the mainnet duty schedule, which does not exist yet and has to be written before the run | [`docs/benchmarks.md`](../benchmarks.md) |
| Reference-VM runs of B1-B15 and B18-B20 | Each benchmark on the 4-vCPU amd64 and arm64 reference VMs, with `benchstat` over at least 10 runs where it is a Go benchmark, within its threshold; the rows recorded so far are development-machine numbers. B10's memory bound needs a maintainers' decision first (its section in `docs/benchmarks.md`), and B12, which now measures signing, missed its bound on the development machine | [`docs/benchmarks.md`](../benchmarks.md) |
| The deployment guides brought up by an independent reviewer | A reviewer who did not write the code brings up a signer with [`deploy-docker.md`](deploy-docker.md) alone and with [`deploy-systemd.md`](deploy-systemd.md) alone, and the maintainers accept the documentation pull request (#22). So far the guides have been checked only by their author, reading them as a first-time reader would | the documentation pull request |
| The stacked pull requests merged into `main` | The stacked pull requests #2 to #22, from the bootstrap to the operator documentation, and the one that prepares this release, reviewed and merged into `main` in order, so that the commit to be tagged is on `main` and CI has passed it there (section 5) | the pull requests |
| The stack signed off (DCO) | [`CONTRIBUTING.md`](../../CONTRIBUTING.md#developer-certificate-of-origin-dco) asks a `Signed-off-by` of every commit, and the commits of the stacked pull requests carry none. The maintainers who merge the stack into `main` sign it off as they merge it: each squash-merge commit carries the merging maintainer's `Signed-off-by`, or the branch is rewritten with `git rebase --signoff` before a merge commit, so that every commit the tag reaches is signed off. From then on a DCO check on pull requests to `main` keeps it so | the pull requests |
| The first tag run of the Release workflow, with public ghcr.io packages | The workflow's first run for `v1.0.0` publishes the archives, `checksums.txt` with its signature and the provenance attestation, and both images; the `remotesigner` and `remotesigner-consensus` packages on ghcr.io are made public once the repository is public, so that `docker pull` works without a login; section 3 verifies the release | the GitHub release |
| Making the repository public | The maintainers' decision to make `rgeraldes24/go-remotesigner` public, taken after a secret scan of its full history finds nothing to remove; once the repository is public, qrysm CI fetches the signer without credentials ([`docs/contract.md`](../contract.md#23-access-from-qrysm-ci) section 23) | the repository settings |

Cutting the release, once section 6.2 is met: a pull request to `main` dates the 1.0.0 entry of `CHANGELOG.md` (and
moves anything listed under `Unreleased` into it); after it is merged, the tag is pushed as section 5 shows.

## 7. The v1.1 release checklist

`v1.1.0` adds execution mode and the secret stores to 1.0.0, and is tagged only after `v1.0.0` and when every item
below holds. As for 1.0.0, CI checks the items of section 7.1 that a test or a make target checks on every pull
request, and the others (the review of the register, the comparison of the ConsenSys lines with Web3Signer, the
benchmark runs and `make release-version`) are done by hand before the tag. The gates of section 7.2 need
infrastructure, decisions or a release this repository does not have; each is recorded where the table says once it
is met. Section 6.2's gates that concern the qrysm validator client, the deployment guides and the repository's
visibility are met once, for 1.0.0, and are not repeated here.

### 7.1 Met in the repository

| Item | Checked by |
|---|---|
| `CHANGELOG.md` has the 1.1.0 entry, newest first and in Keep a Changelog form: what execution mode, the secret stores and the release's source archive add, and what changes for the default flavour | `TestChangelog` (`tools/releasedocs`) |
| `PROVENANCE.md` records every file that execution mode and the secret stores add or change, every header matches its class, and the ConsenSys lines of their Web3Signer-derived files, the ported tests included, are those of the upstream files their rows name | `make headercheck`; `TestProvenanceCoversEveryFile` (`test/repo`); by hand, `ConsenSysLinesMatchUpstream` against a Web3Signer checkout (`PROVENANCE.md`, "Header classes") |
| `DEVIATIONS.md` rows X25, X26, X28, X76-X106 and X116 are reviewed against the code, and the register says which release brought them | the review for 1.1.0; `make contract` |
| The default flavour's archives and images carry the go-qrl paragraph of `NOTICE.execution` in their `NOTICE`, the LGPL and GPL texts in `LICENSES/` and go-qrl's licence files, and no go-qrl source; the consensus flavour's carry none of them, and `go version -m` lists no go-qrl module in its binaries | `make release-check` (section 4); `TestConsensusFlavourLinksNoGoQRL` and `TestNoticeSplitsFlavours` (`test/repo`) |
| The source archive, `remotesigner-<version>-src-vendored.tar.gz`, holds both NOTICE files, the GNU texts and every linked module in `vendor/`, go-qrl at the version `go.mod` requires, is listed in `checksums.txt`, rebuilds the default flavour offline, and is attached to the release next to the archives, where the default flavour's `NOTICE` says it is | `make release-check` (`TestReleaseSource`); `TestReleaseAttachesSource` (`test/repo`), for the release step the dry run skips |
| The binaries of the tag `v1.1.0` report `1.1.0`, the default flavour's followed by go-qrl's notice | `make release-version RELEASE_TAG=v1.1.0` (section 4) by hand; in CI, `TestReleaseVersion` on the dry run and `TestVersionNotice` (`cmd/remotesigner`) |
| Execution mode in front of gqrl `--dev`: a transfer is mined, the nonce retry works, a wrong chain ID, a fill that changes the request, a filled nonce far above the pending one and a fee over the cap are refused, a `qrl_sign` signature verifies with go-qrllib under the key `GET /api/v1/execution/publicKeys` lists, and the allowlist forwards `net_version` and keeps `admin_*`, `debug_*`, `personal_*` and `qrl_signTypedData` from the node | `make gqrl-e2e` (`TestGQRLDev`), the `gqrl-e2e` jobs of CI, on every pull request, and of the nightly workflow (`TestNightlyWorkflow`, `test/repo`) |
| Transaction hashes equal those of go-qrl's own `SignTx` in the golden vectors, and the message `qrl_sign` signs equals go-qrl's `accounts.TextHash` in them | `TestTransactionVectors` and `TestTextHashVectors` (`internal/execution`); `make vectors` leaves no difference |
| The secret stores read seeds from a Vault dev server and LocalStack's Secrets Manager, and their GCP and Azure clients pass against in-process fakes of those services; the consensus flavour links no cloud SDK and neither flavour a Vault SDK | `make test-cloud`, the `cloud-secrets` job of CI; `TestCloudSDKsInDefaultFlavourOnly` and `TestNoVaultSDKLinked` (`test/repo`) |
| [`execution.md`](execution.md) and the store pages ([`hashicorp-vault.md`](hashicorp-vault.md), [`aws-secrets-manager.md`](aws-secrets-manager.md), [`gcp-secret-manager.md`](gcp-secret-manager.md), [`azure-key-vault.md`](azure-key-vault.md)) exist and are linked from the README with every other operator page; the flag reference lists the execution and store flags | `TestOperatorDocs` (`test/repo`); `go run ./tools/flagdoc -check` |
| The benchmarks that run on a development machine are re-run for the release | [`docs/benchmarks.md`](../benchmarks.md#v11-release-run-dev-machine), "v1.1 release run" |

### 7.2 Open: gates this repository cannot meet today

| Gate | What meets it | Recorded in |
|---|---|---|
| `v1.0.0` released first | Section 6 met and `v1.0.0` tagged on the commit of `main` that merges the pull request preparing it (#23), before the pull requests of execution mode and the secret stores merge, so that 1.0.0 holds neither; the `[1.1.0]` link of `CHANGELOG.md` compares with that tag | the GitHub release of `v1.0.0` |
| The stacked pull requests merged into `main` | The pull requests of execution mode's JSON-RPC endpoint and proxy (#24), the secret stores (#25) and transaction signing (#26), and the one that prepares this release, reviewed and merged into `main` in order after `v1.0.0`, so that the commit to be tagged is on `main` and CI has passed it there (section 5). Before they merge, the pull request of transaction signing is squashed, or its licence-check commits reordered, so that every commit of `main` passes `make licenses` | the pull requests |
| The stack signed off (DCO) | As for 1.0.0 (section 6.2): the maintainers who merge the pull requests of execution mode and the secret stores into `main` sign them off as they merge them, so that every commit the tag reaches carries a `Signed-off-by` | the pull requests |
| The gqrl end-to-end test on the reference VMs | `make gqrl-e2e` on the 4-vCPU amd64 and arm64 reference VMs, against gqrl built from the go-qrl commit `go.mod` requires, on the commit to be tagged; so far it has run on a development machine and in CI | the release pull request |
| Both nightly end-to-end runs green for 7 consecutive nights on the 1.1.0 candidate | The end-to-end runs of section 6.2, the signer's `qrysm-e2e` job and qrysm CI's runs, against the commit to be tagged: the secret stores changed how consensus mode loads keys, so the 1.0.0 nights do not carry over; and the signer's other nightly jobs (B19, the gqrl end-to-end test, and the fuzzers of the keystore decoder, the interchange, the request decoders, the hash-tree-root differential and the network parser) green on the same nights | qrysm CI and the signer's nightly workflow, linked from the release pull request |
| An OpenAPI description of execution mode, or not | The maintainers decide whether v1.1.0 ships `api/openapi/execution.yaml`, an OpenAPI description of execution mode's JSON-RPC endpoint and `GET /api/v1/execution/publicKeys`, next to `consensus.yaml`, which the design planned for 1.1; the repository has none, and [`execution.md`](execution.md) is the only description of execution mode's interface. Either the file is written and checked as `consensus.yaml` is (`make contract`), or the decision not to ship it is recorded | the release pull request |
| The secret stores against the real services | The store tests run once against real AWS Secrets Manager, GCP Secret Manager and Azure Key Vault accounts, with each authentication mode the store pages document, and against a Vault server with Kubernetes authentication; CI has no such accounts and runs them against a Vault dev server, LocalStack and in-process fakes only | the release pull request |
| Reference-VM benchmark runs for the 1.1.0 candidate | B1-B16 and B18-B20 as section 6.2 describes them, on the commit to be tagged, with B10's memory bound decided | [`docs/benchmarks.md`](../benchmarks.md) |
| The first tag run attaches the source archive | The Release workflow's run for `v1.1.0` attaches `remotesigner-1.1.0-src-vendored.tar.gz` to the GitHub release, with its checksum in the signed `checksums.txt`, and the default flavour's image on ghcr.io carries the `LGPL-3.0-or-later` licence label; the dry run builds and checks the same files but publishes nothing | the GitHub release |

Cutting the release, once section 7.2 is met: a pull request to `main` dates the 1.1.0 entry of `CHANGELOG.md`
(and moves anything listed under `Unreleased` into it); after it is merged, `v1.1.0` is pushed as section 5 shows.
