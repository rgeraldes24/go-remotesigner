# Releases

This page lists what a release contains, how the licence files differ per flavour, how to verify a release, how
maintainers run the release dry run and publish, and what still stands between the repository and `v1.0.0`. The
configuration is [`.goreleaser.yaml`](../../.goreleaser.yaml) (goreleaser v2) and the workflow
[`.github/workflows/release.yml`](../../.github/workflows/release.yml).

## 1. What a release contains

Two flavours, built from the same commit with `CGO_ENABLED=0 -trimpath`:

| Flavour | Build | Licences linked |
|---|---|---|
| `remotesigner` | default | permissive only today; execution mode will add go-qrl (LGPL-3.0-or-later) to this flavour only |
| `remotesigner-consensus` | `-tags noexecution` | permissive only, always: it never links go-qrl or any GPL or LGPL code |

| File | Content |
|---|---|
| `<flavour>_<version>_<os>_<arch>.tar.gz` | for linux and darwin, amd64 and arm64: a directory with the binary, `LICENSE`, the flavour's `NOTICE`, `LICENSES/`, `third_party_licenses/`, `README.md`, and the release's systemd unit and example configuration files in `deploy/systemd/` and `deploy/config/` ([`deploy-systemd.md`](deploy-systemd.md) installs them from there) |
| `<archive>.sbom.json` | the archive's SPDX SBOM (syft) |
| `checksums.txt` | SHA-256 of every archive and SBOM |
| `checksums.txt.sigstore.json` | the keyless cosign signature bundle of `checksums.txt` |
| `ghcr.io/rgeraldes24/<flavour>:<version>` (and `:latest` unless a pre-release) | the multi-platform image ([`deploy-docker.md`](deploy-docker.md)), with an SBOM and a SLSA provenance attestation attached, signed with cosign |

GitHub also stores a build provenance attestation for every file in `checksums.txt`.

`third_party_licenses/` is `go-licenses save` of the flavour's binary: the licence and notice files of every module it
links, under the module's path. `README.md` is the repository's, with each link to a file the archive does not hold
pointing at that file in the repository at the release's tag. The image carries the same files under
`/usr/share/doc/remotesigner/`, and its
`org.opencontainers.image.licenses` label is the SPDX expression of the licences the binary links, generated per
flavour from `go-licenses report` (for example `Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND MIT`).

## 2. NOTICE and licence texts per flavour

[`tools/releasedocs`](../../tools/releasedocs/main.go) assembles each flavour's files from the repository
(`make release-docs`, which goreleaser runs first):

- `NOTICE`: the repository's [`NOTICE`](../../NOTICE). For the default flavour, a `NOTICE.execution` fragment, when
  the repository has one, is appended: it will carry the go-qrl notice once execution mode exists. The consensus
  flavour's NOTICE is the repository's NOTICE only.
- `LICENSES/`: the texts in [`LICENSES/`](../../LICENSES). `GPL-3.0-or-later.txt` and `LGPL-3.0-or-later.txt`, when
  present, ship in the default flavour only. Any other GNU GPL, LGPL or AGPL text, recognised by `GPL` in its file
  name or by its GNU title line, makes `make release-docs` fail until it is listed as execution-only.

Today both flavours link the same permissively licensed modules, so their files are identical. The release checks
(section 4) enforce the split on what was built: an archive or image of the consensus flavour whose NOTICE mentions
the LGPL, or whose `LICENSES/` holds a GNU GPL, LGPL or AGPL text by either test, whatever its name, fails them.

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
```

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
  module's `NOTICE` where its source has one), the repository's `deploy/config/` and `deploy/systemd/` files, and a
  `README.md` whose relative links all name files the archive holds;
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
make release-version RELEASE_TAG=v1.0.0 GO_LICENSES="$(go env GOPATH)/bin/go-licenses"
```

It builds every binary as the release would (`goreleaser build` with `GORELEASER_CURRENT_TAG`, into `dist/`; nothing
is tagged, archived or published) and checks that each one of this machine prints
`remotesigner version 1.0.0 (commit …)`. `make build` on a checkout of the tag reports the same version: the
Makefile drops the `v` of `git describe` too (`TestMakeBuildVersion` in `test/repo`).

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
   `Unreleased`; goreleaser publishes it as the release's description (`--release-notes`);
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

### 6.2 Open: gates this repository cannot meet today

| Gate | What meets it | Recorded in |
|---|---|---|
| qrysm's remote-signer client merged | rgeraldes24/qrysm pull requests #60 to #62 (the proposal slot for RANDAO reveals, the revived `remote-web3signer` keymanager and its validator wiring) merged into qrysm, or a qrysm release that ships them; the pin of `tools/vectorgen/contract` moved to the merged commit, with `make vectors-test` and `make vectors-contract` passing; and [`requirements.md`](requirements.md#5-a-qrysm-validator-client-with-the-remote-signer-keymanager) section 5 naming that release or commit instead of the review branch. The signer's contract checks and the nightly runs above test that unmerged branch, so meeting them does not close this gate | [`tools/vectorgen/README.md`](../../tools/vectorgen/README.md#contract-pin) ("Contract pin") and `requirements.md` section 5 |
| Both nightly end-to-end runs green for 7 consecutive nights | The qrysm side's nightly end-to-end runs: the remote-signer scenario (`TestEndToEnd_MinimalConfig_Web3Signer`) and its hardened variant over TLS with the token, both green on seven consecutive nights against the commit to be tagged, with the qrysm validator client of [`requirements.md`](requirements.md#5-a-qrysm-validator-client-with-the-remote-signer-keymanager) | qrysm CI, linked from the release pull request |
| Benchmark B16 | A 24 h soak with 4,096 keys on a reference VM, within its threshold. It is driven by a time-compressed replay of the mainnet duty schedule, which does not exist yet and has to be written before the run | [`docs/benchmarks.md`](../benchmarks.md) |
| Reference-VM runs of B1-B15 and B18-B20 | Each benchmark on the 4-vCPU amd64 and arm64 reference VMs, with `benchstat` over at least 10 runs where it is a Go benchmark, within its threshold; the rows recorded so far are development-machine numbers. B10's memory bound needs a maintainers' decision first (its section in `docs/benchmarks.md`), and B12, which now measures signing, missed its bound on the development machine | [`docs/benchmarks.md`](../benchmarks.md) |
| The deployment guides brought up by an independent reviewer | A reviewer who did not write the code brings up a signer with [`deploy-docker.md`](deploy-docker.md) alone and with [`deploy-systemd.md`](deploy-systemd.md) alone, and the maintainers accept the documentation pull request (#22). So far the guides have been checked only by their author, reading them as a first-time reader would | the documentation pull request |
| The stacked pull requests merged into `main` | The stacked pull requests #2 to #22, from the bootstrap to the operator documentation, and the one that prepares this release, reviewed and merged into `main` in order, so that the commit to be tagged is on `main` and CI has passed it there (section 5) | the pull requests |
| The first tag run of the Release workflow, with public ghcr.io packages | The workflow's first run for `v1.0.0` publishes the archives, `checksums.txt` with its signature and the provenance attestation, and both images; the `remotesigner` and `remotesigner-consensus` packages on ghcr.io are made public once the repository is public, so that `docker pull` works without a login; section 3 verifies the release | the GitHub release |
| Making the repository public | The maintainers' decision to make `rgeraldes24/go-remotesigner` public, taken after a secret scan of its full history finds nothing to remove; once the repository is public, qrysm CI fetches the signer without credentials ([`docs/contract.md`](../contract.md#23-access-from-qrysm-ci) section 23) | the repository settings |

Cutting the release, once section 6.2 is met: a pull request to `main` dates the 1.0.0 entry of `CHANGELOG.md` (and
moves anything listed under `Unreleased` into it); after it is merged, the tag is pushed as section 5 shows.
