# Releases

This page lists what a release contains, how the licence files differ per flavour, how to verify a release, and how
maintainers run the release dry run and publish. The configuration is [`.goreleaser.yaml`](../../.goreleaser.yaml)
(goreleaser v2) and the workflow [`.github/workflows/release.yml`](../../.github/workflows/release.yml).

## 1. What a release contains

Two flavours, built from the same commit with `CGO_ENABLED=0 -trimpath`:

| Flavour | Build | Licences linked |
|---|---|---|
| `remotesigner` | default | permissive only today; execution mode will add go-qrl (LGPL-3.0-or-later) to this flavour only |
| `remotesigner-consensus` | `-tags noexecution` | permissive only, always: it never links go-qrl or any GPL or LGPL code |

| File | Content |
|---|---|
| `<flavour>_<version>_<os>_<arch>.tar.gz` | for linux and darwin, amd64 and arm64: a directory with the binary, `LICENSE`, the flavour's `NOTICE`, `LICENSES/` and `third_party_licenses/` |
| `<archive>.sbom.json` | the archive's SPDX SBOM (syft) |
| `checksums.txt` | SHA-256 of every archive and SBOM |
| `checksums.txt.sigstore.json` | the keyless cosign signature bundle of `checksums.txt` |
| `ghcr.io/rgeraldes24/<flavour>:<version>` (and `:latest` unless a pre-release) | the multi-platform image ([`deploy-docker.md`](deploy-docker.md)), with an SBOM and a SLSA provenance attestation attached, signed with cosign |

GitHub also stores a build provenance attestation for every file in `checksums.txt`.

`third_party_licenses/` is `go-licenses save` of the flavour's binary: the licence and notice files of every module it
links, under the module's path. The image carries the same files under `/usr/share/doc/remotesigner/`, and its
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
- every archive holds its binary, `LICENSE`, the flavour's `NOTICE`, exactly the flavour's `LICENSES/` texts, and
  `third_party_licenses/`;
- every binary is static and trimmed; the consensus binaries are built with `noexecution` and `go version -m` lists
  no go-qrl module;
- every archive has an SPDX SBOM (unless the dry run skipped them);
- every image (both flavours, amd64 and arm64) runs as `65532:65532` with the documented entrypoint and no
  plaintext-token override, carries its flavour's labels and licence files, holds a binary that passes the same build
  checks, and has `/data` owned by the nonroot user with mode `0700`;
- the images of this machine's architecture, one per flavour, pass the Docker smoke test
  ([`deploy-docker.md`](deploy-docker.md#8-building-the-image)): run hardened, with a read-only root file system and
  no capabilities, as the Docker guide runs them, they check and load a keystore, serve TLS as the nonroot user to a
  client container that pins the generated certificate, migrate a stopped signer's data volume, and refuse to start
  without a certificate, a host allowlist or a network.

`make docker-smoke` runs the same smoke test on an image `make image` builds, and `make systemd-smoke` checks the
systemd unit ([`deploy-systemd.md`](deploy-systemd.md#7-what-the-unit-restricts)).

## 5. Publishing

A release is published only by pushing a version tag, `v<major>.<minor>.<patch>` (with an optional pre-release
suffix, which makes a pre-release without the `latest` tags), on a commit of `main` that CI has passed:

```
git tag -s v1.0.0 -m 'v1.0.0'
git push origin v1.0.0
```

The Release workflow then checks the tagged tree before it publishes anything:

1. the tagged commit is on `main` (`git merge-base --is-ancestor`); a tag on any other commit fails the job;
2. the compliance gates of CI: `make license-hash headercheck nogpl licenses` and `go vet` in both flavours;
3. the dry run and its checks (section 4).

Only if they all pass does it run `goreleaser release`. It builds with a cold Go module and build cache, never one
that an earlier workflow run saved. The full test suite, lint and the vectors are not rerun: they ran on the commit
when it reached `main`. Its job is the only one with write access: `contents: write` for the GitHub release,
`packages: write` for ghcr.io, and `id-token: write` with `attestations: write` for the keyless signatures and the
provenance attestation. Every other workflow reads only.
