# Copyright 2026 The go-remotesigner Authors.
# SPDX-License-Identifier: Apache-2.0

GO            ?= go
GOLANGCI_LINT ?= golangci-lint
GO_LICENSES   ?= go-licenses
GOVULNCHECK   ?= govulncheck
GORELEASER    ?= goreleaser
DOCKER        ?= docker
BIN_DIR       ?= bin

# The version without the tag's "v", as goreleaser's {{ .Version }} has it: a build of the tag v1.0.0 reports 1.0.0.
GIT_DESCRIBE ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
VERSION      ?= $(patsubst v%,%,$(GIT_DESCRIBE))
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

# Release builds are static: no cgo, no local paths in the binary.
BUILD := CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)'

# Licences allowed in shipped binaries (CONTRIBUTING.md, "What you may and may not bring in").
ALLOWED_LICENSES := Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0
# sha256 of the verbatim Apache-2.0 text.
LICENSE_SHA256 := c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4

.PHONY: all build build-consensus test test-postgres test-cloud fuzz gqrl-e2e release-src fuzz-target fuzz-keystore fuzz-interchange bench-b14 bench-postgres contract lint headercheck licenses license-hash vuln nogpl vectors vectors-test vectors-verify vectors-verify-binary vectors-contract docs acceptance b19 bench-e2e bench-loading bench-keymanager bench-micro b16 release-docs release-snapshot release-check release-version image docker-smoke systemd-smoke clean

all: build build-consensus

## build: default flavour (consensus and execution mode)
build:
	$(BUILD) -o $(BIN_DIR)/remotesigner ./cmd/remotesigner

## build-consensus: consensus-only flavour, permissive licences only
build-consensus:
	$(BUILD) -tags noexecution -o $(BIN_DIR)/remotesigner-consensus ./cmd/remotesigner

## test: unit tests with the race detector (which needs cgo), both flavours
test:
	CGO_ENABLED=1 $(GO) test -race ./...
	CGO_ENABLED=1 $(GO) test -race -tags noexecution ./...

## test-postgres: the Postgres store's tests against the server REMOTESIGNER_TEST_POSTGRES names, the URL of a role
## that may create databases and roles (CI runs a postgres service): pgstore, the interchange and pruning suites on it,
## the runner and the CLI with the race detector, then the built binary's replica tests. `make test` skips them.
test-postgres:
	@test -n "$$REMOTESIGNER_TEST_POSTGRES" || { echo "test-postgres: set REMOTESIGNER_TEST_POSTGRES" >&2; exit 2; }
	CGO_ENABLED=1 $(GO) test -race -count=1 -p 2 ./internal/slashing/... ./internal/runner/... ./cmd/...
	$(GO) test -count=1 -run Postgres ./test/acceptance/

## test-cloud: the secret-store tests against a real HashiCorp Vault (a dev server), LocalStack's Secrets Manager and
## the emulators of GCP Secret Manager (floci-gcp) and Azure Key Vault (Lowkey Vault, with its managed-identity token
## endpoint): the clients (internal/keys/secrets) and the built binary (test/acceptance). With the REMOTESIGNER_TEST_*
## variables of all four set (the CI job cloud-secrets), it uses those servers; otherwise it starts the four images in
## Docker on free loopback ports and removes the containers and their anonymous volumes afterwards. Each of the six
## server tests must run and pass: none may skip. floci-gcp ignores ListSecrets' filter, so the GCP label filters are
## tested against the in-process fake of `make test`, as are the protocols' error paths.
# renovate: datasource=docker
VAULT_IMAGE ?= hashicorp/vault:2.1.2@sha256:c2f666266f383d2cf424d86b8bb8ce7d065562173ffec2b476d762943608bb55
# LocalStack 4.14.0 is the last release that serves Secrets Manager without an auth token.
# renovate: datasource=docker
LOCALSTACK_IMAGE ?= localstack/localstack:4.14.0@sha256:3ebc37595918b8accb852f8048fef2aff047d465167edd655528065b07bc364a
# renovate: datasource=docker
FLOCI_GCP_IMAGE ?= floci/floci-gcp:0.11.0@sha256:eae9683d806ceb643bcb36aee97cdb8cad13c3e2959cd053bf40e481994fde12
# Lowkey Vault is published for linux/amd64 only; Docker emulates it elsewhere.
# renovate: datasource=docker
LOWKEY_VAULT_IMAGE ?= nagyesta/lowkey-vault:7.3.127@sha256:d92adc63759571b2ef68e84f4fad94e6d9603c1faf9d338a2d90c2302303c952
LOWKEY_ARGS := --server.port=8443 --app.token.port=8080 --LOWKEY_VAULT_RELAXED_PORTS=true
CLOUD_TESTS := TestVaultDevServer TestLocalStack TestSecretStoresDevServers TestGCPEmulator TestLowkeyVault \
	TestSecretStoresEmulators
# CLOUD_TEST runs CLOUD_TESTS with REMOTESIGNER_TEST_CLOUD_REQUIRED=1, under which a test whose server variables are
# missing fails instead of skipping, then requires each of them to have passed: -run matching nothing exits 0.
CLOUD_TEST = log=$$(mktemp) || exit 1; \
	{ REMOTESIGNER_TEST_CLOUD_REQUIRED=1 CGO_ENABLED=1 $(GO) test -race -count=1 -v \
		-run '^($(subst $(space),|,$(CLOUD_TESTS)))$$' ./internal/keys/secrets/... ./test/acceptance/ 2>&1; \
		echo "go test exit status $$?"; } | tee $$log; \
	ok=1; grep -qx 'go test exit status 0' $$log || ok=0; \
	for t in $(CLOUD_TESTS); do grep -q "^--- PASS: $$t " $$log || { echo "test-cloud: $$t did not pass" >&2; ok=0; }; done; \
	rm -f $$log; [ $$ok = 1 ]
space := $(subst ,, )
test-cloud:
	@if [ -n "$$REMOTESIGNER_TEST_VAULT_ADDR" ] && [ -n "$$REMOTESIGNER_TEST_AWS_ENDPOINT" ] && \
		[ -n "$$REMOTESIGNER_TEST_GCP_ENDPOINT" ] && [ -n "$$REMOTESIGNER_TEST_AZURE_VAULT" ]; then \
		$(CLOUD_TEST); exit $$?; \
	fi; \
	started=""; trap '[ -z "$$started" ] || $(DOCKER) rm -f -v $$started >/dev/null' EXIT; \
	vault=$$($(DOCKER) run -d --rm -e VAULT_DEV_ROOT_TOKEN_ID=remotesigner-test-root -p 127.0.0.1::8200 $(VAULT_IMAGE)) && \
		started="$$vault" && \
	localstack=$$($(DOCKER) run -d --rm -e SERVICES=secretsmanager -p 127.0.0.1::4566 $(LOCALSTACK_IMAGE)) && \
		started="$$started $$localstack" && \
	gcp=$$($(DOCKER) run -d --rm -p 127.0.0.1::4588 $(FLOCI_GCP_IMAGE)) && started="$$started $$gcp" && \
	azure=$$($(DOCKER) run -d --rm --platform linux/amd64 -e LOWKEY_ARGS="$(LOWKEY_ARGS)" -p 127.0.0.1::8443 \
		-p 127.0.0.1::8080 $(LOWKEY_VAULT_IMAGE)) && started="$$started $$azure" || exit 1; \
	vaddr=http://$$($(DOCKER) port $$vault 8200/tcp | head -1); aws=http://$$($(DOCKER) port $$localstack 4566/tcp | head -1); \
	gcpaddr=http://$$($(DOCKER) port $$gcp 4588/tcp | head -1); \
	akv=https://localhost:$$($(DOCKER) port $$azure 8443/tcp | head -1 | sed 's/.*://'); \
	aid=http://$$($(DOCKER) port $$azure 8080/tcp | head -1)/metadata/identity/oauth2/token; \
	for i in $$(seq 120); do curl -sf $$vaddr/v1/sys/health >/dev/null && \
		curl -sf $$aws/_localstack/health | grep -Eq '"secretsmanager": "(available|running)"' && \
		curl -sf $$gcpaddr/health >/dev/null && curl -sfk $$akv/ping >/dev/null && break; sleep 1; done; \
	export REMOTESIGNER_TEST_VAULT_ADDR=$$vaddr REMOTESIGNER_TEST_VAULT_TOKEN=remotesigner-test-root \
		REMOTESIGNER_TEST_AWS_ENDPOINT=$$aws REMOTESIGNER_TEST_GCP_ENDPOINT=$$gcpaddr \
		REMOTESIGNER_TEST_AZURE_VAULT=$$akv REMOTESIGNER_TEST_AZURE_IDENTITY_ENDPOINT=$$aid; \
	$(CLOUD_TEST)

## fuzz: the CI fuzz runs, FUZZTIME each: the differential hash-tree-root fuzz against fastssz, the strict
## request decoders, the JSON-RPC request and batch decoders against encoding/json, the network configuration
## parser, the keystore decoder and the EIP-3076 interchange
FUZZTIME ?= 10s
fuzz: fuzz-keystore fuzz-interchange
	$(GO) test -run '^$$' -fuzz '^FuzzParseConfig$$' -fuzztime $(FUZZTIME) ./internal/network/
	$(GO) test -run '^$$' -fuzz '^FuzzHashTreeRootDifferential$$' -fuzztime $(FUZZTIME) ./internal/consensus/types/
	$(GO) test -run '^$$' -fuzz '^FuzzDecodeSignRequest$$' -fuzztime $(FUZZTIME) ./internal/consensus/types/
	$(GO) test -run '^$$' -fuzz '^FuzzDecodeRandaoRevealRequest$$' -fuzztime $(FUZZTIME) ./internal/consensus/types/
	$(GO) test -run '^$$' -fuzz '^FuzzDecodeRequest$$' -fuzztime $(FUZZTIME) ./internal/execution/

## fuzz-target: one fuzz target FUZZ of the package FUZZPKG, FUZZTIME long, for example
## `make fuzz-target FUZZ=FuzzParseConfig FUZZPKG=./internal/network/ FUZZTIME=30m`; the nightly workflow runs the
## sign-request, RANDAO and JSON-RPC decoders, the hash-tree-root differential and the network parser this way for
## 30 min each
FUZZ    ?=
FUZZPKG ?=
fuzz-target:
	@test -n "$(FUZZ)" && test -n "$(FUZZPKG)" || { echo "fuzz-target: set FUZZ and FUZZPKG" >&2; exit 2; }
	$(GO) test -run '^$$' -fuzz '^$(FUZZ)$$' -fuzztime $(FUZZTIME) $(FUZZPKG)

## fuzz-keystore: the keystore decoder fuzz alone; the nightly workflow runs it with FUZZTIME=30m
fuzz-keystore:
	$(GO) test -run '^$$' -fuzz '^FuzzDecrypt$$' -fuzztime $(FUZZTIME) ./internal/keys/keystore/qrlv1/

## fuzz-interchange: the EIP-3076 interchange import and export fuzz, FUZZTIME long; nightly runs it for 30 min.
## Minimising a new input is capped at 5 s: inputs carry 5,186-character keys, and the default 60 s stalls every
## worker while it minimises.
fuzz-interchange:
	$(GO) test -run '^$$' -fuzz '^FuzzInterchange$$' -fuzztime $(FUZZTIME) -fuzzminimizetime 5s ./internal/slashing/interchange/

## contract: lint api/openapi/consensus.yaml and execution.yaml (kin-openapi), validate their examples, check
## docs/contract.md and docs/operations/execution.md against them, and execution mode's handler against execution.yaml
contract:
	$(GO) test ./api/openapi/...
	$(GO) test -run '^TestOpenAPI' ./internal/execution/

## lint: go vet, golangci-lint (incl. depguard), headercheck and licence checks
lint: headercheck license-hash
	$(GO) vet ./...
	$(GO) vet -tags noexecution ./...
	$(GOLANGCI_LINT) run ./...
	$(GOLANGCI_LINT) run --build-tags noexecution ./...

headercheck:
	$(GO) run ./tools/headercheck

license-hash:
	@echo "$(LICENSE_SHA256)  LICENSE" | shasum -a 256 -c -
	@echo "$(LICENSE_SHA256)  LICENSES/Apache-2.0.txt" | shasum -a 256 -c -

## licenses: go-licenses check of both flavours against ALLOWED_LICENSES, with one exception: go-qrl in the default
## flavour. go-licenses reads go-qrl's COPYING (the GPL text) and reports GPL-3.0, while the go-qrl library the
## default flavour links is LGPL-3.0-or-later (docs/operations/release.md). So the default flavour's check leaves out
## go-qrl's packages (the prefix ends in a slash: go-licenses matches prefixes, and the bare module path would also
## leave out go-qrllib), and two tests check go-qrl instead: every go-qrl file the binary links on any target is
## LGPL and none is under cmd/ or internal/, and LICENSES/ holds go-qrl's own LGPL and GPL texts. The consensus
## flavour has no exception: go-qrl there fails the check.
## Both checks read the dependencies that ship: the binaries are built with CGO_ENABLED=0, which links
## github.com/decred/dcrd/dcrec/secp256k1 where a cgo build links go-qrl's own crypto/secp256k1, and the release
## documents are made for linux/amd64 (tools/releasedocs).
GO_QRL_LIBRARY := github.com/theQRL/go-qrl/
LICENSES_ENV   := CGO_ENABLED=0 GOOS=linux GOARCH=amd64
licenses:
	$(LICENSES_ENV) $(GO_LICENSES) check ./... --allowed_licenses=$(ALLOWED_LICENSES) --ignore $(GO_QRL_LIBRARY)
	$(LICENSES_ENV) GOFLAGS=-tags=noexecution $(GO_LICENSES) check ./... --allowed_licenses=$(ALLOWED_LICENSES)
	$(GO) test -count=1 -run '^(TestLinkedGoQRLIsLGPL|TestGNUTextsAreGoQRLs|TestConsensusFlavourLinksNoGoQRL)$$' ./test/repo/

vuln:
	$(GOVULNCHECK) ./...

## nogpl: the signer module links no qrysm package, in either flavour (only the tools/vectorgen modules may)
## The dependency list is captured first, so a failing go list fails the gate instead of feeding grep nothing.
nogpl:
	@for tags in '' noexecution; do \
		deps=$$($(GO) list -deps -tags "$$tags" ./...) || exit 1; \
		if printf '%s\n' "$$deps" | grep '^github.com/theQRL/qrysm'; then \
			echo "nogpl: qrysm is in the signer's dependencies (tags '$$tags')" >&2; exit 1; \
		fi; \
	done

## vectors: regenerate testdata/vectors and internal/network/embedded with the nested tools/vectorgen module.
## The built tool links qrysm (GPL-3.0) and is never shipped; see tools/vectorgen/README.md.
vectors:
	cd tools/vectorgen && $(GO) run . gen

## vectors-test: vet and test tools/vectorgen and tools/vectorgen/contract (each its own module)
vectors-test:
	cd tools/vectorgen && $(GO) vet ./... && $(GO) test -short ./...
	cd tools/vectorgen/contract && $(GO) vet ./... && $(GO) test ./...

## vectors-verify: check a running signer against the golden vectors (SIGNER, TOKEN_FILE)
SIGNER     ?= http://127.0.0.1:9000
TOKEN_FILE ?=
vectors-verify:
	cd tools/vectorgen && $(GO) run . verify -signer $(SIGNER) $(if $(TOKEN_FILE),-token-file $(abspath $(TOKEN_FILE)))

## vectors-verify-binary: build the binary (or use REMOTESIGNER_BINARY), run it with the interop keys on both
## end-to-end networks and check it with `vectorgen verify`, and round-trip qrysm's interchange export through it
## back into qrysm with `vectorgen interchange-check` (builds tools/vectorgen, which links qrysm)
vectors-verify-binary:
	REMOTESIGNER_VECTORS_VERIFY=1 $(GO) test -count=1 -run '^(TestVectorgenVerify|TestQrysmInterchangeRoundTrip)$$' -v ./test/acceptance/

## vectors-contract: vectorgen contract mode: build the binary (or use REMOTESIGNER_BINARY), run it with the interop
## keys on both end-to-end networks and drive it with qrysm's own remote-web3signer keymanager at the commit
## tools/vectorgen/contract pins; then check that a deliberate DTO rename on either side fails the run (builds
## tools/vectorgen/contract, which links qrysm)
vectors-contract:
	REMOTESIGNER_VECTORS_CONTRACT=1 $(GO) test -count=1 -run '^TestVectorgenContract' -v ./test/acceptance/

## docs: regenerate docs/reference/flags.md with tools/flagdoc
docs:
	$(GO) run ./tools/flagdoc

## acceptance: the built-binary acceptance tests (also part of `make test`)
acceptance:
	$(GO) test -count=1 ./test/acceptance/

## b19: the nightly idle-connection race (benchmark B19), B19_DURATION long
B19_DURATION ?= 1h
b19:
	REMOTESIGNER_B19_DURATION=$(B19_DURATION) $(GO) test -count=1 -run '^TestB19IdleConnectionRace$$' -timeout 90m -v ./test/acceptance/

## gqrl-e2e: execution mode against gqrl --dev (TestGQRLDev in internal/execution): a mined transfer, the nonce
## retry, the chain-ID, payload, nonce cross-check and fee-cap refusals, qrl_sign verified with go-qrllib, and the
## proxy allowlist (net_version forwarded; admin_*, debug_*, personal_* refused). gqrl is built from go-qrl at the
## commit go.mod requires, in GQRL_SRC (cloned when missing), unless GQRL names a gqrl binary built from that commit.
## GQRL_SRC defaults to a clone per commit in the user's cache directory, outside the source tree: go-qrl's own
## files are not gofmt-clean, and `gofmt -l .` would list them from a clone under the repository.
GQRL_COMMIT = $(lastword $(subst -, ,$(shell $(GO) list -m -f '{{.Version}}' github.com/theQRL/go-qrl)))
GQRL_SRC   ?= $(or $(XDG_CACHE_HOME),$(HOME)/.cache)/go-remotesigner/go-qrl-$(GQRL_COMMIT)
GQRL       ?=
gqrl-e2e:
	@if [ -z "$(GQRL)" ]; then \
		set -e; \
		test -d "$(GQRL_SRC)/.git" || git clone --filter=blob:none --no-checkout https://github.com/theQRL/go-qrl "$(GQRL_SRC)"; \
		git -C "$(GQRL_SRC)" -c advice.detachedHead=false checkout -q $(GQRL_COMMIT) 2>/dev/null || \
			{ git -C "$(GQRL_SRC)" fetch -q --filter=blob:none origin && git -C "$(GQRL_SRC)" checkout -q $(GQRL_COMMIT); }; \
		echo "building gqrl at go-qrl $(GQRL_COMMIT)"; \
		cd "$(GQRL_SRC)" && CGO_ENABLED=0 $(GO) build -trimpath -o $(abspath $(BIN_DIR))/gqrl ./cmd/gqrl; \
	fi
	REMOTESIGNER_GQRL=$(if $(GQRL),$(abspath $(GQRL)),$(abspath $(BIN_DIR))/gqrl) \
		$(GO) test -count=1 -timeout 10m -run '^TestGQRLDev$$' -v ./internal/execution/

## bench-b14: benchmark B14, a pruning run over 4,096 validators x 512 epochs in a bbolt store, with signing alongside
bench-b14:
	REMOTESIGNER_BENCH=1 $(GO) test -count=1 -run '^TestB14' -timeout 30m -v ./internal/slashing/boltstore/

## bench-postgres: benchmarks B13 (Postgres slashing transactions and the stalled-database bound) and B14 (Postgres
## variant) against the server REMOTESIGNER_TEST_POSTGRES names; B14 writes about 1 GB to it
bench-postgres:
	@test -n "$$REMOTESIGNER_TEST_POSTGRES" || { echo "bench-postgres: set REMOTESIGNER_TEST_POSTGRES" >&2; exit 2; }
	REMOTESIGNER_BENCH=1 $(GO) test -count=1 -run '^TestB1[34]' -timeout 60m -v ./internal/slashing/pgstore/

## bench-e2e: the end-to-end benchmarks B7 (attestation burst), B8 (contribution burst), B9 (RANDAO reveals) and
## B20 (TLS handshake storm)
bench-e2e:
	REMOTESIGNER_BENCH=1 $(GO) test -count=1 -run '^TestB([789]|20)' -v ./test/acceptance/

## release-docs: the licence and documentation files each release flavour ships, into build/release/<flavour>/
## (LICENSE, NOTICE, LICENSES/, third_party_licenses/ from go-licenses save, README.md with its links to the
## repository at RELEASE_REF, and deploy/config/ and deploy/systemd/), and build/release/<flavour>.licenses, the SPDX
## expression of the image's licence label (tools/releasedocs)
RELEASE_DIR ?= build/release
RELEASE_REF ?= main
release-docs:
	$(GO) run ./tools/releasedocs -out $(RELEASE_DIR) -go-licenses "$(GO_LICENSES)" -ref "$(RELEASE_REF)"

## release-src: RELEASE_DIR/remotesigner-<VERSION>-src-vendored.tar.gz, the source each release attaches: the
## committed tree (git archive HEAD) with every module it links in vendor/ (go mod vendor), so that the default
## flavour can be rebuilt with a modified go-qrl, as the LGPL asks (docs/operations/release.md). Run it after
## release-docs, which empties RELEASE_DIR. The archive carries no extended attributes: COPYFILE_DISABLE=1 keeps
## macOS's tar (bsdtar) from adding an AppleDouble ._ entry per file, and --no-xattrs, which GNU tar takes too,
## its LIBARCHIVE.xattr headers.
SRC_NAME = remotesigner-$(VERSION)-src-vendored
release-src:
	rm -rf $(RELEASE_DIR)/src
	mkdir -p $(RELEASE_DIR)/src/$(SRC_NAME)
	git archive --format=tar HEAD | tar -x -C $(RELEASE_DIR)/src/$(SRC_NAME)
	cd $(RELEASE_DIR)/src/$(SRC_NAME) && $(GO) mod vendor
	COPYFILE_DISABLE=1 tar --no-xattrs -C $(RELEASE_DIR)/src -czf $(RELEASE_DIR)/$(SRC_NAME).tar.gz $(SRC_NAME)
	rm -rf $(RELEASE_DIR)/src

## release-snapshot: the release dry run: goreleaser (v2) builds every archive, SBOM and image of both flavours into
## dist/ and the local image store, and publishes and signs nothing. Signing is always skipped; add sbom to
## RELEASE_SKIP when syft is not installed.
RELEASE_SKIP ?= sign
release-snapshot:
	GO_LICENSES="$(GO_LICENSES)" $(GORELEASER) release --snapshot --clean --skip=$(RELEASE_SKIP)

## release-check: check the dry run's output (test/release): both flavours for every target, each archive and image
## with LICENSE, its flavour's NOTICE, LICENSES/, third_party_licenses/ with the licence (and any NOTICE) of every
## module its binary links, the README without dead links, and the repository's deploy/config/ and deploy/systemd/;
## static binaries, the consensus ones built with noexecution and linking no go-qrl module; the version this
## machine's binaries and images report; checksums and SBOMs; the images' nonroot user, entrypoint, labels and /data;
## and the docker-smoke checks on the images of this machine's architecture, one per flavour
RELEASE_DIST ?= dist
release-check:
	REMOTESIGNER_RELEASE_DIST=$(abspath $(RELEASE_DIST)) REMOTESIGNER_RELEASE_DOCS=$(abspath $(RELEASE_DIR)) \
		$(if $(findstring sbom,$(RELEASE_SKIP)),,REMOTESIGNER_RELEASE_SBOM=1) \
		$(GO) test -count=1 -run '^TestRelease' -v ./test/release/

## release-version: build every binary as goreleaser builds them for the release of RELEASE_TAG, through a
## GORELEASER_CURRENT_TAG that needs no git tag (nothing is tagged, archived or published), into RELEASE_DIST, and
## check that each binary of this machine reports the tag's version (1.1.0 for v1.1.0), and the default flavour's
## binaries go-qrl's notice. RELEASE_TAG defaults to the tag of the newest version that CHANGELOG.md has an entry for.
RELEASE_TAG ?= v$(shell sed -n 's/^.. \[\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)\] - .*/\1/p' CHANGELOG.md | head -n 1)
release-version:
	GORELEASER_CURRENT_TAG=$(RELEASE_TAG) GO_LICENSES="$(GO_LICENSES)" $(GORELEASER) build --clean --skip=validate
	REMOTESIGNER_RELEASE_DIST=$(abspath $(RELEASE_DIST)) $(GO) test -count=1 -run '^TestReleaseVersion$$' -v ./test/release/

## image: one image of FLAVOUR (remotesigner or remotesigner-consensus) for linux/IMAGE_ARCH (default: the Docker
## daemon's architecture), tagged IMAGE, built from deploy/docker/Dockerfile into the local image store
FLAVOUR    ?= remotesigner-consensus
IMAGE_ARCH ?= $(shell $(DOCKER) version --format '{{.Server.Arch}}' 2>/dev/null || $(GO) env GOARCH)
IMAGE      ?= local/$(FLAVOUR):dev
IMAGE_CTX  := build/docker/$(FLAVOUR)
CREATED    ?= $(shell git log -1 --format=%cI 2>/dev/null)
image: release-docs
	@case "$(FLAVOUR)" in remotesigner|remotesigner-consensus) ;; \
		*) echo "FLAVOUR must be remotesigner or remotesigner-consensus" >&2; exit 2;; esac
	rm -rf $(IMAGE_CTX)
	mkdir -p $(IMAGE_CTX)/linux/$(IMAGE_ARCH) $(IMAGE_CTX)/build/release
	GOOS=linux GOARCH=$(IMAGE_ARCH) $(BUILD) $(if $(filter remotesigner-consensus,$(FLAVOUR)),-tags noexecution) \
		-o $(IMAGE_CTX)/linux/$(IMAGE_ARCH)/$(FLAVOUR) ./cmd/remotesigner
	cp -R $(RELEASE_DIR)/$(FLAVOUR) $(IMAGE_CTX)/build/release/
	$(DOCKER) buildx build --load --platform linux/$(IMAGE_ARCH) -f deploy/docker/Dockerfile \
		--build-arg FLAVOUR=$(FLAVOUR) --build-arg VERSION=$(VERSION) --build-arg REVISION=$(COMMIT) \
		--build-arg CREATED=$(CREATED) --build-arg LICENSES="$$(cat $(RELEASE_DIR)/$(FLAVOUR).licenses)" \
		-t $(IMAGE) $(IMAGE_CTX)

## docker-smoke: build the image of FLAVOUR, then run its real entrypoint in Docker (test/release), as
## docs/operations/deploy-docker.md does: keystore verify on the key volume; the signer with a file network, its
## genesis time and validators root, and one keystore from a keystore directory with its password file; a client
## container that reaches https://signer:9000 by name and pins the generated certificate by its logged fingerprint
## (/upcheck, publicKeys); consensus migrate on the stopped signer's data volume; the refusals without a certificate,
## a host allowlist or a network; and the compose example's configuration
docker-smoke: image
	REMOTESIGNER_SMOKE_IMAGE=$(IMAGE) $(GO) test -count=1 -run '^TestDockerSmoke$$' -timeout 15m -v ./test/release/

## systemd-smoke: in a privileged container that runs systemd (test/release), run docs/operations/deploy-systemd.md's
## commands as written, as an unprivileged user with sudo: extract a release archive laid out as the release's,
## install the binary, deploy/config/single-host.yaml and deploy/systemd/remotesigner.service, and check that the
## hardened unit serves TLS, /upcheck and publicKeys for a key file and a keystore, logs its fingerprint, reloads its
## TLS files and its keys, upgrades as docs/operations/upgrade.md says, and stops cleanly
systemd-smoke:
	REMOTESIGNER_SYSTEMD_SMOKE=1 $(GO) test -count=1 -run '^TestSystemdSmoke$$' -timeout 15m -v ./test/release/

## bench-loading: the key-loading benchmarks B11 (startup with 10,000 file-raw keys, and with 100 and 1,000
## standard-KDF keystores; REMOTESIGNER_B11_KEYSTORES=<n> runs one count) and B12 (a reload of 100 standard-KDF
## keystores during the B7 burst)
bench-loading:
	REMOTESIGNER_BENCH=1 $(GO) test -count=1 -run '^TestB1[12]' -timeout 3h -v ./test/acceptance/

## bench-keymanager: B18, a keymanager import of 100 standard-KDF keystores (in two requests: at most 64 each)
bench-keymanager:
	REMOTESIGNER_BENCH=1 $(GO) test -count=1 -run '^TestB18' -timeout 1h -v ./test/acceptance/

## bench-micro: the Go benchmarks B1-B4 (ML-DSA-87 signing, key derivation, parallel signing), B5 and B6
## (hash-tree-root, strict decoding), B10 (Argon2id decryption at P = 1, 2 and 4) and B15 (publicKeys for 10,000
## keys), BENCH_COUNT runs each, in benchstat's input format
BENCH_COUNT ?= 10
bench-micro:
	$(GO) test -run '^$$' -bench 'SignHedged|SignDeterministic|KeyFromSeed' -benchtime 20000x -count $(BENCH_COUNT) -timeout 60m ./internal/crypto/mldsa87/
	$(GO) test -run '^$$' -bench SignParallel -cpu 4 -benchtime 5000x -count $(BENCH_COUNT) -timeout 30m ./internal/crypto/mldsa87/
	$(GO) test -run '^$$' -bench 'SigningRoot|DecodeContribution' -benchtime 2s -count $(BENCH_COUNT) -timeout 30m ./internal/consensus/types/
	$(GO) test -run '^$$' -bench PublicKeys10k -benchtime 10x -count $(BENCH_COUNT) -timeout 30m ./internal/api/consensus/
	$(GO) test -run '^$$' -bench 'B10Argon2idDecrypt/P=[124]$$' -benchtime 2x -count 3 -timeout 30m ./internal/keys/keystore/qrlv1/

## b16: benchmark B16, the duty soak (TestB16DutySoak): 4,096 file-raw keys and the duty schedule of every slot of a
## mainnet-sized network (178 requests a slot) replayed against the built binary for B16_DURATION, at B16_SLOT seconds
## per slot (mainnet's 60 by default; fewer compress the run). B16_TIMEOUT must exceed B16_DURATION. Without
## REMOTESIGNER_B16_DURATION the test is a smoke of 3 slots of 6 s, which make test and CI run.
B16_DURATION ?= 24h
B16_SLOT     ?= 60
B16_TIMEOUT  ?= 26h
b16:
	REMOTESIGNER_B16_DURATION=$(B16_DURATION) REMOTESIGNER_B16_SLOT=$(B16_SLOT) $(GO) test -count=1 -run '^TestB16DutySoak$$' -timeout $(B16_TIMEOUT) -v ./test/acceptance/

clean:
	rm -rf $(BIN_DIR) build
