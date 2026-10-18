# Copyright 2026 The go-remotesigner Authors.
# SPDX-License-Identifier: Apache-2.0

GO            ?= go
GOLANGCI_LINT ?= golangci-lint
GO_LICENSES   ?= go-licenses
GOVULNCHECK   ?= govulncheck
DOCKER        ?= docker
BIN_DIR       ?= bin

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

# Release builds are static: no cgo, no local paths in the binary.
BUILD := CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)'

# Licences allowed in shipped binaries (CONTRIBUTING.md, "What you may and may not bring in").
ALLOWED_LICENSES := Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0
# sha256 of the verbatim Apache-2.0 text.
LICENSE_SHA256 := c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4

.PHONY: all build build-consensus test fuzz fuzz-keystore fuzz-interchange bench-b14 contract lint headercheck licenses license-hash vuln nogpl vectors vectors-test vectors-verify vectors-verify-binary vectors-contract docs acceptance b19 bench-e2e release-docs image clean

all: build build-consensus

## build: default flavour (consensus; execution mode from v1.1)
build:
	$(BUILD) -o $(BIN_DIR)/remotesigner ./cmd/remotesigner

## build-consensus: consensus-only flavour, permissive licences only
build-consensus:
	$(BUILD) -tags noexecution -o $(BIN_DIR)/remotesigner-consensus ./cmd/remotesigner

## test: unit tests with the race detector (which needs cgo), both flavours
test:
	CGO_ENABLED=1 $(GO) test -race ./...
	CGO_ENABLED=1 $(GO) test -race -tags noexecution ./...

## fuzz: the CI fuzz runs, FUZZTIME each: the differential hash-tree-root fuzz against fastssz, the strict
## request decoders, the keystore decoder and the EIP-3076 interchange
FUZZTIME ?= 10s
fuzz: fuzz-keystore fuzz-interchange
	$(GO) test -run '^$$' -fuzz '^FuzzHashTreeRootDifferential$$' -fuzztime $(FUZZTIME) ./internal/consensus/types/
	$(GO) test -run '^$$' -fuzz '^FuzzDecodeSignRequest$$' -fuzztime $(FUZZTIME) ./internal/consensus/types/
	$(GO) test -run '^$$' -fuzz '^FuzzDecodeRandaoRevealRequest$$' -fuzztime $(FUZZTIME) ./internal/consensus/types/

## fuzz-keystore: the keystore decoder fuzz alone; the nightly workflow runs it with FUZZTIME=30m
fuzz-keystore:
	$(GO) test -run '^$$' -fuzz '^FuzzDecrypt$$' -fuzztime $(FUZZTIME) ./internal/keys/keystore/qrlv1/

## fuzz-interchange: the EIP-3076 interchange import and export fuzz, FUZZTIME long; nightly runs it for 30 min.
## Minimising a new input is capped at 5 s: inputs carry 5,186-character keys, and the default 60 s stalls every
## worker while it minimises.
fuzz-interchange:
	$(GO) test -run '^$$' -fuzz '^FuzzInterchange$$' -fuzztime $(FUZZTIME) -fuzzminimizetime 5s ./internal/slashing/interchange/

## contract: lint api/openapi/consensus.yaml (kin-openapi), validate its examples, check docs/contract.md against it
contract:
	$(GO) test ./api/openapi/...

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

licenses:
	$(GO_LICENSES) check ./... --allowed_licenses=$(ALLOWED_LICENSES)
	GOFLAGS=-tags=noexecution $(GO_LICENSES) check ./... --allowed_licenses=$(ALLOWED_LICENSES)

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

## bench-b14: benchmark B14, a pruning run over 4,096 validators x 512 epochs in a bbolt store, with signing alongside
bench-b14:
	REMOTESIGNER_BENCH=1 $(GO) test -count=1 -run '^TestB14' -timeout 30m -v ./internal/slashing/boltstore/

## bench-e2e: the end-to-end benchmarks B7 (attestation burst), B8 (contribution burst), B9 (RANDAO reveals) and
## B20 (TLS handshake storm)
bench-e2e:
	REMOTESIGNER_BENCH=1 $(GO) test -count=1 -run '^TestB([789]|20)' -v ./test/acceptance/

## release-docs: the licence files each release flavour ships, into build/release/<flavour>/ (LICENSE, NOTICE,
## LICENSES/, third_party_licenses/ from go-licenses save), and build/release/<flavour>.licenses, the SPDX expression
## of the image's licence label (tools/releasedocs)
RELEASE_DIR ?= build/release
release-docs:
	$(GO) run ./tools/releasedocs -out $(RELEASE_DIR) -go-licenses "$(GO_LICENSES)"

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

clean:
	rm -rf $(BIN_DIR) build
