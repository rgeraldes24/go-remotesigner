# Copyright 2026 The go-remotesigner Authors.
# SPDX-License-Identifier: Apache-2.0

GO            ?= go
GOLANGCI_LINT ?= golangci-lint
GO_LICENSES   ?= go-licenses
GOVULNCHECK   ?= govulncheck
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

.PHONY: all build build-consensus test fuzz contract lint headercheck licenses license-hash vuln nogpl vectors vectors-test vectors-verify vectors-verify-binary vectors-contract docs acceptance b19 bench-e2e clean

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
## request decoders, and the keystore decoder (G4 S9)
FUZZTIME ?= 10s
fuzz:
	$(GO) test -run '^$$' -fuzz '^FuzzHashTreeRootDifferential$$' -fuzztime $(FUZZTIME) ./internal/consensus/types/
	$(GO) test -run '^$$' -fuzz '^FuzzDecodeSignRequest$$' -fuzztime $(FUZZTIME) ./internal/consensus/types/
	$(GO) test -run '^$$' -fuzz '^FuzzDecodeRandaoRevealRequest$$' -fuzztime $(FUZZTIME) ./internal/consensus/types/
	$(GO) test -run '^$$' -fuzz '^FuzzDecrypt$$' -fuzztime $(FUZZTIME) ./internal/keys/keystore/qrlv1/

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
## end-to-end networks and check it with `vectorgen verify` (builds tools/vectorgen, which links qrysm)
vectors-verify-binary:
	REMOTESIGNER_VECTORS_VERIFY=1 $(GO) test -count=1 -run '^TestVectorgenVerify$$' -v ./test/acceptance/

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

## bench-e2e: the end-to-end benchmarks B7 (attestation burst), B8 (contribution burst) and B9 (RANDAO reveals)
bench-e2e:
	REMOTESIGNER_BENCH=1 $(GO) test -count=1 -run '^TestB[789]' -v ./test/acceptance/

clean:
	rm -rf $(BIN_DIR)
