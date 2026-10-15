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

# Licences allowed in shipped binaries (DESIGN §6.5).
ALLOWED_LICENSES := Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0
# sha256 of the verbatim Apache-2.0 text (DESIGN §6.1).
LICENSE_SHA256 := c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4

.PHONY: all build build-consensus test lint headercheck licenses license-hash vuln vectors docs clean

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

## vectors: regenerate testdata/vectors with the nested tools/vectorgen module (milestone S3)
vectors:
	@test -f tools/vectorgen/go.mod || { echo "vectors: tools/vectorgen does not exist yet (milestone S3)" >&2; exit 1; }
	cd tools/vectorgen && $(GO) run .

## docs: regenerate docs/reference/flags.md with tools/flagdoc (milestone S5a)
docs:
	@test -d tools/flagdoc || { echo "docs: tools/flagdoc does not exist yet (milestone S5a)" >&2; exit 1; }
	$(GO) run ./tools/flagdoc

clean:
	rm -rf $(BIN_DIR)
