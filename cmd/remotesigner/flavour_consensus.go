// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build noexecution

package main

import (
	"io"

	"github.com/urfave/cli/v2"
)

// binaryName is the name of the consensus-only flavour, built with
// -tags noexecution. It links permissively licensed code only.
const binaryName = "remotesigner-consensus"

// flavourNotice: this flavour links no code whose licence asks for a
// notice in --version.
const flavourNotice = ""

// flavourCommands: this flavour has no execution mode.
func flavourCommands(func(runFunc) runFunc, io.Writer, io.Writer) []*cli.Command { return nil }

// flavourSections: an execution section of --config-file is an unknown key
// here.
func flavourSections() map[string][]cli.Flag { return nil }

// cloudSecretStores reports whether this flavour links the cloud SDKs of
// the AWS, Azure and GCP secret stores. Like execution mode, they are in
// the default flavour only, which keeps this one small; HashiCorp Vault,
// read through Vault's HTTP API without a Vault SDK, is in both.
const cloudSecretStores = false
