// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package main

import (
	"io"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
)

// binaryName is the name of the default flavour: consensus and execution
// mode.
const binaryName = "remotesigner"

// flavourCommands are the commands only this flavour has: execution.
func flavourCommands(pick func(runFunc) runFunc, stdout, stderr io.Writer) []*cli.Command {
	return []*cli.Command{executionCommand(pick(executionRun), stdout, stderr)}
}

// flavourSections are the --config-file sections of flavourCommands.
func flavourSections() map[string][]cli.Flag {
	return map[string][]cli.Flag{flags.ExecutionCommand: flags.Execution()}
}

// cloudSecretStores reports whether this flavour links the cloud SDKs of
// the AWS, Azure and GCP secret stores.
const cloudSecretStores = true
