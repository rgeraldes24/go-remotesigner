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

// flavourNotice follows the version in --version: the notice of go-qrl,
// which execution mode links, as the LGPL asks of a combined work that
// shows notices at run time.
const flavourNotice = `
This binary links the go-qrl library (https://github.com/theQRL/go-qrl),
Copyright 2014-2025 The go-ethereum Authors, licensed under the GNU Lesser
General Public License v3.0 or later. See NOTICE, LICENSES/LGPL-3.0-or-later.txt
and LICENSES/GPL-3.0-or-later.txt in the release; the release's source, with
go-qrl vendored, is remotesigner-<version>-src-vendored.tar.gz.`

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
