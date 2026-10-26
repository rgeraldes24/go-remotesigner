// Copyright 2026 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// commandline/src/main/java/tech/pegasys/web3signer/commandline/subcommands/XHelpSubCommand.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/urfave/cli/v2"
)

// xhelpCommand is Web3Signer's hidden help topic for its unstable options,
// the hidden flags whose names start with X. It is not listed by --help.
const xhelpCommand = "Xhelp"

// stabilityNotice heads the Xhelp output, as Web3Signer's does.
const stabilityNotice = "No stability or compatibility guarantee applies to unstable options. " +
	"They may be added, changed or removed between releases without announcement."

// printUnstableOptions writes the stability notice and, for the app and for
// each of its commands that has any, the flags whose names start with X.
// docs/reference/flags.md explains each override.
func printUnstableOptions(w io.Writer, app *cli.App) {
	_, _ = fmt.Fprintf(w, "%s\n", stabilityNotice)
	unstable(w, app.Name, app.Flags)
	var walk func(prefix string, cmds []*cli.Command)
	walk = func(prefix string, cmds []*cli.Command) {
		for _, c := range cmds {
			name := prefix + " " + c.Name
			unstable(w, name, c.Flags)
			walk(name, c.Subcommands)
		}
	}
	walk(app.Name, app.Commands)
}

// unstable writes the X flags of one command.
func unstable(w io.Writer, command string, fs []cli.Flag) {
	var lines []string
	for _, f := range fs {
		if strings.HasPrefix(f.Names()[0], "X") {
			lines = append(lines, "   "+f.String())
		}
	}
	if len(lines) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "\nUnstable options for %s:\n%s\n", command, strings.Join(lines, "\n"))
}
