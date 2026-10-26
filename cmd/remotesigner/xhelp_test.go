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
// commandline/src/test/java/tech/pegasys/web3signer/commandline/XHelpSubCommandTest.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
)

// Web3Signer's hidden Xhelp lists the unstable --X… options by command,
// under its stability notice, and --help does not list Xhelp.
func TestXhelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runWith([]string{binaryName, "Xhelp"}, &stdout, &stderr, noRun); code != exitOK {
		t.Fatalf("Xhelp: exit %d: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{stabilityNotice, "Unstable options for " + binaryName + ":",
		"--" + flags.AllowPlaintextTokenAuth, "Unstable options for " + binaryName + " consensus:",
		"--" + flags.AllowGVRTOFU, "--" + flags.AllowUnknownGenesisTime} {
		if !strings.Contains(out, want) {
			t.Errorf("Xhelp output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "--"+flags.HTTPListenPort) {
		t.Errorf("Xhelp lists a stable option:\n%s", out)
	}
	stdout.Reset()
	if code := runWith([]string{binaryName, "--help"}, &stdout, &stderr, noRun); code != exitOK ||
		strings.Contains(stdout.String(), xhelpCommand) {
		t.Errorf("--help: exit %d, lists Xhelp: %v", code, strings.Contains(stdout.String(), xhelpCommand))
	}
	if code := runWith([]string{binaryName, "Xhelp", "more"}, &stdout, &stderr, noRun); code != exitUsage {
		t.Errorf("Xhelp with an argument: exit %d, want %d", code, exitUsage)
	}
}
