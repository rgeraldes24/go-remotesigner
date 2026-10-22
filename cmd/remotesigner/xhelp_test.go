// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

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

// --enable-key-manager-api is Web3Signer's alias of --key-manager-api-enabled,
// with the environment variable and config-file key of its name.
func TestKeyManagerAPIAlias(t *testing.T) {
	cfg, code, stderr := capture(t, "consensus", "--network=e2e", "--enable-key-manager-api")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !cfg.Consensus.KeyManagerAPIEnabled {
		t.Fatal("--enable-key-manager-api did not enable the keymanager API")
	}
	t.Setenv("REMOTESIGNER_CONSENSUS_ENABLE_KEY_MANAGER_API", "true")
	if cfg, code, stderr = capture(t, "consensus", "--network=e2e"); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !cfg.Consensus.KeyManagerAPIEnabled {
		t.Fatal("REMOTESIGNER_CONSENSUS_ENABLE_KEY_MANAGER_API did not enable the keymanager API")
	}
}
