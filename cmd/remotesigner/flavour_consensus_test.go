// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build noexecution

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The consensus-only flavour has no execution command and no execution
// section in its config file.
func TestConsensusFlavourHasNoExecution(t *testing.T) {
	_, code, stderr := capture(t, "execution")
	if code != exitUsage || !strings.Contains(stderr, `unknown command "execution"`) {
		t.Fatalf("execution: exit %d %q", code, stderr)
	}
	for _, c := range newApp(nil, nil, nil).Commands {
		if c.Name != "consensus" {
			t.Errorf("command %s in the consensus flavour", c.Name)
		}
	}
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte("execution:\n  downstream-http-port: 9545\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, code, stderr := capture(t, "--config-file="+file, "consensus", "--network=e2e"); code != exitUsage ||
		!strings.Contains(stderr, "unknown option(s): execution") {
		t.Fatalf("an execution section: exit %d %q", code, stderr)
	}
}
