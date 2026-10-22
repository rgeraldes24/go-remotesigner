// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution && unix

package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Execution mode reads its token files under --strict-file-permissions as
// consensus mode does: a sign token file that others can read refuses the
// start, and is loaded with a warning when the policy is off.
func TestExecutionTokenFilePermissions(t *testing.T) {
	node := newGQRLNode(t)
	data := t.TempDir()
	first := start(t, options{command: "execution", data: data, consensus: downstreamFlags(t, node.Server)})
	first.waitReady()
	first.stop()
	sign := filepath.Join(data, "auth-token")
	if err := os.Chmod(sign, 0o644); err != nil {
		t.Fatal(err)
	}

	refused := launch(t, options{command: "execution", data: data, keys: first.keys,
		consensus: downstreamFlags(t, node.Server)})
	if code := refused.exitCode(15 * time.Second); code != 1 || !strings.Contains(refused.output.String(), sign) {
		t.Fatalf("a 0644 sign token file: exit %d\n%s", code, refused.output.String())
	}
	lax := start(t, options{command: "execution", data: data, keys: first.keys,
		global: []string{"--strict-file-permissions=false"}, consensus: downstreamFlags(t, node.Server)})
	lax.waitReady()
	lax.stop()
	if !strings.Contains(lax.output.String(), "A token or TLS key file is readable by its group or other users") {
		t.Fatalf("no warning:\n%s", lax.output.String())
	}
}
