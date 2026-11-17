// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Whoever can write the config file decides how the signer runs, so one
// that its group or other users can write refuses the start (exit 1)
// under --strict-file-permissions, for the signer and for its offline
// commands, and is used with a warning without it, whether the command
// line or the file itself turns the policy off. It holds no secret here,
// so anyone may read it.
func TestConfigFileWritableByOthers(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.yaml")
	write := func(content string, mode fs.FileMode) {
		t.Helper()
		_ = os.Remove(file)
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, mode); err != nil { // not subject to the umask
			t.Fatal(err)
		}
	}
	const content = "http-listen-port: 9100\n"
	for _, mode := range []fs.FileMode{0o600, 0o400, 0o640, 0o644, 0o444} {
		write(content, mode)
		cfg, code, stderr := capture(t, "--config-file="+file, "consensus", "--network=e2e")
		if code != exitOK || cfg.HTTP.ListenPort != 9100 || strings.Contains(stderr, "warning") {
			t.Fatalf("a %04o config file: exit %d\n%s", mode, code, stderr)
		}
	}
	for _, mode := range []fs.FileMode{0o660, 0o664, 0o646, 0o602, 0o666} {
		write(content, mode)
		refusal := fmt.Sprintf("refusing to start: --config-file %s: mode %04o: writable by group or other users", file, mode)
		cfg, code, stderr := capture(t, "--config-file="+file, "consensus", "--network=e2e")
		if code != exitStartup || cfg != nil || !strings.Contains(stderr, refusal) ||
			!strings.Contains(stderr, "--strict-file-permissions=false") {
			t.Fatalf("a %04o config file: exit %d\n%s", mode, code, stderr)
		}
		code, _, stderr = runCLI(t, "--config-file="+file, "consensus", "keystore", "verify", "--file", "none.json",
			"--password-file", "none.txt")
		if code != exitStartup || !strings.Contains(stderr, refusal) {
			t.Fatalf("an offline command with a %04o config file: exit %d\n%s", mode, code, stderr)
		}
		warning := fmt.Sprintf("warning: --config-file %s: mode %04o: writable by group or other users", file, mode)
		cfg, code, stderr = capture(t, "--strict-file-permissions=false", "--config-file="+file, "consensus", "--network=e2e")
		if code != exitOK || cfg.HTTP.ListenPort != 9100 || strings.Count(stderr, warning) != 1 {
			t.Fatalf("a %04o config file, not strict: exit %d\n%s", mode, code, stderr)
		}
	}
	write(content+"strict-file-permissions: false\n", 0o664)
	cfg, code, stderr := capture(t, "--config-file="+file, "consensus", "--network=e2e")
	if code != exitOK || cfg.StrictFilePermissions || !strings.Contains(stderr, "warning: --config-file "+file+": mode 0664") {
		t.Fatalf("a 0664 config file that turns the policy off: exit %d\n%s", code, stderr)
	}
	// The command line wins over the file, here too.
	_, code, stderr = capture(t, "--strict-file-permissions=true", "--config-file="+file, "consensus", "--network=e2e")
	if code != exitStartup || !strings.Contains(stderr, "refusing to start: --config-file "+file+": mode 0664") {
		t.Fatalf("a 0664 config file with the policy forced on: exit %d\n%s", code, stderr)
	}
}

// A config file that really belongs to another user refuses the start;
// only root can make one.
func TestConfigFileOfAnotherUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("giving a file to another user needs root")
	}
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte("http-listen-port: 9100\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(file, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	_, code, stderr := capture(t, "--config-file="+file, "consensus", "--network=e2e")
	if code != exitStartup || !strings.Contains(stderr, "refusing to start: --config-file "+file+": owner uid 1000, signer uid 0") {
		t.Fatalf("another user's config file: exit %d\n%s", code, stderr)
	}
	cfg, code, stderr := capture(t, "--strict-file-permissions=false", "--config-file="+file, "consensus", "--network=e2e")
	if code != exitOK || cfg.HTTP.ListenPort != 9100 ||
		!strings.Contains(stderr, "warning: --config-file "+file+": owned by uid 1000") {
		t.Fatalf("another user's config file, not strict: exit %d\n%s", code, stderr)
	}
}
