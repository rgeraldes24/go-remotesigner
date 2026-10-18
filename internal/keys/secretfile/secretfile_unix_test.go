// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package secretfile

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The refusals that need a Unix file system: FIFOs, symlinks and modes.
func TestReadRefusalsUnix(t *testing.T) {
	dir := t.TempDir()
	// A FIFO is refused at once instead of blocking the open until a
	// writer comes.
	fifo := filepath.Join(dir, "fifo.txt")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadCapped(fifo, 64); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("a FIFO: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
	// A symlink is followed: the mode checked is the target's.
	target := write(t, "pw", 0o644)
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(link, 64, Policy{Strict: true}); !errors.Is(err, ErrInsecure) {
		t.Errorf("a symlink to a world-readable file: %v", err)
	}
	// ReadCapped checks no mode.
	if got, err := ReadCapped(target, 64); err != nil || string(got) != "pw" {
		t.Errorf("ReadCapped = %q, %v", got, err)
	}
	// ReadInfo returns the mode it read the file with.
	if _, fi, err := ReadInfo(target, 64); err != nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("ReadInfo = %v, %v", fi, err)
	}
}
