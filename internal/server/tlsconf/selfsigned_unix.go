// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package tlsconf

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// dirGuarded reports whether this platform checks and locks the
// self-signed directory.
const dirGuarded = true

// checkSelfSignedDir refuses a directory that its group or other users
// can write: they could replace the key and certificate the signer
// serves, or plant them before the first start.
func checkSelfSignedDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is writable by its group or by other users (mode %04o), who could replace the TLS key "+
			"the signer serves: chmod 0700 it, and check the files in it", dir, perm)
	}
	return nil
}

// lockSelfSignedDir takes an exclusive flock(2) on the directory and
// returns its release. It serializes the check-then-generate of
// selfSigned across processes, so two signers sharing a data path never
// both generate a certificate (the slashing-protection store's lock does
// not cover every setup). The kernel drops the lock if the process dies.
func lockSelfSignedDir(dir string) (func(), error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	fd := int(f.Fd())
	for {
		err = syscall.Flock(fd, syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", dir, err)
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
