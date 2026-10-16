// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package tlsconf

import (
	"fmt"
	"os"
)

// dirGuarded reports whether this platform checks the self-signed
// directory.
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
