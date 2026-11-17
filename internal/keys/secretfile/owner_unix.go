// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package secretfile

import (
	"io/fs"
	"syscall"
)

// ownerOf returns the uid that owns the file fi describes, when fi comes
// from the operating system.
func ownerOf(fi fs.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
