// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || freebsd

package source

import (
	"io/fs"
	"strconv"
	"syscall"
)

// identity is the device, inode number and status-change time of the file
// fi describes, when fi comes from the operating system. The field types
// vary by architecture, hence the conversions.
func identity(fi fs.FileInfo) (string, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	return strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(uint64(st.Ino), 10) + ":" +
		strconv.FormatInt(st.Ctimespec.Nano(), 10), true
}
