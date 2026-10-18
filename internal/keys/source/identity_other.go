// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !freebsd

package source

import "io/fs"

// identity reports no identity: the platform's file information has no
// inode number and status-change time, so a version is size and
// modification time only.
func identity(fs.FileInfo) (string, bool) { return "", false }
