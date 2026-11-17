// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package secretfile

import "io/fs"

// ownerOf reports no owner: files here have no uid, and access to them is
// governed by other means (an ACL on Windows).
func ownerOf(fs.FileInfo) (uint32, bool) { return 0, false }
