// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package main

import "os"

// ownerUID returns -1: this system has no numeric file owners.
func ownerUID(os.FileInfo) int64 { return -1 }
