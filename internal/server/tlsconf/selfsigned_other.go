// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package tlsconf

// dirGuarded reports whether this platform checks and locks the
// self-signed directory: only Linux and macOS do.
const dirGuarded = false

func checkSelfSignedDir(string) error { return nil }

func lockSelfSignedDir(string) (func(), error) { return func() {}, nil }
