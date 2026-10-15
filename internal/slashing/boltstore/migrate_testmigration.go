// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build testmigration

package boltstore

import bolt "go.etcd.io/bbolt"

// The testmigration build tag registers a no-op migration from schema version 0, which stands in for an older
// schema until a real one exists. Only the binary the acceptance tests build sets the tag, so that they can drive
// `consensus migrate` and a restart end to end; release builds never do.
func init() {
	migrations[0] = func(*bolt.Tx) error { return nil }
}
