// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package boltstore

import (
	"errors"
	"fmt"
	"os"

	bolt "go.etcd.io/bbolt"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// migrations[v] upgrades a file in place from schema version v to v+1. Version 1 is the first schema, so there are
// none yet; every later schema change adds one here together with an upgrade test.
var migrations = map[uint32]func(*bolt.Tx) error{}

// Migration reports what Migrate did.
type Migration struct {
	// From and To are the schema versions before and after; they are equal when the file was already current.
	From, To uint32
	// Backup is the path of the copy taken before migrating, or empty when nothing was migrated.
	Backup string
}

// Migrate upgrades the store at path to slashing.SchemaVersion. It is the offline `consensus migrate` path: it
// takes the file's exclusive lock, waiting up to DefaultLockTimeout, so it fails with ErrLocked while a signer has
// the store open.
//
// Before it changes anything it copies the file to "<path>.v<old version>.bak" (mode 0600, never overwriting an
// existing backup). All steps then run in one transaction, so a failed migration leaves the file at its old version.
// A current file is left untouched, and a newer one is refused with a *slashing.SchemaError.
func Migrate(path string) (Migration, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Migration{}, fmt.Errorf("boltstore: migrate: %w", err)
	}
	if fi.Size() == 0 {
		// bolt.Open would lay out an empty database in it before the version probe could refuse it.
		return Migration{}, fmt.Errorf("boltstore: migrate %s: %w", path, ErrNotStore)
	}
	db, err := openDB(path, DefaultLockTimeout)
	if err != nil {
		return Migration{}, err
	}
	m, err := migrate(db, path)
	if cerr := db.Close(); err == nil && cerr != nil {
		err = fmt.Errorf("boltstore: migrate %s: %w", path, cerr)
	}
	return m, err
}

func migrate(db *bolt.DB, path string) (Migration, error) {
	var from uint32
	if err := db.View(func(tx *bolt.Tx) error {
		var err error
		from, err = schemaVersion(tx)
		return err
	}); err != nil {
		return Migration{}, fmt.Errorf("boltstore: migrate %s: %w", path, err)
	}
	to := slashing.SchemaVersion
	switch {
	case from == to:
		return Migration{From: from, To: to}, nil
	case from > to:
		return Migration{}, &slashing.SchemaError{Stored: from, Expected: to}
	}
	for v := from; v < to; v++ {
		if migrations[v] == nil {
			return Migration{}, fmt.Errorf("boltstore: migrate %s: no migration from schema version %d", path, v)
		}
	}

	backup := fmt.Sprintf("%s.v%d.bak", path, from)
	if err := writeBackup(db, backup); err != nil {
		return Migration{}, err
	}
	err := db.Update(func(tx *bolt.Tx) error {
		for v := from; v < to; v++ {
			if err := migrations[v](tx); err != nil {
				return fmt.Errorf("schema version %d to %d: %w", v, v+1, err)
			}
		}
		return tx.Bucket(bucketMeta).Put(keySchemaVersion, encodeVersion(to))
	})
	if err != nil {
		return Migration{}, fmt.Errorf("boltstore: migrate %s (backup kept at %s): %w", path, backup, err)
	}
	return Migration{From: from, To: to, Backup: backup}, nil
}

// writeBackup writes a consistent copy of the database to path and fsyncs it. It refuses to overwrite a file.
func writeBackup(db *bolt.DB, path string) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return fmt.Errorf("boltstore: create backup: %w", err)
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			err = errors.Join(fmt.Errorf("boltstore: write backup %s: %w", path, err), os.Remove(path))
		}
	}()
	if err := db.View(func(tx *bolt.Tx) error {
		_, err := tx.WriteTo(f)
		return err
	}); err != nil {
		return err
	}
	return f.Sync()
}
