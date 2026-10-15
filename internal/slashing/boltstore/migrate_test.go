// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package boltstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// newStoreFile creates a current store at a fresh path with one registered key and a RANDAO frontier, and closes it.
func newStoreFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "slashing-protection.db")
	s, err := Open(path, Options{GenesisValidatorsRoot: &slashingtest.GVR})
	mustNil(t, err)
	ctx := context.Background()
	mustNil(t, s.RegisterValidators(ctx, [][]byte{slashingtest.Key(0)}))
	_, err = s.CompareAndSwapRandaoState(ctx, slashing.KeyIDOf(slashingtest.Key(0)), nil, testFrontier)
	mustNil(t, err)
	mustNil(t, s.Close())
	return path
}

var testFrontier = slashing.RandaoState{Index: 99, Reveal: slashingtest.RootOf(99), LastSlot: 7}

// setSchemaVersion rewrites meta/schema_version, simulating a file written by an older or newer build.
func setSchemaVersion(t *testing.T, path string, v uint32) {
	t.Helper()
	db, err := bolt.Open(path, fileMode, nil)
	mustNil(t, err)
	mustNil(t, db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(keySchemaVersion, encodeVersion(v))
	}))
	mustNil(t, db.Close())
}

func fileSchemaVersion(t *testing.T, path string) uint32 {
	t.Helper()
	db, err := bolt.Open(path, fileMode, &bolt.Options{ReadOnly: true})
	mustNil(t, err)
	defer db.Close()
	var v uint32
	mustNil(t, db.View(func(tx *bolt.Tx) error {
		v, err = schemaVersion(tx)
		return err
	}))
	return v
}

// withMigration installs fn as the migration from version from for the duration of the test.
func withMigration(t *testing.T, from uint32, fn func(*bolt.Tx) error) {
	t.Helper()
	migrations[from] = fn
	t.Cleanup(func() { delete(migrations, from) })
}

func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestOpenRefusesOtherSchemaVersions(t *testing.T) {
	tests := []struct {
		stored  uint32
		is      error
		message string
	}{
		{0, slashing.ErrSchemaTooOld, `run "remotesigner consensus migrate"`},
		{slashing.SchemaVersion + 1, slashing.ErrSchemaTooNew, "downgrade is not supported"},
	}
	for _, tc := range tests {
		t.Run(tc.message, func(t *testing.T) {
			path := newStoreFile(t)
			setSchemaVersion(t, path, tc.stored)
			_, err := Open(path, Options{})
			var se *slashing.SchemaError
			if !errors.Is(err, tc.is) || !errors.As(err, &se) || se.Stored != tc.stored {
				t.Fatalf("Open: %v, want a SchemaError matching %v", err, tc.is)
			}
			if !strings.Contains(err.Error(), tc.message) {
				t.Errorf("error %q does not contain %q", err, tc.message)
			}
			if v := fileSchemaVersion(t, path); v != tc.stored {
				t.Errorf("refused Open changed the schema version to %d", v)
			}
		})
	}
}

func TestMigrate(t *testing.T) {
	path := newStoreFile(t)
	setSchemaVersion(t, path, 0)
	if _, err := Open(path, Options{}); !errors.Is(err, slashing.ErrSchemaTooOld) {
		t.Fatalf("Open before migrating: %v, want ErrSchemaTooOld", err)
	}
	var ran int
	withMigration(t, 0, func(tx *bolt.Tx) error {
		ran++
		return nil
	})

	m, err := Migrate(path)
	mustNil(t, err)
	wantBackup := path + ".v0.bak"
	if m != (Migration{From: 0, To: slashing.SchemaVersion, Backup: wantBackup}) || ran != 1 {
		t.Fatalf("Migrate: %+v after %d steps, want 0 → %d with backup %s after 1", m, ran, slashing.SchemaVersion, wantBackup)
	}
	if v := fileSchemaVersion(t, wantBackup); v != 0 {
		t.Errorf("backup has schema version %d, want 0", v)
	}
	if fi, err := os.Stat(wantBackup); err != nil || fi.Mode().Perm() != fileMode {
		t.Errorf("backup: %v, mode %v", err, fi.Mode())
	}

	s, err := Open(path, Options{GenesisValidatorsRoot: &slashingtest.GVR})
	if err != nil {
		t.Fatalf("Open after migrating: %v", err)
	}
	got, ok, err := s.RandaoState(context.Background(), slashing.KeyIDOf(slashingtest.Key(0)))
	if err != nil || !ok || got != testFrontier {
		t.Errorf("RandaoState after migrating: %+v %v %v, want %+v", got, ok, err, testFrontier)
	}
	mustNil(t, s.Close())

	m, err = Migrate(path)
	if err != nil || m != (Migration{From: slashing.SchemaVersion, To: slashing.SchemaVersion}) || ran != 1 {
		t.Fatalf("Migrate of a current store: %+v %v (steps %d), want a no-op", m, err, ran)
	}
}

func TestMigrateRefusals(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name       string
		stored     uint32
		migration  func(*bolt.Tx) error // installed from version 0 when set
		prepare    func(t *testing.T, path string)
		wantErr    error // matched with errors.Is when set
		wantBackup bool
	}{
		{name: "newer store", stored: slashing.SchemaVersion + 1, wantErr: slashing.ErrSchemaTooNew},
		{name: "no migration step", stored: 0},
		{
			name: "failing step", stored: 0, wantErr: boom, wantBackup: true,
			migration: func(tx *bolt.Tx) error {
				if err := tx.Bucket(bucketMeta).Put([]byte("half-done"), []byte{1}); err != nil {
					return err
				}
				return boom
			},
		},
		{
			name: "backup exists", stored: 0, wantErr: os.ErrExist, wantBackup: true,
			migration: func(*bolt.Tx) error { return nil },
			prepare: func(t *testing.T, path string) {
				mustNil(t, os.WriteFile(path+".v0.bak", []byte("an earlier backup"), fileMode))
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := newStoreFile(t)
			setSchemaVersion(t, path, tc.stored)
			if tc.migration != nil {
				withMigration(t, 0, tc.migration)
			}
			if tc.prepare != nil {
				tc.prepare(t, path)
			}
			_, err := Migrate(path)
			if err == nil || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) {
				t.Fatalf("Migrate: %v, want an error matching %v", err, tc.wantErr)
			}
			if v := fileSchemaVersion(t, path); v != tc.stored {
				t.Errorf("schema version after a refused migration: %d, want %d", v, tc.stored)
			}
			db, err := bolt.Open(path, fileMode, &bolt.Options{ReadOnly: true})
			mustNil(t, err)
			mustNil(t, db.View(func(tx *bolt.Tx) error {
				if tx.Bucket(bucketMeta).Get([]byte("half-done")) != nil {
					t.Error("a failed migration step left its write behind")
				}
				return nil
			}))
			mustNil(t, db.Close())
			_, statErr := os.Stat(path + ".v0.bak")
			if (statErr == nil) != tc.wantBackup {
				t.Errorf("backup present: %v, want %v", statErr == nil, tc.wantBackup)
			}
		})
	}
}

func TestMigrateLockedAndMissing(t *testing.T) {
	path := newStoreFile(t)
	s, err := Open(path, Options{})
	mustNil(t, err)
	if _, err := Migrate(path); !errors.Is(err, ErrLocked) {
		t.Errorf("Migrate of an open store: %v, want ErrLocked", err)
	}
	mustNil(t, s.Close())

	missing := filepath.Join(t.TempDir(), "absent.db")
	if _, err := Migrate(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Migrate of a missing file: %v, want os.ErrNotExist", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Migrate created %s", missing)
	}
}
