// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	enc "encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// writeSchemaVersion rewrites meta/schema_version of the store at path.
func writeSchemaVersion(t *testing.T, path string, v uint32) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("meta")).Put([]byte("schema_version"), enc.BigEndian.AppendUint32(nil, v))
	}); err != nil {
		t.Fatal(err)
	}
}

// olderStore starts and stops a signer on a fresh data path, then marks its
// store as schema version 0, and returns the data path and the store. A
// prebuilt REMOTESIGNER_BINARY without the testmigration tag that TestMain
// builds with cannot migrate it, so the test is skipped then.
func olderStore(t *testing.T) (string, string) {
	t.Helper()
	data := t.TempDir()
	s := start(t, options{data: data})
	s.waitReady()
	s.signal(syscall.SIGTERM)
	if code := s.exitCode(15 * time.Second); code != 0 {
		t.Fatalf("exit %d", code)
	}
	db := filepath.Join(data, "slashing-protection.db")
	writeSchemaVersion(t, db, 0)
	if os.Getenv("REMOTESIGNER_BINARY") != "" {
		b, err := os.ReadFile(db)
		if err != nil {
			t.Fatal(err)
		}
		probe := filepath.Join(t.TempDir(), "probe.db")
		if err := os.WriteFile(probe, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, out := runOffline(t, "consensus", "migrate", "--slashing-protection-db-url=bolt://"+probe); strings.Contains(out, "no migration from schema version 0") {
			t.Skip("REMOTESIGNER_BINARY was built without -tags testmigration")
		}
	}
	return data, db
}

// A store at an older schema version stops the signer with
// a message naming `consensus migrate`; after `consensus migrate`, which
// keeps a .v0.bak backup, the signer starts. With
// --slashing-protection-db-migrate the signer migrates at startup instead.
// TestMain builds the binary with the testmigration tag, whose no-op
// migration from version 0 stands in for an older schema.
func TestMigrateOlderStore(t *testing.T) {
	t.Run("consensus migrate", func(t *testing.T) {
		data, db := olderStore(t)
		s := launch(t, options{data: data})
		if code := s.exitCode(15 * time.Second); code == 0 || !strings.Contains(s.output.String(), "consensus migrate") {
			t.Fatalf("start on an older store: exit %d\n%s", code, s.output.String())
		}

		code, out := runOffline(t, "--data-path="+data, "consensus", "migrate")
		if code != 0 || !strings.Contains(out, "migrated from schema version 0 to 1; backup at "+db+".v0.bak") {
			t.Fatalf("migrate: %d %s", code, out)
		}
		if fi, err := os.Stat(db + ".v0.bak"); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("backup: %v %v", fi, err)
		}

		start(t, options{data: data}).waitReady()
	})
	t.Run("--slashing-protection-db-migrate", func(t *testing.T) {
		data, db := olderStore(t)
		start(t, options{data: data, consensus: []string{"--slashing-protection-db-migrate"}}).waitReady()
		if _, err := os.Stat(db + ".v0.bak"); err != nil {
			t.Fatalf("backup: %v", err)
		}
	})
}
