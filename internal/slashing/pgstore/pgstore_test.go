// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package pgstore_test

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/pgstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/pgstore/pgtest"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

var bg = context.Background()

// config is the store configuration of a test database, as the admin role.
func config(db *pgtest.DB) pgstore.Config {
	return pgstore.Config{URL: db.URL, Password: db.Password}
}

// migrated returns a fresh database with the current schema.
func migrated(t testing.TB) *pgtest.DB {
	t.Helper()
	db := pgtest.New(t)
	if _, err := pgstore.Migrate(bg, config(db)); err != nil {
		t.Fatal(err)
	}
	return db
}

// open opens a store on db, closed when the test ends.
func open(t testing.TB, cfg pgstore.Config) *pgstore.Store {
	t.Helper()
	s, err := pgstore.Open(bg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// fresh is the conformance suite's factory: every call gets its own migrated database. The stress tests put a
// thousand calls on one validator at once, which queue on its advisory lock for longer than the signing profile's
// 4.5 s under the race detector, so the suite's stores have a longer per-call bound.
func fresh(t *testing.T) slashing.Store {
	cfg := config(migrated(t))
	cfg.Timeout = time.Minute
	s, err := pgstore.Open(bg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPostgresConformance(t *testing.T) {
	pgtest.Skip(t)
	slashingtest.Run(t, fresh)
}

func key(i int) slashing.KeyID { return slashing.KeyIDOf(slashingtest.Key(i)) }

func register(t testing.TB, s slashing.Store, n int) {
	t.Helper()
	keys := make([][]byte, n)
	for i := range keys {
		keys[i] = slashingtest.Key(i)
	}
	if err := s.RegisterValidators(bg, keys); err != nil {
		t.Fatal(err)
	}
}

// Slots, epochs and onion indices above 2^63-1 do not fit a BIGINT: writes refuse them with ErrOutOfRange and
// change nothing, and reads treat them as values no record has.
func TestPostgresOutOfRange(t *testing.T) {
	s := open(t, config(migrated(t)))
	register(t, s, 1)
	if _, err := s.PinGenesisValidatorsRoot(bg, slashingtest.GVR); err != nil {
		t.Fatal(err)
	}
	const top = math.MaxInt64
	big := uint64(top) + 1
	refused := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, pgstore.ErrOutOfRange) {
			t.Errorf("%s: %v, want ErrOutOfRange", what, err)
		}
	}
	refused("InsertBlock", s.UpdateBlocks(bg, key(0), func(tx slashing.BlockTx) error {
		return tx.InsertBlock(slashing.SignedBlock{Slot: big})
	}))
	refused("RaiseSlotLowWatermark", s.UpdateBlocks(bg, key(0), func(tx slashing.BlockTx) error {
		return tx.RaiseSlotLowWatermark(math.MaxUint64)
	}))
	for _, a := range []slashing.SignedAttestation{{SourceEpoch: 1, TargetEpoch: big}, {SourceEpoch: big, TargetEpoch: big}} {
		refused("InsertAttestation", s.UpdateAttestations(bg, key(0), func(tx slashing.AttestationTx) error {
			return tx.InsertAttestation(a)
		}))
	}
	refused("RaiseEpochLowWatermarks", s.UpdateAttestations(bg, key(0), func(tx slashing.AttestationTx) error {
		return tx.RaiseEpochLowWatermarks(1, big)
	}))
	refused("SetHighWatermark", s.SetHighWatermark(bg, slashing.HighWatermark{Epoch: slashingtest.U64(big)}))
	_, err := s.CompareAndSwapRandaoState(bg, key(0), nil, slashing.RandaoState{Index: big})
	refused("CompareAndSwapRandaoState index", err)
	_, err = s.CompareAndSwapRandaoState(bg, key(0), nil, slashing.RandaoState{Index: 1, LastSlot: big})
	refused("CompareAndSwapRandaoState slot", err)
	if _, ok, err := s.RandaoState(bg, key(0)); err != nil || ok {
		t.Errorf("RandaoState after refused writes: %v, %v", ok, err)
	}
	if h, err := s.HighWatermark(bg); err != nil || h.IsSet() {
		t.Errorf("high watermark after a refused write: %+v, %v", h, err)
	}

	// The largest value fits, and reads compare correctly against it and beyond it.
	if err := slashingtest.ImportBlocks(bg, s, key(0), slashing.SignedBlock{Slot: top}); err != nil {
		t.Fatal(err)
	}
	top1 := slashing.SignedAttestation{SourceEpoch: top - 1, TargetEpoch: top, SigningRoot: slashingtest.RootPtr(1)}
	low := slashing.SignedAttestation{SourceEpoch: 2, TargetEpoch: 3, SigningRoot: slashingtest.RootPtr(2)}
	if err := slashingtest.ImportAttestations(bg, s, key(0), low, top1); err != nil {
		t.Fatal(err)
	}
	err = s.UpdateBlocks(bg, key(0), func(tx slashing.BlockTx) error {
		if _, ok, err := tx.BlockAt(big); err != nil || ok {
			t.Errorf("BlockAt(2^63): %v, %v", ok, err)
		}
		if _, ok, err := tx.NearestBlock(big); err != nil || ok {
			t.Errorf("NearestBlock(2^63): %v, %v", ok, err)
		}
		if b, ok, err := tx.NearestBlock(top); err != nil || !ok || b.Slot != top {
			t.Errorf("NearestBlock(2^63-1): %+v, %v, %v", b, ok, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = s.UpdateAttestations(bg, key(0), func(tx slashing.AttestationTx) error {
		if _, ok, err := tx.AttestationAt(big); err != nil || ok {
			t.Errorf("AttestationAt(2^63): %v, %v", ok, err)
		}
		// The records are (2, 3) and (2^63-2, 2^63-1). (1, 2^63) and (1, MaxUint64) surround both.
		for _, target := range []uint64{big, math.MaxUint64} {
			if a, ok, err := tx.SurroundedAttestation(1, target); err != nil || !ok || a.TargetEpoch != top {
				t.Errorf("SurroundedAttestation(1, %d): %+v, %v, %v; want the attestation at 2^63-1", target, a, ok, err)
			}
			if _, ok, err := tx.SurroundingAttestation(1, target); err != nil || ok {
				t.Errorf("SurroundingAttestation(1, %d): %v, %v", target, ok, err)
			}
		}
		// No record has a target above 2^63, or a source above 2^63.
		if _, ok, err := tx.SurroundingAttestation(big, big); err != nil || ok {
			t.Errorf("SurroundingAttestation(2^63, 2^63): %v, %v", ok, err)
		}
		if _, ok, err := tx.SurroundedAttestation(big, math.MaxUint64); err != nil || ok {
			t.Errorf("SurroundedAttestation(2^63, MaxUint64): %v, %v", ok, err)
		}
		// Every record's source is below 2^63+5, and (2^63-2, 2^63-1) has a target above 4.
		if a, ok, err := tx.SurroundingAttestation(big+5, 4); err != nil || !ok || a.TargetEpoch != top {
			t.Errorf("SurroundingAttestation(2^63+5, 4): %+v, %v, %v; want the attestation at 2^63-1", a, ok, err)
		}
		if _, ok, err := tx.NearestAttestation(big); err != nil || ok {
			t.Errorf("NearestAttestation(2^63): %v, %v", ok, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCheckURL(t *testing.T) {
	for raw, want := range map[string]string{
		"postgres://u@db:5432/signer?sslmode=verify-full": "",
		"postgresql://db/signer":                          "",
		"postgres://u:secret@db/signer":                   "password",
		"postgres://u@db/signer?password=secret":          "password",
		"postgres://u@db/signer?pool_max_conns=50":        "pool_max_conns",
		"mysql://db/signer":                               "postgres://",
		"db/signer":                                       "postgres://",
	} {
		err := pgstore.CheckURL(raw)
		if (want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), want)) {
			t.Errorf("CheckURL(%q) = %v, want an error containing %q", raw, err, want)
		}
	}
}

func TestOpenRefusesPGPASSWORD(t *testing.T) {
	t.Setenv("PGPASSWORD", "secret")
	_, err := pgstore.Open(bg, pgstore.Config{URL: "postgres://u@127.0.0.1:1/x"})
	if !errors.Is(err, pgstore.ErrPasswordInEnv) {
		t.Fatalf("Open with PGPASSWORD set: %v", err)
	}
	if _, err := pgstore.Migrate(bg, pgstore.Config{URL: "postgres://u@127.0.0.1:1/x"}); !errors.Is(err, pgstore.ErrPasswordInEnv) {
		t.Fatalf("Migrate with PGPASSWORD set: %v", err)
	}
}

// A database without the schema, and one with an older schema, refuse to open with a message naming consensus
// migrate; a newer schema and a schema the store did not create are always refused. Migrate creates the schema
// once and is idempotent.
func TestPostgresSchemaVersions(t *testing.T) {
	t.Run("empty database", func(t *testing.T) {
		db := pgtest.New(t)
		_, err := pgstore.Open(bg, config(db))
		if !errors.Is(err, slashing.ErrSchemaTooOld) || !strings.Contains(err.Error(), "consensus migrate") {
			t.Fatalf("Open on an empty database: %v", err)
		}
		m, err := pgstore.Migrate(bg, config(db))
		if err != nil || m != (pgstore.Migration{From: 0, To: slashing.SchemaVersion}) {
			t.Fatalf("Migrate: %+v, %v", m, err)
		}
		m, err = pgstore.Migrate(bg, config(db))
		if err != nil || m != (pgstore.Migration{From: slashing.SchemaVersion, To: slashing.SchemaVersion}) {
			t.Fatalf("second Migrate: %+v, %v", m, err)
		}
		s := open(t, config(db))
		if err := slashing.CheckSchema(bg, s); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("newer schema", func(t *testing.T) {
		db := migrated(t)
		db.Exec(t, `UPDATE database_version SET version = $1 WHERE id = 1`, int32(slashing.SchemaVersion+1))
		_, err := pgstore.Open(bg, config(db))
		if !errors.Is(err, slashing.ErrSchemaTooNew) || !strings.Contains(err.Error(), "downgrade is not supported") {
			t.Fatalf("Open on a newer schema: %v", err)
		}
		if _, err := pgstore.Migrate(bg, config(db)); !errors.Is(err, slashing.ErrSchemaTooNew) {
			t.Fatalf("Migrate on a newer schema: %v", err)
		}
	})
	t.Run("Web3Signer schema", func(t *testing.T) {
		db := pgtest.New(t)
		// The shape of a Web3Signer database: its validators table and database_version at version 12.
		db.Exec(t, `CREATE TABLE validators (id SERIAL PRIMARY KEY, public_key BYTEA NOT NULL UNIQUE);
			CREATE TABLE database_version (id INTEGER PRIMARY KEY, version INTEGER NOT NULL);
			INSERT INTO database_version VALUES (1, 12)`)
		if _, err := pgstore.Open(bg, config(db)); !errors.Is(err, pgstore.ErrForeignSchema) {
			t.Fatalf("Open on a Web3Signer database: %v", err)
		}
		if _, err := pgstore.Migrate(bg, config(db)); !errors.Is(err, pgstore.ErrForeignSchema) {
			t.Fatalf("Migrate on a Web3Signer database: %v", err)
		}
	})
	t.Run("missing version row", func(t *testing.T) {
		db := migrated(t)
		db.Exec(t, `DELETE FROM database_version`)
		if _, err := pgstore.Open(bg, config(db)); !errors.Is(err, pgstore.ErrForeignSchema) {
			t.Fatalf("Open without a version row: %v", err)
		}
	})
}

// Signers starting together migrate once: the others wait for the migration lock and find the schema current.
func TestPostgresConcurrentMigrate(t *testing.T) {
	db := pgtest.New(t)
	const n = 8
	var (
		wg   sync.WaitGroup
		ms   [n]pgstore.Migration
		errs [n]error
	)
	start := make(chan struct{})
	for i := range n {
		wg.Go(func() {
			<-start
			ms[i], errs[i] = pgstore.Migrate(bg, config(db))
		})
	}
	close(start)
	wg.Wait()
	created := 0
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("Migrate %d: %v", i, errs[i])
		}
		if ms[i].To != slashing.SchemaVersion {
			t.Fatalf("Migrate %d: %+v", i, ms[i])
		}
		if ms[i].From == 0 {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("%d migrations created the schema, want 1", created)
	}
	open(t, config(db))
}

func TestPostgresGenesisValidatorsRootAtOpen(t *testing.T) {
	db := migrated(t)
	gvr := slashingtest.GVR
	var pinned []slashing.Root
	cfg := config(db)
	cfg.OnPin = func(r slashing.Root) { pinned = append(pinned, r) }
	cfg.GenesisValidatorsRoot = &gvr
	s := open(t, cfg)
	if got, ok, err := s.GenesisValidatorsRoot(bg); err != nil || !ok || got != gvr {
		t.Fatalf("root pinned by Open: %x, %v, %v", got, ok, err)
	}
	if len(pinned) != 0 {
		t.Fatal("OnPin called for the root Open pinned")
	}
	other := slashingtest.RootOf(7)
	cfg.GenesisValidatorsRoot = &other
	if _, err := pgstore.Open(bg, cfg); !errors.Is(err, slashing.ErrGenesisValidatorsRootMismatch) {
		t.Fatalf("Open with another root: %v", err)
	}

	db2 := migrated(t)
	cfg2 := config(db2)
	cfg2.OnPin = cfg.OnPin
	s2 := open(t, cfg2)
	if _, err := s2.PinGenesisValidatorsRoot(bg, other); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.PinGenesisValidatorsRoot(bg, gvr); err != nil {
		t.Fatal(err)
	}
	if len(pinned) != 1 || pinned[0] != other {
		t.Fatalf("OnPin calls %x, want one with the first root", pinned)
	}
}

func TestPostgresClosed(t *testing.T) {
	s := open(t, config(migrated(t)))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SchemaVersion(bg); !errors.Is(err, pgstore.ErrClosed) {
		t.Fatalf("SchemaVersion after Close: %v", err)
	}
	if err := s.ViewHistory(bg, func(slashing.HistoryView) error { return nil }); !errors.Is(err, pgstore.ErrClosed) {
		t.Fatalf("ViewHistory after Close: %v", err)
	}
}

// Registering known keys again never writes their rows: the row version (xmin) of an existing validator stays the
// same, so a reload on one replica cannot overwrite a flag another replica set.
func TestPostgresRegisterNeverWritesKnownRows(t *testing.T) {
	db := migrated(t)
	s := open(t, config(db))
	register(t, s, 3)
	if err := s.SetValidatorEnabled(bg, key(1), false); err != nil {
		t.Fatal(err)
	}
	conn := db.Connect(t)
	xmins := func() map[string]string {
		rows, err := conn.Query(bg, `SELECT encode(pubkey_hash, 'hex'), xmin::text || ':' || enabled::text FROM validators`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]string{}
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err != nil {
				t.Fatal(err)
			}
			out[k] = v
		}
		return out
	}
	before := xmins()
	register(t, s, 5)
	if err := s.RegisterValidatorsDisabled(bg, [][]byte{slashingtest.Key(0), slashingtest.Key(1)}); err != nil {
		t.Fatal(err)
	}
	after := xmins()
	for k, v := range before {
		if after[k] != v {
			t.Errorf("validator %s: row %s became %s", k[:8], v, after[k])
		}
	}
	if len(after) != 5 {
		t.Errorf("%d validators, want 5", len(after))
	}
}

func TestReadPasswordFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	strict := secretfile.Policy{Strict: true}
	for content, want := range map[string]string{"s3cret\n": "s3cret", "s3cret\r\nignored\n": "s3cret", "s3cret": "s3cret"} {
		got, err := pgstore.ReadPasswordFile(write("pw", content, 0o600), strict)
		if err != nil || got != want {
			t.Errorf("%q: %q, %v; want %q", content, got, err, want)
		}
	}
	if _, err := pgstore.ReadPasswordFile(write("empty", "\nsecond\n", 0o600), strict); err == nil {
		t.Error("an empty first line was accepted")
	}
	if runtime.GOOS != "windows" {
		open := write("open", "s3cret\n", 0o644)
		if _, err := pgstore.ReadPasswordFile(open, strict); !errors.Is(err, secretfile.ErrInsecure) {
			t.Errorf("a world-readable file under the strict policy: %v", err)
		}
		if got, err := pgstore.ReadPasswordFile(open, secretfile.Policy{}); err != nil || got != "s3cret" {
			t.Errorf("a world-readable file under the lax policy: %q, %v", got, err)
		}
	}
}
