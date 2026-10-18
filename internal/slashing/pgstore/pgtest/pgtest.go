// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package pgtest gives tests their own Postgres databases on a server named by the environment. Tests that need
// Postgres call New, which skips the test unless REMOTESIGNER_TEST_POSTGRES holds the URL of a role that may create
// databases and roles, so that the default `go test ./...` passes without a server:
//
//	REMOTESIGNER_TEST_POSTGRES=postgres://postgres:secret@127.0.0.1:5432/postgres?sslmode=disable
//
// `make test-postgres` runs the tests that do (every one has Postgres in its name); CI runs them against a postgres
// service container.
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing/pgstore"
)

// Env names the variable that holds the server's admin URL.
const Env = "REMOTESIGNER_TEST_POSTGRES"

// DB is a fresh database that the test owns; it is dropped when the test ends.
type DB struct {
	// Name is the database name.
	Name string
	// URL connects to it as the admin role, without the password.
	URL string
	// User and Password are the admin role's.
	User, Password string
	admin          string
}

// Enabled reports whether a test server is configured.
func Enabled() bool { return os.Getenv(Env) != "" }

// Skip skips t unless a test server is configured.
func Skip(t testing.TB) {
	t.Helper()
	if !Enabled() {
		t.Skipf("set %s to the URL of a Postgres admin role to run this test", Env)
	}
}

// New creates an empty database for t and drops it, with FORCE, when the test ends. It skips t unless a test server
// is configured.
func New(t testing.TB) *DB {
	t.Helper()
	Skip(t)
	admin := os.Getenv(Env)
	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("%s: %v", Env, err)
	}
	name := "rs_" + Random(t, 8)
	Exec(t, admin, `CREATE DATABASE `+pgx.Identifier{name}.Sanitize())
	t.Cleanup(func() {
		// The database may still be closing its last connections.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, admin)
		if err != nil {
			t.Errorf("drop database %s: %v", name, err)
			return
		}
		defer func() { _ = conn.Close(context.Background()) }()
		if _, err := conn.Exec(ctx, `DROP DATABASE `+pgx.Identifier{name}.Sanitize()+` WITH (FORCE)`); err != nil {
			t.Errorf("drop database %s: %v", name, err)
		}
	})
	db := &DB{Name: name, admin: admin, User: u.User.Username()}
	db.Password, _ = u.User.Password()
	u.User = url.User(db.User)
	u.Path = "/" + name
	db.URL = u.String()
	return db
}

// AdminURL is the database's URL with the admin role's password, for test helpers that connect directly.
func (d *DB) AdminURL() string {
	u, _ := url.Parse(d.URL)
	u.User = url.UserPassword(d.User, d.Password)
	return u.String()
}

// URLFor is the database's URL as another role, without a password.
func (d *DB) URLFor(user string) string {
	u, _ := url.Parse(d.URL)
	u.User = url.User(user)
	return u.String()
}

// PasswordFile writes the admin role's password to a 0600 file under a temporary directory and returns its path.
func (d *DB) PasswordFile(t testing.TB) string {
	t.Helper()
	return WritePasswordFile(t, d.Password)
}

// WritePasswordFile writes password to a 0600 file under a temporary directory and returns its path.
func WritePasswordFile(t testing.TB, password string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "db-password")
	if err := os.WriteFile(p, []byte(password+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// Exec runs sql, which may hold several statements, on the database at dsn.
func Exec(t testing.TB, dsn, sql string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	if _, err := conn.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// Exec runs sql on the database as the admin role.
func (d *DB) Exec(t testing.TB, sql string, args ...any) {
	t.Helper()
	Exec(t, d.AdminURL(), sql, args...)
}

// Connect opens a connection to the database as the admin role, closed when the test ends.
func (d *DB) Connect(t testing.TB) *pgx.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, d.AdminURL())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// ExecServer runs sql as the admin role on the server's maintenance database, for statements about roles.
func ExecServer(t testing.TB, sql string, args ...any) {
	t.Helper()
	Exec(t, os.Getenv(Env), sql, args...)
}

// Random returns n random bytes in hex, for unique names.
func Random(t testing.TB, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// String describes the database for test logs.
func (d *DB) String() string { return fmt.Sprintf("database %s", d.Name) }

// Store opens a Postgres store on a fresh database with the current schema, as the admin role. The caller closes
// it; the database is dropped when the test ends. It skips t unless a test server is configured.
func Store(t testing.TB) *pgstore.Store {
	t.Helper()
	db := New(t)
	cfg := pgstore.Config{URL: db.URL, Password: db.Password}
	if _, err := pgstore.Migrate(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	s, err := pgstore.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
