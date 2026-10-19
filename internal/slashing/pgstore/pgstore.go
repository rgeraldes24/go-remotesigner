// Copyright 2021 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go; the advisory locks gain the RANDAO type
// and one fixed order everywhere, and the connection profile bounds every call.
// Derived from Web3Signer
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbLocker.java and
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbConnection.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

// Package pgstore is the Postgres slashing.Store: one database that several signers serving the same keys share.
//
// Every check-and-record runs in one READ COMMITTED transaction under pg_advisory_xact_lock(type, validator id), the
// type being 0 for blocks, 1 for attestations and 2 for RANDAO frontiers. A transaction that takes several locks
// takes them in that order, and one that covers several validators (UpdateHistory: the interchange import, pruning,
// the watermark repair) takes them validator by validator in KeyID order, so no two transactions wait on each other
// in a cycle. Disabling a validator takes its block and then its attestation lock. A transaction that fails with
// SQLSTATE 40001 (serialisation failure) or 40P01 (deadlock detected) is rolled back and run again.
//
// Each call is bounded as a whole, acquiring a connection and any retry included, by Config.Timeout (4.5 s by
// default), and every session runs with lock_timeout 2 s, statement_timeout 5 s and
// idle_in_transaction_session_timeout 10 s, so that a stalled database fails a signing request with an error inside
// the server's 5 s write deadline instead of holding it.
//
// The schema is versioned in database_version. Open refuses a database without the schema or with an older one
// (run Migrate, `remotesigner consensus migrate`), and always one with a newer one or a schema it did not write.
//
// Slots and epochs are stored as BIGINT: values above 2^63-1 are refused with ErrOutOfRange before they reach the
// database.
package pgstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// The operations profile (docs/operations/postgres.md).
const (
	// DefaultMaxConns and DefaultMinConns size the signing pool.
	DefaultMaxConns = 16
	DefaultMinConns = 2
	// DefaultTimeout bounds one store call: acquiring a connection, the transaction and its retries. It leaves the
	// rest of a signing request room inside the server's 5 s write deadline.
	DefaultTimeout = 4500 * time.Millisecond
	// CommandTimeout bounds one store call of a store command (consensus import, export, watermark-repair, ...):
	// an online import writes a validator's whole history in one call, at two or three round trips per record, so
	// the signing bound would fail a long but valid history. lock_timeout and statement_timeout still bound every
	// wait and every statement.
	CommandTimeout = 10 * time.Minute
	// ConnectTimeout bounds opening one connection.
	ConnectTimeout = 5 * time.Second
	// Session settings of every connection.
	LockTimeout                     = 2 * time.Second
	StatementTimeout                = 5 * time.Second
	IdleInTransactionSessionTimeout = 10 * time.Second
	// maxAttempts bounds the runs of a transaction that keeps failing with 40001 or 40P01.
	maxAttempts = 5
)

// Advisory lock types: the first key of pg_advisory_xact_lock(type, validator id), in the order they are taken.
const (
	lockBlock       = 0
	lockAttestation = 1
	lockRandao      = 2
	// lockMigration is the first key of the session lock pg_advisory_lock(3, 0) that Migrate holds.
	lockMigration = 3
)

// SQLSTATE codes.
const (
	codeSerializationFailure = "40001"
	codeDeadlockDetected     = "40P01"
	// codeWatermark is raised by the schema's watermark triggers.
	codeWatermark = "RSW01"
)

var (
	// ErrClosed is returned by every method after Close.
	ErrClosed = errors.New("pgstore: store is closed")
	// ErrOutOfRange: a slot, epoch or onion index is above 2^63-1, the largest value a BIGINT column holds.
	ErrOutOfRange = errors.New("pgstore: value above 9223372036854775807, the largest the Postgres store holds")
	// ErrForeignSchema: the database holds tables this store did not create, such as Web3Signer's schema.
	ErrForeignSchema = errors.New("pgstore: the database holds a schema this remotesigner did not create " +
		"(a Web3Signer database?); use an empty database and import the old history with consensus import")
	// ErrPasswordInURL: the connection URL carries a password, which belongs in a password file.
	ErrPasswordInURL = errors.New("the URL carries a password: give it in --slashing-protection-db-password-file " +
		"or a PGPASSFILE file instead")
	// ErrPasswordInEnv: PGPASSWORD is set, which puts the password in the environment of the process.
	ErrPasswordInEnv = errors.New("PGPASSWORD is set: give the password in --slashing-protection-db-password-file " +
		"or a PGPASSFILE file instead, and unset it")
)

// Config configures Open and Migrate.
type Config struct {
	// URL is the connection URL, postgres:// or postgresql://, with libpq's parameters. It must not carry a
	// password.
	URL string
	// User, when set, replaces the URL's user name.
	User string
	// Password, when set, is the user's password. Otherwise the password, if one is needed, comes from libpq's
	// password file (PGPASSFILE, by default ~/.pgpass).
	Password string
	// GenesisValidatorsRoot, when set, is the network's configured root. A store that has no root yet is pinned to
	// it; a store pinned to a different root is refused with slashing.ErrGenesisValidatorsRootMismatch.
	GenesisValidatorsRoot *slashing.Root
	// OnPin, when set, is called with the root after PinGenesisValidatorsRoot has pinned a store that had none. It
	// is not called for a root pinned by Open.
	OnPin func(slashing.Root)
	// MaxConns and MinConns size the pool; zero means DefaultMaxConns and DefaultMinConns.
	MaxConns, MinConns int32
	// Timeout bounds each store call; zero means DefaultTimeout.
	Timeout time.Duration
}

// String names the database for messages: host, port and database, without credentials.
func (c Config) String() string {
	cc, err := pgconn.ParseConfig(c.URL)
	if err != nil {
		return "the Postgres database"
	}
	return fmt.Sprintf("Postgres database %q on %s:%d", cc.Database, cc.Host, cc.Port)
}

// configure applies the user, the password and the session settings to a parsed connection configuration. A
// password in PGPASSWORD is refused: it belongs in a password file.
func (c Config) configure(cc *pgx.ConnConfig) error {
	if os.Getenv("PGPASSWORD") != "" {
		return ErrPasswordInEnv
	}
	if c.User != "" {
		cc.User = c.User
	}
	if c.Password != "" {
		cc.Password = c.Password
	}
	if cc.ConnectTimeout == 0 || cc.ConnectTimeout > ConnectTimeout {
		cc.ConnectTimeout = ConnectTimeout
	}
	if cc.RuntimeParams == nil {
		cc.RuntimeParams = map[string]string{}
	}
	if cc.RuntimeParams["application_name"] == "" {
		cc.RuntimeParams["application_name"] = "remotesigner"
	}
	cc.RuntimeParams["lock_timeout"] = millis(LockTimeout)
	cc.RuntimeParams["statement_timeout"] = millis(StatementTimeout)
	cc.RuntimeParams["idle_in_transaction_session_timeout"] = millis(IdleInTransactionSessionTimeout)
	return nil
}

func millis(d time.Duration) string { return fmt.Sprint(d.Milliseconds()) }

// CheckURL refuses a connection URL that is not postgres:// or postgresql://, that carries a password, or that sets
// the pool, whose profile is fixed.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return errors.New("want a postgres:// or postgresql:// URL")
	}
	if _, set := u.User.Password(); set || u.Query().Has("password") {
		return ErrPasswordInURL
	}
	for k := range u.Query() {
		if strings.HasPrefix(k, "pool_") {
			return fmt.Errorf("the URL sets %s: the pool profile is fixed (docs/operations/postgres.md)", k)
		}
	}
	return nil
}

// Store is a Postgres-backed slashing.Store, safe for concurrent use and shared by any number of processes.
type Store struct {
	pool    *pgxpool.Pool
	timeout time.Duration
	onPin   func(slashing.Root)
	name    string
	closed  atomic.Bool
}

var _ slashing.Store = (*Store)(nil)

// Open connects to the database and checks its schema version. It fails with a *slashing.SchemaError (wrapped)
// when the database has no schema yet, an older or a newer one, with ErrForeignSchema for a database it did not
// create, and with slashing.ErrGenesisValidatorsRootMismatch when cfg.GenesisValidatorsRoot differs from the pinned
// root.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	if err := CheckURL(cfg.URL); err != nil {
		return nil, err
	}
	pc, err := pgxpool.ParseConfig(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("pgstore: %w", err)
	}
	if err := cfg.configure(pc.ConnConfig); err != nil {
		return nil, err
	}
	pc.MaxConns, pc.MinConns = DefaultMaxConns, DefaultMinConns
	if cfg.MaxConns > 0 {
		pc.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns > 0 || cfg.MaxConns > 0 {
		pc.MinConns = min(cfg.MinConns, pc.MaxConns)
	}
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("pgstore: %w", err)
	}
	s := &Store{pool: pool, timeout: cfg.Timeout, onPin: cfg.OnPin, name: cfg.String()}
	if s.timeout <= 0 {
		s.timeout = DefaultTimeout
	}
	if err := s.open(ctx, cfg.GenesisValidatorsRoot); err != nil {
		pool.Close()
		return nil, fmt.Errorf("%s: %w", s.name, err)
	}
	return s, nil
}

// open checks the schema version and applies the configured genesis validators root.
func (s *Store) open(ctx context.Context, gvr *slashing.Root) error {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	v, err := schemaVersion(ctx, s.pool)
	if err != nil {
		return err
	}
	if v != slashing.SchemaVersion {
		err := &slashing.SchemaError{Stored: v, Expected: slashing.SchemaVersion}
		if v == 0 {
			return fmt.Errorf("the database has no slashing-protection schema yet: %w", err)
		}
		return err
	}
	if gvr == nil {
		return nil
	}
	pinned, _, err := s.pin(ctx, *gvr)
	if err != nil {
		return err
	}
	if pinned != *gvr {
		return fmt.Errorf("%w: configured %#x, store pinned to %#x",
			slashing.ErrGenesisValidatorsRootMismatch, gvr[:], pinned[:])
	}
	return nil
}

// Close closes the pool. It waits for the connections in use to be returned.
func (s *Store) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	s.pool.Close()
	return nil
}

// Name names the database for messages, without credentials.
func (s *Store) Name() string { return s.name }

// call runs fn with a context bounded by the store's timeout.
func (s *Store) call(ctx context.Context, op string, fn func(ctx context.Context) error) error {
	if s.closed.Load() {
		return ErrClosed
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	return wrap(op, fn(ctx))
}

// inTx runs fn in a READ COMMITTED transaction bounded by the store's timeout, and runs it again after a
// serialisation failure or a deadlock.
func (s *Store) inTx(ctx context.Context, op string, fn func(ctx context.Context, tx pgx.Tx) error) error {
	return s.call(ctx, op, func(ctx context.Context) error {
		return retry(ctx, func() error {
			return pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
				func(tx pgx.Tx) error { return fn(ctx, tx) })
		})
	})
}

// inValidatorTx runs fn in a READ COMMITTED transaction that holds one validator's advisory lock of type typ, with
// the validator's head (its enabled flag and both watermarks) read. BEGIN, the lock and the head read reach the
// server together, in one round trip: the head is read by a statement that starts once the lock is granted, so it
// sees every transaction that held the lock before. An unknown key is slashing.ErrValidatorNotRegistered. Like
// inTx, it is bounded by the store's timeout and runs fn again after a serialisation failure or a deadlock.
func (s *Store) inValidatorTx(ctx context.Context, op string, id slashing.KeyID, typ int,
	fn func(*validatorTx) error) error {
	return s.call(ctx, op, func(ctx context.Context) error {
		return retry(ctx, func() error {
			conn, err := s.pool.Acquire(ctx)
			if err != nil {
				return err
			}
			// A connection left inside a transaction (a failed rollback) is closed by the pool, not reused.
			defer conn.Release()
			return runValidatorTx(ctx, conn, id, typ, fn)
		})
	})
}

// runValidatorTx is one run of inValidatorTx's transaction on conn.
func runValidatorTx(ctx context.Context, conn *pgxpool.Conn, id slashing.KeyID, typ int,
	fn func(*validatorTx) error) error {
	b := &pgx.Batch{}
	b.Queue(`BEGIN ISOLATION LEVEL READ COMMITTED`)
	b.Queue(fmt.Sprintf(`SELECT pg_advisory_xact_lock(%d, id) FROM validators WHERE pubkey_hash = $1`, typ), id[:])
	b.Queue(headSQL+`v.pubkey_hash = $1`, id[:])
	br := conn.SendBatch(ctx, b)
	_, err := br.Exec()
	if err == nil {
		_, err = br.Exec()
	}
	var (
		vid int32
		h   *head
	)
	if err == nil {
		vid, h, err = scanHead(br.QueryRow())
		if errors.Is(err, pgx.ErrNoRows) {
			err = slashing.ErrValidatorNotRegistered
		}
	}
	if cerr := br.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = fn(&validatorTx{ctx: ctx, tx: conn, vid: vid, head: h})
	}
	if err != nil {
		_, _ = conn.Exec(ctx, `ROLLBACK`)
		return err
	}
	tag, err := conn.Exec(ctx, `COMMIT`)
	if err == nil && tag.String() == "ROLLBACK" {
		// A statement failed and fn went on: the server rolled the transaction back.
		err = pgx.ErrTxCommitRollback
	}
	return err
}

// retry runs fn until it succeeds, fails with an error other than 40001 or 40P01, has run maxAttempts times, or ctx
// ends.
func retry(ctx context.Context, fn func() error) error {
	for attempt := 1; ; attempt++ {
		err := fn()
		if err == nil || !Retryable(err) || attempt == maxAttempts {
			return err
		}
		select {
		case <-time.After(time.Duration(attempt) * 5 * time.Millisecond):
		case <-ctx.Done():
			return err
		}
	}
}

// Retryable reports whether err is a serialisation failure (40001) or a detected deadlock (40P01), after which the
// whole transaction can run again.
func Retryable(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && (pe.Code == codeSerializationFailure || pe.Code == codeDeadlockDetected)
}

// wrap names the operation in a database error and maps the schema's watermark refusals to
// slashing.ErrWatermarkConflict. The store's own sentinel errors pass unchanged.
func wrap(op string, err error) error {
	var pe *pgconn.PgError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &pe) && pe.Code == codeWatermark:
		return fmt.Errorf("%w (%s)", slashing.ErrWatermarkConflict, pe.Message)
	case errors.Is(err, slashing.ErrValidatorNotRegistered), errors.Is(err, slashing.ErrWatermarkConflict),
		errors.Is(err, slashing.ErrNoGenesisValidatorsRoot), errors.Is(err, slashing.ErrInvalidPublicKey),
		errors.Is(err, slashing.ErrDuplicateRecord), errors.Is(err, ErrOutOfRange), errors.Is(err, ErrClosed):
		return err
	}
	return fmt.Errorf("pgstore: %s: %w", op, err)
}

// i64 converts a slot, epoch or index for a BIGINT column.
func i64(v uint64) (int64, error) {
	if v > math.MaxInt64 {
		return 0, fmt.Errorf("%w: %d", ErrOutOfRange, v)
	}
	return int64(v), nil
}

// u64 converts a BIGINT value read from the store; the schema's checks keep it non-negative.
func u64(v int64) (uint64, error) {
	if v < 0 {
		return 0, fmt.Errorf("pgstore: negative value %d in the database", v)
	}
	return uint64(v), nil
}

func u64p(v *int64) (*uint64, error) {
	if v == nil {
		return nil, nil
	}
	u, err := u64(*v)
	return &u, err
}

// root decodes a 32-byte root column; nil stays nil.
func root(b []byte) (*slashing.Root, error) {
	if b == nil {
		return nil, nil
	}
	if len(b) != len(slashing.Root{}) {
		return nil, fmt.Errorf("pgstore: a %d-byte root in the database", len(b))
	}
	r := slashing.Root(b)
	return &r, nil
}

// rootBytes encodes a root for a nullable column.
func rootBytes(r *slashing.Root) []byte {
	if r == nil {
		return nil
	}
	return r[:]
}

// lockValidator resolves a validator's id and takes its advisory lock of type typ, in one statement. It returns
// slashing.ErrValidatorNotRegistered for an unknown key.
func lockValidator(ctx context.Context, tx pgx.Tx, id slashing.KeyID, typ int) (int32, error) {
	var vid int32
	err := tx.QueryRow(ctx, fmt.Sprintf(
		`SELECT id, pg_advisory_xact_lock(%d, id) FROM validators WHERE pubkey_hash = $1`, typ), id[:]).Scan(&vid, nil)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, slashing.ErrValidatorNotRegistered
	}
	return vid, err
}

// lock takes the advisory lock of type typ of a validator whose id is known.
func lock(ctx context.Context, tx pgx.Tx, vid int32, typ int) error {
	_, err := tx.Exec(ctx, fmt.Sprintf(`SELECT pg_advisory_xact_lock(%d, $1)`, typ), vid)
	return err
}

// maxPasswordFile bounds a password file.
const maxPasswordFile = 64 << 10

// ReadPasswordFile reads a password file (--slashing-protection-db-password-file) under the secret-file policy p:
// its first line, without the line ending, is the password. An empty password is refused.
func ReadPasswordFile(path string, p secretfile.Policy) (string, error) {
	data, err := secretfile.Read(path, maxPasswordFile, p)
	if err != nil {
		return "", err
	}
	defer mldsa87.Wipe(data)
	line, _, _ := bytes.Cut(data, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	if len(line) == 0 {
		return "", fmt.Errorf("%s: the first line is empty", path)
	}
	return string(line), nil
}
