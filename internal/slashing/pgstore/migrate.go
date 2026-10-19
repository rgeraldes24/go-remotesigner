// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package pgstore

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"path"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// migrations holds the schema migrations: sql/NNNN.sql brings the schema to version NNNN.
//
//go:embed sql/*.sql
var migrations embed.FS

// migration returns the SQL that brings the schema from version v-1 to v.
func migration(v uint32) (string, error) {
	b, err := migrations.ReadFile(path.Join("sql", fmt.Sprintf("%04d.sql", v)))
	if err != nil {
		return "", fmt.Errorf("pgstore: no migration to schema version %d: %w", v, err)
	}
	return string(b), nil
}

// queryer is a connection, a pool or a transaction.
type queryer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// schemaVersion reads the schema version: 0 for a database without the schema, ErrForeignSchema for one whose
// tables this store did not create.
func schemaVersion(ctx context.Context, q queryer) (uint32, error) {
	var versioned, validators, randao bool
	err := q.QueryRow(ctx, `SELECT to_regclass('database_version') IS NOT NULL, to_regclass('validators') IS NOT NULL,
		to_regclass('randao_reveal_state') IS NOT NULL`).Scan(&versioned, &validators, &randao)
	switch {
	case err != nil:
		return 0, err
	case !versioned && !validators && !randao:
		return 0, nil
	case !versioned || !randao:
		return 0, ErrForeignSchema
	}
	var v int32
	err = q.QueryRow(ctx, `SELECT version FROM database_version WHERE id = 1`).Scan(&v)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, ErrForeignSchema
	case err != nil:
		return 0, err
	case v < 1:
		return 0, fmt.Errorf("pgstore: schema version %d in database_version", v)
	}
	return uint32(v), nil
}

// SchemaVersion returns the schema version recorded in database_version.
func (s *Store) SchemaVersion(ctx context.Context) (uint32, error) {
	var v uint32
	err := s.call(ctx, "read the schema version", func(ctx context.Context) error {
		var err error
		v, err = schemaVersion(ctx, s.pool)
		return err
	})
	return v, err
}

// Ping reads the schema version for the database health check, bounded by ctx alone: not by the store's call
// bound, which would cut short a check timeout longer than it. Each statement still runs under statement_timeout.
func (s *Store) Ping(ctx context.Context) error {
	if s.closed.Load() {
		return ErrClosed
	}
	_, err := schemaVersion(ctx, s.pool)
	return wrap("health check", err)
}

// Migration reports what Migrate did.
type Migration struct {
	From, To uint32
}

// Migrate brings the database's schema to slashing.SchemaVersion, creating it in a database that has none. It holds
// the session lock pg_advisory_lock(3, 0) while it reads and upgrades the schema, so that signers starting together
// migrate once: the others wait for the lock and then find the schema current. Each migration runs in its own
// transaction. A newer schema is refused with a *slashing.SchemaError, a schema this store did not create with
// ErrForeignSchema. Migrations need a role that may create tables, functions and triggers in the database.
func Migrate(ctx context.Context, cfg Config) (Migration, error) {
	if err := CheckURL(cfg.URL); err != nil {
		return Migration{}, err
	}
	cc, err := pgx.ParseConfig(cfg.URL)
	if err != nil {
		return Migration{}, fmt.Errorf("pgstore: %w", err)
	}
	if err := cfg.configure(cc); err != nil {
		return Migration{}, err
	}
	// A migration may wait for another one and may take long on a large database: it is bounded by ctx only.
	cc.RuntimeParams["lock_timeout"] = "0"
	cc.RuntimeParams["statement_timeout"] = "0"
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return Migration{}, fmt.Errorf("%s: %w", cfg, err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	m, err := migrate(ctx, conn)
	if err != nil {
		return m, fmt.Errorf("%s: %w", cfg, err)
	}
	return m, nil
}

func migrate(ctx context.Context, conn *pgx.Conn) (Migration, error) {
	if _, err := conn.Exec(ctx, fmt.Sprintf(`SELECT pg_advisory_lock(%d, 0)`, lockMigration)); err != nil {
		return Migration{}, fmt.Errorf("take the migration lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), fmt.Sprintf(`SELECT pg_advisory_unlock(%d, 0)`, lockMigration))
	}()
	from, err := schemaVersion(ctx, conn)
	if err != nil {
		return Migration{}, err
	}
	m := Migration{From: from, To: from}
	if from > slashing.SchemaVersion {
		return m, &slashing.SchemaError{Stored: from, Expected: slashing.SchemaVersion}
	}
	for v := from + 1; v <= slashing.SchemaVersion; v++ {
		sql, err := migration(v)
		if err != nil {
			return m, err
		}
		err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			// With no arguments the statements run in the simple protocol, several in one call.
			if _, err := tx.Exec(ctx, sql); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE database_version SET version = `+strconv.FormatUint(uint64(v), 10)+
				` WHERE id = 1`)
			return err
		})
		if err != nil {
			return m, fmt.Errorf("migrate to schema version %d: %w", v, err)
		}
		m.To = v
	}
	return m, nil
}
