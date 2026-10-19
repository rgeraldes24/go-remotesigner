// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package pgstore

import (
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool is the store's connection pool, for the tests of its operations profile.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Timeout is the bound of one store call.
func (s *Store) Timeout() time.Duration { return s.timeout }

// Password is the password a connection with cfg sends, from cfg.Password or libpq's password file.
func Password(cfg Config) (string, error) {
	cc, err := pgx.ParseConfig(cfg.URL)
	if err != nil {
		return "", err
	}
	err = cfg.configure(cc)
	return cc.Password, err
}
