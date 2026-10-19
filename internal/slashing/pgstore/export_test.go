// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package pgstore

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool is the store's connection pool, for the tests of its operations profile.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Timeout is the bound of one store call.
func (s *Store) Timeout() time.Duration { return s.timeout }
