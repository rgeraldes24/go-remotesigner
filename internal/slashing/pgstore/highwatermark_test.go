// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package pgstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// The schema keeps a high watermark whole: a write made around the store
// that sets one part alone violates its CHECK constraint, and a store that
// holds one anyway (a database from before the constraint) is reported as
// damaged instead of being served.
func TestPostgresPartialHighWatermark(t *testing.T) {
	db := migrated(t)
	s := open(t, config(db))
	if _, err := s.PinGenesisValidatorsRoot(bg, slashingtest.GVR); err != nil {
		t.Fatal(err)
	}
	conn := db.Connect(t)
	for _, sql := range []string{
		`UPDATE metadata SET high_watermark_epoch = 5 WHERE id = 1`,
		`UPDATE metadata SET high_watermark_slot = 5 WHERE id = 1`,
	} {
		_, err := conn.Exec(context.Background(), sql)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "both_high_watermark_parts_set_or_null" {
			t.Errorf("%s: %v, want a check_violation of both_high_watermark_parts_set_or_null", sql, err)
		}
	}
	if h, err := s.HighWatermark(bg); err != nil || h.IsSet() {
		t.Fatalf("high watermark after the refused writes: %+v, %v", h, err)
	}

	// Without the constraint, as a database migrated before it would be, a
	// partial watermark is read as an error.
	if _, err := conn.Exec(context.Background(),
		`ALTER TABLE metadata DROP CONSTRAINT both_high_watermark_parts_set_or_null`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(context.Background(), `UPDATE metadata SET high_watermark_epoch = 5 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HighWatermark(bg); !errors.Is(err, slashing.ErrPartialHighWatermark) {
		t.Fatalf("HighWatermark of a partial row: %v, want ErrPartialHighWatermark", err)
	}
}
