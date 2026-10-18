// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package slashingtest

import (
	"context"
	"errors"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// Retrying wraps s so that every UpdateHistory runs its function twice, as a backend that retries a transaction
// after a serialisation failure or a deadlock (a Postgres store) does: the first attempt calls fn for every id and
// is rolled back, and the second calls it again from the first id. A caller of UpdateHistory must get the same
// result through it as through s.
func Retrying(s slashing.Store) slashing.Store { return retrying{s} }

type retrying struct{ slashing.Store }

var errRetry = errors.New("slashingtest: simulated serialisation failure")

func (r retrying) UpdateHistory(ctx context.Context, ids []slashing.KeyID, fn func(slashing.KeyID, slashing.HistoryTx) error) error {
	calls := 0
	err := r.Store.UpdateHistory(ctx, ids, func(id slashing.KeyID, tx slashing.HistoryTx) error {
		if err := fn(id, tx); err != nil {
			return err
		}
		if calls++; calls == len(ids) {
			return errRetry
		}
		return nil
	})
	if !errors.Is(err, errRetry) {
		return err
	}
	return r.Store.UpdateHistory(ctx, ids, fn)
}
