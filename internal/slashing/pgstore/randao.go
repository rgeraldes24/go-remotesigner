// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package pgstore

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// RandaoState returns the validator's frontier, if one is stored, from one indexed read of its row. The reveal
// service classifies every request against it, not against anything a process remembers.
func (s *Store) RandaoState(ctx context.Context, id slashing.KeyID) (slashing.RandaoState, bool, error) {
	var (
		st slashing.RandaoState
		ok bool
	)
	err := s.call(ctx, "read the RANDAO frontier", func(ctx context.Context) error {
		var (
			index, last *int64
			reveal      []byte
		)
		err := s.pool.QueryRow(ctx, `SELECT r.deepest_index, r.deepest_reveal, r.last_new_slot
			FROM validators v LEFT JOIN randao_reveal_state r ON r.validator_id = v.id WHERE v.pubkey_hash = $1`,
			id[:]).Scan(&index, &reveal, &last)
		if errors.Is(err, pgx.ErrNoRows) {
			return slashing.ErrValidatorNotRegistered
		}
		if err != nil || index == nil {
			return err
		}
		st, ok, err = randaoState(*index, reveal, *last)
		return err
	})
	return st, ok, err
}

func randaoState(index int64, reveal []byte, last int64) (slashing.RandaoState, bool, error) {
	var (
		st  slashing.RandaoState
		err error
	)
	if st.Index, err = u64(index); err != nil {
		return st, false, err
	}
	if st.LastSlot, err = u64(last); err != nil {
		return st, false, err
	}
	r, err := root(reveal)
	if err != nil || r == nil {
		return st, false, err
	}
	st.Reveal = *r
	return st, true, nil
}

// CompareAndSwapRandaoState stores next if the stored frontier equals old (nil: none stored). It takes the
// validator's RANDAO lock, re-reads the row under it and compares; the write itself is a compare-and-set on the
// row's values as well. Next is committed before it returns.
func (s *Store) CompareAndSwapRandaoState(ctx context.Context, id slashing.KeyID, old *slashing.RandaoState, next slashing.RandaoState) (bool, error) {
	index, err := i64(next.Index)
	if err != nil {
		return false, err
	}
	last, err := i64(next.LastSlot)
	if err != nil {
		return false, err
	}
	var swapped bool
	err = s.inTx(ctx, "store the RANDAO frontier", func(ctx context.Context, tx pgx.Tx) error {
		swapped = false
		vid, err := lockValidator(ctx, tx, id, lockRandao)
		if err != nil {
			return err
		}
		var (
			curIndex, curLast int64
			curReveal         []byte
		)
		err = tx.QueryRow(ctx, `SELECT deepest_index, deepest_reveal, last_new_slot FROM randao_reveal_state
			WHERE validator_id = $1`, vid).Scan(&curIndex, &curReveal, &curLast)
		found := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if found != (old != nil) {
			return nil
		}
		var cmd string
		args := []any{vid, index, next.Reveal[:], last}
		if old == nil {
			cmd = `INSERT INTO randao_reveal_state (validator_id, deepest_index, deepest_reveal, last_new_slot, updated_at)
				VALUES ($1, $2, $3, $4, now()) ON CONFLICT (validator_id) DO NOTHING`
		} else {
			cur, _, err := randaoState(curIndex, curReveal, curLast)
			if err != nil || cur != *old {
				return err
			}
			cmd = `UPDATE randao_reveal_state SET deepest_index = $2, deepest_reveal = $3, last_new_slot = $4,
				updated_at = now() WHERE validator_id = $1 AND deepest_index = $5 AND deepest_reveal = $6
				AND last_new_slot = $7`
			args = append(args, curIndex, curReveal, curLast)
		}
		tag, err := tx.Exec(ctx, cmd, args...)
		swapped = err == nil && tag.RowsAffected() == 1
		return err
	})
	return swapped && err == nil, err
}

// DeleteRandaoState removes the validator's frontier under its RANDAO lock.
func (s *Store) DeleteRandaoState(ctx context.Context, id slashing.KeyID) error {
	return s.inTx(ctx, "delete the RANDAO frontier", func(ctx context.Context, tx pgx.Tx) error {
		vid, err := lockValidator(ctx, tx, id, lockRandao)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM randao_reveal_state WHERE validator_id = $1`, vid)
		return err
	})
}
