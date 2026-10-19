// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package pgstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// viewPage is how many validators one query of HistoryView.Validators reads.
const viewPage = 256

// UpdateHistory runs fn once for each of ids, in order, in one transaction. It first takes the block and then the
// attestation lock of every validator, validator by validator in KeyID order, and holds them to the commit. A
// retried transaction runs fn again for every id.
func (s *Store) UpdateHistory(ctx context.Context, ids []slashing.KeyID, fn func(slashing.KeyID, slashing.HistoryTx) error) error {
	sorted := slices.Clone(ids)
	slices.SortFunc(sorted, func(a, b slashing.KeyID) int { return bytes.Compare(a[:], b[:]) })
	sorted = slices.Compact(sorted)
	hashes := make([][]byte, len(sorted))
	for i := range sorted {
		hashes[i] = sorted[i][:]
	}
	return s.inTx(ctx, "history transaction", func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT pubkey_hash, id FROM validators WHERE pubkey_hash = ANY($1)`, hashes)
		if err != nil {
			return err
		}
		vids := make(map[slashing.KeyID]int32, len(sorted))
		var (
			hash []byte
			vid  int32
		)
		_, err = pgx.ForEachRow(rows, []any{&hash, &vid}, func() error {
			vids[slashing.KeyID(hash)] = vid
			return nil
		})
		if err != nil {
			return err
		}
		if len(vids) != len(sorted) {
			return slashing.ErrValidatorNotRegistered
		}
		for _, id := range sorted {
			for _, typ := range []int{lockBlock, lockAttestation} {
				if err := lock(ctx, tx, vids[id], typ); err != nil {
					return err
				}
			}
		}
		for _, id := range ids {
			if err := fn(id, newHistoryTx(ctx, tx, vids[id])); err != nil {
				return err
			}
		}
		return nil
	})
}

// ViewHistory runs fn in a read-only REPEATABLE READ transaction: one snapshot of the whole store, taken without
// any advisory lock. It is bounded by ctx only, not by the store's timeout: an export may read for long. Every
// statement still runs under statement_timeout.
func (s *Store) ViewHistory(ctx context.Context, fn func(slashing.HistoryView) error) error {
	if s.closed.Load() {
		return ErrClosed
	}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly},
		func(tx pgx.Tx) error { return fn(&historyView{ctx: ctx, tx: tx}) })
	return wrap("read the history", err)
}

type historyView struct {
	ctx context.Context
	tx  pgx.Tx
}

var _ slashing.HistoryView = (*historyView)(nil)

func (v *historyView) GenesisValidatorsRoot() (slashing.Root, bool, error) {
	return genesisValidatorsRoot(v.ctx, v.tx)
}

// Validators reads the validators a page at a time, so that fn may query the view while it runs.
func (v *historyView) Validators(fn func(slashing.KeyID, []byte) error) error {
	after := []byte{}
	for {
		rows, err := v.tx.Query(v.ctx, `SELECT pubkey_hash, public_key FROM validators WHERE pubkey_hash > $1
			ORDER BY pubkey_hash LIMIT $2`, after, viewPage)
		if err != nil {
			return err
		}
		type validator struct {
			Hash []byte
			Key  []byte
		}
		page, err := pgx.CollectRows(rows, pgx.RowToStructByPos[validator])
		if err != nil {
			return err
		}
		for _, p := range page {
			if len(p.Hash) != len(slashing.KeyID{}) || len(p.Key) != slashing.PublicKeyLength {
				return fmt.Errorf("pgstore: a validator row with a %d-byte hash and a %d-byte key", len(p.Hash), len(p.Key))
			}
			if err := fn(slashing.KeyID(p.Hash), p.Key); err != nil {
				return err
			}
		}
		if len(page) < viewPage {
			return nil
		}
		after = page[len(page)-1].Hash
	}
}

func (v *historyView) id(id slashing.KeyID) (int32, error) {
	var vid int32
	err := v.tx.QueryRow(v.ctx, `SELECT id FROM validators WHERE pubkey_hash = $1`, id[:]).Scan(&vid)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, slashing.ErrValidatorNotRegistered
	}
	return vid, err
}

func (v *historyView) LowWatermark(id slashing.KeyID) (slashing.LowWatermark, error) {
	vid, err := v.id(id)
	if err != nil {
		return slashing.LowWatermark{}, err
	}
	return lowWatermark(v.ctx, v.tx, vid)
}

func (v *historyView) Blocks(id slashing.KeyID, fn func(slashing.SignedBlock) error) error {
	vid, err := v.id(id)
	if err != nil {
		return err
	}
	rows, err := v.tx.Query(v.ctx, `SELECT slot, signing_root FROM signed_blocks WHERE validator_id = $1 ORDER BY slot`, vid)
	if err != nil {
		return err
	}
	var (
		slot int64
		r    []byte
	)
	_, err = pgx.ForEachRow(rows, []any{&slot, &r}, func() error {
		var b slashing.SignedBlock
		var err error
		if b.Slot, err = u64(slot); err != nil {
			return err
		}
		if b.SigningRoot, err = root(r); err != nil {
			return err
		}
		return fn(b)
	})
	return err
}

func (v *historyView) Attestations(id slashing.KeyID, fn func(slashing.SignedAttestation) error) error {
	vid, err := v.id(id)
	if err != nil {
		return err
	}
	rows, err := v.tx.Query(v.ctx, `SELECT source_epoch, target_epoch, signing_root FROM signed_attestations
		WHERE validator_id = $1 ORDER BY target_epoch`, vid)
	if err != nil {
		return err
	}
	var (
		source, target int64
		r              []byte
	)
	_, err = pgx.ForEachRow(rows, []any{&source, &target, &r}, func() error {
		var a slashing.SignedAttestation
		var err error
		if a.SourceEpoch, err = u64(source); err != nil {
			return err
		}
		if a.TargetEpoch, err = u64(target); err != nil {
			return err
		}
		if a.SigningRoot, err = root(r); err != nil {
			return err
		}
		return fn(a)
	})
	return err
}
