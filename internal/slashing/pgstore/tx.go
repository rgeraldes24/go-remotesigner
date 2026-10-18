// Copyright 2020 ConsenSys AG.
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
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL: BIGINT bounds, the
// high watermark checked and fenced before a low watermark moves, duplicates reported without aborting the
// transaction.
// Derived from Web3Signer
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/SignedBlocksDao.java,
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/SignedAttestationsDao.java,
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/LowWatermarkDao.java and
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/ValidatorsDao.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package pgstore

import (
	"context"
	"errors"
	"math"

	"github.com/jackc/pgx/v5"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// validatorTx is one validator's part of a transaction that holds its advisory lock(s). The validator's enabled
// flag and both watermarks are read together, in one statement, the first time a check asks for one of them, and
// then remembered: no other transaction can change them meanwhile, and the transaction's own writes update or drop
// what it remembers.
type validatorTx struct {
	ctx  context.Context
	tx   pgx.Tx
	vid  int32
	head *head
}

// head is what a check reads first.
type head struct {
	enabled bool
	high    slashing.HighWatermark
	low     slashing.LowWatermark
}

// read returns the validator's head. It reads the high watermark FOR SHARE: SetHighWatermark then waits for this
// transaction, so that once it returns no message decided under the old high watermark is still to be recorded.
func (t *validatorTx) read() (*head, error) {
	if t.head != nil {
		return t.head, nil
	}
	var (
		h                          head
		highEpoch, highSlot        *int64
		lowSlot, lowSource, lowTgt *int64
	)
	err := t.tx.QueryRow(t.ctx, `SELECT v.enabled, m.high_watermark_epoch, m.high_watermark_slot,
			l.slot, l.source_epoch, l.target_epoch
		FROM validators v
		LEFT JOIN LATERAL (SELECT high_watermark_epoch, high_watermark_slot FROM metadata WHERE id = 1 FOR SHARE) m
			ON true
		LEFT JOIN low_watermarks l ON l.validator_id = v.id
		WHERE v.id = $1`, t.vid).Scan(&h.enabled, &highEpoch, &highSlot, &lowSlot, &lowSource, &lowTgt)
	if err != nil {
		return nil, err
	}
	for _, f := range []struct {
		in  *int64
		out **uint64
	}{{highEpoch, &h.high.Epoch}, {highSlot, &h.high.Slot}, {lowSlot, &h.low.Slot}, {lowSource, &h.low.SourceEpoch},
		{lowTgt, &h.low.TargetEpoch}} {
		if *f.out, err = u64p(f.in); err != nil {
			return nil, err
		}
	}
	t.head = &h
	return t.head, nil
}

func (t *validatorTx) Enabled() (bool, error) {
	h, err := t.read()
	if err != nil {
		return false, err
	}
	return h.enabled, nil
}

func (t *validatorTx) HighWatermark() (slashing.HighWatermark, error) {
	h, err := t.read()
	if err != nil {
		return slashing.HighWatermark{}, err
	}
	return h.high, nil
}

func (t *validatorTx) LowWatermark() (slashing.LowWatermark, error) {
	h, err := t.read()
	if err != nil {
		return slashing.LowWatermark{}, err
	}
	return h.low, nil
}

// lowChanged drops the remembered low watermark after a write to it, so that the next read sees the row.
func (t *validatorTx) lowChanged() { t.head = nil }

func lowWatermark(ctx context.Context, q queryer, vid int32) (slashing.LowWatermark, error) {
	var slot, source, target *int64
	err := q.QueryRow(ctx, `SELECT slot, source_epoch, target_epoch FROM low_watermarks WHERE validator_id = $1`, vid).
		Scan(&slot, &source, &target)
	if errors.Is(err, pgx.ErrNoRows) {
		return slashing.LowWatermark{}, nil
	}
	if err != nil {
		return slashing.LowWatermark{}, err
	}
	var w slashing.LowWatermark
	if w.Slot, err = u64p(slot); err != nil {
		return w, err
	}
	if w.SourceEpoch, err = u64p(source); err != nil {
		return w, err
	}
	w.TargetEpoch, err = u64p(target)
	return w, err
}

type blockTx struct{ *validatorTx }

var _ slashing.BlockTx = (*blockTx)(nil)

func (t *blockTx) BlockAt(slot uint64) (slashing.SignedBlock, bool, error) {
	if slot > math.MaxInt64 {
		return slashing.SignedBlock{}, false, nil
	}
	return t.block(`SELECT slot, signing_root FROM signed_blocks WHERE validator_id = $1 AND slot = $2`, int64(slot))
}

func (t *blockTx) block(sql string, args ...any) (slashing.SignedBlock, bool, error) {
	var (
		slot int64
		r    []byte
	)
	err := t.tx.QueryRow(t.ctx, sql, append([]any{t.vid}, args...)...).Scan(&slot, &r)
	if errors.Is(err, pgx.ErrNoRows) {
		return slashing.SignedBlock{}, false, nil
	}
	if err != nil {
		return slashing.SignedBlock{}, false, err
	}
	b := slashing.SignedBlock{}
	if b.Slot, err = u64(slot); err != nil {
		return b, false, err
	}
	b.SigningRoot, err = root(r)
	return b, err == nil, err
}

// InsertBlock records b; a block already recorded at the slot is reported as slashing.ErrDuplicateRecord and leaves
// the transaction usable.
func (t *blockTx) InsertBlock(b slashing.SignedBlock) error {
	slot, err := i64(b.Slot)
	if err != nil {
		return err
	}
	tag, err := t.tx.Exec(t.ctx, `INSERT INTO signed_blocks (validator_id, slot, signing_root) VALUES ($1, $2, $3)
		ON CONFLICT (validator_id, slot) DO NOTHING`, t.vid, slot, rootBytes(b.SigningRoot))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return slashing.ErrDuplicateRecord
	}
	return nil
}

func (t *blockTx) RaiseSlotLowWatermark(slot uint64) error {
	v, err := i64(slot)
	if err != nil {
		return err
	}
	high, err := t.HighWatermark()
	if err != nil {
		return err
	}
	if high.Slot != nil && slot > *high.Slot {
		return slashing.ErrWatermarkConflict
	}
	_, err = t.tx.Exec(t.ctx, `INSERT INTO low_watermarks (validator_id, slot) VALUES ($1, $2)
		ON CONFLICT (validator_id) DO UPDATE SET slot = EXCLUDED.slot
		WHERE low_watermarks.slot IS NULL OR low_watermarks.slot <= EXCLUDED.slot`, t.vid, v)
	t.lowChanged()
	return err
}

func (t *blockTx) LastBlock() (slashing.SignedBlock, bool, error) {
	return t.block(`SELECT slot, signing_root FROM signed_blocks WHERE validator_id = $1 ORDER BY slot DESC LIMIT 1`)
}

func (t *blockTx) NearestBlock(slot uint64) (slashing.SignedBlock, bool, error) {
	if slot > math.MaxInt64 {
		return slashing.SignedBlock{}, false, nil
	}
	return t.block(`SELECT slot, signing_root FROM signed_blocks WHERE validator_id = $1 AND slot >= $2
		ORDER BY slot ASC LIMIT 1`, int64(slot))
}

func (t *blockTx) PruneBlocks() (int, error) {
	tag, err := t.tx.Exec(t.ctx, `DELETE FROM signed_blocks WHERE validator_id = $1
		AND slot < (SELECT slot FROM low_watermarks WHERE validator_id = $1)`, t.vid)
	return int(tag.RowsAffected()), err
}

type attestationTx struct{ *validatorTx }

var _ slashing.AttestationTx = (*attestationTx)(nil)

func (t *attestationTx) AttestationAt(target uint64) (slashing.SignedAttestation, bool, error) {
	if target > math.MaxInt64 {
		return slashing.SignedAttestation{}, false, nil
	}
	return t.attestation(`SELECT source_epoch, target_epoch, signing_root FROM signed_attestations
		WHERE validator_id = $1 AND target_epoch = $2`, int64(target))
}

func (t *attestationTx) attestation(sql string, args ...any) (slashing.SignedAttestation, bool, error) {
	var (
		source, target int64
		r              []byte
	)
	err := t.tx.QueryRow(t.ctx, sql, append([]any{t.vid}, args...)...).Scan(&source, &target, &r)
	if errors.Is(err, pgx.ErrNoRows) {
		return slashing.SignedAttestation{}, false, nil
	}
	if err != nil {
		return slashing.SignedAttestation{}, false, err
	}
	a := slashing.SignedAttestation{}
	if a.SourceEpoch, err = u64(source); err != nil {
		return a, false, err
	}
	if a.TargetEpoch, err = u64(target); err != nil {
		return a, false, err
	}
	a.SigningRoot, err = root(r)
	return a, err == nil, err
}

// SurroundingAttestation finds a recorded a with a.SourceEpoch < source and a.TargetEpoch > target, the highest
// target first. The bounds are rewritten as inclusive ones that fit a BIGINT: no stored value exceeds 2^63-1.
func (t *attestationTx) SurroundingAttestation(source, target uint64) (slashing.SignedAttestation, bool, error) {
	if source == 0 || target >= math.MaxInt64 {
		return slashing.SignedAttestation{}, false, nil
	}
	maxSource := int64(min(source-1, math.MaxInt64))
	return t.attestation(`SELECT source_epoch, target_epoch, signing_root FROM signed_attestations
		WHERE validator_id = $1 AND target_epoch >= $2 AND source_epoch <= $3 ORDER BY target_epoch DESC LIMIT 1`,
		int64(target+1), maxSource)
}

// SurroundedAttestation finds a recorded a with a.SourceEpoch > source and a.TargetEpoch < target, the highest
// target first, with the bounds rewritten as in SurroundingAttestation.
func (t *attestationTx) SurroundedAttestation(source, target uint64) (slashing.SignedAttestation, bool, error) {
	if target == 0 || source >= math.MaxInt64 {
		return slashing.SignedAttestation{}, false, nil
	}
	maxTarget := int64(min(target-1, math.MaxInt64))
	return t.attestation(`SELECT source_epoch, target_epoch, signing_root FROM signed_attestations
		WHERE validator_id = $1 AND target_epoch <= $2 AND source_epoch >= $3 ORDER BY target_epoch DESC LIMIT 1`,
		maxTarget, int64(source+1))
}

// InsertAttestation records a; an attestation already recorded at the target is reported as
// slashing.ErrDuplicateRecord and leaves the transaction usable.
func (t *attestationTx) InsertAttestation(a slashing.SignedAttestation) error {
	source, err := i64(a.SourceEpoch)
	if err != nil {
		return err
	}
	target, err := i64(a.TargetEpoch)
	if err != nil {
		return err
	}
	tag, err := t.tx.Exec(t.ctx, `INSERT INTO signed_attestations (validator_id, source_epoch, target_epoch, signing_root)
		VALUES ($1, $2, $3, $4) ON CONFLICT (validator_id, target_epoch) DO NOTHING`,
		t.vid, source, target, rootBytes(a.SigningRoot))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return slashing.ErrDuplicateRecord
	}
	return nil
}

func (t *attestationTx) RaiseEpochLowWatermarks(source, target uint64) error {
	s, err := i64(source)
	if err != nil {
		return err
	}
	tg, err := i64(target)
	if err != nil {
		return err
	}
	high, err := t.HighWatermark()
	if err != nil {
		return err
	}
	if high.Epoch != nil && (source > *high.Epoch || target > *high.Epoch) {
		return slashing.ErrWatermarkConflict
	}
	_, err = t.tx.Exec(t.ctx, `INSERT INTO low_watermarks (validator_id, source_epoch, target_epoch) VALUES ($1, $2, $3)
		ON CONFLICT (validator_id) DO UPDATE SET source_epoch = EXCLUDED.source_epoch,
			target_epoch = EXCLUDED.target_epoch
		WHERE low_watermarks.source_epoch IS NULL OR (low_watermarks.source_epoch <= EXCLUDED.source_epoch
			AND low_watermarks.target_epoch <= EXCLUDED.target_epoch)`, t.vid, s, tg)
	t.lowChanged()
	return err
}

func (t *attestationTx) LastAttestation() (slashing.SignedAttestation, bool, error) {
	return t.attestation(`SELECT source_epoch, target_epoch, signing_root FROM signed_attestations
		WHERE validator_id = $1 ORDER BY target_epoch DESC LIMIT 1`)
}

func (t *attestationTx) NearestAttestation(target uint64) (slashing.SignedAttestation, bool, error) {
	if target > math.MaxInt64 {
		return slashing.SignedAttestation{}, false, nil
	}
	return t.attestation(`SELECT source_epoch, target_epoch, signing_root FROM signed_attestations
		WHERE validator_id = $1 AND target_epoch >= $2 ORDER BY target_epoch ASC LIMIT 1`, int64(target))
}

func (t *attestationTx) PruneAttestations() (int, error) {
	tag, err := t.tx.Exec(t.ctx, `DELETE FROM signed_attestations WHERE validator_id = $1
		AND target_epoch < (SELECT target_epoch FROM low_watermarks WHERE validator_id = $1)`, t.vid)
	return int(tag.RowsAffected()), err
}

// historyTx is one validator's part of a transaction of UpdateHistory, which holds both its block and its
// attestation lock.
type historyTx struct {
	*blockTx
	*attestationTx
}

var _ slashing.HistoryTx = historyTx{}

func newHistoryTx(ctx context.Context, tx pgx.Tx, vid int32) historyTx {
	v := &validatorTx{ctx: ctx, tx: tx, vid: vid}
	return historyTx{&blockTx{v}, &attestationTx{v}}
}

func (t historyTx) Enabled() (bool, error) { return t.blockTx.Enabled() }

func (t historyTx) HighWatermark() (slashing.HighWatermark, error) { return t.blockTx.HighWatermark() }

func (t historyTx) LowWatermark() (slashing.LowWatermark, error) { return t.blockTx.LowWatermark() }

func (t historyTx) SetEnabled(enabled bool) error {
	v := t.blockTx.validatorTx
	_, err := v.tx.Exec(v.ctx, `UPDATE validators SET enabled = $2 WHERE id = $1`, v.vid, enabled)
	v.head = nil
	return err
}
