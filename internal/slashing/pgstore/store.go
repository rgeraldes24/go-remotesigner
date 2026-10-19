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
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL: validators keyed by
// sha256(public key), the high watermark fenced against concurrent signing, and disabling under both validator locks.
// Derived from Web3Signer
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/MetadataDao.java,
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/dao/ValidatorsDao.java,
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbSlashingProtection.java and
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbValidatorManager.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package pgstore

import (
	"bytes"
	"context"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// registerChunk is how many keys one registration statement carries.
const registerChunk = 1024

// GenesisValidatorsRoot returns the pinned root, if any.
func (s *Store) GenesisValidatorsRoot(ctx context.Context) (slashing.Root, bool, error) {
	var (
		r  slashing.Root
		ok bool
	)
	err := s.call(ctx, "read the genesis validators root", func(ctx context.Context) error {
		var err error
		r, ok, err = genesisValidatorsRoot(ctx, s.pool)
		return err
	})
	return r, ok, err
}

func genesisValidatorsRoot(ctx context.Context, q queryer) (slashing.Root, bool, error) {
	var b []byte
	err := q.QueryRow(ctx, `SELECT genesis_validators_root FROM metadata WHERE id = 1`).Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return slashing.Root{}, false, nil
	}
	if err != nil {
		return slashing.Root{}, false, err
	}
	r, err := root(b)
	if err != nil {
		return slashing.Root{}, false, err
	}
	return *r, true, nil
}

// PinGenesisValidatorsRoot pins gvr unless a root is already pinned, and returns the pinned root. When it pins, it
// calls the OnPin hook after the commit.
func (s *Store) PinGenesisValidatorsRoot(ctx context.Context, gvr slashing.Root) (slashing.Root, error) {
	var (
		pinned slashing.Root
		wrote  bool
	)
	err := s.call(ctx, "pin the genesis validators root", func(ctx context.Context) error {
		var err error
		pinned, wrote, err = s.pin(ctx, gvr)
		return err
	})
	if err != nil {
		return slashing.Root{}, err
	}
	if wrote && s.onPin != nil {
		s.onPin(pinned)
	}
	return pinned, nil
}

// pin inserts gvr unless a root is pinned, then reads the pinned root in a second statement, which sees a root that
// a concurrent first pin committed while the insert waited for it.
func (s *Store) pin(ctx context.Context, gvr slashing.Root) (slashing.Root, bool, error) {
	tag, err := s.pool.Exec(ctx, `INSERT INTO metadata (id, genesis_validators_root) VALUES (1, $1)
		ON CONFLICT (id) DO NOTHING`, gvr[:])
	if err != nil {
		return slashing.Root{}, false, err
	}
	if tag.RowsAffected() == 1 {
		return gvr, true, nil
	}
	pinned, ok, err := genesisValidatorsRoot(ctx, s.pool)
	if err == nil && !ok {
		err = errors.New("pgstore: the genesis validators root vanished")
	}
	return pinned, false, err
}

// HighWatermark returns the global high watermark.
func (s *Store) HighWatermark(ctx context.Context) (slashing.HighWatermark, error) {
	var h slashing.HighWatermark
	err := s.call(ctx, "read the high watermark", func(ctx context.Context) error {
		var err error
		h, err = highWatermark(ctx, s.pool)
		return err
	})
	return h, err
}

// highWatermark reads the high watermark.
func highWatermark(ctx context.Context, q queryer) (slashing.HighWatermark, error) {
	var epoch, slot *int64
	err := q.QueryRow(ctx, `SELECT high_watermark_epoch, high_watermark_slot FROM metadata WHERE id = 1`).
		Scan(&epoch, &slot)
	if errors.Is(err, pgx.ErrNoRows) {
		return slashing.HighWatermark{}, nil
	}
	if err != nil {
		return slashing.HighWatermark{}, err
	}
	var h slashing.HighWatermark
	if h.Epoch, err = u64p(epoch); err != nil {
		return h, err
	}
	h.Slot, err = u64p(slot)
	return h, err
}

// SetHighWatermark replaces the global high watermark. It locks the metadata row first, so it waits for every
// transaction that read the old high watermark (they read it FOR SHARE) and every later one reads the new one; the
// schema's trigger then checks it against every low watermark, which no transaction can raise meanwhile.
func (s *Store) SetHighWatermark(ctx context.Context, h slashing.HighWatermark) error {
	var epoch, slot *int64
	for _, v := range []struct {
		in  *uint64
		out **int64
	}{{h.Epoch, &epoch}, {h.Slot, &slot}} {
		if v.in == nil {
			continue
		}
		x, err := i64(*v.in)
		if err != nil {
			return err
		}
		*v.out = &x
	}
	return s.inTx(ctx, "set the high watermark", func(ctx context.Context, tx pgx.Tx) error {
		var id int32
		err := tx.QueryRow(ctx, `SELECT id FROM metadata WHERE id = 1 FOR UPDATE`).Scan(&id)
		switch {
		case errors.Is(err, pgx.ErrNoRows) && h.IsSet():
			return slashing.ErrNoGenesisValidatorsRoot
		case errors.Is(err, pgx.ErrNoRows):
			return nil
		case err != nil:
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE metadata SET high_watermark_epoch = $1, high_watermark_slot = $2 WHERE id = 1`,
			epoch, slot)
		return err
	})
}

// RegisterValidators registers new keys as enabled and leaves known keys unchanged.
func (s *Store) RegisterValidators(ctx context.Context, pubkeys [][]byte) error {
	return s.register(ctx, pubkeys, true)
}

// RegisterValidatorsDisabled registers new keys as disabled and leaves known keys unchanged.
func (s *Store) RegisterValidatorsDisabled(ctx context.Context, pubkeys [][]byte) error {
	return s.register(ctx, pubkeys, false)
}

// register inserts the keys that are not registered yet, in KeyID order, so that two processes registering the same
// new keys do not deadlock. A known key's row is never written: not even its enabled flag is touched.
func (s *Store) register(ctx context.Context, pubkeys [][]byte, enabled bool) error {
	type key struct {
		id slashing.KeyID
		pk []byte
	}
	keys := make([]key, 0, len(pubkeys))
	for _, pk := range pubkeys {
		if err := slashing.CheckPublicKey(pk); err != nil {
			return err
		}
		keys = append(keys, key{slashing.KeyIDOf(pk), pk})
	}
	slices.SortFunc(keys, func(a, b key) int { return bytes.Compare(a.id[:], b.id[:]) })
	keys = slices.CompactFunc(keys, func(a, b key) bool { return a.id == b.id })
	for chunk := range slices.Chunk(keys, registerChunk) {
		hashes := make([][]byte, len(chunk))
		for i, k := range chunk {
			hashes[i] = k.id[:]
		}
		err := s.inTx(ctx, "register validators", func(ctx context.Context, tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT pubkey_hash FROM validators WHERE pubkey_hash = ANY($1)`, hashes)
			if err != nil {
				return err
			}
			known, err := pgx.CollectRows(rows, pgx.RowTo[[]byte])
			if err != nil {
				return err
			}
			var newHashes, newKeys [][]byte
			for _, k := range chunk {
				if !slices.ContainsFunc(known, func(h []byte) bool { return bytes.Equal(h, k.id[:]) }) {
					newHashes, newKeys = append(newHashes, k.id[:]), append(newKeys, k.pk)
				}
			}
			if len(newKeys) == 0 {
				return nil
			}
			_, err = tx.Exec(ctx, `INSERT INTO validators (pubkey_hash, public_key, enabled)
				SELECT h, k, $3 FROM unnest($1::bytea[], $2::bytea[]) WITH ORDINALITY AS t(h, k, n) ORDER BY n
				ON CONFLICT (pubkey_hash) DO NOTHING`, newHashes, newKeys, enabled)
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// ValidatorStatus returns a key's registration state.
func (s *Store) ValidatorStatus(ctx context.Context, id slashing.KeyID) (slashing.ValidatorStatus, error) {
	var st slashing.ValidatorStatus
	err := s.call(ctx, "read a validator's status", func(ctx context.Context) error {
		err := s.pool.QueryRow(ctx, `SELECT enabled FROM validators WHERE pubkey_hash = $1`, id[:]).Scan(&st.Enabled)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		st.Registered = err == nil
		return err
	})
	return st, err
}

// SetValidatorEnabled sets a registered key's enabled flag under the validator's block and then attestation lock, as
// Web3Signer's lockAllForValidator does: a check-and-record that read the old flag has committed before it returns,
// in this process or another one.
func (s *Store) SetValidatorEnabled(ctx context.Context, id slashing.KeyID, enabled bool) error {
	return s.inTx(ctx, "set a validator's enabled flag", func(ctx context.Context, tx pgx.Tx) error {
		vid, err := lockValidator(ctx, tx, id, lockBlock)
		if err != nil {
			return err
		}
		if err := lock(ctx, tx, vid, lockAttestation); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE validators SET enabled = $2 WHERE id = $1`, vid, enabled)
		return err
	})
}

// UpdateBlocks runs fn in a block transaction for one validator, under its block lock.
func (s *Store) UpdateBlocks(ctx context.Context, id slashing.KeyID, fn func(slashing.BlockTx) error) error {
	return s.inValidatorTx(ctx, "block transaction", id, lockBlock, func(v *validatorTx) error {
		return fn(&blockTx{v})
	})
}

// UpdateAttestations runs fn in an attestation transaction for one validator, under its attestation lock.
func (s *Store) UpdateAttestations(ctx context.Context, id slashing.KeyID, fn func(slashing.AttestationTx) error) error {
	return s.inValidatorTx(ctx, "attestation transaction", id, lockAttestation, func(v *validatorTx) error {
		return fn(&attestationTx{validatorTx: v})
	})
}
