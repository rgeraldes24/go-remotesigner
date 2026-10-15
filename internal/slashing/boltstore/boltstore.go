// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package boltstore is the embedded slashing.Store: one bbolt file on a single host, the default backend.
//
// Only one process can open the file: bbolt takes an exclusive flock, and Open fails with ErrLocked while another
// process holds it, so the store's in-memory view is always coherent. Every write is one bbolt transaction that is
// fsynced on commit, before the call returns, so a signature or RANDAO reveal is released only after its record is
// durable. Check-and-record calls are additionally serialised per validator by in-memory mutexes, in the fixed order
// block, attestation, RANDAO.
//
// The file carries its schema version in meta/schema_version. Open refuses a file written with any other version:
// an older one must first be upgraded offline with Migrate (`remotesigner consensus migrate`), and a newer one is
// never opened.
package boltstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	bolterrors "go.etcd.io/bbolt/errors"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// DefaultLockTimeout is how long Open waits for the file lock before it fails with ErrLocked.
const DefaultLockTimeout = time.Second

// fileMode is the permission of a new store file and of a migration backup.
const fileMode os.FileMode = 0o600

var (
	// ErrLocked: another process holds the store file open.
	ErrLocked = errors.New("boltstore: the slashing-protection store is locked by another process")
	// ErrClosed is returned by every method after Close.
	ErrClosed = errors.New("boltstore: store is closed")
	// ErrNotStore: the file is a bbolt database but not a slashing-protection store.
	ErrNotStore = errors.New("boltstore: file is not a slashing-protection store")
)

// Options configure Open.
type Options struct {
	// GenesisValidatorsRoot, when set, is the network's configured root. A store that has no root yet is pinned to
	// it; a store pinned to a different root is refused with slashing.ErrGenesisValidatorsRootMismatch. When nil,
	// the store stays unpinned until the first PinGenesisValidatorsRoot call (trust on first use).
	GenesisValidatorsRoot *slashing.Root
	// OnPin, when set, is called with the root after PinGenesisValidatorsRoot has durably pinned a store that had
	// none: the trust-on-first-use pin hook. It is not called for a root pinned by Open.
	OnPin func(slashing.Root)
	// LockTimeout is how long Open waits for the file lock; zero means DefaultLockTimeout.
	LockTimeout time.Duration
}

// Store is a bbolt-backed slashing.Store, safe for concurrent use within one process.
type Store struct {
	db    *bolt.DB
	onPin func(slashing.Root)
	locks sync.Map // slashing.KeyID → *validatorLocks
}

// validatorLocks serialise one validator's transactions of each kind. Code that takes several takes them in the
// order block, attestation, RANDAO.
type validatorLocks struct {
	block, attestation, randao sync.Mutex
}

var _ slashing.Store = (*Store)(nil)

// Open opens the store at path, creating the file (mode 0600) and its directory (mode 0700) when they do not exist.
// It fails with ErrLocked when another process holds the file, with a *slashing.SchemaError when the file has a
// different schema version, and with slashing.ErrGenesisValidatorsRootMismatch when opts.GenesisValidatorsRoot
// differs from the pinned root.
func Open(path string, opts Options) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("boltstore: create directory: %w", err)
	}
	db, err := openDB(path, opts.LockTimeout)
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error { return initialise(tx, opts.GenesisValidatorsRoot) }); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("boltstore: open %s: %w", path, err)
	}
	return &Store{db: db, onPin: opts.OnPin}, nil
}

// openDB opens the bbolt file with an exclusive lock.
func openDB(path string, timeout time.Duration) (*bolt.DB, error) {
	if timeout <= 0 {
		timeout = DefaultLockTimeout
	}
	db, err := bolt.Open(path, fileMode, &bolt.Options{Timeout: timeout})
	if errors.Is(err, bolterrors.ErrTimeout) {
		return nil, fmt.Errorf("%w: %s (stop the signer, or use its admin API)", ErrLocked, path)
	}
	if err != nil {
		return nil, fmt.Errorf("boltstore: open %s: %w", path, err)
	}
	return db, nil
}

// initialise lays out a new file, or checks the schema version of an existing one, and applies the configured
// genesis validators root.
func initialise(tx *bolt.Tx, gvr *slashing.Root) error {
	meta := tx.Bucket(bucketMeta)
	if meta == nil {
		if k, _ := tx.Cursor().First(); k != nil {
			return ErrNotStore
		}
		var err error
		if meta, err = tx.CreateBucket(bucketMeta); err != nil {
			return err
		}
		if _, err := tx.CreateBucket(bucketValidators); err != nil {
			return err
		}
		if err := meta.Put(keySchemaVersion, encodeVersion(slashing.SchemaVersion)); err != nil {
			return err
		}
	}
	version, err := schemaVersion(tx)
	if err != nil {
		return err
	}
	if version != slashing.SchemaVersion {
		return &slashing.SchemaError{Stored: version, Expected: slashing.SchemaVersion}
	}
	if gvr == nil {
		return nil
	}
	pinned, ok, err := genesisValidatorsRoot(tx)
	switch {
	case err != nil:
		return err
	case !ok:
		return meta.Put(keyGVR, gvr[:])
	case pinned != *gvr:
		return fmt.Errorf("%w: configured %#x, store pinned to %#x",
			slashing.ErrGenesisValidatorsRootMismatch, gvr[:], pinned[:])
	}
	return nil
}

func schemaVersion(tx *bolt.Tx) (uint32, error) {
	meta := tx.Bucket(bucketMeta)
	if meta == nil {
		return 0, ErrNotStore
	}
	b := meta.Get(keySchemaVersion)
	if b == nil {
		return 0, ErrNotStore
	}
	return decodeVersion(b)
}

func genesisValidatorsRoot(tx *bolt.Tx) (slashing.Root, bool, error) {
	b := tx.Bucket(bucketMeta).Get(keyGVR)
	if b == nil {
		return slashing.Root{}, false, nil
	}
	r, err := decodeRoot32("genesis validators root", b)
	return r, err == nil, err
}

func highWatermark(tx *bolt.Tx) (slashing.HighWatermark, error) {
	return decodeHighWatermark(tx.Bucket(bucketMeta).Get(keyHighWatermark))
}

// validatorBucket returns the validator's bucket, or ErrValidatorNotRegistered.
func validatorBucket(tx *bolt.Tx, id slashing.KeyID) (*bolt.Bucket, error) {
	b := tx.Bucket(bucketValidators).Bucket(id[:])
	if b == nil {
		return nil, slashing.ErrValidatorNotRegistered
	}
	return b, nil
}

// SchemaVersion returns the schema version recorded in the file.
func (s *Store) SchemaVersion(ctx context.Context) (uint32, error) {
	var v uint32
	err := s.view(ctx, func(tx *bolt.Tx) error {
		var err error
		v, err = schemaVersion(tx)
		return err
	})
	return v, err
}

// GenesisValidatorsRoot returns the pinned root, if any.
func (s *Store) GenesisValidatorsRoot(ctx context.Context) (slashing.Root, bool, error) {
	var (
		r  slashing.Root
		ok bool
	)
	err := s.view(ctx, func(tx *bolt.Tx) error {
		var err error
		r, ok, err = genesisValidatorsRoot(tx)
		return err
	})
	return r, ok, err
}

// PinGenesisValidatorsRoot pins gvr unless a root is already pinned, and returns the pinned root. When it pins, it
// calls the OnPin hook after the commit.
func (s *Store) PinGenesisValidatorsRoot(ctx context.Context, gvr slashing.Root) (slashing.Root, error) {
	var (
		pinned slashing.Root
		wrote  bool
	)
	err := s.update(ctx, func(tx *bolt.Tx) error {
		r, ok, err := genesisValidatorsRoot(tx)
		if err != nil || ok {
			pinned = r
			return err
		}
		pinned, wrote = gvr, true
		return tx.Bucket(bucketMeta).Put(keyGVR, gvr[:])
	})
	if err != nil {
		return slashing.Root{}, err
	}
	if wrote && s.onPin != nil {
		s.onPin(pinned)
	}
	return pinned, nil
}

// HighWatermark returns the global high watermark.
func (s *Store) HighWatermark(ctx context.Context) (slashing.HighWatermark, error) {
	var h slashing.HighWatermark
	err := s.view(ctx, func(tx *bolt.Tx) error {
		var err error
		h, err = highWatermark(tx)
		return err
	})
	return h, err
}

// SetHighWatermark replaces the global high watermark after checking it against every low watermark. bbolt runs
// one write transaction at a time, so no low watermark moves while it checks.
func (s *Store) SetHighWatermark(ctx context.Context, h slashing.HighWatermark) error {
	return s.update(ctx, func(tx *bolt.Tx) error {
		meta := tx.Bucket(bucketMeta)
		if !h.IsSet() {
			return meta.Delete(keyHighWatermark)
		}
		if meta.Get(keyGVR) == nil {
			return slashing.ErrNoGenesisValidatorsRoot
		}
		err := tx.Bucket(bucketValidators).ForEachBucket(func(k []byte) error {
			low, err := decodeLowWatermark(tx.Bucket(bucketValidators).Bucket(k).Get(keyLowWatermark))
			if err != nil {
				return err
			}
			if h.Slot != nil && low.Slot != nil && *h.Slot <= *low.Slot {
				return slashing.ErrWatermarkConflict
			}
			if h.Epoch != nil && low.SourceEpoch != nil &&
				(*h.Epoch <= *low.SourceEpoch || *h.Epoch <= *low.TargetEpoch) {
				return slashing.ErrWatermarkConflict
			}
			return nil
		})
		if err != nil {
			return err
		}
		return meta.Put(keyHighWatermark, encodeHighWatermark(h))
	})
}

// RegisterValidators registers new keys as enabled and leaves known keys unchanged, in one transaction.
func (s *Store) RegisterValidators(ctx context.Context, pubkeys [][]byte) error {
	for _, pk := range pubkeys {
		if err := slashing.CheckPublicKey(pk); err != nil {
			return err
		}
	}
	return s.update(ctx, func(tx *bolt.Tx) error {
		vs := tx.Bucket(bucketValidators)
		for _, pk := range pubkeys {
			id := slashing.KeyIDOf(pk)
			if vs.Bucket(id[:]) != nil {
				continue
			}
			if err := createValidator(vs, id, pk); err != nil {
				return err
			}
		}
		return nil
	})
}

func createValidator(vs *bolt.Bucket, id slashing.KeyID, pk []byte) error {
	b, err := vs.CreateBucket(id[:])
	if err != nil {
		return err
	}
	if err := b.Put(keyPublicKey, pk); err != nil {
		return err
	}
	if err := b.Put(keyEnabled, encodeBool(true)); err != nil {
		return err
	}
	if _, err := b.CreateBucket(bucketBlocks); err != nil {
		return err
	}
	_, err = b.CreateBucket(bucketAtts)
	return err
}

// ValidatorStatus returns a key's registration state.
func (s *Store) ValidatorStatus(ctx context.Context, id slashing.KeyID) (slashing.ValidatorStatus, error) {
	var st slashing.ValidatorStatus
	err := s.view(ctx, func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketValidators).Bucket(id[:])
		if b == nil {
			return nil
		}
		enabled, err := decodeBool("enabled", b.Get(keyEnabled))
		st = slashing.ValidatorStatus{Registered: true, Enabled: enabled}
		return err
	})
	return st, err
}

// SetValidatorEnabled sets a registered key's enabled flag, holding the validator's block and attestation locks.
func (s *Store) SetValidatorEnabled(ctx context.Context, id slashing.KeyID, enabled bool) error {
	l := s.lockFor(id)
	l.block.Lock()
	defer l.block.Unlock()
	l.attestation.Lock()
	defer l.attestation.Unlock()
	return s.update(ctx, func(tx *bolt.Tx) error {
		b, err := validatorBucket(tx, id)
		if err != nil {
			return err
		}
		return b.Put(keyEnabled, encodeBool(enabled))
	})
}

// UpdateBlocks runs fn in a block transaction for one validator.
func (s *Store) UpdateBlocks(ctx context.Context, id slashing.KeyID, fn func(slashing.BlockTx) error) error {
	l := s.lockFor(id)
	l.block.Lock()
	defer l.block.Unlock()
	return s.update(ctx, func(tx *bolt.Tx) error {
		b, err := validatorBucket(tx, id)
		if err != nil {
			return err
		}
		return fn(&blockTx{validatorTx{tx: tx, b: b}})
	})
}

// UpdateAttestations runs fn in an attestation transaction for one validator.
func (s *Store) UpdateAttestations(ctx context.Context, id slashing.KeyID, fn func(slashing.AttestationTx) error) error {
	l := s.lockFor(id)
	l.attestation.Lock()
	defer l.attestation.Unlock()
	return s.update(ctx, func(tx *bolt.Tx) error {
		b, err := validatorBucket(tx, id)
		if err != nil {
			return err
		}
		return fn(&attestationTx{validatorTx{tx: tx, b: b}})
	})
}

// RandaoState returns the validator's RANDAO frontier, if one is stored.
func (s *Store) RandaoState(ctx context.Context, id slashing.KeyID) (slashing.RandaoState, bool, error) {
	var (
		st slashing.RandaoState
		ok bool
	)
	err := s.view(ctx, func(tx *bolt.Tx) error {
		b, err := validatorBucket(tx, id)
		if err != nil {
			return err
		}
		v := b.Get(keyRandao)
		if v == nil {
			return nil
		}
		st, err = decodeRandao(v)
		ok = err == nil
		return err
	})
	return st, ok, err
}

// CompareAndSwapRandaoState stores next if the stored frontier equals old (nil: none stored). A stored next is
// fsynced before it returns.
func (s *Store) CompareAndSwapRandaoState(ctx context.Context, id slashing.KeyID, old *slashing.RandaoState, next slashing.RandaoState) (bool, error) {
	l := s.lockFor(id)
	l.randao.Lock()
	defer l.randao.Unlock()
	var swapped bool
	err := s.update(ctx, func(tx *bolt.Tx) error {
		b, err := validatorBucket(tx, id)
		if err != nil {
			return err
		}
		cur := b.Get(keyRandao)
		switch {
		case old == nil && cur != nil:
			return nil
		case old != nil:
			if cur == nil {
				return nil
			}
			st, err := decodeRandao(cur)
			if err != nil {
				return err
			}
			if st != *old {
				return nil
			}
		}
		swapped = true
		return b.Put(keyRandao, encodeRandao(next))
	})
	return swapped && err == nil, err
}

// DeleteRandaoState removes the validator's RANDAO frontier.
func (s *Store) DeleteRandaoState(ctx context.Context, id slashing.KeyID) error {
	l := s.lockFor(id)
	l.randao.Lock()
	defer l.randao.Unlock()
	return s.update(ctx, func(tx *bolt.Tx) error {
		b, err := validatorBucket(tx, id)
		if err != nil {
			return err
		}
		return b.Delete(keyRandao)
	})
}

// Close closes the file and releases its lock. It waits for running transactions.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) lockFor(id slashing.KeyID) *validatorLocks {
	if l, ok := s.locks.Load(id); ok {
		return l.(*validatorLocks)
	}
	l, _ := s.locks.LoadOrStore(id, new(validatorLocks))
	return l.(*validatorLocks)
}

// update runs fn in a read-write transaction; bbolt fsyncs the commit before it returns.
func (s *Store) update(ctx context.Context, fn func(*bolt.Tx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return closedErr(s.db.Update(fn))
}

// view runs fn in a read-only transaction.
func (s *Store) view(ctx context.Context, fn func(*bolt.Tx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return closedErr(s.db.View(fn))
}

func closedErr(err error) error {
	if errors.Is(err, bolterrors.ErrDatabaseNotOpen) {
		return ErrClosed
	}
	return err
}
