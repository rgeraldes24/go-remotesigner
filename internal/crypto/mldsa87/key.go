// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package mldsa87

import (
	"fmt"
	"sync"

	"github.com/theQRL/go-qrllib/wallet/common"
	walletmldsa87 "github.com/theQRL/go-qrllib/wallet/ml_dsa_87"
)

// Key is an ML-DSA-87 consensus key held as a go-qrllib wallet. It is safe
// for concurrent use: signing is serialised per key, as go-qrllib requires.
// Call Zeroize when the key is removed.
type Key struct {
	pk PublicKey
	id [IDSize]byte

	mu     sync.Mutex
	wallet *walletmldsa87.Wallet // nil once zeroized

	// seedMu is held for reading by every running WithSeed callback, so
	// that Zeroize can wait for them without taking mu, which would block
	// signing for the length of an onion scan.
	seedMu sync.RWMutex
}

// FromSeed48 builds a consensus key from the validator's 48-byte wallet seed
// (the key pair is generated from SHA-256 of it, inside go-qrllib). The
// derived public key must pass ParsePublicKey's weak-key rule.
//
// The caller keeps ownership of seed and should Wipe it once the key is
// built; the key holds its own copy until Zeroize.
func FromSeed48(seed *[SeedSize]byte) (*Key, error) {
	w, err := walletmldsa87.NewWalletFromSeed(common.Seed(*seed))
	if err != nil {
		return nil, fmt.Errorf("mldsa87: derive key from seed: %w", err)
	}
	packed := w.GetPK()
	pk, err := ParsePublicKey(packed[:])
	if err != nil {
		w.Zeroize()
		return nil, err
	}
	return &Key{pk: pk, id: pk.ID(), wallet: w}, nil
}

// PublicKey returns the key's packed public key. It stays available after
// Zeroize.
func (k *Key) PublicKey() PublicKey {
	return k.pk
}

// ID returns the key id, SHA-256 of the public key.
func (k *Key) ID() [IDSize]byte {
	return k.id
}

// Sign signs message under the consensus signing context in the given mode.
// It returns ErrZeroized once the key has been zeroized and ErrUnknownMode for
// a mode other than Hedged or Deterministic. Sign does not verify the result;
// the caller verifies before releasing it.
func (k *Key) Sign(message []byte, mode Mode) ([SignatureSize]byte, error) {
	if mode != Hedged && mode != Deterministic {
		return [SignatureSize]byte{}, fmt.Errorf("%w: %v", ErrUnknownMode, mode)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.wallet == nil {
		return [SignatureSize]byte{}, ErrZeroized
	}
	var (
		sig [SignatureSize]byte
		err error
	)
	if mode == Deterministic {
		sig, err = k.wallet.SignDeterministic(message)
	} else {
		sig, err = k.wallet.Sign(message)
	}
	if err != nil {
		return [SignatureSize]byte{}, fmt.Errorf("mldsa87: sign: %w", err)
	}
	return sig, nil
}

// Verify reports whether sig is a valid consensus signature over message
// under this key.
func (k *Key) Verify(message, sig []byte) bool {
	return Verify(&k.pk, message, sig)
}

// WithSeed calls fn with a temporary copy of the 48-byte wallet seed, which it
// wipes when fn returns. Only seed holders can compute RANDAO reveals. It
// returns ErrZeroized, without calling fn, once the key has been zeroized.
//
// Signing is not blocked while fn runs, so a long onion scan does not delay
// Sign. Zeroize does wait for fn to return, so a caller that sees WithSeed
// return nil knows the key was live for the whole of fn. fn must not retain
// the pointer and must not call Zeroize on the same key.
func (k *Key) WithSeed(fn func(seed *[SeedSize]byte) error) error {
	k.seedMu.RLock()
	defer k.seedMu.RUnlock()
	k.mu.Lock()
	if k.wallet == nil {
		k.mu.Unlock()
		return ErrZeroized
	}
	seed := [SeedSize]byte(k.wallet.GetSeed())
	k.mu.Unlock()
	defer Wipe(seed[:])
	return fn(&seed)
}

// Zeroize clears the wallet's seed and secret key and makes the key refuse
// to sign. It waits for an in-flight Sign and for running WithSeed callbacks
// to finish; once it returns, no copy of the seed made by this key remains.
// It is idempotent.
func (k *Key) Zeroize() {
	k.mu.Lock()
	if k.wallet != nil {
		k.wallet.Zeroize()
		k.wallet = nil
	}
	k.mu.Unlock()
	// Taking seedMu for writing waits for the WithSeed callbacks that copied
	// the seed before the wallet went; later ones see ErrZeroized.
	k.seedMu.Lock()
	defer k.seedMu.Unlock()
}

// Zeroized reports whether Zeroize has been called.
func (k *Key) Zeroized() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.wallet == nil
}
