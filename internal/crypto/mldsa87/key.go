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
// wipes when fn returns. Only seed holders can compute RANDAO reveals. The key
// lock is not held while fn runs, so a long onion scan does not block signing;
// it returns ErrZeroized if the key was zeroized before the copy was taken.
// fn must not retain the pointer.
func (k *Key) WithSeed(fn func(seed *[SeedSize]byte) error) error {
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
// to sign. It waits for an in-flight Sign to finish. It is idempotent.
func (k *Key) Zeroize() {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.wallet != nil {
		k.wallet.Zeroize()
		k.wallet = nil
	}
}

// Zeroized reports whether Zeroize has been called.
func (k *Key) Zeroized() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.wallet == nil
}
