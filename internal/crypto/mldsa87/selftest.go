// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package mldsa87

import (
	"crypto/rand"
	"fmt"
)

// SelfTest exercises signing with an ephemeral key: two hedged signatures over
// the same message must differ and both verify, and a deterministic signature
// must verify. The signer runs it at startup and refuses to start on failure.
func SelfTest() error {
	var seed [SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return fmt.Errorf("%w: seed: %v", ErrSelfTest, err)
	}
	k, err := FromSeed48(&seed)
	Wipe(seed[:])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSelfTest, err)
	}
	defer k.Zeroize()

	var msg [32]byte
	if _, err := rand.Read(msg[:]); err != nil {
		return fmt.Errorf("%w: message: %v", ErrSelfTest, err)
	}
	h1, err := k.Sign(msg[:], Hedged)
	if err != nil {
		return fmt.Errorf("%w: hedged sign: %v", ErrSelfTest, err)
	}
	h2, err := k.Sign(msg[:], Hedged)
	if err != nil {
		return fmt.Errorf("%w: hedged sign: %v", ErrSelfTest, err)
	}
	if h1 == h2 {
		return fmt.Errorf("%w: two hedged signatures are identical", ErrSelfTest)
	}
	if !k.Verify(msg[:], h1[:]) || !k.Verify(msg[:], h2[:]) {
		return fmt.Errorf("%w: hedged signature does not verify", ErrSelfTest)
	}
	d, err := k.Sign(msg[:], Deterministic)
	if err != nil {
		return fmt.Errorf("%w: deterministic sign: %v", ErrSelfTest, err)
	}
	if !k.Verify(msg[:], d[:]) {
		return fmt.Errorf("%w: deterministic signature does not verify", ErrSelfTest)
	}
	return nil
}
