// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package mldsa87 wraps the go-qrllib ML-DSA-87 wallet for consensus keys.
//
// Every signature goes through the wallet API, which signs under the FIPS 204
// context "ZOND" ‖ 0x01 ‖ descriptor (5a4f4e44 01 010000 for consensus keys).
// That is the context qrysm verifies with; signing through go-qrllib's raw
// crypto/ml_dsa_87 API with an empty context produces signatures qrysm
// rejects, so this package never does.
//
// A Key is built from the validator's 48-byte wallet seed, signs in hedged or
// deterministic mode, serialises signing with a mutex (go-qrllib forbids
// concurrent signing on one wallet) and zeroizes its secret material on
// request. Verify-before-release, the per-type mode table and quarantine
// belong to the signer layer above this package.
package mldsa87

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"

	"github.com/theQRL/go-qrllib/wallet/common"
	walletmldsa87 "github.com/theQRL/go-qrllib/wallet/ml_dsa_87"
)

// Sizes of ML-DSA-87 consensus key material.
const (
	SeedSize      = common.SeedSize       // 48-byte wallet seed
	PublicKeySize = walletmldsa87.PKSize  // 2,592 bytes
	SignatureSize = walletmldsa87.SigSize // 4,627 bytes
	IDSize        = sha256.Size           // key id: SHA-256 of the public key
)

// Errors returned by this package. Callers match them with errors.Is.
var (
	ErrInvalidPublicKey = errors.New("mldsa87: invalid public key")
	ErrZeroized         = errors.New("mldsa87: key has been zeroized")
	ErrUnknownMode      = errors.New("mldsa87: unknown signing mode")
	ErrSelfTest         = errors.New("mldsa87: self-test failed")
)

// descriptor is the wallet descriptor of every consensus key: ML-DSA-87 with
// no parameters (01 00 00). It selects the signing context.
var descriptor = func() [3]byte {
	d, err := walletmldsa87.NewMLDSA87Descriptor()
	if err != nil {
		panic("mldsa87: go-qrllib rejected its own default descriptor: " + err.Error())
	}
	return [3]byte(d)
}()

// Mode selects how a signature's per-signature randomness is chosen.
type Mode uint8

const (
	// Hedged mixes fresh randomness into every signature (FIPS 204 §3.4
	// default). It is the zero value, so an unset mode is hedged.
	Hedged Mode = iota
	// Deterministic uses all-zero randomness: the same key and message give
	// byte-identical signatures. Verifiers accept either mode.
	Deterministic
)

// String returns the mode's flag spelling.
func (m Mode) String() string {
	switch m {
	case Hedged:
		return "hedged"
	case Deterministic:
		return "deterministic"
	default:
		return fmt.Sprintf("Mode(%d)", uint8(m))
	}
}

// ParseMode parses the flag spelling of a mode: "hedged" or "deterministic".
func ParseMode(s string) (Mode, error) {
	switch s {
	case "hedged":
		return Hedged, nil
	case "deterministic":
		return Deterministic, nil
	default:
		return 0, fmt.Errorf("%w %q (want hedged or deterministic)", ErrUnknownMode, s)
	}
}

// PublicKey is a packed ML-DSA-87 public key. Values from ParsePublicKey or
// Key.PublicKey have passed go-qrllib's weak-key check.
type PublicKey [PublicKeySize]byte

// ParsePublicKey checks the length of b and go-qrllib's weak-key rule, and
// returns the key. Use it for every configured or declared public key.
func ParsePublicKey(b []byte) (PublicKey, error) {
	pk, err := walletmldsa87.BytesToPK(b)
	if err != nil {
		return PublicKey{}, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	return PublicKey(pk), nil
}

// ID returns the key id, SHA-256 of the packed public key.
func (pk *PublicKey) ID() [IDSize]byte {
	return sha256.Sum256(pk[:])
}

// Verify reports whether sig is a valid consensus signature over message
// under pk, using the consensus signing context. It returns false for a nil
// or weak key and for a signature of the wrong length.
func Verify(pk *PublicKey, message, sig []byte) bool {
	if pk == nil {
		return false
	}
	return walletmldsa87.Verify(message, sig, (*walletmldsa87.PK)(pk), descriptor)
}

// Wipe overwrites b with zeros. Use it on seed buffers once a Key has been
// built from them. Like go-qrllib's own zeroization it is best effort: copies
// the Go runtime made earlier are out of reach.
func Wipe(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}
