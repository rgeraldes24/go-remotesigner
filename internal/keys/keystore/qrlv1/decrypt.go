// Copyright © 2019 - 2023 Weald Technology Trading.
// Copyright (c) 2023 The Quantum Resistant Ledger
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
// The Quantum Resistant Ledger's version of this file is licensed under the MIT License (LICENSES/MIT.txt).
//
// SPDX-License-Identifier: MIT AND Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: a KDF is required, and its function and parameters, the salt, the
// IV and the ciphertext are checked before Argon2id runs; the passphrase is no longer normalised here (see
// password.go); errors are typed; the decryption key and plaintext are wiped after use; the encryptor type and its
// options are dropped.
// Derived from qrysm pkg/go-qrl-wallet-encryptor-keystore/decrypt.go and encryptor.go (MIT) at commit
// 0b9cdf251d1f022957d35c4edeb6dd3ce42a617d, themselves derived from wealdtech/go-eth2-wallet-encryptor-keystorev4
// decrypt.go and encryptor.go (Apache-2.0), compared against v1.4.1.

package qrlv1

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

const (
	// Algorithms.
	algoArgon2id = "argon2id"

	// Ciphers.
	cipherAes256Gcm = "aes-256-gcm"
)

// The keystore policy (docs/operations/keystores.md, section 2). Every bound
// is checked on the decoded int before any value reaches Argon2id, so that a
// keystore can neither make it panic (t or p of 0, p truncated to uint8) nor
// allocate more than MaxM KiB.
const (
	MinT = 1      // Argon2id passes
	MaxT = 16     //
	MinM = 4096   // Argon2id memory in KiB: 4 MiB, the deposit CLI's light KDF
	MaxM = 262144 // 256 MiB, the standard KDF of qrysm and the deposit CLI
	MinP = 1      // Argon2id lanes
	MaxP = 4      //

	keySize     = 32                    // dklen: AES-256
	minSaltSize = 16                    //
	maxSaltSize = 64                    //
	ivSize      = 12                    // the GCM standard nonce; cipher.AEAD.Open panics on any other length
	messageSize = mldsa87.SeedSize + 16 // the 48-byte seed and the GCM tag
)

type ksKDFParams struct {
	// Shared parameters
	Salt  string `json:"salt"`
	DKLen int    `json:"dklen"`
	// Argon2id-specific parameters
	T int `json:"t,omitempty"`
	M int `json:"m,omitempty"`
	P int `json:"p,omitempty"`
}

type ksKDF struct {
	Function string       `json:"function"`
	Params   *ksKDFParams `json:"params"`
}

type ksCipherParams struct {
	// AES-256-GCM-specific parameters
	IV string `json:"iv,omitempty"`
}

type ksCipher struct {
	Function string          `json:"function"`
	Params   *ksCipherParams `json:"params"`
	Message  string          `json:"message"`
}

type keystoreV1 struct {
	KDF    *ksKDF    `json:"kdf"`
	Cipher *ksCipher `json:"cipher"`
}

// KDF holds a keystore's Argon2id parameters.
type KDF struct {
	T int // passes
	M int // memory in KiB
	P int // lanes
}

// sealed is a crypto section that passed the policy, decoded.
type sealed struct {
	kdf     KDF
	salt    []byte
	iv      [ivSize]byte
	message [messageSize]byte
}

// errAuth is the GCM authentication failure: a wrong passphrase or a
// tampered ciphertext.
var errAuth = errors.New("failed to decrypt and authenticate ciphertext")

// checkCrypto applies the policy to a keystore's crypto section. It runs no
// KDF and allocates nothing in proportion to the parameters it checks.
func checkCrypto(ks *keystoreV1) (*sealed, error) {
	if ks == nil {
		return nil, fmt.Errorf("%w: no crypto section", ErrFormat)
	}
	// The original falls back to the bare passphrase as the AES key when
	// there is no KDF; here a KDF is required.
	if ks.KDF == nil {
		return nil, fmt.Errorf("%w: no KDF", ErrPolicy)
	}
	if ks.KDF.Function != algoArgon2id {
		return nil, fmt.Errorf("%w: unsupported KDF %q", ErrPolicy, truncate(ks.KDF.Function))
	}
	kdfParams := ks.KDF.Params
	if kdfParams == nil {
		return nil, fmt.Errorf("%w: no KDF params", ErrFormat)
	}
	switch {
	case kdfParams.T < MinT || kdfParams.T > MaxT:
		return nil, fmt.Errorf("%w: KDF t=%d outside [%d, %d]", ErrPolicy, kdfParams.T, MinT, MaxT)
	case kdfParams.M < MinM || kdfParams.M > MaxM:
		return nil, fmt.Errorf("%w: KDF m=%d KiB outside [%d, %d]", ErrPolicy, kdfParams.M, MinM, MaxM)
	case kdfParams.P < MinP || kdfParams.P > MaxP:
		return nil, fmt.Errorf("%w: KDF p=%d outside [%d, %d]", ErrPolicy, kdfParams.P, MinP, MaxP)
	case kdfParams.DKLen != keySize:
		return nil, fmt.Errorf("%w: KDF dklen=%d, want %d", ErrPolicy, kdfParams.DKLen, keySize)
	}
	s := &sealed{kdf: KDF{T: kdfParams.T, M: kdfParams.M, P: kdfParams.P}}
	if n := len(kdfParams.Salt) / 2; n < minSaltSize || n > maxSaltSize {
		return nil, fmt.Errorf("%w: KDF salt of %d bytes, want %d to %d", ErrPolicy, n, minSaltSize, maxSaltSize)
	}
	salt, err := hex.DecodeString(kdfParams.Salt) // at most 2*maxSaltSize+1 characters
	if err != nil {
		return nil, fmt.Errorf("%w: invalid KDF salt", ErrFormat)
	}
	s.salt = salt

	if ks.Cipher == nil {
		return nil, fmt.Errorf("%w: no cipher", ErrFormat)
	}
	if ks.Cipher.Function != cipherAes256Gcm {
		return nil, fmt.Errorf("%w: unsupported cipher %q", ErrPolicy, truncate(ks.Cipher.Function))
	}
	if ks.Cipher.Params == nil {
		return nil, fmt.Errorf("%w: no cipher params", ErrFormat)
	}
	if err := decodeFixed(s.iv[:], ks.Cipher.Params.IV); err != nil {
		return nil, fmt.Errorf("%w: invalid IV: %v", ErrFormat, err)
	}
	if err := decodeFixed(s.message[:], ks.Cipher.Message); err != nil {
		return nil, fmt.Errorf("%w: invalid cipher message: %v", ErrFormat, err)
	}
	return s, nil
}

// open derives the decryption key from the normalised passphrase and opens
// the ciphertext into seed. It returns errAuth when GCM authentication fails.
func (s *sealed) open(normedPassphrase []byte, seed *[mldsa87.SeedSize]byte) error {
	decryptionKey := argon2.IDKey(
		normedPassphrase,
		s.salt,
		uint32(s.kdf.T),
		uint32(s.kdf.M),
		uint8(s.kdf.P), // MinP to MaxP: checkCrypto bounds it as an int first
		keySize,
	)
	defer mldsa87.Wipe(decryptionKey)

	aesCipher, err := aes.NewCipher(decryptionKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}
	block, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return fmt.Errorf("invalid cipher: %w", err)
	}
	// Open writes the plaintext into seed, whose capacity is exactly the
	// plaintext size, so that no copy of the seed is left on the heap.
	if _, err := block.Open(seed[:0], s.iv[:], s.message[:], nil); err != nil {
		mldsa87.Wipe(seed[:])
		return errAuth
	}
	return nil
}

// decodeFixed decodes a hex field of exactly len(dst) bytes into dst.
func decodeFixed(dst []byte, s string) error {
	if len(s) != 2*len(dst) {
		return fmt.Errorf("%d hex characters, want %d bytes as %d", len(s), len(dst), 2*len(dst))
	}
	if _, err := hex.Decode(dst, []byte(s)); err != nil {
		return errors.New("not hex")
	}
	return nil
}
