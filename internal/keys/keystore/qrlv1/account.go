// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package qrlv1

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// The go-qrl account keystore is the keystore v1 that gqrl's account
// manager writes (`gqrl account new`, `account import`): a flat crypto
// section (cipher, ciphertext, cipherparams.iv, kdf, kdfparams), a "Q"
// address, an id and version 1. It seals the account's 51-byte extended
// seed, descriptor first, with Argon2id and AES-256-GCM, under the password
// as raw bytes. go-qrl's own decryptor does not compare the address with
// the decrypted key; this one does.
//
// Its crypto section goes through the same policy as the validator
// keystores (checkCrypto), with a 51-byte plaintext.

// ErrAddressMismatch: the keystore's address is not the address of the key
// its extended seed derives.
var ErrAddressMismatch = errors.New("keystore: address does not match the decrypted seed")

// accountCrypto is the flat crypto section of a go-qrl account keystore.
type accountCrypto struct {
	Cipher       string `json:"cipher"`
	CipherText   string `json:"ciphertext"`
	CipherParams *struct {
		IV string `json:"iv"`
	} `json:"cipherparams"`
	KDF       string       `json:"kdf"`
	KDFParams *ksKDFParams `json:"kdfparams"`
}

// accountFile is the go-qrl account keystore JSON.
type accountFile struct {
	Address *string        `json:"address"`
	Crypto  *accountCrypto `json:"crypto"`
	ID      string         `json:"id"`
	Version *int           `json:"version"`
}

// ParseAccount reads a go-qrl account keystore and applies the structure and
// KDF policy. It runs no KDF. Validator keystores, which Parse reads, are
// refused: they hold consensus keys.
func ParseAccount(data []byte) (ks *Keystore, err error) {
	defer func() {
		if r := recover(); r != nil {
			ks, err = nil, panicked(r)
		}
	}()
	if len(data) > MaxSize {
		return nil, fmt.Errorf("%w: %d bytes, larger than %d", ErrFormat, len(data), MaxSize)
	}
	var f accountFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%w: not a single go-qrl account keystore JSON object", ErrFormat)
	}
	switch {
	case f.Address == nil:
		return nil, fmt.Errorf("%w: no address: not a go-qrl account keystore (a validator keystore holds a "+
			"consensus key, which execution mode does not load)", ErrFormat)
	case f.Version == nil:
		return nil, fmt.Errorf("%w: no version", ErrFormat)
	case *f.Version != 1:
		return nil, fmt.Errorf("%w: unsupported version %d (want 1)", ErrPolicy, *f.Version)
	case f.Crypto == nil:
		return nil, fmt.Errorf("%w: no crypto section", ErrFormat)
	}
	addr, err := parseAddress(*f.Address)
	if err != nil {
		return nil, err
	}
	// The flat section in the validator keystore's shape, so that one
	// policy checks both. A missing kdf or cipher is an empty name here,
	// which the policy refuses like any other unsupported one.
	c := f.Crypto
	v1 := &keystoreV1{Cipher: &ksCipher{Function: c.Cipher, Message: c.CipherText}}
	if c.KDF != "" || c.KDFParams != nil {
		v1.KDF = &ksKDF{Function: c.KDF, Params: c.KDFParams}
	}
	if c.CipherParams != nil {
		v1.Cipher.Params = &ksCipherParams{IV: c.CipherParams.IV}
	}
	ks = &Keystore{Flavour: Account, UUID: printable(f.ID), address: &addr}
	if ks.sealed, err = checkCrypto(v1, mldsa87.ExtendedSeedSize); err != nil {
		return nil, err
	}
	ks.KDF = ks.sealed.kdf
	return ks, nil
}

// Address returns an account keystore's declared address. It is not
// trusted until Decrypt has compared it with the derived key's.
func (ks *Keystore) Address() ([mldsa87.AddressSize]byte, bool) {
	if ks.address == nil {
		return [mldsa87.AddressSize]byte{}, false
	}
	return *ks.address, true
}

// deriveAccount builds the key of an account keystore's extended seed and
// checks it against the declared address.
func (ks *Keystore) deriveAccount(ext *[mldsa87.ExtendedSeedSize]byte) (*mldsa87.Key, error) {
	key, err := mldsa87.FromExtendedSeed51(ext)
	if err != nil {
		return nil, fmt.Errorf("%w: the decrypted extended seed gives no valid key: %v", ErrFormat, err)
	}
	pk := key.PublicKey()
	if derived := pk.Address(); derived != *ks.address {
		key.Zeroize()
		return nil, fmt.Errorf("%w: declared %s, derived %s", ErrAddressMismatch,
			shortAddress(*ks.address), shortAddress(derived))
	}
	return key, nil
}

// parseAddress reads an address field: "Q" followed by 128 hex characters
// in either case (go-qrl writes them in lower case).
func parseAddress(s string) ([mldsa87.AddressSize]byte, error) {
	var a [mldsa87.AddressSize]byte
	if len(s) != 1+2*len(a) || s[0] != 'Q' {
		return a, fmt.Errorf("%w: address is not \"Q\" followed by %d hex characters", ErrFormat, 2*len(a))
	}
	if _, err := hex.Decode(a[:], []byte(s[1:])); err != nil {
		return a, fmt.Errorf("%w: address is not hex", ErrFormat)
	}
	return a, nil
}

// shortAddress is the form of an address that errors print.
func shortAddress(a [mldsa87.AddressSize]byte) string {
	return "Q" + hex.EncodeToString(a[:5]) + "…"
}
