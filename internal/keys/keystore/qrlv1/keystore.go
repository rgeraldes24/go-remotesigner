// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package qrlv1 decrypts QRL validator keystores: the keystore v1 that
// qrysm's validator writes (`version: 1`) and the deposit CLI's keystore
// (`version: 0`). Both seal the validator's 48-byte ML-DSA-87 wallet seed
// with Argon2id and AES-256-GCM.
//
// The package is a hardened copy of qrysm's MIT keystore v1 decryptor
// (third_party/qrl-keystore holds the pristine original). The hardening,
// which docs/operations/keystores.md describes for operators:
//
//   - Parse applies the structure and KDF policy before any Argon2id run:
//     a KDF is required, argon2id only, t, m, p and dklen bounded, and the
//     salt, IV and ciphertext lengths checked, so that no keystore can make
//     Argon2id or GCM panic or allocate more than MaxM KiB.
//   - Decrypt tries the password's deduplicated candidate set (Password),
//     so an ASCII password costs one Argon2id run, and recovers any panic
//     into ErrInternal. The caller wipes the Password when done with it.
//   - The public key derived from the decrypted seed is compared with the
//     keystore's pubkey field; the caller gets the derived key.
//   - The fields GCM does not authenticate and decryption does not use
//     (uuid, path, description) are kept only in a form that is safe to
//     print: path only when it is a derivation path, the others without
//     control or format characters.
//
// Errors wrap one of ErrFormat, ErrPolicy, ErrPassword, ErrPubkeyMismatch
// or ErrInternal and never contain key material or passwords.
package qrlv1

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// MaxSize is the largest keystore file accepted. A keystore with its
// 5,184-character public key is about 6 KB.
const MaxSize = 64 << 10

// Errors. Callers match them with errors.Is.
var (
	// ErrFormat: the input is not a keystore this package can read: not
	// JSON, too large, a missing section, bad hex, or a wrong field length.
	ErrFormat = errors.New("keystore: malformed keystore")
	// ErrPolicy: a well-formed keystore whose version, KDF or cipher this
	// signer refuses, including a keystore without a KDF.
	ErrPolicy = errors.New("keystore: refused by the keystore policy")
	// ErrPassword: no password candidate opens the ciphertext. GCM cannot
	// tell a wrong password from a tampered ciphertext.
	ErrPassword = errors.New("keystore: wrong password or corrupted ciphertext")
	// ErrPubkeyMismatch: the keystore's pubkey is not the key its seed
	// derives.
	ErrPubkeyMismatch = errors.New("keystore: pubkey does not match the decrypted seed")
	// ErrInternal: decryption panicked; the panic was recovered.
	ErrInternal = errors.New("keystore: decryption failed unexpectedly")
)

// Flavour is a keystore's producer, given by its version field.
type Flavour uint8

const (
	// DepositCLI is the deposit CLI's keystore: version 0, a 0x-prefixed
	// pubkey, and the password used as raw bytes.
	DepositCLI Flavour = iota + 1
	// QRLV1 is qrysm's keystore v1 (accounts backup and import): version
	// 1, a pubkey without 0x, and an NFKD-normalised password.
	QRLV1
)

func (f Flavour) String() string {
	switch f {
	case DepositCLI:
		return "deposit-cli"
	case QRLV1:
		return "qrl-v1"
	default:
		return fmt.Sprintf("Flavour(%d)", uint8(f))
	}
}

// Version returns the keystore version field of the flavour.
func (f Flavour) Version() int {
	if f == QRLV1 {
		return 1
	}
	return 0
}

// file is the keystore JSON. Fields neither flavour needs (the deposit
// CLI's crypto.checksum and kdf.message) are ignored.
type file struct {
	Crypto      *keystoreV1 `json:"crypto"`
	Version     *int        `json:"version"`
	Pubkey      *string     `json:"pubkey"`
	UUID        string      `json:"uuid"`
	Path        string      `json:"path"`
	Description string      `json:"description"`
}

// Keystore is a parsed keystore that passed the policy. Decrypting it runs
// Argon2id with at most MaxM KiB.
//
// UUID, Path and Description come from fields that anyone who can edit the
// file can change without the password. Parse keeps them only in a form that
// is safe to print to a terminal or a log line.
type Keystore struct {
	Flavour     Flavour
	KDF         KDF
	UUID        string // printable characters only, at most 64 bytes
	Path        string // the derivation path (m/12381/238/0/0); empty in qrysm's keystores and when the field is not one
	Description string // printable characters only, at most 64 bytes

	pubkey *mldsa87.PublicKey // the declared pubkey, nil when the file has none
	sealed *sealed
}

// Parse reads a keystore and applies the structure and KDF policy. It runs
// no KDF.
func Parse(data []byte) (ks *Keystore, err error) {
	defer func() {
		if r := recover(); r != nil {
			ks, err = nil, panicked(r)
		}
	}()
	if len(data) > MaxSize {
		return nil, fmt.Errorf("%w: %d bytes, larger than %d", ErrFormat, len(data), MaxSize)
	}
	// Unmarshal, unlike a Decoder, also refuses any data after the object,
	// a stray closing bracket included.
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%w: not a single keystore JSON object", ErrFormat)
	}
	ks = &Keystore{UUID: printable(f.UUID), Path: derivationPath(f.Path), Description: printable(f.Description)}
	switch {
	case f.Version == nil:
		return nil, fmt.Errorf("%w: no version", ErrFormat)
	case *f.Version == 0:
		ks.Flavour = DepositCLI
	case *f.Version == 1:
		ks.Flavour = QRLV1
	default:
		return nil, fmt.Errorf("%w: unsupported version %d (want 1, or 0 for the deposit CLI)", ErrPolicy, *f.Version)
	}
	if ks.sealed, err = checkCrypto(f.Crypto); err != nil {
		return nil, err
	}
	ks.KDF = ks.sealed.kdf
	if f.Pubkey != nil {
		pk, err := parsePubkey(*f.Pubkey)
		if err != nil {
			return nil, err
		}
		ks.pubkey = &pk
	}
	return ks, nil
}

// PublicKey returns the keystore's declared pubkey, if it has one. It is
// not trusted until Decrypt has compared it with the derived key.
func (ks *Keystore) PublicKey() (mldsa87.PublicKey, bool) {
	if ks.pubkey == nil {
		return mldsa87.PublicKey{}, false
	}
	return *ks.pubkey, true
}

// Decrypt opens the keystore with the first password candidate that
// authenticates, derives the key from the seed and compares it with the
// declared pubkey. Each distinct candidate costs one Argon2id run; a wrong
// password costs one run per candidate. The seed is wiped before Decrypt
// returns; the caller owns the key and zeroizes it when done.
func (ks *Keystore) Decrypt(pw *Password) (key *mldsa87.Key, err error) {
	defer func() {
		if r := recover(); r != nil {
			key, err = nil, panicked(r)
		}
	}()
	var seed [mldsa87.SeedSize]byte
	defer mldsa87.Wipe(seed[:])
	for _, c := range pw.candidates(ks.Flavour) {
		err := ks.sealed.open(c, &seed)
		if errors.Is(err, errAuth) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInternal, err)
		}
		return ks.derive(&seed)
	}
	return nil, ErrPassword
}

// Decrypt parses data and decrypts it with pw.
func Decrypt(data []byte, pw *Password) (*mldsa87.Key, error) {
	ks, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return ks.Decrypt(pw)
}

// derive builds the key of seed and checks it against the declared pubkey.
func (ks *Keystore) derive(seed *[mldsa87.SeedSize]byte) (*mldsa87.Key, error) {
	key, err := mldsa87.FromSeed48(seed)
	if err != nil {
		return nil, fmt.Errorf("%w: the decrypted seed gives no valid key", ErrFormat)
	}
	if ks.pubkey != nil {
		if derived := key.PublicKey(); derived != *ks.pubkey {
			key.Zeroize()
			return nil, fmt.Errorf("%w: declared %s, derived %s", ErrPubkeyMismatch, ks.pubkey.LogID(), derived.LogID())
		}
	}
	return key, nil
}

// parsePubkey reads a pubkey field: 2,592 bytes in hex, with or without
// 0x (qrysm writes it bare, the deposit CLI with 0x), and a valid ML-DSA-87
// public key.
func parsePubkey(s string) (mldsa87.PublicKey, error) {
	var raw [mldsa87.PublicKeySize]byte
	h := strings.TrimPrefix(s, "0x")
	if len(h) != 2*len(raw) {
		return mldsa87.PublicKey{}, fmt.Errorf("%w: pubkey of %d hex characters, want %d", ErrFormat, len(h), 2*len(raw))
	}
	if _, err := hex.Decode(raw[:], []byte(h)); err != nil {
		return mldsa87.PublicKey{}, fmt.Errorf("%w: pubkey is not hex", ErrFormat)
	}
	pk, err := mldsa87.ParsePublicKey(raw[:])
	if err != nil {
		return mldsa87.PublicKey{}, fmt.Errorf("%w: pubkey: %v", ErrFormat, err)
	}
	return pk, nil
}

// panicked is the error of a recovered panic. Parse and Decrypt recover
// their own panics: a panic in a decrypt worker goroutine would otherwise
// end the process, since net/http recovers only its handler goroutines.
func panicked(r any) error {
	return fmt.Errorf("%w: %v", ErrInternal, r)
}

// derivationPathRE matches a derivation path: m, then at most 10 numeric
// components of at most 10 digits, each optionally hardened.
var derivationPathRE = regexp.MustCompile(`^m(/[0-9]{1,10}'?){0,10}$`)

// derivationPath returns s when it is a derivation path, else "": the path
// field is printed (keystore verify), and anything else in it, such as a
// terminal escape that rewrites the identifier line above it, is ignored.
func derivationPath(s string) string {
	if derivationPathRE.MatchString(s) {
		return s
	}
	return ""
}

// printable returns the printable characters of an untrusted string kept in
// a Keystore, truncated: no control characters (C0, DEL, C1, so no ESC and
// no line break), no format characters such as bidirectional overrides, and
// no space other than U+0020 (unicode.IsPrint).
func printable(s string) string {
	return truncate(strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s))
}

// truncate bounds an untrusted string kept or quoted in an error.
func truncate(s string) string {
	if len(s) > 64 {
		return strings.ToValidUTF8(s[:64], "") + "…"
	}
	return s
}
