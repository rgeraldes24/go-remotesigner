// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package keystoretest writes keystores for tests: the deposit CLI's
// format, which qrysm's validator client and the signer load, qrysm's
// keystore v1, and, for execution mode, go-qrl's account keystore. Only
// tests import it; the signer never writes keystores.
//
// A Sealer derives its Argon2id key once and gives every keystore its own
// random IV, so that a test can write thousands of keystores, even with
// the standard KDF, at the cost of one Argon2id run. Every keystore it
// writes shares the password and the salt; the signer still runs Argon2id
// for each one.
package keystoretest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystore/qrlv1"
)

// KDFs.
var (
	// Light is the deposit CLI's --lightkdf: t=8, m=4 MiB, p=1.
	Light = qrlv1.KDF{T: 8, M: 4096, P: 1}
	// Standard is the KDF of qrysm and the deposit CLI: t=8, m=256 MiB,
	// p=1.
	Standard = qrlv1.KDF{T: 8, M: 262144, P: 1}
	// Cheapest is the cheapest KDF the signer accepts, for fast tests.
	Cheapest = qrlv1.KDF{T: qrlv1.MinT, M: qrlv1.MinM, P: 1}
)

// Sealer seals seeds under one password.
type Sealer struct {
	kdf  qrlv1.KDF
	salt [32]byte
	aead cipher.AEAD
}

// NewSealer derives the key of password with kdf and a random salt. The
// password is used as given: for an ASCII password every keystore flavour
// encrypts with the same bytes.
func NewSealer(password string, kdf qrlv1.KDF) (*Sealer, error) {
	s := &Sealer{kdf: kdf}
	if _, err := rand.Read(s.salt[:]); err != nil {
		return nil, err
	}
	key := argon2.IDKey([]byte(password), s.salt[:], uint32(kdf.T), uint32(kdf.M), uint8(kdf.P), 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if s.aead, err = cipher.NewGCM(block); err != nil {
		return nil, err
	}
	return s, nil
}

// Seed returns the deterministic seed number i of a test, tagged so that
// tests can keep their key sets apart.
func Seed(tag string, i int) *[mldsa87.SeedSize]byte {
	h := sha256.Sum256(binary.BigEndian.AppendUint64([]byte(tag), uint64(i)))
	var seed [mldsa87.SeedSize]byte
	copy(seed[:], h[:])
	copy(seed[32:], h[:16])
	return &seed
}

// PublicKeyHex returns the public key of seed in hex, without 0x.
func PublicKeyHex(seed *[mldsa87.SeedSize]byte) (string, error) {
	k, err := mldsa87.FromSeed48(seed)
	if err != nil {
		return "", err
	}
	defer k.Zeroize()
	pk := k.PublicKey()
	return hex.EncodeToString(pk[:]), nil
}

type kdfParams struct {
	DKLen int    `json:"dklen"`
	M     int    `json:"m"`
	P     int    `json:"p"`
	Salt  string `json:"salt"`
	T     int    `json:"t"`
}

type kdfSection struct {
	Function string    `json:"function"`
	Params   kdfParams `json:"params"`
	Message  *string   `json:"message,omitempty"`
}

type cipherSection struct {
	Function string `json:"function"`
	Params   struct {
		IV string `json:"iv"`
	} `json:"params"`
	Message string `json:"message"`
}

type cryptoV1 struct {
	KDF    kdfSection    `json:"kdf"`
	Cipher cipherSection `json:"cipher"`
}

type cryptoDeposit struct {
	KDF      kdfSection    `json:"kdf"`
	Checksum *string       `json:"checksum"`
	Cipher   cipherSection `json:"cipher"`
}

// seal builds the KDF and cipher sections of seed.
func (s *Sealer) seal(seed *[mldsa87.SeedSize]byte) (kdfSection, cipherSection, error) {
	return s.sealBytes(seed[:])
}

// sealBytes builds the KDF and cipher sections of a plaintext.
func (s *Sealer) sealBytes(plaintext []byte) (kdfSection, cipherSection, error) {
	var iv [12]byte
	if _, err := rand.Read(iv[:]); err != nil {
		return kdfSection{}, cipherSection{}, err
	}
	k := kdfSection{Function: "argon2id", Params: kdfParams{
		DKLen: 32, M: s.kdf.M, P: s.kdf.P, Salt: hex.EncodeToString(s.salt[:]), T: s.kdf.T,
	}}
	c := cipherSection{Function: "aes-256-gcm", Message: hex.EncodeToString(s.aead.Seal(nil, iv[:], plaintext, nil))}
	c.Params.IV = hex.EncodeToString(iv[:])
	return k, c, nil
}

func uuid() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// DepositPath is the derivation path qrysm's deposit CLI records for key i
// (docs/operations/keystores.md).
func DepositPath(i int) string { return fmt.Sprintf("m/12381/238/%d/0", i) }

// DepositFileName is the deposit CLI's file name for key i, written at the
// Unix time unix: keystore-<path with _ for />-<unix>.json.
func DepositFileName(i int, unix int64) string {
	return fmt.Sprintf("keystore-m_12381_238_%d_0-%d.json", i, unix)
}

// DepositCLI returns the deposit CLI keystore of seed, key i of its seed
// phrase: compact JSON, version 0, a 0x pubkey (left out when withPubkey
// is false, which skips deriving it), a null checksum.
func (s *Sealer) DepositCLI(seed *[mldsa87.SeedSize]byte, i int, withPubkey bool) ([]byte, error) {
	k, c, err := s.seal(seed)
	if err != nil {
		return nil, err
	}
	empty := ""
	k.Message = &empty
	ks := struct {
		Crypto      cryptoDeposit `json:"crypto"`
		Description string        `json:"description"`
		Pubkey      string        `json:"pubkey,omitempty"`
		Path        string        `json:"path"`
		UUID        string        `json:"uuid"`
		Version     int           `json:"version"`
	}{Crypto: cryptoDeposit{KDF: k, Cipher: c}, Path: DepositPath(i), UUID: uuid()}
	if withPubkey {
		pk, err := PublicKeyHex(seed)
		if err != nil {
			return nil, err
		}
		ks.Pubkey = "0x" + pk
	}
	return json.Marshal(ks)
}

// QRLV1 returns the qrysm keystore v1 of seed: version 1, a pubkey without
// 0x (left out when withPubkey is false).
func (s *Sealer) QRLV1(seed *[mldsa87.SeedSize]byte, withPubkey bool) ([]byte, error) {
	k, c, err := s.seal(seed)
	if err != nil {
		return nil, err
	}
	ks := struct {
		Crypto      cryptoV1 `json:"crypto"`
		UUID        string   `json:"uuid"`
		Pubkey      string   `json:"pubkey,omitempty"`
		Version     int      `json:"version"`
		Description string   `json:"description"`
		Path        string   `json:"path"`
	}{Crypto: cryptoV1{KDF: k, Cipher: c}, UUID: uuid(), Version: 1, Description: "keystore"}
	if withPubkey {
		pk, err := PublicKeyHex(seed)
		if err != nil {
			return nil, err
		}
		ks.Pubkey = pk
	}
	return json.Marshal(ks)
}

// ExtendedSeed returns the deterministic 51-byte extended seed number i of
// a test: the descriptor 01 00 00 followed by Seed(tag, i).
func ExtendedSeed(tag string, i int) *[mldsa87.ExtendedSeedSize]byte {
	var ext [mldsa87.ExtendedSeedSize]byte
	ext[0] = 0x01
	copy(ext[3:], Seed(tag, i)[:])
	return &ext
}

// Address returns the account address of an extended seed in go-qrl's
// keystore form: "Q" and lowercase hex.
func Address(ext *[mldsa87.ExtendedSeedSize]byte) (string, error) {
	k, err := mldsa87.FromExtendedSeed51(ext)
	if err != nil {
		return "", err
	}
	defer k.Zeroize()
	pk := k.PublicKey()
	a := pk.Address()
	return "Q" + hex.EncodeToString(a[:]), nil
}

// Account returns go-qrl's account keystore of an extended seed, as gqrl's
// account manager writes it: a flat crypto section, the address in "Q" and
// lowercase hex, an id and version 1. An empty address leaves the field out.
func (s *Sealer) Account(ext *[mldsa87.ExtendedSeedSize]byte, address string) ([]byte, error) {
	k, c, err := s.sealBytes(ext[:])
	if err != nil {
		return nil, err
	}
	type cryptoAccount struct {
		Cipher       string `json:"cipher"`
		CipherText   string `json:"ciphertext"`
		CipherParams struct {
			IV string `json:"iv"`
		} `json:"cipherparams"`
		KDF       string    `json:"kdf"`
		KDFParams kdfParams `json:"kdfparams"`
	}
	ks := struct {
		Address string        `json:"address,omitempty"`
		Crypto  cryptoAccount `json:"crypto"`
		ID      string        `json:"id"`
		Version int           `json:"version"`
	}{Address: address, ID: uuid(), Version: 1}
	ks.Crypto = cryptoAccount{Cipher: c.Function, CipherText: c.Message, KDF: k.Function, KDFParams: k.Params}
	ks.Crypto.CipherParams.IV = c.Params.IV
	return json.Marshal(ks)
}

// WriteFile writes data to dir/name with mode 0600.
func WriteFile(dir, name string, data []byte) (string, error) {
	p := filepath.Join(dir, name)
	return p, os.WriteFile(p, data, 0o600)
}
