// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package qrlv1

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// lightKDF is the cheapest KDF the policy accepts, for fast tests.
var lightKDF = KDF{T: MinT, M: MinM, P: 1}

// testSeed returns interop key i's seed from the golden vectors.
func testSeed(t testing.TB, i int) *[mldsa87.SeedSize]byte {
	t.Helper()
	b := vectors.Hex(t, vectors.Keys(t)[i].Seed)
	if len(b) != mldsa87.SeedSize {
		t.Fatalf("interop seed %d is %d bytes", i, len(b))
	}
	return (*[mldsa87.SeedSize]byte)(b)
}

// pubkeyHex returns the public key of seed in hex, without 0x.
func pubkeyHex(t testing.TB, seed *[mldsa87.SeedSize]byte) string {
	t.Helper()
	k, err := mldsa87.FromSeed48(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Zeroize()
	pk := k.PublicKey()
	return hex.EncodeToString(pk[:])
}

// seal builds a keystore of the flavour's shape that seals seed under
// kdfPassword, the exact bytes its producer feeds Argon2id. The salt and IV
// are fixed. It returns the keystore as a JSON map, ready to be edited.
func seal(t testing.TB, f Flavour, kdf KDF, kdfPassword []byte, seed *[mldsa87.SeedSize]byte) map[string]any {
	t.Helper()
	salt := bytes.Repeat([]byte{0x5a}, 32)
	iv := bytes.Repeat([]byte{0xa5}, ivSize)
	key := argon2.IDKey(kdfPassword, salt, uint32(kdf.T), uint32(kdf.M), uint8(kdf.P), keySize)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	message := gcm.Seal(nil, iv, seed[:], nil)
	kdfSection := map[string]any{
		"function": "argon2id",
		"params": map[string]any{
			"dklen": keySize, "t": kdf.T, "m": kdf.M, "p": kdf.P, "salt": hex.EncodeToString(salt),
		},
	}
	cipherSection := map[string]any{
		"function": "aes-256-gcm",
		"params":   map[string]any{"iv": hex.EncodeToString(iv)},
		"message":  hex.EncodeToString(message),
	}
	pk := pubkeyHex(t, seed)
	if f == DepositCLI {
		kdfSection["message"] = ""
		return map[string]any{
			"crypto":      map[string]any{"kdf": kdfSection, "checksum": nil, "cipher": cipherSection},
			"description": "",
			"pubkey":      "0x" + pk,
			"path":        "m/12381/238/0/0",
			"uuid":        "00000000-0000-4000-8000-00000000000a",
			"version":     0,
		}
	}
	return map[string]any{
		"crypto":      map[string]any{"kdf": kdfSection, "cipher": cipherSection},
		"uuid":        "00000000-0000-4000-8000-00000000000b",
		"pubkey":      pk,
		"version":     1,
		"description": "keystore",
		"path":        "",
	}
}

// encode marshals a keystore map.
func encode(t testing.TB, ks map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(ks)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// edit returns a copy of the keystore JSON data with the field at the
// dotted path set to v, or deleted when v is the deleteField marker.
func edit(t testing.TB, data []byte, path string, v any) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(path, ".")
	cur := m
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			t.Fatalf("edit %s: %s is not an object", path, p)
		}
		cur = next
	}
	last := parts[len(parts)-1]
	if v == deleteField {
		delete(cur, last)
	} else {
		cur[last] = v
	}
	return encode(t, m)
}

type marker struct{}

// deleteField makes edit remove a field.
var deleteField = marker{}

// allocated returns the bytes the heap allocated while fn ran.
func allocated(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}
