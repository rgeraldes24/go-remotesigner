// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package qrlv1

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// testExtendedSeed is interop key i's seed behind the descriptor 01 00 00.
func testExtendedSeed(t testing.TB, i int) *[mldsa87.ExtendedSeedSize]byte {
	t.Helper()
	var ext [mldsa87.ExtendedSeedSize]byte
	ext[0] = 0x01
	copy(ext[3:], testSeed(t, i)[:])
	return &ext
}

// accountAddress is the address of an extended seed's key, in go-qrl's
// keystore form.
func accountAddress(t testing.TB, ext *[mldsa87.ExtendedSeedSize]byte) string {
	t.Helper()
	k, err := mldsa87.FromExtendedSeed51(ext)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Zeroize()
	pk := k.PublicKey()
	a := pk.Address()
	return "Q" + hex.EncodeToString(a[:])
}

// sealAccount builds a go-qrl account keystore of plaintext under the raw
// password, as gqrl's account manager writes it, as a JSON map.
func sealAccount(t testing.TB, kdf KDF, password, plaintext []byte, address string) map[string]any {
	t.Helper()
	salt := bytes.Repeat([]byte{0x3c}, 32)
	iv := bytes.Repeat([]byte{0xc3}, ivSize)
	key := argon2.IDKey(password, salt, uint32(kdf.T), uint32(kdf.M), uint8(kdf.P), keySize)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"address": address,
		"crypto": map[string]any{
			"cipher":       "aes-256-gcm",
			"ciphertext":   hex.EncodeToString(gcm.Seal(nil, iv, plaintext, nil)),
			"cipherparams": map[string]any{"iv": hex.EncodeToString(iv)},
			"kdf":          "argon2id",
			"kdfparams":    map[string]any{"dklen": keySize, "m": kdf.M, "p": kdf.P, "salt": hex.EncodeToString(salt), "t": kdf.T},
		},
		"id":      "6e7f8a90-1b2c-4d3e-8f40-5a6b7c8d9e0f",
		"version": 1,
	}
}

func TestAccountKeystore(t *testing.T) {
	ext := testExtendedSeed(t, 0)
	addr := accountAddress(t, ext)
	password := []byte("account password")
	data := encode(t, sealAccount(t, lightKDF, password, ext[:], addr))

	ks, err := ParseAccount(data)
	if err != nil {
		t.Fatal(err)
	}
	if ks.Flavour != Account || ks.Flavour.Version() != 1 || ks.Flavour.String() != "gqrl-account" {
		t.Fatalf("flavour %v (version %d)", ks.Flavour, ks.Flavour.Version())
	}
	if ks.KDF != lightKDF {
		t.Fatalf("KDF = %+v, want %+v", ks.KDF, lightKDF)
	}
	declared, ok := ks.Address()
	if !ok || "Q"+hex.EncodeToString(declared[:]) != addr {
		t.Fatalf("Address() = %x, %v", declared, ok)
	}
	if _, ok := ks.PublicKey(); ok {
		t.Fatal("an account keystore declares no public key")
	}
	pw := NewPassword(password)
	defer pw.Wipe()
	key, err := ks.Decrypt(pw)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zeroize()
	want, err := mldsa87.FromExtendedSeed51(ext)
	if err != nil {
		t.Fatal(err)
	}
	defer want.Zeroize()
	if key.PublicKey() != want.PublicKey() {
		t.Fatal("the decrypted key is not the extended seed's key")
	}

	// go-qrl writes the address in lower case; either case is read.
	upper := "Q" + strings.ToUpper(addr[1:])
	if _, err := ParseAccount(encode(t, sealAccount(t, lightKDF, password, ext[:], upper))); err != nil {
		t.Fatalf("upper-case address: %v", err)
	}
}

// The password is used as raw bytes, as go-qrl does: no other candidate is
// tried, so a wrong password costs one Argon2id run.
func TestAccountKeystorePassword(t *testing.T) {
	ext := testExtendedSeed(t, 1)
	addr := accountAddress(t, ext)
	nfc := []byte("pässword") // its NFKD form differs
	ks, err := ParseAccount(encode(t, sealAccount(t, lightKDF, []byte(normPassphrase(string(nfc))), ext[:], addr)))
	if err != nil {
		t.Fatal(err)
	}
	pw := NewPassword(nfc)
	defer pw.Wipe()
	if n := len(pw.candidates(Account)); n != 1 {
		t.Fatalf("%d candidates for an account keystore, want 1 (the raw bytes)", n)
	}
	if _, err := ks.Decrypt(pw); !errors.Is(err, ErrPassword) {
		t.Fatalf("a normalised password opened a raw-password keystore: %v", err)
	}
	wrong := NewPassword([]byte("wrong"))
	defer wrong.Wipe()
	if _, err := ks.Decrypt(wrong); !errors.Is(err, ErrPassword) {
		t.Fatalf("wrong password: %v", err)
	}
}

func TestAccountKeystoreRefusals(t *testing.T) {
	ext := testExtendedSeed(t, 2)
	addr := accountAddress(t, ext)
	other := accountAddress(t, testExtendedSeed(t, 3))
	password := []byte("pw")
	base := sealAccount(t, lightKDF, password, ext[:], addr)
	with := func(f func(m map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(encode(t, base), &m); err != nil {
			t.Fatal(err)
		}
		f(m)
		return encode(t, m)
	}
	crypto := func(m map[string]any) map[string]any { return m["crypto"].(map[string]any) }
	kdfParams := func(m map[string]any) map[string]any { return crypto(m)["kdfparams"].(map[string]any) }
	badDescriptor := *ext
	badDescriptor[1] = 0x01

	parse := []struct {
		name string
		data []byte
		want error
	}{
		{"validator keystore", encode(t, seal(t, QRLV1, lightKDF, password, testSeed(t, 2))), ErrFormat},
		{"no address", with(func(m map[string]any) { delete(m, "address") }), ErrFormat},
		{"address without Q", with(func(m map[string]any) { m["address"] = "0x" + addr[1:] }), ErrFormat},
		{"lower-case q", with(func(m map[string]any) { m["address"] = "q" + addr[1:] }), ErrFormat},
		{"short address", with(func(m map[string]any) { m["address"] = addr[:41] }), ErrFormat},
		{"address not hex", with(func(m map[string]any) { m["address"] = "Q" + strings.Repeat("z", 128) }), ErrFormat},
		{"no version", with(func(m map[string]any) { delete(m, "version") }), ErrFormat},
		{"version 3", with(func(m map[string]any) { m["version"] = 3 }), ErrPolicy},
		{"no crypto", with(func(m map[string]any) { delete(m, "crypto") }), ErrFormat},
		{"no KDF", with(func(m map[string]any) { delete(crypto(m), "kdf"); delete(crypto(m), "kdfparams") }), ErrPolicy},
		{"scrypt", with(func(m map[string]any) { crypto(m)["kdf"] = "scrypt" }), ErrPolicy},
		{"no KDF params", with(func(m map[string]any) { delete(crypto(m), "kdfparams") }), ErrFormat},
		{"m above the bound", with(func(m map[string]any) { kdfParams(m)["m"] = MaxM + 1 }), ErrPolicy},
		{"t of 0", with(func(m map[string]any) { kdfParams(m)["t"] = 0 }), ErrPolicy},
		{"p of 256", with(func(m map[string]any) { kdfParams(m)["p"] = 256 }), ErrPolicy},
		{"dklen 16", with(func(m map[string]any) { kdfParams(m)["dklen"] = 16 }), ErrPolicy},
		{"aes-128-ctr", with(func(m map[string]any) { crypto(m)["cipher"] = "aes-128-ctr" }), ErrPolicy},
		{"no IV", with(func(m map[string]any) { delete(crypto(m), "cipherparams") }), ErrFormat},
		{"16-byte IV", with(func(m map[string]any) {
			crypto(m)["cipherparams"] = map[string]any{"iv": strings.Repeat("00", 16)}
		}), ErrFormat},
		// A 48-byte seed and its tag: a consensus seed in an account keystore.
		{"48-byte plaintext", encode(t, sealAccount(t, lightKDF, password, ext[3:], addr)), ErrFormat},
		{"trailing data", append(encode(t, base), '}'), ErrFormat},
		{"too large", bytes.Repeat([]byte(" "), MaxSize+1), ErrFormat},
	}
	for _, tt := range parse {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseAccount(tt.data); !errors.Is(err, tt.want) {
				t.Fatalf("ParseAccount: %v, want %v", err, tt.want)
			}
		})
	}

	decrypt := []struct {
		name string
		data []byte
		want error
	}{
		{"address of another key", with(func(m map[string]any) { m["address"] = other }), ErrAddressMismatch},
		{"descriptor 01 01 00", encode(t, sealAccount(t, lightKDF, password, badDescriptor[:], addr)), ErrFormat},
	}
	pw := NewPassword(password)
	defer pw.Wipe()
	for _, tt := range decrypt {
		t.Run(tt.name, func(t *testing.T) {
			ks, err := ParseAccount(tt.data)
			if err != nil {
				t.Fatal(err)
			}
			if k, err := ks.Decrypt(pw); !errors.Is(err, tt.want) {
				if k != nil {
					k.Zeroize()
				}
				t.Fatalf("Decrypt: %v, want %v", err, tt.want)
			}
		})
	}
}

// Consensus mode refuses an account keystore, and says what it is.
func TestParseRefusesAccountKeystore(t *testing.T) {
	ext := testExtendedSeed(t, 4)
	data := encode(t, sealAccount(t, lightKDF, []byte("pw"), ext[:], accountAddress(t, ext)))
	_, err := Parse(data)
	if !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), "execution-layer key") {
		t.Fatalf("Parse: %v", err)
	}
}

// A keystore that go-qrl itself wrote, at the commit DESIGN pins (b92884a):
// accounts/keystore.EncryptKey with the light Argon2id parameters, for the
// extended seed gqrlExtendedSeed under gqrlPassword. gqrlAddress is go-qrl's
// common.Address.Hex of the same key. The fixture was generated once outside
// this module, which links no go-qrl; PROVENANCE.md ("Golden vectors") says
// how it was made and how to check it again.
const (
	gqrlExtendedSeed = "010000a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
	gqrlPassword     = "gqrl account password"
	gqrlAddress      = "QC9CD783BbB87765B7395C856348Ef35b107bd9e35484648E35C18D1449Da8E12B49376B92C6F29dE62fAF272cFE1afAf31808733089F90c4b1E67E6Ceda0BE09"
	gqrlKeystore     = `{"address":"Qc9cd783bbb87765b7395c856348ef35b107bd9e35484648e35c18d1449da8e12b49376b92c6f29de62faf272cfe1afaf31808733089f90c4b1e67e6ceda0be09","crypto":{"cipher":"aes-256-gcm","ciphertext":"866f40521dbc0f9b9fe58bf9d9b96a04811e37cf259af1f9a1c24402ac356ebcc51ffd6830670aa826e213977c75fd47f0799eb23324165357b8e36fb9eb4318d71285","cipherparams":{"iv":"7d48373d2a8d0c9c434ce69e"},"kdf":"argon2id","kdfparams":{"dklen":32,"m":4096,"p":1,"salt":"d5135aa3a0e542e4eb2969b5c07fb5d88347542f87bb7df9ef8de19a8d71d05d","t":8}},"id":"3198bc9c-6672-5ab3-d995-4942343ae5b6","version":1}`
)

// The hardened decryptor opens what gqrl writes: the address check passes,
// the key is the extended seed's, the QIP-55 form is go-qrl's own, and the
// keystore is refused in consensus mode and under another address.
func TestGoQRLAccountKeystore(t *testing.T) {
	ks, err := ParseAccount([]byte(gqrlKeystore))
	if err != nil {
		t.Fatal(err)
	}
	if ks.KDF != (KDF{T: 8, M: 4096, P: 1}) || ks.UUID != "3198bc9c-6672-5ab3-d995-4942343ae5b6" {
		t.Fatalf("KDF %+v, id %q", ks.KDF, ks.UUID)
	}
	pw := NewPassword(TrimPassword([]byte(gqrlPassword + "\n"))) // as a password file holds it
	defer pw.Wipe()
	key, err := ks.Decrypt(pw)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zeroize()

	extBytes, err := hex.DecodeString(gqrlExtendedSeed)
	if err != nil {
		t.Fatal(err)
	}
	want, err := mldsa87.FromExtendedSeed51((*[mldsa87.ExtendedSeedSize]byte)(extBytes))
	if err != nil {
		t.Fatal(err)
	}
	defer want.Zeroize()
	if key.PublicKey() != want.PublicKey() {
		t.Fatal("the key gqrl's keystore holds is not its extended seed's")
	}
	pk := key.PublicKey()
	addr := pk.Address()
	if got := mldsa87.ChecksumAddress(addr); got != gqrlAddress {
		t.Fatalf("QIP-55 address %s, go-qrl's %s", got, gqrlAddress)
	}
	if declared, _ := ks.Address(); declared != addr {
		t.Fatal("the declared address is not the derived one")
	}

	wrong := NewPassword([]byte("wrong"))
	defer wrong.Wipe()
	if _, err := ks.Decrypt(wrong); !errors.Is(err, ErrPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := Parse([]byte(gqrlKeystore)); !errors.Is(err, ErrFormat) {
		t.Fatalf("consensus Parse: %v", err)
	}
	other := accountAddress(t, testExtendedSeed(t, 5))
	moved, err := ParseAccount([]byte(strings.Replace(gqrlKeystore, "Q"+hex.EncodeToString(addr[:]), other, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if k, err := moved.Decrypt(pw); !errors.Is(err, ErrAddressMismatch) {
		if k != nil {
			k.Zeroize()
		}
		t.Fatalf("gqrl's keystore under another address: %v", err)
	}
}
