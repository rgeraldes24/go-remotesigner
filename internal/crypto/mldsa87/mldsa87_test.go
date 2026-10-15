// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package mldsa87

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	rawmldsa87 "github.com/theQRL/go-qrllib/crypto/ml_dsa_87"
	walletmldsa87 "github.com/theQRL/go-qrllib/wallet/ml_dsa_87"
)

// consensusContext is the FIPS 204 context qrysm verifies consensus
// signatures with: "ZOND" ‖ 0x01 ‖ descriptor 01 00 00.
var consensusContext = mustHex("5a4f4e4401010000")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func testSeed(fill byte) [SeedSize]byte {
	var s [SeedSize]byte
	for i := range s {
		s[i] = fill + byte(i)
	}
	return s
}

func newTestKey(t testing.TB, fill byte) *Key {
	t.Helper()
	seed := testSeed(fill)
	k, err := FromSeed48(&seed)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Zeroize)
	return k
}

func rawPublicKey(t *testing.T, pk PublicKey) *rawmldsa87.PublicKey {
	t.Helper()
	raw, err := rawmldsa87.ParsePublicKey(pk[:])
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDescriptor(t *testing.T) {
	if descriptor != [3]byte{0x01, 0x00, 0x00} {
		t.Fatalf("descriptor = %x, want 010000", descriptor)
	}
}

// TestSigningContext is the acceptance check: a signature made through the
// go-qrllib wallet verifies under the explicit context 5a4f4e4401010000.
func TestSigningContext(t *testing.T) {
	k := newTestKey(t, 1)
	msg := sha256.Sum256([]byte("signing root"))
	raw := rawPublicKey(t, k.PublicKey())

	for _, mode := range []Mode{Hedged, Deterministic} {
		t.Run(mode.String(), func(t *testing.T) {
			sig, err := k.Sign(msg[:], mode)
			if err != nil {
				t.Fatal(err)
			}
			if !rawmldsa87.Verify(consensusContext, msg[:], sig, raw) {
				t.Fatal("signature does not verify under context 5a4f4e4401010000")
			}
			if rawmldsa87.Verify(nil, msg[:], sig, raw) {
				t.Fatal("signature verifies under the empty context")
			}
		})
	}
}

// TestEmptyContextSignatureRejected is the negative control: the same key
// signing through the raw crypto API with an empty context produces a
// signature that consensus verification rejects.
func TestEmptyContextSignatureRejected(t *testing.T) {
	seed := testSeed(1)
	k := newTestKey(t, 1)
	raw, err := rawmldsa87.NewMLDSA87FromSeed(sha256.Sum256(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Zeroize()
	if raw.GetPK() != [PublicKeySize]byte(k.PublicKey()) {
		t.Fatal("raw key and wallet key differ; the control would prove nothing")
	}
	msg := sha256.Sum256([]byte("signing root"))
	sig, err := raw.Sign(nil, msg[:])
	if err != nil {
		t.Fatal(err)
	}
	pk := k.PublicKey()
	if Verify(&pk, msg[:], sig[:]) {
		t.Fatal("empty-context signature verified as a consensus signature")
	}
	if !rawmldsa87.Verify(nil, msg[:], sig, rawPublicKey(t, pk)) {
		t.Fatal("control signature does not verify under its own (empty) context")
	}
}

func TestModes(t *testing.T) {
	k := newTestKey(t, 2)
	msg := sha256.Sum256([]byte("selection proof root"))

	d1, err := k.Sign(msg[:], Deterministic)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := k.Sign(msg[:], Deterministic)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatal("deterministic signatures over the same message differ")
	}
	h1, err := k.Sign(msg[:], Hedged)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := k.Sign(msg[:], Hedged)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 || h1 == d1 {
		t.Fatal("hedged signatures repeat")
	}
	for _, sig := range [][SignatureSize]byte{d1, h1, h2} {
		if !k.Verify(msg[:], sig[:]) {
			t.Fatal("signature does not verify")
		}
	}

	// A different key gives a different deterministic signature.
	other := newTestKey(t, 3)
	d3, err := other.Sign(msg[:], Deterministic)
	if err != nil {
		t.Fatal(err)
	}
	if d3 == d1 {
		t.Fatal("two keys produced the same deterministic signature")
	}
}

func TestSignUnknownMode(t *testing.T) {
	k := newTestKey(t, 4)
	if _, err := k.Sign([]byte("m"), Mode(2)); !errors.Is(err, ErrUnknownMode) {
		t.Fatalf("err = %v, want ErrUnknownMode", err)
	}
}

func TestParseMode(t *testing.T) {
	tests := []struct {
		in      string
		want    Mode
		wantErr bool
	}{
		{"hedged", Hedged, false},
		{"deterministic", Deterministic, false},
		{"", 0, true},
		{"Deterministic", 0, true},
		{"random", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseMode(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("ParseMode(%q) = %v, %v", tt.in, got, err)
		}
		if err != nil && !errors.Is(err, ErrUnknownMode) {
			t.Errorf("ParseMode(%q) error %v is not ErrUnknownMode", tt.in, err)
		}
		if err == nil && got.String() != tt.in {
			t.Errorf("%v.String() = %q, want %q", got, got.String(), tt.in)
		}
	}
	if Mode(9).String() != "Mode(9)" {
		t.Errorf("Mode(9).String() = %q", Mode(9).String())
	}
}

func TestParsePublicKey(t *testing.T) {
	good := newTestKey(t, 5).PublicKey()
	tests := []struct {
		name    string
		in      []byte
		wantErr bool
	}{
		{"valid", good[:], false},
		{"empty", nil, true},
		{"one byte short", good[:PublicKeySize-1], true},
		{"one byte long", append(append([]byte(nil), good[:]...), 0), true},
		{"all zero (weak key)", make([]byte, PublicKeySize), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk, err := ParsePublicKey(tt.in)
			if tt.wantErr {
				if !errors.Is(err, ErrInvalidPublicKey) {
					t.Fatalf("err = %v, want ErrInvalidPublicKey", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if pk != good {
				t.Fatal("parsed key differs")
			}
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	k := newTestKey(t, 6)
	other := newTestKey(t, 7).PublicKey()
	msg := []byte("root")
	sig, err := k.Sign(msg, Hedged)
	if err != nil {
		t.Fatal(err)
	}
	pk := k.PublicKey()
	tampered := sig
	tampered[100] ^= 0x01
	var zero PublicKey

	tests := []struct {
		name string
		pk   *PublicKey
		msg  []byte
		sig  []byte
		want bool
	}{
		{"valid", &pk, msg, sig[:], true},
		{"other message", &pk, []byte("Root"), sig[:], false},
		{"other key", &other, msg, sig[:], false},
		{"tampered signature", &pk, msg, tampered[:], false},
		{"short signature", &pk, msg, sig[:SignatureSize-1], false},
		{"nil key", nil, msg, sig[:], false},
		{"zero (weak) key", &zero, msg, sig[:], false},
	}
	for _, tt := range tests {
		if got := Verify(tt.pk, tt.msg, tt.sig); got != tt.want {
			t.Errorf("%s: Verify = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestKeyMatchesWallet(t *testing.T) {
	seed := testSeed(8)
	w, err := walletmldsa87.NewWalletFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Zeroize()
	k := newTestKey(t, 8)
	pk := k.PublicKey()
	if [PublicKeySize]byte(w.GetPK()) != [PublicKeySize]byte(pk) {
		t.Fatal("public key differs from go-qrllib's wallet")
	}
	if k.ID() != sha256.Sum256(pk[:]) || pk.ID() != k.ID() {
		t.Fatal("ID is not SHA-256 of the public key")
	}
}

func TestWithSeed(t *testing.T) {
	seed := testSeed(9)
	k := newTestKey(t, 9)
	var seen *[SeedSize]byte
	err := k.WithSeed(func(s *[SeedSize]byte) error {
		if *s != seed {
			t.Error("WithSeed passed a different seed")
		}
		seen = s
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if *seen != ([SeedSize]byte{}) {
		t.Fatal("seed copy was not wiped after fn returned")
	}
	sentinel := errors.New("fn failed")
	if err := k.WithSeed(func(*[SeedSize]byte) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want fn's error", err)
	}
}

func TestZeroize(t *testing.T) {
	k := newTestKey(t, 10)
	pk := k.PublicKey()
	if k.Zeroized() {
		t.Fatal("new key reports zeroized")
	}
	w := k.wallet
	k.Zeroize()
	k.Zeroize() // idempotent

	if !k.Zeroized() {
		t.Fatal("Zeroized() = false after Zeroize")
	}
	if w.GetSeed() != ([SeedSize]byte{}) {
		t.Fatal("wallet seed not cleared")
	}
	if w.GetSK() != ([walletmldsa87.SKSize]byte{}) {
		t.Fatal("wallet secret key not cleared")
	}
	if _, err := k.Sign([]byte("m"), Hedged); !errors.Is(err, ErrZeroized) {
		t.Fatalf("Sign after Zeroize: err = %v, want ErrZeroized", err)
	}
	called := false
	if err := k.WithSeed(func(*[SeedSize]byte) error { called = true; return nil }); !errors.Is(err, ErrZeroized) || called {
		t.Fatalf("WithSeed after Zeroize: err = %v, called = %v", err, called)
	}
	if k.PublicKey() != pk {
		t.Fatal("public key changed after Zeroize")
	}
}

// TestConcurrentSignAndZeroize runs under -race: every Sign either returns a
// verifying signature or ErrZeroized.
func TestConcurrentSignAndZeroize(t *testing.T) {
	k := newTestKey(t, 11)
	msg := []byte("root")
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 4 {
				mode := Mode(i % 2)
				sig, err := k.Sign(msg, mode)
				switch {
				case errors.Is(err, ErrZeroized):
				case err != nil:
					errs <- err
				case !k.Verify(msg, sig[:]):
					errs <- errors.New("signature does not verify")
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		k.Zeroize()
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestSelfTest(t *testing.T) {
	if err := SelfTest(); err != nil {
		t.Fatal(err)
	}
}

func TestWipe(t *testing.T) {
	b := bytes.Repeat([]byte{0xaa}, SeedSize)
	Wipe(b)
	if !bytes.Equal(b, make([]byte, SeedSize)) {
		t.Fatal("Wipe left data behind")
	}
	Wipe(nil)
}
