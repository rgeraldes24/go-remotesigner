// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package mldsa87

import (
	"errors"
	"strings"
	"testing"

	"github.com/theQRL/go-qrllib/wallet/common"
	walletmldsa87 "github.com/theQRL/go-qrllib/wallet/ml_dsa_87"
)

func testExtendedSeed(fill byte) [ExtendedSeedSize]byte {
	var ext [ExtendedSeedSize]byte
	ext[0] = 0x01
	seed := testSeed(fill)
	copy(ext[3:], seed[:])
	return ext
}

// The key of an extended seed is the key of its 48-byte tail, and its
// address and QIP-55 form are what go-qrllib's own wallet derives from the
// same extended seed.
func TestFromExtendedSeed51(t *testing.T) {
	ext := testExtendedSeed(7)
	k, err := FromExtendedSeed51(&ext)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Zeroize()

	if tail := newTestKey(t, 7); k.PublicKey() != tail.PublicKey() {
		t.Fatal("the extended seed's key differs from the key of its 48-byte tail")
	}

	w, err := walletmldsa87.NewWalletFromExtendedSeed(common.ExtendedSeed(ext))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Zeroize()
	pk := k.PublicKey()
	if got, want := pk.Address(), w.GetAddress(); got != want {
		t.Fatalf("Address() = %x, wallet address %x", got, want)
	}
	if got, want := ChecksumAddress(pk.Address()), w.GetChecksumAddressStr(); got != want {
		t.Fatalf("ChecksumAddress() = %s, wallet %s", got, want)
	}
	if !common.IsValidChecksumAddress(ChecksumAddress(pk.Address())) {
		t.Fatal("ChecksumAddress is not a valid QIP-55 address")
	}
	if s := ChecksumAddress(pk.Address()); s[0] != 'Q' || strings.ToLower(s[1:]) != w.GetAddressStr()[1:] {
		t.Fatalf("ChecksumAddress %s does not case-fold to %s", s, w.GetAddressStr())
	}
}

func TestFromExtendedSeed51Descriptor(t *testing.T) {
	for _, d := range [][3]byte{{0x00, 0, 0}, {0x02, 0, 0}, {0x01, 0x01, 0}, {0x01, 0, 0x01}, {0xff, 0xff, 0xff}} {
		ext := testExtendedSeed(1)
		copy(ext[:3], d[:])
		if k, err := FromExtendedSeed51(&ext); !errors.Is(err, ErrDescriptor) {
			if k != nil {
				k.Zeroize()
			}
			t.Errorf("descriptor %x: err = %v, want ErrDescriptor", d, err)
		}
	}
}
