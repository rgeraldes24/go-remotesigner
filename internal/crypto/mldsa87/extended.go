// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package mldsa87

import (
	"errors"
	"fmt"

	"github.com/theQRL/go-qrllib/wallet/common"
	qrldescriptor "github.com/theQRL/go-qrllib/wallet/common/descriptor"
)

// Sizes of execution-layer key material.
const (
	// ExtendedSeedSize is the 51-byte extended seed of an execution account:
	// the 3-byte descriptor followed by the 48-byte wallet seed.
	ExtendedSeedSize = common.ExtendedSeedSize
	// AddressSize is the 64-byte QRL account address.
	AddressSize = common.AddressSize
)

// descriptorSize is the length of a wallet descriptor.
const descriptorSize = qrldescriptor.DescriptorSize

// ErrDescriptor reports an extended seed whose descriptor is not ML-DSA-87
// with no parameters (01 00 00).
var ErrDescriptor = errors.New("mldsa87: extended seed descriptor is not 01 00 00 (ML-DSA-87)")

// FromExtendedSeed51 builds an execution-layer key from a 51-byte extended
// seed. Its descriptor must be exactly 01 00 00: go-qrl checks only the
// first byte, go-qrllib only that the other two are zero, and this signer
// accepts nothing else. The key pair is the one FromSeed48 builds from the
// 48 bytes after the descriptor, so execution and consensus keys share the
// signing context; only the seed length tells the two modes apart.
//
// The caller keeps ownership of ext and should Wipe it once the key is
// built.
func FromExtendedSeed51(ext *[ExtendedSeedSize]byte) (*Key, error) {
	if [descriptorSize]byte(ext[:descriptorSize]) != descriptor {
		return nil, ErrDescriptor
	}
	seed := [SeedSize]byte(ext[descriptorSize:])
	defer Wipe(seed[:])
	k, err := FromSeed48(&seed)
	if err != nil {
		return nil, fmt.Errorf("mldsa87: derive key from extended seed: %w", err)
	}
	return k, nil
}

// Address returns the QRL account address of pk: the first 64 bytes of
// SHAKE-256 over the descriptor 01 00 00 and the public key.
func (pk *PublicKey) Address() [AddressSize]byte {
	return common.UnsafeGetAddress(pk[:], qrldescriptor.Descriptor(descriptor))
}

// ChecksumAddress renders an address in its QIP-55 form: "Q" followed by
// the hex of the address, each letter upper-cased where the matching nibble
// of SHAKE-256 over the lowercase hex is 8 or more.
func ChecksumAddress(addr [AddressSize]byte) string {
	return common.ToChecksumAddress(addr)
}
