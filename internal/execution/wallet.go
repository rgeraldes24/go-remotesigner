// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"errors"
	"fmt"

	"github.com/theQRL/go-qrl/common"
	"github.com/theQRL/go-qrl/crypto/pqcrypto/wallet"
	walletcommon "github.com/theQRL/go-qrllib/wallet/common"
	"github.com/theQRL/go-qrllib/wallet/common/descriptor"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// errSeedNotExported is GetSeed's answer: the seed never leaves the key.
var errSeedNotExported = errors.New("execution: the signer never exports an account's seed")

// errSignatureInvalid reports a signature that failed verification; it is
// discarded.
var errSignatureInvalid = errors.New("execution: the signature failed verification and was discarded")

// accountDescriptor is the wallet descriptor of every account key the
// signer loads: ML-DSA-87 without parameters, 01 00 00.
var accountDescriptor = descriptor.Descriptor{byte(wallet.ML_DSA_87), 0, 0}

// keyWallet is go-qrl's pqcrypto/wallet.Wallet over a loaded account key,
// for types.SignTx. It signs in mode, hedged in production, and verifies
// each signature before go-qrl sees it. GetSeed fails: go-qrl's signing
// never asks for the seed, and nothing else gets it.
type keyWallet struct {
	key  *mldsa87.Key
	mode mldsa87.Mode
}

var _ wallet.Wallet = keyWallet{}

func (w keyWallet) GetSeed() (walletcommon.ExtendedSeed, error) {
	return walletcommon.ExtendedSeed{}, errSeedNotExported
}

func (w keyWallet) GetAddress() [common.AddressLength]uint8 {
	pk := w.key.PublicKey()
	return pk.Address()
}

func (w keyWallet) GetDescriptor() descriptor.Descriptor { return accountDescriptor }

func (w keyWallet) GetPK() []byte {
	pk := w.key.PublicKey()
	return pk[:]
}

// Sign signs a 32-byte transaction signing hash and verifies the
// signature against the key's public key.
func (w keyWallet) Sign(message []uint8) ([]byte, error) {
	sig, err := w.key.Sign(message, w.mode)
	if err != nil {
		return nil, fmt.Errorf("execution: sign: %w", err)
	}
	if !w.key.Verify(message, sig[:]) {
		return nil, errSignatureInvalid
	}
	return sig[:], nil
}
