// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrGenesisState reports a genesis state that cannot be read.
var ErrGenesisState = errors.New("network: unreadable genesis state")

// GenesisPrefixSize is the number of leading bytes of an SSZ-encoded genesis
// BeaconState that the signer reads.
const GenesisPrefixSize = 64

// Fork is the SSZ Fork container: previous version, current version, epoch.
type Fork struct {
	PreviousVersion [4]byte
	CurrentVersion  [4]byte
	Epoch           uint64
}

// GenesisPrefix holds the fixed-size fields at the start of an SSZ-encoded
// BeaconState. They are its first four fields, in this order:
//
//	bytes  0-8   genesis_time            uint64, little endian
//	bytes  8-40  genesis_validators_root Bytes32
//	bytes 40-48  slot                    uint64, little endian
//	bytes 48-64  fork                    Fork (4 + 4 + 8 bytes)
type GenesisPrefix struct {
	GenesisTime           uint64
	GenesisValidatorsRoot [32]byte
	Slot                  uint64
	Fork                  Fork
}

// ParseGenesisPrefix decodes the first GenesisPrefixSize bytes of b.
func ParseGenesisPrefix(b []byte) (GenesisPrefix, error) {
	if len(b) < GenesisPrefixSize {
		return GenesisPrefix{}, fmt.Errorf("%w: %d bytes, need at least %d", ErrGenesisState, len(b), GenesisPrefixSize)
	}
	var p GenesisPrefix
	p.GenesisTime = binary.LittleEndian.Uint64(b[0:8])
	p.GenesisValidatorsRoot = [32]byte(b[8:40])
	p.Slot = binary.LittleEndian.Uint64(b[40:48])
	p.Fork.PreviousVersion = [4]byte(b[48:52])
	p.Fork.CurrentVersion = [4]byte(b[52:56])
	p.Fork.Epoch = binary.LittleEndian.Uint64(b[56:64])
	return p, nil
}

// ReadGenesisPrefix reads and decodes the prefix from r. It reads exactly
// GenesisPrefixSize bytes, so a multi-megabyte state is never loaded.
func ReadGenesisPrefix(r io.Reader) (GenesisPrefix, error) {
	var b [GenesisPrefixSize]byte
	n, err := io.ReadFull(r, b[:])
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return GenesisPrefix{}, fmt.Errorf("%w: %d bytes, need at least %d", ErrGenesisState, n, GenesisPrefixSize)
		}
		return GenesisPrefix{}, fmt.Errorf("%w: %v", ErrGenesisState, err)
	}
	return ParseGenesisPrefix(b[:])
}

// ReadGenesisPrefixFile reads the prefix of the genesis state file at path.
func ReadGenesisPrefixFile(path string) (GenesisPrefix, error) {
	f, err := os.Open(path)
	if err != nil {
		return GenesisPrefix{}, fmt.Errorf("%w: %v", ErrGenesisState, err)
	}
	defer func() { _ = f.Close() }()
	p, err := ReadGenesisPrefix(f)
	if err != nil {
		return GenesisPrefix{}, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}
