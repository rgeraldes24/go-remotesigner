// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package network resolves the chain the signer is bound to: its chain
// configuration, genesis validators root (GVR) and genesis time.
//
// The configuration comes from --network, either a built-in name or a
// qrysm-format YAML file (see ParseConfig). The GVR and genesis time come,
// in precedence order, from the named network (when it has a published
// genesis), from the --network-genesis-validators-root and
// --network-genesis-time flags, and from the first bytes of a
// --network-genesis-state file. Whenever two sources give the same value
// they must agree, or Load refuses. A file network whose GVR no source gives
// may pin it on first use (TOFU); a named network may not.
//
// Networks are never looked up by fork version: QRL Testnet V1, V2 and
// betanet all use 0x20000089.
//
// The package is written from facts (key names and values of qrysm's
// configuration, the BeaconState field order of the consensus specs), not
// from qrysm code.
package network

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// Errors returned by Load. Callers match them with errors.Is; each source
// pair has its own conflict error.
var (
	ErrNoNetwork          = errors.New("network: --network is required")
	ErrUnknownNetwork     = errors.New("network: unknown network")
	ErrNamedFlagConflict  = errors.New("network: named network and flag disagree")
	ErrNamedStateConflict = errors.New("network: named network and genesis state disagree")
	ErrFlagStateConflict  = errors.New("network: flag and genesis state disagree")
	ErrGenesisForkVersion = errors.New("network: genesis state fork does not carry GENESIS_FORK_VERSION")
)

// Source says where a value came from.
type Source uint8

// Value sources, in precedence order after SourceNone.
const (
	SourceNone         Source = iota // not known
	SourceNamed                      // compiled into a named network
	SourceFlag                       // --network-genesis-validators-root or --network-genesis-time
	SourceGenesisState               // --network-genesis-state
)

// String names the source as an operator would recognise it.
func (s Source) String() string {
	switch s {
	case SourceNone:
		return "none"
	case SourceNamed:
		return "named network"
	case SourceFlag:
		return "flag"
	case SourceGenesisState:
		return "--network-genesis-state"
	default:
		return fmt.Sprintf("Source(%d)", uint8(s))
	}
}

// Sources are the operator inputs that bind the signer to a chain.
type Sources struct {
	Network               string    // --network: a built-in name or a YAML file path
	GenesisValidatorsRoot *[32]byte // --network-genesis-validators-root, nil when unset
	GenesisTime           *uint64   // --network-genesis-time, nil when unset
	GenesisStateFile      string    // --network-genesis-state, "" when unset
}

// Network is a resolved chain binding.
type Network struct {
	// Name is the canonical built-in name, or the YAML file path.
	Name string
	// Named is true for a built-in network and false for a file network.
	Named  bool
	Config Config

	// GenesisValidatorsRoot is valid when GVRSource is not SourceNone.
	GenesisValidatorsRoot [32]byte
	GVRSource             Source
	// GenesisTime (Unix seconds) is valid when GenesisTimeSource is not SourceNone.
	GenesisTime       uint64
	GenesisTimeSource Source
}

// GVRKnown reports whether the GVR is known at startup.
func (n *Network) GVRKnown() bool { return n.GVRSource != SourceNone }

// GenesisTimeKnown reports whether the genesis time is known.
func (n *Network) GenesisTimeKnown() bool { return n.GenesisTimeSource != SourceNone }

// TOFUAllowed reports whether the GVR may be pinned on first use: only for a
// file network whose GVR no source gives. Listener checks are the caller's.
func (n *Network) TOFUAllowed() bool { return !n.Named && !n.GVRKnown() }

// ConflictError reports two sources that give different values for the same
// field. It unwraps to the sentinel for its source pair.
type ConflictError struct {
	Field string // "genesis validators root" or "genesis time"
	A, B  Source // A has the higher precedence
	ValA  string
	ValB  string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("network: %s from %s (%s) disagrees with %s (%s)",
		e.Field, e.sourceName(e.A), e.ValA, e.sourceName(e.B), e.ValB)
}

func (e *ConflictError) sourceName(s Source) string {
	if s != SourceFlag {
		return s.String()
	}
	if e.Field == fieldGVR {
		return "--network-genesis-validators-root"
	}
	return "--network-genesis-time"
}

// Unwrap returns the sentinel for the source pair.
func (e *ConflictError) Unwrap() error {
	switch {
	case e.A == SourceNamed && e.B == SourceFlag:
		return ErrNamedFlagConflict
	case e.A == SourceNamed && e.B == SourceGenesisState:
		return ErrNamedStateConflict
	default:
		return ErrFlagStateConflict
	}
}

const (
	fieldGVR         = "genesis validators root"
	fieldGenesisTime = "genesis time"
)

// Load resolves src against the built-in networks.
func Load(src Sources) (*Network, error) {
	return builtin.load(src)
}

func (r registry) load(src Sources) (*Network, error) {
	if src.Network == "" {
		return nil, ErrNoNetwork
	}
	n := &Network{}
	var gvrs []sourced[[32]byte]
	var times []sourced[uint64]

	if nn, ok := r.lookup(src.Network); ok {
		cfg, err := nn.config()
		if err != nil {
			return nil, err
		}
		n.Name, n.Named, n.Config = nn.name, true, cfg
		if nn.gvr != nil {
			gvrs = append(gvrs, sourced[[32]byte]{SourceNamed, *nn.gvr})
		}
		if nn.genesisTime != nil {
			times = append(times, sourced[uint64]{SourceNamed, *nn.genesisTime})
		}
	} else {
		data, err := os.ReadFile(src.Network)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w %q: not a built-in network (%s) and no such file",
				ErrUnknownNetwork, src.Network, strings.Join(r.names(), ", "))
		}
		if err != nil {
			return nil, fmt.Errorf("network: read %s: %w", src.Network, err)
		}
		cfg, err := ParseConfig(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src.Network, err)
		}
		n.Name, n.Config = src.Network, cfg
	}

	if src.GenesisValidatorsRoot != nil {
		gvrs = append(gvrs, sourced[[32]byte]{SourceFlag, *src.GenesisValidatorsRoot})
	}
	if src.GenesisTime != nil {
		times = append(times, sourced[uint64]{SourceFlag, *src.GenesisTime})
	}
	if src.GenesisStateFile != "" {
		p, err := ReadGenesisPrefixFile(src.GenesisStateFile)
		if err != nil {
			return nil, err
		}
		want := Fork{n.Config.GenesisForkVersion, n.Config.GenesisForkVersion, 0}
		if p.Fork != want {
			return nil, fmt.Errorf("%w: %s has fork {%#x, %#x, %d}, network %s wants {%#x, %#x, 0}",
				ErrGenesisForkVersion, src.GenesisStateFile,
				p.Fork.PreviousVersion, p.Fork.CurrentVersion, p.Fork.Epoch,
				n.Name, want.PreviousVersion, want.CurrentVersion)
		}
		gvrs = append(gvrs, sourced[[32]byte]{SourceGenesisState, p.GenesisValidatorsRoot})
		times = append(times, sourced[uint64]{SourceGenesisState, p.GenesisTime})
	}

	var err error
	if n.GenesisValidatorsRoot, n.GVRSource, err = agree(fieldGVR, gvrs, func(v [32]byte) string {
		return fmt.Sprintf("%#x", v)
	}); err != nil {
		return nil, err
	}
	if n.GenesisTime, n.GenesisTimeSource, err = agree(fieldGenesisTime, times, func(v uint64) string {
		return fmt.Sprint(v)
	}); err != nil {
		return nil, err
	}
	return n, nil
}

// sourced is a value and where it came from.
type sourced[T comparable] struct {
	src Source
	val T
}

// agree checks that every source gives the same value and returns it with
// the highest-precedence source (vals is in precedence order).
func agree[T comparable](field string, vals []sourced[T], format func(T) string) (T, Source, error) {
	var zero T
	if len(vals) == 0 {
		return zero, SourceNone, nil
	}
	for i := range vals {
		for j := i + 1; j < len(vals); j++ {
			if vals[i].val != vals[j].val {
				return zero, SourceNone, &ConflictError{
					Field: field,
					A:     vals[i].src, B: vals[j].src,
					ValA: format(vals[i].val), ValB: format(vals[j].val),
				}
			}
		}
	}
	return vals[0].val, vals[0].src, nil
}
