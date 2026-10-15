// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestBuiltinNetworks(t *testing.T) {
	tests := []struct {
		name     string
		want     string // canonical name
		preset   string
		fork     [4]byte
		sps, spe uint64
		chainID  uint64
		syncBits uint64
	}{
		{"minimal", "minimal", PresetMinimal, [4]byte{0, 0, 0, 0x01}, 6, 8, 5, 16},
		{"end-to-end", "end-to-end", PresetMinimal, [4]byte{0, 0, 0, 0xfd}, 10, 6, 1337, 16},
		{"e2e", "end-to-end", PresetMinimal, [4]byte{0, 0, 0, 0xfd}, 10, 6, 1337, 16},
		{"end-to-end-mainnet", "end-to-end-mainnet", PresetMainnet, [4]byte{0, 0, 0, 0xfe}, 6, 128, 1337, 128},
		{"interop", "interop", PresetMainnet, [4]byte{0, 0, 0, 0xeb}, 60, 128, 1, 128},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := Load(Sources{Network: tt.name})
			if err != nil {
				t.Fatal(err)
			}
			c := n.Config
			if n.Name != tt.want || !n.Named || c.ConfigName != tt.want {
				t.Fatalf("name = %q (named %v, CONFIG_NAME %q), want %q", n.Name, n.Named, c.ConfigName, tt.want)
			}
			if c.PresetBase != tt.preset || c.GenesisForkVersion != tt.fork || c.SecondsPerSlot != tt.sps ||
				c.SlotsPerEpoch != tt.spe || c.DepositChainID != tt.chainID || c.DepositNetworkID != tt.chainID ||
				c.SyncSubcommitteeSize() != tt.syncBits {
				t.Fatalf("config = %+v", c)
			}
			// No built-in network has a published genesis yet, and named
			// networks never pin their GVR on first use.
			if n.GVRKnown() || n.GenesisTimeKnown() || n.TOFUAllowed() {
				t.Fatalf("GVR %v, genesis time %v, TOFU %v", n.GVRKnown(), n.GenesisTimeKnown(), n.TOFUAllowed())
			}
		})
	}
}

func TestNames(t *testing.T) {
	want := []string{"e2e", "end-to-end", "end-to-end-mainnet", "interop", "minimal"}
	if got := Names(); !slices.Equal(got, want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	// Testnet V1, V2 and betanet are not signable with this stack.
	for _, name := range []string{"testnet", "testnetv2", "betanet", "mainnet"} {
		if _, ok := builtin.lookup(name); ok {
			t.Errorf("%q is a built-in network", name)
		}
	}
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func genesisState(genesisTime uint64, gvr [32]byte, fork Fork) []byte {
	b := make([]byte, GenesisPrefixSize, GenesisPrefixSize+256)
	binary.LittleEndian.PutUint64(b[0:8], genesisTime)
	copy(b[8:40], gvr[:])
	binary.LittleEndian.PutUint64(b[40:48], 0)
	copy(b[48:52], fork.PreviousVersion[:])
	copy(b[52:56], fork.CurrentVersion[:])
	binary.LittleEndian.PutUint64(b[56:64], fork.Epoch)
	return append(b, bytes.Repeat([]byte{0xee}, 256)...) // the rest of the state
}

func TestLoadFileNetwork(t *testing.T) {
	path := writeFile(t, "config.yaml", []byte(e2eComponentYAML))
	n, err := Load(Sources{Network: path})
	if err != nil {
		t.Fatal(err)
	}
	if n.Named || n.Name != path || n.Config.ConfigName != "end-to-end" {
		t.Fatalf("network = %+v", n)
	}
	if !n.TOFUAllowed() {
		t.Fatal("file network without a GVR source must allow TOFU")
	}

	gvr := [32]byte{1}
	n, err = Load(Sources{Network: path, GenesisValidatorsRoot: &gvr})
	if err != nil {
		t.Fatal(err)
	}
	if n.TOFUAllowed() || n.GVRSource != SourceFlag || n.GenesisValidatorsRoot != gvr {
		t.Fatalf("GVR %x from %v, TOFU %v", n.GenesisValidatorsRoot, n.GVRSource, n.TOFUAllowed())
	}
}

func TestLoadErrors(t *testing.T) {
	bad := writeFile(t, "bad.yaml", []byte("CONFIG_NAME: x\n"))
	tests := []struct {
		name    string
		network string
		want    error
	}{
		{"missing", "", ErrNoNetwork},
		{"unknown name", "testnet", ErrUnknownNetwork},
		{"missing file", filepath.Join(t.TempDir(), "nope.yaml"), ErrUnknownNetwork},
		{"invalid file", bad, ErrInvalidConfig},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Load(Sources{Network: tt.network}); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}

	// A directory is neither a name nor a readable file.
	if _, err := Load(Sources{Network: t.TempDir()}); err == nil || errors.Is(err, ErrUnknownNetwork) {
		t.Fatalf("directory: err = %v", err)
	}
}

// TestSourceAgreement covers the genesis-source rules: precedence, and a
// distinct error for every conflicting pair and for wrong fork bytes.
func TestSourceAgreement(t *testing.T) {
	var (
		gvrA, gvrB   = [32]byte{0xaa}, [32]byte{0xbb}
		timeA, timeB = uint64(1_760_000_000), uint64(1_760_000_060)
		e2eFork      = [4]byte{0, 0, 0, 0xfd}
		goodFork     = Fork{e2eFork, e2eFork, 0}
	)
	// "pubnet" is a named network with a published genesis.
	reg := registry{{name: "pubnet", file: "end-to-end.yaml", genesisTime: &timeA, gvr: &gvrA}}
	fileNet := writeFile(t, "config.yaml", []byte(e2eComponentYAML))
	state := func(tm uint64, gvr [32]byte, fork Fork) string {
		return writeFile(t, "genesis.ssz", genesisState(tm, gvr, fork))
	}
	ptr := func(v uint64) *uint64 { return &v }
	short := writeFile(t, "short.ssz", make([]byte, GenesisPrefixSize-1))

	allConflicts := []error{ErrNamedFlagConflict, ErrNamedStateConflict, ErrFlagStateConflict, ErrGenesisForkVersion}
	tests := []struct {
		name     string
		src      Sources
		wantErr  error
		wantGVR  Source
		wantTime Source
	}{
		{"named only", Sources{Network: "pubnet"}, nil, SourceNamed, SourceNamed},
		{"named and agreeing flags and state",
			Sources{Network: "pubnet", GenesisValidatorsRoot: &gvrA, GenesisTime: &timeA, GenesisStateFile: state(timeA, gvrA, goodFork)},
			nil, SourceNamed, SourceNamed},
		{"named vs GVR flag", Sources{Network: "pubnet", GenesisValidatorsRoot: &gvrB}, ErrNamedFlagConflict, 0, 0},
		{"named vs genesis-time flag", Sources{Network: "pubnet", GenesisTime: ptr(timeB)}, ErrNamedFlagConflict, 0, 0},
		{"named vs genesis state GVR", Sources{Network: "pubnet", GenesisStateFile: state(timeA, gvrB, goodFork)}, ErrNamedStateConflict, 0, 0},
		{"named vs genesis state time", Sources{Network: "pubnet", GenesisStateFile: state(timeB, gvrA, goodFork)}, ErrNamedStateConflict, 0, 0},
		{"flags only", Sources{Network: fileNet, GenesisValidatorsRoot: &gvrA, GenesisTime: &timeA}, nil, SourceFlag, SourceFlag},
		{"genesis state only", Sources{Network: fileNet, GenesisStateFile: state(timeA, gvrA, goodFork)}, nil, SourceGenesisState, SourceGenesisState},
		{"flag and agreeing state", Sources{Network: fileNet, GenesisTime: &timeA, GenesisStateFile: state(timeA, gvrA, goodFork)}, nil, SourceGenesisState, SourceFlag},
		{"GVR flag vs genesis state", Sources{Network: fileNet, GenesisValidatorsRoot: &gvrB, GenesisStateFile: state(timeA, gvrA, goodFork)}, ErrFlagStateConflict, 0, 0},
		{"genesis-time flag vs genesis state", Sources{Network: fileNet, GenesisTime: ptr(timeB), GenesisStateFile: state(timeA, gvrA, goodFork)}, ErrFlagStateConflict, 0, 0},
		{"wrong current fork version", Sources{Network: fileNet, GenesisStateFile: state(timeA, gvrA, Fork{e2eFork, [4]byte{0x20, 0, 0, 0x89}, 0})}, ErrGenesisForkVersion, 0, 0},
		{"wrong previous fork version", Sources{Network: fileNet, GenesisStateFile: state(timeA, gvrA, Fork{[4]byte{0, 0, 0, 1}, e2eFork, 0})}, ErrGenesisForkVersion, 0, 0},
		{"non-genesis fork epoch", Sources{Network: fileNet, GenesisStateFile: state(timeA, gvrA, Fork{e2eFork, e2eFork, 5})}, ErrGenesisForkVersion, 0, 0},
		{"genesis state of another network", Sources{Network: "pubnet", GenesisStateFile: state(timeA, gvrA, Fork{[4]byte{0, 0, 0, 0xfe}, [4]byte{0, 0, 0, 0xfe}, 0})}, ErrGenesisForkVersion, 0, 0},
		{"short genesis state", Sources{Network: fileNet, GenesisStateFile: short}, ErrGenesisState, 0, 0},
		{"missing genesis state", Sources{Network: fileNet, GenesisStateFile: filepath.Join(t.TempDir(), "x.ssz")}, ErrGenesisState, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := reg.load(tt.src)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				for _, other := range allConflicts {
					if other != tt.wantErr && errors.Is(err, other) {
						t.Fatalf("err = %v also matches %v", err, other)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if n.GVRSource != tt.wantGVR || n.GenesisTimeSource != tt.wantTime {
				t.Fatalf("sources = %v, %v, want %v, %v", n.GVRSource, n.GenesisTimeSource, tt.wantGVR, tt.wantTime)
			}
			if n.GenesisValidatorsRoot != gvrA || n.GenesisTime != timeA || n.TOFUAllowed() {
				t.Fatalf("GVR %x, time %d, TOFU %v", n.GenesisValidatorsRoot, n.GenesisTime, n.TOFUAllowed())
			}
		})
	}
}

func TestConflictErrorMessage(t *testing.T) {
	gvrA, gvrB := [32]byte{0xaa}, [32]byte{0xbb}
	reg := registry{{name: "pubnet", file: "end-to-end.yaml", gvr: &gvrA}}
	_, err := reg.load(Sources{Network: "pubnet", GenesisValidatorsRoot: &gvrB})
	var ce *ConflictError
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v, want *ConflictError", err)
	}
	want := "network: genesis validators root from named network (0xaa00000000000000000000000000000000000000000000000000000000000000) " +
		"disagrees with --network-genesis-validators-root (0xbb00000000000000000000000000000000000000000000000000000000000000)"
	if err.Error() != want {
		t.Fatalf("message:\n%s\nwant\n%s", err, want)
	}
}

func TestGenesisPrefix(t *testing.T) {
	gvr := [32]byte{0x7a, 0x1e, 31: 0x09}
	fork := Fork{[4]byte{0, 0, 0, 0xfd}, [4]byte{0, 0, 0, 0xfd}, 0}
	b := genesisState(1775003316, gvr, fork)
	binary.LittleEndian.PutUint64(b[40:48], 7)

	p, err := ReadGenesisPrefix(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	want := GenesisPrefix{GenesisTime: 1775003316, GenesisValidatorsRoot: gvr, Slot: 7, Fork: fork}
	if p != want {
		t.Fatalf("got %+v, want %+v", p, want)
	}
	// Little endian: 1775003316 = 0x69cc66b4.
	if !bytes.Equal(b[0:8], []byte{0xb4, 0x66, 0xcc, 0x69, 0, 0, 0, 0}) {
		t.Fatalf("genesis_time bytes = %x", b[0:8])
	}

	for _, n := range []int{0, 8, GenesisPrefixSize - 1} {
		if _, err := ReadGenesisPrefix(bytes.NewReader(b[:n])); !errors.Is(err, ErrGenesisState) {
			t.Errorf("%d bytes: err = %v, want ErrGenesisState", n, err)
		}
		if _, err := ParseGenesisPrefix(b[:n]); !errors.Is(err, ErrGenesisState) {
			t.Errorf("parse %d bytes: err = %v, want ErrGenesisState", n, err)
		}
	}
}

func TestSourceString(t *testing.T) {
	for s, want := range map[Source]string{
		SourceNone: "none", SourceNamed: "named network", SourceFlag: "flag",
		SourceGenesisState: "--network-genesis-state", Source(9): "Source(9)",
	} {
		if s.String() != want {
			t.Errorf("%d: %q, want %q", s, s.String(), want)
		}
	}
}
