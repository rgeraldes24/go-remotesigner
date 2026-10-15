// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package signingroot

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func decodeHex(t *testing.T, s string, n int) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != n {
		t.Fatalf("bad %d-byte hex %q", n, s)
	}
	return b
}

func root32(t *testing.T, s string) [32]byte  { t.Helper(); return [32]byte(decodeHex(t, s, 32)) }
func version(t *testing.T, s string) Version  { t.Helper(); return Version(decodeHex(t, s, 4)) }
func domainHex(t *testing.T, s string) Domain { t.Helper(); return Domain(decodeHex(t, s, 32)) }

func TestComputeForkDataRootZero(t *testing.T) {
	// HTR(ForkData{0x00000000, zero root}) is sha256 of 64 zero bytes.
	got := ComputeForkDataRoot(Version{}, [32]byte{})
	if want := root32(t, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"); got != want {
		t.Fatalf("ComputeForkDataRoot(0, 0) = %x, want %x", got, want)
	}
}

func TestComputeForkDataRootLayout(t *testing.T) {
	v := Version{0x00, 0x00, 0x00, 0xfd}
	gvr := [32]byte{1, 2, 3}
	var buf [64]byte
	copy(buf[:4], v[:]) // the version right-padded to a chunk
	copy(buf[32:], gvr[:])
	if got, want := ComputeForkDataRoot(v, gvr), sha256.Sum256(buf[:]); got != want {
		t.Fatalf("ComputeForkDataRoot = %x, want sha256(pad32(version) ‖ gvr) = %x", got, want)
	}
}

// Genesis-version domains with a zero genesis validators root, as DEPOSIT and
// APPLICATION_BUILDER use them. The mainnet DEPOSIT domain is byte-identical
// to Ethereum mainnet's, because both use GENESIS_FORK_VERSION 0x00000000.
func TestGenesisDomains(t *testing.T) {
	tests := []struct {
		network string
		version string
		deposit string
		builder string
	}{
		{"mainnet", "0x00000000",
			"0x03000000f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9",
			"0x00000001f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a9"},
		{"minimal", "0x00000001",
			"0x0300000018ae4ccbda9538839d79bb18ca09e23e24ae8c1550f56cbb3d84b053",
			"0x0000000118ae4ccbda9538839d79bb18ca09e23e24ae8c1550f56cbb3d84b053"},
		{"e2e", "0x000000fd",
			"0x030000002c3c06efe6456ca45340ee2bf169ae9fcd41f600b9cd0a54cbe6b472",
			"0x000000012c3c06efe6456ca45340ee2bf169ae9fcd41f600b9cd0a54cbe6b472"},
		{"e2e-mainnet", "0x000000fe",
			"0x03000000c73bfd082b705da602272cd8ee18fb3bd3caac1a8a80338ce585947a",
			"0x00000001c73bfd082b705da602272cd8ee18fb3bd3caac1a8a80338ce585947a"},
	}
	for _, tt := range tests {
		t.Run(tt.network, func(t *testing.T) {
			v := version(t, tt.version)
			if got := ComputeDomain(DomainDeposit, v, [32]byte{}); got != domainHex(t, tt.deposit) {
				t.Errorf("DEPOSIT domain = %x, want %s", got, tt.deposit)
			}
			if got := ComputeDomain(DomainApplicationBuilder, v, [32]byte{}); got != domainHex(t, tt.builder) {
				t.Errorf("APPLICATION_BUILDER domain = %x, want %s", got, tt.builder)
			}
		})
	}
}

func TestComputeDomainLayout(t *testing.T) {
	v := Version{0x00, 0x00, 0x00, 0xfd}
	gvr := [32]byte{9, 8, 7}
	got := ComputeDomain(DomainSyncCommittee, v, gvr)
	fdr := ComputeForkDataRoot(v, gvr)
	if [4]byte(got[:4]) != DomainSyncCommittee {
		t.Errorf("domain prefix = %x, want %x", got[:4], DomainSyncCommittee)
	}
	if [28]byte(got[4:]) != [28]byte(fdr[:28]) {
		t.Errorf("domain suffix = %x, want fork data root[:28] = %x", got[4:], fdr[:28])
	}
}

func TestDomainTypeValues(t *testing.T) {
	tests := []struct {
		name string
		got  DomainType
		want string
	}{
		{"BEACON_PROPOSER", DomainBeaconProposer, "00000000"},
		{"BEACON_ATTESTER", DomainBeaconAttester, "01000000"},
		{"DEPOSIT", DomainDeposit, "03000000"},
		{"VOLUNTARY_EXIT", DomainVoluntaryExit, "04000000"},
		{"SELECTION_PROOF", DomainSelectionProof, "05000000"},
		{"AGGREGATE_AND_PROOF", DomainAggregateAndProof, "06000000"},
		{"SYNC_COMMITTEE", DomainSyncCommittee, "07000000"},
		{"SYNC_COMMITTEE_SELECTION_PROOF", DomainSyncCommitteeSelectionProof, "08000000"},
		{"CONTRIBUTION_AND_PROOF", DomainContributionAndProof, "09000000"},
		{"APPLICATION_BUILDER", DomainApplicationBuilder, "00000001"},
	}
	for _, tt := range tests {
		if got := hex.EncodeToString(tt.got[:]); got != tt.want {
			t.Errorf("DOMAIN_%s = %s, want %s", tt.name, got, tt.want)
		}
	}
}

func TestForkVersionAt(t *testing.T) {
	f := Fork{PreviousVersion: Version{0, 0, 0, 0xfd}, CurrentVersion: Version{1, 0, 0, 0xfd}, Epoch: 10}
	tests := []struct {
		epoch uint64
		want  Version
	}{
		{0, f.PreviousVersion},
		{9, f.PreviousVersion},
		{10, f.CurrentVersion},
		{^uint64(0), f.CurrentVersion},
	}
	for _, tt := range tests {
		if got := f.VersionAt(tt.epoch); got != tt.want {
			t.Errorf("VersionAt(%d) = %x, want %x", tt.epoch, got, tt.want)
		}
	}
	gvr := [32]byte{4}
	if got, want := GetDomain(f, 9, DomainBeaconAttester, gvr), ComputeDomain(DomainBeaconAttester, f.PreviousVersion, gvr); got != want {
		t.Errorf("GetDomain before the fork = %x, want %x", got, want)
	}
	if got, want := GetDomain(f, 10, DomainBeaconAttester, gvr), ComputeDomain(DomainBeaconAttester, f.CurrentVersion, gvr); got != want {
		t.Errorf("GetDomain at the fork = %x, want %x", got, want)
	}
}

func TestComputeSigningRoot(t *testing.T) {
	obj := [32]byte{0xaa}
	d := Domain{0xbb}
	if got, want := ComputeSigningRoot(obj, d), sha256.Sum256(append(obj[:], d[:]...)); got != want {
		t.Fatalf("ComputeSigningRoot = %x, want sha256(object_root ‖ domain) = %x", got, want)
	}
}

func TestComputeEpochAtSlot(t *testing.T) {
	tests := []struct{ slot, spe, want uint64 }{
		{0, 6, 0}, {5, 6, 0}, {6, 6, 1}, {1234, 8, 154}, {1234, 128, 9}, {^uint64(0), 1, ^uint64(0)},
	}
	for _, tt := range tests {
		if got := ComputeEpochAtSlot(tt.slot, tt.spe); got != tt.want {
			t.Errorf("ComputeEpochAtSlot(%d, %d) = %d, want %d", tt.slot, tt.spe, got, tt.want)
		}
	}
}
