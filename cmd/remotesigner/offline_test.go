// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// cli runs the CLI with no signer and returns the exit code and output.
func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runWith(append([]string{binaryName}, args...), &stdout, &stderr, noRun)
	return code, stdout.String(), stderr.String()
}

func TestRandaoAndStoreFlags(t *testing.T) {
	cfg, code, stderr := capture(t, "consensus", "--network=e2e")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	want := config.Randao{MaxLayers: 1 << 20, ReorgWindow: 1024, NewLayerBurst: 3, NewLayerRefillEpochs: 1}
	if cfg.Consensus.Randao != want || cfg.Consensus.SlashingProtectionDBPath != "" || cfg.Consensus.SlashingProtectionDBMigrate {
		t.Fatalf("defaults %+v", cfg.Consensus)
	}

	cfg, code, stderr = capture(t, "consensus", "--network=e2e", "--randao-max-layers=4096", "--randao-reorg-window=16",
		"--randao-full-scan-min-interval=30s", "--randao-new-layer-burst=8", "--randao-new-layer-refill-epochs=0",
		"--randao-protection-required", "--slashing-protection-db-url=bolt:///var/lib/signer/sp.db",
		"--slashing-protection-db-migrate")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	want = config.Randao{MaxLayers: 4096, ReorgWindow: 16, FullScanMinInterval: 30 * time.Second, NewLayerBurst: 8,
		ProtectionRequired: true}
	if cfg.Consensus.Randao != want || !cfg.Consensus.SlashingProtectionDBMigrate ||
		cfg.SlashingProtectionDB() != "/var/lib/signer/sp.db" {
		t.Fatalf("flags %+v, store %s", cfg.Consensus, cfg.SlashingProtectionDB())
	}

	for args, want := range map[string]string{
		"--randao-max-layers=0":                      "at least 1",
		"--randao-new-layer-burst=0":                 "turns it off",
		"--randao-new-layer-refill-epochs=99999999":  "at most",
		"--randao-full-scan-min-interval=-1s":        "negative",
		"--slashing-protection-db-url=postgres://db": "Postgres",
		"--slashing-protection-db-url=bolt://host/x": "no host",
		"--slashing-protection-db-url=bolt:///":      "absolute file path",
		"--slashing-protection-db-url=file:///x.db":  "unsupported scheme",
	} {
		if _, code, stderr := capture(t, "consensus", "--network=e2e", args); code != exitUsage || !strings.Contains(stderr, want) {
			t.Errorf("%s: exit %d %q, want a usage error mentioning %q", args, code, stderr, want)
		}
	}
	// A bucket that is off needs no burst.
	if _, code, stderr := capture(t, "consensus", "--network=e2e", "--randao-new-layer-burst=0",
		"--randao-new-layer-refill-epochs=0"); code != exitOK {
		t.Fatalf("bucket off with burst 0: exit %d %s", code, stderr)
	}
}

// storeWithFrontier creates a closed store at path with interop-like key 0
// registered and given a RANDAO frontier, and returns the key's id.
func storeWithFrontier(t *testing.T, path string) slashing.KeyID {
	t.Helper()
	s, err := boltstore.Open(path, boltstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pk := slashingtest.Key(0)
	if err := s.RegisterValidators(ctx, [][]byte{pk}); err != nil {
		t.Fatal(err)
	}
	id := slashing.KeyIDOf(pk)
	if _, err := s.CompareAndSwapRandaoState(ctx, id, nil, slashing.RandaoState{Index: 9, LastSlot: 3}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return id
}

func frontierOf(t *testing.T, path string, id slashing.KeyID) bool {
	t.Helper()
	s, err := boltstore.Open(path, boltstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	_, ok, err := s.RandaoState(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestRandaoStateReset(t *testing.T) {
	data := t.TempDir()
	path := filepath.Join(data, config.SlashingProtectionFile)
	id := storeWithFrontier(t, path)
	alias := "0x" + hex.EncodeToString(id[:])
	canonical := "0x" + hex.EncodeToString(slashingtest.Key(0))

	// While the signer holds the store, the command points to the admin API.
	held, err := boltstore.Open(path, boltstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, "--data-path="+data, "consensus", "randao-state", "reset", "--key="+alias)
	if code != exitStartup || !strings.Contains(stderr, "stop the signer") || !strings.Contains(stderr, "DELETE /api/v1/consensus/randao_state") {
		t.Fatalf("locked store: exit %d %q", code, stderr)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runCLI(t, "--data-path="+data, "consensus", "randao-state", "reset", "--key="+canonical)
	if code != exitOK || !strings.Contains(stdout, "next reveal is a first use") {
		t.Fatalf("reset: exit %d %q %q", code, stdout, stderr)
	}
	if frontierOf(t, path, id) {
		t.Fatal("frontier survived the reset")
	}

	// The store may also be named by URL, on the subcommand or on consensus.
	other := filepath.Join(t.TempDir(), "other.db")
	id2 := storeWithFrontier(t, other)
	if code, _, stderr := runCLI(t, "consensus", "--slashing-protection-db-url=bolt://"+other, "randao-state", "reset",
		"--key="+alias); code != exitOK {
		t.Fatalf("reset by URL on consensus: exit %d %s", code, stderr)
	}
	if frontierOf(t, other, id2) {
		t.Fatal("frontier survived the reset by URL")
	}

	unknown := sha256.Sum256([]byte("nobody"))
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--data-path=" + data, "consensus", "randao-state", "reset", "--key=0x" + hex.EncodeToString(unknown[:])}, exitStartup, "not registered"},
		{[]string{"--data-path=" + data, "consensus", "randao-state", "reset", "--key=0x12"}, exitUsage, "--key"},
		{[]string{"--data-path=" + data, "consensus", "randao-state", "reset"}, exitUsage, "key"},
		{[]string{"--data-path=" + t.TempDir(), "consensus", "randao-state", "reset", "--key=" + alias}, exitUsage, "no slashing-protection store"},
		{[]string{"consensus", "randao-state", "reset", "--key=" + alias}, exitUsage, "--data-path"},
		{[]string{"consensus", "randao-state", "--key=" + alias}, exitUsage, "key"},
		{[]string{"consensus", "randao-state"}, exitUsage, "reset"},
	} {
		code, _, stderr := runCLI(t, tc.args...)
		if code != tc.code || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: exit %d %q, want %d mentioning %q", tc.args, code, stderr, tc.code, tc.want)
		}
	}
}

func TestMigrateCommand(t *testing.T) {
	data := t.TempDir()
	path := filepath.Join(data, config.SlashingProtectionFile)
	storeWithFrontier(t, path)

	code, stdout, stderr := runCLI(t, "--data-path="+data, "consensus", "migrate")
	if code != exitOK || !strings.Contains(stdout, "already at schema version 1") {
		t.Fatalf("current store: exit %d %q %q", code, stdout, stderr)
	}
	code, stdout, _ = runCLI(t, "consensus", "migrate", "--slashing-protection-db-url=bolt://"+path)
	if code != exitOK || !strings.Contains(stdout, path) {
		t.Fatalf("by URL: exit %d %q", code, stdout)
	}

	held, err := boltstore.Open(path, boltstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	code, _, stderr = runCLI(t, "--data-path="+data, "consensus", "migrate")
	_ = held.Close()
	if code != exitStartup || !strings.Contains(stderr, "stop the signer first, then run consensus migrate again") {
		t.Fatalf("locked store: exit %d %q", code, stderr)
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--data-path=" + t.TempDir(), "consensus", "migrate"}, "no slashing-protection store"},
		{[]string{"consensus", "migrate"}, "--data-path"},
		{[]string{"--data-path=" + data, "consensus", "migrate", "extra"}, "unexpected argument"},
		{[]string{"consensus", "migrate", "--slashing-protection-db-url=postgres://x"}, "Postgres"},
	} {
		if code, _, stderr := runCLI(t, tc.args...); code != exitUsage || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: exit %d %q, want a usage error mentioning %q", tc.args, code, stderr, tc.want)
		}
	}
}
