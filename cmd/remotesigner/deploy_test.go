// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
)

// deployConfig holds the example configuration files.
const deployConfig = "../../deploy/config"

// loadExample runs the CLI on an example config file, as the systemd unit
// does, with extra consensus flags on the command line, and checks that the
// resulting configuration passes every startup fail-safe. The example's
// network file does not exist here, so --network=end-to-end replaces it (the
// command line wins over the file); its genesis time and validators root
// still come from the file.
func loadExample(t *testing.T, file string, consensus ...string) *config.Config {
	t.Helper()
	args := append([]string{"--config-file=" + file, "consensus", "--network=end-to-end"}, consensus...)
	cfg, code, stderr := capture(t, args...)
	if code != exitOK {
		t.Fatalf("%s: exit %d: %s", file, code, stderr)
	}
	n, err := network.Load(cfg.Consensus.Network)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.CheckFailSafes(cfg, n); err != nil {
		t.Fatalf("%s: refused at startup: %v", file, err)
	}
	return cfg
}

// The single-host example loads as the systemd unit runs it: a TLS listener
// on every interface with a generated certificate for the allowlist names,
// the bbolt store under the state directory, metrics on loopback, and the
// chain's genesis values, which a non-loopback listener requires.
func TestSingleHostExampleConfig(t *testing.T) {
	cfg := loadExample(t, filepath.Join(deployConfig, "single-host.yaml"))
	if cfg.DataPath != "/var/lib/remotesigner" || cfg.KeyConfigPath != "/var/lib/remotesigner/keys" {
		t.Errorf("data path %q, key-config path %q", cfg.DataPath, cfg.KeyConfigPath)
	}
	if cfg.HTTP.ListenHost != "0.0.0.0" || !cfg.TLS.GenerateSelfSigned || cfg.TLS.HasCertificate() ||
		!slices.Equal(cfg.HTTP.HostAllowlist, []string{"signer.internal", "10.0.0.5"}) {
		t.Errorf("listener %q, self-signed %v, allowlist %q", cfg.HTTP.ListenHost, cfg.TLS.GenerateSelfSigned,
			cfg.HTTP.HostAllowlist)
	}
	if got := cfg.Consensus.SlashingProtectionDBPath; got != "/var/lib/remotesigner/slashing-protection.db" {
		t.Errorf("store %q", got)
	}
	if !cfg.Metrics.Enabled || !config.IsLoopbackHost(cfg.Metrics.Host) {
		t.Errorf("metrics %+v, want enabled on loopback", cfg.Metrics)
	}
	if cfg.Consensus.Network.GenesisTime == nil || cfg.Consensus.Network.GenesisValidatorsRoot == nil {
		t.Error("the genesis time or validators root did not come from the file")
	}
}

// flagNames returns every name and alias of fs.
func flagNames(fs []cli.Flag) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Names()...)
	}
	return out
}

// exampleKeys returns the keys of a config file, with the consensus
// section's keys as they apply (bare).
func exampleKeys(t *testing.T, data []byte) (global, consensus []string) {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for k, v := range doc {
		if k != "consensus" {
			global = append(global, k)
			continue
		}
		section, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("consensus: %T, want a mapping", v)
		}
		for ck := range section {
			consensus = append(consensus, ck)
		}
	}
	return global, consensus
}

// The Postgres HA example names only flags this binary has, and loads with its postgres:// URL and password file
// as every replica runs it: one shared name, a configured certificate, token files given explicitly so that every
// replica uses the same ones, and the shared database, which no start migrates.
func TestPostgresHAExampleConfig(t *testing.T) {
	file := filepath.Join(deployConfig, "postgres-ha.yaml")
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	global, consensus := exampleKeys(t, data)
	known := slices.Concat(flagNames(flags.Global()), flagNames(flags.Consensus()))
	for _, k := range slices.Concat(global, consensus) {
		if !slices.Contains(known, k) {
			t.Errorf("%s: %s names no flag", file, k)
		}
	}
	cfg := loadExample(t, file)
	checkHAConfig(t, cfg)
	want := config.Postgres{
		URL:                 "postgres://remotesigner@db.internal:5432/remotesigner?sslmode=verify-full",
		PasswordFile:        "/etc/remotesigner/db-password",
		HealthCheckTimeout:  3 * time.Second,
		HealthCheckInterval: 30 * time.Second,
	}
	if cfg.Consensus.Postgres != want {
		t.Errorf("Postgres store %+v, want %+v", cfg.Consensus.Postgres, want)
	}
}

func checkHAConfig(t *testing.T, cfg *config.Config) {
	t.Helper()
	if cfg.HTTP.ListenHost != "0.0.0.0" || !slices.Equal(cfg.HTTP.HostAllowlist, []string{"signer.internal"}) {
		t.Errorf("listener %q, allowlist %q", cfg.HTTP.ListenHost, cfg.HTTP.HostAllowlist)
	}
	if !cfg.TLS.HasCertificate() || cfg.TLS.GenerateSelfSigned {
		t.Errorf("TLS %+v, want the configured certificate and no generated one", cfg.TLS)
	}
	if cfg.SignTokenFile() != "/etc/remotesigner/auth-token" || cfg.AdminTokenFile() != "/etc/remotesigner/admin-token" {
		t.Errorf("token files %q and %q", cfg.SignTokenFile(), cfg.AdminTokenFile())
	}
	if cfg.Consensus.SlashingProtectionDBMigrate {
		t.Error("the example migrates the shared schema on every start")
	}
}
