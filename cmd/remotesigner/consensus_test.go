// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
)

// noRun fails the test if the signer would start.
func noRun(context.Context, *config.Config, *logrus.Logger, <-chan struct{}) error {
	return errors.New("the signer must not start in this test")
}

// capture runs the CLI and returns the configuration it would run with.
func capture(t *testing.T, args ...string) (*config.Config, int, string) {
	t.Helper()
	var got *config.Config
	run := func(_ context.Context, cfg *config.Config, _ *logrus.Logger, _ <-chan struct{}) error {
		got = cfg
		return nil
	}
	var stdout, stderr bytes.Buffer
	code := runWith(append([]string{binaryName}, args...), &stdout, &stderr, run)
	return got, code, stderr.String()
}

// The flags the qrysm e2e passes work verbatim.
func TestE2EInvocation(t *testing.T) {
	cfg, code, stderr := capture(t,
		"--key-store-path=/tmp/web3signerkeystore",
		"--data-path=/tmp/web3signerdata",
		"--http-listen-port=9000",
		"--logging=ALL",
		"consensus",
		"--network=/tmp/config.yaml",
		"--network-genesis-time=1760000000",
		"--slashing-protection-enabled=true",
		"--key-manager-api-enabled=true",
	)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if cfg.KeyConfigPath != "/tmp/web3signerkeystore" || cfg.DataPath != "/tmp/web3signerdata" ||
		cfg.HTTP.ListenPort != 9000 || cfg.Logging.Level != "ALL" || cfg.Consensus.Network.Network != "/tmp/config.yaml" ||
		*cfg.Consensus.Network.GenesisTime != 1760000000 || !cfg.Consensus.SlashingProtectionEnabled ||
		!cfg.Consensus.KeyManagerAPIEnabled {
		t.Fatalf("config %+v", cfg)
	}
}

func TestDefaults(t *testing.T) {
	cfg, code, stderr := capture(t, "consensus", "--network=e2e")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	want := config.HTTP{
		ListenHost: "127.0.0.1", ListenPort: 9000, HostAllowlist: []string{"localhost", "127.0.0.1", "::1"},
		AuthMode: auth.ModeToken, MaxConnections: 1024, IdleTimeout: 120 * time.Second,
	}
	got := cfg.HTTP
	if got.ListenHost != want.ListenHost || got.ListenPort != want.ListenPort || !slices.Equal(got.HostAllowlist, want.HostAllowlist) ||
		got.AuthMode != want.AuthMode || got.MaxConnections != want.MaxConnections || got.IdleTimeout != want.IdleTimeout || got.AccessLogs {
		t.Fatalf("HTTP defaults %+v", got)
	}
	if cfg.Logging.Level != "INFO" || cfg.Logging.Format != "text" || !cfg.Consensus.SlashingProtectionEnabled ||
		cfg.Consensus.KeyManagerAPIEnabled || cfg.Consensus.Network.GenesisTime != nil || cfg.Consensus.Network.GenesisValidatorsRoot != nil {
		t.Fatalf("defaults %+v", cfg)
	}
}

func TestHostAllowlistWords(t *testing.T) {
	for args, want := range map[string][]string{
		"--http-host-allowlist=all":        {"*"},
		"--http-host-allowlist=none":       {},
		"--http-host-allowlist=a, b":       {"a", "b"},
		"--http-host-allowlist=signer,ALL": {"signer", "*"},
	} {
		cfg, code, stderr := capture(t, args, "consensus", "--network=e2e")
		if code != exitOK || !slices.Equal(cfg.HTTP.HostAllowlist, want) {
			t.Errorf("%s: exit %d %s, allowlist %q, want %q", args, code, stderr, cfg.HTTP.HostAllowlist, want)
		}
	}
}

// Command line beats environment beats config file beats default.
func TestSourcePrecedence(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.yaml")
	content := `
http-listen-port: 9100
logging: DEBUG
http-host-allowlist: [signer.internal]
consensus:
  network: minimal
  network-genesis-time: 5
`
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, code, stderr := capture(t, "--config-file="+file, "consensus")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if cfg.HTTP.ListenPort != 9100 || cfg.Logging.Level != "DEBUG" || cfg.Consensus.Network.Network != "minimal" ||
		*cfg.Consensus.Network.GenesisTime != 5 || !slices.Equal(cfg.HTTP.HostAllowlist, []string{"signer.internal"}) {
		t.Fatalf("from YAML: %+v", cfg)
	}

	t.Setenv("REMOTESIGNER_HTTP_LISTEN_PORT", "9200")
	t.Setenv("REMOTESIGNER_CONSENSUS_NETWORK", "interop")
	t.Setenv("REMOTESIGNER_KEY_STORE_PATH", "/keys-from-alias")
	cfg, code, stderr = capture(t, "--config-file="+file, "--logging=WARN", "consensus")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if cfg.HTTP.ListenPort != 9200 || cfg.Consensus.Network.Network != "interop" || cfg.Logging.Level != "WARN" ||
		cfg.KeyConfigPath != "/keys-from-alias" {
		t.Fatalf("env and CLI over YAML: %+v", cfg)
	}

	cfg, code, _ = capture(t, "--config-file="+file, "--http-listen-port=9300", "consensus", "--network=e2e")
	if code != exitOK || cfg.HTTP.ListenPort != 9300 || cfg.Consensus.Network.Network != "e2e" {
		t.Fatalf("CLI over env: %d %+v", code, cfg)
	}
}

func TestUsageErrors(t *testing.T) {
	dir := t.TempDir()
	badYAML := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(badYAML, []byte("http-listen-prot: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		env  map[string]string
		args []string
		want string
	}{
		{name: "missing --network", args: []string{"consensus"}, want: "--network is required"},
		{name: "unknown consensus flag", args: []string{"consensus", "--network=e2e", "--nope"}, want: "nope"},
		{name: "positional argument", args: []string{"consensus", "--network=e2e", "extra"}, want: `unexpected argument "extra"`},
		{name: "unknown auth mode", args: []string{"--http-auth-mode=basic", "consensus", "--network=e2e"}, want: "want token or none"},
		{name: "mtls without TLS", args: []string{"--http-auth-mode=mtls", "consensus", "--network=e2e"}, want: "needs TLS"},
		{name: "bad log level", args: []string{"--logging=LOUD", "consensus", "--network=e2e"}, want: "level"},
		{name: "bad log format", args: []string{"--logging-format=xml", "consensus", "--network=e2e"}, want: "format"},
		{name: "port out of range", args: []string{"--http-listen-port=70000", "consensus", "--network=e2e"}, want: "not a TCP port"},
		{name: "zero max connections", args: []string{"--http-max-connections=0", "consensus", "--network=e2e"}, want: "at least 1"},
		{name: "zero idle timeout", args: []string{"--idle-connection-timeout-seconds=0", "consensus", "--network=e2e"}, want: "at least 1"},
		{name: "bad GVR", args: []string{"consensus", "--network=e2e", "--network-genesis-validators-root=0x12"}, want: "64 hex"},
		{name: "bad genesis time", args: []string{"consensus", "--network=e2e", "--network-genesis-time=soon"}, want: "network-genesis-time"},
		{name: "bad genesis time from env", env: map[string]string{"REMOTESIGNER_CONSENSUS_NETWORK_GENESIS_TIME": "soon"},
			args: []string{"consensus", "--network=e2e"}, want: "soon"},
		{name: "unknown config-file key", args: []string{"--config-file=" + badYAML, "consensus", "--network=e2e"}, want: "unknown option(s): http-listen-prot"},
		{name: "missing config file", args: []string{"--config-file=" + filepath.Join(dir, "none.yaml"), "consensus"}, want: "config file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			_, code, stderr := capture(t, tt.args...)
			if code != exitUsage || !strings.Contains(stderr, tt.want) {
				t.Fatalf("exit %d, stderr %q; want exit 2 mentioning %q", code, stderr, tt.want)
			}
		})
	}
}

func TestStartupFailureExitsOne(t *testing.T) {
	var stdout, stderr bytes.Buffer
	failing := func(context.Context, *config.Config, *logrus.Logger, <-chan struct{}) error {
		return errors.New("refusing to start: example")
	}
	code := runWith([]string{binaryName, "consensus", "--network=e2e"}, &stdout, &stderr, failing)
	if code != exitStartup || !strings.Contains(stderr.String(), "refusing to start: example") {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
}
