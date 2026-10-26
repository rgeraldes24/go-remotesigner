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
	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
	"github.com/rgeraldes24/go-remotesigner/internal/server/tlsconf"
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

// The metrics listener and the signing policy flags: Web3Signer's metrics
// names and defaults, exits off, deterministic selection proofs.
func TestSigningAndMetricsFlags(t *testing.T) {
	cfg, code, stderr := capture(t, "consensus", "--network=e2e")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if cfg.Metrics.Enabled || cfg.Metrics.Host != "127.0.0.1" || cfg.Metrics.Port != 9001 ||
		!slices.Equal(cfg.Metrics.HostAllowlist, []string{"localhost", "127.0.0.1"}) {
		t.Fatalf("metrics defaults %+v", cfg.Metrics)
	}
	c := cfg.Consensus
	if c.VoluntaryExitsEnabled || c.FeeRecipientFile != "" || c.ClockSkewSlots != 1 || c.SelectionProofMode != mldsa87.Deterministic {
		t.Fatalf("signing defaults %+v", c)
	}
	if cfg.Version == "" {
		t.Fatal("no release version")
	}

	cfg, code, stderr = capture(t, "--metrics-enabled", "--metrics-host=0.0.0.0", "--metrics-port=9101",
		"--metrics-host-allowlist=prometheus,all-the-rest", "consensus", "--network=e2e",
		"--voluntary-exit-signing-enabled", "--registration-fee-recipient-file=/pins.yaml",
		"--signing-clock-skew-slots=2", "--selection-proof-signing=hedged")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	want := config.Metrics{Enabled: true, Host: "0.0.0.0", Port: 9101, HostAllowlist: []string{"prometheus", "all-the-rest"}}
	if cfg.Metrics.Enabled != want.Enabled || cfg.Metrics.Addr() != "0.0.0.0:9101" || !slices.Equal(cfg.Metrics.HostAllowlist, want.HostAllowlist) {
		t.Fatalf("metrics %+v", cfg.Metrics)
	}
	c = cfg.Consensus
	if !c.VoluntaryExitsEnabled || c.FeeRecipientFile != "/pins.yaml" || c.ClockSkewSlots != 2 || c.SelectionProofMode != mldsa87.Hedged {
		t.Fatalf("signing flags %+v", c)
	}

	for args, want := range map[string]string{
		"--selection-proof-signing=random": "selection-proof-signing",
		"--metrics-port=70000":             "not a TCP port",
		"--metrics-host-allowlist=none,a":  "cannot be combined",
	} {
		global := strings.HasPrefix(args, "--metrics")
		argv := []string{"consensus", "--network=e2e", args}
		if global {
			argv = []string{args, "consensus", "--network=e2e"}
		}
		if _, code, stderr := capture(t, argv...); code != exitUsage || !strings.Contains(stderr, want) {
			t.Errorf("%s: exit %d %q, want a usage error mentioning %q", args, code, stderr, want)
		}
	}
}

// The TLS, metrics-token and process-hygiene flags: TLS off, core dumps
// disabled and memory unlocked by default.
func TestTLSAndHygieneFlags(t *testing.T) {
	cfg, code, stderr := capture(t, "consensus", "--network=e2e")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if cfg.TLS != (tlsconf.Config{}) || cfg.Metrics.AuthTokenFile != "" || !cfg.Hygiene.DisableCoreDumps || cfg.Hygiene.MlockAll {
		t.Fatalf("defaults: TLS %+v, metrics token %q, hygiene %+v", cfg.TLS, cfg.Metrics.AuthTokenFile, cfg.Hygiene)
	}
	cfg, code, stderr = capture(t, "--http-auth-mode=token+mtls", "--tls-cert-file=/tls/c.pem", "--tls-key-file=/tls/k.pem",
		"--tls-known-clients-file=/tls/known", "--tls-client-ca-file=/tls/ca.pem", "--tls-generate-self-signed",
		"--metrics-auth-token-file=/m", "--disable-core-dumps=false", "--mlock-all", "consensus", "--network=e2e")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	want := tlsconf.Config{CertFile: "/tls/c.pem", KeyFile: "/tls/k.pem", KnownClientsFile: "/tls/known", ClientCAFile: "/tls/ca.pem", GenerateSelfSigned: true}
	if cfg.TLS != want || cfg.HTTP.AuthMode != auth.ModeTokenMTLS || cfg.Metrics.AuthTokenFile != "/m" ||
		cfg.Hygiene.DisableCoreDumps || !cfg.Hygiene.MlockAll {
		t.Fatalf("flags: TLS %+v, mode %s, metrics token %q, hygiene %+v", cfg.TLS, cfg.HTTP.AuthMode, cfg.Metrics.AuthTokenFile, cfg.Hygiene)
	}
	cfg, code, stderr = capture(t, "--http-auth-mode=mtls", "--tls-keystore-file=/k.p12", "--tls-keystore-password-file=/pw",
		"--tls-client-ca-file=/ca.pem", "consensus", "--network=e2e")
	if code != exitOK || cfg.TLS.KeystoreFile != "/k.p12" || cfg.TLS.KeystorePasswordFile != "/pw" || cfg.HTTP.AuthMode != auth.ModeMTLS {
		t.Fatalf("PKCS#12: exit %d %s %+v", code, stderr, cfg)
	}
}

// Pruning keeps 512 epochs and runs every 12 h by default; both values must be positive.
func TestPruningFlags(t *testing.T) {
	cfg, code, stderr := capture(t, "consensus", "--network=e2e")
	if code != exitOK || cfg.Consensus.Pruning != (config.Pruning{EpochsToKeep: 512, Interval: 12 * time.Hour}) {
		t.Fatalf("defaults: exit %d %s, pruning %+v", code, stderr, cfg.Consensus.Pruning)
	}
	cfg, code, stderr = capture(t, "consensus", "--network=e2e", "--slashing-protection-pruning-epochs-to-keep=64",
		"--slashing-protection-pruning-interval=30m")
	if code != exitOK || cfg.Consensus.Pruning != (config.Pruning{EpochsToKeep: 64, Interval: 30 * time.Minute}) {
		t.Fatalf("flags: exit %d %s, pruning %+v", code, stderr, cfg.Consensus.Pruning)
	}
	for arg, want := range map[string]string{
		"--slashing-protection-pruning-epochs-to-keep=0": "--slashing-protection-pruning-epochs-to-keep must be at least 1",
		"--slashing-protection-pruning-interval=0s":      "--slashing-protection-pruning-interval must be positive",
		"--slashing-protection-pruning-interval=-1h":     "--slashing-protection-pruning-interval must be positive",
		// Web3Signer's number of hours is not a duration (X56).
		"--slashing-protection-pruning-interval=12": "invalid value \"12\" for flag -slashing-protection-pruning-interval",
	} {
		if _, code, stderr := capture(t, "consensus", "--network=e2e", arg); code != exitUsage || !strings.Contains(stderr, want) {
			t.Errorf("%s: exit %d %q, want a usage error %q", arg, code, stderr, want)
		}
	}
}

func TestHostAllowlistWords(t *testing.T) {
	for args, want := range map[string][]string{
		"--http-host-allowlist=all":  {"*"},
		"--http-host-allowlist=none": {},
		"--http-host-allowlist=a, b": {"a", "b"},
		"--http-host-allowlist=ALL":  {"*"},
		"--http-host-allowlist=None": {},
	} {
		cfg, code, stderr := capture(t, args, "consensus", "--network=e2e")
		if code != exitOK || !slices.Equal(cfg.HTTP.HostAllowlist, want) {
			t.Errorf("%s: exit %d %s, allowlist %q, want %q", args, code, stderr, cfg.HTTP.HostAllowlist, want)
		}
	}
	// As in Web3Signer, "none" and "*" stand alone.
	for _, args := range []string{"--http-host-allowlist=none,signer", "--http-host-allowlist=signer,*"} {
		if _, code, stderr := capture(t, args, "consensus", "--network=e2e"); code != exitUsage || !strings.Contains(stderr, "cannot be combined") {
			t.Errorf("%s: exit %d %s, want a usage error", args, code, stderr)
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

// The one-letter alias -l of --logging is a command-line shorthand only:
// REMOTESIGNER_L sets nothing, and an l key in the config file is an
// unknown option.
func TestShortAliasHasNoOtherSource(t *testing.T) {
	cfg, code, stderr := capture(t, "-l", "DEBUG", "consensus", "--network=e2e")
	if code != exitOK || cfg.Logging.Level != "DEBUG" {
		t.Fatalf("-l: exit %d %s", code, stderr)
	}
	t.Setenv("REMOTESIGNER_L", "TRACE")
	if cfg, code, stderr = capture(t, "consensus", "--network=e2e"); code != exitOK || cfg.Logging.Level != "INFO" {
		t.Fatalf("REMOTESIGNER_L: exit %d %s, level %v", code, stderr, cfg)
	}
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte("l: DEBUG\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, code, stderr := capture(t, "--config-file="+file, "consensus", "--network=e2e"); code != exitUsage ||
		!strings.Contains(stderr, "unknown option(s): l") {
		t.Fatalf("an l key: exit %d %s", code, stderr)
	}
	var stdout, errOut bytes.Buffer
	if code := runWith([]string{binaryName, "--help"}, &stdout, &errOut, noRun); code != exitOK ||
		!strings.Contains(stdout.String(), "$REMOTESIGNER_LOGGING]") || strings.Contains(stdout.String(), "REMOTESIGNER_L]") {
		t.Fatalf("--help: exit %d\n%s", code, stdout.String())
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
		{name: "unknown auth mode", args: []string{"--http-auth-mode=basic", "consensus", "--network=e2e"}, want: "want token, mtls, token+mtls or none"},
		{name: "mtls without TLS", args: []string{"--http-auth-mode=mtls", "consensus", "--network=e2e"}, want: "need TLS"},
		{name: "token+mtls without client trust", args: []string{"--http-auth-mode=token+mtls", "--tls-generate-self-signed", "consensus", "--network=e2e"},
			want: "need --tls-known-clients-file or --tls-client-ca-file"},
		{name: "cert without key", args: []string{"--tls-cert-file=/c", "consensus", "--network=e2e"}, want: "together with --tls-key-file"},
		{name: "keystore without password", args: []string{"--tls-keystore-file=/k.p12", "consensus", "--network=e2e"},
			want: "--tls-keystore-file must be specified together with --tls-keystore-password-file"},
		{name: "PEM and PKCS#12", args: []string{"--tls-cert-file=/c", "--tls-key-file=/k", "--tls-keystore-file=/p", "--tls-keystore-password-file=/pw", "consensus", "--network=e2e"},
			want: "not both"},
		{name: "known clients in token mode", args: []string{"--tls-generate-self-signed", "--tls-known-clients-file=/kc", "consensus", "--network=e2e"},
			want: "only with --http-auth-mode=mtls or token+mtls"},
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

// boolFlagCase is one boolean flag of one command: the arguments that lead
// to the command, and the flag.
type boolFlagCase struct {
	path []string
	flag string
}

// boolFlagCases walks the command tree and returns every boolean flag of
// every command, with the arguments that reach it.
func boolFlagCases(t *testing.T, dataPath string) []boolFlagCase {
	t.Helper()
	var out []boolFlagCase
	var walk func(path []string, fs []cli.Flag, cmds []*cli.Command)
	walk = func(path []string, fs []cli.Flag, cmds []*cli.Command) {
		for _, f := range fs {
			if _, ok := f.(*cli.BoolFlag); ok {
				out = append(out, boolFlagCase{path: slices.Clone(path), flag: f.Names()[0]})
			}
		}
		for _, c := range cmds {
			next := append(slices.Clone(path), c.Name)
			if c.Name == flags.ConsensusCommand {
				next = append(next, "--network=e2e")
			}
			walk(next, c.Flags, c.Subcommands)
		}
	}
	app := newApp(&bytes.Buffer{}, &bytes.Buffer{}, noRun)
	walk([]string{"--data-path=" + dataPath}, app.Flags, app.Commands)
	if len(out) < 10 {
		t.Fatalf("found %d boolean flags; the walk is broken", len(out))
	}
	return out
}

// A boolean takes its value after "=". "--flag false" leaves "false" as an
// argument, which every command refuses as a usage error, so a command line
// written for Web3Signer, whose --slashing-protection-enabled and
// --key-manager-api-enabled take their value as the next argument, can never
// leave a flag on that it meant to turn off (docs/reference/flags.md,
// DEVIATIONS.md X75).
func TestBooleanFlagValues(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range boolFlagCases(t, dir) {
		name := strings.Join(append(slices.Clone(tc.path[1:]), "--"+tc.flag), " ")
		t.Run(name, func(t *testing.T) {
			code, _, stderr := runCLI(t, append(slices.Clone(tc.path), "--"+tc.flag, "false")...)
			if code != exitUsage || !strings.Contains(stderr, `"false"`) {
				t.Errorf("--%s false: exit %d, stderr %q; want exit 2 naming the stray argument", tc.flag, code, stderr)
			}
		})
	}
	// The global flags precede the command, so there "false" is read as the
	// command's name.
	if code, _, stderr := runCLI(t, "--strict-file-permissions", "false", "consensus", "--network=e2e"); code != exitUsage ||
		!strings.Contains(stderr, `unknown command "false"`) {
		t.Errorf("global --strict-file-permissions false: exit %d, stderr %q", code, stderr)
	}
	for _, args := range [][]string{
		{"consensus", "--network=e2e", "--slashing-protection-enabled=false"},
		{"--strict-file-permissions=false", "consensus", "--network=e2e"},
	} {
		cfg, code, stderr := capture(t, args...)
		if code != exitOK {
			t.Fatalf("%q: exit %d: %s", args, code, stderr)
		}
		if cfg.Consensus.SlashingProtectionEnabled == slices.Contains(args, "--slashing-protection-enabled=false") ||
			cfg.StrictFilePermissions == slices.Contains(args, "--strict-file-permissions=false") {
			t.Errorf("%q: protection %v, strict permissions %v", args, cfg.Consensus.SlashingProtectionEnabled,
				cfg.StrictFilePermissions)
		}
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

// --enable-key-manager-api is Web3Signer's alias of --key-manager-api-enabled,
// with the environment variable and config-file key of its name.
func TestKeyManagerAPIAlias(t *testing.T) {
	cfg, code, stderr := capture(t, "consensus", "--network=e2e", "--enable-key-manager-api")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !cfg.Consensus.KeyManagerAPIEnabled {
		t.Fatal("--enable-key-manager-api did not enable the keymanager API")
	}
	t.Setenv("REMOTESIGNER_CONSENSUS_ENABLE_KEY_MANAGER_API", "true")
	if cfg, code, stderr = capture(t, "consensus", "--network=e2e"); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !cfg.Consensus.KeyManagerAPIEnabled {
		t.Fatal("REMOTESIGNER_CONSENSUS_ENABLE_KEY_MANAGER_API did not enable the keymanager API")
	}
}
