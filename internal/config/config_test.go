// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/internal/network"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
	"github.com/rgeraldes24/go-remotesigner/internal/server/tlsconf"
)

func base() *Config {
	return &Config{
		DataPath: "/data",
		HTTP: HTTP{
			ListenHost:    "127.0.0.1",
			ListenPort:    9000,
			HostAllowlist: []string{"localhost", "127.0.0.1", "::1"},
			AuthMode:      auth.ModeToken,
		},
		Consensus: Consensus{SlashingProtectionEnabled: true},
	}
}

func fileNetwork(gvr, genesis bool) *network.Network {
	n := &network.Network{Name: "config.yaml"}
	if gvr {
		n.GVRSource = network.SourceFlag
	}
	if genesis {
		n.GenesisTimeSource = network.SourceFlag
	}
	return n
}

// The startup refusals on a non-loopback listener (DEVIATIONS.md X38), with
// and without TLS.
func TestCheckFailSafes(t *testing.T) {
	known := fileNetwork(true, true)
	remote := func(c *Config) {
		c.HTTP.ListenHost = "0.0.0.0"
		c.HTTP.HostAllowlist = []string{"signer.internal"}
		c.AllowPlaintextTokenAuth = true
	}
	remoteTLS := func(c *Config) {
		remote(c)
		c.AllowPlaintextTokenAuth = false
		c.TLS = tlsconf.Config{GenerateSelfSigned: true}
	}
	mtls := func(mode auth.Mode) func(*Config) {
		return func(c *Config) {
			remoteTLS(c)
			c.HTTP.AuthMode = mode
			c.TLS.KnownClientsFile = "/known-clients"
		}
	}
	tests := []struct {
		name   string
		mutate func(*Config)
		n      *network.Network
		want   []error
	}{
		{"loopback defaults", nil, known, nil},
		{"loopback, protection off", func(c *Config) { c.Consensus.SlashingProtectionEnabled = false }, known, nil},
		{"loopback, auth none", func(c *Config) { c.HTTP.AuthMode = auth.ModeNone }, known, nil},
		{"loopback, TOFU and unknown genesis", nil, fileNetwork(false, false), nil},
		{"localhost and ::1 are loopback", func(c *Config) { c.HTTP.ListenHost = "::1"; c.HTTP.AuthMode = auth.ModeNone }, known, nil},
		{"remote, everything acknowledged", remote, known, nil},
		{"remote, auth none", func(c *Config) { remote(c); c.HTTP.AuthMode = auth.ModeNone }, known, []error{ErrAuthNoneNonLoopback}},
		{"0.0.0.0 with auth none and defaults", func(c *Config) { c.HTTP.ListenHost = "0.0.0.0"; c.HTTP.AuthMode = auth.ModeNone }, known,
			[]error{ErrAuthNoneNonLoopback, ErrLoopbackAllowlist}},
		{"remote, plaintext token", func(c *Config) { remote(c); c.AllowPlaintextTokenAuth = false }, known, []error{ErrPlaintextToken}},
		{"remote, default allowlist", func(c *Config) { remote(c); c.HTTP.HostAllowlist = base().HTTP.HostAllowlist }, known, []error{ErrLoopbackAllowlist}},
		{"remote, allowlist with *", func(c *Config) { remote(c); c.HTTP.HostAllowlist = []string{"localhost", "*"} }, known, nil},
		{"remote, protection off (no override exists)", func(c *Config) { remote(c); c.Consensus.SlashingProtectionEnabled = false }, known,
			[]error{ErrProtectionDisabledNonLoopback}},
		{"remote, TOFU", remote, fileNetwork(false, true), []error{ErrGVRTOFUNonLoopback}},
		{"remote, TOFU acknowledged", func(c *Config) { remote(c); c.Consensus.AllowGVRTOFU = true }, fileNetwork(false, true), nil},
		{"remote, genesis unknown", remote, fileNetwork(true, false), []error{ErrUnknownGenesisNonLoopback}},
		{"remote, genesis unknown acknowledged", func(c *Config) { remote(c); c.Consensus.AllowUnknownGenesisTime = true }, fileNetwork(true, false), nil},
		{"named network never TOFU", remote, &network.Network{Named: true, GenesisTimeSource: network.SourceNamed}, nil},
		{"protection without data path", func(c *Config) { c.DataPath = ""; c.HTTP.AuthTokenFile = "/t" }, known, []error{ErrNoDataPath}},
		{"protection in Postgres without data path", func(c *Config) {
			c.DataPath, c.HTTP.AuthTokenFile, c.Consensus.Postgres.URL = "", "/t", "postgres://u@db/signer"
		}, known, nil},
		{"protection with a store URL and no data path", func(c *Config) {
			c.DataPath = ""
			c.HTTP.AuthTokenFile = "/t"
			c.Consensus.SlashingProtectionDBPath = "/var/lib/sp.db"
		}, known, nil},
		{"RANDAO protection required, protection off", func(c *Config) {
			c.Consensus.SlashingProtectionEnabled = false
			c.Consensus.Randao.ProtectionRequired = true
		}, known, []error{ErrRandaoProtectionRequired}},
		{"RANDAO protection required, protection on", func(c *Config) { c.Consensus.Randao.ProtectionRequired = true }, known, nil},
		{"token mode without token file", func(c *Config) { c.DataPath = ""; c.Consensus.SlashingProtectionEnabled = false }, known, []error{ErrNoSignToken}},
		{"keymanager without admin token", func(c *Config) {
			c.DataPath = ""
			c.HTTP.AuthTokenFile = "/t"
			c.Consensus.SlashingProtectionEnabled = false
			c.Consensus.KeyManagerAPIEnabled = true
			c.KeyConfigPath = "/keys"
		}, known, []error{ErrKeyManagerNoAdmin}},
		{"keymanager without key-config directory", func(c *Config) { c.Consensus.KeyManagerAPIEnabled = true }, known,
			[]error{ErrKeyManagerNoKeyConfig}},
		{"keymanager with admin token and key-config directory", func(c *Config) {
			c.Consensus.KeyManagerAPIEnabled = true
			c.KeyConfigPath = "/keys"
		}, known, nil},
		{"loopback metrics, protection off", func(c *Config) {
			c.Metrics = Metrics{Enabled: true, Host: "127.0.0.1", HostAllowlist: []string{"localhost"}}
			c.Consensus.SlashingProtectionEnabled = false
		}, known, nil},
		{"remote metrics, protection off (no override exists)", func(c *Config) {
			c.Metrics = Metrics{Enabled: true, Host: "0.0.0.0", HostAllowlist: []string{"prometheus"}}
			c.Consensus.SlashingProtectionEnabled = false
		}, known, []error{ErrProtectionDisabledNonLoopback}},
		{"remote metrics, default allowlist", func(c *Config) {
			c.Metrics = Metrics{Enabled: true, Host: "0.0.0.0", HostAllowlist: []string{"localhost", "127.0.0.1"}}
		}, known, []error{ErrMetricsLoopbackAllowlist}},
		{"remote metrics, scraper allowed", func(c *Config) {
			c.Metrics = Metrics{Enabled: true, Host: "0.0.0.0", HostAllowlist: []string{"prometheus"}}
		}, known, nil},
		{"remote metrics host while disabled", func(c *Config) {
			c.Metrics = Metrics{Host: "0.0.0.0", HostAllowlist: []string{"localhost"}}
			c.Consensus.SlashingProtectionEnabled = false
		}, known, nil},
		{"remote, token over TLS", remoteTLS, known, nil},
		{"remote, token over a PEM certificate", func(c *Config) {
			remote(c)
			c.AllowPlaintextTokenAuth = false
			c.TLS = tlsconf.Config{CertFile: "/c", KeyFile: "/k"}
		}, known, nil},
		{"remote, mtls", mtls(auth.ModeMTLS), known, nil},
		{"remote, token+mtls", mtls(auth.ModeTokenMTLS), known, nil},
		{"remote, auth none over TLS", func(c *Config) { remoteTLS(c); c.HTTP.AuthMode = auth.ModeNone }, known, []error{ErrAuthNoneNonLoopback}},
		{"remote, TLS does not lift the other refusals", func(c *Config) {
			remoteTLS(c)
			c.HTTP.HostAllowlist = []string{"localhost"}
			c.Consensus.SlashingProtectionEnabled = false
		}, fileNetwork(false, false), []error{ErrLoopbackAllowlist, ErrProtectionDisabledNonLoopback, ErrGVRTOFUNonLoopback, ErrUnknownGenesisNonLoopback}},
		{"mtls without TLS", func(c *Config) { c.HTTP.AuthMode = auth.ModeMTLS }, known, []error{tlsconf.ErrMTLSWithoutTLS}},
		{"token+mtls without a trust source", func(c *Config) {
			c.HTTP.AuthMode = auth.ModeTokenMTLS
			c.TLS.GenerateSelfSigned = true
		}, known, []error{tlsconf.ErrMTLSWithoutTrust}},
		{"token+mtls without a sign token file", func(c *Config) {
			mtls(auth.ModeTokenMTLS)(c)
			c.HTTP.ListenHost = "127.0.0.1"
			c.TLS = tlsconf.Config{CertFile: "/c", KeyFile: "/k", ClientCAFile: "/ca"}
			c.DataPath = ""
			c.Consensus.SlashingProtectionEnabled = false
		}, known, []error{ErrNoSignToken}},
		{"mtls needs no sign token file", func(c *Config) {
			mtls(auth.ModeMTLS)(c)
			c.HTTP.ListenHost = "127.0.0.1"
			c.TLS = tlsconf.Config{CertFile: "/c", KeyFile: "/k", ClientCAFile: "/ca"}
			c.DataPath = ""
			c.Consensus.SlashingProtectionEnabled = false
		}, known, nil},
		{"self-signed without a data path", func(c *Config) {
			c.TLS.GenerateSelfSigned = true
			c.DataPath = ""
			c.HTTP.AuthTokenFile = "/t"
			c.Consensus.SlashingProtectionEnabled = false
		}, known, []error{ErrSelfSignedNoDataPath}},
		{"remote API and metrics, protection off: refused once", func(c *Config) {
			remote(c)
			c.Metrics = Metrics{Enabled: true, Host: "0.0.0.0", HostAllowlist: []string{"prometheus"}}
			c.Consensus.SlashingProtectionEnabled = false
		}, known, []error{ErrProtectionDisabledNonLoopback}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base()
			if tt.mutate != nil {
				tt.mutate(c)
			}
			err := CheckFailSafes(c, tt.n)
			if len(tt.want) == 0 {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("error %v does not wrap ErrRefused", err)
			}
			for _, w := range tt.want {
				if !errors.Is(err, w) {
					t.Errorf("error %v, want it to include %v", err, w)
				}
			}
			if got := len(strings.Split(err.Error(), "\n")); got != len(tt.want) {
				t.Errorf("%d refusals, want %d: %v", got, len(tt.want), err)
			}
		})
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"127.0.0.1": true, "127.1.2.3": true, "::1": true, "[::1]": true, "localhost": true, "LocalHost": true,
		"": false, "0.0.0.0": false, "::": false, "10.0.0.1": false, "signer": false, "localhost.example": false,
	} {
		if got := IsLoopbackHost(host); got != want {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestDerivedPaths(t *testing.T) {
	c := base()
	if c.SignTokenFile() != "/data/auth-token" || c.AdminTokenFile() != "/data/admin-token" ||
		c.SlashingProtectionDB() != "/data/slashing-protection.db" || c.ListenAddr() != "127.0.0.1:9000" {
		t.Fatalf("derived paths: %q %q %q %q", c.SignTokenFile(), c.AdminTokenFile(), c.SlashingProtectionDB(), c.ListenAddr())
	}
	if c.SelfSignedTLSPath() != "/data/tls" {
		t.Fatalf("self-signed TLS directory %q", c.SelfSignedTLSPath())
	}
	c.HTTP.AuthTokenFile, c.DataPath, c.HTTP.ListenHost = "/s", "", "::1"
	if c.SignTokenFile() != "/s" || c.AdminTokenFile() != "" || c.ListenAddr() != "[::1]:9000" || c.SelfSignedTLSPath() != "" {
		t.Fatalf("explicit paths: %q %q %q %q", c.SignTokenFile(), c.AdminTokenFile(), c.ListenAddr(), c.SelfSignedTLSPath())
	}
}

func TestEnvVars(t *testing.T) {
	if got := EnvVars("", "key-config-path", "key-store-path"); !slices.Equal(got, []string{
		"REMOTESIGNER_KEY_CONFIG_PATH", "REMOTESIGNER_KEY_STORE_PATH"}) {
		t.Errorf("global: %v", got)
	}
	if got := EnvVars("consensus", "network"); !slices.Equal(got, []string{"REMOTESIGNER_CONSENSUS_NETWORK"}) {
		t.Errorf("consensus: %v", got)
	}
	// A one-letter alias has no variable, as it has no config-file key.
	if got := EnvVars("", "logging", "l"); !slices.Equal(got, []string{"REMOTESIGNER_LOGGING"}) {
		t.Errorf("short alias: %v", got)
	}
	if got := EnvVars("", "Xallow-plaintext-token-auth"); !slices.Equal(got, []string{
		"REMOTESIGNER_XALLOW_PLAINTEXT_TOKEN_AUTH"}) {
		t.Errorf("hidden: %v", got)
	}
	// A name that begins with its command's name does not repeat it; one
	// that only resembles it, or a global flag, keeps its name.
	for _, tt := range []struct {
		command, name, want string
	}{
		{"execution", "execution-policy-file", "REMOTESIGNER_EXECUTION_POLICY_FILE"},
		{"execution", "execution-proxy-allowed-methods", "REMOTESIGNER_EXECUTION_PROXY_ALLOWED_METHODS"},
		{"execution", "chain-id", "REMOTESIGNER_EXECUTION_CHAIN_ID"},
		{"execution", "executions-x", "REMOTESIGNER_EXECUTION_EXECUTIONS_X"},
		{"execution", "execution", "REMOTESIGNER_EXECUTION_EXECUTION"},
		{"consensus", "consensus-x", "REMOTESIGNER_CONSENSUS_X"},
		{"", "execution-policy-file", "REMOTESIGNER_EXECUTION_POLICY_FILE"},
	} {
		if got := EnvVars(tt.command, tt.name); !slices.Equal(got, []string{tt.want}) {
			t.Errorf("%s --%s: %v, want %s", tt.command, tt.name, got, tt.want)
		}
	}
}

func TestLongNames(t *testing.T) {
	if got := LongNames([]string{"logging", "l", "-v", "log", "--x"}); !slices.Equal(got, []string{"logging", "log"}) {
		t.Errorf("LongNames: %v", got)
	}
}

// yamlApp runs a two-level app whose flags take their defaults from yaml.
func yamlApp(t *testing.T, yaml string, args ...string) (map[string]any, error) {
	t.Helper()
	global := []cli.Flag{
		&cli.UintFlag{Name: "http-listen-port", Value: 9000, EnvVars: EnvVars("", "http-listen-port")},
		&cli.StringSliceFlag{Name: "http-host-allowlist", Value: cli.NewStringSlice("localhost")},
		&cli.StringFlag{Name: "key-config-path", Aliases: []string{"key-store-path"}},
		&cli.StringFlag{Name: "logging", Aliases: []string{"l"}, Value: "INFO", EnvVars: EnvVars("", "logging", "l")},
	}
	cons := []cli.Flag{
		&cli.StringFlag{Name: "network", EnvVars: EnvVars("consensus", "network")},
		&cli.BoolFlag{Name: "slashing-protection-enabled", Value: true},
	}
	src, err := ParseYAML("test.yaml", []byte(yaml))
	if err != nil {
		return nil, err
	}
	if err := src.Validate(global, map[string][]cli.Flag{"consensus": cons}); err != nil {
		return nil, err
	}
	got := map[string]any{}
	app := &cli.App{
		Flags:  global,
		Before: func(c *cli.Context) error { return src.Apply(c, global, "") },
		Commands: []*cli.Command{{
			Name:   "consensus",
			Flags:  cons,
			Before: func(c *cli.Context) error { return src.Apply(c, cons, "consensus") },
			Action: func(c *cli.Context) error {
				got["port"] = c.Uint("http-listen-port")
				got["allowlist"] = strings.Join(c.StringSlice("http-host-allowlist"), ",")
				got["keys"] = c.String("key-config-path")
				got["network"] = c.String("network")
				got["protection"] = c.Bool("slashing-protection-enabled")
				got["logging"] = c.String("logging")
				for _, n := range []string{"http-listen-port", "key-config-path", "network"} {
					got["applied "+n], got["gives "+n] = src.Applied(n), src.Gives(n)
				}
				return nil
			},
		}},
		ExitErrHandler: func(*cli.Context, error) {},
	}
	return got, app.Run(append([]string{"x"}, args...))
}

func TestYAMLSource(t *testing.T) {
	const file = `
http-listen-port: 9100
http-host-allowlist: [a, b]
key-store-path: /keys
consensus:
  network: end-to-end
  slashing-protection-enabled: false
`
	got, err := yamlApp(t, file, "consensus")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"port": uint(9100), "allowlist": "a,b", "keys": "/keys", "network": "end-to-end", "protection": false}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}

	// CLI beats env beats YAML.
	t.Setenv("REMOTESIGNER_HTTP_LISTEN_PORT", "9200")
	t.Setenv("REMOTESIGNER_CONSENSUS_NETWORK", "minimal")
	got, err = yamlApp(t, file, "--http-listen-port=9300", "consensus")
	if err != nil {
		t.Fatal(err)
	}
	if got["port"] != uint(9300) || got["network"] != "minimal" {
		t.Errorf("precedence: port %v network %v", got["port"], got["network"])
	}

	// A consensus flag may sit at the top level.
	got, err = yamlApp(t, "network: interop\n", "consensus")
	if err != nil || got["network"] != "minimal" { // env still set
		t.Errorf("top-level consensus flag with env: %v %v", got, err)
	}

	// The one-letter alias -l works on the command line only: neither
	// REMOTESIGNER_L nor an l key (refused, TestYAMLSourceErrors) sets it.
	t.Setenv("REMOTESIGNER_L", "TRACE")
	got, err = yamlApp(t, "logging: WARN\n", "consensus")
	if err != nil || got["logging"] != "WARN" {
		t.Errorf("REMOTESIGNER_L: %v %v, want the config file's WARN", got, err)
	}
	got, err = yamlApp(t, "logging: WARN\n", "-l", "DEBUG", "consensus")
	if err != nil || got["logging"] != "DEBUG" {
		t.Errorf("-l: %v %v", got, err)
	}
}

// Applied names the flags the file set; Gives also those it gives a value
// that the command line or the environment set first, by a flag's first
// name whichever name the file uses.
func TestYAMLSourceAppliedAndGives(t *testing.T) {
	t.Setenv("REMOTESIGNER_CONSENSUS_NETWORK", "from-env")
	got, err := yamlApp(t, "http-listen-port: 1\nkey-store-path: /keys\nconsensus:\n  network: n\n",
		"--http-listen-port=2", "consensus")
	if err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string][2]bool{
		"http-listen-port": {false, true}, // the command line won
		"key-config-path":  {true, true},  // set by its alias
		"network":          {false, true}, // the environment won
	} {
		if got["applied "+n] != want[0] || got["gives "+n] != want[1] {
			t.Errorf("%s: applied %v, gives %v, want %v", n, got["applied "+n], got["gives "+n], want)
		}
	}
	if got, err = yamlApp(t, "logging: WARN\n", "consensus"); err != nil || got["gives network"] != false {
		t.Errorf("a flag the file does not give: %v %v", got, err)
	}
}

// LoadYAML keeps the type and mode of the file it read, which a later
// change of the file's mode does not alter; ParseYAML has no file.
func TestLoadYAMLInfo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("logging: WARN\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := LoadYAML(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if fi := src.Info(); fi == nil || !fi.Mode().IsRegular() || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("Info %v, want the regular 0600 file that was read", fi)
	}
	if src, err := ParseYAML("test.yaml", []byte("logging: WARN\n")); err != nil || src.Info() != nil {
		t.Fatalf("ParseYAML: %v %v", src, err)
	}
	if _, err := LoadYAML(filepath.Join(t.TempDir(), "missing.yaml")); !errors.Is(err, ErrConfigFile) {
		t.Fatalf("a missing file: %v", err)
	}
}

func TestYAMLSourceErrors(t *testing.T) {
	tests := map[string]string{
		"unknown key":           "http-listen-prot: 1\n",
		"unknown section":       "execution:\n  network: x\n",
		"unknown section key":   "consensus:\n  http-listen-port: 1\n",
		"duplicate key":         "http-listen-port: 1\nhttp-listen-port: 2\n",
		"name and alias":        "key-config-path: /a\nkey-store-path: /b\n",
		"one-letter alias":      "l: DEBUG\n",
		"top level and section": "network: a\nconsensus:\n  network: b\n",
		"list for scalar":       "http-listen-port: [1, 2]\n",
		"null value":            "http-listen-port:\n",
		"bad value":             "http-listen-port: many\n",
		"not a mapping":         "- a\n",
		"empty":                 "",
		"invalid":               "a: [\n",
	}
	for name, file := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := yamlApp(t, file, "consensus"); !errors.Is(err, ErrConfigFile) {
				t.Fatalf("error %v, want ErrConfigFile", err)
			}
		})
	}
}

func TestParseDBURL(t *testing.T) {
	for raw, want := range map[string]DBURL{
		"bolt:///var/lib/signer/sp.db":                      {Path: "/var/lib/signer/sp.db"},
		"bolt:///var/lib/signer/../sp.db":                   {Path: "/var/lib/sp.db"},
		"postgres://u@db/signer?sslmode=verify-full":        {Postgres: "postgres://u@db/signer?sslmode=verify-full"},
		"postgresql://db:5433/signer":                       {Postgres: "postgresql://db:5433/signer"},
		"jdbc:postgresql://db/web3signer?sslmode=verify-ca": {Postgres: "postgresql://db/web3signer?sslmode=verify-ca"},
		"jdbc:postgresql://u@db.internal:5432/remotesigner": {Postgres: "postgresql://u@db.internal:5432/remotesigner"},
	} {
		if got, err := ParseDBURL(raw); err != nil || got != want {
			t.Errorf("%s: %+v %v, want %+v", raw, got, err, want)
		}
	}
	for raw, want := range map[string]string{
		"postgres://u:secret@db/signer":          "password",
		"jdbc:postgresql://db/signer?password=x": "password",
		"postgres://db/signer?pool_max_conns=40": "pool profile is fixed",
		"jdbc:mysql://db/signer":                 "unsupported scheme",
		"bolt://host/sp.db":                      "no host",
		"bolt:///sp.db?mode=ro":                  "no host or query",
		"bolt:relative.db":                       "no host",
		"bolt:///":                               "absolute file path",
		"/var/lib/sp.db":                         "unsupported scheme",
		"sqlite:///var/lib/sp.db":                "unsupported scheme",
		"bolt://%zz":                             "not a URL",
	} {
		if _, err := ParseDBURL(raw); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want an error mentioning %q", raw, err, want)
		}
	}
}

func TestSlashingProtectionDB(t *testing.T) {
	c := base()
	if got := c.SlashingProtectionDB(); got != "/data/slashing-protection.db" {
		t.Fatalf("default %s", got)
	}
	c.Consensus.SlashingProtectionDBPath = "/elsewhere/sp.db"
	if got := c.SlashingProtectionDB(); got != "/elsewhere/sp.db" {
		t.Fatalf("from the URL %s", got)
	}
}

// The zero Signing is the gate's defaults; any other value is taken as it is,
// a queue of 0 included.
func TestSigningLimits(t *testing.T) {
	tests := []struct {
		in                 Signing
		concurrent, queued int
	}{
		{Signing{}, 32, 512},
		{Signing{MaxConcurrent: 1}, 1, 0},
		{Signing{MaxConcurrent: 64, MaxQueued: 1024}, 64, 1024},
	}
	for _, tt := range tests {
		if c, q := tt.in.Limits(); c != tt.concurrent || q != tt.queued {
			t.Errorf("%+v.Limits() = %d, %d, want %d, %d", tt.in, c, q, tt.concurrent, tt.queued)
		}
	}
}
