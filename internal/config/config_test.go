// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/internal/network"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
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

// The startup refusals of the walking skeleton (G4 S3).
func TestCheckFailSafes(t *testing.T) {
	known := fileNetwork(true, true)
	remote := func(c *Config) {
		c.HTTP.ListenHost = "0.0.0.0"
		c.HTTP.HostAllowlist = []string{"signer.internal"}
		c.AllowPlaintextTokenAuth = true
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
		{"token mode without token file", func(c *Config) { c.DataPath = ""; c.Consensus.SlashingProtectionEnabled = false }, known, []error{ErrNoSignToken}},
		{"keymanager without admin token", func(c *Config) {
			c.DataPath = ""
			c.HTTP.AuthTokenFile = "/t"
			c.Consensus.SlashingProtectionEnabled = false
			c.Consensus.KeyManagerAPIEnabled = true
		}, known, []error{ErrKeyManagerNoAdmin}},
		{"keymanager with admin token", func(c *Config) { c.Consensus.KeyManagerAPIEnabled = true }, known, nil},
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
	c.HTTP.AuthTokenFile, c.DataPath, c.HTTP.ListenHost = "/s", "", "::1"
	if c.SignTokenFile() != "/s" || c.AdminTokenFile() != "" || c.ListenAddr() != "[::1]:9000" {
		t.Fatalf("explicit paths: %q %q %q", c.SignTokenFile(), c.AdminTokenFile(), c.ListenAddr())
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
	if got := EnvVars("", "Xallow-plaintext-token-auth", "l"); !slices.Equal(got, []string{
		"REMOTESIGNER_XALLOW_PLAINTEXT_TOKEN_AUTH", "REMOTESIGNER_L"}) {
		t.Errorf("hidden and short: %v", got)
	}
}

// yamlApp runs a two-level app whose flags take their defaults from yaml.
func yamlApp(t *testing.T, yaml string, args ...string) (map[string]any, error) {
	t.Helper()
	global := []cli.Flag{
		&cli.UintFlag{Name: "http-listen-port", Value: 9000, EnvVars: EnvVars("", "http-listen-port")},
		&cli.StringSliceFlag{Name: "http-host-allowlist", Value: cli.NewStringSlice("localhost")},
		&cli.StringFlag{Name: "key-config-path", Aliases: []string{"key-store-path"}},
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
}

func TestYAMLSourceErrors(t *testing.T) {
	tests := map[string]string{
		"unknown key":           "http-listen-prot: 1\n",
		"unknown section":       "execution:\n  network: x\n",
		"unknown section key":   "consensus:\n  http-listen-port: 1\n",
		"duplicate key":         "http-listen-port: 1\nhttp-listen-port: 2\n",
		"name and alias":        "key-config-path: /a\nkey-store-path: /b\n",
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
