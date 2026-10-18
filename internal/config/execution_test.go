// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
	"github.com/rgeraldes24/go-remotesigner/internal/server/tlsconf"
)

// Execution mode applies the listener refusals of consensus mode, and none
// of the slashing-protection or network ones.
func TestCheckExecutionFailSafes(t *testing.T) {
	remote := func(c *Config) {
		c.HTTP.ListenHost = "0.0.0.0"
		c.HTTP.HostAllowlist = []string{"signer.internal"}
	}
	tests := []struct {
		name   string
		mutate func(*Config)
		want   []error
	}{
		{"loopback defaults", func(*Config) {}, nil},
		{"loopback without protection or network", func(c *Config) { c.Consensus.SlashingProtectionEnabled = false }, nil},
		{"auth none on loopback", func(c *Config) { c.HTTP.AuthMode = auth.ModeNone }, nil},
		{"no sign token", func(c *Config) { c.DataPath = "" }, []error{ErrNoSignToken}},
		{"self-signed without a data path", func(c *Config) {
			c.DataPath, c.HTTP.AuthTokenFile = "", "/t"
			c.TLS = tlsconf.Config{GenerateSelfSigned: true}
		}, []error{ErrSelfSignedNoDataPath}},
		{"mtls without TLS", func(c *Config) { c.HTTP.AuthMode = auth.ModeMTLS }, []error{ErrRefused}},
		{"remote plaintext token", remote, []error{ErrPlaintextToken}},
		{"remote plaintext token allowed", func(c *Config) { remote(c); c.AllowPlaintextTokenAuth = true }, nil},
		{"remote with TLS", func(c *Config) { remote(c); c.TLS = tlsconf.Config{GenerateSelfSigned: true} }, nil},
		{"remote auth none", func(c *Config) { remote(c); c.HTTP.AuthMode = auth.ModeNone }, []error{ErrAuthNoneNonLoopback}},
		{"remote loopback allowlist", func(c *Config) {
			remote(c)
			c.HTTP.HostAllowlist, c.AllowPlaintextTokenAuth = []string{"localhost"}, true
		}, []error{ErrLoopbackAllowlist}},
		{"remote metrics with a loopback allowlist", func(c *Config) {
			c.Metrics = Metrics{Enabled: true, Host: "0.0.0.0", HostAllowlist: []string{"127.0.0.1"}}
		}, []error{ErrMetricsLoopbackAllowlist}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base()
			tt.mutate(c)
			err := CheckExecutionFailSafes(c)
			if len(tt.want) == 0 && err != nil {
				t.Fatalf("refused: %v", err)
			}
			for _, w := range tt.want {
				if !errors.Is(err, w) {
					t.Errorf("err = %v, want %v", err, w)
				}
			}
		})
	}
}
