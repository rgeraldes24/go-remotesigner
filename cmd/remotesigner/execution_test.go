// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
)

func TestExecutionDefaults(t *testing.T) {
	cfg, code, stderr := capture(t, "execution", "--chain-id=1337")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	want := config.Downstream{Host: "127.0.0.1", Port: 8545, Path: "/", Timeout: 5 * time.Second, ProxyPort: 80}
	if cfg.Execution.Downstream != want {
		t.Fatalf("downstream %+v, want %+v", cfg.Execution.Downstream, want)
	}
	if !slices.Equal(cfg.Execution.AllowedMethods, []string{"qrl_*", "net_*", "web3_*"}) ||
		!slices.Equal(cfg.Execution.AllowedMethods, flags.DefaultAllowedMethods) {
		t.Fatalf("allowed methods %v", cfg.Execution.AllowedMethods)
	}
	if cfg.HTTP.ListenPort != 9000 || cfg.HTTP.AuthMode != "token" || cfg.Consensus.Network.Network != "" {
		t.Fatalf("global config %+v", cfg)
	}
	e := cfg.Execution
	if e.ChainID != 1337 || e.PolicyFile != "" || e.AuditLogFile != "" || !e.NonceCrosscheck {
		t.Fatalf("transaction settings %+v", e)
	}
}

func TestExecutionFlags(t *testing.T) {
	cfg, code, stderr := capture(t, "--http-listen-port=9100", "--key-config-path=/keys",
		"execution", "--downstream-http-host=gqrl", "--downstream-http-port=8546", "--downstream-http-path=/rpc",
		"--downstream-http-request-timeout=750", "--downstream-http-auth-header-file=/auth",
		"--downstream-http-tls-enabled", "--downstream-http-tls-ca-file=/ca.pem",
		"--downstream-http-proxy-host=proxy", "--downstream-http-proxy-port=3128",
		"--execution-proxy-allowed-methods=qrl_*,net_version", "--keystores-path=/ks", "--keystores-password-file=/pw",
		"--chain-id=0x539", "--execution-policy-file=/policy.yaml", "--execution-audit-log-file=/audit.jsonl",
		"--execution-nonce-crosscheck=false")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	want := config.Downstream{Host: "gqrl", Port: 8546, Path: "/rpc", Timeout: 750 * time.Millisecond,
		AuthHeaderFile: "/auth", TLS: true, TLSCAFile: "/ca.pem", ProxyHost: "proxy", ProxyPort: 3128}
	if cfg.Execution.Downstream != want || !slices.Equal(cfg.Execution.AllowedMethods, []string{"qrl_*", "net_version"}) ||
		cfg.Execution.Keystores != (config.Keystores{Path: "/ks", PasswordFile: "/pw"}) || cfg.HTTP.ListenPort != 9100 ||
		cfg.KeyConfigPath != "/keys" || cfg.Execution.ChainID != 1337 || cfg.Execution.PolicyFile != "/policy.yaml" ||
		cfg.Execution.AuditLogFile != "/audit.jsonl" || cfg.Execution.NonceCrosscheck {
		t.Fatalf("config %+v", cfg.Execution)
	}
}

// The execution flags read REMOTESIGNER_EXECUTION_* and an execution:
// section of the config file.
func TestExecutionSources(t *testing.T) {
	file := filepath.Join(t.TempDir(), "config.yaml")
	content := "http-listen-port: 9200\nexecution:\n  downstream-http-port: 9545\n  execution-proxy-allowed-methods: [\"*\"]\n" +
		"  chain-id: 1337\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, code, stderr := capture(t, "--config-file="+file, "execution")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if cfg.HTTP.ListenPort != 9200 || cfg.Execution.Downstream.Port != 9545 ||
		!slices.Equal(cfg.Execution.AllowedMethods, []string{"*"}) {
		t.Fatalf("from YAML: %+v", cfg.Execution)
	}
	t.Setenv("REMOTESIGNER_EXECUTION_DOWNSTREAM_HTTP_HOST", "gqrl.internal")
	t.Setenv("REMOTESIGNER_EXECUTION_DOWNSTREAM_HTTP_PORT", "8000")
	cfg, code, stderr = capture(t, "--config-file="+file, "execution")
	if code != exitOK || cfg.Execution.Downstream.Host != "gqrl.internal" || cfg.Execution.Downstream.Port != 8000 {
		t.Fatalf("env over YAML: %d %s %+v", code, stderr, cfg)
	}
	// The execution-* flags' variables do not repeat the command; the
	// doubled names set nothing.
	t.Setenv("REMOTESIGNER_EXECUTION_PROXY_ALLOWED_METHODS", "net_*")
	t.Setenv("REMOTESIGNER_EXECUTION_POLICY_FILE", "/policy.yaml")
	t.Setenv("REMOTESIGNER_EXECUTION_AUDIT_LOG_FILE", "/audit.jsonl")
	t.Setenv("REMOTESIGNER_EXECUTION_NONCE_CROSSCHECK", "false")
	t.Setenv("REMOTESIGNER_EXECUTION_EXECUTION_CHAIN_ID", "7")
	cfg, code, stderr = capture(t, "execution", "--chain-id=1337")
	if code != exitOK || !slices.Equal(cfg.Execution.AllowedMethods, []string{"net_*"}) ||
		cfg.Execution.PolicyFile != "/policy.yaml" || cfg.Execution.AuditLogFile != "/audit.jsonl" ||
		cfg.Execution.NonceCrosscheck || cfg.Execution.ChainID != 1337 {
		t.Fatalf("execution-* variables: %d %s %+v", code, stderr, cfg)
	}
	t.Setenv("REMOTESIGNER_EXECUTION_EXECUTION_POLICY_FILE", "/doubled.yaml")
	if cfg, _, _ = capture(t, "execution", "--chain-id=1337"); cfg.Execution.PolicyFile != "/policy.yaml" {
		t.Fatalf("the doubled variable set --execution-policy-file to %s", cfg.Execution.PolicyFile)
	}
	// A consensus section is still valid YAML for this binary; consensus
	// flags do not reach the execution command.
	both := filepath.Join(t.TempDir(), "both.yaml")
	if err := os.WriteFile(both, []byte("consensus:\n  network: e2e\nexecution:\n  downstream-http-port: 9545\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, code, stderr := capture(t, "--config-file="+both, "execution", "--chain-id=1"); code != exitOK {
		t.Fatalf("both sections: %d %s", code, stderr)
	}
}

func TestExecutionUsageErrors(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"execution", "extra"}, `unexpected argument "extra"`},
		{[]string{"execution", "--network=e2e"}, "network"},
		{[]string{"execution", "--downstream-http-port=0"}, "--downstream-http-port must be 1 to 65535"},
		{[]string{"execution", "--downstream-http-port=70000"}, "not a TCP port"},
		{[]string{"execution", "--downstream-http-host="}, "--downstream-http-host must name a host"},
		{[]string{"execution", "--downstream-http-request-timeout=0"}, "--downstream-http-request-timeout must be 1 to"},
		{[]string{"execution", "--downstream-http-request-timeout=3600001"}, "--downstream-http-request-timeout must be 1 to"},
		{[]string{"execution", "--downstream-http-path=/rpc?x=1"}, "--downstream-http-path: illegal characters"},
		{[]string{"execution", "--downstream-http-tls-ca-file=/ca.pem"}, "needs --downstream-http-tls-enabled"},
		{[]string{"execution", "--downstream-http-proxy-host=p", "--downstream-http-proxy-port=0"}, "--downstream-http-proxy-port must be 1 to 65535"},
		{[]string{"execution", "--execution-proxy-allowed-methods=qrl-*"}, "--execution-proxy-allowed-methods"},
		{[]string{"execution", "--keystores-path=/ks"}, "--keystores-path needs"},
		{[]string{"execution", "--keystores-password-file=/pw", "--keystores-passwords-path=/d", "--keystores-path=/ks"}, "only one of"},
		{[]string{"--http-auth-mode=mtls", "execution"}, "need TLS"},
		{[]string{"--http-listen-port=70000", "execution"}, "not a TCP port"},
		{[]string{"execution"}, "--chain-id is required"},
		{[]string{"execution", "--chain-id=0"}, "--chain-id is required"},
		{[]string{"execution", "--chain-id=-1"}, "chain-id"},
	}
	for _, tt := range tests {
		_, code, stderr := capture(t, tt.args...)
		if code != exitUsage || !strings.Contains(stderr, tt.want) {
			t.Errorf("%v: exit %d %q, want a usage error mentioning %q", tt.args, code, stderr, tt.want)
		}
	}
	file := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(file, []byte("execution:\n  network: e2e\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, code, stderr := capture(t, "--config-file="+file, "execution"); code != exitUsage ||
		!strings.Contains(stderr, "unknown option(s): execution.network") {
		t.Fatalf("a consensus flag in the execution section: %d %s", code, stderr)
	}
}

// execution has no subcommands, and its help says so: urfave/cli writes
// "execution command [command options]" for a command that has some.
func TestExecutionHelp(t *testing.T) {
	for _, args := range [][]string{{"execution", "--help"}, {"execution", "-h"}} {
		var stdout, stderr bytes.Buffer
		if code := runWith(append([]string{binaryName}, args...), &stdout, &stderr, noRun); code != exitOK {
			t.Fatalf("%v: exit %d %s", args, code, stderr.String())
		}
		out := stdout.String()
		if !strings.Contains(out, binaryName+" execution [command options]") || strings.Contains(out, "command [command options]") ||
			strings.Contains(out, "COMMANDS:") {
			t.Errorf("%v: usage\n%s", args, out)
		}
		if !strings.Contains(out, "$REMOTESIGNER_EXECUTION_POLICY_FILE") || strings.Contains(out, "EXECUTION_EXECUTION") {
			t.Errorf("%v: environment names\n%s", args, out)
		}
	}
}

// The production run function of execution mode is execution.Run.
func TestExecutionRunIsWired(t *testing.T) {
	if executionRun == nil {
		t.Fatal("no execution run function")
	}
	var names []string
	for _, c := range newApp(nil, nil, nil).Commands {
		names = append(names, c.Name)
	}
	if !slices.Equal(names, []string{"consensus", "execution"}) {
		t.Fatalf("commands %v", names)
	}
}
