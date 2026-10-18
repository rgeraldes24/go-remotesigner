// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

func TestKeyLoadingFlags(t *testing.T) {
	cfg, code, stderr := capture(t, "consensus", "--network=e2e")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !cfg.StrictFilePermissions || cfg.ReloadTimeout != time.Hour || cfg.SignerLoadParallelism != 0 ||
		cfg.Consensus.Keystores != (config.Keystores{}) {
		t.Fatalf("defaults: strict %v, timeout %v, parallelism %d, keystores %+v", cfg.StrictFilePermissions,
			cfg.ReloadTimeout, cfg.SignerLoadParallelism, cfg.Consensus.Keystores)
	}

	// The qrl-package invocation: keystores and one shared password file.
	cfg, code, stderr = capture(t, "--strict-file-permissions=false", "--reload-timeout=5", "--signer-load-parallelism=2",
		"consensus", "--network=e2e", "--keystores-path=/remote-signer/keystores",
		"--keystores-password-file=/remote-signer/password.txt")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	want := config.Keystores{Path: "/remote-signer/keystores", PasswordFile: "/remote-signer/password.txt"}
	if cfg.StrictFilePermissions || cfg.ReloadTimeout != 5*time.Minute || cfg.SignerLoadParallelism != 2 ||
		cfg.Consensus.Keystores != want {
		t.Fatalf("flags: %+v", cfg)
	}
	cfg, code, _ = capture(t, "consensus", "--network=e2e", "--keystores-path=/k", "--keystores-passwords-path=/p")
	if code != exitOK || cfg.Consensus.Keystores != (config.Keystores{Path: "/k", PasswordsPath: "/p"}) {
		t.Fatalf("password directory: exit %d %+v", code, cfg.Consensus.Keystores)
	}
	// Environment variables, as for every flag.
	t.Run("environment", func(t *testing.T) {
		t.Setenv("REMOTESIGNER_CONSENSUS_KEYSTORES_PATH", "/env/k")
		t.Setenv("REMOTESIGNER_CONSENSUS_KEYSTORES_PASSWORD_FILE", "/env/p")
		t.Setenv("REMOTESIGNER_STRICT_FILE_PERMISSIONS", "false")
		cfg, code, _ := capture(t, "consensus", "--network=e2e")
		if code != exitOK || cfg.Consensus.Keystores != (config.Keystores{Path: "/env/k", PasswordFile: "/env/p"}) ||
			cfg.StrictFilePermissions {
			t.Fatalf("environment: exit %d %+v", code, cfg)
		}
	})

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"consensus", "--network=e2e", "--keystores-path=/k"}, "--keystores-path needs --keystores-password-file or --keystores-passwords-path"},
		{[]string{"consensus", "--network=e2e", "--keystores-path=/k", "--keystores-password-file=/p", "--keystores-passwords-path=/d"},
			"only one of --keystores-passwords-path or --keystores-password-file"},
		{[]string{"consensus", "--network=e2e", "--keystores-password-file=/p"}, "need --keystores-path"},
		{[]string{"--reload-timeout=0", "consensus", "--network=e2e"}, "--reload-timeout must be 1"},
		{[]string{"--reload-timeout=1000001", "consensus", "--network=e2e"}, "--reload-timeout must be 1"},
		{[]string{"--signer-load-parallelism=-1", "consensus", "--network=e2e"}, "--signer-load-parallelism must be 0"},
		{[]string{"--signer-load-parallelism=65", "consensus", "--network=e2e"}, "--signer-load-parallelism must be 0"},
	} {
		if _, code, stderr := capture(t, tc.args...); code != exitUsage || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: exit %d %q, want a usage error mentioning %q", tc.args, code, stderr, tc.want)
		}
	}
}

func TestDisableValidator(t *testing.T) {
	data := t.TempDir()
	path := filepath.Join(data, config.SlashingProtectionFile)
	id := storeWithFrontier(t, path)
	canonical := "0x" + hex.EncodeToString(slashingtest.Key(0))
	status := func() slashing.ValidatorStatus {
		t.Helper()
		s, err := boltstore.Open(path, boltstore.Options{})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.Close() }()
		st, err := s.ValidatorStatus(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}

	held, err := boltstore.Open(path, boltstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, "--data-path="+data, "consensus", "disable-validator", "--key="+canonical)
	_ = held.Close()
	if code != exitStartup || !strings.Contains(stderr, "stop the signer first, then run consensus disable-validator again") {
		t.Fatalf("locked store: exit %d %q", code, stderr)
	}
	if !status().Enabled {
		t.Fatal("a refused command disabled the key")
	}

	code, stdout, stderr := runCLI(t, "--data-path="+data, "consensus", "disable-validator", "--key="+canonical)
	if code != exitOK || !strings.Contains(stdout, "disabled in "+path) || !strings.Contains(stdout, "412 VALIDATOR_DISABLED") {
		t.Fatalf("disable: exit %d %q %q", code, stdout, stderr)
	}
	if st := status(); !st.Registered || st.Enabled {
		t.Fatalf("after disable-validator: %+v", st)
	}
	// Again, by the id alias and by URL: already disabled, exit 0.
	alias := "0x" + hex.EncodeToString(id[:])
	code, stdout, _ = runCLI(t, "consensus", "disable-validator", "--slashing-protection-db-url=bolt://"+path, "--key="+alias)
	if code != exitOK || !strings.Contains(stdout, "already disabled") {
		t.Fatalf("again: exit %d %q", code, stdout)
	}

	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"--data-path=" + data, "consensus", "disable-validator", "--key=0x" + strings.Repeat("ab", 32)}, exitStartup, "not registered"},
		{[]string{"--data-path=" + data, "consensus", "disable-validator", "--key=0x12"}, exitUsage, "--key"},
		{[]string{"--data-path=" + data, "consensus", "disable-validator"}, exitUsage, "--key is required"},
		{[]string{"--data-path=" + t.TempDir(), "consensus", "disable-validator", "--key=" + alias}, exitUsage, "no slashing-protection store"},
		{[]string{"--data-path=" + data, "consensus", "disable-validator", "--key=" + alias, "extra"}, exitUsage, "unexpected argument"},
	} {
		code, _, stderr := runCLI(t, tc.args...)
		if code != tc.code || !strings.Contains(stderr, tc.want) {
			t.Errorf("%v: exit %d %q, want %d mentioning %q", tc.args, code, stderr, tc.code, tc.want)
		}
	}
}

// keystoreDir writes n deposit CLI keystores with the cheapest KDF and one
// password file, and returns the directory and the password file.
func keystoreDir(t *testing.T, n int, names ...string) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "keystores")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := keystoretest.NewSealer("pw", keystoretest.Cheapest)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		data, err := s.DepositCLI(keystoretest.Seed(t.Name(), i), i, true)
		if err != nil {
			t.Fatal(err)
		}
		name := keystoretest.DepositFileName(i, 1760000000)
		if i < len(names) {
			name = names[i]
		}
		if _, err := keystoretest.WriteFile(dir, name, data); err != nil {
			t.Fatal(err)
		}
	}
	pw, err := keystoretest.WriteFile(root, "password.txt", []byte("pw\n"))
	if err != nil {
		t.Fatal(err)
	}
	return dir, pw
}

// The directory form checks a keystore directory as the signer loads it,
// prints the names it lists quoted, and exits 1 when any keystore is
// refused.
func TestKeystoreVerifyDirectory(t *testing.T) {
	dir, pw := keystoreDir(t, 3, "a.json", "b\x1b[2Kc.json")
	code, stdout, stderr := runCLI(t, "consensus", "keystore", "verify", "--keystores-path", dir, "--keystores-password-file", pw)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{`"a.json": OK`, `"b\x1b[2Kc.json": OK`, "3 keystores: 3 OK, 0 refused", "identifier 0x"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "\x1b") {
		t.Errorf("an escape character reached the output:\n%q", stdout)
	}

	// A broken keystore is refused on its own line; the others still pass.
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runCLI(t, "consensus", "keystore", "verify", "--keystores-path", dir, "--keystores-password-file", pw)
	if code != exitStartup || !strings.Contains(stderr, `"broken.json": REFUSED: keystore: malformed keystore`) ||
		!strings.Contains(stdout, "4 keystores: 3 OK, 1 refused") {
		t.Fatalf("broken keystore: exit %d\n%s\n%s", code, stdout, stderr)
	}

	// The password file rule is the signer's: refused when world-readable,
	// unless --strict-file-permissions=false.
	if err := os.Remove(filepath.Join(dir, "broken.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pw, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = runCLI(t, "consensus", "keystore", "verify", "--keystores-path", dir, "--keystores-password-file", pw)
	if code != exitStartup || !strings.Contains(stderr, "readable by group or other users") {
		t.Fatalf("world-readable password file: exit %d %q", code, stderr)
	}
	code, _, stderr = runCLI(t, "--strict-file-permissions=false", "consensus", "keystore", "verify", "--keystores-path", dir,
		"--keystores-password-file", pw)
	if code != exitOK || !strings.Contains(stderr, "warning: "+pw+": mode 0644") {
		t.Fatalf("lax policy: exit %d %q", code, stderr)
	}
	// The single form applies the rule too.
	ks := filepath.Join(dir, "a.json")
	code, _, stderr = runCLI(t, "consensus", "keystore", "verify", "--file", ks, "--password-file", pw)
	if code != exitStartup || !strings.Contains(stderr, "readable by group or other users") {
		t.Fatalf("single form, world-readable password file: exit %d %q", code, stderr)
	}

	// A password directory: <name>.txt per keystore.
	pwDir := t.TempDir()
	for _, n := range []string{"a", "b\x1b[2Kc", keystoretest.DepositFileName(2, 1760000000)} {
		if _, err := keystoretest.WriteFile(pwDir, strings.TrimSuffix(n, ".json")+".txt", []byte("pw")); err != nil {
			t.Fatal(err)
		}
	}
	code, stdout, stderr = runCLI(t, "consensus", "keystore", "verify", "--keystores-path", dir, "--keystores-passwords-path", pwDir)
	if code != exitOK || !strings.Contains(stdout, "3 keystores: 3 OK") {
		t.Fatalf("password directory: exit %d\n%s\n%s", code, stdout, stderr)
	}
}

func TestKeystoreVerifyForms(t *testing.T) {
	for _, args := range [][]string{
		{"--file", "k.json", "--password-file", "p", "--keystores-path", "d"},
		{"--keystores-path", "d"},
		{"--keystores-password-file", "p"},
		{"--keystores-path", "d", "--keystores-password-file", "p", "--keystores-passwords-path", "q"},
		{"--password-file", "p"},
	} {
		code, _, stderr := runCLI(t, append([]string{"consensus", "keystore", "verify"}, args...)...)
		if code != exitUsage || !strings.Contains(stderr, "usage error") {
			t.Errorf("%v: exit %d %q, want a usage error", args, code, stderr)
		}
	}
}
