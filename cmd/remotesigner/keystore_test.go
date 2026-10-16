// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// lightKeystores returns the light-KDF keystore vectors by file name.
func lightKeystores(t *testing.T) map[string]vectors.KeystoreCase {
	t.Helper()
	out := map[string]vectors.KeystoreCase{}
	for _, c := range vectors.Keystores(t) {
		if c.KDF.M == 4096 {
			out[c.File] = c
		}
	}
	return out
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestKeystoreVerify(t *testing.T) {
	cases := lightKeystores(t)
	for _, file := range []string{"qrl-v1-light.json", "deposit-cli-light.json", "qrl-v1-light-unicode.json"} {
		c, ok := cases[file]
		if !ok {
			t.Fatalf("no %s in index.json", file)
		}
		t.Run(file, func(t *testing.T) {
			ks := filepath.Join(vectors.Dir(), "keystores", file)
			pw := writeTemp(t, "password.txt", []byte(c.Password+"\r\n"))
			code, stdout, stderr := runCLI(t, "consensus", "keystore", "verify", "--keystore-file", ks, "--keystore-password-file", pw)
			if code != exitOK {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			id := sha256.Sum256(vectors.Hex(t, c.Pubkey))
			for _, want := range []string{ks + ": OK", c.Flavour, "m=4096 KiB", "matches the key the seed derives", "0x" + hex.EncodeToString(id[:])} {
				if !strings.Contains(stdout, want) {
					t.Errorf("output lacks %q:\n%s", want, stdout)
				}
			}
			if strings.Contains(stdout, strings.TrimPrefix(c.Pubkey, "0x")[:32]) || strings.Contains(stdout, c.Password) {
				t.Errorf("output shows the full public key or the password:\n%s", stdout)
			}
		})
	}
}

func TestKeystoreVerifyRefusals(t *testing.T) {
	c := lightKeystores(t)["qrl-v1-light.json"]
	other := lightKeystores(t)["qrl-v1-light-unicode.json"]
	data := vectors.Raw(t, "keystores/qrl-v1-light.json")
	editKeystore := func(edit func(m map[string]any)) string {
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return writeTemp(t, "keystore.json", b)
	}
	good := filepath.Join(vectors.Dir(), "keystores", "qrl-v1-light.json")
	pw := writeTemp(t, "password.txt", []byte(c.Password))
	for _, tt := range []struct {
		name     string
		keystore string
		password string
		want     string
	}{
		{"wrong password", good, writeTemp(t, "wrong.txt", []byte("not the password")), "wrong password"},
		{"pubkey of another key", editKeystore(func(m map[string]any) { m["pubkey"] = strings.TrimPrefix(other.Pubkey, "0x") }), pw, "pubkey does not match"},
		{"m=2^31", editKeystore(func(m map[string]any) {
			m["crypto"].(map[string]any)["kdf"].(map[string]any)["params"].(map[string]any)["m"] = 1 << 31
		}), pw, "refused by the keystore policy"},
		{"no KDF", editKeystore(func(m map[string]any) { delete(m["crypto"].(map[string]any), "kdf") }), pw, "no KDF"},
		{"not a keystore", writeTemp(t, "x.json", []byte("{")), pw, "malformed keystore"},
		{"too large", writeTemp(t, "big.json", make([]byte, 65<<10)), pw, "larger than 65536 bytes"},
		{"missing keystore", filepath.Join(t.TempDir(), "none.json"), pw, "no such file"},
		{"missing password file", good, filepath.Join(t.TempDir(), "none.txt"), "no such file"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, "consensus", "keystore", "verify", "--keystore-file", tt.keystore, "--keystore-password-file", tt.password)
			if code != exitStartup || !strings.Contains(stderr, tt.want) {
				t.Fatalf("exit %d, stderr %q; want exit %d mentioning %q", code, stderr, exitStartup, tt.want)
			}
			if strings.Contains(stdout, "OK") {
				t.Errorf("stdout %q", stdout)
			}
		})
	}
}

func TestKeystoreVerifyUsage(t *testing.T) {
	for _, args := range [][]string{
		{"consensus", "keystore"},
		{"consensus", "keystore", "verify"},
		{"consensus", "keystore", "verify", "--keystore-file", "k.json"},
		{"consensus", "keystore", "verify", "--keystore-password-file", "p.txt"},
		{"consensus", "keystore", "verify", "--keystore-file", "k.json", "--keystore-password-file", "p.txt", "extra"},
		{"consensus", "keystore", "verify", "--unknown"},
	} {
		if code, _, stderr := runCLI(t, args...); code != exitUsage || !strings.Contains(stderr, "usage error") {
			t.Errorf("%v: exit %d %q, want a usage error", args, code, stderr)
		}
	}
}
