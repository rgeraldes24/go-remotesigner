// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

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

// TestKeystoreVerifyUntrustedPath checks that the keystore's path field,
// which GCM does not authenticate, cannot write terminal escapes or extra
// lines into the output: only a derivation path is printed.
func TestKeystoreVerifyUntrustedPath(t *testing.T) {
	c := lightKeystores(t)["deposit-cli-light.json"]
	data := vectors.Raw(t, "keystores/deposit-cli-light.json")
	pw := writeTemp(t, "password.txt", []byte(c.Password))
	for _, tt := range []struct{ name, path, want string }{
		{"derivation path", "m/12381/3600/0/0/0", "  path:       m/12381/3600/0/0/0\n"},
		{"cursor escapes over the identifier", "\x1b[2K\x1b[1A\x1b[17G" + strings.Repeat("f", 40), ""},
		{"a forged OK line", "m/12381\x1b[31mRED\x1b[0m\nkeystore-0.json: OK", ""},
		{"OSC 52 clipboard write", "\x1b]52;c;ZWNobyBoaQ==\x07", ""},
		{"carriage return", "m/12381/3600/0/0/0\r  identifier: 0xdead", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatal(err)
			}
			m["path"] = tt.path
			b, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			ks := writeTemp(t, "keystore.json", b)
			code, stdout, stderr := runCLI(t, "consensus", "keystore", "verify", "--keystore-file", ks, "--keystore-password-file", pw)
			if code != exitOK {
				t.Fatalf("exit %d: %s", code, stderr)
			}
			if i := strings.IndexFunc(stdout, func(r rune) bool { return r != '\n' && !unicode.IsPrint(r) }); i >= 0 {
				t.Errorf("output holds the control character %q:\n%q", stdout[i], stdout)
			}
			if n := strings.Count(stdout, ": OK"); n != 1 {
				t.Errorf("%d OK lines:\n%s", n, stdout)
			}
			if n := strings.Count(stdout, "identifier:"); n != 1 {
				t.Errorf("%d identifier lines:\n%s", n, stdout)
			}
			if gotPath := strings.Contains(stdout, "path:"); gotPath != (tt.want != "") || !strings.Contains(stdout, tt.want) {
				t.Errorf("path line: want %q:\n%s", tt.want, stdout)
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

// retainingReader serves data, then fails with err, and keeps the slices
// of the caller's buffer it wrote into, so that a test can check that the
// caller wiped them.
type retainingReader struct {
	data    []byte
	err     error
	written [][]byte
}

func (r *retainingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	r.written = append(r.written, p[:n])
	return n, nil
}

// TestReadLimitedWipes checks that the password file reader wipes what it
// read when the read fails or the file is too large, and returns the
// content otherwise.
func TestReadLimitedWipes(t *testing.T) {
	const limit = 64
	for _, tt := range []struct {
		name    string
		data    string
		err     error
		wantErr string
	}{
		{"read error after part of the file", "hunter2-partial", errors.New("input/output error"), "input/output error"},
		{"larger than the limit", strings.Repeat("hunter2!", limit/8+1), io.EOF, "larger than 64 bytes"},
		{"exactly the limit", strings.Repeat("hunter2!", limit/8), io.EOF, ""},
		{"short", "hunter2\n", io.EOF, ""},
		{"empty", "", io.EOF, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &retainingReader{data: []byte(tt.data), err: tt.err}
			got, err := readLimited(r, limit)
			if tt.wantErr == "" {
				if err != nil || string(got) != tt.data {
					t.Fatalf("got %q, %v; want %q", got, err, tt.data)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) || got != nil {
				t.Fatalf("got %q, %v; want an error mentioning %q", got, err, tt.wantErr)
			}
			if len(r.written) == 0 {
				t.Fatal("the reader was never read")
			}
			for _, b := range r.written {
				if !bytes.Equal(b, make([]byte, len(b))) {
					t.Errorf("the buffer still holds %q", b)
				}
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
