// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package keyconfig

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/argon"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
)

func seedHex(b byte) string {
	return "0x" + strings.Repeat(hex.EncodeToString([]byte{b}), mldsa87.SeedSize)
}

func pubkeyOf(t *testing.T, b byte) mldsa87.PublicKey {
	t.Helper()
	var seed [mldsa87.SeedSize]byte
	for i := range seed {
		seed[i] = b
	}
	k, err := mldsa87.FromSeed48(&seed)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Zeroize()
	return k.PublicKey()
}

var strict = secretfile.Policy{Strict: true}

func writeFile(t *testing.T, dir, name, content string, mode fs.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// backdate moves a file's modification time out of the racy window, as for
// a file written long before the load.
func backdate(t *testing.T, paths ...string) {
	t.Helper()
	old := time.Now().Add(-time.Hour)
	for _, p := range paths {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		keys []byte // seed bytes of the expected keys
		err  error
	}{
		{"file-raw", "type: file-raw\nkeyType: ML_DSA_87\nprivateKey: \"" + seedHex(1) + "\"\n", []byte{1}, nil},
		{"default keyType, unquoted, no prefix", "type: file-raw\nprivateKey: " + seedHex(2)[2:] + "\n", []byte{2}, nil},
		{"unquoted with prefix", "type: file-raw\nprivateKey: " + seedHex(3) + "\n", []byte{3}, nil},
		{"multi-document", "type: file-raw\nprivateKey: " + seedHex(1) + "\n---\ntype: file-raw\nprivateKey: " + seedHex(2) + "\n---\n", []byte{1, 2}, nil},
		{"unknown key", "type: file-raw\nprivateKey: " + seedHex(1) + "\npassword: x\n", nil, ErrFormat},
		{"duplicate key", "type: file-raw\nprivateKey: " + seedHex(1) + "\nprivateKey: " + seedHex(2) + "\n", nil, ErrFormat},
		{"missing type", "privateKey: " + seedHex(1) + "\n", nil, ErrFormat},
		{"missing privateKey", "type: file-raw\n", nil, ErrFormat},
		{"not a mapping", "- a\n- b\n", nil, ErrFormat},
		{"nested value", "type: file-raw\nprivateKey: {a: b}\n", nil, ErrFormat},
		{"invalid YAML", "type: [\n", nil, ErrFormat},
		{"empty", "", nil, ErrFormat},
		{"keystore without keystoreFile", "type: file-keystore\nkeystorePasswordFile: p.txt\n", nil, ErrFormat},
		{"keystore without password file", "type: file-keystore\nkeystoreFile: k.json\n", nil, ErrFormat},
		{"keystore with privateKey", "type: file-keystore\nkeystoreFile: k.json\nkeystorePasswordFile: p.txt\nprivateKey: " + seedHex(1) + "\n", nil, ErrFormat},
		{"raw with keystoreFile", "type: file-raw\nprivateKey: " + seedHex(1) + "\nkeystoreFile: k.json\n", nil, ErrFormat},
		{"unknown type", "type: hashicorp\n", nil, ErrUnsupported},
		{"BLS", "type: file-raw\nkeyType: BLS\nprivateKey: " + seedHex(1) + "\n", nil, ErrUnsupported},
		{"32 bytes", "type: file-raw\nprivateKey: 0x" + strings.Repeat("ab", 32) + "\n", nil, ErrPrivateKey},
		{"51 bytes", "type: file-raw\nprivateKey: 0x" + strings.Repeat("ab", 51) + "\n", nil, ErrPrivateKey},
		{"4896 bytes", "type: file-raw\nprivateKey: 0x" + strings.Repeat("ab", 4896) + "\n", nil, ErrPrivateKey},
		{"not hex", "type: file-raw\nprivateKey: 0x" + strings.Repeat("zz", 48) + "\n", nil, ErrPrivateKey},
		{"one bad document fails the file", "type: file-raw\nprivateKey: " + seedHex(1) + "\n---\ntype: file-raw\n", nil, ErrFormat},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			p := writeFile(t, dir, "k.yaml", tt.yaml, 0o600)
			keys, err := Config{Dir: dir, Policy: strict}.LoadFile(context.Background(), p)
			if !errors.Is(err, tt.err) {
				t.Fatalf("LoadFile error = %v, want %v", err, tt.err)
			}
			if err != nil {
				if strings.Contains(err.Error(), "abab") || strings.Contains(err.Error(), "0101") {
					t.Fatalf("error leaks key material: %v", err)
				}
				return
			}
			if len(keys) != len(tt.keys) {
				t.Fatalf("%d keys, want %d", len(keys), len(tt.keys))
			}
			for i, b := range tt.keys {
				if keys[i].PublicKey() != pubkeyOf(t, b) {
					t.Errorf("key %d is not the key of seed %#x", i, b)
				}
				keys[i].Zeroize()
			}
		})
	}
}

// A key of another common length is refused with a message that says what
// it is, so that an execution key's extended seed, or a raw secret key, is
// recognised for what it is (docs/operations/requirements.md section 2).
func TestPrivateKeyLengthHints(t *testing.T) {
	for _, tt := range []struct {
		bytes int
		want  string
	}{
		{32, "32 bytes; a QRL consensus key is the validator's 48-byte wallet seed"},
		{51, "a 51-byte extended seed belongs to execution mode"},
		{4896, "a 4,896-byte ML-DSA-87 secret key is not accepted"},
		{47, "want a 48-byte seed"},
	} {
		dir := t.TempDir()
		p := writeFile(t, dir, "k.yaml", "type: file-raw\nprivateKey: 0x"+strings.Repeat("ab", tt.bytes)+"\n", 0o600)
		_, err := Config{Dir: dir, Policy: strict}.LoadFile(context.Background(), p)
		if !errors.Is(err, ErrPrivateKey) || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%d bytes: %v, want %v saying %q", tt.bytes, err, ErrPrivateKey, tt.want)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) { writeFile(t, dir, name, content, 0o600) }
	write("b.yaml", "type: file-raw\nprivateKey: "+seedHex(2)+"\n")
	write("a.YML", "type: file-raw\nprivateKey: "+seedHex(1)+"\n")
	write("bad.yaml", "type: file-raw\n")
	write(".hidden.yaml", "type: file-raw\nprivateKey: "+seedHex(3)+"\n")
	write("notes.txt", "ignored")
	if err := os.Mkdir(filepath.Join(dir, "sub.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	write("sub.yaml/c.yaml", "type: file-raw\nprivateKey: "+seedHex(4)+"\n")
	if err := os.Symlink(filepath.Join(dir, "gone.yaml"), filepath.Join(dir, "dangling.yaml")); err != nil {
		t.Fatal(err)
	}

	res, err := Config{Dir: dir, Policy: strict}.Load(context.Background(), 2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range res {
		names = append(names, filepath.Base(strings.TrimPrefix(r.Source, SourcePrefix)))
	}
	if got := strings.Join(names, ","); got != "a.YML,b.yaml,bad.yaml,dangling.yaml" {
		t.Fatalf("loaded files %s", got)
	}
	// A file that cannot be stat'ed is a load error, not a removal.
	if res[3].Err == nil || len(res[3].Keys) != 0 {
		t.Errorf("dangling.yaml: %+v", res[3])
	}
	if res[0].Err != nil || len(res[0].Keys) != 1 || res[0].Keys[0].PublicKey() != pubkeyOf(t, 1) {
		t.Errorf("a.YML: %+v", res[0])
	}
	if res[2].Err == nil || len(res[2].Keys) != 0 || !strings.Contains(res[2].Err.Error(), "bad.yaml") {
		t.Errorf("bad.yaml: %+v", res[2])
	}

	if _, err := (Config{Dir: filepath.Join(dir, "missing")}).Load(context.Background(), 1, nil, nil); err == nil {
		t.Error("Load of a missing directory succeeded")
	}
	// Files not reached before the context ends fail on their own, so that
	// they keep their previous keys.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err = Config{Dir: dir, Policy: strict}.Load(ctx, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if !errors.Is(r.Err, context.Canceled) && !strings.Contains(filepath.Base(r.Source), "bad") &&
			!strings.Contains(r.Source, "dangling") {
			t.Errorf("%s with a cancelled context: %+v", r.Source, r)
		}
	}
}

// A key-config file larger than MaxFileSize fails to load on its own; the
// others still load, and 0 means the 100 MiB default.
func TestMaxFileSize(t *testing.T) {
	dir := t.TempDir()
	small := "type: file-raw\nprivateKey: " + seedHex(1) + "\n"
	writeFile(t, dir, "a.yaml", small, 0o600)
	writeFile(t, dir, "b.yaml", small+"# "+strings.Repeat("x", 64)+"\n", 0o600)
	res, err := Config{Dir: dir, Policy: strict, MaxFileSize: int64(len(small))}.Load(context.Background(), 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Err != nil || len(res[0].Keys) != 1 {
		t.Fatalf("a file at the limit: %+v", res[0])
	}
	if !errors.Is(res[1].Err, secretfile.ErrTooLarge) || len(res[1].Keys) != 0 ||
		!strings.Contains(res[1].Err.Error(), "b.yaml") {
		t.Fatalf("a file over the limit: %+v", res[1])
	}
	res, err = Config{Dir: dir, Policy: strict}.Load(context.Background(), 1, nil, nil)
	if err != nil || res[1].Err != nil || DefaultMaxFileSize != 104_857_600 {
		t.Fatalf("default limit: %v %+v", err, res)
	}
}

// A file-keystore document names a keystore and its password file,
// relative to the key-config directory or absolute; the keystore is opened
// through Decrypt.
func TestFileKeystore(t *testing.T) {
	dir := t.TempDir()
	sealer, err := keystoretest.NewSealer("p@ss", keystoretest.Cheapest)
	if err != nil {
		t.Fatal(err)
	}
	seed := keystoretest.Seed("keyconfig", 0)
	ks, err := sealer.DepositCLI(seed, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "ks"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "ks/k.json", string(ks), 0o600)
	pw := writeFile(t, t.TempDir(), "k.txt", "p@ss\n", 0o600)
	writeFile(t, dir, "k.yaml", "type: file-keystore\nkeyType: ML_DSA_87\nkeystoreFile: ks/k.json\nkeystorePasswordFile: "+pw+"\n", 0o644)
	want, _ := keystoretest.PublicKeyHex(seed)

	sem := argon.New(2, 0)
	c := Config{Dir: dir, Policy: strict, Decrypt: sem.Decrypt}
	keys, err := c.LoadFile(context.Background(), filepath.Join(dir, "k.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if pk := keys[0].PublicKey(); hex.EncodeToString(pk[:]) != want {
		t.Fatal("the file-keystore document gave another key")
	}
	// The batch records that the key came from a keystore, with the
	// derivation path the keystore records (the keymanager lists both).
	res, err := c.Load(context.Background(), 1, nil, nil)
	if err != nil || len(res) != 1 || res[0].Err != nil {
		t.Fatalf("Load: %v %+v", err, res)
	}
	if m := res[0].Meta; len(m) != 1 || m[0] != (provider.Meta{DerivationPath: keystoretest.DepositPath(0), Keystore: true}) {
		t.Fatalf("meta %+v", m)
	}
	zeroize(res[0].Keys)

	// A world-readable YAML of keystore references is not a secret, but a
	// world-readable password file is refused under the strict policy.
	if err := os.Chmod(pw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.LoadFile(context.Background(), filepath.Join(dir, "k.yaml")); !errors.Is(err, secretfile.ErrInsecure) {
		t.Fatalf("world-readable password file: %v", err)
	}
	var warned []string
	lax := Config{Dir: dir, Policy: secretfile.Policy{Warn: func(p string, _ fs.FileMode) { warned = append(warned, p) }},
		Decrypt: sem.Decrypt}
	if _, err := lax.LoadFile(context.Background(), filepath.Join(dir, "k.yaml")); err != nil || len(warned) == 0 {
		t.Fatalf("lax policy: %v, warned %v", err, warned)
	}
	if err := os.Chmod(pw, 0o600); err != nil {
		t.Fatal(err)
	}

	// Without a decryptor the type is refused; a wrong password is a load
	// error that names the keystore.
	if _, err := (Config{Dir: dir, Policy: strict}).LoadFile(context.Background(), filepath.Join(dir, "k.yaml")); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("no decryptor: %v", err)
	}
	if err := os.WriteFile(pw, []byte("wrong"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.LoadFile(context.Background(), filepath.Join(dir, "k.yaml")); err == nil || !strings.Contains(err.Error(), "wrong password") ||
		!strings.Contains(err.Error(), "k.json") {
		t.Fatalf("wrong password: %v", err)
	}
}

// A key-config file with a seed is a secret file: refused when group- or
// world-readable under the strict policy, loaded with a warning otherwise.
func TestFileRawPermissions(t *testing.T) {
	dir := t.TempDir()
	p := writeFile(t, dir, "k.yaml", "type: file-raw\nprivateKey: "+seedHex(1)+"\n", 0o640)
	if _, err := (Config{Dir: dir, Policy: strict}).LoadFile(context.Background(), p); !errors.Is(err, secretfile.ErrInsecure) {
		t.Fatalf("group-readable seed file: %v", err)
	}
	warned := 0
	keys, err := Config{Dir: dir, Policy: secretfile.Policy{Warn: func(string, fs.FileMode) { warned++ }}}.LoadFile(context.Background(), p)
	if err != nil || len(keys) != 1 || warned != 1 {
		t.Fatalf("lax policy: %d keys, %v, %d warnings", len(keys), err, warned)
	}
}

// A file whose content and referenced files are unchanged is kept without
// deriving its keys again; a changed one is loaded again. A file modified
// within the racy window gets no version.
func TestLoadUnchanged(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, dir, "a.yaml", "type: file-raw\nprivateKey: "+seedHex(1)+"\n", 0o600)
	b := writeFile(t, dir, "b.yaml", "type: file-raw\nprivateKey: "+seedHex(2)+"\n", 0o600)
	backdate(t, a)
	c := Config{Dir: dir, Policy: strict}
	quiet := logrus.New()
	quiet.SetOutput(io.Discard)
	p := provider.New(quiet)
	apply := func(batches []provider.Batch) provider.Delta {
		t.Helper()
		d, err := p.Apply(batches, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	unchanged := func(src, v string) bool { return p.Unchanged(src, v, nil) }
	res, err := c.Load(context.Background(), 2, unchanged, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Version == "" || res[1].Version != "" {
		t.Fatalf("versions %q, %q: a backdated file has one, a fresh one has none", res[0].Version, res[1].Version)
	}
	apply(res)

	res, err = c.Load(context.Background(), 2, unchanged, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res[0].Keep || len(res[0].Keys) != 0 || res[1].Keep || len(res[1].Keys) != 1 {
		t.Fatalf("second load: %+v / %+v", res[0], res[1])
	}
	if d := apply(res); d.Unchanged != 1 {
		t.Fatalf("delta %+v", d)
	}

	// Rewriting a.yaml with another key changes its version.
	writeFile(t, dir, "a.yaml", "type: file-raw\nprivateKey: "+seedHex(3)+"\n", 0o600)
	backdate(t, b)
	old := time.Now().Add(-30 * time.Minute)
	if err := os.Chtimes(a, old, old); err != nil {
		t.Fatal(err)
	}
	res, err = c.Load(context.Background(), 2, unchanged, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Keep || len(res[0].Keys) != 1 || res[0].Keys[0].PublicKey() != pubkeyOf(t, 3) {
		t.Fatalf("a changed file was not loaded again: %+v", res[0])
	}
	apply(res)
	if p.Len() != 2 {
		t.Fatalf("%d keys", p.Len())
	}
}
