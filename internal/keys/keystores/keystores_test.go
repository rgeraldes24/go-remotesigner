// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package keystores

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/argon"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystore/qrlv1"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// fixture writes deposit CLI keystores with the cheapest KDF, one sealer
// per password.
type fixture struct {
	sealers map[string]*keystoretest.Sealer
	kdf     qrlv1.KDF
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return &fixture{sealers: map[string]*keystoretest.Sealer{}, kdf: keystoretest.Cheapest}
}

type written struct {
	name   string // file name in the keystore directory
	pubkey string // hex, no 0x
}

// keystore writes key i's keystore into ksDir and, when pwDir is set, its
// password file <stem>.txt into pwDir.
func (f *fixture) keystore(t *testing.T, ksDir, pwDir string, i int, password string) written {
	t.Helper()
	s, ok := f.sealers[password]
	if !ok {
		var err error
		if s, err = keystoretest.NewSealer(password, f.kdf); err != nil {
			t.Fatal(err)
		}
		f.sealers[password] = s
	}
	seed := keystoretest.Seed(t.Name(), i)
	data, err := s.DepositCLI(seed, i, true)
	if err != nil {
		t.Fatal(err)
	}
	name := keystoretest.DepositFileName(i, 1760000000)
	writeSecret(t, ksDir, name, string(data))
	if pwDir != "" {
		writeSecret(t, pwDir, strings.TrimSuffix(name, ".json")+".txt", password+"\n")
	}
	pk, err := keystoretest.PublicKeyHex(seed)
	if err != nil {
		t.Fatal(err)
	}
	return written{name: name, pubkey: pk}
}

func writeSecret(t *testing.T, dir, name, content string) string {
	t.Helper()
	p, err := keystoretest.WriteFile(dir, name, []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// withDefaults fills the strict policy and a decryptor in c.
func withDefaults(c Config) Config {
	if c.Decrypt == nil {
		c.Decrypt = argon.New(4, 0).Decrypt
	}
	if !c.Policy.Strict && c.Policy.Warn == nil {
		c.Policy.Strict = true
	}
	return c
}

func mustLoad(t *testing.T, c Config) []provider.Batch {
	t.Helper()
	res, err := withDefaults(c).Load(context.Background(), 4, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func pubkeyHex(k *mldsa87.Key) string {
	pk := k.PublicKey()
	return hex.EncodeToString(pk[:])
}

func assertKeys(t *testing.T, res []provider.Batch, want ...written) {
	t.Helper()
	var got, exp []string
	for _, b := range res {
		for _, k := range b.Keys {
			got = append(got, pubkeyHex(k))
		}
	}
	for _, w := range want {
		exp = append(exp, w.pubkey)
	}
	slices.Sort(got)
	slices.Sort(exp)
	if !slices.Equal(got, exp) {
		t.Fatalf("loaded %d keys, want %d (or other keys)", len(got), len(exp))
	}
}

func assertErrors(t *testing.T, res []provider.Batch, want int) {
	t.Helper()
	n := 0
	for _, b := range res {
		if b.Err != nil {
			n++
		}
	}
	if n != want {
		t.Fatalf("%d failed batches, want %d", n, want)
	}
}

func quiet() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func backdate(t *testing.T, dir string) {
	t.Helper()
	old := time.Now().Add(-time.Hour)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.Chtimes(filepath.Join(dir, e.Name()), old, old); err != nil {
			t.Fatal(err)
		}
	}
}

// The layout qrl-package gives the signer for one participant: the deposit
// CLI's keystore-*.json files copied into one directory, and the shared
// password file the deposit CLI was given ("password" and a line feed, as
// echo writes it), every file 0600 in 0700 directories. One keystore is
// the deposit CLI's own output (the golden vector), the others are written
// in the same format; all of them load and give the keys their pubkeys
// declare.
func TestDepositCLILayout(t *testing.T) {
	root := t.TempDir()
	ksDir := filepath.Join(root, "keystores")
	if err := os.Mkdir(ksDir, 0o700); err != nil {
		t.Fatal(err)
	}
	var golden vectors.KeystoreCase
	for _, c := range vectors.Keystores(t) {
		if c.File == "deposit-cli-light.json" {
			golden = c
		}
	}
	if golden.File == "" {
		t.Fatal("no deposit-cli-light.json vector")
	}
	writeSecret(t, ksDir, keystoretest.DepositFileName(0, 1760000000),
		string(vectors.Raw(t, "keystores/deposit-cli-light.json")))
	f := newFixture(t)
	f.kdf = keystoretest.Light
	want := []written{{pubkey: strings.TrimPrefix(golden.Pubkey, "0x")}}
	for i := 1; i <= 3; i++ {
		want = append(want, f.keystore(t, ksDir, "", i, golden.Password))
	}
	pw := writeSecret(t, root, "password.txt", golden.Password+"\n")

	// The files are the deposit CLI's: compact JSON, version 0, 0x pubkey.
	data, err := os.ReadFile(filepath.Join(ksDir, keystoretest.DepositFileName(1, 1760000000)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "\n") || !strings.Contains(string(data), `"pubkey":"0x`) ||
		!strings.Contains(string(data), `"version":0`) || !strings.Contains(string(data), `"checksum":null`) {
		t.Fatalf("not the deposit CLI's format: %.200s", data)
	}
	res := mustLoad(t, Config{Dir: ksDir, PasswordFile: pw})
	assertErrors(t, res, 0)
	assertKeys(t, res, want...)
}

// A keystore whose password file and keystore are unchanged is kept
// without a decrypt. A password file made world-readable is refused on the
// next load, which fails that keystore only (its key stays with the
// provider); once the mode is fixed, it is kept unchanged again.
func TestReloadUnchangedAndPermissions(t *testing.T) {
	ksDir, pwDir := t.TempDir(), t.TempDir()
	f := newFixture(t)
	a := f.keystore(t, ksDir, pwDir, 1, "pa")
	f.keystore(t, ksDir, pwDir, 2, "pb")
	backdate(t, ksDir)
	backdate(t, pwDir)
	var decrypts atomic.Int64
	sem := argon.New(4, 0)
	c := withDefaults(Config{Dir: ksDir, PasswordsDir: pwDir, Decrypt: func(ctx context.Context, ks *qrlv1.Keystore,
		pw *qrlv1.Password) (*mldsa87.Key, error) {
		decrypts.Add(1)
		return sem.Decrypt(ctx, ks, pw)
	}})
	p := provider.New(quiet())
	load := func() []provider.Batch {
		t.Helper()
		res, err := c.Load(context.Background(), 2, func(src, v string) bool { return p.Unchanged(src, v, nil) }, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Apply(res, nil, nil); err != nil {
			t.Fatal(err)
		}
		return res
	}
	load()
	if decrypts.Load() != 2 || p.Len() != 2 {
		t.Fatalf("first load: %d decrypts, %d keys", decrypts.Load(), p.Len())
	}
	res := load()
	if decrypts.Load() != 2 || !res[0].Keep || !res[1].Keep {
		t.Fatalf("unchanged reload decrypted: %d decrypts", decrypts.Load())
	}

	pwA := filepath.Join(pwDir, strings.TrimSuffix(a.name, ".json")+".txt")
	if err := os.Chmod(pwA, 0o644); err != nil {
		t.Fatal(err)
	}
	res = load()
	if !errors.Is(res[0].Err, secretfile.ErrInsecure) || res[1].Err != nil || p.Len() != 2 {
		t.Fatalf("world-readable password file: %v / %v, %d keys", res[0].Err, res[1].Err, p.Len())
	}
	if err := os.Chmod(pwA, 0o600); err != nil {
		t.Fatal(err)
	}
	res = load()
	if !res[0].Keep || decrypts.Load() != 2 {
		t.Fatalf("after fixing the mode: keep=%v, %d decrypts", res[0].Keep, decrypts.Load())
	}

	// A new password file is a new version: the keystore is decrypted again.
	if err := os.WriteFile(pwA, []byte("pa"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(pwA, old, old); err != nil {
		t.Fatal(err)
	}
	res = load()
	if res[0].Keep || res[0].Err != nil || decrypts.Load() != 3 {
		t.Fatalf("after a password change: %+v, %d decrypts", res[0], decrypts.Load())
	}
}

// The shared password file applies to every keystore: refused or missing,
// the loader fails as a whole.
func TestSharedPasswordFile(t *testing.T) {
	dir := t.TempDir()
	ksDir := filepath.Join(dir, "keystores")
	if err := os.Mkdir(ksDir, 0o700); err != nil {
		t.Fatal(err)
	}
	f := newFixture(t)
	f.keystore(t, ksDir, "", 1, "shared")
	pw := writeSecret(t, dir, "password.txt", "shared\r\n")
	if err := os.Chmod(pw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := withDefaults(Config{Dir: ksDir, PasswordFile: pw}).Load(context.Background(), 1, nil, nil); !errors.Is(err, secretfile.ErrInsecure) {
		t.Fatalf("world-readable shared password file: %v", err)
	}
	// Without the strict policy it loads with a warning.
	warned := 0
	res, err := withDefaults(Config{Dir: ksDir, PasswordFile: pw,
		Policy: secretfile.Policy{Warn: func(string, os.FileMode) { warned++ }}}).Load(context.Background(), 1, nil, nil)
	if err != nil || len(res) != 1 || res[0].Err != nil || warned == 0 {
		t.Fatalf("lax policy: %v %+v, %d warnings", err, res, warned)
	}
	if err := os.Chmod(pw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pw, []byte("not it"), 0o600); err != nil {
		t.Fatal(err)
	}
	res = mustLoad(t, Config{Dir: ksDir, PasswordFile: pw})
	if !errors.Is(res[0].Err, qrlv1.ErrPassword) {
		t.Fatalf("wrong shared password: %v", res[0].Err)
	}
	var fe *FileError
	if !errors.As(res[0].Err, &fe) || filepath.Base(fe.Path) != keystoretest.DepositFileName(1, 1760000000) {
		t.Fatalf("the error does not name the keystore: %v", res[0].Err)
	}
}

func TestFiles(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"b.json", "A.JSON", ".hidden.json", "notes.txt", "deposit_data-1.json"} {
		writeSecret(t, dir, n, "{}")
	}
	if err := os.Mkdir(filepath.Join(dir, "sub.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "gone.json"), filepath.Join(dir, "dangling.json")); err != nil {
		t.Fatal(err)
	}
	files, err := Files(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range files {
		names = append(names, filepath.Base(p))
	}
	if got := strings.Join(names, ","); got != "A.JSON,b.json,dangling.json,deposit_data-1.json" {
		t.Fatalf("Files = %s", got)
	}
	if got := PasswordFileFor("/pw", "/ks/keystore-m_12381_3600_0_0_0-1.json"); got != "/pw/keystore-m_12381_3600_0_0_0-1.txt" {
		t.Fatalf("PasswordFileFor = %s", got)
	}
	if got := Path(Source("/ks/a.json")); got != "/ks/a.json" {
		t.Fatalf("Path(Source) = %s", got)
	}
}

// Keystores not reached before the context ends fail one by one, so that
// each keeps its previous key.
func TestLoadCancelled(t *testing.T) {
	ksDir, pwDir := t.TempDir(), t.TempDir()
	f := newFixture(t)
	f.keystore(t, ksDir, pwDir, 1, "p")
	f.keystore(t, ksDir, pwDir, 2, "p")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := withDefaults(Config{Dir: ksDir, PasswordsDir: pwDir}).Load(ctx, 1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range res {
		if !errors.Is(b.Err, context.Canceled) || len(b.Keys) != 0 {
			t.Fatalf("%s: %+v", b.Source, b)
		}
	}
}
