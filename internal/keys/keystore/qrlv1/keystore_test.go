// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package qrlv1

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/logging"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// refusalBudget bounds what a refused keystore may allocate: parsing the
// JSON, never an Argon2id memory block (at least MinM KiB).
const refusalBudget = 1 << 20

// lightVector returns the light qrl-v1 golden keystore and its password.
func lightVector(t testing.TB) ([]byte, string) {
	t.Helper()
	for _, c := range vectors.Keystores(t) {
		if c.File == "qrl-v1-light.json" {
			return vectors.Raw(t, "keystores/"+c.File), c.Password
		}
	}
	t.Fatal("no qrl-v1-light.json in index.json")
	return nil, ""
}

// TestPolicyRefusals covers the structure and KDF policy: each keystore is
// refused by Parse, before any Argon2id run, without a panic and without a
// large allocation.
func TestPolicyRefusals(t *testing.T) {
	base, password := lightVector(t)
	hexOf := func(n int) string { return strings.Repeat("ab", n) }
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"no KDF", edit(t, base, "crypto.kdf", deleteField), ErrPolicy},
		{"null KDF", edit(t, base, "crypto.kdf", nil), ErrPolicy},
		{"m=2^31", edit(t, base, "crypto.kdf.params.m", 1<<31), ErrPolicy},
		{"m=2^32-1", edit(t, base, "crypto.kdf.params.m", 1<<32-1), ErrPolicy},
		{"m above the standard KDF", edit(t, base, "crypto.kdf.params.m", MaxM+1), ErrPolicy},
		{"m below the light KDF", edit(t, base, "crypto.kdf.params.m", MinM-1), ErrPolicy},
		{"m negative", edit(t, base, "crypto.kdf.params.m", -1), ErrPolicy},
		{"m beyond int64", edit(t, base, "crypto.kdf.params.m", 1e30), ErrFormat},
		{"IV of 11 bytes", edit(t, base, "crypto.cipher.params.iv", hexOf(11)), ErrFormat},
		{"IV of 13 bytes", edit(t, base, "crypto.cipher.params.iv", hexOf(13)), ErrFormat},
		{"IV of 0 bytes", edit(t, base, "crypto.cipher.params.iv", ""), ErrFormat},
		{"IV not hex", edit(t, base, "crypto.cipher.params.iv", strings.Repeat("zz", 12)), ErrFormat},
		{"p=256", edit(t, base, "crypto.kdf.params.p", 256), ErrPolicy},
		{"p=0", edit(t, base, "crypto.kdf.params.p", 0), ErrPolicy},
		{"p=5", edit(t, base, "crypto.kdf.params.p", MaxP+1), ErrPolicy},
		{"t=0", edit(t, base, "crypto.kdf.params.t", 0), ErrPolicy},
		{"t=17", edit(t, base, "crypto.kdf.params.t", MaxT+1), ErrPolicy},
		{"dklen=0", edit(t, base, "crypto.kdf.params.dklen", 0), ErrPolicy},
		{"dklen=16", edit(t, base, "crypto.kdf.params.dklen", 16), ErrPolicy},
		{"dklen=2^31", edit(t, base, "crypto.kdf.params.dklen", 1<<31), ErrPolicy},
		{"unsupported KDF", edit(t, base, "crypto.kdf.function", "scrypt"), ErrPolicy},
		{"null KDF params", edit(t, base, "crypto.kdf.params", nil), ErrFormat},
		{"salt of the wrong type", edit(t, base, "crypto.kdf.params.salt", 12345), ErrFormat},
		{"salt of 8 bytes", edit(t, base, "crypto.kdf.params.salt", hexOf(8)), ErrPolicy},
		{"salt of 65 bytes", edit(t, base, "crypto.kdf.params.salt", hexOf(65)), ErrPolicy},
		{"salt not hex", edit(t, base, "crypto.kdf.params.salt", strings.Repeat("zz", 32)), ErrFormat},
		{"no cipher", edit(t, base, "crypto.cipher", deleteField), ErrFormat},
		{"unsupported cipher", edit(t, base, "crypto.cipher.function", "aes-128-ctr"), ErrPolicy},
		{"null cipher params", edit(t, base, "crypto.cipher.params", nil), ErrFormat},
		{"ciphertext of 63 bytes", edit(t, base, "crypto.cipher.message", hexOf(63)), ErrFormat},
		{"ciphertext of 67 bytes", edit(t, base, "crypto.cipher.message", hexOf(67)), ErrFormat},
		{"no crypto", edit(t, base, "crypto", deleteField), ErrFormat},
		{"version 2", edit(t, base, "version", 2), ErrPolicy},
		{"version as a string", edit(t, base, "version", "1"), ErrFormat},
		{"no version", edit(t, base, "version", deleteField), ErrFormat},
		{"pubkey of 11 characters", edit(t, base, "pubkey", "0123456789a"), ErrFormat},
		{"pubkey not hex", edit(t, base, "pubkey", strings.Repeat("zz", 2592)), ErrFormat},
		{"pubkey with a path", edit(t, base, "pubkey", "../../etc/passwd"), ErrFormat},
		{"not JSON", []byte("not a keystore"), ErrFormat},
		{"JSON array", []byte("[1, 2]"), ErrFormat},
		{"data after the object", append(bytes.Clone(base), []byte(" {}")...), ErrFormat},
		{"closing brace after the object", append(bytes.Clone(base), '}'), ErrFormat},
		{"closing bracket after the object", append(bytes.Clone(base), ']'), ErrFormat},
		{"JSON null", []byte("null"), ErrFormat},
		{"larger than MaxSize", append(bytes.Clone(base), bytes.Repeat([]byte(" "), MaxSize)...), ErrFormat},
		{"empty", nil, ErrFormat},
	}
	pw := NewPassword([]byte(password))
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var err error
			n := allocated(func() { _, err = Decrypt(c.data, pw) })
			if !errors.Is(err, c.want) {
				t.Fatalf("error %v, want %v", err, c.want)
			}
			t.Logf("%v; allocated %d bytes", err, n)
			if n > refusalBudget {
				t.Errorf("allocated %d bytes, want at most %d", n, refusalBudget)
			}
		})
	}
}

// TestMetadataFields checks what Parse keeps of the fields that GCM does
// not authenticate and that the signer prints: path only when it is a
// derivation path, uuid and description without control or format
// characters, so that a keystore edited without its password cannot put
// terminal escapes or line breaks into keystore verify's output or a log.
func TestMetadataFields(t *testing.T) {
	base, _ := lightVector(t)
	for _, c := range []struct{ field, in, want string }{
		{"path", "m/12381/238/0/0", "m/12381/238/0/0"},
		{"path", "m/12381'/238'/0", "m/12381'/238'/0"},
		{"path", "m", "m"},
		{"path", "", ""},
		{"path", "\x1b[2K\x1b[1A\x1b[17G" + strings.Repeat("f", 40), ""},
		{"path", "m/12381\x1b[31mRED\x1b[0m\nkeystore-0.json: OK", ""},
		{"path", "m/12381/238/0/0\n", ""},
		{"path", "m/12381/238/0/0 ", ""},
		{"path", "m/1/2/3/4/5/6/7/8/9/10/11", ""},
		{"path", "m/12345678901", ""},
		{"path", "M/12381", ""},
		{"path", "m/-1", ""},
		{"uuid", "00000000-0000-4000-8000-00000000000b", "00000000-0000-4000-8000-00000000000b"},
		{"uuid", "abc\x1b[2Jdef\r\n", "abc[2Jdef"},
		{"description", "keystore", "keystore"},
		{"description", "a b", "a b"},
		{"description", "pässwörd\u202eevil\u200b\u00a0\x7f\u0085\tx", "pässwördevilx"},
		{"description", strings.Repeat("é", 40), strings.Repeat("é", 32) + "…"},
	} {
		ks, err := Parse(edit(t, base, c.field, c.in))
		if err != nil {
			t.Fatalf("%s %q: %v", c.field, c.in, err)
		}
		got := map[string]string{"path": ks.Path, "uuid": ks.UUID, "description": ks.Description}[c.field]
		if got != c.want {
			t.Errorf("%s %q: kept %q, want %q", c.field, c.in, got, c.want)
		}
	}
}

// TestDecryptRefusals covers the refusals that need the KDF: a tampered
// ciphertext, a pubkey that belongs to another key and a wrong password.
// Each costs Argon2id at the keystore's own, bounded parameters.
func TestDecryptRefusals(t *testing.T) {
	base, password := lightVector(t)
	ks, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	budget := uint64(ks.KDF.M)<<10 + 2<<20 // the Argon2id block plus key derivation

	flip := func(i int) string {
		msg := ks.sealed.message
		msg[i] ^= 1
		return hex.EncodeToString(msg[:])
	}
	var otherPK string // a pubkey of another key: the unicode vector's
	for _, c := range vectors.Keystores(t) {
		if c.File == "qrl-v1-light-unicode.json" {
			otherPK = c.Pubkey
		}
	}

	cases := []struct {
		name     string
		data     []byte
		password string
		want     error
	}{
		{"GCM tag tampered", edit(t, base, "crypto.cipher.message", flip(48+tagSize-1)), password, ErrPassword},
		{"ciphertext tampered", edit(t, base, "crypto.cipher.message", flip(0)), password, ErrPassword},
		{"pubkey of another key", edit(t, base, "pubkey", strings.TrimPrefix(otherPK, "0x")), password, ErrPubkeyMismatch},
		{"pubkey of another key with 0x", edit(t, base, "pubkey", otherPK), password, ErrPubkeyMismatch},
		{"wrong password", base, password + "!", ErrPassword},
		{"empty password", base, "", ErrPassword},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var (
				key interface{ Zeroize() }
				err error
			)
			n := allocated(func() {
				k, e := Decrypt(c.data, NewPassword([]byte(c.password)))
				if k != nil {
					key = k
				}
				err = e
			})
			if key != nil {
				key.Zeroize()
				t.Fatal("got a key")
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("error %v, want %v", err, c.want)
			}
			t.Logf("%v; allocated %d bytes", err, n)
			if n > budget {
				t.Errorf("allocated %d bytes, want at most %d", n, budget)
			}
			if strings.Contains(err.Error(), strings.TrimPrefix(otherPK, "0x")[:32]) {
				t.Error("the error quotes the public key in full")
			}
		})
	}
}

// TestDecryptRecoversPanics checks the recover in Decrypt: a sealed
// section that skipped the policy, with t or p of 0, makes Argon2id panic,
// and Decrypt turns the panic into ErrInternal instead of ending the
// process. Parse never builds such a section (TestPolicyRefusals).
func TestDecryptRecoversPanics(t *testing.T) {
	base, password := lightVector(t)
	ks, err := Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	for name, kdf := range map[string]KDF{
		"t=0": {T: 0, M: MinM, P: 1},
		"p=0": {T: 1, M: MinM, P: 0},
	} {
		t.Run(name, func(t *testing.T) {
			s := *ks.sealed
			s.kdf = kdf
			bad := &Keystore{Flavour: ks.Flavour, sealed: &s}
			key, err := bad.Decrypt(NewPassword([]byte(password)))
			if key != nil {
				key.Zeroize()
				t.Fatal("got a key")
			}
			if !errors.Is(err, ErrInternal) || !strings.Contains(err.Error(), "argon2") {
				t.Fatalf("error %v, want ErrInternal from the recovered argon2 panic", err)
			}
		})
	}
}

// TestFlavourShapes decrypts keystores of both shapes with the pubkey
// field bare, 0x-prefixed or absent.
func TestFlavourShapes(t *testing.T) {
	seed := testSeed(t, 2)
	pk := pubkeyHex(t, seed)
	for _, f := range []Flavour{QRLV1, DepositCLI} {
		data := encode(t, seal(t, f, lightKDF, []byte("password"), seed))
		for name, d := range map[string][]byte{
			"as written": data,
			"bare":       edit(t, data, "pubkey", pk),
			"0x":         edit(t, data, "pubkey", "0x"+pk),
			"absent":     edit(t, data, "pubkey", deleteField),
		} {
			t.Run(f.String()+"/"+name, func(t *testing.T) {
				ks, err := Parse(d)
				if err != nil {
					t.Fatal(err)
				}
				if ks.Flavour != f || ks.KDF != lightKDF {
					t.Fatalf("flavour %s KDF %+v", ks.Flavour, ks.KDF)
				}
				if _, declared := ks.PublicKey(); declared != (name != "absent") {
					t.Fatalf("declared pubkey present: %t", declared)
				}
				key, err := ks.Decrypt(NewPassword([]byte("password")))
				if err != nil {
					t.Fatal(err)
				}
				defer key.Zeroize()
				if got := key.PublicKey(); hex.EncodeToString(got[:]) != pk {
					t.Fatal("wrong key")
				}
			})
		}
	}
}

// TestPasswordForms decrypts keystores sealed with each candidate form of a
// non-ASCII password: the deposit CLI's raw bytes, qrysm's NFKD form and
// the alternative normalisation older keystores may carry.
func TestPasswordForms(t *testing.T) {
	seed := testSeed(t, 3)
	password := []byte("ÜnïcödéⅣ\x7f-pässwörd") // NFKD, the alternative form and raw all differ
	pw := NewPassword(password)
	if bytes.Equal(pw.norm, pw.raw) || bytes.Equal(pw.alt, pw.raw) || bytes.Equal(pw.norm, pw.alt) {
		t.Fatalf("the test password has fewer than three distinct forms: %q %q %q", pw.norm, pw.alt, pw.raw)
	}
	for _, c := range []struct {
		name   string
		f      Flavour
		sealed []byte
	}{
		{"deposit-cli raw", DepositCLI, pw.raw},
		{"deposit-cli NFKD", DepositCLI, pw.norm},
		{"qrl-v1 NFKD", QRLV1, pw.norm},
		{"qrl-v1 alternative", QRLV1, pw.alt},
		{"qrl-v1 raw", QRLV1, pw.raw},
	} {
		t.Run(c.name, func(t *testing.T) {
			key, err := Decrypt(encode(t, seal(t, c.f, lightKDF, c.sealed, seed)), NewPassword(password))
			if err != nil {
				t.Fatal(err)
			}
			key.Zeroize()
		})
	}
	// A file's trailing newline is not part of the password.
	key, err := Decrypt(encode(t, seal(t, QRLV1, lightKDF, pw.norm, seed)), NewPassword(TrimPassword(append(bytes.Clone(password), "\r\n"...))))
	if err != nil {
		t.Fatal(err)
	}
	key.Zeroize()
}

// TestCandidates checks the deduplicated candidate set and its order: an
// ASCII password is a single candidate, so it costs one Argon2id run, and
// each flavour tries its producer's form first.
func TestCandidates(t *testing.T) {
	if got := NewPassword([]byte("testpassword")).candidates(QRLV1); len(got) != 1 || string(got[0]) != "testpassword" {
		t.Fatalf("ASCII candidates %q", got)
	}
	pw := NewPassword([]byte("pässwörd"))
	qrl, dep := pw.candidates(QRLV1), pw.candidates(DepositCLI)
	if len(qrl) != 3 || len(dep) != 3 {
		t.Fatalf("%d and %d candidates, want 3", len(qrl), len(dep))
	}
	if !bytes.Equal(qrl[0], pw.norm) || !bytes.Equal(qrl[1], pw.alt) || !bytes.Equal(qrl[2], pw.raw) {
		t.Error("qrl-v1 order is not NFKD, alternative, raw")
	}
	if !bytes.Equal(dep[0], pw.raw) {
		t.Error("deposit-cli does not try the raw password first")
	}
	// Control characters are stripped from the normalised forms only.
	pw = NewPassword([]byte("pass\tword"))
	if got := pw.candidates(QRLV1); len(got) != 2 || string(got[0]) != "password" || string(got[1]) != "pass\tword" {
		t.Errorf("candidates %q", got)
	}
	if got := (*Password)(nil).candidates(QRLV1); got != nil {
		t.Errorf("nil password candidates %q", got)
	}
	if _, err := Decrypt(encode(t, seal(t, QRLV1, lightKDF, nil, testSeed(t, 0))), nil); !errors.Is(err, ErrPassword) {
		t.Errorf("nil password: %v", err)
	}
}

// TestPasswordWipe checks that Wipe zeroes every candidate in place and
// that a wiped password opens nothing.
func TestPasswordWipe(t *testing.T) {
	seed := testSeed(t, 4)
	password := []byte("pässwörd")
	pw := NewPassword(password)
	data := encode(t, seal(t, QRLV1, lightKDF, pw.norm, seed))
	key, err := Decrypt(data, pw)
	if err != nil {
		t.Fatal(err)
	}
	key.Zeroize()

	held := [][]byte{pw.norm, pw.alt, pw.raw}
	pw.Wipe()
	for i, b := range held {
		if len(b) == 0 || !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("candidate %d after Wipe: %q", i, b)
		}
	}
	if !bytes.Equal(password, []byte("pässwörd")) {
		t.Error("Wipe changed the caller's buffer, which NewPassword copied")
	}
	if got := pw.candidates(QRLV1); got != nil {
		t.Errorf("wiped password candidates %q", got)
	}
	if _, err := Decrypt(data, pw); !errors.Is(err, ErrPassword) {
		t.Errorf("wiped password: %v, want ErrPassword", err)
	}
	pw.Wipe()
	(*Password)(nil).Wipe()
}

// TestPasswordRedacted checks that a Password is a secret type: every fmt
// verb, on the pointer, the value or a field holding it, and log/slog print
// logging.Redacted, and marshalling it fails.
func TestPasswordRedacted(t *testing.T) {
	const secret = "hunter2-pässwörd"
	pw := NewPassword([]byte(secret))
	defer pw.Wipe()
	// The password as text, as hex and as a list of decimal bytes.
	leaks := []string{"hunter2", "68756e74657232", "104 117 110 116 101 114 50", "0x68, 0x75"}
	check := func(what, out string) {
		t.Helper()
		if !strings.Contains(out, logging.Redacted) {
			t.Errorf("%s = %q, want it to show %s", what, out, logging.Redacted)
		}
		for _, l := range leaks {
			if strings.Contains(out, l) {
				t.Errorf("%s = %q shows the password (%q)", what, out, l)
			}
		}
	}
	holder := struct{ Password *Password }{pw}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%10.3v"} {
		check("Sprintf("+verb+", pw)", fmt.Sprintf(verb, pw))
		check("Sprintf("+verb+", *pw)", fmt.Sprintf(verb, *pw))
		check("Sprintf("+verb+", holder)", fmt.Sprintf(verb, holder))
	}
	check("String", pw.String())
	check("GoString", pw.GoString())
	check("Sprint", fmt.Sprint(pw))

	for name, h := range map[string]func(*bytes.Buffer) slog.Handler{
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		var buf bytes.Buffer
		slog.New(h(&buf)).Info("decrypt", "password", pw, "holder", holder)
		check("slog "+name, buf.String())
	}

	for name, v := range map[string]any{"pointer": pw, "value": *pw, "field": holder} {
		if b, err := json.Marshal(v); !errors.Is(err, logging.ErrSecretMarshal) {
			t.Errorf("json.Marshal(%s) = %q, %v; want ErrSecretMarshal", name, b, err)
		}
	}
	if b, err := pw.MarshalText(); !errors.Is(err, logging.ErrSecretMarshal) || b != nil {
		t.Errorf("MarshalText = %q, %v; want ErrSecretMarshal", b, err)
	}
}

func TestTrimPassword(t *testing.T) {
	for in, want := range map[string]string{
		"secret":         "secret",
		"secret\n":       "secret",
		"secret\r\n":     "secret",
		"secret\r\n\n\r": "secret",
		"secret \n":      "secret ",
		"\nsecret":       "\nsecret",
		"":               "",
	} {
		if got := string(TrimPassword([]byte(in))); got != want {
			t.Errorf("TrimPassword(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFlavourString(t *testing.T) {
	if QRLV1.String() != "qrl-v1" || DepositCLI.String() != "deposit-cli" || Flavour(9).String() != "Flavour(9)" {
		t.Fatal("flavour names")
	}
	if QRLV1.Version() != 1 || DepositCLI.Version() != 0 {
		t.Fatal("flavour versions")
	}
}
