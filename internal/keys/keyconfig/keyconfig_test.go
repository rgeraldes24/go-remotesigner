// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package keyconfig

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
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
		{"keystore", "type: file-keystore\nkeystoreFile: k.json\nkeystorePasswordFile: p.txt\n", nil, ErrUnsupported},
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
			keys, err := Parse([]byte(tt.yaml))
			if !errors.Is(err, tt.err) {
				t.Fatalf("Parse error = %v, want %v", err, tt.err)
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

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("b.yaml", "type: file-raw\nprivateKey: "+seedHex(2)+"\n")
	write("a.YML", "type: file-raw\nprivateKey: "+seedHex(1)+"\n")
	write("bad.yaml", "type: file-raw\n")
	write(".hidden.yaml", "type: file-raw\nprivateKey: "+seedHex(3)+"\n")
	write("notes.txt", "ignored")
	if err := os.Mkdir(filepath.Join(dir, "sub.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	write("sub.yaml/c.yaml", "type: file-raw\nprivateKey: "+seedHex(4)+"\n")

	res, err := Load(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range res {
		names = append(names, filepath.Base(r.Path))
	}
	if got := strings.Join(names, ","); got != "a.YML,b.yaml,bad.yaml" {
		t.Fatalf("loaded files %s", got)
	}
	if res[0].Err != nil || len(res[0].Keys) != 1 || res[0].Keys[0].PublicKey() != pubkeyOf(t, 1) {
		t.Errorf("a.YML: %+v", res[0])
	}
	if res[2].Err == nil || len(res[2].Keys) != 0 || !strings.Contains(res[2].Err.Error(), "bad.yaml") {
		t.Errorf("bad.yaml: %+v", res[2])
	}

	if _, err := Load(context.Background(), filepath.Join(dir, "missing")); err == nil {
		t.Error("Load of a missing directory succeeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Load(ctx, dir); !errors.Is(err, context.Canceled) {
		t.Errorf("Load with a cancelled context = %v", err)
	}
}
