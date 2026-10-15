// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestStreamIsStable(t *testing.T) {
	a, b := newStream(7), newStream(7)
	if !bytes.Equal(a.bytes(100), b.bytes(100)) {
		t.Fatal("same seed, different streams")
	}
	if bytes.Equal(newStream(1).bytes(32), newStream(2).bytes(32)) {
		t.Fatal("different seeds, same stream")
	}
	// Reads of any size see the same bytes as one long read.
	long := newStream(3).bytes(4627 + 9)
	s := newStream(3)
	if got := append(s.bytes(4627), s.bytes(9)...); !bytes.Equal(got, long) {
		t.Fatal("split reads differ from one read")
	}
}

func TestBitlist32IsValid(t *testing.T) {
	lengths := map[int]bool{}
	for seed := range uint64(2000) {
		b := newStream(seed).bitlist32()
		last := b[len(b)-1]
		if len(b) == 0 || len(b) > 5 || last == 0 {
			t.Fatalf("seed %d: bitlist %x", seed, b)
		}
		n := 8*(len(b)-1) + bitLen(last) - 1
		if n > 32 {
			t.Fatalf("seed %d: %d bits", seed, n)
		}
		lengths[n] = true
	}
	if len(lengths) != 33 {
		t.Errorf("2000 seeds drew %d of the 33 lengths", len(lengths))
	}
}

func bitLen(b byte) int {
	n := 0
	for ; b != 0; b >>= 1 {
		n++
	}
	return n
}

func TestRequestEditing(t *testing.T) {
	o := obj{}.set("a", "1").set("b", obj{}.set("c", "2"))
	if got := compact(with(o, "b.c", "3")); got != `{"a":"1","b":{"c":"3"}}` {
		t.Errorf("with: %s", got)
	}
	if got := compact(without(o, "b.c")); got != `{"a":"1","b":{}}` {
		t.Errorf("without: %s", got)
	}
	if got := compact(plus(o, "b", "d", "4")); got != `{"a":"1","b":{"c":"2","d":"4"}}` {
		t.Errorf("plus: %s", got)
	}
	if got := compact(renamed(o, "a", "z")); got != `{"z":"1","b":{"c":"2"}}` {
		t.Errorf("renamed: %s", got)
	}
	if got := compact(o); got != `{"a":"1","b":{"c":"2"}}` {
		t.Errorf("the edits changed the original: %s", got)
	}
}

// TestReplacesMirrorQrysm checks that this module repeats qrysm's replace
// directives exactly, in particular the go-qrl one: replaces apply only in
// the main module, and a different go-qrl would change what is generated.
func TestReplacesMirrorQrysm(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-json", "github.com/theQRL/qrysm").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	var m struct {
		Replace *struct{ GoMod string }
	}
	if err := json.Unmarshal(out, &m); err != nil || m.Replace == nil || m.Replace.GoMod == "" {
		t.Fatalf("go list gave no replaced qrysm go.mod: %v %s", err, out)
	}
	theirs := replaces(t, m.Replace.GoMod)
	ours := replaces(t, "go.mod")
	if len(theirs) == 0 {
		t.Fatal("qrysm's go.mod has no replace directives")
	}
	for path, target := range theirs {
		if ours[path] != target {
			t.Errorf("replace %s => %q here, qrysm has %q", path, ours[path], target)
		}
	}
	if !strings.HasPrefix(ours["github.com/theQRL/go-qrl"], "github.com/cyyber/go-qrl ") {
		t.Errorf("go-qrl is not replaced by cyyber/go-qrl: %q", ours["github.com/theQRL/go-qrl"])
	}
}

// replaces returns the single-line replace directives of a go.mod file.
func replaces(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "replace ")
		if !ok {
			continue
		}
		from, to, ok := strings.Cut(rest, " => ")
		if ok {
			out[strings.TrimSpace(from)] = strings.TrimSpace(to)
		}
	}
	return out
}

// TestGenerateIsDeterministic generates the fixtures twice and compares the
// trees byte for byte. It takes about a minute and a half, so it is skipped
// with -short and under the race detector; CI's regeneration diff covers it
// there.
func TestGenerateIsDeterministic(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("generates the fixtures twice")
	}
	a, b := t.TempDir(), t.TempDir()
	for _, dir := range []string{a, b} {
		if err := generate(dir); err != nil {
			t.Fatal(err)
		}
	}
	files := 0
	err := filepath.WalkDir(a, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(a, p)
		x, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		y, err := os.ReadFile(filepath.Join(b, rel))
		if err != nil {
			return err
		}
		if !bytes.Equal(x, y) {
			t.Errorf("%s differs between two runs", rel)
		}
		files++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 40 {
		t.Fatalf("only %d files generated", files)
	}
}
