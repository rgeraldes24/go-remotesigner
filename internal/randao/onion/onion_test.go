// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package onion

import (
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Vectors from docs/spec/randao-onion.md.
var (
	seed0 = func() []byte {
		s := make([]byte, 48)
		for i := range s {
			s[i] = byte(i)
		}
		return s
	}()

	v1x0 = layer("bad1b225316b32675bd274b5f209449593995f2807dc53020ec640552ef90182")
	v1x1 = layer("a7a70e5e8ec3852c1b80d42af6b59c70acaaee13d8b1e8ed257e9d1e80bdb3cf")
	v1x7 = layer("2084686c9a18304e24d4e10f977066bc85cc30d85bc9872faacbd7ad6ce29338")
	v1x8 = layer("e5a508b11f92cf756ee98e55604cfff7712de2d0922369ab24eb74a64e28c1ae")

	v2x5 = layer("7cc43d4b182dcac4728d997d2dffefd709b5a2f4b752006b228142a2c5ab0e73")

	v3x1023 = layer("7be31017d3ac2ca66321e3c018d4ea47ac3e39fdf0826d755fe12e461884e926")
	v3x1024 = layer("f0f017898e20ca070ad07e8c2a72331ec950d7b688adf17b51f1e5b0db6b3c64")
	v3Below = layer("f276643d55e51c864effdc5f67588f7ba0bf1b08e7676921038446f44a5b1f2a")
	v3Top   = layer("f2f69ca0faa14d5d382ef99d1a77babeea9dabf5e57947e26231a0fe3ceb7dc3")
)

func layer(s string) [Size]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != Size {
		panic("bad test vector " + s)
	}
	return [Size]byte(b)
}

func TestVectors(t *testing.T) {
	tests := []struct {
		name  string
		seed  []byte
		index uint64
		want  [Size]byte
	}{
		{"V1 x_0", seed0, 0, v1x0},
		{"V1 x_1", seed0, 1, v1x1},
		{"V1 x_7", seed0, 7, v1x7},
		{"V1 x_8 commitment", seed0, 8, v1x8},
		{"V2 x_5 short seed", []byte("seed-a"), 5, v2x5},
		{"V3 x_1023", seed0, 1023, v3x1023},
		{"V3 x_1024", seed0, 1024, v3x1024},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Top(tt.seed, tt.index); got != tt.want {
				t.Fatalf("Top(seed, %d) = %x, want %x", tt.index, got, tt.want)
			}
			if got := Advance(Base(tt.seed), tt.index); got != tt.want {
				t.Fatalf("Advance(Base(seed), %d) = %x, want %x", tt.index, got, tt.want)
			}
		})
	}
}

func TestV3DefaultLength(t *testing.T) {
	if testing.Short() {
		t.Skip("2^20 hashes")
	}
	below := Top(seed0, DefaultLayers-1)
	if below != v3Below {
		t.Fatalf("x_{2^20-1} = %x, want %x", below, v3Below)
	}
	if top := Step(below); top != v3Top {
		t.Fatalf("x_{2^20} = %x, want %x", top, v3Top)
	}
	j, reveal, ok := Find(seed0, v3Top, DefaultLayers)
	if !ok || j != DefaultLayers || reveal != v3Below {
		t.Fatalf("Find(commitment) = (%d, %x, %v), want (%d, %x, true)", j, reveal, ok, DefaultLayers, v3Below)
	}
}

func TestStepChecksReveal(t *testing.T) {
	// The reveal for the V1 commitment is x_7, and SHA-256(x_7) is the commitment.
	if Step(v1x7) != v1x8 {
		t.Fatal("Step(x_7) != x_8")
	}
	if Step(v1x0) != v1x1 {
		t.Fatal("Step(x_0) != x_1")
	}
	if Step(v1x8) == v1x7 {
		t.Fatal("Step must not walk down")
	}
}

func TestAdvanceZero(t *testing.T) {
	if Advance(v1x7, 0) != v1x7 {
		t.Fatal("Advance(x, 0) != x")
	}
	if Advance(v1x0, 7) != v1x7 {
		t.Fatal("Advance(x_0, 7) != x_7")
	}
}

func TestFind(t *testing.T) {
	other := Top([]byte("another seed"), 3)
	tests := []struct {
		name       string
		c          [Size]byte
		maxDepth   uint64
		wantOK     bool
		wantIndex  uint64
		wantReveal [Size]byte
	}{
		{"commitment at the depth bound", v1x8, 8, true, 8, v1x7},
		{"commitment beyond the bound", v1x8, 7, false, 0, [Size]byte{}},
		{"inner layer", v1x7, 8, true, 7, Top(seed0, 6)},
		{"layer 1 reveals the base", v1x1, 8, true, 1, v1x0},
		{"base layer has no reveal", v1x0, 8, true, 0, [Size]byte{}},
		{"base layer with zero bound", v1x0, 0, true, 0, [Size]byte{}},
		{"layer 1 with zero bound", v1x1, 0, false, 0, [Size]byte{}},
		{"other onion", other, 64, false, 0, [Size]byte{}},
		{"zero value", [Size]byte{}, 64, false, 0, [Size]byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j, reveal, ok := Find(seed0, tt.c, tt.maxDepth)
			if ok != tt.wantOK || j != tt.wantIndex || reveal != tt.wantReveal {
				t.Fatalf("Find = (%d, %x, %v), want (%d, %x, %v)", j, reveal, ok, tt.wantIndex, tt.wantReveal, tt.wantOK)
			}
			if ok && j > 0 && Step(reveal) != tt.c {
				t.Fatal("returned reveal does not hash to the commitment")
			}
		})
	}
}

func TestBaseDoesNotModifySeed(t *testing.T) {
	seed := append([]byte(nil), seed0...)
	_ = Base(seed)
	if string(seed) != string(seed0) {
		t.Fatal("Base modified its input")
	}
}

// TestExportedNames keeps the API shape apart from qrysm's GPL onion package,
// whose exported names this package must not reuse (docs/spec/randao-onion.md).
func TestExportedNames(t *testing.T) {
	forbidden := map[string]bool{"Origin": true, "Next": true, "Verify": true, "Commitment": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var exported []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				exported = append(exported, d.Name.Name)
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.ValueSpec:
						for _, n := range s.Names {
							exported = append(exported, n.Name)
						}
					case *ast.TypeSpec:
						exported = append(exported, s.Name.Name)
					}
				}
			}
		}
	}
	if len(exported) == 0 {
		t.Fatal("no declarations found")
	}
	for _, n := range exported {
		if ast.IsExported(n) && forbidden[n] {
			t.Errorf("package onion exports %s", n)
		}
	}
}

func BenchmarkStep(b *testing.B) {
	x := v1x0
	for b.Loop() {
		x = Step(x)
	}
}

// BenchmarkFindDefault is the stateless first-use scan at L = 2^20.
func BenchmarkFindDefault(b *testing.B) {
	c := Top(seed0, DefaultLayers)
	for b.Loop() {
		if _, _, ok := Find(seed0, c, DefaultLayers); !ok {
			b.Fatal("not found")
		}
	}
}
