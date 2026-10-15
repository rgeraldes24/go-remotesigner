// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"strings"
	"testing"
)

const tableHead = "| Path | Class | Upstream repository | Upstream path(s) | Revision |\n|---|---|---|---|---|\n"

func table(rows ...string) string {
	return "# Provenance\n\nprose | with a pipe\n\n" + beginMarker + "\n" + tableHead + strings.Join(rows, "\n") + "\n" + endMarker + "\n"
}

func TestParseProvenance(t *testing.T) {
	const tree = "6c97bfffa7d145c2be452fa4435c81b6c7532554"
	got, err := parseProvenance(strings.NewReader(table(
		"| `cmd/app/main.go` | new | | | |",
		"| `internal/a.go` | w3s-derived | Web3Signer | `x/A.java`<br>`x/B.java` | `30af06dc` |",
		"| `internal/k.go` | mit-derived | qrysm | `pkg/k/k.go` | `0b9cdf25` |",
		"| `third_party/k/` | vendored | qrysm | `pkg/k` | tree `"+tree+"` |",
	)))
	if err != nil {
		t.Fatal(err)
	}
	want := []row{
		{path: "cmd/app/main.go", class: classNew, line: 8},
		{path: "internal/a.go", class: classW3S, upstream: []string{"x/A.java", "x/B.java"}, revision: "30af06dc", line: 9},
		{path: "internal/k.go", class: classMIT, upstream: []string{"pkg/k/k.go"}, revision: "0b9cdf25", line: 10},
		{path: "third_party/k/", class: classVendored, upstream: []string{"pkg/k"}, revision: "tree " + tree, line: 11},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseProvenance:\n got %+v\nwant %+v", got, want)
	}
	if id := got[3].treeID(); id != tree {
		t.Fatalf("treeID = %q, want %q", id, tree)
	}
}

func TestParseProvenanceErrors(t *testing.T) {
	tests := []struct {
		name, doc, want string
	}{
		{"no markers", "# Provenance\n", "markers"},
		{"unknown class", table("| a.go | borrowed | | | |"), "unknown class"},
		{"wrong column count", table("| a.go | new | |"), "want 5 columns"},
		{"duplicate path", table("| a.go | new | | | |", "| a.go | new | | | |"), "already listed"},
		{"derived without upstream", table("| a.go | w3s-derived | Web3Signer | | 30af06dc |"), "needs an upstream path"},
		{"mit without upstream", table("| a.go | mit-derived | qrysm | | |"), "needs an upstream path"},
		{"vendored without tree", table("| third_party/k/ | vendored | qrysm | pkg/k | 0b9cdf25 |"), "tree <40-hex id>"},
		{"vendored file", table("| third_party/k.go | vendored | qrysm | pkg/k | tree " + strings.Repeat("a", 40) + " |"), "trailing /"},
		{"directory for a new row", table("| internal/ | new | | | |"), "only vendored rows"},
		{"parent path", table("| ../a.go | new | | | |"), "invalid path"},
		{"absolute path", table("| /a.go | new | | | |"), "invalid path"},
		{"unclean path", table("| a//b.go | new | | | |"), "invalid path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseProvenance(strings.NewReader(tt.doc))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}
