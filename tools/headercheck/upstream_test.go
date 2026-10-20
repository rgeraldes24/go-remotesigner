// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// consensysLine is a ConsenSys copyright notice as Web3Signer's files state
// it.
var consensysLine = regexp.MustCompile(`Copyright \d{4}(?:-\d{4})? ConsenSys AG\.`)

// upstreamHeaderBytes is how much of an upstream file is read for its
// notices: its licence header.
const upstreamHeaderBytes = 2048

// consensysLines returns the distinct ConsenSys notices in text, sorted.
func consensysLines(text string) []string {
	lines := consensysLine.FindAllString(text, -1)
	slices.Sort(lines)
	return slices.Compact(lines)
}

func TestConsenSysLines(t *testing.T) {
	java := "/*\n * Copyright 2022 ConsenSys AG.\n *\n * Licensed under the Apache License\n */\npackage x;\n"
	if got := consensysLines(java); !slices.Equal(got, []string{"Copyright 2022 ConsenSys AG."}) {
		t.Errorf("Java header: %q", got)
	}
	header := "Copyright 2022 ConsenSys AG.\nCopyright 2020 ConsenSys AG.\nCopyright 2020 ConsenSys AG.\n" +
		"Copyright 2026 The go-remotesigner Authors.\n"
	if got := consensysLines(header); !slices.Equal(got, []string{"Copyright 2020 ConsenSys AG.", "Copyright 2022 ConsenSys AG."}) {
		t.Errorf("Go header: %q", got)
	}
}

// Every w3s-derived file carries exactly the ConsenSys notices of the
// upstream files its row names, at the recorded commit (Apache-2.0 §4(c);
// PROVENANCE.md, "Header classes"): headercheck itself checks only that a
// ConsenSys line is there, since CI has no Web3Signer checkout. Set
// REMOTESIGNER_WEB3SIGNER_DIR to a Web3Signer checkout at the commit the rows
// record to run it.
func TestConsenSysLinesMatchUpstream(t *testing.T) {
	upstream := os.Getenv("REMOTESIGNER_WEB3SIGNER_DIR")
	if upstream == "" {
		t.Skip("set REMOTESIGNER_WEB3SIGNER_DIR to a Web3Signer checkout to compare the ConsenSys notices with upstream")
	}
	out, err := exec.Command("git", "-C", upstream, "-c", "gc.auto=0", "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("git rev-parse in %s: %v", upstream, err)
	}
	head := strings.TrimSpace(string(out))

	const root = "../.."
	f, err := os.Open(filepath.Join(root, "PROVENANCE.md"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := parseProvenance(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, r := range rows {
		if r.class != classW3S || kindOf(r.path) == "" {
			continue
		}
		if !strings.HasPrefix(head, r.revision) {
			t.Fatalf("%s records Web3Signer commit %s, the checkout is at %s", r.path, r.revision, head)
		}
		var want []string
		for _, u := range r.upstream {
			data, err := os.ReadFile(filepath.Join(upstream, filepath.FromSlash(u)))
			if err != nil {
				t.Errorf("%s: upstream %s: %v", r.path, u, err)
				continue
			}
			want = append(want, consensysLines(string(data[:min(len(data), upstreamHeaderBytes)]))...)
		}
		slices.Sort(want)
		want = slices.Compact(want)
		lines, err := headerOf(filepath.Join(root, filepath.FromSlash(r.path)), kindOf(r.path))
		if err != nil {
			t.Errorf("%s: %v", r.path, err)
			continue
		}
		got := consensysLines(strings.Join(lines, "\n"))
		// Web3Signer's SQL migrations, OpenAPI files and dashboard carry no
		// notice, so they add none. A file derived from those alone keeps
		// the ConsenSys line headercheck requires, which no upstream file
		// states and this test cannot check.
		if len(want) > 0 && !slices.Equal(got, want) {
			t.Errorf("%s carries %q, its upstream files %q", r.path, got, want)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("PROVENANCE.md has no w3s-derived rows")
	}
	t.Logf("%d w3s-derived files compared with %s at %s", checked, upstream, head)
}
