// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

// class is the provenance class of a file (PROVENANCE.md, "Header classes").
type class string

const (
	classNew      class = "new"
	classW3S      class = "w3s-derived"
	classMIT      class = "mit-derived"
	classVendored class = "vendored"
)

// The file table sits between these markers in PROVENANCE.md.
const (
	beginMarker = "<!-- headercheck:begin -->"
	endMarker   = "<!-- headercheck:end -->"
)

// row is one entry of the PROVENANCE.md file table, whose columns are:
// path | class | upstream repository | upstream path(s) | revision.
type row struct {
	path     string   // slash-separated, relative to the root; vendored rows end in "/"
	class    class    // header class
	upstream []string // upstream paths ("Derived from" targets)
	revision string   // upstream commit, "tree <id>" for vendored rows, or "sha256 <hex>" pinning a file's content
	line     int      // line number in PROVENANCE.md
}

var (
	treeRevision   = regexp.MustCompile(`^tree ([0-9a-f]{40})$`)
	sha256Revision = regexp.MustCompile(`^sha256 ([0-9a-f]{64})$`)
	commitRevision = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
)

// treeID returns the git tree id recorded for a vendored row.
func (r row) treeID() string {
	if m := treeRevision.FindStringSubmatch(r.revision); m != nil {
		return m[1]
	}
	return ""
}

// contentHash returns the sha256 recorded for a file row, if any.
func (r row) contentHash() string {
	if m := sha256Revision.FindStringSubmatch(r.revision); m != nil {
		return m[1]
	}
	return ""
}

// parseProvenance reads the file table from PROVENANCE.md.
func parseProvenance(rd io.Reader) ([]row, error) {
	var (
		rows    []row
		seen    = map[string]int{}
		inTable bool
		ended   bool
		header  int
	)
	sc := bufio.NewScanner(rd)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == beginMarker:
			inTable = true
			continue
		case line == endMarker:
			if !inTable {
				return nil, fmt.Errorf("line %d: %s before %s", n, endMarker, beginMarker)
			}
			inTable, ended = false, true
			continue
		case !inTable || !strings.HasPrefix(line, "|"):
			continue
		}
		if header < 2 { // column titles and the |---| separator
			header++
			continue
		}
		r, err := parseRow(line, n)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[r.path]; dup {
			return nil, fmt.Errorf("line %d: %s already listed on line %d", n, r.path, prev)
		}
		seen[r.path] = n
		rows = append(rows, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if !ended {
		return nil, fmt.Errorf("file table markers %s ... %s not found", beginMarker, endMarker)
	}
	return rows, nil
}

func parseRow(line string, n int) (row, error) {
	cells := strings.Split(strings.Trim(line, "|"), "|")
	if len(cells) != 5 {
		return row{}, fmt.Errorf("line %d: want 5 columns, got %d", n, len(cells))
	}
	r := row{
		path:     unquote(cells[0]),
		class:    class(unquote(cells[1])),
		revision: unquote(cells[4]),
		line:     n,
	}
	for _, p := range strings.FieldsFunc(strings.ReplaceAll(cells[3], "<br>", ","), func(c rune) bool { return c == ',' }) {
		if p = unquote(p); p != "" {
			r.upstream = append(r.upstream, p)
		}
	}
	clean := strings.TrimSuffix(r.path, "/")
	if clean == "" || path.IsAbs(clean) || path.Clean(clean) != clean || strings.HasPrefix(clean, "../") || clean == ".." {
		return row{}, fmt.Errorf("line %d: invalid path %q", n, r.path)
	}
	switch r.class {
	case classNew:
		if r.revision != "" && r.contentHash() == "" {
			return row{}, fmt.Errorf("line %d: %s: a new row's revision is empty or \"sha256 <64-hex>\"", n, r.path)
		}
	case classW3S, classMIT:
		if len(r.upstream) == 0 {
			return row{}, fmt.Errorf("line %d: %s: class %s needs an upstream path", n, r.path, r.class)
		}
		if !commitRevision.MatchString(r.revision) {
			return row{}, fmt.Errorf("line %d: %s: class %s needs the upstream commit (7-40 hex digits) as its revision", n, r.path, r.class)
		}
	case classVendored:
		if !strings.HasSuffix(r.path, "/") || r.treeID() == "" {
			return row{}, fmt.Errorf("line %d: %s: vendored rows name a directory (trailing /) and a revision \"tree <40-hex id>\"", n, r.path)
		}
	default:
		return row{}, fmt.Errorf("line %d: %s: unknown class %q", n, r.path, r.class)
	}
	if r.class != classVendored && strings.HasSuffix(r.path, "/") {
		return row{}, fmt.Errorf("line %d: %s: only vendored rows may name a directory", n, r.path)
	}
	return r, nil
}

// unquote drops Markdown code spans and surrounding space from a cell.
func unquote(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(s, "`", ""))
}
