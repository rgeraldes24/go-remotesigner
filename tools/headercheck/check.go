// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// result is the outcome of a check run.
type result struct {
	problems []string
	files    int // files whose header was checked
	trees    int // vendored trees verified
}

// skipRootDirs are build and release outputs that are never committed.
var skipRootDirs = map[string]bool{"bin": true, "dist": true, "third_party_licenses": true}

// isJunk reports whether name is an editor or OS file that .gitignore keeps
// out of the repository ("Editors and OS files"). Such files are skipped
// everywhere, including inside vendored trees, so that a stray .DS_Store does
// not fail a local run although nothing tracked has changed.
func isJunk(name string) bool {
	switch name {
	case ".DS_Store", ".idea", ".vscode":
		return true
	}
	return strings.HasSuffix(name, ".swp")
}

const thirdParty = "third_party/"

var (
	ourLine        = regexp.MustCompile(`^Copyright \d{4}(-\d{4})? The go-remotesigner Authors\.$`)
	consensysRE    = regexp.MustCompile(`(?i)^copyright\b.*\bconsensys\b`)
	mitCopyright   = regexp.MustCompile(`^Copyright \(c\) \d{4}`)
	wealdCopyright = regexp.MustCompile(`^Copyright © \d{4}.* Weald Technology Trading\.?$`)
)

const (
	spdxApache    = "SPDX-License-Identifier: Apache-2.0"
	spdxMIT       = "SPDX-License-Identifier: MIT"
	spdxMITApache = "SPDX-License-Identifier: MIT AND Apache-2.0"
	apacheNotice  = `Licensed under the Apache License, Version 2.0`

	// wealdKeystore is the upstream path of qrysm's MIT keystore v1, which
	// derives from Weald Technology's Apache-2.0 keystore v4 encryptor with
	// Weald's notices removed. Copies of it restore them (Apache-2.0
	// §4(c); PROVENANCE.md, "QRL code").
	wealdKeystore = "pkg/go-qrl-wallet-encryptor-keystore/"
)

// check verifies the tree at root against the PROVENANCE file prov (relative
// to root). It returns an error only when the check cannot run at all.
func check(root, prov string) (result, error) {
	var res result
	f, err := os.Open(filepath.Join(root, prov))
	if err != nil {
		return res, err
	}
	rows, err := parseProvenance(f)
	_ = f.Close()
	if err != nil {
		return res, fmt.Errorf("%s: %w", prov, err)
	}

	byPath := make(map[string]row, len(rows))
	for _, r := range rows {
		byPath[r.path] = r
	}
	seen := map[string]bool{}
	problemf := func(format string, args ...any) {
		res.problems = append(res.problems, fmt.Sprintf(format, args...))
	}

	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel != "." && isJunk(d.Name()) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if rel == "." {
				return nil
			}
			if d.Name() == ".git" || (!strings.Contains(rel, "/") && skipRootDirs[rel]) {
				return filepath.SkipDir
			}
			if r, ok := byPath[rel+"/"]; ok && r.class == classVendored {
				seen[r.path] = true
				res.trees++
				got, err := gitTreeHash(p)
				if err != nil {
					return err
				}
				if got != r.treeID() {
					problemf("%s: vendored tree is %s, PROVENANCE.md records %s: files under third_party/ must stay byte-identical to upstream", r.path, got, r.treeID())
				}
				return filepath.SkipDir
			}
			return nil
		}

		r, listed := byPath[rel]
		if listed {
			seen[rel] = true
		}
		inThirdParty := strings.HasPrefix(rel, thirdParty)
		switch {
		case inThirdParty && !listed:
			problemf("%s: not recorded in PROVENANCE.md (everything under third_party/ must be)", rel)
		case inThirdParty && r.contentHash() == "":
			problemf("%s: files under third_party/ outside a vendored tree need the revision \"sha256 <hex>\" in PROVENANCE.md", rel)
		}
		if listed && r.contentHash() != "" {
			got, err := fileSHA256(p)
			if err != nil {
				return err
			}
			if got != r.contentHash() {
				problemf("%s: content sha256 is %s, PROVENANCE.md records %s: update the row in the same reviewed change", rel, got, r.contentHash())
			}
		}
		k := kindOf(rel)
		switch {
		case k == "":
		case !listed:
			if !inThirdParty {
				problemf("%s: no PROVENANCE.md row", rel)
			}
		default:
			res.files++
			lines, err := headerOf(p, k)
			if err != nil {
				problemf("%s: %v", rel, err)
				return nil
			}
			for _, msg := range checkHeader(r, lines) {
				problemf("%s: %s: %s", rel, r.class, msg)
			}
		}
		return nil
	})
	if err != nil {
		return res, err
	}

	for _, r := range rows {
		if !seen[r.path] {
			problemf("%s: listed in PROVENANCE.md (line %d) but missing on disk", r.path, r.line)
		}
	}
	sort.Strings(res.problems)
	return res, nil
}

// fileSHA256 returns the hex sha256 of the file at p.
func fileSHA256(p string) (string, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// kindOf returns the comment prefix used for the header of the file at rel,
// "json" for files whose notice lives in a "description" field, or "" for
// files that carry no header.
func kindOf(rel string) string {
	base := path.Base(rel)
	switch {
	case strings.HasPrefix(base, "Dockerfile"):
		return "#"
	case strings.HasSuffix(base, ".go"):
		return "//"
	case strings.HasSuffix(base, ".sql"):
		return "--"
	case strings.HasSuffix(base, ".yaml"), strings.HasSuffix(base, ".yml"), strings.HasSuffix(base, ".sh"):
		return "#"
	case strings.HasSuffix(base, ".json") && strings.HasPrefix(rel, "deploy/"):
		return "json"
	}
	return ""
}

// headerOf returns the header lines of a file, comment markers stripped: the
// leading run of comment and blank lines (after an optional shebang), or the
// lines of the top-level "description" field of a JSON file.
func headerOf(p, kind string) ([]string, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if kind == "json" {
		var doc struct {
			Description *string `json:"description"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("parse JSON: %w", err)
		}
		if doc.Description == nil {
			return nil, fmt.Errorf(`no top-level "description" field carrying the licence notice`)
		}
		return strings.Split(*doc.Description, "\n"), nil
	}
	var out []string
	for i, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case i == 0 && strings.HasPrefix(t, "#!"):
		case t == "":
			out = append(out, "")
		case strings.HasPrefix(t, kind):
			out = append(out, strings.TrimSpace(strings.TrimPrefix(t, kind)))
		default:
			return out, nil
		}
	}
	return out, nil
}

// checkHeader returns what the header lines lack for the row's class.
func checkHeader(r row, lines []string) []string {
	has := func(match func(string) bool) bool {
		for _, l := range lines {
			if match(l) {
				return true
			}
		}
		return false
	}
	equals := func(s string) func(string) bool { return func(l string) bool { return l == s } }
	joined := strings.Join(lines, " ")

	var missing []string
	need := func(ok bool, what string) {
		if !ok {
			missing = append(missing, what)
		}
	}
	switch r.class {
	case classNew:
		need(has(ourLine.MatchString), `missing "Copyright <year> The go-remotesigner Authors." line`)
		need(has(equals(spdxApache)), "missing "+spdxApache)
		need(!has(consensysRE.MatchString), "has a ConsenSys copyright line; record the file as w3s-derived")
	case classW3S:
		need(has(consensysRE.MatchString), "missing the original ConsenSys copyright line")
		need(has(ourLine.MatchString), `missing "Copyright <year> The go-remotesigner Authors." line`)
		need(has(equals(spdxApache)), "missing "+spdxApache)
		need(has(func(l string) bool { return strings.HasPrefix(l, "Modified by ") }), `missing "Modified by" line`)
		need(strings.Contains(joined, "Derived from"), `missing "Derived from" line`)
		for _, u := range r.upstream {
			need(strings.Contains(joined, u), fmt.Sprintf("header does not name upstream path %s", u))
		}
		need(strings.Contains(joined, r.revision), fmt.Sprintf("header does not name upstream commit %s", r.revision))
	case classMIT:
		need(has(mitCopyright.MatchString), `missing the original "Copyright (c) <year> ..." MIT line`)
		switch {
		case has(equals(spdxMIT)):
		case has(equals(spdxMITApache)):
			need(strings.Contains(joined, apacheNotice), "SPDX MIT AND Apache-2.0 without the Apache-2.0 licence notice")
		default:
			missing = append(missing, "missing "+spdxMIT+" or "+spdxMITApache)
		}
		if slices.ContainsFunc(r.upstream, func(u string) bool { return strings.HasPrefix(u, wealdKeystore) }) {
			need(has(wealdCopyright.MatchString), `missing Weald Technology's "Copyright © <years> Weald Technology Trading" line, which copies of the QRL keystore restore`)
			need(has(equals(spdxMITApache)), "the QRL keystore derives from Apache-2.0 code: want "+spdxMITApache)
		}
		need(has(func(l string) bool { return strings.HasPrefix(l, "Modified by ") }), `missing "Modified by" line`)
	case classVendored:
		missing = append(missing, "vendored rows must name a directory")
	}
	return missing
}
