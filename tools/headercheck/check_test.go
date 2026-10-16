// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	w3sCommit   = "30af06dc975ba5b8ed0e17e53cba8683ca50ec02"
	w3sUpstream = "slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbSlashingProtection.java"

	newGo = "// Copyright 2026 The go-remotesigner Authors.\n// SPDX-License-Identifier: Apache-2.0\n\n//go:build linux\n\npackage app\n"

	w3sGo = `// Copyright 2020 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License").
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// ` + w3sUpstream + `
// at commit ` + w3sCommit + `.

package slashing
`

	// mitGo is a copy of the QRL keystore, which derives from Weald's
	// Apache-2.0 keystore v4: it carries both notices.
	mitGo = `// Copyright © 2019 - 2023 Weald Technology Trading.
// Copyright (c) 2023 The Quantum Resistant Ledger
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License.
//
// The Quantum Resistant Ledger's version of this file is licensed under the MIT License (LICENSES/MIT.txt).
//
// SPDX-License-Identifier: MIT AND Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: KDF bounds.

package qrlv1
`

	newSQL        = "-- Copyright 2026 The go-remotesigner Authors.\n-- SPDX-License-Identifier: Apache-2.0\n\nCREATE TABLE t (id INT);\n"
	newSh         = "#!/bin/sh\n# Copyright 2026 The go-remotesigner Authors.\n# SPDX-License-Identifier: Apache-2.0\nset -eu\n"
	newYAML       = "# Copyright 2026 The go-remotesigner Authors.\n# SPDX-License-Identifier: Apache-2.0\nname: ci\n"
	newDockerfile = "# Copyright 2026 The go-remotesigner Authors.\n# SPDX-License-Identifier: Apache-2.0\nFROM scratch\n"
	w3sJSON       = `{"title": "dashboard", "description": "Copyright 2020 ConsenSys AG.\nCopyright 2026 The go-remotesigner Authors.\nSPDX-License-Identifier: Apache-2.0\nModified by The go-remotesigner Authors, 2026.\nDerived from Web3Signer dashboard/web3signer.json at commit ` + w3sCommit + `."}`
)

// fixture is a repository that passes headercheck.
func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"README.md":                                 "# fixture\n",
		"cmd/app/main.go":                           newGo,
		"internal/slashing/engine.go":               w3sGo,
		"internal/keys/keystore/qrlv1/decrypt.go":   mitGo,
		"internal/slashing/pgstore/sql/0001.sql":    newSQL,
		"deploy/entrypoint.sh":                      newSh,
		"deploy/Dockerfile":                         newDockerfile,
		"deploy/grafana/dashboard.json":             w3sJSON,
		".github/workflows/ci.yml":                  newYAML,
		"third_party/ks/go.mod":                     "module x\n",
		"third_party/ks/pkg/LICENSE":                "MIT License\n",
		"third_party/ks/pkg/x.go":                   "package ks\n",
		"third_party/ks/pkg/.golangci.yml":          "run: {}\n",
		"bin/remotesigner.go":                       "not checked: build output\n",
		"tools/vectorgen/testdata/ignored-notes.md": "not a checked kind\n",
	}
	for p, c := range files {
		writeFile(t, filepath.Join(dir, filepath.FromSlash(p)), c, 0o644)
	}
	tree, err := gitTreeHash(filepath.Join(dir, "third_party", "ks", "pkg"))
	if err != nil {
		t.Fatal(err)
	}
	modSum, err := fileSHA256(filepath.Join(dir, "third_party", "ks", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "PROVENANCE.md"), table(
		"| `cmd/app/main.go` | new | | | |",
		"| `internal/slashing/engine.go` | w3s-derived | Web3Signer | `"+w3sUpstream+"` | `"+w3sCommit+"` |",
		"| `internal/keys/keystore/qrlv1/decrypt.go` | mit-derived | qrysm | `pkg/go-qrl-wallet-encryptor-keystore/decrypt.go` | `0b9cdf25` |",
		"| `internal/slashing/pgstore/sql/0001.sql` | new | | | |",
		"| `deploy/entrypoint.sh` | new | | | |",
		"| `deploy/Dockerfile` | new | | | |",
		"| `deploy/grafana/dashboard.json` | w3s-derived | Web3Signer | `dashboard/web3signer.json` | `"+w3sCommit+"` |",
		"| `.github/workflows/ci.yml` | new | | | |",
		"| `third_party/ks/go.mod` | new | | | sha256 `"+modSum+"` |",
		"| `third_party/ks/pkg/` | vendored | qrysm | `pkg/ks` | tree `"+tree+"` |",
	), 0o644)
	return dir
}

func TestCheckFixturePasses(t *testing.T) {
	res, err := check(fixture(t), "PROVENANCE.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.problems) != 0 {
		t.Fatalf("unexpected problems:\n%s", strings.Join(res.problems, "\n"))
	}
	if res.files != 8 || res.trees != 1 {
		t.Fatalf("checked %d files and %d trees, want 8 and 1", res.files, res.trees)
	}
}

func TestCheckIgnoresEditorAndOSFiles(t *testing.T) {
	dir := fixture(t)
	for _, p := range []string{
		".DS_Store",
		"third_party/ks/.DS_Store",
		"third_party/ks/pkg/.DS_Store",
		"third_party/ks/pkg/.x.go.swp",
		"third_party/ks/pkg/.idea/workspace.xml",
		"internal/slashing/.engine.go.swp",
	} {
		writeFile(t, filepath.Join(dir, filepath.FromSlash(p)), "junk\n", 0o644)
	}
	res, err := check(dir, "PROVENANCE.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.problems) != 0 {
		t.Fatalf("editor and OS files caused problems:\n%s", strings.Join(res.problems, "\n"))
	}
}

func TestCheckFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, dir string)
		want   []string
	}{
		{
			name: "sql file without a header or row",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "internal/slashing/pgstore/sql/0002.sql"), "CREATE TABLE u (id INT);\n", 0o644)
			},
			want: []string{"0002.sql: no PROVENANCE.md row"},
		},
		{
			name: "sql file with a row but no header",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "internal/slashing/pgstore/sql/0001.sql"), "CREATE TABLE t (id INT);\n", 0o644)
			},
			want: []string{"0001.sql: new: missing \"Copyright <year> The go-remotesigner Authors.\" line", "0001.sql: new: missing SPDX-License-Identifier: Apache-2.0"},
		},
		{
			name: "edited file under third_party",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "third_party/ks/pkg/x.go"), "package ks // edited\n", 0o644)
			},
			want: []string{"third_party/ks/pkg/: vendored tree is"},
		},
		{
			name: "file added inside a vendored tree",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "third_party/ks/pkg/extra.go"), "package ks\n", 0o644)
			},
			want: []string{"third_party/ks/pkg/: vendored tree is"},
		},
		{
			name: "mode change inside a vendored tree",
			mutate: func(t *testing.T, dir string) {
				if err := os.Chmod(filepath.Join(dir, "third_party/ks/pkg/LICENSE"), 0o755); err != nil {
					t.Fatal(err)
				}
			},
			want: []string{"third_party/ks/pkg/: vendored tree is"},
		},
		{
			name: "edited project file under third_party",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "third_party/ks/go.mod"), "module x\n\nrequire github.com/theQRL/qrysm v0.2.2\n", 0o644)
			},
			want: []string{"third_party/ks/go.mod: content sha256 is"},
		},
		{
			name: "third_party file recorded without a sha256",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "third_party/ks/NOTES.md"), "notes\n", 0o644)
				prov := filepath.Join(dir, "PROVENANCE.md")
				data, err := os.ReadFile(prov)
				if err != nil {
					t.Fatal(err)
				}
				doc := strings.Replace(string(data), endMarker, "| `third_party/ks/NOTES.md` | new | | | |\n"+endMarker, 1)
				writeFile(t, prov, doc, 0o644)
			},
			want: []string{`third_party/ks/NOTES.md: files under third_party/ outside a vendored tree need the revision "sha256 <hex>"`},
		},
		{
			name: "unrecorded file under third_party",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "third_party/ks/NOTES.md"), "notes\n", 0o644)
			},
			want: []string{"third_party/ks/NOTES.md: not recorded in PROVENANCE.md"},
		},
		{
			name: "row whose file is missing",
			mutate: func(t *testing.T, dir string) {
				if err := os.Remove(filepath.Join(dir, "cmd/app/main.go")); err != nil {
					t.Fatal(err)
				}
			},
			want: []string{"cmd/app/main.go: listed in PROVENANCE.md (line 8) but missing on disk"},
		},
		{
			name: "vendored tree missing",
			mutate: func(t *testing.T, dir string) {
				if err := os.RemoveAll(filepath.Join(dir, "third_party/ks/pkg")); err != nil {
					t.Fatal(err)
				}
			},
			want: []string{"third_party/ks/pkg/: listed in PROVENANCE.md"},
		},
		{
			name: "go file without a row",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "internal/other/other.go"), newGo, 0o644)
			},
			want: []string{"internal/other/other.go: no PROVENANCE.md row"},
		},
		{
			name: "new file carrying a ConsenSys line",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "cmd/app/main.go"), "// Copyright 2020 ConsenSys AG.\n"+newGo, 0o644)
			},
			want: []string{"cmd/app/main.go: new: has a ConsenSys copyright line"},
		},
		{
			name: "derived file naming the wrong upstream path",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "internal/slashing/engine.go"), strings.Replace(w3sGo, "DbSlashingProtection", "Other", 1), 0o644)
			},
			want: []string{"engine.go: w3s-derived: header does not name upstream path " + w3sUpstream},
		},
		{
			name: "derived file without the ConsenSys line",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "internal/slashing/engine.go"), strings.Replace(w3sGo, "// Copyright 2020 ConsenSys AG.\n", "", 1), 0o644)
			},
			want: []string{"engine.go: w3s-derived: missing the original ConsenSys copyright line"},
		},
		{
			name: "mit-derived file without a Modified by line",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "internal/keys/keystore/qrlv1/decrypt.go"), strings.Replace(mitGo, "// Modified by", "// Changed by", 1), 0o644)
			},
			want: []string{"decrypt.go: mit-derived: missing \"Modified by\" line"},
		},
		{
			name: "mit-derived file with an Apache-only header",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "internal/keys/keystore/qrlv1/decrypt.go"), newGo, 0o644)
			},
			want: []string{
				`decrypt.go: mit-derived: missing the original "Copyright (c) <year> ..." MIT line`,
				"decrypt.go: mit-derived: missing SPDX-License-Identifier: MIT or SPDX-License-Identifier: MIT AND Apache-2.0",
				"decrypt.go: mit-derived: missing Weald Technology's",
			},
		},
		{
			name: "yaml without SPDX",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, ".github/workflows/ci.yml"), "# Copyright 2026 The go-remotesigner Authors.\nname: ci\n", 0o644)
			},
			want: []string{"ci.yml: new: missing SPDX-License-Identifier: Apache-2.0"},
		},
		{
			name: "header after code does not count",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "deploy/Dockerfile"), "FROM scratch\n"+newDockerfile, 0o644)
			},
			want: []string{"deploy/Dockerfile: new: missing"},
		},
		{
			name: "deploy json without a row",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "deploy/example/keys.json"), `{"keys": []}`, 0o644)
			},
			want: []string{"deploy/example/keys.json: no PROVENANCE.md row"},
		},
		{
			name: "json without description",
			mutate: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "deploy/grafana/dashboard.json"), `{"title": "dashboard"}`, 0o644)
			},
			want: []string{`deploy/grafana/dashboard.json: no top-level "description" field`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := fixture(t)
			tt.mutate(t, dir)
			res, err := check(dir, "PROVENANCE.md")
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(res.problems, "\n")
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("problems do not mention %q:\n%s", want, got)
				}
			}
		})
	}
}

// TestMITHeaders covers the mit-derived class: copies of the QRL keystore
// carry Weald's line, the Apache notice and SPDX "MIT AND Apache-2.0" next
// to the MIT line; other MIT code needs only the MIT notice.
func TestMITHeaders(t *testing.T) {
	keystore := row{class: classMIT, upstream: []string{"pkg/go-qrl-wallet-encryptor-keystore/norm.go"}, revision: "0b9cdf25"}
	other := row{class: classMIT, upstream: []string{"pkg/other/x.go"}, revision: "0b9cdf25"}
	lines := func(src string) []string {
		var out []string
		for _, l := range strings.Split(src, "\n") {
			if l == "package qrlv1" {
				break
			}
			out = append(out, strings.TrimSpace(strings.TrimPrefix(l, "//")))
		}
		return out
	}
	qrlOnly := "// Copyright (c) 2023 The Quantum Resistant Ledger\n// SPDX-License-Identifier: MIT\n//\n// Modified by The go-remotesigner Authors, 2026: KDF bounds.\n"
	tests := []struct {
		name   string
		r      row
		header string
		want   []string // substrings of the problems; none when empty
	}{
		{"keystore copy with both notices", keystore, mitGo, nil},
		{"keystore copy with only the QRL MIT notice", keystore, qrlOnly, []string{"Weald Technology", "want " + spdxMITApache}},
		{"keystore copy with SPDX MIT only", keystore, strings.Replace(mitGo, "MIT AND Apache-2.0", "MIT", 1), []string{"want " + spdxMITApache}},
		{"keystore copy without the Apache notice", keystore, strings.Replace(mitGo, "Licensed under", "Covered by", 1), []string{"without the Apache-2.0 licence notice"}},
		{"keystore copy with an Apache-only header", keystore, newGo, []string{"MIT line", "missing " + spdxMIT, "Weald Technology", "Modified by"}},
		{"keystore copy without the Weald line", keystore, strings.Replace(mitGo, "Weald Technology Trading", "Someone", 1), []string{"Weald Technology"}},
		{"other MIT code with the MIT notice", other, qrlOnly, nil},
		{"other MIT code with an Apache-only header", other, newGo, []string{"MIT line", "missing " + spdxMIT}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Join(checkHeader(tt.r, lines(tt.header)), "\n")
			if len(tt.want) == 0 && got != "" {
				t.Fatalf("unexpected problems:\n%s", got)
			}
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("problems do not mention %q:\n%s", w, got)
				}
			}
		})
	}
}

// TestQRLV1Classes checks the directory rule for the hardened keystore copy:
// a file under qrlv1/ that headercheck does not list as written for this
// project must be mit-derived, whatever its row says.
func TestQRLV1Classes(t *testing.T) {
	for _, tt := range []struct {
		name, file, content, class, want string
	}{
		{"listed new file", "keystore.go", newGo, "new", ""},
		{"listed test classed new", "keystore_test.go", newGo, "new", ""},
		{"unlisted file recorded as new", "encrypt.go", newGo, "new", "encrypt.go: new: files under internal/keys/keystore/qrlv1/ are mit-derived copies"},
		{"unlisted test recorded as new", "decrypt_test.go", newGo, "new", "decrypt_test.go: new: files under internal/keys/keystore/qrlv1/ are mit-derived copies"},
		{"unlisted file in a subdirectory", "sub/password.go", newGo, "new", "sub/password.go: new: files under"},
		{"unlisted mit-derived copy", "encrypt.go", mitGo, "mit-derived", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := fixture(t)
			rel := "internal/keys/keystore/qrlv1/" + tt.file
			writeFile(t, filepath.Join(dir, filepath.FromSlash(rel)), tt.content, 0o644)
			upstream, revision := "", ""
			if tt.class == "mit-derived" {
				upstream, revision = "`pkg/go-qrl-wallet-encryptor-keystore/encrypt.go`", "`0b9cdf25`"
			}
			prov := filepath.Join(dir, "PROVENANCE.md")
			data, err := os.ReadFile(prov)
			if err != nil {
				t.Fatal(err)
			}
			row := "| `" + rel + "` | " + tt.class + " | | " + upstream + " | " + revision + " |\n"
			writeFile(t, prov, strings.Replace(string(data), endMarker, row+endMarker, 1), 0o644)
			res, err := check(dir, "PROVENANCE.md")
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(res.problems, "\n")
			switch {
			case tt.want == "" && got != "":
				t.Fatalf("unexpected problems:\n%s", got)
			case tt.want != "" && !strings.Contains(got, tt.want):
				t.Fatalf("problems do not mention %q:\n%s", tt.want, got)
			}
		})
	}
}

func TestCheckMissingProvenance(t *testing.T) {
	if _, err := check(t.TempDir(), "PROVENANCE.md"); err == nil {
		t.Fatal("check succeeded without a PROVENANCE.md")
	}
}
