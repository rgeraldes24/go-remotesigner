// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package repo checks the repository's own text for a reader of the public
// repository: statements about publication hold before and after the
// repository is made public, and no reference points at a document that is
// not in the repository.
package repo

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// root is the repository root, relative to this package.
const root = "../.."

// textFile is a text file of the repository, with its slash-separated path
// relative to the root.
type textFile struct {
	path string
	text string
}

var (
	loadOnce sync.Once
	loaded   []textFile
	loadErr  error
)

// skipRootDirs are build and release outputs that are never committed.
var skipRootDirs = map[string]bool{"bin": true, "dist": true, "third_party_licenses": true}

// skipDir reports whether the walk leaves out the directory rel: git's own
// data, build outputs, editor and Python caches, and third_party/, whose
// files are upstream code kept byte-identical.
func skipDir(rel, name string) bool {
	switch name {
	case ".git", ".idea", ".vscode", "__pycache__":
		return true
	}
	return rel == "third_party" || (!strings.Contains(rel, "/") && skipRootDirs[rel])
}

// repoFiles returns every text file of the repository outside the
// directories skipDir leaves out. Binary files (any NUL byte) are skipped.
func repoFiles(t *testing.T) []textFile {
	t.Helper()
	loadOnce.Do(func() {
		loadErr = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if rel != "." && skipDir(rel, d.Name()) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() || d.Name() == ".DS_Store" || strings.HasSuffix(d.Name(), ".swp") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if bytes.IndexByte(b, 0) >= 0 {
				return nil
			}
			loaded = append(loaded, textFile{path: rel, text: string(b)})
			return nil
		})
	})
	if loadErr != nil {
		t.Fatalf("walk %s: %v", root, loadErr)
	}
	if len(loaded) == 0 {
		t.Fatalf("no files found under %s", root)
	}
	return loaded
}

// ownFile reports whether path is one of this package's files, which spell
// out the patterns they reject.
func ownFile(path string) bool {
	return strings.HasPrefix(path, "test/repo/")
}
