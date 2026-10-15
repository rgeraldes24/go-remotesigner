// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha1" // git object ids are SHA-1: identity, not security
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// emptyTree is git's object id for a tree with no entries.
const emptyTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

// gitTreeHash returns the object id git would assign to the directory dir,
// as printed by `git rev-parse <commit>:<path>`. Empty subdirectories are
// ignored, as git does not record them.
func gitTreeHash(dir string) (string, error) {
	id, err := treeID(dir)
	if err != nil {
		return "", err
	}
	if id == nil {
		return emptyTree, nil
	}
	return hex.EncodeToString(id), nil
}

// treeID returns the raw tree id of dir, or nil for a tree without entries.
func treeID(dir string) ([]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type entry struct {
		mode, name, key string
		id              []byte
	}
	var list []entry
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		ent := entry{name: e.Name(), key: e.Name()}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return nil, err
			}
			ent.mode, ent.id = "120000", objectID("blob", []byte(filepath.ToSlash(target)))
		case info.IsDir():
			sub, err := treeID(p)
			if err != nil {
				return nil, err
			}
			if sub == nil {
				continue
			}
			ent.mode, ent.key, ent.id = "40000", e.Name()+"/", sub
		case info.Mode().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			ent.mode = "100644"
			if info.Mode()&0o111 != 0 {
				ent.mode = "100755"
			}
			ent.id = objectID("blob", data)
		default:
			return nil, fmt.Errorf("%s: unsupported file type %s", p, info.Mode().Type())
		}
		list = append(list, ent)
	}
	if len(list) == 0 {
		return nil, nil
	}
	// git orders tree entries bytewise, comparing a directory as "name/".
	sort.Slice(list, func(i, j int) bool { return list[i].key < list[j].key })
	var buf bytes.Buffer
	for _, e := range list {
		fmt.Fprintf(&buf, "%s %s\x00", e.mode, e.name)
		buf.Write(e.id)
	}
	return objectID("tree", buf.Bytes()), nil
}

func objectID(kind string, data []byte) []byte {
	h := sha1.New()
	_, _ = fmt.Fprintf(h, "%s %d\x00", kind, len(data))
	h.Write(data)
	return h.Sum(nil)
}
