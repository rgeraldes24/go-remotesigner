// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// obj is a JSON object whose keys keep their insertion order, so request
// bodies come out in the canonical order of docs/contract.md.
type obj []kv

type kv struct {
	k string
	v any
}

// set appends a key; keys are never repeated by the builders.
func (o obj) set(k string, v any) obj { return append(o, kv{k, v}) }

// MarshalJSON writes the keys in order.
func (o obj) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, e := range o {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, err := json.Marshal(e.k)
		if err != nil {
			return nil, err
		}
		buf.Write(k)
		buf.WriteByte(':')
		v, err := json.Marshal(e.v)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.k, err)
		}
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// hx is lowercase 0x-prefixed hex.
func hx(b []byte) string { return "0x" + hex.EncodeToString(b) }

// u64s is a uint64 as the contract's decimal string.
func u64s(v uint64) string { return strconv.FormatUint(v, 10) }

// qaddr is a 64-byte execution address in the contract's Q form.
func qaddr(b []byte) string { return "Q" + hex.EncodeToString(b) }

// compact returns v as compact JSON, for raw request bodies.
func compact(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// writeJSON writes v to root/rel with a stable layout: two-space indent,
// no HTML escaping and a final newline. Output is byte-identical across runs
// for the same input, which the regeneration check in CI relies on.
func writeJSON(root, rel string, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("%s: %w", rel, err)
	}
	return writeFile(root, rel, buf.Bytes())
}

// writeFile writes data to root/rel, creating directories.
func writeFile(root, rel string, data []byte) error {
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}
