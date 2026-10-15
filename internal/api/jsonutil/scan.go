// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package jsonutil

import (
	"bytes"
	"encoding/json"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
)

// Validate is the pre-scan every request body passes before it is decoded:
// the body must be syntactically valid JSON with no duplicate key in any
// object. Both failures are MALFORMED_JSON, so they take precedence over the
// field-level reasons a decoder reports. Keys are compared after unescaping,
// so "slot" and "slot" are duplicates.
func Validate(b []byte) error {
	if !json.Valid(b) {
		return apierr.New(apierr.MalformedJSON, "body is not valid JSON")
	}
	return checkDuplicateKeys(b)
}

// keySet holds the keys of one object. Objects in the contract have at most
// six keys, so a slice is searched first; a map takes over for large objects
// so that a hostile body cannot make the scan quadratic.
type keySet struct {
	object    bool
	expectKey bool
	keys      []string
	set       map[string]struct{}
}

const keySetSliceMax = 16

// add records key and reports whether it was new.
func (s *keySet) add(key string) bool {
	if s.set != nil {
		if _, dup := s.set[key]; dup {
			return false
		}
		s.set[key] = struct{}{}
		return true
	}
	for _, k := range s.keys {
		if k == key {
			return false
		}
	}
	if len(s.keys) < keySetSliceMax {
		s.keys = append(s.keys, key)
		return true
	}
	s.set = make(map[string]struct{}, 2*keySetSliceMax)
	for _, k := range s.keys {
		s.set[k] = struct{}{}
	}
	s.set[key] = struct{}{}
	s.keys = nil
	return true
}

// checkDuplicateKeys scans valid JSON and fails on the first object that
// repeats a key.
func checkDuplicateKeys(b []byte) error {
	var stack []keySet
	for i := 0; i < len(b); {
		switch c := b[i]; c {
		case '{':
			stack = append(stack, keySet{object: true, expectKey: true})
			i++
		case '[':
			stack = append(stack, keySet{})
			i++
		case '}', ']':
			if len(stack) == 0 {
				return malformed()
			}
			stack = stack[:len(stack)-1]
			i++
		case ',':
			if n := len(stack); n > 0 && stack[n-1].object {
				stack[n-1].expectKey = true
			}
			i++
		case '"':
			end, escaped, err := stringEnd(b, i)
			if err != nil {
				return err
			}
			if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].expectKey {
				key, err := unquote(b[i:end], escaped)
				if err != nil {
					return err
				}
				if !stack[n-1].add(string(key)) {
					return apierr.New(apierr.MalformedJSON, "duplicate key "+fieldName(key))
				}
				stack[n-1].expectKey = false
			}
			i = end
		default:
			i++
		}
	}
	return nil
}

// malformed returns a fresh error: callers extend the field path of the errors
// they receive, so errors are never shared.
func malformed() *apierr.Error { return apierr.New(apierr.MalformedJSON, "body is not valid JSON") }

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func skipSpace(b []byte, i int) int {
	for i < len(b) && isSpace(b[i]) {
		i++
	}
	return i
}

// stringEnd returns the index just past the closing quote of the JSON string
// that starts at b[i], and whether the string contains escapes.
func stringEnd(b []byte, i int) (end int, escaped bool, err error) {
	for j := i + 1; j <= len(b); {
		k := bytes.IndexByte(b[j:], '"')
		if k < 0 {
			break
		}
		q := j + k
		backslashes := 0
		for p := q - 1; p > i && b[p] == '\\'; p-- {
			backslashes++
		}
		if backslashes%2 == 0 {
			return q + 1, bytes.IndexByte(b[i+1:q], '\\') >= 0, nil
		}
		j = q + 1
	}
	return 0, false, apierr.New(apierr.MalformedJSON, "unterminated string")
}

// valueEnd returns the index just past the JSON value that starts at b[i].
func valueEnd(b []byte, i int) (int, error) {
	if i >= len(b) {
		return 0, malformed()
	}
	switch b[i] {
	case '"':
		end, _, err := stringEnd(b, i)
		return end, err
	case '{', '[':
		depth := 0
		for j := i; j < len(b); {
			switch b[j] {
			case '"':
				end, _, err := stringEnd(b, j)
				if err != nil {
					return 0, err
				}
				j = end
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return j + 1, nil
				}
			}
			j++
		}
		return 0, malformed()
	default:
		j := i
		for j < len(b) && !isSpace(b[j]) && b[j] != ',' && b[j] != '}' && b[j] != ']' {
			j++
		}
		if j == i {
			return 0, malformed()
		}
		return j, nil
	}
}

// unquote returns the content of the JSON string token s.
func unquote(s []byte, escaped bool) ([]byte, error) {
	if !escaped {
		return s[1 : len(s)-1], nil
	}
	var out string
	if err := json.Unmarshal(s, &out); err != nil {
		return nil, apierr.New(apierr.MalformedJSON, "invalid string escape")
	}
	return []byte(out), nil
}

// fieldName renders a key for an error path or detail. Keys made of
// identifier characters are shown as they are; anything else is quoted in
// ASCII and truncated, so request data cannot inject text into logs.
func fieldName(key []byte) string {
	const maxLen = 40
	plain := len(key) > 0 && len(key) <= maxLen
	for _, c := range key {
		if !isIdentChar(c) {
			plain = false
			break
		}
	}
	if plain {
		return string(key)
	}
	if len(key) > maxLen {
		key = key[:maxLen]
	}
	out := []byte{'"'}
	for _, c := range key {
		if c >= 0x20 && c < 0x7f && c != '"' && c != '\\' {
			out = append(out, c)
		} else {
			out = append(out, '?')
		}
	}
	return string(append(out, '"'))
}

func isIdentChar(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}
