// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package jsonutil is the strict JSON codec of the consensus API
// (docs/contract.md, "Encoding rules").
//
// encoding/json is too lenient for the contract: it matches keys
// case-insensitively, keeps the last of duplicate keys, accepts numbers for
// fields a schema declares as strings and treats a missing field as its zero
// value. This package decodes objects field by field instead:
//
//   - Validate rejects invalid JSON and duplicate keys (MALFORMED_JSON);
//   - DecodeObject matches keys exactly, rejects unknown keys at every level
//     (UNKNOWN_FIELD) and missing required fields (BAD_FIELD);
//   - the value types (Uint64String, HexBytesN, Bitlist32, BitvectorN,
//     QAddress, String) accept only their canonical string form (BAD_FIELD).
//
// Decoders read the request body in place and do not copy it. Every error is
// an *apierr.Error whose Field is the JSON path of the offending value.
package jsonutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
)

// Value is a JSON value with a strict decoder. UnmarshalJSON receives
// exactly one JSON value, without surrounding whitespace. MarshalJSON writes
// the canonical form, which UnmarshalJSON accepts.
type Value interface {
	json.Marshaler
	json.Unmarshaler
}

// Field is one key of a JSON object.
type Field struct {
	Name  string
	Value Value
	// Optional fields may be absent. EncodeObject omits an optional field
	// whose Value is nil.
	Optional bool
}

// maxFields is the number of fields one DecodeObject call can track.
const maxFields = 64

// DecodeObject decodes the JSON object b into fields. Keys must match a
// field name exactly, each at most once; every field that is not Optional
// must be present.
//
// b must be one JSON value, as passed to UnmarshalJSON or checked by
// Validate. DecodeObject never panics on other input, but its reasons are
// only meaningful for valid JSON.
func DecodeObject(b []byte, fields ...Field) error {
	if len(fields) > maxFields {
		return apierr.New(apierr.Internal, "too many fields")
	}
	i := skipSpace(b, 0)
	if i >= len(b) || b[i] != '{' {
		return wrongType("an object")
	}
	i = skipSpace(b, i+1)
	var seen uint64
	if i < len(b) && b[i] == '}' {
		i++
	} else {
		for {
			if i >= len(b) || b[i] != '"' {
				return malformed()
			}
			keyEnd, escaped, err := stringEnd(b, i)
			if err != nil {
				return err
			}
			key, err := unquote(b[i:keyEnd], escaped)
			if err != nil {
				return err
			}
			i = skipSpace(b, keyEnd)
			if i >= len(b) || b[i] != ':' {
				return malformed()
			}
			i = skipSpace(b, i+1)
			end, err := valueEnd(b, i)
			if err != nil {
				return err
			}
			k := match(fields, key)
			if k < 0 {
				return apierr.New(apierr.UnknownField, "unknown field").In(fieldName(key))
			}
			if seen&(1<<k) != 0 {
				return apierr.New(apierr.MalformedJSON, "duplicate key").In(fields[k].Name)
			}
			seen |= 1 << k
			if err := fields[k].Value.UnmarshalJSON(b[i:end]); err != nil {
				return within(err, fields[k].Name)
			}
			i = skipSpace(b, end)
			if i < len(b) && b[i] == ',' {
				i = skipSpace(b, i+1)
				continue
			}
			if i < len(b) && b[i] == '}' {
				i++
				break
			}
			return malformed()
		}
	}
	if skipSpace(b, i) != len(b) {
		return malformed()
	}
	for k, f := range fields {
		if !f.Optional && seen&(1<<k) == 0 {
			return apierr.New(apierr.BadField, "missing field").In(f.Name)
		}
	}
	return nil
}

func match(fields []Field, key []byte) int {
	for k := range fields {
		if fields[k].Name == string(key) {
			return k
		}
	}
	return -1
}

// within adds a path segment to err, which a Value returned for the field
// or element named segment.
func within(err error, segment string) error {
	var e *apierr.Error
	if errors.As(err, &e) {
		return e.In(segment)
	}
	return apierr.New(apierr.BadField, "invalid value").In(segment)
}

func wrongType(want string) *apierr.Error {
	return apierr.New(apierr.BadField, "wrong JSON type, want "+want)
}

// EncodeObject writes the fields in order as a JSON object, omitting
// optional fields whose Value is nil.
func EncodeObject(fields ...Field) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	first := true
	for _, f := range fields {
		if f.Value == nil {
			if f.Optional {
				continue
			}
			return nil, errors.New("jsonutil: required field " + f.Name + " has no value")
		}
		v, err := f.Value.MarshalJSON()
		if err != nil {
			return nil, err
		}
		if !first {
			buf.WriteByte(',')
		}
		first = false
		name, _ := json.Marshal(f.Name)
		buf.Write(name)
		buf.WriteByte(':')
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// DecodeArray calls elem for each element of the JSON array b, with the
// element's index and raw value, and returns the number of elements. A nil
// elem only counts. Errors from elem get the index as a path segment.
func DecodeArray(b []byte, elem func(i int, raw []byte) error) (int, error) {
	i := skipSpace(b, 0)
	if i >= len(b) || b[i] != '[' {
		return 0, wrongType("an array")
	}
	i = skipSpace(b, i+1)
	n := 0
	if i < len(b) && b[i] == ']' {
		i++
	} else {
		for {
			end, err := valueEnd(b, i)
			if err != nil {
				return 0, err
			}
			if elem != nil {
				if err := elem(n, b[i:end]); err != nil {
					return 0, within(err, apierr.Index(n))
				}
			}
			n++
			i = skipSpace(b, end)
			if i < len(b) && b[i] == ',' {
				i = skipSpace(b, i+1)
				continue
			}
			if i < len(b) && b[i] == ']' {
				i++
				break
			}
			return 0, malformed()
		}
	}
	if skipSpace(b, i) != len(b) {
		return 0, malformed()
	}
	return n, nil
}

// RawValue captures a JSON value without decoding it, so that a decoder can
// look at one key (such as `type`) before it decodes the others.
//
// When filled by DecodeObject, a RawValue aliases the decoded input and is
// valid only as long as that input is. It must not be used with
// encoding/json.Unmarshal, whose buffers are reused.
type RawValue []byte

// UnmarshalJSON stores b without copying it.
func (r *RawValue) UnmarshalJSON(b []byte) error {
	*r = b
	return nil
}

// MarshalJSON returns the captured value, or null.
func (r RawValue) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	return r, nil
}

// String is a JSON string. Escapes are decoded.
type String string

// UnmarshalJSON accepts only a JSON string.
func (s *String) UnmarshalJSON(b []byte) error {
	c, err := stringContent(b)
	if err != nil {
		return err
	}
	*s = String(c)
	return nil
}

// MarshalJSON quotes s.
func (s String) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}

// stringContent returns the content of the JSON string b, with escapes
// decoded, or BAD_FIELD if b is another JSON type.
func stringContent(b []byte) ([]byte, error) {
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return nil, wrongType("a string")
	}
	end, escaped, err := stringEnd(b, 0)
	if err != nil {
		return nil, err
	}
	if end != len(b) {
		return nil, malformed()
	}
	return unquote(b, escaped)
}

// Bytes is a JSON string decoded into a buffer of its own, escapes
// included, without passing through a Go string: a secret held in one (a
// password, a keystore) can be wiped once it is used. Bytes that are not
// valid UTF-8 are kept as they are.
type Bytes []byte

// UnmarshalJSON accepts only a JSON string.
func (v *Bytes) UnmarshalJSON(b []byte) error {
	if len(b) < 2 || b[0] != '"' || b[len(b)-1] != '"' {
		return wrongType("a string")
	}
	end, _, err := stringEnd(b, 0)
	if err != nil {
		return err
	}
	if end != len(b) {
		return malformed()
	}
	out, err := unescape(b[1 : len(b)-1])
	if err != nil {
		return err
	}
	*v = out
	return nil
}

// MarshalJSON quotes v.
func (v Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(v))
}

// unescape decodes the escapes of a JSON string's content into a new
// buffer. An unpaired surrogate becomes U+FFFD, as encoding/json does.
func unescape(s []byte) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		if i+1 >= len(s) {
			return nil, apierr.New(apierr.MalformedJSON, "invalid string escape")
		}
		i++
		switch s[i] {
		case '"', '\\', '/':
			out = append(out, s[i])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, ok := hex4(s, i+1)
			if !ok {
				return nil, apierr.New(apierr.MalformedJSON, "invalid string escape")
			}
			i += 4
			if utf16.IsSurrogate(r) {
				r2, ok := rune(-1), false
				if i+2 < len(s) && s[i+1] == '\\' && s[i+2] == 'u' {
					r2, ok = hex4(s, i+3)
				}
				if dec := utf16.DecodeRune(r, r2); ok && dec != unicode.ReplacementChar {
					r = dec
					i += 6
				} else {
					r = unicode.ReplacementChar
				}
			}
			out = utf8.AppendRune(out, r)
		default:
			return nil, apierr.New(apierr.MalformedJSON, "invalid string escape")
		}
	}
	return out, nil
}

// hex4 reads the four hex digits of a \u escape at s[i:].
func hex4(s []byte, i int) (rune, bool) {
	if i+4 > len(s) {
		return 0, false
	}
	var r rune
	for _, c := range s[i : i+4] {
		switch {
		case '0' <= c && c <= '9':
			c -= '0'
		case 'a' <= c && c <= 'f':
			c -= 'a' - 10
		case 'A' <= c && c <= 'F':
			c -= 'A' - 10
		default:
			return 0, false
		}
		r = r<<4 | rune(c)
	}
	return r, true
}
