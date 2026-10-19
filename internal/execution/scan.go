// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import "encoding/json"

// The functions below walk JSON that json.Valid has accepted. They check
// nothing and copy nothing: they only find where each value starts and
// ends, so that reading a request, a batch or a method's params costs
// about the same however many members or elements it carries that the
// signer does not use.
// Decoded whole, a 5 MiB body of tiny members or elements takes tens of
// times its size: into a map, a request object of 400,000 members costs
// over 100 MB, and into a slice, an array of 2.6 million numbers over
// 300 MB. On anything other than valid JSON they return wrong spans, but
// stay within data. (jsonutil's decoders are the consensus API's strict
// ones: they refuse unknown and repeated members, which a JSON-RPC request
// may have.)

// skipSpace returns the index of the first byte of data at or after i that
// is not JSON whitespace.
func skipSpace(data []byte, i int) int {
	for ; i < len(data); i++ {
		switch data[i] {
		case ' ', '\t', '\n', '\r':
		default:
			return i
		}
	}
	return i
}

// stringEnd returns the index just past the string that starts at data[i].
// No escape holds a quote other than the one it escapes: \u escapes are
// hex digits.
func stringEnd(data []byte, i int) int {
	for i++; i < len(data); i++ {
		switch data[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return len(data)
}

// valueEnd returns the index just past the value that starts at data[i].
func valueEnd(data []byte, i int) int {
	if i >= len(data) {
		return len(data)
	}
	switch data[i] {
	case '"':
		return stringEnd(data, i)
	case '{', '[':
		depth := 0
		for i < len(data) {
			switch data[i] {
			case '"':
				i = stringEnd(data, i)
				continue
			case '{', '[':
				depth++
			case '}', ']':
				if depth--; depth == 0 {
					return i + 1
				}
			}
			i++
		}
		return len(data)
	default: // a number, true, false or null, whose first byte is none of the bytes that end it
		for i++; i < len(data); i++ {
			switch data[i] {
			case ',', '}', ']', ' ', '\t', '\n', '\r':
				return i
			}
		}
		return i
	}
}

// members calls fn with the raw name (the JSON string, quotes included)
// and the raw value of each member of the object data, in order. It
// reports false, and calls fn for none, when data is not an object.
func members(data []byte, fn func(name, value []byte)) bool {
	i := skipSpace(data, 0)
	if i >= len(data) || data[i] != '{' {
		return false
	}
	for i = skipSpace(data, i+1); i < len(data) && data[i] != '}'; i = skipSpace(data, i) {
		if data[i] == ',' {
			i = skipSpace(data, i+1)
		}
		nameEnd := stringEnd(data, i)
		name := data[i:nameEnd]
		i = skipSpace(data, min(skipSpace(data, nameEnd)+1, len(data))) // past the ':'
		end := valueEnd(data, i)
		fn(name, data[i:end])
		i = end
	}
	return true
}

// elements returns the raw elements of the array data, in order, as
// slices of data. It reports false when data is not an array or has more
// than limit elements, which it counts as it goes: it never collects more
// than limit, and allocates nothing else.
func elements(data []byte, limit int) ([]json.RawMessage, bool) {
	i := skipSpace(data, 0)
	if i >= len(data) || data[i] != '[' {
		return nil, false
	}
	var elems []json.RawMessage
	for i = skipSpace(data, i+1); i < len(data) && data[i] != ']'; i = skipSpace(data, i) {
		if data[i] == ',' {
			i = skipSpace(data, i+1)
		}
		if len(elems) == limit {
			return nil, false
		}
		end := valueEnd(data, i)
		elems = append(elems, data[i:end])
		i = end
	}
	return elems, true
}

// memberName decodes the name of a member from its raw JSON string into
// buf, as encoding/json decodes a map key, when that name could be one of
// a request's. It returns nil for any other name: one longer than buf, or
// with an escape that is not a \u escape of an ASCII character (the names
// a request defines are all ASCII letters, and only a \u escape stands for
// a letter). Comparing the result with a name therefore matches the member
// exactly as a decoded map key would, case included.
func memberName(raw []byte, buf *[len("jsonrpc")]byte) []byte {
	if len(raw) < 2 {
		return nil
	}
	s := raw[1 : len(raw)-1]
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' {
			if i+5 >= len(s) || s[i+1] != 'u' {
				return nil
			}
			r, ok := hex4(s[i+2 : i+6])
			if !ok || r >= 0x80 {
				return nil
			}
			c = byte(r)
			i += 5
		}
		if n == len(buf) {
			return nil
		}
		buf[n] = c
		n++
	}
	return buf[:n]
}

// hex4 decodes the four hex digits of a \u escape.
func hex4(h []byte) (rune, bool) {
	var r rune
	for _, c := range h {
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
