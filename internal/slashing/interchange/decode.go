// Copyright 2020 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/model/Metadata.java,
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/model/SignedBlock.java,
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/model/SignedAttestation.java
// and slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/InterchangeJsonProvider.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

// Package interchange reads and writes EIP-3076 slashing-protection interchange files, format version 5, with QRL's
// 2,592-byte ML-DSA-87 public keys, and imports them into and exports them from a slashing.Store.
//
// The codec streams: a file is read one validator entry at a time and written one record at a time, so its size is
// not bounded by memory. It is strict where a lax reading could lose history: the metadata must come before the
// data, unknown and repeated fields are refused, public keys must be exactly 2,592 bytes and roots exactly 32, and
// slots and epochs are canonical decimal strings. Hex may carry a 0x prefix and either case; files are written in
// lowercase with the prefix.
package interchange

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// FormatVersion is the only interchange_format_version this package reads and writes.
const FormatVersion = "5"

var (
	// ErrFormat: the file is not an interchange document this package can read. Nothing after the error was read.
	ErrFormat = errors.New("interchange: malformed file")
	// ErrVersion: the file's interchange_format_version is not FormatVersion.
	ErrVersion = errors.New("interchange: unsupported interchange_format_version, want \"5\"")
)

// Metadata is the file's metadata object.
type Metadata struct {
	GenesisValidatorsRoot slashing.Root
}

// Entry is one validator's history: one element of the file's data array.
type Entry struct {
	PublicKey    []byte
	Blocks       []slashing.SignedBlock
	Attestations []slashing.SignedAttestation
}

// EntryError is a data element that is well-formed JSON but not a valid entry. Decoding continues after it.
type EntryError struct {
	// Index is the element's position in the data array.
	Index int
	// PublicKey is the entry's public key when that field was valid, so that the key can still be acted on.
	PublicKey []byte
	Err       error
}

func (e *EntryError) Error() string { return fmt.Sprintf("data[%d]: %v", e.Index, e.Err) }

func (e *EntryError) Unwrap() error { return e.Err }

// Decode reads an interchange document from r. It calls meta once, before any entry, and then entry for each element
// of the data array, in order, with the element's index and a nil *EntryError for a valid entry. A missing or null data array has no
// entries. Decode stops at the first error a callback returns, and at anything that makes the rest of the file
// unreadable (wrapped in ErrFormat or ErrVersion); callbacks may already have run for the entries before it.
func Decode(r io.Reader, meta func(Metadata) error, entry func(int, Entry, *EntryError) error) error {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	if err := expectDelim(dec, '{', "the document"); err != nil {
		return err
	}
	seen := map[string]bool{}
	for dec.More() {
		key, err := objectKey(dec, "the document", seen)
		if err != nil {
			return formatErr("%v", err)
		}
		switch key {
		case "metadata":
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return formatErr("metadata: %v", err)
			}
			m, err := parseMetadata(raw)
			if err != nil {
				return err
			}
			if err := meta(m); err != nil {
				return err
			}
		case "data":
			if !seen["metadata"] {
				return formatErr("metadata must come before data")
			}
			if err := decodeData(dec, entry); err != nil {
				return err
			}
		default:
			return formatErr("unknown field %q", key)
		}
	}
	if err := expectDelim(dec, '}', "the document"); err != nil {
		return err
	}
	if !seen["metadata"] {
		return formatErr("metadata is missing")
	}
	if _, err := dec.Token(); err != io.EOF {
		return formatErr("data after the document")
	}
	return nil
}

func decodeData(dec *json.Decoder, entry func(int, Entry, *EntryError) error) error {
	tok, err := dec.Token()
	if err != nil {
		return formatErr("data: %v", err)
	}
	if tok == nil {
		return nil
	}
	if tok != json.Delim('[') {
		return formatErr("data: want an array")
	}
	for i := 0; dec.More(); i++ {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return formatErr("data[%d]: %v", i, err)
		}
		e, err := parseEntry(raw)
		var eerr *EntryError
		if err != nil {
			eerr = &EntryError{Index: i, PublicKey: entryKey(raw), Err: err}
		}
		if err := entry(i, e, eerr); err != nil {
			return err
		}
	}
	return expectDelim(dec, ']', "data")
}

func parseMetadata(raw []byte) (Metadata, error) {
	var (
		m       Metadata
		version string
		gvr     []byte
	)
	dec := newStrict(raw)
	err := dec.object("metadata", func(key, path string) error {
		var err error
		switch key {
		case "interchange_format_version":
			version, err = dec.str(path)
		case "genesis_validators_root":
			gvr, err = dec.hex(path, len(m.GenesisValidatorsRoot))
		default:
			err = fmt.Errorf("unknown field %s", path)
		}
		return err
	})
	switch {
	case err != nil:
		return m, formatErr("%v", err)
	case version == "":
		return m, formatErr("metadata.interchange_format_version is missing")
	case version != FormatVersion:
		return m, fmt.Errorf("%w: got %q", ErrVersion, version)
	case gvr == nil:
		return m, formatErr("metadata.genesis_validators_root is missing")
	}
	copy(m.GenesisValidatorsRoot[:], gvr)
	return m, nil
}

func parseEntry(raw []byte) (Entry, error) {
	var e Entry
	dec := newStrict(raw)
	err := dec.object("", func(key, path string) error {
		switch key {
		case "pubkey":
			pk, err := dec.hex(path, slashing.PublicKeyLength)
			e.PublicKey = pk
			return err
		case "signed_blocks":
			return dec.array(path, func(path string) error {
				b, err := parseBlock(dec, path)
				e.Blocks = append(e.Blocks, b)
				return err
			})
		case "signed_attestations":
			return dec.array(path, func(path string) error {
				a, err := parseAttestation(dec, path)
				e.Attestations = append(e.Attestations, a)
				return err
			})
		}
		return fmt.Errorf("unknown field %s", path)
	})
	if err == nil && e.PublicKey == nil {
		err = errors.New("pubkey is missing")
	}
	return e, err
}

func parseBlock(dec *strict, path string) (slashing.SignedBlock, error) {
	var (
		b       slashing.SignedBlock
		hasSlot bool
	)
	err := dec.object(path, func(key, p string) error {
		var err error
		switch key {
		case "slot":
			b.Slot, err = dec.uint64(p)
			hasSlot = true
		case "signing_root":
			b.SigningRoot, err = dec.root(p)
		default:
			err = fmt.Errorf("unknown field %s", p)
		}
		return err
	})
	if err == nil && !hasSlot {
		err = fmt.Errorf("%s.slot is missing", path)
	}
	return b, err
}

func parseAttestation(dec *strict, path string) (slashing.SignedAttestation, error) {
	var (
		a                 slashing.SignedAttestation
		hasSource, hasTgt bool
	)
	err := dec.object(path, func(key, p string) error {
		var err error
		switch key {
		case "source_epoch":
			a.SourceEpoch, err = dec.uint64(p)
			hasSource = true
		case "target_epoch":
			a.TargetEpoch, err = dec.uint64(p)
			hasTgt = true
		case "signing_root":
			a.SigningRoot, err = dec.root(p)
		default:
			err = fmt.Errorf("unknown field %s", p)
		}
		return err
	})
	switch {
	case err != nil:
	case !hasSource:
		err = fmt.Errorf("%s.source_epoch is missing", path)
	case !hasTgt:
		err = fmt.Errorf("%s.target_epoch is missing", path)
	}
	return a, err
}

// entryKey returns the public key of a data element whose other fields may be invalid, or nil.
func entryKey(raw []byte) []byte {
	var e struct {
		Pubkey *string `json:"pubkey"`
	}
	if json.Unmarshal(raw, &e) != nil || e.Pubkey == nil {
		return nil
	}
	pk, err := parseHex(*e.Pubkey, slashing.PublicKeyLength)
	if err != nil {
		return nil
	}
	return pk
}

// strict walks one JSON value token by token, refusing repeated keys and values of the wrong type.
type strict struct{ dec *json.Decoder }

func newStrict(raw []byte) *strict {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return &strict{dec}
}

// object reads an object and calls field for each key, which must consume the value.
func (s *strict) object(path string, field func(key, path string) error) error {
	tok, err := s.dec.Token()
	if err != nil {
		return err
	}
	if tok != json.Delim('{') {
		return fmt.Errorf("%s: want an object", describe(path))
	}
	seen := map[string]bool{}
	for s.dec.More() {
		key, err := objectKey(s.dec, describe(path), seen)
		if err != nil {
			return err
		}
		if err := field(key, join(path, key)); err != nil {
			return err
		}
	}
	_, err = s.dec.Token()
	return err
}

// array reads an array, or null as an empty one, and calls elem for each element, which must consume it.
func (s *strict) array(path string, elem func(path string) error) error {
	tok, err := s.dec.Token()
	if err != nil {
		return err
	}
	if tok == nil {
		return nil
	}
	if tok != json.Delim('[') {
		return fmt.Errorf("%s: want an array", path)
	}
	for i := 0; s.dec.More(); i++ {
		if err := elem(fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
	}
	_, err = s.dec.Token()
	return err
}

// str reads a string.
func (s *strict) str(path string) (string, error) {
	tok, err := s.dec.Token()
	if err != nil {
		return "", err
	}
	v, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("%s: want a string", path)
	}
	return v, nil
}

// uint64 reads a decimal string.
func (s *strict) uint64(path string) (uint64, error) {
	v, err := s.str(path)
	if err != nil {
		return 0, err
	}
	n, err := parseUint64(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	return n, nil
}

// hex reads a hex string of exactly n bytes.
func (s *strict) hex(path string, n int) ([]byte, error) {
	v, err := s.str(path)
	if err != nil {
		return nil, err
	}
	b, err := parseHex(v, n)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return b, nil
}

// root reads an optional signing root: a 32-byte hex string, or null.
func (s *strict) root(path string) (*slashing.Root, error) {
	tok, err := s.dec.Token()
	if err != nil || tok == nil {
		return nil, err
	}
	v, ok := tok.(string)
	if !ok {
		return nil, fmt.Errorf("%s: want a string or null", path)
	}
	b, err := parseHex(v, len(slashing.Root{}))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	r := slashing.Root(b)
	return &r, nil
}

func objectKey(dec *json.Decoder, where string, seen map[string]bool) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", fmt.Errorf("%s: %w", where, err)
	}
	key, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("%s: want a field name", where)
	}
	if seen[key] {
		return "", fmt.Errorf("%s: field %q appears twice", where, key)
	}
	seen[key] = true
	return key, nil
}

func expectDelim(dec *json.Decoder, want json.Delim, where string) error {
	tok, err := dec.Token()
	if err != nil {
		return formatErr("%s: %v", where, err)
	}
	if tok != want {
		return formatErr("%s: want %q", where, want)
	}
	return nil
}

// parseUint64 accepts the canonical decimal form of a uint64: digits only, no sign and no leading zero.
func parseUint64(s string) (uint64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') || strings.TrimLeft(s, "0123456789") != "" {
		return 0, errors.New("want a decimal string")
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, errors.New("out of the uint64 range")
	}
	return n, nil
}

// parseHex decodes a hex string of exactly n bytes, with an optional 0x prefix, in either case.
func parseHex(s string, n int) ([]byte, error) {
	h := s
	if strings.HasPrefix(h, "0x") || strings.HasPrefix(h, "0X") {
		h = h[2:]
	}
	if len(h) != 2*n {
		return nil, fmt.Errorf("want %d bytes of hex, got %d characters", n, len(h))
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, errors.New("not hex")
	}
	return b, nil
}

func formatErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrFormat}, args...)...)
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func describe(path string) string {
	if path == "" {
		return "the entry"
	}
	return path
}
