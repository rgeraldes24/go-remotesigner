// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package interchange_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing/interchange"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

type decoded struct {
	meta    *interchange.Metadata
	entries []interchange.Entry
	errs    []*interchange.EntryError
}

func decode(d string) (decoded, error) {
	var out decoded
	err := interchange.Decode(strings.NewReader(d),
		func(m interchange.Metadata) error { out.meta = &m; return nil },
		func(i int, e interchange.Entry, eerr *interchange.EntryError) error {
			if i != len(out.entries)+len(out.errs) {
				return errors.New("entries out of order")
			}
			if eerr != nil {
				out.errs = append(out.errs, eerr)
			} else {
				out.entries = append(out.entries, e)
			}
			return nil
		})
	return out, err
}

func TestDecodeAcceptsQRLFiles(t *testing.T) {
	key := slashingtest.Key(3)
	// Uppercase hex, a missing 0x prefix, null roots and null arrays are all read.
	d := `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` +
		strings.ToUpper(hx(gvr[:])[2:]) + `"},"data":[` +
		`{"pubkey":"` + strings.ToUpper(pk(3)) + `","signed_blocks":[{"slot":"0"},{"slot":"18446744073709551615","signing_root":null}],` +
		`"signed_attestations":[{"source_epoch":"1","target_epoch":"2","signing_root":"` + *root(7) + `"}]},` +
		`{"signed_attestations":null,"pubkey":"` + pk(4) + `","signed_blocks":null},` +
		`{"pubkey":"` + pk(5) + `"}]}`
	got, err := decode(d)
	must(t, err)
	if got.meta == nil || got.meta.GenesisValidatorsRoot != gvr || len(got.errs) != 0 || len(got.entries) != 3 {
		t.Fatalf("decoded %+v", got)
	}
	e := got.entries[0]
	if !bytes.Equal(e.PublicKey, key) || len(e.Blocks) != 2 || e.Blocks[1].Slot != 1<<64-1 || e.Blocks[1].SigningRoot != nil ||
		len(e.Attestations) != 1 || *e.Attestations[0].SigningRoot != slashingtest.RootOf(7) {
		t.Fatalf("entry %+v", e)
	}
	if len(got.entries[1].Blocks)+len(got.entries[1].Attestations)+len(got.entries[2].Blocks) != 0 {
		t.Fatalf("null and missing arrays: %+v", got.entries[1:])
	}
}

func TestDecodeRefusesMalformedFiles(t *testing.T) {
	meta := `"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + hx(gvr[:]) + `"}`
	for name, tc := range map[string]struct {
		doc  string
		want error
	}{
		"empty":                          {``, interchange.ErrFormat},
		"not an object":                  {`[]`, interchange.ErrFormat},
		"syntax error":                   {`{` + meta + `,"data":[{]}`, interchange.ErrFormat},
		"metadata missing":               {`{"data":[]}`, interchange.ErrFormat},
		"metadata after data":            {`{"data":[],` + meta + `}`, interchange.ErrFormat},
		"metadata repeated":              {`{` + meta + `,` + meta + `}`, interchange.ErrFormat},
		"unknown top-level field":        {`{` + meta + `,"extra":1}`, interchange.ErrFormat},
		"trailing data":                  {`{` + meta + `} {}`, interchange.ErrFormat},
		"data is an object":              {`{` + meta + `,"data":{}}`, interchange.ErrFormat},
		"metadata is null":               {`{"metadata":null}`, interchange.ErrFormat},
		"version 4":                      {`{"metadata":{"interchange_format_version":"4","genesis_validators_root":"` + hx(gvr[:]) + `"}}`, interchange.ErrVersion},
		"version as a number":            {`{"metadata":{"interchange_format_version":5,"genesis_validators_root":"` + hx(gvr[:]) + `"}}`, interchange.ErrFormat},
		"version missing":                {`{"metadata":{"genesis_validators_root":"` + hx(gvr[:]) + `"}}`, interchange.ErrFormat},
		"genesis validators root short":  {`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x1234"}}`, interchange.ErrFormat},
		"genesis validators root absent": {`{"metadata":{"interchange_format_version":"5"}}`, interchange.ErrFormat},
		"unknown metadata field":         {`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + hx(gvr[:]) + `","x":"y"}}`, interchange.ErrFormat},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decode(tc.doc); !errors.Is(err, tc.want) {
				t.Fatalf("decode: %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDecodeReportsInvalidEntries(t *testing.T) {
	key := `"pubkey":"` + pk(1) + `"`
	for name, tc := range map[string]struct {
		entry   string
		want    string
		withKey bool
	}{
		"not an object":            {`[]`, "want an object", false},
		"public key missing":       {`{"signed_blocks":[]}`, "pubkey is missing", false},
		"public key of 48 bytes":   {`{"pubkey":"0x` + strings.Repeat("ab", 48) + `"}`, "pubkey: want 2592 bytes", false},
		"public key not hex":       {`{"pubkey":"0x` + strings.Repeat("zz", 2592) + `"}`, "not hex", false},
		"public key repeated":      {`{` + key + `,` + key + `}`, "appears twice", true},
		"unknown entry field":      {`{` + key + `,"signed_votes":[]}`, "unknown field signed_votes", true},
		"blocks not an array":      {`{` + key + `,"signed_blocks":{}}`, "signed_blocks: want an array", true},
		"slot missing":             {`{` + key + `,"signed_blocks":[{}]}`, "signed_blocks[0].slot is missing", true},
		"slot as a number":         {`{` + key + `,"signed_blocks":[{"slot":1}]}`, "want a string", true},
		"slot with a leading zero": {`{` + key + `,"signed_blocks":[{"slot":"01"}]}`, "want a decimal string", true},
		"slot negative":            {`{` + key + `,"signed_blocks":[{"slot":"-1"}]}`, "want a decimal string", true},
		"slot above uint64":        {`{` + key + `,"signed_blocks":[{"slot":"18446744073709551616"}]}`, "out of the uint64 range", true},
		"root of 3 bytes":          {`{` + key + `,"signed_blocks":[{"slot":"1","signing_root":"0x123456"}]}`, "want 32 bytes", true},
		"root as a number":         {`{` + key + `,"signed_blocks":[{"slot":"1","signing_root":1}]}`, "want a string or null", true},
		"unknown block field":      {`{` + key + `,"signed_blocks":[{"slot":"1","root":"x"}]}`, "unknown field signed_blocks[0].root", true},
		"source missing":           {`{` + key + `,"signed_attestations":[{"target_epoch":"1"}]}`, "source_epoch is missing", true},
		"target missing":           {`{` + key + `,"signed_attestations":[{"source_epoch":"1"}]}`, "target_epoch is missing", true},
		"target repeated":          {`{` + key + `,"signed_attestations":[{"source_epoch":"1","target_epoch":"2","target_epoch":"3"}]}`, "appears twice", true},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := decode(doc(gvr, tc.entry, jEntry{Pubkey: pk(2)}))
			must(t, err)
			if len(got.errs) != 1 || len(got.entries) != 1 {
				t.Fatalf("decoded %+v", got)
			}
			e := got.errs[0]
			if e.Index != 0 || !strings.Contains(e.Error(), tc.want) || (e.PublicKey != nil) != tc.withKey {
				t.Fatalf("entry error %q (key %v), want %q (key %v)", e, e.PublicKey != nil, tc.want, tc.withKey)
			}
			if tc.withKey && !bytes.Equal(e.PublicKey, slashingtest.Key(1)) {
				t.Fatal("wrong public key in the entry error")
			}
		})
	}
}

func TestDecodeStopsAtCallbackErrors(t *testing.T) {
	stop := errors.New("stop")
	d := doc(gvr, jEntry{Pubkey: pk(0)}, jEntry{Pubkey: pk(1)})
	calls := 0
	err := interchange.Decode(strings.NewReader(d), func(interchange.Metadata) error { return nil },
		func(int, interchange.Entry, *interchange.EntryError) error { calls++; return stop })
	if !errors.Is(err, stop) || calls != 1 {
		t.Fatalf("entry callback error: %v after %d calls", err, calls)
	}
	err = interchange.Decode(strings.NewReader(d), func(interchange.Metadata) error { return stop },
		func(int, interchange.Entry, *interchange.EntryError) error {
			t.Fatal("entry after a metadata error")
			return nil
		})
	if !errors.Is(err, stop) {
		t.Fatalf("metadata callback error: %v", err)
	}
}
