// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package interchange_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/interchange"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
)

// FuzzInterchange feeds arbitrary files to the importer. Whatever the input, the import must not panic, only
// 2,592-byte keys may reach the store, and what the store then exports must import again without a failure and
// reach a fixed point after one more round: a signer can always read back its own exports.
func FuzzInterchange(f *testing.F) {
	f.Add([]byte(doc(gvr, jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(1, root(1)), blk(1, root(2))},
		Atts: []jAtt{att(1, 2, nil), att(0, 3, root(3))}})))
	f.Add([]byte(doc(gvr, jEntry{Pubkey: pk(0), Atts: []jAtt{att(3, 4, nil)}},
		jEntry{Pubkey: pk(0), Atts: []jAtt{att(1, 8, nil)}}, `{"pubkey":"0x00"}`, jEntry{Pubkey: pk(1)})))
	f.Add([]byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x` +
		"00000000000000000000000000000000000000000000000000000000000000aa" + `"},"data":null}`))
	f.Add([]byte(`{"data":[],"metadata":{}}`))
	f.Add([]byte(`{"metadata":{"interchange_format_version":"5"`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s := memstore.New()
		res, _ := interchange.Import(bg, s, bytes.NewReader(data), interchange.ImportOptions{Batch: 2})
		fuzzKeyLengths(t, s, res)
		first, ok := fuzzExport(t, s)
		if !ok {
			return
		}
		second := fuzzRoundTrip(t, first)
		if third := fuzzRoundTrip(t, second); !bytes.Equal(second, third) {
			t.Fatalf("no fixed point:\n%s\n---\n%s", second, third)
		}
	})
}

// fuzzKeyLengths checks that only 2,592-byte keys reach the result and the store, whatever the file held.
func fuzzKeyLengths(t *testing.T, s slashing.Store, res interchange.ImportResult) {
	for _, v := range res.Validators {
		if v.PublicKey != nil && len(v.PublicKey) != slashing.PublicKeyLength {
			t.Fatalf("data[%d] has a %d-byte key", v.Index, len(v.PublicKey))
		}
	}
	err := s.ViewHistory(bg, func(v slashing.HistoryView) error {
		return v.Validators(func(_ slashing.KeyID, pk []byte) error {
			if len(pk) != slashing.PublicKeyLength {
				t.Fatalf("the store holds a %d-byte key", len(pk))
			}
			return nil
		})
	})
	if err != nil {
		t.Fatalf("view: %v", err)
	}
}

// fuzzExport exports s; it reports false when the store was never pinned to a network.
func fuzzExport(t *testing.T, s slashing.Store) ([]byte, bool) {
	var buf bytes.Buffer
	_, err := interchange.Export(bg, s, &buf, interchange.ExportOptions{})
	if errors.Is(err, slashing.ErrNoGenesisValidatorsRoot) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	return buf.Bytes(), true
}

// fuzzRoundTrip imports an export into an empty store and exports it again.
func fuzzRoundTrip(t *testing.T, export []byte) []byte {
	s := memstore.New()
	res, err := interchange.Import(bg, s, bytes.NewReader(export), interchange.ImportOptions{})
	if err != nil || len(res.Failed()) != 0 {
		t.Fatalf("re-import of an export: %v %+v\n%s", err, res.Failed(), export)
	}
	out, ok := fuzzExport(t, s)
	if !ok {
		t.Fatal("re-imported export did not pin the store")
	}
	return out
}
