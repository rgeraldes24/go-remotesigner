// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package interchange_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/interchange"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// An export always names its network, also when it holds no validator (PLAN S8; SP §18.2 fix 5).
func TestEmptyExportCarriesTheGenesisValidatorsRoot(t *testing.T) {
	want := `{
  "metadata": {
    "interchange_format_version": "5",
    "genesis_validators_root": "` + hx(gvr[:]) + `"
  },
  "data": []
}
`
	t.Run("pinned store", func(t *testing.T) {
		forEachStore(t, func(t *testing.T, s slashing.Store) {
			_, err := s.PinGenesisValidatorsRoot(bg, gvr)
			must(t, err)
			must(t, s.RegisterValidators(bg, [][]byte{slashingtest.Key(0)})) // registered, never signed
			var buf bytes.Buffer
			_, err = interchange.Export(bg, s, &buf, interchange.ExportOptions{})
			must(t, err)
			if buf.String() != want {
				t.Fatalf("export:\n%s\nwant:\n%s", buf.String(), want)
			}
		})
	})
	t.Run("unpinned store with the network's root", func(t *testing.T) {
		forEachStore(t, func(t *testing.T, s slashing.Store) {
			var buf bytes.Buffer
			root := gvr
			_, err := interchange.Export(bg, s, &buf, interchange.ExportOptions{GenesisValidatorsRoot: &root})
			must(t, err)
			if buf.String() != want {
				t.Fatalf("export:\n%s\nwant:\n%s", buf.String(), want)
			}
		})
	})
	t.Run("a network root that differs from the store's", func(t *testing.T) {
		forEachStore(t, func(t *testing.T, s slashing.Store) {
			_, err := s.PinGenesisValidatorsRoot(bg, gvr)
			must(t, err)
			other := slashing.Root{1}
			_, err = interchange.Export(bg, s, &bytes.Buffer{}, interchange.ExportOptions{GenesisValidatorsRoot: &other})
			if !errors.Is(err, slashing.ErrGenesisValidatorsRootMismatch) {
				t.Fatalf("export: %v", err)
			}
		})
	})
}

// The layout is fixed: one record per line, lowercase hex, roots left out when unknown. The golden vectors' signer
// export depends on it.
func TestExportLayout(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		importDoc(t, s, doc(gvr, jEntry{Pubkey: pk(0),
			Blocks: []jBlock{blk(7, nil), blk(9, root(9))},
			Atts:   []jAtt{att(1, 2, root(2)), att(2, 3, nil)}}))
		var buf bytes.Buffer
		_, err := interchange.Export(bg, s, &buf, interchange.ExportOptions{})
		must(t, err)
		want := `{
  "metadata": {
    "interchange_format_version": "5",
    "genesis_validators_root": "` + hx(gvr[:]) + `"
  },
  "data": [
    {
      "pubkey": "` + pk(0) + `",
      "signed_blocks": [
        {"slot": "7"},
        {"slot": "9", "signing_root": "` + *root(9) + `"}
      ],
      "signed_attestations": [
        {"source_epoch": "1", "target_epoch": "2", "signing_root": "` + *root(2) + `"},
        {"source_epoch": "2", "target_epoch": "3"}
      ]
    }
  ]
}
`
		if buf.String() != want {
			t.Fatalf("export:\n%s\nwant:\n%s", buf.String(), want)
		}
	})
}

// Export, import into an empty store and export again: the two files are identical.
func TestExportImportRoundTrip(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		// Key 0 has attestations only, key 5 nothing: a validator without a watermark has no history to export.
		entries := []any{jEntry{Pubkey: pk(0), Atts: []jAtt{att(4, 5, root(1))}}, jEntry{Pubkey: pk(5)}}
		for i := 1; i < 5; i++ {
			e := jEntry{Pubkey: pk(i)}
			for j := range uint64(i) {
				e.Blocks = append(e.Blocks, blk(100*j+uint64(i), root(j)))
				e.Atts = append(e.Atts, att(j, j+1, nil))
			}
			entries = append(entries, e)
		}
		importDoc(t, s, doc(gvr, entries...))
		var first bytes.Buffer
		res, err := interchange.Export(bg, s, &first, interchange.ExportOptions{})
		must(t, err)
		if res.Validators != 5 || res.Blocks != 10 || res.Attestations != 11 {
			t.Fatalf("result %+v", res)
		}
		for _, other := range stores {
			s2 := other.open(t)
			importDoc(t, s2, first.String())
			var second bytes.Buffer
			_, err = interchange.Export(bg, s2, &second, interchange.ExportOptions{})
			must(t, err)
			_ = s2.Close()
			if first.String() != second.String() {
				t.Fatalf("round trip through %s differs:\n%s\n---\n%s", other.name, first.String(), second.String())
			}
		}
		if !strings.Contains(first.String(), `"signed_blocks": [],`) {
			t.Fatal("key 0's empty block list is missing")
		}
	})
}
