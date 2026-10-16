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

// request is a block (when block is set) or an attestation request for test key key, with signing root RootOf(root).
type request struct {
	key            int
	block          bool
	slot           uint64
	source, target uint64
	root           uint64
}

func blockReq(key int, slot, root uint64) request {
	return request{key: key, block: true, slot: slot, root: root}
}

func attReq(key int, source, target, root uint64) request {
	return request{key: key, source: source, target: target, root: root}
}

// decide runs r through e, recording it when it is allowed.
func decide(t *testing.T, e *slashing.Engine, r request) slashing.Decision {
	t.Helper()
	var (
		d   slashing.Decision
		err error
	)
	if r.block {
		d, err = e.CheckAndRecordBlock(bg, slashing.BlockRequest{PublicKey: slashingtest.Key(r.key),
			GenesisValidatorsRoot: gvr, Slot: r.slot, SigningRoot: slashingtest.RootOf(r.root)})
	} else {
		d, err = e.CheckAndRecordAttestation(bg, slashing.AttestationRequest{PublicKey: slashingtest.Key(r.key),
			GenesisValidatorsRoot: gvr, SourceEpoch: r.source, TargetEpoch: r.target, SigningRoot: slashingtest.RootOf(r.root)})
	}
	must(t, err)
	return d
}

// A watermark repair raises the watermarks above the signed history. The export carries them: the signer that
// imports the file refuses what this one refuses, including the double vote and the double proposal that the
// signed records rule out, which Web3Signer's filter left out of the file (X54). The one request the importer
// allows that this signer refuses is an attestation with a source below the repaired epoch and a target above it,
// next to a signed attestation at the repaired target; it neither double-votes nor surrounds a signed attestation.
func TestRepairedWatermarksSurviveTheRoundTrip(t *testing.T) {
	const slot, epoch = 200, 150
	keys := [][]byte{slashingtest.Key(0), slashingtest.Key(1)}
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		e := slashing.NewEngine(s)
		must(t, e.RegisterValidators(bg, keys))
		// Key 0 proposed at slot 100 and attested (149, 150); key 1's whole history is below the repair.
		for _, r := range []request{blockReq(0, 100, 1), attReq(0, 149, 150, 1), blockReq(1, 50, 1), attReq(1, 40, 41, 1)} {
			if d := decide(t, e, r); !d.Allowed {
				t.Fatalf("seeding %+v: %+v", r, d)
			}
		}
		if n, err := slashing.RepairLowWatermarks(bg, s, slot, epoch); err != nil || n != 2 {
			t.Fatalf("repair: %d, %v", n, err)
		}
		var file bytes.Buffer
		res, err := interchange.Export(bg, s, &file, interchange.ExportOptions{})
		must(t, err)
		// Key 0: the slot watermark as a block, and the attestation at the target watermark. Key 1: both watermarks
		// as records of their own.
		if res.Blocks != 2 || res.Attestations != 2 || res.Watermarks != 3 {
			t.Fatalf("export result %+v:\n%s", res, file.String())
		}
		refused := []request{
			blockReq(0, 100, 2), blockReq(0, 150, 2), blockReq(0, slot, 2),
			attReq(0, 149, 150, 2), attReq(0, 150, 150, 2), attReq(0, 140, 145, 2), attReq(0, 148, 151, 2),
			blockReq(1, 50, 2), blockReq(1, slot, 2),
			attReq(1, 40, 41, 2), attReq(1, 150, 150, 2), attReq(1, 149, 151, 2), attReq(1, 100, 160, 2),
		}
		allowed := []request{blockReq(0, slot+1, 2), attReq(0, epoch, epoch+1, 2), blockReq(1, slot+1, 2), attReq(1, epoch, epoch+1, 2)}
		for _, other := range stores {
			t.Run("into "+other.name, func(t *testing.T) {
				r := other.open(t)
				t.Cleanup(func() { _ = r.Close() })
				importDoc(t, r, file.String())
				re := slashing.NewEngine(r)
				must(t, re.RegisterValidators(bg, keys))
				for _, req := range refused {
					if d := decide(t, e, req); d.Allowed {
						t.Fatalf("the exporting signer allows %+v", req)
					}
					if d := decide(t, re, req); d.Allowed {
						t.Fatalf("the importing signer allows %+v, which the exporting signer refuses", req)
					}
				}
				for _, req := range allowed {
					if d := decide(t, re, req); !d.Allowed {
						t.Fatalf("the importing signer refuses %+v: %s", req, d.Reason)
					}
				}
			})
		}
	})
}
