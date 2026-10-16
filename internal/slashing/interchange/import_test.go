// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package interchange_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/interchange"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// A validator whose history crosses the high watermark fails on its own, inside a batch with others; its key is
// disabled, and the rest of the batch is written.
func TestImportFailureDisablesOnlyThatKey(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		_, err := s.PinGenesisValidatorsRoot(bg, gvr)
		must(t, err)
		must(t, s.SetHighWatermark(bg, slashing.HighWatermark{Epoch: u64(100), Slot: u64(1000)}))
		res := importDoc(t, s, doc(gvr,
			jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(10, root(1))}},
			jEntry{Pubkey: pk(1), Blocks: []jBlock{blk(2000, root(1))}}, // its slot watermark would pass the fence
			jEntry{Pubkey: pk(2), Atts: []jAtt{att(200, 201, root(1))}}, // and its epoch watermarks
			jEntry{Pubkey: pk(3), Atts: []jAtt{att(5, 6, root(1))}}))
		failed := res.Failed()
		if len(failed) != 2 || failed[0].Index != 1 || failed[1].Index != 2 ||
			!errors.Is(failed[0].Err, slashing.ErrWatermarkConflict) || !errors.Is(failed[1].Err, slashing.ErrWatermarkConflict) {
			t.Fatalf("failures %+v", failed)
		}
		got := dump(t, s)
		wantState(t, got, 0, state{blocks: []slashing.SignedBlock{sb(10, slashingtest.RootPtr(1))}, low: lw(u64(10), nil, nil)})
		wantState(t, got, 1, state{})
		wantState(t, got, 2, state{})
		wantState(t, got, 3, state{atts: []slashing.SignedAttestation{sa(5, 6, slashingtest.RootPtr(1))}, low: lw(nil, u64(5), u64(6))})
		for i, want := range []bool{true, false, false, true} {
			if st := enabled(t, s, i); !st.Registered || st.Enabled != want {
				t.Fatalf("key %d: %+v, want enabled %v", i, st, want)
			}
		}
		if res.Validators[0].Blocks.Imported != 1 || res.Validators[1].Blocks.Imported != 0 {
			t.Fatalf("counts %+v", res.Validators)
		}
	})
}

// A failed element disables a key that was signing; importing a corrected file enables it again.
func TestImportFailureDisablesUntilACleanImport(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		importDoc(t, s, doc(gvr, jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(10, root(1))}}))
		if !enabled(t, s, 0).Enabled {
			t.Fatal("imported key is not enabled")
		}
		bad := `{"pubkey":"` + pk(0) + `","signed_blocks":[{"slot":"11","signing_root":"0x00"}]}`
		if f := importDoc(t, s, doc(gvr, bad)).Failed(); len(f) != 1 {
			t.Fatalf("failures %+v", f)
		}
		if enabled(t, s, 0).Enabled {
			t.Fatal("a failed import left the key enabled")
		}
		wantState(t, dump(t, s), 0, state{blocks: []slashing.SignedBlock{sb(10, slashingtest.RootPtr(1))}, low: lw(u64(10), nil, nil)})
		importDoc(t, s, doc(gvr, jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(11, root(2))}}))
		if !enabled(t, s, 0).Enabled {
			t.Fatal("a clean import did not enable the key")
		}
	})
}

// A key that appears twice in one file is written element by element; a failure in either element leaves it
// disabled.
func TestImportRepeatedKey(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		res := importDoc(t, s, doc(gvr,
			jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(10, root(1))}},
			jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(10, root(1)), blk(12, root(2))}}))
		if len(res.Failed()) != 0 || res.Validators[1].Blocks != (interchange.Counts{Imported: 1, Duplicates: 1}) {
			t.Fatalf("result %+v", res.Validators)
		}
		// The second element's newly inserted minimum, 12, is above the watermark: the watermark rises to it.
		wantState(t, dump(t, s), 0, state{blocks: []slashing.SignedBlock{sb(10, slashingtest.RootPtr(1)), sb(12, slashingtest.RootPtr(2))},
			low: lw(u64(12), nil, nil)})

		bad := `{"pubkey":"` + pk(1) + `","signed_blocks":[{"slot":"x"}]}`
		res = importDoc(t, s, doc(gvr, bad, jEntry{Pubkey: pk(1), Blocks: []jBlock{blk(3, root(3))}}))
		if len(res.Failed()) != 1 || enabled(t, s, 1).Enabled {
			t.Fatalf("a key with a failed element is enabled: %+v", res.Validators)
		}
	})
}

func TestImportBatches(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		var entries []any
		for i := range 10 {
			entries = append(entries, jEntry{Pubkey: pk(i), Blocks: []jBlock{blk(uint64(i), root(1))},
				Atts: []jAtt{att(uint64(i), uint64(i+1), root(2))}})
		}
		res, err := interchange.Import(bg, s, strings.NewReader(doc(gvr, entries...)), interchange.ImportOptions{Batch: 3})
		must(t, err)
		if len(res.Validators) != 10 || len(res.Failed()) != 0 {
			t.Fatalf("result %+v", res)
		}
		got := dump(t, s)
		for i := range 10 {
			wantState(t, got, i, state{blocks: []slashing.SignedBlock{sb(uint64(i), slashingtest.RootPtr(1))},
				atts: []slashing.SignedAttestation{sa(uint64(i), uint64(i+1), slashingtest.RootPtr(2))},
				low:  lw(u64(uint64(i)), u64(uint64(i)), u64(uint64(i+1)))})
		}
	})
}

func TestImportStopsOnFileErrors(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		d := `{"metadata":{"interchange_format_version":"4","genesis_validators_root":"` + hx(gvr[:]) + `"},"data":[]}`
		if _, err := interchange.Import(bg, s, strings.NewReader(d), interchange.ImportOptions{}); !errors.Is(err, interchange.ErrVersion) {
			t.Fatalf("version 4: %v", err)
		}
		if _, ok, _ := s.GenesisValidatorsRoot(bg); ok {
			t.Fatal("a refused file pinned the store")
		}
		// A file that breaks after its first element keeps that element and reports the break.
		d = strings.TrimSuffix(doc(gvr, jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(1, root(1))}}), "]}") + `,{"pubkey":`
		res, err := interchange.Import(bg, s, strings.NewReader(d), interchange.ImportOptions{})
		if !errors.Is(err, interchange.ErrFormat) || len(res.Validators) != 1 || len(res.Failed()) != 0 {
			t.Fatalf("truncated file: %v %+v", err, res)
		}
		wantState(t, dump(t, s), 0, state{blocks: []slashing.SignedBlock{sb(1, slashingtest.RootPtr(1))}, low: lw(u64(1), nil, nil)})
		ctx, cancel := context.WithCancel(bg)
		cancel()
		if _, err := interchange.Import(ctx, s, strings.NewReader(doc(gvr, jEntry{Pubkey: pk(1)})), interchange.ImportOptions{}); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled import: %v", err)
		}
	})
}

// failingRegistration is a store whose RegisterValidators always fails.
type failingRegistration struct{ slashing.Store }

var errRegistration = errors.New("registration failed")

func (failingRegistration) RegisterValidators(context.Context, [][]byte) error {
	return errRegistration
}

// An element that was read but could not be written is reported as failed, never as imported.
func TestImportReportsUnwrittenElements(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		res, err := interchange.Import(bg, failingRegistration{s}, strings.NewReader(doc(gvr,
			jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(1, root(1))}}, jEntry{Pubkey: pk(1)})), interchange.ImportOptions{})
		if !errors.Is(err, errRegistration) {
			t.Fatalf("import: %v", err)
		}
		failed := res.Failed()
		if len(res.Validators) != 2 || len(failed) != 2 {
			t.Fatalf("result %+v", res.Validators)
		}
		for _, v := range failed {
			if !errors.Is(v.Err, errRegistration) || !strings.Contains(v.Err.Error(), "not imported") ||
				v.Blocks != (interchange.Counts{}) {
				t.Fatalf("data[%d]: %+v", v.Index, v)
			}
		}
		if got := dump(t, s); len(got) != 0 {
			t.Fatalf("the store holds %+v", got)
		}
	})
}

// A record that the store already holds at the same slot or target epoch is never written over (SP §18.2): one
// without a signing root, or with the same root, is already covered; one with another root, or with a root where
// the stored record has none, is a conflict. Neither fails the element.
func TestImportOverExistingRecords(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		seed := jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(10, root(1)), blk(11, nil)},
			Atts: []jAtt{att(5, 6, root(1)), att(6, 7, nil)}}
		importDoc(t, s, doc(gvr, seed))
		before := dump(t, s)[0]

		res := importDoc(t, s, doc(gvr, jEntry{Pubkey: pk(0),
			Blocks: []jBlock{blk(10, nil), blk(10, root(1)), blk(10, root(9)), blk(11, root(2))},
			Atts:   []jAtt{att(5, 6, nil), att(4, 6, root(1)), att(5, 6, root(9)), att(6, 7, root(2))}}))
		v := res.Validators[0]
		want := interchange.Counts{Duplicates: 2, Conflicts: 2}
		if v.Err != nil || v.Blocks != want || v.Attestations != want {
			t.Fatalf("result %+v, want %+v for blocks and attestations", v, want)
		}
		wantState(t, dump(t, s), 0, before)
		if !enabled(t, s, 0).Enabled {
			t.Fatal("the key is not enabled")
		}
	})
}
