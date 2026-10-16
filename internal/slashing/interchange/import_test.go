// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package interchange_test

import (
	"context"
	"errors"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/interchange"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
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

// failingRegistration is a store whose registrations always fail.
type failingRegistration struct{ slashing.Store }

var errRegistration = errors.New("registration failed")

func (failingRegistration) RegisterValidators(context.Context, [][]byte) error {
	return errRegistration
}

func (failingRegistration) RegisterValidatorsDisabled(context.Context, [][]byte) error {
	return errRegistration
}

// statusWatch is a store that, whenever the import is about to commit a history transaction or an enabled flag,
// checks whether the watched key is enabled: the state the key is left in if the process stops there.
type statusWatch struct {
	slashing.Store
	t       *testing.T
	key     slashing.KeyID
	checks  int
	enabled int
}

func (w *statusWatch) check() {
	st, err := w.ValidatorStatus(bg, w.key)
	must(w.t, err)
	w.checks++
	if st.Enabled {
		w.enabled++
	}
}

func (w *statusWatch) UpdateHistory(ctx context.Context, ids []slashing.KeyID, fn func(slashing.KeyID, slashing.HistoryTx) error) error {
	w.check()
	return w.Store.UpdateHistory(ctx, ids, fn)
}

func (w *statusWatch) SetValidatorEnabled(ctx context.Context, id slashing.KeyID, enabled bool) error {
	w.check()
	return w.Store.SetValidatorEnabled(ctx, id, enabled)
}

// A key new to the store is enabled only by the transaction that writes its history: at every commit before it,
// it is registered disabled, so an import that stops half-way never leaves a key enabled without its history (SP
// §18.2 fix 1). A failed element's key is never enabled at all.
func TestImportNeverEnablesAKeyBeforeItsHistory(t *testing.T) {
	for _, tc := range []struct {
		name    string
		key     int
		element any
		enabled bool
	}{
		{"an element that imports", 0, jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(10, root(1))}}, true},
		{"an element whose history crosses the high watermark", 1, jEntry{Pubkey: pk(1), Blocks: []jBlock{blk(5000, root(1))}}, false},
		{"an element that is not valid", 2, `{"pubkey":"` + pk(2) + `","signed_blocks":[{"slot":"x"}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forEachStore(t, func(t *testing.T, s slashing.Store) {
				_, err := s.PinGenesisValidatorsRoot(bg, gvr)
				must(t, err)
				must(t, s.SetHighWatermark(bg, slashing.HighWatermark{Epoch: u64(100), Slot: u64(1000)}))
				w := &statusWatch{Store: s, t: t, key: slashing.KeyIDOf(slashingtest.Key(tc.key))}
				res, err := interchange.Import(bg, w, strings.NewReader(doc(gvr, tc.element)), interchange.ImportOptions{})
				must(t, err)
				if w.checks == 0 || w.enabled != 0 {
					t.Fatalf("the key was enabled at %d of %d commits before its history was written", w.enabled, w.checks)
				}
				if st := enabled(t, s, tc.key); !st.Registered || st.Enabled != tc.enabled || (len(res.Failed()) == 0) != tc.enabled {
					t.Fatalf("after the import: %+v, failures %+v", st, res.Failed())
				}
			})
		})
	}
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

// A backend may run an UpdateHistory function again when it retries the transaction (Postgres, DESIGN §3.7). The
// import's history and counts are then the same as without the retry.
func TestImportThroughARetriedTransaction(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		var entries []any
		for i := range 5 {
			entries = append(entries, jEntry{Pubkey: pk(i), Blocks: []jBlock{blk(uint64(i), root(1))},
				Atts: []jAtt{att(uint64(i), uint64(i+1), root(2))}})
		}
		res, err := interchange.Import(bg, slashingtest.Retrying(s), strings.NewReader(doc(gvr, entries...)),
			interchange.ImportOptions{Batch: 3})
		must(t, err)
		one := interchange.Counts{Imported: 1}
		for _, v := range res.Validators {
			if v.Err != nil || v.Blocks != one || v.Attestations != one {
				t.Fatalf("data[%d]: %+v", v.Index, v)
			}
		}
		got := dump(t, s)
		for i := range 5 {
			wantState(t, got, i, state{blocks: []slashing.SignedBlock{sb(uint64(i), slashingtest.RootPtr(1))},
				atts: []slashing.SignedAttestation{sa(uint64(i), uint64(i+1), slashingtest.RootPtr(2))},
				low:  lw(u64(uint64(i)), u64(uint64(i)), u64(uint64(i+1)))})
			if !enabled(t, s, i).Enabled {
				t.Fatalf("key %d is not enabled", i)
			}
		}
	})
}

// Imported attestations that make the history slashable are written, and counted: Web3Signer logs each one, and
// qrysm blocklists such keys. A slashable pair the store already held before the import is not counted again.
func TestImportCountsSlashableAttestations(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		importDoc(t, s, doc(gvr, jEntry{Pubkey: pk(0), Atts: []jAtt{att(3, 10, root(1))}},
			jEntry{Pubkey: pk(1), Atts: []jAtt{att(3, 10, root(1)), att(4, 8, root(1))}}))
		res := importDoc(t, s, doc(gvr,
			// (4, 8) is surrounded by the stored (3, 10), (2, 12) surrounds it, (6, 5) has its source after its target
			// (and (3, 10) surrounds it), and (12, 13) is clean.
			jEntry{Pubkey: pk(0), Atts: []jAtt{att(4, 8, root(2)), att(2, 12, root(2)), att(6, 5, root(2)), att(12, 13, root(2))}},
			// Key 1's stored pair is slashable already; the import adds a clean attestation.
			jEntry{Pubkey: pk(1), Atts: []jAtt{att(12, 13, root(2))}}))
		if c := res.Validators[0].Attestations; c != (interchange.Counts{Imported: 4, Slashable: 3}) {
			t.Fatalf("key 0: %+v", c)
		}
		if c := res.Validators[1].Attestations; c != (interchange.Counts{Imported: 1}) {
			t.Fatalf("key 1: %+v", c)
		}
	})
}

// The count matches a direct check of every pair, over random histories.
func TestImportSlashableCountMatchesPairs(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	random := func(n int) []jAtt {
		out := make([]jAtt, n)
		for i := range out {
			out[i] = att(rng.Uint64N(12), rng.Uint64N(12), root(rng.Uint64N(2)))
		}
		return out
	}
	for trial := range 300 {
		s := memstore.New()
		seed, file := random(rng.IntN(5)), random(rng.IntN(8))
		importDoc(t, s, doc(gvr, jEntry{Pubkey: pk(0), Atts: seed}))
		res := importDoc(t, s, doc(gvr, jEntry{Pubkey: pk(0), Atts: file}))
		// The import writes a file attestation only at a target the store, and the file before it, have not used.
		stored := map[string]bool{}
		for _, a := range seed {
			stored[a.Target] = true
		}
		var inserted []jAtt
		for _, a := range file {
			if !stored[a.Target] {
				stored[a.Target] = true
				inserted = append(inserted, a)
			}
		}
		history := dump(t, s)[0].atts
		want := 0
		for _, a := range inserted {
			as, at := mustU64(t, a.Source), mustU64(t, a.Target)
			bad := as > at
			for _, r := range history {
				if (r.SourceEpoch < as && r.TargetEpoch > at) || (r.SourceEpoch > as && r.TargetEpoch < at) {
					bad = true
				}
			}
			if bad {
				want++
			}
		}
		if got := res.Validators[0].Attestations.Slashable; got != want {
			t.Fatalf("trial %d: seed %v, file %v: %d slashable, want %d", trial, seed, file, got, want)
		}
	}
}

func mustU64(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	must(t, err)
	return v
}

// A failed element disables the key under its exact "pubkey" field, not one under a field that differs in case.
func TestImportDisablesTheKeyTheElementNames(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		bad := `{"pubkey":"` + pk(1) + `","PUBKEY":"` + pk(3) + `","signed_blocks":[],"signed_attestations":[]}`
		res := importDoc(t, s, doc(gvr, bad))
		if f := res.Failed(); len(f) != 1 || !strings.Contains(f[0].Err.Error(), "unknown field PUBKEY") {
			t.Fatalf("failures %+v", f)
		}
		if st := enabled(t, s, 1); !st.Registered || st.Enabled {
			t.Fatalf("key 1: %+v, want registered and disabled", st)
		}
		if st := enabled(t, s, 3); st.Registered {
			t.Fatalf("key 3: %+v, want untouched", st)
		}
	})
}
