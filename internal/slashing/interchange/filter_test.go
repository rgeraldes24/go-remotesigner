// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package interchange_test

import (
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/interchange"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// An import limited to some keys writes, registers and disables nothing for
// the others, even when their elements fail, and reports only the elements
// of its keys. An element whose key is not valid is skipped too.
func TestImportKeysFilter(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		bad := `{"pubkey":"` + pk(3) + `","signed_blocks":[{"slot":"11","signing_root":"0x00"}]}`
		noKey := `{"pubkey":"0x00","signed_blocks":[]}`
		d := doc(gvr,
			jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(10, root(1))}},
			jEntry{Pubkey: pk(1), Blocks: []jBlock{blk(20, root(2))}},
			bad, noKey,
			jEntry{Pubkey: pk(2), Atts: []jAtt{att(5, 6, root(3))}})
		keys := []slashing.KeyID{slashing.KeyIDOf(slashingtest.Key(0)), slashing.KeyIDOf(slashingtest.Key(2))}
		res, err := interchange.Import(bg, s, strings.NewReader(d), interchange.ImportOptions{Keys: keys})
		must(t, err)
		if len(res.Validators) != 2 || res.Validators[0].Index != 0 || res.Validators[1].Index != 4 ||
			len(res.Failed()) != 0 {
			t.Fatalf("results %+v", res.Validators)
		}
		got := dump(t, s)
		wantState(t, got, 0, state{blocks: []slashing.SignedBlock{sb(10, slashingtest.RootPtr(1))}, low: lw(u64(10), nil, nil)})
		wantState(t, got, 2, state{atts: []slashing.SignedAttestation{sa(5, 6, slashingtest.RootPtr(3))}, low: lw(nil, u64(5), u64(6))})
		for _, i := range []int{1, 3} {
			if st := enabled(t, s, i); st.Registered {
				t.Fatalf("key %d outside the filter was registered: %+v", i, st)
			}
		}

		// The failing element of a key in the filter still fails and
		// disables it.
		res, err = interchange.Import(bg, s, strings.NewReader(doc(gvr, bad)),
			interchange.ImportOptions{Keys: []slashing.KeyID{slashing.KeyIDOf(slashingtest.Key(3))}})
		must(t, err)
		if f := res.Failed(); len(f) != 1 || !f[0].Disabled {
			t.Fatalf("failures %+v", f)
		}
		if st := enabled(t, s, 3); !st.Registered || st.Enabled {
			t.Fatalf("key 3: %+v", st)
		}

		// An empty filter imports nothing.
		res, err = interchange.Import(bg, s, strings.NewReader(d), interchange.ImportOptions{Keys: []slashing.KeyID{}})
		must(t, err)
		if len(res.Validators) != 0 {
			t.Fatalf("results %+v", res.Validators)
		}
	})
}

// LeaveEnabled writes the history but leaves the enabled flag as it was: a
// key new to the store stays registered disabled, a disabled key stays
// disabled, an enabled one stays enabled, and a failed element still
// disables its key.
func TestImportLeaveEnabled(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		must(t, s.RegisterValidators(bg, [][]byte{slashingtest.Key(1), slashingtest.Key(2), slashingtest.Key(3)}))
		must(t, s.SetValidatorEnabled(bg, slashing.KeyIDOf(slashingtest.Key(1)), false))
		bad := `{"pubkey":"` + pk(3) + `","signed_blocks":[{"slot":"11","signing_root":"0x00"}]}`
		res, err := interchange.Import(bg, s, strings.NewReader(doc(gvr,
			jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(10, root(1))}},
			jEntry{Pubkey: pk(1), Blocks: []jBlock{blk(10, root(1))}},
			jEntry{Pubkey: pk(2), Blocks: []jBlock{blk(10, root(1))}},
			bad)), interchange.ImportOptions{LeaveEnabled: true})
		must(t, err)
		if f := res.Failed(); len(f) != 1 || f[0].Index != 3 {
			t.Fatalf("failures %+v", f)
		}
		for i, want := range []bool{false, false, true, false} {
			if st := enabled(t, s, i); !st.Registered || st.Enabled != want {
				t.Fatalf("key %d: %+v, want enabled %v", i, st, want)
			}
		}
		wantState(t, dump(t, s), 0, state{blocks: []slashing.SignedBlock{sb(10, slashingtest.RootPtr(1))}, low: lw(u64(10), nil, nil)})
	})
}
