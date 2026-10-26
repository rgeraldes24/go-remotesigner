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

// importWith imports d into s with opts, which must not stop it.
func importWith(t *testing.T, s slashing.Store, d string, opts interchange.ImportOptions) interchange.ImportResult {
	t.Helper()
	res, err := interchange.Import(bg, s, strings.NewReader(d), opts)
	must(t, err)
	return res
}

// A clean element enables a key only when an import disabled it: one new to
// the store, or one whose element failed before. A key disabled on purpose
// (a keymanager DELETE or disable-validator) stays disabled, even when the
// file covers its whole history, and is reported KeptDisabled; Enable names
// the keys to enable all the same.
func TestImportReenablesOnlyKeysAnImportDisabled(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		id := func(i int) slashing.KeyID { return slashing.KeyIDOf(slashingtest.Key(i)) }
		must(t, s.RegisterValidators(bg, [][]byte{slashingtest.Key(0), slashingtest.Key(1), slashingtest.Key(2)}))
		must(t, s.SetValidatorEnabled(bg, id(1), false)) // disable-validator
		must(t, s.SetValidatorEnabled(bg, id(2), false)) // keymanager DELETE

		// A failed element disables key 0 by import; key 1 stays disabled on purpose; key 3 is new.
		bad := func(i int) string { return `{"pubkey":"` + pk(i) + `","signed_blocks":[{"slot":"x"}]}` }
		res := importDoc(t, s, doc(gvr, bad(0), bad(1), jEntry{Pubkey: pk(3), Blocks: []jBlock{blk(9, root(1))}}))
		if len(res.Failed()) != 2 {
			t.Fatalf("failures %+v", res.Failed())
		}
		for i, want := range []slashing.ValidatorStatus{
			{Registered: true, DisabledByImport: true},
			{Registered: true},
			{Registered: true},
			{Registered: true, Enabled: true},
		} {
			if got := enabled(t, s, i); got != want {
				t.Fatalf("after the failed import, key %d: %+v, want %+v", i, got, want)
			}
		}

		// The same history, now valid: key 0 is enabled again, keys 1 and 2 stay disabled and are reported.
		clean := func(i int) jEntry { return jEntry{Pubkey: pk(i), Blocks: []jBlock{blk(10, root(1))}} }
		res = importWith(t, s, doc(gvr, clean(0), clean(1), clean(2), clean(3)), interchange.ImportOptions{})
		if len(res.Failed()) != 0 {
			t.Fatalf("failures %+v", res.Failed())
		}
		for i, kept := range []bool{false, true, true, false} {
			if res.Validators[i].KeptDisabled != kept {
				t.Errorf("data[%d].KeptDisabled = %v, want %v", i, res.Validators[i].KeptDisabled, kept)
			}
		}
		for i, want := range []bool{true, false, false, true} {
			if st := enabled(t, s, i); st.Enabled != want || st.DisabledByImport {
				t.Fatalf("after the clean import, key %d: %+v, want enabled %v", i, st, want)
			}
		}

		// Enable names key 1: its clean element enables it; key 2 stays disabled.
		res = importWith(t, s, doc(gvr, clean(1), clean(2)), interchange.ImportOptions{Enable: []slashing.KeyID{id(1)}})
		if res.Validators[0].KeptDisabled || !res.Validators[1].KeptDisabled {
			t.Fatalf("results %+v", res.Validators)
		}
		if !enabled(t, s, 1).Enabled || enabled(t, s, 2).Enabled {
			t.Fatalf("after --enable-keys of key 1: key 1 %+v, key 2 %+v", enabled(t, s, 1), enabled(t, s, 2))
		}

		// A failed element of a key disabled on purpose leaves it disabled on purpose: a later clean import does not
		// enable it either.
		importDoc(t, s, doc(gvr, bad(2)))
		if st := enabled(t, s, 2); st.Enabled || st.DisabledByImport {
			t.Fatalf("a key disabled on purpose, after its element failed: %+v", st)
		}
		res = importWith(t, s, doc(gvr, clean(2)), interchange.ImportOptions{})
		if !res.Validators[0].KeptDisabled || enabled(t, s, 2).Enabled {
			t.Fatalf("a key disabled on purpose was enabled by a clean import: %+v", res.Validators[0])
		}
	})
}

// The keymanager's import (LeaveEnabled) neither enables nor reports a key;
// the keymanager enables it itself once its files are written.
func TestImportLeaveEnabledReportsNothingKept(t *testing.T) {
	forEachStore(t, func(t *testing.T, s slashing.Store) {
		must(t, s.RegisterValidators(bg, [][]byte{slashingtest.Key(0)}))
		must(t, s.SetValidatorEnabled(bg, slashing.KeyIDOf(slashingtest.Key(0)), false))
		res := importWith(t, s, doc(gvr, jEntry{Pubkey: pk(0), Blocks: []jBlock{blk(10, root(1))}}),
			interchange.ImportOptions{LeaveEnabled: true})
		if res.Validators[0].KeptDisabled || enabled(t, s, 0).Enabled {
			t.Fatalf("result %+v, status %+v", res.Validators[0], enabled(t, s, 0))
		}
	})
}
