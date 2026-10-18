// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package interchange_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/interchange"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

var bg = context.Background()

// gvr is the genesis validators root of the test files.
var gvr = slashingtest.GVR

// stores are the backends the tests run on.
var stores = []struct {
	name string
	open func(t *testing.T) slashing.Store
}{
	{"memstore", func(*testing.T) slashing.Store { return memstore.New() }},
	{"boltstore", func(t *testing.T) slashing.Store {
		s, err := boltstore.Open(filepath.Join(t.TempDir(), "sp.db"), boltstore.Options{})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}},
}

func forEachStore(t *testing.T, test func(t *testing.T, s slashing.Store)) {
	t.Helper()
	for _, st := range stores {
		t.Run(st.name, func(t *testing.T) {
			s := st.open(t)
			t.Cleanup(func() { _ = s.Close() })
			test(t, s)
		})
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// The JSON shapes of the test files, written independently of the package's encoder.
type (
	jBlock struct {
		Slot string  `json:"slot"`
		Root *string `json:"signing_root,omitempty"`
	}
	jAtt struct {
		Source string  `json:"source_epoch"`
		Target string  `json:"target_epoch"`
		Root   *string `json:"signing_root,omitempty"`
	}
	jEntry struct {
		Pubkey string   `json:"pubkey"`
		Blocks []jBlock `json:"signed_blocks"`
		Atts   []jAtt   `json:"signed_attestations"`
	}
)

func hx(b []byte) string { return "0x" + hex.EncodeToString(b) }

func pk(i int) string { return hx(slashingtest.Key(i)) }

func root(n uint64) *string {
	s := hx(slashingtest.RootPtr(n)[:])
	return &s
}

func u(v uint64) string { return strconv.FormatUint(v, 10) }

func blk(slot uint64, r *string) jBlock { return jBlock{Slot: u(slot), Root: r} }

func att(source, target uint64, r *string) jAtt {
	return jAtt{Source: u(source), Target: u(target), Root: r}
}

// doc renders an interchange file with the metadata first. Entries are jEntry values or raw JSON strings.
func doc(root slashing.Root, entries ...any) string {
	parts := make([]string, len(entries))
	for i, e := range entries {
		if s, ok := e.(string); ok {
			parts[i] = s
			continue
		}
		b, err := json.Marshal(e)
		if err != nil {
			panic(err)
		}
		parts[i] = string(b)
	}
	return `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"` + hx(root[:]) +
		`"},"data":[` + strings.Join(parts, ",") + `]}`
}

func importDoc(t *testing.T, s slashing.Store, d string) interchange.ImportResult {
	t.Helper()
	res, err := interchange.Import(bg, s, strings.NewReader(d), interchange.ImportOptions{})
	must(t, err)
	return res
}

// state is one validator's history in a store.
type state struct {
	blocks []slashing.SignedBlock
	atts   []slashing.SignedAttestation
	low    slashing.LowWatermark
}

// dump returns every validator's history, keyed by key index among the first 16 test keys.
func dump(t *testing.T, s slashing.Store) map[int]state {
	t.Helper()
	index := map[slashing.KeyID]int{}
	for i := range 16 {
		index[slashing.KeyIDOf(slashingtest.Key(i))] = i
	}
	out := map[int]state{}
	must(t, s.ViewHistory(bg, func(v slashing.HistoryView) error {
		return v.Validators(func(id slashing.KeyID, _ []byte) error {
			var st state
			var err error
			if st.low, err = v.LowWatermark(id); err != nil {
				return err
			}
			if err := v.Blocks(id, func(b slashing.SignedBlock) error { st.blocks = append(st.blocks, b); return nil }); err != nil {
				return err
			}
			err = v.Attestations(id, func(a slashing.SignedAttestation) error { st.atts = append(st.atts, a); return nil })
			out[index[id]] = st
			return err
		})
	}))
	return out
}

func enabled(t *testing.T, s slashing.Store, i int) slashing.ValidatorStatus {
	t.Helper()
	st, err := s.ValidatorStatus(bg, slashing.KeyIDOf(slashingtest.Key(i)))
	must(t, err)
	return st
}

func wantState(t *testing.T, got map[int]state, i int, want state) {
	t.Helper()
	g, ok := got[i]
	if !ok {
		t.Fatalf("validator %d is not in the store", i)
	}
	if len(g.blocks) != len(want.blocks) || len(g.atts) != len(want.atts) ||
		(len(want.blocks) > 0 && !reflect.DeepEqual(g.blocks, want.blocks)) ||
		(len(want.atts) > 0 && !reflect.DeepEqual(g.atts, want.atts)) || !reflect.DeepEqual(g.low, want.low) {
		t.Fatalf("validator %d:\ngot  %s\nwant %s", i, g, want)
	}
}

func sb(slot uint64, r *slashing.Root) slashing.SignedBlock {
	return slashing.SignedBlock{Slot: slot, SigningRoot: r}
}

func sa(source, target uint64, r *slashing.Root) slashing.SignedAttestation {
	return slashing.SignedAttestation{SourceEpoch: source, TargetEpoch: target, SigningRoot: r}
}

func lw(slot, source, target *uint64) slashing.LowWatermark {
	return slashing.LowWatermark{Slot: slot, SourceEpoch: source, TargetEpoch: target}
}

var u64 = slashingtest.U64

func (s state) String() string {
	var b strings.Builder
	b.WriteString("blocks [")
	for _, x := range s.blocks {
		b.WriteString(" " + u(x.Slot) + fmtRoot(x.SigningRoot))
	}
	b.WriteString(" ] attestations [")
	for _, x := range s.atts {
		b.WriteString(" " + u(x.SourceEpoch) + "/" + u(x.TargetEpoch) + fmtRoot(x.SigningRoot))
	}
	return b.String() + " ] low " + fmtLow(s.low)
}

func fmtRoot(r *slashing.Root) string {
	if r == nil {
		return ":-"
	}
	return ":" + hex.EncodeToString(r[28:])
}
