// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"errors"
	"testing"
)

// Add registers and adds one source's keys with their metadata, refuses a
// key or a source that is loaded already, and changes nothing when the
// registration fails.
func TestAdd(t *testing.T) {
	p := New(quiet())
	if _, err := p.Apply([]Batch{{Source: "a", Keys: keys(t, 1)}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	k := keys(t, 2)
	var registered int
	meta := Meta{DerivationPath: "m/12381/238/0/0", Keystore: true}
	if err := p.Add(Batch{Source: "km", Keys: k, Meta: []Meta{meta}},
		func(pks [][]byte) error { registered += len(pks); return nil }); err != nil {
		t.Fatal(err)
	}
	e, ok := p.Entry(k[0].ID())
	if !ok || e.Key != k[0] || e.Source != "km" || e.Meta != meta || registered != 1 || p.Len() != 2 ||
		p.SourceLen("km") != 1 {
		t.Fatalf("after Add: entry %+v, %v, registered %d, len %d", e, ok, registered, p.Len())
	}
	n := 0
	for range p.Entries() {
		n++
	}
	if n != 2 {
		t.Fatalf("Entries yielded %d", n)
	}

	dup := keys(t, 1)
	if err := p.Add(Batch{Source: "other", Keys: dup}, nil); !errors.Is(err, ErrDuplicate) || !dup[0].Zeroized() {
		t.Fatalf("Add of a loaded key = %v", err)
	}
	again := keys(t, 3)
	if err := p.Add(Batch{Source: "km", Keys: again}, nil); !errors.Is(err, ErrDuplicate) || !again[0].Zeroized() {
		t.Fatalf("Add of a loaded source = %v", err)
	}
	boom := errors.New("store down")
	fresh := keys(t, 4)
	if err := p.Add(Batch{Source: "b", Keys: fresh}, func([][]byte) error { return boom }); !errors.Is(err, boom) ||
		!fresh[0].Zeroized() || p.Len() != 2 {
		t.Fatalf("Add with a failing registration = %v, len %d", err, p.Len())
	}
	p.Close()
	late := keys(t, 5)
	if err := p.Add(Batch{Source: "c", Keys: late}, nil); !errors.Is(err, ErrClosed) || !late[0].Zeroized() {
		t.Fatalf("Add after Close = %v", err)
	}
	if _, err := p.Remove("km"); !errors.Is(err, ErrClosed) {
		t.Fatalf("Remove after Close = %v", err)
	}
}

// Remove evicts and zeroizes a source's keys, and reports 0 for a source
// that holds none.
func TestRemove(t *testing.T) {
	p := New(quiet())
	ks := keys(t, 1, 2)
	if _, err := p.Apply([]Batch{{Source: "a", Keys: ks[:1]}, {Source: "b", Keys: ks[1:]}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if n, err := p.Remove("a"); n != 1 || err != nil {
		t.Fatalf("Remove = %d, %v", n, err)
	}
	if _, ok := p.Get(ks[0].ID()); ok || !ks[0].Zeroized() || p.Len() != 1 {
		t.Fatal("Remove left the key loaded or unzeroized")
	}
	if n, err := p.Remove("nothing"); n != 0 || err != nil {
		t.Fatalf("Remove of an empty source = %d, %v", n, err)
	}
	if got := p.Sources(""); len(got) != 1 || got[0] != "b" {
		t.Fatalf("sources %q", got)
	}
}

// A load that read its sources before an Add or a Remove does not undo
// them: the added source keeps its key though the load did not list it, and
// the removed one stays out though the load loaded it. A load that starts
// after the change applies its batches for those sources as usual.
func TestApplySinceKeepsLaterChanges(t *testing.T) {
	p := New(quiet())
	ks := keys(t, 1, 2)
	if _, err := p.Apply([]Batch{{Source: "deleted", Keys: ks[:1]}, {Source: "kept", Keys: ks[1:]}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	since := p.Generation() // the load starts and lists its sources

	imported := keys(t, 3)
	if err := p.Add(Batch{Source: "imported", Keys: imported}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Remove("deleted"); err != nil {
		t.Fatal(err)
	}

	// The load saw "deleted" and "kept" but not "imported".
	stale := keys(t, 1, 2)
	d, err := p.ApplySince(since, []Batch{{Source: "deleted", Keys: stale[:1]}, {Source: "kept", Keys: stale[1:]}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Get(ks[0].ID()); ok || !stale[0].Zeroized() {
		t.Fatal("a load that started before a Remove brought the key back")
	}
	if e, ok := p.Entry(imported[0].ID()); !ok || e.Key != imported[0] || imported[0].Zeroized() {
		t.Fatal("a load that started before an Add dropped the added key")
	}
	if p.Len() != 2 || d.Kept != 1 || d.Removed != 0 {
		t.Fatalf("len %d, delta %+v", p.Len(), d)
	}

	// The next load lists "imported" without "deleted": both as usual.
	since = p.Generation()
	again := keys(t, 2, 3)
	if _, err := p.ApplySince(since, []Batch{{Source: "kept", Keys: again[:1]}, {Source: "imported", Keys: again[1:]}},
		nil, nil); err != nil {
		t.Fatal(err)
	}
	if e, ok := p.Entry(imported[0].ID()); !ok || e.Key != imported[0] || p.Len() != 2 {
		t.Fatal("a later load did not keep the imported key")
	}
	// A load after that one without "imported" evicts it: the change no
	// longer shields the source.
	since = p.Generation()
	if _, err := p.ApplySince(since, []Batch{{Source: "kept", Keys: keys(t, 2)}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Get(imported[0].ID()); ok || !imported[0].Zeroized() {
		t.Fatal("a load that started after the Add did not evict the key its files no longer hold")
	}
}

// A source changed during a load wins over a duplicate of its key in one of
// the load's batches.
func TestApplySinceChangedSourceWinsDuplicates(t *testing.T) {
	p := New(quiet())
	since := p.Generation()
	k := keys(t, 9)
	if err := p.Add(Batch{Source: "km", Keys: k}, nil); err != nil {
		t.Fatal(err)
	}
	dup := keys(t, 9)
	if _, err := p.ApplySince(since, []Batch{{Source: "bulk", Keys: dup}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if e, ok := p.Entry(k[0].ID()); !ok || e.Source != "km" || e.Key != k[0] || !dup[0].Zeroized() {
		t.Fatalf("entry %+v", e)
	}
}

// A load sets the metadata of its batches, also on keys it keeps.
func TestApplySetsMeta(t *testing.T) {
	p := New(quiet())
	ks := keys(t, 1)
	m1 := Meta{DerivationPath: "m/12381/238/0/0", Keystore: true}
	if _, err := p.Apply([]Batch{{Source: "a", Keys: ks, Meta: []Meta{m1}}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if e, _ := p.Entry(ks[0].ID()); e.Meta != m1 {
		t.Fatalf("meta %+v", e.Meta)
	}
	// The same key, now from a raw seed in another source: the kept object
	// takes the new metadata.
	if _, err := p.Apply([]Batch{{Source: "b", Keys: keys(t, 1)}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if e, _ := p.Entry(ks[0].ID()); e.Key != ks[0] || e.Source != "b" || e.Meta != (Meta{}) {
		t.Fatalf("entry %+v", e)
	}
}
