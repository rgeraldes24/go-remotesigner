// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// keyset derives keys from fixed seeds; each call returns fresh objects for
// the same keys, as a reload does.
func keys(t *testing.T, seeds ...byte) []*mldsa87.Key {
	t.Helper()
	var out []*mldsa87.Key
	for _, b := range seeds {
		var seed [mldsa87.SeedSize]byte
		seed[0] = b
		k, err := mldsa87.FromSeed48(&seed)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, k)
	}
	return out
}

func quiet() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func publicKeys(p *Provider) [][]byte {
	var out [][]byte
	for pk := range p.PublicKeys() {
		out = append(out, bytes.Clone(pk[:]))
	}
	return out
}

func TestApplyAndLookup(t *testing.T) {
	p := New(quiet())
	ks := keys(t, 1, 2, 3)
	var registered [][]byte
	d, err := p.Apply([]Batch{{Source: "a", Keys: ks[:2]}, {Source: "b", Keys: ks[2:]}}, func(pks [][]byte) error {
		registered = append(registered, pks...)
		return nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d != (Delta{Added: 3}) || len(registered) != 3 || p.Len() != 3 {
		t.Fatalf("delta %+v, registered %d, len %d", d, len(registered), p.Len())
	}
	for _, k := range ks {
		got, ok := p.Get(k.ID())
		if !ok || got != k {
			t.Fatalf("Get(%x) = %v, %v", k.ID(), got, ok)
		}
	}
	if _, ok := p.Get(ID{}); ok {
		t.Fatal("Get of an unknown id succeeded")
	}
	pks := publicKeys(p)
	if !slices.IsSortedFunc(pks, bytes.Compare) || len(pks) != 3 {
		t.Fatalf("PublicKeys not sorted: %d keys", len(pks))
	}
}

// A reload keeps existing key objects, evicts and zeroizes removed keys,
// registers only new ones, and keeps the previous keys of a failed source.
func TestReloadSemantics(t *testing.T) {
	p := New(quiet())
	first := keys(t, 1, 2, 3)
	if _, err := p.Apply([]Batch{{Source: "a", Keys: first[:1]}, {Source: "b", Keys: first[1:2]}, {Source: "c", Keys: first[2:]}}, nil, nil); err != nil {
		t.Fatal(err)
	}

	again := keys(t, 1, 4) // a: unchanged key 1; b: fails; c: gone; d: new key 4
	var registered int
	d, err := p.Apply([]Batch{
		{Source: "a", Keys: again[:1]},
		{Source: "b", Err: errors.New("unreadable")},
		{Source: "d", Keys: again[1:]},
	}, func(pks [][]byte) error { registered += len(pks); return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d != (Delta{Added: 1, Removed: 1, Kept: 1, Errors: 1}) || registered != 1 {
		t.Fatalf("delta %+v, registered %d", d, registered)
	}
	if k, _ := p.Get(first[0].ID()); k != first[0] || k.Zeroized() {
		t.Fatal("an unchanged key lost its object")
	}
	if !again[0].Zeroized() {
		t.Fatal("the re-derived duplicate of a loaded key was not zeroized")
	}
	if k, ok := p.Get(first[1].ID()); !ok || k != first[1] {
		t.Fatal("a failed source lost its previous key")
	}
	if _, ok := p.Get(first[2].ID()); ok || !first[2].Zeroized() {
		t.Fatal("a removed key is still loaded or not zeroized")
	}
	if _, ok := p.Get(again[1].ID()); !ok {
		t.Fatal("the new key was not added")
	}
}

// A key that renew names is replaced by the copy just derived, without
// registering it again; the old object is zeroized. Others keep theirs.
func TestApplyRenews(t *testing.T) {
	p := New(quiet())
	first := keys(t, 1, 2)
	if _, err := p.Apply([]Batch{{Source: "a", Keys: first}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	again := keys(t, 1, 2)
	registered := 0
	d, err := p.Apply([]Batch{{Source: "a", Keys: again}},
		func(pks [][]byte) error { registered += len(pks); return nil },
		func(id ID) bool { return id == first[0].ID() })
	if err != nil {
		t.Fatal(err)
	}
	if d != (Delta{Renewed: 1}) || registered != 0 {
		t.Fatalf("delta %+v, registered %d", d, registered)
	}
	if k, _ := p.Get(first[0].ID()); k != again[0] || k.Zeroized() || !first[0].Zeroized() {
		t.Fatal("the renewed key was not replaced by its fresh copy")
	}
	if k, _ := p.Get(first[1].ID()); k != first[1] || !again[1].Zeroized() {
		t.Fatal("a key renew did not name lost its object")
	}
}

func TestDuplicateKeepsFirst(t *testing.T) {
	p := New(quiet())
	a, b := keys(t, 7), keys(t, 7)
	d, err := p.Apply([]Batch{{Source: "a", Keys: a}, {Source: "b", Keys: b}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.Added != 1 || p.Len() != 1 {
		t.Fatalf("delta %+v", d)
	}
	if k, _ := p.Get(a[0].ID()); k != a[0] || !b[0].Zeroized() {
		t.Fatal("the first duplicate did not win")
	}
}

func TestRegisterFailureChangesNothing(t *testing.T) {
	p := New(quiet())
	old := keys(t, 1)
	if _, err := p.Apply([]Batch{{Source: "a", Keys: old}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	fresh := keys(t, 2)
	boom := errors.New("store down")
	if _, err := p.Apply([]Batch{{Source: "b", Keys: fresh}}, func([][]byte) error { return boom }, nil); !errors.Is(err, boom) {
		t.Fatalf("Apply = %v", err)
	}
	if k, ok := p.Get(old[0].ID()); !ok || k.Zeroized() {
		t.Fatal("a failed registration removed the old key")
	}
	if _, ok := p.Get(fresh[0].ID()); ok || !fresh[0].Zeroized() {
		t.Fatal("a failed registration left the new key loaded or unzeroized")
	}
}

func TestCloseZeroizes(t *testing.T) {
	p := New(quiet())
	ks := keys(t, 1, 2)
	if _, err := p.Apply([]Batch{{Source: "a", Keys: ks}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	p.Close()
	if p.Len() != 0 || !ks[0].Zeroized() || !ks[1].Zeroized() {
		t.Fatal("Close left keys loaded or unzeroized")
	}
	late := keys(t, 3)
	if _, err := p.Apply([]Batch{{Source: "a", Keys: late}}, nil, nil); !errors.Is(err, ErrClosed) || !late[0].Zeroized() {
		t.Fatalf("Apply after Close = %v", err)
	}
}

// Readers see one snapshot or the other while reloads run.
func TestConcurrentReadsDuringApply(t *testing.T) {
	p := New(quiet())
	if _, err := p.Apply([]Batch{{Source: "a", Keys: keys(t, 1, 2)}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				n := len(publicKeys(p))
				if n != 2 && n != 3 {
					t.Errorf("snapshot with %d keys", n)
					return
				}
			}
		}()
	}
	for i := range 20 {
		seeds := []byte{1, 2}
		if i%2 == 0 {
			seeds = append(seeds, 3)
		}
		if _, err := p.Apply([]Batch{{Source: "a", Keys: keys(t, seeds...)}}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
}
