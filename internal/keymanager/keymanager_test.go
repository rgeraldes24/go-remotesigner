// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package keymanager

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keyconfig"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystores"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/interchange"
)

// An import writes each key's three files, 0600 and named by the SHA-256
// of the key, loads and enables it, and the list shows it as deletable with
// its keystore's derivation path. A delete disables the key, removes its
// files, evicts it and exports its history.
func TestImportListDelete(t *testing.T) {
	f := newFixture(t)
	a, b := newKey(t, "km", 0), newKey(t, "km", 1)
	history := doc(gvr, entry(a.hex, []uint64{10}, [2]uint64{2, 3}))
	rs, err := f.m.Import(bg, importReq(history, a.qrlV1(t), []byte(password), b.depositCLI(t, 1), []byte(password)))
	if err != nil {
		t.Fatal(err)
	}
	wantStatuses(t, rs, Imported, Imported)
	if f.changed != 1 {
		t.Fatalf("Changed called %d times", f.changed)
	}
	for _, k := range []testKey{a, b} {
		fl := filesOf(f.dir, &k.pk)
		for _, p := range []string{fl.config(), fl.keystore(), fl.password()} {
			fi, err := os.Stat(p)
			if err != nil || fi.Mode().Perm() != FileMode {
				t.Fatalf("%s: %v, mode %v", p, err, fi)
			}
		}
		id := k.pk.ID()
		if filepath.Base(fl.config()) != hex.EncodeToString(id[:])+".yaml" {
			t.Fatalf("file name %s", fl.config())
		}
		if st := f.status(t, k); !st.Registered || !st.Enabled || !f.loaded(k) {
			t.Fatalf("key %s: %+v, loaded %v", k.pk.LogID(), st, f.loaded(k))
		}
		// The written files load the same key: the next reload keeps it.
		keys, err := (keyconfig.Config{Dir: f.dir, Policy: secretfile.Policy{Strict: true}, Decrypt: f.sem.Decrypt}).
			LoadFile(bg, fl.config())
		if err != nil || len(keys) != 1 || keys[0].PublicKey() != k.pk {
			t.Fatalf("loading the written files: %v", err)
		}
		keys[0].Zeroize()
	}
	if fi, err := os.Stat(f.dir); err != nil || fi.Mode().Perm() != DirMode {
		t.Fatalf("directory: %v %v", err, fi)
	}
	if got := f.history(t, a); got != "low 10 2 3; b10 a2-3" {
		t.Fatalf("history of a: %q", got)
	}
	list := f.m.List()
	if len(list) != 2 {
		t.Fatalf("list %+v", list)
	}
	for _, k := range list {
		want := ""
		if *k.PublicKey == b.pk {
			want = "m/12381/238/1/0"
		}
		if k.ReadOnly || k.DerivationPath != want {
			t.Fatalf("listed %+v", k)
		}
	}

	rs, export := f.m.Delete(bg, []mldsa87.PublicKey{a.pk})
	wantStatuses(t, rs, Deleted)
	if f.loaded(a) || f.status(t, a).Enabled || len(f.files(t)) != 3 {
		t.Fatalf("after delete: loaded %v, %+v, files %v", f.loaded(a), f.status(t, a), f.files(t))
	}
	var want bytes.Buffer
	if _, err := interchange.Export(bg, f.store, &want, interchange.ExportOptions{Keys: []slashing.KeyID{slashing.KeyID(a.pk.ID())}}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(export, want.Bytes()) || !strings.Contains(string(export), a.hex[2:]) {
		t.Fatalf("export %s", export)
	}
	if len(f.m.List()) != 1 || f.changed != 2 {
		t.Fatalf("list after delete %+v, changed %d", f.m.List(), f.changed)
	}
}

// A key that is loaded already is a duplicate. Of two keystores of one key
// in a request, the second is a duplicate when the first is imported, takes
// the first one's place when it cannot be opened, and is an error when the
// first one opened but failed later.
func TestImportDuplicates(t *testing.T) {
	f := newFixture(t)
	a, b, c := newKey(t, "dup", 0), newKey(t, "dup", 1), newKey(t, "dup", 2)
	if _, err := f.m.Import(bg, importReq("", a.qrlV1(t), []byte(password))); err != nil {
		t.Fatal(err)
	}
	// c's history fails (its element's attestation has an invalid root).
	bad := `{"pubkey":"` + c.hex + `","signed_blocks":[],"signed_attestations":[{"source_epoch":"1","target_epoch":"2","signing_root":"0x00"}]}`
	rs, err := f.m.Import(bg, importReq(doc(gvr, bad),
		a.qrlV1(t), []byte(password), // loaded
		b.qrlV1(t), []byte(password), b.depositCLI(t, 0), []byte(password), // imported, then a copy
		c.qrlV1(t), []byte("wrong"), c.qrlV1(t), []byte(password), c.qrlV1(t), []byte(password)))
	if err != nil {
		t.Fatal(err)
	}
	wantStatuses(t, rs, Duplicate, Imported, Duplicate, Error, Error, Error)
	if !strings.Contains(rs[3].Message, "wrong password") || !strings.Contains(rs[4].Message, "slashing-protection") ||
		!strings.Contains(rs[5].Message, "keystore 4") {
		t.Fatalf("messages %+v", rs)
	}
	if f.loaded(c) || f.status(t, c).Enabled || len(f.files(t)) != 6 {
		t.Fatalf("c: loaded %v, %+v, files %v", f.loaded(c), f.status(t, c), f.files(t))
	}
}

// The keystore refusals: a keystore whose pubkey is another key's (the
// victim's), a KDF beyond the policy (m of 2^31 KiB), a missing KDF, a
// 16-byte dklen, a pubkey that is not hex, a keystore without a pubkey and
// an oversized password are each an error, before Argon2id runs where the
// keystore alone shows it. No file is written and the victim's history and
// enabled flag are unchanged, although the request carries history for it.
func TestImportRefusals(t *testing.T) {
	f := newFixture(t)
	victim, attacker := newKey(t, "victim", 0), newKey(t, "attacker", 0)
	if _, err := f.m.Import(bg, importReq(doc(gvr, entry(victim.hex, []uint64{5})), victim.qrlV1(t), []byte(password))); err != nil {
		t.Fatal(err)
	}
	if rs, _ := f.m.Delete(bg, []mldsa87.PublicKey{victim.pk}); rs[0].Status != Deleted {
		t.Fatalf("delete %+v", rs)
	}
	before, beforeStatus := f.history(t, victim), f.status(t, victim)
	decrypts, _ := f.sem.Stats()

	spoofed := edit(t, attacker.qrlV1(t), func(m map[string]any) { m["pubkey"] = victim.hex[2:] })
	hugeM := edit(t, attacker.qrlV1(t), func(m map[string]any) { kdfParams(m)["m"] = math.MaxInt32 + 1 })
	noKDF := edit(t, attacker.qrlV1(t), func(m map[string]any) { delete(m["crypto"].(map[string]any), "kdf") })
	dklen := edit(t, attacker.qrlV1(t), func(m map[string]any) { kdfParams(m)["dklen"] = 16 })
	traversal := edit(t, attacker.qrlV1(t), func(m map[string]any) { m["pubkey"] = "../../etc/passwd" })
	noPubkey := edit(t, attacker.qrlV1(t), func(m map[string]any) { delete(m, "pubkey") })
	pw := []byte(password)
	long := bytes.Repeat([]byte("p"), keystores.MaxPasswordFile+1)
	history := doc(gvr, entry(victim.hex, []uint64{50, 60}, [2]uint64{7, 8}), entry(attacker.hex, []uint64{70}))
	rs, err := f.m.Import(bg, importReq(history,
		spoofed, pw, hugeM, pw, noKDF, pw, dklen, pw, traversal, pw, noPubkey, pw, attacker.qrlV1(t), long))
	if err != nil {
		t.Fatal(err)
	}
	wantStatuses(t, rs, Error, Error, Error, Error, Error, Error, Error)
	for i, want := range []string{"pubkey does not match", "refused by the keystore policy", "refused by the keystore policy",
		"refused by the keystore policy", "malformed keystore", "declares no pubkey", "longer than 65536 bytes"} {
		if !strings.Contains(rs[i].Message, want) {
			t.Errorf("keystore %d: %q, want %q", i, rs[i].Message, want)
		}
	}
	if got := f.files(t); len(got) != 0 {
		t.Fatalf("files written: %v", got)
	}
	if got := f.history(t, victim); got != before || f.status(t, victim) != beforeStatus {
		t.Fatalf("victim's history %q (was %q), status %+v (was %+v)", got, before, f.status(t, victim), beforeStatus)
	}
	if st := f.status(t, attacker); st.Registered {
		t.Fatalf("attacker registered: %+v", st)
	}
	// Only the spoofed keystore was decrypted: the policy refusals, the
	// missing pubkey and the long password stop before Argon2id.
	if after, _ := f.sem.Stats(); after-decrypts != 1 {
		t.Fatalf("%d Argon2id runs, want 1", after-decrypts)
	}
	if f.loaded(victim) || f.loaded(attacker) {
		t.Fatal("a refused key was loaded")
	}
}

// Only the history of the keys being added is imported: elements of other
// keys write nothing and register nothing. A history file that cannot be
// read, or is for another network, refuses the request before any keystore
// is opened.
func TestImportHistoryFilterAndRefusal(t *testing.T) {
	f := newFixture(t)
	a, other := newKey(t, "hist", 0), newKey(t, "hist", 1)
	history := doc(gvr, entry(a.hex, []uint64{10}), entry(other.hex, []uint64{20}, [2]uint64{1, 2}))
	rs, err := f.m.Import(bg, importReq(history, a.qrlV1(t), []byte(password)))
	if err != nil {
		t.Fatal(err)
	}
	wantStatuses(t, rs, Imported)
	if st := f.status(t, other); st.Registered {
		t.Fatalf("a key outside the request was registered: %+v", st)
	}
	if got := f.history(t, a); got != "low 10 - -; b10" {
		t.Fatalf("history %q", got)
	}

	b := newKey(t, "hist", 2)
	decrypts, _ := f.sem.Stats()
	for _, h := range []string{
		`{"metadata":{"interchange_format_version":"5"`,  // truncated
		doc(slashing.Root{1}, entry(b.hex, []uint64{1})), // another network
		`{"metadata":{"interchange_format_version":"4","genesis_validators_root":"0x` + hex.EncodeToString(gvr[:]) + `"},"data":[]}`,
	} {
		if _, err := f.m.Import(bg, importReq(h, b.qrlV1(t), []byte(password))); !errors.Is(err, ErrInterchange) {
			t.Fatalf("history %.40s: %v", h, err)
		}
	}
	if after, _ := f.sem.Stats(); after != decrypts || f.loaded(b) || f.status(t, b).Registered || len(f.files(t)) != 3 {
		t.Fatalf("a refused request opened or wrote something")
	}
	if _, err := f.m.Import(bg, ImportRequest{Keystores: [][]byte{nil}}); !errors.Is(err, ErrRequest) {
		t.Fatalf("mismatched request: %v", err)
	}
}

// A store not bound to a network yet is pinned to the history's root.
func TestImportPinsAnUnboundStore(t *testing.T) {
	f := newFixture(t, fixtureOptions{unbound: true})
	a := newKey(t, "pin", 0)
	root := slashing.Root{7}
	rs, err := f.m.Import(bg, importReq(doc(root, entry(a.hex, []uint64{3})), a.qrlV1(t), []byte(password)))
	if err != nil {
		t.Fatal(err)
	}
	wantStatuses(t, rs, Imported)
	if got, ok, err := f.store.GenesisValidatorsRoot(bg); err != nil || !ok || got != root {
		t.Fatalf("store root %x %v %v", got, ok, err)
	}
}

// A deleted key is disabled; importing it again enables it, with or without
// history (the documented way to enable a key again).
func TestReimportEnables(t *testing.T) {
	f := newFixture(t)
	a := newKey(t, "again", 0)
	for _, h := range []string{"", doc(gvr, entry(a.hex, []uint64{9}))} {
		if rs, err := f.m.Import(bg, importReq(h, a.qrlV1(t), []byte(password))); err != nil || rs[0].Status != Imported {
			t.Fatalf("import: %+v %v", rs, err)
		}
		if !f.status(t, a).Enabled {
			t.Fatal("the import did not enable the key")
		}
		if rs, _ := f.m.Delete(bg, []mldsa87.PublicKey{a.pk}); rs[0].Status != Deleted || f.status(t, a).Enabled {
			t.Fatalf("delete: %+v %+v", rs, f.status(t, a))
		}
	}
}

// A key that is not loaded is disabled anyway: not_active when it has
// history, not_found when it has none (a key the store never saw is
// registered disabled). A read-only key is an error and stays enabled; a
// second delete of a deleted key with history is not_active, with the
// same export.
func TestDeleteStatuses(t *testing.T) {
	f := newFixture(t)
	a, unknown, raw := newKey(t, "del", 0), newKey(t, "del", 1), newKey(t, "del", 2)
	if _, err := f.m.Import(bg, importReq(doc(gvr, entry(a.hex, []uint64{4})), a.qrlV1(t), []byte(password))); err != nil {
		t.Fatal(err)
	}
	// raw is loaded from a file-raw key-config file: read-only.
	k, err := mldsa87.FromSeed48(raw.seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.keys.Add(provider.Batch{Source: keyconfig.Source(filepath.Join(f.dir, "raw.yaml")), Keys: []*mldsa87.Key{k}},
		func(pks [][]byte) error { return f.engine.RegisterValidators(bg, pks) }); err != nil {
		t.Fatal(err)
	}
	rs, first := f.m.Delete(bg, []mldsa87.PublicKey{a.pk, unknown.pk, raw.pk})
	wantStatuses(t, rs, Deleted, NotFound, Error)
	if !strings.Contains(rs[2].Message, "read-only") || !f.loaded(raw) || !f.status(t, raw).Enabled {
		t.Fatalf("read-only key: %+v, loaded %v, %+v", rs[2], f.loaded(raw), f.status(t, raw))
	}
	if st := f.status(t, unknown); !st.Registered || st.Enabled {
		t.Fatalf("unknown key: %+v", st)
	}
	if strings.Contains(string(first), raw.hex[2:]) || !strings.Contains(string(first), a.hex[2:]) {
		t.Fatalf("export %s", first)
	}
	rs, second := f.m.Delete(bg, []mldsa87.PublicKey{a.pk, unknown.pk})
	wantStatuses(t, rs, NotActive, NotFound)
	if !bytes.Equal(first, second) {
		t.Fatalf("second export differs:\n%s\n%s", first, second)
	}
	// An empty request exports an empty document of the network.
	rs, empty := f.m.Delete(bg, nil)
	if len(rs) != 0 || !strings.Contains(string(empty), hex.EncodeToString(gvr[:])) {
		t.Fatalf("empty delete: %+v %s", rs, empty)
	}
}

// A signer not bound to a network has no history: a delete still deletes,
// and its export is empty.
func TestDeleteUnbound(t *testing.T) {
	f := newFixture(t, fixtureOptions{unbound: true})
	a, b := newKey(t, "unbound", 0), newKey(t, "unbound", 1)
	if _, err := f.m.Import(bg, importReq("", a.qrlV1(t), []byte(password))); err != nil {
		t.Fatal(err)
	}
	rs, export := f.m.Delete(bg, []mldsa87.PublicKey{a.pk, b.pk})
	wantStatuses(t, rs, Deleted, NotFound)
	if export != nil || f.loaded(a) || f.status(t, a).Enabled || len(f.files(t)) != 0 {
		t.Fatalf("export %q, loaded %v, %+v", export, f.loaded(a), f.status(t, a))
	}
}

// The delete's export is interchange.Export with the key filter, so the
// same placeholder rule applies: after a watermark repair raised a key's
// watermarks above its records, the export carries the watermark records.
func TestDeleteExportPlaceholders(t *testing.T) {
	f := newFixture(t)
	a := newKey(t, "repair", 0)
	if _, err := f.m.Import(bg, importReq(doc(gvr, entry(a.hex, []uint64{10}, [2]uint64{2, 3})), a.qrlV1(t), []byte(password))); err != nil {
		t.Fatal(err)
	}
	id := slashing.KeyID(a.pk.ID())
	if err := f.store.UpdateHistory(bg, []slashing.KeyID{id}, func(_ slashing.KeyID, tx slashing.HistoryTx) error {
		if err := tx.RaiseSlotLowWatermark(100); err != nil {
			return err
		}
		return tx.RaiseEpochLowWatermarks(20, 21)
	}); err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	res, err := interchange.Export(bg, f.store, &want, interchange.ExportOptions{Keys: []slashing.KeyID{id}})
	if err != nil || res.Watermarks != 2 {
		t.Fatalf("export: %+v %v", res, err)
	}
	_, export := f.m.Delete(bg, []mldsa87.PublicKey{a.pk})
	if !bytes.Equal(export, want.Bytes()) {
		t.Fatalf("delete export:\n%s\nwant:\n%s", export, want.Bytes())
	}
}

// A key not loaded yet whose files exist (the startup load or a reload has
// not reached it, or its load failed) is deleted: disabled, its files
// removed, its source marked, so that a load that read the files before
// cannot load it. A key imported during a load stays loaded after it.
func TestChangesDuringALoad(t *testing.T) {
	f := newFixture(t)
	gone, kept := newKey(t, "load", 0), newKey(t, "load", 1)
	if _, err := f.m.Import(bg, importReq("", gone.qrlV1(t), []byte(password))); err != nil {
		t.Fatal(err)
	}
	// The process restarts: the files are there, nothing is loaded.
	src := filesOf(f.dir, &gone.pk).source()
	if _, err := f.keys.Remove(src); err != nil {
		t.Fatal(err)
	}
	if _, err := f.keys.Apply(nil, nil, nil); err != nil { // the restart's empty set
		t.Fatal(err)
	}
	since := f.keys.Generation() // the startup load lists the directory
	cfg := keyconfig.Config{Dir: f.dir, Policy: secretfile.Policy{Strict: true}, Decrypt: f.sem.Decrypt}
	batches, err := cfg.Load(bg, 1, nil, nil)
	if err != nil || len(batches) != 1 || batches[0].Err != nil {
		t.Fatalf("load: %v %+v", err, batches)
	}

	rs, _ := f.m.Delete(bg, []mldsa87.PublicKey{gone.pk})
	wantStatuses(t, rs, Deleted)
	if rs, err := f.m.Import(bg, importReq("", kept.qrlV1(t), []byte(password))); err != nil || rs[0].Status != Imported {
		t.Fatalf("import during the load: %+v %v", rs, err)
	}

	// The load applies what it read: the deleted key stays out, the
	// imported one stays in.
	if _, err := f.keys.ApplySince(since, batches, nil, nil); err != nil {
		t.Fatal(err)
	}
	if f.loaded(gone) || !f.loaded(kept) || f.status(t, gone).Enabled {
		t.Fatalf("after the load: gone loaded %v, kept loaded %v, gone %+v", f.loaded(gone), f.loaded(kept), f.status(t, gone))
	}
	if got := f.files(t); len(got) != 3 {
		t.Fatalf("files %v", got)
	}
}

// A reload that loads an imported key from the files the import has just
// written does not make the import fail or remove the files.
func TestImportRacesAReload(t *testing.T) {
	f := newFixture(t)
	a := newKey(t, "race", 0)
	f.m.afterWrite = func() {
		cfg := keyconfig.Config{Dir: f.dir, Policy: secretfile.Policy{Strict: true}, Decrypt: f.sem.Decrypt}
		batches, err := cfg.Load(bg, 1, nil, nil)
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := f.keys.Apply(batches, func(pks [][]byte) error { return f.engine.RegisterValidators(bg, pks) }, nil); err != nil {
			t.Error(err)
		}
	}
	rs, err := f.m.Import(bg, importReq("", a.qrlV1(t), []byte(password)))
	if err != nil {
		t.Fatal(err)
	}
	wantStatuses(t, rs, Imported)
	if !f.loaded(a) || !f.status(t, a).Enabled || len(f.files(t)) != 3 {
		t.Fatalf("loaded %v, %+v, files %v", f.loaded(a), f.status(t, a), f.files(t))
	}
	if e, _ := f.keys.Entry(a.pk.ID()); e.Source != filesOf(f.dir, &a.pk).source() {
		t.Fatalf("source %s", e.Source)
	}
}

// failingStore fails the writes its flags name.
type failingStore struct {
	slashing.Store
	failRegister, failEnable bool
}

func (s *failingStore) RegisterValidators(ctx context.Context, pks [][]byte) error {
	if s.failRegister {
		return errors.New("store down")
	}
	return s.Store.RegisterValidators(ctx, pks)
}

func (s *failingStore) UpdateHistory(ctx context.Context, ids []slashing.KeyID,
	fn func(slashing.KeyID, slashing.HistoryTx) error) error {
	if !s.failEnable {
		return s.Store.UpdateHistory(ctx, ids, fn)
	}
	return s.Store.UpdateHistory(ctx, ids, func(id slashing.KeyID, tx slashing.HistoryTx) error {
		return fn(id, enableFails{tx})
	})
}

// enableFails is a transaction whose SetEnabled(true) fails.
type enableFails struct{ slashing.HistoryTx }

func (t enableFails) SetEnabled(enabled bool) error {
	if enabled {
		return errors.New("store down")
	}
	return t.HistoryTx.SetEnabled(enabled)
}

// An import that fails after the key's files are written leaves nothing:
// no file, no loaded key, and the enabled flag as it was (a deleted key
// stays disabled).
func TestImportFailureRollsBack(t *testing.T) {
	var fs *failingStore
	f := newFixture(t, fixtureOptions{store: func(s slashing.Store) slashing.Store {
		fs = &failingStore{Store: s}
		return fs
	}})
	a := newKey(t, "rollback", 0)
	if _, err := f.m.Import(bg, importReq("", a.qrlV1(t), []byte(password))); err != nil {
		t.Fatal(err)
	}
	if rs, _ := f.m.Delete(bg, []mldsa87.PublicKey{a.pk}); rs[0].Status != Deleted {
		t.Fatalf("delete %+v", rs)
	}
	for _, step := range []struct {
		name string
		set  func()
	}{
		{"registration", func() { fs.failRegister, fs.failEnable = true, false }},
		{"enabling", func() { fs.failRegister, fs.failEnable = false, true }},
	} {
		step.set()
		rs, err := f.m.Import(bg, importReq(doc(gvr, entry(a.hex, []uint64{30})), a.qrlV1(t), []byte(password)))
		if err != nil {
			t.Fatal(err)
		}
		wantStatuses(t, rs, Error)
		if f.loaded(a) || f.status(t, a).Enabled || len(f.files(t)) != 0 {
			t.Fatalf("%s failed: loaded %v, %+v, files %v", step.name, f.loaded(a), f.status(t, a), f.files(t))
		}
	}

	// A key the store did not know: without history, a failed enable
	// leaves it registered and enabled, as any load would register it;
	// with history, the history step registered it disabled, and it stays
	// so.
	fs.failRegister, fs.failEnable = false, true
	for _, c := range []struct {
		key     testKey
		history bool
	}{{newKey(t, "rollback", 1), false}, {newKey(t, "rollback", 2), true}} {
		h := ""
		if c.history {
			h = doc(gvr, entry(c.key.hex, []uint64{40}))
		}
		rs, err := f.m.Import(bg, importReq(h, c.key.qrlV1(t), []byte(password)))
		if err != nil {
			t.Fatal(err)
		}
		wantStatuses(t, rs, Error)
		if st := f.status(t, c.key); f.loaded(c.key) || !st.Registered || st.Enabled == c.history || len(f.files(t)) != 0 {
			t.Fatalf("new key, history %v: loaded %v, %+v, files %v", c.history, f.loaded(c.key), st, f.files(t))
		}
	}
}

// A password with trailing line breaks opens the keystore as the password
// file written for it will be read back: without them.
func TestImportPasswordAsTheFileReadsIt(t *testing.T) {
	f := newFixture(t)
	a := newKey(t, "newline", 0)
	rs, err := f.m.Import(bg, importReq("", a.qrlV1(t), []byte(password+"\r\n")))
	if err != nil {
		t.Fatal(err)
	}
	wantStatuses(t, rs, Imported)
	fl := filesOf(f.dir, &a.pk)
	if data, err := os.ReadFile(fl.password()); err != nil || string(data) != password+"\r\n" {
		t.Fatalf("password file %q %v", data, err)
	}
	keys, err := (keyconfig.Config{Dir: f.dir, Policy: secretfile.Policy{Strict: true}, Decrypt: f.sem.Decrypt}).LoadFile(bg, fl.config())
	if err != nil || keys[0].PublicKey() != a.pk {
		t.Fatalf("reload: %v", err)
	}
	keys[0].Zeroize()
}

// Writing replaces a symlink or a 0644 file planted at a file's name
// without writing through it, and a failed write leaves no file.
func TestFilesReplacePlantedFiles(t *testing.T) {
	f := newFixture(t)
	a := newKey(t, "planted", 0)
	fl := filesOf(f.dir, &a.pk)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, fl.keystore()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fl.password(), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rs, err := f.m.Import(bg, importReq("", a.qrlV1(t), []byte(password))); err != nil || rs[0].Status != Imported {
		t.Fatalf("import: %+v %v", rs, err)
	}
	for _, p := range []string{fl.keystore(), fl.password()} {
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != FileMode {
			t.Fatalf("%s: %v %v", p, err, fi)
		}
	}
	if data, _ := os.ReadFile(target); string(data) != "outside" {
		t.Fatal("the write went through the symlink")
	}

	b := newKey(t, "planted", 1)
	if err := os.Chmod(f.dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.dir, DirMode) })
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	rs, err := f.m.Import(bg, importReq("", b.qrlV1(t), []byte(password)))
	if err != nil {
		t.Fatal(err)
	}
	wantStatuses(t, rs, Error)
	if err := os.Chmod(f.dir, DirMode); err != nil {
		t.Fatal(err)
	}
	if got := f.files(t); len(got) != 3 || f.loaded(b) {
		t.Fatalf("files %v, loaded %v", got, f.loaded(b))
	}
}

// A keystore file at a key's name that declares another key is left in
// place, and the delete changes nothing.
func TestDeleteRefusesAnotherKeysFile(t *testing.T) {
	f := newFixture(t)
	a, b := newKey(t, "other", 0), newKey(t, "other", 1)
	fl := filesOf(f.dir, &a.pk)
	if err := os.WriteFile(fl.keystore(), b.qrlV1(t), 0o600); err != nil {
		t.Fatal(err)
	}
	rs, _ := f.m.Delete(bg, []mldsa87.PublicKey{a.pk})
	wantStatuses(t, rs, Error)
	if _, err := os.Stat(fl.keystore()); err != nil || f.status(t, a).Registered {
		t.Fatalf("the file was removed or the key disabled: %v %+v", err, f.status(t, a))
	}
}

func TestPrepareDir(t *testing.T) {
	root := t.TempDir()
	made := filepath.Join(root, "a", "b")
	if err := PrepareDir(made, true, nil); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(made); err != nil || fi.Mode().Perm() != DirMode {
		t.Fatalf("created: %v %v", err, fi)
	}
	open := filepath.Join(root, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := PrepareDir(open, true, nil); !errors.Is(err, ErrDirInsecure) {
		t.Fatalf("strict: %v", err)
	}
	var warned []fs.FileMode
	if err := PrepareDir(open, false, func(m fs.FileMode) { warned = append(warned, m) }); err != nil ||
		!slices.Equal(warned, []fs.FileMode{0o755}) {
		t.Fatalf("lax: %v, warned %v", err, warned)
	}
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PrepareDir(file, true, nil); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("file: %v", err)
	}
}

// Imports run through the Argon2id semaphore: one run per keystore with an
// ASCII password.
func TestImportUsesTheSemaphore(t *testing.T) {
	f := newFixture(t)
	var req ImportRequest
	for i := range 5 {
		k := newKey(t, "sem", i)
		req.Keystores = append(req.Keystores, k.qrlV1(t))
		req.Passwords = append(req.Passwords, []byte(password))
	}
	before, _ := f.sem.Stats()
	if rs, err := f.m.Import(bg, req); err != nil || len(rs) != 5 {
		t.Fatalf("%+v %v", rs, err)
	}
	if after, _ := f.sem.Stats(); after-before != 5 {
		t.Fatalf("%d decrypts", after-before)
	}
}

// Nothing secret reaches the log at TRACE: no password, no keystore
// ciphertext, no full public key.
func TestNoSecretsInTheLog(t *testing.T) {
	f := newFixture(t)
	a, b := newKey(t, "log", 0), newKey(t, "log", 1)
	ks := a.qrlV1(t)
	if _, err := f.m.Import(bg, importReq("", ks, []byte(password), b.qrlV1(t), []byte("wrong-password-123"))); err != nil {
		t.Fatal(err)
	}
	f.m.Delete(bg, []mldsa87.PublicKey{a.pk, b.pk})
	cipher := edit(t, ks, func(m map[string]any) {})
	msg := string(cipher)
	i := strings.Index(msg, `"message":"`)
	ciphertext := msg[i+11 : i+11+64]
	out := f.log.String()
	for _, secret := range []string{password, "wrong-password-123", ciphertext, a.hex[2:], b.hex[2:]} {
		if strings.Contains(out, secret) {
			t.Fatalf("the log holds %.20s…:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "Keymanager import") || !strings.Contains(out, a.pk.LogID()) {
		t.Fatalf("log:\n%s", out)
	}
}
