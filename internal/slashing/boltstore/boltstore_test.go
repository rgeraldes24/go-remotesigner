// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package boltstore_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

func TestConformance(t *testing.T) {
	slashingtest.Run(t, func(t *testing.T) slashing.Store {
		s, err := boltstore.Open(filepath.Join(t.TempDir(), "slashing-protection.db"), boltstore.Options{})
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func dbPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "data", "slashing-protection.db")
}

func open(t *testing.T, path string, opts boltstore.Options) *boltstore.Store {
	t.Helper()
	s, err := boltstore.Open(path, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestReopenKeepsState(t *testing.T) {
	ctx := context.Background()
	path := dbPath(t)
	key := slashingtest.Key(0)
	id := slashing.KeyIDOf(key)
	block := slashing.BlockRequest{PublicKey: key, GenesisValidatorsRoot: slashingtest.GVR, Slot: 10, SigningRoot: slashingtest.RootOf(1)}
	att := slashing.AttestationRequest{
		PublicKey: key, GenesisValidatorsRoot: slashingtest.GVR, SourceEpoch: 2, TargetEpoch: 3, SigningRoot: slashingtest.RootOf(2),
	}
	frontier := slashing.RandaoState{Index: 1<<20 - 1, Reveal: slashingtest.RootOf(3), LastSlot: 10}
	high := slashing.HighWatermark{Epoch: slashingtest.U64(100), Slot: slashingtest.U64(1000)}

	s := open(t, path, boltstore.Options{})
	e := slashing.NewEngine(s)
	must(t, e.RegisterValidators(ctx, [][]byte{key, slashingtest.Key(1)}))
	for _, d := range []func() (slashing.Decision, error){
		func() (slashing.Decision, error) { return e.CheckAndRecordBlock(ctx, block) },
		func() (slashing.Decision, error) { return e.CheckAndRecordAttestation(ctx, att) },
	} {
		got, err := d()
		must(t, err)
		if !got.Allowed || got.Repeat {
			t.Fatalf("first signing: %+v, want allowed", got)
		}
	}
	if swapped, err := s.CompareAndSwapRandaoState(ctx, id, nil, frontier); err != nil || !swapped {
		t.Fatalf("CompareAndSwapRandaoState: %v %v", swapped, err)
	}
	must(t, s.SetHighWatermark(ctx, high))
	must(t, s.SetValidatorEnabled(ctx, slashing.KeyIDOf(slashingtest.Key(1)), false))
	must(t, s.Close())

	s = open(t, path, boltstore.Options{})
	t.Cleanup(func() { _ = s.Close() })
	e = slashing.NewEngine(s)
	must(t, e.RegisterValidators(ctx, [][]byte{key, slashingtest.Key(1)}))

	if gvr, ok, err := s.GenesisValidatorsRoot(ctx); err != nil || !ok || gvr != slashingtest.GVR {
		t.Errorf("GenesisValidatorsRoot after reopen: %x %v %v", gvr, ok, err)
	}
	if d, err := e.CheckAndRecordBlock(ctx, block); err != nil || !d.Repeat {
		t.Errorf("block after reopen: %+v %v, want a repeat", d, err)
	}
	block.SigningRoot = slashingtest.RootOf(9)
	if d, err := e.CheckAndRecordBlock(ctx, block); err != nil || d.Reason != slashing.ReasonDoubleProposal {
		t.Errorf("conflicting block after reopen: %+v %v, want a double proposal", d, err)
	}
	if d, err := e.CheckAndRecordAttestation(ctx, att); err != nil || !d.Repeat {
		t.Errorf("attestation after reopen: %+v %v, want a repeat", d, err)
	}
	if got, ok, err := s.RandaoState(ctx, id); err != nil || !ok || got != frontier {
		t.Errorf("RandaoState after reopen: %+v %v %v, want %+v", got, ok, err, frontier)
	}
	if got, err := s.HighWatermark(ctx); err != nil || *got.Epoch != *high.Epoch || *got.Slot != *high.Slot {
		t.Errorf("HighWatermark after reopen: %+v %v", got, err)
	}
	if st, err := s.ValidatorStatus(ctx, slashing.KeyIDOf(slashingtest.Key(1))); err != nil || !st.Registered || st.Enabled {
		t.Errorf("disabled validator after reopen: %+v %v", st, err)
	}
}

func TestGenesisValidatorsRootPin(t *testing.T) {
	ctx := context.Background()
	other := slashingtest.RootOf(42)
	gvr := slashingtest.GVR

	t.Run("pinned at creation", func(t *testing.T) {
		path := dbPath(t)
		var hooked int
		s := open(t, path, boltstore.Options{GenesisValidatorsRoot: &gvr, OnPin: func(slashing.Root) { hooked++ }})
		if got, ok, err := s.GenesisValidatorsRoot(ctx); err != nil || !ok || got != gvr {
			t.Fatalf("GenesisValidatorsRoot: %x %v %v", got, ok, err)
		}
		if got, err := s.PinGenesisValidatorsRoot(ctx, other); err != nil || got != gvr {
			t.Fatalf("PinGenesisValidatorsRoot over a pinned root: %x %v, want %x", got, err, gvr)
		}
		if hooked != 0 {
			t.Fatalf("OnPin called %d times for a root pinned at creation", hooked)
		}
		must(t, s.Close())

		for name, opts := range map[string]boltstore.Options{"same": {GenesisValidatorsRoot: &gvr}, "unset": {}} {
			s := open(t, path, opts)
			if got, _, _ := s.GenesisValidatorsRoot(ctx); got != gvr {
				t.Errorf("%s: pinned root %x, want %x", name, got, gvr)
			}
			must(t, s.Close())
		}
		_, err := boltstore.Open(path, boltstore.Options{GenesisValidatorsRoot: &other})
		if !errors.Is(err, slashing.ErrGenesisValidatorsRootMismatch) {
			t.Fatalf("Open with a different configured root: %v, want ErrGenesisValidatorsRootMismatch", err)
		}
	})

	t.Run("trust on first use", func(t *testing.T) {
		path := dbPath(t)
		var pins []slashing.Root
		s := open(t, path, boltstore.Options{OnPin: func(r slashing.Root) { pins = append(pins, r) }})
		if _, ok, err := s.GenesisValidatorsRoot(ctx); err != nil || ok {
			t.Fatalf("new store without a configured root is pinned: %v %v", ok, err)
		}
		for _, r := range []slashing.Root{gvr, other} {
			if got, err := s.PinGenesisValidatorsRoot(ctx, r); err != nil || got != gvr {
				t.Fatalf("PinGenesisValidatorsRoot(%x): %x %v, want %x", r, got, err, gvr)
			}
		}
		if len(pins) != 1 || pins[0] != gvr {
			t.Fatalf("OnPin calls %x, want exactly one with %x", pins, gvr)
		}
		must(t, s.Close())
		if _, err := boltstore.Open(path, boltstore.Options{GenesisValidatorsRoot: &other}); !errors.Is(err, slashing.ErrGenesisValidatorsRootMismatch) {
			t.Fatalf("Open with a root other than the TOFU pin: %v, want ErrGenesisValidatorsRootMismatch", err)
		}
	})

	t.Run("configured on an unpinned store", func(t *testing.T) {
		path := dbPath(t)
		must(t, open(t, path, boltstore.Options{}).Close())
		s := open(t, path, boltstore.Options{GenesisValidatorsRoot: &gvr})
		defer s.Close()
		if got, ok, err := s.GenesisValidatorsRoot(ctx); err != nil || !ok || got != gvr {
			t.Fatalf("GenesisValidatorsRoot: %x %v %v, want %x", got, ok, err, gvr)
		}
	})
}

func TestSecondOpenIsLocked(t *testing.T) {
	path := dbPath(t)
	s := open(t, path, boltstore.Options{})
	start := time.Now()
	_, err := boltstore.Open(path, boltstore.Options{LockTimeout: 100 * time.Millisecond})
	if !errors.Is(err, boltstore.ErrLocked) {
		t.Fatalf("second Open: %v, want ErrLocked", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("second Open took %v, want about the lock timeout", d)
	}
	must(t, s.Close())
	must(t, open(t, path, boltstore.Options{}).Close())
}

func TestFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	path := dbPath(t)
	must(t, open(t, path, boltstore.Options{}).Close())
	for p, want := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700 | os.ModeDir} {
		fi, err := os.Stat(p)
		must(t, err)
		if fi.Mode() != want {
			t.Errorf("%s: mode %v, want %v", p, fi.Mode(), want)
		}
	}
}

func TestNotStore(t *testing.T) {
	t.Run("foreign bbolt file", func(t *testing.T) {
		path := dbPath(t)
		must(t, os.MkdirAll(filepath.Dir(path), 0o700))
		db, err := bolt.Open(path, 0o600, nil)
		must(t, err)
		must(t, db.Update(func(tx *bolt.Tx) error {
			_, err := tx.CreateBucket([]byte("something-else"))
			return err
		}))
		must(t, db.Close())
		if _, err := boltstore.Open(path, boltstore.Options{}); !errors.Is(err, boltstore.ErrNotStore) {
			t.Fatalf("Open: %v, want ErrNotStore", err)
		}
	})
	t.Run("not a bbolt file", func(t *testing.T) {
		path := dbPath(t)
		must(t, os.MkdirAll(filepath.Dir(path), 0o700))
		must(t, os.WriteFile(path, make([]byte, 8192), 0o600))
		if _, err := boltstore.Open(path, boltstore.Options{}); err == nil {
			t.Fatal("Open of a zero-filled file succeeded")
		}
	})
}

func TestClosed(t *testing.T) {
	ctx := context.Background()
	s := open(t, dbPath(t), boltstore.Options{})
	must(t, s.RegisterValidators(ctx, [][]byte{slashingtest.Key(0)}))
	must(t, s.Close())
	id := slashing.KeyIDOf(slashingtest.Key(0))
	for name, err := range map[string]error{
		"SchemaVersion":             second(s.SchemaVersion(ctx)),
		"PinGenesisValidatorsRoot":  second(s.PinGenesisValidatorsRoot(ctx, slashingtest.GVR)),
		"HighWatermark":             second(s.HighWatermark(ctx)),
		"RegisterValidators":        s.RegisterValidators(ctx, [][]byte{slashingtest.Key(1)}),
		"ValidatorStatus":           second(s.ValidatorStatus(ctx, id)),
		"UpdateBlocks":              s.UpdateBlocks(ctx, id, func(slashing.BlockTx) error { return nil }),
		"CompareAndSwapRandaoState": second(s.CompareAndSwapRandaoState(ctx, id, nil, slashing.RandaoState{})),
	} {
		if !errors.Is(err, boltstore.ErrClosed) {
			t.Errorf("%s after Close: %v, want ErrClosed", name, err)
		}
	}
}

func TestCanceledContext(t *testing.T) {
	s := open(t, dbPath(t), boltstore.Options{})
	t.Cleanup(func() { _ = s.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.RegisterValidators(ctx, [][]byte{slashingtest.Key(0)}); !errors.Is(err, context.Canceled) {
		t.Fatalf("RegisterValidators with a canceled context: %v, want context.Canceled", err)
	}
}

// TestFailedTransactionLeavesNoTrace checks that an error from the transaction function rolls back its writes.
func TestFailedTransactionLeavesNoTrace(t *testing.T) {
	ctx := context.Background()
	s := open(t, dbPath(t), boltstore.Options{})
	t.Cleanup(func() { _ = s.Close() })
	must(t, s.RegisterValidators(ctx, [][]byte{slashingtest.Key(0)}))
	id := slashing.KeyIDOf(slashingtest.Key(0))
	boom := errors.New("boom")
	err := s.UpdateBlocks(ctx, id, func(tx slashing.BlockTx) error {
		must(t, tx.InsertBlock(slashing.SignedBlock{Slot: 5, SigningRoot: slashingtest.RootPtr(5)}))
		must(t, tx.RaiseSlotLowWatermark(5))
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("UpdateBlocks: %v, want the function's error", err)
	}
	must(t, s.UpdateBlocks(ctx, id, func(tx slashing.BlockTx) error {
		if _, found, err := tx.BlockAt(5); err != nil || found {
			t.Errorf("BlockAt after rollback: found %v, %v", found, err)
		}
		if low, err := tx.LowWatermark(); err != nil || low.Slot != nil {
			t.Errorf("LowWatermark after rollback: %+v, %v", low, err)
		}
		return nil
	}))
}

func second[T any](_ T, err error) error { return err }

// TestSurroundQueries checks the cursor walks of SurroundingAttestation and SurroundedAttestation against a brute
// force search over every (source, target) pair around the recorded attestations, including the epoch extremes.
func TestSurroundQueries(t *testing.T) {
	ctx := context.Background()
	s := open(t, dbPath(t), boltstore.Options{})
	t.Cleanup(func() { _ = s.Close() })
	must(t, s.RegisterValidators(ctx, [][]byte{slashingtest.Key(0)}))
	id := slashing.KeyIDOf(slashingtest.Key(0))
	const maxEpoch = ^uint64(0)
	recorded := []slashing.SignedAttestation{
		{SourceEpoch: 0, TargetEpoch: 0},
		{SourceEpoch: 1, TargetEpoch: 10, SigningRoot: slashingtest.RootPtr(1)},
		{SourceEpoch: 2, TargetEpoch: 8},
		{SourceEpoch: 5, TargetEpoch: 6, SigningRoot: slashingtest.RootPtr(2)},
		{SourceEpoch: 0, TargetEpoch: 20},
		{SourceEpoch: 7, TargetEpoch: 9},
		{SourceEpoch: maxEpoch - 1, TargetEpoch: maxEpoch},
	}
	must(t, s.UpdateAttestations(ctx, id, func(tx slashing.AttestationTx) error {
		for _, a := range recorded {
			if err := tx.InsertAttestation(a); err != nil {
				return err
			}
		}
		return nil
	}))
	brute := func(match func(a slashing.SignedAttestation) bool) (best slashing.SignedAttestation, found bool) {
		for _, a := range recorded {
			if match(a) && (!found || a.TargetEpoch > best.TargetEpoch) {
				best, found = a, true
			}
		}
		return best, found
	}
	epochs := []uint64{maxEpoch - 2, maxEpoch - 1, maxEpoch}
	for e := range uint64(23) {
		epochs = append(epochs, e)
	}
	must(t, s.UpdateAttestations(ctx, id, func(tx slashing.AttestationTx) error {
		for _, source := range epochs {
			for _, target := range epochs {
				got, ok, err := tx.SurroundingAttestation(source, target)
				want, wantOK := brute(func(a slashing.SignedAttestation) bool {
					return a.SourceEpoch < source && a.TargetEpoch > target
				})
				if err != nil || ok != wantOK || (ok && !sameAttestation(got, want)) {
					t.Errorf("SurroundingAttestation(%d, %d) = %+v %v %v, want %+v %v", source, target, got, ok, err, want, wantOK)
				}
				got, ok, err = tx.SurroundedAttestation(source, target)
				want, wantOK = brute(func(a slashing.SignedAttestation) bool {
					return a.SourceEpoch > source && a.TargetEpoch < target
				})
				if err != nil || ok != wantOK || (ok && !sameAttestation(got, want)) {
					t.Errorf("SurroundedAttestation(%d, %d) = %+v %v %v, want %+v %v", source, target, got, ok, err, want, wantOK)
				}
			}
		}
		return nil
	}))
}

func sameAttestation(a, b slashing.SignedAttestation) bool {
	if a.SourceEpoch != b.SourceEpoch || a.TargetEpoch != b.TargetEpoch || (a.SigningRoot == nil) != (b.SigningRoot == nil) {
		return false
	}
	return a.SigningRoot == nil || *a.SigningRoot == *b.SigningRoot
}
