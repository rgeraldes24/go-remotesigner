// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package boltstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/slashingtest"
)

// The tests below re-run the test binary as a helper process that acts on the store and then exits abruptly.
const (
	envHelper = "BOLTSTORE_TEST_HELPER"
	envPath   = "BOLTSTORE_TEST_PATH"

	exitLocked    = 10 // the helper's Open failed with ErrLocked
	exitNotLocked = 11 // the helper's Open failed with another error
	exitOpened    = 12 // the helper's Open succeeded
)

var (
	frontierFirst = slashing.RandaoState{Index: 1<<20 - 1, Reveal: slashingtest.RootOf(1), LastSlot: 100}
	frontierNext  = slashing.RandaoState{Index: 1<<20 - 2, Reveal: slashingtest.RootOf(2), LastSlot: 101}
)

func helperBlock() slashing.BlockRequest {
	return slashing.BlockRequest{
		PublicKey: slashingtest.Key(0), GenesisValidatorsRoot: slashingtest.GVR, Slot: 100, SigningRoot: slashingtest.RootOf(7),
	}
}

func helperAttestation() slashing.AttestationRequest {
	return slashing.AttestationRequest{
		PublicKey: slashingtest.Key(0), GenesisValidatorsRoot: slashingtest.GVR, SourceEpoch: 4, TargetEpoch: 5,
		SigningRoot: slashingtest.RootOf(8),
	}
}

// TestHelperProcess is the helper's entry point; it does nothing in a normal test run.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv(envHelper)
	if mode == "" {
		return
	}
	path := os.Getenv(envPath)
	if mode == "open" {
		s, err := Open(path, Options{LockTimeout: 200 * time.Millisecond})
		switch {
		case err == nil:
			_ = s.Close()
			os.Exit(exitOpened)
		case errors.Is(err, ErrLocked):
			os.Exit(exitLocked)
		}
		fmt.Fprintln(os.Stderr, "helper open:", err)
		os.Exit(exitNotLocked)
	}

	ctx := context.Background()
	s, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	e := slashing.NewEngine(s)
	if err := e.RegisterValidators(ctx, [][]byte{slashingtest.Key(0)}); err != nil {
		t.Fatal(err)
	}
	id := slashing.KeyIDOf(slashingtest.Key(0))
	var ok bool
	switch mode {
	case "block":
		d, err := e.CheckAndRecordBlock(ctx, helperBlock())
		ok = err == nil && d.Allowed && !d.Repeat
	case "attestation":
		d, err := e.CheckAndRecordAttestation(ctx, helperAttestation())
		ok = err == nil && d.Allowed && !d.Repeat
	case "randao-first-use":
		ok, err = s.CompareAndSwapRandaoState(ctx, id, nil, frontierFirst)
		ok = ok && err == nil
	case "randao-new-layer":
		ok, err = s.CompareAndSwapRandaoState(ctx, id, &frontierFirst, frontierNext)
		ok = ok && err == nil
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
	if !ok {
		t.Fatalf("helper %s: the write was not committed", mode)
	}
	// The commit has returned; die before any response could be sent.
	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
	select {}
}

func runHelper(t *testing.T, mode, path string) *os.ProcessState {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(), envHelper+"="+mode, envPath+"="+path)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("helper %s: %v", mode, err)
	}
	t.Logf("helper %s: %v\n%s", mode, cmd.ProcessState, out)
	return cmd.ProcessState
}

func TestSecondProcessCannotOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "slashing-protection.db")
	s, err := Open(path, Options{})
	mustNil(t, err)
	if st := runHelper(t, "open", path); st.ExitCode() != exitLocked {
		t.Fatalf("second process exit code %d, want %d (ErrLocked)", st.ExitCode(), exitLocked)
	}
	mustNil(t, s.Close())
	if st := runHelper(t, "open", path); st.ExitCode() != exitOpened {
		t.Fatalf("after Close the second process got exit code %d, want %d (opened)", st.ExitCode(), exitOpened)
	}
}

// TestCrashBetweenCommitAndResponse kills a process right after its check-and-record (or RANDAO compare-and-set)
// has committed. The retry must be an idempotent repeat, and the file must hold exactly one record.
func TestCrashBetweenCommitAndResponse(t *testing.T) {
	ctx := context.Background()
	id := slashing.KeyIDOf(slashingtest.Key(0))
	tests := []struct {
		mode    string
		prepare func(t *testing.T, s *Store)
		check   func(t *testing.T, s *Store, e *slashing.Engine)
	}{
		{
			mode: "block",
			check: func(t *testing.T, s *Store, e *slashing.Engine) {
				if d, err := e.CheckAndRecordBlock(ctx, helperBlock()); err != nil || !d.Allowed || !d.Repeat {
					t.Errorf("retried block: %+v %v, want an allowed repeat", d, err)
				}
				if n := countRecords(t, s, id, bucketBlocks); n != 1 {
					t.Errorf("%d block records, want 1", n)
				}
			},
		},
		{
			mode: "attestation",
			check: func(t *testing.T, s *Store, e *slashing.Engine) {
				if d, err := e.CheckAndRecordAttestation(ctx, helperAttestation()); err != nil || !d.Allowed || !d.Repeat {
					t.Errorf("retried attestation: %+v %v, want an allowed repeat", d, err)
				}
				if n := countRecords(t, s, id, bucketAtts); n != 1 {
					t.Errorf("%d attestation records, want 1", n)
				}
			},
		},
		{
			mode: "randao-first-use",
			check: func(t *testing.T, s *Store, _ *slashing.Engine) {
				wantFrontier(t, s, frontierFirst)
				// The retried request now finds the frontier it created and is classified as a re-reveal, which
				// writes nothing; a blind retry of the same first-use swap must not write either.
				if swapped, err := s.CompareAndSwapRandaoState(ctx, id, nil, frontierFirst); err != nil || swapped {
					t.Errorf("retried first-use swap: %v %v, want no write", swapped, err)
				}
				wantFrontier(t, s, frontierFirst)
			},
		},
		{
			mode: "randao-new-layer",
			prepare: func(t *testing.T, s *Store) {
				mustNil(t, s.RegisterValidators(ctx, [][]byte{slashingtest.Key(0)}))
				swapped, err := s.CompareAndSwapRandaoState(ctx, id, nil, frontierFirst)
				if err != nil || !swapped {
					t.Fatalf("prepare frontier: %v %v", swapped, err)
				}
			},
			check: func(t *testing.T, s *Store, _ *slashing.Engine) {
				wantFrontier(t, s, frontierNext)
				if swapped, err := s.CompareAndSwapRandaoState(ctx, id, &frontierFirst, frontierNext); err != nil || swapped {
					t.Errorf("retried new-layer swap: %v %v, want no write", swapped, err)
				}
				wantFrontier(t, s, frontierNext)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "slashing-protection.db")
			if tc.prepare != nil {
				s, err := Open(path, Options{})
				mustNil(t, err)
				tc.prepare(t, s)
				mustNil(t, s.Close())
			}
			st := runHelper(t, tc.mode, path)
			if ws, ok := st.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
				t.Fatalf("helper did not die by SIGKILL after committing: %v", st)
			}
			s, err := Open(path, Options{})
			mustNil(t, err)
			t.Cleanup(func() { _ = s.Close() })
			e := slashing.NewEngine(s)
			mustNil(t, e.RegisterValidators(ctx, [][]byte{slashingtest.Key(0)}))
			tc.check(t, s, e)
		})
	}
}

func wantFrontier(t *testing.T, s *Store, want slashing.RandaoState) {
	t.Helper()
	got, ok, err := s.RandaoState(context.Background(), slashing.KeyIDOf(slashingtest.Key(0)))
	if err != nil || !ok || got != want {
		t.Fatalf("frontier %+v (present %v, %v), want %+v", got, ok, err, want)
	}
}

// countRecords counts the entries of one of a validator's history buckets.
func countRecords(t *testing.T, s *Store, id slashing.KeyID, bucket []byte) int {
	t.Helper()
	var n int
	mustNil(t, s.db.View(func(tx *bolt.Tx) error {
		b, err := validatorBucket(tx, id)
		if err != nil {
			return err
		}
		n = b.Bucket(bucket).Stats().KeyN
		return nil
	}))
	return n
}
