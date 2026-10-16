// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package hygiene

import (
	"errors"
	"strings"
	"testing"
)

// On Linux, Apply makes the process non-dumpable with no core dumps;
// elsewhere it is a no-op. --mlock-all is not exercised here: it would lock
// this test process for the rest of the run, the race detector's shadow
// mappings included. The acceptance test TestMlockAllLinux runs it on the
// built binary.
func TestApply(t *testing.T) {
	if !Supported {
		if err := Apply(Config{DisableCoreDumps: true, MlockAll: true}); err != nil {
			t.Fatalf("Apply off Linux = %v, want a no-op", err)
		}
		if _, _, err := State(); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("State off Linux = %v", err)
		}
		t.Skip("process hygiene acts on Linux only")
	}
	if err := Apply(Config{}); err != nil {
		t.Fatal(err)
	}
	if err := Apply(Config{DisableCoreDumps: true}); err != nil {
		t.Fatal(err)
	}
	dumpable, core, err := State()
	if err != nil {
		t.Fatal(err)
	}
	if dumpable || core != 0 {
		t.Fatalf("PR_GET_DUMPABLE = %v, RLIMIT_CORE = %d after Apply; want 0 and 0", dumpable, core)
	}
}

// --mlock-all is accepted with CAP_IPC_LOCK or an unlimited RLIMIT_MEMLOCK
// only: any finite limit without the capability is refused, however large,
// because MCL_FUTURE counts every later allocation against it.
func TestCheckMlockAll(t *testing.T) {
	tests := []struct {
		name           string
		cap, unlimited bool
		limit          uint64
		ok             bool
	}{
		{"capability, finite limit", true, false, 8 << 20, true},
		{"capability, unlimited", true, true, ^uint64(0), true},
		{"unlimited", false, true, ^uint64(0), true},
		{"8 MiB", false, false, 8 << 20, false},
		{"above the startup size", false, false, 1310720 << 10, false},
		{"64 GiB", false, false, 64 << 30, false},
		{"zero", false, false, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkMlockAll(tt.cap, tt.unlimited, tt.limit)
			if (err == nil) != tt.ok {
				t.Fatalf("checkMlockAll = %v, want ok %v", err, tt.ok)
			}
			if err != nil && !strings.Contains(err.Error(), "--mlock-all needs CAP_IPC_LOCK or an unlimited RLIMIT_MEMLOCK") {
				t.Fatalf("the refusal does not name what the flag needs: %v", err)
			}
		})
	}
}
