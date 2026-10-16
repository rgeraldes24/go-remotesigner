// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package hygiene

import (
	"errors"
	"testing"
)

// On Linux, Apply makes the process non-dumpable with no core dumps;
// elsewhere it is a no-op. --mlock-all is not exercised here: locking the
// memory of a race-instrumented test binary needs CAP_IPC_LOCK.
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
