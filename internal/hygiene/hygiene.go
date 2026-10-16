// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package hygiene hardens the process against leaking key material through
// core dumps, debuggers and swap (docs/operations/tls.md, "Process
// hygiene"). It acts on Linux only; on other platforms Apply changes
// nothing.
//
//   - DisableCoreDumps (--disable-core-dumps, on by default) makes the
//     process non-dumpable with prctl(PR_SET_DUMPABLE, 0), which also keeps
//     other processes of the same user from attaching to it or reading its
//     memory through /proc, and sets RLIMIT_CORE to 0, soft and hard.
//   - MlockAll (--mlock-all) locks current and future memory with
//     mlockall(MCL_CURRENT|MCL_FUTURE), so that keys are never swapped out.
//     It needs CAP_IPC_LOCK, or an RLIMIT_MEMLOCK above the process size.
package hygiene

import (
	"errors"
	"runtime"
)

// Config selects the controls.
type Config struct {
	DisableCoreDumps bool
	MlockAll         bool
}

// Supported reports whether this platform applies the controls (Linux).
const Supported = supported

// ErrUnsupported is returned by State off Linux.
var ErrUnsupported = errors.New("hygiene: not supported on " + runtime.GOOS)

// Apply applies the selected controls to the whole process. It fails when
// a selected control cannot be applied; off Linux it does nothing.
func Apply(cfg Config) error { return apply(cfg) }

// State reports whether the process is dumpable and its soft core-size
// limit, for tests and diagnostics; off Linux it returns ErrUnsupported.
func State() (dumpable bool, coreLimit uint64, err error) { return state() }
