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
//     It needs CAP_IPC_LOCK or an unlimited RLIMIT_MEMLOCK, and refuses to
//     run under a finite limit without the capability (checkMlockAll).
package hygiene

import (
	"errors"
	"fmt"
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

// checkMlockAll decides whether --mlock-all can hold for the life of the
// process. MCL_FUTURE locks every later mapping too, and without
// CAP_IPC_LOCK each one counts against RLIMIT_MEMLOCK. A finite limit that
// covers the startup size therefore runs out once the Go heap grows (a
// burst of requests, a keystore reload), and the runtime then aborts with
// "out of memory": the start must be refused instead. Only CAP_IPC_LOCK,
// which lifts the limit, or an unlimited soft limit is safe. (In a user
// namespace other than the initial one, as in rootless containers, the
// kernel does not let CAP_IPC_LOCK lift the limit; use an unlimited limit
// there.)
func checkMlockAll(capIPCLock, unlimited bool, limit uint64) error {
	if capIPCLock || unlimited {
		return nil
	}
	return fmt.Errorf("hygiene: --mlock-all needs CAP_IPC_LOCK or an unlimited RLIMIT_MEMLOCK, and the process has "+
		"neither (the limit is %d bytes): under a finite limit every later allocation is locked too, and the process "+
		"would die once its memory outgrew the limit; grant CAP_IPC_LOCK (docker run --cap-add IPC_LOCK) or set the "+
		"limit to unlimited (--ulimit memlock=-1, LimitMEMLOCK=infinity)", limit)
}
