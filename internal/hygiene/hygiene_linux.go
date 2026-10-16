// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hygiene

import (
	"fmt"
	"syscall"
)

const supported = true

func apply(cfg Config) error {
	if cfg.DisableCoreDumps {
		if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); errno != 0 {
			return fmt.Errorf("hygiene: prctl(PR_SET_DUMPABLE, 0): %w", errno)
		}
		if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
			return fmt.Errorf("hygiene: setrlimit(RLIMIT_CORE, 0): %w", err)
		}
	}
	if cfg.MlockAll {
		if err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE); err != nil {
			return fmt.Errorf("hygiene: mlockall: %w (--mlock-all needs CAP_IPC_LOCK, or an RLIMIT_MEMLOCK above the process size)", err)
		}
	}
	return nil
}

func state() (bool, uint64, error) {
	r, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
	if errno != 0 {
		return false, 0, fmt.Errorf("hygiene: prctl(PR_GET_DUMPABLE): %w", errno)
	}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &lim); err != nil {
		return false, 0, fmt.Errorf("hygiene: getrlimit(RLIMIT_CORE): %w", err)
	}
	return r != 0, lim.Cur, nil
}
