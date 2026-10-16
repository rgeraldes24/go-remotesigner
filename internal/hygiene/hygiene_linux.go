// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hygiene

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
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
		if err := mlockAllPossible(); err != nil {
			return err
		}
		if err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE); err != nil {
			return fmt.Errorf("hygiene: mlockall: %w", err)
		}
	}
	return nil
}

// mlockAllPossible reads the effective CAP_IPC_LOCK and the soft
// RLIMIT_MEMLOCK, and applies checkMlockAll.
func mlockAllPossible() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData // version 3 takes two 32-bit words per set
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("hygiene: --mlock-all: capget: %w", err)
	}
	hasCap := data[unix.CAP_IPC_LOCK/32].Effective&(1<<(unix.CAP_IPC_LOCK%32)) != 0
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		return fmt.Errorf("hygiene: --mlock-all: getrlimit(RLIMIT_MEMLOCK): %w", err)
	}
	return checkMlockAll(hasCap, lim.Cur == unix.RLIM_INFINITY, lim.Cur)
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
