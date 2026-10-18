// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package argon

import "golang.org/x/sys/unix"

func cgroupLimit() (int64, bool) { return 0, false }

func totalRAM() (uint64, bool) {
	ram, err := unix.SysctlUint64("hw.memsize")
	return ram, err == nil && ram > 0
}
