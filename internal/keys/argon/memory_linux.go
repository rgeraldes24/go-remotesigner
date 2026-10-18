// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package argon

import (
	"os"

	"golang.org/x/sys/unix"
)

func cgroupLimit() (int64, bool) {
	return cgroupLimitIn(os.DirFS("/"))
}

func totalRAM() (uint64, bool) {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil || info.Totalram == 0 {
		return 0, false
	}
	return uint64(info.Totalram) * uint64(info.Unit), true
}
