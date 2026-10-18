// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package argon

import (
	"bytes"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

// unlimitedV1 is the smallest cgroup v1 memory.limit_in_bytes that means no
// limit: the kernel reports "unlimited" as a page-aligned value near 2^63.
const unlimitedV1 = 1 << 62

// cgroupLimitIn reads the memory limit of the process's cgroup from fsys,
// a view of / (sys/fs/cgroup and proc/self/cgroup). It tries cgroup v2
// (memory.max of the process's own group, then of the root the container
// sees) and then cgroup v1 (memory.limit_in_bytes). "max", an unlimited v1
// value and anything unreadable count as no limit.
func cgroupLimitIn(fsys fs.FS) (int64, bool) {
	var candidates []string
	if self, err := fs.ReadFile(fsys, "proc/self/cgroup"); err == nil {
		for line := range strings.SplitSeq(string(self), "\n") {
			if rel, ok := strings.CutPrefix(line, "0::"); ok && rel != "/" && rel != "" {
				candidates = append(candidates, path.Join("sys/fs/cgroup", path.Clean("/"+rel), "memory.max"))
			}
		}
	}
	candidates = append(candidates, "sys/fs/cgroup/memory.max")
	for _, p := range candidates {
		if v, ok := readLimit(fsys, p, false); ok {
			return v, true
		}
	}
	return readLimit(fsys, "sys/fs/cgroup/memory/memory.limit_in_bytes", true)
}

func readLimit(fsys fs.FS, name string, v1 bool) (int64, bool) {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return 0, false
	}
	s := string(bytes.TrimSpace(b))
	if s == "max" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 || v1 && v >= unlimitedV1 {
		return 0, false
	}
	return v, true
}
