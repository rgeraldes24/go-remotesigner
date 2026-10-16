// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package acceptance

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
)

// coreLimit returns the soft and hard "Max core file size" of pid from
// /proc/<pid>/limits.
func coreLimit(t *testing.T, pid int) (soft, hard string) {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/limits", pid))
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "Max core file size"); ok {
			f := strings.Fields(rest)
			if len(f) < 2 {
				t.Fatalf("limits line %q", line)
			}
			return f[0], f[1]
		}
	}
	t.Fatal("no core file size in /proc/<pid>/limits")
	return "", ""
}

// procOwner returns the owner of /proc/<pid>/status. proc(5): the files of
// a process that is not dumpable are owned by root.
func procOwner(t *testing.T, pid int) uint32 {
	t.Helper()
	fi, err := os.Stat(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Uid
}

// On Linux the started binary is not dumpable and its core-file limit is
// 0, soft and hard (--disable-core-dumps, on by default); with
// --disable-core-dumps=false it keeps the limits it inherited.
func TestHygieneAfterStartupLinux(t *testing.T) {
	s := start(t, options{})
	s.waitReady()
	pid := s.cmd.Process.Pid
	if soft, hard := coreLimit(t, pid); soft != "0" || hard != "0" {
		t.Fatalf("RLIMIT_CORE %s/%s after startup, want 0/0", soft, hard)
	}
	if !strings.Contains(s.output.String(), "dumpable=false") || !strings.Contains(s.output.String(), "core-limit=0") {
		t.Fatalf("the startup log does not report PR_GET_DUMPABLE 0 and RLIMIT_CORE 0:\n%s", s.output.String())
	}
	uid := uint32(os.Getuid())
	if uid != 0 {
		if owner := procOwner(t, pid); owner != 0 {
			t.Fatalf("/proc/%d is owned by uid %d: the process is dumpable", pid, owner)
		}
	}

	// The control: without the flag the process stays dumpable.
	var before syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &before); err != nil {
		t.Fatal(err)
	}
	off := start(t, options{global: []string{"--disable-core-dumps=false"}})
	off.waitReady()
	if !strings.Contains(off.output.String(), "dumpable=true") {
		t.Fatalf("--disable-core-dumps=false: the log does not report a dumpable process:\n%s", off.output.String())
	}
	if uid != 0 {
		if owner := procOwner(t, off.cmd.Process.Pid); owner != uid {
			t.Fatalf("--disable-core-dumps=false: /proc owned by uid %d, want %d", owner, uid)
		}
	}
	if before.Max != 0 {
		if _, hard := coreLimit(t, off.cmd.Process.Pid); hard == "0" {
			t.Fatal("--disable-core-dumps=false still set the hard core-file limit to 0")
		}
	}
}
