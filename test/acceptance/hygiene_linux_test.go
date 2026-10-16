// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package acceptance

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// procLimit returns the soft and hard values of the limit called name
// ("Max core file size") in /proc/<pid>/limits ("self" for this process).
func procLimit(t *testing.T, pid, name string) (soft, hard string) {
	t.Helper()
	data, err := os.ReadFile("/proc/" + pid + "/limits")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, name); ok {
			f := strings.Fields(rest)
			if len(f) < 2 {
				t.Fatalf("limits line %q", line)
			}
			return f[0], f[1]
		}
	}
	t.Fatalf("no %q in /proc/%s/limits", name, pid)
	return "", ""
}

// coreLimit returns the soft and hard "Max core file size" of pid.
func coreLimit(t *testing.T, pid int) (soft, hard string) {
	t.Helper()
	return procLimit(t, strconv.Itoa(pid), "Max core file size")
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

// procStatusField returns the value of a "<name>:" line of
// /proc/<pid>/status ("self" for this process).
func procStatusField(t *testing.T, pid, name string) string {
	t.Helper()
	data, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, name+":"); ok {
			return strings.TrimSpace(rest)
		}
	}
	t.Fatalf("no %s in /proc/%s/status", name, pid)
	return ""
}

// capIPCLock is CAP_IPC_LOCK's bit in the capability sets
// (linux/capability.h).
const capIPCLock = 14

// --mlock-all starts only when the lock can hold for the life of the
// process. With CAP_IPC_LOCK, or with an unlimited RLIMIT_MEMLOCK, the
// signer starts with locked pages (VmLck) and logs it. Under any finite
// limit without the capability, however large, the start is refused with
// exit code 1, naming both options: MCL_FUTURE counts every later
// allocation against the limit, so a process that started would die once
// its heap outgrew it.
func TestMlockAllLinux(t *testing.T) {
	limit, _ := procLimit(t, "self", "Max locked memory")
	capEff, err := strconv.ParseUint(procStatusField(t, "self", "CapEff"), 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	hasCap := capEff&(1<<capIPCLock) != 0
	canLock := hasCap || limit == "unlimited"
	t.Logf("CAP_IPC_LOCK %v, RLIMIT_MEMLOCK %s", hasCap, limit)

	s := launch(t, options{global: []string{"--mlock-all"}})
	ports := filepath.Join(s.data, "remotesigner.ports")
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case <-s.done:
			if canLock {
				t.Fatalf("--mlock-all with CAP_IPC_LOCK or no lock limit did not start: %v\n%s", s.waitErr, s.output.String())
			}
			const want = "--mlock-all needs CAP_IPC_LOCK or an unlimited RLIMIT_MEMLOCK"
			if code := s.exitCode(time.Second); code != 1 || !strings.Contains(s.output.String(), want) {
				t.Fatalf("refused --mlock-all: exit %d, want 1 and %q\n%s", code, want, s.output.String())
			}
			return
		default:
		}
		if _, err := os.Stat(ports); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("neither started nor refused\n%s", s.output.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !canLock {
		t.Fatalf("--mlock-all started without CAP_IPC_LOCK under a finite %s-byte lock limit\n%s", limit, s.output.String())
	}
	locked := strings.Fields(procStatusField(t, strconv.Itoa(s.cmd.Process.Pid), "VmLck"))
	if len(locked) != 2 || locked[0] == "0" || locked[1] != "kB" {
		t.Fatalf("VmLck %v after starting with --mlock-all, want locked pages", locked)
	}
	if !strings.Contains(s.output.String(), "memory-locked=true") {
		t.Fatalf("the startup log does not report locked memory:\n%s", s.output.String())
	}
}
