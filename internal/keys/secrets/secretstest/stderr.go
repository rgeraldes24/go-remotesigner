// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package secretstest

import (
	"io"
	"os"
	"testing"
)

// CaptureStderr redirects os.Stderr to a pipe until the returned function
// is called, which returns what was written, or until t ends. The SDKs
// must write nothing there: the signer's log is its only output.
func CaptureStderr(t testing.TB) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	restored := false
	restore := func() string {
		if restored {
			return ""
		}
		restored = true
		os.Stderr = orig
		_ = w.Close()
		out := <-done
		_ = r.Close()
		return out
	}
	t.Cleanup(func() { restore() })
	return restore
}
