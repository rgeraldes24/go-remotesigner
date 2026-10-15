// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout []string
		wantStderr []string
	}{
		{
			name:       "long version flag",
			args:       []string{"--version"},
			wantCode:   exitOK,
			wantStdout: []string{binaryName + " version ", runtime.Version(), runtime.GOOS + "/" + runtime.GOARCH},
		},
		{
			name:       "short version flag",
			args:       []string{"-v"},
			wantCode:   exitOK,
			wantStdout: []string{binaryName + " version "},
		},
		{
			name:       "no arguments prints help",
			args:       nil,
			wantCode:   exitOK,
			wantStdout: []string{"USAGE:", binaryName},
		},
		{
			name:       "unknown flag is a usage error",
			args:       []string{"--no-such-flag"},
			wantCode:   exitUsage,
			wantStderr: []string{"usage error", "no-such-flag"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(append([]string{binaryName}, tt.args...), &stdout, &stderr)
			if code != tt.wantCode {
				t.Fatalf("exit code = %d, want %d (stdout %q, stderr %q)", code, tt.wantCode, stdout.String(), stderr.String())
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout %q does not contain %q", stdout.String(), want)
				}
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr %q does not contain %q", stderr.String(), want)
				}
			}
		})
	}
}

func TestVersionStringUsesLinkerValues(t *testing.T) {
	oldVersion, oldCommit := version, commit
	t.Cleanup(func() { version, commit = oldVersion, oldCommit })

	version, commit = "v1.2.3", "abc123"
	got := versionString()
	if !strings.HasPrefix(got, "v1.2.3 (commit abc123, ") {
		t.Fatalf("versionString() = %q, want the linker-provided version and commit", got)
	}
}
