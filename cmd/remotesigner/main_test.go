// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"runtime"
	"runtime/debug"
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
			name:       "help prints help",
			args:       []string{"help"},
			wantCode:   exitOK,
			wantStdout: []string{"USAGE:", binaryName},
		},
		{
			name:       "long help flag",
			args:       []string{"--help"},
			wantCode:   exitOK,
			wantStdout: []string{"USAGE:"},
		},
		{
			name:       "unknown command is a usage error",
			args:       []string{"eth1"},
			wantCode:   exitUsage,
			wantStderr: []string{"usage error", `unknown command "eth1"`},
		},
		{
			name:       "extra argument after help is a usage error",
			args:       []string{"help", "foo"},
			wantCode:   exitUsage,
			wantStderr: []string{"usage error", "help takes no arguments"},
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
			code := runWith(append([]string{binaryName}, tt.args...), &stdout, &stderr, noRun)
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

// Without link-time values the version comes from the build info: the
// module version `go install …@v1.0.0` records, without its v, as the
// release binaries and make build report it.
func TestReleaseFromBuildInfo(t *testing.T) {
	withRev := func(v string) *debug.BuildInfo {
		return &debug.BuildInfo{Main: debug.Module{Version: v},
			Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abc123"}}}
	}
	for _, tt := range []struct {
		name         string
		v, c         string
		info         *debug.BuildInfo
		wantV, wantC string
	}{
		{"go install of a tag", "", "", withRev("v1.0.0"), "1.0.0", "abc123"},
		{"go install of a pre-release", "", "", withRev("v1.0.0-rc.1"), "1.0.0-rc.1", "abc123"},
		{"go install of a commit", "", "", withRev("v0.0.0-20261020120000-abcdef123456"),
			"0.0.0-20261020120000-abcdef123456", "abc123"},
		{"go build in the checkout", "", "", withRev("(devel)"), "dev", "abc123"},
		{"link-time values win", "1.0.0", "def456", withRev("v9.9.9"), "1.0.0", "def456"},
		{"no build info", "", "", nil, "dev", "unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if v, c := releaseFrom(tt.v, tt.c, tt.info); v != tt.wantV || c != tt.wantC {
				t.Errorf("releaseFrom = %q, %q; want %q, %q", v, c, tt.wantV, tt.wantC)
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
