// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// The signing gate's flags: 32 in flight and 512 queued by default, from
// the command line, the environment or the config file, and a usage error
// for a value the gate cannot take.
func TestSigningGateFlags(t *testing.T) {
	cfg, code, stderr := capture(t, "consensus", "--network=e2e")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if cfg.Signing.MaxConcurrent != 32 || cfg.Signing.MaxQueued != 512 {
		t.Fatalf("signing gate defaults %+v, want 32 and 512", cfg.Signing)
	}

	cfg, code, stderr = capture(t, "--max-concurrent-signing-requests=4", "--max-queued-signing-requests=0",
		"consensus", "--network=e2e")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if cfg.Signing.MaxConcurrent != 4 || cfg.Signing.MaxQueued != 0 {
		t.Fatalf("signing gate %+v, want 4 and 0", cfg.Signing)
	}
	t.Setenv("REMOTESIGNER_MAX_QUEUED_SIGNING_REQUESTS", "7")
	if cfg, code, stderr = capture(t, "consensus", "--network=e2e"); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if cfg.Signing.MaxQueued != 7 {
		t.Fatalf("queue %d from the environment, want 7", cfg.Signing.MaxQueued)
	}

	for _, arg := range []string{"--max-concurrent-signing-requests=0", "--max-queued-signing-requests=-1"} {
		if _, code, stderr := capture(t, arg, "consensus", "--network=e2e"); code != exitUsage ||
			!strings.Contains(stderr, strings.TrimPrefix(strings.SplitN(arg, "=", 2)[0], "--")) {
			t.Errorf("%s: exit %d %q, want a usage error naming the flag", arg, code, stderr)
		}
	}
}
