// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"strings"
	"testing"
)

// With slashing protection disabled (loopback only) the store's health check
// is DOWN, so /healthcheck never reports the signer healthy, while /upcheck
// and signing go on (DEVIATIONS.md X114).
func TestHealthcheckProtectionDisabled(t *testing.T) {
	s := start(t, options{consensus: []string{"--slashing-protection-enabled=false"}})
	s.waitReady()
	code, body, _ := s.do(request{path: "/healthcheck", token: s.signToken()})
	if code != 503 || !strings.Contains(body, `"status":"DOWN"`) ||
		!strings.Contains(body, `{"id":"slashing-protection-db-health-check","status":"DOWN"`) {
		t.Fatalf("healthcheck: %d %s", code, body)
	}
	if code, _, _ := s.do(request{path: "/upcheck"}); code != 200 {
		t.Fatalf("upcheck: %d", code)
	}
	if !strings.Contains(s.output.String(), "level=error") {
		t.Fatalf("no ERROR banner for disabled slashing protection:\n%s", s.output.String())
	}
}
