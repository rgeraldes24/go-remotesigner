// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// metricsPort reads metrics-port from the ports file, or "".
func (s *signer) metricsPort() string {
	s.t.Helper()
	data, err := os.ReadFile(filepath.Join(s.data, "remotesigner.ports"))
	if err != nil {
		s.t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if p, ok := strings.CutPrefix(line, "metrics-port="); ok {
			return p
		}
	}
	return ""
}

func scrape(t *testing.T, port, host string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+port+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// freePort returns a TCP port nothing listens on now.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// writeInteropKey picks the golden minimal-preset selection-proof case,
// writes its interop key as a file-raw key and returns the case.
func writeInteropKey(t *testing.T, dir string) vectors.SignCase {
	t.Helper()
	var c vectors.SignCase
	for _, sc := range vectors.Signing(t) {
		if sc.Preset == "minimal" && sc.Type == "AGGREGATION_SLOT" && sc.Name == "typical" {
			c = sc
		}
	}
	k := vectors.Keys(t)[c.KeyIndex]
	content := "type: file-raw\nkeyType: ML_DSA_87\nprivateKey: \"" + k.Seed + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, "interop.yaml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

// S5b acceptance: with --metrics-enabled the metrics listener serves every
// contract counter with its documented label values behind its host
// allowlist; a signed request moves the counters.
func TestMetricsListener(t *testing.T) {
	keys := t.TempDir()
	c := writeInteropKey(t, keys)
	s := start(t, options{keys: keys, global: []string{"--metrics-enabled", "--metrics-port=0"}})
	s.waitReady()
	port := s.metricsPort()
	if port == "" {
		t.Fatalf("no metrics-port in the ports file\n%s", s.output.String())
	}

	code, body, _ := s.do(request{method: "POST", path: "/api/v1/consensus/sign/" + c.Pubkey, token: s.signToken(),
		contentType: "application/json", body: bytes.NewReader(c.RequestJSON)})
	if code != 200 || body != `{"signature":"`+c.DeterministicSignature+`"}` {
		t.Fatalf("sign: %d %.120s", code, body)
	}

	code, text := scrape(t, port, "")
	if code != 200 {
		t.Fatalf("scrape: %d", code)
	}
	var want []string
	for _, r := range []string{"first_use", "new_layer", "gap_advanced", "re_reveal", "refused", "error"} {
		want = append(want, fmt.Sprintf(`consensus_randao_reveals_total{result=%q} 0`, r))
	}
	for _, r := range []string{"slashing_double_proposal", "slashing_double_vote", "slashing_surrounding_vote",
		"slashing_surrounded_vote", "slashing_below_watermark", "slashing_above_high_watermark", "validator_disabled"} {
		want = append(want, fmt.Sprintf(`consensus_slashingprotection_prevented_signings_total{reason=%q} 0`, r))
	}
	for _, ty := range []string{"BLOCK_V2", "ATTESTATION", "AGGREGATION_SLOT", "AGGREGATE_AND_PROOF", "VOLUNTARY_EXIT",
		"SYNC_COMMITTEE_MESSAGE", "SYNC_COMMITTEE_SELECTION_PROOF", "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF",
		"VALIDATOR_REGISTRATION"} {
		for _, r := range []string{"ok", "refused", "bad_request", "error"} {
			n := 0
			if ty == "AGGREGATION_SLOT" && r == "ok" {
				n = 1
			}
			want = append(want, fmt.Sprintf(`signing_requests_total{result=%q,type=%q} %d`, r, ty, n))
		}
	}
	want = append(want,
		"consensus_randao_new_layer_rate_limited_total 0",
		"signing_verify_failures_total 0",
		`http_request_duration_seconds_count{code="200",route="/api/v1/consensus/sign/{identifier}"} 1`,
		"http_connections_open ",
		"http_connections_limit_reached_total 0",
	)
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Errorf("scrape lacks %s", w)
		}
	}
	if code, body := scrape(t, port, "evil.example:"+port); code != 403 || reasonOf(t, body) != "HOST_NOT_ALLOWED" {
		t.Errorf("foreign Host: %d %s", code, body)
	}
}

// Without --metrics-enabled nothing listens on the metrics port.
func TestMetricsListenerOffByDefault(t *testing.T) {
	port := freePort(t)
	s := start(t, options{global: []string{"--metrics-port=" + strconv.Itoa(port)}})
	s.waitReady()
	if p := s.metricsPort(); p != "" {
		t.Fatalf("ports file names metrics-port=%s", p)
	}
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
	if err == nil {
		_ = c.Close()
		t.Fatalf("something listens on the metrics port %d", port)
	}
}
