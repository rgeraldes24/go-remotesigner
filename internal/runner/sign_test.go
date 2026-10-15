// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// writeInteropKeys writes the golden-vector interop keys as file-raw
// key-config files.
func writeInteropKeys(t *testing.T, dir string) {
	t.Helper()
	for _, k := range vectors.Keys(t) {
		content := "type: file-raw\nkeyType: ML_DSA_87\nprivateKey: \"" + k.Seed + "\"\n"
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("interop-%d.yaml", k.Index)), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func goldenCase(t *testing.T, preset string, typ signingroot.ArtifactType, name string) vectors.SignCase {
	t.Helper()
	for _, c := range vectors.Signing(t) {
		if c.Preset == preset && c.Type == string(typ) && c.Name == name {
			return c
		}
	}
	t.Fatalf("no golden case %s/%s/%s", preset, typ, name)
	return vectors.SignCase{}
}

// post sends a JSON body to a path of the API.
func (r *running) post(t *testing.T, path, token string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, r.base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// scrape reads the metrics listener with a Host header.
func (r *running) scrape(t *testing.T, host string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, r.metrics+"/metrics", nil)
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

func signPath(c vectors.SignCase) string {
	return "/api/v1/consensus/sign/" + c.Pubkey
}

// The walking skeleton signs: the first request pins the file network's
// GVR, a selection proof is qrysm's deterministic signature, the store
// refuses a double vote, and the metrics listener reports all of it with
// the contract's label values.
func TestRunSignAndMetrics(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Metrics = config.Metrics{Enabled: true, Host: "127.0.0.1", HostAllowlist: []string{"localhost", "127.0.0.1"}}
	writeInteropKeys(t, cfg.KeyConfigPath)
	r := start(t, cfg)
	r.waitReady(t)
	if r.metrics == "" {
		t.Fatal("no metrics-port in the ports file")
	}

	sel := goldenCase(t, "minimal", signingroot.AggregationSlot, "typical")
	code, body := r.post(t, signPath(sel), r.sign, sel.RequestJSON)
	if code != 200 || string(body) != `{"signature":"`+sel.DeterministicSignature+`"}` {
		t.Fatalf("selection proof: %d %.120s", code, body)
	}
	conforms(t, "SignatureResponse", body)

	att := goldenCase(t, "minimal", signingroot.Attestation, "typical")
	if code, body := r.post(t, signPath(att), r.sign, att.RequestJSON); code != 200 {
		t.Fatalf("attestation: %d %s", code, body)
	}
	var v map[string]any
	if err := json.Unmarshal(att.RequestJSON, &v); err != nil {
		t.Fatal(err)
	}
	delete(v, "signing_root")
	v["attestation"].(map[string]any)["beacon_block_root"] = "0x" + strings.Repeat("ee", 32)
	double, _ := json.Marshal(v)
	code, body = r.post(t, signPath(att), r.sign, double)
	if code != 412 || !strings.Contains(string(body), `"reason":"SLASHING_DOUBLE_VOTE"`) {
		t.Fatalf("double vote: %d %s", code, body)
	}
	conforms(t, "ErrorResponse", body)

	code, text := r.scrape(t, "")
	if code != 200 {
		t.Fatalf("scrape: %d", code)
	}
	for _, want := range []string{
		`signing_requests_total{result="ok",type="AGGREGATION_SLOT"} 1`,
		`signing_requests_total{result="ok",type="ATTESTATION"} 1`,
		`signing_requests_total{result="refused",type="ATTESTATION"} 1`,
		`signing_requests_total{result="bad_request",type="VOLUNTARY_EXIT"} 0`,
		`signing_requests_total{result="error",type="VALIDATOR_REGISTRATION"} 0`,
		`consensus_slashingprotection_prevented_signings_total{reason="slashing_double_vote"} 1`,
		`consensus_slashingprotection_prevented_signings_total{reason="validator_disabled"} 0`,
		`consensus_slashingprotection_permitted_signings_total 1`,
		`signing_verify_failures_total 0`,
		`signing_keys_quarantined 0`,
		`signing_signers_loaded_count 8`,
		`consensus_randao_reveals_total{result="first_use"} 0`,
		`consensus_randao_reveals_total{result="gap_advanced"} 0`,
		`consensus_randao_new_layer_rate_limited_total 0`,
		`http_request_duration_seconds_count{code="200",route="/api/v1/consensus/sign/{identifier}"} 2`,
		`http_request_duration_seconds_count{code="412",route="/api/v1/consensus/sign/{identifier}"} 1`,
		`http_connections_open `,
		`http_connections_limit_reached_total 0`,
		`http_requests_in_flight 0`,
		`process_release{version=""} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("scrape lacks %s", want)
		}
	}
	if strings.Contains(text, sel.Pubkey[:42]) {
		t.Error("a metric carries a public key")
	}
	if code, _ := r.scrape(t, "evil.example"); code != 403 {
		t.Errorf("foreign Host on the metrics listener: %d", code)
	}
}

// G4 S7: a 1.19 MB contribution (128 signatures, mainnet preset) passes the
// 2 MiB body limit, and 2 MiB + 1 is 413.
func TestRunLargeContribution(t *testing.T) {
	c := goldenCase(t, "mainnet", signingroot.SyncCommitteeContributionAndProof, "signatures_128")
	if len(c.RequestJSON) < 1_190_000 {
		t.Fatalf("the contribution is %d bytes, want about 1.19 MB", len(c.RequestJSON))
	}
	cfg := baseConfig(t)
	gvr := vectors.Hex32(t, c.Network.GVR)
	cfg.Consensus.Network.Network = c.Network.ConfigName
	cfg.Consensus.Network.GenesisValidatorsRoot = &gvr
	writeInteropKeys(t, cfg.KeyConfigPath)
	r := start(t, cfg)
	r.waitReady(t)

	if code, body := r.post(t, signPath(c), r.sign, c.RequestJSON); code != 200 {
		t.Fatalf("1.19 MB contribution: %d %s", code, body)
	}
	tooLarge := append(bytes.Repeat([]byte(" "), 2<<20), '{')
	code, body := r.post(t, signPath(c), r.sign, tooLarge)
	if code != 413 || !strings.Contains(string(body), `"reason":"BODY_TOO_LARGE"`) {
		t.Fatalf("2 MiB + 1: %d %s", code, body)
	}
}
