// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// The end-to-end benchmarks, against the built binary with
// a Go client on the default transport (docs/benchmarks.md):
//
//   - B7, the t = 20 s burst: 32 ATTESTATION and 126 SYNC_COMMITTEE_MESSAGE
//     requests at once, each for its own key (so that the response cache
//     answers none of them), slashing protection on. Last response ≤ 1 s,
//     p99 ≤ 500 ms, no errors.
//   - B8, the t = 40 s burst: 16 concurrent 1.2 MB contributions. Each
//     ≤ 250 ms; RSS grows by ≤ 128 MiB.
//   - B9, RANDAO: four concurrent first reveals at L = 2^20 (p99 ≤ 0.5 s),
//     an unknown commitment (≤ 0.6 s, and answered from the negative cache
//     on retry), and the B7 burst running while they do (p99 still
//     ≤ 500 ms).
//
// Timing thresholds depend on the machine, so they run only with
// REMOTESIGNER_BENCH=1 (make bench-e2e).
func benchEnabled(t *testing.T) {
	if os.Getenv("REMOTESIGNER_BENCH") == "" {
		t.Skip("set REMOTESIGNER_BENCH=1 to run the end-to-end benchmarks B7-B9")
	}
}

// timedPost posts body and returns the status and the client-side latency.
func timedPost(client *http.Client, url, token string, body []byte) (int, time.Duration, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, time.Since(start), nil
}

// percentile returns the p-th percentile (0 < p ≤ 1) of ds.
func percentile(ds []time.Duration, p float64) time.Duration {
	s := slices.Clone(ds)
	slices.Sort(s)
	i := int(float64(len(s))*p+0.999999) - 1
	return s[max(0, min(i, len(s)-1))]
}

type burstRequest struct {
	ident string
	body  []byte
}

// b7Keys is the number of keys the B7 burst needs: one per request.
const b7Keys = 32 + 126

// b7Requests builds the B7 burst over ids: 32 attestations, so that
// slashing protection records each, and 126 sync committee messages. With
// b7Keys ids every request is for its own key, so each one is signed: the
// response cache would answer a repeat of a key and root.
func b7Requests(t *testing.T, ids []string) []burstRequest {
	t.Helper()
	var att, msg []byte
	for _, c := range vectors.Signing(t) {
		if c.Preset != "minimal" || c.Name != "typical" {
			continue
		}
		switch c.Type {
		case "ATTESTATION":
			att = c.RequestJSON
		case "SYNC_COMMITTEE_MESSAGE":
			msg = c.RequestJSON
		}
	}
	if att == nil || msg == nil {
		t.Fatal("no typical attestation or sync committee message")
	}
	var out []burstRequest
	for i := range 32 {
		out = append(out, burstRequest{ids[i%len(ids)], att})
	}
	for i := range 126 {
		out = append(out, burstRequest{ids[(32+i)%len(ids)], msg})
	}
	return out
}

// burst sends every request at once over plaintext HTTP and returns the
// latencies; any non-200 answer or transport error fails the test.
func burst(t *testing.T, s *signer, reqs []burstRequest) (lat []time.Duration, wall time.Duration) {
	t.Helper()
	return burstWith(t, &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}, s.base, s.signToken(), reqs)
}

// burstWith sends every request at once with client to base.
func burstWith(t *testing.T, client *http.Client, base, tok string, reqs []burstRequest) (lat []time.Duration, wall time.Duration) {
	t.Helper()
	lat = make([]time.Duration, len(reqs))
	var wg sync.WaitGroup
	start := time.Now()
	for i, r := range reqs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, d, err := timedPost(client, base+"/api/v1/consensus/sign/"+r.ident, tok, r.body)
			if err != nil || code != 200 {
				t.Errorf("request %d: %d %v", i, code, err)
			}
			lat[i] = d
		}()
	}
	wg.Wait()
	return lat, time.Since(start)
}

func TestB7AttestationBurst(t *testing.T) {
	benchEnabled(t)
	keys := t.TempDir()
	ids := writeKeys(t, keys, b7Keys)
	s := start(t, options{keys: keys})
	s.waitReady()
	lat, wall := burst(t, s, b7Requests(t, ids))
	p99 := percentile(lat, 0.99)
	t.Logf("B7: %d requests, last response after %v, p50 %v, p99 %v", len(lat), wall, percentile(lat, 0.5), p99)
	if wall > time.Second || p99 > 500*time.Millisecond {
		t.Errorf("B7 missed: last %v (≤ 1 s), p99 %v (≤ 500 ms)", wall, p99)
	}
}

// rssKiB returns the resident set size of pid.
func rssKiB(t *testing.T, pid int) int {
	t.Helper()
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestB8ContributionBurst(t *testing.T) {
	benchEnabled(t)
	var c vectors.SignCase
	for _, sc := range vectors.Signing(t) {
		if sc.Preset == "mainnet" && sc.Type == "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF" && sc.Name == "signatures_128" {
			c = sc
		}
	}
	keys := t.TempDir()
	writeInteropKeys(t, keys)
	s := start(t, options{keys: keys, noNetwork: true, consensus: []string{"--network=" + c.Network.ConfigName,
		"--network-genesis-validators-root=" + c.Network.GVR, "--network-genesis-time=" + strconv.Itoa(harnessGenesis)}})
	s.waitReady()
	before := rssKiB(t, s.cmd.Process.Pid)
	reqs := make([]burstRequest, 16)
	for i := range reqs {
		reqs[i] = burstRequest{c.Pubkey, c.RequestJSON}
	}
	lat, wall := burst(t, s, reqs)
	after := rssKiB(t, s.cmd.Process.Pid)
	worst := percentile(lat, 1)
	t.Logf("B8: 16 × %d B, all done after %v, slowest %v, RSS %d → %d KiB (+%d)", len(c.RequestJSON), wall, worst,
		before, after, after-before)
	if worst > 250*time.Millisecond || after-before > 128<<10 {
		t.Errorf("B8 missed: slowest %v (≤ 250 ms), RSS +%d KiB (≤ 128 MiB)", worst, after-before)
	}
}

func TestB9RandaoReveal(t *testing.T) {
	benchEnabled(t)
	keysDir := t.TempDir()
	keys := writeInteropKeys(t, keysDir)
	extra := writeKeys(t, keysDir, b7Keys)
	s := start(t, options{keys: keysDir})
	s.waitReady()
	var forkInfo string
	for _, c := range vectors.Signing(t) {
		if c.Preset == "minimal" {
			forkInfo = `{"fork":{"previous_version":"` + c.Network.GenesisForkVersion + `","current_version":"` +
				c.Network.GenesisForkVersion + `","epoch":"0"},"genesis_validators_root":"` + c.Network.GVR + `"}`
			break
		}
	}
	client := &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}
	tok := s.signToken()
	reveal := func(pubkey, commitment string) (int, time.Duration) {
		body := `{"slot":"` + strconv.FormatUint(currentSlot(), 10) + `","randao_commitment":"` + commitment +
			`","fork_info":` + forkInfo + `}`
		code, d, err := timedPost(client, s.base+"/api/v1/consensus/randao_reveal/"+pubkey, tok, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		return code, d
	}

	// Four concurrent first reveals at L = 2^20, with the B7 burst alongside.
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		lats []time.Duration
	)
	for _, k := range keys[:4] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, d := reveal(k.Pubkey, k.RandaoCommitment)
			if code != 200 {
				t.Errorf("first reveal of key %d: %d", k.Index, code)
			}
			mu.Lock()
			lats = append(lats, d)
			mu.Unlock()
		}()
	}
	signLat, _ := burst(t, s, b7Requests(t, extra))
	wg.Wait()
	p99 := percentile(lats, 0.99)
	signP99 := percentile(signLat, 0.99)

	code, unknown := reveal(keys[4].Pubkey, keys[5].RandaoCommitment)
	if code != 422 {
		t.Fatalf("unknown commitment: %d", code)
	}
	code, cached := reveal(keys[4].Pubkey, keys[5].RandaoCommitment)
	if code != 422 {
		t.Fatalf("unknown commitment again: %d (the negative cache must answer before the scan budget)", code)
	}
	t.Logf("B9: 4 concurrent first reveals p99 %v (%v); unknown commitment %v, retry %v; B7 signing p99 alongside %v",
		p99, lats, unknown, cached, signP99)
	if p99 > 500*time.Millisecond || unknown > 600*time.Millisecond || cached > 50*time.Millisecond ||
		signP99 > 500*time.Millisecond {
		t.Errorf("B9 missed: reveal p99 %v (≤ 0.5 s), unknown %v (≤ 0.6 s), retry %v (cached), signing p99 %v (≤ 500 ms)",
			p99, unknown, cached, signP99)
	}
}
