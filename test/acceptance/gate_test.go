// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"
)

// gateBurst sends the B7 burst (32 attestations and 126 sync committee
// messages, each for its own key, slashing protection on) at once and
// returns the statuses, the reasons of the refusals and whether every 503
// carried Retry-After.
func gateBurst(t *testing.T, s *signer, reqs []burstRequest) (codes map[int]int, reasons map[string]int, retryAfter bool) {
	t.Helper()
	client := &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}
	tok := s.signToken()
	codes, reasons, retryAfter = map[int]int{}, map[string]int{}, true
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for _, r := range reqs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest(http.MethodPost, s.base+"/api/v1/consensus/sign/"+r.ident, bytes.NewReader(r.body))
			if err != nil {
				t.Error(err)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := client.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			mu.Lock()
			defer mu.Unlock()
			codes[resp.StatusCode]++
			if resp.StatusCode != http.StatusOK {
				var e struct{ Reason string }
				_ = json.Unmarshal(body, &e)
				reasons[e.Reason]++
				if resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get("Retry-After") == "" {
					retryAfter = false
				}
			}
		}()
	}
	wg.Wait()
	return codes, reasons, retryAfter
}

// TestSigningGate saturates the signing gate of the built binary
// (docs/contract.md section 13). With one slot and no queue, a burst of 158 sign requests that each
// commit a slashing record or sign gets 503 OVERLOADED with Retry-After for
// the requests that find the slot taken, and 200 for the rest; with the
// default queue of 512 the same burst is signed in full.
func TestSigningGate(t *testing.T) {
	keys := t.TempDir()
	ids := writeKeys(t, keys, b7Keys)

	s := start(t, options{keys: keys, global: []string{
		"--max-concurrent-signing-requests=1", "--max-queued-signing-requests=0"}})
	s.waitReady()
	codes, reasons, retryAfter := gateBurst(t, s, b7Requests(t, ids))
	t.Logf("one slot, no queue: statuses %v, reasons %v", codes, reasons)
	if codes[http.StatusServiceUnavailable] == 0 || codes[http.StatusOK] == 0 ||
		codes[http.StatusOK]+codes[http.StatusServiceUnavailable] != b7Keys {
		t.Errorf("statuses %v: want 200 and 503 only, some of each", codes)
	}
	if reasons["OVERLOADED"] != codes[http.StatusServiceUnavailable] || len(reasons) != 1 {
		t.Errorf("refusal reasons %v, want OVERLOADED only", reasons)
	}
	if !retryAfter {
		t.Error("a 503 OVERLOADED without Retry-After")
	}

	// A second signer, with a store of its own, on the default gate.
	s = start(t, options{keys: keys})
	s.waitReady()
	if codes, reasons, _ := gateBurst(t, s, b7Requests(t, ids)); codes[http.StatusOK] != b7Keys {
		t.Errorf("default gate: statuses %v, reasons %v, want %d × 200", codes, reasons, b7Keys)
	}
}
