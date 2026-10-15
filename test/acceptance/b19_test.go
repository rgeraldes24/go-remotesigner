// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// B19 (nightly): the idle-connection race. A Go client with the default
// transport (90 s IdleConnTimeout) POSTs at intervals just below the old
// Web3Signer idle timeout and just above the Go client's own; with the
// server's IdleTimeout of 120 s, no POST may hit a connection the server
// closed. Threshold: 0 errors over 1 h. Set REMOTESIGNER_B19_DURATION
// (for example 1h) to run it.
func TestB19IdleConnectionRace(t *testing.T) {
	d, err := time.ParseDuration(os.Getenv("REMOTESIGNER_B19_DURATION"))
	if err != nil || d <= 0 {
		t.Skip("set REMOTESIGNER_B19_DURATION to run the B19 idle-connection race")
	}
	s := start(t, options{})
	s.waitReady()
	admin := s.adminToken()
	deadline := time.Now().Add(d)

	var mu sync.Mutex
	var posts, failures int
	run := func(minGap, maxGap time.Duration) {
		client := &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}
		for {
			req, _ := http.NewRequest(http.MethodPost, s.base+"/reload", strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+admin)
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			mu.Lock()
			posts++
			if err != nil {
				failures++
				t.Errorf("POST after an idle gap: %v", err)
			} else {
				_ = resp.Body.Close()
			}
			mu.Unlock()
			gap := minGap + rand.N(maxGap-minGap)
			if time.Now().Add(gap).After(deadline) {
				return
			}
			time.Sleep(gap)
		}
	}
	var wg sync.WaitGroup
	for _, gap := range [][2]time.Duration{{25 * time.Second, 35 * time.Second}, {85 * time.Second, 95 * time.Second}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			run(gap[0], gap[1])
		}()
	}
	wg.Wait()
	t.Logf("B19: %d POSTs over %v, %d connection errors", posts, d, failures)
}
