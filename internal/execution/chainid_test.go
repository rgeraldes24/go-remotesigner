// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"sync"
	"testing"
	"time"
)

// The chain-ID check: unchecked until the node answers, then matches or
// differs with the node's qrl_chainId; a check the node does not answer
// keeps the last verdict; once the node has answered, run checks at once
// and then at each interval.
func TestChainMonitor(t *testing.T) {
	g, nd := newFakeGQRL(t)
	f := newFixtureWith(t, 0, defaultAllow, downstreamOf(t, nd.Server), nd)
	m := f.txs.chain
	if m.verdict.Load() != chainUnchecked || m.refusal() != nil {
		t.Fatal("refuses before any check")
	}
	m.check(t.Context())
	if m.verdict.Load() != chainMatches || m.refusal() != nil {
		t.Fatalf("verdict %d", m.verdict.Load())
	}
	g.set(func(g *fakeGQRL) { g.chainID = big.NewInt(7) })
	m.check(t.Context())
	if r := m.refusal(); r == nil || r.reason != "the downstream node's chain ID is 7, not --chain-id 1337" {
		t.Fatalf("refusal %v", r)
	}
	// The node stops answering: the verdict stands.
	nd.setHandler(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	m.check(t.Context())
	if m.verdict.Load() != chainDiffers {
		t.Fatal("an unanswered check changed the verdict")
	}
	// A result that is not a quantity is no answer either.
	nd.setHandler(func(w http.ResponseWriter, r *http.Request) {
		var c fakeCall
		_ = json.NewDecoder(r.Body).Decode(&c)
		_, _ = w.Write(encodeResult(c.ID, "one thousand", nil))
	})
	m.check(t.Context())
	if m.verdict.Load() != chainDiffers {
		t.Fatal("a non-quantity changed the verdict")
	}
	g.set(func(g *fakeGQRL) { g.chainID = big.NewInt(testChainID) })
	nd.setHandler(g.serve)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); m.run(ctx, 10*time.Millisecond, time.Hour) }()
	deadline := time.Now().Add(5 * time.Second)
	for m.verdict.Load() != chainMatches && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	for len(g.callsOf(MethodChainID)) < 4 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if m.verdict.Load() != chainMatches || len(g.callsOf(MethodChainID)) < 4 {
		t.Fatalf("verdict %d after %d checks", m.verdict.Load(), len(g.callsOf(MethodChainID)))
	}
}

// Until the node first answers, run asks again every retry, not every
// interval: a node that is down at startup is compared with --chain-id as
// soon as it is up. After the answer, the interval applies. The signer
// runs it with a 15-second retry and the 10-minute interval of DESIGN
// §4.2.
func TestChainMonitorRetriesUntilAnswered(t *testing.T) {
	if ChainCheckInterval != 10*time.Minute || ChainRetryInterval != 15*time.Second {
		t.Fatalf("intervals %v and %v, want 10m and 15s", ChainCheckInterval, ChainRetryInterval)
	}
	g, nd := newFakeGQRL(t)
	f := newFixtureWith(t, 0, defaultAllow, downstreamOf(t, nd.Server), nd)
	m := f.txs.chain
	var mu sync.Mutex
	down := 0
	nd.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		down++
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	downCalls := func() int {
		mu.Lock()
		defer mu.Unlock()
		return down
	}
	g.set(func(g *fakeGQRL) { g.chainID = big.NewInt(7) })
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); m.run(ctx, time.Hour, 10*time.Millisecond) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(10 * time.Second)
	for downCalls() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := downCalls(); n < 3 || m.verdict.Load() != chainUnchecked {
		t.Fatalf("%d checks of a node that is down, verdict %d", n, m.verdict.Load())
	}
	nd.setHandler(g.serve)
	for m.verdict.Load() != chainDiffers && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if r := m.refusal(); r == nil {
		t.Fatal("the node's first answer was not checked")
	}
	answered := len(g.callsOf(MethodChainID))
	time.Sleep(100 * time.Millisecond)
	if n := len(g.callsOf(MethodChainID)); n != answered {
		t.Fatalf("%d more checks after the node answered, within the interval", n-answered)
	}
}
