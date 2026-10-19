// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"
	"time"
)

// The chain-ID check: unchecked until the node answers, then matches or
// differs with the node's qrl_chainId; a check the node does not answer
// keeps the last verdict; run checks at once and then at each interval.
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
	go func() { defer close(done); m.run(ctx, 10*time.Millisecond) }()
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
