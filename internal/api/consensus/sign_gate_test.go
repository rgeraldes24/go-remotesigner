// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package consensus

import (
	"fmt"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/admission"
	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/signer"
)

// blocking is a key whose Sign, while hold is set, waits until release is
// closed; it counts the signs in progress.
type blocking struct {
	signer.Key
	hold    *atomic.Bool
	release <-chan struct{}
	running *atomic.Int64
}

func (b *blocking) Sign(m []byte, mode mldsa87.Mode) (signer.Signature, error) {
	b.running.Add(1)
	defer b.running.Add(-1)
	if b.hold.Load() {
		<-b.release
	}
	return b.Key.Sign(m, mode)
}

// TestSignGateSaturated fills the signing gate (docs/contract.md section
// 13, "Signing concurrency"): the requests
// beyond its slots wait in its queue, the requests beyond the queue get 503
// OVERLOADED with Retry-After at once and never reach the key, the queued
// ones are signed once slots free, and a repeat answered by the response
// cache takes no slot.
func TestSignGateSaturated(t *testing.T) {
	const concurrent, queued, extra = 2, 3, 4
	c := goldenCase(t, signingroot.SyncCommitteeMessage, "typical")
	f := newSignFixture(t, signOptions{network: goldenSources(t, c.Network)})
	gate, err := admission.New(concurrent, queued)
	if err != nil {
		t.Fatal(err)
	}
	f.h.Gate = gate
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	var (
		running atomic.Int64
		hold    atomic.Bool
	)
	f.h.Signer = signer.New(signer.Config{
		Lookup: func(id signer.ID) (signer.Key, bool) {
			k, ok := f.keys[id]
			if !ok {
				return nil, false
			}
			return &blocking{Key: k, hold: &hold, release: release, running: &running}, true
		},
		Metrics: f.m, Log: f.log, CacheTTL: time.Hour,
	})
	ident := f.ident(c.KeyIndex)

	// A request signed before the gate fills, to repeat from the cache.
	signature(t, f.post(ident, c.RequestJSON))
	hold.Store(true)
	body := func(i int) []byte {
		return edit(t, c.RequestJSON, func(m map[string]any) {
			delete(m, "signing_root")
			m["sync_committee_message"].(map[string]any)["beacon_block_root"] = fmt.Sprintf("0x%064x", i+1)
		})
	}
	var wg sync.WaitGroup
	recs := make([]*httptest.ResponseRecorder, concurrent+queued)
	for i := range recs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recs[i] = f.post(ident, body(i))
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for running.Load() != concurrent || gate.Queued() != queued {
		if time.Now().After(deadline) {
			t.Fatalf("%d signing and %d queued, want %d and %d", running.Load(), gate.Queued(), concurrent, queued)
		}
		time.Sleep(time.Millisecond)
	}

	for i := range extra {
		rec := f.post(ident, body(100+i))
		if r := reason(t, rec, 503); r != apierr.Overloaded {
			t.Fatalf("request beyond the queue: %s, want OVERLOADED", r)
		}
		if ra := rec.Header().Get("Retry-After"); ra == "" {
			t.Error("503 OVERLOADED without Retry-After")
		}
	}
	if n := running.Load(); n != concurrent {
		t.Fatalf("%d signs in progress after the refusals, want %d", n, concurrent)
	}
	if got := f.requests(signingroot.SyncCommitteeMessage, "error"); got != extra {
		t.Errorf("signing_requests_total{result=error} = %v, want %d", got, extra)
	}

	// The cache answers a repeat without a slot, and without the key.
	signature(t, f.post(ident, c.RequestJSON))
	if n := running.Load(); n != concurrent {
		t.Fatalf("the cached repeat reached the key: %d signs in progress", n)
	}

	unblock()
	wg.Wait()
	for i, rec := range recs {
		if rec.Code != 200 {
			t.Errorf("admitted request %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	if gate.InFlight() != 0 || gate.Queued() != 0 {
		t.Errorf("%d in flight and %d queued at the end", gate.InFlight(), gate.Queued())
	}
}
