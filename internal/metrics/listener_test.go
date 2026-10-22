// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

// The metrics listener holds at most MaxConnections open connections: with
// the cap taken by idle connections, a scrape waits until one closes.
func TestListenerConnectionCap(t *testing.T) {
	if MaxConnections < 1 {
		t.Fatalf("MaxConnections = %d", MaxConnections)
	}
	const limit = 2
	m := newMetrics(t)
	l := NewListener(ListenerConfig{Addr: "127.0.0.1:0", HostAllowlist: []string{"127.0.0.1"}, Gatherer: m.Registry,
		Log: quiet(), MaxConnections: limit})
	if err := l.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = l.Serve() }()
	t.Cleanup(func() { _ = l.Shutdown(context.Background()) })
	url := "http://" + l.Addr().String() + Path
	scrape := func(timeout time.Duration) error {
		client := &http.Client{Timeout: timeout, Transport: &http.Transport{DisableKeepAlives: true}}
		resp, err := client.Get(url)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	}
	if err := scrape(5 * time.Second); err != nil {
		t.Fatalf("a scrape below the cap: %v", err)
	}

	var idle []net.Conn
	for range limit {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		idle = append(idle, c)
	}
	// The listener's read timeout (5 s) closes the idle connections later;
	// until then they hold the cap.
	if err := scrape(500 * time.Millisecond); err == nil {
		t.Fatalf("a scrape was served with %d idle connections open and a cap of %d", limit, limit)
	}
	_ = idle[0].Close()
	if err := scrape(3 * time.Second); err != nil {
		t.Fatalf("a scrape after one connection closed: %v", err)
	}
}
