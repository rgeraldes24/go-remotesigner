// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
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

// A scrape refused for its token (401) or its Host (403) closes its
// connection, so that refused scrapes cannot hold the listener's few
// connection slots; a served scrape keeps its connection.
func TestListenerRefusalClosesConnection(t *testing.T) {
	dir := t.TempDir()
	const (
		tok     = "0x4444444444444444444444444444444444444444444444444444444444444444"
		signTok = "0x5555555555555555555555555555555555555555555555555555555555555555"
	)
	cfg := auth.Config{Mode: auth.ModeToken, SignTokenFile: filepath.Join(dir, "sign"),
		MetricsTokenFile: filepath.Join(dir, "metrics")}
	if err := os.WriteFile(cfg.SignTokenFile, []byte(signTok), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.MetricsTokenFile, []byte(tok), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := auth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	l := NewListener(ListenerConfig{Addr: "127.0.0.1:0", HostAllowlist: []string{"localhost"},
		Gatherer: newMetrics(t).Registry, Auth: a, Log: quiet()})
	if err := l.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = l.Serve() }()
	t.Cleanup(func() { _ = l.Shutdown(context.Background()) })

	for _, tt := range []struct {
		name, req string
		status    int
		closes    bool
	}{
		{"no token", "GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n", 401, true},
		{"bad Host", "GET /metrics HTTP/1.1\r\nHost: evil.example\r\nAuthorization: Bearer " + tok + "\r\n\r\n", 403, true},
		{"metrics token", "GET /metrics HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + tok + "\r\n\r\n", 200, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			if _, err := io.WriteString(c, tt.req); err != nil {
				t.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != tt.status || resp.Close != tt.closes {
				t.Fatalf("status %d, Connection: close %v; want %d, %v", resp.StatusCode, resp.Close, tt.status, tt.closes)
			}
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			_, err = br.ReadByte()
			if closed := errors.Is(err, io.EOF); closed != tt.closes {
				t.Fatalf("connection closed %v after the response (%v), want %v", closed, err, tt.closes)
			}
		})
	}
}
