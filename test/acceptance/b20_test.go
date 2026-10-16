// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"
)

// B20, the TLS handshake storm (docs/benchmarks.md), against the built
// binary with an RSA-2048 and with an ECDSA P-256 certificate:
//
//   - the storm: 160 new connections at once, each a full TLS 1.3
//     handshake (no session to resume), p99 handshake ≤ 200 ms;
//   - the B7 burst over TLS on HTTP/1.1, where a client with its own TLS
//     configuration (as qrysm's is) opens a connection, and so a handshake,
//     per concurrent request, and on h2 (Go's default transport), which
//     multiplexes the burst on one connection. Both keep B7's bounds: last
//     response ≤ 1 s, p99 ≤ 500 ms, no errors.
//
// Like B7-B9 it runs only with REMOTESIGNER_BENCH=1 (make bench-e2e).
func TestB20TLSHandshakeStorm(t *testing.T) {
	benchEnabled(t)
	for _, c := range []struct {
		name string
		rsa  bool
	}{{"P-256", false}, {"RSA-2048", true}} {
		t.Run(c.name, func(t *testing.T) {
			srv := serverCert(t, c.rsa)
			roots := poolOf(srv.cert)
			s := tlsBenchSigner(t, srv)
			lat := handshakeStorm(t, "127.0.0.1:"+s.port, roots, 160)
			p99 := percentile(lat, 0.99)
			t.Logf("B20 %s storm: %d handshakes, p50 %v, p99 %v, max %v", c.name, len(lat), percentile(lat, 0.5), p99,
				percentile(lat, 1))
			if p99 > 200*time.Millisecond {
				t.Errorf("B20 %s missed: p99 handshake %v (≤ 200 ms)", c.name, p99)
			}

			for _, h2 := range []bool{false, true} {
				proto := "HTTP/1.1"
				if h2 {
					proto = "h2"
				}
				// A fresh signer, so that the burst's keys have no history.
				s := tlsBenchSigner(t, srv)
				tr := http.DefaultTransport.(*http.Transport).Clone()
				tr.TLSClientConfig = &tls.Config{RootCAs: roots}
				tr.ForceAttemptHTTP2 = h2
				lat, wall := burstWith(t, &http.Client{Transport: tr}, s.tlsBase(), s.signToken(), b7Requests(t, s.ids))
				p99 := percentile(lat, 0.99)
				t.Logf("B20 %s B7 over TLS (%s): %d requests, last response after %v, p50 %v, p99 %v", c.name, proto,
					len(lat), wall, percentile(lat, 0.5), p99)
				if wall > time.Second || p99 > 500*time.Millisecond {
					t.Errorf("B20 %s B7 over TLS (%s) missed: last %v (≤ 1 s), p99 %v (≤ 500 ms)", c.name, proto, wall, p99)
				}
			}
		})
	}
}

// benchSigner is a started signer with the B7 keys.
type benchSigner struct {
	*signer
	ids []string
}

// tlsBenchSigner starts a signer with the B7 keys serving srv over TLS in
// token mode, and waits until it is ready.
func tlsBenchSigner(t *testing.T, srv tlsPair) benchSigner {
	t.Helper()
	keys := t.TempDir()
	ids := writeKeys(t, keys, b7Keys)
	cf, kf := writePEMPair(t, t.TempDir(), "server", srv)
	s := start(t, options{keys: keys, global: []string{"--tls-cert-file=" + cf, "--tls-key-file=" + kf}})
	s.waitReadyTLS(tlsClient(poolOf(srv.cert), nil, nil))
	return benchSigner{signer: s, ids: ids}
}

// handshakeStorm opens n connections to addr at once and returns each
// one's dial-plus-handshake time. Every client has no session cache, so
// every handshake is a full one.
func handshakeStorm(t *testing.T, addr string, roots *x509.CertPool, n int) []time.Duration {
	t.Helper()
	lat := make([]time.Duration, n)
	conns := make([]*tls.Conn, n)
	var wg sync.WaitGroup
	gate := make(chan struct{})
	for i := range n {
		wg.Go(func() {
			<-gate
			d := &net.Dialer{Timeout: 10 * time.Second}
			start := time.Now()
			c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{RootCAs: roots, ServerName: "localhost"})
			if err != nil {
				t.Errorf("handshake %d: %v", i, err)
				return
			}
			lat[i] = time.Since(start)
			if c.ConnectionState().DidResume || c.ConnectionState().Version != tls.VersionTLS13 {
				t.Errorf("handshake %d: resumed %v, version %x", i, c.ConnectionState().DidResume, c.ConnectionState().Version)
			}
			conns[i] = c
		})
	}
	close(gate)
	wg.Wait()
	// Close only once every handshake is done, so that all n are open at
	// once.
	for _, c := range conns {
		if c != nil {
			_ = c.Close()
		}
	}
	return lat
}
