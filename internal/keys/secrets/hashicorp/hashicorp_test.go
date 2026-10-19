// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package hashicorp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets/secretstest"
	"github.com/rgeraldes24/go-remotesigner/internal/server/tlsconf"
)

const seed = "0x" + "ab" + "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

// specFor returns a TOKEN spec for the secret at keyPath on srv.
func specFor(t *testing.T, srv *httptest.Server, keyPath, token string) *secrets.Hashicorp {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, port, _ := net.SplitHostPort(u.Host)
	p, _ := strconv.Atoi(port)
	return &secrets.Hashicorp{
		ServerHost: host, ServerPort: p, KeyPath: keyPath, KeyName: "value", Token: []byte(token),
		Timeout: 5 * time.Second, TLSEnabled: u.Scheme == "https", HTTPProtocolVersion: secrets.HTTP2,
		AuthMethod: secrets.VaultAuthToken, KubernetesAuthPath: "kubernetes",
	}
}

func TestFetch(t *testing.T) {
	v := secretstest.NewVault(t, false)
	v.Put("/v1/secret/data/k1", map[string]any{"value": seed, "other": "x"})
	v.Put("/v1/secret/data/k2", map[string]any{"seed": seed})
	v.Put("/v1/secret/data/escaped", map[string]any{"value": "0xé"})
	v.Put("/v1/secret/data/number", map[string]any{"value": 12})
	c := New(4)
	defer c.Close()
	tests := []struct {
		name    string
		edit    func(*secrets.Hashicorp)
		want    string
		err     error
		errText string
	}{
		{name: "value", want: seed},
		{name: "key name", edit: func(h *secrets.Hashicorp) { h.KeyPath, h.KeyName = "/v1/secret/data/k2", "seed" }, want: seed},
		{name: "dot segments resolved", edit: func(h *secrets.Hashicorp) { h.KeyPath = "/v1/secret/data/x/../k1" }, want: seed},
		{name: "query kept", edit: func(h *secrets.Hashicorp) { h.KeyPath = "/v1/secret/data/k1?version=1" }, want: seed},
		{name: "escaped string", edit: func(h *secrets.Hashicorp) { h.KeyPath = "/v1/secret/data/escaped" }, want: "0xé"},
		{name: "missing key", edit: func(h *secrets.Hashicorp) { h.KeyName = "nope" }, err: secrets.ErrNotFound},
		{name: "missing secret", edit: func(h *secrets.Hashicorp) { h.KeyPath = "/v1/secret/data/none" }, err: secrets.ErrNotFound},
		{name: "not a string", edit: func(h *secrets.Hashicorp) { h.KeyPath = "/v1/secret/data/number" }, errText: "not a string"},
		{name: "bad token", edit: func(h *secrets.Hashicorp) { h.Token = []byte("wrong") }, errText: "HTTP 403: permission denied"},
		{name: "absolute URL refused", edit: func(h *secrets.Hashicorp) { h.KeyPath = "http://evil.example/v1/x" }, err: secrets.ErrConfig},
		{name: "scheme-relative refused", edit: func(h *secrets.Hashicorp) { h.KeyPath = "//evil.example/v1/x" }, err: secrets.ErrConfig},
		{name: "relative refused", edit: func(h *secrets.Hashicorp) { h.KeyPath = "v1/secret/data/k1" }, err: secrets.ErrConfig},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := specFor(t, v.Server, "/v1/secret/data/k1", v.Token)
			if tt.edit != nil {
				tt.edit(h)
			}
			got, err := c.Fetch(context.Background(), h)
			switch {
			case tt.err != nil || tt.errText != "":
				if (tt.err != nil && !errors.Is(err, tt.err)) || (tt.errText != "" && (err == nil || !strings.Contains(err.Error(), tt.errText))) {
					t.Fatalf("error = %v, want %v %q", err, tt.err, tt.errText)
				}
				if strings.Contains(err.Error(), "cdcd") || strings.Contains(err.Error(), v.Token) {
					t.Fatalf("error quotes a secret: %v", err)
				}
			case err != nil:
				t.Fatal(err)
			case string(got) != tt.want:
				t.Fatalf("value = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFetchBadResponses(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"not KV v2":  func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"data":{"value":"x"}}`)) },
		"not JSON":   func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`<html>`)) },
		"no content": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) },
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://127.0.0.1:1/v1/secret/data/k1", http.StatusTemporaryRedirect)
		},
		"too large": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(secrets.MaxResponseSize+1))
			_, _ = w.Write(make([]byte, secrets.MaxResponseSize+1))
		},
	}
	want := map[string]string{
		"not KV v2": "not a KV version 2 secret", "not JSON": "not a KV version 2 secret", "no content": "no content",
		"redirect": "redirect", "too large": "too large",
	}
	c := New(8)
	defer c.Close()
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			_, err := c.Fetch(context.Background(), specFor(t, srv, "/v1/secret/data/k1", "t"))
			if err == nil || !strings.Contains(err.Error(), want[name]) {
				t.Fatalf("error = %v, want %q", err, want[name])
			}
		})
	}
}

func TestFetchTimeout(t *testing.T) {
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-stop }))
	defer srv.Close()
	defer close(stop)
	h := specFor(t, srv, "/v1/secret/data/k1", "t")
	h.Timeout = 50 * time.Millisecond
	start := time.Now()
	if _, err := New(1).Fetch(context.Background(), h); err == nil {
		t.Fatal("no timeout")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("the read took %v with a 50 ms timeout", d)
	}
}

func TestFetchTLS(t *testing.T) {
	v := secretstest.NewVault(t, true)
	v.Put("/v1/secret/data/k1", map[string]any{"value": seed})
	dir := t.TempDir()
	fp := tlsconf.FingerprintOf(v.Certificate().Raw)
	h := specFor(t, v.Server, "/v1/secret/data/k1", v.Token)
	write := func(content string) string {
		p := filepath.Join(dir, "known_servers")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// httptest's certificate does not chain to the system roots.
	if _, err := New(1).Fetch(context.Background(), h); err == nil {
		t.Fatal("a certificate that is neither CA-signed nor pinned was accepted")
	}

	h.TLSKnownServersFile = write("# pinned\n\n" + h.Addr() + " " + fp.String() + "\n")
	got, err := New(1).Fetch(context.Background(), h)
	if err != nil || string(got) != seed {
		t.Fatalf("pinned: %q, %v", got, err)
	}
	if v.Protos[len(v.Protos)-1] != 2 {
		t.Errorf("HTTP_2 over TLS used HTTP/%d", v.Protos[len(v.Protos)-1])
	}

	h.HTTPProtocolVersion = secrets.HTTP11
	if _, err := New(1).Fetch(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if v.Protos[len(v.Protos)-1] != 1 {
		t.Errorf("HTTP_1_1 used HTTP/%d", v.Protos[len(v.Protos)-1])
	}

	other := tlsconf.FingerprintOf([]byte("another certificate"))
	h.TLSKnownServersFile = write(h.Addr() + " " + other.String() + "\n" + "localhost:1 " + fp.String() + "\n")
	if _, err := New(1).Fetch(context.Background(), h); err == nil || !strings.Contains(err.Error(), "not listed") {
		t.Fatalf("a certificate pinned for another server or with another fingerprint: %v", err)
	}

	h.TLSKnownServersFile = write("127.0.0.1 " + fp.String() + "\n")
	if _, err := New(1).Fetch(context.Background(), h); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("a malformed known-servers file: %v", err)
	}
	h.TLSKnownServersFile = filepath.Join(dir, "missing")
	if _, err := New(1).Fetch(context.Background(), h); err == nil {
		t.Fatal("a missing known-servers file was accepted")
	}
}

// One Client reads the known-servers file when it builds the server's HTTP
// client, and again after Close, which the runner calls after each load:
// a pin added or removed takes effect on the next load, as with
// Web3Signer's connection factory, built for each load.
func TestKnownServersRotation(t *testing.T) {
	v := secretstest.NewVault(t, true)
	v.Put("/v1/secret/data/k1", map[string]any{"value": seed})
	fp := tlsconf.FingerprintOf(v.Certificate().Raw)
	other := tlsconf.FingerprintOf([]byte("the previous certificate"))
	h := specFor(t, v.Server, "/v1/secret/data/k1", v.Token)
	h.TLSKnownServersFile = filepath.Join(t.TempDir(), "known_servers")
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(h.TLSKnownServersFile, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c := New(16)
	defer c.Close()
	fetch := func() error { _, err := c.Fetch(context.Background(), h); return err }

	write(h.Addr() + " " + other.String() + "\n")
	if err := fetch(); err == nil || !strings.Contains(err.Error(), "not listed") {
		t.Fatalf("a certificate that is not pinned: %v", err)
	}
	write(h.Addr() + " " + fp.String() + "\n")
	c.Close()
	if err := fetch(); err != nil {
		t.Fatalf("after the pin was added and the client closed: %v", err)
	}
	write("# revoked\n")
	c.Close()
	if err := fetch(); err == nil || !strings.Contains(err.Error(), "not listed") {
		t.Fatalf("after the pin was removed and the client closed: %v", err)
	}
}

func TestFetchKubernetes(t *testing.T) {
	v := secretstest.NewVault(t, false)
	v.Put("/v1/secret/data/k1", map[string]any{"value": seed})
	v.EnableKubernetes("k8s/cluster", "signer", "jwt-of-the-pod", "s.k8s-issued")
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("jwt-of-the-pod\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := specFor(t, v.Server, "/v1/secret/data/k1", "")
	h.AuthMethod, h.KubernetesRole, h.KubernetesTokenPath, h.KubernetesAuthPath =
		secrets.VaultAuthKubernetes, "signer", tokenFile, "k8s/cluster"
	c := New(1)
	got, err := c.Fetch(context.Background(), h)
	if err != nil || string(got) != seed {
		t.Fatalf("Fetch = %q, %v", got, err)
	}
	if v.Logins != 1 {
		t.Fatalf("%d logins", v.Logins)
	}

	h.KubernetesRole = "other"
	if _, err := c.Fetch(context.Background(), h); err == nil || !strings.Contains(err.Error(), "invalid role") ||
		strings.Contains(err.Error(), "jwt-of-the-pod") {
		t.Fatalf("wrong role: %v", err)
	}
	h.KubernetesRole = ""
	if _, err := c.Fetch(context.Background(), h); !errors.Is(err, secrets.ErrConfig) {
		t.Fatalf("no role: %v", err)
	}
	h.KubernetesRole, h.KubernetesTokenPath = "signer", filepath.Join(dir, "none")
	if _, err := c.Fetch(context.Background(), h); err == nil || !strings.Contains(err.Error(), "service-account token") {
		t.Fatalf("no token file: %v", err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.KubernetesTokenPath = empty
	if _, err := c.Fetch(context.Background(), h); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("empty token file: %v", err)
	}
}

func TestClientCache(t *testing.T) {
	v := secretstest.NewVault(t, false)
	v.Put("/v1/secret/data/k1", map[string]any{"value": seed})
	c := New(2)
	h := specFor(t, v.Server, "/v1/secret/data/k1", v.Token)
	for range 3 {
		if _, err := c.Fetch(context.Background(), h); err != nil {
			t.Fatal(err)
		}
	}
	if c.clients.Len() != 1 {
		t.Fatalf("%d clients for one server", c.clients.Len())
	}
	h2 := *h
	h2.Timeout = time.Second
	if _, err := c.Fetch(context.Background(), &h2); err != nil {
		t.Fatal(err)
	}
	if c.clients.Len() != 2 {
		t.Fatalf("%d clients for two connection settings", c.clients.Len())
	}
}

func TestLoadKnownServers(t *testing.T) {
	fp := tlsconf.FingerprintOf([]byte("x"))
	p := filepath.Join(t.TempDir(), "known")
	content := "Vault.Example:8200 " + fp.String() + "\n[::1]:8200 " + strings.ReplaceAll(fp.String(), ":", "") + "\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadKnownServers(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got["vault.example:8200"]) != 1 || len(got["[::1]:8200"]) != 1 {
		t.Fatalf("known servers = %v", got)
	}
}
