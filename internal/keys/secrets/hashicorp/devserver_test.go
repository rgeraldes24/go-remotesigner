// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package hashicorp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets/secretstest"
)

// The environment of the tests against a real Vault: a dev server
// (`vault server -dev`, or the hashicorp/vault image) with its root token.
// make test-cloud starts one in Docker; the CI job cloud-secrets runs one as
// a service container.
const (
	EnvVaultAddr  = "REMOTESIGNER_TEST_VAULT_ADDR"
	EnvVaultToken = "REMOTESIGNER_TEST_VAULT_TOKEN"
)

// devServer returns the dev server's address and root token, or skips t
// (fails it under make test-cloud).
func devServer(t *testing.T) (*url.URL, string) {
	t.Helper()
	env := secretstest.CloudEnv(t, "a Vault dev server: make test-cloud", EnvVaultAddr, EnvVaultToken)
	addr, token := env[0], env[1]
	u, err := url.Parse(addr)
	if err != nil {
		t.Fatal(err)
	}
	return u, token
}

// vaultWrite writes a KV version 2 secret with the Vault HTTP API.
func vaultWrite(t *testing.T, base *url.URL, token, path string, data map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"data": data})
	req, _ := http.NewRequest(http.MethodPost, base.JoinPath(path).String(), bytes.NewReader(body))
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("write %s: HTTP %d", path, resp.StatusCode)
	}
}

func TestVaultDevServer(t *testing.T) {
	base, token := devServer(t)
	host, port, _ := net.SplitHostPort(base.Host)
	p, _ := strconv.Atoi(port)
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	name := "remotesigner-" + hex.EncodeToString(rnd[:])
	seed1, seed2 := "0x"+strings.Repeat("a1", 48), "0x"+strings.Repeat("b2", 48)
	vaultWrite(t, base, token, "/v1/secret/data/"+name, map[string]any{"value": seed1})
	vaultWrite(t, base, token, "/v1/secret/data/"+name, map[string]any{"value": seed2, "other": "x"})

	c := New(2)
	defer c.Close()
	spec := func(keyPath, keyName, tok string) *secrets.Hashicorp {
		return &secrets.Hashicorp{ServerHost: host, ServerPort: p, KeyPath: keyPath, KeyName: keyName,
			Token: []byte(tok), Timeout: 10 * time.Second, HTTPProtocolVersion: secrets.HTTP2,
			AuthMethod: secrets.VaultAuthToken, KubernetesAuthPath: "kubernetes"}
	}
	ctx := context.Background()
	got, err := c.Fetch(ctx, spec("/v1/secret/data/"+name, "value", token))
	if err != nil || string(got) != seed2 {
		t.Fatalf("latest version: %q, %v", got, err)
	}
	got, err = c.Fetch(ctx, spec("/v1/secret/data/"+name+"?version=1", "value", token))
	if err != nil || string(got) != seed1 {
		t.Fatalf("version 1: %q, %v", got, err)
	}
	if _, err := c.Fetch(ctx, spec("/v1/secret/data/"+name, "missing", token)); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("missing key: %v", err)
	}
	if _, err := c.Fetch(ctx, spec("/v1/secret/data/"+name+"-none", "value", token)); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("missing secret: %v", err)
	}
	_, err = c.Fetch(ctx, spec("/v1/secret/data/"+name, "value", "not-a-token"))
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") || strings.Contains(err.Error(), "not-a-token") {
		t.Fatalf("bad token: %v", err)
	}
	// A KV version 1 style path is not a KV version 2 read.
	if _, err := c.Fetch(ctx, spec("/v1/secret/"+name, "value", token)); err == nil {
		t.Fatal("a read outside the data/ path succeeded")
	}
}
