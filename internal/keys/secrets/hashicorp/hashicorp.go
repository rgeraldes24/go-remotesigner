// Copyright 2020 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// keystorage/src/main/java/tech/pegasys/web3signer/keystorage/hashicorp/HashicorpConnection.java,
// keystorage/src/main/java/tech/pegasys/web3signer/keystorage/hashicorp/HashicorpConnectionFactory.java,
// keystorage/src/main/java/tech/pegasys/web3signer/keystorage/hashicorp/HashicorpKVResponseMapper.java and
// signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/AbstractArtifactSignerFactory.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

// Package hashicorp reads seeds from HashiCorp Vault's KV version 2 secrets
// engine over plain HTTP, as Web3Signer does: no Vault SDK is linked. A
// read is GET <scheme>://<host>:<port><keyPath> with the X-Vault-Token
// header, and the seed is the value of one key of the secret's data
// (data.data[keyName]). The token is configured (TOKEN) or obtained per
// read by logging in with the pod's Kubernetes service-account token
// (KUBERNETES, POST /v1/auth/<mount>/login).
//
// Over TLS the server certificate must chain to the system roots, or have
// its SHA-256 fingerprint listed for the server's host:port in the
// known-servers file (Web3Signer's allowlist of CA-signed or listed
// servers). Every request has the configured timeout, follows no redirect
// and reads at most secrets.MaxResponseSize bytes.
package hashicorp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/server/tlsconf"
)

// maxTokenFile bounds the Kubernetes service-account token file.
const maxTokenFile = 64 << 10

// Client reads Vault secrets. It keeps one HTTP client per server and
// connection settings, as Web3Signer keeps one per server URI, until
// Close; the known-servers file is read when the HTTP client is built. It
// is safe for concurrent use.
type Client struct {
	clients secrets.Cache[connKey, *http.Client]
}

type connKey struct {
	scheme, addr string
	knownServers string
	http1        bool
	timeout      time.Duration
}

// New returns a client with room for maxServers HTTP clients.
func New(maxServers int) *Client {
	c := &Client{}
	c.clients.Max = maxServers
	c.clients.Close = func(hc *http.Client) { hc.CloseIdleConnections() }
	return c
}

// Close drops every cached HTTP client and closes its idle connections.
// The client stays usable: the next fetch builds a new HTTP client, which
// reads the known-servers file again.
func (c *Client) Close() { c.clients.Purge() }

// Fetch implements secrets.Fetcher for *secrets.Hashicorp specs.
func (c *Client) Fetch(ctx context.Context, s secrets.Spec) ([]byte, error) {
	h, ok := s.(*secrets.Hashicorp)
	if !ok {
		return nil, fmt.Errorf("hashicorp: %w: not a hashicorp secret", secrets.ErrConfig)
	}
	v, err := c.fetch(ctx, h)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.Describe(), err)
	}
	return v, nil
}

func (c *Client) fetch(ctx context.Context, h *secrets.Hashicorp) ([]byte, error) {
	base, read, err := urls(h)
	if err != nil {
		return nil, err
	}
	hc, release, err := c.httpClient(h, base.Scheme)
	if err != nil {
		return nil, err
	}
	defer release()
	token := []byte(h.Token)
	if h.AuthMethod == secrets.VaultAuthKubernetes {
		if token, err = login(ctx, hc, base, h); err != nil {
			return nil, err
		}
		defer mldsa87.Wipe(token)
	}
	return readKV(ctx, hc, read, token, h.KeyName)
}

// urls returns the server's base URL and the secret's read URL. The key
// path is a path on the server, with an optional query (a KV version 2
// ?version=N); dot segments are resolved, as Web3Signer's URI.normalize
// does.
func urls(h *secrets.Hashicorp) (base, read *url.URL, err error) {
	scheme := "http"
	if h.TLSEnabled {
		scheme = "https"
	}
	base = &url.URL{Scheme: scheme, Host: net.JoinHostPort(h.ServerHost, strconv.Itoa(h.ServerPort))}
	kp, err := url.Parse(h.KeyPath)
	if err != nil || kp.Scheme != "" || kp.Host != "" || kp.User != nil || !strings.HasPrefix(kp.Path, "/") ||
		strings.HasPrefix(h.KeyPath, "//") {
		return nil, nil, fmt.Errorf("%w: keyPath must be a path on the server, such as /v1/secret/data/<name>",
			secrets.ErrConfig)
	}
	read = base.JoinPath()
	read.Path = path.Clean(kp.Path)
	read.RawQuery = kp.RawQuery
	return base, read, nil
}

// httpClient returns the cached HTTP client of h's connection settings and
// the function that releases it.
func (c *Client) httpClient(h *secrets.Hashicorp, scheme string) (*http.Client, func(), error) {
	k := connKey{scheme: scheme, addr: h.Addr(), http1: h.HTTPProtocolVersion == secrets.HTTP11, timeout: h.Timeout}
	if h.TLSEnabled {
		k.knownServers = h.TLSKnownServersFile
	}
	return c.clients.Get(k, func() (*http.Client, error) {
		o := secrets.HTTPOptions{Timeout: h.Timeout, HTTP1Only: k.http1}
		if h.TLSEnabled {
			conf, err := tlsConfig(h)
			if err != nil {
				return nil, err
			}
			o.TLS = conf
		}
		return secrets.HTTPClient(o), nil
	})
}

// tlsConfig is the TLS configuration of h: the system roots, and with a
// known-servers file, also the certificates it lists for h's host:port.
func tlsConfig(h *secrets.Hashicorp) (*tls.Config, error) {
	conf := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: h.ServerHost}
	if h.TLSKnownServersFile == "" {
		return conf, nil
	}
	known, err := LoadKnownServers(h.TLSKnownServersFile)
	if err != nil {
		return nil, err
	}
	pins := known[strings.ToLower(h.Addr())]
	// The handshake's own verification is replaced by VerifyConnection,
	// which accepts what it would have accepted, and the pinned
	// certificates besides.
	conf.InsecureSkipVerify = true
	conf.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("hashicorp: the server sent no certificate")
		}
		leaf := cs.PeerCertificates[0]
		inter := x509.NewCertPool()
		for _, c := range cs.PeerCertificates[1:] {
			inter.AddCert(c)
		}
		_, verr := leaf.Verify(x509.VerifyOptions{DNSName: h.ServerHost, Intermediates: inter})
		if verr == nil {
			return nil
		}
		fp := tlsconf.FingerprintOf(leaf.Raw)
		for _, p := range pins {
			if p == fp {
				return nil
			}
		}
		return fmt.Errorf("hashicorp: the certificate of %s (SHA-256 %s) is not CA-signed (%v) and not listed for "+
			"it in %s", h.Addr(), fp, verr, h.TLSKnownServersFile)
	}
	return conf, nil
}

// kvResponse is a KV version 2 read response; Web3Signer reads data.data.
type kvResponse struct {
	Data *struct {
		Data map[string]json.RawMessage `json:"data"`
	} `json:"data"`
}

// readKV reads the secret at u and returns the value of its key name.
func readKV(ctx context.Context, hc *http.Client, u *url.URL, token []byte, keyName string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header["X-Vault-Token"] = []string{string(token)}
	req.Header.Set("Content-Type", "application/json")
	body, err := do(hc, req)
	if err != nil {
		return nil, err
	}
	defer mldsa87.Wipe(body)
	var r kvResponse
	err = json.Unmarshal(body, &r)
	if r.Data != nil {
		defer func() {
			for _, v := range r.Data.Data {
				mldsa87.Wipe(v)
			}
		}()
	}
	if err != nil || r.Data == nil || r.Data.Data == nil {
		return nil, errors.New("invalid response returned from Hashicorp Vault: not a KV version 2 secret " +
			"(want data.data)")
	}
	raw, ok := r.Data.Data[keyName]
	if !ok || string(raw) == "null" {
		return nil, fmt.Errorf("%w: the secret has no key %q", secrets.ErrNotFound, keyName)
	}
	return jsonString(raw)
}

// jsonString returns the content of a JSON string in a new buffer. A string
// without escapes, as a hex seed is, is copied as it is, so that no Go
// string holds the seed.
func jsonString(raw json.RawMessage) ([]byte, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, errors.New("the secret's value is not a string")
	}
	inner := raw[1 : len(raw)-1]
	if !bytes.ContainsAny(inner, `\"`) {
		return bytes.Clone(inner), nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, errors.New("the secret's value is not a valid JSON string")
	}
	return []byte(s), nil
}

// login obtains a client token with the Kubernetes auth method.
func login(ctx context.Context, hc *http.Client, base *url.URL, h *secrets.Hashicorp) ([]byte, error) {
	if h.KubernetesRole == "" {
		return nil, fmt.Errorf("%w: kubernetesRole must be provided when using KUBERNETES auth method",
			secrets.ErrConfig)
	}
	mount, err := secrets.CheckKubernetesAuthPath(h.KubernetesAuthPath)
	if err != nil {
		return nil, err
	}
	jwt, err := secretfile.ReadCapped(h.KubernetesTokenPath, maxTokenFile)
	if err != nil {
		return nil, fmt.Errorf("read the Kubernetes service-account token: %w", err)
	}
	defer mldsa87.Wipe(jwt)
	if len(bytes.TrimSpace(jwt)) == 0 {
		return nil, fmt.Errorf("the Kubernetes service-account token %s is empty", h.KubernetesTokenPath)
	}
	reqBody, err := json.Marshal(struct {
		Role string `json:"role"`
		JWT  string `json:"jwt"`
	}{h.KubernetesRole, string(bytes.TrimSpace(jwt))})
	if err != nil {
		return nil, err
	}
	defer mldsa87.Wipe(reqBody)
	u := base.JoinPath("v1", "auth", mount, "login")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	body, err := do(hc, req)
	if err != nil {
		return nil, fmt.Errorf("login with the Kubernetes auth method (role %q): %w", h.KubernetesRole, err)
	}
	defer mldsa87.Wipe(body)
	var r struct {
		Auth *struct {
			ClientToken json.RawMessage `json:"client_token"`
		} `json:"auth"`
	}
	err = json.Unmarshal(body, &r)
	if err != nil || r.Auth == nil {
		return nil, errors.New("the Kubernetes auth login response did not contain 'auth' field; Vault may have rejected " +
			"the request")
	}
	defer mldsa87.Wipe(r.Auth.ClientToken)
	tok, err := jsonString(r.Auth.ClientToken)
	if err != nil || len(bytes.TrimSpace(tok)) == 0 {
		return nil, fmt.Errorf("the Kubernetes auth login response did not contain a valid 'client_token'; Vault role "+
			"%q may not be configured correctly", h.KubernetesRole)
	}
	return tok, nil
}

// do sends req and returns the body of a 200 response. Any other status is
// an error with Vault's error messages; 404 is secrets.ErrNotFound.
func do(hc *http.Client, req *http.Request) ([]byte, error) {
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error communicating with Hashicorp Vault: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := secrets.ReadBody(resp, secrets.MaxResponseSize)
	if err != nil {
		return nil, fmt.Errorf("error communicating with Hashicorp Vault: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusNoContent:
		mldsa87.Wipe(body)
		return nil, errors.New("invalid response returned from Hashicorp Vault: no content")
	}
	defer mldsa87.Wipe(body)
	msg := fmt.Sprintf("Hashicorp Vault answered HTTP %d", resp.StatusCode)
	var e struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(body, &e) == nil && len(e.Errors) > 0 {
		msg += ": " + bounded(strings.Join(e.Errors, "; "))
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s", secrets.ErrNotFound, msg)
	}
	return nil, errors.New(msg)
}

// bounded cuts a server message quoted in an error.
func bounded(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
