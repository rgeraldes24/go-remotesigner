// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package secretstest holds in-process fakes of the secret stores for
// tests: HashiCorp Vault's KV version 2 and Kubernetes login endpoints,
// AWS Secrets Manager's JSON API, Azure Key Vault with a Microsoft Entra
// ID token endpoint, and GCP Secret Manager's gRPC service. Each speaks the
// store's wire protocol as its SDK or Web3Signer's client uses it, so a
// test drives the real client code. The env-gated tests run the same
// clients against a Vault dev server and LocalStack.
package secretstest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Vault is a fake HashiCorp Vault: KV version 2 reads at any /v1/ path and
// the Kubernetes auth login.
type Vault struct {
	*httptest.Server
	// Token is the static token reads accept.
	Token string

	mu      sync.Mutex
	secrets map[string]map[string]any // read path -> data
	// Kubernetes login: mount, role, the service-account JWT it accepts,
	// and the client token it issues.
	k8sMount, k8sRole, k8sJWT, k8sToken string
	// Protos records the HTTP major version of each request.
	Protos []int
	// Logins counts the Kubernetes logins.
	Logins int
}

// NewVault starts a fake Vault, over TLS when tls is set (the server's
// certificate is httptest's), and stops it when t ends.
func NewVault(t testing.TB, tls bool) *Vault {
	t.Helper()
	v := &Vault{Token: "s.test-token", secrets: map[string]map[string]any{}}
	h := http.HandlerFunc(v.serve)
	if tls {
		v.Server = httptest.NewUnstartedServer(h)
		v.EnableHTTP2 = true
		v.StartTLS()
	} else {
		v.Server = httptest.NewServer(h)
	}
	t.Cleanup(v.Close)
	return v
}

// Put stores a KV version 2 secret's data at its read path, such as
// /v1/secret/data/validator-1.
func (v *Vault) Put(path string, data map[string]any) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.secrets[path] = data
}

// Delete removes the secret at its read path.
func (v *Vault) Delete(path string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.secrets, path)
}

// EnableKubernetes turns on the Kubernetes login at /v1/auth/<mount>/login
// for role and the service-account JWT jwt; it issues token.
func (v *Vault) EnableKubernetes(mount, role, jwt, token string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.k8sMount, v.k8sRole, v.k8sJWT, v.k8sToken = mount, role, jwt, token
}

func (v *Vault) serve(w http.ResponseWriter, r *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.Protos = append(v.Protos, r.ProtoMajor)
	if r.Method == http.MethodPost && v.k8sMount != "" && r.URL.Path == "/v1/auth/"+v.k8sMount+"/login" {
		var req struct{ Role, JWT string }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Role != v.k8sRole || req.JWT != v.k8sJWT {
			writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []string{"invalid role or service account token"}})
			return
		}
		v.Logins++
		writeJSON(w, http.StatusOK, map[string]any{"auth": map[string]any{"client_token": v.k8sToken, "lease_duration": 3600}})
		return
	}
	if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/v1/") {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"errors": []string{"unsupported"}})
		return
	}
	tok := r.Header.Get("X-Vault-Token")
	if tok == "" || (tok != v.Token && (v.k8sToken == "" || tok != v.k8sToken)) {
		writeJSON(w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
		return
	}
	data, ok := v.secrets[r.URL.Path]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"errors": []string{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"request_id": "fake", "lease_id": "", "renewable": false, "lease_duration": 0,
		"data": map[string]any{"data": data, "metadata": map[string]any{"version": 1, "destroyed": false}},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
