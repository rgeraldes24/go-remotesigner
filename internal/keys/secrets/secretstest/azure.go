// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package secretstest

import (
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// AzureTenant is the tenant id of the fake's Microsoft Entra ID.
const AzureTenant = "11111111-2222-3333-4444-555555555555"

// Azure is a fake Azure Key Vault and Microsoft Entra ID on one TLS
// server, as the SDK reaches them with Web3Signer's endpoint and authority
// host overrides:
//
//   - Key Vault's challenge: a request without a bearer token gets 401 with
//     a WWW-Authenticate challenge naming the tenant and the vault
//     resource;
//   - Entra ID's OpenID configuration and token endpoint (client
//     credentials), and the App Service managed identity endpoint at
//     /msi/token (IDENTITY_ENDPOINT, IDENTITY_HEADER);
//   - Key Vault's secret listing, in pages of PageSize with nextLink, and
//     its secret read by name.
//
// CertFile is the server's certificate as a PEM file, for the trust
// certificate override.
type Azure struct {
	*httptest.Server
	CertFile string
	// ClientID and ClientSecret are the application credentials the token
	// endpoint accepts; IdentityHeader is the managed identity endpoint's
	// secret header.
	ClientID, ClientSecret, IdentityHeader string
	PageSize                               int

	mu      sync.Mutex
	secrets []azureSecret
	// TokenRequests counts the client-credential and managed identity
	// token requests; ManagedIdentityClientIDs records the client ids
	// those asked for.
	TokenRequests            int
	ManagedIdentityClientIDs []string
	// hang: every Key Vault request waits, unanswered, until its client
	// gives up; the token endpoints still answer.
	hang bool
	// reads counts the secret reads by name.
	reads map[string]int
}

type azureSecret struct {
	name, value string
	tags        map[string]string
}

const azureToken = "fake-access-token"

// NewAzure starts the fake and stops it when t ends.
func NewAzure(t testing.TB) *Azure {
	t.Helper()
	a := &Azure{ClientID: "fake-client", ClientSecret: "fake-client-secret", IdentityHeader: "fake-identity-header",
		PageSize: 2}
	a.Server = httptest.NewTLSServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.Close)
	a.CertFile = filepath.Join(t.TempDir(), "azure-fake.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Certificate().Raw})
	if err := os.WriteFile(a.CertFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return a
}

// Put stores a secret with tags.
func (a *Azure) Put(name, value string, tags map[string]string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.secrets = append(a.secrets, azureSecret{name: name, value: value, tags: tags})
}

// SetHang makes every Key Vault request wait, unanswered, until its client
// gives up (on) or answers them again (off).
func (a *Azure) SetHang(on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hang = on
}

// Reads returns the number of reads of the secret name.
func (a *Azure) Reads(name string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reads[name]
}

// IdentityEndpoint is the managed identity endpoint, for IDENTITY_ENDPOINT.
func (a *Azure) IdentityEndpoint() string { return a.URL + "/msi/token" }

func (a *Azure) serve(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	a.mu.Lock()
	hang := a.hang && (p == "/secrets" || strings.HasPrefix(p, "/secrets/"))
	a.mu.Unlock()
	if hang {
		// The server notices that the client went away only once the
		// request body has been read.
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case p == "/"+AzureTenant+"/v2.0/.well-known/openid-configuration":
		base := a.URL + "/" + AzureTenant
		writeJSON(w, http.StatusOK, map[string]any{
			"token_endpoint": base + "/oauth2/v2.0/token", "authorization_endpoint": base + "/oauth2/v2.0/authorize",
			"issuer": base + "/v2.0", "tenant_region_scope": "NA",
		})
	case p == "/"+AzureTenant+"/oauth2/v2.0/token" && r.Method == http.MethodPost:
		if r.ParseForm() != nil || r.PostForm.Get("client_id") != a.ClientID ||
			r.PostForm.Get("client_secret") != a.ClientSecret ||
			!strings.Contains(r.PostForm.Get("scope"), "https://vault.azure.net/.default") {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client",
				"error_description": "AADSTS7000215: Invalid client secret provided."})
			return
		}
		a.TokenRequests++
		writeJSON(w, http.StatusOK, map[string]any{"token_type": "Bearer", "expires_in": 3600, "ext_expires_in": 3600,
			"access_token": azureToken})
	case p == "/msi/token":
		if r.Header.Get("X-IDENTITY-HEADER") != a.IdentityHeader || r.URL.Query().Get("resource") != "https://vault.azure.net" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
			return
		}
		a.TokenRequests++
		a.ManagedIdentityClientIDs = append(a.ManagedIdentityClientIDs, r.URL.Query().Get("client_id"))
		writeJSON(w, http.StatusOK, map[string]any{"access_token": azureToken, "expires_on": "4102444800",
			"resource": "https://vault.azure.net", "token_type": "Bearer"})
	case p == "/secrets" || strings.HasPrefix(p, "/secrets/"):
		if r.Header.Get("Authorization") != "Bearer "+azureToken {
			w.Header().Set("WWW-Authenticate", `Bearer authorization="https://login.microsoftonline.com/`+AzureTenant+
				`", resource="https://vault.azure.net"`)
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "Unauthorized",
				"message": "AKV10000: Request is missing a Bearer or PoP token."}})
			return
		}
		if p == "/secrets" {
			a.list(w, r)
			return
		}
		a.get(w, strings.Trim(strings.TrimPrefix(p, "/secrets/"), "/"))
	default:
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]string{"code": "NotFound", "message": p}})
	}
}

func (a *Azure) list(w http.ResponseWriter, r *http.Request) {
	start, _ := strconv.Atoi(r.URL.Query().Get("$skiptoken"))
	end := min(len(a.secrets), start+a.PageSize)
	var value []map[string]any
	for _, s := range a.secrets[start:end] {
		value = append(value, map[string]any{"id": a.URL + "/secrets/" + s.name, "tags": s.tags,
			"attributes": map[string]any{"enabled": true, "recoveryLevel": "Recoverable+Purgeable"}})
	}
	out := map[string]any{"value": value, "nextLink": nil}
	if end < len(a.secrets) {
		q := url.Values{"api-version": {r.URL.Query().Get("api-version")}, "$skiptoken": {strconv.Itoa(end)}}
		out["nextLink"] = a.URL + "/secrets?" + q.Encode()
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *Azure) get(w http.ResponseWriter, name string) {
	if a.reads == nil {
		a.reads = map[string]int{}
	}
	a.reads[name]++
	for _, s := range a.secrets {
		if s.name == name {
			writeJSON(w, http.StatusOK, map[string]any{"value": s.value, "id": a.URL + "/secrets/" + s.name + "/0123",
				"tags": s.tags, "attributes": map[string]any{"enabled": true}})
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]string{"code": "SecretNotFound",
		"message": "A secret with (name/id) " + name + " was not found in this key vault."}})
}
