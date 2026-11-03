// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package secretstest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// The environment of the tests against the emulators of GCP Secret Manager
// (floci-gcp, an http://host:port endpoint that takes no credentials) and
// Azure Key Vault (Lowkey Vault: its vault URL, https://localhost:port with
// relaxed port matching, and its managed-identity token endpoint,
// http://host:port/metadata/identity/oauth2/token). make test-cloud starts
// both in Docker.
const (
	EnvGCPEmulator   = "REMOTESIGNER_TEST_GCP_ENDPOINT"
	EnvAzureVault    = "REMOTESIGNER_TEST_AZURE_VAULT"
	EnvAzureIdentity = "REMOTESIGNER_TEST_AZURE_IDENTITY_ENDPOINT"
)

// GCPEmulator returns the endpoint of the Secret Manager emulator, or skips
// the test (fails it under REMOTESIGNER_TEST_CLOUD_REQUIRED=1).
func GCPEmulator(t testing.TB) string {
	t.Helper()
	return CloudEnv(t, "a GCP Secret Manager emulator: make test-cloud", EnvGCPEmulator)[0]
}

// PutGCPSecret creates the secret name in project on the emulator with the
// labels and adds each version in order, the last one being the latest; the
// secret is deleted when the test ends. It returns the secret's resource
// name.
func PutGCPSecret(t testing.TB, endpoint, project, name string, labels map[string]string, versions ...string) string {
	t.Helper()
	ctx := context.Background()
	sm, err := secretmanager.NewClient(ctx, option.WithEndpoint(strings.TrimPrefix(endpoint, "http://")),
		option.WithoutAuthentication(), option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sm.Close() }()
	s, err := sm.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{Parent: "projects/" + project, SecretId: name,
		Secret: &secretmanagerpb.Secret{Labels: labels, Replication: &secretmanagerpb.Replication{
			Replication: &secretmanagerpb.Replication_Automatic_{Automatic: &secretmanagerpb.Replication_Automatic{}}}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range versions {
		if _, err := sm.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{Parent: s.Name,
			Payload: &secretmanagerpb.SecretPayload{Data: []byte(v)}}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		sm, err := secretmanager.NewClient(context.Background(), option.WithEndpoint(strings.TrimPrefix(endpoint, "http://")),
			option.WithoutAuthentication(), option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
		if err == nil {
			_ = sm.DeleteSecret(context.Background(), &secretmanagerpb.DeleteSecretRequest{Name: s.Name})
			_ = sm.Close()
		}
	})
	return s.Name
}

// LowkeyVault returns the emulator's vault URL and token endpoint, and a PEM
// file of the certificate it serves, for the trust-certificate override; or
// skips the test (fails it under REMOTESIGNER_TEST_CLOUD_REQUIRED=1).
func LowkeyVault(t testing.TB) (vaultURL, identity, certFile string) {
	t.Helper()
	env := CloudEnv(t, "Lowkey Vault: make test-cloud", EnvAzureVault, EnvAzureIdentity)
	vaultURL, identity = env[0], env[1]
	u, err := url.Parse(vaultURL)
	if err != nil {
		t.Fatal(err)
	}
	// The certificate is read without verification, to be trusted from now on.
	conn, err := tls.Dial("tcp", u.Host, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // see above
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	certFile = filepath.Join(t.TempDir(), "lowkey-vault.pem")
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: conn.ConnectionState().PeerCertificates[0].Raw})
	if err := os.WriteFile(certFile, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	return vaultURL, identity, certFile
}

// PutLowkeySecret sets a new version of the secret name, with tags, through
// the Key Vault REST API, which the emulator serves to any bearer token. The
// secret is deleted when the test ends.
func PutLowkeySecret(t testing.TB, vaultURL, certFile, name, value string, tags map[string]string) {
	t.Helper()
	data, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		t.Fatal("no certificate in " + certFile)
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	do := func(method string, body []byte) (int, error) {
		req, err := http.NewRequest(method, vaultURL+"/secrets/"+name+"?api-version=7.4", bytes.NewReader(body))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer emulator")
		resp, err := hc.Do(req)
		if err != nil {
			return 0, err
		}
		_ = resp.Body.Close()
		return resp.StatusCode, nil
	}
	body, _ := json.Marshal(map[string]any{"value": value, "tags": tags})
	if code, err := do(http.MethodPut, body); err != nil || code != http.StatusOK {
		t.Fatalf("set the Lowkey Vault secret %s: HTTP %d %v", name, code, err)
	}
	t.Cleanup(func() { _, _ = do(http.MethodDelete, nil) })
}
