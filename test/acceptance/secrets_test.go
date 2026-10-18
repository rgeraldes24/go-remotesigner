// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets/secretstest"
)

// seedKey returns the hex seed and canonical identifier of the key whose
// seed is 48 bytes of b.
func seedKey(t *testing.T, b byte) (seed, pubkey string) {
	t.Helper()
	var s [mldsa87.SeedSize]byte
	for i := range s {
		s[i] = b
	}
	k, err := mldsa87.FromSeed48(&s)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Zeroize()
	pk := k.PublicKey()
	return "0x" + hex.EncodeToString(s[:]), "0x" + hex.EncodeToString(pk[:])
}

// awsIsolation keeps the signer's AWS SDK away from the developer's AWS
// configuration and the instance metadata service.
func awsIsolation(t *testing.T) []string {
	dir := t.TempDir()
	return []string{"AWS_CONFIG_FILE=" + filepath.Join(dir, "config"),
		"AWS_SHARED_CREDENTIALS_FILE=" + filepath.Join(dir, "credentials"), "AWS_EC2_METADATA_DISABLED=true",
		"AWS_PROFILE=", "AWS_REGION=", "AWS_ENDPOINT_URL="}
}

// healthChecks returns the /healthcheck checks by id.
func (s *signer) healthChecks() (int, map[string]string) {
	s.t.Helper()
	code, body, _ := s.do(request{path: "/healthcheck", token: s.signToken()})
	var h struct {
		Checks []struct {
			ID, Status string
			Data       map[string]any
		}
	}
	if err := json.Unmarshal([]byte(body), &h); err != nil {
		s.t.Fatalf("healthcheck %d %s: %v", code, body, err)
	}
	out := map[string]string{}
	for _, c := range h.Checks {
		out[c.ID] = fmt.Sprintf("%s %v/%v", c.Status, c.Data["keys-loaded"], c.Data["error-count"])
	}
	return code, out
}

func writeDoc(t *testing.T, dir, name, doc string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The built binary loads seeds from every secret store, through the
// key-config types and the bulk-loading flags as an operator writes them,
// against the in-process fakes of Vault, AWS Secrets Manager, GCP Secret
// Manager and Azure Key Vault (Azure through Web3Signer's three overrides,
// GCP through --Xgcp-endpoint-override). Every key signs, every health
// check reports its keys, and the log carries no credential and no seed.
func TestSecretStoreSources(t *testing.T) {
	seeds, pubkeys := map[byte]string{}, map[byte]string{}
	for b := byte(1); b <= 8; b++ {
		seeds[b], pubkeys[b] = seedKey(t, b)
	}
	v := secretstest.NewVault(t, false)
	v.Put("/v1/secret/data/one", map[string]any{"value": seeds[1]})
	az := secretstest.NewAzure(t)
	az.Put("two", seeds[2], nil)
	az.Put("bulk-8", seeds[8], map[string]string{"role": "validator"})
	az.Put("other", seeds[3], map[string]string{"role": "other"})
	g := secretstest.NewGCP(t)
	g.Put("p", "three", []byte(seeds[3]+"\n"), map[string]string{"role": "single"})
	g.Put("p", "bulk-7", []byte(seeds[7]), map[string]string{"role": "validator"})
	a := secretstest.NewAWS(t)
	a.Put("single/four", seeds[4], nil)
	a.Put("validators/5-6", seeds[5]+"\n"+seeds[6]+"\n", nil)

	keys := t.TempDir()
	vu, _ := url.Parse(v.URL)
	writeDoc(t, keys, "vault.yaml", fmt.Sprintf("type: hashicorp\nkeyType: ML_DSA_87\nserverHost: %s\nserverPort: %s\n"+
		"keyPath: /v1/secret/data/one\ntoken: %s\n", vu.Hostname(), vu.Port(), v.Token))
	writeDoc(t, keys, "azure.yaml", fmt.Sprintf("type: azure-secret\nvaultName: fake\nsecretName: two\nclientId: %s\n"+
		"clientSecret: %s\ntenantId: %s\nendpointOverride: %s\nauthorityHostOverride: %s\ntrustCertificateOverride: %s\n",
		az.ClientID, az.ClientSecret, secretstest.AzureTenant, az.URL, az.URL, az.CertFile))
	writeDoc(t, keys, "gcp.yaml", "type: gcp-secret\nprojectId: p\nsecretName: three\nendpointOverride: "+g.Endpoint+"\n")
	writeDoc(t, keys, "aws.yaml", "type: aws-secret\nregion: us-east-1\nsecretName: single/four\naccessKeyId: AKIDDOC\n"+
		"secretAccessKey: aws-doc-secret\nendpointOverride: "+a.URL+"\n")

	// The credentials of the bulk loaders come from the environment.
	env := append(awsIsolation(t), "REMOTESIGNER_CONSENSUS_AWS_SECRETS_SECRET_ACCESS_KEY=aws-bulk-secret",
		"REMOTESIGNER_CONSENSUS_AZURE_CLIENT_SECRET="+az.ClientSecret)
	s := start(t, options{keys: keys, env: env, consensus: []string{
		"--aws-secrets-enabled", "--aws-secrets-access-key-id=AKIDBULK", "--aws-secrets-region=us-east-1",
		"--aws-endpoint-override=" + a.URL, "--aws-secrets-prefixes-filter=validators/",
		"--gcp-secrets-enabled", "--gcp-project-id=p", "--gcp-secrets-filter=labels.role=validator",
		"--Xgcp-endpoint-override=" + g.Endpoint,
		"--azure-vault-enabled", "--azure-vault-name=fake", "--azure-client-id=" + az.ClientID,
		"--azure-tenant-id=" + secretstest.AzureTenant, "--azure-tags=role=validator",
		"--Xazure-endpoint-override=" + az.URL, "--Xazure-authority-host-override=" + az.URL,
		"--Xazure-trust-certificate-override=" + az.CertFile,
	}})
	s.waitReadyWithin(time.Minute)
	s.waitReloadStatus("completed", time.Minute)

	got := s.publicKeys()
	for b, pk := range pubkeys {
		if !slices.Contains(got, pk) {
			t.Errorf("key %d is not loaded", b)
		}
	}
	if len(got) != 8 {
		t.Errorf("%d keys loaded, want 8", len(got))
	}
	body := selectionProof(t)
	for b, pk := range pubkeys {
		if code, out := s.post("/api/v1/consensus/sign/"+pk, s.signToken(), body); code != 200 {
			t.Errorf("sign with key %d: %d %s", b, code, out)
		}
	}
	code, checks := s.healthChecks()
	want := map[string]string{
		"keys-check/config-files-loading": "UP 4/0", "keys-check/aws-bulk-loading": "UP 2/0",
		"keys-check/gcp-bulk-loading": "UP 1/0", "keys-check/azure-bulk-loading": "UP 1/0",
	}
	for id, w := range want {
		if checks[id] != w {
			t.Errorf("%s: %s, want %s", id, checks[id], w)
		}
	}
	if code != 200 {
		t.Errorf("/healthcheck %d", code)
	}
	if !slices.Contains(a.AccessKeys, "AKIDBULK") || !slices.Contains(a.AccessKeys, "AKIDDOC") {
		t.Errorf("AWS requests signed with %v", a.AccessKeys)
	}
	out := s.output.String()
	for _, secret := range []string{v.Token, az.ClientSecret, "aws-doc-secret", "aws-bulk-secret",
		strings.TrimPrefix(seeds[1], "0x"), strings.TrimPrefix(seeds[5], "0x")} {
		if strings.Contains(out, secret) {
			t.Errorf("the log carries a credential or a seed: %q", secret)
		}
	}
}

// The environment of the tests against a Vault dev server and LocalStack;
// make test-cloud starts both in Docker, the CI job cloud-secrets runs both
// as service containers.
const (
	envVaultAddr  = "REMOTESIGNER_TEST_VAULT_ADDR"
	envVaultToken = "REMOTESIGNER_TEST_VAULT_TOKEN"
	envLocalStack = "REMOTESIGNER_TEST_AWS_ENDPOINT"
)

// The built binary against a real Vault dev server and LocalStack's
// Secrets Manager: a hashicorp document, an aws-secret document and the
// AWS bulk loader. A secret that turns bad keeps its keys and turns its
// health check DOWN; a deleted secret's keys are evicted on reload.
func TestSecretStoresDevServers(t *testing.T) {
	vaultAddr, vaultToken, endpoint := os.Getenv(envVaultAddr), os.Getenv(envVaultToken), os.Getenv(envLocalStack)
	if vaultAddr == "" || vaultToken == "" || endpoint == "" {
		t.Skipf("set %s, %s and %s to run against a Vault dev server and LocalStack (make test-cloud)",
			envVaultAddr, envVaultToken, envLocalStack)
	}
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	name := "remotesigner-" + hex.EncodeToString(rnd[:])
	seeds, pubkeys := map[byte]string{}, map[byte]string{}
	for b := byte(0x41); b <= 0x44; b++ {
		seeds[b], pubkeys[b] = seedKey(t, b)
	}

	// Vault: one KV version 2 secret.
	vu, err := url.Parse(vaultAddr)
	if err != nil {
		t.Fatal(err)
	}
	reqBody, _ := json.Marshal(map[string]any{"data": map[string]any{"value": seeds[0x41]}})
	req, _ := http.NewRequest(http.MethodPost, vaultAddr+"/v1/secret/data/"+name, bytes.NewReader(reqBody))
	req.Header.Set("X-Vault-Token", vaultToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("write the Vault secret: HTTP %d", resp.StatusCode)
	}

	// LocalStack: one secret for a document, two for the bulk loader.
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")))
	if err != nil {
		t.Fatal(err)
	}
	sm := secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) { o.BaseEndpoint = aws.String(endpoint) })
	put := func(secret, value string) {
		t.Helper()
		if _, err := sm.CreateSecret(ctx, &secretsmanager.CreateSecretInput{Name: aws.String(secret),
			SecretString: aws.String(value)}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = sm.DeleteSecret(context.Background(), &secretsmanager.DeleteSecretInput{SecretId: aws.String(secret),
				ForceDeleteWithoutRecovery: aws.Bool(true)})
		})
	}
	put(name+"/single", seeds[0x42])
	put(name+"/bulk/a", seeds[0x43]+"\n")
	put(name+"/bulk/b", seeds[0x44])

	keys := t.TempDir()
	writeDoc(t, keys, "vault.yaml", fmt.Sprintf("type: hashicorp\nserverHost: %s\nserverPort: %s\nkeyPath: /v1/secret/data/%s\n"+
		"token: %s\n", vu.Hostname(), vu.Port(), name, vaultToken))
	writeDoc(t, keys, "aws.yaml", fmt.Sprintf("type: aws-secret\nregion: us-east-1\nsecretName: %s/single\naccessKeyId: test\n"+
		"secretAccessKey: test\nendpointOverride: %s\n", name, endpoint))
	s := start(t, options{keys: keys, env: awsIsolation(t), consensus: []string{
		"--aws-secrets-enabled", "--aws-secrets-access-key-id=test", "--aws-secrets-secret-access-key=test",
		"--aws-secrets-region=us-east-1", "--aws-endpoint-override=" + endpoint,
		"--aws-secrets-prefixes-filter=" + name + "/bulk/",
	}})
	s.waitReadyWithin(time.Minute)
	s.waitReloadStatus("completed", time.Minute)
	got := s.publicKeys()
	for b, pk := range pubkeys {
		if !slices.Contains(got, pk) {
			t.Errorf("key %#x is not loaded", b)
		}
	}
	if _, checks := s.healthChecks(); checks["keys-check/config-files-loading"] != "UP 2/0" ||
		checks["keys-check/aws-bulk-loading"] != "UP 2/0" {
		t.Fatalf("health: %v", checks)
	}

	// A bulk secret with a bad line keeps its key; a deleted one is evicted.
	if _, err := sm.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: aws.String(name + "/bulk/a"),
		SecretString: aws.String(seeds[0x43] + "\n0x" + strings.Repeat("ab", 32))}); err != nil {
		t.Fatal(err)
	}
	if _, err := sm.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{SecretId: aws.String(name + "/bulk/b"),
		ForceDeleteWithoutRecovery: aws.Bool(true)}); err != nil {
		t.Fatal(err)
	}
	s.reload("completed_with_errors", time.Minute)
	got = s.publicKeys()
	if !slices.Contains(got, pubkeys[0x43]) || slices.Contains(got, pubkeys[0x44]) {
		t.Fatalf("after the reload: key 0x43 loaded %v, deleted key 0x44 loaded %v",
			slices.Contains(got, pubkeys[0x43]), slices.Contains(got, pubkeys[0x44]))
	}
	if _, checks := s.healthChecks(); checks["keys-check/aws-bulk-loading"] != "DOWN 1/1" {
		t.Fatalf("health after the reload: %v", checks)
	}
}
