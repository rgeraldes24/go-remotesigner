// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// The secret-store tests drive the default flavour, which links the cloud
// SDKs, and use the SDKs' fakes.

//go:build !noexecution

package acceptance

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
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

	// The credentials of the bulk loaders come from their -file flags.
	creds := t.TempDir()
	writeDoc(t, creds, "aws-key", "aws-bulk-secret\n")
	writeDoc(t, creds, "azure-secret", az.ClientSecret+"\n")
	s := start(t, options{keys: keys, env: awsIsolation(t), consensus: []string{
		"--aws-secrets-secret-access-key-file=" + filepath.Join(creds, "aws-key"),
		"--azure-client-secret-file=" + filepath.Join(creds, "azure-secret"),
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
	if strings.Contains(out, "deprecated plain secret flag") {
		t.Errorf("the -file flags brought a deprecation warning")
	}
	// The process's command line, which every local user can read, names
	// the credential files only.
	cmdline := commandLine(t, s.cmd.Process.Pid)
	if !strings.Contains(cmdline, "--azure-client-secret-file=") ||
		strings.Contains(cmdline, az.ClientSecret) || strings.Contains(cmdline, "aws-bulk-secret") {
		t.Errorf("the command line carries a credential: %s", cmdline)
	}
}

// commandLine returns the command line of process pid as ps shows it to any
// local user.
func commandLine(t *testing.T, pid int) string {
	t.Helper()
	out, err := exec.Command("ps", "-ww", "-o", "command=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		t.Fatalf("ps: %v", err)
	}
	return string(out)
}

// The plain credential flags, kept because Web3Signer has them, still work,
// and the signer warns at startup: each is deprecated in favour of its
// -file flag, and a value on the command line can be read by every local
// user. A config file that sets one is a secret file: readable by its group
// or other users, it refuses the start under --strict-file-permissions.
func TestPlainSecretFlags(t *testing.T) {
	seed, pubkey := seedKey(t, 9)
	az := secretstest.NewAzure(t)
	az.Put("bulk-9", seed, map[string]string{"role": "validator"})
	azure := []string{"--azure-vault-enabled", "--azure-vault-name=fake", "--azure-client-id=" + az.ClientID,
		"--azure-tenant-id=" + secretstest.AzureTenant, "--Xazure-endpoint-override=" + az.URL,
		"--Xazure-authority-host-override=" + az.URL, "--Xazure-trust-certificate-override=" + az.CertFile}

	s := start(t, options{consensus: append([]string{"--azure-client-secret=" + az.ClientSecret}, azure...)})
	s.waitReadyWithin(time.Minute)
	s.waitReloadStatus("completed", time.Minute)
	if got := s.publicKeys(); !slices.Equal(got, []string{pubkey}) {
		t.Fatalf("keys %v, want the Azure key", got)
	}
	out := s.output.String()
	for _, want := range []string{"A deprecated plain secret flag is set", "flag=--azure-client-secret",
		"instead=--azure-client-secret-file", "A secret is on the command line"} {
		if !strings.Contains(out, want) {
			t.Errorf("the log lacks %q", want)
		}
	}
	if strings.Contains(out, az.ClientSecret) {
		t.Errorf("the log carries the client secret")
	}

	config := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(config, []byte("consensus:\n  azure-client-secret: "+az.ClientSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(config, 0o644); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"--config-file=" + config}, defaultArgs(t, t.TempDir(), t.TempDir(), options{consensus: azure})...)
	got, err := exec.Command(binary, args...).CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 || !strings.Contains(string(got),
		"refusing to start: --config-file holds --azure-client-secret, so it is a secret file") {
		t.Fatalf("a group-readable config file with a secret: %v\n%s", err, got)
	}
	// The file holds the secret even when the environment gives the flag
	// the value that is used. A signer that starts instead is stopped.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = append(os.Environ(), "REMOTESIGNER_CONSENSUS_AZURE_CLIENT_SECRET="+az.ClientSecret)
	got, err = cmd.CombinedOutput()
	if !errors.As(err, &ee) || ee.ExitCode() != 1 || !strings.Contains(string(got),
		"refusing to start: --config-file holds --azure-client-secret, so it is a secret file") {
		t.Fatalf("a group-readable config file with a secret the environment overrides: %v\n%s", err, got)
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
	env := secretstest.CloudEnv(t, "a Vault dev server and LocalStack: make test-cloud", envVaultAddr, envVaultToken,
		envLocalStack)
	vaultAddr, vaultToken, endpoint := env[0], env[1], env[2]
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

// The built binary against the emulators of GCP Secret Manager (floci-gcp)
// and Azure Key Vault (Lowkey Vault, with its managed-identity token
// endpoint as App Service's IDENTITY_ENDPOINT): a gcp-secret and an
// azure-secret document, and both bulk loaders. A rotated secret serves its
// latest version, and the Azure loader selects by tags. floci-gcp ignores
// ListSecrets' filter, so the GCP loader reads a project of its own whole.
func TestSecretStoresEmulators(t *testing.T) {
	gcp := secretstest.GCPEmulator(t)
	vaultURL, identity, certFile := secretstest.LowkeyVault(t)
	var rnd [5]byte
	_, _ = rand.Read(rnd[:])
	run := "remotesigner-" + hex.EncodeToString(rnd[:])
	seeds, pubkeys := map[byte]string{}, map[byte]string{}
	for b := byte(0x51); b <= 0x56; b++ {
		seeds[b], pubkeys[b] = seedKey(t, b)
	}
	secretstest.PutGCPSecret(t, gcp, run, "single", nil, "not a seed", seeds[0x51]+"\n")
	secretstest.PutGCPSecret(t, gcp, run+"-bulk", "a", map[string]string{"role": "validator"}, seeds[0x52])
	secretstest.PutGCPSecret(t, gcp, run+"-bulk", "b", nil, seeds[0x53]+"\n")
	secretstest.PutLowkeySecret(t, vaultURL, certFile, run+"-single", seeds[0x54], nil)
	secretstest.PutLowkeySecret(t, vaultURL, certFile, run+"-bulk", seeds[0x55]+"\n"+seeds[0x56]+"\n",
		map[string]string{"run": run})
	secretstest.PutLowkeySecret(t, vaultURL, certFile, run+"-other", seeds[0x51], map[string]string{"run": "other"})

	keys := t.TempDir()
	writeDoc(t, keys, "gcp.yaml", fmt.Sprintf("type: gcp-secret\nprojectId: %s\nsecretName: single\nendpointOverride: %s\n",
		run, gcp))
	writeDoc(t, keys, "azure.yaml", fmt.Sprintf("type: azure-secret\nvaultName: lowkey\nsecretName: %s-single\n"+
		"authenticationMode: SYSTEM_ASSIGNED_MANAGED_IDENTITY\nendpointOverride: %s\ntrustCertificateOverride: %s\n",
		run, vaultURL, certFile))
	s := start(t, options{keys: keys, env: []string{"IDENTITY_ENDPOINT=" + identity, "IDENTITY_HEADER=header"},
		consensus: []string{
			"--gcp-secrets-enabled", "--gcp-project-id=" + run + "-bulk", "--Xgcp-endpoint-override=" + gcp,
			"--azure-vault-enabled", "--azure-vault-name=lowkey", "--azure-vault-auth-mode=SYSTEM_ASSIGNED_MANAGED_IDENTITY",
			"--azure-tags=run=" + run, "--Xazure-endpoint-override=" + vaultURL,
			"--Xazure-trust-certificate-override=" + certFile,
		}})
	s.waitReadyWithin(time.Minute)
	s.waitReloadStatus("completed", time.Minute)
	got := s.publicKeys()
	for b, pk := range pubkeys {
		if !slices.Contains(got, pk) {
			t.Errorf("key %#x is not loaded", b)
		}
	}
	if len(got) != len(pubkeys) {
		t.Errorf("%d keys loaded, want %d", len(got), len(pubkeys))
	}
	if _, checks := s.healthChecks(); checks["keys-check/config-files-loading"] != "UP 2/0" ||
		checks["keys-check/gcp-bulk-loading"] != "UP 2/0" || checks["keys-check/azure-bulk-loading"] != "UP 2/0" {
		t.Fatalf("health: %v", checks)
	}
	body := selectionProof(t)
	for b, pk := range pubkeys {
		if code, out := s.post("/api/v1/consensus/sign/"+pk, s.signToken(), body); code != 200 {
			t.Errorf("sign with key %#x: %d %s", b, code, out)
		}
	}
}
