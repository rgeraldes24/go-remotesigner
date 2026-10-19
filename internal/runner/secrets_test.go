// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package runner

import (
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

	"github.com/rgeraldes24/go-remotesigner/internal/api/ops"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets/secretstest"
	"github.com/rgeraldes24/go-remotesigner/internal/server/tlsconf"
)

// hashicorpDoc is a hashicorp key-config document for the secret at path
// on the fake v.
func hashicorpDoc(t *testing.T, v *secretstest.Vault, path string) string {
	t.Helper()
	u, err := url.Parse(v.URL)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("type: hashicorp\nserverHost: %s\nserverPort: %s\nkeyPath: %s\ntoken: %s\ntimeout: 5000\n",
		u.Hostname(), u.Port(), path, v.Token)
}

// Each load builds the key-config documents' store clients again, as
// Web3Signer does, so that a rewritten Vault known-servers file applies to
// the next reload that fetches the document: a pin added makes it load, a
// pin removed makes it fail, and it keeps its key.
func TestRunVaultKnownServersRotation(t *testing.T) {
	cfg := baseConfig(t)
	v := secretstest.NewVault(t, true)
	v.Put("/v1/secret/data/k4", map[string]any{"value": seedHex(4)})
	u, err := url.Parse(v.URL)
	if err != nil {
		t.Fatal(err)
	}
	pin := func(content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(cfg.KeyConfigPath, "known_servers"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	doc := func(extra string) {
		t.Helper()
		body := fmt.Sprintf("type: hashicorp\nserverHost: %s\nserverPort: %s\nkeyPath: /v1/secret/data/k4\ntoken: %s\n"+
			"tlsEnabled: true\ntlsKnownServersPath: known_servers\n%s", u.Hostname(), u.Port(), v.Token, extra)
		if err := os.WriteFile(filepath.Join(cfg.KeyConfigPath, "vault.yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pin(u.Host + " " + tlsconf.FingerprintOf([]byte("the previous certificate")).String() + "\n")
	doc("")
	r := start(t, cfg)
	r.waitReady(t)
	r.waitReload(t, "completed_with_errors")
	check := func(want string) {
		t.Helper()
		_, checks := r.health(t)
		c := checks[ops.CheckConfigFilesLoading]
		if got := c["status"].(string) + " " + fmt.Sprint(c["data"]); got != want {
			t.Errorf("%s: %s, want %s", ops.CheckConfigFilesLoading, got, want)
		}
	}
	check("DOWN map[error-count:1 keys-loaded:0]")

	pin(u.Host + " " + tlsconf.FingerprintOf(v.Certificate().Raw).String() + "\n")
	r.reload(t, "completed")
	check("UP map[error-count:0 keys-loaded:1]")

	pin("# revoked\n")
	doc("keyName: value\n") // changed, so fetched again
	r.reload(t, "completed_with_errors")
	check("DOWN map[error-count:1 keys-loaded:1]")
	sel := goldenCase(t, "minimal", signingroot.AggregationSlot, "typical")
	if code, body := r.post(t, "/api/v1/consensus/sign/"+pubkeyHex(t, 4), r.sign, sel.RequestJSON); code != 200 {
		t.Fatalf("the failed document's key: %d %s", code, body)
	}
}

// The secret stores as key sources, with Web3Signer's load order and
// health checks and the rule that a load error is never a removal: a
// HashiCorp document and a file-raw document in the key-config directory,
// and the AWS Secrets Manager bulk loader. A bad line or a listing failure
// keeps the keys the secrets had and turns the AWS check DOWN; a secret that
// is gone evicts its keys without disabling them; the key-config files win
// a key that the bulk loader also lists.
func TestRunSecretStoreSources(t *testing.T) {
	isolateAWS(t)
	cfg := baseConfig(t)
	v := secretstest.NewVault(t, false)
	v.Put("/v1/secret/data/k4", map[string]any{"value": seedHex(4)})
	aws := secretstest.NewAWS(t)
	aws.Put("validators/a", seedHex(1)+"\n"+seedHex(2)+"\n", nil)
	aws.Put("validators/b", seedHex(3), nil)
	aws.Put("other/c", seedHex(5), nil)
	writeKeyFile(t, cfg.KeyConfigPath, "raw.yaml", 3)
	vaultFile := filepath.Join(cfg.KeyConfigPath, "vault.yaml")
	if err := os.WriteFile(vaultFile, []byte(hashicorpDoc(t, v, "/v1/secret/data/k4")), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Consensus.SecretStores = secretStoresConfig(aws.URL)
	r := start(t, cfg)
	r.waitReady(t)

	sel := goldenCase(t, "minimal", signingroot.AggregationSlot, "typical")
	signs := func(seed byte) {
		t.Helper()
		if code, body := r.post(t, "/api/v1/consensus/sign/"+pubkeyHex(t, seed), r.sign, sel.RequestJSON); code != 200 {
			t.Fatalf("sign with key %d: %d %s", seed, code, body)
		}
	}
	listed := func() string {
		t.Helper()
		_, body := r.do(t, http.MethodGet, "/api/v1/consensus/publicKeys", r.sign)
		return string(body)
	}
	health := func(wantCode int, want map[string]string) {
		t.Helper()
		code, checks := r.health(t)
		for id, w := range want {
			if got := checks[id]["status"].(string) + " " + fmt.Sprint(checks[id]["data"]); got != w {
				t.Errorf("%s: %s, want %s", id, got, w)
			}
		}
		if code != wantCode {
			t.Errorf("/healthcheck %d, want %d", code, wantCode)
		}
	}
	for _, seed := range []byte{1, 2, 3, 4} {
		signs(seed)
	}
	if strings.Contains(listed(), pubkeyHex(t, 5)) {
		t.Fatal("a secret outside the prefix filter was loaded")
	}
	health(200, map[string]string{
		ops.CheckConfigFilesLoading: "UP map[error-count:0 keys-loaded:2]",
		ops.CheckAWSBulkLoading:     "UP map[error-count:0 keys-loaded:2]",
	})

	// A bad line fails its secret, which keeps its keys.
	aws.Put("validators/a", seedHex(1)+"\n0x"+strings.Repeat("ab", 32)+"\n", nil)
	r.reload(t, "completed_with_errors")
	signs(1)
	signs(2)
	health(503, map[string]string{ops.CheckAWSBulkLoading: "DOWN map[error-count:1 keys-loaded:2]"})

	// A listing failure keeps every key of the loader, and counts one error.
	aws.Put("validators/a", seedHex(1)+"\n"+seedHex(2)+"\n", nil)
	aws.SetListError("AccessDeniedException")
	r.reload(t, "completed_with_errors")
	signs(1)
	health(503, map[string]string{ops.CheckAWSBulkLoading: "DOWN map[error-count:1 keys-loaded:2]"})
	aws.SetListError("")

	// A Vault secret that cannot be read keeps its key; the file is
	// fetched again because it changed.
	v.Delete("/v1/secret/data/k4")
	if err := os.WriteFile(vaultFile, []byte(hashicorpDoc(t, v, "/v1/secret/data/k4")+"keyName: value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.reload(t, "completed_with_errors")
	signs(4)
	health(503, map[string]string{
		ops.CheckConfigFilesLoading: "DOWN map[error-count:1 keys-loaded:2]",
		ops.CheckAWSBulkLoading:     "UP map[error-count:0 keys-loaded:2]",
	})

	// Gone: the AWS secret and the Vault document. Their keys are evicted.
	aws.Delete("validators/a")
	if err := os.Remove(vaultFile); err != nil {
		t.Fatal(err)
	}
	r.reload(t, "completed")
	s := listed()
	if strings.Contains(s, pubkeyHex(t, 1)) || strings.Contains(s, pubkeyHex(t, 2)) || strings.Contains(s, pubkeyHex(t, 4)) {
		t.Fatal("the keys of a deleted secret are still listed")
	}
	signs(3)
	health(200, map[string]string{
		ops.CheckConfigFilesLoading: "UP map[error-count:0 keys-loaded:1]",
		ops.CheckAWSBulkLoading:     "UP map[error-count:0 keys-loaded:0]",
	})
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	for _, seed := range []byte{1, 2, 4} {
		if st := storeStatus(t, cfg.SlashingProtectionDB(), pubkeyHex(t, seed)); !st.Registered || !st.Enabled {
			t.Errorf("evicted key %d: slashing-protection row %+v, want registered and enabled", seed, st)
		}
	}
}

// Every source kind loads in Web3Signer's order: the key-config files,
// Azure Key Vault, the keystores, AWS Secrets Manager, then GCP Secret
// Manager. A key that two kinds provide is loaded from the earlier one, so
// each health check counts the one key that only its kind wins, and
// /healthcheck lists the checks in that order.
func TestRunSecretStoreLoadOrder(t *testing.T) {
	isolateAWS(t)
	cfg := baseConfig(t)
	ks := newKeystoreFixture(t)
	cfg.Consensus.Keystores.Path, cfg.Consensus.Keystores.PasswordsPath = ks.dir, ks.passwords
	kHex := func(i int) string { return "0x" + hex.EncodeToString(keystoretest.Seed(t.Name(), i)[:]) }
	// Keystore key 1 is also in AWS and GCP, and keystore key 2 in Azure;
	// seed 5 is in a key-config file and in Azure, seed 3 in AWS and GCP,
	// and seed 4 in GCP only.
	pk1, _ := ks.add(t, 1)
	pk2, _ := ks.add(t, 2)
	writeKeyFile(t, cfg.KeyConfigPath, "raw.yaml", 5)
	az := secretstest.NewAzure(t)
	az.Put("k2", kHex(2), nil)
	az.Put("s5", seedHex(5), nil)
	aws := secretstest.NewAWS(t)
	aws.Put("validators/k1", kHex(1), nil)
	aws.Put("validators/s3", seedHex(3), nil)
	g := secretstest.NewGCP(t)
	g.Put("p", "k1", []byte(kHex(1)), nil)
	g.Put("p", "s3", []byte(seedHex(3)), nil)
	g.Put("p", "s4", []byte(seedHex(4)), nil)
	cfg.Consensus.SecretStores = secretStoresConfig(aws.URL)
	cfg.Consensus.SecretStores.Azure = &secrets.AzureBulk{AzureVault: secrets.AzureVault{
		AuthMode: secrets.AzureClientSecret, VaultName: "fake", ClientID: az.ClientID, TenantID: secretstest.AzureTenant,
		ClientSecret: []byte(az.ClientSecret), Timeout: 10 * time.Second, EndpointOverride: az.URL,
		AuthorityHostOverride: az.URL, TrustCertificateOverride: az.CertFile}}
	cfg.Consensus.SecretStores.GCP = &secrets.GCPBulk{ProjectID: "p", EndpointOverride: g.Endpoint}

	r := start(t, cfg)
	r.waitReady(t)
	r.waitReload(t, "completed")
	_, body := r.do(t, http.MethodGet, "/api/v1/consensus/publicKeys", r.sign)
	for _, pk := range []string{pk1, pk2, pubkeyHex(t, 3), pubkeyHex(t, 4), pubkeyHex(t, 5)} {
		if !strings.Contains(string(body), pk) {
			t.Errorf("key %s… is not loaded", pk[:10])
		}
	}
	order := []string{ops.CheckConfigFilesLoading, ops.CheckAzureBulkLoading, ops.CheckKeystoresBulkLoading,
		ops.CheckAWSBulkLoading, ops.CheckGCPBulkLoading}
	code, checks := r.health(t)
	for _, id := range order {
		if got := checks[id]["status"].(string) + " " + fmt.Sprint(checks[id]["data"]); got != "UP map[error-count:0 keys-loaded:1]" {
			t.Errorf("%s: %s, want UP with the one key only it provides", id, got)
		}
	}
	if code != http.StatusOK {
		t.Errorf("/healthcheck %d", code)
	}
	_, raw := r.do(t, http.MethodGet, "/healthcheck", r.sign)
	var h struct{ Checks []struct{ ID string } }
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range h.Checks {
		if slices.Contains(order, c.ID) {
			ids = append(ids, c.ID)
		}
	}
	if !slices.Equal(ids, order) {
		t.Errorf("keys-check order %v, want %v", ids, order)
	}
}

// A store that stops answering cannot hold a reload past --reload-timeout:
// the reload completes with errors, the bulk loader keeps its keys, which
// still sign, and its check is DOWN until the store answers again. GCP's
// calls carry the reload's deadline into the SDK, which then ignores its
// own call timeout; the reload is bounded all the same.
func TestRunSecretStoreReloadTimeout(t *testing.T) {
	for _, tt := range []struct {
		kind, check string
		setup       func(t *testing.T, cfg *config.Config) (hang func(bool))
	}{
		{secrets.KindAWS, ops.CheckAWSBulkLoading, func(t *testing.T, cfg *config.Config) func(bool) {
			aws := secretstest.NewAWS(t)
			aws.Put("validators/a", seedHex(1), nil)
			cfg.Consensus.SecretStores = secretStoresConfig(aws.URL)
			return aws.SetHang
		}},
		{secrets.KindGCP, ops.CheckGCPBulkLoading, func(t *testing.T, cfg *config.Config) func(bool) {
			g := secretstest.NewGCP(t)
			g.Put("p", "a", []byte(seedHex(1)), nil)
			cfg.Consensus.SecretStores = config.SecretStores{AWSClientCacheSize: 1,
				GCP: &secrets.GCPBulk{ProjectID: "p", EndpointOverride: g.Endpoint}}
			return g.SetHang
		}},
	} {
		t.Run(tt.kind, func(t *testing.T) {
			isolateAWS(t)
			cfg := baseConfig(t)
			cfg.ReloadTimeout = time.Second
			hang := tt.setup(t, cfg)
			r := start(t, cfg)
			r.waitReady(t)
			r.waitReload(t, "completed")
			sel := goldenCase(t, "minimal", signingroot.AggregationSlot, "typical")
			check := func(want string) {
				t.Helper()
				if code, body := r.post(t, "/api/v1/consensus/sign/"+pubkeyHex(t, 1), r.sign, sel.RequestJSON); code != 200 {
					t.Fatalf("sign: %d %s", code, body)
				}
				_, checks := r.health(t)
				c := checks[tt.check]
				if got := c["status"].(string) + " " + fmt.Sprint(c["data"]); got != want {
					t.Errorf("%s: %s, want %s", tt.check, got, want)
				}
			}

			hang(true)
			begin := time.Now()
			r.reload(t, "completed_with_errors")
			if d := time.Since(begin); d > 4*time.Second {
				t.Errorf("the reload took %v with a %v --reload-timeout", d, cfg.ReloadTimeout)
			}
			check("DOWN map[error-count:1 keys-loaded:1]")

			hang(false)
			r.reload(t, "completed")
			check("UP map[error-count:0 keys-loaded:1]")
		})
	}
}

// secretStoresConfig enables the AWS bulk loader against the fake at
// endpoint, for the secrets under validators/.
func secretStoresConfig(endpoint string) config.SecretStores {
	return config.SecretStores{AWSClientCacheSize: 1, AWS: &secrets.AWSBulk{
		AWSConn: secrets.AWSConn{AuthMode: secrets.AWSSpecified, Region: "us-east-1", AccessKeyID: "AKID",
			SecretAccessKey: []byte("secret"), EndpointOverride: endpoint},
		PrefixesFilter: []string{"validators/"}}}
}

// isolateAWS keeps the AWS SDK away from the developer's configuration.
func isolateAWS(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	for _, v := range []string{"AWS_PROFILE", "AWS_REGION", "AWS_ENDPOINT_URL"} {
		t.Setenv(v, "")
	}
}
