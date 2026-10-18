// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build noexecution

package runner

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/ops"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets/secretstest"
)

// The consensus flavour links no cloud SDK: a key-config document of a
// cloud type fails its file with a hint, a bulk loader that a configuration
// carries anyway fails every load, and HashiCorp Vault, read over plain
// HTTP, works.
func TestRunConsensusFlavourSecretStores(t *testing.T) {
	cfg := baseConfig(t)
	v := secretstest.NewVault(t, false)
	v.Put("/v1/secret/data/k4", map[string]any{"value": seedHex(4)})
	u, _ := url.Parse(v.URL)
	vault := fmt.Sprintf("type: hashicorp\nserverHost: %s\nserverPort: %s\nkeyPath: /v1/secret/data/k4\ntoken: %s\n",
		u.Hostname(), u.Port(), v.Token)
	aws := "type: aws-secret\nauthenticationMode: ENVIRONMENT\nregion: us-east-1\nsecretName: s\n"
	for name, doc := range map[string]string{"vault.yaml": vault, "aws.yaml": aws} {
		if err := os.WriteFile(filepath.Join(cfg.KeyConfigPath, name), []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg.Consensus.SecretStores = config.SecretStores{AWSClientCacheSize: 1, GCP: &secrets.GCPBulk{ProjectID: "p"}}
	var logs bytes.Buffer
	log := logrus.New()
	log.SetOutput(&logs)
	r := startWithLog(t, cfg, log)
	r.waitReady(t)
	r.waitReload(t, "completed_with_errors")
	_, checks := r.health(t)
	if got := fmt.Sprint(checks[ops.CheckConfigFilesLoading]["data"]); got != "map[error-count:1 keys-loaded:1]" {
		t.Errorf("config files: %s", got)
	}
	if got := fmt.Sprint(checks[ops.CheckGCPBulkLoading]["data"]); got != "map[error-count:1 keys-loaded:0]" {
		t.Errorf("GCP bulk loading: %s", got)
	}
	_ = r.stop()
	if !strings.Contains(logs.String(), "remotesigner-consensus links no cloud SDK; use the remotesigner flavour") {
		t.Errorf("no hint in the log:\n%s", logs.String())
	}
}
