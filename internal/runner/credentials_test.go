// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
)

// credentialLog returns a logger that writes text lines to the buffer.
func credentialLog() (*logrus.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	log := logrus.New()
	log.SetOutput(&buf)
	log.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true, DisableColors: true})
	return log, &buf
}

func writeCredential(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// The -file credentials are secret files: their first line is the secret,
// and under --strict-file-permissions one that its group or other users
// can read refuses the start; otherwise it loads with a warning.
func TestStoreCredentialFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes")
	}
	aws := writeCredential(t, "aws-secret\r\nsecond line\n", 0o600)
	az := writeCredential(t, "azure-secret\n", 0o400)
	cfg := &config.Config{StrictFilePermissions: true}
	cfg.Consensus.SecretStores = config.SecretStores{AWS: &secrets.AWSBulk{}, Azure: &secrets.AzureBulk{},
		AWSSecretAccessKeyFile: aws, AzureClientSecretFile: az}
	log, out := credentialLog()
	if err := StoreCredentials(cfg, log); err != nil {
		t.Fatal(err)
	}
	ss := cfg.Consensus.SecretStores
	if string(ss.AWS.SecretAccessKey) != "aws-secret" || string(ss.Azure.ClientSecret) != "azure-secret" || out.Len() != 0 {
		t.Fatalf("read %q %q, log %q", ss.AWS.SecretAccessKey, ss.Azure.ClientSecret, out)
	}

	for _, tt := range []struct {
		name, content string
		mode          os.FileMode
		strict        bool
		want          string // an error, or "" for a warning only
	}{
		{"group-readable, strict", "the-secret\n", 0o640, true, "--aws-secrets-secret-access-key-file: "},
		{"world-readable, strict", "the-secret\n", 0o604, true, "readable by group or other users"},
		{"group-readable, not strict", "the-secret\n", 0o640, false, ""},
		{"empty first line", "\nsecret\n", 0o600, true, "the first line is empty"},
		{"blank first line", "  \r\n", 0o600, true, "the first line is empty"},
		{"too large", strings.Repeat("s", maxCredentialFile+1), 0o600, true, "too large"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{StrictFilePermissions: tt.strict}
			cfg.Consensus.SecretStores = config.SecretStores{AWS: &secrets.AWSBulk{},
				AWSSecretAccessKeyFile: writeCredential(t, tt.content, tt.mode)}
			log, out := credentialLog()
			err := StoreCredentials(cfg, log)
			switch {
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want) ||
				!strings.HasPrefix(err.Error(), "refusing to start: ")):
				t.Fatalf("error %v, want one mentioning %q", err, tt.want)
			case tt.want == "" && (err != nil || !strings.Contains(out.String(), "A secret file is readable by its group")):
				t.Fatalf("error %v, log %q: want a warning", err, out)
			case strings.Contains(out.String(), "the-secret") || (err != nil && strings.Contains(err.Error(), "the-secret")):
				t.Fatalf("the log or the error carries the secret: %q %v", out, err)
			}
		})
	}
	// A credential file whose loader is off is not read.
	cfg = &config.Config{StrictFilePermissions: true}
	cfg.Consensus.SecretStores = config.SecretStores{AzureClientSecretFile: "/no/such/file"}
	if err := StoreCredentials(cfg, logrus.New()); err != nil {
		t.Fatalf("a credential file without its loader: %v", err)
	}
}

// Every plain secret flag in use brings a deprecation warning naming its
// -file flag, one on the command line a second warning, and one in a config
// file the secret-file rule for that file, whichever source won. No line
// carries the secret.
func TestPlainSecretWarnings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes")
	}
	open := writeCredential(t, "consensus:\n  azure-client-secret: from-file\n", 0o644)
	closed := writeCredential(t, "consensus:\n  azure-client-secret: from-file\n", 0o600)
	plain := func(source config.SecretSource, file string) []config.PlainSecret {
		return []config.PlainSecret{{Flag: "azure-client-secret", FileFlag: "azure-client-secret-file", Source: source,
			File: file}}
	}
	for _, tt := range []struct {
		name     string
		plain    []config.PlainSecret
		strict   bool
		want     []string
		unwanted []string
		err      string
	}{
		{name: "command line", plain: plain(config.FromCommandLine, ""), strict: true,
			want: []string{"A deprecated plain secret flag is set", `flag=--azure-client-secret`,
				`instead=--azure-client-secret-file`, `source="command line"`, "A secret is on the command line"}},
		{name: "environment", plain: plain(config.FromEnvironment, ""), strict: true,
			want:     []string{"A deprecated plain secret flag is set", "source=environment"},
			unwanted: []string{"process list"}},
		{name: "owner-only config file", plain: plain(config.FromConfigFile, closed), strict: true,
			want:     []string{"A deprecated plain secret flag is set", `source="config file"`},
			unwanted: []string{"process list", "readable by its group"}},
		{name: "open config file, strict", plain: plain(config.FromConfigFile, open), strict: true,
			err: "refusing to start: --config-file holds --azure-client-secret, so it is a secret file: " + open +
				": mode 0644: readable by group or other users"},
		{name: "open config file, not strict", plain: plain(config.FromConfigFile, open),
			want: []string{"A deprecated plain secret flag is set", "A secret file is readable by its group", "file=" + open}},
		// The command line or the environment won, but the file holds the
		// secret all the same.
		{name: "open config file overridden on the command line, strict", plain: plain(config.FromCommandLine, open),
			strict: true, err: "refusing to start: --config-file holds --azure-client-secret, so it is a secret file: " +
				open + ": mode 0644: readable by group or other users"},
		{name: "owner-only config file overridden by the environment", plain: plain(config.FromEnvironment, closed),
			strict: true, want: []string{"A deprecated plain secret flag is set", "source=environment"},
			unwanted: []string{"process list", "readable by its group"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{StrictFilePermissions: tt.strict}
			cfg.Consensus.SecretStores.Plain = tt.plain
			log, out := credentialLog()
			err := StoreCredentials(cfg, log)
			if tt.err != "" {
				if err == nil || !strings.HasPrefix(err.Error(), tt.err) {
					t.Fatalf("error %v, want %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range tt.want {
				if !strings.Contains(out.String(), w) {
					t.Errorf("log lacks %q:\n%s", w, out)
				}
			}
			for _, u := range tt.unwanted {
				if strings.Contains(out.String(), u) {
					t.Errorf("log has %q:\n%s", u, out)
				}
			}
			if !strings.Contains(out.String(), "level=warning") || strings.Contains(out.String(), "from-file") {
				t.Errorf("log:\n%s", out)
			}
		})
	}
}
