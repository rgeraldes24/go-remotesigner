// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package repo

import (
	"path"
	"slices"
	"strings"
	"testing"
)

// operatorPages are the pages of the operator documentation, each with the
// headings or phrases that show it covers its topic.
var operatorPages = []struct {
	page  string
	about []string
}{
	{"docs/operations/requirements.md", []string{"## 1. Testnet V3 only; Testnet V2 is unsupported",
		"## 2. One seed is a validator key or an account key, never both",
		"## 3. Booleans take `=`: `--flag=false`, never `--flag false`",
		"## 4. Deploy signers next to their validator clients"}},
	{"docs/operations/quickstart.md", []string{"## 2. Key files", "## 3. Network"}},
	{"docs/operations/deploy-docker.md", []string{"## 2. The entrypoint", "## 3. Volumes and keys",
		"## 4. First start: pin the certificate", "## 5. The compose example", "## 9. Orchestrators", "Kurtosis",
		"Kubernetes"}},
	{"docs/operations/deploy-systemd.md", []string{"## 2. User, directories and keys", "## 4. Start",
		"## 7. What the unit restricts"}},
	{"docs/operations/postgres.md", []string{"## 2. Setting up the database and its roles",
		"## 3. Creating and upgrading the schema: `consensus migrate`", "## 5. Pool and timeout profile"}},
	{"docs/operations/tls.md", []string{"## 3. Client certificates (mTLS)", "## 4. Scopes in the mTLS modes",
		"## 5. Rotating tokens and certificates with SIGHUP"}},
	{"docs/operations/keystores.md", []string{"## 1. Formats", "## 3. Password files", "## 4. Checking keystores"}},
	{"docs/operations/reload.md", []string{"## 1. Key sources", "## 3. Reload", "## 5. Disabling a validator",
		"### 5.1 Enabling a key again", "## 6. Memory for keystore decryption", "60 KiB"}},
	{"docs/operations/keymanager.md", []string{"## 3. Importing keys", "## 4. Deleting keys"}},
	{"docs/operations/migration.md", []string{"## 2. Import the history", "## 3. Fence the store with a high watermark",
		"## 7. Exporting and moving back", "Why a source below the repaired epoch is safe"}},
	{"docs/operations/backup.md", []string{"## 1. Taking a backup", "## 2. Restoring"}},
	{"docs/operations/randao.md", []string{"## 1. The frontier rule", "gap_advanced", "## 3. Sizing the bucket",
		"## 6. Resetting a key's state", "## 7. Health and alerts"}},
	{"docs/operations/metrics.md", []string{"## 2. Catalogue", "## 4. Alerts"}},
	{"docs/operations/upgrade.md", []string{"## 2. The schema-version rule", "## 4. Postgres replicas",
		"## 5. Going back to an older release"}},
	{"docs/operations/release.md", []string{"## 3. Verifying a release"}},
	{"docs/reference/flags.md", []string{"## Override flags", "### What each override accepts"}},
	{"docs/reference/registration-fee-recipient-file.md", nil},
}

// Every page of the operator documentation exists, covers its topic, and is
// linked from the README; no page under docs/operations or docs/reference is
// left out of the README.
func TestOperatorDocs(t *testing.T) {
	files := repoFiles(t)
	text := map[string]string{}
	for _, f := range files {
		text[f.path] = f.text
	}
	readme, ok := text["README.md"]
	if !ok {
		t.Fatal("no README.md")
	}
	targets, _ := mdLinks(readme)
	linked := map[string]bool{}
	for _, target := range targets {
		file, _, _ := strings.Cut(target, "#")
		linked[path.Clean(file)] = true
	}
	var listed []string
	for _, p := range operatorPages {
		listed = append(listed, p.page)
		body, ok := text[p.page]
		if !ok {
			t.Errorf("%s does not exist", p.page)
			continue
		}
		if !linked[p.page] {
			t.Errorf("%s is not linked from the README", p.page)
		}
		for _, want := range p.about {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %q", p.page, want)
			}
		}
	}
	for _, f := range files {
		if (strings.HasPrefix(f.path, "docs/operations/") || strings.HasPrefix(f.path, "docs/reference/")) &&
			strings.HasSuffix(f.path, ".md") && !slices.Contains(listed, f.path) {
			t.Errorf("%s is not in the operator documentation list (and maybe not in the README)", f.path)
		}
	}
}
