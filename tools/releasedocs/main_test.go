// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var (
	full      = flavours[0]
	consensus = flavours[1]
)

// fakeReadme is the README of fakeRepo: links to files a release ships and
// to files it does not.
const fakeReadme = "# go-remotesigner\n\nSee [the guide](docs/operations/deploy-systemd.md#1-install-the-binary), " +
	"[`deploy/`](deploy), [LICENSE](LICENSE), [the unit](deploy/systemd/remotesigner.service), " +
	"[LICENSES/](LICENSES), [upstream](https://github.com/Consensys/web3signer) and [below](#license).\n"

// fakeRepo writes a repository root with the files assemble reads, and
// NOTICE.execution and the GPL texts when execution is set.
func fakeRepo(t *testing.T, execution bool) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"LICENSE":                             "Apache License\n",
		"README.md":                           fakeReadme,
		"NOTICE":                              "go-remotesigner\nCopyright 2026 The go-remotesigner Authors\n",
		"LICENSES/Apache-2.0.txt":             "Apache\n",
		"LICENSES/MIT.txt":                    "MIT\n",
		"LICENSES/BSD-3-Clause.txt":           "BSD\n",
		"deploy/config/single-host.yaml":      "data-path: /var/lib/remotesigner\n",
		"deploy/config/postgres-ha.yaml":      "data-path: /var/lib/remotesigner\n",
		"deploy/systemd/remotesigner.service": "[Unit]\n",
		"deploy/docker/Dockerfile":            "FROM scratch\n",
	}
	if execution {
		files[executionNotice] = "This product links go-qrl, licensed under the LGPL.\n"
		files["LICENSES/LGPL-3.0-or-later.txt"] = "LGPL\n"
		files["LICENSES/GPL-3.0-or-later.txt"] = "GPL\n"
	}
	for name, content := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestFlavours(t *testing.T) {
	if full.name != "remotesigner" || full.tags != "" || !full.execution {
		t.Errorf("default flavour = %+v", full)
	}
	if consensus.name != "remotesigner-consensus" || consensus.tags != "noexecution" || consensus.execution {
		t.Errorf("consensus flavour = %+v", consensus)
	}
}

func TestNoticeFor(t *testing.T) {
	tests := []struct {
		name      string
		execution bool // the repository has NOTICE.execution
		f         flavour
		want      string
	}{
		{"consensus", false, consensus, "go-remotesigner\nCopyright 2026 The go-remotesigner Authors\n"},
		{"default without a fragment", false, full, "go-remotesigner\nCopyright 2026 The go-remotesigner Authors\n"},
		{"consensus with a fragment", true, consensus, "go-remotesigner\nCopyright 2026 The go-remotesigner Authors\n"},
		{"default with a fragment", true, full, "go-remotesigner\nCopyright 2026 The go-remotesigner Authors\n\n" +
			"This product links go-qrl, licensed under the LGPL.\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := noticeFor(fakeRepo(t, tt.execution), tt.f)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("NOTICE = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNoticeForWithoutTrailingNewline(t *testing.T) {
	root := fakeRepo(t, true)
	if err := os.WriteFile(filepath.Join(root, "NOTICE"), []byte("go-remotesigner"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := noticeFor(root, full)
	if err != nil {
		t.Fatal(err)
	}
	if want := "go-remotesigner\n\nThis product links go-qrl, licensed under the LGPL.\n"; string(got) != want {
		t.Errorf("NOTICE = %q, want %q", got, want)
	}
}

func TestLicenseTexts(t *testing.T) {
	tests := []struct {
		name      string
		execution bool
		f         flavour
		want      []string
	}{
		{"consensus", false, consensus, []string{"Apache-2.0.txt", "BSD-3-Clause.txt", "MIT.txt"}},
		{"default", false, full, []string{"Apache-2.0.txt", "BSD-3-Clause.txt", "MIT.txt"}},
		{"consensus leaves out the GPL texts", true, consensus, []string{"Apache-2.0.txt", "BSD-3-Clause.txt", "MIT.txt"}},
		{"default ships the GPL texts", true, full, []string{"Apache-2.0.txt", "BSD-3-Clause.txt", "GPL-3.0-or-later.txt",
			"LGPL-3.0-or-later.txt", "MIT.txt"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := licenseTexts(fakeRepo(t, tt.execution), tt.f)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("LICENSES = %q, want %q", got, tt.want)
			}
		})
	}
}

// A GNU text that executionOnly does not list stops the consensus flavour,
// whatever its name, and the default flavour ships it.
func TestLicenseTextsRefusesUnlistedGNUTexts(t *testing.T) {
	tests := []struct {
		name, file, content string
	}{
		{"LGPL under another name", "LGPL-3.0-only.txt", "LGPL\n"},
		{"GPL-2.0", "GPL-2.0-or-later.txt", "GPL\n"},
		{"AGPL", "AGPL-3.0-or-later.txt", "AGPL\n"},
		{"lower case", "lgpl-2.1.txt", "LGPL\n"},
		{"GPL by its title", "COPYING.txt", "                    GNU GENERAL PUBLIC LICENSE\n                       Version 3, 29 June 2007\n"},
		{"LGPL by its title", "LICENSE-LESSER.txt", "                   GNU LESSER GENERAL PUBLIC LICENSE\n"},
		{"Library GPL by its title", "LIBRARY.txt", "                  GNU LIBRARY GENERAL PUBLIC LICENSE\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := fakeRepo(t, true)
			if err := os.WriteFile(filepath.Join(root, "LICENSES", tt.file), []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}
			if got, err := licenseTexts(root, consensus); err == nil || !strings.Contains(err.Error(), tt.file) {
				t.Errorf("consensus: texts %q, error %v; want an error naming %s", got, err, tt.file)
			}
			got, err := licenseTexts(root, full)
			if err != nil || !slices.Contains(got, tt.file) {
				t.Errorf("default: texts %q, error %v; want %s shipped", got, err, tt.file)
			}
		})
	}
	// MPL-2.0 names the GNU licences as its Secondary Licenses, but is not one.
	root := fakeRepo(t, false)
	mpl := "Mozilla Public License Version 2.0\n\"Secondary License\" means either the GNU General Public License, Version 2.0, the GNU Lesser General Public License, ...\n"
	if err := os.WriteFile(filepath.Join(root, "LICENSES", "MPL-2.0.txt"), []byte(mpl), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := licenseTexts(root, consensus); err != nil || !slices.Contains(got, "MPL-2.0.txt") {
		t.Errorf("consensus with MPL-2.0: texts %q, error %v", got, err)
	}
}

func TestAssemble(t *testing.T) {
	root := fakeRepo(t, true)
	for _, f := range flavours {
		t.Run(f.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), f.name)
			if err := assemble(root, dir, f, "v1.0.0"); err != nil {
				t.Fatal(err)
			}
			var got []string
			err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				rel, err := filepath.Rel(dir, p)
				got = append(got, filepath.ToSlash(rel))
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			// The unit and the example configuration ship; the Docker files
			// do not.
			want := []string{"LICENSE", "LICENSES/Apache-2.0.txt", "LICENSES/BSD-3-Clause.txt", "LICENSES/MIT.txt",
				"NOTICE", "README.md", "deploy/config/postgres-ha.yaml", "deploy/config/single-host.yaml",
				"deploy/systemd/remotesigner.service"}
			if f.execution {
				want = []string{"LICENSE", "LICENSES/Apache-2.0.txt", "LICENSES/BSD-3-Clause.txt",
					"LICENSES/GPL-3.0-or-later.txt", "LICENSES/LGPL-3.0-or-later.txt", "LICENSES/MIT.txt", "NOTICE",
					"README.md", "deploy/config/postgres-ha.yaml", "deploy/config/single-host.yaml",
					"deploy/systemd/remotesigner.service"}
			}
			if !slices.Equal(got, want) {
				t.Errorf("files = %q, want %q", got, want)
			}
			for _, name := range []string{"deploy/config/single-host.yaml", "deploy/systemd/remotesigner.service"} {
				a, errA := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
				b, errB := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
				if errA != nil || errB != nil || string(a) != string(b) {
					t.Errorf("%s: shipped %q, the repository's %q (%v, %v)", name, b, a, errB, errA)
				}
			}
			readme, err := os.ReadFile(filepath.Join(dir, "README.md"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(readme), "(https://github.com/rgeraldes24/go-remotesigner/blob/v1.0.0/docs/operations/deploy-systemd.md#1-install-the-binary)") {
				t.Errorf("the shipped README links to the guide in the release directory, which has none:\n%s", readme)
			}
			notice, err := os.ReadFile(filepath.Join(dir, "NOTICE"))
			if err != nil {
				t.Fatal(err)
			}
			if lgpl := strings.Contains(string(notice), "LGPL"); lgpl != f.execution {
				t.Errorf("NOTICE mentions the LGPL: %v, want %v", lgpl, f.execution)
			}
		})
	}
}

// The shipped README keeps a link to a file the release directory holds,
// and points every other relative link at the repository's file at the
// release's ref; absolute links and links within the page stay.
func TestShippedReadme(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"LICENSE", "deploy/systemd/remotesigner.service"} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "LICENSES"), 0o755); err != nil {
		t.Fatal(err)
	}
	const blob = "https://github.com/rgeraldes24/go-remotesigner/blob/v1.2.3/"
	got := string(shippedReadme([]byte(fakeReadme), dir, "v1.2.3"))
	for _, want := range []string{
		"[the guide](" + blob + "docs/operations/deploy-systemd.md#1-install-the-binary)",
		// A directory the release holds only part of, or a copy of.
		"[`deploy/`](" + blob + "deploy)",
		"[LICENSES/](" + blob + "LICENSES)",
		"[LICENSE](LICENSE)",
		"[the unit](deploy/systemd/remotesigner.service)",
		"[upstream](https://github.com/Consensys/web3signer)",
		"[below](#license)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("shipped README lacks %q:\n%s", want, got)
		}
	}
}

func TestSPDXExpression(t *testing.T) {
	tests := []struct {
		name, report, want string
		wantErr            bool
	}{
		{"own licence only", "", "Apache-2.0", false},
		{"sorted and distinct", "github.com/sirupsen/logrus,https://github.com/sirupsen/logrus/blob/v1.9.3/LICENSE,MIT\n" +
			"golang.org/x/crypto,https://cs.opensource.google/go/x/crypto/+/v0.52.0:LICENSE,BSD-3-Clause\n" +
			"go.etcd.io/bbolt,https://github.com/etcd-io/bbolt/blob/v1.5.0/LICENSE,MIT\n" +
			"github.com/russross/blackfriday/v2,https://github.com/russross/blackfriday/blob/v2.1.0/LICENSE.txt,BSD-2-Clause\n" +
			"github.com/rgeraldes24/go-remotesigner,https://github.com/rgeraldes24/go-remotesigner/blob/HEAD/LICENSE,Apache-2.0\n",
			"Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND MIT", false},
		{"an LGPL module", "github.com/theQRL/go-qrl/rlp,https://github.com/theQRL/go-qrl/blob/b92884a3a1d5/COPYING.LESSER,LGPL-3.0\n",
			"Apache-2.0 AND LGPL-3.0", false},
		{"unknown licence", "example.com/m,https://example.com/m,Unknown\n", "", true},
		{"empty licence", "example.com/m,https://example.com/m,\n", "", true},
		{"malformed", "example.com/m,MIT\n", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := spdxExpression([]byte(tt.report))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, want error %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("expression = %q, want %q", got, tt.want)
			}
		})
	}
}
