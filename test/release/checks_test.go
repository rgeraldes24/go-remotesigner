// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"archive/tar"
	"bytes"
	"maps"
	"slices"
	"strings"
	"testing"
)

// The checks of TestRelease* and TestDockerSmoke catch what they are for,
// on synthetic input, on every test run.

func regular(data string) tarFile {
	return tarFile{hdr: &tar.Header{Typeflag: tar.TypeReg, Mode: 0o644}, data: []byte(data)}
}

// A GNU text in the consensus flavour fails the check even when the
// expected files list it, as they would if the list of execution-only texts
// missed it, and whatever it is named.
func TestLicenceProblemsGNUTexts(t *testing.T) {
	for _, tt := range []struct{ name, data string }{
		{"LGPL-3.0-only.txt", "LGPL"},
		{"AGPL-3.0-or-later.txt", "AGPL"},
		{"COPYING.txt", "                    GNU GENERAL PUBLIC LICENSE\n"},
		{"LESSER.txt", "                   GNU LESSER GENERAL PUBLIC LICENSE\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			want := releaseDocs{license: []byte("Apache"), notice: []byte("go-remotesigner\n"),
				texts: map[string][]byte{"Apache-2.0.txt": []byte("Apache"), tt.name: []byte(tt.data)}}
			files := map[string]tarFile{
				"LICENSE": regular("Apache"), "NOTICE": regular("go-remotesigner\n"),
				"LICENSES/Apache-2.0.txt": regular("Apache"), "LICENSES/" + tt.name: regular(tt.data),
				qrllibLicense: regular("MIT"),
			}
			got := licenceProblems(consensusFlavour, want, files)
			if len(got) != 1 || !strings.Contains(got[0], "is a GNU GPL-family text") {
				t.Errorf("consensus: problems %q, want one naming the GNU text", got)
			}
			if got := licenceProblems(fullFlavour, want, files); len(got) != 0 {
				t.Errorf("default: problems %q, want none", got)
			}
		})
	}
	// MPL-2.0 mentions the GNU licences, but is not one.
	mpl := "Mozilla Public License Version 2.0\n\"Secondary License\" means either the GNU General Public License, ...\n"
	if gnuText("MPL-2.0.txt", []byte(mpl)) {
		t.Error("MPL-2.0 counted as a GNU text")
	}
}

func TestLicenceProblems(t *testing.T) {
	want := releaseDocs{license: []byte("Apache"), notice: []byte("go-remotesigner\n"),
		texts: map[string][]byte{"Apache-2.0.txt": []byte("Apache"), "MIT.txt": []byte("MIT")}}
	good := map[string]tarFile{
		"LICENSE": regular("Apache"), "NOTICE": regular("go-remotesigner\n"),
		"LICENSES/Apache-2.0.txt": regular("Apache"), "LICENSES/MIT.txt": regular("MIT"),
		qrllibLicense: regular("MIT"), "remotesigner-consensus": regular("binary"),
	}
	with := func(edit func(map[string]tarFile)) map[string]tarFile {
		files := maps.Clone(good)
		edit(files)
		return files
	}
	tests := []struct {
		name  string
		files map[string]tarFile
		want  string // a substring of the one problem; "" for none
	}{
		{"complete", good, ""},
		{"no LICENSE", with(func(f map[string]tarFile) { delete(f, "LICENSE") }), "LICENSE missing"},
		{"another NOTICE", with(func(f map[string]tarFile) { f["NOTICE"] = regular("other\n") }), "not the remotesigner-consensus flavour's NOTICE"},
		{"LGPL in the consensus NOTICE", with(func(f map[string]tarFile) {
			f["NOTICE"] = regular("go-remotesigner\nThis product links go-qrl (LGPL-3.0-or-later).\n")
		}), "mentions the LGPL"},
		{"a GPL text", with(func(f map[string]tarFile) { f["LICENSES/GPL-3.0-or-later.txt"] = regular("GPL") }), "LICENSES/GPL-3.0-or-later.txt is a GNU"},
		{"another text", with(func(f map[string]tarFile) { f["LICENSES/ISC.txt"] = regular("ISC") }), "LICENSES/ISC.txt is not one of"},
		{"a missing text", with(func(f map[string]tarFile) { delete(f, "LICENSES/MIT.txt") }), "LICENSES/MIT.txt missing"},
		{"no third-party licences", with(func(f map[string]tarFile) { delete(f, qrllibLicense) }), "third_party_licenses/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := licenceProblems(consensusFlavour, want, tt.files)
			switch {
			case tt.want == "" && len(got) != 0:
				t.Errorf("problems %q, want none", got)
			case tt.want != "" && (len(got) != 1 || !strings.Contains(got[0], tt.want)):
				t.Errorf("problems %q, want one mentioning %q", got, tt.want)
			}
		})
	}
}

func TestShippedDocsProblems(t *testing.T) {
	want := map[string][]byte{"deploy/config/single-host.yaml": []byte("data-path: /x\n"),
		"deploy/systemd/remotesigner.service": []byte("[Unit]\n")}
	good := map[string]tarFile{
		"README.md": regular("See [LICENSE](LICENSE), [the example](deploy/config/single-host.yaml#L1), " +
			"[the guide](https://github.com/rgeraldes24/go-remotesigner/blob/v1.0.0/docs/operations/deploy-systemd.md) " +
			"and [below](#license).\n"),
		"LICENSE":                             regular("Apache"),
		"deploy/config/single-host.yaml":      regular("data-path: /x\n"),
		"deploy/systemd/remotesigner.service": regular("[Unit]\n"),
	}
	with := func(edit func(map[string]tarFile)) map[string]tarFile {
		files := maps.Clone(good)
		edit(files)
		return files
	}
	tests := []struct {
		name  string
		files map[string]tarFile
		want  string
	}{
		{"complete", good, ""},
		{"no unit", with(func(f map[string]tarFile) { delete(f, "deploy/systemd/remotesigner.service") }),
			"deploy/systemd/remotesigner.service missing"},
		{"another configuration", with(func(f map[string]tarFile) { f["deploy/config/single-host.yaml"] = regular("other\n") }),
			"deploy/config/single-host.yaml missing or not the repository's"},
		{"no README", with(func(f map[string]tarFile) { delete(f, "README.md") }), "README.md missing"},
		{"a dead link", with(func(f map[string]tarFile) {
			f["README.md"] = regular("Start with [the guide](docs/operations/deploy-systemd.md).\n")
		}), "links to docs/operations/deploy-systemd.md"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shippedDocsProblems(want, tt.files)
			switch {
			case tt.want == "" && len(got) != 0:
				t.Errorf("problems %q, want none", got)
			case tt.want != "" && (len(got) != 1 || !strings.Contains(got[0], tt.want)):
				t.Errorf("problems %q, want one mentioning %q", got, tt.want)
			}
		})
	}
}

// goVersionOutput is `go version -m` output for a build with the given tags
// and extra dependency lines.
func goVersionOutput(tags, cgo string, deps ...string) string {
	var b strings.Builder
	b.WriteString("/tmp/remotesigner-consensus: go1.26.9\n")
	b.WriteString("\tpath\tgithub.com/rgeraldes24/go-remotesigner/cmd/remotesigner\n")
	b.WriteString("\tdep\tgithub.com/theQRL/go-qrllib\tv0.11.0\th1:abc=\n")
	for _, d := range deps {
		b.WriteString("\tdep\t" + d + "\tv0.3.4\th1:def=\n")
	}
	b.WriteString("\tbuild\t-trimpath=true\n")
	if tags != "" {
		b.WriteString("\tbuild\t-tags=" + tags + "\n")
	}
	b.WriteString("\tbuild\tCGO_ENABLED=" + cgo + "\n")
	return b.String()
}

func TestBuildProblems(t *testing.T) {
	tests := []struct {
		name, flavour, out string
		want               string
	}{
		{"consensus", consensusFlavour, goVersionOutput("noexecution", "0"), ""},
		{"default", fullFlavour, goVersionOutput("", "0"), ""},
		{"default with go-qrl", fullFlavour, goVersionOutput("", "0", goQRL), ""},
		{"consensus without the tag", consensusFlavour, goVersionOutput("", "0"), "want noexecution"},
		{"consensus with go-qrl", consensusFlavour, goVersionOutput("noexecution", "0", goQRL), "lists github.com/theQRL/go-qrl"},
		{"default with the tag", fullFlavour, goVersionOutput("netgo,noexecution", "0"), "built with noexecution"},
		{"cgo", consensusFlavour, goVersionOutput("noexecution", "1"), "static"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildProblems(tt.flavour, parseGoVersionM(tt.out))
			switch {
			case tt.want == "" && len(got) != 0:
				t.Errorf("problems %q, want none", got)
			case tt.want != "" && (len(got) != 1 || !strings.Contains(got[0], tt.want)):
				t.Errorf("problems %q, want one mentioning %q", got, tt.want)
			}
		})
	}
	// go-qrllib is not go-qrl.
	if bi := parseGoVersionM(goVersionOutput("noexecution", "0")); !slices.Equal(bi.paths(), []string{"github.com/theQRL/go-qrllib"}) {
		t.Errorf("deps %q", bi.deps)
	}
}

func TestParseGoVersionMDeps(t *testing.T) {
	out := goVersionOutput("noexecution", "0", "github.com/prometheus/common") +
		"\tdep\tgithub.com/a/b\tv1.0.0\n\t=>\tgithub.com/fork/b\tv1.0.1\th1:ghi=\n"
	want := []module{
		{path: "github.com/theQRL/go-qrllib", version: "v0.11.0", source: "github.com/theQRL/go-qrllib@v0.11.0"},
		{path: "github.com/prometheus/common", version: "v0.3.4", source: "github.com/prometheus/common@v0.3.4"},
		{path: "github.com/a/b", version: "v1.0.0", source: "github.com/fork/b@v1.0.1"},
	}
	if got := parseGoVersionM(out).deps; !slices.Equal(got, want) {
		t.Errorf("deps %+v, want %+v", got, want)
	}
}

// Every module the binary links needs its licence under
// third_party_licenses/, and its NOTICE where its source has one; a file of
// another module does not count, even one whose path the module's prefixes.
func TestThirdPartyProblems(t *testing.T) {
	deps := []module{{path: "github.com/theQRL/go-qrllib"}, {path: "github.com/prometheus/common"},
		{path: "golang.org/x/net"}}
	notices := map[string]bool{"github.com/prometheus/common": true}
	good := map[string]tarFile{
		qrllibLicense: regular("MIT"),
		"third_party_licenses/github.com/prometheus/common/LICENSE": regular("Apache"),
		"third_party_licenses/github.com/prometheus/common/NOTICE":  regular("Prometheus"),
		"third_party_licenses/golang.org/x/net/netutil/LICENSE":     regular("BSD"),
	}
	with := func(edit func(map[string]tarFile)) map[string]tarFile {
		files := maps.Clone(good)
		edit(files)
		return files
	}
	tests := []struct {
		name  string
		files map[string]tarFile
		want  string
	}{
		{"complete", good, ""},
		{"no licence of a module other than go-qrllib", with(func(f map[string]tarFile) {
			delete(f, "third_party_licenses/github.com/prometheus/common/LICENSE")
		}), "holds no licence file of github.com/prometheus/common"},
		{"no NOTICE", with(func(f map[string]tarFile) {
			delete(f, "third_party_licenses/github.com/prometheus/common/NOTICE")
		}), "lacks the NOTICE file of github.com/prometheus/common"},
		{"only a NOTICE", with(func(f map[string]tarFile) {
			delete(f, "third_party_licenses/golang.org/x/net/netutil/LICENSE")
			f["third_party_licenses/golang.org/x/net/NOTICE"] = regular("x")
		}), "holds no licence file of golang.org/x/net"},
		{"another module's licence", with(func(f map[string]tarFile) {
			delete(f, "third_party_licenses/golang.org/x/net/netutil/LICENSE")
			f["third_party_licenses/golang.org/x/network/LICENSE"] = regular("BSD")
		}), "holds no licence file of golang.org/x/net"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := thirdPartyProblems(deps, notices, tt.files)
			switch {
			case tt.want == "" && len(got) != 0:
				t.Errorf("problems %q, want none", got)
			case tt.want != "" && (len(got) != 1 || !strings.Contains(got[0], tt.want)):
				t.Errorf("problems %q, want one mentioning %q", got, tt.want)
			}
		})
	}
}

func TestImageConfigProblems(t *testing.T) {
	var good imageConfig
	good.Config.User = nonroot
	good.Config.Entrypoint = slices.Clone(entrypoint)
	good.Config.Cmd = []string{"consensus"}
	good.Config.Labels = map[string]string{
		"org.opencontainers.image.title":    consensusFlavour,
		"org.opencontainers.image.licenses": "Apache-2.0 AND MIT",
		"org.opencontainers.image.source":   "https://github.com/rgeraldes24/go-remotesigner",
	}
	with := func(edit func(*imageConfig)) imageConfig {
		c := good
		c.Config.Entrypoint = slices.Clone(good.Config.Entrypoint)
		c.Config.Labels = maps.Clone(good.Config.Labels)
		edit(&c)
		return c
	}
	tests := []struct {
		name string
		cfg  imageConfig
		want string
	}{
		{"good", good, ""},
		{"root", with(func(c *imageConfig) { c.Config.User = "" }), "non-root"},
		{"uid 0", with(func(c *imageConfig) { c.Config.User = "0:0" }), "non-root"},
		{"override in the entrypoint", with(func(c *imageConfig) {
			c.Config.Entrypoint = append(c.Config.Entrypoint, "--Xallow-plaintext-token-auth")
		}), "entrypoint"},
		{"override in the environment", with(func(c *imageConfig) {
			c.Config.Env = []string{"REMOTESIGNER_XALLOW_PLAINTEXT_TOKEN_AUTH=true"}
		}), "plaintext-token override"},
		{"no TLS", with(func(c *imageConfig) { c.Config.Entrypoint = c.Config.Entrypoint[:3] }), "entrypoint"},
		{"another title", with(func(c *imageConfig) { c.Config.Labels["org.opencontainers.image.title"] = fullFlavour }), "title"},
		{"a GPL label", with(func(c *imageConfig) {
			c.Config.Labels["org.opencontainers.image.licenses"] = "Apache-2.0 AND LGPL-3.0"
		}), "GPL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := imageConfigProblems(consensusFlavour, tt.cfg, "Apache-2.0 AND MIT")
			switch {
			case tt.want == "" && len(got) != 0:
				t.Errorf("problems %q, want none", got)
			case tt.want != "" && !slices.ContainsFunc(got, func(p string) bool { return strings.Contains(p, tt.want) }):
				t.Errorf("problems %q, want one mentioning %q", got, tt.want)
			}
		})
	}
}

func TestReadTar(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range []struct{ name, data string }{
		{"remotesigner_1.0.0_linux_amd64/", ""},
		{"remotesigner_1.0.0_linux_amd64/LICENSE", "Apache"},
		{"remotesigner_1.0.0_linux_amd64/LICENSES/MIT.txt", "MIT"},
	} {
		hdr := &tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), Typeflag: tar.TypeReg}
		if strings.HasSuffix(f.name, "/") {
			hdr.Typeflag, hdr.Mode = tar.TypeDir, 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := readTar(&buf, 1)
	if err != nil {
		t.Fatal(err)
	}
	names := slices.Sorted(maps.Keys(files))
	if !slices.Equal(names, []string{"LICENSE", "LICENSES/MIT.txt"}) || string(files["LICENSES/MIT.txt"].data) != "MIT" {
		t.Errorf("entries %q", names)
	}
}

func TestFingerprintRE(t *testing.T) {
	fp := strings.TrimSuffix(strings.Repeat("5F:", 32), ":")
	line := `time="2026-10-18T12:53:56Z" level=info msg="Generated a self-signed TLS certificate" ` +
		`certificate=/data/tls/cert.pem sha256-fingerprint="` + fp + `" source=self-signed`
	if m := fingerprintRE.FindStringSubmatch(line); m == nil || m[1] != fp {
		t.Errorf("match %q, want %s", m, fp)
	}
	if fingerprintRE.MatchString(`sha256-fingerprint="5F:5F"`) {
		t.Error("matched a short fingerprint")
	}
}
