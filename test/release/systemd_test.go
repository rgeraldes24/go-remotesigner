// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// systemdBase is the distribution the systemd smoke test installs the unit
// on, pinned by digest. Renovate moves the pin (renovate.json, the marker
// below).
//
// renovate: datasource=docker
const systemdBase = "ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac"

// systemdGuide is the systemd deployment guide. The smoke test runs its
// block marked systemdArchiveBlock (extracting the release archive and
// installing the binary) and then its blocks marked systemdBlock as written,
// and its blocks marked systemdFingerprintBlock, systemdCheckBlock and
// systemdReloadBlock once the signer is up. upgradeGuide's block marked
// systemdUpgradeBlock is the upgrade of a systemd signer, which it runs last.
const (
	systemdGuide            = "docs/operations/deploy-systemd.md"
	systemdArchiveBlock     = "<!-- systemd-smoke:archive -->"
	systemdBlock            = "<!-- systemd-smoke -->"
	systemdFingerprintBlock = "<!-- systemd-smoke:fingerprint -->"
	systemdCheckBlock       = "<!-- systemd-smoke:check -->"
	systemdReloadBlock      = "<!-- systemd-smoke:reload -->"
	upgradeGuide            = "docs/operations/upgrade.md"
	systemdUpgradeBlock     = "<!-- systemd-smoke:upgrade -->"
)

// The release archive the smoke test extracts: named and laid out as
// .goreleaser.yaml names and lays out the consensus flavour's archive for
// linux, with smokeVersion for the version.
const (
	smokeVersion = "1.0.0-smoke"
	// guideArchive is the archive's name in the guide, for linux/amd64.
	guideArchive = "remotesigner-consensus_<version>_linux_amd64"
)

// smokeUser is the unprivileged user the smoke test runs the guide's
// commands as: it may run every command with sudo, and is in neither the
// adm nor the systemd-journal group, so a command the guide gives without
// sudo runs without root's rights, as on an operator's host.
const smokeUser = "op"

// guideResolve is how the guide's curl commands reach the signer by an
// allowlist name from its own host, whether or not the name resolves there.
const guideResolve = "--resolve signer.internal:9000:127.0.0.1"

// markedBlocks returns the code blocks of a Markdown text that directly
// follow the line marker, in order.
func markedBlocks(text, marker string) []string {
	var blocks []string
	for _, part := range strings.Split(text, marker+"\n```\n")[1:] {
		block, _, _ := strings.Cut(part, "\n```")
		blocks = append(blocks, block)
	}
	return blocks
}

// archiveName is the name of the consensus flavour's linux archive for
// arch, without .tar.gz, as the guide's archive block names it for amd64.
func archiveName(arch string) string {
	return strings.NewReplacer("<version>", smokeVersion, "_amd64", "_"+arch).Replace(guideArchive)
}

// guideScript returns the guide's installation as one shell script that
// stops at the first failing command, for the archive of arch: the block
// marked systemdArchiveBlock, which extracts the archive, enters its
// directory and installs the binary, with the version and architecture
// filled in; a copy of the operator's files from ../inputs into that
// directory, which the guide asks for in prose; and the blocks marked
// systemdBlock.
func guideScript(t *testing.T, arch string) string {
	t.Helper()
	text := string(readRepo(t, systemdGuide))
	archive := markedBlocks(text, systemdArchiveBlock)
	if len(archive) != 1 {
		t.Fatalf("%s: want one block marked %s, got %d", systemdGuide, systemdArchiveBlock, len(archive))
	}
	blocks := markedBlocks(text, systemdBlock)
	if len(blocks) == 0 {
		t.Fatalf("%s has no blocks marked %s", systemdGuide, systemdBlock)
	}
	archiveBlock := strings.NewReplacer(guideArchive, archiveName(arch)).Replace(archive[0])
	return "set -e\n" + archiveBlock + "\ncp -R ../inputs/. .\n" + strings.Join(blocks, "\n") + "\n"
}

// unprivilegedJournal finds a journalctl the guides run without sudo, which
// shows an operator outside the adm and systemd-journal groups nothing.
var unprivilegedJournal = regexp.MustCompile(`(?m)(?:^|[^\w-])journalctl\b`)

// placeholder finds a placeholder such as <version> in a command.
var placeholder = regexp.MustCompile(`<[a-z][a-z0-9 -]*>`)

// sudoJournal is journalctl run with sudo.
var sudoJournal = regexp.MustCompile(`sudo journalctl\b`)

// The guide's marked blocks are its installation, from extracting the
// release archive to the started unit, and nothing that waits forever, such
// as journalctl -f: the smoke test runs them as written. The unit and the
// configuration they install are files the release archive ships. The check
// and reload blocks reach the signer by an allowlist name without relying
// on the host's DNS, the journal is read with sudo, and the upgrade guide's
// block stops, migrates and starts the unit. This runs without Docker, so a
// guide edit that breaks the smoke test fails every test run.
func TestSystemdGuideBlocks(t *testing.T) {
	script := guideScript(t, "amd64")
	for _, want := range []string{"tar -xzf remotesigner-consensus_" + smokeVersion + "_linux_amd64.tar.gz",
		"cd remotesigner-consensus_" + smokeVersion + "_linux_amd64",
		"sudo install -m 0755 remotesigner-consensus /usr/local/bin/remotesigner",
		"useradd --system", "install -d -m 0700 -o remotesigner -g remotesigner",
		"/etc/remotesigner/remotesigner.yaml", "/etc/remotesigner/network.yaml", "/etc/systemd/system/",
		"systemctl daemon-reload", "systemctl enable --now remotesigner",
		"validator_keys/keystore-*.json", "sudo -u remotesigner remotesigner consensus keystore verify",
		"  keystores-path: /var/lib/remotesigner/keystores"} {
		if !strings.Contains(script, want) {
			t.Errorf("the guide's installation lacks %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, " -f") && strings.Contains(script, "journalctl") {
		t.Errorf("the guide's installation follows a log, which never returns:\n%s", script)
	}
	if p := placeholder.FindString(script); p != "" {
		t.Errorf("the guide's installation has the placeholder %s left:\n%s", p, script)
	}
	upgrade := markedBlocks(string(readRepo(t, upgradeGuide)), systemdUpgradeBlock)
	if len(upgrade) != 1 {
		t.Fatalf("%s: want one block marked %s, got %d", upgradeGuide, systemdUpgradeBlock, len(upgrade))
	}
	for _, want := range []string{"systemctl stop remotesigner",
		"sudo -u remotesigner remotesigner --config-file=/etc/remotesigner/remotesigner.yaml consensus migrate",
		"systemctl start remotesigner"} {
		if !strings.Contains(upgrade[0], want) {
			t.Errorf("%s: the systemd upgrade lacks %q:\n%s", upgradeGuide, want, upgrade[0])
		}
	}
	if strings.ContainsAny(upgrade[0], "<>") || strings.Contains(upgrade[0], " -f") {
		t.Errorf("%s: the systemd upgrade has a placeholder or follows a log:\n%s", upgradeGuide, upgrade[0])
	}
	text := string(readRepo(t, systemdGuide))
	for _, b := range []struct{ marker, want string }{
		{systemdFingerprintBlock, "sha256-fingerprint"},
		{systemdCheckBlock, "/upcheck"},
		{systemdCheckBlock, "publicKeys"},
		{systemdReloadBlock, "-X POST"},
		{systemdReloadBlock, "admin-token"},
		{systemdReloadBlock, "/reload"},
	} {
		if blocks := markedBlocks(text, b.marker); len(blocks) != 1 || !strings.Contains(blocks[0], b.want) {
			t.Errorf("%s: want one block marked %s that has %q, got %q", systemdGuide, b.marker, b.want, blocks)
		}
	}
	// Every curl to the signer names the allowlist name and points it at
	// the host itself.
	for _, marker := range []string{systemdCheckBlock, systemdReloadBlock} {
		for _, block := range markedBlocks(text, marker) {
			if n, m := strings.Count(block, "https://signer.internal:9000"), strings.Count(block, guideResolve); n == 0 || n != m {
				t.Errorf("%s: %d requests to https://signer.internal:9000 and %d %q in:\n%s", marker, n, m, guideResolve, block)
			}
		}
	}
	for name, page := range map[string]string{systemdGuide: text, upgradeGuide: string(readRepo(t, upgradeGuide))} {
		if all, withSudo := len(unprivilegedJournal.FindAllString(page, -1)), len(sudoJournal.FindAllString(page, -1)); all != withSudo {
			t.Errorf("%s: %d journalctl commands, %d of them with sudo", name, all, withSudo)
		}
	}
	// The files the installation reads from the archive's directory ship in
	// the release archive.
	for _, f := range []string{"deploy/config/single-host.yaml", "deploy/systemd/remotesigner.service"} {
		if !strings.Contains(script, f) {
			t.Errorf("the guide's installation does not install %s", f)
		}
		if _, ok := wantDeploy(t)[f]; !ok {
			t.Errorf("the guide installs %s, which no release archive ships (shippedDeployDirs)", f)
		}
	}
}

// TestSystemdSmoke installs deploy/systemd/remotesigner.service with
// deploy/config/single-host.yaml in a container that runs systemd, by
// running the systemd deployment guide's own commands as an unprivileged
// user with sudo, from a release archive that holds the binary and the
// repository's deploy/ files, and checks that the hardened unit runs the
// signer: TLS with the generated certificate for the allowlist names (which
// no DNS resolves in the container), the fingerprint in the journal,
// /upcheck and publicKeys with the key file's and the keystore's keys, its
// files owned by the service user and closed to others, `systemctl reload`
// re-reading the tokens and certificate, the guide's POST /reload, the
// upgrade guide's stop, migrate and start, and a clean stop. It runs when
// REMOTESIGNER_SYSTEMD_SMOKE=1 (make systemd-smoke) and needs a Docker
// daemon that runs privileged containers.
func TestSystemdSmoke(t *testing.T) {
	if os.Getenv("REMOTESIGNER_SYSTEMD_SMOKE") != "1" {
		t.Skip("set REMOTESIGNER_SYSTEMD_SMOKE=1 to run the unit under systemd in Docker (make systemd-smoke)")
	}
	requireDocker(t)
	arch := strings.TrimSpace(docker(t, "version", "--format", "{{.Server.Arch}}"))

	var keys struct {
		Keys []struct{ Seed, Pubkey string } `json:"keys"`
	}
	if err := json.Unmarshal(readRepo(t, "testdata/vectors/keys/interop.json"), &keys); err != nil || len(keys.Keys) == 0 {
		t.Fatalf("interop keys: %v", err)
	}
	keystorePubkey, keystorePassword := smokeKeystoreKey(t)
	wantKeys := []string{keys.Keys[0].Pubkey, keystorePubkey}
	slices.Sort(wantKeys)
	ctx := t.TempDir()
	bin := filepath.Join(ctx, consensusFlavour)
	build := exec.Command("go", "build", "-trimpath", "-tags", "noexecution", "-o", bin, "../../cmd/remotesigner")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build remotesigner: %v: %s", err, out)
	}
	binary, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	// The operator's working directory: the release archive, which holds
	// the binary and the repository's deploy/ files at their paths, and the
	// files the guide asks the operator to put in its directory: the
	// chain's config, one key file and a deposit CLI output directory with
	// one keystore and its password.
	archive := archiveName(arch)
	for name, content := range map[string][]byte{
		"guide/" + archive + ".tar.gz":                     releaseArchive(t, archive, binary),
		"guide/inputs/config.yaml":                         readRepo(t, smokeNetwork),
		"guide/inputs/key-0.yaml":                          fmt.Appendf(nil, "type: file-raw\nkeyType: ML_DSA_87\nprivateKey: %q\n", keys.Keys[0].Seed),
		"guide/inputs/validator_keys/" + smokeKeystoreName: readRepo(t, smokeKeystoreInRepo),
		"guide/inputs/keystores-password.txt":              []byte(keystorePassword + "\n"),
		"guide/install.sh":                                 []byte(guideScript(t, arch)),
		"guide/upgrade.sh":                                 []byte("set -e\n" + markedBlocks(string(readRepo(t, upgradeGuide)), systemdUpgradeBlock)[0] + "\n"),
		"Dockerfile": []byte("FROM " + systemdBase + "\n" +
			"RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends " +
			"systemd systemd-sysv curl ca-certificates sudo && rm -rf /var/lib/apt/lists/*\n" +
			"RUN useradd --create-home --shell /bin/sh " + smokeUser + " && " +
			"echo '" + smokeUser + " ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/" + smokeUser + " && " +
			"chmod 0440 /etc/sudoers.d/" + smokeUser + "\n" +
			"COPY --chown=" + smokeUser + ":" + smokeUser + " guide /home/" + smokeUser + "/guide\n" +
			"CMD [\"/lib/systemd/systemd\"]\n"),
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(ctx, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ctx, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}

	var id [4]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	name := "remotesigner-systemd-" + hex.EncodeToString(id[:])
	docker(t, "buildx", "build", "--load", "--quiet", "--tag", "local/"+name, ctx)
	t.Cleanup(func() { _, _, _, _ = dockerRun("image", "rm", "--force", "local/"+name) })
	// No --add-host: the guide's commands reach signer.internal on their
	// own.
	docker(t, "run", "--detach", "--name", name, "--privileged", "--cgroupns=host",
		"--tmpfs", "/run", "--tmpfs", "/run/lock", "--volume", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "local/"+name)
	t.Cleanup(func() { _, _, _, _ = dockerRun("rm", "--force", "--volumes", name) })
	// sh runs a script as root, for the test's own checks; op runs one as
	// smokeUser in the working directory, for the guides' commands.
	run := func(script string, user ...string) (string, int) {
		t.Helper()
		args := append([]string{"exec"}, user...)
		out, errOut, code, err := dockerRun(append(args, name, "sh", "-c", script)...)
		if err != nil {
			t.Fatal(err)
		}
		return out + errOut, code
	}
	sh := func(script string) (string, int) { t.Helper(); return run(script) }
	op := func(script string) (string, int) {
		t.Helper()
		return run(script, "--user", smokeUser, "--workdir", "/home/"+smokeUser+"/guide")
	}
	waitFor := func(what, script string) string {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for {
			out, code := sh(script)
			if code == 0 {
				return out
			}
			if time.Now().After(deadline) {
				journal, _ := sh("journalctl --no-pager -u remotesigner | tail -40")
				t.Fatalf("%s: %s\n%s", what, out, journal)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}

	waitFor("systemd did not start", `state=$(systemctl is-system-running); [ "$state" = running ] || [ "$state" = degraded ]`)
	if out, code := sh("getent hosts signer.internal"); code == 0 {
		t.Fatalf("signer.internal resolves in the container (%s): the guide's checks would not show they need no DNS", out)
	}
	out, code := op("sh -x install.sh")
	if code != 0 {
		t.Fatalf("the guide's installation: exit %d: %s", code, out)
	}
	if !strings.Contains(out, "1 keystores: 1 OK, 0 refused") {
		t.Errorf("the guide's keystore verify did not check the keystore: %s", out)
	}

	curl := "curl --silent --show-error --fail " + guideResolve + " --cacert /var/lib/remotesigner/tls/cert.pem "
	if out := waitFor("no /upcheck", curl+"https://signer.internal:9000/upcheck"); strings.TrimSpace(out) != "OK" {
		t.Errorf("/upcheck: %q", out)
	}
	publicKeys := curl + `-H "Authorization: Bearer $(cat /var/lib/remotesigner/auth-token)" ` +
		"https://signer.internal:9000/api/v1/consensus/publicKeys"
	out = waitFor("no publicKeys", publicKeys)
	var listed []string
	if err := json.Unmarshal([]byte(out), &listed); err != nil || !slices.Equal(listed, wantKeys) {
		t.Errorf("publicKeys: %v: %.80s; want the key file's and the keystore's key", err, out)
	}
	files := waitFor("stat", "stat -c '%n %a %U' /var/lib/remotesigner /var/lib/remotesigner/auth-token "+
		"/var/lib/remotesigner/admin-token /var/lib/remotesigner/tls /var/lib/remotesigner/tls/cert.pem "+
		"/var/lib/remotesigner/tls/key.pem /var/lib/remotesigner/slashing-protection.db")
	for _, line := range strings.Split(strings.TrimSpace(files), "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[2] != "remotesigner" || (f[1] != "700" && f[1] != "600") {
			t.Errorf("%q: want mode 0700 or 0600, owned by remotesigner", line)
		}
	}
	text := string(readRepo(t, systemdGuide))
	// The guide's own commands: the fingerprint from the journal, the
	// check, which prints OK and the key, and the key reload.
	if out, code := op(markedBlocks(text, systemdFingerprintBlock)[0]); code != 0 || !fingerprintRE.MatchString(out) {
		t.Errorf("the guide's fingerprint command: exit %d: %.200s", code, out)
	}
	if out, code := op(markedBlocks(text, systemdCheckBlock)[0]); code != 0 ||
		!strings.Contains(out, "OK") || !strings.Contains(out, keys.Keys[0].Pubkey) {
		t.Errorf("the guide's check: exit %d: %.200s", code, out)
	}
	if out, code := op(markedBlocks(text, systemdReloadBlock)[0]); code != 0 || !strings.Contains(out, `"reload started"`) {
		t.Errorf("the guide's reload: exit %d: %.200s", code, out)
	}
	waitFor("the reload did not complete", curl+`-H "Authorization: Bearer $(cat /var/lib/remotesigner/auth-token)" `+
		`https://signer.internal:9000/reload | grep -q '"status":"completed"'`)
	if out := waitFor("metrics", "curl --silent --fail http://127.0.0.1:9001/metrics"); !strings.Contains(out, "process_resident_memory_bytes") {
		t.Error("the process collector reports nothing under the unit's /proc restrictions")
	}

	if out, code := sh("systemctl reload remotesigner"); code != 0 {
		t.Fatalf("systemctl reload: %s", out)
	}
	waitFor("no reload logged", `journalctl --no-pager -u remotesigner | grep -q "TLS files reloaded"`)

	// The upgrade guide's steps, with the binary already in place: stop,
	// migrate the store as the service user, start, and show the journal.
	out, code = op("sh -x upgrade.sh")
	if code != 0 || !strings.Contains(out, "is already at schema version") || !strings.Contains(out, "nothing to do") {
		t.Fatalf("the upgrade guide's steps: exit %d: %s", code, out)
	}
	if !strings.Contains(out, "Started remotesigner.service") {
		t.Errorf("the upgrade guide's journalctl showed no journal entries: %s", out)
	}
	if out := waitFor("no /upcheck after the upgrade", curl+"https://signer.internal:9000/upcheck"); strings.TrimSpace(out) != "OK" {
		t.Errorf("/upcheck after the upgrade: %q", out)
	}
	if out := waitFor("no publicKeys after the upgrade", publicKeys); !strings.Contains(out, keystorePubkey) {
		t.Errorf("publicKeys after the upgrade: %.80s", out)
	}
	if out, code := sh("systemctl stop remotesigner && systemctl show remotesigner --property=ExecMainStatus --value"); code != 0 || strings.TrimSpace(out) != "0" {
		t.Errorf("stop: exit status %q (code %d), want 0", out, code)
	}
}

// releaseArchive returns a gzipped tar laid out as a release archive of the
// consensus flavour (.goreleaser.yaml, tools/releasedocs): a directory
// named name with the binary and the repository's deploy/ files the release
// ships, at their paths.
func releaseArchive(t *testing.T, name string, binary []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	tw := tar.NewWriter(zw)
	add := func(path string, mode int64, data []byte) {
		hdr := &tar.Header{Typeflag: tar.TypeReg, Name: name + "/" + path, Mode: mode, Size: int64(len(data)),
			ModTime: time.Now()}
		if strings.HasSuffix(path, "/") || path == "" {
			hdr.Typeflag, hdr.Size, hdr.Mode = tar.TypeDir, 0, 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	add("", 0, nil)
	add(consensusFlavour, 0o755, binary)
	deploy := wantDeploy(t)
	for _, dir := range shippedDeployDirs {
		add(dir+"/", 0, nil)
	}
	for _, path := range slices.Sorted(maps.Keys(deploy)) {
		add(path, 0o644, deploy[path])
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
