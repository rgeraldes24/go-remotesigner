// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// systemdBase is the distribution the systemd smoke test installs the unit
// on, pinned by digest.
const systemdBase = "ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac"

// systemdInstall is the installation of docs/operations/deploy-systemd.md,
// with the binary, unit, config and network file already in place: the
// service user, the key directory and one key, and the service started.
const systemdInstall = `set -e
useradd --system --no-create-home --shell /usr/sbin/nologin remotesigner
install -d -m 0700 -o remotesigner -g remotesigner /var/lib/remotesigner /var/lib/remotesigner/keys
install -m 0600 -o remotesigner -g remotesigner /root/key-0.yaml /var/lib/remotesigner/keys/key-0.yaml
systemd-analyze verify /etc/systemd/system/remotesigner.service
systemctl daemon-reload
systemctl enable --now remotesigner
`

// TestSystemdSmoke installs deploy/systemd/remotesigner.service with
// deploy/config/single-host.yaml in a container that runs systemd, as the
// systemd deployment guide does, and checks that the hardened unit runs the
// signer: TLS with the generated certificate for the allowlist names,
// /upcheck and publicKeys, its files owned by the service user and closed
// to others, `systemctl reload` re-reading the tokens and certificate, and a
// clean stop. It runs when REMOTESIGNER_SYSTEMD_SMOKE=1 (make systemd-smoke)
// and needs a Docker daemon that runs privileged containers.
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
	ctx := t.TempDir()
	build := exec.Command("go", "build", "-trimpath", "-o", filepath.Join(ctx, "remotesigner"), "../../cmd/remotesigner")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build remotesigner: %v: %s", err, out)
	}
	for name, content := range map[string][]byte{
		"remotesigner.service": readRepo(t, "deploy/systemd/remotesigner.service"),
		"remotesigner.yaml":    readRepo(t, "deploy/config/single-host.yaml"),
		"network.yaml":         readRepo(t, smokeNetwork),
		"key-0.yaml":           fmt.Appendf(nil, "type: file-raw\nkeyType: ML_DSA_87\nprivateKey: %q\n", keys.Keys[0].Seed),
		"Dockerfile": []byte("FROM " + systemdBase + "\n" +
			"RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends " +
			"systemd systemd-sysv curl ca-certificates && rm -rf /var/lib/apt/lists/*\n" +
			"COPY remotesigner /usr/local/bin/remotesigner\n" +
			"COPY remotesigner.service /etc/systemd/system/remotesigner.service\n" +
			"COPY remotesigner.yaml /etc/remotesigner/remotesigner.yaml\n" +
			"COPY network.yaml /etc/remotesigner/network.yaml\n" +
			"COPY key-0.yaml /root/key-0.yaml\n" +
			"CMD [\"/lib/systemd/systemd\"]\n"),
	} {
		if err := os.WriteFile(filepath.Join(ctx, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Join(ctx, "remotesigner"), 0o755); err != nil {
		t.Fatal(err)
	}

	var id [4]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	name := "remotesigner-systemd-" + hex.EncodeToString(id[:])
	docker(t, "buildx", "build", "--load", "--quiet", "--tag", "local/"+name, ctx)
	t.Cleanup(func() { _, _, _, _ = dockerRun("image", "rm", "--force", "local/"+name) })
	docker(t, "run", "--detach", "--name", name, "--privileged", "--cgroupns=host",
		"--tmpfs", "/run", "--tmpfs", "/run/lock", "--volume", "/sys/fs/cgroup:/sys/fs/cgroup:rw",
		"--add-host", "signer.internal:127.0.0.1", "local/"+name)
	t.Cleanup(func() { _, _, _, _ = dockerRun("rm", "--force", "--volumes", name) })
	sh := func(script string) (string, int) {
		t.Helper()
		out, errOut, code, err := dockerRun("exec", name, "sh", "-c", script)
		if err != nil {
			t.Fatal(err)
		}
		return out + errOut, code
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
	if out, code := sh(systemdInstall); code != 0 {
		t.Fatalf("install: exit %d: %s", code, out)
	}

	const curl = "curl --silent --show-error --fail --cacert /var/lib/remotesigner/tls/cert.pem "
	if out := waitFor("no /upcheck", curl+"https://signer.internal:9000/upcheck"); strings.TrimSpace(out) != "OK" {
		t.Errorf("/upcheck: %q", out)
	}
	out := waitFor("no publicKeys", curl+`-H "Authorization: Bearer $(cat /var/lib/remotesigner/auth-token)" `+
		"https://signer.internal:9000/api/v1/consensus/publicKeys")
	var listed []string
	if err := json.Unmarshal([]byte(out), &listed); err != nil || len(listed) != 1 || listed[0] != keys.Keys[0].Pubkey {
		t.Errorf("publicKeys: %v: %.80s", err, out)
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
	if out := waitFor("metrics", "curl --silent --fail http://127.0.0.1:9001/metrics"); !strings.Contains(out, "process_resident_memory_bytes") {
		t.Error("the process collector reports nothing under the unit's /proc restrictions")
	}

	if out, code := sh("systemctl reload remotesigner"); code != 0 {
		t.Fatalf("systemctl reload: %s", out)
	}
	waitFor("no reload logged", `journalctl --no-pager -u remotesigner | grep -q "TLS files reloaded"`)
	if out, code := sh("systemctl stop remotesigner && systemctl show remotesigner --property=ExecMainStatus --value"); code != 0 || strings.TrimSpace(out) != "0" {
		t.Errorf("stop: exit status %q (code %d), want 0", out, code)
	}
}
