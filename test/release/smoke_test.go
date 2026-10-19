// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package release

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// The smoke test's chain: the end-to-end file network with its interop
// genesis validators root and a fixed genesis time.
const (
	smokeNetwork     = "internal/network/embedded/end-to-end.yaml"
	smokeGenesisTime = "1760000000"
	// signerAlias is the name the client container dials, as a compose
	// service name would be.
	signerAlias = "signer"
)

// The smoke test's key: a deposit CLI keystore with the light KDF, so that
// decrypting it takes milliseconds, in the layout deploy-docker.md gives
// the key volume: the keystores in keystores/ and their password in
// password.txt.
const (
	smokeKeystore       = "deposit-cli-light.json"
	smokeKeystoresPath  = "/keys/keystores"
	smokePasswordFile   = "/keys/password.txt"
	smokeKeystoreInRepo = "testdata/vectors/keystores/" + smokeKeystore
)

// fingerprintRE finds the certificate fingerprint the signer logs.
var fingerprintRE = regexp.MustCompile(`sha256-fingerprint="?([0-9A-F]{2}(?::[0-9A-F]{2}){31})"?`)

// smokeEnv is one smoke test run: the image, a user-defined network and the
// read-only inputs the containers mount.
type smokeEnv struct {
	t       *testing.T
	image   string
	prefix  string // container, volume and network names start with it
	network string
	keys    string // key volume: one keystore and its password file
	netDir  string // directory holding network.yaml
	client  string // directory holding the smokeclient binary
	pubkey  string
	gvr     string
}

// TestDockerSmoke runs the smoke test on the image named by
// REMOTESIGNER_SMOKE_IMAGE (make docker-smoke). TestReleaseImages runs it on
// the release dry run's images.
func TestDockerSmoke(t *testing.T) {
	image := os.Getenv("REMOTESIGNER_SMOKE_IMAGE")
	if image == "" {
		t.Skip("set REMOTESIGNER_SMOKE_IMAGE to an image built from deploy/docker/Dockerfile (make docker-smoke)")
	}
	requireDocker(t)
	smoke(t, image)
}

// smoke runs image through its real entrypoint on a user-defined Docker
// network, as an operator would, hardened (read-only root file system, no
// capabilities, no new privileges): a file network with
// --network-genesis-time and --network-genesis-validators-root, one
// keystore loaded from a keystore directory with its password file, and a
// client container that reaches the signer by name at
// https://signer:9000, pinning the certificate by the fingerprint the signer
// logged, and checks that the signer runs as the nonroot user. It also
// checks the refusals: no certificate with generation off, no host
// allowlist, no network.
func smoke(t *testing.T, image string) {
	t.Helper()
	e := newSmokeEnv(t, image)

	t.Run("image configuration", func(t *testing.T) {
		cfg := inspectImage(t, image)
		flavour := cfg.Config.Labels["org.opencontainers.image.title"]
		if flavour != fullFlavour && flavour != consensusFlavour {
			t.Fatalf("image title %q names no flavour", flavour)
		}
		licences := cfg.Config.Labels["org.opencontainers.image.licenses"]
		checkImageConfig(t, flavour, cfg, licences)
		if !strings.Contains(licences, "Apache-2.0") {
			t.Errorf("licence label %q does not name Apache-2.0", licences)
		}
	})

	// The guide checks the keystores with the image before the first start.
	t.Run("keystore verify", func(t *testing.T) {
		out, errOut, code, err := dockerRun(append(append([]string{"run", "--rm"}, e.signerFlags(e.volume("verify"))...),
			image, "consensus", "keystore", "verify", "--keystores-path="+smokeKeystoresPath,
			"--keystores-password-file="+smokePasswordFile)...)
		if err != nil {
			t.Fatal(err)
		}
		if code != 0 || !strings.Contains(out, "1 keystores: 1 OK, 0 refused") {
			t.Errorf("keystore verify: exit %d: %s%s", code, out, errOut)
		}
	})

	t.Run("serves TLS with a generated certificate", func(t *testing.T) {
		vol := e.volume("data")
		ctr := e.startSigner(vol)
		fp := e.fingerprint(ctr)
		e.checkNonroot(ctr)
		r := e.runClient(vol, fp)
		if r.TLSVersion != "TLS 1.3" || r.Upcheck != "OK" {
			t.Errorf("client saw %s and /upcheck %q, want TLS 1.3 and OK", r.TLSVersion, r.Upcheck)
		}
		for name, want := range map[string]string{".": "0700", "auth-token": "0600", "admin-token": "0600",
			"tls": "0700", "tls/cert.pem": "0600", "tls/key.pem": "0600"} {
			f, ok := r.Files[name]
			switch {
			case !ok:
				t.Errorf("/data/%s: not reported", name)
			case f.Mode != want || f.UID != 65532:
				t.Errorf("/data/%s: mode %s owner %d, want mode %s owner 65532", name, f.Mode, f.UID, want)
			}
		}
		if f := r.Files["slashing-protection.db"]; f.UID != 65532 {
			t.Errorf("/data/slashing-protection.db: owner %d, want 65532", f.UID)
		}

		// SIGTERM stops it cleanly, and the next start on the same volume
		// serves the same certificate.
		docker(t, "stop", "--time=30", ctr)
		if code := strings.TrimSpace(docker(t, "inspect", "--format", "{{.State.ExitCode}}", ctr)); code != "0" {
			t.Errorf("exit code %s after SIGTERM, want 0", code)
		}
		// The upgrade guide migrates the stopped signer's volume with the
		// new image before it starts that image.
		out, errOut, code, err := dockerRun(append(append([]string{"run", "--rm"}, e.signerFlags(vol)...),
			image, "consensus", "migrate")...)
		if err != nil {
			t.Fatal(err)
		}
		if code != 0 || !strings.Contains(out, "; nothing to do") {
			t.Errorf("consensus migrate on the data volume: exit %d: %s%s", code, out, errOut)
		}
		again := e.startSigner(vol)
		if fp2 := e.fingerprint(again); fp2 != fp {
			t.Errorf("after a restart the signer serves %s, want the certificate it generated, %s", fp2, fp)
		}
		e.runClient(vol, fp)
		docker(t, "rm", "--force", again)
	})

	// An orchestrator (a compose file, Kurtosis) appends its flags after
	// the entrypoint's, and for a single-value flag the last one wins.
	t.Run("appended flags override the entrypoint's", func(t *testing.T) {
		ctr := e.startSigner(e.volume("override"), "--http-listen-host=127.0.0.1", "--http-listen-port=9100")
		e.waitLog(ctr, `msg="remotesigner is listening; loading keys" address="127.0.0.1:9100"`)
		docker(t, "rm", "--force", ctr)
	})

	refusals := []struct {
		name string
		args []string // replace the default arguments; nil keeps them
		// global are extra flags before consensus.
		global   []string
		wantCode int
		wantText string
	}{
		{name: "no certificate and generation off", global: []string{"--tls-generate-self-signed=false"},
			wantCode: 1, wantText: "plaintext"},
		{name: "no host allowlist", args: e.consensusArgs(),
			wantCode: 1, wantText: "--http-host-allowlist"},
		{name: "no network", args: []string{}, wantCode: 2, wantText: "--network is required"},
	}
	for _, tt := range refusals {
		t.Run("refuses to start: "+tt.name, func(t *testing.T) {
			args := tt.args
			if args == nil {
				args = e.signerArgs(tt.global)
			}
			run := append(e.signerFlags(e.volume("refused")), image)
			out, errOut, code, err := dockerRun(append(append([]string{"run", "--rm"}, run...), args...)...)
			if err != nil {
				t.Fatal(err)
			}
			if code != tt.wantCode || !strings.Contains(out+errOut, tt.wantText) {
				t.Errorf("exit %d, want %d mentioning %q: %s%s", code, tt.wantCode, tt.wantText, out, errOut)
			}
		})
	}

	t.Run("compose example", func(t *testing.T) {
		if _, _, code, err := dockerRun("compose", "version"); err != nil || code != 0 {
			t.Skip("docker compose is not installed")
		}
		cmd := exec.Command("docker", "compose", "--file", filepath.Join(root, "deploy/docker/compose.yaml"),
			"config", "--quiet")
		cmd.Env = append(os.Environ(), "REMOTESIGNER_IMAGE="+image, "GENESIS_TIME="+smokeGenesisTime,
			"GENESIS_VALIDATORS_ROOT="+e.gvr, "QRYSM_VALIDATOR_IMAGE=example/validator:latest",
			"BEACON_RPC_PROVIDER=beacon:4000")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("docker compose config: %v: %s", err, out)
		}
	})
}

func newSmokeEnv(t *testing.T, image string) *smokeEnv {
	t.Helper()
	var id [4]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	e := &smokeEnv{t: t, image: image, prefix: "remotesigner-smoke-" + hex.EncodeToString(id[:])}

	// One keystore, with the light KDF.
	var password string
	e.pubkey, password = smokeKeystoreKey(t)
	var nets struct {
		Networks []struct {
			Name string `json:"name"`
			GVR  string `json:"interop_genesis_validators_root"`
		} `json:"networks"`
	}
	if err := json.Unmarshal(readRepo(t, "testdata/vectors/networks.json"), &nets); err != nil {
		t.Fatal(err)
	}
	for _, n := range nets.Networks {
		if n.Name == "end-to-end" {
			e.gvr = n.GVR
		}
	}
	if e.gvr == "" {
		t.Fatal("no end-to-end genesis validators root in testdata/vectors/networks.json")
	}

	t.Cleanup(func() { e.cleanup() })
	// The containers run as 65532. The network config is readable by
	// everyone; the password file is a secret file, which
	// --strict-file-permissions refuses when its group or other users can
	// read it, so the key volume is given to 65532 alone, as deploy-docker.md
	// says.
	e.keys = e.keyVolume([]volumeEntry{
		{name: "keystores/", mode: 0o700},
		{name: "keystores/" + smokeKeystoreName, mode: 0o600,
			content: string(readRepo(t, smokeKeystoreInRepo))},
		{name: "password.txt", mode: 0o600, content: password + "\n"},
	})
	e.netDir = inputDir(t, "network", "config.yaml", string(readRepo(t, smokeNetwork)), 0o644)
	e.client = e.buildClient()

	e.network = e.prefix
	docker(t, "network", "create", e.network)
	return e
}

// smokeKeystoreKey returns the public key and the password of the smoke
// test's keystore, from the keystore vectors' index.
func smokeKeystoreKey(t *testing.T) (pubkey, password string) {
	t.Helper()
	var index struct {
		Keystores []struct{ File, Password, Pubkey string } `json:"keystores"`
	}
	if err := json.Unmarshal(readRepo(t, "testdata/vectors/keystores/index.json"), &index); err != nil {
		t.Fatalf("keystore index: %v", err)
	}
	for _, k := range index.Keystores {
		if k.File == smokeKeystore {
			return k.Pubkey, k.Password
		}
	}
	t.Fatalf("testdata/vectors/keystores/index.json lists no %s", smokeKeystore)
	return "", ""
}

// smokeKeystoreName is the smoke test's keystore under the name the deposit
// CLI gives it.
const smokeKeystoreName = "keystore-m_12381_238_0_0-1760000000.json"

// volumeEntry is a file, or a directory when its name ends in "/", of a
// volume keyVolume fills.
type volumeEntry struct {
	name    string
	mode    int64
	content string
}

// keyVolume creates a named volume holding entries, owned by the image's
// user, and returns the volume's name. A bind mount cannot set that owner
// without root on the host, so the files go in through docker cp, from a
// tar stream that carries the owner and modes.
func (e *smokeEnv) keyVolume(entries []volumeEntry) string {
	t := e.t
	t.Helper()
	vol := e.volume("keys")
	ctr := strings.TrimSpace(docker(t, "create", "--label", "remotesigner-smoke="+e.prefix,
		"--volume", vol+":/keys", e.image))
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, en := range entries {
		hdr := &tar.Header{Typeflag: tar.TypeReg, Name: en.name, Mode: en.mode, Uid: 65532, Gid: 65532,
			Size: int64(len(en.content)), ModTime: time.Now()}
		if strings.HasSuffix(en.name, "/") {
			hdr.Typeflag, hdr.Size = tar.TypeDir, 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(en.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("docker", "cp", "--archive", "-", ctr+":/keys")
	cmd.Stdin = &b
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("docker cp into the key volume: %v: %s", err, out)
	}
	docker(t, "rm", ctr)
	return vol
}

// inputDir writes one file into a new directory, both readable by every
// user, and returns the directory.
func inputDir(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), dir)
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, name), []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	// Mkdir and WriteFile apply the umask.
	for p, m := range map[string]os.FileMode{d: 0o755, filepath.Join(d, name): mode} {
		if err := os.Chmod(p, m); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// buildClient builds the smokeclient for the image's architecture and
// returns the directory that holds it.
func (e *smokeEnv) buildClient() string {
	t := e.t
	t.Helper()
	cfg := inspectImage(t, e.image)
	dir := filepath.Join(t.TempDir(), "client")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-trimpath", "-o", filepath.Join(dir, "smokeclient"), "./smokeclient")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+cfg.Architecture, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build smokeclient: %v: %s", err, out)
	}
	return dir
}

// volume creates a named volume for one signer's /data and returns its
// name.
func (e *smokeEnv) volume(suffix string) string {
	e.t.Helper()
	var id [3]byte
	if _, err := rand.Read(id[:]); err != nil {
		e.t.Fatal(err)
	}
	name := e.prefix + "-" + suffix + "-" + hex.EncodeToString(id[:])
	docker(e.t, "volume", "create", "--label", "remotesigner-smoke="+e.prefix, name)
	return name
}

// signerFlags are the docker run flags of a signer container: hardened, on
// the test network under the service name, with its data volume and the
// read-only inputs.
func (e *smokeEnv) signerFlags(vol string) []string {
	return []string{"--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=2g",
		"--stop-timeout=30", "--label", "remotesigner-smoke=" + e.prefix,
		"--network", e.network, "--network-alias", signerAlias,
		"--volume", vol + ":/data",
		"--volume", e.keys + ":/keys:ro",
		"--volume", e.netDir + ":/network:ro"}
}

// consensusArgs are the consensus arguments an operator appends to the
// entrypoint, after the global flags given: the network, its genesis time
// and validators root, and the keystore directory with its password file.
func (e *smokeEnv) consensusArgs(global ...string) []string {
	return append(global, "consensus", "--network=/network/config.yaml",
		"--network-genesis-time="+smokeGenesisTime, "--network-genesis-validators-root="+e.gvr,
		"--keystores-path="+smokeKeystoresPath, "--keystores-password-file="+smokePasswordFile)
}

// signerArgs are the arguments of a working signer, with extra global
// flags after the host allowlist.
func (e *smokeEnv) signerArgs(extra []string) []string {
	return e.consensusArgs(append([]string{"--http-host-allowlist=" + signerAlias}, extra...)...)
}

// startSigner starts a signer container on vol, with extra global flags
// after the entrypoint's, and returns its name.
func (e *smokeEnv) startSigner(vol string, extra ...string) string {
	e.t.Helper()
	var id [3]byte
	if _, err := rand.Read(id[:]); err != nil {
		e.t.Fatal(err)
	}
	name := e.prefix + "-signer-" + hex.EncodeToString(id[:])
	args := append([]string{"run", "--detach", "--name", name}, e.signerFlags(vol)...)
	args = append(append(args, e.image), e.signerArgs(extra)...)
	docker(e.t, args...)
	return name
}

// fingerprint waits for the signer in ctr to log its certificate's
// fingerprint and returns it.
func (e *smokeEnv) fingerprint(ctr string) string {
	e.t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		out, errOut, _, err := dockerRun("logs", ctr)
		if err != nil {
			e.t.Fatal(err)
		}
		if m := fingerprintRE.FindStringSubmatch(out + errOut); m != nil {
			return m[1]
		}
		running := strings.TrimSpace(docker(e.t, "inspect", "--format", "{{.State.Running}}", ctr))
		if running != "true" || time.Now().After(deadline) {
			e.t.Fatalf("the signer logged no certificate fingerprint (running: %s):\n%s%s", running, out, errOut)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// waitLog waits for the signer in ctr to log a line containing want.
func (e *smokeEnv) waitLog(ctr, want string) {
	e.t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		out, errOut, _, err := dockerRun("logs", ctr)
		if err != nil {
			e.t.Fatal(err)
		}
		if strings.Contains(out+errOut, want) {
			return
		}
		running := strings.TrimSpace(docker(e.t, "inspect", "--format", "{{.State.Running}}", ctr))
		if running != "true" || time.Now().After(deadline) {
			e.t.Fatalf("the signer did not log %q (running: %s):\n%s%s", want, running, out, errOut)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// checkNonroot checks that the signer's process runs as the nonroot user.
func (e *smokeEnv) checkNonroot(ctr string) {
	e.t.Helper()
	out := docker(e.t, "top", ctr, "-o", "pid,uid,gid,args")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		e.t.Fatalf("docker top: want one process:\n%s", out)
	}
	if f := strings.Fields(lines[1]); len(f) < 3 || f[1] != "65532" || f[2] != "65532" {
		e.t.Errorf("the signer runs as %q, want uid and gid 65532", lines[1])
	}
}

// clientReport is smokeclient's JSON report.
type clientReport struct {
	TLSVersion string   `json:"tls_version"`
	Upcheck    string   `json:"upcheck"`
	Keys       []string `json:"keys"`
	Files      map[string]struct {
		Mode string `json:"mode"`
		UID  int64  `json:"uid"`
	} `json:"files"`
}

// runClient runs the client container against the signer that uses vol,
// pinning fingerprint, and returns its report.
func (e *smokeEnv) runClient(vol, fingerprint string) clientReport {
	e.t.Helper()
	out, errOut, code, err := dockerRun("run", "--rm", "--read-only", "--cap-drop=ALL",
		"--security-opt=no-new-privileges", "--label", "remotesigner-smoke="+e.prefix,
		"--network", e.network,
		"--volume", vol+":/signer-data:ro",
		"--volume", e.client+":/client:ro",
		"--entrypoint", "/client/smokeclient",
		e.image,
		"-url", "https://"+signerAlias+":9000", "-fingerprint", fingerprint,
		"-token-file", "/signer-data/auth-token", "-want-key", e.pubkey, "-data", "/signer-data")
	if err != nil {
		e.t.Fatal(err)
	}
	if code != 0 {
		e.t.Fatalf("client container: exit %d: %s%s", code, out, errOut)
	}
	var r clientReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		e.t.Fatalf("client report: %v: %s", err, out)
	}
	return r
}

// cleanup removes every container and volume of this run, and its network.
func (e *smokeEnv) cleanup() {
	filter := "label=remotesigner-smoke=" + e.prefix
	if out, _, _, err := dockerRun("ps", "--all", "--quiet", "--filter", filter); err == nil {
		if ids := strings.Fields(out); len(ids) > 0 {
			_, _, _, _ = dockerRun(append([]string{"rm", "--force", "--volumes"}, ids...)...)
		}
	}
	if out, _, _, err := dockerRun("volume", "ls", "--quiet", "--filter", filter); err == nil {
		if names := strings.Fields(out); len(names) > 0 {
			_, _, _, _ = dockerRun(append([]string{"volume", "rm", "--force"}, names...)...)
		}
	}
	_, _, _, _ = dockerRun("network", "rm", e.network)
}

// guideMarker marks the `docker run` example of the Docker guide that the
// smoke test mirrors.
const guideMarker = "<!-- docker-smoke:run -->"

// guideRun returns the docker options and the signer's arguments of the
// `docker run` command in the block that follows guideMarker in
// docs/operations/deploy-docker.md.
func guideRun(t *testing.T) (opts, args []string) {
	t.Helper()
	text := string(readRepo(t, "docs/operations/deploy-docker.md"))
	_, after, ok := strings.Cut(text, guideMarker+"\n```\n")
	if !ok {
		t.Fatalf("deploy-docker.md has no code block after %s", guideMarker)
	}
	block, _, _ := strings.Cut(after, "\n```")
	for _, line := range strings.Split(strings.ReplaceAll(block, "\\\n", " "), "\n") {
		words := shellWords(line)
		if len(words) < 2 || words[0] != "docker" || words[1] != "run" {
			continue
		}
		for i, w := range words[2:] {
			if strings.HasPrefix(w, "ghcr.io/") {
				return words[2 : 2+i], words[3+i:]
			}
		}
	}
	t.Fatalf("the block after %s has no docker run of a ghcr.io image", guideMarker)
	return nil, nil
}

// shellWords splits a shell command line into words, with double quotes
// grouping, as the guide's commands use them.
func shellWords(line string) []string {
	var words []string
	var w strings.Builder
	inWord, quoted := false, false
	for _, r := range line {
		switch {
		case r == '"':
			quoted, inWord = !quoted, true
		case (r == ' ' || r == '\t') && !quoted:
			if inWord {
				words, inWord = append(words, w.String()), false
				w.Reset()
			}
		default:
			w.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		words = append(words, w.String())
	}
	return words
}

// dockerOptions groups docker run options by name; an option given as
// "--name value" or "--name=value" gets its value, a bare one "".
func dockerOptions(words []string) map[string][]string {
	takesValue := map[string]bool{"--name": true, "--network": true, "--network-alias": true, "-v": true,
		"--volume": true, "--label": true}
	out := map[string][]string{}
	for i := 0; i < len(words); i++ {
		name, value, hasValue := strings.Cut(words[i], "=")
		if name == "-v" {
			name = "--volume"
		}
		if !hasValue && takesValue[words[i]] && i+1 < len(words) {
			value, i = words[i+1], i+1
		}
		out[name] = append(out[name], value)
	}
	return out
}

// volumeTargets returns the container side of each volume option, with its
// mode: "/keys:ro" for "$PWD/keys:/keys:ro".
func volumeTargets(volumes []string) []string {
	var out []string
	for _, v := range volumes {
		_, target, _ := strings.Cut(v, ":")
		out = append(out, target)
	}
	slices.Sort(out)
	return out
}

// TestDockerGuideMatchesSmoke keeps the Docker guide's `docker run` example
// and the smoke test in step, without Docker: the same hardening, memory
// limit, service name and mounts, and the same signer arguments, chain values
// aside. The smoke test then runs what the guide tells an operator to run.
func TestDockerGuideMatchesSmoke(t *testing.T) {
	opts, args := guideRun(t)
	e := &smokeEnv{prefix: "p", network: "n", keys: "k", netDir: "d",
		gvr: "0x9471e8fb19e0faae953e9d46889f207192bcec9b14293d7ba418ae4dc5e3ac8f"}
	guide, smoke := dockerOptions(opts), dockerOptions(e.signerFlags("v"))
	for _, name := range []string{"--read-only", "--cap-drop", "--security-opt", "--memory", "--stop-timeout",
		"--network-alias"} {
		if !slices.Equal(guide[name], smoke[name]) {
			t.Errorf("%s: the guide gives %q, the smoke test %q", name, guide[name], smoke[name])
		}
	}
	if g, s := volumeTargets(guide["--volume"]), volumeTargets(smoke["--volume"]); !slices.Equal(g, s) {
		t.Errorf("mounts: the guide has %q, the smoke test %q", g, s)
	}
	if g, s := withoutChainValues(args), withoutChainValues(e.signerArgs(nil)); !slices.Equal(g, s) {
		t.Errorf("signer arguments:\n the guide      %q\n the smoke test %q", g, s)
	}
}

// chainValue is a signer argument that carries one chain's value.
var chainValue = regexp.MustCompile(`^(--network-genesis-time|--network-genesis-validators-root)=.*`)

// withoutChainValues returns args with the chain's values replaced by a
// placeholder, which the guide, the smoke test and the compose example each
// give their own way.
func withoutChainValues(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = chainValue.ReplaceAllString(a, "$1=<value>")
	}
	return out
}

// TestComposeMatchesGuide keeps the compose example's signer in step with
// the Docker guide's `docker run` example, and so with the smoke test that
// runs it: the same arguments, chain values aside, the same mounts, memory
// limit and stop grace period, and the same hardening.
func TestComposeMatchesGuide(t *testing.T) {
	opts, args := guideRun(t)
	guide := dockerOptions(opts)
	var c struct {
		Services map[string]struct {
			Command         []string `yaml:"command"`
			ReadOnly        bool     `yaml:"read_only"`
			CapDrop         []string `yaml:"cap_drop"`
			SecurityOpt     []string `yaml:"security_opt"`
			MemLimit        string   `yaml:"mem_limit"`
			StopGracePeriod string   `yaml:"stop_grace_period"`
			Volumes         []string `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(readRepo(t, "deploy/docker/compose.yaml"), &c); err != nil {
		t.Fatal(err)
	}
	s, ok := c.Services["signer"]
	if !ok {
		t.Fatal("deploy/docker/compose.yaml has no signer service")
	}
	if g, s := withoutChainValues(args), withoutChainValues(s.Command); !slices.Equal(g, s) {
		t.Errorf("signer arguments:\n the guide   %q\n compose.yaml %q", g, s)
	}
	if g, s := volumeTargets(guide["--volume"]), volumeTargets(s.Volumes); !slices.Equal(g, s) {
		t.Errorf("mounts: the guide has %q, compose.yaml %q", g, s)
	}
	for _, tt := range []struct{ option, guide, compose string }{
		{"--memory / mem_limit", strings.Join(guide["--memory"], ","), s.MemLimit},
		{"--stop-timeout / stop_grace_period", strings.Join(guide["--stop-timeout"], ",") + "s", s.StopGracePeriod},
		{"--cap-drop / cap_drop", strings.Join(guide["--cap-drop"], ","), strings.Join(s.CapDrop, ",")},
		{"--security-opt / security_opt", strings.Join(guide["--security-opt"], ",") + ":true",
			strings.Join(s.SecurityOpt, ",")},
	} {
		if tt.guide != tt.compose {
			t.Errorf("%s: the guide gives %q, compose.yaml %q", tt.option, tt.guide, tt.compose)
		}
	}
	if _, ok := guide["--read-only"]; !ok || !s.ReadOnly {
		t.Errorf("read-only root file system: the guide %v, compose.yaml %v", ok, s.ReadOnly)
	}
}
