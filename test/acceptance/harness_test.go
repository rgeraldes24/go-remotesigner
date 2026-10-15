// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package acceptance runs the built remotesigner binary and checks its
// behaviour over HTTP and signals. TestMain builds the binary once, unless
// REMOTESIGNER_BINARY names one already built.
package acceptance

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

var binary string

func TestMain(m *testing.M) {
	os.Exit(func() int {
		if b := os.Getenv("REMOTESIGNER_BINARY"); b != "" {
			binary = b
			return m.Run()
		}
		dir, err := os.MkdirTemp("", "remotesigner-acceptance")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer func() { _ = os.RemoveAll(dir) }()
		binary = filepath.Join(dir, "remotesigner")
		build := exec.Command("go", "build", "-o", binary, "../../cmd/remotesigner")
		build.Stdout, build.Stderr = os.Stdout, os.Stderr
		if err := build.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "build remotesigner:", err)
			return 1
		}
		return m.Run()
	}())
}

// networkFile is a file network (the e2e flavour: genesis validators root
// pinned on first use).
func networkFile(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../../internal/network/embedded/end-to-end.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// lockedBuffer collects a process's output safely.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type signer struct {
	t       *testing.T
	cmd     *exec.Cmd
	data    string
	keys    string
	base    string
	port    string
	output  *lockedBuffer
	done    chan struct{}
	waitErr error
	started time.Time
}

// options for one signer process.
type options struct {
	global    []string // before "consensus"
	consensus []string // after it
	env       []string
	keys      string // key-config directory; created when empty
	// noNetwork leaves --network and --network-genesis-time off the command
	// line, for tests that set them through other sources.
	noNetwork bool
}

// defaultArgs is the e2e invocation shape on an ephemeral port.
func defaultArgs(t *testing.T, data, keys string, o options) []string {
	args := []string{"--data-path=" + data, "--key-store-path=" + keys, "--http-listen-port=0", "--logging=DEBUG"}
	args = append(args, o.global...)
	args = append(args, "consensus")
	if !o.noNetwork {
		args = append(args, "--network="+networkFile(t), "--network-genesis-time=1760000000")
	}
	return append(args, o.consensus...)
}

func launch(t *testing.T, o options) *signer {
	t.Helper()
	s := &signer{t: t, data: t.TempDir(), keys: o.keys, output: &lockedBuffer{}, done: make(chan struct{})}
	if s.keys == "" {
		s.keys = t.TempDir()
	}
	s.cmd = exec.Command(binary, defaultArgs(t, s.data, s.keys, o)...)
	s.cmd.Env = append(os.Environ(), o.env...)
	s.cmd.Stdout, s.cmd.Stderr = s.output, s.output
	s.started = time.Now()
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		s.waitErr = s.cmd.Wait()
		close(s.done)
	}()
	t.Cleanup(func() {
		_ = s.cmd.Process.Kill()
		<-s.done
		if t.Failed() {
			t.Logf("signer output:\n%s", s.output.String())
		}
	})
	return s
}

// start launches a signer and waits for its ports file.
func start(t *testing.T, o options) *signer {
	t.Helper()
	s := launch(t, o)
	ports := filepath.Join(s.data, "remotesigner.ports")
	deadline := time.Now().Add(10 * time.Second)
	for s.port == "" {
		select {
		case <-s.done:
			t.Fatalf("signer exited: %v\n%s", s.waitErr, s.output.String())
		default:
		}
		if data, err := os.ReadFile(ports); err == nil {
			for line := range strings.SplitSeq(string(data), "\n") {
				if p, ok := strings.CutPrefix(line, "http-port="); ok {
					s.port = p
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no ports file\n%s", s.output.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.base = "http://localhost:" + s.port
	return s
}

func (s *signer) token(name string) string {
	s.t.Helper()
	data, err := os.ReadFile(filepath.Join(s.data, name))
	if err != nil {
		s.t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func (s *signer) signToken() string  { return s.token("auth-token") }
func (s *signer) adminToken() string { return s.token("admin-token") }

// request is one HTTP call; zero fields are left out.
type request struct {
	method, path, token, contentType, origin, host string
	body                                           io.Reader
}

func (s *signer) do(r request) (int, string, http.Header) {
	s.t.Helper()
	if r.method == "" {
		r.method = http.MethodGet
	}
	req, err := http.NewRequest(r.method, s.base+r.path, r.body)
	if err != nil {
		s.t.Fatal(err)
	}
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	if r.contentType != "" {
		req.Header.Set("Content-Type", r.contentType)
	}
	if r.origin != "" {
		req.Header.Set("Origin", r.origin)
	}
	if r.host != "" {
		req.Host = r.host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header
}

func (s *signer) waitReady() time.Duration {
	s.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if code, _, _ := s.do(request{path: "/upcheck"}); code == 200 {
			return time.Since(s.started)
		}
		if time.Now().After(deadline) {
			s.t.Fatalf("never ready\n%s", s.output.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (s *signer) signal(sig syscall.Signal) {
	s.t.Helper()
	if err := s.cmd.Process.Signal(sig); err != nil {
		s.t.Fatal(err)
	}
}

// exitCode waits for the process to exit and returns its code.
func (s *signer) exitCode(timeout time.Duration) int {
	s.t.Helper()
	select {
	case <-s.done:
	case <-time.After(timeout):
		s.t.Fatalf("signer did not exit\n%s", s.output.String())
	}
	var ee *exec.ExitError
	if errors.As(s.waitErr, &ee) {
		return ee.ExitCode()
	}
	if s.waitErr != nil {
		s.t.Fatal(s.waitErr)
	}
	return 0
}

// writeKeys writes n file-raw key files and returns their canonical
// identifiers.
func writeKeys(t *testing.T, dir string, n int) []string {
	t.Helper()
	ids := make([]string, n)
	for i := range n {
		var seed [mldsa87.SeedSize]byte
		seed[0], seed[1] = byte(i), byte(i>>8)
		k, err := mldsa87.FromSeed48(&seed)
		if err != nil {
			t.Fatal(err)
		}
		pk := k.PublicKey()
		k.Zeroize()
		ids[i] = "0x" + hex.EncodeToString(pk[:])
		content := fmt.Sprintf("type: file-raw\nkeyType: ML_DSA_87\nprivateKey: \"0x%s\"\n", hex.EncodeToString(seed[:]))
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("key-%d.yaml", i)), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return ids
}
