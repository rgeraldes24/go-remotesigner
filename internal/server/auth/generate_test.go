// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
)

// The process test re-runs the test binary as helpers that each load or
// generate one token file.
const (
	envGenerateHelper = "AUTH_TEST_GENERATE_HELPER"
	helperReady       = "ready"
)

// TestGenerateHelperProcess is the helper's entry point; it does nothing in
// a normal test run. It reports that it is ready, waits for the line that
// starts every helper at once, loads or generates the token file and prints
// the token's digest.
func TestGenerateHelperProcess(t *testing.T) {
	path := os.Getenv(envGenerateHelper)
	if path == "" {
		return
	}
	fmt.Println(helperReady)
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		fmt.Fprintln(os.Stderr, "helper: wait for the start:", err)
		os.Exit(2)
	}
	d, err := loadOrGenerate(path, secretfile.Policy{Strict: true})
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(d[:]))
	os.Exit(0)
}

// result is one caller's outcome.
type result struct {
	digest [sha256.Size]byte
	err    error
}

// inGoroutines runs n callers of loadOrGenerate on path, released at once.
func inGoroutines(t *testing.T, path string, n int) []result {
	t.Helper()
	out := make([]result, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			out[i].digest, out[i].err = loadOrGenerate(path, secretfile.Policy{Strict: true})
		}()
	}
	close(start)
	wg.Wait()
	return out
}

// inProcesses runs n helper processes on path, released at once once all
// of them are ready.
func inProcesses(t *testing.T, path string, n int) []result {
	t.Helper()
	type helper struct {
		cmd    *exec.Cmd
		stdin  io.WriteCloser
		stdout *bufio.Reader
		stderr *bytes.Buffer
	}
	helpers := make([]helper, n)
	for i := range helpers {
		cmd := exec.Command(os.Args[0], "-test.run=^TestGenerateHelperProcess$", "-test.count=1")
		cmd.Env = append(os.Environ(), envGenerateHelper+"="+path)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		stderr := new(bytes.Buffer)
		cmd.Stderr = stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = stdin.Close()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
		helpers[i] = helper{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout), stderr: stderr}
	}
	for i, h := range helpers {
		if line, err := h.stdout.ReadString('\n'); err != nil || strings.TrimSpace(line) != helperReady {
			t.Fatalf("helper %d: %q, %v; want %q", i, line, err, helperReady)
		}
	}
	for _, h := range helpers {
		if _, err := io.WriteString(h.stdin, "go\n"); err != nil {
			t.Fatal(err)
		}
	}
	out := make([]result, n)
	for i, h := range helpers {
		line, _ := h.stdout.ReadString('\n')
		if err := h.cmd.Wait(); err != nil {
			out[i].err = fmt.Errorf("helper %d: %w: %s", i, err, strings.TrimSpace(h.stderr.String()))
			continue
		}
		b, err := hex.DecodeString(strings.TrimSpace(line))
		if err != nil || len(b) != sha256.Size {
			out[i].err = fmt.Errorf("helper %d printed %q", i, line)
			continue
		}
		copy(out[i].digest[:], b)
	}
	return out
}

// Signers started at once on one data path, as goroutines and as separate
// processes, all end up with the one token that was generated: none loads
// the file another caller has created but not yet written. No temporary
// file is left next to it. Before token files were linked into place, a
// few rounds were enough for a caller to load an empty or a partial file.
func TestConcurrentTokenGeneration(t *testing.T) {
	for _, tt := range []struct {
		name            string
		rounds, callers int
		run             func(t *testing.T, path string, n int) []result
	}{
		{"goroutines", 50, 16, inGoroutines},
		{"processes", 5, 8, inProcesses},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for round := range tt.rounds {
				dir := filepath.Join(t.TempDir(), "data")
				path := filepath.Join(dir, "auth-token")
				got := tt.run(t, path, tt.callers)

				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("round %d: %v", round, err)
				}
				tok := bytes.TrimSpace(data)
				if !ValidToken(tok) {
					t.Fatalf("round %d: the token file holds %q", round, data)
				}
				want := sha256.Sum256(tok)
				for i, r := range got {
					switch {
					case r.err != nil:
						t.Fatalf("round %d: caller %d: %v", round, i, r.err)
					case r.digest != want:
						t.Fatalf("round %d: caller %d loaded another token than the file's", round, i)
					}
				}
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				var names []string
				for _, e := range entries {
					names = append(names, e.Name())
				}
				if !slices.Equal(names, []string{"auth-token"}) {
					t.Fatalf("round %d: the directory holds %v, want the token file only", round, names)
				}
			}
		})
	}
}

// A token file is written to a temporary file next to it, which holds the
// whole token, mode 0600, before it is linked into place; a caller that
// finds a file there already loads that one; a file system without hard
// links gets the file written in place; and no path leaves the temporary
// file behind.
func TestCreateExclusive(t *testing.T) {
	const winner = "0x4444444444444444444444444444444444444444444444444444444444444444"
	linkErr := func(errno syscall.Errno) func(string, string) error {
		return func(oldname, newname string) error {
			return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: errno}
		}
	}
	// plant writes a complete file at the token's name, as a concurrent
	// signer would, before the link.
	plant := func(content string, then func(string, string) error) func(string, string) error {
		return func(oldname, newname string) error {
			if err := os.WriteFile(newname, []byte(content), 0o600); err != nil {
				return err
			}
			return then(oldname, newname)
		}
	}
	// blocked puts a directory at the token's name, so that neither the
	// link nor the exclusive create in place can make the file.
	blocked := func(then func(string, string) error) func(string, string) error {
		return func(oldname, newname string) error {
			if err := os.Mkdir(newname, 0o700); err != nil {
				return err
			}
			return then(oldname, newname)
		}
	}
	for _, tt := range []struct {
		name    string
		link    func(oldname, newname string) error
		want    string // the token loaded; empty for the one generated
		wantErr error
	}{
		{name: "linked", link: os.Link},
		{name: "another caller linked first", link: plant(winner+"\n", os.Link), want: winner},
		{name: "another caller linked an invalid token", link: plant("0x12\n", os.Link), wantErr: ErrInvalidToken},
		{name: "no hard links, EPERM", link: linkErr(syscall.EPERM)},
		{name: "no hard links, ENOTSUP", link: linkErr(syscall.ENOTSUP)},
		{name: "no hard links, another caller first", link: plant(winner+"\n", linkErr(syscall.EPERM)), want: winner},
		{name: "no hard links, ENOSYS", link: linkErr(syscall.ENOSYS)},
		{name: "no hard links, an error of the file system's own", link: linkErr(syscall.EIO)},
		{name: "neither a link nor a file in place", link: blocked(linkErr(syscall.EIO)), wantErr: secretfile.ErrNotRegular},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "data")
			path := filepath.Join(dir, "auth-token")
			linked := 0
			link = func(oldname, newname string) error {
				linked++
				if base := filepath.Base(oldname); filepath.Dir(oldname) != dir ||
					!strings.HasPrefix(base, ".auth-token.") || !strings.HasSuffix(base, ".tmp") || newname != path {
					t.Errorf("link(%s, %s), want a temporary .auth-token.*.tmp file next to %s", oldname, newname, path)
				}
				data, err := os.ReadFile(oldname)
				if err != nil || !ValidToken(bytes.TrimSpace(data)) {
					t.Errorf("the temporary file holds %q (%v) when it is linked, want the whole token", data, err)
				}
				if fi, err := os.Stat(oldname); err != nil || fi.Mode().Perm()&^0o600 != 0 {
					t.Errorf("the temporary file: %v, %v; want mode 0600 at most", fi, err)
				}
				return tt.link(oldname, newname)
			}
			t.Cleanup(func() { link = os.Link })

			d, err := loadOrGenerate(path, secretfile.Policy{Strict: true})
			if linked != 1 {
				t.Fatalf("%d links, want 1", linked)
			}
			entries, rerr := os.ReadDir(dir)
			if rerr != nil {
				t.Fatal(rerr)
			}
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("loadOrGenerate = %v, want %v", err, tt.wantErr)
				}
				if !slices.Equal(names, []string{"auth-token"}) {
					t.Fatalf("the directory holds %v, want what was at the token's name only", names)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadOrGenerate = %v", err)
			}
			if !slices.Equal(names, []string{"auth-token"}) {
				t.Fatalf("the directory holds %v, want the token file only", names)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			tok := string(bytes.TrimSpace(data))
			switch {
			case tt.want != "" && tok != tt.want:
				t.Fatalf("the token file holds %q, want the other caller's %q", tok, tt.want)
			case !ValidToken([]byte(tok)):
				t.Fatalf("the token file holds %q", data)
			case d != sha256.Sum256([]byte(tok)):
				t.Fatal("loaded another token than the file's")
			}
			if fi, err := os.Stat(path); err != nil || fi.Mode().Perm()&^0o600 != 0 {
				t.Fatalf("the token file: %v, %v; want mode 0600 at most", fi, err)
			}
		})
	}
}
