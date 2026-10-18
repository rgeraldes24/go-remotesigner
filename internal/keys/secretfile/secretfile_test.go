// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package secretfile

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, data string, mode fs.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // not subject to the umask
		t.Fatal(err)
	}
	return p
}

// A secret file readable by group or others is refused under the strict
// policy and read with a warning otherwise; owner-only modes pass silently.
func TestReadPolicy(t *testing.T) {
	if !posixModes {
		t.Skip("file modes carry no POSIX permissions on this platform")
	}
	for _, tt := range []struct {
		mode   fs.FileMode
		strict bool
		refuse bool
		warn   bool
	}{
		{0o600, true, false, false},
		{0o400, true, false, false},
		{0o700, true, false, false},
		{0o620, true, false, false}, // group-writable but not readable
		{0o640, true, true, false},
		{0o604, true, true, false},
		{0o644, true, true, false},
		{0o644, false, false, true},
		{0o640, false, false, true},
		{0o600, false, false, false},
	} {
		t.Run(tt.mode.String(), func(t *testing.T) {
			p := write(t, "hunter2\n", tt.mode)
			var warned []string
			pol := Policy{Strict: tt.strict, Warn: func(path string, mode fs.FileMode) {
				warned = append(warned, path)
				if mode != tt.mode {
					t.Errorf("warned with mode %v", mode)
				}
			}}
			got, err := Read(p, 64, pol)
			if tt.refuse {
				if !errors.Is(err, ErrInsecure) || got != nil {
					t.Fatalf("Read = %q, %v; want ErrInsecure", got, err)
				}
				if !strings.Contains(err.Error(), p) || !strings.Contains(err.Error(), "--strict-file-permissions=false") {
					t.Errorf("error %q does not name the file and the flag", err)
				}
				return
			}
			if err != nil || string(got) != "hunter2\n" {
				t.Fatalf("Read = %q, %v", got, err)
			}
			if (len(warned) == 1) != tt.warn {
				t.Fatalf("warnings %v, want warn=%v", warned, tt.warn)
			}
		})
	}
}

func TestReadRefusals(t *testing.T) {
	dir := t.TempDir()
	if _, err := Read(dir, 64, Policy{Strict: true}); !errors.Is(err, ErrNotRegular) {
		t.Errorf("a directory: %v", err)
	}
	if _, err := Read(filepath.Join(dir, "missing"), 64, Policy{Strict: true}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing file: %v", err)
	}
	big := write(t, strings.Repeat("x", 65), 0o600)
	if _, err := Read(big, 64, Policy{Strict: true}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("a file over the limit: %v", err)
	}
	if got, err := ReadCapped(write(t, "pw", 0o600), 64); err != nil || string(got) != "pw" {
		t.Errorf("ReadCapped = %q, %v", got, err)
	}
}

// Where file modes carry no POSIX permissions (Windows), the strict policy
// refuses only what is not a regular file.
func TestCheckWithoutPOSIXModes(t *testing.T) {
	defer func(v bool) { posixModes = v }(posixModes)
	posixModes = false
	p := write(t, "pw", 0o644)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	warned := false
	pol := Policy{Strict: true, Warn: func(string, fs.FileMode) { warned = true }}
	if err := pol.Check(p, fi); err != nil || warned {
		t.Fatalf("Check = %v, warned %v", err, warned)
	}
	dir, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := pol.Check("dir", dir); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("a directory: %v", err)
	}
}

// retainingReader serves data, then fails with err, and keeps the slices
// of the caller's buffer it wrote into, so that a test can check that the
// caller wiped them.
type retainingReader struct {
	data    []byte
	err     error
	written [][]byte
}

func (r *retainingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	r.written = append(r.written, p[:n])
	return n, nil
}

// TestReadLimitedWipes checks that the reader wipes what it read when the
// read fails or the file is too large, and returns the content otherwise.
func TestReadLimitedWipes(t *testing.T) {
	const limit = 64
	for _, tt := range []struct {
		name    string
		data    string
		err     error
		wantErr string
	}{
		{"read error after part of the file", "hunter2-partial", errors.New("input/output error"), "input/output error"},
		{"larger than the limit", strings.Repeat("hunter2!", limit/8+1), io.EOF, "larger than 64 bytes"},
		{"exactly the limit", strings.Repeat("hunter2!", limit/8), io.EOF, ""},
		{"short", "hunter2\n", io.EOF, ""},
		{"empty", "", io.EOF, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &retainingReader{data: []byte(tt.data), err: tt.err}
			got, err := ReadLimited(r, limit)
			if tt.wantErr == "" {
				if err != nil || string(got) != tt.data {
					t.Fatalf("got %q, %v; want %q", got, err, tt.data)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) || got != nil {
				t.Fatalf("got %q, %v; want an error mentioning %q", got, err, tt.wantErr)
			}
			if len(r.written) == 0 {
				t.Fatal("the reader was never read")
			}
			for _, b := range r.written {
				if !bytes.Equal(b, make([]byte, len(b))) {
					t.Errorf("the buffer still holds %q", b)
				}
			}
		})
	}
}
