// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	kmapi "github.com/rgeraldes24/go-remotesigner/internal/api/keymanager"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keymanager"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
	"github.com/rgeraldes24/go-remotesigner/internal/vectors"
)

// send sends body with method to path and returns the status and body.
func (r *running) send(t *testing.T, method, path, token string, body io.Reader, size int64) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, r.base+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if size > 0 {
		req.ContentLength = size
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

// importBody is a POST /qrl/v1/keystores body.
func importBody(t *testing.T, keystores [][]byte, password string) []byte {
	t.Helper()
	ks := make([]string, len(keystores))
	pws := make([]string, len(keystores))
	for i, k := range keystores {
		ks[i], pws[i] = string(k), password
	}
	b, err := json.Marshal(map[string]any{"keystores": ks, "passwords": pws})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// interopKeystore is the qrysm keystore v1 of a golden-vector interop key.
func interopKeystore(t *testing.T, s *keystoretest.Sealer, k vectors.Key) []byte {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimPrefix(k.Seed, "0x"))
	if err != nil || len(raw) != mldsa87.SeedSize {
		t.Fatalf("seed %v", err)
	}
	var seed [mldsa87.SeedSize]byte
	copy(seed[:], raw)
	ks, err := s.QRLV1(&seed, true)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

// The keymanager routes take the admin token, 32 MiB bodies and a
// 10-minute write deadline.
func TestKeymanagerRouteLimits(t *testing.T) {
	rs := keymanagerRoutes(keymanager.New(keymanager.Config{}), quiet())
	if len(rs) != 3 {
		t.Fatalf("%d routes", len(rs))
	}
	for _, rt := range rs {
		if rt.Pattern != "/qrl/v1/keystores" || rt.Scope != auth.ScopeAdmin || rt.WriteTimeout != 10*time.Minute ||
			rt.NeedsReady {
			t.Fatalf("route %+v", rt)
		}
		switch rt.Method {
		case http.MethodPost, http.MethodDelete:
			if rt.BodyLimit != 32<<20 || !rt.ReadsBody {
				t.Fatalf("route %s: limit %d", rt.Method, rt.BodyLimit)
			}
		case http.MethodGet:
			if rt.BodyLimit != 0 {
				t.Fatalf("GET body limit %d", rt.BodyLimit)
			}
		default:
			t.Fatalf("method %s", rt.Method)
		}
	}
	if kmapi.BodyLimit != 32<<20 || kmapi.WriteTimeout != 10*time.Minute || keymanager.MaxKeystores != 64 {
		t.Fatal("limits changed")
	}
}

// Against a running signer: an import loads and enables a key that then
// signs; the list shows it; a delete evicts it; the routes need the admin
// token; a body over 32 MiB is 413, and a DELETE body that is not
// application/json 415; 64 keystores are imported in one request and 65
// are refused.
func TestRunKeymanager(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Consensus.KeyManagerAPIEnabled = true
	cfg.StrictFilePermissions = true
	if err := os.Chmod(cfg.KeyConfigPath, 0o700); err != nil {
		t.Fatal(err)
	}
	r := start(t, cfg)
	r.waitReady(t)
	sealer, err := keystoretest.NewSealer("pw", keystoretest.Cheapest)
	if err != nil {
		t.Fatal(err)
	}
	sel := goldenCase(t, "minimal", signingroot.AggregationSlot, "typical")
	key := vectors.Keys(t)[sel.KeyIndex]
	const path = "/qrl/v1/keystores"

	if code, _ := r.send(t, http.MethodGet, path, r.sign, nil, 0); code != 403 {
		t.Fatalf("sign token: %d", code)
	}
	if code, _ := r.send(t, http.MethodGet, path, "", nil, 0); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := r.post(t, signPath(sel), r.sign, sel.RequestJSON); code != 404 {
		t.Fatalf("sign before the import: %d", code)
	}
	code, body := r.send(t, http.MethodPost, path, r.admin, bytes.NewReader(importBody(t, [][]byte{interopKeystore(t, sealer, key)}, "pw")), 0)
	if code != 200 || !strings.Contains(string(body), `"imported"`) {
		t.Fatalf("import: %d %s", code, body)
	}
	conforms(t, "ImportKeystoresResponse", body)
	if code, body := r.post(t, signPath(sel), r.sign, sel.RequestJSON); code != 200 {
		t.Fatalf("sign after the import: %d %s", code, body)
	}
	code, body = r.send(t, http.MethodGet, path, r.admin, nil, 0)
	if code != 200 || !strings.Contains(string(body), key.Pubkey) || !strings.Contains(string(body), `"readonly":false`) {
		t.Fatalf("list: %d %.200s", code, body)
	}
	conforms(t, "ListKeystoresResponse", body)
	entries, err := os.ReadDir(cfg.KeyConfigPath)
	if err != nil || len(entries) != 3 {
		t.Fatalf("key-config directory: %v %v", entries, err)
	}

	code, body = r.send(t, http.MethodDelete, path, r.admin, strings.NewReader(`{"pubkeys":["`+key.Pubkey+`"]}`), 0)
	if code != 200 || !strings.Contains(string(body), `"deleted"`) {
		t.Fatalf("delete: %d %s", code, body)
	}
	conforms(t, "DeleteKeystoresResponse", body)
	if code, _ := r.post(t, signPath(sel), r.sign, sel.RequestJSON); code != 404 {
		t.Fatalf("sign after the delete: %d", code)
	}

	// 32 MiB + 1 is refused on its Content-Length, before it is read.
	for _, m := range []string{http.MethodPost, http.MethodDelete} {
		code, body := r.send(t, m, path, r.admin, io.LimitReader(zeros{}, kmapi.BodyLimit+1), kmapi.BodyLimit+1)
		if code != 413 || !strings.Contains(string(body), "BODY_TOO_LARGE") {
			t.Fatalf("%s 32 MiB + 1: %d %s", m, code, body)
		}
	}

	// A DELETE body, like a POST's, must be application/json.
	for _, ctype := range []string{"", "text/plain"} {
		req, err := http.NewRequest(http.MethodDelete, r.base+path, strings.NewReader(`{"pubkeys":[]}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+r.admin)
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 415 || !strings.Contains(string(out), "UNSUPPORTED_MEDIA_TYPE") {
			t.Fatalf("DELETE with Content-Type %q: %d %s", ctype, resp.StatusCode, out)
		}
	}

	var many [][]byte
	for i := range keymanager.MaxKeystores + 1 {
		ks, err := sealer.QRLV1(keystoretest.Seed("runner-many", i), true)
		if err != nil {
			t.Fatal(err)
		}
		many = append(many, ks)
	}
	code, body = r.send(t, http.MethodPost, path, r.admin, bytes.NewReader(importBody(t, many, "pw")), 0)
	if code != 400 || !strings.Contains(string(body), "INVARIANT_VIOLATION") {
		t.Fatalf("65 keystores: %d %s", code, body)
	}
	code, body = r.send(t, http.MethodPost, path, r.admin, bytes.NewReader(importBody(t, many[:64], "pw")), 0)
	if code != 200 || strings.Count(string(body), `"imported"`) != 64 {
		t.Fatalf("64 keystores: %d %.300s", code, body)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// The keymanager needs a key-config directory that only its owner can
// access: one open to others is refused under --strict-file-permissions and
// reported otherwise, and a missing one is created 0700. Without the flag
// the routes do not exist.
func TestRunKeymanagerDirectory(t *testing.T) {
	t.Run("no key-config path", func(t *testing.T) {
		cfg := baseConfig(t)
		cfg.Consensus.KeyManagerAPIEnabled = true
		cfg.KeyConfigPath = ""
		if err := Run(context.Background(), cfg, quiet(), nil); !errors.Is(err, config.ErrKeyManagerNoKeyConfig) {
			t.Fatalf("Run = %v", err)
		}
	})
	open := func(t *testing.T) *config.Config {
		cfg := baseConfig(t)
		cfg.Consensus.KeyManagerAPIEnabled = true
		cfg.KeyConfigPath = filepath.Join(t.TempDir(), "keys")
		if err := os.Mkdir(cfg.KeyConfigPath, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(cfg.KeyConfigPath, 0o755); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	t.Run("open directory, strict", func(t *testing.T) {
		cfg := open(t)
		cfg.StrictFilePermissions = true
		if err := Run(context.Background(), cfg, quiet(), nil); !errors.Is(err, keymanager.ErrDirInsecure) {
			t.Fatalf("Run = %v", err)
		}
	})
	t.Run("open directory, lax", func(t *testing.T) {
		cfg := open(t)
		var log bytes.Buffer
		l := quiet()
		l.SetOutput(&lockedWriter{w: &log})
		r := startWithLog(t, cfg, l)
		r.waitReady(t)
		_ = r.stop()
		if !strings.Contains(log.String(), "accessible to its group or other users") {
			t.Fatalf("no warning:\n%s", log.String())
		}
	})
	t.Run("missing directory", func(t *testing.T) {
		cfg := baseConfig(t)
		cfg.Consensus.KeyManagerAPIEnabled = true
		cfg.StrictFilePermissions = true
		cfg.KeyConfigPath = filepath.Join(t.TempDir(), "new")
		r := start(t, cfg)
		r.waitReady(t)
		if fi, err := os.Stat(cfg.KeyConfigPath); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("created: %v %v", err, fi)
		}
	})
	t.Run("flag off", func(t *testing.T) {
		cfg := baseConfig(t)
		r := start(t, cfg)
		r.waitReady(t)
		if code, _ := r.send(t, http.MethodGet, "/qrl/v1/keystores", r.admin, nil, 0); code != 404 {
			t.Fatalf("GET without the flag: %d", code)
		}
	})
}

// lockedWriter serialises writes to w.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
