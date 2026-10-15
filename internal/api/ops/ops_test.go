// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package ops

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func quiet() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func get(h http.Handler) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec
}

func TestUpcheck(t *testing.T) {
	var ready atomic.Bool
	h := Upcheck(ready.Load)
	rec := get(h)
	if rec.Code != 503 || rec.Body.String() != "LOADING" || rec.Header().Get("Content-Type") != textPlain {
		t.Fatalf("not ready: %d %q %q", rec.Code, rec.Body, rec.Header().Get("Content-Type"))
	}
	ready.Store(true)
	if rec = get(h); rec.Code != 200 || rec.Body.String() != "OK" {
		t.Fatalf("ready: %d %q", rec.Code, rec.Body)
	}
}

func TestHealthcheck(t *testing.T) {
	var storeUp atomic.Bool
	storeUp.Store(true)
	var sawDeadline bool
	checks := []Check{
		{ID: CheckDefault, Run: func(context.Context) (bool, map[string]any) { return true, nil }},
		{ID: CheckSlashingProtection, Run: func(ctx context.Context) (bool, map[string]any) {
			_, sawDeadline = ctx.Deadline()
			return storeUp.Load(), nil
		}},
		{ID: CheckConfigFilesLoading, Run: func(context.Context) (bool, map[string]any) {
			return true, map[string]any{"keys-loaded": 2, "error-count": 0}
		}},
	}
	var detail bool
	h := Healthcheck(checks, func(*http.Request) bool { return detail })

	decode := func(rec *httptest.ResponseRecorder) map[string]any {
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	rec := get(h)
	if m := decode(rec); rec.Code != 200 || m["status"] != "UP" || m["outcome"] != "UP" || m["checks"] != nil {
		t.Fatalf("anonymous UP: %d %v", rec.Code, m)
	}
	if !sawDeadline {
		t.Error("check ran without a deadline")
	}

	detail = true
	rec = get(h)
	m := decode(rec)
	cs, _ := m["checks"].([]any)
	if len(cs) != 3 {
		t.Fatalf("detail: %v", m)
	}
	last := cs[2].(map[string]any)
	if last["id"] != CheckConfigFilesLoading || last["status"] != "UP" || last["data"].(map[string]any)["keys-loaded"] != 2.0 {
		t.Fatalf("detail check: %v", last)
	}

	storeUp.Store(false)
	detail = false
	rec = get(h)
	if m := decode(rec); rec.Code != 503 || m["status"] != "DOWN" || m["outcome"] != "DOWN" {
		t.Fatalf("DOWN: %d %v", rec.Code, m)
	}
}

func TestReloader(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	results := []struct {
		errs int
		err  error
	}{{0, nil}, {2, nil}, {0, errors.New("store down at /secret/path")}}
	r := NewReloader(func(ctx context.Context) (int, error) {
		i := calls.Add(1) - 1
		<-release
		return results[i].errs, results[i].err
	}, quiet())
	defer r.Close()

	status := func() map[string]any {
		var m map[string]any
		if err := json.Unmarshal(get(r.StatusHandler()).Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := status(); m["status"] != "idle" || m["lastOperationTime"] != nil {
		t.Fatalf("initial status %v", m)
	}

	post := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		r.StartHandler(quiet()).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/reload", nil))
		return rec
	}
	for i, want := range []struct {
		status    string
		lastError string
	}{
		{"completed", ""},
		{"completed_with_errors", "reload completed with 2 key loading error(s)"},
		{"failed", "reload failed; see the signer log"},
	} {
		rec := post()
		if rec.Code != 202 || rec.Body.String() != `{"code":202,"message":"reload started"}` {
			t.Fatalf("run %d: POST = %d %s", i, rec.Code, rec.Body)
		}
		if m := status(); m["status"] != "running" {
			t.Fatalf("run %d: status while running %v", i, m)
		}
		if rec := post(); rec.Code != 409 {
			t.Fatalf("run %d: second POST = %d", i, rec.Code)
		} else {
			var e map[string]any
			_ = json.Unmarshal(rec.Body.Bytes(), &e)
			if e["reason"] != "RELOAD_IN_PROGRESS" {
				t.Fatalf("409 body %v", e)
			}
		}
		release <- struct{}{}
		waitStatus(t, status, want.status)
		m := status()
		if got, _ := m["lastError"].(string); got != want.lastError {
			t.Fatalf("run %d: lastError %q, want %q", i, got, want.lastError)
		}
		if _, err := time.Parse(time.RFC3339, m["lastOperationTime"].(string)); err != nil {
			t.Fatalf("run %d: lastOperationTime: %v", i, err)
		}
	}
}

func waitStatus(t *testing.T, status func() map[string]any, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for status()["status"] != want {
		if time.Now().After(deadline) {
			t.Fatalf("status %v, want %s", status(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestReloaderCloseCancels(t *testing.T) {
	r := NewReloader(func(ctx context.Context) (int, error) {
		<-ctx.Done()
		return 0, ctx.Err()
	}, quiet())
	done := r.Start()
	if done == nil {
		t.Fatal("Start did not start")
	}
	r.Close()
	select {
	case <-done:
	default:
		t.Fatal("Close returned before the load stopped")
	}
	if r.Start() != nil {
		t.Fatal("Start after Close started a load")
	}
}
