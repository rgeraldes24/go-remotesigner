// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPClientRefusesRedirects(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("X-Vault-Token", "t")
	_, err := HTTPClient(HTTPOptions{Timeout: time.Second}).Do(req)
	if !errors.Is(err, ErrRedirect) {
		t.Fatalf("error = %v, want ErrRedirect", err)
	}
	if hits.Load() != 0 {
		t.Fatal("the redirect was followed")
	}
}

func TestHTTPClientTimeout(t *testing.T) {
	stop := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-stop }))
	defer srv.Close()
	defer close(stop)
	start := time.Now()
	_, err := HTTPClient(HTTPOptions{Timeout: 100 * time.Millisecond}).Get(srv.URL)
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("error = %v after %v, want a timeout", err, time.Since(start))
	}
}

func TestHTTPClientBoundsResponses(t *testing.T) {
	big := strings.Repeat("a", MaxResponseSize+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/chunked" {
			w.(http.Flusher).Flush() // no Content-Length
		} else {
			w.Header().Set("Content-Length", strconv.Itoa(len(big)))
		}
		_, _ = io.WriteString(w, big)
	}))
	defer srv.Close()
	hc := HTTPClient(HTTPOptions{Timeout: 5 * time.Second})
	if _, err := hc.Get(srv.URL + "/declared"); !errors.Is(err, ErrTooLarge) {
		t.Errorf("declared length: error = %v, want ErrTooLarge", err)
	}
	resp, err := hc.Get(srv.URL + "/chunked")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ContentLength != -1 {
		t.Fatalf("Content-Length %d, want a chunked response", resp.ContentLength)
	}
	if _, err := ReadBody(resp, MaxResponseSize); !errors.Is(err, ErrTooLarge) {
		t.Errorf("chunked: error = %v, want ErrTooLarge", err)
	}
}

func TestReadBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	defer srv.Close()
	resp, err := HTTPClient(HTTPOptions{Timeout: time.Second}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := ReadBody(resp, 64)
	if err != nil || string(b) != "hello" {
		t.Fatalf("ReadBody = %q, %v", b, err)
	}
}

func TestCache(t *testing.T) {
	var closed []string
	c := Cache[string, string]{Max: 2, Close: func(v string) { closed = append(closed, v) }}
	builds := 0
	get := func(k string) string {
		v, err := c.Get(k, func() (string, error) { builds++; return "client-" + k, nil })
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	get("a")
	get("b")
	get("a") // a is now the most recently used
	get("c") // evicts b
	if builds != 3 || c.Len() != 2 || !slices.Equal(closed, []string{"client-b"}) {
		t.Fatalf("builds %d, len %d, closed %v", builds, c.Len(), closed)
	}
	if _, err := c.Get("d", func() (string, error) { return "", errors.New("no") }); err == nil || c.Len() != 2 {
		t.Fatal("a failed build was cached")
	}
	c.Purge()
	if c.Len() != 0 || len(closed) != 3 {
		t.Fatalf("after Purge: len %d, closed %v", c.Len(), closed)
	}
}

func TestParseTags(t *testing.T) {
	got, err := ParseTags([]string{"a=1|b=2", "c", "d="})
	want := []Tag{{"a", "1"}, {"b", "2"}, {"c", ""}, {"d", ""}}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("ParseTags = %v, %v", got, err)
	}
	if _, err := ParseTags([]string{"=x"}); !errors.Is(err, ErrConfig) {
		t.Fatalf("empty key: %v", err)
	}
}

func TestCheckKubernetesAuthPath(t *testing.T) {
	for in, want := range map[string]string{"": "kubernetes", " /k8s/ ": "k8s", "a/b": "a/b"} {
		if got, err := CheckKubernetesAuthPath(in); err != nil || got != want {
			t.Errorf("CheckKubernetesAuthPath(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"a//b", "a/./b", "../x"} {
		if _, err := CheckKubernetesAuthPath(bad); err == nil {
			t.Errorf("CheckKubernetesAuthPath(%q) accepted", bad)
		}
	}
}

func TestParseEnum(t *testing.T) {
	if v, err := ParseEnum("specified", AWSSpecified, AWSEnvironment); err != nil || v != AWSSpecified {
		t.Fatalf("ParseEnum = %q, %v", v, err)
	}
	if _, err := ParseEnum("IAM", AWSSpecified, AWSEnvironment); !errors.Is(err, ErrConfig) {
		t.Fatalf("ParseEnum(IAM) = %v", err)
	}
}

type panicky struct{}

func (panicky) Fetch(context.Context, Spec) ([]byte, error) { panic("boom") }

func TestStores(t *testing.T) {
	st := Stores{KindGCP: panicky{}}
	if _, err := st.Fetch(context.Background(), &AWS{SecretName: "s"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing store: %v", err)
	}
	if _, err := st.Fetch(context.Background(), &GCP{ProjectID: "p", SecretName: "s"}); err == nil ||
		!strings.Contains(err.Error(), "panicked: boom") {
		t.Fatalf("panicking store: %v", err)
	}
}

// fakeLister is an in-memory bulk store.
type fakeLister struct {
	values  map[string]string
	order   []string
	listErr error
	panicOn string
}

func (f *fakeLister) List(context.Context) ([]string, error) { return f.order, f.listErr }

func (f *fakeLister) Get(_ context.Context, name string) ([]byte, error) {
	if name == f.panicOn {
		panic("bad response")
	}
	v, ok := f.values[name]
	if !ok {
		return nil, fmt.Errorf("%s: %w", name, ErrNotFound)
	}
	return []byte(v), nil
}

func TestBulk(t *testing.T) {
	s1, s2, s3 := "0x"+hexOf(1, 48), hexOf(2, 48), "0x"+hexOf(3, 48)
	f := &fakeLister{
		order: []string{"good", "two-lines", "bad-line", "missing", "too-large", "empty", "panics"},
		values: map[string]string{
			"good":      s1 + "\n",
			"two-lines": s2 + "\r\n" + s3 + "\r\n",
			"bad-line":  s1 + "\n0x" + hexOf(9, 32) + "\n",
			"too-large": strings.Repeat("0", MaxValueSize+1),
			"empty":     "\n",
		},
		panicOn: "panics",
	}
	b := Bulk{Kind: KindAWS, Store: f}
	batches, err := b.Load(context.Background(), 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{ // source -> error substring; "" loads
		"aws-bulk:good": "", "aws-bulk:two-lines": "", "aws-bulk:bad-line": "line 2: invalid seed: 32 bytes",
		"aws-bulk:missing": "secret not found", "aws-bulk:too-large": "too large", "aws-bulk:empty": "holds no seed",
		"aws-bulk:panics": "panicked",
	}
	if len(batches) != len(want) {
		t.Fatalf("%d batches, want %d", len(batches), len(want))
	}
	for _, x := range batches {
		w, ok := want[x.Source]
		switch {
		case !ok:
			t.Errorf("unexpected source %s", x.Source)
		case w == "" && x.Err != nil:
			t.Errorf("%s: %v", x.Source, x.Err)
		case w != "" && (x.Err == nil || !strings.Contains(x.Err.Error(), w) || len(x.Keys) != 0):
			t.Errorf("%s: error %v, %d keys; want %q and none", x.Source, x.Err, len(x.Keys), w)
		}
		if x.Err != nil && (strings.Contains(x.Err.Error(), "0101") || strings.Contains(x.Err.Error(), "0909")) {
			t.Errorf("%s: error quotes the value: %v", x.Source, x.Err)
		}
		if x.Source == "aws-bulk:two-lines" && len(x.Keys) != 2 {
			t.Errorf("two-lines: %d keys", len(x.Keys))
		}
		for _, k := range x.Keys {
			k.Zeroize()
		}
	}

	f.listErr = errors.New("throttled")
	if _, err := b.Load(context.Background(), 1, nil); err == nil || !strings.Contains(err.Error(), "list secrets") {
		t.Fatalf("list failure: %v", err)
	}

	f.listErr = nil
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	batches, err = b.Load(ctx, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range batches {
		if !errors.Is(x.Err, context.Canceled) {
			t.Errorf("%s after cancel: %v", x.Source, x.Err)
		}
	}
}
