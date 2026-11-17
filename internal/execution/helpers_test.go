// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"bytes"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
)

func quiet() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

// node is a fake gqrl node: it records every request and answers with its
// handler, by default an echo of each call's method as its result.
type node struct {
	*httptest.Server
	mu       sync.Mutex
	requests []recorded
	handler  http.HandlerFunc
}

// recorded is a request the node received.
type recorded struct {
	header           http.Header
	trailer          http.Header
	transferEncoding []string
	contentLength    int64
	host             string
	path             string
	body             []byte
}

func newNode(t *testing.T) *node {
	t.Helper()
	n := &node{}
	n.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		n.mu.Lock()
		n.requests = append(n.requests, recorded{header: r.Header.Clone(), trailer: r.Trailer.Clone(),
			transferEncoding: r.TransferEncoding, contentLength: r.ContentLength, host: r.Host, path: r.URL.Path,
			body: body})
		h := n.handler
		n.mu.Unlock()
		if h != nil {
			r.Body = io.NopCloser(bytes.NewReader(body))
			h(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(echo(body))
	}))
	t.Cleanup(n.Close)
	return n
}

// echo answers each call of a request or batch with its method name.
func echo(body []byte) []byte {
	answer := func(raw json.RawMessage) json.RawMessage {
		var r struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal(raw, &r)
		if r.ID == nil {
			return nil
		}
		return encodeResult(r.ID, "node:"+r.Method, nil)
	}
	if !isBatch(body) {
		return answer(body)
	}
	var elems []json.RawMessage
	_ = json.Unmarshal(body, &elems)
	var out []json.RawMessage
	for _, e := range elems {
		if a := answer(e); a != nil {
			out = append(out, a)
		}
	}
	data, _ := json.Marshal(out)
	return data
}

func (n *node) setHandler(h http.HandlerFunc) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.handler = h
}

func (n *node) received() []recorded {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]recorded(nil), n.requests...)
}

// clientCalls is received without the chain-ID checks a running signer
// makes on its own.
func (n *node) clientCalls() []recorded {
	var out []recorded
	for _, r := range n.received() {
		var m struct {
			Method string `json:"method"`
		}
		if json.Unmarshal(r.body, &m) == nil && m.Method == MethodChainID {
			continue
		}
		out = append(out, r)
	}
	return out
}

// downstreamOf is the downstream configuration of a test server.
func downstreamOf(t *testing.T, srv *httptest.Server) config.Downstream {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return config.Downstream{Host: u.Hostname(), Port: uint16(port), Path: "/", Timeout: 2 * time.Second}
}

// testChainID is the chain ID of the fixtures: gqrl --dev's.
const testChainID = 1337

// fixture is a Handler over loaded accounts and a fake node.
type fixture struct {
	t        *testing.T
	keys     *provider.Provider
	accounts *Accounts
	node     *node
	handler  *Handler
	txs      *Transactions
	ext      []*[mldsa87.ExtendedSeedSize]byte
}

// newFixture loads n accounts and forwards to a fake node with the allowlist.
func newFixture(t *testing.T, n int, allow []string) *fixture {
	t.Helper()
	nd := newNode(t)
	return newFixtureWith(t, n, allow, downstreamOf(t, nd.Server), nd)
}

func newFixtureWith(t *testing.T, n int, allow []string, d config.Downstream, nd *node) *fixture {
	t.Helper()
	f := &fixture{t: t, keys: provider.New(quiet()), node: nd}
	var keys []*mldsa87.Key
	for i := range n {
		ext := keystoretest.ExtendedSeed("execution", i)
		k, err := mldsa87.FromExtendedSeed51(ext)
		if err != nil {
			t.Fatal(err)
		}
		f.ext = append(f.ext, ext)
		keys = append(keys, k)
	}
	if _, err := f.keys.Apply([]provider.Batch{{Source: "test", Keys: keys}}, nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.keys.Close)
	f.accounts = NewAccounts(f.keys)
	f.accounts.Refresh()
	a, err := ParseAllowlist(allow)
	if err != nil {
		t.Fatal(err)
	}
	ds, err := newDownstream(d, secretfile.Policy{Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	p, closeLog := newProxy(ds, quiet())
	t.Cleanup(closeLog)
	f.txs = NewTransactions(TransactionsConfig{ChainID: big.NewInt(testChainID), NonceCrosscheck: true})
	f.txs.chain = newChainMonitor(big.NewInt(testChainID), p, quiet())
	f.handler = newHandler(f.accounts, a, p, f.txs, quiet())
	return f
}

// key returns account i's key and address.
func (f *fixture) key(i int) (*mldsa87.Key, string) {
	f.t.Helper()
	k, err := mldsa87.FromExtendedSeed51(f.ext[i])
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(k.Zeroize)
	pk := k.PublicKey()
	return k, mldsa87.ChecksumAddress(pk.Address())
}

// post sends a body to the handler with headers and returns the response.
func (f *fixture) post(body string, header http.Header) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		r.Header[k] = v
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

// rpcResponse is a decoded JSON-RPC response.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *Error          `json:"error"`
}

func decodeOne(t *testing.T, body []byte) rpcResponse {
	t.Helper()
	var r rpcResponse
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("response %q: %v", body, err)
	}
	if r.JSONRPC != Version {
		t.Fatalf("response %q: jsonrpc %q", body, r.JSONRPC)
	}
	return r
}

func decodeBatch(t *testing.T, body []byte) []rpcResponse {
	t.Helper()
	var rs []rpcResponse
	if err := json.Unmarshal(body, &rs); err != nil {
		t.Fatalf("batch response %q: %v", body, err)
	}
	return rs
}

// call renders a request.
func call(id any, method string, params ...any) string {
	m := map[string]any{"jsonrpc": "2.0", "method": method}
	if id != nil {
		m["id"] = id
	}
	if params != nil {
		m["params"] = params
	}
	data, _ := json.Marshal(m)
	return string(data)
}

func batch(calls ...string) string { return "[" + strings.Join(calls, ",") + "]" }
