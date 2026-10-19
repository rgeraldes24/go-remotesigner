// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package acceptance

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	walletmldsa87 "github.com/theQRL/go-qrllib/wallet/ml_dsa_87"
	"golang.org/x/crypto/sha3"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
)

// gqrlNode is a fake gqrl node for the built binary: it records each
// request, except the signer's own chain-ID checks, and answers every call
// with its method name, or with handler.
type gqrlNode struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*http.Request
	bodies   []string
	handler  http.HandlerFunc
}

func newGQRLNode(t *testing.T) *gqrlNode {
	t.Helper()
	n := &gqrlNode{}
	n.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		n.mu.Lock()
		if !chainCheck(body) {
			n.requests, n.bodies = append(n.requests, r.Clone(r.Context())), append(n.bodies, string(body))
		}
		h := n.handler
		n.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		var calls []struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		batch := strings.HasPrefix(strings.TrimSpace(string(body)), "[")
		if !batch {
			body = []byte("[" + string(body) + "]")
		}
		_ = json.Unmarshal(body, &calls)
		var out []string
		for _, c := range calls {
			out = append(out, fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":"node:%s"}`, c.ID, c.Method))
		}
		w.Header().Set("Content-Type", "application/json")
		if batch {
			_, _ = io.WriteString(w, "["+strings.Join(out, ",")+"]")
		} else if len(out) == 1 {
			_, _ = io.WriteString(w, out[0])
		}
	}))
	t.Cleanup(n.Close)
	return n
}

// chainCheck reports whether a body is the signer's own qrl_chainId call,
// which it makes at startup and every 10 minutes: unlike a forwarded call,
// it always carries params.
func chainCheck(body []byte) bool {
	var c struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	return json.Unmarshal(body, &c) == nil && c.Method == "qrl_chainId" && string(c.Params) == "[]"
}

func (n *gqrlNode) received() ([]*http.Request, []string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]*http.Request(nil), n.requests...), append([]string(nil), n.bodies...)
}

func (n *gqrlNode) setHandler(h http.HandlerFunc) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.handler = h
}

// downstreamFlags point the signer at a test server.
func downstreamFlags(t *testing.T, srv *httptest.Server) []string {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return []string{"--downstream-http-host=" + u.Hostname(), "--downstream-http-port=" + u.Port(), "--chain-id=1337"}
}

// writeAccountKey writes a file-raw key config of a 51-byte extended seed
// and returns the account's address in lower case.
func writeAccountKey(t *testing.T, dir, name string, ext *[mldsa87.ExtendedSeedSize]byte) string {
	t.Helper()
	content := "type: file-raw\nkeyType: ML_DSA_87\nprivateKey: \"0x" + hex.EncodeToString(ext[:]) + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	addr, err := keystoretest.Address(ext)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

// rpc posts a JSON-RPC body with the sign token and extra headers.
func (s *signer) rpc(body string, header http.Header) (int, string) {
	s.t.Helper()
	req, err := http.NewRequest(http.MethodPost, s.base+"/", strings.NewReader(body))
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header[k] = v
	}
	if req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "Bearer "+s.signToken())
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

type rpcReply struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func reply(t *testing.T, body string) rpcReply {
	t.Helper()
	var r rpcReply
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("response %q: %v", body, err)
	}
	return r
}

func textHash(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = fmt.Fprintf(h, "\x19QRL Signed Message:\n%d", len(data))
	_, _ = h.Write(data)
	return h.Sum(nil)
}

// The built binary in execution mode: a 48-byte validator seed is refused
// and only the extended seed's account is served; qrl_sign verifies with
// go-qrllib; admin_* never reaches the node; the node never sees the
// client's token, cookies or forwarding headers; and a redirect from the
// node is passed back without being followed.
func TestExecutionMode(t *testing.T) {
	node := newGQRLNode(t)
	keys := t.TempDir()
	ext := keystoretest.ExtendedSeed("acceptance", 0)
	addr := writeAccountKey(t, keys, "account.yaml", ext)
	seed := keystoretest.Seed("acceptance", 1)
	validator := "type: file-raw\nprivateKey: \"0x" + hex.EncodeToString(seed[:]) + "\"\n"
	if err := os.WriteFile(filepath.Join(keys, "validator.yaml"), []byte(validator), 0o600); err != nil {
		t.Fatal(err)
	}
	s := start(t, options{command: "execution", keys: keys, consensus: downstreamFlags(t, node.Server)})
	s.waitReady()

	t.Run("48-byte seed refused", func(t *testing.T) {
		_, body := s.rpc(`{"jsonrpc":"2.0","id":1,"method":"qrl_accounts"}`, nil)
		var accounts []string
		if err := json.Unmarshal(reply(t, body).Result, &accounts); err != nil || len(accounts) != 1 ||
			"Q"+strings.ToLower(accounts[0][1:]) != addr {
			t.Fatalf("accounts %s, want only %s", body, addr)
		}
		code, health, _ := s.do(request{path: "/healthcheck", token: s.signToken()})
		if code != 503 || !strings.Contains(health, `"keys-check/config-files-loading","status":"DOWN","data":{"error-count":1,"keys-loaded":1}`) {
			t.Fatalf("healthcheck %d %s", code, health)
		}
		if !strings.Contains(s.output.String(), "a 48-byte seed is a consensus validator key") {
			t.Fatal("the refusal is not logged")
		}
	})

	t.Run("qrl_sign verifies with go-qrllib", func(t *testing.T) {
		k, err := mldsa87.FromExtendedSeed51(ext)
		if err != nil {
			t.Fatal(err)
		}
		defer k.Zeroize()
		pk := k.PublicKey()
		data := []byte("acceptance")
		_, body := s.rpc(fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"qrl_sign","params":["%s","0x%x"]}`, addr, data), nil)
		var sigHex string
		if err := json.Unmarshal(reply(t, body).Result, &sigHex); err != nil {
			t.Fatalf("qrl_sign: %s", body)
		}
		sig, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
		if err != nil || len(sig) != 4627 {
			t.Fatalf("signature of %d bytes", len(sig))
		}
		desc, err := walletmldsa87.NewMLDSA87Descriptor()
		if err != nil {
			t.Fatal(err)
		}
		if !walletmldsa87.Verify(textHash(data), sig, (*walletmldsa87.PK)(&pk), [3]byte(desc)) {
			t.Fatal("the signature does not verify with go-qrllib")
		}
	})

	t.Run("admin methods blocked", func(t *testing.T) {
		for _, m := range []string{"admin_addPeer", "admin_nodeInfo", "debug_traceTransaction", "personal_unlockAccount"} {
			_, body := s.rpc(fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"%s","params":[]}`, m), nil)
			if r := reply(t, body); r.Error == nil || r.Error.Code != -32601 {
				t.Errorf("%s: %s", m, body)
			}
		}
		// gqrl would also read a second member name in another case.
		_, body := s.rpc(`{"jsonrpc":"2.0","id":3,"method":"qrl_blockNumber","METHOD":"admin_addPeer","params":["enode://x"]}`, nil)
		if r := reply(t, body); string(r.Result) != `"node:qrl_blockNumber"` {
			t.Errorf("METHOD member: %s", body)
		}
		_, body = s.rpc(`[{"jsonrpc":"2.0","id":1,"method":"admin_peers"},{"jsonrpc":"2.0","id":2,"method":"qrl_blockNumber"}]`, nil)
		var rs []rpcReply
		if err := json.Unmarshal([]byte(body), &rs); err != nil || len(rs) != 2 || rs[0].Error == nil ||
			string(rs[1].Result) != `"node:qrl_blockNumber"` {
			t.Fatalf("batch: %s", body)
		}
		_, bodies := node.received()
		for _, b := range bodies {
			if strings.Contains(b, "admin_") || strings.Contains(b, "debug_") || strings.Contains(b, "personal_") {
				t.Fatalf("a blocked method reached the node: %s", b)
			}
		}
	})

	t.Run("client credentials and forwarding headers stripped", func(t *testing.T) {
		before, _ := node.received()
		_, body := s.rpc(`{"jsonrpc":"2.0","id":4,"method":"qrl_chainId"}`, http.Header{
			"Cookie":              {"session=secret"},
			"Proxy-Authorization": {"Basic eDp5"},
			"Forwarded":           {"for=192.0.2.60"},
			"X-Forwarded-For":     {"192.0.2.60"},
			"X-Forwarded-Host":    {"evil.example"},
			"X-Forwarded-Proto":   {"https"},
		})
		if string(reply(t, body).Result) != `"node:qrl_chainId"` {
			t.Fatalf("qrl_chainId: %s", body)
		}
		reqs, _ := node.received()
		if len(reqs) != len(before)+1 {
			t.Fatalf("%d new requests at the node", len(reqs)-len(before))
		}
		r := reqs[len(reqs)-1]
		for _, name := range []string{"Authorization", "Cookie", "Proxy-Authorization", "Forwarded",
			"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
			if v := r.Header.Get(name); v != "" {
				t.Errorf("%s: %q reached the node", name, v)
			}
		}
		if r.Host != strings.TrimPrefix(node.URL, "http://") {
			t.Errorf("the node saw Host %q", r.Host)
		}
		for _, v := range r.Header {
			if strings.Contains(strings.Join(v, ","), s.signToken()) {
				t.Fatal("the signer's token reached the node")
			}
		}
	})

	t.Run("no redirects followed", func(t *testing.T) {
		var hits atomic.Int32
		metadata := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
		defer metadata.Close()
		node.setHandler(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Set-Cookie", "node=1")
			http.Redirect(w, r, metadata.URL+"/latest/meta-data/", http.StatusFound)
		})
		defer node.setHandler(nil)
		req, _ := http.NewRequest(http.MethodPost, s.base+"/", strings.NewReader(`{"jsonrpc":"2.0","id":5,"method":"qrl_blockNumber"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+s.signToken())
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != metadata.URL+"/latest/meta-data/" ||
			resp.Header.Get("Set-Cookie") != "" {
			t.Fatalf("%d %v", resp.StatusCode, resp.Header)
		}
		if n := hits.Load(); n != 0 {
			t.Fatalf("the redirect target was requested %d times", n)
		}
	})
}

// Consensus mode refuses an account's extended seed, the mirror rule.
func TestConsensusRefusesExtendedSeed(t *testing.T) {
	keys := t.TempDir()
	writeAccountKey(t, keys, "account.yaml", keystoretest.ExtendedSeed("acceptance", 2))
	s := start(t, options{keys: keys})
	s.waitReady()
	code, body, _ := s.do(request{path: "/api/v1/consensus/publicKeys", token: s.signToken()})
	if code != 200 || body != "[]" {
		t.Fatalf("publicKeys %d %s", code, body)
	}
	if !strings.Contains(s.output.String(), "a 51-byte extended seed belongs to execution mode") {
		t.Fatal("the refusal is not logged")
	}
}

// Transaction signing on the built binary, with a policy file and an
// audit log: qrl_signTransaction returns gqrl's {raw, tx} for a type-0x2
// transaction and never asks the node; a recipient the policy does not
// allow, a chain ID other than --chain-id and a fee over the cap are each
// refused with -32003; and the audit log holds a line for each. Without a
// policy file, a non-loopback listener refuses to start.
func TestExecutionTransactions(t *testing.T) {
	node := newGQRLNode(t)
	keys := t.TempDir()
	addr := writeAccountKey(t, keys, "account.yaml", keystoretest.ExtendedSeed("acceptance-tx", 0))
	dir := t.TempDir()
	allowed := "Q" + strings.Repeat("11", 64)
	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte("accounts:\n  "+addr+":\n    allowed-recipients: ["+allowed+"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	audit := filepath.Join(dir, "audit.jsonl")
	flags := append(downstreamFlags(t, node.Server), "--execution-policy-file="+policy, "--execution-audit-log-file="+audit)
	s := start(t, options{command: "execution", keys: keys, consensus: flags})
	s.waitReady()
	before, _ := node.received()

	tx := func(members ...string) string {
		m := map[string]string{"from": addr, "to": allowed, "gas": "0x5208", "maxFeePerGas": "0x2e90edd001",
			"maxPriorityFeePerGas": "0x3b9aca00", "nonce": "0x0", "value": "0x1"}
		for i := 0; i+1 < len(members); i += 2 {
			m[members[i]] = members[i+1]
		}
		data, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "qrl_signTransaction", "params": []any{m}})
		return string(data)
	}
	_, body := s.rpc(tx(), nil)
	var res struct {
		Raw string                     `json:"raw"`
		Tx  map[string]json.RawMessage `json:"tx"`
	}
	if r := reply(t, body); r.Error != nil || json.Unmarshal(r.Result, &res) != nil || !strings.HasPrefix(res.Raw, "0x02") ||
		string(res.Tx["type"]) != `"0x2"` || string(res.Tx["chainId"]) != `"0x539"` ||
		string(res.Tx["descriptor"]) != `"0x010000"` || string(res.Tx["extraParams"]) != `"0x"` {
		t.Fatalf("qrl_signTransaction: %.400s", body)
	}
	for _, refused := range []string{
		tx("to", "Q"+strings.Repeat("22", 64)),
		tx("chainId", "0x1"),
		tx("gas", "0x1000000", "maxFeePerGas", "0xe8d4a51000"),
	} {
		if r := reply(t, mustRPC(t, s, refused)); r.Error == nil || r.Error.Code != -32003 {
			t.Errorf("refused: %+v", r.Error)
		}
	}
	if after, _ := node.received(); len(after) != len(before) {
		t.Fatalf("qrl_signTransaction asked the node %d times", len(after)-len(before))
	}
	data, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 4 || !strings.Contains(lines[0], `"outcome":"signed"`) ||
		!strings.Contains(lines[1], `"outcome":"refused"`) || !strings.Contains(lines[3], "above the cap") {
		t.Fatalf("audit log:\n%s", data)
	}
	if fi, err := os.Stat(audit); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("audit log mode %v (%v)", fi.Mode(), err)
	}

	// A non-loopback listener needs a policy file.
	cmd := exec.Command(binary, "--data-path="+t.TempDir(), "--http-listen-host=0.0.0.0",
		"--http-host-allowlist=signer.example", "--Xallow-plaintext-token-auth", "execution", "--chain-id=1337")
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 || !strings.Contains(string(out), "--execution-policy-file") {
		t.Fatalf("non-loopback without a policy file: %v\n%s", err, out)
	}
}

func mustRPC(t *testing.T, s *signer, body string) string {
	t.Helper()
	_, out := s.rpc(body, nil)
	return out
}
