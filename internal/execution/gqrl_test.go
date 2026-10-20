// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/theQRL/go-qrl/common"
	"github.com/theQRL/go-qrl/common/hexutil"
	"github.com/theQRL/go-qrl/core/types"
	walletmldsa87 "github.com/theQRL/go-qrllib/wallet/ml_dsa_87"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
)

// GQRLEnv names the gqrl binary the end-to-end test runs, built from
// go-qrl at the commit go.mod requires (make gqrl-e2e builds it). The test
// is skipped without it.
const GQRLEnv = "REMOTESIGNER_GQRL"

// devChainID is gqrl --dev's chain ID.
const devChainID = 1337

// gqrlDev is a gqrl --dev node: a one-node chain that seals a block for
// each pending transaction, with a funded developer account it signs with
// itself.
type gqrlDev struct {
	url string
	dev common.Address
}

func startGQRL(t *testing.T, bin string) *gqrlDev {
	t.Helper()
	port := freePort(t)
	dir := t.TempDir()
	logFile, err := os.Create(filepath.Join(dir, "gqrl.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--dev", "--datadir", filepath.Join(dir, "data"), "--http", "--http.addr", "127.0.0.1",
		"--http.port", strconv.Itoa(port), "--http.api", "qrl,net,web3", "--nodiscover", "--maxpeers", "0",
		"--port", "0", "--authrpc.port", "0", "--ipcdisable", "--verbosity", "3")
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
		_ = logFile.Close()
		if t.Failed() {
			if data, err := os.ReadFile(logFile.Name()); err == nil {
				t.Logf("gqrl log (tail):\n%s", tail(data, 40))
			}
		}
	})
	g := &gqrlDev{url: "http://127.0.0.1:" + strconv.Itoa(port)}
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		var accounts []common.Address
		if err := g.call(&accounts, "qrl_accounts"); err == nil && len(accounts) == 1 {
			g.dev = accounts[0]
			return g
		}
		if time.Now().After(deadline) {
			t.Fatal("gqrl --dev did not start")
		}
	}
}

// checkGQRLCommit fails unless the gqrl binary was built from the go-qrl
// commit that the signer links: gqrl version prints it.
func checkGQRLCommit(t *testing.T, bin string) {
	t.Helper()
	v, err := exec.Command("go", "list", "-m", "-f", "{{.Version}}", "github.com/theQRL/go-qrl").Output()
	if err != nil {
		t.Fatalf("go list -m: %v", err)
	}
	version := strings.TrimSpace(string(v))
	want := version[strings.LastIndex(version, "-")+1:] // the pseudo-version's commit
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		t.Fatalf("gqrl version: %v", err)
	}
	m := regexp.MustCompile(`(?m)^Git Commit: ([0-9a-f]{40})$`).FindSubmatch(out)
	if want == "" || m == nil || !strings.HasPrefix(string(m[1]), want) {
		t.Fatalf("gqrl was built from %q, not go-qrl %s:\n%s", m, want, out)
	}
}

func tail(data []byte, n int) string {
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// call calls the node directly.
func (g *gqrlDev) call(result any, method string, params ...any) error {
	return rpcCall(http.DefaultClient, g.url, nil, result, method, params...)
}

// rpcCall posts one JSON-RPC call and decodes its result; a JSON-RPC error
// is returned as an *Error.
func rpcCall(c *http.Client, url string, header http.Header, result any, method string, params ...any) error {
	if params == nil {
		params = []any{}
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	var r struct {
		Result json.RawMessage `json:"result"`
		Error  *Error          `json:"error"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("%s: %d %q", method, resp.StatusCode, data)
	}
	if r.Error != nil {
		return r.Error
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(r.Result, result)
}

// interposer stands between the signer and gqrl: it forwards every call,
// counts the methods that reach the node, and when armed, rewrites the
// transaction of the next qrl_fillTransaction answer, as a malicious or
// broken node would.
type interposer struct {
	*httptest.Server
	mu    sync.Mutex
	edit  func(tx *types.DynamicFeeTx)
	fills int
	seen  map[string]int
}

func newInterposer(t *testing.T, target string) *interposer {
	t.Helper()
	ip := &interposer{seen: map[string]int{}}
	ip.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ip.record(body)
		resp, err := http.Post(target, "application/json", bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var c fakeCall
		if json.Unmarshal(body, &c) == nil && c.Method == MethodFillTransaction {
			ip.mu.Lock()
			ip.fills++
			edit := ip.edit
			ip.edit = nil
			ip.mu.Unlock()
			if edit != nil {
				data = rewriteFill(t, c.ID, data, edit)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	t.Cleanup(ip.Close)
	return ip
}

// arm makes the interposer rewrite the next fill answer with edit.
func (ip *interposer) arm(edit func(tx *types.DynamicFeeTx)) {
	ip.mu.Lock()
	defer ip.mu.Unlock()
	ip.edit = edit
}

func (ip *interposer) fillCount() int {
	ip.mu.Lock()
	defer ip.mu.Unlock()
	return ip.fills
}

// record counts the method of each call in body, a call or a batch.
func (ip *interposer) record(body []byte) {
	var calls []fakeCall
	var c fakeCall
	if json.Unmarshal(body, &c) == nil {
		calls = []fakeCall{c}
	} else {
		_ = json.Unmarshal(body, &calls)
	}
	ip.mu.Lock()
	defer ip.mu.Unlock()
	for _, c := range calls {
		ip.seen[c.Method]++
	}
}

// count is how many calls of method reached the node.
func (ip *interposer) count(method string) int {
	ip.mu.Lock()
	defer ip.mu.Unlock()
	return ip.seen[method]
}

// rewriteFill applies edit to the transaction of a qrl_fillTransaction
// answer and encodes it again.
func rewriteFill(t *testing.T, id json.RawMessage, data []byte, edit func(tx *types.DynamicFeeTx)) []byte {
	var r struct {
		Result struct {
			Raw hexutil.Bytes `json:"raw"`
		} `json:"result"`
	}
	tx := new(types.Transaction)
	if err := json.Unmarshal(data, &r); err != nil || tx.UnmarshalBinary(r.Result.Raw) != nil {
		t.Errorf("the node's fill answer %q does not decode", data)
		return data
	}
	d := &types.DynamicFeeTx{ChainID: tx.ChainId(), Nonce: tx.Nonce(), GasTipCap: tx.GasTipCap(),
		GasFeeCap: tx.GasFeeCap(), Gas: tx.Gas(), To: tx.To(), Value: tx.Value(), Data: tx.Data(),
		AccessList: tx.AccessList()}
	edit(d)
	edited := types.NewTx(d)
	raw, err := edited.MarshalBinary()
	if err != nil {
		t.Error(err)
		return data
	}
	return encodeResult(id, signTransactionResult{Raw: raw, Tx: edited}, nil)
}

// e2eSigner is a signer process (Run) in front of a node URL.
type e2eSigner struct {
	*running
	from  string
	audit string
}

func startE2ESigner(t *testing.T, nodeURL string, chainID uint64, account int) *e2eSigner {
	t.Helper()
	u := strings.TrimPrefix(nodeURL, "http://")
	host, portText, _ := net.SplitHostPort(u)
	port, _ := strconv.Atoi(portText)
	cfg := &config.Config{
		DataPath:              t.TempDir(),
		KeyConfigPath:         t.TempDir(),
		StrictFilePermissions: true,
		HTTP: config.HTTP{ListenHost: "127.0.0.1", HostAllowlist: []string{"localhost", "127.0.0.1"},
			AuthMode: "token", MaxConnections: 64, IdleTimeout: time.Minute},
		Execution: config.Execution{
			Downstream:      config.Downstream{Host: host, Port: uint16(port), Path: "/", Timeout: 10 * time.Second},
			AllowedMethods:  defaultAllow,
			ChainID:         chainID,
			NonceCrosscheck: true,
		},
	}
	cfg.Execution.AuditLogFile = filepath.Join(cfg.DataPath, "audit.jsonl")
	from := writeAccount(t, cfg.KeyConfigPath, account)
	r := startExec(t, cfg)
	r.waitReady(t)
	return &e2eSigner{running: r, from: from, audit: cfg.Execution.AuditLogFile}
}

// rpc calls the signer.
func (s *e2eSigner) rpc(result any, method string, params ...any) error {
	return rpcCall(http.DefaultClient, s.base+"/", s.bearer(), result, method, params...)
}

// waitMined waits for a transaction's receipt through the signer's proxy
// and returns its status.
func (s *e2eSigner) waitMined(t *testing.T, hash common.Hash) string {
	t.Helper()
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		var receipt map[string]json.RawMessage
		if err := s.rpc(&receipt, "qrl_getTransactionReceipt", hash); err == nil && receipt != nil {
			var status string
			_ = json.Unmarshal(receipt["status"], &status)
			return status
		}
	}
	t.Fatalf("transaction %s was not mined", hash.Hex())
	return ""
}

func (s *e2eSigner) pendingNonce(t *testing.T) uint64 {
	t.Helper()
	var n hexutil.Uint64
	if err := s.rpc(&n, "qrl_getTransactionCount", s.from, "pending"); err != nil {
		t.Fatal(err)
	}
	return uint64(n)
}

func (s *e2eSigner) auditOutcomes(t *testing.T) []string {
	t.Helper()
	f, err := os.Open(s.audit)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e AuditEntry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e.Method+" "+e.Outcome+" "+e.Reason)
	}
	return out
}

// TestGQRLDev runs the signer in front of gqrl --dev, the chain the node
// builds at the go-qrl commit go.mod requires: a transfer is mined, also
// under a client id that gqrl's answer escapes; a taken nonce is filled,
// signed and sent again; a wrong chain ID is
// refused, in the request and from the node; a node that changes to,
// value, input, the access list or the chain ID in qrl_fillTransaction is
// refused; so is a filled nonce far above the pending one; the fee cap
// holds for both methods and for fees the node proposes; qrl_sign's
// signature verifies with go-qrllib under the public key the signer lists;
// and the allowlist forwards net_version to the node and keeps admin_*,
// debug_*, personal_* and qrl_signTypedData from it.
func TestGQRLDev(t *testing.T) {
	bin := os.Getenv(GQRLEnv)
	if bin == "" {
		t.Skip(GQRLEnv + " names no gqrl binary (make gqrl-e2e)")
	}
	checkGQRLCommit(t, bin)
	node := startGQRL(t, bin)
	ip := newInterposer(t, node.url)
	s := startE2ESigner(t, ip.URL, devChainID, 0)

	// Fund the signer's account from gqrl's developer account, which gqrl
	// signs for itself.
	var fund common.Hash
	quanta := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	if err := node.call(&fund, "qrl_sendTransaction", map[string]any{"from": node.dev, "to": s.from,
		"value": (*hexutil.Big)(new(big.Int).Mul(quanta, big.NewInt(1000)))}); err != nil {
		t.Fatalf("funding: %v", err)
	}
	if status := s.waitMined(t, fund); status != "0x1" {
		t.Fatalf("funding status %s", status)
	}
	recipient := common.Address{0x52, 0x53}

	t.Run("a transfer is mined", func(t *testing.T) {
		var hash common.Hash
		if err := s.rpc(&hash, MethodSendTransaction, map[string]any{"from": s.from, "to": recipient,
			"value": (*hexutil.Big)(quanta)}); err != nil {
			t.Fatal(err)
		}
		if status := s.waitMined(t, hash); status != "0x1" {
			t.Fatalf("status %s", status)
		}
		var balance hexutil.Big
		if err := s.rpc(&balance, "qrl_getBalance", recipient, "latest"); err != nil || balance.ToInt().Cmp(quanta) != 0 {
			t.Fatalf("recipient balance %v (%v)", balance.ToInt(), err)
		}
		// The client's own signature, sent by the client.
		var signed signTransactionResult
		nonce := s.pendingNonce(t)
		if err := s.rpc(&signed, MethodSignTransaction, map[string]any{"from": s.from, "to": recipient,
			"value": "0x1", "nonce": hexutil.Uint64(nonce), "gas": "0x5208", "maxFeePerGas": "0x2e90edd001",
			"maxPriorityFeePerGas": "0x3b9aca00"}); err != nil {
			t.Fatal(err)
		}
		raw, _ := signed.Tx.MarshalBinary()
		if !bytes.Equal(raw, signed.Raw) {
			t.Fatal("raw and tx differ")
		}
		if err := s.rpc(&hash, MethodSendRawTransaction, signed.Raw); err != nil {
			t.Fatal(err)
		}
		if status := s.waitMined(t, hash); status != "0x1" || hash != signed.Tx.Hash() {
			t.Fatalf("status %s", status)
		}
	})

	t.Run("an id the node escapes", func(t *testing.T) {
		// gqrl writes <, > and & in the id it answers with as \u escapes;
		// its answer to a transaction it took is still that answer.
		before := s.pendingNonce(t)
		params, _ := json.Marshal([]any{map[string]any{"from": s.from, "to": recipient, "value": "0x7"}})
		req, err := http.NewRequest(http.MethodPost, s.base+"/", strings.NewReader(
			`{"jsonrpc":"2.0","id":"<a&b>","method":"`+MethodSendTransaction+`","params":`+string(params)+`}`))
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range s.bearer() {
			req.Header[k] = v
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		var r struct {
			ID     json.RawMessage `json:"id"`
			Result common.Hash     `json:"result"`
			Error  *Error          `json:"error"`
		}
		if err := json.Unmarshal(data, &r); err != nil || resp.StatusCode != http.StatusOK || r.Error != nil ||
			!sameID(r.ID, json.RawMessage(`"<a&b>"`)) {
			t.Fatalf("%d %s", resp.StatusCode, data)
		}
		if status := s.waitMined(t, r.Result); status != "0x1" {
			t.Fatalf("status %s", status)
		}
		if after := s.pendingNonce(t); after != before+1 {
			t.Fatalf("nonce %d -> %d", before, after)
		}
		outcomes := s.auditOutcomes(t)
		if last := outcomes[len(outcomes)-1]; last != "qrl_sendTransaction sent " {
			t.Fatalf("last audit line %q", last)
		}
	})

	t.Run("a taken nonce is retried", func(t *testing.T) {
		next := s.pendingNonce(t)
		if next == 0 {
			t.Fatal("no nonce used yet")
		}
		ip.arm(func(tx *types.DynamicFeeTx) { tx.Nonce = next - 1 }) // a stale fill: that nonce is mined
		fills := ip.fillCount()
		var hash common.Hash
		if err := s.rpc(&hash, MethodSendTransaction, map[string]any{"from": s.from, "to": recipient, "value": "0x2"}); err != nil {
			t.Fatal(err)
		}
		if status := s.waitMined(t, hash); status != "0x1" {
			t.Fatalf("status %s", status)
		}
		if n := ip.fillCount() - fills; n != 2 {
			t.Fatalf("%d fills, want 2", n)
		}
		outcomes := s.auditOutcomes(t)
		found := false
		for _, o := range outcomes {
			found = found || strings.HasPrefix(o, "qrl_sendTransaction node-refused nonce too low")
		}
		if !found {
			t.Fatalf("no nonce-too-low refusal in the audit log:\n%s", strings.Join(outcomes, "\n"))
		}
	})

	refused := func(t *testing.T, method string, params map[string]any, code int, want string) {
		t.Helper()
		before := s.pendingNonce(t)
		err := s.rpc(nil, method, params)
		e, ok := err.(*Error)
		if !ok || e.Code != code || !strings.Contains(fmt.Sprint(e.Data)+e.Message, want) {
			t.Fatalf("%s: %v, want %d %q", method, err, code, want)
		}
		if after := s.pendingNonce(t); after != before {
			t.Fatalf("a refused transaction reached the pool (nonce %d -> %d)", before, after)
		}
	}

	t.Run("a wrong chain ID is refused", func(t *testing.T) {
		for _, method := range []string{MethodSendTransaction, MethodSignTransaction} {
			refused(t, method, map[string]any{"from": s.from, "to": recipient, "value": "0x1", "chainId": "0x1",
				"nonce": "0x0", "gas": "0x5208", "maxFeePerGas": "0x2e90edd001", "maxPriorityFeePerGas": "0x3b9aca00"},
				ErrTxRejected.Code, "chainId 1 is not --chain-id 1337")
		}
		// A signer with --chain-id 1 in front of the 1337 node refuses every
		// transaction once its startup check has the node's answer.
		other := startE2ESigner(t, ip.URL, 1, 0)
		var err error
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			err = other.rpc(nil, MethodSignTransaction, map[string]any{"from": other.from, "to": recipient,
				"value": "0x1", "nonce": "0x0", "gas": "0x5208", "maxFeePerGas": "0x2e90edd001",
				"maxPriorityFeePerGas": "0x3b9aca00"})
			if e, ok := err.(*Error); ok && strings.Contains(fmt.Sprint(e.Data), "the downstream node's chain ID") {
				break
			}
		}
		if e, ok := err.(*Error); !ok || e.Code != ErrTxRejected.Code ||
			!strings.Contains(fmt.Sprint(e.Data), "the downstream node's chain ID is 1337, not --chain-id 1") {
			t.Fatalf("signer on chain 1: %v", err)
		}
		before := s.pendingNonce(t)
		err = other.rpc(nil, MethodSendTransaction, map[string]any{"from": other.from, "to": recipient, "value": "0x1"})
		if e, ok := err.(*Error); !ok || e.Code != ErrTxRejected.Code ||
			!strings.Contains(fmt.Sprint(e.Data), "the downstream node's chain ID is 1337, not --chain-id 1") {
			t.Fatalf("qrl_sendTransaction on chain 1: %v", err)
		}
		if after := s.pendingNonce(t); after != before {
			t.Fatal("the signer on chain 1 sent a transaction")
		}
	})

	t.Run("a node that changes the transaction is refused", func(t *testing.T) {
		attacker := common.Address{0xee}
		for _, tt := range []struct {
			field string
			edit  func(tx *types.DynamicFeeTx)
		}{
			{"to", func(tx *types.DynamicFeeTx) { tx.To = &attacker }},
			{"value", func(tx *types.DynamicFeeTx) { tx.Value = new(big.Int).Mul(quanta, big.NewInt(900)) }},
			{"input", func(tx *types.DynamicFeeTx) { tx.Data = []byte{0xa9, 0x05, 0x9c, 0xbb} }},
			{"accessList", func(tx *types.DynamicFeeTx) { tx.AccessList = types.AccessList{{Address: attacker}} }},
			{"chainId", func(tx *types.DynamicFeeTx) { tx.ChainID = big.NewInt(1) }},
		} {
			ip.arm(tt.edit)
			refused(t, MethodSendTransaction, map[string]any{"from": s.from, "to": recipient, "value": "0x3"},
				ErrTxRejected.Code, "changed the transaction's "+tt.field)
		}
	})

	t.Run("a filled nonce far above the pending nonce is refused", func(t *testing.T) {
		next := s.pendingNonce(t)
		ip.arm(func(tx *types.DynamicFeeTx) { tx.Nonce = next + 65 })
		refused(t, MethodSendTransaction, map[string]any{"from": s.from, "to": recipient, "value": "0x4"},
			ErrTxRejected.Code, "more than 64 above the node's pending nonce")
	})

	t.Run("the fee cap holds", func(t *testing.T) {
		huge := map[string]any{"from": s.from, "to": recipient, "value": "0x5", "gas": "0x989680",
			"maxFeePerGas": "0xe8d4a51000", "maxPriorityFeePerGas": "0x1"} // 10^7 × 10^12 = 10 quanta
		refused(t, MethodSendTransaction, huge, ErrTxRejected.Code, "above the cap of 1000000000000000000 Planck")
		withNonce := map[string]any{"nonce": hexutil.Uint64(s.pendingNonce(t))}
		for k, v := range huge {
			withNonce[k] = v
		}
		refused(t, MethodSignTransaction, withNonce, ErrTxRejected.Code, "above the cap")
		ip.arm(func(tx *types.DynamicFeeTx) {
			tx.Gas, tx.GasFeeCap = 10_000_000, new(big.Int).Exp(big.NewInt(10), big.NewInt(12), nil)
		})
		refused(t, MethodSendTransaction, map[string]any{"from": s.from, "to": recipient, "value": "0x6"},
			ErrTxRejected.Code, "above the cap")
	})

	t.Run("qrl_sign verifies with go-qrllib", func(t *testing.T) {
		code, list := s.do(t, req{method: http.MethodGet, path: PublicKeysPath, header: s.bearer()})
		var keys []struct {
			Address   string        `json:"address"`
			PublicKey hexutil.Bytes `json:"public_key"`
		}
		if err := json.Unmarshal([]byte(list), &keys); code != http.StatusOK || err != nil || len(keys) != 1 {
			t.Fatalf("publicKeys: %d %.200s (%v)", code, list, err)
		}
		pk, err := walletmldsa87.BytesToPK(keys[0].PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		desc, err := walletmldsa87.NewMLDSA87Descriptor()
		if err != nil {
			t.Fatal(err)
		}
		if addr, err := walletmldsa87.GetMLDSA87Address(pk, desc); err != nil ||
			!strings.EqualFold(common.Address(addr).Hex(), s.from) {
			t.Fatalf("go-qrllib derives %x from the listed key, not %s (%v)", addr, s.from, err)
		}
		data := []byte("go-remotesigner end-to-end")
		var sig hexutil.Bytes
		if err := s.rpc(&sig, MethodSign, s.from, hexutil.Bytes(data)); err != nil {
			t.Fatal(err)
		}
		digest := TextHash(data)
		if !walletmldsa87.Verify(digest[:], sig, &pk, [3]byte(desc)) {
			t.Fatal("the qrl_sign signature does not verify with go-qrllib")
		}
		if n := ip.count(MethodSign); n != 0 {
			t.Fatalf("qrl_sign reached the node %d times", n)
		}
	})

	t.Run("the allowlist", func(t *testing.T) {
		var version string
		if err := s.rpc(&version, "net_version"); err != nil || version != strconv.Itoa(devChainID) {
			t.Fatalf("net_version %q (%v), want %d from the node", version, err, devChainID)
		}
		if ip.count("net_version") == 0 {
			t.Fatal("net_version did not reach the node")
		}
		for _, method := range []string{"admin_nodeInfo", "debug_getRawHeader", "personal_listAccounts",
			MethodSignTypedData} {
			err := s.rpc(nil, method)
			if e, ok := err.(*Error); !ok || e.Code != ErrMethodNotFound.Code {
				t.Errorf("%s: %v, want %d", method, err, ErrMethodNotFound.Code)
			}
			if n := ip.count(method); n != 0 {
				t.Errorf("%s reached the node %d times", method, n)
			}
		}
	})
}
