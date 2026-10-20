// Copyright 2019 ConsenSys AG.
// Copyright 2023 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/eth1rpc/PassThroughAcceptanceTest.java,
// acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/eth1rpc/AccountManagementAcceptanceTest.java,
// acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/eth1rpc/Eth1RpcReloadKeysTest.java and
// acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/bulkloading/SecpV3KeystoresBulkLoadAcceptanceTest.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

package acceptance

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
)

// accounts returns qrl_accounts, the "Q" kept and the rest in lower case.
func (s *signer) accounts(t *testing.T) []string {
	t.Helper()
	_, body := s.rpc(`{"jsonrpc":"2.0","id":1,"method":"qrl_accounts","params":[]}`, nil)
	var accounts []string
	if err := json.Unmarshal(reply(t, body).Result, &accounts); err != nil {
		t.Fatalf("qrl_accounts: %s", body)
	}
	for i, a := range accounts {
		accounts[i] = "Q" + strings.ToLower(a[1:])
	}
	slices.Sort(accounts)
	return accounts
}

// proxiesRequestToWeb3Provider: a method the signer does not answer gets
// the node's own answer.
func TestW3SProxiesRequestToNode(t *testing.T) {
	node := newGQRLNode(t)
	node.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":7,"result":"0x56bc75e2d63100000"}`))
	})
	s := start(t, options{command: "execution", consensus: downstreamFlags(t, node.Server)})
	s.waitReady()
	_, body := s.rpc(`{"jsonrpc":"2.0","id":7,"method":"qrl_getBalance","params":["Q`+strings.Repeat("00", 64)+`","latest"]}`, nil)
	if body != `{"jsonrpc":"2.0","id":7,"result":"0x56bc75e2d63100000"}` {
		t.Fatalf("qrl_getBalance: %s", body)
	}
}

// ethSignerAccountListHasSingleEntry and ethNodeAccountListIsEmpty: the
// signer lists its one account, and the node is never asked for its own.
func TestW3SAccountListHasSingleEntry(t *testing.T) {
	node := newGQRLNode(t)
	keys := t.TempDir()
	addr := writeAccountKey(t, keys, "account.yaml", keystoretest.ExtendedSeed("w3s-accounts", 0))
	s := start(t, options{command: "execution", keys: keys, consensus: downstreamFlags(t, node.Server)})
	s.waitReady()
	if got := s.accounts(t); !slices.Equal(got, []string{addr}) {
		t.Fatalf("accounts %v, want [%s]", got, addr)
	}
	if reqs, _ := node.received(); len(reqs) != 0 {
		t.Fatalf("the node was asked %d times", len(reqs))
	}
}

// additionalPublicKeyAreReportedAfterReloadUsingEth1RPC: an account added
// to the key-config directory is listed after POST /reload.
func TestW3SAccountsReportedAfterReload(t *testing.T) {
	node := newGQRLNode(t)
	keys := t.TempDir()
	first := writeAccountKey(t, keys, "first.yaml", keystoretest.ExtendedSeed("w3s-reload", 0))
	s := start(t, options{command: "execution", keys: keys, consensus: downstreamFlags(t, node.Server)})
	s.waitReady()
	if got := s.accounts(t); !slices.Equal(got, []string{first}) {
		t.Fatalf("accounts before the reload %v", got)
	}
	second := writeAccountKey(t, keys, "second.yaml", keystoretest.ExtendedSeed("w3s-reload", 1))
	if code, body, _ := s.do(request{method: http.MethodPost, path: "/reload", token: s.adminToken(),
		contentType: "application/json"}); code != http.StatusAccepted {
		t.Fatalf("POST /reload: %d %s", code, body)
	}
	want := []string{first, second}
	slices.Sort(want)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if got := s.accounts(t); slices.Equal(got, want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("accounts after the reload %v, want %v", s.accounts(t), want)
		}
	}
}

// v3KeystoresAreBulkLoaded, for go-qrl account keystores: with a password
// directory or one password file, from the command line or the config
// file, every keystore loads, publicKeys lists them, and the keystore
// check is UP with no error.
func TestW3SAccountKeystoresAreBulkLoaded(t *testing.T) {
	ksDir, pwDir := t.TempDir(), t.TempDir()
	sealer, err := keystoretest.NewSealer("test123", keystoretest.Cheapest)
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for i := range 4 {
		ext := keystoretest.ExtendedSeed("w3s-bulk", i)
		addr, err := keystoretest.Address(ext)
		if err != nil {
			t.Fatal(err)
		}
		data, err := sealer.Account(ext, addr)
		if err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("UTC--2026-10-18T00-00-0%dZ--%s", i, addr[1:9])
		if _, err := keystoretest.WriteFile(ksDir, name+".json", data); err != nil {
			t.Fatal(err)
		}
		if _, err := keystoretest.WriteFile(pwDir, name+".txt", []byte("test123")); err != nil {
			t.Fatal(err)
		}
		want = append(want, addr)
	}
	slices.Sort(want)
	entries, err := os.ReadDir(pwDir)
	if err != nil {
		t.Fatal(err)
	}
	passwordFile := filepath.Join(pwDir, entries[0].Name())
	for _, tt := range []struct {
		name     string
		password string
		config   bool
	}{
		{"password directory, flags", "--keystores-passwords-path=" + pwDir, false},
		{"password file, flags", "--keystores-password-file=" + passwordFile, false},
		{"password directory, config file", "keystores-passwords-path: " + pwDir, true},
		{"password file, config file", "keystores-password-file: " + passwordFile, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			node := newGQRLNode(t)
			o := options{command: "execution", consensus: downstreamFlags(t, node.Server)}
			if tt.config {
				file := filepath.Join(t.TempDir(), "config.yaml")
				content := "execution:\n  keystores-path: " + ksDir + "\n  " + tt.password + "\n"
				if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
				o.global = []string{"--config-file=" + file}
			} else {
				o.consensus = append(o.consensus, "--keystores-path="+ksDir, tt.password)
			}
			s := start(t, o)
			s.waitReady()
			code, body, _ := s.do(request{path: "/api/v1/execution/publicKeys", token: s.signToken()})
			var keys []struct {
				Address string `json:"address"`
			}
			if err := json.Unmarshal([]byte(body), &keys); code != 200 || err != nil {
				t.Fatalf("publicKeys %d %.200s", code, body)
			}
			var got []string
			for _, k := range keys {
				got = append(got, "Q"+strings.ToLower(k.Address[1:]))
			}
			if !slices.Equal(got, want) {
				t.Fatalf("publicKeys %v, want %v", got, want)
			}
			code, health, _ := s.do(request{path: "/healthcheck", token: s.signToken()})
			if code != 200 || !strings.Contains(health, `"status":"UP"`) ||
				!strings.Contains(health, `{"id":"keys-check/keystores-bulk-loading","status":"UP","data":{"error-count":0,"keys-loaded":4}}`) {
				t.Fatalf("healthcheck %d %s", code, health)
			}
		})
	}
}
