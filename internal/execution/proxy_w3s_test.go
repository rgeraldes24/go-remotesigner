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
// core/src/integrationTest/java/tech/pegasys/web3signer/core/jsonrpcproxy/ProxyIntegrationTest.java,
// core/src/integrationTest/java/tech/pegasys/web3signer/core/jsonrpcproxy/FailedConnectionIntegrationTest.java,
// core/src/integrationTest/java/tech/pegasys/web3signer/core/jsonrpcproxy/TimeoutTest.java and
// core/src/test/java/tech/pegasys/web3signer/core/service/DownstreamPathCalculatorTest.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

package execution

import (
	"encoding/json"
	"net"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
)

const (
	w3sRPCRequest  = `{"jsonrpc":"2.0","method":"net_version","params":[],"id":0}`
	w3sRPCResponse = `{"id":0,"jsonrpc":2.0,"result":"4","error":null,"rawResponse":null,"netVersion":"4"}`
)

// w3sNode answers net_version as Web3Signer's integration tests do, under
// --downstream-http-path=/arbitraryRootPath.
func w3sNode(t *testing.T) *fixture {
	t.Helper()
	nd := newNode(t)
	nd.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "Application/Json")
		_, _ = w.Write([]byte(w3sRPCResponse))
	})
	d := downstreamOf(t, nd.Server)
	d.Path = "/arbitraryRootPath"
	return newFixtureWith(t, 1, defaultAllow, d, nd)
}

// rpcRequestWithHeadersIsProxied: the node's response passes unchanged,
// the node is posted to at the configured path, and it receives the same
// request. Web3Signer passes the client's bytes on; here the node gets the
// signer's encoding of the request (TestForwardedRequestIsTheCheckedOne).
func TestW3SRPCRequestWithHeadersIsProxied(t *testing.T) {
	f := w3sNode(t)
	w := f.post(w3sRPCRequest, http.Header{"Accept": {"*/*"}})
	if w.Code != http.StatusOK || w.Body.String() != w3sRPCResponse || w.Header().Get("Content-Type") != "Application/Json" {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body)
	}
	got := f.node.received()
	if len(got) != 1 || !sameJSON(t, got[0].body, []byte(w3sRPCRequest)) || got[0].header.Get("Accept") != "*/*" ||
		got[0].path != "/arbitraryRootPath" {
		t.Fatalf("the node received %+v", got)
	}
}

// sameJSON reports whether two JSON texts hold the same value.
func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var va, vb any
	if err := json.Unmarshal(a, &va); err != nil {
		t.Fatalf("%s: %v", a, err)
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	return reflect.DeepEqual(va, vb)
}

// requestWithHostHeaderIsRenamedToXForwardedHost and
// requestWithHostHeaderOverwritesExistingXForwardedHost: Web3Signer passes
// the client's Host on as X-Forwarded-Host. Here no forwarding header
// reaches the node, and its Host is its own.
func TestW3SHostHeaderIsNotForwarded(t *testing.T) {
	f := w3sNode(t)
	f.post(w3sRPCRequest, http.Header{"Accept": {"*.*"}, "X-Forwarded-Host": {"nowhere"}})
	got := f.node.received()
	if len(got) != 1 || got[0].header.Get("X-Forwarded-Host") != "" || got[0].host != f.node.Listener.Addr().String() {
		t.Fatalf("the node received %+v", got)
	}
}

// requestReturningErrorIsProxied: the node's status and body pass back.
func TestW3SRequestReturningErrorIsProxied(t *testing.T) {
	f := w3sNode(t)
	f.node.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Not Found"))
	})
	w := f.post(call(1, "qrl_protocolVersion"), nil)
	if w.Code != http.StatusNotFound || w.Body.String() != "Not Found" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// nonRpcRequestsAreNotProxied: a body that is not JSON-RPC never reaches
// the node. Web3Signer then answers 404; here it is a JSON-RPC invalid
// request.
func TestW3SNonRPCRequestsAreNotProxied(t *testing.T) {
	f := w3sNode(t)
	w := f.post(`{"username":"username1","password":"pegasys"}`, nil)
	if r := decodeOne(t, w.Body.Bytes()); w.Code != http.StatusBadRequest || r.Error.Code != ErrInvalidRequest.Code {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if n := len(f.node.received()); n != 0 {
		t.Fatalf("the node received %d requests", n)
	}
}

// multiValueHeadersFromDownstreamArePassedBackToCallingApplication.
func TestW3SMultiValueHeadersArePassedBack(t *testing.T) {
	f := w3sNode(t)
	f.node.setHandler(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Random", "firstValue")
		w.Header().Add("Random", "secondValue")
		_, _ = w.Write([]byte(w3sRPCResponse))
	})
	w := f.post(w3sRPCRequest, nil)
	if v := w.Header().Values("Random"); len(v) != 2 || v[0] != "firstValue" || v[1] != "secondValue" {
		t.Fatalf("Random: %v", v)
	}
}

// failsToConnectToDownStreamRaisesTimeout: 504 with "Failed to connect to
// downstream node" and the request's id.
func TestW3SFailsToConnectToDownstream(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	f := newFixtureWith(t, 0, defaultAllow,
		config.Downstream{Host: "127.0.0.1", Port: uint16(port), Timeout: time.Second}, nil)
	w := f.post(call(1, "qrl_protocolVersion"), nil)
	if w.Code != http.StatusGatewayTimeout || w.Body.String() != string(encodeResult([]byte("1"), nil, ErrDownstreamConnect)) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// downstreamConnectsButDoesNotRespondReturnsGatewayTimeout.
func TestW3SDownstreamDoesNotRespond(t *testing.T) {
	nd := newNode(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	nd.setHandler(func(http.ResponseWriter, *http.Request) { <-release })
	d := downstreamOf(t, nd.Server)
	d.Timeout = 50 * time.Millisecond
	f := newFixtureWith(t, 0, defaultAllow, d, nd)
	w := f.post(call(1, "qrl_protocolVersion"), nil)
	if w.Code != http.StatusGatewayTimeout || w.Body.String() != string(encodeResult([]byte("1"), nil, ErrDownstreamTimeout)) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// DownstreamPathCalculatorTest, for the one request path this signer
// serves, "/".
func TestW3SDownstreamPath(t *testing.T) {
	for prefix, want := range map[string]string{
		"rootPath/child":   "/rootPath/child",
		"/rootPath/child":  "/rootPath/child",
		"/rootPath/child/": "/rootPath/child",
		"prefix":           "/prefix",
		"/":                "/",
		"":                 "/",
		"////":             "/",
	} {
		if got := DownstreamPath(prefix); got != want {
			t.Errorf("DownstreamPath(%q) = %q, want %q", prefix, got, want)
		}
	}
}
