// Copyright 2019 ConsenSys AG.
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
// core/src/integrationTest/java/tech/pegasys/web3signer/core/jsonrpcproxy/SigningEthSendTransactionIntegrationTest.java
// and core/src/test/java/tech/pegasys/web3signer/core/service/jsonrpc/sendtransaction/NonceTooLowRetryMechanismTest.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

package execution

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/theQRL/go-qrl/core/types"
)

// NonceTooLowRetryMechanismTest: the node's answers that mean the nonce is
// taken need a retry, other answers do not. gqrl's messages are matched
// as parts of -32000 messages (DEVIATIONS.md X25), not as Besu's exact
// (code, message) pairs.
func TestW3SNonceTooLowRetryMechanism(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  *Error
		want bool
	}{
		{"retryIsRequiredIfErrorIsNonceTooLow", &Error{Code: -32000, Message: "nonce too low: next nonce 5, tx nonce 4"}, true},
		{"retryIsRequiredIfErrorIsKnownTransaction", &Error{Code: -32000, Message: "already known"}, true},
		{"retryIsRequiredIfErrorIsReplacementTransactionUnderpriced", &Error{Code: -32000, Message: "replacement transaction underpriced"}, true},
		{"retryIsNotRequiredIfErrorIsNotNonceTooLow", ErrInvalidParams, false},
		{"retryIsNotRequiredForUnknownErrorType", &Error{Code: -9000, Message: "Unknown error"}, false},
		{"Besu's nonce-too-low code", &Error{Code: -32001, Message: "Nonce too low"}, false},
		{"no error", nil, false},
	} {
		if got := needsRetry(tt.err); got != tt.want {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}
}

// The transaction scenarios of SigningEthSendTransactionIntegrationTest
// against the fake gqrl node.
func TestW3SSigningSendTransaction(t *testing.T) {
	t.Run("invalidParamsResponseWhenNonceIsNaN", func(t *testing.T) {
		f, _ := sendFixture(t, 1)
		_, addr := f.key(0)
		code, r := f.sendTx(t, 1, fullTx(addr, "nonce", "I'm an invalid nonce format!"))
		if code != http.StatusBadRequest || r.Error == nil || r.Error.Code != ErrInvalidParams.Code {
			t.Fatalf("%d %+v", code, r.Error)
		}
	})
	t.Run("missingNonceResultsInEthNodeRespondingSuccessfully", func(t *testing.T) {
		f, g := sendFixture(t, 1)
		_, addr := f.key(0)
		code, r := f.sendTx(t, 1, fullTx(addr, "nonce", ""))
		if code != http.StatusOK || r.Error != nil || len(g.sentTxs()) != 1 {
			t.Fatalf("%d %+v", code, r.Error)
		}
	})
	// Web3Signer answers a malformed from with "no unlocked account"; the
	// signer refuses it as invalid params, as it does for qrl_sign
	// (DEVIATIONS.md X79).
	for _, from := range []string{
		"invalidParamsResponseWhenFromAddressIsTooShort:Q" + strings.Repeat("ab", 63),
		"invalidParamsResponseWhenFromAddressIsTooLong:Q" + strings.Repeat("ab", 65),
		"invalidParamsResponseWhenFromAddressIsMalformedHex:Q" + strings.Repeat("ab", 63) + "XX",
		"invalidParamsWhenFromAddressIsEmpty:",
	} {
		name, value, _ := strings.Cut(from, ":")
		t.Run(name, func(t *testing.T) {
			f, g := sendFixture(t, 1)
			_, addr := f.key(0)
			code, r := f.sendTx(t, 1, fullTx(addr, "from", value))
			if value == "" {
				code, r = f.sendTx(t, 1, map[string]any{"from": "", "to": recipient})
			}
			if code != http.StatusBadRequest || r.Error == nil || r.Error.Code != ErrInvalidParams.Code || len(g.methods()) != 0 {
				t.Fatalf("%d %+v", code, r.Error)
			}
		})
	}
	t.Run("signTransactionWhenFromAddressCaseMismatchesUnlockedAccount", func(t *testing.T) {
		f, g := sendFixture(t, 1)
		_, addr := f.key(0)
		for _, from := range []string{"Q" + strings.ToLower(addr[1:]), "Q" + strings.ToUpper(addr[1:])} {
			if code, r := f.sendTx(t, 1, fullTx(from, "nonce", "")); code != http.StatusOK || r.Error != nil {
				t.Fatalf("%s: %d %+v", from, code, r.Error)
			}
		}
		if len(g.sentTxs()) != 2 {
			t.Fatalf("sent %d", len(g.sentTxs()))
		}
	})
	t.Run("invalidParamsResponseWhenMissingFromAddress", func(t *testing.T) {
		f, _ := sendFixture(t, 1)
		_, addr := f.key(0)
		code, r := f.sendTx(t, 1, fullTx(addr, "from", ""))
		if code != http.StatusBadRequest || r.Error == nil || r.Error.Data != "from is required" {
			t.Fatalf("%d %+v", code, r.Error)
		}
	})
	// signTransactionWhenMissingToAddress and signSendTransactionWhenContract:
	// a transaction without to creates a contract, which needs input.
	t.Run("signSendTransactionWhenContract", func(t *testing.T) {
		f, g := sendFixture(t, 1)
		_, addr := f.key(0)
		code, r := f.sendTx(t, 1, fullTx(addr, "to", "", "input", "0x6080604052"))
		if code != http.StatusOK || r.Error != nil || g.sentTxs()[0].To() != nil {
			t.Fatalf("%d %+v", code, r.Error)
		}
		code, r = f.sendTx(t, 2, fullTx(addr, "to", "", "nonce", "0x1"))
		if code != http.StatusBadRequest || r.Error == nil || r.Error.Data != "contract creation without any data provided" {
			t.Fatalf("no input: %d %+v", code, r.Error)
		}
	})
	t.Run("signTransactionWhenEmptyToAddress", func(t *testing.T) {
		f, _ := sendFixture(t, 1)
		_, addr := f.key(0)
		code, r := f.sendTx(t, 1, fullTx(addr, "to", "Q"))
		if code != http.StatusBadRequest || r.Error == nil || r.Error.Code != ErrInvalidParams.Code {
			t.Fatalf("%d %+v", code, r.Error)
		}
	})
	t.Run("signTransactionWhenMissingValue", func(t *testing.T) {
		f, g := sendFixture(t, 1)
		_, addr := f.key(0)
		if code, r := f.sendTx(t, 1, fullTx(addr, "value", "")); code != http.StatusOK || r.Error != nil ||
			g.sentTxs()[0].Value().Sign() != 0 {
			t.Fatalf("%d %+v", code, r.Error)
		}
	})
	// signTransactionWhenMissingGas: Web3Signer defaults to 90,000 gas; the
	// signer asks the node, as gqrl estimates it.
	t.Run("signTransactionWhenMissingGas", func(t *testing.T) {
		f, g := sendFixture(t, 1)
		_, addr := f.key(0)
		if code, r := f.sendTx(t, 1, fullTx(addr, "gas", "")); code != http.StatusOK || r.Error != nil ||
			g.sentTxs()[0].Gas() != 21_000 || len(g.callsOf(MethodFillTransaction)) != 1 {
			t.Fatalf("%d %+v", code, r.Error)
		}
	})
	for _, tt := range []struct{ name, nonce, msg string }{
		{"missingNonceResultsInNewNonceBeingCreatedAndResent", "", "nonce too low: next nonce 1, tx nonce 0"},
		{"nullNonceResultsInNewNonceBeingCreatedAndResent", "null", "nonce too low: next nonce 1, tx nonce 0"},
		{"nullNonceWithUnderpricedResponseResultsInNewNonceBeingCreatedAndResent", "null", "replacement transaction underpriced"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, g := sendFixture(t, 1)
			_, addr := f.key(0)
			first := true
			g.set(func(g *fakeGQRL) {
				g.onSend = func(tx *types.Transaction) *Error {
					if first {
						first = false
						return &Error{Code: -32000, Message: tt.msg}
					}
					return nil
				}
			})
			tx := fullTx(addr, "nonce", "")
			if tt.nonce == "null" {
				tx["nonce"] = nil
			}
			if code, r := f.sendTx(t, 1, tx); code != http.StatusOK || r.Error != nil {
				t.Fatalf("%d %+v", code, r.Error)
			}
			if n := len(g.callsOf(MethodSendRawTransaction)); n != 2 {
				t.Fatalf("%d sends, want 2", n)
			}
		})
	}
	t.Run("transactionWithMissingNonceReturnsErrorsOtherThanLowNonceToCaller", func(t *testing.T) {
		f, g := sendFixture(t, 1)
		_, addr := f.key(0)
		g.set(func(g *fakeGQRL) {
			g.onSend = func(*types.Transaction) *Error { return &Error{Code: -32602, Message: "invalid argument 0"} }
		})
		code, r := f.sendTx(t, 1, fullTx(addr, "nonce", ""))
		if code != http.StatusOK || r.Error == nil || r.Error.Code != -32602 || r.Error.Message != "invalid argument 0" {
			t.Fatalf("%d %+v", code, r.Error)
		}
	})
	for _, msg := range []string{"nonce too low", "replacement transaction underpriced"} {
		t.Run("moreThanTenErrorsReturnsAnErrorToUser/"+msg, func(t *testing.T) {
			f, g := sendFixture(t, 1)
			_, addr := f.key(0)
			g.set(func(g *fakeGQRL) {
				g.onSend = func(*types.Transaction) *Error { return &Error{Code: -32000, Message: msg} }
			})
			code, r := f.sendTx(t, 1, fullTx(addr, "nonce", ""))
			if code != http.StatusBadRequest || r.Error == nil || r.Error.Code != ErrInternal.Code {
				t.Fatalf("%d %+v", code, r.Error)
			}
		})
	}
	t.Run("thirdNonceRetryTimesOutAndGatewayTimeoutIsReturnedToClient", func(t *testing.T) {
		g, nd := newFakeGQRL(t)
		d := downstreamOf(t, nd.Server)
		d.Timeout = 200 * time.Millisecond
		f := newFixtureWith(t, 1, defaultAllow, d, nd)
		_, addr := f.key(0)
		release := make(chan struct{})
		defer close(release)
		sends := 0
		nd.setHandler(func(w http.ResponseWriter, r *http.Request) {
			var c fakeCall
			_ = json.NewDecoder(r.Body).Decode(&c)
			if c.Method == MethodSendRawTransaction {
				if sends++; sends == 3 {
					<-release // the node never answers the third send
					return
				}
				_, _ = w.Write(encodeResult(c.ID, nil, &Error{Code: -32000, Message: "nonce too low"}))
				return
			}
			result, e := g.answer(c)
			_, _ = w.Write(encodeResult(c.ID, result, e))
		})
		code, r := f.sendTx(t, 1, fullTx(addr, "nonce", ""))
		if code != http.StatusGatewayTimeout || r.Error == nil || r.Error.Message != ErrDownstreamTimeout.Message {
			t.Fatalf("%d %+v", code, r.Error)
		}
	})
	// proxyMalformedJsonResponseFromNode: Web3Signer relays a malformed
	// answer to the send as it is; the signer reads the answer to its own
	// call, so it answers that the node's response is invalid.
	t.Run("proxyMalformedJsonResponseFromNode", func(t *testing.T) {
		f, _ := sendFixture(t, 1)
		_, addr := f.key(0)
		f.node.setHandler(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":`))
		})
		code, r := f.sendTx(t, 1, fullTx(addr))
		if code != http.StatusBadGateway || r.Error == nil || r.Error.Message != ErrDownstreamResponse.Message {
			t.Fatalf("%d %+v", code, r.Error)
		}
	})
}
