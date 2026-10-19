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
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/sendtransaction/SendTransactionHandler.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/sendtransaction/TransactionTransmitter.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/sendtransaction/RetryingTransactionTransmitter.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/sendtransaction/NonceTooLowRetryMechanism.java
// and core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/sendtransaction/RetryMechanism.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

package execution

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/theQRL/go-qrl/common/hexutil"
)

// MaxNonceRetries is how many times qrl_sendTransaction fills, signs and
// sends again after the node refuses a nonce the client did not choose.
const MaxNonceRetries = 10

// nonceErrorCode is the code of gqrl's transaction-pool errors.
const nonceErrorCode = -32000

// nonceMessages are the parts of gqrl's transaction-pool messages that mean
// another transaction holds the nonce: "nonce too low: next nonce …",
// "already known" and "replacement transaction underpriced". A hedged
// re-signature changes the transaction's hash, so a resent nonce gives the
// last one rather than "already known".
var nonceMessages = []string{"nonce too low", "already known", "replacement transaction underpriced"}

// needsRetry reports whether the node's refusal of a sent transaction is a
// nonce taken by another transaction.
func needsRetry(e *Error) bool {
	if e == nil || e.Code != nonceErrorCode {
		return false
	}
	for _, m := range nonceMessages {
		if strings.Contains(e.Message, m) {
			return true
		}
	}
	return false
}

// qrlSendTransaction is qrl_sendTransaction: the signer completes the
// transaction (asking the node with qrl_fillTransaction when the request
// lacks a nonce, gas, a fee cap or a chain ID), applies the chain ID, fee
// cap and policy, signs it and sends it to the node with
// qrl_sendRawTransaction under the client's id, then relays the node's
// answer. The sender's lock is held from the fill to the node's answer,
// so that two calls for one account never take the same nonce. When the
// client did not choose the nonce and the node answers that another
// transaction holds it, the signer fills, signs and sends again, up to
// MaxNonceRetries times.
func (h *Handler) qrlSendTransaction(ctx context.Context, req *Request) (any, *Error) {
	a, e := parseTxArgs(req)
	if e != nil {
		return nil, e
	}
	t := h.txs
	from := Address(*a.From)
	key, ok := h.accounts.Lookup(from)
	if !ok {
		t.auditRefusal(req.Method, a, ErrUnknownAccount.Message, h.log)
		return nil, ErrUnknownAccount
	}
	if r := t.checkChain(a); r != nil {
		return nil, t.refused(req.Method, a, r, h.log)
	}
	unlock, err := t.locks.lock(ctx, from)
	if err != nil {
		// The client went, or the request reached its end waiting for the
		// account's earlier transactions.
		return nil, ErrInternal.with("timed out waiting for this account's earlier transactions").
			withStatus(http.StatusServiceUnavailable)
	}
	defer unlock()

	reserved := false
	for retries := 0; ; retries++ {
		f, r, e := h.complete(ctx, a)
		if e != nil {
			return nil, e
		}
		if r == nil {
			r = t.check(from, f.tx)
		}
		if r == nil && !reserved {
			// One request counts once against max-transactions-per-hour,
			// however many times it is signed.
			r = t.policy.Reserve(from, t.now())
		}
		if r != nil {
			return nil, t.refused(req.Method, a, r, h.log)
		}
		reserved = true
		signed, e := t.sign(req.Method, key, from, f.tx, h.log)
		if e != nil {
			return nil, e
		}
		raw, err := signed.MarshalBinary()
		if err != nil {
			h.log.WithError(err).Error("Encoding a signed transaction failed")
			return nil, ErrInternal
		}
		answer, e := h.proxy.call(ctx, req.ID, MethodSendRawTransaction, hexutil.Bytes(raw))
		if e != nil {
			return nil, e
		}
		outcome, reason := AuditSent, ""
		if answer.err != nil {
			outcome, reason = AuditNodeRefused, cut(answer.err.Message)
		}
		if t.audit != nil {
			if err := t.audit.Write(auditTx(req.Method, outcome, from, signed, reason)); err != nil {
				h.log.WithError(err).Error("Writing the audit log failed")
			}
		}
		if answer.err == nil {
			return answer.result, nil
		}
		if a.Nonce != nil || !needsRetry(answer.err) {
			return nil, answer.err
		}
		if retries == MaxNonceRetries {
			h.log.WithFields(logrus.Fields{"retries": MaxNonceRetries, "error": cut(answer.err.Message)}).
				Warn("The node kept refusing the nonce of a transaction; giving up")
			return nil, ErrInternal.with("the node refused the transaction's nonce " +
				strconv.Itoa(MaxNonceRetries+1) + " times: " + cut(answer.err.Message)).withStatus(http.StatusBadRequest)
		}
		h.log.WithFields(logrus.Fields{"retry": retries + 1, "error": cut(answer.err.Message)}).
			Info("The node refused the transaction's nonce; filling, signing and sending it again")
	}
}
