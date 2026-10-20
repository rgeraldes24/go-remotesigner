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
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/internalresponse/EthSignTransactionResultProvider.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/EthSendTransactionJsonParameters.java and
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/signing/TransactionSerializer.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/theQRL/go-qrl/common"
	"github.com/theQRL/go-qrl/common/hexutil"
	"github.com/theQRL/go-qrl/core/types"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// Transactions signs transactions for the execution endpoint: the chain
// they are for, the policy that limits them, the audit log that records
// them, and the per-sender locks of qrl_sendTransaction.
type Transactions struct {
	chainID *big.Int
	signer  types.Signer
	policy  *Policy
	audit   *AuditLog // nil: no audit log
	chain   *chainMonitor
	// crosscheck compares a nonce the node filled in with its pending nonce.
	crosscheck bool
	// mode is how transactions are signed: hedged, except in tests that
	// compare signed transactions with golden vectors.
	mode  mldsa87.Mode
	locks senderLocks
	now   func() time.Time
}

// TransactionsConfig configures Transactions.
type TransactionsConfig struct {
	// ChainID is --chain-id.
	ChainID *big.Int
	// Policy is the --execution-policy-file policy, or OpenPolicy().
	Policy *Policy
	// Audit is the --execution-audit-log-file log, or nil.
	Audit *AuditLog
	// NonceCrosscheck is --execution-nonce-crosscheck.
	NonceCrosscheck bool
}

// NewTransactions returns the transaction signer of cfg.
func NewTransactions(cfg TransactionsConfig) *Transactions {
	policy := cfg.Policy
	if policy == nil {
		policy = OpenPolicy()
	}
	return &Transactions{
		chainID:    new(big.Int).Set(cfg.ChainID),
		signer:     types.NewZondSigner(new(big.Int).Set(cfg.ChainID)),
		policy:     policy,
		audit:      cfg.Audit,
		crosscheck: cfg.NonceCrosscheck,
		mode:       mldsa87.Hedged,
		now:        time.Now,
	}
}

// txArgs is the transaction object of qrl_signTransaction and
// qrl_sendTransaction, with gqrl's member names and encodings: Q
// addresses, 0x quantities without leading zeros, 0x data. Members it does
// not name are ignored, as gqrl ignores them; type, when present, must be
// 0x2.
type txArgs struct {
	From                 *common.Address   `json:"from"`
	To                   *common.Address   `json:"to"`
	Gas                  *hexutil.Uint64   `json:"gas"`
	MaxFeePerGas         *hexutil.Big      `json:"maxFeePerGas"`
	MaxPriorityFeePerGas *hexutil.Big      `json:"maxPriorityFeePerGas"`
	Value                *hexutil.Big      `json:"value"`
	Nonce                *hexutil.Uint64   `json:"nonce"`
	Data                 *hexutil.Bytes    `json:"data"`
	Input                *hexutil.Bytes    `json:"input"`
	AccessList           *types.AccessList `json:"accessList"`
	ChainID              *hexutil.Big      `json:"chainId"`
	Type                 json.RawMessage   `json:"type"`
}

// typeRefusal is the refusal of a transaction whose type is not 0x2.
const typeRefusal = "only dynamic-fee transactions (type 0x2) are signed"

// parseTxArgs reads the params of a transaction method: one transaction
// object. A member that is not valid for its field is -32602, as gqrl
// refuses it. A type other than 0x2 is -32602 too, and, as a transaction
// the signer refuses, is logged and written to the audit log once from is
// known.
func (t *Transactions) parseTxArgs(req *Request, log logrus.FieldLogger) (*txArgs, *Error) {
	params, ok := elements(req.Params, 1)
	if !ok || len(params) != 1 {
		return nil, ErrInvalidParams.with(req.Method + " takes [transaction]")
	}
	if !isObject(params[0]) {
		return nil, ErrInvalidParams.with("the transaction must be a JSON object")
	}
	var a txArgs
	if err := json.Unmarshal(params[0], &a); err != nil {
		return nil, ErrInvalidParams.with(paramError(err))
	}
	switch {
	case a.From == nil:
		return nil, ErrInvalidParams.with("from is required")
	case a.Type != nil && !isDynamicFeeType(a.Type):
		t.logRefusal(req.Method, typeRefusal, log)
		t.auditRefusal(req.Method, &a, typeRefusal, log)
		return nil, ErrInvalidParams.with(typeRefusal)
	case a.Data != nil && a.Input != nil && !bytes.Equal(*a.Data, *a.Input):
		return nil, ErrInvalidParams.with(`both "data" and "input" are set and not equal; use "input"`)
	case a.To == nil && len(a.data()) == 0:
		return nil, ErrInvalidParams.with("contract creation without any data provided")
	case a.MaxFeePerGas != nil && a.MaxPriorityFeePerGas != nil &&
		a.MaxFeePerGas.ToInt().Cmp(a.MaxPriorityFeePerGas.ToInt()) < 0:
		return nil, ErrInvalidParams.with("maxFeePerGas is below maxPriorityFeePerGas")
	}
	return &a, nil
}

// isObject reports whether raw JSON is an object.
func isObject(raw json.RawMessage) bool {
	b := bytes.TrimLeft(raw, " \t\r\n")
	return len(b) > 0 && b[0] == '{'
}

// isDynamicFeeType reports whether a type member is 2: "0x2" (leading
// zeros allowed) or the number 2.
func isDynamicFeeType(raw json.RawMessage) bool {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		h, ok := cutHexPrefix(s)
		if !ok {
			return false
		}
		v, err := strconv.ParseUint(h, 16, 8)
		return err == nil && v == types.DynamicFeeTxType
	}
	var n json.Number
	return json.Unmarshal(raw, &n) == nil && n.String() == "2"
}

// paramError is the data of an invalid-params error: the field and what is
// wrong with it, as go-qrl's decoders say it.
func paramError(err error) string {
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) && te.Field != "" {
		return te.Field + ": " + cut(te.Value)
	}
	msg := err.Error()
	if i := strings.Index(msg, "into Go struct field txArgs."); i >= 0 {
		rest := msg[i+len("into Go struct field txArgs."):]
		field, _, _ := strings.Cut(rest, " ")
		return field + ": " + strings.TrimSpace(msg[:i])
	}
	return cut(msg)
}

// data is the input: input, or data when input is absent.
func (a *txArgs) data() []byte {
	switch {
	case a.Input != nil:
		return *a.Input
	case a.Data != nil:
		return *a.Data
	}
	return nil
}

// value is the value, 0 when absent.
func (a *txArgs) value() *big.Int {
	if a.Value == nil {
		return new(big.Int)
	}
	return a.Value.ToInt()
}

// accessList is the access list, empty when absent.
func (a *txArgs) accessList() types.AccessList {
	if a.AccessList == nil {
		return types.AccessList{}
	}
	return *a.AccessList
}

// complete reports whether the transaction needs nothing from the node.
func (a *txArgs) complete() bool {
	return a.Nonce != nil && a.Gas != nil && a.MaxFeePerGas != nil && a.MaxPriorityFeePerGas != nil &&
		a.ChainID != nil
}

// unsigned is the transaction of a with chain ID chainID.
func (a *txArgs) unsigned(chainID *big.Int) *types.DynamicFeeTx {
	return &types.DynamicFeeTx{
		ChainID:    new(big.Int).Set(chainID),
		Nonce:      uint64(*a.Nonce),
		GasTipCap:  new(big.Int).Set(a.MaxPriorityFeePerGas.ToInt()),
		GasFeeCap:  new(big.Int).Set(a.MaxFeePerGas.ToInt()),
		Gas:        uint64(*a.Gas),
		To:         a.To,
		Value:      a.value(),
		Data:       a.data(),
		AccessList: a.accessList(),
	}
}

// fee is gas × maxFeePerGas, the most a transaction can pay.
func fee(tx *types.DynamicFeeTx) *big.Int {
	return new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas), tx.GasFeeCap)
}

// signTransactionResult is the result of qrl_signTransaction, as gqrl's:
// the encoded signed transaction and its JSON form.
type signTransactionResult struct {
	Raw hexutil.Bytes      `json:"raw"`
	Tx  *types.Transaction `json:"tx"`
}

// qrlSignTransaction is qrl_signTransaction, as gqrl's: from, nonce, gas,
// maxFeePerGas and maxPriorityFeePerGas are required, the signer never asks
// the node for anything, and the result is {raw, tx}. The chain ID, the
// fee cap and the account's policy apply.
func (h *Handler) qrlSignTransaction(_ context.Context, req *Request) (any, *Error) {
	t := h.txs
	a, e := t.parseTxArgs(req, h.log)
	if e != nil {
		return nil, e
	}
	switch {
	case a.Gas == nil:
		return nil, ErrInvalidParams.with("gas not specified")
	case a.MaxFeePerGas == nil || a.MaxPriorityFeePerGas == nil:
		return nil, ErrInvalidParams.with("missing maxFeePerGas/maxPriorityFeePerGas")
	case a.Nonce == nil:
		return nil, ErrInvalidParams.with("nonce not specified")
	}
	from := Address(*a.From)
	key, ok := h.accounts.Lookup(from)
	if !ok {
		t.auditRefusal(req.Method, a, ErrUnknownAccount.Message, h.log)
		return nil, ErrUnknownAccount
	}
	if r := t.checkChain(a); r != nil {
		return nil, t.refused(req.Method, a, r, h.log)
	}
	tx := a.unsigned(t.chainID)
	if r := t.check(from, tx); r != nil {
		return nil, t.refused(req.Method, a, r, h.log)
	}
	if r := t.policy.Reserve(from, t.now()); r != nil {
		return nil, t.refused(req.Method, a, r, h.log)
	}
	signed, e := t.sign(req.Method, key, from, tx, h.log)
	if e != nil {
		return nil, e
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		h.log.WithError(err).Error("Encoding a signed transaction failed")
		return nil, ErrInternal
	}
	return signTransactionResult{Raw: raw, Tx: signed}, nil
}

// checkChain refuses a transaction for another chain than --chain-id, and
// every transaction while the node's chain ID differs from it.
func (t *Transactions) checkChain(a *txArgs) *refusal {
	if a.ChainID != nil && a.ChainID.ToInt().Cmp(t.chainID) != 0 {
		return refuse("chainId %s is not --chain-id %s", a.ChainID.ToInt(), t.chainID)
	}
	return t.chain.refusal()
}

// check applies the policy of from to a transaction: recipient, value,
// input length and fee.
func (t *Transactions) check(from Address, tx *types.DynamicFeeTx) *refusal {
	var to *Address
	if tx.To != nil {
		a := Address(*tx.To)
		to = &a
	}
	return t.policy.Check(from, to, tx.Value, len(tx.Data), fee(tx))
}

// sign signs tx with key, the account from, and audits the signature
// before it leaves the signer. Only a dynamic-fee transaction is signed:
// go-qrl hashes any other type to zeros. The signed transaction must
// verify, and its sender must be from.
func (t *Transactions) sign(method string, key *mldsa87.Key, from Address, data *types.DynamicFeeTx,
	log logrus.FieldLogger) (*types.Transaction, *Error) {
	tx := types.NewTx(data)
	if tx.Type() != types.DynamicFeeTxType {
		return nil, ErrInternal
	}
	signed, err := types.SignTx(tx, t.signer, keyWallet{key: key, mode: t.mode})
	switch {
	case errors.Is(err, mldsa87.ErrZeroized):
		return nil, ErrUnknownAccount // removed by a reload while the request ran
	case err != nil:
		log.WithError(err).WithField("key", logID(key)).Error("Signing a transaction failed")
		return nil, ErrInternal
	}
	sender, err := types.Sender(t.signer, signed)
	if err != nil || Address(sender) != from {
		log.WithField("key", logID(key)).Error("A signed transaction failed verification and was discarded")
		return nil, ErrInternal
	}
	if t.audit != nil {
		if err := t.audit.Write(auditTx(method, AuditSigned, from, signed, "")); err != nil {
			log.WithError(err).Error("Writing the audit log failed; the signed transaction was discarded")
			return nil, ErrInternal
		}
	}
	return signed, nil
}

// refused records a refusal in the log and the audit log and returns its
// error.
func (t *Transactions) refused(method string, a *txArgs, r *refusal, log logrus.FieldLogger) *Error {
	t.logRefusal(method, r.reason, log)
	t.auditRefusal(method, a, r.reason, log)
	return ErrTxRejected.with(r.reason)
}

// logRefusal logs the refusal of a transaction.
func (*Transactions) logRefusal(method, reason string, log logrus.FieldLogger) {
	log.WithFields(logrus.Fields{"method": method, "reason": reason}).Warn("A transaction was refused")
}

// auditRefusal writes the refusal of a's transaction to the audit log.
func (t *Transactions) auditRefusal(method string, a *txArgs, reason string, log logrus.FieldLogger) {
	if t.audit == nil {
		return
	}
	e := AuditEntry{Method: method, Outcome: AuditRefused, Reason: reason, From: a.From.Hex(), Value: quantityHex(a.value())}
	if a.To != nil {
		e.To = a.To.Hex()
	}
	if a.Nonce != nil {
		e.Nonce = a.Nonce.String()
	}
	if a.Gas != nil && a.MaxFeePerGas != nil {
		e.Fee = quantityHex(new(big.Int).Mul(new(big.Int).SetUint64(uint64(*a.Gas)), a.MaxFeePerGas.ToInt()))
	}
	if a.ChainID != nil {
		e.ChainID = a.ChainID.String()
	}
	if err := t.audit.Write(e); err != nil {
		log.WithError(err).Error("Writing the audit log failed")
	}
}

// auditTx is the audit entry of a signed transaction.
func auditTx(method, outcome string, from Address, tx *types.Transaction, reason string) AuditEntry {
	e := AuditEntry{
		Method:  method,
		Outcome: outcome,
		Hash:    tx.Hash().Hex(),
		From:    common.Address(from).Hex(),
		Nonce:   hexutil.EncodeUint64(tx.Nonce()),
		Value:   quantityHex(tx.Value()),
		Fee:     quantityHex(new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas()), tx.GasFeeCap())),
		ChainID: quantityHex(tx.ChainId()),
		Reason:  reason,
	}
	if to := tx.To(); to != nil {
		e.To = to.Hex()
	}
	return e
}

// quantityHex is a quantity in 0x hex.
func quantityHex(v *big.Int) string { return hexutil.EncodeBig(v) }
