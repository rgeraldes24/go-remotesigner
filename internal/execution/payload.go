// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"net/http"

	"github.com/theQRL/go-qrl/common"
	"github.com/theQRL/go-qrl/common/hexutil"
	"github.com/theQRL/go-qrl/core/types"
)

// maxNonceAhead is how far above the node's pending nonce a filled-in nonce
// may be (--execution-nonce-crosscheck). A higher one would wait in the
// pool behind a gap that nothing fills.
const maxNonceAhead = 64

// fillArgs is the transaction object the signer sends to
// qrl_fillTransaction: what the client's request holds, in gqrl's own
// encoding, from the signer's decoding of it. The node never gets the
// client's bytes, so it cannot read a member the signer did not.
type fillArgs struct {
	From                 *common.Address   `json:"from"`
	To                   *common.Address   `json:"to,omitempty"`
	Gas                  *hexutil.Uint64   `json:"gas,omitempty"`
	MaxFeePerGas         *hexutil.Big      `json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas *hexutil.Big      `json:"maxPriorityFeePerGas,omitempty"`
	Value                *hexutil.Big      `json:"value,omitempty"`
	Nonce                *hexutil.Uint64   `json:"nonce,omitempty"`
	Input                *hexutil.Bytes    `json:"input,omitempty"`
	AccessList           *types.AccessList `json:"accessList,omitempty"`
	ChainID              *hexutil.Big      `json:"chainId,omitempty"`
}

func (a *txArgs) fillArgs() fillArgs {
	f := fillArgs{From: a.From, To: a.To, Gas: a.Gas, MaxFeePerGas: a.MaxFeePerGas,
		MaxPriorityFeePerGas: a.MaxPriorityFeePerGas, Value: a.Value, Nonce: a.Nonce, AccessList: a.AccessList,
		ChainID: a.ChainID}
	if d := a.data(); d != nil {
		in := hexutil.Bytes(d)
		f.Input = &in
	}
	return f
}

// filled is a transaction completed by the node, and whether its nonce
// came from the node.
type filled struct {
	tx        *types.DynamicFeeTx
	nodeNonce bool
}

// complete returns the transaction of a, asking the node to fill in what a
// lacks. When a has a nonce, gas, both fee caps and a chain ID, the node
// is not asked. Otherwise qrl_fillTransaction runs gqrl's own defaults, and
// its answer is checked against the request: the payload check. The
// sender is always a's from, which the answer cannot change (go-qrl's
// transaction has no from); the answer's to, value, input, access list and
// chain ID must equal the request's, an absent access list being empty and
// an absent chain ID --chain-id; and of the answer only the nonce, gas and
// fee caps are taken, into a transaction rebuilt from the request. A node
// can therefore only propose a nonce, gas and fees, and the fee cap and the
// nonce cross-check bound those. An answer the check refuses is a refusal
// of the transaction; a node that fails to answer is an error.
func (h *Handler) complete(ctx context.Context, a *txArgs) (filled, *refusal, *Error) {
	t := h.txs
	if a.complete() {
		return filled{tx: a.unsigned(t.chainID)}, nil, nil
	}
	answer, e := h.proxy.call(ctx, nextCallID(), MethodFillTransaction, a.fillArgs())
	if e != nil {
		return filled{}, nil, e
	}
	if answer.err != nil {
		return filled{}, nil, answer.err // the node's own refusal, such as another chain ID
	}
	var result struct {
		Raw hexutil.Bytes `json:"raw"`
	}
	if err := json.Unmarshal(answer.result, &result); err != nil || len(result.Raw) == 0 {
		return filled{}, nil, ErrDownstreamResponse.with(MethodFillTransaction + " returned no raw transaction").
			withStatus(http.StatusBadGateway)
	}
	// The type is checked before anything else reads the transaction.
	got := new(types.Transaction)
	if result.Raw[0] != types.DynamicFeeTxType || got.UnmarshalBinary(result.Raw) != nil ||
		got.Type() != types.DynamicFeeTxType {
		return filled{}, fillRefusal("is not a dynamic-fee (0x2) transaction"), nil
	}
	want := a.unsignedWith(t.chainID, got)
	if field := payloadDiff(want.tx, got); field != "" {
		h.log.WithField("field", field).Error("The downstream node changed a transaction it was asked to fill")
		return filled{}, fillRefusal("changed the transaction's " + field), nil
	}
	if want.tx.GasFeeCap.Cmp(want.tx.GasTipCap) < 0 {
		return filled{}, fillRefusal("has maxFeePerGas below maxPriorityFeePerGas"), nil
	}
	if want.nodeNonce && t.crosscheck {
		pending, e := h.proxy.pendingNonce(ctx, *a.From)
		if e != nil {
			return filled{}, nil, e
		}
		if n := want.tx.Nonce; n > pending && n-pending > maxNonceAhead {
			return filled{}, fillRefusal("has nonce %d, more than %d above the node's pending nonce %d",
				want.tx.Nonce, maxNonceAhead, pending), nil
		}
	}
	return want, nil, nil
}

// fillRefusal refuses the node's answer to qrl_fillTransaction.
func fillRefusal(format string, args ...any) *refusal {
	return refuse("the node's "+MethodFillTransaction+" answer "+format, args...)
}

// unsignedWith is the transaction of a with the nonce, gas and fee caps
// that a lacks taken from the node's transaction got.
func (a *txArgs) unsignedWith(chainID *big.Int, got *types.Transaction) filled {
	b := *a
	f := filled{}
	if b.Nonce == nil {
		n := hexutil.Uint64(got.Nonce())
		b.Nonce, f.nodeNonce = &n, true
	}
	if b.Gas == nil {
		g := hexutil.Uint64(got.Gas())
		b.Gas = &g
	}
	if b.MaxFeePerGas == nil {
		b.MaxFeePerGas = (*hexutil.Big)(got.GasFeeCap())
	}
	if b.MaxPriorityFeePerGas == nil {
		b.MaxPriorityFeePerGas = (*hexutil.Big)(got.GasTipCap())
	}
	f.tx = b.unsigned(chainID)
	return f
}

// payloadDiff returns the first field of the payload check in which the
// node's transaction got differs from want, the transaction of the
// request, or "". want's chain ID is the request's, which is --chain-id
// whether the request has one or not.
func payloadDiff(want *types.DynamicFeeTx, got *types.Transaction) string {
	switch {
	case !sameRecipient(want.To, got.To()):
		return "to"
	case want.Value.Cmp(got.Value()) != 0:
		return "value"
	case !bytes.Equal(want.Data, got.Data()):
		return "input"
	case !sameAccessList(want.AccessList, got.AccessList()):
		return "accessList"
	case want.ChainID.Cmp(got.ChainId()) != 0:
		return "chainId"
	}
	return ""
}

func sameRecipient(a, b *common.Address) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// sameAccessList compares two access lists entry by entry; nil and empty
// lists are equal.
func sameAccessList(a, b types.AccessList) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Address != b[i].Address || len(a[i].StorageKeys) != len(b[i].StorageKeys) {
			return false
		}
		for j := range a[i].StorageKeys {
			if a[i].StorageKeys[j] != b[i].StorageKeys[j] {
				return false
			}
		}
	}
	return true
}
