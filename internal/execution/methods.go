// Copyright 2023 ConsenSys AG.
// Copyright 2024 ConsenSys AG.
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
// core/src/main/java/tech/pegasys/web3signer/core/routes/eth1/JsonRpcRoute.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/Eth1AccountsHandler.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/jsonrpc/handlers/internalresponse/EthSignResultProvider.java
// and core/src/main/java/tech/pegasys/web3signer/core/util/EthMessageUtil.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"golang.org/x/crypto/sha3"

	"github.com/rgeraldes24/go-remotesigner/internal/api/jsonutil"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// The methods this signer answers itself. Every other method is forwarded
// when the allowlist allows it.
const (
	MethodAccounts        = "qrl_accounts"
	MethodSign            = "qrl_sign"
	MethodHealthStatus    = "health_status"
	MethodSignTransaction = "qrl_signTransaction"
	MethodSendTransaction = "qrl_sendTransaction"
	MethodSignTypedData   = "qrl_signTypedData"
)

// method answers one intercepted request. A method that takes parameters
// finds them with elements, which stops past the last one it takes; params
// decoded whole, of the largest size and of tiny elements, would cost tens
// of times their size.
type method func(ctx context.Context, req *Request) (any, *Error)

// methods is the table of intercepted methods. The transaction methods are
// answered here, so that they never reach the downstream node, which would
// sign with keys of its own. Typed-data signing is not offered at all, and
// its method is never forwarded either.
func (h *Handler) methods() map[string]method {
	return map[string]method{
		MethodAccounts:        h.qrlAccounts,
		MethodSign:            h.qrlSign,
		MethodHealthStatus:    func(context.Context, *Request) (any, *Error) { return "OK", nil },
		MethodSignTransaction: h.qrlSignTransaction,
		MethodSendTransaction: h.qrlSendTransaction,
		MethodSignTypedData: func(context.Context, *Request) (any, *Error) {
			return nil, ErrMethodNotFound.with("typed-data signing is not offered")
		},
	}
}

// qrlAccounts is qrl_accounts: the loaded addresses in QIP-55 form, sorted
// by address. Its params must be absent, null or an empty array.
func (h *Handler) qrlAccounts(_ context.Context, req *Request) (any, *Error) {
	if _, ok := elements(req.Params, 0); req.Params != nil && !ok {
		return nil, ErrInvalidParams.with(MethodAccounts + " takes no parameters")
	}
	list := h.accounts.List()
	out := make([]string, len(list))
	for i, a := range list {
		out[i] = mldsa87.ChecksumAddress(a.Address)
	}
	return out, nil
}

// qrlSign is qrl_sign(address, data), as gqrl's: the data is hex, the signed
// message is TextHash(data), the signature is hedged ML-DSA-87, and the
// result is the raw 4,627-byte signature in hex. ML-DSA signatures are not
// recoverable and carry no public key: verifiers take it from
// GET /api/v1/execution/publicKeys.
func (h *Handler) qrlSign(ctx context.Context, req *Request) (any, *Error) {
	params, ok := elements(req.Params, 2)
	if !ok || len(params) != 2 {
		return nil, ErrInvalidParams.with(MethodSign + " takes [address, data]")
	}
	var addrText, dataText string
	if json.Unmarshal(params[0], &addrText) != nil || json.Unmarshal(params[1], &dataText) != nil {
		return nil, ErrInvalidParams.with(MethodSign + " takes two strings")
	}
	addr, err := jsonutil.ParseQAddress(addrText)
	if err != nil {
		return nil, ErrInvalidParams.with("address must be Q followed by 128 hex characters")
	}
	data, ok := hexData(dataText)
	if !ok {
		return nil, ErrInvalidParams.with("data must be 0x followed by an even number of hex characters")
	}
	key, ok := h.accounts.Lookup(Address(addr))
	if !ok {
		return nil, ErrUnknownAccount
	}
	release, e := h.admit(ctx)
	if e != nil {
		return nil, e
	}
	defer release()
	digest := TextHash(data)
	sig, err := key.Sign(digest[:], mldsa87.Hedged)
	switch {
	case errors.Is(err, mldsa87.ErrZeroized):
		return nil, ErrUnknownAccount // removed by a reload while the request ran
	case err != nil:
		h.log.WithError(err).Error("qrl_sign failed")
		return nil, ErrInternal
	case !key.Verify(digest[:], sig[:]):
		// The bytes never leave the signer.
		h.log.WithField("key", logID(key)).Error("A qrl_sign signature failed verification and was discarded")
		return nil, ErrInternal
	}
	return "0x" + hex.EncodeToString(sig[:]), nil
}

// admit takes a slot of the signing gate for one signing call (qrl_sign,
// qrl_signTransaction or qrl_sendTransaction; each element of a batch takes
// its own), waiting in the gate's queue when every slot is taken. When the
// queue is full too it refuses at once with -32005, whose single response is
// a 503, like consensus mode's 503 OVERLOADED. The caller calls release
// once its signing work is done.
func (h *Handler) admit(ctx context.Context) (release func(), e *Error) {
	if h.gate == nil {
		return func() {}, nil
	}
	release, err := h.gate.Acquire(ctx)
	if err != nil {
		return nil, ErrLimitExceeded.with("too many signing requests at once; retry later").
			withStatus(http.StatusServiceUnavailable)
	}
	return release, nil
}

// TextHash is go-qrl's accounts.TextHash: Keccak-256 of
// "\x19QRL Signed Message:\n", the data's length in decimal, and the data.
// The prefix keeps a signed message from being a valid transaction hash.
func TextHash(data []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("\x19QRL Signed Message:\n" + strconv.Itoa(len(data))))
	h.Write(data)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// hexData decodes go-qrl's hexutil.Bytes form: 0x and an even number of hex
// digits. Text data is refused, as gqrl refuses it.
func hexData(s string) ([]byte, bool) {
	h, ok := cutHexPrefix(s)
	if !ok || len(h)%2 != 0 {
		return nil, false
	}
	b, err := hex.DecodeString(h)
	return b, err == nil
}

func cutHexPrefix(s string) (string, bool) {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:], true
	}
	return "", false
}

// logID is the form of a key that logs print.
func logID(k *mldsa87.Key) string {
	pk := k.PublicKey()
	return pk.LogID()
}
