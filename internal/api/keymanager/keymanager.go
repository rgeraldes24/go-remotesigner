// Copyright 2021 ConsenSys AG.
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
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/list/ListKeystoresHandler.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/list/KeystoreInfo.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/imports/ImportKeystoresHandler.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/imports/ImportKeystoresRequestBody.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/imports/ImportKeystoreResult.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/delete/DeleteKeystoresHandler.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/delete/DeleteKeystoresRequestBody.java and
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/keymanager/delete/DeleteKeystoresResponse.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

// Package keymanager serves the keymanager API, GET, POST and DELETE
// /qrl/v1/keystores (docs/contract.md section 17,
// docs/operations/keymanager.md): strict decoding of the request bodies,
// which are never logged, and the response shapes of the contract. The
// operations themselves are package internal/keymanager's.
package keymanager

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/apierr"
	"github.com/rgeraldes24/go-remotesigner/internal/api/jsonutil"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	km "github.com/rgeraldes24/go-remotesigner/internal/keymanager"
	"github.com/rgeraldes24/go-remotesigner/internal/server"
)

// Route limits (docs/contract.md section 13).
const (
	// BodyLimit bounds a POST or DELETE body: 64 keystores of about 6 KB
	// leave the rest to the slashing-protection history.
	BodyLimit = 32 << 20
	// WriteTimeout replaces the server's write deadline: an import of 64
	// standard-KDF keystores decrypts for minutes on a small machine.
	WriteTimeout = 10 * time.Minute
)

// Handlers serves the keymanager routes over a Manager.
type Handlers struct {
	Manager *km.Manager
	Log     logrus.FieldLogger
}

// List serves GET /qrl/v1/keystores: every loaded key, sorted, with the
// derivation path its keystore records and whether it is read-only. The
// list is written as it is read, without building it in memory.
func (h *Handlers) List() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		keys := h.Manager.List()
		w.Header().Set("Content-Type", server.ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		bw := bufio.NewWriterSize(w, 64<<10)
		_, _ = bw.WriteString(`{"data":[`)
		hexBuf := make([]byte, 2*mldsa87.PublicKeySize)
		for i, k := range keys {
			if i > 0 {
				_ = bw.WriteByte(',')
			}
			hex.Encode(hexBuf, k.PublicKey[:])
			path, _ := json.Marshal(k.DerivationPath)
			_, _ = bw.WriteString(`{"validating_pubkey":"0x`)
			_, _ = bw.Write(hexBuf)
			_, _ = bw.WriteString(`","derivation_path":`)
			_, _ = bw.Write(path)
			if k.ReadOnly {
				_, _ = bw.WriteString(`,"readonly":true}`)
			} else {
				_, _ = bw.WriteString(`,"readonly":false}`)
			}
		}
		_, _ = bw.WriteString("]}")
		_ = bw.Flush()
	})
}

// result is one element of a response's data array.
type result struct {
	Status  km.Status `json:"status"`
	Message string    `json:"message"`
}

func results(rs []km.Result) []result {
	out := make([]result, len(rs))
	for i, r := range rs {
		out[i] = result{Status: r.Status, Message: r.Message}
	}
	return out
}

// Import serves POST /qrl/v1/keystores.
func (h *Handlers) Import() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, e := server.ReadBody(r)
		if e != nil {
			server.WriteError(w, h.Log, r, e)
			return
		}
		defer mldsa87.Wipe(body)
		req, e := DecodeImport(body)
		defer wipeImport(&req)
		if e != nil {
			server.WriteError(w, h.Log, r, e)
			return
		}
		rs, err := h.Manager.Import(r.Context(), req)
		switch {
		case errors.Is(err, km.ErrInterchange):
			// err names the kind of refusal only, never a value of the body.
			h.Log.WithError(err).Warn("Keymanager import refused: its slashing_protection cannot be imported")
			server.WriteError(w, h.Log, r, apierr.New(apierr.BadField, "slashing_protection cannot be imported").
				In("slashing_protection"))
			return
		case errors.Is(err, km.ErrStore):
			h.Log.WithError(err).Error("Keymanager import failed: the slashing-protection store could not be read")
			server.WriteError(w, h.Log, r, apierr.New(apierr.StoreUnavailable, "slashing-protection store"))
			return
		case err != nil:
			server.WriteError(w, h.Log, r, apierr.New(apierr.InvariantViolation, "keystores and passwords"))
			return
		}
		writeJSON(w, h.Log, struct {
			Data []result `json:"data"`
		}{results(rs)})
	})
}

// Delete serves DELETE /qrl/v1/keystores.
func (h *Handlers) Delete() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, e := server.ReadBody(r)
		if e != nil {
			server.WriteError(w, h.Log, r, e)
			return
		}
		pubkeys, e := DecodeDelete(body)
		if e != nil {
			server.WriteError(w, h.Log, r, e)
			return
		}
		rs, export := h.Manager.Delete(r.Context(), pubkeys)
		writeJSON(w, h.Log, struct {
			Data               []result `json:"data"`
			SlashingProtection string   `json:"slashing_protection"`
		}{results(rs), string(export)})
	})
}

func writeJSON(w http.ResponseWriter, log logrus.FieldLogger, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		// Unreachable: the responses hold strings only.
		log.WithError(err).Error("Encoding a keymanager response failed")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", server.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// byteList is a JSON array of strings, each decoded into a buffer of its
// own. Decoding stops at the element after max, so that a body of millions
// of empty strings costs no more than max of them.
type byteList struct {
	items *[][]byte
	max   int
}

func (l byteList) UnmarshalJSON(b []byte) error {
	_, err := jsonutil.DecodeArray(b, func(i int, raw []byte) error {
		if i >= l.max {
			return apierr.New(apierr.InvariantViolation, "more than 64 keystores")
		}
		var v jsonutil.Bytes
		if err := v.UnmarshalJSON(raw); err != nil {
			return err
		}
		*l.items = append(*l.items, v)
		return nil
	})
	return err
}

func (byteList) MarshalJSON() ([]byte, error) { return nil, errors.New("keymanager: not encoded") }

// DecodeImport decodes a POST body: {keystores, passwords,
// slashing_protection?}, at most 64 keystores with as many passwords.
// Errors carry no request values.
func DecodeImport(body []byte) (km.ImportRequest, *apierr.Error) {
	var req km.ImportRequest
	if err := jsonutil.Validate(body); err != nil {
		return req, asAPIErr(err)
	}
	var sp jsonutil.Bytes
	err := jsonutil.DecodeObject(body,
		jsonutil.Field{Name: "keystores", Value: byteList{items: &req.Keystores, max: km.MaxKeystores}},
		jsonutil.Field{Name: "passwords", Value: byteList{items: &req.Passwords, max: km.MaxKeystores}},
		jsonutil.Field{Name: "slashing_protection", Value: &sp, Optional: true})
	req.SlashingProtection = sp
	if err != nil {
		return req, asAPIErr(err)
	}
	if len(req.Keystores) != len(req.Passwords) {
		return req, apierr.New(apierr.InvariantViolation, "keystores and passwords differ in length")
	}
	return req, nil
}

// wipeImport wipes the passwords and keystores a request holds.
func wipeImport(req *km.ImportRequest) {
	for _, l := range [][][]byte{req.Keystores, req.Passwords} {
		for _, b := range l {
			mldsa87.Wipe(b)
		}
	}
	mldsa87.Wipe(req.SlashingProtection)
}

// pubkeyList is a JSON array of 2,592-byte public keys.
type pubkeyList struct{ items *[]mldsa87.PublicKey }

func (l pubkeyList) UnmarshalJSON(b []byte) error {
	_, err := jsonutil.DecodeArray(b, func(_ int, raw []byte) error {
		var pk mldsa87.PublicKey
		if err := jsonutil.HexBytesN(pk[:]).UnmarshalJSON(raw); err != nil {
			return err
		}
		*l.items = append(*l.items, pk)
		return nil
	})
	return err
}

func (pubkeyList) MarshalJSON() ([]byte, error) { return nil, errors.New("keymanager: not encoded") }

// DecodeDelete decodes a DELETE body: {pubkeys}, each 0x and 5,184 hex
// characters.
func DecodeDelete(body []byte) ([]mldsa87.PublicKey, *apierr.Error) {
	if err := jsonutil.Validate(body); err != nil {
		return nil, asAPIErr(err)
	}
	var pubkeys []mldsa87.PublicKey
	if err := jsonutil.DecodeObject(body, jsonutil.Field{Name: "pubkeys", Value: pubkeyList{items: &pubkeys}}); err != nil {
		return nil, asAPIErr(err)
	}
	return pubkeys, nil
}

func asAPIErr(err error) *apierr.Error {
	var e *apierr.Error
	if errors.As(err, &e) {
		return e
	}
	return apierr.New(apierr.MalformedJSON, "body could not be decoded")
}
