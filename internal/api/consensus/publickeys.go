// Copyright 2020 ConsenSys AG.
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
// core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/PublicKeysListHandler.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package consensus

import (
	"bufio"
	"compress/gzip"
	"encoding/hex"
	"io"
	"iter"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// PublicKeysWriteTimeout is the write deadline of GET publicKeys: 4,096 keys
// are about 21 MB.
const PublicKeysWriteTimeout = 120 * time.Second

// PublicKeys serves GET /api/v1/consensus/publicKeys: a JSON array of the
// canonical identifiers of the loaded keys, in sorted order. It is streamed
// key by key, never rendered whole, and gzip-encoded when the client accepts
// gzip.
func PublicKeys(keys func() iter.Seq[*mldsa87.PublicKey]) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "application/json; charset=utf-8")
		h.Add("Vary", "Accept-Encoding")
		gzipped := acceptsGzip(r.Header.Get("Accept-Encoding"))
		if gzipped {
			h.Set("Content-Encoding", "gzip")
		}
		if r.Method == http.MethodHead {
			return
		}
		var out io.Writer = w
		if gzipped {
			// Hex keys compress about 2:1 at any level; BestSpeed keeps
			// 10,000 keys well inside the B15 bound.
			gz, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
			defer func() { _ = gz.Close() }()
			out = gz
		}
		bw := bufio.NewWriterSize(out, 64<<10)
		defer func() { _ = bw.Flush() }()
		_ = writeKeys(bw, keys())
	})
}

// writeKeys writes the JSON array, stopping at the first write error (the
// client went away).
func writeKeys(w *bufio.Writer, keys iter.Seq[*mldsa87.PublicKey]) error {
	var item [1 + CanonicalIdentifierLength + 2]byte // ,"0x…"
	if err := w.WriteByte('['); err != nil {
		return err
	}
	first := true
	for pk := range keys {
		item[0] = ','
		copy(item[1:], `"0x`)
		hex.Encode(item[4:], pk[:])
		item[len(item)-1] = '"'
		b := item[:]
		if first {
			b, first = b[1:], false
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	return w.WriteByte(']')
}

// acceptsGzip reports whether an Accept-Encoding value lists gzip with a
// non-zero quality.
func acceptsGzip(header string) bool {
	for part := range strings.SplitSeq(header, ",") {
		coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(coding), "gzip") {
			continue
		}
		q, ok := strings.CutPrefix(strings.TrimSpace(params), "q=")
		if !ok {
			return true
		}
		v, err := strconv.ParseFloat(q, 64)
		return err == nil && v > 0
	}
	return false
}
