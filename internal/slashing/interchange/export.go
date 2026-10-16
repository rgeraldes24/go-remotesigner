// Copyright 2020 ConsenSys AG.
// Copyright 2022 ConsenSys AG.
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
// slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/InterchangeV5Exporter.java
// and slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/interchange/EmptyDataIncrementalInterchangeV5Exporter.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package interchange

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"

	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// ExportOptions configure Export.
type ExportOptions struct {
	// Keys, when not nil, limits the export to these validators.
	Keys []slashing.KeyID
	// GenesisValidatorsRoot is the network's root, when known. It is written when the store has no root pinned yet
	// (a store that never signed nor imported), so that every export names its network; a store pinned to another
	// root is refused.
	GenesisValidatorsRoot *slashing.Root
}

// ExportResult counts what an export wrote.
type ExportResult struct {
	Validators   int
	Blocks       int
	Attestations int
	// Watermarks counts the records, included in Blocks and Attestations, that stand for a low watermark no stored
	// record sits at (as after a watermark repair). They have no signing root.
	Watermarks int
	// Missing are the requested keys that the store has no history for: unknown keys, and keys without a low
	// watermark.
	Missing []slashing.KeyID
}

// Export writes the store's history to w as an interchange file, from one consistent snapshot.
//
// The metadata always carries a genesis validators root: the store's, or opts.GenesisValidatorsRoot for a store
// that has none; with neither, Export fails with slashing.ErrNoGenesisValidatorsRoot before writing anything.
// Validators are written in KeyID order. A validator without a low watermark has no history and is left out.
//
// The file carries what an importing signer needs to refuse what this one refuses. Blocks are written from the slot
// watermark up, and attestations from the target watermark up whatever their source epoch: an attestation with a
// source below the source watermark still rules out a double vote at its target. Records below the watermarks are
// left out, since an importer takes its watermarks from the oldest records it imports. A watermark that no stored
// record sits at, as after a watermark repair, is written as a record of its own without a signing root (the slot
// watermark as a block, the two epoch watermarks as an attestation), so that the importer refuses everything at and
// below it, as this signer does. The high watermark is not exported; the format has no field for it.
func Export(ctx context.Context, s slashing.Store, w io.Writer, opts ExportOptions) (ExportResult, error) {
	var res ExportResult
	var want map[slashing.KeyID]bool
	if opts.Keys != nil {
		want = make(map[slashing.KeyID]bool, len(opts.Keys))
		for _, k := range opts.Keys {
			want[k] = true
		}
	}
	err := s.ViewHistory(ctx, func(v slashing.HistoryView) error {
		gvr, err := exportRoot(v, opts.GenesisValidatorsRoot)
		if err != nil {
			return err
		}
		out := &writer{w: bufio.NewWriterSize(w, 1<<16)}
		out.str("{\n  \"metadata\": {\n    \"interchange_format_version\": \"" + FormatVersion + "\",\n" +
			"    \"genesis_validators_root\": \"").hex(gvr[:]).str("\"\n  },\n  \"data\": [")
		found := map[slashing.KeyID]bool{}
		err = v.Validators(func(id slashing.KeyID, pk []byte) error {
			if want != nil && !want[id] {
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			low, err := v.LowWatermark(id)
			if err != nil {
				return err
			}
			if low.Slot == nil && low.SourceEpoch == nil {
				return nil
			}
			found[id] = true
			if res.Validators > 0 {
				out.str(",")
			}
			res.Validators++
			out.str("\n    {\n      \"pubkey\": \"").hex(pk).str("\",\n      \"signed_blocks\": [")
			n := 0
			if low.Slot != nil {
				// pending: no record at or above the watermark has been written yet.
				at, pending := *low.Slot, true
				err = v.Blocks(id, func(b slashing.SignedBlock) error {
					if b.Slot < at {
						return out.err
					}
					if pending && b.Slot != at {
						n = out.block(n, at, nil)
						res.Watermarks++
					}
					pending = false
					n = out.block(n, b.Slot, b.SigningRoot)
					return out.err
				})
				if err != nil {
					return err
				}
				if pending {
					n = out.block(n, at, nil)
					res.Watermarks++
				}
			}
			res.Blocks += n
			out.end(n).str(",\n      \"signed_attestations\": [")
			n = 0
			if low.SourceEpoch != nil {
				at, pending := *low.TargetEpoch, true
				err = v.Attestations(id, func(a slashing.SignedAttestation) error {
					if a.TargetEpoch < at {
						return out.err
					}
					if pending && a.TargetEpoch != at {
						n = out.attestation(n, *low.SourceEpoch, at, nil)
						res.Watermarks++
					}
					pending = false
					n = out.attestation(n, a.SourceEpoch, a.TargetEpoch, a.SigningRoot)
					return out.err
				})
				if err != nil {
					return err
				}
				if pending {
					n = out.attestation(n, *low.SourceEpoch, at, nil)
					res.Watermarks++
				}
			}
			res.Attestations += n
			out.end(n).str("\n    }")
			return out.err
		})
		if err != nil {
			return err
		}
		if res.Validators > 0 {
			out.str("\n  ")
		}
		out.str("]\n}\n")
		for _, k := range opts.Keys {
			if !found[k] {
				res.Missing = append(res.Missing, k)
			}
		}
		if out.err != nil {
			return out.err
		}
		return out.w.Flush()
	})
	if err != nil {
		return ExportResult{}, err
	}
	return res, nil
}

// exportRoot is the root an export names: the store's, or the configured one for a store that has none.
func exportRoot(v slashing.HistoryView, configured *slashing.Root) (slashing.Root, error) {
	pinned, ok, err := v.GenesisValidatorsRoot()
	switch {
	case err != nil:
		return slashing.Root{}, err
	case ok && configured != nil && *configured != pinned:
		return slashing.Root{}, fmt.Errorf("%w: configured %#x, store pinned to %#x",
			slashing.ErrGenesisValidatorsRootMismatch, configured[:], pinned[:])
	case ok:
		return pinned, nil
	case configured != nil:
		return *configured, nil
	}
	return slashing.Root{}, fmt.Errorf("%w: the store is not bound to a network; name one to export from it",
		slashing.ErrNoGenesisValidatorsRoot)
}

// writer writes the export layout: one record per line. The first write error sticks.
type writer struct {
	w   *bufio.Writer
	err error
	buf []byte
}

func (o *writer) str(s string) *writer {
	if o.err == nil {
		_, o.err = o.w.WriteString(s)
	}
	return o
}

func (o *writer) hex(b []byte) *writer {
	o.buf = append(append(o.buf[:0], "0x"...), make([]byte, hex.EncodedLen(len(b)))...)
	hex.Encode(o.buf[2:], b)
	if o.err == nil {
		_, o.err = o.w.Write(o.buf)
	}
	return o
}

func (o *writer) u64(v uint64) *writer {
	o.buf = strconv.AppendUint(o.buf[:0], v, 10)
	if o.err == nil {
		_, o.err = o.w.Write(o.buf)
	}
	return o
}

// root closes the quoted number before it and writes the optional signing root, which is left out when unknown.
func (o *writer) root(r *slashing.Root) *writer {
	if r == nil {
		return o.str(`"`)
	}
	return o.str(`", "signing_root": "`).hex(r[:]).str(`"`)
}

// block writes the n-th element of signed_blocks and returns n+1.
func (o *writer) block(n int, slot uint64, r *slashing.Root) int {
	o.item(n).str(`{"slot": "`).u64(slot).root(r).str("}")
	return n + 1
}

// attestation writes the n-th element of signed_attestations and returns n+1.
func (o *writer) attestation(n int, source, target uint64, r *slashing.Root) int {
	o.item(n).str(`{"source_epoch": "`).u64(source).str(`", "target_epoch": "`).u64(target).root(r).str("}")
	return n + 1
}

// item starts the n-th element of a record array.
func (o *writer) item(n int) *writer {
	if n > 0 {
		o.str(",")
	}
	return o.str("\n        ")
}

// end closes a record array of n elements.
func (o *writer) end(n int) *writer {
	if n > 0 {
		o.str("\n      ")
	}
	return o.str("]")
}
