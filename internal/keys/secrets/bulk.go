// Copyright 2020 ConsenSys AG.
// Copyright 2022 ConsenSys AG.
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
// keystorage/src/main/java/tech/pegasys/web3signer/keystorage/common/SecretValueMapperUtil.java,
// keystorage/src/main/java/tech/pegasys/web3signer/keystorage/common/MappedResults.java,
// signing/src/main/java/tech/pegasys/web3signer/signing/bulkloading/BlsAwsBulkLoader.java,
// signing/src/main/java/tech/pegasys/web3signer/signing/bulkloading/BlsGcpBulkLoader.java and
// core/src/main/java/tech/pegasys/web3signer/core/Eth2Runner.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package secrets

import (
	"context"
	"fmt"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/source"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
)

// BulkSuffix ends the source prefix of a bulk loader: aws-bulk:,
// azure-bulk:, gcp-bulk:.
const BulkSuffix = "-bulk:"

// Bulk is a bulk loader: every secret Store lists is one source, whose
// value holds one consensus seed per line.
//
// Unlike Web3Signer, which loads the good lines of a secret and counts the
// bad ones, a secret loads as a whole or fails: a secret with one bad line
// keeps the keys it had, as a failed key-config file does, so that a typo
// in one line never evicts the keys of the others.
type Bulk struct {
	// Kind is the store kind; it names the sources and the health check.
	Kind  string
	Store Lister
}

// Prefix starts the source name of every secret of b.
func (b Bulk) Prefix() string { return b.Kind + BulkSuffix }

// Source is the source name of the secret name.
func (b Bulk) Source(name string) string { return b.Prefix() + name }

// Load lists the store's secrets and loads each, on up to workers
// goroutines, into one batch per secret: its keys or the error that made it
// fail. Secrets not reached before ctx ends fail with ctx's error. Load
// fails as a whole only when the secrets cannot be listed; the caller then
// keeps every key the loader had.
func (b Bulk) Load(ctx context.Context, workers int, report func(done, total int)) (batches []provider.Batch,
	err error) {
	defer recoverInto(&err)
	names, err := b.Store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s bulk loading: list secrets: %w", b.Kind, err)
	}
	out := make([]provider.Batch, len(names))
	source.Each(ctx, len(names), workers, func(i int) {
		out[i] = b.load(ctx, names[i])
	}, report)
	return out, nil
}

// load loads one secret.
func (b Bulk) load(ctx context.Context, name string) (batch provider.Batch) {
	batch.Source = b.Source(name)
	defer func() {
		if batch.Err != nil {
			batch.Err = fmt.Errorf("%s: %w", batch.Source, batch.Err)
		}
	}()
	if err := ctx.Err(); err != nil {
		batch.Err = fmt.Errorf("not loaded: %w", err)
		return batch
	}
	var value []byte
	func() {
		defer recoverInto(&batch.Err)
		value, batch.Err = b.Store.Get(ctx, name)
	}()
	if batch.Err != nil {
		return batch
	}
	defer WipeAll([][]byte{value})
	if batch.Err = CheckSize(len(value)); batch.Err != nil {
		return batch
	}
	batch.Keys, batch.Err = Keys(value, false)
	return batch
}
