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
// signing/src/main/java/tech/pegasys/web3signer/signing/config/SignerLoader.java,
// signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/parser/YamlSignerParser.java and
// signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/FileRawSigningMetadata.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

// Package keyconfig loads key-config files (--key-config-path, alias
// --key-store-path): every non-hidden *.yaml or *.yml file directly in the
// directory, each holding one or more YAML documents.
//
// This build supports `type: file-raw` documents: `privateKey` is the
// validator's 48-byte wallet seed (0x + 96 hex characters) and `keyType` is
// ML_DSA_87, the default and only value. Unknown keys are rejected. A file
// that fails to load is reported on its own and does not stop the others.
// Error messages never contain key material.
package keyconfig

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
)

// Supported values.
const (
	TypeFileRaw      = "file-raw"
	TypeFileKeystore = "file-keystore"
	KeyTypeMLDSA87   = "ML_DSA_87"
)

// Errors returned for a file. Callers match them with errors.Is.
var (
	ErrFormat      = errors.New("keyconfig: invalid key-config file")
	ErrUnsupported = errors.New("keyconfig: unsupported key configuration")
	ErrPrivateKey  = errors.New("keyconfig: invalid privateKey")
)

// FileResult is the outcome of loading one file: its keys, or the error that
// made the whole file fail.
type FileResult struct {
	Path string
	Keys []*mldsa87.Key
	Err  error
}

// Load reads every key-config file in dir, in name order. It fails only when
// dir cannot be listed; per-file failures are in the results. It stops
// early, returning ctx's error, when ctx ends.
func Load(ctx context.Context, dir string) ([]FileResult, error) {
	paths, err := configFiles(dir)
	if err != nil {
		return nil, err
	}
	out := make([]FileResult, 0, len(paths))
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			for _, r := range out {
				zeroize(r.Keys)
			}
			return nil, err
		}
		keys, err := LoadFile(p)
		out = append(out, FileResult{Path: p, Keys: keys, Err: err})
	}
	return out, nil
}

// configFiles lists the non-hidden *.yaml and *.yml regular files directly in
// dir, sorted.
func configFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("keyconfig: read key-config directory: %w", err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if strings.HasPrefix(name, ".") || (ext != ".yaml" && ext != ".yml") {
			continue
		}
		p := filepath.Join(dir, name)
		fi, err := os.Stat(p) // follows symlinks
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		out = append(out, p)
	}
	slices.Sort(out)
	return out, nil
}

// LoadFile parses the key-config file at path and builds its keys. Either
// every document loads or the file fails as a whole.
func LoadFile(path string) ([]*mldsa87.Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	keys, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return keys, nil
}

// Parse builds the keys of a key-config file's content.
func Parse(data []byte) ([]*mldsa87.Key, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var keys []*mldsa87.Key
	for i := 0; ; i++ {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			zeroize(keys)
			return nil, fmt.Errorf("%w: not valid YAML", ErrFormat)
		}
		if len(doc.Content) == 0 || doc.Content[0].ShortTag() == "!!null" {
			continue // an empty document
		}
		k, err := parseDocument(doc.Content[0])
		if err != nil {
			zeroize(keys)
			return nil, fmt.Errorf("document %d: %w", i+1, err)
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: no key documents", ErrFormat)
	}
	return keys, nil
}

// parseDocument reads one `type: file-raw` mapping.
func parseDocument(n *yaml.Node) (*mldsa87.Key, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w: a document must be a mapping", ErrFormat)
	}
	fields := map[string]*yaml.Node{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode || v.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("%w: keys and values must be scalars", ErrFormat)
		}
		if _, dup := fields[k.Value]; dup {
			return nil, fmt.Errorf("%w: duplicate key %q", ErrFormat, k.Value)
		}
		fields[k.Value] = v
	}

	typ := ""
	if v, ok := fields["type"]; ok {
		typ = v.Value
	}
	switch typ {
	case TypeFileRaw:
	case TypeFileKeystore:
		return nil, fmt.Errorf("%w: type %s is not supported by this build; use file-raw", ErrUnsupported, typ)
	case "":
		return nil, fmt.Errorf("%w: missing type", ErrFormat)
	default:
		return nil, fmt.Errorf("%w: unknown type %q", ErrUnsupported, truncate(typ))
	}
	for k := range fields {
		switch k {
		case "type", "keyType", "privateKey":
		default:
			return nil, fmt.Errorf("%w: unknown key %q for type %s", ErrFormat, truncate(k), TypeFileRaw)
		}
	}
	if v, ok := fields["keyType"]; ok {
		switch v.Value {
		case KeyTypeMLDSA87:
		case "BLS":
			return nil, fmt.Errorf("%w: keyType BLS: QRL validators sign with ML-DSA-87; "+
				"configure the validator's 48-byte ML-DSA-87 wallet seed with keyType %s", ErrUnsupported, KeyTypeMLDSA87)
		default:
			return nil, fmt.Errorf("%w: unknown keyType %q (want %s)", ErrUnsupported, truncate(v.Value), KeyTypeMLDSA87)
		}
	}
	v, ok := fields["privateKey"]
	if !ok {
		return nil, fmt.Errorf("%w: missing privateKey", ErrFormat)
	}
	return keyFromSeedHex(v.Value)
}

// keyFromSeedHex decodes a 48-byte seed and derives its key. Other common
// lengths get a hint about what they are.
func keyFromSeedHex(s string) (*mldsa87.Key, error) {
	h := strings.TrimPrefix(s, "0x")
	switch len(h) {
	case 2 * mldsa87.SeedSize:
	case 64:
		return nil, fmt.Errorf("%w: 32 bytes; a QRL consensus key is the validator's 48-byte wallet seed", ErrPrivateKey)
	case 102:
		return nil, fmt.Errorf("%w: a 51-byte extended seed belongs to execution mode; "+
			"consensus keys are the 48-byte wallet seed", ErrPrivateKey)
	case 2 * 4896:
		return nil, fmt.Errorf("%w: a 4,896-byte ML-DSA-87 secret key is not accepted; "+
			"configure the 48-byte wallet seed it was derived from", ErrPrivateKey)
	default:
		return nil, fmt.Errorf("%w: want a 48-byte seed, 0x + 96 hex characters", ErrPrivateKey)
	}
	var seed [mldsa87.SeedSize]byte
	defer mldsa87.Wipe(seed[:])
	if _, err := hex.Decode(seed[:], []byte(h)); err != nil {
		return nil, fmt.Errorf("%w: not hex", ErrPrivateKey)
	}
	k, err := mldsa87.FromSeed48(&seed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPrivateKey, err)
	}
	return k, nil
}

func zeroize(keys []*mldsa87.Key) {
	for _, k := range keys {
		k.Zeroize()
	}
}

// truncate bounds an untrusted string quoted in an error.
func truncate(s string) string {
	if len(s) > 32 {
		return s[:32] + "…"
	}
	return s
}
