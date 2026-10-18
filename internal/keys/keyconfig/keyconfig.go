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
// signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/parser/YamlSignerParser.java,
// signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/FileRawSigningMetadata.java,
// signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/FileKeyStoreMetadata.java and
// signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/AbstractArtifactSignerFactory.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

// Package keyconfig loads key-config files (--key-config-path, alias
// --key-store-path): every non-hidden *.yaml or *.yml file directly in the
// directory, each holding one or more YAML documents of these types:
//
//   - `type: file-raw`: `privateKey` is the validator's 48-byte wallet seed
//     (0x + 96 hex characters);
//   - `type: file-keystore`: `keystoreFile` and `keystorePasswordFile` name
//     a keystore and its password file, relative to the key-config
//     directory unless absolute;
//   - `type: hashicorp`, `aws-secret`, `azure-secret` and `gcp-secret`:
//     the seed is the value of one secret in HashiCorp Vault (KV version
//     2), AWS Secrets Manager, Azure Key Vault or GCP Secret Manager, with
//     Web3Signer's fields (remote.go), fetched through Config.Secrets.
//
// In execution mode (Config.Execution) the same files hold account keys:
// `privateKey` is the account's 51-byte extended seed (102 hex characters,
// with or without 0x, descriptor 01 00 00 first) and `keystoreFile` a
// go-qrl account keystore. Each mode refuses the other's keys, so one file
// cannot serve both a validator and an account.
//
// `keyType` is ML_DSA_87, the default and only value. Unknown keys are
// rejected. Each file is one source: either every document in it loads or
// the file fails as a whole, keeping the keys it had, and the others still
// load. A file is read again on every load, but its keys are derived again
// only when it, or a keystore or password file it names, has changed: as
// in Web3Signer, the secrets of an unchanged file are not fetched again.
//
// A file with a file-raw document holds seeds in the clear, and one whose
// documents carry a store credential (a Vault token, an AWS secret access
// key, an Azure client secret) holds credentials, so both are secret
// files, as is every keystore password file: the caller's
// secretfile.Policy decides what happens when its group or other users can
// read it. Error messages never contain key material or credentials.
package keyconfig

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystore/qrlv1"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystores"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/source"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
)

// Supported values.
const (
	TypeFileRaw      = "file-raw"
	TypeFileKeystore = "file-keystore"
	TypeHashicorp    = "hashicorp"
	TypeAWSSecret    = "aws-secret"
	TypeAzureSecret  = "azure-secret"
	TypeGCPSecret    = "gcp-secret"
	KeyTypeMLDSA87   = "ML_DSA_87"
)

// SourcePrefix starts the source name of every key-config file.
const SourcePrefix = "key-config:"

// DefaultMaxFileSize bounds a key-config file when Config.MaxFileSize is 0:
// 100 MiB, the default of --key-store-config-file-max-size.
const DefaultMaxFileSize = 100 << 20

// Errors returned for a file. Callers match them with errors.Is.
var (
	ErrFormat      = errors.New("keyconfig: invalid key-config file")
	ErrUnsupported = errors.New("keyconfig: unsupported key configuration")
	ErrPrivateKey  = errors.New("keyconfig: invalid privateKey")
)

// Config is a key-config source.
type Config struct {
	Dir string
	// Policy is applied to files with a file-raw document and to keystore
	// password files.
	Policy secretfile.Policy
	// Decrypt opens file-keystore keystores; nil refuses them.
	Decrypt keystores.DecryptFunc
	// Secrets fetches the seeds of the secret-store types; nil refuses
	// them.
	Secrets secrets.Fetcher
	// MaxFileSize is the largest key-config file loaded, in bytes
	// (--key-store-config-file-max-size); 0 means DefaultMaxFileSize. A
	// larger file fails to load, before any of it is read.
	MaxFileSize int64
	// Execution loads account keys: 51-byte extended seeds and go-qrl
	// account keystores. Otherwise the keys are validator keys: 48-byte
	// seeds and validator keystores.
	Execution bool
}

// Source is the source name of the key-config file at path.
func Source(path string) string { return SourcePrefix + path }

// Load loads every key-config file in c.Dir, in name order, on up to
// workers goroutines, and returns one batch per file: Keep when unchanged
// reports its version (nil keeps nothing), else its keys or the error that
// made the file fail. Files not reached before ctx ends fail with ctx's
// error. Load fails as a whole only when the directory cannot be listed.
func (c Config) Load(ctx context.Context, workers int, unchanged source.Unchanged,
	report func(done, total int)) ([]provider.Batch, error) {
	start := time.Now()
	paths, err := configFiles(c.Dir)
	if err != nil {
		return nil, err
	}
	out := make([]provider.Batch, len(paths))
	source.Each(ctx, len(paths), workers, func(i int) {
		out[i] = c.load(ctx, start, paths[i], unchanged)
	}, report)
	return out, nil
}

// configFiles lists the non-hidden *.yaml and *.yml regular files directly in
// dir, sorted. An entry that cannot be stat'ed (a dangling symlink, a secret
// mount being swapped) is listed too, so that loading it fails and its
// source keeps its previous keys: a load error is never a removal. Only
// entries that stat as something other than a regular file are skipped.
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
		if fi, err := os.Stat(p); err == nil && !fi.Mode().IsRegular() { // Stat follows symlinks
			continue
		}
		out = append(out, p)
	}
	slices.Sort(out)
	return out, nil
}

// load loads one key-config file.
func (c Config) load(ctx context.Context, start time.Time, path string, unchanged source.Unchanged) provider.Batch {
	b := provider.Batch{Source: Source(path)}
	keys, metas, version, err := c.loadFile(ctx, start, path, func(version string) bool {
		return unchanged != nil && unchanged(b.Source, version)
	})
	if err != nil {
		b.Err = fmt.Errorf("%s: %w", path, err)
		return b
	}
	b.Version = version
	b.Keys, b.Meta = keys, metas
	b.Keep = keys == nil
	return b
}

// LoadFile loads the key-config file at path and builds its keys. Either
// every document loads or the file fails as a whole.
func (c Config) LoadFile(ctx context.Context, path string) ([]*mldsa87.Key, error) {
	keys, _, _, err := c.loadFile(ctx, time.Now(), path, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return keys, nil
}

// loadFile reads, checks and parses the file at path, and returns its keys
// with their metadata. It returns no keys and no error when keep reports
// true for the file's version.
func (c Config) loadFile(ctx context.Context, start time.Time, path string, keep func(version string) bool) (
	[]*mldsa87.Key, []provider.Meta, string, error) {
	limit := c.MaxFileSize
	if limit <= 0 {
		limit = DefaultMaxFileSize
	}
	data, fi, err := secretfile.ReadInfo(path, limit)
	if err != nil {
		return nil, nil, "", err
	}
	docs, err := parse(data, c.Dir, c.Execution)
	mldsa87.Wipe(data)
	if err != nil {
		return nil, nil, "", err
	}
	defer wipeDocs(docs)
	keyFiles, passwords := []fs.FileInfo{fi}, []fs.FileInfo(nil)
	for _, d := range docs {
		if d.raw() || d.credential {
			if err := c.Policy.Check(path, fi); err != nil {
				return nil, nil, "", err
			}
			break
		}
	}
	for _, d := range docs {
		if d.raw() || d.remote != nil {
			continue
		}
		ksInfo, err := os.Stat(d.keystoreFile)
		if err != nil {
			return nil, nil, "", fmt.Errorf("keystoreFile: %w", err)
		}
		pwInfo, err := os.Stat(d.passwordFile)
		if err == nil {
			err = c.Policy.Check(d.passwordFile, pwInfo)
		}
		if err != nil {
			return nil, nil, "", fmt.Errorf("keystorePasswordFile: %w", err)
		}
		keyFiles, passwords = append(keyFiles, ksInfo), append(passwords, pwInfo)
	}
	version := source.Version(start, keyFiles, passwords...)
	if keep != nil && keep(version) {
		return nil, nil, version, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, "", fmt.Errorf("not loaded: %w", err)
	}
	keys := make([]*mldsa87.Key, 0, len(docs))
	metas := make([]provider.Meta, 0, len(docs))
	for _, d := range docs {
		k, meta, err := c.build(ctx, d)
		if err != nil {
			zeroize(keys)
			return nil, nil, "", fmt.Errorf("document %d: %w", d.index, err)
		}
		keys, metas = append(keys, k), append(metas, meta)
	}
	return keys, metas, version, nil
}

// build derives the key of one document.
func (c Config) build(ctx context.Context, d document) (*mldsa87.Key, provider.Meta, error) {
	if d.seed != nil {
		k, err := mldsa87.FromSeed48(d.seed)
		if err != nil {
			return nil, provider.Meta{}, fmt.Errorf("%w: %v", ErrPrivateKey, err)
		}
		return k, provider.Meta{}, nil
	}
	if d.ext != nil {
		k, err := mldsa87.FromExtendedSeed51(d.ext)
		if err != nil {
			return nil, provider.Meta{}, fmt.Errorf("%w: %v", ErrPrivateKey, err)
		}
		return k, provider.Meta{}, nil
	}
	if d.remote != nil {
		k, err := c.fetch(ctx, d.remote)
		return k, provider.Meta{}, err
	}
	if c.Decrypt == nil {
		return nil, provider.Meta{}, fmt.Errorf("%w: type %s is not supported here", ErrUnsupported, TypeFileKeystore)
	}
	data, err := secretfile.ReadCapped(d.keystoreFile, qrlv1.MaxSize)
	if err != nil {
		return nil, provider.Meta{}, fmt.Errorf("keystoreFile: %w", err)
	}
	parseKeystore := qrlv1.Parse
	if c.Execution {
		parseKeystore = qrlv1.ParseAccount
	}
	ks, err := parseKeystore(data)
	if err != nil {
		return nil, provider.Meta{}, fmt.Errorf("keystoreFile %s: %w", d.keystoreFile, err)
	}
	pwData, err := secretfile.Read(d.passwordFile, keystores.MaxPasswordFile, c.Policy)
	if err != nil {
		return nil, provider.Meta{}, fmt.Errorf("keystorePasswordFile: %w", err)
	}
	pw := qrlv1.NewPassword(qrlv1.TrimPassword(pwData))
	mldsa87.Wipe(pwData)
	defer pw.Wipe()
	k, err := c.Decrypt(ctx, ks, pw)
	if err != nil {
		return nil, provider.Meta{}, fmt.Errorf("keystoreFile %s: %w", d.keystoreFile, err)
	}
	return k, provider.Meta{DerivationPath: ks.Path, Keystore: true}, nil
}

// document is one parsed key document: a file-raw seed (a validator's
// seed, or in execution mode an account's extended seed), the absolute
// paths of a file-keystore's keystore and password file, or the secret of
// a secret-store type.
type document struct {
	index                      int // 1-based, among all documents of the file
	seed                       *[mldsa87.SeedSize]byte
	ext                        *[mldsa87.ExtendedSeedSize]byte
	keystoreFile, passwordFile string
	remote                     secrets.Spec
	// credential: the document holds a store credential.
	credential bool
}

// raw reports whether the document is a file-raw seed.
func (d document) raw() bool { return d.seed != nil || d.ext != nil }

func wipeDocs(docs []document) {
	for _, d := range docs {
		if d.seed != nil {
			mldsa87.Wipe(d.seed[:])
		}
		if d.ext != nil {
			mldsa87.Wipe(d.ext[:])
		}
	}
}

// parse reads the documents of a key-config file's content; relative
// keystore paths are resolved against dir.
func parse(data []byte, dir string, execution bool) ([]document, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docs []document
	for i := 1; ; i++ {
		var n yaml.Node
		err := dec.Decode(&n)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			wipeDocs(docs)
			return nil, fmt.Errorf("%w: not valid YAML", ErrFormat)
		}
		if len(n.Content) == 0 || n.Content[0].ShortTag() == "!!null" {
			continue // an empty document
		}
		d, err := parseDocument(n.Content[0], dir, execution)
		if err != nil {
			wipeDocs(docs)
			return nil, fmt.Errorf("document %d: %w", i, err)
		}
		d.index = i
		docs = append(docs, d)
	}
	if len(docs) == 0 {
		return nil, fmt.Errorf("%w: no key documents", ErrFormat)
	}
	return docs, nil
}

// Allowed keys per type.
var allowed = map[string][]string{
	TypeFileRaw:      {"type", "keyType", "privateKey"},
	TypeFileKeystore: {"type", "keyType", "keystoreFile", "keystorePasswordFile"},
	TypeHashicorp: {"type", "keyType", "serverHost", "serverPort", "keyPath", "keyName", "token", "timeout",
		"tlsEnabled", "tlsKnownServersPath", "httpProtocolVersion", "authMethod", "kubernetesRole",
		"kubernetesServiceAccountTokenPath", "kubernetesAuthPath"},
	TypeAWSSecret: {"type", "keyType", "authenticationMode", "region", "secretName", "accessKeyId",
		"secretAccessKey", "endpointOverride"},
	TypeAzureSecret: {"type", "keyType", "authenticationMode", "vaultName", "secretName", "clientId",
		"clientSecret", "tenantId", "timeout", "endpointOverride", "authorityHostOverride",
		"trustCertificateOverride"},
	TypeGCPSecret: {"type", "keyType", "projectId", "secretName", "endpointOverride"},
}

// parseDocument reads one mapping.
func parseDocument(n *yaml.Node, dir string, execution bool) (document, error) {
	if n.Kind != yaml.MappingNode {
		return document{}, fmt.Errorf("%w: a document must be a mapping", ErrFormat)
	}
	fields := map[string]*yaml.Node{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Kind != yaml.ScalarNode || v.Kind != yaml.ScalarNode {
			return document{}, fmt.Errorf("%w: keys and values must be scalars", ErrFormat)
		}
		if _, dup := fields[k.Value]; dup {
			return document{}, fmt.Errorf("%w: duplicate key %q", ErrFormat, k.Value)
		}
		fields[k.Value] = v
	}

	typ := ""
	if v, ok := fields["type"]; ok {
		typ = v.Value
	}
	switch typ {
	case TypeFileRaw, TypeFileKeystore, TypeHashicorp, TypeAWSSecret, TypeAzureSecret, TypeGCPSecret:
	case "":
		return document{}, fmt.Errorf("%w: missing type", ErrFormat)
	default:
		return document{}, fmt.Errorf("%w: unknown type %q", ErrUnsupported, truncate(typ))
	}
	for k := range fields {
		if !slices.Contains(allowed[typ], k) {
			return document{}, fmt.Errorf("%w: unknown key %q for type %s", ErrFormat, truncate(k), typ)
		}
	}
	if v, ok := fields["keyType"]; ok {
		switch v.Value {
		case KeyTypeMLDSA87:
		case "BLS":
			return document{}, fmt.Errorf("%w: keyType BLS: QRL validators sign with ML-DSA-87; "+
				"configure the validator's 48-byte ML-DSA-87 wallet seed with keyType %s", ErrUnsupported, KeyTypeMLDSA87)
		default:
			return document{}, fmt.Errorf("%w: unknown keyType %q (want %s)", ErrUnsupported, truncate(v.Value), KeyTypeMLDSA87)
		}
	}
	if typ != TypeFileRaw && typ != TypeFileKeystore {
		return parseRemote(typ, fields, dir)
	}
	if typ == TypeFileKeystore {
		var d document
		for _, f := range []struct {
			key string
			dst *string
		}{{"keystoreFile", &d.keystoreFile}, {"keystorePasswordFile", &d.passwordFile}} {
			v, ok := fields[f.key]
			if !ok || v.Value == "" {
				return document{}, fmt.Errorf("%w: missing %s", ErrFormat, f.key)
			}
			*f.dst = v.Value
			if !filepath.IsAbs(v.Value) {
				*f.dst = filepath.Join(dir, v.Value)
			}
		}
		return d, nil
	}
	v, ok := fields["privateKey"]
	if !ok {
		return document{}, fmt.Errorf("%w: missing privateKey", ErrFormat)
	}
	if execution {
		ext, err := extendedSeedFromHex(v.Value)
		if err != nil {
			return document{}, err
		}
		return document{ext: ext}, nil
	}
	seed, err := seedFromHex(v.Value)
	if err != nil {
		return document{}, err
	}
	return document{seed: seed}, nil
}

// seedFromHex decodes a 48-byte seed by the rules of secrets.ParseSeed:
// other common lengths get a hint about what they are.
func seedFromHex(s string) (*[mldsa87.SeedSize]byte, error) {
	hb := []byte(s)
	defer mldsa87.Wipe(hb)
	seed, err := secrets.ConsensusSeed(hb)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPrivateKey, strings.TrimPrefix(err.Error(), secrets.ErrSeed.Error()+": "))
	}
	return seed, nil
}

// extendedSeedFromHex decodes an account's 51-byte extended seed, with or
// without 0x (go-qrl's seed files have none). A validator's 48-byte seed is
// refused with a hint.
func extendedSeedFromHex(s string) (*[mldsa87.ExtendedSeedSize]byte, error) {
	h := strings.TrimPrefix(s, "0x")
	switch len(h) {
	case 2 * mldsa87.ExtendedSeedSize:
	case 2 * mldsa87.SeedSize:
		return nil, fmt.Errorf("%w: a 48-byte seed is a consensus validator key; execution mode takes the "+
			"account's 51-byte extended seed (descriptor 010000, then the seed)", ErrPrivateKey)
	default:
		return nil, fmt.Errorf("%w: want a 51-byte extended seed, 102 hex characters (0x optional)", ErrPrivateKey)
	}
	ext := new([mldsa87.ExtendedSeedSize]byte)
	hb := []byte(h)
	defer mldsa87.Wipe(hb)
	if _, err := hex.Decode(ext[:], hb); err != nil {
		mldsa87.Wipe(ext[:])
		return nil, fmt.Errorf("%w: not hex", ErrPrivateKey)
	}
	return ext, nil
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
