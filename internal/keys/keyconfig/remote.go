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
// signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/HashicorpSigningMetadata.java,
// signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/AwsKeySigningMetadataDeserializer.java,
// signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/AzureSecretSigningMetadataDeserializer.java
// and signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/AbstractArtifactSignerFactory.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package keyconfig

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/logging"
)

// maxTimeoutMillis bounds a timeout field, a day.
const maxTimeoutMillis = 24 * 60 * 60 * 1000

// fieldReader reads the scalar fields of one document, collecting the
// required ones that are missing and the first invalid one.
type fieldReader struct {
	fields  map[string]*yaml.Node
	dir     string
	missing []string
	err     error
}

func (r *fieldReader) str(key string) string {
	if v, ok := r.fields[key]; ok {
		return v.Value
	}
	return ""
}

func (r *fieldReader) required(key string) string {
	v := r.str(key)
	if v == "" {
		r.missing = append(r.missing, key)
	}
	return v
}

func (r *fieldReader) fail(key, want string) {
	if r.err == nil {
		r.err = fmt.Errorf("%w: %s: want %s", ErrFormat, key, want)
	}
}

// enum reads key as one of allowed, ignoring case; def when absent.
func (r *fieldReader) enum(key, def string, allowed ...string) string {
	v, ok := r.fields[key]
	if !ok {
		return def
	}
	e, err := secrets.ParseEnum(v.Value, allowed...)
	if err != nil {
		r.fail(key, "one of "+strings.Join(allowed, ", "))
	}
	return e
}

// number reads a positive integer of at most max; def when absent.
func (r *fieldReader) number(key string, def, max int) int {
	v, ok := r.fields[key]
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v.Value)
	if err != nil || n < 1 || n > max {
		r.fail(key, fmt.Sprintf("a whole number from 1 to %d", max))
	}
	return n
}

func (r *fieldReader) boolean(key string) bool {
	v, ok := r.fields[key]
	if !ok {
		return false
	}
	switch strings.ToLower(v.Value) {
	case "true":
		return true
	case "false":
		return false
	}
	r.fail(key, "true or false")
	return false
}

// path reads a file path, relative to the key-config directory unless
// absolute; def when absent.
func (r *fieldReader) path(key, def string) string {
	p := r.str(key)
	if p == "" {
		return def
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(r.dir, p)
	}
	return p
}

// endpoint reads an http or https URL.
func (r *fieldReader) endpoint(key string) string {
	v := r.str(key)
	if v == "" {
		return ""
	}
	if u, err := url.Parse(v); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		r.fail(key, "an http:// or https:// URL")
	}
	return v
}

// secret reads a credential.
func (r *fieldReader) secret(key string) logging.Secret {
	if v := r.str(key); v != "" {
		return logging.Secret(v)
	}
	return nil
}

func (r *fieldReader) done() error {
	if r.err != nil {
		return r.err
	}
	if len(r.missing) > 0 {
		return fmt.Errorf("%w: missing values for required parameters: %s", ErrFormat, strings.Join(r.missing, ", "))
	}
	return nil
}

// parseRemote reads a document of a secret-store type.
func parseRemote(typ string, fields map[string]*yaml.Node, dir string) (document, error) {
	r := &fieldReader{fields: fields, dir: dir}
	var (
		spec       secrets.Spec
		credential bool
	)
	switch typ {
	case TypeHashicorp:
		h := &secrets.Hashicorp{
			ServerHost:          r.required("serverHost"),
			ServerPort:          r.number("serverPort", secrets.DefaultVaultPort, 65535),
			KeyPath:             r.required("keyPath"),
			KeyName:             r.str("keyName"),
			Token:               r.secret("token"),
			Timeout:             time.Duration(r.number("timeout", int(secrets.DefaultVaultTimeout/time.Millisecond), maxTimeoutMillis)) * time.Millisecond,
			TLSEnabled:          r.boolean("tlsEnabled"),
			TLSKnownServersFile: r.path("tlsKnownServersPath", ""),
			HTTPProtocolVersion: r.enum("httpProtocolVersion", secrets.HTTP2, secrets.HTTP11, secrets.HTTP2),
			AuthMethod:          r.enum("authMethod", secrets.VaultAuthToken, secrets.VaultAuthToken, secrets.VaultAuthKubernetes),
			KubernetesRole:      r.str("kubernetesRole"),
			KubernetesTokenPath: r.path("kubernetesServiceAccountTokenPath", secrets.DefaultKubernetesToken),
		}
		if h.KeyName == "" {
			h.KeyName = secrets.DefaultVaultKeyName
		}
		if err := r.done(); err != nil {
			return document{}, err
		}
		var err error
		if h.KubernetesAuthPath, err = secrets.CheckKubernetesAuthPath(r.str("kubernetesAuthPath")); err != nil {
			return document{}, fmt.Errorf("%w: %v", ErrFormat, err)
		}
		switch {
		case h.AuthMethod == secrets.VaultAuthToken && len(h.Token) == 0:
			return document{}, fmt.Errorf("%w: token must be provided when using TOKEN auth method", ErrFormat)
		case h.AuthMethod == secrets.VaultAuthKubernetes && h.KubernetesRole == "":
			return document{}, fmt.Errorf("%w: kubernetesRole must be provided when using KUBERNETES auth method",
				ErrFormat)
		}
		spec, credential = h, len(h.Token) > 0
	case TypeAWSSecret:
		a := &secrets.AWS{AWSConn: secrets.AWSConn{
			AuthMode:         r.enum("authenticationMode", secrets.AWSSpecified, secrets.AWSSpecified, secrets.AWSEnvironment),
			Region:           r.required("region"),
			EndpointOverride: r.endpoint("endpointOverride"),
		}, SecretName: r.required("secretName")}
		if a.AuthMode == secrets.AWSSpecified {
			a.AccessKeyID = r.required("accessKeyId")
			r.required("secretAccessKey")
		}
		a.SecretAccessKey = r.secret("secretAccessKey")
		if err := r.done(); err != nil {
			return document{}, err
		}
		spec, credential = a, len(a.SecretAccessKey) > 0
	case TypeAzureSecret:
		a := &secrets.Azure{AzureVault: secrets.AzureVault{
			AuthMode: r.enum("authenticationMode", secrets.AzureClientSecret, secrets.AzureClientSecret,
				secrets.AzureUserAssignedIdentity, secrets.AzureSystemAssignedIdentity),
			VaultName:                r.required("vaultName"),
			Timeout:                  time.Duration(r.number("timeout", int(secrets.DefaultAzureTimeout/time.Second), maxTimeoutMillis/1000)) * time.Second,
			EndpointOverride:         r.endpoint("endpointOverride"),
			AuthorityHostOverride:    r.endpoint("authorityHostOverride"),
			TrustCertificateOverride: r.path("trustCertificateOverride", ""),
		}, SecretName: r.required("secretName")}
		switch a.AuthMode {
		case secrets.AzureClientSecret:
			a.ClientID, a.TenantID = r.required("clientId"), r.required("tenantId")
			r.required("clientSecret")
		case secrets.AzureUserAssignedIdentity:
			a.ClientID = r.required("clientId")
		}
		a.ClientSecret = r.secret("clientSecret")
		if err := r.done(); err != nil {
			return document{}, err
		}
		spec, credential = a, len(a.ClientSecret) > 0
	case TypeGCPSecret:
		g := &secrets.GCP{ProjectID: r.required("projectId"), SecretName: r.required("secretName"),
			EndpointOverride: r.str("endpointOverride")}
		if err := r.done(); err != nil {
			return document{}, err
		}
		spec = g
	}
	return document{remote: spec, credential: credential}, nil
}

// fetch fetches a secret-store document's seed and derives its key.
func (c Config) fetch(ctx context.Context, s secrets.Spec) (*mldsa87.Key, error) {
	if c.Secrets == nil {
		return nil, fmt.Errorf("%w: secret-store types are not supported here", ErrUnsupported)
	}
	value, err := c.Secrets.Fetch(ctx, s)
	if errors.Is(err, secrets.ErrUnavailable) {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	if err != nil {
		return nil, err
	}
	defer mldsa87.Wipe(value)
	if err := secrets.CheckSize(len(value)); err != nil {
		return nil, fmt.Errorf("%s: %w", s.Describe(), err)
	}
	keys, err := secrets.Keys(value, true)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", s.Describe(), ErrPrivateKey, err)
	}
	return keys[0], nil
}
