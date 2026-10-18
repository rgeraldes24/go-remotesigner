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
// keystorage/src/main/java/tech/pegasys/web3signer/keystorage/azure/AzureKeyVault.java,
// keystorage/src/main/java/tech/pegasys/web3signer/keystorage/azure/AzureOverrides.java and
// signing/src/main/java/tech/pegasys/web3signer/signing/config/AzureKeyVaultFactory.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

// Package azurekv reads seeds from Azure Key Vault secrets with
// azure-sdk-for-go (azsecrets and azidentity): one secret per azure-secret
// key-config document, and every secret of a vault that carries the bulk
// loader's tags (--azure-*). Keys are not read: Azure has no ML-DSA key
// type, so Web3Signer's azure-key signer has no QRL counterpart.
//
// Credentials are a client secret of a Microsoft Entra ID application
// (CLIENT_SECRET), a user-assigned managed identity
// (USER_ASSIGNED_MANAGED_IDENTITY) or the system-assigned one
// (SYSTEM_ASSIGNED_MANAGED_IDENTITY). Web3Signer's overrides are kept: the
// vault endpoint, the authority host, and a certificate trusted instead of
// the system roots, for sovereign clouds and emulators. The timeout bounds
// each HTTP request and each call, retries included. The SDK's log
// listener is removed, so AZURE_SDK_GO_LOGGING cannot make it log.
package azurekv

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	azlog "github.com/Azure/azure-sdk-for-go/sdk/azcore/log"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
)

func init() {
	// The SDK logs to stderr when AZURE_SDK_GO_LOGGING=all; the signer's
	// own log is the only output.
	azlog.SetListener(nil)
}

// vaultName is the form of a key vault's name.
var vaultName = regexp.MustCompile(`^[A-Za-z0-9-]{1,127}$`)

// maxCertFile bounds the trust certificate override's file.
const maxCertFile = 1 << 20

// Client fetches the secrets of azure-secret documents. It keeps up to
// secrets.DefaultAzureClientCache SDK clients, by credentials, vault and
// overrides, as Web3Signer's AzureKeyVaultFactory does. It is safe for
// concurrent use.
type Client struct {
	clients secrets.Cache[vaultKey, *vault]
}

type vaultKey struct {
	mode, vaultURL, clientID, tenantID string
	secret                             [32]byte // digest of the client secret
	timeout                            time.Duration
	authority, trust                   string
}

// vault is an SDK client and the timeout of its calls.
type vault struct {
	c       *azsecrets.Client
	timeout time.Duration
}

// New returns a client.
func New() *Client {
	c := &Client{}
	c.clients.Max = secrets.DefaultAzureClientCache
	return c
}

// Fetch implements secrets.Fetcher for *secrets.Azure specs.
func (c *Client) Fetch(ctx context.Context, s secrets.Spec) ([]byte, error) {
	a, ok := s.(*secrets.Azure)
	if !ok {
		return nil, fmt.Errorf("azurekv: %w: not an Azure secret", secrets.ErrConfig)
	}
	v := a.AzureVault
	k := vaultKey{mode: v.AuthMode, vaultURL: v.VaultURL(), clientID: v.ClientID, tenantID: v.TenantID,
		secret: secrets.Digest(v.ClientSecret), timeout: v.Timeout, authority: v.AuthorityHostOverride,
		trust: v.TrustCertificateOverride}
	kv, err := c.clients.Get(k, func() (*vault, error) { return newVault(v) })
	if err != nil {
		return nil, fmt.Errorf("%s: %w", a.Describe(), err)
	}
	value, err := kv.get(ctx, a.SecretName)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", a.Describe(), err)
	}
	return value, nil
}

// newVault builds the SDK client of v.
func newVault(v secrets.AzureVault) (*vault, error) {
	if v.EndpointOverride == "" && !vaultName.MatchString(v.VaultName) {
		return nil, fmt.Errorf("%w: vault name %q: want letters, digits and hyphens", secrets.ErrConfig,
			strings.ToValidUTF8(v.VaultName[:min(len(v.VaultName), 32)], "?"))
	}
	if v.Timeout <= 0 {
		v.Timeout = secrets.DefaultAzureTimeout
	}
	o := secrets.HTTPOptions{Timeout: v.Timeout}
	if v.TrustCertificateOverride != "" {
		pool, err := certPool(v.TrustCertificateOverride)
		if err != nil {
			return nil, err
		}
		o.TLS = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}
	// One HTTP client for the credential and the vault, as Web3Signer
	// shares its Netty client.
	opts := azcore.ClientOptions{Transport: secrets.HTTPClient(o), Logging: policy.LogOptions{IncludeBody: false}}
	var (
		cred azcore.TokenCredential
		err  error
	)
	switch v.AuthMode {
	case secrets.AzureClientSecret:
		if v.ClientID == "" || v.TenantID == "" || len(v.ClientSecret) == 0 {
			return nil, fmt.Errorf("%w: CLIENT_SECRET authentication needs a client id, a tenant id and a client "+
				"secret", secrets.ErrConfig)
		}
		co := &azidentity.ClientSecretCredentialOptions{ClientOptions: opts}
		if v.AuthorityHostOverride != "" {
			co.Cloud = cloud.Configuration{ActiveDirectoryAuthorityHost: v.AuthorityHostOverride,
				Services: map[cloud.ServiceName]cloud.ServiceConfiguration{}}
			co.DisableInstanceDiscovery = true
		}
		cred, err = azidentity.NewClientSecretCredential(v.TenantID, v.ClientID, string(v.ClientSecret), co)
	case secrets.AzureUserAssignedIdentity, secrets.AzureSystemAssignedIdentity:
		if v.AuthMode == secrets.AzureUserAssignedIdentity && v.ClientID == "" {
			return nil, fmt.Errorf("%w: USER_ASSIGNED_MANAGED_IDENTITY authentication needs a client id",
				secrets.ErrConfig)
		}
		mo := &azidentity.ManagedIdentityCredentialOptions{ClientOptions: opts}
		if v.ClientID != "" {
			mo.ID = azidentity.ClientID(v.ClientID)
		}
		cred, err = azidentity.NewManagedIdentityCredential(mo)
	default:
		return nil, fmt.Errorf("%w: unknown authentication mode %q", secrets.ErrConfig, v.AuthMode)
	}
	if err != nil {
		return nil, fmt.Errorf("build the Azure credential: %s", oneLine(err))
	}
	c, err := azsecrets.NewClient(v.VaultURL(), cred, &azsecrets.ClientOptions{
		ClientOptions: opts, DisableChallengeResourceVerification: v.EndpointOverride != ""})
	if err != nil {
		return nil, fmt.Errorf("build the Azure Key Vault client: %s", oneLine(err))
	}
	return &vault{c: c, timeout: v.Timeout}, nil
}

// certPool reads the certificate file of the trust certificate override,
// PEM or DER, into a pool that holds only its certificates.
func certPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("trust certificate override: %w", err)
	}
	if len(data) > maxCertFile {
		return nil, fmt.Errorf("trust certificate override %s: %w", path, secrets.ErrTooLarge)
	}
	pool, n := x509.NewCertPool(), 0
	if !bytes.Contains(data, []byte("-----BEGIN")) {
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("trust certificate override %s: not a PEM or DER certificate: %w", path, err)
		}
		pool.AddCert(cert)
		return pool, nil
	}
	for rest := data; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("trust certificate override %s: %w", path, err)
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("trust certificate override %s: no certificate", path)
	}
	return pool, nil
}

// get returns the latest value of the secret name.
func (v *vault) get(ctx context.Context, name string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()
	resp, err := v.c.GetSecret(ctx, name, "", nil)
	if err != nil {
		var re *azcore.ResponseError
		if errors.As(err, &re) && re.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%w: secret %q doesn't exist", secrets.ErrNotFound, name)
		}
		return nil, fmt.Errorf("failed to fetch the secret: %s", oneLine(err))
	}
	if resp.Value == nil {
		return nil, fmt.Errorf("%w: the secret has no value", secrets.ErrNotFound)
	}
	if err := secrets.CheckSize(len(*resp.Value)); err != nil {
		return nil, err
	}
	return []byte(*resp.Value), nil
}

// oneLine shortens an SDK error to one line: azcore's response errors
// span many lines with the full error response.
func oneLine(err error) string {
	var re *azcore.ResponseError
	if errors.As(err, &re) {
		return fmt.Sprintf("Azure answered HTTP %d %s", re.StatusCode, re.ErrorCode)
	}
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// Bulk is the Azure Key Vault bulk loader's store.
type Bulk struct {
	v    *vault
	tags []secrets.Tag
}

// NewBulk returns the store of the bulk loader b.
func NewBulk(b secrets.AzureBulk) (*Bulk, error) {
	v, err := newVault(b.AzureVault)
	if err != nil {
		return nil, err
	}
	return &Bulk{v: v, tags: b.Tags}, nil
}

// List implements secrets.Lister: the names of the vault's secrets that
// carry every tag with its value (Web3Signer's subset match; no tags
// selects every secret).
func (b *Bulk) List(ctx context.Context) ([]string, error) {
	pager := b.v.c.NewListSecretPropertiesPager(nil)
	var names []string
	for pager.More() {
		page, err := func() (azsecrets.ListSecretPropertiesResponse, error) {
			ctx, cancel := context.WithTimeout(ctx, b.v.timeout)
			defer cancel()
			return pager.NextPage(ctx)
		}()
		if err != nil {
			return nil, fmt.Errorf("unexpected error during Azure list-secrets operation: %s", oneLine(err))
		}
		for _, p := range page.Value {
			if p == nil || p.ID == nil || !hasTags(p.Tags, b.tags) {
				continue
			}
			names = append(names, p.ID.Name())
		}
	}
	return names, nil
}

func hasTags(have map[string]*string, want []secrets.Tag) bool {
	for _, t := range want {
		v, ok := have[t.Key]
		if !ok || v == nil || *v != t.Value {
			return false
		}
	}
	return true
}

// Get implements secrets.Lister.
func (b *Bulk) Get(ctx context.Context, name string) ([]byte, error) { return b.v.get(ctx, name) }
