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
// commandline/src/main/java/tech/pegasys/web3signer/commandline/subcommands/Eth2SubCommand.java,
// commandline/src/main/java/tech/pegasys/web3signer/commandline/PicoCliAwsSecretsManagerParameters.java,
// commandline/src/main/java/tech/pegasys/web3signer/commandline/PicoCliGcpSecretManagerParameters.java and
// commandline/src/main/java/tech/pegasys/web3signer/commandline/PicoCliAzureKeyVaultParameters.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package main

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/logging"
)

// maxAzureTimeout bounds --azure-response-timeout, a day in seconds.
const maxAzureTimeout = 24 * 60 * 60

// secretStores resolves the secret-store flags: the bulk loaders that are
// enabled, checked as Web3Signer's eth2 command checks them, and the AWS
// client cache. The flavour without cloud SDKs refuses the bulk loaders.
func secretStores(c *cli.Context) (config.SecretStores, error) {
	st := config.SecretStores{AWSClientCacheSize: c.Int(flags.AWSConnectionCacheSize)}
	if st.AWSClientCacheSize < 1 {
		return st, fmt.Errorf("--%s must be at least 1", flags.AWSConnectionCacheSize)
	}
	for _, f := range []string{flags.AzureVaultEnabled, flags.AWSSecretsEnabled, flags.GCPSecretsEnabled} {
		if c.Bool(f) && !cloudSecretStores {
			return st, fmt.Errorf("--%s: %s has no cloud secret stores; use the remotesigner flavour", f, binaryName)
		}
	}
	var err error
	if c.Bool(flags.AzureVaultEnabled) {
		if st.Azure, err = azureBulk(c); err != nil {
			return st, err
		}
	}
	if c.Bool(flags.AWSSecretsEnabled) {
		if st.AWS, err = awsBulk(c); err != nil {
			return st, err
		}
	}
	if c.Bool(flags.GCPSecretsEnabled) {
		st.GCP = &secrets.GCPBulk{ProjectID: c.String(flags.GCPProjectID), Filter: c.String(flags.GCPSecretsFilter),
			EndpointOverride: c.String(flags.GCPEndpointOverride)}
		if st.GCP.ProjectID == "" {
			return st, fmt.Errorf("--%s=true, but the following parameters were missing [--%s]",
				flags.GCPSecretsEnabled, flags.GCPProjectID)
		}
	}
	return st, nil
}

func awsBulk(c *cli.Context) (*secrets.AWSBulk, error) {
	mode, err := secrets.ParseEnum(c.String(flags.AWSSecretsAuthMode), secrets.AWSSpecified, secrets.AWSEnvironment)
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", flags.AWSSecretsAuthMode, err)
	}
	b := &secrets.AWSBulk{AWSConn: secrets.AWSConn{AuthMode: mode, Region: c.String(flags.AWSSecretsRegion),
		AccessKeyID: c.String(flags.AWSSecretsAccessKeyID), EndpointOverride: c.String(flags.AWSEndpointOverride)},
		PrefixesFilter: c.StringSlice(flags.AWSSecretsPrefixesFilter)}
	if s := c.String(flags.AWSSecretsSecretAccessKey); s != "" {
		b.SecretAccessKey = logging.Secret(s)
	}
	if mode == secrets.AWSSpecified {
		var missing []string
		for _, f := range []struct {
			name string
			set  bool
		}{{flags.AWSSecretsAccessKeyID, b.AccessKeyID != ""}, {flags.AWSSecretsSecretAccessKey, len(b.SecretAccessKey) > 0},
			{flags.AWSSecretsRegion, b.Region != ""}} {
			if !f.set {
				missing = append(missing, "--"+f.name)
			}
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("--%s=%s, but the following parameters were missing [%s]", flags.AWSSecretsAuthMode,
				secrets.AWSSpecified, strings.Join(missing, ", "))
		}
	}
	if err := checkURL(flags.AWSEndpointOverride, b.EndpointOverride); err != nil {
		return nil, err
	}
	if b.Tags, err = secrets.ParseTags(c.StringSlice(flags.AWSSecretsTag)); err != nil {
		return nil, fmt.Errorf("--%s: %w", flags.AWSSecretsTag, err)
	}
	return b, nil
}

func azureBulk(c *cli.Context) (*secrets.AzureBulk, error) {
	mode, err := secrets.ParseEnum(c.String(flags.AzureVaultAuthMode), secrets.AzureClientSecret,
		secrets.AzureUserAssignedIdentity, secrets.AzureSystemAssignedIdentity)
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", flags.AzureVaultAuthMode, err)
	}
	t := c.Uint(flags.AzureResponseTimeout)
	if t < 1 || t > maxAzureTimeout {
		return nil, fmt.Errorf("--%s must be 1 to %d (seconds)", flags.AzureResponseTimeout, maxAzureTimeout)
	}
	b := &secrets.AzureBulk{AzureVault: secrets.AzureVault{AuthMode: mode, VaultName: c.String(flags.AzureVaultName),
		ClientID: c.String(flags.AzureClientID), TenantID: c.String(flags.AzureTenantID),
		Timeout: time.Duration(t) * time.Second, EndpointOverride: c.String(flags.AzureEndpointOverride),
		AuthorityHostOverride: c.String(flags.AzureAuthorityOverride), TrustCertificateOverride: c.String(flags.AzureTrustCertOverride)}}
	if s := c.String(flags.AzureClientSecret); s != "" {
		b.ClientSecret = logging.Secret(s)
	}
	var missing []string
	need := func(name string, set bool) {
		if !set {
			missing = append(missing, "--"+name)
		}
	}
	need(flags.AzureVaultName, b.VaultName != "")
	switch mode {
	case secrets.AzureClientSecret:
		need(flags.AzureClientID, b.ClientID != "")
		need(flags.AzureClientSecret, len(b.ClientSecret) > 0)
		need(flags.AzureTenantID, b.TenantID != "")
	case secrets.AzureUserAssignedIdentity:
		need(flags.AzureClientID, b.ClientID != "")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("--%s=true, but the following parameters were missing [%s]", flags.AzureVaultEnabled,
			strings.Join(missing, ", "))
	}
	for _, u := range []struct{ name, v string }{{flags.AzureEndpointOverride, b.EndpointOverride},
		{flags.AzureAuthorityOverride, b.AuthorityHostOverride}} {
		if err := checkURL(u.name, u.v); err != nil {
			return nil, err
		}
	}
	if b.Tags, err = secrets.ParseTags(c.StringSlice(flags.AzureTags)); err != nil {
		return nil, fmt.Errorf("--%s: %w", flags.AzureTags, err)
	}
	return b, nil
}

// checkURL checks an optional endpoint URL flag.
func checkURL(name, v string) error {
	if v == "" {
		return nil
	}
	if u, err := url.Parse(v); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("--%s: want an http:// or https:// URL", name)
	}
	return nil
}
