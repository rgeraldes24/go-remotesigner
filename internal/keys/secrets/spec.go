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
// signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/HashicorpSigningMetadata.java,
// signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/AwsKeySigningMetadataDeserializer.java,
// signing/src/main/java/tech/pegasys/web3signer/signing/config/metadata/AzureSecretSigningMetadataDeserializer.java,
// keystorage/src/main/java/tech/pegasys/web3signer/keystorage/hashicorp/config/ConnectionParameters.java,
// keystorage/src/main/java/tech/pegasys/web3signer/keystorage/hashicorp/config/KubernetesAuthOptions.java,
// keystorage/src/main/java/tech/pegasys/web3signer/keystorage/azure/AzureOverrides.java,
// common/src/main/java/tech/pegasys/web3signer/common/config/AwsAuthenticationMode.java and
// signing/src/main/java/tech/pegasys/web3signer/signing/config/AzureAuthenticationMode.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package secrets

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/logging"
)

// HashiCorp Vault defaults, Web3Signer's.
const (
	DefaultVaultPort        = 8200
	DefaultVaultTimeout     = 10 * time.Second
	DefaultVaultKeyName     = "value"
	DefaultKubernetesAuth   = "kubernetes"
	DefaultKubernetesToken  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	DefaultAzureTimeout     = 60 * time.Second
	DefaultAWSClientCache   = 1
	DefaultAzureClientCache = 10
)

// Vault authentication methods and HTTP versions.
const (
	VaultAuthToken      = "TOKEN"
	VaultAuthKubernetes = "KUBERNETES"
	HTTP11              = "HTTP_1_1"
	HTTP2               = "HTTP_2"
)

// AWS authentication modes.
const (
	// AWSSpecified uses the configured access key.
	AWSSpecified = "SPECIFIED"
	// AWSEnvironment uses the SDK's default credential chain: the
	// environment, the shared credentials and config files, web identity,
	// and the ECS and EC2 instance roles.
	AWSEnvironment = "ENVIRONMENT"
)

// Azure authentication modes.
const (
	AzureClientSecret           = "CLIENT_SECRET"
	AzureUserAssignedIdentity   = "USER_ASSIGNED_MANAGED_IDENTITY"
	AzureSystemAssignedIdentity = "SYSTEM_ASSIGNED_MANAGED_IDENTITY"
)

// ParseEnum returns the value of allowed that s names, ignoring case, as
// Web3Signer's YAML and command-line parsers do.
func ParseEnum(s string, allowed ...string) (string, error) {
	for _, a := range allowed {
		if strings.EqualFold(s, a) {
			return a, nil
		}
	}
	return "", fmt.Errorf("%w: %q is not one of %s", ErrConfig, truncate(s), strings.Join(allowed, ", "))
}

// Hashicorp is a `type: hashicorp` key-config document: one key of a KV
// version 2 secret in HashiCorp Vault, read over HTTP.
type Hashicorp struct {
	ServerHost string
	ServerPort int
	// KeyPath is the secret's read path, /v1/<mount>/data/<path>.
	KeyPath string
	// KeyName is the key of the secret's data that holds the seed.
	KeyName string
	// Token is the Vault token of the TOKEN method.
	Token   logging.Secret
	Timeout time.Duration
	// TLSEnabled connects over HTTPS; the server certificate must chain to
	// the system roots or, with TLSKnownServersFile, have a fingerprint
	// listed there for ServerHost:ServerPort.
	TLSEnabled          bool
	TLSKnownServersFile string
	HTTPProtocolVersion string
	AuthMethod          string
	// The KUBERNETES method's role, service-account token file and auth
	// mount path.
	KubernetesRole      string
	KubernetesTokenPath string
	KubernetesAuthPath  string
}

// Kind implements Spec.
func (*Hashicorp) Kind() string { return KindHashicorp }

// Describe implements Spec.
func (h *Hashicorp) Describe() string {
	return fmt.Sprintf("hashicorp secret %s key %q on %s", h.KeyPath, h.KeyName, h.Addr())
}

// Addr is the server's host:port.
func (h *Hashicorp) Addr() string { return net.JoinHostPort(h.ServerHost, strconv.Itoa(h.ServerPort)) }

// AWSConn is how to reach AWS Secrets Manager.
type AWSConn struct {
	AuthMode string
	// Region is required in key-config documents and in the bulk loader's
	// SPECIFIED mode; in ENVIRONMENT mode an empty region is the SDK's.
	Region          string
	AccessKeyID     string
	SecretAccessKey logging.Secret
	// EndpointOverride replaces the service endpoint (an emulator, a VPC
	// endpoint).
	EndpointOverride string
}

// AWS is a `type: aws-secret` key-config document.
type AWS struct {
	AWSConn
	SecretName string
}

// Kind implements Spec.
func (*AWS) Kind() string { return KindAWS }

// Describe implements Spec.
func (a *AWS) Describe() string {
	return fmt.Sprintf("aws secret %q in %s", a.SecretName, regionOrDefault(a.Region))
}

func regionOrDefault(r string) string {
	if r == "" {
		return "the default region"
	}
	return r
}

// Tag is a tag filter of a bulk loader: a secret matches when it has the
// tag. An empty Value matches the key alone in AWS, and only an empty value
// in Azure, as in Web3Signer.
type Tag struct{ Key, Value string }

// AWSBulk is the AWS Secrets Manager bulk loader (--aws-secrets-*).
type AWSBulk struct {
	AWSConn
	// PrefixesFilter keeps the secrets whose names start with any prefix.
	PrefixesFilter []string
	// Tags keeps the secrets that carry any of the tag keys and, when a
	// value is set, any of the values (AWS's tag-key and tag-value filters,
	// as Web3Signer builds them).
	Tags []Tag
}

// AzureVault is how to reach an Azure key vault.
type AzureVault struct {
	AuthMode  string
	VaultName string
	ClientID  string
	TenantID  string
	// ClientSecret is the CLIENT_SECRET mode's secret.
	ClientSecret logging.Secret
	// Timeout bounds each HTTP request.
	Timeout time.Duration
	// The overrides of Web3Signer's AzureOverrides: the vault URL, the
	// Microsoft Entra ID authority host (sovereign clouds, emulators) and a
	// certificate file trusted instead of the system roots.
	EndpointOverride         string
	AuthorityHostOverride    string
	TrustCertificateOverride string
}

// VaultURL is the vault's URL: the endpoint override, else
// https://<vault>.vault.azure.net.
func (v *AzureVault) VaultURL() string {
	if v.EndpointOverride != "" {
		return v.EndpointOverride
	}
	return "https://" + v.VaultName + ".vault.azure.net"
}

// Azure is a `type: azure-secret` key-config document.
type Azure struct {
	AzureVault
	SecretName string
}

// Kind implements Spec.
func (*Azure) Kind() string { return KindAzure }

// Describe implements Spec.
func (a *Azure) Describe() string {
	return fmt.Sprintf("azure secret %q in %s", a.SecretName, a.VaultURL())
}

// AzureBulk is the Azure Key Vault bulk loader (--azure-*).
type AzureBulk struct {
	AzureVault
	// Tags keeps the secrets that carry every tag with its value.
	Tags []Tag
}

// GCP is a `type: gcp-secret` key-config document: the latest version of
// a Secret Manager secret, with Application Default Credentials.
type GCP struct {
	ProjectID  string
	SecretName string
	// EndpointOverride replaces the service endpoint, host:port; an
	// http:// endpoint is an emulator, reached without TLS and without
	// credentials.
	EndpointOverride string
}

// Kind implements Spec.
func (*GCP) Kind() string { return KindGCP }

// Describe implements Spec.
func (g *GCP) Describe() string { return g.Resource() }

// Resource is the secret's resource name.
func (g *GCP) Resource() string { return "projects/" + g.ProjectID + "/secrets/" + g.SecretName }

// GCPBulk is the GCP Secret Manager bulk loader (--gcp-secrets-*).
type GCPBulk struct {
	ProjectID string
	// Filter is a Secret Manager list filter; empty lists every secret.
	Filter           string
	EndpointOverride string
}

// ParseTags parses tag filters written as KEY=VALUE. Each element may hold
// several, separated by |, as Web3Signer's --aws-secrets-tag and
// --azure-tags take them; a KEY without = has the empty value.
func ParseTags(elems []string) ([]Tag, error) {
	var out []Tag
	for _, e := range elems {
		for _, kv := range strings.Split(e, "|") {
			k, v, _ := strings.Cut(kv, "=")
			if k == "" {
				return nil, fmt.Errorf("%w: tag %q: want KEY=VALUE", ErrConfig, truncate(kv))
			}
			out = append(out, Tag{Key: k, Value: v})
		}
	}
	return out, nil
}

// CheckKubernetesAuthPath normalises the KUBERNETES method's auth mount
// path as Web3Signer does: blank is "kubernetes", surrounding slashes are
// dropped, and an empty, "." or ".." segment is refused.
func CheckKubernetesAuthPath(p string) (string, error) {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "" {
		return DefaultKubernetesAuth, nil
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("%w: kubernetesAuthPath must not contain '.' or '..' or empty path segments",
				ErrConfig)
		}
	}
	return p, nil
}

// truncate bounds an untrusted string quoted in an error.
func truncate(s string) string {
	if len(s) > 32 {
		return s[:32] + "…"
	}
	return s
}
