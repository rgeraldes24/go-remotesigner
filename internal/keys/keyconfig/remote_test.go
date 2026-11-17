// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package keyconfig

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
)

// fakeStores answers every secret-store fetch with the value of the spec's
// description, and counts the fetches.
type fakeStores struct {
	values map[string]string // Describe() -> value
	specs  []secrets.Spec
	n      atomic.Int64
}

func (f *fakeStores) Fetch(_ context.Context, s secrets.Spec) ([]byte, error) {
	f.n.Add(1)
	f.specs = append(f.specs, s)
	v, ok := f.values[s.Describe()]
	if !ok {
		return nil, fmt.Errorf("%s: %w", s.Describe(), secrets.ErrNotFound)
	}
	return []byte(v), nil
}

func TestParseRemote(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name       string
		yaml       string
		want       secrets.Spec
		credential bool
		err        string // substring of the error; "" for none
	}{
		{name: "hashicorp defaults",
			yaml: "type: hashicorp\nserverHost: vault\nkeyPath: /v1/secret/data/k\ntoken: s.tok\n",
			want: &secrets.Hashicorp{ServerHost: "vault", ServerPort: 8200, KeyPath: "/v1/secret/data/k", KeyName: "value",
				Token: []byte("s.tok"), Timeout: 10 * time.Second, HTTPProtocolVersion: secrets.HTTP2,
				AuthMethod: secrets.VaultAuthToken, KubernetesTokenPath: secrets.DefaultKubernetesToken,
				KubernetesAuthPath: "kubernetes"},
			credential: true},
		{name: "hashicorp every field",
			yaml: "type: hashicorp\nkeyType: ML_DSA_87\nserverHost: vault\nserverPort: 8201\nkeyPath: /v1/kv/data/k\n" +
				"keyName: seed\ntimeout: 2500\ntlsEnabled: true\ntlsKnownServersPath: known.txt\n" +
				"httpProtocolVersion: http_1_1\nauthMethod: kubernetes\nkubernetesRole: signer\n" +
				"kubernetesServiceAccountTokenPath: /t/token\nkubernetesAuthPath: /k8s/cluster1/\n",
			want: &secrets.Hashicorp{ServerHost: "vault", ServerPort: 8201, KeyPath: "/v1/kv/data/k", KeyName: "seed",
				Timeout: 2500 * time.Millisecond, TLSEnabled: true, TLSKnownServersFile: filepath.Join(dir, "known.txt"),
				HTTPProtocolVersion: secrets.HTTP11, AuthMethod: secrets.VaultAuthKubernetes, KubernetesRole: "signer",
				KubernetesTokenPath: "/t/token", KubernetesAuthPath: "k8s/cluster1"}},
		{name: "hashicorp missing", yaml: "type: hashicorp\ntoken: x\n",
			err: "missing values for required parameters: serverHost, keyPath"},
		{name: "hashicorp no token", yaml: "type: hashicorp\nserverHost: v\nkeyPath: /v1/a\n",
			err: "token must be provided when using TOKEN auth method"},
		{name: "hashicorp no role", yaml: "type: hashicorp\nserverHost: v\nkeyPath: /v1/a\nauthMethod: KUBERNETES\n",
			err: "kubernetesRole must be provided"},
		{name: "hashicorp bad auth path", yaml: "type: hashicorp\nserverHost: v\nkeyPath: /v1/a\ntoken: x\n" +
			"kubernetesAuthPath: a/../b\n", err: "must not contain"},
		{name: "hashicorp bad port", yaml: "type: hashicorp\nserverHost: v\nkeyPath: /v1/a\ntoken: x\nserverPort: 70000\n",
			err: "serverPort"},
		{name: "hashicorp bad bool", yaml: "type: hashicorp\nserverHost: v\nkeyPath: /v1/a\ntoken: x\ntlsEnabled: yes\n",
			err: "tlsEnabled"},
		{name: "hashicorp bad version", yaml: "type: hashicorp\nserverHost: v\nkeyPath: /v1/a\ntoken: x\n" +
			"httpProtocolVersion: HTTP_3\n", err: "httpProtocolVersion"},
		{name: "aws specified",
			yaml: "type: aws-secret\nregion: us-east-1\nsecretName: s\naccessKeyId: AKID\nsecretAccessKey: shh\n" +
				"endpointOverride: http://localhost:4566\n",
			want: &secrets.AWS{AWSConn: secrets.AWSConn{AuthMode: secrets.AWSSpecified, Region: "us-east-1",
				AccessKeyID: "AKID", SecretAccessKey: []byte("shh"), EndpointOverride: "http://localhost:4566"},
				SecretName: "s"},
			credential: true},
		{name: "aws environment", yaml: "type: aws-secret\nauthenticationMode: ENVIRONMENT\nregion: eu-west-1\nsecretName: s\n",
			want: &secrets.AWS{AWSConn: secrets.AWSConn{AuthMode: secrets.AWSEnvironment, Region: "eu-west-1"},
				SecretName: "s"}},
		{name: "aws specified missing", yaml: "type: aws-secret\nsecretName: s\n",
			err: "missing values for required parameters: region, accessKeyId, secretAccessKey"},
		{name: "aws bad endpoint", yaml: "type: aws-secret\nauthenticationMode: ENVIRONMENT\nregion: r\nsecretName: s\n" +
			"endpointOverride: localhost:4566\n", err: "endpointOverride"},
		{name: "aws unknown mode", yaml: "type: aws-secret\nauthenticationMode: IAM\nregion: r\nsecretName: s\n",
			err: "authenticationMode"},
		{name: "azure client secret",
			yaml: "type: azure-secret\nvaultName: v\nsecretName: s\nclientId: c\nclientSecret: shh\ntenantId: t\n" +
				"timeout: 5\nendpointOverride: https://127.0.0.1:8443\nauthorityHostOverride: https://127.0.0.1:8444\n" +
				"trustCertificateOverride: ca.pem\n",
			want: &secrets.Azure{AzureVault: secrets.AzureVault{AuthMode: secrets.AzureClientSecret, VaultName: "v",
				ClientID: "c", TenantID: "t", ClientSecret: []byte("shh"), Timeout: 5 * time.Second,
				EndpointOverride: "https://127.0.0.1:8443", AuthorityHostOverride: "https://127.0.0.1:8444",
				TrustCertificateOverride: filepath.Join(dir, "ca.pem")}, SecretName: "s"},
			credential: true},
		{name: "azure user-assigned",
			yaml: "type: azure-secret\nauthenticationMode: USER_ASSIGNED_MANAGED_IDENTITY\nvaultName: v\nsecretName: s\nclientId: c\n",
			want: &secrets.Azure{AzureVault: secrets.AzureVault{AuthMode: secrets.AzureUserAssignedIdentity, VaultName: "v",
				ClientID: "c", Timeout: 60 * time.Second}, SecretName: "s"}},
		{name: "azure system-assigned",
			yaml: "type: azure-secret\nauthenticationMode: SYSTEM_ASSIGNED_MANAGED_IDENTITY\nvaultName: v\nsecretName: s\n",
			want: &secrets.Azure{AzureVault: secrets.AzureVault{AuthMode: secrets.AzureSystemAssignedIdentity, VaultName: "v",
				Timeout: 60 * time.Second}, SecretName: "s"}},
		{name: "azure client secret missing", yaml: "type: azure-secret\nvaultName: v\nsecretName: s\n",
			err: "missing values for required parameters: clientId, tenantId, clientSecret"},
		{name: "azure user-assigned missing",
			yaml: "type: azure-secret\nauthenticationMode: USER_ASSIGNED_MANAGED_IDENTITY\nvaultName: v\nsecretName: s\n",
			err:  "missing values for required parameters: clientId"},
		{name: "gcp", yaml: "type: gcp-secret\nprojectId: p\nsecretName: s\n",
			want: &secrets.GCP{ProjectID: "p", SecretName: "s"}},
		{name: "gcp missing", yaml: "type: gcp-secret\n", err: "missing values for required parameters: projectId, secretName"},
		{name: "unknown field", yaml: "type: gcp-secret\nprojectId: p\nsecretName: s\nfilter: x\n", err: "unknown key"},
		{name: "BLS", yaml: "type: aws-secret\nkeyType: BLS\nregion: r\nsecretName: s\nauthenticationMode: ENVIRONMENT\n",
			err: "keyType BLS"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs, err := parse([]byte(tt.yaml), dir, false)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("parse error = %v, want %q", err, tt.err)
				}
				for _, secret := range []string{"shh", "s.tok"} {
					if strings.Contains(err.Error(), secret) {
						t.Fatalf("error quotes a credential: %v", err)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(docs) != 1 || docs[0].remote == nil {
				t.Fatalf("docs = %+v", docs)
			}
			if got, want := fmt.Sprintf("%#v", docs[0].remote), fmt.Sprintf("%#v", tt.want); got != want {
				t.Errorf("spec =\n%s\nwant\n%s", got, want)
			}
			if docs[0].credential != tt.credential {
				t.Errorf("credential = %v, want %v", docs[0].credential, tt.credential)
			}
		})
	}
}

func TestRemoteLoad(t *testing.T) {
	dir := t.TempDir()
	const aws = "type: aws-secret\nauthenticationMode: ENVIRONMENT\nregion: r\nsecretName: "
	stores := &fakeStores{values: map[string]string{
		`aws secret "one" in r`:     seedHex(1) + "\n",
		`aws secret "two" in r`:     strings.TrimPrefix(seedHex(2), "0x"),
		`aws secret "ext" in r`:     "0x010000" + strings.Repeat("03", 48),
		`aws secret "xi" in r`:      "0x" + strings.Repeat("04", 32),
		`aws secret "lines" in r`:   seedHex(1) + "\n" + seedHex(2) + "\n",
		`aws secret "notahex" in r`: "0x" + strings.Repeat("zz", 48),
	}}
	c := Config{Dir: dir, Policy: strict, Secrets: stores}
	tests := []struct {
		name, yaml string
		keys       []byte
		err        string
	}{
		{"one seed", aws + "one\n", []byte{1}, ""},
		{"without 0x", aws + "two\n", []byte{2}, ""},
		{"two documents", aws + "one\n---\n" + aws + "two\n", []byte{1, 2}, ""},
		{"extended seed refused", aws + "ext\n", nil, "51-byte extended seed belongs to execution mode"},
		{"32 bytes refused", aws + "xi\n", nil, "32 bytes"},
		{"one seed per secret", aws + "lines\n", nil, "want a 48-byte seed"},
		{"not hex", aws + "notahex\n", nil, "not hex"},
		{"not found keeps nothing", aws + "one\n---\n" + aws + "missing\n", nil, "secret not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := writeFile(t, dir, "k.yaml", tt.yaml, 0o644) // no inline credential: not a secret file
			keys, err := c.LoadFile(context.Background(), p)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("error = %v, want %q", err, tt.err)
				}
				for _, leak := range []string{"0303", "0404", "zzzz"} {
					if strings.Contains(err.Error(), leak) {
						t.Fatalf("error quotes the value: %v", err)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(keys) != len(tt.keys) {
				t.Fatalf("%d keys, want %d", len(keys), len(tt.keys))
			}
			for i, b := range tt.keys {
				if keys[i].PublicKey() != pubkeyOf(t, b) {
					t.Errorf("key %d is not the key of seed %#x", i, b)
				}
				keys[i].Zeroize()
			}
		})
	}
}

func TestRemoteCredentialMakesSecretFile(t *testing.T) {
	dir := t.TempDir()
	stores := &fakeStores{values: map[string]string{`aws secret "one" in r`: seedHex(1)}}
	c := Config{Dir: dir, Policy: strict, Secrets: stores}
	inline := "type: aws-secret\nregion: r\nsecretName: one\naccessKeyId: AKID\nsecretAccessKey: shh\n"
	p := writeFile(t, dir, "k.yaml", inline, 0o644)
	if _, err := c.LoadFile(context.Background(), p); !errors.Is(err, secretfile.ErrInsecure) {
		t.Fatalf("a world-readable file with a credential: error = %v, want ErrInsecure", err)
	}
	if stores.n.Load() != 0 {
		t.Fatal("the secret was fetched from a refused file")
	}
	p = writeFile(t, dir, "k.yaml", inline, 0o600)
	keys, err := c.LoadFile(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	keys[0].Zeroize()
	spec := stores.specs[0].(*secrets.AWS)
	if string(spec.SecretAccessKey) != "shh" || fmt.Sprint(spec.SecretAccessKey) == "shh" {
		t.Errorf("secret access key %q printed as %v", spec.SecretAccessKey, spec.SecretAccessKey)
	}
}

// TestRemoteUnchangedNotFetched checks Web3Signer's cache: the secrets of
// an unchanged key-config file are not fetched again, and a changed file
// is.
func TestRemoteUnchangedNotFetched(t *testing.T) {
	dir := t.TempDir()
	stores := &fakeStores{values: map[string]string{
		"projects/p/secrets/one": seedHex(1),
		"projects/p/secrets/two": seedHex(2),
	}}
	p := writeFile(t, dir, "k.yaml", "type: gcp-secret\nprojectId: p\nsecretName: one\n", 0o600)
	backdate(t, p)
	c := Config{Dir: dir, Policy: strict, Secrets: stores}
	quiet := logrus.New()
	quiet.SetOutput(io.Discard)
	keys := provider.New(quiet)
	load := func() []provider.Batch {
		t.Helper()
		b, err := c.Load(context.Background(), 1, func(src, v string) bool { return keys.Unchanged(src, v, nil) }, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := keys.Apply(b, nil, nil); err != nil {
			t.Fatal(err)
		}
		return b
	}
	load()
	load()
	if n := stores.n.Load(); n != 1 {
		t.Fatalf("%d fetches after two loads of an unchanged file, want 1", n)
	}
	writeFile(t, dir, "k.yaml", "type: gcp-secret\nprojectId: p\nsecretName: two\n", 0o600)
	backdate(t, p)
	load()
	if n := stores.n.Load(); n != 2 {
		t.Fatalf("%d fetches after the file changed, want 2", n)
	}
	if keys.Len() != 1 {
		t.Fatalf("%d keys loaded, want 1", keys.Len())
	}
	for pk := range keys.PublicKeys() {
		if *pk != pubkeyOf(t, 2) {
			t.Error("the changed file's key is not loaded")
		}
	}
}
