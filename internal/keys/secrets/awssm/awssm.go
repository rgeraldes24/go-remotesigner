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
// keystorage/src/main/java/tech/pegasys/web3signer/keystorage/aws/AwsSecretsManager.java,
// keystorage/src/main/java/tech/pegasys/web3signer/keystorage/aws/AwsSecretsManagerProvider.java,
// keystorage/src/main/java/tech/pegasys/web3signer/keystorage/aws/AwsKeyIdentifier.java and
// signing/src/main/java/tech/pegasys/web3signer/signing/config/AwsSecretsManagerFactory.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

// Package awssm reads seeds from AWS Secrets Manager with aws-sdk-go-v2:
// one secret per aws-secret key-config document, and every secret a bulk
// loader's name prefixes and tags select (--aws-secrets-*).
//
// Credentials are the configured access key (SPECIFIED) or the SDK's
// default chain (ENVIRONMENT): the environment, the shared credentials and
// config files, web identity, and the ECS and EC2 instance roles. Every
// request goes through the store HTTP client (a timeout, no redirect, a
// bounded response) and each call is bounded by secrets.DefaultTimeout,
// retries included. The SDK logs nothing: its logger, which by default
// writes warnings to stderr, is replaced by a no-op, and no request or
// response logging is turned on.
package awssm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go/logging"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
)

// callTimeout bounds each call, retries included, and each HTTP request:
// secrets.DefaultTimeout, a variable so that the tests can shorten it.
var callTimeout = secrets.DefaultTimeout

// Client fetches the secrets of aws-secret documents. It keeps up to the
// configured number of SDK clients, by credentials, region and endpoint
// (--aws-connection-cache-size, as Web3Signer's cache). It is safe for
// concurrent use.
type Client struct {
	clients secrets.Cache[clientKey, *secretsmanager.Client]
}

type clientKey struct {
	mode, accessKeyID string
	secret            [32]byte // digest of the secret access key
	region, endpoint  string
}

// New returns a client that caches up to cacheSize SDK clients.
func New(cacheSize int) *Client {
	c := &Client{}
	c.clients.Max = cacheSize
	c.clients.Close = closeIdle
	return c
}

// Close drops every cached SDK client and closes its idle connections. The
// client stays usable: the next fetch builds a new SDK client.
func (c *Client) Close() { c.clients.Purge() }

// closeIdle closes the idle connections of an SDK client's HTTP client.
func closeIdle(sm *secretsmanager.Client) {
	if hc, ok := sm.Options().HTTPClient.(interface{ CloseIdleConnections() }); ok {
		hc.CloseIdleConnections()
	}
}

// Fetch implements secrets.Fetcher for *secrets.AWS specs.
func (c *Client) Fetch(ctx context.Context, s secrets.Spec) ([]byte, error) {
	a, ok := s.(*secrets.AWS)
	if !ok {
		return nil, fmt.Errorf("awssm: %w: not an AWS secret", secrets.ErrConfig)
	}
	k := clientKey{mode: a.AuthMode, accessKeyID: a.AccessKeyID, secret: secrets.Digest(a.SecretAccessKey),
		region: a.Region, endpoint: a.EndpointOverride}
	// The client outlives this fetch, so it must not inherit the fetch's
	// cancellation.
	sm, release, err := c.clients.Get(k, func() (*secretsmanager.Client, error) {
		return newClient(context.WithoutCancel(ctx), a.AWSConn, storeHTTPClient())
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", a.Describe(), err)
	}
	defer release()
	v, err := get(ctx, sm, a.SecretName)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", a.Describe(), err)
	}
	return v, nil
}

// storeHTTPClient is the HTTP client of one SDK client.
func storeHTTPClient() *http.Client {
	return secrets.HTTPClient(secrets.HTTPOptions{Timeout: callTimeout})
}

// newClient builds an SDK client for conn that sends its requests with hc.
func newClient(ctx context.Context, conn secrets.AWSConn, hc *http.Client) (*secretsmanager.Client, error) {
	// The SDK's default logger writes its warnings to stderr, outside the
	// signer's log.
	opts := []func(*config.LoadOptions) error{config.WithHTTPClient(hc), config.WithLogger(logging.Nop{})}
	if conn.Region != "" {
		opts = append(opts, config.WithRegion(conn.Region))
	}
	switch conn.AuthMode {
	case secrets.AWSSpecified:
		if conn.AccessKeyID == "" || len(conn.SecretAccessKey) == 0 {
			return nil, fmt.Errorf("%w: SPECIFIED authentication needs an access key id and a secret access key",
				secrets.ErrConfig)
		}
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(conn.AccessKeyID, string(conn.SecretAccessKey), "")))
	case secrets.AWSEnvironment:
	default:
		return nil, fmt.Errorf("%w: unknown authentication mode %q", secrets.ErrConfig, conn.AuthMode)
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil && strings.Contains(err.Error(), "custom RootCAs") {
		// The SDK adds a CA bundle to its own HTTP client type only, and the
		// store HTTP client, which bounds every response, is not one.
		return nil, fmt.Errorf("%w: AWS_CA_BUNDLE and the shared config's ca_bundle are not supported; trust the CA "+
			"with SSL_CERT_FILE or SSL_CERT_DIR instead", secrets.ErrConfig)
	}
	if err != nil {
		return nil, fmt.Errorf("AWS configuration: %w", err)
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("%w: no AWS region: configure one, or set AWS_REGION for ENVIRONMENT authentication",
			secrets.ErrConfig)
	}
	return secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) {
		if conn.EndpointOverride != "" {
			o.BaseEndpoint = aws.String(conn.EndpointOverride)
		}
	}), nil
}

// get returns the latest value of the secret name: its SecretString.
func get(ctx context.Context, sm *secretsmanager.Client, name string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	out, err := sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(name)})
	var nf *types.ResourceNotFoundException
	switch {
	case errors.As(err, &nf):
		return nil, fmt.Errorf("%w: %v", secrets.ErrNotFound, err)
	case err != nil:
		return nil, fmt.Errorf("failed to fetch secret from AWS Secrets Manager: %w", err)
	case out.SecretString == nil:
		return nil, errors.New("the secret has no string value; store the seed as hex text")
	}
	if err := secrets.CheckSize(len(*out.SecretString)); err != nil {
		return nil, err
	}
	return []byte(*out.SecretString), nil
}

// Bulk is the AWS Secrets Manager bulk loader's store, built for one load.
type Bulk struct {
	sm      *secretsmanager.Client
	hc      *http.Client
	filters []types.Filter
}

// NewBulk returns the store of the bulk loader b. Close it when the load is
// done.
func NewBulk(ctx context.Context, b secrets.AWSBulk) (*Bulk, error) {
	hc := storeHTTPClient()
	sm, err := newClient(ctx, b.AWSConn, hc)
	if err != nil {
		return nil, err
	}
	return &Bulk{sm: sm, hc: hc, filters: Filters(b.PrefixesFilter, b.Tags)}, nil
}

// Close closes the store's idle connections.
func (b *Bulk) Close() { b.hc.CloseIdleConnections() }

// Filters are the ListSecrets filters of name prefixes and tags, as
// Web3Signer builds them: one name filter with every prefix, one tag-key
// filter with every key, and one tag-value filter with every non-empty
// value. AWS ORs the values of a filter and ANDs the filters.
func Filters(prefixes []string, tags []secrets.Tag) []types.Filter {
	var out []types.Filter
	if len(prefixes) > 0 {
		out = append(out, types.Filter{Key: types.FilterNameStringTypeName, Values: prefixes})
	}
	if len(tags) > 0 {
		var keys, values []string
		for _, t := range tags {
			keys = append(keys, t.Key)
			if t.Value != "" {
				values = append(values, t.Value)
			}
		}
		out = append(out, types.Filter{Key: types.FilterNameStringTypeTagKey, Values: keys})
		if len(values) > 0 {
			out = append(out, types.Filter{Key: types.FilterNameStringTypeTagValue, Values: values})
		}
	}
	return out
}

// List implements secrets.Lister: the names of the secrets the filters
// select, page by page.
func (b *Bulk) List(ctx context.Context) ([]string, error) {
	p := secretsmanager.NewListSecretsPaginator(b.sm, &secretsmanager.ListSecretsInput{Filters: b.filters})
	var names []string
	for p.HasMorePages() {
		page, err := func() (*secretsmanager.ListSecretsOutput, error) {
			ctx, cancel := context.WithTimeout(ctx, callTimeout)
			defer cancel()
			return p.NextPage(ctx)
		}()
		if err != nil {
			return nil, fmt.Errorf("unexpected error during AWS list-secrets operation: %w", err)
		}
		for _, s := range page.SecretList {
			if s.Name != nil {
				names = append(names, *s.Name)
			}
		}
	}
	return names, nil
}

// Get implements secrets.Lister.
func (b *Bulk) Get(ctx context.Context, name string) ([]byte, error) { return get(ctx, b.sm, name) }
