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
// keystorage/src/main/java/tech/pegasys/web3signer/keystorage/gcp/GcpSecretManager.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

// Package gcpsm reads seeds from GCP Secret Manager with
// cloud.google.com/go/secretmanager over gRPC, the SDK's default transport,
// as Web3Signer's client does: the latest version of one secret per
// gcp-secret key-config document, and of every secret of a project that a
// bulk loader's filter selects (--gcp-secrets-*).
//
// Credentials are Application Default Credentials: the file
// GOOGLE_APPLICATION_CREDENTIALS names, gcloud's user credentials, or the
// metadata server's service account on GCE, GKE and Cloud Run. Each call
// is bounded by secrets.DefaultTimeout, retries included, and each message
// by secrets.MaxResponseSize. The SDK's logger is replaced by one that
// discards, so GOOGLE_SDK_GO_LOGGING_LEVEL cannot make it log payloads.
//
// An endpoint override of the form http://host:port is an emulator or a
// test fake: it is reached without TLS and without credentials. Any other
// override, host:port, keeps TLS and Application Default Credentials (a
// regional or private endpoint).
package gcpsm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
)

// maxClients is the number of SDK clients a Client keeps, one per
// endpoint.
const maxClients = 4

// Client fetches the secrets of gcp-secret documents, with one SDK client
// per endpoint. It is safe for concurrent use.
type Client struct {
	clients secrets.Cache[string, *secretmanager.Client]
}

// New returns a client.
func New() *Client {
	c := &Client{}
	c.clients.Max = maxClients
	c.clients.Close = func(sm *secretmanager.Client) { _ = sm.Close() }
	return c
}

// Close closes every SDK client.
func (c *Client) Close() { c.clients.Purge() }

// Fetch implements secrets.Fetcher for *secrets.GCP specs.
func (c *Client) Fetch(ctx context.Context, s secrets.Spec) ([]byte, error) {
	g, ok := s.(*secrets.GCP)
	if !ok {
		return nil, fmt.Errorf("gcpsm: %w: not a GCP secret", secrets.ErrConfig)
	}
	sm, err := c.clients.Get(g.EndpointOverride, func() (*secretmanager.Client, error) {
		return newClient(ctx, g.EndpointOverride)
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", g.Describe(), err)
	}
	v, err := access(ctx, sm, g.Resource())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", g.Describe(), err)
	}
	return v, nil
}

// newClient builds an SDK client for the endpoint override ("" is
// Google's endpoint).
func newClient(ctx context.Context, endpoint string) (*secretmanager.Client, error) {
	opts := []option.ClientOption{
		option.WithLogger(slog.New(slog.DiscardHandler)),
		option.WithGRPCDialOption(grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(secrets.MaxResponseSize))),
	}
	switch {
	case strings.HasPrefix(endpoint, "http://"):
		opts = append(opts, option.WithEndpoint(strings.TrimPrefix(endpoint, "http://")), option.WithoutAuthentication(),
			option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())))
	case endpoint != "":
		opts = append(opts, option.WithEndpoint(strings.TrimPrefix(endpoint, "https://")))
	}
	sm, err := secretmanager.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("GCP Secret Manager client: %w", err)
	}
	return sm, nil
}

// access returns the payload of the latest version of the secret resource,
// projects/<project>/secrets/<name>.
func access(ctx context.Context, sm *secretmanager.Client, resource string) ([]byte, error) {
	resp, err := sm.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: resource + "/versions/latest"},
		gax.WithTimeout(secrets.DefaultTimeout))
	switch {
	case status.Code(err) == codes.NotFound:
		return nil, fmt.Errorf("%w: %v", secrets.ErrNotFound, status.Convert(err).Message())
	case err != nil:
		return nil, fmt.Errorf("access the latest version: %w", err)
	case resp.GetPayload() == nil:
		return nil, fmt.Errorf("%w: the latest version has no payload", secrets.ErrNotFound)
	}
	data := resp.GetPayload().GetData()
	defer mldsa87.Wipe(data)
	if err := secrets.CheckSize(len(data)); err != nil {
		return nil, err
	}
	return append([]byte(nil), data...), nil
}

// Bulk is the GCP Secret Manager bulk loader's store.
type Bulk struct {
	sm     *secretmanager.Client
	parent string
	filter string
}

// NewBulk returns the store of the bulk loader b. Close it when done.
func NewBulk(ctx context.Context, b secrets.GCPBulk) (*Bulk, error) {
	if b.ProjectID == "" {
		return nil, fmt.Errorf("%w: no GCP project id", secrets.ErrConfig)
	}
	sm, err := newClient(ctx, b.EndpointOverride)
	if err != nil {
		return nil, err
	}
	return &Bulk{sm: sm, parent: "projects/" + b.ProjectID, filter: b.Filter}, nil
}

// Close closes the SDK client.
func (b *Bulk) Close() error { return b.sm.Close() }

// List implements secrets.Lister: the resource names of the project's
// secrets that the filter selects.
func (b *Bulk) List(ctx context.Context) ([]string, error) {
	it := b.sm.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{Parent: b.parent, Filter: b.filter},
		gax.WithTimeout(secrets.DefaultTimeout))
	var names []string
	for {
		s, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return names, nil
		}
		if err != nil {
			return nil, fmt.Errorf("unexpected error during GCP list-secrets operation: %w", err)
		}
		names = append(names, s.GetName())
	}
}

// Get implements secrets.Lister; name is a secret's resource name.
func (b *Bulk) Get(ctx context.Context, name string) ([]byte, error) { return access(ctx, b.sm, name) }
