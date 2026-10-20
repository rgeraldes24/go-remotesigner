// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package secrets loads validator seeds from remote secret stores:
// HashiCorp Vault's KV version 2 engine, AWS Secrets Manager, GCP Secret
// Manager and Azure Key Vault secrets. The stores hold seeds only; signing
// always happens in this process.
//
// A store is reached in two ways, as in Web3Signer:
//
//   - a key-config document names one secret (types hashicorp, aws-secret,
//     azure-secret and gcp-secret); its value is one seed (Spec, Fetcher);
//   - a bulk loader lists the secrets of a store, filtered by name prefix,
//     tags or a filter expression, and loads every one; each value holds
//     one seed per line (Bulk, Lister).
//
// This package holds what the stores share and needs no cloud SDK: the
// seed formats of each signer mode (ParseSeed), the description of each
// secret (the Spec types), the bulk loader, the HTTP client every
// store's requests go through (a timeout, no redirects, a bounded
// response) and a bounded client cache. The stores themselves are in
// sub-packages: hashicorp (net/http only, in both flavours) and awssm,
// gcpsm and azurekv (their vendors' SDKs, in the default flavour only).
//
// Values are wiped once their seeds are decoded, and their seeds once the
// keys are derived, where the clients hand them over as bytes. No error
// of this package or of the stores quotes a secret value or a credential.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Store kinds.
const (
	KindHashicorp = "hashicorp"
	KindAWS       = "aws"
	KindAzure     = "azure"
	KindGCP       = "gcp"
)

// Limits on every fetch.
const (
	// MaxValueSize bounds a secret value: Secrets Manager and Secret
	// Manager store at most 64 KiB, Key Vault 25 KB. A bulk secret of
	// 0x-prefixed seeds holds at most 661 of them.
	MaxValueSize = 64 << 10
	// MaxResponseSize bounds one HTTP response or gRPC message of a store:
	// a secret, or one page of a listing.
	MaxResponseSize = 4 << 20
	// DefaultTimeout bounds one request to AWS Secrets Manager or GCP
	// Secret Manager, which Web3Signer gives no timeout option. Vault and
	// Azure requests take theirs from the configuration.
	DefaultTimeout = 30 * time.Second
)

// Errors. Callers match them with errors.Is.
var (
	// ErrNotFound: the store has no such secret, or it has no value.
	ErrNotFound = errors.New("secret not found")
	// ErrTooLarge: a value or response is larger than its limit.
	ErrTooLarge = errors.New("too large")
	// ErrConfig: the description of a secret or store is invalid.
	ErrConfig = errors.New("invalid secret store configuration")
	// ErrUnavailable: this build has no client for the store.
	ErrUnavailable = errors.New("secret store not available in this build")
)

// Spec describes one secret, as a key-config document names it.
type Spec interface {
	// Kind is the store kind, one of the Kind constants.
	Kind() string
	// Describe names the secret in errors and logs: never a credential.
	Describe() string
}

// Fetcher fetches the value of one secret.
type Fetcher interface {
	// Fetch returns the latest value of the secret s describes, at most
	// MaxValueSize bytes. The caller wipes it.
	Fetch(ctx context.Context, s Spec) ([]byte, error)
}

// Lister is a store a bulk loader reads.
type Lister interface {
	// List returns the names of the secrets to load.
	List(ctx context.Context) ([]string, error)
	// Get returns the latest value of the secret name, at most
	// MaxValueSize bytes. The caller wipes it.
	Get(ctx context.Context, name string) ([]byte, error)
}

// Stores is a Fetcher that hands each Spec to the store of its kind.
type Stores map[string]Fetcher

// Fetch fetches s from the store of its kind. A store client that panics
// fails the fetch instead of the process: a store's responses are remote
// input.
func (st Stores) Fetch(ctx context.Context, s Spec) (value []byte, err error) {
	f, ok := st[s.Kind()]
	if !ok {
		return nil, fmt.Errorf("%s: %w", s.Describe(), ErrUnavailable)
	}
	defer recoverInto(&err)
	return f.Fetch(ctx, s)
}

// recoverInto turns a panic into an error.
func recoverInto(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("secret store client panicked: %v", r)
	}
}

// CheckSize fails a value larger than MaxValueSize.
func CheckSize(n int) error {
	if n > MaxValueSize {
		return fmt.Errorf("secret value: %w: more than %d bytes", ErrTooLarge, MaxValueSize)
	}
	return nil
}
