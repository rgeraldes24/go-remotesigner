// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"errors"
	"log/slog"
)

// ErrSecretMarshal is returned when a Secret is marshalled to JSON.
var ErrSecretMarshal = errors.New("logging: a secret cannot be marshalled")

// Secret holds secret bytes, such as a bearer token. Every way of printing it
// yields Redacted, and marshalling it to JSON fails, so it cannot reach a log
// or a response by accident.
type Secret []byte

// String returns Redacted.
func (Secret) String() string { return Redacted }

// GoString returns Redacted, for %#v.
func (Secret) GoString() string { return Redacted }

// LogValue returns Redacted, for log/slog.
func (Secret) LogValue() slog.Value { return slog.StringValue(Redacted) }

// MarshalJSON always fails.
func (Secret) MarshalJSON() ([]byte, error) { return nil, ErrSecretMarshal }

// MarshalText always fails, so encoders that fall back to text cannot leak
// the value either.
func (Secret) MarshalText() ([]byte, error) { return nil, ErrSecretMarshal }
