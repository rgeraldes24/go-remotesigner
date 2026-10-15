// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package slashing

import (
	"context"
	"errors"
	"fmt"
)

// SchemaVersion is the store schema version this build reads and writes. Version 1 is the first schema of every
// backend; each later schema change ships a migration and raises it.
const SchemaVersion uint32 = 1

// Schema-version refusals, matched with errors.Is against the *SchemaError that CheckSchema returns.
var (
	ErrSchemaTooOld = errors.New("slashing: store schema is older than this build")
	ErrSchemaTooNew = errors.New("slashing: store schema is newer than this build")
)

// SchemaError reports a store whose schema version differs from SchemaVersion.
type SchemaError struct {
	Stored   uint32
	Expected uint32
}

func (e *SchemaError) Error() string {
	if e.Stored < e.Expected {
		return fmt.Sprintf("slashing-protection store has schema version %d, this remotesigner expects %d: "+
			"run \"remotesigner consensus migrate\" to upgrade it", e.Stored, e.Expected)
	}
	return fmt.Sprintf("slashing-protection store has schema version %d, written by a newer remotesigner "+
		"(this one expects %d); downgrade is not supported", e.Stored, e.Expected)
}

// Is matches ErrSchemaTooOld or ErrSchemaTooNew.
func (e *SchemaError) Is(target error) bool {
	switch target {
	case ErrSchemaTooOld:
		return e.Stored < e.Expected
	case ErrSchemaTooNew:
		return e.Stored > e.Expected
	}
	return false
}

// CheckSchema is the startup schema-version hook: it returns a *SchemaError unless the store's schema version is
// exactly SchemaVersion. An older store must be migrated first; a newer one is always refused.
func CheckSchema(ctx context.Context, s Store) error {
	v, err := s.SchemaVersion(ctx)
	if err != nil {
		return fmt.Errorf("read slashing-protection schema version: %w", err)
	}
	if v != SchemaVersion {
		return &SchemaError{Stored: v, Expected: SchemaVersion}
	}
	return nil
}
