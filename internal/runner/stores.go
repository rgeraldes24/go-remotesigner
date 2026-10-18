// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
)

// stores are the secret-store clients of a run: the fetchers of the
// key-config documents' secrets, by kind, and the bulk loaders that are
// enabled. newStores, in stores_full.go and stores_consensus.go, builds
// them from the flavour's clients.
type stores struct {
	fetch secrets.Stores
	// bulk opens the store of each enabled bulk loader, by kind, for one
	// load; the returned function releases it.
	bulk  map[string]func(ctx context.Context) (secrets.Lister, func(), error)
	close func()
}

// vaultClients is the number of HTTP clients kept for HashiCorp Vault
// servers.
const vaultClients = 16
