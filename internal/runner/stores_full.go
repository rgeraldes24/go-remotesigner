// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package runner

import (
	"context"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets/awssm"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets/azurekv"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets/gcpsm"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets/hashicorp"
)

// newStores returns the clients of every secret store: the default flavour
// links the AWS, Azure and GCP SDKs.
func newStores(cfg *config.Config) *stores {
	ss := cfg.Consensus.SecretStores
	hc, aws, az, gcp := hashicorp.New(vaultClients), awssm.New(max(1, ss.AWSClientCacheSize)), azurekv.New(), gcpsm.New()
	st := &stores{
		fetch: secrets.Stores{
			secrets.KindHashicorp: hc,
			secrets.KindAWS:       aws,
			secrets.KindAzure:     az,
			secrets.KindGCP:       gcp,
		},
		bulk:  map[string]func(context.Context) (secrets.Lister, func(), error){},
		close: func() { hc.Close(); aws.Close(); az.Close(); gcp.Close() },
	}
	if b := ss.Azure; b != nil {
		st.bulk[secrets.KindAzure] = func(context.Context) (secrets.Lister, func(), error) {
			store, err := azurekv.NewBulk(*b)
			if err != nil {
				return nil, nil, err
			}
			return store, store.Close, nil
		}
	}
	if b := ss.AWS; b != nil {
		st.bulk[secrets.KindAWS] = func(ctx context.Context) (secrets.Lister, func(), error) {
			store, err := awssm.NewBulk(ctx, *b)
			if err != nil {
				return nil, nil, err
			}
			return store, store.Close, nil
		}
	}
	if b := ss.GCP; b != nil {
		st.bulk[secrets.KindGCP] = func(ctx context.Context) (secrets.Lister, func(), error) {
			store, err := gcpsm.NewBulk(ctx, *b)
			if err != nil {
				return nil, nil, err
			}
			return store, func() { _ = store.Close() }, nil
		}
	}
	return st
}
