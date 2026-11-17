// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build noexecution

package runner

import (
	"context"
	"fmt"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets/hashicorp"
)

// errNoCloudSDK explains a cloud store in the consensus flavour.
var errNoCloudSDK = fmt.Errorf("%w: remotesigner-consensus links no cloud SDK; use the remotesigner flavour",
	secrets.ErrUnavailable)

// unavailable is the store of a kind this flavour has no client for.
type unavailable struct{}

func (unavailable) Fetch(_ context.Context, s secrets.Spec) ([]byte, error) {
	return nil, fmt.Errorf("%s: %w", s.Describe(), errNoCloudSDK)
}

// newStores returns the HashiCorp Vault client, which needs no SDK. The
// AWS, Azure and GCP stores fail every fetch with a hint: their SDKs are
// linked by the default flavour only. The command line refuses their bulk
// loaders before a run starts; a configuration that has one anyway fails
// its every load.
func newStores(cfg *config.Config) *stores {
	hc := hashicorp.New(vaultClients)
	st := &stores{
		fetch: secrets.Stores{secrets.KindHashicorp: hc, secrets.KindAWS: unavailable{}, secrets.KindAzure: unavailable{},
			secrets.KindGCP: unavailable{}},
		bulk:  map[string]func(context.Context) (secrets.Lister, func(), error){},
		close: hc.Close,
	}
	ss := cfg.Consensus.SecretStores
	for kind, on := range map[string]bool{secrets.KindAzure: ss.Azure != nil, secrets.KindAWS: ss.AWS != nil,
		secrets.KindGCP: ss.GCP != nil} {
		if on {
			st.bulk[kind] = func(context.Context) (secrets.Lister, func(), error) { return nil, nil, errNoCloudSDK }
		}
	}
	return st
}
