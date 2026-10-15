// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package runner runs `remotesigner consensus`: it binds the network, applies
// the startup fail-safes, opens the slashing-protection store, loads the
// token files, starts the API listener, loads the keys in the background
// and shuts everything down in order when its context ends.
package runner

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/consensus"
	"github.com/rgeraldes24/go-remotesigner/internal/api/ops"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/policy"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keyconfig"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
	"github.com/rgeraldes24/go-remotesigner/internal/server"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
)

// ShutdownTimeout bounds how long in-flight requests may run after SIGTERM.
const ShutdownTimeout = 10 * time.Second

// Run runs the signer until ctx ends, then shuts down gracefully and returns
// nil. A value on hup re-reads the token files. Any error returned before
// the listener is up is a startup refusal.
func Run(ctx context.Context, cfg *config.Config, log *logrus.Logger, hup <-chan struct{}) error {
	n, err := network.Load(cfg.Consensus.Network)
	if err != nil {
		return err
	}
	if err := config.CheckFailSafes(cfg, n); err != nil {
		return err
	}
	pol, err := policy.New(policy.Config{Network: n, ClockSkewSlots: policy.DefaultClockSkewSlots})
	if err != nil {
		return err
	}
	logNetwork(log, n)

	store, err := openStore(cfg, n, pol, log)
	if err != nil {
		return err
	}
	closeStore := func() {
		if err := store.Close(); err != nil {
			log.WithError(err).Error("Closing the slashing-protection store failed")
		}
	}

	authn, err := auth.New(auth.Config{
		Mode:           cfg.HTTP.AuthMode,
		SignTokenFile:  cfg.SignTokenFile(),
		AdminTokenFile: cfg.AdminTokenFile(),
	})
	if err != nil {
		closeStore()
		return err
	}
	if cfg.Consensus.KeyManagerAPIEnabled {
		log.Warn("--key-manager-api-enabled: this release has no keymanager API; the flag only requires an admin token")
	}

	keys := provider.New(log)
	loads := &loadState{}
	reloader := ops.NewReloader(loadKeys(cfg.KeyConfigPath, keys, store, loads, log), log)
	var ready atomic.Bool

	srv, err := server.New(server.Config{
		Addr:           cfg.ListenAddr(),
		HostAllowlist:  cfg.HTTP.HostAllowlist,
		Auth:           authn,
		Routes:         routes(cfg, n, pol, authn, keys, store, loads, reloader, ready.Load, log),
		Ready:          ready.Load,
		MaxConnections: cfg.HTTP.MaxConnections,
		ReadTimeout:    server.ReadTimeout(n.Config.SecondsPerSlot),
		WriteTimeout:   server.WriteTimeout(n.Config.SecondsPerSlot),
		IdleTimeout:    cfg.HTTP.IdleTimeout,
		AccessLogs:     cfg.HTTP.AccessLogs,
		Log:            log,
	})
	if err == nil {
		err = srv.Listen()
	}
	if err != nil {
		closeStore()
		return err
	}
	portsFile := ""
	if cfg.DataPath != "" {
		if portsFile, err = server.WritePortsFile(cfg.DataPath, srv.Addr().Port); err != nil {
			log.WithError(err).Warn("Could not write the ports file")
		}
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()
	log.WithFields(logrus.Fields{
		"address":   srv.Addr().String(),
		"auth-mode": cfg.HTTP.AuthMode,
		"tls":       "disabled",
	}).Info("remotesigner is listening; loading keys")

	initial := reloader.Start()
	go func() {
		<-initial
		ready.Store(true)
		log.WithField("keys", keys.Len()).Info("remotesigner is ready")
	}()

	var serveErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-hup:
			if err := authn.Reload(); err != nil {
				log.WithError(err).Error("Reloading the token files failed; the previous tokens stay in force")
			} else {
				log.Info("Token files reloaded")
			}
		case serveErr = <-served:
			log.WithError(serveErr).Error("The API listener failed")
			break loop
		}
	}

	log.Info("Shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()
	err = srv.Shutdown(shutdownCtx)
	if err != nil {
		log.WithError(err).Warn("In-flight requests did not finish in time")
	}
	if serveErr == nil {
		serveErr = <-served
	}
	reloader.Close()
	if errors.Is(err, server.ErrHandlersRunning) {
		// A handler may still use the store or a key; the process exit
		// releases both (bbolt is crash-safe).
		log.Error("Request handlers are still running; the process exits without closing the slashing-protection store")
	} else {
		closeStore()
		keys.Close()
	}
	if portsFile != "" {
		_ = os.Remove(portsFile)
	}
	log.Info("Shutdown complete")
	return serveErr
}

// openStore opens the bbolt store, or a memory store when protection is
// disabled (CheckFailSafes has allowed that only on loopback). A store
// pinned to a GVR binds the policy to it.
func openStore(cfg *config.Config, n *network.Network, pol *policy.Policy, log *logrus.Logger) (slashing.Store, error) {
	if !cfg.Consensus.SlashingProtectionEnabled {
		log.Error("SLASHING PROTECTION IS DISABLED: blocks and attestations are signed without any slashing check. " +
			"This is allowed only because every listener is loopback.")
		return memstore.New(), nil
	}
	opts := boltstore.Options{OnPin: func(gvr slashing.Root) {
		if err := pol.PinGenesisValidatorsRoot(gvr); err != nil {
			log.WithError(err).Error("The store pinned a genesis validators root the policy refused")
		}
	}}
	if n.GVRKnown() {
		gvr := slashing.Root(n.GenesisValidatorsRoot)
		opts.GenesisValidatorsRoot = &gvr
	}
	store, err := boltstore.Open(cfg.SlashingProtectionDB(), opts)
	if err != nil {
		return nil, err
	}
	gvr, pinned, err := store.GenesisValidatorsRoot(context.Background())
	if err == nil && pinned && !n.GVRKnown() {
		err = pol.PinGenesisValidatorsRoot(gvr)
		log.WithField("genesis-validators-root", hexRoot(gvr)).Info("Genesis validators root pinned by the store")
	}
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

// loadState is what the keys-check/config-files-loading health check reads.
type loadState struct {
	done   atomic.Bool
	failed atomic.Bool
	errors atomic.Int64
}

// loadKeys returns the reloader's load function: read the key-config
// directory, then apply it to the provider, registering new keys in the
// store first.
func loadKeys(dir string, keys *provider.Provider, store slashing.Store, st *loadState, log *logrus.Logger) ops.LoadFunc {
	return func(ctx context.Context) (int, error) {
		errs, err := loadOnce(ctx, dir, keys, store, log)
		st.errors.Store(int64(errs))
		st.failed.Store(err != nil)
		st.done.Store(true)
		return errs, err
	}
}

func loadOnce(ctx context.Context, dir string, keys *provider.Provider, store slashing.Store, log *logrus.Logger) (int, error) {
	var batches []provider.Batch
	if dir == "" {
		log.Warn("No --key-config-path: no keys are loaded")
	} else {
		results, err := keyconfig.Load(ctx, dir)
		if err != nil {
			return 0, err
		}
		for _, r := range results {
			if r.Err != nil {
				log.WithError(r.Err).Error("A key-config file failed to load; its previous keys stay loaded")
			}
			batches = append(batches, provider.Batch{Source: r.Path, Keys: r.Keys, Err: r.Err})
		}
	}
	d, err := keys.Apply(batches, func(pks [][]byte) error { return store.RegisterValidators(ctx, pks) })
	if err != nil {
		return d.Errors, fmt.Errorf("register keys in slashing protection: %w", err)
	}
	log.WithFields(logrus.Fields{
		"loaded": keys.Len(), "added": d.Added, "removed": d.Removed, "errors": d.Errors,
	}).Info("Keys loaded")
	return d.Errors, nil
}

func routes(cfg *config.Config, n *network.Network, pol *policy.Policy, authn *auth.Authenticator,
	keys *provider.Provider, store slashing.Store, loads *loadState, reloader *ops.Reloader,
	ready func() bool, log *logrus.Logger) []server.Route {
	protection := consensus.ProtectionBolt
	if !cfg.Consensus.SlashingProtectionEnabled {
		protection = consensus.ProtectionDisabled
	}
	caps := consensus.Capabilities{
		Network:               n,
		Types:                 pol.EnabledTypes,
		GenesisValidatorsRoot: pol.GenesisValidatorsRoot,
		SelectionProofMode:    mldsa87.Deterministic.String(),
		SlashingProtection:    protection,
	}
	checks := []ops.Check{
		{ID: ops.CheckDefault, Run: func(context.Context) (bool, map[string]any) { return true, nil }},
		{ID: ops.CheckSlashingProtection, Run: func(ctx context.Context) (bool, map[string]any) {
			if !cfg.Consensus.SlashingProtectionEnabled {
				return false, map[string]any{"enabled": false}
			}
			_, err := store.SchemaVersion(ctx)
			return err == nil, nil
		}},
		{ID: ops.CheckConfigFilesLoading, Run: func(context.Context) (bool, map[string]any) {
			errs := loads.errors.Load()
			up := loads.done.Load() && !loads.failed.Load() && errs == 0
			return up, map[string]any{"keys-loaded": keys.Len(), "error-count": errs}
		}},
	}

	rs := []server.Route{
		{Method: http.MethodGet, Pattern: "/upcheck", Scope: auth.ScopeNone, Handler: ops.Upcheck(ready)},
		{Method: http.MethodGet, Pattern: "/healthcheck", Scope: auth.ScopeNone,
			Handler: ops.Healthcheck(checks, func(r *http.Request) bool { return authn.Allows(r, auth.ScopeSign) })},
		{Method: http.MethodGet, Pattern: "/api/v1/consensus/publicKeys", Scope: auth.ScopeSign, NeedsReady: true,
			WriteTimeout: consensus.PublicKeysWriteTimeout, Handler: consensus.PublicKeys(keys.PublicKeys)},
		{Method: http.MethodGet, Pattern: "/api/v1/consensus/capabilities", Scope: auth.ScopeSign, NeedsReady: true,
			Handler: caps.Handler()},
		{Method: http.MethodGet, Pattern: "/reload", Scope: auth.ScopeSign, Handler: reloader.StatusHandler()},
	}
	if authn.HasAdmin() {
		rs = append(rs, server.Route{Method: http.MethodPost, Pattern: "/reload", Scope: auth.ScopeAdmin,
			Handler: reloader.StartHandler(log)})
	}
	return rs
}

// logNetwork records the chain binding at startup.
func logNetwork(log *logrus.Logger, n *network.Network) {
	// DEPOSIT and the builder's registration domain use the genesis fork
	// version and a zero GVR, so they are fixed by the configuration alone.
	v := signingroot.Version(n.Config.GenesisForkVersion)
	deposit := signingroot.ComputeDomain(signingroot.DomainDeposit, v, [32]byte{})
	builder := signingroot.ComputeDomain(signingroot.DomainApplicationBuilder, v, [32]byte{})
	f := logrus.Fields{
		"network":              n.Name,
		"genesis-fork-version": "0x" + hex.EncodeToString(n.Config.GenesisForkVersion[:]),
		"seconds-per-slot":     n.Config.SecondsPerSlot,
		"slots-per-epoch":      n.Config.SlotsPerEpoch,
		"deposit-domain":       hexRoot(deposit),
		"builder-domain":       hexRoot(builder),
	}
	if n.GVRKnown() {
		f["genesis-validators-root"] = hexRoot(n.GenesisValidatorsRoot)
	} else {
		f["genesis-validators-root"] = "pending pin (trust on first use)"
	}
	if n.GenesisTimeKnown() {
		f["genesis-time"] = n.GenesisTime
	} else {
		f["genesis-time"] = "unknown"
	}
	log.WithFields(f).Info("Network bound")
	if !n.GenesisTimeKnown() {
		log.Warn("Genesis time is unknown: signing wall-clock bounds are off and no RANDAO layer can be released; " +
			"set --network-genesis-time or --network-genesis-state")
	}
}

func hexRoot(r [32]byte) string { return "0x" + hex.EncodeToString(r[:]) }
