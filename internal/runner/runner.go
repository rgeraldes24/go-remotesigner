// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package runner runs `remotesigner consensus`: it applies the process
// hygiene, binds the network, applies the startup fail-safes and the
// signing self-test, opens the slashing-protection store, loads the TLS
// configuration and the token files, starts the API listener and, when
// enabled, the metrics listener, loads the keys in the background, reloads
// the token and TLS files on SIGHUP, and shuts everything down in order
// when its context ends.
package runner

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/consensus"
	"github.com/rgeraldes24/go-remotesigner/internal/api/ops"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/policy"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/hygiene"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keyconfig"
	"github.com/rgeraldes24/go-remotesigner/internal/metrics"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
	"github.com/rgeraldes24/go-remotesigner/internal/randao"
	"github.com/rgeraldes24/go-remotesigner/internal/server"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
	"github.com/rgeraldes24/go-remotesigner/internal/server/tlsconf"
	"github.com/rgeraldes24/go-remotesigner/internal/signer"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/memstore"
)

// ShutdownTimeout bounds how long in-flight requests may run after SIGTERM.
const ShutdownTimeout = 10 * time.Second

// Run runs the signer until ctx ends, then shuts down gracefully and returns
// nil. A value on hup re-reads the token files and the TLS files. Any error
// returned before the listeners are up is a startup refusal.
func Run(ctx context.Context, cfg *config.Config, log *logrus.Logger, hup <-chan struct{}) error {
	if err := applyHygiene(cfg.Hygiene, log); err != nil {
		return err
	}
	n, err := network.Load(cfg.Consensus.Network)
	if err != nil {
		return err
	}
	if err := config.CheckFailSafes(cfg, n); err != nil {
		return err
	}
	if err := mldsa87.SelfTest(); err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	pol, err := newPolicy(cfg, n)
	if err != nil {
		return err
	}
	store, err := openStore(cfg, n, pol, log)
	if err != nil {
		return err
	}
	logNetwork(log, n, pol)
	closeStore := func() {
		if err := store.Close(); err != nil {
			log.WithError(err).Error("Closing the slashing-protection store failed")
		}
	}

	// TLS loads after the store opens: the store's lock keeps a second
	// signer on the same data path from generating a certificate too.
	var tlsSrv *tlsconf.Server
	authCfg := auth.Config{
		Mode:           cfg.HTTP.AuthMode,
		SignTokenFile:  cfg.SignTokenFile(),
		AdminTokenFile: cfg.AdminTokenFile(),
	}
	if cfg.TLS.Enabled() {
		tlsSrv, err = tlsconf.New(cfg.TLS, tlsconf.Options{
			SelfSignedDir:     cfg.SelfSignedTLSPath(),
			SelfSignedHosts:   cfg.HTTP.HostAllowlist,
			RequireClientCert: cfg.HTTP.AuthMode.ClientCerts(),
		})
		if err != nil {
			closeStore()
			return fmt.Errorf("refusing to start: TLS: %w", err)
		}
		logTLS(log, cfg, tlsSrv.Info(), false)
		authCfg.VerifyClient = tlsSrv.VerifyClient
	}
	if cfg.Metrics.Enabled {
		authCfg.MetricsTokenFile = cfg.Metrics.AuthTokenFile
	}
	authn, err := auth.New(authCfg)
	if err != nil {
		closeStore()
		return err
	}
	if cfg.Consensus.KeyManagerAPIEnabled {
		log.Warn("--key-manager-api-enabled: this release has no keymanager API; the flag only requires an admin token")
	}

	keys := provider.New(log)
	m, err := metrics.New(metrics.Config{Version: cfg.Version, SignersLoaded: keys.Len})
	if err != nil {
		closeStore()
		return fmt.Errorf("metrics: %w", err)
	}
	engine := slashing.NewEngine(store)
	sig := signer.New(signer.Config{
		Lookup: func(id signer.ID) (signer.Key, bool) {
			k, ok := keys.Get(id)
			if !ok {
				return nil, false
			}
			return k, true
		},
		SelectionProofMode: cfg.Consensus.SelectionProofMode,
		Metrics:            m,
		Log:                log,
		CacheTTL:           signer.CacheTTL(n.Config.SecondsPerSlot, n.Config.SlotsPerEpoch),
	})
	reveals := newReveals(cfg, n, store, m, log)
	loads := &loadState{}
	reloader := ops.NewReloader(loadKeys(cfg.KeyConfigPath, keys, engine, sig, reveals, loads, log), log)
	var ready atomic.Bool

	sign := &consensus.Sign{Policy: pol, Signer: sig, Pinner: store, Metrics: m, Log: log}
	if cfg.Consensus.SlashingProtectionEnabled {
		sign.Protector = engine
	}
	reveal := &consensus.RandaoReveal{Policy: pol, Signer: sig, Reveals: reveals, Pinner: store, Metrics: m, Log: log}
	var serverTLS *tls.Config
	if tlsSrv != nil {
		serverTLS = tlsSrv.TLSConfig()
	}
	srv, err := server.New(server.Config{
		Addr:           cfg.ListenAddr(),
		TLS:            serverTLS,
		HostAllowlist:  cfg.HTTP.HostAllowlist,
		Auth:           authn,
		Routes:         routes(cfg, n, pol, authn, keys, store, sign, reveal, loads, reloader, ready.Load, log),
		Ready:          ready.Load,
		MaxConnections: cfg.HTTP.MaxConnections,
		ReadTimeout:    server.ReadTimeout(n.Config.SecondsPerSlot),
		WriteTimeout:   server.WriteTimeout(n.Config.SecondsPerSlot),
		IdleTimeout:    cfg.HTTP.IdleTimeout,
		AccessLogs:     cfg.HTTP.AccessLogs,
		Log:            log,
		Registerer:     m.Registry,
	})
	if err == nil {
		err = srv.Listen()
	}
	if err != nil {
		reveals.Close()
		closeStore()
		return err
	}
	var ml *metrics.Listener
	if cfg.Metrics.Enabled {
		ml = metrics.NewListener(metrics.ListenerConfig{
			Addr: cfg.Metrics.Addr(), HostAllowlist: cfg.Metrics.HostAllowlist, Gatherer: m.Registry, Auth: authn, Log: log,
		})
		if err := ml.Listen(); err != nil {
			_ = srv.Shutdown(context.Background())
			reveals.Close()
			closeStore()
			return err
		}
	}
	portsFile := ""
	if cfg.DataPath != "" {
		metricsPort := 0
		if ml != nil {
			metricsPort = ml.Addr().Port
		}
		if portsFile, err = server.WritePortsFile(cfg.DataPath, srv.Addr().Port, metricsPort); err != nil {
			log.WithError(err).Warn("Could not write the ports file")
		}
	}
	served, serving := make(chan error, 2), 1
	go func() { served <- srv.Serve() }()
	if ml != nil {
		serving++
		go func() { served <- ml.Serve() }()
		log.WithFields(logrus.Fields{
			"address": ml.Addr().String(), "token": cfg.Metrics.AuthTokenFile != "",
		}).Info("Metrics listener is listening")
	}
	tlsStatus := "disabled"
	if tlsSrv != nil {
		tlsStatus = "enabled"
	}
	log.WithFields(logrus.Fields{
		"address":   srv.Addr().String(),
		"auth-mode": cfg.HTTP.AuthMode,
		"tls":       tlsStatus,
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
			if tlsSrv != nil {
				if info, err := tlsSrv.Reload(); err != nil {
					log.WithError(err).Error("Reloading the TLS files failed; the previous certificate and client trust stay in force")
				} else {
					logTLS(log, cfg, info, true)
				}
			}
		case serveErr = <-served:
			serving--
			log.WithError(serveErr).Error("A listener failed")
			break loop
		}
	}

	log.Info("Shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer cancel()
	if ml != nil {
		if err := ml.Shutdown(shutdownCtx); err != nil {
			log.WithError(err).Warn("The metrics listener did not stop in time")
		}
	}
	err = srv.Shutdown(shutdownCtx)
	if err != nil {
		log.WithError(err).Warn("In-flight requests did not finish in time")
	}
	for ; serving > 0; serving-- {
		if e := <-served; serveErr == nil {
			serveErr = e
		}
	}
	reloader.Close()
	reveals.Close()
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

// applyHygiene applies --disable-core-dumps and --mlock-all before anything
// secret is in memory.
func applyHygiene(h hygiene.Config, log *logrus.Logger) error {
	if err := hygiene.Apply(h); err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	if !hygiene.Supported {
		if h.MlockAll {
			log.Warnf("--mlock-all has no effect on %s; it locks memory on Linux only", runtime.GOOS)
		}
		return nil
	}
	f := logrus.Fields{"core-dumps-disabled": h.DisableCoreDumps, "memory-locked": h.MlockAll}
	if dumpable, core, err := hygiene.State(); err == nil {
		f["dumpable"], f["core-limit"] = dumpable, core
	}
	log.WithFields(f).Info("Process hygiene applied")
	return nil
}

// logTLS records the TLS configuration at startup and after each reload:
// where the certificate comes from, its SHA-256 fingerprint (for pinning)
// and how clients are checked.
func logTLS(log *logrus.Logger, cfg *config.Config, info tlsconf.Info, reloaded bool) {
	f := logrus.Fields{
		"source":             info.Source,
		"certificate":        info.Path,
		"sha256-fingerprint": info.Fingerprint.String(),
		"not-after":          info.NotAfter.UTC().Format(time.RFC3339),
		"client-auth":        info.ClientAuth,
	}
	if info.ClientAuth != tlsconf.ClientAuthNone {
		f["known-clients"], f["client-cas"] = info.KnownClients, info.ClientCAs
	}
	switch {
	case info.Generated:
		log.WithFields(f).Info("Generated a self-signed TLS certificate: give its file to the validator client " +
			"(--validators-external-signer-tls-ca-file) and compare the fingerprint")
	case reloaded:
		log.WithFields(f).Info("TLS files reloaded")
	default:
		log.WithFields(f).Info("TLS enabled")
	}
	if len(info.Uncovered) > 0 {
		log.WithField("names", strings.Join(info.Uncovered, ",")).Warnf("The self-signed TLS certificate is not valid "+
			"for these --http-host-allowlist names, so clients connecting by them fail hostname verification; delete %s "+
			"to generate a new one, then pin it again in every client", filepath.Dir(info.Path))
	}
	if cfg.TLS.GenerateSelfSigned && info.Source != tlsconf.SourceSelfSigned && !reloaded {
		log.Info("--tls-generate-self-signed has no effect: a certificate is configured")
	}
}

// newPolicy builds the request policy from the consensus flags, loading
// the fee-recipient pins when a file is given.
func newPolicy(cfg *config.Config, n *network.Network) (*policy.Policy, error) {
	pc := policy.Config{
		Network:               n,
		ClockSkewSlots:        cfg.Consensus.ClockSkewSlots,
		VoluntaryExitsEnabled: cfg.Consensus.VoluntaryExitsEnabled,
	}
	if f := cfg.Consensus.FeeRecipientFile; f != "" {
		pins, err := policy.LoadFeeRecipientPins(f)
		if err != nil {
			return nil, fmt.Errorf("refusing to start: --registration-fee-recipient-file: %w", err)
		}
		pc.FeeRecipients = pins
	}
	return policy.New(pc)
}

// openStore opens the bbolt store, or a memory store when protection is
// disabled (CheckFailSafes has allowed that only on loopback). A store
// pinned to a GVR binds the policy to it.
func openStore(cfg *config.Config, n *network.Network, pol *policy.Policy, log *logrus.Logger) (slashing.Store, error) {
	if !cfg.Consensus.SlashingProtectionEnabled {
		log.Error("SLASHING PROTECTION IS DISABLED: blocks and attestations are signed without any slashing check. " +
			"This is allowed only because every listener is loopback.")
		log.Warn("RANDAO frontiers are kept in memory only: after a restart every key's next reveal is a first use " +
			"(set --randao-protection-required to refuse this)")
		return memstore.New(), nil
	}
	path := cfg.SlashingProtectionDB()
	if cfg.Consensus.SlashingProtectionDBMigrate {
		if err := migrateStore(path, log); err != nil {
			return nil, err
		}
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
	store, err := boltstore.Open(path, opts)
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

// migrateStore upgrades an existing store file before it is opened
// (--slashing-protection-db-migrate); a missing file is created current by
// Open.
func migrateStore(path string, log *logrus.Logger) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	m, err := boltstore.Migrate(path)
	if err != nil {
		return fmt.Errorf("refusing to start: --slashing-protection-db-migrate: %w", err)
	}
	if m.From != m.To {
		log.WithFields(logrus.Fields{"from": m.From, "to": m.To, "backup": m.Backup}).
			Warn("Slashing-protection store migrated")
	}
	return nil
}

// newReveals builds the RANDAO reveal service over the store and logs the
// effective new-layer rate.
func newReveals(cfg *config.Config, n *network.Network, store slashing.Store, m *metrics.Metrics,
	log *logrus.Logger) *randao.Service {
	rc := cfg.Consensus.Randao
	interval := rc.FullScanMinInterval
	if interval == 0 {
		interval = time.Duration(n.Config.SecondsPerSlot) * time.Second
	}
	s := randao.New(randao.Config{
		Store:                store,
		GenesisTime:          n.GenesisTime,
		GenesisKnown:         n.GenesisTimeKnown(),
		SecondsPerSlot:       n.Config.SecondsPerSlot,
		SlotsPerEpoch:        n.Config.SlotsPerEpoch,
		ClockSkewSlots:       cfg.Consensus.ClockSkewSlots,
		MaxLayers:            rc.MaxLayers,
		ReorgWindow:          rc.ReorgWindow,
		FullScanMinInterval:  interval,
		NewLayerBurst:        rc.NewLayerBurst,
		NewLayerRefillEpochs: rc.NewLayerRefillEpochs,
		Metrics:              m,
		Log:                  log,
	})
	f := logrus.Fields{"max-layers": rc.MaxLayers, "reorg-window": rc.ReorgWindow, "full-scan-min-interval": interval}
	if p := s.RefillPeriod(); p > 0 {
		f["new-layer-burst"] = rc.NewLayerBurst
		f["new-layer-refill"] = p
		log.WithFields(f).Infof("RANDAO reveals: at most %d new layers per key in a burst, then one per %s", rc.NewLayerBurst, p)
	} else {
		log.WithFields(f).Info("RANDAO reveals: the per-key new-layer bucket is off (one new layer per slot)")
	}
	if !n.GenesisTimeKnown() {
		log.Error("RANDAO: genesis time is unknown, so no new layer can be released and capabilities reports " +
			"randao_reveal false; set --network-genesis-time or --network-genesis-state")
	}
	return s
}

// loadState is what the keys-check/config-files-loading health check reads.
type loadState struct {
	done   atomic.Bool
	failed atomic.Bool
	errors atomic.Int64
}

// loadKeys returns the reloader's load function: read the key-config
// directory, then apply it to the provider, registering new keys in
// slashing protection first. Quarantined keys are renewed from the fresh
// load, which lifts their quarantine.
func loadKeys(dir string, keys *provider.Provider, engine *slashing.Engine, sig *signer.Signer, reveals *randao.Service,
	st *loadState, log *logrus.Logger) ops.LoadFunc {
	return func(ctx context.Context) (int, error) {
		errs, err := loadOnce(ctx, dir, keys, engine, sig, reveals, log)
		st.errors.Store(int64(errs))
		st.failed.Store(err != nil)
		st.done.Store(true)
		return errs, err
	}
}

func loadOnce(ctx context.Context, dir string, keys *provider.Provider, engine *slashing.Engine, sig *signer.Signer,
	reveals *randao.Service, log *logrus.Logger) (int, error) {
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
	d, err := keys.Apply(batches, func(pks [][]byte) error { return engine.RegisterValidators(ctx, pks) }, sig.Quarantined)
	if err != nil {
		return d.Errors, fmt.Errorf("register keys in slashing protection: %w", err)
	}
	var ids []slashing.KeyID
	for pk := range keys.PublicKeys() {
		ids = append(ids, slashing.KeyID(pk.ID()))
	}
	if err := reveals.Track(ctx, ids); err != nil {
		log.WithError(err).Error("Reading the RANDAO frontiers of the loaded keys failed")
	}
	quarantined := sig.Release()
	log.WithFields(logrus.Fields{
		"loaded": keys.Len(), "added": d.Added, "removed": d.Removed, "renewed": d.Renewed, "errors": d.Errors,
		"quarantined": quarantined,
	}).Info("Keys loaded")
	return d.Errors, nil
}

func routes(cfg *config.Config, n *network.Network, pol *policy.Policy, authn *auth.Authenticator,
	keys *provider.Provider, store slashing.Store, sign *consensus.Sign, reveal *consensus.RandaoReveal,
	loads *loadState, reloader *ops.Reloader, ready func() bool, log *logrus.Logger) []server.Route {
	protection := consensus.ProtectionBolt
	if !cfg.Consensus.SlashingProtectionEnabled {
		protection = consensus.ProtectionDisabled
	}
	caps := consensus.Capabilities{
		Network:               n,
		Types:                 pol.EnabledTypes,
		GenesisValidatorsRoot: pol.GenesisValidatorsRoot,
		SelectionProofMode:    cfg.Consensus.SelectionProofMode.String(),
		SlashingProtection:    protection,
	}
	checks := []ops.Check{{ID: ops.CheckDefault, Run: func(context.Context) (bool, map[string]any) { return true, nil }}}
	// Like Web3Signer, the store check exists only when there is a store:
	// with protection disabled (loopback only) it is left out rather than
	// reported DOWN, which would fail /healthcheck forever.
	if cfg.Consensus.SlashingProtectionEnabled {
		checks = append(checks, ops.Check{ID: ops.CheckSlashingProtection, Run: func(ctx context.Context) (bool, map[string]any) {
			_, err := store.SchemaVersion(ctx)
			return err == nil, nil
		}})
	}
	checks = append(checks, ops.Check{ID: ops.CheckConfigFilesLoading, Run: func(context.Context) (bool, map[string]any) {
		errs := loads.errors.Load()
		up := loads.done.Load() && !loads.failed.Load() && errs == 0
		return up, map[string]any{"keys-loaded": keys.Len(), "error-count": errs}
	}})
	checks = append(checks, ops.Check{ID: ops.CheckRandao, Run: randaoCheck(n, reveal.Reveals)})

	rs := []server.Route{
		{Method: http.MethodGet, Pattern: "/upcheck", Scope: auth.ScopeNone, Handler: ops.Upcheck(ready)},
		{Method: http.MethodGet, Pattern: "/healthcheck", Scope: auth.ScopeNone,
			Handler: ops.Healthcheck(checks, func(r *http.Request) bool { return authn.Allows(r, auth.ScopeSign) })},
		{Method: http.MethodGet, Pattern: "/api/v1/consensus/publicKeys", Scope: auth.ScopeSign, NeedsReady: true,
			WriteTimeout: consensus.PublicKeysWriteTimeout, Handler: consensus.PublicKeys(keys.PublicKeys)},
		{Method: http.MethodGet, Pattern: "/api/v1/consensus/capabilities", Scope: auth.ScopeSign, NeedsReady: true,
			Handler: caps.Handler()},
		{Method: http.MethodPost, Pattern: "/api/v1/consensus/sign/{identifier}", Scope: auth.ScopeSign, NeedsReady: true,
			BodyLimit: consensus.SignBodyLimit, ReadsBody: true, Handler: sign},
		{Method: http.MethodPost, Pattern: "/api/v1/consensus/randao_reveal/{identifier}", Scope: auth.ScopeSign,
			NeedsReady: true, BodyLimit: consensus.RandaoBodyLimit, ReadsBody: true, Handler: reveal},
		{Method: http.MethodGet, Pattern: "/reload", Scope: auth.ScopeSign, Handler: reloader.StatusHandler()},
	}
	if authn.HasAdmin() {
		reset := &consensus.RandaoReset{Log: log}
		if cfg.Consensus.SlashingProtectionEnabled {
			reset.Reveals = reveal.Reveals
		}
		rs = append(rs,
			server.Route{Method: http.MethodPost, Pattern: "/reload", Scope: auth.ScopeAdmin,
				Handler: reloader.StartHandler(log)},
			server.Route{Method: http.MethodDelete, Pattern: "/api/v1/consensus/randao_state/{identifier}",
				Scope: auth.ScopeAdmin, Handler: reset})
	}
	return rs
}

// randaoCheck is keys-check/randao: DOWN when no new layer can be released
// (genesis time unknown) or a loaded key has fewer than
// randao.LowLayersThreshold layers left. Every key this release loads holds
// its seed, so keys-without-seed is always 0.
func randaoCheck(n *network.Network, reveals *randao.Service) func(context.Context) (bool, map[string]any) {
	return func(context.Context) (bool, map[string]any) {
		data := map[string]any{"keys-without-seed": 0}
		up := n.GenesisTimeKnown()
		if least, ok := reveals.MinLayersRemaining(); ok {
			data["min-layers-remaining"] = least
			up = up && least >= randao.LowLayersThreshold
		}
		return up, data
	}
}

// logNetwork records the chain binding at startup, once the store has had
// its say on the GVR, and warns about what is not bound yet.
func logNetwork(log *logrus.Logger, n *network.Network, pol *policy.Policy) {
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
	gvr, pinned := pol.GenesisValidatorsRoot()
	if pinned {
		f["genesis-validators-root"] = hexRoot(gvr)
	} else {
		f["genesis-validators-root"] = "pending pin (trust on first use)"
	}
	if n.GenesisTimeKnown() {
		f["genesis-time"] = n.GenesisTime
	} else {
		f["genesis-time"] = "unknown"
	}
	log.WithFields(f).Info("Network bound")
	if !pinned {
		log.Warn("The genesis validators root is not configured: it will be pinned from the first signing request " +
			"(trust on first use); set --network-genesis-validators-root or --network-genesis-state to bind it now")
	}
	if !n.GenesisTimeKnown() {
		log.Warn("Genesis time is unknown: signing wall-clock bounds are off and no RANDAO layer can be released; " +
			"set --network-genesis-time or --network-genesis-state")
	}
}

func hexRoot(r [32]byte) string { return "0x" + hex.EncodeToString(r[:]) }
