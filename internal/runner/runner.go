// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package runner runs `remotesigner consensus`: it applies the process
// hygiene, binds the network, applies the startup fail-safes and the
// signing self-test, opens the slashing-protection store, loads the TLS
// configuration and the token files, starts the API listener and, when
// enabled, the metrics listener, loads the keys and prunes the store in the
// background, reloads the token and TLS files on SIGHUP, and shuts
// everything down in order when its context ends.
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
	kmapi "github.com/rgeraldes24/go-remotesigner/internal/api/keymanager"
	"github.com/rgeraldes24/go-remotesigner/internal/api/ops"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/policy"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/signingroot"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/hygiene"
	"github.com/rgeraldes24/go-remotesigner/internal/keymanager"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/argon"
	"github.com/rgeraldes24/go-remotesigner/internal/metrics"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
	"github.com/rgeraldes24/go-remotesigner/internal/randao"
	"github.com/rgeraldes24/go-remotesigner/internal/server"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
	"github.com/rgeraldes24/go-remotesigner/internal/server/tlsconf"
	"github.com/rgeraldes24/go-remotesigner/internal/signer"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
)

// ShutdownTimeout bounds how long in-flight requests may run after SIGTERM.
const ShutdownTimeout = 10 * time.Second

// Run runs the signer until ctx ends, then shuts down gracefully and returns
// nil. A value on hup re-reads the token files and the TLS files. Any error
// returned before the listeners are up is a startup refusal.
func Run(ctx context.Context, cfg *config.Config, log *logrus.Logger, hup <-chan struct{}) error {
	if err := ApplyHygiene(cfg.Hygiene, log); err != nil {
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
	set, err := openStore(ctx, cfg, n, pol, log)
	if err != nil {
		return err
	}
	store := set.store
	logNetwork(log, n, pol)
	closeStore := func() {
		if err := set.close(); err != nil {
			log.WithError(err).Error("Closing the slashing-protection store failed")
		}
	}

	// TLS loads after the store opens. A second signer on the same data
	// path never generates a certificate of its own: tlsconf generates
	// the self-signed one under a lock on its directory, which also holds
	// when the store's lock does not (no store, or a store elsewhere).
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
		LogTLS(log, cfg, tlsSrv.Info(), false)
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
	sem, sizing := argon.Auto(cfg.SignerLoadParallelism)
	LogKeySources(log, cfg, sizing)
	loader := NewKeyLoader(cfg, KeySources{Keystores: cfg.Consensus.Keystores}, sem, keys,
		consensusHooks(keys, engine, sig, reveals, log), log)
	var manager *keymanager.Manager
	if cfg.Consensus.KeyManagerAPIEnabled {
		if manager, err = newKeyManager(cfg, keys, engine, store, pol, sem, loader, log); err != nil {
			reveals.Close()
			closeStore()
			return err
		}
	}
	reloader := ops.NewReloader(loader.Load, log)
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
		Routes:         routes(cfg, n, pol, authn, keys, set, sign, reveal, loader, reloader, manager, ready.Load, log),
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
	var prune *pruner
	if cfg.Consensus.SlashingProtectionEnabled {
		prune = startPruner(set.pruner, cfg.Consensus.Pruning, n.Config.SlotsPerEpoch, set.shared, log)
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
				info, err := tlsSrv.Reload()
				LogTLSReload(log, cfg, info, err)
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
	loader.Close()
	reveals.Close()
	prune.stop()
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

// ApplyHygiene applies --disable-core-dumps and --mlock-all before anything
// secret is in memory.
func ApplyHygiene(h hygiene.Config, log *logrus.Logger) error {
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

// tlsFields are the log fields of a TLS configuration.
func tlsFields(info tlsconf.Info) logrus.Fields {
	f := logrus.Fields{
		"source":             info.Source,
		"certificate":        info.Path,
		"sha256-fingerprint": info.Fingerprint.String(),
		"not-after":          info.NotAfter.UTC().Format(time.RFC3339),
		"client-auth":        info.ClientAuth,
	}
	if info.ClientAuth != tlsconf.ClientAuthNone && info.ClientAuth != tlsconf.ClientAuthRefused {
		f["known-clients"], f["client-cas"] = info.KnownClients, info.ClientCAs
	}
	return f
}

// LogTLSReload records the outcome of a SIGHUP reload of the TLS files. A
// certificate that failed to load leaves the previous one in force; a
// client trust that failed to load refuses every client (tlsconf.Reload).
func LogTLSReload(log *logrus.Logger, cfg *config.Config, info tlsconf.Info, err error) {
	if err == nil {
		LogTLS(log, cfg, info, true)
		return
	}
	var re *tlsconf.ReloadError
	if !errors.As(err, &re) {
		log.WithFields(tlsFields(info)).WithError(err).Error("Reloading the TLS files failed")
		return
	}
	if re.Certificate != nil {
		log.WithFields(tlsFields(info)).WithError(re.Certificate).Error("Reloading the TLS certificate failed; " +
			"the previous certificate stays in force")
	}
	if re.ClientTrust != nil {
		log.WithFields(tlsFields(info)).WithError(re.ClientTrust).Error("Reloading the TLS client trust failed; " +
			"every client certificate is refused, on open connections too, until a reload succeeds")
	} else {
		warnEmptyTrust(log, info)
	}
}

// warnEmptyTrust warns when a reload left a client trust that lists
// nobody: every client is then refused, which is how the last client is
// revoked.
func warnEmptyTrust(log *logrus.Logger, info tlsconf.Info) {
	if info.ClientAuth != tlsconf.ClientAuthNone && info.ClientAuth != tlsconf.ClientAuthRefused &&
		info.KnownClients+info.ClientCAs == 0 {
		log.Warn("The TLS client trust lists no client and no CA: every client certificate is refused")
	}
}

// LogTLS records the TLS configuration at startup and after each reload:
// where the certificate comes from, its SHA-256 fingerprint (for pinning)
// and how clients are checked.
func LogTLS(log *logrus.Logger, cfg *config.Config, info tlsconf.Info, reloaded bool) {
	f := tlsFields(info)
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
	warnEmptyTrust(log, info)
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

func routes(cfg *config.Config, n *network.Network, pol *policy.Policy, authn *auth.Authenticator,
	keys *provider.Provider, set *storeSet, sign *consensus.Sign, reveal *consensus.RandaoReveal,
	loader *KeyLoader, reloader *ops.Reloader, manager *keymanager.Manager, ready func() bool,
	log *logrus.Logger) []server.Route {
	store := set.store
	protection := set.kind
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
	if set.health != nil {
		checks = append(checks, ops.Check{ID: ops.CheckSlashingProtection, Run: func(ctx context.Context) (bool, map[string]any) {
			return set.health(ctx), nil
		}})
	}
	checks = append(checks, loader.Checks()...)
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
		{Method: http.MethodGet, Pattern: "/api/v1/consensus/highWatermark", Scope: auth.ScopeSign,
			Handler: highWatermark(cfg, store, log)},
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
	if manager != nil {
		rs = append(rs, keymanagerRoutes(manager, log)...)
	}
	return rs
}

// keystoresPath is the keymanager API's path, the one the qrysm validator
// client's own keymanager API serves.
const keystoresPath = "/qrl/v1/keystores"

// keymanagerRoutes are the keymanager API's routes (--key-manager-api-enabled),
// all with the admin token. They serve during the startup load too: an
// import or a delete then changes its key at once, and the load cannot undo
// it (provider.ApplySince); the list shows the keys loaded so far.
func keymanagerRoutes(manager *keymanager.Manager, log *logrus.Logger) []server.Route {
	h := &kmapi.Handlers{Manager: manager, Log: log}
	return []server.Route{
		{Method: http.MethodGet, Pattern: keystoresPath, Scope: auth.ScopeAdmin, WriteTimeout: kmapi.WriteTimeout,
			Handler: h.List()},
		{Method: http.MethodPost, Pattern: keystoresPath, Scope: auth.ScopeAdmin, BodyLimit: kmapi.BodyLimit,
			ReadsBody: true, WriteTimeout: kmapi.WriteTimeout, Handler: h.Import()},
		{Method: http.MethodDelete, Pattern: keystoresPath, Scope: auth.ScopeAdmin, BodyLimit: kmapi.BodyLimit,
			ReadsBody: true, WriteTimeout: kmapi.WriteTimeout, Handler: h.Delete()},
	}
}

// newKeyManager readies the key-config directory and returns the keymanager
// over the signer's key set, store and Argon2id semaphore. A directory its
// group or other users can access is a startup refusal under
// --strict-file-permissions.
func newKeyManager(cfg *config.Config, keys *provider.Provider, engine *slashing.Engine, store slashing.Store,
	pol *policy.Policy, sem *argon.Semaphore, loader *KeyLoader, log *logrus.Logger) (*keymanager.Manager, error) {
	dir := cfg.KeyConfigPath
	err := keymanager.PrepareDir(dir, cfg.StrictFilePermissions, func(mode os.FileMode) {
		log.WithFields(logrus.Fields{"directory": dir, "mode": fmt.Sprintf("%04o", mode)}).Warn("The key-config " +
			"directory, where the keymanager writes keystores and password files, is accessible to its group or " +
			"other users; restrict it to its owner (chmod 0700)")
	})
	if err != nil {
		return nil, fmt.Errorf("refusing to start: --key-manager-api-enabled: %w", err)
	}
	return keymanager.New(keymanager.Config{
		Dir:     dir,
		Keys:    keys,
		Engine:  engine,
		Store:   store,
		History: cfg.Consensus.SlashingProtectionEnabled,
		GenesisValidatorsRoot: func() (slashing.Root, bool) {
			gvr, ok := pol.GenesisValidatorsRoot()
			return slashing.Root(gvr), ok
		},
		Decrypt: sem.Decrypt,
		Workers: sem.Procs(),
		Changed: func() { loader.refresh(context.Background()) },
		Log:     log,
	}), nil
}

// highWatermark serves the store's high watermark, or 404 PROTECTION_DISABLED when protection is off: the memory
// store then has no high watermark to report.
func highWatermark(cfg *config.Config, store slashing.Store, log *logrus.Logger) http.Handler {
	h := &consensus.HighWatermark{Log: log}
	if cfg.Consensus.SlashingProtectionEnabled {
		h.Store = store
	}
	return h
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
