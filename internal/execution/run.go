// Copyright 2020 ConsenSys AG.
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
// core/src/main/java/tech/pegasys/web3signer/core/Eth1Runner.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

package execution

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/api/consensus"
	"github.com/rgeraldes24/go-remotesigner/internal/api/ops"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/argon"
	"github.com/rgeraldes24/go-remotesigner/internal/metrics"
	"github.com/rgeraldes24/go-remotesigner/internal/runner"
	"github.com/rgeraldes24/go-remotesigner/internal/server"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
	"github.com/rgeraldes24/go-remotesigner/internal/server/tlsconf"
	"github.com/rgeraldes24/go-remotesigner/internal/signer/provider"
)

// Limits of the JSON-RPC endpoint.
const (
	// BodyLimit is the largest request body, gqrl's own limit: 5 MiB.
	BodyLimit = 5 << 20
	// ReadTimeout bounds reading a request.
	ReadTimeout = 15 * time.Second
	// localWork bounds the signer's own part of a response: a batch of
	// MaxBatch qrl_sign requests takes about a second.
	localWork = 30 * time.Second
)

// WriteTimeout is the endpoint's write timeout: the downstream node's time
// and the signer's own. The server writes nothing after it, and the handler
// ends a request's downstream exchange and local work there too.
func WriteTimeout(downstream time.Duration) time.Duration { return downstream + localWork }

// Run runs `remotesigner execution` until ctx ends, then shuts down
// gracefully and returns nil. It applies the process hygiene and the
// startup fail-safes, runs the signing self-test, prepares the downstream
// client, loads the TLS configuration and the token files, starts the API
// listener and, when enabled, the metrics listener, and loads the account
// keys while it listens. A value on hup re-reads the token and TLS files.
// Any error returned before the listeners are up is a startup refusal.
func Run(ctx context.Context, cfg *config.Config, log *logrus.Logger, hup <-chan struct{}) error {
	if err := runner.ApplyHygiene(cfg.Hygiene, log); err != nil {
		return err
	}
	if err := config.CheckExecutionFailSafes(cfg); err != nil {
		return err
	}
	if err := mldsa87.SelfTest(); err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	allow, err := ParseAllowlist(cfg.Execution.AllowedMethods)
	if err != nil {
		return fmt.Errorf("refusing to start: --execution-proxy-allowed-methods: %w", err)
	}
	ds, err := newDownstream(cfg.Execution.Downstream, runner.SecretPolicy(cfg, log))
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	proxy, closeProxyLog := newProxy(ds, log)
	defer closeProxyLog()
	txs, closeTxs, err := transactionsFrom(cfg, proxy, log)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	defer closeTxs()

	var tlsSrv *tlsconf.Server
	files := runner.ServerFilePolicy(cfg, log)
	authCfg := auth.Config{Mode: cfg.HTTP.AuthMode, SignTokenFile: cfg.SignTokenFile(), AdminTokenFile: cfg.AdminTokenFile(),
		Files: files}
	if cfg.TLS.Enabled() {
		tlsSrv, err = tlsconf.New(cfg.TLS, tlsconf.Options{
			SelfSignedDir:     cfg.SelfSignedTLSPath(),
			SelfSignedHosts:   cfg.HTTP.HostAllowlist,
			RequireClientCert: cfg.HTTP.AuthMode.ClientCerts(),
			Files:             files,
		})
		if err != nil {
			return fmt.Errorf("refusing to start: TLS: %w", err)
		}
		runner.LogTLS(log, cfg, tlsSrv.Info(), false)
		authCfg.VerifyClient = tlsSrv.VerifyClient
	}
	if cfg.Metrics.Enabled {
		authCfg.MetricsTokenFile = cfg.Metrics.AuthTokenFile
	}
	authn, err := auth.New(authCfg)
	if err != nil {
		return err
	}

	keys := provider.New(log)
	accounts := NewAccounts(keys)
	registry, err := metrics.NewRegistry(metrics.Config{Version: cfg.Version, SignersLoaded: keys.Len})
	if err != nil {
		return fmt.Errorf("metrics: %w", err)
	}
	sem, sizing := argon.Auto(cfg.SignerLoadParallelism)
	runner.LogKeySources(log, cfg, sizing)
	loader := runner.NewKeyLoader(cfg, runner.KeySources{Keystores: cfg.Execution.Keystores, Execution: true}, sem,
		keys, runner.LoadHooks{Applied: func(context.Context) int { accounts.Refresh(); return 0 }}, log)
	reloader := ops.NewReloader(loader.Load, log)
	var ready atomic.Bool

	var serverTLS *tls.Config
	if tlsSrv != nil {
		serverTLS = tlsSrv.TLSConfig()
	}
	srv, err := server.New(server.Config{
		Addr:           cfg.ListenAddr(),
		TLS:            serverTLS,
		HostAllowlist:  cfg.HTTP.HostAllowlist,
		Auth:           authn,
		Routes:         routes(newHandler(accounts, allow, proxy, txs, log), accounts, loader, reloader, authn, ready.Load, log),
		Ready:          ready.Load,
		MaxConnections: cfg.HTTP.MaxConnections,
		ReadTimeout:    ReadTimeout,
		WriteTimeout:   WriteTimeout(cfg.Execution.Downstream.Timeout),
		IdleTimeout:    cfg.HTTP.IdleTimeout,
		AccessLogs:     cfg.HTTP.AccessLogs,
		Log:            log,
		Registerer:     registry,
	})
	if err == nil {
		err = srv.Listen()
	}
	if err != nil {
		return err
	}
	var ml *metrics.Listener
	if cfg.Metrics.Enabled {
		ml = metrics.NewListener(metrics.ListenerConfig{
			Addr: cfg.Metrics.Addr(), HostAllowlist: cfg.Metrics.HostAllowlist, Gatherer: registry, Auth: authn, Log: log,
		})
		if err := ml.Listen(); err != nil {
			_ = srv.Shutdown(context.Background())
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
		log.WithFields(logrus.Fields{"address": ml.Addr().String(), "token": cfg.Metrics.AuthTokenFile != ""}).
			Info("Metrics listener is listening")
	}
	log.WithFields(logrus.Fields{
		"address":         srv.Addr().String(),
		"auth-mode":       cfg.HTTP.AuthMode,
		"tls":             tlsSrv != nil,
		"downstream":      ds.String(),
		"allowed-methods": strings.Join(cfg.Execution.AllowedMethods, ","),
	}).Info("remotesigner execution is listening; loading keys")

	initial := reloader.Start()
	go func() {
		<-initial
		ready.Store(true)
		log.WithField("accounts", keys.Len()).Info("remotesigner execution is ready")
	}()
	chainCtx, stopChain := context.WithCancel(ctx)
	chainDone := make(chan struct{})
	go func() {
		defer close(chainDone)
		txs.chain.run(chainCtx, ChainCheckInterval, ChainRetryInterval)
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
				runner.LogTLSReload(log, cfg, info, err)
			}
			if txs.audit != nil {
				if err := txs.audit.Reopen(); err != nil {
					log.WithError(err).Error("Reopening the audit log failed; the signer keeps writing to the open file")
				} else {
					log.Info("Audit log reopened")
				}
			}
		case serveErr = <-served:
			serving--
			log.WithError(serveErr).Error("A listener failed")
			break loop
		}
	}

	log.Info("Shutting down")
	stopChain()
	<-chainDone
	shutdownCtx, cancel := context.WithTimeout(context.Background(), runner.ShutdownTimeout)
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
	ds.transport.CloseIdleConnections()
	if errors.Is(err, server.ErrHandlersRunning) {
		log.Error("Request handlers are still running; the process exits without zeroizing the keys they use")
	} else {
		keys.Close()
	}
	if portsFile != "" {
		_ = os.Remove(portsFile)
	}
	log.Info("Shutdown complete")
	return serveErr
}

// transactionsFrom builds the transaction signer of cfg: the chain ID, the
// policy file (or the default fee cap alone), the audit log and the
// chain-ID check against the node. close closes the audit log.
func transactionsFrom(cfg *config.Config, p *proxy, log logrus.FieldLogger) (*Transactions, func(), error) {
	e := cfg.Execution
	policy := OpenPolicy()
	if e.PolicyFile != "" {
		var err error
		if policy, err = LoadPolicy(e.PolicyFile); err != nil {
			return nil, nil, err
		}
	}
	var audit *AuditLog
	if e.AuditLogFile != "" {
		var err error
		if audit, err = OpenAuditLog(e.AuditLogFile); err != nil {
			return nil, nil, err
		}
	}
	chainID := new(big.Int).SetUint64(e.ChainID)
	txs := NewTransactions(TransactionsConfig{ChainID: chainID, Policy: policy, Audit: audit,
		NonceCrosscheck: e.NonceCrosscheck})
	txs.chain = newChainMonitor(chainID, p, log)
	log.WithFields(logrus.Fields{
		"chain-id":         e.ChainID,
		"policy-file":      e.PolicyFile != "",
		"policy-accounts":  policy.Accounts(),
		"audit-log":        e.AuditLogFile != "",
		"nonce-crosscheck": e.NonceCrosscheck,
	}).Info("Transaction signing configured")
	return txs, func() {
		if audit != nil {
			_ = audit.Close()
		}
	}, nil
}

// routes are execution mode's API: the JSON-RPC endpoint, the account list
// with public keys, and the operational routes both modes share.
func routes(h *Handler, accounts *Accounts, loader *runner.KeyLoader, reloader *ops.Reloader,
	authn *auth.Authenticator, ready func() bool, log *logrus.Logger) []server.Route {
	checks := append([]ops.Check{{ID: ops.CheckDefault, Run: func(context.Context) (bool, map[string]any) {
		return true, nil
	}}}, loader.Checks()...)
	rs := []server.Route{
		{Method: http.MethodPost, Pattern: "/{$}", Scope: auth.ScopeSign, NeedsReady: true, BodyLimit: BodyLimit,
			ReadsBody: true, Handler: h},
		{Method: http.MethodGet, Pattern: PublicKeysPath, Scope: auth.ScopeSign, NeedsReady: true,
			WriteTimeout: consensus.PublicKeysWriteTimeout, Handler: publicKeys(accounts)},
		{Method: http.MethodGet, Pattern: "/upcheck", Scope: auth.ScopeNone, Handler: ops.Upcheck(ready)},
		{Method: http.MethodGet, Pattern: "/healthcheck", Scope: auth.ScopeNone,
			Handler: ops.Healthcheck(checks, func(r *http.Request) bool { return authn.Allows(r, auth.ScopeSign) })},
		{Method: http.MethodGet, Pattern: "/reload", Scope: auth.ScopeSign, Handler: reloader.StatusHandler()},
	}
	if authn.HasAdmin() {
		rs = append(rs, server.Route{Method: http.MethodPost, Pattern: "/reload", Scope: auth.ScopeAdmin,
			Handler: reloader.StartHandler(log)})
	}
	return rs
}
