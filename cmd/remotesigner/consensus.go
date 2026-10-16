// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/logging"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
	"github.com/rgeraldes24/go-remotesigner/internal/runner"
	"github.com/rgeraldes24/go-remotesigner/internal/server"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
)

// runFunc runs the signer with a resolved configuration until ctx ends; a
// value on hup re-reads the token files.
type runFunc func(ctx context.Context, cfg *config.Config, log *logrus.Logger, hup <-chan struct{}) error

// metaConfigFile is the App.Metadata key of the parsed --config-file.
const metaConfigFile = "config-file"

func consensusCommand(run runFunc, stdout, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name:  flags.ConsensusCommand,
		Usage: "run the consensus-layer remote signer for qrysm validator clients",
		Flags: flags.Consensus(),
		Before: func(c *cli.Context) error {
			if src, ok := c.App.Metadata[metaConfigFile].(*config.YAMLSource); ok {
				if err := src.Apply(c, c.Command.Flags, flags.ConsensusCommand); err != nil {
					return usageError(err)
				}
			}
			return nil
		},
		OnUsageError:    onUsageError,
		HideHelpCommand: true,
		Subcommands:     []*cli.Command{migrateCommand(stdout), randaoStateCommand(stdout), keystoreCommand(stdout)},
		Action: func(c *cli.Context) error {
			if c.NArg() > 0 {
				return usageError(fmt.Errorf("unexpected argument %q", c.Args().First()))
			}
			cfg, err := configFrom(c)
			if err != nil {
				return usageError(err)
			}
			log, closer, err := logging.New(cfg.Logging, stderr)
			if err != nil {
				return usageError(err)
			}
			defer func() { _ = closer.Close() }()
			return runWithSignals(c.Context, cfg, log, run)
		},
	}
}

// loadConfigFile is the root Before hook: it parses --config-file, rejects
// unknown keys, and applies the global flags it sets.
func loadConfigFile(c *cli.Context) error {
	path := c.String(flags.ConfigFile)
	if path == "" {
		return nil
	}
	src, err := config.LoadYAML(path)
	if err != nil {
		return usageError(err)
	}
	if err := src.Validate(c.App.Flags, map[string][]cli.Flag{flags.ConsensusCommand: flags.Consensus()}); err != nil {
		return usageError(err)
	}
	if err := src.Apply(c, c.App.Flags, ""); err != nil {
		return usageError(err)
	}
	c.App.Metadata[metaConfigFile] = src
	return nil
}

// runWithSignals runs the signer, stopping it on SIGTERM or SIGINT and
// reloading the token files on SIGHUP.
func runWithSignals(parent context.Context, cfg *config.Config, log *logrus.Logger, run runFunc) error {
	ctx, stop := signal.NotifyContext(parent, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	defer signal.Stop(sighup)
	hup := make(chan struct{})
	go func() {
		for {
			select {
			case <-sighup:
				select {
				case hup <- struct{}{}:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return run(ctx, cfg, log, hup)
}

// configFrom resolves the flags into a configuration. Its errors are usage
// errors.
func configFrom(c *cli.Context) (*config.Config, error) {
	v, _ := release()
	cfg := &config.Config{
		Version:       v,
		DataPath:      c.String(flags.DataPath),
		KeyConfigPath: c.String(flags.KeyConfigPath),
		Logging: logging.Config{
			Level:  c.String(flags.Logging),
			Format: c.String(flags.LoggingFormat),
			File:   c.String(flags.LogFile),
		},
		HTTP: config.HTTP{
			ListenHost:     c.String(flags.HTTPListenHost),
			AuthMode:       auth.Mode(c.String(flags.HTTPAuthMode)),
			AuthTokenFile:  c.String(flags.HTTPAuthTokenFile),
			AdminTokenFile: c.String(flags.HTTPAdminTokenFile),
			MaxConnections: c.Int(flags.HTTPMaxConnections),
			IdleTimeout:    time.Duration(c.Uint(flags.IdleConnectionTimeout)) * time.Second,
			AccessLogs:     c.Bool(flags.AccessLogsEnabled),
		},
		AllowPlaintextTokenAuth: c.Bool(flags.AllowPlaintextTokenAuth),
		Consensus: config.Consensus{
			Network: network.Sources{
				Network:          c.String(flags.Network),
				GenesisStateFile: c.String(flags.NetworkGenesisState),
			},
			SlashingProtectionEnabled:   c.Bool(flags.SlashingProtectionEnabled),
			KeyManagerAPIEnabled:        c.Bool(flags.KeyManagerAPIEnabled),
			AllowUnknownGenesisTime:     c.Bool(flags.AllowUnknownGenesisTime),
			AllowGVRTOFU:                c.Bool(flags.AllowGVRTOFU),
			VoluntaryExitsEnabled:       c.Bool(flags.VoluntaryExitSigning),
			FeeRecipientFile:            c.String(flags.RegistrationFeeRecipients),
			ClockSkewSlots:              c.Uint64(flags.SigningClockSkewSlots),
			SlashingProtectionDBMigrate: c.Bool(flags.SlashingProtectionMigrate),
			Randao: config.Randao{
				MaxLayers:            c.Uint64(flags.RandaoMaxLayers),
				ReorgWindow:          c.Uint64(flags.RandaoReorgWindow),
				FullScanMinInterval:  c.Duration(flags.RandaoFullScanMinInterval),
				NewLayerBurst:        c.Uint64(flags.RandaoNewLayerBurst),
				NewLayerRefillEpochs: c.Uint64(flags.RandaoRefillEpochs),
				ProtectionRequired:   c.Bool(flags.RandaoProtectionRequired),
			},
		},
		Metrics: config.Metrics{
			Enabled: c.Bool(flags.MetricsEnabled),
			Host:    c.String(flags.MetricsHost),
		},
	}
	hosts, err := server.ParseHostAllowlist(c.StringSlice(flags.HTTPHostAllowlist))
	if err != nil {
		return nil, fmt.Errorf("--%s: %w", flags.HTTPHostAllowlist, err)
	}
	cfg.HTTP.HostAllowlist = hosts
	if cfg.Metrics.HostAllowlist, err = server.ParseHostAllowlist(c.StringSlice(flags.MetricsHostAllowlist)); err != nil {
		return nil, fmt.Errorf("--%s: %w", flags.MetricsHostAllowlist, err)
	}
	if cfg.Consensus.SelectionProofMode, err = mldsa87.ParseMode(c.String(flags.SelectionProofSigning)); err != nil {
		return nil, fmt.Errorf("--%s: %w", flags.SelectionProofSigning, err)
	}
	if cfg.Consensus.Network.Network == "" {
		return nil, fmt.Errorf("--%s is required: a built-in name (%s) or a network config file",
			flags.Network, strings.Join(network.Names(), ", "))
	}
	if err := cfg.Logging.Validate(); err != nil {
		return nil, err
	}
	switch cfg.HTTP.AuthMode {
	case auth.ModeToken, auth.ModeNone:
	case "mtls", "token+mtls":
		return nil, fmt.Errorf("--%s=%s needs TLS, which this release does not have; use token or none", flags.HTTPAuthMode, cfg.HTTP.AuthMode)
	default:
		return nil, fmt.Errorf("--%s=%q: want token or none", flags.HTTPAuthMode, cfg.HTTP.AuthMode)
	}
	port := c.Uint(flags.HTTPListenPort)
	if port > 65535 {
		return nil, fmt.Errorf("--%s=%d: not a TCP port", flags.HTTPListenPort, port)
	}
	cfg.HTTP.ListenPort = uint16(port)
	metricsPort := c.Uint(flags.MetricsPort)
	if metricsPort > 65535 {
		return nil, fmt.Errorf("--%s=%d: not a TCP port", flags.MetricsPort, metricsPort)
	}
	cfg.Metrics.Port = uint16(metricsPort)
	if cfg.HTTP.MaxConnections < 1 {
		return nil, fmt.Errorf("--%s must be at least 1", flags.HTTPMaxConnections)
	}
	if cfg.HTTP.IdleTimeout < time.Second {
		return nil, fmt.Errorf("--%s must be at least 1", flags.IdleConnectionTimeout)
	}
	if err := checkRandao(&cfg.Consensus.Randao); err != nil {
		return nil, err
	}
	if cfg.Consensus.SlashingProtectionDBPath, err = dbPath(c); err != nil {
		return nil, err
	}
	if c.IsSet(flags.NetworkGenesisTime) {
		t := c.Uint64(flags.NetworkGenesisTime)
		cfg.Consensus.Network.GenesisTime = &t
	}
	if s := c.String(flags.NetworkGenesisGVR); s != "" {
		gvr, err := parseRoot(s)
		if err != nil {
			return nil, fmt.Errorf("--%s: %w", flags.NetworkGenesisGVR, err)
		}
		cfg.Consensus.Network.GenesisValidatorsRoot = &gvr
	}
	return cfg, nil
}

// maxRefillEpochs bounds --randao-new-layer-refill-epochs, so that the
// refill period cannot overflow.
const maxRefillEpochs = 1 << 20

func checkRandao(r *config.Randao) error {
	switch {
	case r.MaxLayers == 0:
		return fmt.Errorf("--%s must be at least 1", flags.RandaoMaxLayers)
	case r.FullScanMinInterval < 0:
		return fmt.Errorf("--%s must not be negative", flags.RandaoFullScanMinInterval)
	case r.NewLayerRefillEpochs > maxRefillEpochs:
		return fmt.Errorf("--%s must be at most %d", flags.RandaoRefillEpochs, maxRefillEpochs)
	case r.NewLayerRefillEpochs > 0 && r.NewLayerBurst == 0:
		return fmt.Errorf("--%s must be at least 1 while the bucket is on (--%s=0 turns it off)",
			flags.RandaoNewLayerBurst, flags.RandaoRefillEpochs)
	}
	return nil
}

// dbPath returns the bbolt file of --slashing-protection-db-url, set on
// the command or on any parent, or "" when it is not set.
func dbPath(c *cli.Context) (string, error) {
	for _, x := range c.Lineage() {
		if !x.IsSet(flags.SlashingProtectionDBURL) {
			continue
		}
		p, err := config.ParseDBURL(x.String(flags.SlashingProtectionDBURL))
		if err != nil {
			return "", fmt.Errorf("--%s: %w", flags.SlashingProtectionDBURL, err)
		}
		return p, nil
	}
	return "", nil
}

func parseRoot(s string) ([32]byte, error) {
	var r [32]byte
	h, ok := strings.CutPrefix(s, "0x")
	if !ok || len(h) != 64 {
		return r, fmt.Errorf("want 0x + 64 hex characters")
	}
	if _, err := hex.Decode(r[:], []byte(h)); err != nil {
		return r, fmt.Errorf("want 0x + 64 hex characters")
	}
	return r, nil
}

// usageError makes err exit with the usage-error code.
func usageError(err error) error {
	return cli.Exit(fmt.Sprintf("usage error: %v", err), exitUsage)
}

func onUsageError(_ *cli.Context, err error, _ bool) error {
	return usageError(err)
}

// defaultRun is the production runFunc.
var defaultRun runFunc = runner.Run
