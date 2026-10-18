// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
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
	"github.com/rgeraldes24/go-remotesigner/internal/hygiene"
	"github.com/rgeraldes24/go-remotesigner/internal/logging"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
	"github.com/rgeraldes24/go-remotesigner/internal/runner"
	"github.com/rgeraldes24/go-remotesigner/internal/server"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
	"github.com/rgeraldes24/go-remotesigner/internal/server/tlsconf"
)

// runFunc runs the signer with a resolved configuration until ctx ends; a
// value on hup re-reads the token and TLS files.
type runFunc func(ctx context.Context, cfg *config.Config, log *logrus.Logger, hup <-chan struct{}) error

// metaConfigFile is the App.Metadata key of the parsed --config-file.
const metaConfigFile = "config-file"

func consensusCommand(run runFunc, stdout, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name:            flags.ConsensusCommand,
		Usage:           "run the consensus-layer remote signer for qrysm validator clients",
		Flags:           flags.Consensus(),
		Before:          applySection(flags.ConsensusCommand),
		OnUsageError:    onUsageError,
		HideHelpCommand: true,
		Subcommands: []*cli.Command{
			migrateCommand(stdout), randaoStateCommand(stdout), importCommand(stdout, stderr), exportCommand(stdout, stderr),
			watermarkRepairCommand(stdout), setHighWatermarkCommand(stdout), keystoreCommand(stdout, stderr),
			disableValidatorCommand(stdout),
		},
		Action: modeAction(configFrom, run, stderr),
	}
}

// modeAction is the action of a mode's command: it resolves the
// configuration with resolve, sets up logging and runs the mode until a
// signal stops it.
func modeAction(resolve func(*cli.Context) (*config.Config, error), run runFunc, stderr io.Writer) cli.ActionFunc {
	return func(c *cli.Context) error {
		if c.NArg() > 0 {
			return usageError(fmt.Errorf("unexpected argument %q", c.Args().First()))
		}
		cfg, err := resolve(c)
		if err != nil {
			return usageError(err)
		}
		log, closer, err := logging.New(cfg.Logging, stderr)
		if err != nil {
			return usageError(err)
		}
		defer func() { _ = closer.Close() }()
		return runWithSignals(c.Context, cfg, log, run)
	}
}

// applySection is a mode command's Before hook: it applies the mode's
// section of --config-file.
func applySection(section string) cli.BeforeFunc {
	return func(c *cli.Context) error {
		if src, ok := c.App.Metadata[metaConfigFile].(*config.YAMLSource); ok {
			if err := src.Apply(c, c.Command.Flags, section); err != nil {
				return usageError(err)
			}
		}
		return nil
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
	sections := map[string][]cli.Flag{flags.ConsensusCommand: flags.Consensus()}
	maps.Copy(sections, flavourSections())
	if err := src.Validate(c.App.Flags, sections); err != nil {
		return usageError(err)
	}
	if err := src.Apply(c, c.App.Flags, ""); err != nil {
		return usageError(err)
	}
	c.App.Metadata[metaConfigFile] = src
	return nil
}

// runWithSignals runs the signer, stopping it on SIGTERM or SIGINT and
// reloading the token and TLS files on SIGHUP.
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

// globalConfig resolves the global flags, which both modes share. Its
// errors are usage errors.
func globalConfig(c *cli.Context) (*config.Config, error) {
	v, _ := release()
	cfg := &config.Config{
		Version:               v,
		DataPath:              c.String(flags.DataPath),
		KeyConfigPath:         c.String(flags.KeyConfigPath),
		KeyConfigFileMaxSize:  int64(c.Int(flags.KeyConfigFileMaxSize)),
		StrictFilePermissions: c.Bool(flags.StrictFilePermissions),
		ReloadTimeout:         time.Duration(c.Uint(flags.ReloadTimeout)) * time.Minute,
		SignerLoadParallelism: c.Int(flags.SignerLoadParallelism),
		Logging: logging.Config{
			Level:  c.String(flags.Logging),
			Format: c.String(flags.LoggingFormat),
			File:   c.String(flags.LogFile),
		},
		HTTP: config.HTTP{
			ListenHost:     c.String(flags.HTTPListenHost),
			AuthTokenFile:  c.String(flags.HTTPAuthTokenFile),
			AdminTokenFile: c.String(flags.HTTPAdminTokenFile),
			MaxConnections: c.Int(flags.HTTPMaxConnections),
			IdleTimeout:    time.Duration(c.Uint(flags.IdleConnectionTimeout)) * time.Second,
			AccessLogs:     c.Bool(flags.AccessLogsEnabled),
		},
		TLS: tlsconf.Config{
			CertFile:             c.String(flags.TLSCertFile),
			KeyFile:              c.String(flags.TLSKeyFile),
			KeystoreFile:         c.String(flags.TLSKeystoreFile),
			KeystorePasswordFile: c.String(flags.TLSKeystorePasswordFile),
			KnownClientsFile:     c.String(flags.TLSKnownClientsFile),
			ClientCAFile:         c.String(flags.TLSClientCAFile),
			GenerateSelfSigned:   c.Bool(flags.TLSGenerateSelfSigned),
		},
		AllowPlaintextTokenAuth: c.Bool(flags.AllowPlaintextTokenAuth),
		Hygiene: hygiene.Config{
			DisableCoreDumps: c.Bool(flags.DisableCoreDumps),
			MlockAll:         c.Bool(flags.MlockAll),
		},
		Metrics: config.Metrics{
			Enabled:       c.Bool(flags.MetricsEnabled),
			Host:          c.String(flags.MetricsHost),
			AuthTokenFile: c.String(flags.MetricsAuthTokenFile),
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
	if err := cfg.Logging.Validate(); err != nil {
		return nil, err
	}
	if cfg.HTTP.AuthMode, err = auth.ParseMode(c.String(flags.HTTPAuthMode)); err != nil {
		return nil, fmt.Errorf("--%s=%w", flags.HTTPAuthMode, err)
	}
	if err := cfg.TLS.Validate(cfg.HTTP.AuthMode.ClientCerts()); err != nil {
		return nil, err
	}
	if cfg.HTTP.ListenPort, err = tcpPort(c, flags.HTTPListenPort); err != nil {
		return nil, err
	}
	if cfg.Metrics.Port, err = tcpPort(c, flags.MetricsPort); err != nil {
		return nil, err
	}
	if cfg.HTTP.MaxConnections < 1 {
		return nil, fmt.Errorf("--%s must be at least 1", flags.HTTPMaxConnections)
	}
	if cfg.HTTP.IdleTimeout < time.Second {
		return nil, fmt.Errorf("--%s must be at least 1", flags.IdleConnectionTimeout)
	}
	if err := checkLoading(c); err != nil {
		return nil, err
	}
	return cfg, nil
}

// tcpPort reads a port flag, 0 to 65535.
func tcpPort(c *cli.Context, name string) (uint16, error) {
	port := c.Uint(name)
	if port > 65535 {
		return 0, fmt.Errorf("--%s=%d: not a TCP port", name, port)
	}
	return uint16(port), nil
}

// configFrom resolves the flags of `consensus` into a configuration. Its
// errors are usage errors.
func configFrom(c *cli.Context) (*config.Config, error) {
	cfg, err := globalConfig(c)
	if err != nil {
		return nil, err
	}
	cfg.Consensus = config.Consensus{
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
		Pruning: config.Pruning{
			EpochsToKeep: c.Uint64(flags.PruningEpochsToKeep),
			Interval:     c.Duration(flags.PruningInterval),
		},
		Keystores: keystoresFrom(c),
	}
	if cfg.Consensus.SelectionProofMode, err = mldsa87.ParseMode(c.String(flags.SelectionProofSigning)); err != nil {
		return nil, fmt.Errorf("--%s: %w", flags.SelectionProofSigning, err)
	}
	if cfg.Consensus.Network.Network == "" {
		return nil, fmt.Errorf("--%s is required: a built-in name (%s) or a network config file",
			flags.Network, strings.Join(network.Names(), ", "))
	}
	if err := checkRandao(&cfg.Consensus.Randao); err != nil {
		return nil, err
	}
	if err := checkPruning(cfg.Consensus.Pruning); err != nil {
		return nil, err
	}
	if err := checkKeystores(cfg.Consensus.Keystores); err != nil {
		return nil, err
	}
	if err := storeConfig(c, &cfg.Consensus); err != nil {
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

// keystoresFrom reads a mode's keystore directory flags.
func keystoresFrom(c *cli.Context) config.Keystores {
	return config.Keystores{
		Path:          c.String(flags.KeystoresPath),
		PasswordFile:  c.String(flags.KeystoresPasswordFile),
		PasswordsPath: c.String(flags.KeystoresPasswordsPath),
	}
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

func checkPruning(p config.Pruning) error {
	switch {
	case p.EpochsToKeep == 0:
		return fmt.Errorf("--%s must be at least 1", flags.PruningEpochsToKeep)
	case p.Interval <= 0:
		return fmt.Errorf("--%s must be positive", flags.PruningInterval)
	}
	return nil
}

// checkKeystores checks the keystore source's flags: --keystores-path needs
// exactly one of the two password flags, and they need it.
func checkKeystores(k config.Keystores) error {
	switch {
	case k.PasswordFile != "" && k.PasswordsPath != "":
		return fmt.Errorf("only one of --%s or --%s can be specified", flags.KeystoresPasswordsPath, flags.KeystoresPasswordFile)
	case k.Path == "" && (k.PasswordFile != "" || k.PasswordsPath != ""):
		return fmt.Errorf("--%s and --%s need --%s", flags.KeystoresPasswordFile, flags.KeystoresPasswordsPath, flags.KeystoresPath)
	case k.Path != "" && k.PasswordFile == "" && k.PasswordsPath == "":
		return fmt.Errorf("--%s needs --%s or --%s", flags.KeystoresPath, flags.KeystoresPasswordFile, flags.KeystoresPasswordsPath)
	}
	return nil
}

// maxReloadTimeout bounds --reload-timeout (minutes) well below the range
// of a time.Duration.
const maxReloadTimeout = 1_000_000

// checkLoading checks --reload-timeout, --signer-load-parallelism and
// --key-store-config-file-max-size.
func checkLoading(c *cli.Context) error {
	if n := c.Int(flags.KeyConfigFileMaxSize); n < 1 {
		return fmt.Errorf("--%s must be a positive number of bytes", flags.KeyConfigFileMaxSize)
	}
	if m := c.Uint(flags.ReloadTimeout); m < 1 || m > maxReloadTimeout {
		return fmt.Errorf("--%s must be 1 to %d (minutes)", flags.ReloadTimeout, maxReloadTimeout)
	}
	if p := c.Int(flags.SignerLoadParallelism); p < 0 || p > flags.MaxSignerLoadParallelism {
		return fmt.Errorf("--%s must be 0 (from the memory limit) to %d", flags.SignerLoadParallelism, flags.MaxSignerLoadParallelism)
	}
	return nil
}

// storeConfig resolves the store flags: the bbolt file or the Postgres database of --slashing-protection-db-url,
// the Postgres user name and password file, which need a Postgres URL, and the health-check timing.
func storeConfig(c *cli.Context, cc *config.Consensus) error {
	u, err := dbURL(c)
	if err != nil {
		return err
	}
	cc.SlashingProtectionDBPath = u.Path
	if u.Postgres == "" && (c.IsSet(flags.SlashingProtectionDBUser) || c.IsSet(flags.SlashingProtectionDBPass)) {
		return fmt.Errorf("--%s and --%s need a postgres:// --%s", flags.SlashingProtectionDBUser,
			flags.SlashingProtectionDBPass, flags.SlashingProtectionDBURL)
	}
	cc.Postgres = config.Postgres{
		URL:                 u.Postgres,
		Username:            c.String(flags.SlashingProtectionDBUser),
		PasswordFile:        c.String(flags.SlashingProtectionDBPass),
		HealthCheckTimeout:  time.Duration(c.Uint64(flags.DBHealthCheckTimeout)) * time.Millisecond,
		HealthCheckInterval: time.Duration(c.Uint64(flags.DBHealthCheckInterval)) * time.Millisecond,
	}
	for _, f := range []string{flags.DBHealthCheckTimeout, flags.DBHealthCheckInterval} {
		if v := c.Uint64(f); v < 1 || v > maxHealthCheckMillis {
			return fmt.Errorf("--%s must be 1 to %d (milliseconds)", f, maxHealthCheckMillis)
		}
	}
	return nil
}

// maxHealthCheckMillis bounds the health-check flags (a day), well below the range of a time.Duration.
const maxHealthCheckMillis = 86_400_000

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
