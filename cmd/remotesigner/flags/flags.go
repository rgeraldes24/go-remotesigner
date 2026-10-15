// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package flags defines the command-line flags of remotesigner. Every flag
// also reads REMOTESIGNER_[<COMMAND>_]<NAME> from the environment (one
// variable per name and alias) and its bare name from --config-file.
// Precedence: command line, then environment, then config file, then
// default. tools/flagdoc renders these definitions into
// docs/reference/flags.md.
//
// Names and defaults follow Web3Signer wherever it has the option, so the
// qrysm e2e invocation works verbatim.
package flags

import (
	"strings"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
)

// Global flag names.
const (
	ConfigFile              = "config-file"
	DataPath                = "data-path"
	KeyConfigPath           = "key-config-path"
	KeyStorePath            = "key-store-path" // alias of KeyConfigPath
	Logging                 = "logging"
	LoggingFormat           = "logging-format"
	LogFile                 = "log-file"
	HTTPListenHost          = "http-listen-host"
	HTTPListenPort          = "http-listen-port"
	HTTPHostAllowlist       = "http-host-allowlist"
	HTTPAuthMode            = "http-auth-mode"
	HTTPAuthTokenFile       = "http-auth-token-file"
	HTTPAdminTokenFile      = "http-admin-token-file"
	HTTPMaxConnections      = "http-max-connections"
	IdleConnectionTimeout   = "idle-connection-timeout-seconds"
	AccessLogsEnabled       = "access-logs-enabled"
	AllowPlaintextTokenAuth = "Xallow-plaintext-token-auth"
	MetricsEnabled          = "metrics-enabled"
	MetricsHost             = "metrics-host"
	MetricsPort             = "metrics-port"
	MetricsHostAllowlist    = "metrics-host-allowlist"
)

// Consensus flag names.
const (
	ConsensusCommand          = "consensus"
	Network                   = "network"
	NetworkGenesisGVR         = "network-genesis-validators-root"
	NetworkGenesisTime        = "network-genesis-time"
	NetworkGenesisState       = "network-genesis-state"
	SlashingProtectionEnabled = "slashing-protection-enabled"
	KeyManagerAPIEnabled      = "key-manager-api-enabled"
	AllowUnknownGenesisTime   = "Xallow-unknown-genesis-time"
	AllowGVRTOFU              = "Xallow-gvr-tofu"
	VoluntaryExitSigning      = "voluntary-exit-signing-enabled"
	RegistrationFeeRecipients = "registration-fee-recipient-file"
	SigningClockSkewSlots     = "signing-clock-skew-slots"
	SelectionProofSigning     = "selection-proof-signing"
	SlashingProtectionDBURL   = "slashing-protection-db-url"
	SlashingProtectionMigrate = "slashing-protection-db-migrate"
	RandaoMaxLayers           = "randao-max-layers"
	RandaoReorgWindow         = "randao-reorg-window"
	RandaoFullScanMinInterval = "randao-full-scan-min-interval"
	RandaoNewLayerBurst       = "randao-new-layer-burst"
	RandaoRefillEpochs        = "randao-new-layer-refill-epochs"
	RandaoProtectionRequired  = "randao-protection-required"
)

// Subcommands of consensus and their flags.
const (
	MigrateCommand     = "migrate"
	RandaoStateCommand = "randao-state"
	ResetCommand       = "reset"
	Key                = "key"
)

// Defaults.
const (
	DefaultListenHost     = "127.0.0.1"
	DefaultListenPort     = 9000
	DefaultAuthMode       = "token"
	DefaultMaxConnections = 1024
	DefaultIdleTimeout    = 120
	DefaultMetricsHost    = "127.0.0.1"
	DefaultMetricsPort    = 9001
	DefaultClockSkew      = 1
	DefaultSelectionProof = "deterministic"
	DefaultRandaoLayers   = 1 << 20
	DefaultReorgWindow    = 1024
	DefaultNewLayerBurst  = 3
	DefaultRefillEpochs   = 1
)

// DefaultHostAllowlist is the default of --http-host-allowlist.
var DefaultHostAllowlist = []string{"localhost", "127.0.0.1", "::1"}

// DefaultMetricsHostAllowlist is the default of --metrics-host-allowlist,
// Web3Signer's.
var DefaultMetricsHostAllowlist = []string{"localhost", "127.0.0.1"}

// Global returns the flags that precede the subcommand.
func Global() []cli.Flag {
	return withEnv("", []cli.Flag{
		&cli.StringFlag{Name: ConfigFile, Usage: "YAML file of flag values: bare flag names, with an optional consensus: section. Unknown keys are rejected.", TakesFile: true},
		&cli.StringFlag{Name: DataPath, Usage: "Directory for the generated token files, the slashing-protection store and the ports file", TakesFile: true},
		&cli.StringFlag{Name: KeyConfigPath, Aliases: []string{KeyStorePath}, Usage: "Directory of key-config files (type file-raw, *.yaml or *.yml); unset loads no keys", TakesFile: true},
		&cli.StringFlag{Name: Logging, Aliases: []string{"l"}, Value: "INFO", Usage: "Log level: OFF, FATAL, ERROR, WARN, INFO, DEBUG, TRACE or ALL"},
		&cli.StringFlag{Name: LoggingFormat, Aliases: []string{"log-format"}, Value: "text", Usage: "Log format: text or json"},
		&cli.StringFlag{Name: LogFile, Usage: "Write logs to this file instead of standard error", TakesFile: true},
		&cli.StringFlag{Name: HTTPListenHost, Value: DefaultListenHost, Usage: "Host the API listens on. A non-loopback host turns on the remote-listener fail-safes."},
		&cli.UintFlag{Name: HTTPListenPort, Value: DefaultListenPort, Usage: "Port the API listens on; 0 picks a free port (see the ports file)"},
		&cli.StringSliceFlag{Name: HTTPHostAllowlist, Value: cli.NewStringSlice(DefaultHostAllowlist...), Usage: "Host header names the API accepts (DNS-rebinding defence); * or all accepts any, none refuses all"},
		&cli.StringFlag{Name: HTTPAuthMode, Value: DefaultAuthMode, Usage: "API authentication: token (bearer tokens) or none (loopback listeners only; the admin token is still required)"},
		&cli.StringFlag{Name: HTTPAuthTokenFile, Usage: "Sign-scope bearer token file (default <data-path>/auth-token, generated 0600 when missing; re-read on SIGHUP)", TakesFile: true},
		&cli.StringFlag{Name: HTTPAdminTokenFile, Usage: "Admin-scope bearer token file (default <data-path>/admin-token, generated 0600 when missing; re-read on SIGHUP). Admin routes exist only with an admin token.", TakesFile: true},
		&cli.IntFlag{Name: HTTPMaxConnections, Value: DefaultMaxConnections, Usage: "Maximum open API connections; further connections wait until one closes"},
		&cli.UintFlag{Name: IdleConnectionTimeout, Value: DefaultIdleTimeout, Usage: "Seconds a kept-alive API connection may stay idle"},
		&cli.BoolFlag{Name: AccessLogsEnabled, Usage: "Log every API request at INFO (route, status, duration; never paths or bodies)"},
		&cli.BoolFlag{Name: AllowPlaintextTokenAuth, Hidden: true, Usage: "Allow bearer tokens over plaintext HTTP on a non-loopback listener"},
		&cli.BoolFlag{Name: MetricsEnabled, Usage: "Serve Prometheus metrics at /metrics on a separate listener"},
		&cli.StringFlag{Name: MetricsHost, Value: DefaultMetricsHost, Usage: "Host the metrics listener binds"},
		&cli.UintFlag{Name: MetricsPort, Value: DefaultMetricsPort, Usage: "Port the metrics listener binds; 0 picks a free port (see the ports file)"},
		&cli.StringSliceFlag{Name: MetricsHostAllowlist, Value: cli.NewStringSlice(DefaultMetricsHostAllowlist...), Usage: "Host header names the metrics listener accepts; * or all accepts any, none refuses all"},
	})
}

// Consensus returns the flags of the consensus subcommand.
func Consensus() []cli.Flag {
	return withEnv(ConsensusCommand, []cli.Flag{
		&cli.StringFlag{Name: Network, Usage: "Required. A built-in network name (minimal, end-to-end or e2e, end-to-end-mainnet, interop) or a qrysm-format config YAML file"},
		&cli.StringFlag{Name: NetworkGenesisGVR, Usage: "Genesis validators root, 0x + 64 hex characters; must agree with every other source"},
		&cli.Uint64Flag{Name: NetworkGenesisTime, DefaultText: "unset", Usage: "Genesis time in Unix seconds; must agree with every other source"},
		&cli.StringFlag{Name: NetworkGenesisState, Usage: "SSZ genesis state; its first 64 bytes give the genesis time, the genesis validators root and the fork", TakesFile: true},
		&cli.BoolFlag{Name: SlashingProtectionEnabled, Value: true, Usage: "Slashing protection (bbolt store at <data-path>/slashing-protection.db). false is allowed only when every listener is loopback."},
		&cli.BoolFlag{Name: KeyManagerAPIEnabled, Usage: "Accepted for Web3Signer compatibility; requires an admin token. This release has no keymanager API."},
		&cli.BoolFlag{Name: AllowUnknownGenesisTime, Hidden: true, Usage: "Allow a non-loopback listener without a genesis time (wall-clock bounds off)"},
		&cli.BoolFlag{Name: AllowGVRTOFU, Hidden: true, Usage: "Allow a non-loopback listener to pin the genesis validators root on first use"},
		&cli.BoolFlag{Name: VoluntaryExitSigning, Usage: "Sign VOLUNTARY_EXIT requests; refused with 403 ARTIFACT_TYPE_DISABLED otherwise"},
		&cli.StringFlag{Name: RegistrationFeeRecipients, Usage: "YAML list of {key, fee_recipient} pins: a VALIDATOR_REGISTRATION for a pinned key must carry its pinned fee recipient", TakesFile: true},
		&cli.Uint64Flag{Name: SigningClockSkewSlots, Value: DefaultClockSkew, Usage: "Slots a slot-scoped request may lie ahead of the wall clock (when genesis time is known)"},
		&cli.StringFlag{Name: SelectionProofSigning, Value: DefaultSelectionProof, Usage: "Signing mode of AGGREGATION_SLOT and SYNC_COMMITTEE_SELECTION_PROOF: deterministic or hedged; other types are always hedged"},
		slashingProtectionDBURL(),
		&cli.BoolFlag{Name: SlashingProtectionMigrate, Usage: "Upgrade an older slashing-protection store to this release's schema before starting (a backup <file>.v<old>.bak is written first)"},
		&cli.Uint64Flag{Name: RandaoMaxLayers, Value: DefaultRandaoLayers, Usage: "Onion layers searched from x_0 when locating a RANDAO commitment; a commitment deeper in a longer onion is unknown"},
		&cli.Uint64Flag{Name: RandaoReorgWindow, Value: DefaultReorgWindow, Usage: "Layers above a key's released frontier searched for a re-reveal before the slow-path scan"},
		&cli.DurationFlag{Name: RandaoFullScanMinInterval, DefaultText: "SECONDS_PER_SLOT", Usage: "Minimum time between two slow-path RANDAO scans of one key (first use, gap advance, deep reorg); sooner gets 429 RANDAO_SCAN_RATE_LIMITED"},
		&cli.Uint64Flag{Name: RandaoNewLayerBurst, Value: DefaultNewLayerBurst, Usage: "Tokens in each key's RANDAO new-layer bucket: frontier-moving reveals allowed in a burst"},
		&cli.Uint64Flag{Name: RandaoRefillEpochs, Value: DefaultRefillEpochs, Usage: "Epochs per new-layer token refill; 0 turns the bucket off. Networks with fewer than about 4 x SLOTS_PER_EPOCH validators should raise the burst or use 0."},
		&cli.BoolFlag{Name: RandaoProtectionRequired, Usage: "Refuse to start when RANDAO frontiers would be kept in memory only (--slashing-protection-enabled=false)"},
	})
}

// slashingProtectionDBURL is --slashing-protection-db-url, which the
// consensus command and its offline subcommands share.
func slashingProtectionDBURL() cli.Flag {
	return &cli.StringFlag{Name: SlashingProtectionDBURL, Usage: "Slashing-protection store as bolt:///absolute/path/file.db (default <data-path>/slashing-protection.db)"}
}

// Migrate returns the flags of `consensus migrate`.
func Migrate() []cli.Flag {
	return withEnv(ConsensusCommand, []cli.Flag{slashingProtectionDBURL()})
}

// RandaoStateReset returns the flags of `consensus randao-state reset`.
func RandaoStateReset() []cli.Flag {
	return append(withEnv(ConsensusCommand, []cli.Flag{slashingProtectionDBURL()}),
		&cli.StringFlag{Name: Key, Usage: "Required. The key whose RANDAO frontier is cleared: its 0x public key or 0x sha256 of it"})
}

// withEnv sets each flag's environment variables, except for --config-file,
// which has none.
func withEnv(command string, fs []cli.Flag) []cli.Flag {
	for _, f := range fs {
		if f.Names()[0] == ConfigFile {
			continue
		}
		env := config.EnvVars(command, f.Names()...)
		switch f := f.(type) {
		case *cli.StringFlag:
			f.EnvVars = env
		case *cli.UintFlag:
			f.EnvVars = env
		case *cli.Uint64Flag:
			f.EnvVars = env
		case *cli.IntFlag:
			f.EnvVars = env
		case *cli.BoolFlag:
			f.EnvVars = env
		case *cli.StringSliceFlag:
			f.EnvVars = env
		case *cli.DurationFlag:
			f.EnvVars = env
		default:
			panic("flags: no environment variables for flag type of " + strings.Join(f.Names(), ","))
		}
	}
	return fs
}
