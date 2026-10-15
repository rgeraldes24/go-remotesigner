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
)

// Defaults.
const (
	DefaultListenHost     = "127.0.0.1"
	DefaultListenPort     = 9000
	DefaultAuthMode       = "token"
	DefaultMaxConnections = 1024
	DefaultIdleTimeout    = 120
)

// DefaultHostAllowlist is the default of --http-host-allowlist.
var DefaultHostAllowlist = []string{"localhost", "127.0.0.1", "::1"}

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
	})
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
		default:
			panic("flags: no environment variables for flag type of " + strings.Join(f.Names(), ","))
		}
	}
	return fs
}
