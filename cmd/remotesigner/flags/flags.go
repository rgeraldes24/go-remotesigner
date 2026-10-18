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
	"time"

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
	MetricsAuthTokenFile    = "metrics-auth-token-file"
	TLSCertFile             = "tls-cert-file"
	TLSKeyFile              = "tls-key-file"
	TLSKeystoreFile         = "tls-keystore-file"
	TLSKeystorePasswordFile = "tls-keystore-password-file"
	TLSKnownClientsFile     = "tls-known-clients-file"
	TLSClientCAFile         = "tls-client-ca-file"
	TLSGenerateSelfSigned   = "tls-generate-self-signed"
	DisableCoreDumps        = "disable-core-dumps"
	MlockAll                = "mlock-all"
	StrictFilePermissions   = "strict-file-permissions"
	ReloadTimeout           = "reload-timeout"
	SignerLoadParallelism   = "signer-load-parallelism"
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
	PruningEpochsToKeep       = "slashing-protection-pruning-epochs-to-keep"
	PruningInterval           = "slashing-protection-pruning-interval"
	RandaoMaxLayers           = "randao-max-layers"
	RandaoReorgWindow         = "randao-reorg-window"
	RandaoFullScanMinInterval = "randao-full-scan-min-interval"
	RandaoNewLayerBurst       = "randao-new-layer-burst"
	RandaoRefillEpochs        = "randao-new-layer-refill-epochs"
	RandaoProtectionRequired  = "randao-protection-required"
	KeystoresPath             = "keystores-path"
	KeystoresPasswordFile     = "keystores-password-file"
	KeystoresPasswordsPath    = "keystores-passwords-path"
)

// Subcommands of consensus and their flags.
const (
	MigrateCommand          = "migrate"
	RandaoStateCommand      = "randao-state"
	ResetCommand            = "reset"
	Key                     = "key"
	KeystoreCommand         = "keystore"
	VerifyCommand           = "verify"
	VerifyFile              = "file"
	VerifyPasswordFile      = "password-file"
	ImportCommand           = "import"
	ExportCommand           = "export"
	WatermarkRepairCommand  = "watermark-repair"
	SetHighWatermarkCommand = "set-high-watermark"
	From                    = "from"
	To                      = "to"
	Keys                    = "keys"
	Epoch                   = "epoch"
	Slot                    = "slot"
	Remove                  = "remove"
	DisableValidator        = "disable-validator"
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
	DefaultPruningEpochs  = 512
	DefaultPruningEvery   = 12 * time.Hour
	// DefaultReloadTimeout is --reload-timeout in minutes, Web3Signer's
	// unit: 10,000 new standard-KDF keystores take about half an hour at 8
	// decrypts at once.
	DefaultReloadTimeout = 60
	// MaxSignerLoadParallelism bounds --signer-load-parallelism.
	MaxSignerLoadParallelism = 64
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
		&cli.StringFlag{Name: KeyConfigPath, Aliases: []string{KeyStorePath}, Usage: "Directory of key-config files (*.yaml or *.yml; types file-raw and file-keystore); unset loads none", TakesFile: true},
		&cli.BoolFlag{Name: StrictFilePermissions, Value: true, Usage: "Refuse secret files (password files, key-config files with a seed) that their group or other users can read; false loads them with a warning"},
		&cli.UintFlag{Name: ReloadTimeout, Value: DefaultReloadTimeout, Usage: "Minutes a POST /reload may load keys; the sources not loaded by then keep their previous keys. The startup load is not bounded."},
		&cli.IntFlag{Name: SignerLoadParallelism, DefaultText: "0 (from the memory limit)", Usage: "Keystore decrypts with the standard KDF that may run at once; 0 sizes the Argon2id budget from GOMEMLIMIT, the cgroup limit or half the RAM"},
		&cli.StringFlag{Name: Logging, Aliases: []string{"l"}, Value: "INFO", Usage: "Log level: OFF, FATAL, ERROR, WARN, INFO, DEBUG, TRACE or ALL"},
		&cli.StringFlag{Name: LoggingFormat, Aliases: []string{"log-format"}, Value: "text", Usage: "Log format: text or json"},
		&cli.StringFlag{Name: LogFile, Usage: "Write logs to this file instead of standard error", TakesFile: true},
		&cli.StringFlag{Name: HTTPListenHost, Value: DefaultListenHost, Usage: "Host the API listens on. A non-loopback host turns on the remote-listener fail-safes."},
		&cli.UintFlag{Name: HTTPListenPort, Value: DefaultListenPort, Usage: "Port the API listens on; 0 picks a free port (see the ports file)"},
		&cli.StringSliceFlag{Name: HTTPHostAllowlist, Value: cli.NewStringSlice(DefaultHostAllowlist...), Usage: "Host header names the API accepts (DNS-rebinding defence); * or all accepts any, none refuses all"},
		&cli.StringFlag{Name: HTTPAuthMode, Value: DefaultAuthMode, Usage: "API authentication: token (the sign token), mtls (a client certificate grants the sign scope), token+mtls (both) or none (loopback listeners only). Admin routes always need the admin token."},
		&cli.StringFlag{Name: HTTPAuthTokenFile, Usage: "Sign-scope bearer token file (default <data-path>/auth-token, generated 0600 when missing; re-read on SIGHUP)", TakesFile: true},
		&cli.StringFlag{Name: HTTPAdminTokenFile, Usage: "Admin-scope bearer token file (default <data-path>/admin-token, generated 0600 when missing; re-read on SIGHUP). Admin routes exist only with an admin token.", TakesFile: true},
		&cli.IntFlag{Name: HTTPMaxConnections, Value: DefaultMaxConnections, Usage: "Maximum open API connections; further connections wait until one closes"},
		&cli.UintFlag{Name: IdleConnectionTimeout, Value: DefaultIdleTimeout, Usage: "Seconds a kept-alive API connection may stay idle"},
		&cli.BoolFlag{Name: AccessLogsEnabled, Usage: "Log every API request at INFO (route, status, duration; never paths or bodies)"},
		&cli.BoolFlag{Name: AllowPlaintextTokenAuth, Hidden: true, Usage: "Allow bearer tokens over plaintext HTTP on a non-loopback listener"},
		&cli.StringFlag{Name: TLSCertFile, Usage: "PEM certificate chain the API serves over TLS 1.3, with --tls-key-file (re-read on SIGHUP)", TakesFile: true},
		&cli.StringFlag{Name: TLSKeyFile, Usage: "PEM private key of --tls-cert-file", TakesFile: true},
		&cli.StringFlag{Name: TLSKeystoreFile, Usage: "PKCS#12 keystore with the API's TLS key and certificate chain, instead of PEM; with --tls-keystore-password-file (re-read on SIGHUP)", TakesFile: true},
		&cli.StringFlag{Name: TLSKeystorePasswordFile, Usage: "File whose first line is the password of --tls-keystore-file", TakesFile: true},
		&cli.BoolFlag{Name: TLSGenerateSelfSigned, Usage: "Serve TLS with a self-signed ECDSA P-256 certificate, generated 0600 into <data-path>/tls/ on first start for the --http-host-allowlist names and reused after; a configured certificate takes precedence"},
		&cli.StringFlag{Name: TLSKnownClientsFile, Usage: "Client certificates the mtls modes accept: lines of \"<label> <SHA-256 fingerprint>\" (Web3Signer's format; re-read on SIGHUP)", TakesFile: true},
		&cli.StringFlag{Name: TLSClientCAFile, Usage: "PEM CAs whose client certificates the mtls modes accept; the system roots are never used (re-read on SIGHUP)", TakesFile: true},
		&cli.BoolFlag{Name: MetricsEnabled, Usage: "Serve Prometheus metrics at /metrics on a separate listener"},
		&cli.StringFlag{Name: MetricsHost, Value: DefaultMetricsHost, Usage: "Host the metrics listener binds"},
		&cli.UintFlag{Name: MetricsPort, Value: DefaultMetricsPort, Usage: "Port the metrics listener binds; 0 picks a free port (see the ports file)"},
		&cli.StringSliceFlag{Name: MetricsHostAllowlist, Value: cli.NewStringSlice(DefaultMetricsHostAllowlist...), Usage: "Host header names the metrics listener accepts; * or all accepts any, none refuses all"},
		&cli.StringFlag{Name: MetricsAuthTokenFile, Usage: "Bearer token file the metrics listener requires (generated 0600 when missing; re-read on SIGHUP); unset leaves /metrics open", TakesFile: true},
		&cli.BoolFlag{Name: DisableCoreDumps, Value: true, Usage: "On Linux, make the process non-dumpable (no core dumps, no ptrace or /proc memory reads by other processes) and set its core-file limit to 0"},
		&cli.BoolFlag{Name: MlockAll, Usage: "On Linux, lock all process memory so that keys are never swapped out (needs CAP_IPC_LOCK or an unlimited RLIMIT_MEMLOCK; refused otherwise)"},
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
		&cli.Uint64Flag{Name: PruningEpochsToKeep, Value: DefaultPruningEpochs, Usage: "Epochs of block and attestation history each validator keeps below its newest record (slots per epoch come from the network); older records are pruned"},
		&cli.DurationFlag{Name: PruningInterval, Value: DefaultPruningEvery, Usage: "Time between two slashing-protection pruning runs, as a duration such as 12h or 90m (Web3Signer's bare number of hours is refused); the first runs at startup"},
		&cli.Uint64Flag{Name: RandaoMaxLayers, Value: DefaultRandaoLayers, Usage: "Onion layers searched from x_0 when locating a RANDAO commitment; a commitment deeper in a longer onion is unknown"},
		&cli.Uint64Flag{Name: RandaoReorgWindow, Value: DefaultReorgWindow, Usage: "Layers above a key's released frontier searched for a re-reveal before the slow-path scan"},
		&cli.DurationFlag{Name: RandaoFullScanMinInterval, DefaultText: "SECONDS_PER_SLOT", Usage: "Minimum time between two slow-path RANDAO scans of one key (first use, gap advance, deep reorg); sooner gets 429 RANDAO_SCAN_RATE_LIMITED"},
		&cli.Uint64Flag{Name: RandaoNewLayerBurst, Value: DefaultNewLayerBurst, Usage: "Tokens in each key's RANDAO new-layer bucket: frontier-moving reveals allowed in a burst"},
		&cli.Uint64Flag{Name: RandaoRefillEpochs, Value: DefaultRefillEpochs, Usage: "Epochs per new-layer token refill; 0 turns the bucket off. Networks with fewer than about 4 x SLOTS_PER_EPOCH validators should raise the burst or use 0."},
		&cli.BoolFlag{Name: RandaoProtectionRequired, Usage: "Refuse to start when RANDAO frontiers would be kept in memory only (--slashing-protection-enabled=false)"},
		keystoresPath(), keystoresPasswordFile(), keystoresPasswordsPath(),
	})
}

// The keystore bulk source's flags, which the consensus command and
// `keystore verify` share.
func keystoresPath() *cli.StringFlag {
	return &cli.StringFlag{Name: KeystoresPath, Usage: "Directory of keystores to load: every non-hidden *.json file in it (deposit CLI or qrysm keystore v1)", TakesFile: true}
}

func keystoresPasswordFile() *cli.StringFlag {
	return &cli.StringFlag{Name: KeystoresPasswordFile, Usage: "File holding the password of every keystore in --keystores-path; not with --keystores-passwords-path", TakesFile: true}
}

func keystoresPasswordsPath() *cli.StringFlag {
	return &cli.StringFlag{Name: KeystoresPasswordsPath, Usage: "Directory of password files, <name>.txt for keystore <name>.json; not with --keystores-password-file", TakesFile: true}
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

// Import returns the flags of `consensus import`.
func Import() []cli.Flag {
	return append(withEnv(ConsensusCommand, []cli.Flag{slashingProtectionDBURL()}),
		&cli.StringFlag{Name: From, Usage: "Required. The EIP-3076 interchange file (format version 5) to import", TakesFile: true})
}

// Export returns the flags of `consensus export`.
func Export() []cli.Flag {
	return append(withEnv(ConsensusCommand, []cli.Flag{slashingProtectionDBURL()}),
		&cli.StringFlag{Name: To, Usage: "Required. The EIP-3076 interchange file to write; an existing file is replaced", TakesFile: true},
		&cli.StringSliceFlag{Name: Keys, Usage: "Export only these validators: 0x public keys or 0x sha256 identifiers, comma-separated or repeated"})
}

// WatermarkRepair returns the flags of `consensus watermark-repair`.
func WatermarkRepair() []cli.Flag {
	return append(withEnv(ConsensusCommand, []cli.Flag{slashingProtectionDBURL()}),
		&cli.Uint64Flag{Name: Epoch, DefaultText: "unset", Usage: "Required. Raise every validator's attestation source and target low watermarks to this epoch"},
		&cli.Uint64Flag{Name: Slot, DefaultText: "unset", Usage: "Required. Raise every validator's block low watermark to this slot"})
}

// SetHighWatermark returns the flags of `consensus set-high-watermark`.
func SetHighWatermark() []cli.Flag {
	return append(withEnv(ConsensusCommand, []cli.Flag{slashingProtectionDBURL()}),
		&cli.Uint64Flag{Name: Epoch, DefaultText: "unset", Usage: "Required unless --remove. The high watermark's epoch: attestations with a source or target epoch at or above it are refused"},
		&cli.Uint64Flag{Name: Slot, DefaultText: "unset", Usage: "Required unless --remove. The high watermark's slot: blocks at or above it are refused"},
		&cli.BoolFlag{Name: Remove, Usage: "Remove the high watermark instead of setting one"})
}

// RandaoStateReset returns the flags of `consensus randao-state reset`.
func RandaoStateReset() []cli.Flag {
	return append(withEnv(ConsensusCommand, []cli.Flag{slashingProtectionDBURL()}),
		&cli.StringFlag{Name: Key, Usage: "Required. The key whose RANDAO frontier is cleared: its 0x public key or 0x sha256 of it"})
}

// KeystoreVerify returns the flags of `consensus keystore verify`: --file
// and --password-file check one keystore; --keystores-path with
// --keystores-password-file or --keystores-passwords-path checks a
// directory as the signer loads it. They read no environment variables, so
// that a signer's REMOTESIGNER_CONSENSUS_KEYSTORES_* settings do not leak
// into a check of another keystore.
func KeystoreVerify() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: VerifyFile, Usage: "The keystore to check: qrysm's keystore v1 or a deposit CLI keystore (JSON); with --password-file", TakesFile: true},
		&cli.StringFlag{Name: VerifyPasswordFile, Usage: "File holding the keystore's password; trailing line breaks are not part of it", TakesFile: true},
		keystoresPath(), keystoresPasswordFile(), keystoresPasswordsPath(),
	}
}

// DisableValidatorFlags returns the flags of `consensus disable-validator`.
func DisableValidatorFlags() []cli.Flag {
	return append(withEnv(ConsensusCommand, []cli.Flag{slashingProtectionDBURL()}),
		&cli.StringFlag{Name: Key, Usage: "Required. The key to disable: its 0x public key or 0x sha256 of it"})
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
