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

	"github.com/rgeraldes24/go-remotesigner/internal/admission"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
)

// Global flag names.
const (
	ConfigFile              = "config-file"
	DataPath                = "data-path"
	KeyConfigPath           = "key-config-path"
	KeyStorePath            = "key-store-path" // alias of KeyConfigPath
	KeyConfigFileMaxSize    = "key-store-config-file-max-size"
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
	MaxConcurrentSigning    = "max-concurrent-signing-requests"
	MaxQueuedSigning        = "max-queued-signing-requests"
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
	KeyManagerAPIAlias        = "enable-key-manager-api" // Web3Signer's alias of KeyManagerAPIEnabled
	AllowUnknownGenesisTime   = "Xallow-unknown-genesis-time"
	AllowGVRTOFU              = "Xallow-gvr-tofu"
	VoluntaryExitSigning      = "voluntary-exit-signing-enabled"
	RegistrationFeeRecipients = "registration-fee-recipient-file"
	SigningClockSkewSlots     = "signing-clock-skew-slots"
	SelectionProofSigning     = "selection-proof-signing"
	SlashingProtectionDBURL   = "slashing-protection-db-url"
	SlashingProtectionDBUser  = "slashing-protection-db-username"
	SlashingProtectionDBPass  = "slashing-protection-db-password-file"
	DBHealthCheckTimeout      = "slashing-protection-db-health-check-timeout-milliseconds"
	DBHealthCheckInterval     = "slashing-protection-db-health-check-interval-milliseconds"
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

// Secret-store flag names of the consensus command, Web3Signer's, and the
// hidden --Xgcp-endpoint-override, which Web3Signer lacks.
const (
	AWSSecretsEnabled         = "aws-secrets-enabled"
	AWSSecretsAuthMode        = "aws-secrets-auth-mode"
	AWSSecretsAccessKeyID     = "aws-secrets-access-key-id"
	AWSSecretsSecretAccessKey = "aws-secrets-secret-access-key"
	AWSSecretsRegion          = "aws-secrets-region"
	AWSEndpointOverride       = "aws-endpoint-override"
	AWSSecretsPrefixesFilter  = "aws-secrets-prefixes-filter"
	AWSSecretsTag             = "aws-secrets-tag"
	AWSConnectionCacheSize    = "aws-connection-cache-size"
	GCPSecretsEnabled         = "gcp-secrets-enabled"
	GCPProjectID              = "gcp-project-id"
	GCPSecretsFilter          = "gcp-secrets-filter"
	GCPEndpointOverride       = "Xgcp-endpoint-override"
	AzureVaultEnabled         = "azure-vault-enabled"
	AzureVaultAuthMode        = "azure-vault-auth-mode"
	AzureVaultName            = "azure-vault-name"
	AzureClientID             = "azure-client-id"
	AzureTenantID             = "azure-tenant-id"
	AzureClientSecret         = "azure-client-secret"
	AzureResponseTimeout      = "azure-response-timeout"
	AzureTags                 = "azure-tags"
	AzureEndpointOverride     = "Xazure-endpoint-override"
	AzureAuthorityOverride    = "Xazure-authority-host-override"
	AzureTrustCertOverride    = "Xazure-trust-certificate-override"
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
	EnableKeys              = "enable-keys"
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
	// DefaultDBHealthCheckTimeout and DefaultDBHealthCheckInterval are
	// Web3Signer's, in milliseconds.
	DefaultDBHealthCheckTimeout  = 3000
	DefaultDBHealthCheckInterval = 30000
	// DefaultReloadTimeout is --reload-timeout in minutes, Web3Signer's
	// unit. At the B10 throughput of the development machine, about 2
	// standard-KDF decrypts a second, it covers about 7,000 new keystores.
	DefaultReloadTimeout = 60
	// MaxSignerLoadParallelism bounds --signer-load-parallelism.
	MaxSignerLoadParallelism = 64
	// DefaultKeyConfigFileMaxSize is Web3Signer's default of
	// --key-store-config-file-max-size, in bytes (100 MiB).
	DefaultKeyConfigFileMaxSize = 104_857_600
	// DefaultAzureResponseTimeout is --azure-response-timeout in seconds.
	DefaultAzureResponseTimeout = 60
)

// Override explains one of the hidden --Xallow-* flags, each of which lifts
// a startup refusal of a non-loopback listener: what is refused without it,
// the risk an operator accepts with it, and the configuration that makes it
// unnecessary. tools/flagdoc renders them into docs/reference/flags.md. The
// other hidden flags, the secret-store overrides (--Xazure-*, --Xgcp-*),
// refuse nothing and are explained on their store pages.
type Override struct {
	Refused string
	Risk    string
	Instead string
}

// Overrides returns the explanation of every --Xallow-* flag, by flag name.
func Overrides() map[string]Override {
	return map[string]Override{
		AllowPlaintextTokenAuth: {
			Refused: "A non-loopback API listener with --http-auth-mode=token and no TLS (no --tls-cert-file, " +
				"--tls-keystore-file or --tls-generate-self-signed). The mtls modes always need TLS, and loopback " +
				"listeners are never refused.",
			Risk: "Every request carries the sign or admin token in clear: anyone who can read the traffic (the " +
				"LAN, the host network, another container on the Docker network) can replay it, sign duties with " +
				"the sign token (slashing protection still applies) and, with the admin token, reload keys, reset " +
				"RANDAO frontiers and, with --key-manager-api-enabled, import and delete keys. Every response can " +
				"be read as well, signatures and RANDAO reveals included.",
			Instead: "Serve TLS: --tls-generate-self-signed, which the container image sets, or --tls-cert-file " +
				"and --tls-key-file, and give the validator client the certificate " +
				"(--validators-external-signer-tls-ca-file). Use the override only on a throwaway test network " +
				"whose keys guard nothing.",
		},
		AllowUnknownGenesisTime: {
			Refused: "A non-loopback API listener when no source gives the genesis time: neither a built-in " +
				"network that knows it, --network-genesis-time nor --network-genesis-state.",
			Risk: "Without a genesis time the signer cannot tell the current slot. Its wall-clock bounds are off, " +
				"so a client with the sign token can have blocks and attestations signed for slots and epochs far " +
				"in the future: signatures it can broadcast later, and slashing-protection records that refuse " +
				"the validator's honest attestations until the chain reaches those epochs. New RANDAO layers are " +
				"refused, so the validators cannot propose, and capabilities reports a null genesis_time, which " +
				"the qrysm validator client refuses at startup.",
			Instead: "Pass --network-genesis-time, or --network-genesis-state with the chain's genesis state.",
		},
		AllowGVRTOFU: {
			Refused: "A non-loopback API listener for a file network when no source gives the genesis validators " +
				"root: neither --network-genesis-validators-root nor --network-genesis-state. A built-in network " +
				"never pins on first use: without one of those flags it refuses to start (exit code 1) on any " +
				"listener, and the override does not change that.",
			Risk: "The first request that carries the network's fork version pins its genesis validators root " +
				"into the slashing-protection store for good, and every later request must match it. Networks " +
				"built from one configuration share their fork version, so the first client to reach the signer " +
				"decides which chain it signs for. When that is another chain that uses the same keys, the signer " +
				"signs for that chain from then on and refuses every request for the intended one. Undoing a wrong " +
				"pin needs a new store.",
			Instead: "Pass --network-genesis-validators-root, or --network-genesis-state with the chain's genesis " +
				"state. Trust on first use is meant for a test network on a loopback listener, as the qrysm " +
				"end-to-end test runs it.",
		},
	}
}

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
		&cli.StringFlag{Name: KeyConfigPath, Aliases: []string{KeyStorePath}, Usage: "Directory of key-config files (*.yaml or *.yml; types file-raw, file-keystore, hashicorp, aws-secret, azure-secret and gcp-secret); unset loads none", TakesFile: true},
		&cli.IntFlag{Name: KeyConfigFileMaxSize, Value: DefaultKeyConfigFileMaxSize, Usage: "Largest key-config file loaded, in bytes (Web3Signer counts code points); a larger file fails to load. Must be above 0."},
		&cli.BoolFlag{Name: StrictFilePermissions, Value: true, Usage: "Refuse secret files (password files, key-config files with a seed or a secret-store credential, the token files, and the TLS private key, keystore and keystore password file) that their group or other users can read, and, with --key-manager-api-enabled, a --key-config-path directory they can access; false loads them with a warning"},
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
		&cli.IntFlag{Name: MaxConcurrentSigning, Value: admission.DefaultConcurrent, Usage: "Sign requests that may be in their slashing check, signature and verification at once; the others wait in the queue (replaces Web3Signer's --vertx-worker-pool-size). Must be at least 1."},
		&cli.IntFlag{Name: MaxQueuedSigning, Value: admission.DefaultQueued, Usage: "Sign requests that may wait for --max-concurrent-signing-requests; one more is refused at once with 503 OVERLOADED and Retry-After. 0 queues none."},
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
		&cli.BoolFlag{Name: SlashingProtectionEnabled, Value: true, Usage: "Slashing protection, in the store --slashing-protection-db-url names (default the bbolt file <data-path>/slashing-protection.db). false is allowed only when every listener is loopback."},
		&cli.BoolFlag{Name: KeyManagerAPIEnabled, Aliases: []string{KeyManagerAPIAlias}, Usage: "Serve the keymanager API (GET, POST and DELETE /qrl/v1/keystores) with the admin token; imported keys are written to --key-config-path, which it requires (docs/operations/keymanager.md)."},
		&cli.BoolFlag{Name: AllowUnknownGenesisTime, Hidden: true, Usage: "Allow a non-loopback listener without a genesis time (wall-clock bounds off)"},
		&cli.BoolFlag{Name: AllowGVRTOFU, Hidden: true, Usage: "Allow a non-loopback listener to pin the genesis validators root on first use"},
		&cli.BoolFlag{Name: VoluntaryExitSigning, Usage: "Sign VOLUNTARY_EXIT requests; refused with 403 ARTIFACT_TYPE_DISABLED otherwise"},
		&cli.StringFlag{Name: RegistrationFeeRecipients, Usage: "YAML list of {key, fee_recipient} pins: a VALIDATOR_REGISTRATION for a pinned key must carry its pinned fee recipient", TakesFile: true},
		&cli.Uint64Flag{Name: SigningClockSkewSlots, Value: DefaultClockSkew, Usage: "Slots a slot-scoped request may lie ahead of the wall clock (when genesis time is known)"},
		&cli.StringFlag{Name: SelectionProofSigning, Value: DefaultSelectionProof, Usage: "Signing mode of AGGREGATION_SLOT and SYNC_COMMITTEE_SELECTION_PROOF: deterministic or hedged; other types are always hedged"},
		slashingProtectionDBURL(), slashingProtectionDBUser(), slashingProtectionDBPassword(),
		&cli.Uint64Flag{Name: DBHealthCheckTimeout, Value: DefaultDBHealthCheckTimeout, Usage: "Milliseconds after which the Postgres store's health check fails (slashing-protection-db-health-check)"},
		&cli.Uint64Flag{Name: DBHealthCheckInterval, Value: DefaultDBHealthCheckInterval, Usage: "Milliseconds between two health checks of the Postgres store; /healthcheck reports the last one"},
		&cli.BoolFlag{Name: SlashingProtectionMigrate, Usage: "Upgrade an older slashing-protection store to this release's schema before starting: a bbolt file is backed up to <file>.v<old>.bak first; a Postgres database without the schema gets it, which needs a role that may create tables"},
		&cli.Uint64Flag{Name: PruningEpochsToKeep, Value: DefaultPruningEpochs, Usage: "Epochs of block and attestation history each validator keeps below its newest record (slots per epoch come from the network); older records are pruned"},
		&cli.DurationFlag{Name: PruningInterval, Value: DefaultPruningEvery, Usage: "Time between two slashing-protection pruning runs, as a duration such as 12h or 90m (Web3Signer's bare number of hours is refused); with bbolt the first runs at startup, with Postgres one interval after it"},
		&cli.Uint64Flag{Name: RandaoMaxLayers, Value: DefaultRandaoLayers, Usage: "Onion layers searched from x_0 when locating a RANDAO commitment; a commitment deeper in a longer onion is unknown"},
		&cli.Uint64Flag{Name: RandaoReorgWindow, Value: DefaultReorgWindow, Usage: "Layers above a key's released frontier searched for a re-reveal before the slow-path scan"},
		&cli.DurationFlag{Name: RandaoFullScanMinInterval, DefaultText: "SECONDS_PER_SLOT", Usage: "Minimum time between two slow-path RANDAO scans of one key (first use, gap advance, deep reorg); sooner gets 429 RANDAO_SCAN_RATE_LIMITED"},
		&cli.Uint64Flag{Name: RandaoNewLayerBurst, Value: DefaultNewLayerBurst, Usage: "Tokens in each key's RANDAO new-layer bucket: frontier-moving reveals allowed in a burst"},
		&cli.Uint64Flag{Name: RandaoRefillEpochs, Value: DefaultRefillEpochs, Usage: "Epochs per new-layer token refill; 0 turns the bucket off. Networks with fewer than about 4 x SLOTS_PER_EPOCH validators should raise the burst or use 0."},
		&cli.BoolFlag{Name: RandaoProtectionRequired, Usage: "Refuse to start when RANDAO frontiers would be kept in memory only (--slashing-protection-enabled=false)"},
		keystoresPath(), keystoresPasswordFile(), keystoresPasswordsPath(),
		&cli.BoolFlag{Name: AWSSecretsEnabled, Usage: "Bulk-load seeds from AWS Secrets Manager: every secret the prefix and tag filters select, one 48-byte seed (hex) per line. Default flavour only."},
		&cli.StringFlag{Name: AWSSecretsAuthMode, Value: secrets.AWSSpecified, Usage: "AWS authentication of the bulk loader: SPECIFIED (--aws-secrets-access-key-id and --aws-secrets-secret-access-key) or ENVIRONMENT (the SDK's default chain: environment, shared credentials and config files, web identity, ECS and EC2 roles)"},
		&cli.StringFlag{Name: AWSSecretsAccessKeyID, Usage: "AWS access key id of SPECIFIED authentication"},
		&cli.StringFlag{Name: AWSSecretsSecretAccessKey, Usage: "AWS secret access key of SPECIFIED authentication; prefer the environment variable, which other users cannot read in the process list"},
		&cli.StringFlag{Name: AWSSecretsRegion, Usage: "AWS region of Secrets Manager; required for SPECIFIED authentication, else the SDK's (AWS_REGION, the shared config file)"},
		&cli.StringFlag{Name: AWSEndpointOverride, Usage: "Secrets Manager endpoint URL instead of AWS's, for the bulk loader (a VPC endpoint, LocalStack)"},
		&cli.StringSliceFlag{Name: AWSSecretsPrefixesFilter, Usage: "Load only the secrets whose names start with one of these prefixes (comma-separated)"},
		&cli.StringSliceFlag{Name: AWSSecretsTag, Usage: "Load only the secrets with these tags: TAG_NAME=TAG_VALUE, repeated or separated by |; a name given twice keeps its last value; AWS matches any of the names and any of the non-empty values"},
		&cli.IntFlag{Name: AWSConnectionCacheSize, Value: secrets.DefaultAWSClientCache, Usage: "AWS Secrets Manager clients kept for aws-secret key-config documents during a load, by credentials and region"},
		&cli.BoolFlag{Name: GCPSecretsEnabled, Usage: "Bulk-load seeds from GCP Secret Manager: the latest version of every secret of --gcp-project-id that --gcp-secrets-filter selects, one 48-byte seed (hex) per line, with Application Default Credentials. Default flavour only."},
		&cli.StringFlag{Name: GCPProjectID, Usage: "GCP project of the bulk loader's secrets"},
		&cli.StringFlag{Name: GCPSecretsFilter, Usage: "Secret Manager list filter (https://cloud.google.com/secret-manager/docs/filtering); empty loads every secret of the project"},
		&cli.StringFlag{Name: GCPEndpointOverride, Hidden: true, Usage: "Secret Manager endpoint host:port instead of Google's; http://host:port is an emulator, reached without TLS and credentials"},
		&cli.BoolFlag{Name: AzureVaultEnabled, Usage: "Bulk-load seeds from the Azure Key Vault --azure-vault-name: every secret with the --azure-tags, one 48-byte seed (hex) per line. Default flavour only."},
		&cli.StringFlag{Name: AzureVaultAuthMode, Value: secrets.AzureClientSecret, Usage: "Azure authentication: CLIENT_SECRET, USER_ASSIGNED_MANAGED_IDENTITY or SYSTEM_ASSIGNED_MANAGED_IDENTITY"},
		&cli.StringFlag{Name: AzureVaultName, Usage: "Name of the key vault, the subdomain of vault.azure.net"},
		&cli.StringFlag{Name: AzureClientID, Usage: "Client id of CLIENT_SECRET or USER_ASSIGNED_MANAGED_IDENTITY authentication; optional for SYSTEM_ASSIGNED_MANAGED_IDENTITY"},
		&cli.StringFlag{Name: AzureTenantID, Usage: "Microsoft Entra ID tenant of CLIENT_SECRET authentication"},
		&cli.StringFlag{Name: AzureClientSecret, Usage: "Client secret of CLIENT_SECRET authentication; prefer the environment variable, which other users cannot read in the process list"},
		&cli.UintFlag{Name: AzureResponseTimeout, Value: DefaultAzureResponseTimeout, Usage: "Seconds each Azure request and call may take"},
		&cli.StringSliceFlag{Name: AzureTags, Usage: "Load only the secrets that carry all these tags: TAG_NAME=TAG_VALUE, repeated or separated by |; a name given twice keeps its last value"},
		&cli.StringFlag{Name: AzureEndpointOverride, Hidden: true, Usage: "Key Vault URL instead of https://<vault>.vault.azure.net"},
		&cli.StringFlag{Name: AzureAuthorityOverride, Hidden: true, Usage: "Microsoft Entra ID authority host URL instead of Azure's"},
		&cli.StringFlag{Name: AzureTrustCertOverride, Hidden: true, Usage: "Certificate file (PEM or DER) trusted for the Key Vault and authority connections instead of the system roots", TakesFile: true},
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
// consensus command and its store subcommands share, like the user name and
// password file of a Postgres store.
func slashingProtectionDBURL() cli.Flag {
	return &cli.StringFlag{Name: SlashingProtectionDBURL, Usage: "Slashing-protection store: bolt:///absolute/path/file.db (default <data-path>/slashing-protection.db), or a Postgres database as postgres://user@host:port/database?sslmode=verify-full (jdbc:postgresql:// is accepted) without a password, migrated with consensus migrate"}
}

func slashingProtectionDBUser() cli.Flag {
	return &cli.StringFlag{Name: SlashingProtectionDBUser, Usage: "User name for the Postgres store, instead of the URL's"}
}

func slashingProtectionDBPassword() cli.Flag {
	return &cli.StringFlag{Name: SlashingProtectionDBPass, Usage: "File whose first line is the Postgres store's password (owner-readable only, like other secret files); without it the password comes from PGPASSFILE (default ~/.pgpass), under the same rule. PGPASSWORD, a password in the URL and one in a pg_service.conf service are refused.", TakesFile: true}
}

// storeFlags are the flags that name a store, which every store subcommand
// takes.
func storeFlags() []cli.Flag {
	return withEnv(ConsensusCommand, []cli.Flag{slashingProtectionDBURL(), slashingProtectionDBUser(), slashingProtectionDBPassword()})
}

// Migrate returns the flags of `consensus migrate`.
func Migrate() []cli.Flag {
	return storeFlags()
}

// Import returns the flags of `consensus import`.
func Import() []cli.Flag {
	return append(storeFlags(),
		&cli.StringFlag{Name: From, Usage: "Required. The EIP-3076 interchange file (format version 5) to import", TakesFile: true},
		&cli.StringSliceFlag{Name: EnableKeys, Usage: "Keys disabled on purpose (keymanager DELETE, disable-validator) that their element in the file enables when it imports: 0x public keys or 0x sha256 identifiers, comma-separated or repeated. Without it such a key stays disabled; a key an earlier import disabled is enabled anyway."})
}

// Export returns the flags of `consensus export`.
func Export() []cli.Flag {
	return append(storeFlags(),
		&cli.StringFlag{Name: To, Usage: "Required. The EIP-3076 interchange file to write; an existing file is replaced", TakesFile: true},
		&cli.StringSliceFlag{Name: Keys, Usage: "Export only these validators: 0x public keys or 0x sha256 identifiers, comma-separated or repeated"})
}

// WatermarkRepair returns the flags of `consensus watermark-repair`.
func WatermarkRepair() []cli.Flag {
	return append(storeFlags(),
		&cli.Uint64Flag{Name: Epoch, DefaultText: "unset", Usage: "Required. Raise every validator's attestation source and target low watermarks to this epoch"},
		&cli.Uint64Flag{Name: Slot, DefaultText: "unset", Usage: "Required. Raise every validator's block low watermark to this slot"})
}

// SetHighWatermark returns the flags of `consensus set-high-watermark`.
func SetHighWatermark() []cli.Flag {
	return append(storeFlags(),
		&cli.Uint64Flag{Name: Epoch, DefaultText: "unset", Usage: "Required unless --remove. The high watermark's epoch: attestations with a source or target epoch at or above it are refused"},
		&cli.Uint64Flag{Name: Slot, DefaultText: "unset", Usage: "Required unless --remove. The high watermark's slot: blocks at or above it are refused"},
		&cli.BoolFlag{Name: Remove, Usage: "Remove the high watermark instead of setting one"})
}

// RandaoStateReset returns the flags of `consensus randao-state reset`.
func RandaoStateReset() []cli.Flag {
	return append(storeFlags(),
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
	return append(storeFlags(),
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
