// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package config holds the resolved configuration of a `remotesigner
// consensus` or `remotesigner execution` run and the startup fail-safes that
// refuse unsafe combinations.
// It also derives the environment variable names of the flags and reads the
// --config-file YAML source (env.go, yaml.go).
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/admission"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/hygiene"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secrets"
	"github.com/rgeraldes24/go-remotesigner/internal/logging"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
	"github.com/rgeraldes24/go-remotesigner/internal/server/tlsconf"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/pgstore"
)

// File names under --data-path.
const (
	SignTokenFileName      = "auth-token"
	AdminTokenFileName     = "admin-token"
	SlashingProtectionFile = "slashing-protection.db"
	// SelfSignedTLSDir holds the certificate of --tls-generate-self-signed.
	SelfSignedTLSDir = "tls"
)

// Config is a resolved `consensus` configuration.
type Config struct {
	// Version is the release, as process_release reports it.
	Version string
	// DataPath holds the token files, the bbolt store and the ports file.
	DataPath string
	// KeyConfigPath is the key-config directory; empty means no key-config
	// source.
	KeyConfigPath string
	// KeyConfigFileMaxSize is --key-store-config-file-max-size: the largest
	// key-config file loaded, in bytes.
	KeyConfigFileMaxSize int64
	// StrictFilePermissions is --strict-file-permissions: refuse secret
	// files readable by group or other users instead of warning.
	StrictFilePermissions bool
	// ReloadTimeout is --reload-timeout: how long a POST /reload may load
	// keys before the sources not loaded yet keep their previous keys.
	ReloadTimeout time.Duration
	// SignerLoadParallelism is --signer-load-parallelism; 0 sizes the
	// Argon2id semaphore from the memory limit.
	SignerLoadParallelism int
	// Signing bounds the sign requests served at once.
	Signing Signing
	Logging logging.Config
	HTTP    HTTP
	// TLS holds the API listener's --tls-* flags.
	TLS tlsconf.Config
	// AllowPlaintextTokenAuth is --Xallow-plaintext-token-auth.
	AllowPlaintextTokenAuth bool
	Metrics                 Metrics
	// Hygiene is --disable-core-dumps and --mlock-all.
	Hygiene   hygiene.Config
	Consensus Consensus
	Execution Execution
}

// Execution holds the execution subcommand's settings.
type Execution struct {
	Downstream Downstream
	// AllowedMethods is --execution-proxy-allowed-methods: the methods
	// forwarded to the downstream node.
	AllowedMethods []string
	// Keystores is the go-qrl account keystore directory.
	Keystores Keystores
	// ChainID is --chain-id, the chain transactions are signed for.
	ChainID uint64
	// PolicyFile is --execution-policy-file; empty applies the default fee
	// cap only.
	PolicyFile string
	// AuditLogFile is --execution-audit-log-file; empty keeps no audit log.
	AuditLogFile string
	// NonceCrosscheck is --execution-nonce-crosscheck: refuse a nonce the
	// node fills in far above its pending nonce.
	NonceCrosscheck bool
}

// Downstream is the node execution mode forwards to (--downstream-http-*).
type Downstream struct {
	Host string
	Port uint16
	// Path is --downstream-http-path, the path requests are posted to.
	Path string
	// Timeout bounds the connection, the TLS handshake and the wait for the
	// response headers.
	Timeout time.Duration
	// AuthHeaderFile holds the Authorization value sent downstream; empty
	// sends none.
	AuthHeaderFile string
	// TLS connects with https, verifying the node's certificate against
	// TLSCAFile, or the system roots when it is empty.
	TLS       bool
	TLSCAFile string
	// ProxyHost and ProxyPort name an HTTP proxy to the node; an empty
	// host connects directly.
	ProxyHost string
	ProxyPort uint16
}

// Metrics configures the metrics listener.
type Metrics struct {
	Enabled       bool
	Host          string
	Port          uint16
	HostAllowlist []string
	// AuthTokenFile is --metrics-auth-token-file; empty leaves the listener
	// open.
	AuthTokenFile string
}

// Addr returns host:port of the metrics listener.
func (m *Metrics) Addr() string {
	return net.JoinHostPort(m.Host, strconv.Itoa(int(m.Port)))
}

// HTTP configures the API listener.
type HTTP struct {
	ListenHost    string
	ListenPort    uint16
	HostAllowlist []string
	AuthMode      auth.Mode
	// AuthTokenFile and AdminTokenFile are the flag values; see
	// Config.SignTokenFile and Config.AdminTokenFile for the defaults.
	AuthTokenFile  string
	AdminTokenFile string
	MaxConnections int
	IdleTimeout    time.Duration
	AccessLogs     bool
}

// Signing is the signing gate: --max-concurrent-signing-requests and
// --max-queued-signing-requests. The zero value means their defaults.
type Signing struct {
	// MaxConcurrent is how many sign requests may be in their slashing
	// check, signature and verification at once.
	MaxConcurrent int
	// MaxQueued is how many more may wait for a slot; beyond them a request
	// is refused with 503 OVERLOADED.
	MaxQueued int
}

// Limits returns the gate's slots and queue size: the defaults for the zero
// value, which the command line never gives (--max-concurrent-signing-requests
// is at least 1).
func (s Signing) Limits() (concurrent, queued int) {
	if s == (Signing{}) {
		return admission.DefaultConcurrent, admission.DefaultQueued
	}
	return s.MaxConcurrent, s.MaxQueued
}

// Consensus holds the consensus subcommand's settings.
type Consensus struct {
	Network                   network.Sources
	SlashingProtectionEnabled bool
	KeyManagerAPIEnabled      bool
	// AllowUnknownGenesisTime is --Xallow-unknown-genesis-time.
	AllowUnknownGenesisTime bool
	// AllowGVRTOFU is --Xallow-gvr-tofu.
	AllowGVRTOFU bool
	// VoluntaryExitsEnabled is --voluntary-exit-signing-enabled.
	VoluntaryExitsEnabled bool
	// FeeRecipientFile is --registration-fee-recipient-file; empty means no
	// pins.
	FeeRecipientFile string
	// ClockSkewSlots is --signing-clock-skew-slots.
	ClockSkewSlots uint64
	// SelectionProofMode is --selection-proof-signing.
	SelectionProofMode mldsa87.Mode
	// SlashingProtectionDBPath is the bbolt file named by
	// --slashing-protection-db-url; empty means the default under
	// --data-path.
	SlashingProtectionDBPath string
	// Postgres is the Postgres store a postgres:// URL in
	// --slashing-protection-db-url names; an empty URL means bbolt.
	Postgres Postgres
	// SlashingProtectionDBMigrate is --slashing-protection-db-migrate.
	SlashingProtectionDBMigrate bool
	Randao                      Randao
	Pruning                     Pruning
	Keystores                   Keystores
	SecretStores                SecretStores
}

// SecretStores holds the secret-store settings: the client cache of
// aws-secret documents and the bulk loaders, each nil when disabled.
type SecretStores struct {
	// AWSClientCacheSize is --aws-connection-cache-size.
	AWSClientCacheSize int
	AWS                *secrets.AWSBulk   // --aws-secrets-enabled
	Azure              *secrets.AzureBulk // --azure-vault-enabled
	GCP                *secrets.GCPBulk   // --gcp-secrets-enabled
}

// Postgres holds the Postgres store's settings.
type Postgres struct {
	// URL is the connection URL, postgres:// or postgresql://, without a
	// password; empty means no Postgres store.
	URL string
	// Username is --slashing-protection-db-username; empty keeps the URL's.
	Username string
	// PasswordFile is --slashing-protection-db-password-file; empty leaves
	// the password to PGPASSFILE (by default ~/.pgpass).
	PasswordFile string
	// HealthCheckTimeout and HealthCheckInterval are the
	// --slashing-protection-db-health-check-* settings.
	HealthCheckTimeout  time.Duration
	HealthCheckInterval time.Duration
}

// Pruning holds the --slashing-protection-pruning-* settings.
type Pruning struct {
	// EpochsToKeep is how many epochs of history each validator keeps.
	EpochsToKeep uint64
	// Interval is the time between two pruning runs; the first runs at startup.
	Interval time.Duration
}

// Keystores is the keystore bulk source: --keystores-path with one of
// --keystores-password-file and --keystores-passwords-path. An empty Path
// means no keystore source.
type Keystores struct {
	Path          string
	PasswordFile  string
	PasswordsPath string
}

// Randao holds the --randao-* settings of the reveal service.
type Randao struct {
	MaxLayers   uint64
	ReorgWindow uint64
	// FullScanMinInterval is the per-key slow-path budget; zero means
	// SECONDS_PER_SLOT.
	FullScanMinInterval  time.Duration
	NewLayerBurst        uint64
	NewLayerRefillEpochs uint64
	// ProtectionRequired is --randao-protection-required.
	ProtectionRequired bool
}

// ListenAddr returns host:port of the API listener.
func (c *Config) ListenAddr() string {
	return net.JoinHostPort(c.HTTP.ListenHost, strconv.Itoa(int(c.HTTP.ListenPort)))
}

// SignTokenFile is --http-auth-token-file, else <data-path>/auth-token, else
// "" (no sign token can exist).
func (c *Config) SignTokenFile() string {
	return c.orDataPath(c.HTTP.AuthTokenFile, SignTokenFileName)
}

// AdminTokenFile is --http-admin-token-file, else <data-path>/admin-token,
// else "" (no admin token, so no admin routes).
func (c *Config) AdminTokenFile() string {
	return c.orDataPath(c.HTTP.AdminTokenFile, AdminTokenFileName)
}

// SelfSignedTLSPath is <data-path>/tls, where --tls-generate-self-signed
// keeps its certificate, or "" without a data path.
func (c *Config) SelfSignedTLSPath() string { return c.orDataPath("", SelfSignedTLSDir) }

// SlashingProtectionDB is the bbolt store file: the path of
// --slashing-protection-db-url, else <data-path>/slashing-protection.db.
// It is not used when Consensus.Postgres names a Postgres store.
func (c *Config) SlashingProtectionDB() string {
	return c.orDataPath(c.Consensus.SlashingProtectionDBPath, SlashingProtectionFile)
}

// DBURL is a parsed --slashing-protection-db-url: exactly one of its
// fields is set.
type DBURL struct {
	// Path is the file of a bolt:/// URL.
	Path string
	// Postgres is a postgres:// or postgresql:// connection URL; a
	// jdbc:postgresql:// URL is rewritten to postgresql://.
	Postgres string
}

// ParseDBURL parses a --slashing-protection-db-url: bolt:/// and an
// absolute file path, or a Postgres URL without a password.
func ParseDBURL(raw string) (DBURL, error) {
	if pg, ok := strings.CutPrefix(raw, "jdbc:"); ok && strings.HasPrefix(pg, "postgresql:") {
		raw = pg
	}
	u, err := url.Parse(raw)
	if err != nil {
		return DBURL{}, errors.New("not a URL; want bolt:///path/to/file.db or postgres://user@host/database")
	}
	switch {
	case u.Scheme == "postgres" || u.Scheme == "postgresql":
		if err := pgstore.CheckURL(raw); err != nil {
			return DBURL{}, err
		}
		return DBURL{Postgres: raw}, nil
	case u.Scheme != "bolt":
		return DBURL{}, errors.New("unsupported scheme; want bolt:///path/to/file.db or postgres://user@host/database")
	case u.Host != "" || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil:
		return DBURL{}, errors.New("want bolt:/// followed by an absolute file path, with no host or query")
	case !filepath.IsAbs(u.Path) || strings.HasSuffix(u.Path, "/"):
		return DBURL{}, errors.New("want bolt:/// followed by an absolute file path")
	}
	return DBURL{Path: filepath.Clean(u.Path)}, nil
}

func (c *Config) orDataPath(flag, name string) string {
	switch {
	case flag != "":
		return flag
	case c.DataPath != "":
		return filepath.Join(c.DataPath, name)
	default:
		return ""
	}
}

// Startup refusals. Each wraps ErrRefused.
var (
	ErrRefused                       = errors.New("refusing to start")
	ErrAuthNoneNonLoopback           = fmt.Errorf("%w: --http-auth-mode=none is allowed only on a loopback listener", ErrRefused)
	ErrPlaintextToken                = fmt.Errorf("%w: token auth over plaintext HTTP on a non-loopback listener sends the token in clear; configure TLS (--tls-cert-file and --tls-key-file, --tls-keystore-file, or --tls-generate-self-signed) or set --Xallow-plaintext-token-auth to accept that", ErrRefused)
	ErrLoopbackAllowlist             = fmt.Errorf("%w: a non-loopback listener with a host allowlist of loopback names only refuses every remote client; add the names clients use to --http-host-allowlist", ErrRefused)
	ErrMetricsLoopbackAllowlist      = fmt.Errorf("%w: a non-loopback metrics listener with a host allowlist of loopback names only refuses every remote scraper; add the names scrapers use to --metrics-host-allowlist", ErrRefused)
	ErrKeyManagerNoAdmin             = fmt.Errorf("%w: --key-manager-api-enabled needs an admin token (--http-admin-token-file or --data-path)", ErrRefused)
	ErrKeyManagerNoKeyConfig         = fmt.Errorf("%w: --key-manager-api-enabled needs --key-config-path, the directory it writes imported keys to", ErrRefused)
	ErrProtectionDisabledNonLoopback = fmt.Errorf("%w: --slashing-protection-enabled=false is allowed only when every listener is loopback", ErrRefused)
	ErrGVRTOFUNonLoopback            = fmt.Errorf("%w: the genesis validators root is unknown and would be pinned on first use, which a non-loopback listener allows only with --Xallow-gvr-tofu; set --network-genesis-validators-root or --network-genesis-state", ErrRefused)
	ErrUnknownGenesisNonLoopback     = fmt.Errorf("%w: genesis time is unknown, so the wall-clock bounds are off, which a non-loopback listener allows only with --Xallow-unknown-genesis-time; set --network-genesis-time or --network-genesis-state", ErrRefused)
	ErrNoDataPath                    = fmt.Errorf("%w: slashing protection needs --data-path or --slashing-protection-db-url for its store", ErrRefused)
	ErrRandaoProtectionRequired      = fmt.Errorf("%w: --randao-protection-required refuses to keep RANDAO frontiers in memory, which --slashing-protection-enabled=false does", ErrRefused)
	ErrNoSignToken                   = fmt.Errorf("%w: --http-auth-mode=token and token+mtls need --http-auth-token-file or --data-path", ErrRefused)
	ErrSelfSignedNoDataPath          = fmt.Errorf("%w: --tls-generate-self-signed needs --data-path for its certificate", ErrRefused)
	ErrPolicyFileNonLoopback         = fmt.Errorf("%w: execution mode on a non-loopback listener signs transactions only under a policy; set --execution-policy-file", ErrRefused)
)

// CheckFailSafes applies the startup fail-safes that depend only on the
// configuration and the resolved network, and returns every refusal that
// applies, joined. The store checks (schema version, pinned GVR) run when the
// store opens.
func CheckFailSafes(c *Config, n *network.Network) error {
	var errs []error
	refuse := func(cond bool, err error) {
		if cond {
			errs = append(errs, err)
		}
	}
	refuse(c.Consensus.SlashingProtectionEnabled && c.Consensus.Postgres.URL == "" && c.SlashingProtectionDB() == "",
		ErrNoDataPath)
	refuse(c.Consensus.Randao.ProtectionRequired && !c.Consensus.SlashingProtectionEnabled, ErrRandaoProtectionRequired)
	refuse(c.HTTP.AuthMode.SignToken() && c.SignTokenFile() == "", ErrNoSignToken)
	if err := c.TLS.Validate(c.HTTP.AuthMode.ClientCerts()); err != nil {
		errs = append(errs, fmt.Errorf("%w: %w", ErrRefused, err))
	}
	refuse(c.TLS.GenerateSelfSigned && !c.TLS.HasCertificate() && c.DataPath == "", ErrSelfSignedNoDataPath)
	refuse(c.Consensus.KeyManagerAPIEnabled && c.AdminTokenFile() == "", ErrKeyManagerNoAdmin)
	refuse(c.Consensus.KeyManagerAPIEnabled && c.KeyConfigPath == "", ErrKeyManagerNoKeyConfig)
	if c.Metrics.Enabled && !IsLoopbackHost(c.Metrics.Host) {
		refuse(!c.Consensus.SlashingProtectionEnabled && IsLoopbackHost(c.HTTP.ListenHost), ErrProtectionDisabledNonLoopback)
		refuse(loopbackOnly(c.Metrics.HostAllowlist), ErrMetricsLoopbackAllowlist)
	}
	if !IsLoopbackHost(c.HTTP.ListenHost) {
		refuse(!c.Consensus.SlashingProtectionEnabled, ErrProtectionDisabledNonLoopback)
		refuse(c.HTTP.AuthMode == auth.ModeNone, ErrAuthNoneNonLoopback)
		// The mtls modes cannot run without TLS (TLS.Validate above).
		refuse(c.HTTP.AuthMode == auth.ModeToken && !c.TLS.Enabled() && !c.AllowPlaintextTokenAuth, ErrPlaintextToken)
		refuse(loopbackOnly(c.HTTP.HostAllowlist), ErrLoopbackAllowlist)
		refuse(n.TOFUAllowed() && !c.Consensus.AllowGVRTOFU, ErrGVRTOFUNonLoopback)
		refuse(!n.GenesisTimeKnown() && !c.Consensus.AllowUnknownGenesisTime, ErrUnknownGenesisNonLoopback)
	}
	return errors.Join(errs...)
}

// CheckExecutionFailSafes applies the startup fail-safes of execution mode:
// the listener and credential refusals that consensus mode applies too, and
// the policy file that a non-loopback listener requires.
func CheckExecutionFailSafes(c *Config) error {
	var errs []error
	refuse := func(cond bool, err error) {
		if cond {
			errs = append(errs, err)
		}
	}
	refuse(c.HTTP.AuthMode.SignToken() && c.SignTokenFile() == "", ErrNoSignToken)
	if err := c.TLS.Validate(c.HTTP.AuthMode.ClientCerts()); err != nil {
		errs = append(errs, fmt.Errorf("%w: %w", ErrRefused, err))
	}
	refuse(c.TLS.GenerateSelfSigned && !c.TLS.HasCertificate() && c.DataPath == "", ErrSelfSignedNoDataPath)
	if c.Metrics.Enabled && !IsLoopbackHost(c.Metrics.Host) {
		refuse(loopbackOnly(c.Metrics.HostAllowlist), ErrMetricsLoopbackAllowlist)
	}
	if !IsLoopbackHost(c.HTTP.ListenHost) {
		refuse(c.HTTP.AuthMode == auth.ModeNone, ErrAuthNoneNonLoopback)
		refuse(c.HTTP.AuthMode == auth.ModeToken && !c.TLS.Enabled() && !c.AllowPlaintextTokenAuth, ErrPlaintextToken)
		refuse(loopbackOnly(c.HTTP.HostAllowlist), ErrLoopbackAllowlist)
		refuse(c.Execution.PolicyFile == "", ErrPolicyFileNonLoopback)
	}
	return errors.Join(errs...)
}

// IsLoopbackHost reports whether a listen host binds loopback only:
// "localhost" or a loopback IP. The empty host, 0.0.0.0, :: and every other
// name bind beyond loopback.
func IsLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// loopbackOnly reports whether a non-empty allowlist names only loopback
// hosts. "*" is not a loopback name.
func loopbackOnly(allowlist []string) bool {
	if len(allowlist) == 0 {
		return false
	}
	for _, h := range allowlist {
		if !IsLoopbackHost(strings.TrimSpace(h)) {
			return false
		}
	}
	return true
}
