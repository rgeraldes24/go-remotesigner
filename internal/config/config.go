// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Package config holds the resolved configuration of a `remotesigner
// consensus` run and the startup fail-safes that refuse unsafe combinations.
// It also derives the environment variable names of the flags and reads the
// --config-file YAML source (env.go, yaml.go).
package config

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/logging"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
)

// File names under --data-path.
const (
	SignTokenFileName      = "auth-token"
	AdminTokenFileName     = "admin-token"
	SlashingProtectionFile = "slashing-protection.db"
)

// Config is a resolved `consensus` configuration.
type Config struct {
	// DataPath holds the token files, the bbolt store and the ports file.
	DataPath string
	// KeyConfigPath is the key-config directory; empty means no key-config
	// source.
	KeyConfigPath string
	Logging       logging.Config
	HTTP          HTTP
	// AllowPlaintextTokenAuth is --Xallow-plaintext-token-auth.
	AllowPlaintextTokenAuth bool
	Consensus               Consensus
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

// Consensus holds the consensus subcommand's settings.
type Consensus struct {
	Network                   network.Sources
	SlashingProtectionEnabled bool
	KeyManagerAPIEnabled      bool
	// AllowUnknownGenesisTime is --Xallow-unknown-genesis-time.
	AllowUnknownGenesisTime bool
	// AllowGVRTOFU is --Xallow-gvr-tofu.
	AllowGVRTOFU bool
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

// SlashingProtectionDB is the bbolt store file, <data-path>/slashing-protection.db.
func (c *Config) SlashingProtectionDB() string {
	return c.orDataPath("", SlashingProtectionFile)
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
	ErrPlaintextToken                = fmt.Errorf("%w: token auth over plaintext HTTP on a non-loopback listener sends the token in clear; set --Xallow-plaintext-token-auth to accept that", ErrRefused)
	ErrLoopbackAllowlist             = fmt.Errorf("%w: a non-loopback listener with a host allowlist of loopback names only refuses every remote client; add the names clients use to --http-host-allowlist", ErrRefused)
	ErrKeyManagerNoAdmin             = fmt.Errorf("%w: --key-manager-api-enabled needs an admin token (--http-admin-token-file or --data-path)", ErrRefused)
	ErrProtectionDisabledNonLoopback = fmt.Errorf("%w: --slashing-protection-enabled=false is allowed only when every listener is loopback", ErrRefused)
	ErrGVRTOFUNonLoopback            = fmt.Errorf("%w: the genesis validators root is unknown and would be pinned on first use, which a non-loopback listener allows only with --Xallow-gvr-tofu; set --network-genesis-validators-root or --network-genesis-state", ErrRefused)
	ErrUnknownGenesisNonLoopback     = fmt.Errorf("%w: genesis time is unknown, so the wall-clock bounds are off, which a non-loopback listener allows only with --Xallow-unknown-genesis-time; set --network-genesis-time or --network-genesis-state", ErrRefused)
	ErrNoDataPath                    = fmt.Errorf("%w: slashing protection needs --data-path for its store", ErrRefused)
	ErrNoSignToken                   = fmt.Errorf("%w: --http-auth-mode=token needs --http-auth-token-file or --data-path", ErrRefused)
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
	refuse(c.Consensus.SlashingProtectionEnabled && c.DataPath == "", ErrNoDataPath)
	refuse(c.HTTP.AuthMode == auth.ModeToken && c.SignTokenFile() == "", ErrNoSignToken)
	refuse(c.Consensus.KeyManagerAPIEnabled && c.AdminTokenFile() == "", ErrKeyManagerNoAdmin)
	if !IsLoopbackHost(c.HTTP.ListenHost) {
		refuse(!c.Consensus.SlashingProtectionEnabled, ErrProtectionDisabledNonLoopback)
		refuse(c.HTTP.AuthMode == auth.ModeNone, ErrAuthNoneNonLoopback)
		// This build has no TLS, so token auth is always plaintext.
		refuse(c.HTTP.AuthMode == auth.ModeToken && !c.AllowPlaintextTokenAuth, ErrPlaintextToken)
		refuse(loopbackOnly(c.HTTP.HostAllowlist), ErrLoopbackAllowlist)
		refuse(n.TOFUAllowed() && !c.Consensus.AllowGVRTOFU, ErrGVRTOFUNonLoopback)
		refuse(!n.GenesisTimeKnown() && !c.Consensus.AllowUnknownGenesisTime, ErrUnknownGenesisNonLoopback)
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
