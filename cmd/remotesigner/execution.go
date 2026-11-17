// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package main

import (
	"fmt"
	"io"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/execution"
)

// executionRun is the production run function of execution mode.
var executionRun runFunc = execution.Run

func executionCommand(run runFunc, _, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name:            flags.ExecutionCommand,
		Usage:           "run the execution-layer signer: a JSON-RPC endpoint in front of a gqrl node, signing with account keys",
		Flags:           flags.Execution(),
		Before:          applySection(flags.ExecutionCommand),
		OnUsageError:    onUsageError,
		HideHelpCommand: true,
		Action:          modeAction(executionConfigFrom, run, stderr),
	}
}

// maxDownstreamTimeout bounds --downstream-http-request-timeout: an hour.
const maxDownstreamTimeout = time.Hour

// executionConfigFrom resolves the flags of `execution` into a
// configuration. Its errors are usage errors.
func executionConfigFrom(c *cli.Context) (*config.Config, error) {
	cfg, err := globalConfig(c)
	if err != nil {
		return nil, err
	}
	cfg.Execution = config.Execution{
		Downstream: config.Downstream{
			Host:           c.String(flags.DownstreamHTTPHost),
			Path:           c.String(flags.DownstreamHTTPPath),
			Timeout:        time.Duration(c.Uint(flags.DownstreamHTTPRequestTimeout)) * time.Millisecond,
			AuthHeaderFile: c.String(flags.DownstreamHTTPAuthHeaderFile),
			TLS:            c.Bool(flags.DownstreamHTTPTLSEnabled),
			TLSCAFile:      c.String(flags.DownstreamHTTPTLSCAFile),
			ProxyHost:      c.String(flags.DownstreamHTTPProxyHost),
		},
		AllowedMethods:  c.StringSlice(flags.ExecutionProxyAllowedMethods),
		Keystores:       keystoresFrom(c),
		ChainID:         c.Uint64(flags.ChainID),
		PolicyFile:      c.String(flags.ExecutionPolicyFile),
		AuditLogFile:    c.String(flags.ExecutionAuditLogFile),
		NonceCrosscheck: c.Bool(flags.ExecutionNonceCrosscheck),
	}
	d := &cfg.Execution.Downstream
	if d.Port, err = tcpPort(c, flags.DownstreamHTTPPort); err != nil {
		return nil, err
	}
	if d.ProxyPort, err = tcpPort(c, flags.DownstreamHTTPProxyPort); err != nil {
		return nil, err
	}
	switch {
	case d.Host == "":
		return nil, fmt.Errorf("--%s must name a host", flags.DownstreamHTTPHost)
	case d.Port == 0:
		return nil, fmt.Errorf("--%s must be 1 to 65535", flags.DownstreamHTTPPort)
	case d.Timeout <= 0 || d.Timeout > maxDownstreamTimeout:
		return nil, fmt.Errorf("--%s must be 1 to %d (milliseconds)", flags.DownstreamHTTPRequestTimeout,
			maxDownstreamTimeout.Milliseconds())
	case d.TLSCAFile != "" && !d.TLS:
		return nil, fmt.Errorf("--%s needs --%s", flags.DownstreamHTTPTLSCAFile, flags.DownstreamHTTPTLSEnabled)
	case d.ProxyHost != "" && d.ProxyPort == 0:
		return nil, fmt.Errorf("--%s must be 1 to 65535", flags.DownstreamHTTPProxyPort)
	}
	if err := execution.CheckDownstreamPath(d.Path); err != nil {
		return nil, fmt.Errorf("--%s: %w", flags.DownstreamHTTPPath, err)
	}
	if _, err := execution.ParseAllowlist(cfg.Execution.AllowedMethods); err != nil {
		return nil, fmt.Errorf("--%s: %w", flags.ExecutionProxyAllowedMethods, err)
	}
	if err := checkKeystores(cfg.Execution.Keystores); err != nil {
		return nil, err
	}
	if cfg.Execution.ChainID == 0 {
		return nil, fmt.Errorf("--%s is required: the chain ID transactions are signed for", flags.ChainID)
	}
	return cfg, nil
}
