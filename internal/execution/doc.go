// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

// Package execution runs `remotesigner execution`: a JSON-RPC 2.0 endpoint
// at POST / in front of a gqrl node, in a process of its own, behind the same
// authentication, TLS, host allowlist, Origin refusal, connection cap and
// body gate as consensus mode (docs/operations/execution.md).
//
// It answers qrl_accounts, qrl_sign and health_status with the loaded
// account keys, serves GET /api/v1/execution/publicKeys, and forwards the
// methods that --execution-proxy-allowed-methods allows to the node with
// httputil.ReverseProxy: client credentials and forwarding headers never
// reach the node, the node's cookies and CORS headers never reach the
// client, no redirect is followed, and responses are capped at 25 MB.
// Batches of up to 1,000 requests are split between the two and answered
// in request order. Account keys are 51-byte extended seeds: file-raw key
// configs and go-qrl account keystores.
//
// Every file of the package is built only without the noexecution tag, so
// the consensus-only flavour has no execution mode. It is the only package
// that may import go-qrl; it imports none yet.
package execution
