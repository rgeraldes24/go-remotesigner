// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

// Package execution runs `remotesigner execution`: a JSON-RPC 2.0 endpoint
// at POST / in front of a gqrl node, in a process of its own, behind the same
// authentication, TLS, host allowlist, Origin refusal, connection cap and
// body gate as consensus mode (docs/operations/execution.md).
//
// It answers qrl_accounts, qrl_sign, qrl_signTransaction,
// qrl_sendTransaction and health_status with the loaded account keys,
// serves GET /api/v1/execution/publicKeys, and forwards the methods that
// --execution-proxy-allowed-methods allows to the node with
// httputil.ReverseProxy: client credentials and forwarding headers never
// reach the node, the node's cookies and CORS headers never reach the
// client, no redirect is followed, and responses are capped at 25 MB.
// Batches of up to 1,000 requests are split between the two and answered
// in request order. Account keys are 51-byte extended seeds: file-raw key
// configs and go-qrl account keystores.
//
// Transactions are go-qrl's own: a types.DynamicFeeTx signed with
// types.SignTx and types.NewZondSigner(--chain-id) through a
// pqcrypto/wallet.Wallet over the loaded key (wallet.go). The chain ID,
// the fee cap and the per-account policy of --execution-policy-file apply
// to both transaction methods, and the audit log of
// --execution-audit-log-file records what was signed and refused.
// qrl_sendTransaction completes a transaction with the node's
// qrl_fillTransaction under a payload check, signs it, sends it with
// qrl_sendRawTransaction and retries when the node reports its nonce as
// taken.
//
// Every file of the package is built only without the noexecution tag, so
// the consensus-only flavour has no execution mode. It is the only package
// that imports go-qrl (LGPL-3.0-or-later): its library packages, never
// cmd/** or internal/**.
package execution
