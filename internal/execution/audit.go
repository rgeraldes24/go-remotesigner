// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Audit outcomes.
const (
	// AuditSigned is a signed transaction, written before it leaves the
	// signer: returned by qrl_signTransaction or sent by qrl_sendTransaction.
	AuditSigned = "signed"
	// AuditSent is a transaction the node accepted.
	AuditSent = "sent"
	// AuditNodeRefused is a signed transaction the node refused.
	AuditNodeRefused = "node-refused"
	// AuditRefused is a transaction the signer refused to sign.
	AuditRefused = "refused"
)

// AuditEntry is one line of the audit log. Quantities are 0x hex, as in
// JSON-RPC; to is absent for a contract creation, and the fields the
// signer did not know when it refused are absent too.
type AuditEntry struct {
	Time    string `json:"time"`
	Method  string `json:"method"`
	Outcome string `json:"outcome"`
	Hash    string `json:"hash,omitempty"`
	From    string `json:"from,omitempty"`
	To      string `json:"to,omitempty"`
	Nonce   string `json:"nonce,omitempty"`
	Value   string `json:"value,omitempty"`
	// Fee is gas × maxFeePerGas, the most the transaction can pay.
	Fee     string `json:"fee,omitempty"`
	ChainID string `json:"chainId,omitempty"`
	// Reason says why the signer or the node refused.
	Reason string `json:"reason,omitempty"`
}

// errAuditClosed reports a write after Close.
var errAuditClosed = errors.New("execution: the audit log is closed")

// AuditLog is the append-only JSON Lines file of --execution-audit-log-file:
// one entry per signed transaction, per answer of the node to a sent one,
// and per refusal. Each entry is written and synced before the call goes
// on, so a signature leaves the signer only once its entry is on disk.
// Reopen opens the path again, for log rotation (SIGHUP).
type AuditLog struct {
	path string
	now  func() time.Time

	mu sync.Mutex
	f  *os.File
}

// OpenAuditLog opens (creating, mode 0600) the audit log at path for
// appending.
func OpenAuditLog(path string) (*AuditLog, error) {
	a := &AuditLog{path: path, now: time.Now}
	f, err := openAppend(path)
	if err != nil {
		return nil, err
	}
	a.f = f
	return a, nil
}

func openAppend(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("--execution-audit-log-file: %w", err)
	}
	return f, nil
}

// Write appends e, stamped with the current time, and syncs the file.
func (a *AuditLog) Write(e AuditEntry) error {
	e.Time = a.now().UTC().Format(time.RFC3339Nano)
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return errAuditClosed
	}
	if _, err := a.f.Write(line); err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	if err := a.f.Sync(); err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	return nil
}

// Reopen closes the file and opens the path again. On failure the old file
// stays in use.
func (a *AuditLog) Reopen() error {
	f, err := openAppend(a.path)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		_ = f.Close()
		return errAuditClosed
	}
	old := a.f
	a.f = f
	return old.Close()
}

// Close closes the file; later writes fail.
func (a *AuditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return nil
	}
	err := a.f.Close()
	a.f = nil
	return err
}
