// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build !noexecution

package execution

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rgeraldes24/go-remotesigner/internal/api/jsonutil"
)

// Policy limits.
const (
	// maxPolicyFile bounds --execution-policy-file.
	maxPolicyFile = 1 << 20
	// maxRatePerHour bounds max-transactions-per-hour: the counter keeps a
	// timestamp per transaction of the last hour.
	maxRatePerHour = 100_000
	// rateWindow is the window of max-transactions-per-hour.
	rateWindow = time.Hour
)

// DefaultMaxFee is the fee cap of an account whose policy sets none, in
// Planck: one quanta, gqrl's own default --rpc.txfeecap.
var DefaultMaxFee = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)

// AccountPolicy is what one account may sign. A nil limit is no limit.
type AccountPolicy struct {
	// Recipients is the to allowlist; nil allows every recipient.
	Recipients []Address
	// MaxValue is the largest value, in Planck.
	MaxValue *big.Int
	// MaxFee is the largest gas × maxFeePerGas, in Planck; never nil.
	MaxFee *big.Int
	// ContractCreation allows transactions without a to.
	ContractCreation bool
	// MaxDataBytes is the largest input.
	MaxDataBytes *int
	// MaxPerHour is the most transactions signed in any hour.
	MaxPerHour *int
}

// Policy holds the account policies of --execution-policy-file, or, without
// a file, the policy every account gets: the default fee cap and nothing
// else. It counts the transactions each account signs for MaxPerHour; the
// counts live in memory, per process.
type Policy struct {
	file     bool
	accounts map[Address]*AccountPolicy
	fallback *AccountPolicy // the file's default section; nil refuses accounts the file does not name

	mu   sync.Mutex
	sent map[Address][]time.Time // signing times of the last hour, oldest first
}

// OpenPolicy is the policy without a file: every account may sign any
// transaction whose fee is within DefaultMaxFee.
func OpenPolicy() *Policy {
	return &Policy{fallback: &AccountPolicy{MaxFee: DefaultMaxFee, ContractCreation: true}, sent: map[Address][]time.Time{}}
}

// policyFile is the YAML of --execution-policy-file.
type policyFile struct {
	Default  *accountPolicyYAML           `yaml:"default"`
	Accounts map[string]accountPolicyYAML `yaml:"accounts"`
}

// accountPolicyYAML is one account's section. Amounts are decimal Planck,
// as YAML integers or strings. A nil field is an absent key; a key without
// a value never gets here (refuseNulls).
type accountPolicyYAML struct {
	AllowedRecipients *[]string `yaml:"allowed-recipients"`
	MaxValue          *planck   `yaml:"max-value"`
	MaxFee            *planck   `yaml:"max-fee"`
	ContractCreation  *bool     `yaml:"contract-creation"`
	MaxDataBytes      *int      `yaml:"max-data-bytes"`
	MaxPerHour        *int      `yaml:"max-transactions-per-hour"`
}

// planck is a non-negative decimal amount of Planck.
type planck struct{ v *big.Int }

func (p *planck) UnmarshalYAML(n *yaml.Node) error {
	s := strings.ReplaceAll(n.Value, "_", "")
	if n.Kind != yaml.ScalarNode || s == "" || strings.Trim(s, "0123456789") != "" || len(s) > 78 {
		return fmt.Errorf("line %d: %q is not a decimal amount of Planck", n.Line, n.Value)
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.BitLen() > 256 {
		return fmt.Errorf("line %d: %q is not a 256-bit amount of Planck", n.Line, n.Value)
	}
	p.v = v
	return nil
}

// LoadPolicy reads --execution-policy-file.
func LoadPolicy(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("--execution-policy-file: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxPolicyFile+1))
	if err != nil {
		return nil, fmt.Errorf("--execution-policy-file: %w", err)
	}
	if len(data) > maxPolicyFile {
		return nil, fmt.Errorf("--execution-policy-file: larger than %d bytes", maxPolicyFile)
	}
	p, err := ParsePolicy(data)
	if err != nil {
		return nil, fmt.Errorf("--execution-policy-file %s: %w", path, err)
	}
	return p, nil
}

// ParsePolicy parses policy-file content: one YAML document. Unknown
// keys, a key or list entry without a value, an address that is not Q and
// 128 hex characters, an account named twice, a second document and a file
// that names no account and has no default are refused.
func ParsePolicy(data []byte) (*Policy, error) {
	var root yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	switch err := dec.Decode(new(yaml.Node)); {
	case err == nil:
		return nil, errors.New("invalid policy: more than one YAML document (---); a policy file is one document")
	case !errors.Is(err, io.EOF):
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	if err := refuseNulls(&root); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	var pf policyFile
	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	if err := strict.Decode(&pf); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	p := &Policy{file: true, accounts: map[Address]*AccountPolicy{}, sent: map[Address][]time.Time{}}
	if pf.Default != nil {
		ap, err := pf.Default.build()
		if err != nil {
			return nil, fmt.Errorf("default: %w", err)
		}
		p.fallback = ap
	}
	names := make([]string, 0, len(pf.Accounts))
	for name := range pf.Accounts {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		addr, err := jsonutil.ParseQAddress(name)
		if err != nil {
			return nil, fmt.Errorf("accounts: %q is not Q followed by 128 hex characters", name)
		}
		if _, dup := p.accounts[Address(addr)]; dup {
			return nil, fmt.Errorf("accounts: %s is named twice", name)
		}
		section := pf.Accounts[name]
		ap, err := section.build()
		if err != nil {
			return nil, fmt.Errorf("accounts %s: %w", name, err)
		}
		p.accounts[Address(addr)] = ap
	}
	if len(p.accounts) == 0 && p.fallback == nil {
		return nil, errors.New("the policy names no account and has no default: no account could sign")
	}
	return p, nil
}

// refuseNulls refuses a null anywhere in a policy file: a key without a
// value, a list entry without one, or an empty document. The policy reads
// a null key as an absent one, and an absent limit is no limit, so
// "allowed-recipients:" with every entry commented out would otherwise
// allow every recipient, where "allowed-recipients: []" allows none.
func refuseNulls(n *yaml.Node) error {
	for i, c := range n.Content {
		if c.Kind == yaml.ScalarNode && c.ShortTag() == "!!null" {
			switch {
			case n.Kind == yaml.DocumentNode:
				return errors.New("the document is empty")
			case n.Kind == yaml.MappingNode && i%2 == 1:
				k := n.Content[i-1]
				return fmt.Errorf("line %d: %s has no value; give it one ([] for an empty list, {} for an empty "+
					"section), or remove the key for its default", k.Line, k.Value)
			case n.Kind == yaml.SequenceNode:
				return fmt.Errorf("line %d: a list entry has no value", c.Line)
			default:
				return fmt.Errorf("line %d: a key is null", c.Line)
			}
		}
		if err := refuseNulls(c); err != nil {
			return err
		}
	}
	return nil
}

// build checks a section and applies the defaults of a policy file: the
// fee cap is DefaultMaxFee and contract creation is off unless the section
// says otherwise.
func (y *accountPolicyYAML) build() (*AccountPolicy, error) {
	ap := &AccountPolicy{MaxFee: DefaultMaxFee}
	if y.AllowedRecipients != nil {
		ap.Recipients = []Address{}
		for _, s := range *y.AllowedRecipients {
			addr, err := jsonutil.ParseQAddress(s)
			if err != nil {
				return nil, fmt.Errorf("allowed-recipients: %q is not Q followed by 128 hex characters", s)
			}
			ap.Recipients = append(ap.Recipients, Address(addr))
		}
	}
	if y.MaxValue != nil {
		ap.MaxValue = y.MaxValue.v
	}
	if y.MaxFee != nil {
		ap.MaxFee = y.MaxFee.v
	}
	if y.ContractCreation != nil {
		ap.ContractCreation = *y.ContractCreation
	}
	if y.MaxDataBytes != nil {
		if *y.MaxDataBytes < 0 {
			return nil, errors.New("max-data-bytes must not be negative")
		}
		ap.MaxDataBytes = y.MaxDataBytes
	}
	if y.MaxPerHour != nil {
		if *y.MaxPerHour < 0 || *y.MaxPerHour > maxRatePerHour {
			return nil, fmt.Errorf("max-transactions-per-hour must be 0 to %d", maxRatePerHour)
		}
		ap.MaxPerHour = y.MaxPerHour
	}
	return ap, nil
}

// FromFile reports whether the policy came from a file.
func (p *Policy) FromFile() bool { return p.file }

// Accounts returns the number of accounts the file names.
func (p *Policy) Accounts() int { return len(p.accounts) }

// account returns the policy of from, or nil when it may sign nothing.
func (p *Policy) account(from Address) *AccountPolicy {
	if ap, ok := p.accounts[from]; ok {
		return ap
	}
	return p.fallback
}

// refusal is a transaction the policy refuses, with the reason the client
// and the audit log are told.
type refusal struct{ reason string }

func (r *refusal) Error() string { return r.reason }

func refuse(format string, args ...any) *refusal {
	return &refusal{reason: fmt.Sprintf(format, args...)}
}

// Check applies from's policy to a transaction: its recipient (nil for a
// contract creation), value, input length and fee, gas × maxFeePerGas.
// The hourly count is not checked here; see Reserve.
func (p *Policy) Check(from Address, to *Address, value *big.Int, dataLen int, fee *big.Int) *refusal {
	ap := p.account(from)
	if ap == nil {
		return refuse("the policy file has no policy for this account")
	}
	switch {
	case to == nil && !ap.ContractCreation:
		return refuse("contract creation is not allowed for this account")
	case to != nil && ap.Recipients != nil && !slices.Contains(ap.Recipients, *to):
		return refuse("the recipient is not in this account's allowed-recipients")
	case ap.MaxValue != nil && value.Cmp(ap.MaxValue) > 0:
		return refuse("value %s Planck is above this account's max-value of %s", value, ap.MaxValue)
	case ap.MaxDataBytes != nil && dataLen > *ap.MaxDataBytes:
		return refuse("input of %d bytes is above this account's max-data-bytes of %d", dataLen, *ap.MaxDataBytes)
	case fee.Cmp(ap.MaxFee) > 0:
		return refuse("fee (gas × maxFeePerGas) of %s Planck is above the cap of %s Planck", fee, ap.MaxFee)
	}
	return nil
}

// Reserve counts one transaction of from at now against its
// max-transactions-per-hour, or refuses it when the last hour already
// holds that many.
func (p *Policy) Reserve(from Address, now time.Time) *refusal {
	ap := p.account(from)
	if ap == nil {
		return refuse("the policy file has no policy for this account")
	}
	if ap.MaxPerHour == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	times := p.sent[from]
	cut := 0
	for cut < len(times) && !times[cut].After(now.Add(-rateWindow)) {
		cut++
	}
	times = times[cut:]
	if len(times) >= *ap.MaxPerHour {
		p.sent[from] = times
		return refuse("this account has signed %d transactions in the last hour, its max-transactions-per-hour", len(times))
	}
	p.sent[from] = append(times, now)
	return nil
}
