// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"embed"
	"fmt"
	"slices"
)

//go:embed embedded/*.yaml
var embedded embed.FS

// named is a network compiled into the binary. Its chain configuration is an
// embedded YAML. Genesis time and GVR are set only for networks whose genesis
// is published; none of today's built-in networks has one.
type named struct {
	name        string
	aliases     []string
	file        string // under embedded/
	genesisTime *uint64
	gvr         *[32]byte
}

// registry resolves --network names.
type registry []named

// builtin lists the named networks. Per the target-network decision only the
// Testnet V3 stack is supported: QRL Testnet V1, V2 and betanet use other SSZ
// shapes, signing contexts and RANDAO, so they are deliberately absent. Testnet
// V3 and mainnet are added once their genesis time and GVR are published.
var builtin = registry{
	{name: "minimal", file: "minimal.yaml"},
	{name: "end-to-end", aliases: []string{"e2e"}, file: "end-to-end.yaml"},
	{name: "end-to-end-mainnet", file: "end-to-end-mainnet.yaml"},
	{name: "interop", file: "interop.yaml"},
}

// Names returns the built-in network names and aliases, sorted.
func Names() []string {
	return builtin.names()
}

func (r registry) names() []string {
	var out []string
	for _, n := range r {
		out = append(out, n.name)
		out = append(out, n.aliases...)
	}
	slices.Sort(out)
	return out
}

func (r registry) lookup(name string) (named, bool) {
	for _, n := range r {
		if n.name == name || slices.Contains(n.aliases, name) {
			return n, true
		}
	}
	return named{}, false
}

func (n named) config() (Config, error) {
	data, err := embedded.ReadFile("embedded/" + n.file)
	if err != nil {
		return Config{}, fmt.Errorf("network %s: %w", n.name, err)
	}
	cfg, err := ParseConfig(data)
	if err != nil {
		return Config{}, fmt.Errorf("network %s: %w", n.name, err)
	}
	return cfg, nil
}
