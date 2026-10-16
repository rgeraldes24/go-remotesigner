// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	fieldparams "github.com/theQRL/qrysm/config/fieldparams"
	"github.com/theQRL/qrysm/config/params"
	"github.com/theQRL/qrysm/crypto/ml_dsa_87"
	"github.com/theQRL/qrysm/crypto/randao"
	validatorpb "github.com/theQRL/qrysm/proto/qrysm/v1alpha1/validator-client"
	"github.com/theQRL/qrysm/time/slots"
	remote "github.com/theQRL/qrysm/validator/keymanager/remote-web3signer"
	web3signerv1 "github.com/theQRL/qrysm/validator/keymanager/remote-web3signer/v1"
)

type options struct {
	signer, tokenFile, network, vectors string
	genesisTime                         uint64
}

type results struct {
	passed int
	failed []string // the names of the failed checks
}

// configs are the networks the signer and qrysm both define whose genesis
// the golden vectors describe: qrysm's two end-to-end configurations.
var configs = map[string]func() *params.BeaconChainConfig{
	params.EndToEndName:        params.E2ETestConfig,
	params.EndToEndMainnetName: params.E2EMainnetTestConfig,
}

// contract runs the checks and reports each one on log as "ok: <name>" or
// "FAIL: <name>: <error>".
type contract struct {
	km  *remote.Keymanager
	log io.Writer
	res results
}

func (c *contract) check(name string, fn func() error) {
	if err := fn(); err != nil {
		c.res.failed = append(c.res.failed, name)
		_, _ = fmt.Fprintf(c.log, "FAIL: %s: %v\n", name, err)
		return
	}
	c.res.passed++
	_, _ = fmt.Fprintf(c.log, "ok: %s\n", name)
}

// runContract drives the signer at o.signer with qrysm's keymanager as the
// qrysm validator would on o.network, signing with interop key 0. An error
// means the run could not start; failed checks are in the results.
func runContract(ctx context.Context, o options, log io.Writer) (results, error) {
	newConfig, ok := configs[o.network]
	if !ok {
		return results{}, fmt.Errorf("unknown network %q (want %s or %s)", o.network, params.EndToEndName, params.EndToEndMainnetName)
	}
	cfg := newConfig()
	undo, err := params.SetActiveWithUndo(cfg)
	if err != nil {
		return results{}, err
	}
	defer func() { _ = undo() }()
	v, err := loadVectors(o.vectors, cfg)
	if err != nil {
		return results{}, err
	}
	reqs, err := signRequests(cfg, v.gvr, v.key.pub, o.genesisTime)
	if err != nil {
		return results{}, err
	}

	base := strings.TrimSuffix(o.signer, "/")
	km, err := remote.NewKeymanager(ctx, &remote.SetupConfig{
		BaseEndpoint:          base,
		GenesisValidatorsRoot: v.gvr[:],
		PublicKeysURL:         base + "/api/v1/consensus/publicKeys",
		AuthTokenFile:         o.tokenFile,
	})
	if err != nil {
		return results{}, err
	}
	defer km.Close()
	_, _ = fmt.Fprintf(log, "contract: qrysm %s, network %s, signer %s\n", qrysmModule(), o.network, base)

	c := &contract{km: km, log: log}
	c.check("capabilities", func() error { return km.CheckCapabilities(ctx, v.gvr[:], o.genesisTime) })
	c.check("public keys", func() error { return c.publicKeys(ctx, v.key.pub) })
	for _, r := range reqs {
		c.check(fmt.Sprintf("sign %s (%s)", r.oneof, r.typ), func() error { return c.sign(ctx, r.req) })
	}
	c.check("epoch oneof refused by the client", func() error { return c.epoch(ctx, v.key.pub) })
	c.check("randao reveal", func() error { return c.randaoReveal(ctx, v.key, o.genesisTime) })
	return c.res, nil
}

// publicKeys fetches the keys from the signer's publicKeys URL, as the
// validator does when given the URL form, and looks for the contract's key.
func (c *contract) publicKeys(ctx context.Context, pub []byte) error {
	keys, err := c.km.FetchValidatingPublicKeys(ctx)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(keys, func(k [fieldparams.MLDSA87PubkeyLength]byte) bool { return bytes.Equal(k[:], pub) }) {
		return fmt.Errorf("the signer lists %d keys, not interop key 0", len(keys))
	}
	return nil
}

// sign asks for a signature through the keymanager, which verifies it
// itself, and checks it again with qrysm's ml_dsa_87.VerifySignature over
// the signing root qrysm computed.
func (c *contract) sign(ctx context.Context, req *validatorpb.SignRequest) error {
	sig, err := c.km.Sign(ctx, req)
	if err != nil {
		return err
	}
	pk, err := ml_dsa_87.PublicKeyFromBytes(req.PublicKey)
	if err != nil {
		return err
	}
	ok, err := ml_dsa_87.VerifySignature(sig.Marshal(), [32]byte(req.SigningRoot), pk)
	if err != nil {
		return fmt.Errorf("qrysm's verifier: %w", err)
	}
	if !ok {
		return errors.New("qrysm's verifier rejects the signature")
	}
	return nil
}

// epoch checks that the client refuses the legacy epoch oneof without a
// request: RANDAO is a hash-onion reveal, not a signature (contract section
// 19).
func (c *contract) epoch(ctx context.Context, pub []byte) error {
	_, err := c.km.Sign(ctx, &validatorpb.SignRequest{
		PublicKey:   pub,
		SigningRoot: make([]byte, 32),
		Object:      &validatorpb.SignRequest_Epoch{Epoch: 1},
	})
	if !errors.Is(err, web3signerv1.ErrRandaoRevealSignRequest) {
		return fmt.Errorf("got %v, want %v", err, web3signerv1.ErrRandaoRevealSignRequest)
	}
	return nil
}

// randaoReveal asks for the pre-image of the key's commitment at the current
// slot, as the validator does when it proposes. On a fresh signer this is
// the key's first reveal.
func (c *contract) randaoReveal(ctx context.Context, k interopKey, genesisTime uint64) error {
	var pk [fieldparams.MLDSA87PubkeyLength]byte
	copy(pk[:], k.pub)
	reveal, err := c.km.RandaoReveal(ctx, pk, k.commitment, slots.CurrentSlot(genesisTime))
	if err != nil {
		return err
	}
	if !randao.Verify(reveal, k.commitment) {
		return errors.New("qrysm's randao.Verify rejects the reveal")
	}
	if reveal != k.firstReveal {
		return fmt.Errorf("reveal %#x, want the key's first reveal %#x", reveal, k.firstReveal)
	}
	return nil
}
