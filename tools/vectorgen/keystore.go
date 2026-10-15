// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/theQRL/qrysm/cmd/staking-deposit-cli/stakingdeposit/keyhandling"
	keystorev1 "github.com/theQRL/qrysm/pkg/go-qrl-wallet-encryptor-keystore"
	"github.com/theQRL/qrysm/validator/keymanager"
	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// Argon2id parameters: qrysm's standard ones, and the deposit CLI's light
// ones, which are inside the signer's KDF bounds.
const (
	standardT, standardM = 8, 1 << 18
	lightT, lightM       = 8, 1 << 12
)

// unicodePassword is EIP-2335's test password, which NFKD changes.
const unicodePassword = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"

type keystoreVector struct {
	file, flavour, kdf, password string
	key                          int
}

// keystoreVectors: both flavours with the light KDF, both with the standard
// KDF, and the QRL v1 flavour with a password that normalisation changes.
var keystoreVectors = []keystoreVector{
	{"qrl-v1-light.json", "qrl-v1", "light", "testpassword", 0},
	{"qrl-v1-light-unicode.json", "qrl-v1", "light", unicodePassword, 1},
	{"qrl-v1-standard.json", "qrl-v1", "standard", "testpassword", 2},
	{"deposit-cli-light.json", "deposit-cli", "light", "testpassword", 3},
	{"deposit-cli-standard.json", "deposit-cli", "standard", "testpassword", 4},
}

// qrlPassphrase is the EIP-2335 normalisation qrysm's encryptor applies:
// NFKD, then single-byte control characters removed.
func qrlPassphrase(p string) []byte {
	var b strings.Builder
	for _, r := range norm.NFKD.String(p) {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return []byte(b.String())
}

// qrlV1Keystore builds the keystore qrysm's validator writes
// (keymanager.Keystore around keystorev1's crypto object) with a fixed salt
// and IV, which qrysm's encryptor does not allow, and checks that qrysm's
// own decryptor opens it.
func qrlV1Keystore(seed, pub []byte, password, uuid string, t, m uint32, salt, iv []byte) ([]byte, error) {
	key := argon2.IDKey(qrlPassphrase(password), salt, t, m, 1, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	crypto := map[string]any{
		"kdf": map[string]any{
			"function": "argon2id",
			"params": map[string]any{
				"dklen": 32, "t": t, "m": m, "p": 1, "salt": hex.EncodeToString(salt),
			},
		},
		"cipher": map[string]any{
			"function": "aes-256-gcm",
			"params":   map[string]any{"iv": hex.EncodeToString(iv)},
			"message":  hex.EncodeToString(gcm.Seal(nil, iv, seed, nil)),
		},
	}
	got, err := keystorev1.New().Decrypt(crypto, password)
	if err != nil || !bytes.Equal(got, seed) {
		return nil, fmt.Errorf("qrysm's decryptor rejects the keystore: %v", err)
	}
	ks := &keymanager.Keystore{
		Crypto:      crypto,
		ID:          uuid,
		Pubkey:      hex.EncodeToString(pub),
		Version:     keystorev1.New().Version(),
		Description: keystorev1.New().Name(),
	}
	return json.MarshalIndent(ks, "", "  ")
}

// depositCLIKeystore runs the deposit CLI's own Encrypt with a fixed salt and
// IV, pins the UUID, and checks the result with its Decrypt.
func depositCLIKeystore(seed []byte, password, uuid string, light bool, salt, iv []byte) (out []byte, err error) {
	var s [48]byte
	copy(s[:], seed)
	ks, err := keyhandling.Encrypt(s, password, "m/12381/3600/0/0/0", light, salt, iv)
	if err != nil {
		return nil, err
	}
	ks.UUID = uuid
	out, err = json.MarshalIndent(ks, "", "  ")
	if err != nil {
		return nil, err
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("deposit CLI cannot decrypt its keystore: %v", r)
		}
	}()
	// Decrypt the written file, as the CLI reads keystores back.
	if got := keyhandling.NewKeystoreFromJSON(out).Decrypt(password); !bytes.Equal(got[:], seed) {
		return nil, fmt.Errorf("deposit CLI decrypts a different seed")
	}
	return out, nil
}

// genKeystores writes keystores/*.json and keystores/index.json.
func genKeystores(g *generator) error {
	var idx []obj
	for i, v := range keystoreVectors {
		k := g.keys[v.key]
		salt := fill("keystore-salt:"+v.file, 32)
		iv := fill("keystore-iv:"+v.file, 12)
		uuid := fmt.Sprintf("00000000-0000-4000-8000-%012d", i)
		var data []byte
		var err error
		t, m := uint32(lightT), uint32(lightM)
		if v.kdf == "standard" {
			t, m = standardT, standardM
		}
		switch v.flavour {
		case "qrl-v1":
			data, err = qrlV1Keystore(k.seed, k.pub, v.password, uuid, t, m, salt, iv)
		case "deposit-cli":
			data, err = depositCLIKeystore(k.seed, v.password, uuid, v.kdf == "light", salt, iv)
		}
		if err != nil {
			return fmt.Errorf("keystore %s: %w", v.file, err)
		}
		if err := writeFile(g.vectors, "keystores/"+v.file, append(data, '\n')); err != nil {
			return err
		}
		idx = append(idx, obj{}.
			set("file", v.file).
			set("flavour", v.flavour).
			set("kdf", obj{}.set("function", "argon2id").set("t", t).set("m", m).set("p", 1)).
			set("password", v.password).
			set("key_index", v.key).
			set("seed", hx(k.seed)).
			set("pubkey", hx(k.pub)))
	}
	return writeJSON(g.vectors, "keystores/index.json", obj{}.
		set("description", g.description("Keystore vectors. qrl-v1 is the keystore qrysm's validator writes "+
			"(version 1, pubkey without 0x, crypto from pkg/go-qrl-wallet-encryptor-keystore), built with a fixed "+
			"salt and IV and opened by qrysm's decryptor; its password is NFKD-normalised. deposit-cli files come "+
			"from the staking deposit CLI's Encrypt with a fixed salt and IV and a fixed UUID; their password is "+
			"used as raw bytes. light is t=8, m=4096 KiB; standard is t=8, m=262144 KiB.")).
		set("generator", g.info).
		set("keystores", idx))
}
