// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystore/qrlv1"
)

// maxPasswordFile bounds the password file `keystore verify` reads.
const maxPasswordFile = 64 << 10

func keystoreCommand(stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name:            flags.KeystoreCommand,
		Usage:           "check validator keystores offline",
		HideHelpCommand: true,
		OnUsageError:    onUsageError,
		Subcommands: []*cli.Command{{
			Name: flags.VerifyCommand,
			Usage: "decrypt a keystore with its password file through the signer's keystore decryptor and policy, check " +
				"that its pubkey is the key its seed derives, and print the key's identifier (exit 1 when it is refused)",
			Flags:        flags.KeystoreVerify(),
			OnUsageError: onUsageError,
			Action: func(c *cli.Context) error {
				if c.NArg() > 0 {
					return usageError(fmt.Errorf("unexpected argument %q", c.Args().First()))
				}
				for _, name := range []string{flags.KeystoreFile, flags.KeystorePasswordFile} {
					if c.String(name) == "" {
						return usageError(fmt.Errorf("--%s is required", name))
					}
				}
				err := verifyKeystore(stdout, c.String(flags.KeystoreFile), c.String(flags.KeystorePasswordFile))
				if err != nil {
					return cli.Exit(err.Error(), exitStartup)
				}
				return nil
			},
		}},
		Action: func(c *cli.Context) error {
			return usageError(fmt.Errorf("want %s %s --%s <file> --%s <file>", flags.KeystoreCommand, flags.VerifyCommand,
				flags.KeystoreFile, flags.KeystorePasswordFile))
		},
	}
}

// verifyKeystore decrypts the keystore at ksFile with the password in
// pwFile and reports what the signer would load.
func verifyKeystore(stdout io.Writer, ksFile, pwFile string) error {
	data, err := readCapped(ksFile, qrlv1.MaxSize)
	if err != nil {
		return err
	}
	ks, err := qrlv1.Parse(data)
	if err != nil {
		return fmt.Errorf("%s: %w", ksFile, err)
	}
	password, err := readCapped(pwFile, maxPasswordFile)
	if err != nil {
		return err
	}
	defer mldsa87.Wipe(password)
	key, err := ks.Decrypt(qrlv1.NewPassword(qrlv1.TrimPassword(password)))
	if err != nil {
		return fmt.Errorf("%s: %w", ksFile, err)
	}
	defer key.Zeroize()

	pk := key.PublicKey()
	id := pk.ID()
	pubkey := "absent from the keystore; derived from the seed"
	if _, ok := ks.PublicKey(); ok {
		pubkey = "matches the key the seed derives"
	}
	_, _ = fmt.Fprintf(stdout, "%s: OK\n", ksFile)
	_, _ = fmt.Fprintf(stdout, "  format:     %s (version %d)\n", ks.Flavour, ks.Flavour.Version())
	_, _ = fmt.Fprintf(stdout, "  kdf:        argon2id t=%d m=%d KiB p=%d\n", ks.KDF.T, ks.KDF.M, ks.KDF.P)
	_, _ = fmt.Fprintf(stdout, "  pubkey:     %s\n", pubkey)
	_, _ = fmt.Fprintf(stdout, "  public key: %s\n", pk.LogID())
	_, _ = fmt.Fprintf(stdout, "  identifier: 0x%x (sha256 of the public key)\n", id)
	if ks.Path != "" {
		_, _ = fmt.Fprintf(stdout, "  path:       %s\n", ks.Path)
	}
	return nil
}

// readCapped reads a file of at most limit bytes.
func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if int64(len(data)) > limit {
		mldsa87.Wipe(data)
		return nil, fmt.Errorf("%s: larger than %d bytes", path, limit)
	}
	return data, nil
}
