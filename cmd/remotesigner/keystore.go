// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"github.com/urfave/cli/v2"

	"github.com/rgeraldes24/go-remotesigner/cmd/remotesigner/flags"
	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/argon"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystore/qrlv1"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystores"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
)

func keystoreCommand(stdout, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name:            flags.KeystoreCommand,
		Usage:           "check validator keystores offline",
		HideHelpCommand: true,
		OnUsageError:    onUsageError,
		Subcommands: []*cli.Command{{
			Name: flags.VerifyCommand,
			Usage: "decrypt a keystore (--file, --password-file) or a keystore directory as the signer loads it " +
				"(--keystores-path with --keystores-password-file or --keystores-passwords-path) through the signer's " +
				"keystore decryptor, policy and file-permission rule, check that each pubkey is the key its seed " +
				"derives, and print each key's identifier (exit 1 when any keystore is refused)",
			Flags:        flags.KeystoreVerify(),
			OnUsageError: onUsageError,
			Action: func(c *cli.Context) error {
				return keystoreVerify(c, stdout, stderr)
			},
		}},
		Action: func(c *cli.Context) error {
			return usageError(fmt.Errorf("want %s %s --%s <keystore> --%s <file>, or --%s <dir> with a password flag",
				flags.KeystoreCommand, flags.VerifyCommand, flags.VerifyFile, flags.VerifyPasswordFile, flags.KeystoresPath))
		},
	}
}

func keystoreVerify(c *cli.Context, stdout, stderr io.Writer) error {
	if c.NArg() > 0 {
		return usageError(fmt.Errorf("unexpected argument %q", c.Args().First()))
	}
	file, pwFile := c.String(flags.VerifyFile), c.String(flags.VerifyPasswordFile)
	bulk := config.Keystores{
		Path:          c.String(flags.KeystoresPath),
		PasswordFile:  c.String(flags.KeystoresPasswordFile),
		PasswordsPath: c.String(flags.KeystoresPasswordsPath),
	}
	single := file != "" || pwFile != ""
	switch {
	case single && bulk != (config.Keystores{}):
		return usageError(fmt.Errorf("--%s and --%s check one keystore and cannot be combined with the --keystores-* flags",
			flags.VerifyFile, flags.VerifyPasswordFile))
	case single && file == "":
		return usageError(fmt.Errorf("--%s is required with --%s", flags.VerifyFile, flags.VerifyPasswordFile))
	case single && pwFile == "":
		return usageError(fmt.Errorf("--%s is required with --%s", flags.VerifyPasswordFile, flags.VerifyFile))
	case single:
	case bulk == (config.Keystores{}):
		return usageError(fmt.Errorf("want --%s and --%s, or --%s with --%s or --%s", flags.VerifyFile,
			flags.VerifyPasswordFile, flags.KeystoresPath, flags.KeystoresPasswordFile, flags.KeystoresPasswordsPath))
	default:
		if err := checkKeystores(bulk); err != nil {
			return usageError(err)
		}
	}
	if err := checkLoading(c); err != nil {
		return usageError(err)
	}
	policy := secretfile.Policy{Strict: c.Bool(flags.StrictFilePermissions), Warn: func(path string, mode fs.FileMode) {
		_, _ = fmt.Fprintf(stderr, "warning: %s: mode %04o: readable by its group or other users\n", path, mode)
	}}
	sem, _ := argon.Auto(c.Int(flags.SignerLoadParallelism))
	var err error
	if single {
		err = verifyKeystore(c.Context, stdout, file, pwFile, policy, sem)
	} else {
		err = verifyKeystores(c.Context, stdout, stderr, bulk, policy, sem)
	}
	if err != nil {
		return cli.Exit(err.Error(), exitStartup)
	}
	return nil
}

// verifyKeystore decrypts the keystore at ksFile with the password in
// pwFile and reports what the signer would load.
func verifyKeystore(ctx context.Context, stdout io.Writer, ksFile, pwFile string, policy secretfile.Policy,
	sem *argon.Semaphore) error {
	data, err := secretfile.ReadCapped(ksFile, qrlv1.MaxSize)
	if err != nil {
		return err
	}
	ks, err := qrlv1.Parse(data)
	if err != nil {
		return fmt.Errorf("%s: %w", ksFile, err)
	}
	password, err := secretfile.Read(pwFile, keystores.MaxPasswordFile, policy)
	if err != nil {
		return err
	}
	defer mldsa87.Wipe(password)
	pw := qrlv1.NewPassword(qrlv1.TrimPassword(password))
	defer pw.Wipe()
	key, err := sem.Decrypt(ctx, ks, pw)
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

// verifyKeystores loads a keystore directory with the signer's bulk loader
// and prints one line per keystore: OK with its identifier on standard
// output, or the refusal on standard error. File names come from listing
// the directory, so they are printed quoted, and the reasons, which can
// carry a listed path, with their non-printable characters escaped.
func verifyKeystores(ctx context.Context, stdout, stderr io.Writer, k config.Keystores, policy secretfile.Policy,
	sem *argon.Semaphore) error {
	l := keystores.Config{Dir: k.Path, PasswordFile: k.PasswordFile, PasswordsDir: k.PasswordsPath, Policy: policy,
		Decrypt: sem.Decrypt}
	batches, err := l.Load(ctx, sem.Procs(), nil, func(done, total int) {
		_, _ = fmt.Fprintf(stderr, "%d of %d keystores checked\n", done, total)
	})
	if err != nil {
		return err
	}
	refused := 0
	for _, b := range batches {
		name := filepath.Base(keystores.Path(b.Source))
		if b.Err != nil {
			refused++
			reason := b.Err
			var fe *keystores.FileError
			if errors.As(b.Err, &fe) {
				reason = fe.Err
			}
			_, _ = fmt.Fprintf(stderr, "%q: REFUSED: %s\n", name, printable(reason.Error()))
			continue
		}
		for _, key := range b.Keys {
			pk := key.PublicKey()
			_, _ = fmt.Fprintf(stdout, "%q: OK  public key %s  identifier 0x%x\n", name, pk.LogID(), pk.ID())
			key.Zeroize()
		}
	}
	_, _ = fmt.Fprintf(stdout, "%d keystores: %d OK, %d refused\n", len(batches), len(batches)-refused, refused)
	if refused > 0 {
		return fmt.Errorf("%d of %d keystores refused", refused, len(batches))
	}
	return nil
}

// printable returns s with every non-printable character (controls, format
// characters such as bidirectional overrides, spaces other than U+0020)
// escaped as Go would quote it, so that s cannot write terminal escapes.
func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) {
			b.WriteRune(r)
			continue
		}
		q := strconv.QuoteRune(r)
		b.WriteString(q[1 : len(q)-1])
	}
	return b.String()
}
