// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/logging"
)

// maxCredentialFile bounds a secret-store credential file. AWS secret
// access keys and Azure client secrets are about 40 characters.
const maxCredentialFile = 64 << 10

// StoreCredentials prepares the bulk loaders' credentials at startup. It
// warns about each deprecated plain secret flag that is set, and once more
// when its value is on the command line, where other local users can read
// it in the process list. A config file that holds one is a secret file:
// under --strict-file-permissions one that its group or other users can
// read refuses the start. It then reads the first line of
// --aws-secrets-secret-access-key-file and --azure-client-secret-file
// under the secret-file policy. Its errors refuse the start.
func StoreCredentials(cfg *config.Config, log logrus.FieldLogger) error {
	ss := &cfg.Consensus.SecretStores
	policy := SecretPolicy(cfg, log)
	for _, p := range ss.Plain {
		fields := logrus.Fields{"flag": "--" + p.Flag, "instead": "--" + p.FileFlag, "source": string(p.Source)}
		log.WithFields(fields).Warn("A deprecated plain secret flag is set; put the secret in a file owned by the " +
			"signer's user and name it with the -file flag instead")
		switch p.Source {
		case config.FromCommandLine:
			log.WithFields(fields).Warn("A secret is on the command line, where other local users can read it in " +
				"the process list")
		case config.FromConfigFile:
			fi, err := os.Stat(p.File)
			if err == nil {
				err = policy.Check(p.File, fi)
			}
			if err != nil {
				return fmt.Errorf("refusing to start: --config-file holds --%s, so it is a secret file: %w", p.Flag, err)
			}
		}
	}
	if ss.AWS != nil && ss.AWSSecretAccessKeyFile != "" {
		s, err := readCredential(ss.AWSSecretAccessKeyFile, policy)
		if err != nil {
			return fmt.Errorf("refusing to start: --aws-secrets-secret-access-key-file: %w", err)
		}
		ss.AWS.SecretAccessKey = s
	}
	if ss.Azure != nil && ss.AzureClientSecretFile != "" {
		s, err := readCredential(ss.AzureClientSecretFile, policy)
		if err != nil {
			return fmt.Errorf("refusing to start: --azure-client-secret-file: %w", err)
		}
		ss.Azure.ClientSecret = s
	}
	return nil
}

// readCredential returns the first line of a credential file, without a
// trailing carriage return, read under policy.
func readCredential(path string, policy secretfile.Policy) (logging.Secret, error) {
	data, err := secretfile.Read(path, maxCredentialFile, policy)
	if err != nil {
		return nil, err
	}
	defer mldsa87.Wipe(data)
	line, _, _ := bytes.Cut(data, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	if len(bytes.TrimSpace(line)) == 0 {
		return nil, errors.New(path + ": the first line is empty")
	}
	return logging.Secret(bytes.Clone(line)), nil
}
