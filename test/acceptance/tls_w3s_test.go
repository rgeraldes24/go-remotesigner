// Copyright 2019 ConsenSys AG.
// Copyright 2020 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/tls/ServerSideTlsAcceptanceTest.java and
// acceptance-tests/src/test/java/tech/pegasys/web3signer/tests/tls/ServerSideTlsCaClientAcceptanceTest.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package acceptance

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// Web3Signer's server-side TLS acceptance tests, ported. Each case runs
// with the TLS options on the command line and from --config-file, as
// Web3Signer's run with and without a config file. The PKCS#12 keystores
// are generated (one legacy-encrypted, one modern) instead of read from
// fixture files. Known-clients and CA cases run in --http-auth-mode=mtls,
// where go-remotesigner requires client certificates (DEVIATIONS.md X48).

// keystore is a PKCS#12 keystore of a server or client certificate.
type keystore struct {
	pair     tlsPair
	file     string
	password string
}

func newKeystore(t *testing.T, dir, name, password string, enc *pkcs12.Encoder, client bool) keystore {
	t.Helper()
	p := serverCert(t, false)
	if client {
		p = clientCertOf(t, name, nil)
	}
	data, err := enc.Encode(p.key, p.cert, nil, password)
	if err != nil {
		t.Fatal(err)
	}
	return keystore{pair: p, file: writeTestFile(t, filepath.Join(dir, name+".p12"), data), password: password}
}

// tlsOptions turns flags into options: global flags, or a config file
// holding them.
func tlsOptions(t *testing.T, useConfigFile bool, flags map[string]string) options {
	t.Helper()
	if !useConfigFile {
		var global []string
		for k, v := range flags {
			global = append(global, "--"+k+"="+v)
		}
		return options{global: global}
	}
	var b strings.Builder
	for k, v := range flags {
		fmt.Fprintf(&b, "%s: %q\n", k, v)
	}
	cfg := writeTestFile(t, filepath.Join(t.TempDir(), "config.yaml"), []byte(b.String()))
	return options{global: []string{"--config-file=" + cfg}}
}

func forEachSource(t *testing.T, run func(t *testing.T, useConfigFile bool)) {
	for _, useConfigFile := range []bool{true, false} {
		t.Run(fmt.Sprintf("config-file=%v", useConfigFile), func(t *testing.T) { run(t, useConfigFile) })
	}
}

func TestW3SServerSideTLS(t *testing.T) {
	dir := t.TempDir()
	cert1 := newKeystore(t, dir, "cert1", "password", pkcs12.Legacy, false)
	cert2 := newKeystore(t, dir, "cert2", "password2", pkcs12.Modern, true)
	passwordFile := func(k keystore) string {
		return writeTestFile(t, filepath.Join(t.TempDir(), "keystore.passwd"), []byte(k.password))
	}
	keystoreFlags := func(k keystore) map[string]string {
		return map[string]string{"tls-keystore-file": k.file, "tls-keystore-password-file": passwordFile(k)}
	}
	upcheck := func(s *signer, client *http.Client) (int, string, error) {
		return call(client, http.MethodGet, s.tlsBase()+"/upcheck", "")
	}

	t.Run("ableToConnectWhenClientExpectsSameCertificateAsThatPresented", func(t *testing.T) {
		forEachSource(t, func(t *testing.T, useConfigFile bool) {
			s := start(t, tlsOptions(t, useConfigFile, keystoreFlags(cert1)))
			client := tlsClient(poolOf(cert1.pair.cert), nil, nil)
			s.waitReadyTLS(client)
			if code, body, err := upcheck(s, client); err != nil || code != 200 || !strings.EqualFold(body, "OK") {
				t.Fatalf("upcheck: %d %q %v", code, body, err)
			}
		})
	})

	t.Run("nonTlsClientsCannotConnectToTlsEnabledWeb3Signer", func(t *testing.T) {
		forEachSource(t, func(t *testing.T, useConfigFile bool) {
			s := start(t, tlsOptions(t, useConfigFile, keystoreFlags(cert1)))
			s.waitReadyTLS(tlsClient(poolOf(cert1.pair.cert), nil, nil))
			if code, body, err := call(http.DefaultClient, http.MethodGet, s.base+"/upcheck", ""); err == nil && code == 200 {
				t.Fatalf("a plaintext client got %d %q", code, body)
			}
		})
	})

	exits := func(t *testing.T, o options, want string) {
		t.Helper()
		s := launch(t, o)
		if code := s.exitCode(10 * time.Second); code != 1 {
			t.Fatalf("exit %d, want 1\n%s", code, s.output.String())
		}
		if !strings.Contains(s.output.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, s.output.String())
		}
	}

	t.Run("missingPasswordFileResultsInWeb3SignerExiting", func(t *testing.T) {
		forEachSource(t, func(t *testing.T, useConfigFile bool) {
			exits(t, tlsOptions(t, useConfigFile, map[string]string{
				"tls-keystore-file": cert1.file, "tls-keystore-password-file": filepath.Join(t.TempDir(), "missing"),
			}), "--tls-keystore-password-file")
		})
	})

	t.Run("exitsIfPasswordDoesntMatchKeyStoreFile", func(t *testing.T) {
		forEachSource(t, func(t *testing.T, useConfigFile bool) {
			wrong := keystore{pair: cert1.pair, file: cert1.file, password: "wrongPassword"}
			exits(t, tlsOptions(t, useConfigFile, keystoreFlags(wrong)), "--tls-keystore-file")
		})
	})

	t.Run("clientCannotConnectIfExpectedServerCertDoesntMatchServerSuppliedCert", func(t *testing.T) {
		forEachSource(t, func(t *testing.T, useConfigFile bool) {
			s := start(t, tlsOptions(t, useConfigFile, keystoreFlags(cert1)))
			s.waitReadyTLS(tlsClient(poolOf(cert1.pair.cert), nil, nil))
			if _, _, err := upcheck(s, tlsClient(poolOf(cert2.pair.cert), nil, nil)); err == nil {
				t.Fatal("a client expecting another server certificate connected")
			}
		})
	})

	t.Run("missingKeyStoreFileResultsInWeb3SignerExiting", func(t *testing.T) {
		forEachSource(t, func(t *testing.T, useConfigFile bool) {
			missing := keystore{file: filepath.Join(t.TempDir(), "missing_keystore"), password: "password"}
			exits(t, tlsOptions(t, useConfigFile, keystoreFlags(missing)), "--tls-keystore-file")
		})
	})

	t.Run("clientMissingFromAllowedListCannotConnectToWeb3Signer", func(t *testing.T) {
		forEachSource(t, func(t *testing.T, useConfigFile bool) {
			allowed := newKeystore(t, t.TempDir(), "allowed", "password", pkcs12.Modern, true)
			flags := keystoreFlags(cert1)
			flags["http-auth-mode"] = "mtls"
			flags["tls-known-clients-file"] = writeKnownClients(t, filepath.Join(t.TempDir(), "known_clients"), allowed.pair)
			s := start(t, tlsOptions(t, useConfigFile, flags))
			allowedCert := allowed.pair.tls()
			s.waitReadyTLS(tlsClient(poolOf(cert1.pair.cert), &allowedCert, nil))
			presented := cert2.pair.tls()
			if _, _, err := upcheck(s, tlsClient(poolOf(cert1.pair.cert), &presented, nil)); err == nil {
				t.Fatal("a client missing from the known-clients file connected")
			}
		})
	})
}

func TestW3SServerSideTLSCAClient(t *testing.T) {
	dir := t.TempDir()
	server := newKeystore(t, dir, "server", "password", pkcs12.Legacy, false)
	client := newKeystore(t, dir, "client", "password2", pkcs12.Modern, true)
	signerWithCA := func(t *testing.T, useConfigFile bool, certInCA tlsPair) *signer {
		t.Helper()
		return start(t, tlsOptions(t, useConfigFile, map[string]string{
			"http-auth-mode":             "mtls",
			"tls-keystore-file":          server.file,
			"tls-keystore-password-file": writeTestFile(t, filepath.Join(t.TempDir(), "keystore.passwd"), []byte(server.password)),
			"tls-client-ca-file":         writeTestFile(t, filepath.Join(t.TempDir(), "ca.pem"), pemCerts(certInCA.cert)),
		}))
	}

	t.Run("clientWithCertificateInCertificateAuthorityCanConnect", func(t *testing.T) {
		forEachSource(t, func(t *testing.T, useConfigFile bool) {
			s := signerWithCA(t, useConfigFile, client.pair)
			presented := client.pair.tls()
			c := tlsClient(poolOf(server.pair.cert), &presented, nil)
			s.waitReadyTLS(c)
			if code, body, err := call(c, http.MethodGet, s.tlsBase()+"/upcheck", ""); err != nil || code != 200 || !strings.EqualFold(body, "OK") {
				t.Fatalf("upcheck: %d %q %v", code, body, err)
			}
		})
	})

	t.Run("clientNotInCaFailedToConnectToWeb3Signer", func(t *testing.T) {
		forEachSource(t, func(t *testing.T, useConfigFile bool) {
			s := signerWithCA(t, useConfigFile, client.pair)
			presented := client.pair.tls()
			s.waitReadyTLS(tlsClient(poolOf(server.pair.cert), &presented, nil))
			// The client presents the server's certificate, which the CA file does not hold.
			serverAsClient := server.pair.tls()
			if _, _, err := call(tlsClient(poolOf(server.pair.cert), &serverAsClient, nil), http.MethodGet,
				s.tlsBase()+"/upcheck", ""); err == nil {
				t.Fatal("a client outside the CA file connected")
			}
		})
	})
}
