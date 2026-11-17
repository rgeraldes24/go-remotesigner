// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package acceptance

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The files that say whom the signer trusts and how it runs hold no
// secret, but whoever can write them adds a client of their own or changes
// the signer's flags: a known-clients file, a client CA file or a config
// file that its group or other users can write refuses the start under
// the strict policy and is used with a warning without it, and a trust
// file loosened while the signer runs fails the reload, which then
// refuses every client.
func TestTrustAndConfigFilePermissions(t *testing.T) {
	dir := t.TempDir()
	srv := serverCert(t, false)
	cf, kf := writePEMPair(t, dir, "server", srv)
	client := clientCertOf(t, "vc", nil)
	known := writeKnownClients(t, filepath.Join(dir, "known_clients"), client)
	ca := writeTestFile(t, filepath.Join(dir, "ca.pem"), pemCerts(client.cert))
	mtls := []string{"--tls-cert-file=" + cf, "--tls-key-file=" + kf, "--http-auth-mode=mtls"}
	presented := client.tls()
	c := tlsClient(poolOf(srv.cert), &presented, nil)

	for _, tt := range []struct{ flag, file string }{
		{"--tls-known-clients-file", known},
		{"--tls-client-ca-file", ca},
	} {
		t.Run(tt.flag, func(t *testing.T) {
			global := append([]string{tt.flag + "=" + tt.file}, mtls...)
			// Readable by anyone is fine.
			if err := os.Chmod(tt.file, 0o644); err != nil {
				t.Fatal(err)
			}
			s := start(t, options{global: global})
			s.waitReadyTLS(c)

			// Loosened while it runs: the reload fails closed.
			if err := os.Chmod(tt.file, 0o664); err != nil {
				t.Fatal(err)
			}
			s.signal(syscall.SIGHUP)
			logged(t, s, "Reloading the TLS client trust failed")
			if !strings.Contains(s.output.String(), tt.file+": mode 0664: writable by group or other users") {
				t.Fatalf("the reload failure does not name %s and its mode:\n%s", tt.file, s.output.String())
			}
			if code, _, err := call(c, http.MethodGet, s.tlsBase()+"/upcheck", ""); err == nil && code == 200 {
				t.Fatal("a client was accepted after the trust reload failed")
			}
			s.stop()

			refused := launch(t, options{global: global})
			if code := refused.exitCode(15 * time.Second); code != 1 || !strings.Contains(refused.output.String(),
				tt.flag+": "+tt.file+": mode 0664: writable by group or other users") {
				t.Fatalf("a 0664 %s: exit %d\n%s", tt.flag, code, refused.output.String())
			}
			lax := start(t, options{global: append([]string{"--strict-file-permissions=false"}, global...)})
			lax.waitReadyTLS(c)
			lax.stop()
			if out := lax.output.String(); !strings.Contains(out, "A TLS client trust file is writable by its group or other users") ||
				!strings.Contains(out, tt.file) {
				t.Fatalf("no warning naming %s:\n%s", tt.file, out)
			}
		})
	}

	t.Run("--config-file", func(t *testing.T) {
		config := writeTestFile(t, filepath.Join(dir, "config.yaml"), []byte("logging: DEBUG\n"))
		if err := os.Chmod(config, 0o644); err != nil {
			t.Fatal(err)
		}
		ok := start(t, options{global: []string{"--config-file=" + config}})
		ok.waitReady()
		ok.stop()
		if err := os.Chmod(config, 0o664); err != nil {
			t.Fatal(err)
		}
		refused := launch(t, options{global: []string{"--config-file=" + config}})
		if code := refused.exitCode(15 * time.Second); code != 1 || !strings.Contains(refused.output.String(),
			"refusing to start: --config-file "+config+": mode 0664: writable by group or other users") {
			t.Fatalf("a 0664 config file: exit %d\n%s", code, refused.output.String())
		}
		lax := start(t, options{global: []string{"--config-file=" + config, "--strict-file-permissions=false"}})
		lax.waitReady()
		lax.stop()
		if !strings.Contains(lax.output.String(), "warning: --config-file "+config+": mode 0664: writable by group or other users") {
			t.Fatalf("no warning naming %s:\n%s", config, lax.output.String())
		}
	})
}
