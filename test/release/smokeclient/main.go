// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

// Command smokeclient is the client container of the Docker smoke test
// (package release, TestDockerSmoke). It runs next to the signer container
// on a user-defined Docker network and checks the signer the way a
// validator client sees it:
//
//   - it accepts only the certificate whose SHA-256 fingerprint the signer
//     logged, over TLS 1.3, and only if that certificate names the host it
//     dials (the Docker service name);
//   - it waits for /upcheck to answer 200, then lists the keys through
//     publicKeys with the sign token, and checks that the token is required;
//   - it checks that plaintext HTTP on the TLS port gets no API.
//
// With -data it also reports the owner and mode of the files the signer
// wrote into its data volume, mounted read-only. It prints a JSON report on
// standard output and exits 1, with the reason on standard error, when a
// check fails.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// report is what smokeclient prints on success.
type report struct {
	TLSVersion  string          `json:"tls_version"`
	Fingerprint string          `json:"fingerprint"`
	Upcheck     string          `json:"upcheck"`
	Keys        []string        `json:"keys"`
	Files       map[string]file `json:"files,omitempty"`
}

// file is the owner and permission bits of one file in the data volume.
type file struct {
	Mode string `json:"mode"`
	UID  int64  `json:"uid"`
	Dir  bool   `json:"dir"`
}

// dataFiles are the files the signer writes under its data path.
var dataFiles = []string{".", "auth-token", "admin-token", "tls", "tls/cert.pem", "tls/key.pem",
	"slashing-protection.db"}

func main() {
	base := flag.String("url", "https://signer:9000", "signer base URL")
	fingerprint := flag.String("fingerprint", "", "SHA-256 fingerprint of the signer's certificate, as it logged it")
	tokenFile := flag.String("token-file", "", "file holding the sign token")
	wantKey := flag.String("want-key", "", "the one public key the signer must list")
	data := flag.String("data", "", "the signer's data directory, mounted read-only, to report on")
	timeout := flag.Duration("timeout", 90*time.Second, "how long to wait for /upcheck")
	flag.Parse()

	r, err := run(*base, *fingerprint, *tokenFile, *wantKey, *data, *timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "smokeclient:", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		fmt.Fprintln(os.Stderr, "smokeclient:", err)
		os.Exit(1)
	}
}

func run(base, fingerprint, tokenFile, wantKey, data string, timeout time.Duration) (*report, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("-url %q: want an https URL", base)
	}
	pin, err := parseFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("sign token: %w", err)
	}
	r := &report{Fingerprint: fingerprint}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: pinned(pin, u.Hostname())},
	}

	upcheck, version, err := waitUp(client, base+"/upcheck", timeout)
	if err != nil {
		return nil, err
	}
	r.Upcheck, r.TLSVersion = upcheck, version

	keysURL := base + "/api/v1/consensus/publicKeys"
	if code, _, err := get(client, keysURL, ""); err != nil {
		return nil, err
	} else if code != http.StatusUnauthorized {
		return nil, fmt.Errorf("publicKeys without the sign token: status %d, want 401", code)
	}
	code, body, err := get(client, keysURL, strings.TrimSpace(string(token)))
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("publicKeys: status %d: %s", code, body)
	}
	if err := json.Unmarshal(body, &r.Keys); err != nil {
		return nil, fmt.Errorf("publicKeys: %w", err)
	}
	if !slices.Equal(r.Keys, []string{wantKey}) {
		return nil, fmt.Errorf("publicKeys lists %d keys, want exactly %s…", len(r.Keys), wantKey[:min(len(wantKey), 18)])
	}

	if err := plaintextRefused(u.Host); err != nil {
		return nil, err
	}
	if data != "" {
		if r.Files, err = stat(data); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// parseFingerprint decodes a SHA-256 fingerprint written as hex, with or
// without colons, in either case.
func parseFingerprint(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.ReplaceAll(s, ":", ""))
	if err != nil || len(b) != sha256.Size {
		return nil, fmt.Errorf("-fingerprint %q: want a SHA-256 fingerprint", s)
	}
	return b, nil
}

// pinned returns a TLS 1.3 client configuration that accepts exactly the
// certificate whose SHA-256 is pin, and only when it is valid for host,
// with itself as the only root. This is what a validator client given the
// signer's certificate as its CA file checks.
func pinned(pin []byte, host string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// The certificate is checked in VerifyConnection, against the pin.
		InsecureSkipVerify: true, //nolint:gosec // replaced by the fingerprint and hostname check below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("the signer sent no certificate")
			}
			leaf := cs.PeerCertificates[0]
			if sum := sha256.Sum256(leaf.Raw); !bytes.Equal(sum[:], pin) {
				return fmt.Errorf("the signer's certificate has SHA-256 %X, not the logged fingerprint", sum)
			}
			roots := x509.NewCertPool()
			roots.AddCert(leaf)
			if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots}); err != nil {
				return fmt.Errorf("the pinned certificate does not verify for %s: %w", host, err)
			}
			return nil
		},
	}
}

// waitUp polls the /upcheck URL until it answers 200 and returns its body
// and the negotiated TLS version. 503 means the signer is still loading.
func waitUp(client *http.Client, u string, timeout time.Duration) (string, string, error) {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		resp, err := client.Get(u)
		if err == nil {
			body, rerr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			switch {
			case rerr != nil:
				last = rerr
			case resp.StatusCode == http.StatusOK:
				return strings.TrimSpace(string(body)), tls.VersionName(resp.TLS.Version), nil
			default:
				last = fmt.Errorf("status %d: %s", resp.StatusCode, body)
			}
		} else {
			last = err
			// A refused pin never becomes acceptable.
			if strings.Contains(err.Error(), "fingerprint") || strings.Contains(err.Error(), "does not verify") {
				return "", "", err
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return "", "", fmt.Errorf("/upcheck did not answer 200 within %s: %w", timeout, last)
}

// get sends a GET with the bearer token (none when token is empty) and
// returns the status and body.
func get(client *http.Client, u, token string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, err
}

// plaintextRefused checks that plaintext HTTP on the TLS port reaches no
// API: the request fails, or the TLS server answers it with 400.
func plaintextRefused(hostport string) error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("http://" + hostport + "/upcheck")
	if err != nil {
		return nil
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		return fmt.Errorf("plaintext HTTP on the TLS port: status %d, want 400 or no answer", resp.StatusCode)
	}
	return nil
}

// stat reports the owner and permission bits of dataFiles under dir.
func stat(dir string) (map[string]file, error) {
	out := map[string]file{}
	for _, name := range dataFiles {
		fi, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		out[name] = file{Mode: fmt.Sprintf("%04o", fi.Mode().Perm()), UID: ownerUID(fi), Dir: fi.IsDir()}
	}
	return out, nil
}
