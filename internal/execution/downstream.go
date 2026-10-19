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
// core/src/main/java/tech/pegasys/web3signer/core/WebClientOptionsFactory.java,
// core/src/main/java/tech/pegasys/web3signer/core/service/DownstreamPathCalculator.java and
// commandline/src/main/java/tech/pegasys/web3signer/commandline/subcommands/Eth1SubCommand.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

//go:build !noexecution

package execution

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/secretfile"
	"github.com/rgeraldes24/go-remotesigner/internal/logging"
)

// defaultTimeout is the downstream timeout when none is configured:
// Web3Signer's 5 seconds.
const defaultTimeout = 5 * time.Second

// MaxResponseSize bounds a downstream response, gqrl's own bound on a batch
// response: 25 MB.
const MaxResponseSize = 25 * 1000 * 1000

// maxAuthHeaderFile bounds --downstream-http-auth-header-file.
const maxAuthHeaderFile = 64 << 10

// DownstreamPath joins --downstream-http-path with the request path "/", as
// Web3Signer does: one leading "/", no repeated "/", no trailing "/" unless
// the path is "/" itself.
func DownstreamPath(prefix string) string {
	p := repeatedSlashes.ReplaceAllString("/"+prefix+"/", "/")
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

var repeatedSlashes = regexp.MustCompile(`/+`)

// CheckDownstreamPath refuses a --downstream-http-path that is not a plain
// URL path: a query, a fragment, an escape or a scheme.
func CheckDownstreamPath(p string) error {
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.Path != p || strings.ContainsAny(p, "?#%;") {
		return errors.New("illegal characters: want a plain URL path such as /rpc")
	}
	return nil
}

// downstream is where requests are forwarded and how: the target URL, a
// transport that follows no redirects and never reads proxy settings from
// the environment, the Authorization value from the credentials file, and
// the timeout, which also bounds each wait for response data (idleBody).
type downstream struct {
	target    *url.URL
	transport *http.Transport
	auth      logging.Secret // nil without --downstream-http-auth-header-file
	timeout   time.Duration
}

// newDownstream builds the downstream client from the flags. The
// credentials file is a secret file, read once at startup under policy.
func newDownstream(d config.Downstream, policy secretfile.Policy) (*downstream, error) {
	scheme := "http"
	var tlsConfig *tls.Config
	if d.TLS {
		scheme = "https"
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if d.TLSCAFile != "" {
			pool, err := loadCAs(d.TLSCAFile)
			if err != nil {
				return nil, err
			}
			tlsConfig.RootCAs = pool
		}
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	t := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
	}
	if d.ProxyHost != "" {
		proxy := &url.URL{Scheme: "http", Host: net.JoinHostPort(d.ProxyHost, strconv.Itoa(int(d.ProxyPort)))}
		t.Proxy = http.ProxyURL(proxy)
	}
	ds := &downstream{
		target: &url.URL{
			Scheme: scheme,
			Host:   net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port))),
			Path:   DownstreamPath(d.Path),
		},
		transport: t,
		timeout:   timeout,
	}
	if d.AuthHeaderFile != "" {
		auth, err := readAuthHeader(d.AuthHeaderFile, policy)
		if err != nil {
			return nil, err
		}
		ds.auth = auth
	}
	return ds, nil
}

// readAuthHeader reads the Authorization value the signer sends downstream:
// the file's first line, such as "Bearer <token>".
func readAuthHeader(path string, policy secretfile.Policy) (logging.Secret, error) {
	data, err := secretfile.Read(path, maxAuthHeaderFile, policy)
	if err != nil {
		return nil, fmt.Errorf("--downstream-http-auth-header-file: %w", err)
	}
	line, _, _ := strings.Cut(string(data), "\n")
	line = strings.TrimSpace(line)
	clear(data)
	if line == "" || !httpguts.ValidHeaderFieldValue(line) {
		return nil, errors.New("--downstream-http-auth-header-file: the first line must be an Authorization header value")
	}
	return logging.Secret(line), nil
}

// loadCAs reads the PEM CAs that replace the system roots for the
// downstream's certificate.
func loadCAs(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("--downstream-http-tls-ca-file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, errors.New("--downstream-http-tls-ca-file: no PEM certificate")
	}
	return pool, nil
}

// String names the downstream for logs: scheme, host and path.
func (d *downstream) String() string { return d.target.String() }
