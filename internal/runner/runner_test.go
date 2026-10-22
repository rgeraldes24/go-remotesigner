// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/sirupsen/logrus"
	bolt "go.etcd.io/bbolt"

	"github.com/rgeraldes24/go-remotesigner/internal/config"
	"github.com/rgeraldes24/go-remotesigner/internal/consensus/policy"
	"github.com/rgeraldes24/go-remotesigner/internal/crypto/mldsa87"
	"github.com/rgeraldes24/go-remotesigner/internal/network"
	"github.com/rgeraldes24/go-remotesigner/internal/randao"
	"github.com/rgeraldes24/go-remotesigner/internal/server"
	"github.com/rgeraldes24/go-remotesigner/internal/server/auth"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing"
	"github.com/rgeraldes24/go-remotesigner/internal/slashing/boltstore"
)

const fileNetwork = "../network/embedded/end-to-end.yaml"

var (
	specOnce sync.Once
	spec     *openapi3.T
	specErr  error
)

// conforms checks a JSON body against a component schema of the contract.
func conforms(t *testing.T, schema string, body []byte) {
	t.Helper()
	specOnce.Do(func() { spec, specErr = openapi3.NewLoader().LoadFromFile("../../api/openapi/consensus.yaml") })
	if specErr != nil {
		t.Fatal(specErr)
	}
	ref, ok := spec.Components.Schemas[schema]
	if !ok {
		t.Fatalf("no schema %s", schema)
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("%s body %q: %v", schema, body, err)
	}
	if err := ref.Value.VisitJSON(v, openapi3.VisitAsResponse()); err != nil {
		t.Fatalf("%s body %s does not conform: %v", schema, body, err)
	}
}

func seedHex(b byte) string {
	return "0x" + strings.Repeat(hex.EncodeToString([]byte{b}), mldsa87.SeedSize)
}

func writeKeyFile(t *testing.T, dir, name string, seed byte) {
	t.Helper()
	content := "type: file-raw\nkeyType: ML_DSA_87\nprivateKey: \"" + seedHex(seed) + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func baseConfig(t *testing.T) *config.Config {
	t.Helper()
	genesis := uint64(1760000000)
	return &config.Config{
		DataPath:      t.TempDir(),
		KeyConfigPath: t.TempDir(),
		HTTP: config.HTTP{
			ListenHost:    "127.0.0.1",
			HostAllowlist: []string{"localhost", "127.0.0.1", "::1"},
			AuthMode:      auth.ModeToken,
			IdleTimeout:   server.DefaultIdleTimeout,
		},
		Consensus: config.Consensus{
			Network:                   network.Sources{Network: fileNetwork, GenesisTime: &genesis},
			SlashingProtectionEnabled: true,
			ClockSkewSlots:            policy.DefaultClockSkewSlots,
			SelectionProofMode:        mldsa87.Deterministic,
			Randao: config.Randao{MaxLayers: randao.DefaultMaxLayers, ReorgWindow: randao.DefaultReorgWindow,
				NewLayerBurst: randao.DefaultNewLayerBurst, NewLayerRefillEpochs: randao.DefaultRefillEpochs},
			Pruning: config.Pruning{EpochsToKeep: 512, Interval: 12 * time.Hour},
		},
	}
}

type running struct {
	base string
	// metrics is the metrics listener's base URL, when it runs.
	metrics string
	sign    string
	admin   string
	stop    func() error
	hup     chan struct{}
}

func quiet() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func start(t *testing.T, cfg *config.Config) *running {
	t.Helper()
	return startWithLog(t, cfg, quiet())
}

// startWithLog is start with the signer's logger given.
func startWithLog(t *testing.T, cfg *config.Config, log *logrus.Logger) *running {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	hup := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, log, hup) }()

	ports := filepath.Join(cfg.DataPath, server.PortsFileName)
	var port string
	deadline := time.Now().Add(5 * time.Second)
	for port == "" {
		select {
		case err := <-done:
			cancel()
			t.Fatalf("Run returned early: %v", err)
		default:
		}
		if data, err := os.ReadFile(ports); err == nil {
			for line := range strings.SplitSeq(string(data), "\n") {
				if p, ok := strings.CutPrefix(line, "http-port="); ok {
					port = p
				}
			}
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("no ports file")
		}
		time.Sleep(5 * time.Millisecond)
	}
	r := &running{base: "http://localhost:" + port, hup: hup}
	if data, err := os.ReadFile(ports); err == nil {
		for line := range strings.SplitSeq(string(data), "\n") {
			if p, ok := strings.CutPrefix(line, "metrics-port="); ok {
				r.metrics = "http://localhost:" + p
			}
		}
	}
	if cfg.HTTP.AuthMode == auth.ModeToken {
		r.sign = readToken(t, cfg.SignTokenFile())
	}
	r.admin = readToken(t, cfg.AdminTokenFile())
	var once sync.Once
	var stopErr error
	r.stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case stopErr = <-done:
			case <-time.After(15 * time.Second):
				stopErr = errors.New("Run did not return")
			}
		})
		return stopErr
	}
	t.Cleanup(func() { _ = r.stop() })
	return r
}

func readToken(t *testing.T, path string) string {
	t.Helper()
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func (r *running) do(t *testing.T, method, path, token string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, r.base+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

func (r *running) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if code, _ := r.do(t, http.MethodGet, "/upcheck", ""); code == 200 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("never ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (r *running) waitReload(t *testing.T, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, body := r.do(t, http.MethodGet, "/reload", r.sign)
		var s struct{ Status string }
		_ = json.Unmarshal(body, &s)
		if s.Status == want {
			conforms(t, "ReloadStatus", body)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("reload status %s, want %s", body, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func pubkeyHex(t *testing.T, seed byte) string {
	t.Helper()
	var s [mldsa87.SeedSize]byte
	for i := range s {
		s[i] = seed
	}
	k, err := mldsa87.FromSeed48(&s)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Zeroize()
	pk := k.PublicKey()
	return "0x" + hex.EncodeToString(pk[:])
}

func TestRunEndToEnd(t *testing.T) {
	cfg := baseConfig(t)
	writeKeyFile(t, cfg.KeyConfigPath, "a.yaml", 1)
	writeKeyFile(t, cfg.KeyConfigPath, "b.yaml", 2)
	if err := os.WriteFile(filepath.Join(cfg.KeyConfigPath, "bad.yaml"), []byte("type: file-raw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := start(t, cfg)
	r.waitReady(t)

	// publicKeys: the sorted canonical identifiers.
	code, body := r.do(t, http.MethodGet, "/api/v1/consensus/publicKeys", r.sign)
	var pks []string
	if err := json.Unmarshal(body, &pks); code != 200 || err != nil {
		t.Fatalf("publicKeys: %d %v", code, err)
	}
	want := []string{pubkeyHex(t, 1), pubkeyHex(t, 2)}
	slices.Sort(want)
	if !slices.Equal(pks, want) {
		t.Fatal("publicKeys is not the sorted key set")
	}

	// capabilities: TOFU pending, genesis known.
	code, body = r.do(t, http.MethodGet, "/api/v1/consensus/capabilities", r.sign)
	if code != 200 {
		t.Fatalf("capabilities: %d %s", code, body)
	}
	conforms(t, "Capabilities", body)
	var caps struct {
		RandaoReveal       bool   `json:"randao_reveal"`
		SlashingProtection string `json:"slashing_protection"`
		Types              []string
		Network            struct {
			GVR         *string `json:"genesis_validators_root"`
			GenesisTime *string `json:"genesis_time"`
		}
	}
	_ = json.Unmarshal(body, &caps)
	if !caps.RandaoReveal || caps.SlashingProtection != "bolt" || caps.Network.GVR != nil ||
		*caps.Network.GenesisTime != "1760000000" || slices.Contains(caps.Types, "VOLUNTARY_EXIT") || len(caps.Types) != 8 {
		t.Fatalf("capabilities %s", body)
	}

	// healthcheck: one file failed, so DOWN; detail only with the sign token.
	code, body = r.do(t, http.MethodGet, "/healthcheck", "")
	conforms(t, "HealthCheck", body)
	if code != 503 || string(body) != `{"status":"DOWN","outcome":"DOWN"}` {
		t.Fatalf("anonymous healthcheck: %d %s", code, body)
	}
	code, body = r.do(t, http.MethodGet, "/healthcheck", r.sign)
	conforms(t, "HealthCheck", body)
	if code != 503 || !strings.Contains(string(body), `"data":{"error-count":1,"keys-loaded":2}`) {
		t.Fatalf("healthcheck detail: %d %s", code, body)
	}
	r.waitReload(t, "completed_with_errors")

	// Fix the file and reload: 202, then completed and healthy.
	writeKeyFile(t, cfg.KeyConfigPath, "bad.yaml", 3)
	code, body = r.do(t, http.MethodPost, "/reload", r.admin)
	if code != 202 {
		t.Fatalf("POST /reload: %d %s", code, body)
	}
	conforms(t, "ReloadAccepted", body)
	r.waitReload(t, "completed")
	if code, body = r.do(t, http.MethodGet, "/healthcheck", ""); code != 200 {
		t.Fatalf("healthcheck after the fix: %d %s", code, body)
	}

	// Error bodies conform too.
	code, body = r.do(t, http.MethodPost, "/reload", r.sign)
	if code != 403 {
		t.Fatalf("sign token on POST /reload: %d", code)
	}
	conforms(t, "ErrorResponse", body)

	if err := r.stop(); err != nil {
		t.Fatalf("Run = %v, want nil after a graceful shutdown", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataPath, server.PortsFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ports file left behind: %v", err)
	}
	// The store was closed: it opens again and holds the three keys.
	s, err := boltstore.Open(cfg.SlashingProtectionDB(), boltstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	for _, seed := range []byte{1, 2, 3} {
		pk, _ := hex.DecodeString(pubkeyHex(t, seed)[2:])
		if st, err := s.ValidatorStatus(context.Background(), slashing.KeyIDOf(pk)); err != nil || !st.Registered || !st.Enabled {
			t.Fatalf("key %d not registered in the store: %+v %v", seed, st, err)
		}
	}
}

func TestRunTokenReloadOnHUP(t *testing.T) {
	cfg := baseConfig(t)
	r := start(t, cfg)
	r.waitReady(t)
	if code, _ := r.do(t, http.MethodGet, "/reload", r.sign); code != 200 {
		t.Fatalf("sign token refused: %d", code)
	}
	newTok := "0x" + strings.Repeat("ab", 32)
	if err := os.WriteFile(cfg.SignTokenFile(), []byte(newTok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.hup <- struct{}{}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if code, _ := r.do(t, http.MethodGet, "/reload", newTok); code == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("new token never accepted")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if code, _ := r.do(t, http.MethodGet, "/reload", r.sign); code != 401 {
		t.Fatalf("old token after HUP: %d", code)
	}
}

func TestRunProtectionDisabled(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Consensus.SlashingProtectionEnabled = false
	cfg.HTTP.AuthMode = auth.ModeNone
	r := start(t, cfg)
	r.waitReady(t)
	code, body := r.do(t, http.MethodGet, "/api/v1/consensus/capabilities", "")
	if code != 200 || !strings.Contains(string(body), `"slashing_protection":"disabled"`) {
		t.Fatalf("capabilities: %d %s", code, body)
	}
	// Like Web3Signer, there is no store check without a store, so the
	// healthcheck stays UP.
	code, body = r.do(t, http.MethodGet, "/healthcheck", "")
	if code != 200 || !strings.Contains(string(body), `"status":"UP"`) || strings.Contains(string(body), "slashing-protection-db-health-check") {
		t.Fatalf("healthcheck: %d %s", code, body)
	}
	if _, err := os.Stat(cfg.SlashingProtectionDB()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a store file was created with protection disabled")
	}
}

// A store already pinned binds a trust-on-first-use network to its GVR.
func TestRunAdoptsStorePin(t *testing.T) {
	cfg := baseConfig(t)
	gvr := slashing.Root{0x42}
	s, err := boltstore.Open(cfg.SlashingProtectionDB(), boltstore.Options{GenesisValidatorsRoot: &gvr})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	r := start(t, cfg)
	r.waitReady(t)
	_, body := r.do(t, http.MethodGet, "/api/v1/consensus/capabilities", r.sign)
	if !strings.Contains(string(body), `"genesis_validators_root":"0x42`) {
		t.Fatalf("capabilities %s", body)
	}
}

func TestRunStartupRefusals(t *testing.T) {
	t.Run("store locked by a running signer", func(t *testing.T) {
		cfg := baseConfig(t)
		r := start(t, cfg)
		r.waitReady(t)
		second := *cfg
		err := Run(context.Background(), &second, quiet(), nil)
		if !errors.Is(err, boltstore.ErrLocked) {
			t.Fatalf("second Run = %v, want ErrLocked", err)
		}
	})
	t.Run("store pinned to another GVR", func(t *testing.T) {
		cfg := baseConfig(t)
		other := slashing.Root{1}
		s, err := boltstore.Open(cfg.SlashingProtectionDB(), boltstore.Options{GenesisValidatorsRoot: &other})
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Close()
		gvr := [32]byte{2}
		cfg.Consensus.Network.GenesisValidatorsRoot = &gvr
		if err := Run(context.Background(), cfg, quiet(), nil); !errors.Is(err, slashing.ErrGenesisValidatorsRootMismatch) {
			t.Fatalf("Run = %v", err)
		}
	})
	t.Run("fail-safe", func(t *testing.T) {
		cfg := baseConfig(t)
		cfg.HTTP.ListenHost = "0.0.0.0"
		cfg.HTTP.AuthMode = auth.ModeNone
		if err := Run(context.Background(), cfg, quiet(), nil); !errors.Is(err, config.ErrAuthNoneNonLoopback) {
			t.Fatalf("Run = %v", err)
		}
	})
	t.Run("conflicting genesis sources", func(t *testing.T) {
		cfg := baseConfig(t)
		state := make([]byte, network.GenesisPrefixSize)
		copy(state[48:], []byte{0, 0, 0, 0xfd, 0, 0, 0, 0xfd}) // the end-to-end fork, genesis time 0
		path := filepath.Join(t.TempDir(), "genesis.ssz")
		if err := os.WriteFile(path, state, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg.Consensus.Network.GenesisStateFile = path
		if err := Run(context.Background(), cfg, quiet(), nil); !errors.Is(err, network.ErrFlagStateConflict) {
			t.Fatalf("Run = %v", err)
		}
	})
	t.Run("schema too new", func(t *testing.T) {
		cfg := baseConfig(t)
		writeNewerSchema(t, cfg.SlashingProtectionDB())
		if err := Run(context.Background(), cfg, quiet(), nil); !errors.Is(err, slashing.ErrSchemaTooNew) {
			t.Fatalf("Run = %v", err)
		}
	})
	t.Run("invalid fee-recipient file", func(t *testing.T) {
		cfg := baseConfig(t)
		cfg.Consensus.FeeRecipientFile = filepath.Join(t.TempDir(), "pins.yaml")
		if err := os.WriteFile(cfg.Consensus.FeeRecipientFile, []byte("[]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := Run(context.Background(), cfg, quiet(), nil); !errors.Is(err, policy.ErrPinFile) {
			t.Fatalf("Run = %v", err)
		}
	})
	t.Run("metrics address in use", func(t *testing.T) {
		cfg := baseConfig(t)
		r := start(t, cfg)
		r.waitReady(t)
		second := baseConfig(t)
		second.Metrics = config.Metrics{Enabled: true, Host: "127.0.0.1", Port: portOf(t, r.base)}
		err := Run(context.Background(), second, quiet(), nil)
		if err == nil || !strings.Contains(err.Error(), "metrics: listen") {
			t.Fatalf("Run = %v", err)
		}
	})
	t.Run("listen address in use", func(t *testing.T) {
		cfg := baseConfig(t)
		r := start(t, cfg)
		r.waitReady(t)
		second := baseConfig(t)
		second.HTTP.ListenPort = portOf(t, r.base)
		if err := Run(context.Background(), second, quiet(), nil); err == nil || !strings.Contains(err.Error(), "listen") {
			t.Fatalf("Run = %v", err)
		}
	})
}

func portOf(t *testing.T, base string) uint16 {
	t.Helper()
	var p uint16
	for _, c := range base[strings.LastIndexByte(base, ':')+1:] {
		p = p*10 + uint16(c-'0')
	}
	return p
}

// writeNewerSchema creates a store whose schema version is one past this
// build's, as a newer build would leave it.
func writeNewerSchema(t *testing.T, path string) {
	t.Helper()
	s, err := boltstore.Open(path, boltstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	err = db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("meta")).Put([]byte("schema_version"), binary.BigEndian.AppendUint32(nil, slashing.SchemaVersion+1))
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Startup logs the binding, including the DEPOSIT and builder domains, and
// warns when genesis time is unknown and when the GVR waits for its
// first-use pin.
func TestLogNetwork(t *testing.T) {
	bind := func(src network.Sources) (*network.Network, *policy.Policy) {
		t.Helper()
		n, err := network.Load(src)
		if err != nil {
			t.Fatal(err)
		}
		pol, err := policy.New(policy.Config{Network: n, ClockSkewSlots: policy.DefaultClockSkewSlots})
		if err != nil {
			t.Fatal(err)
		}
		return n, pol
	}
	var buf strings.Builder
	log := logrus.New()
	log.SetOutput(&buf)
	n, pol := bind(network.Sources{Network: fileNetwork})
	logNetwork(log, n, pol)
	out := buf.String()
	for _, want := range []string{
		"deposit-domain=0x030000002c3c06ef", "builder-domain=0x000000012c3c06ef",
		`genesis-validators-root="pending pin (trust on first use)"`, "genesis-time=unknown",
		`level=warning msg="Genesis time is unknown`,
		`level=warning msg="The genesis validators root is not configured: it will be pinned from the first signing request`,
		"--network-genesis-validators-root or --network-genesis-state",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("startup log lacks %q:\n%s", want, out)
		}
	}

	// A configured GVR, or one the store has pinned, is logged and not
	// warned about.
	gvr := [32]byte{1}
	buf.Reset()
	n, pol = bind(network.Sources{Network: fileNetwork, GenesisValidatorsRoot: &gvr})
	logNetwork(log, n, pol)
	if out := buf.String(); strings.Contains(out, "trust on first use") || !strings.Contains(out, "genesis-validators-root=0x01") {
		t.Errorf("startup log with a configured GVR:\n%s", out)
	}
	n, pol = bind(network.Sources{Network: fileNetwork})
	if err := pol.PinGenesisValidatorsRoot(gvr); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	logNetwork(log, n, pol)
	if out := buf.String(); strings.Contains(out, "trust on first use") || !strings.Contains(out, "genesis-validators-root=0x01") {
		t.Errorf("startup log with a store-pinned GVR:\n%s", out)
	}
}
