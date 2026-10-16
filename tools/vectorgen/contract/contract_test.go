// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	fieldparams "github.com/theQRL/qrysm/config/fieldparams"
	"github.com/theQRL/qrysm/config/params"
	"github.com/theQRL/qrysm/crypto/ml_dsa_87"
	validatorpb "github.com/theQRL/qrysm/proto/qrysm/v1alpha1/validator-client"
)

const vectorsDir = "../../../testdata/vectors"

// checks is how many checks a run makes: capabilities, public keys, ten
// signing oneofs, the epoch oneof and the RANDAO reveal.
const checks = 14

// fakeSigner answers the keymanager from the golden vectors and signs with
// the interop keys. Its faults make it wrong in one way each.
type fakeSigner struct {
	t       *testing.T
	token   string
	caps    json.RawMessage
	pubkeys []string
	keys    map[string]ml_dsa_87.MLDSA87Key // by lowercase pubkey
	reveals map[string]string               // first reveal by lowercase pubkey

	wrongRootFor string // sign a different root for this artifact type
	revealKey    string // the reveal's response key; empty means randao_reveal
}

func newFakeSigner(t *testing.T, network string) *fakeSigner {
	t.Helper()
	f := &fakeSigner{t: t, token: strings.Repeat("ab", 32), keys: map[string]ml_dsa_87.MLDSA87Key{},
		reveals: map[string]string{}}
	var caps struct {
		Cases []struct {
			Name     string          `json:"name"`
			Response json.RawMessage `json:"response"`
		} `json:"cases"`
	}
	if err := readJSON(filepath.Join(vectorsDir, "capabilities.json"), &caps); err != nil {
		t.Fatal(err)
	}
	for _, c := range caps.Cases {
		var r struct {
			Network struct {
				ConfigName string `json:"config_name"`
			} `json:"network"`
		}
		if err := json.Unmarshal(c.Response, &r); err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(c.Name, "/matching") && r.Network.ConfigName == network {
			f.caps = c.Response
		}
	}
	if f.caps == nil {
		t.Fatalf("no matching capabilities fixture for %s", network)
	}
	var keys struct {
		Keys []struct {
			Seed              string `json:"seed"`
			Pubkey            string `json:"pubkey"`
			RandaoFirstReveal string `json:"randao_first_reveal"`
		} `json:"keys"`
	}
	if err := readJSON(filepath.Join(vectorsDir, "keys", "interop.json"), &keys); err != nil {
		t.Fatal(err)
	}
	for _, k := range keys.Keys {
		seed, err := hex.DecodeString(strings.TrimPrefix(k.Seed, "0x"))
		if err != nil {
			t.Fatal(err)
		}
		key, err := ml_dsa_87.SecretKeyFromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		pk := strings.ToLower(k.Pubkey)
		f.pubkeys = append(f.pubkeys, pk)
		f.keys[pk] = key
		f.reveals[pk] = k.RandaoFirstReveal
	}
	return f
}

func (f *fakeSigner) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		http.Error(w, "no token", http.StatusUnauthorized)
		return
	}
	const api = "/api/v1/consensus/"
	switch {
	case r.Method == http.MethodGet && r.URL.Path == api+"capabilities":
		f.reply(w, f.caps)
	case r.Method == http.MethodGet && r.URL.Path == api+"publicKeys":
		f.reply(w, f.pubkeys)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, api+"sign/"):
		var body struct {
			Type        string `json:"type"`
			SigningRoot string `json:"signing_root"`
		}
		key, ok := f.keys[strings.ToLower(strings.TrimPrefix(r.URL.Path, api+"sign/"))]
		if json.NewDecoder(r.Body).Decode(&body) != nil || !ok {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		root, err := hex.DecodeString(strings.TrimPrefix(body.SigningRoot, "0x"))
		if err != nil || len(root) != 32 {
			http.Error(w, "bad signing root", http.StatusBadRequest)
			return
		}
		if body.Type == f.wrongRootFor {
			root[0] ^= 1
		}
		sig, err := key.Sign(root)
		if err != nil {
			f.t.Error(err)
			return
		}
		f.reply(w, map[string]string{"signature": "0x" + hex.EncodeToString(sig.Marshal())})
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, api+"randao_reveal/"):
		name := f.revealKey
		if name == "" {
			name = "randao_reveal"
		}
		f.reply(w, map[string]string{name: f.reveals[strings.ToLower(strings.TrimPrefix(r.URL.Path, api+"randao_reveal/"))]})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeSigner) reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		f.t.Error(err)
	}
}

// runAgainst runs the contract against f and returns the results and log.
func runAgainst(t *testing.T, f *fakeSigner, network string, genesisTime uint64) (results, string) {
	t.Helper()
	srv := httptest.NewServer(f)
	defer srv.Close()
	tokenFile := filepath.Join(t.TempDir(), "auth-token")
	if err := os.WriteFile(tokenFile, []byte(f.token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	res, err := runContract(context.Background(), options{signer: srv.URL, tokenFile: tokenFile, network: network,
		genesisTime: genesisTime, vectors: vectorsDir}, &log)
	if err != nil {
		t.Fatal(err)
	}
	return res, log.String()
}

func TestContractAgainstFakeSigner(t *testing.T) {
	for _, network := range []string{"end-to-end", "end-to-end-mainnet"} {
		t.Run(network, func(t *testing.T) {
			res, log := runAgainst(t, newFakeSigner(t, network), network, fixtureGenesisTime)
			if res.passed != checks || len(res.failed) != 0 {
				t.Fatalf("%d passed, failed %q, want %d passed\n%s", res.passed, res.failed, checks, log)
			}
			for _, typ := range []string{"BLOCK_V2", "ATTESTATION", "AGGREGATION_SLOT", "AGGREGATE_AND_PROOF",
				"VOLUNTARY_EXIT", "SYNC_COMMITTEE_MESSAGE", "SYNC_COMMITTEE_SELECTION_PROOF",
				"SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF", "VALIDATOR_REGISTRATION"} {
				if !strings.Contains(log, "("+typ+")\n") {
					t.Errorf("no %s request:\n%s", typ, log)
				}
			}
		})
	}
}

// TestContractCatchesTheFaults checks that each fault fails exactly the
// check it concerns, and only that one.
func TestContractCatchesTheFaults(t *testing.T) {
	tests := []struct {
		name        string
		fault       func(f *fakeSigner)
		genesisTime uint64
		want        []string
	}{
		{"attestation signed over another root", func(f *fakeSigner) { f.wrongRootFor = "ATTESTATION" },
			fixtureGenesisTime, []string{"sign attestation_data (ATTESTATION)"}},
		{"reveal under a renamed key", func(f *fakeSigner) { f.revealKey = "reveal" },
			fixtureGenesisTime, []string{"randao reveal"}},
		{"another genesis time", func(*fakeSigner) {}, fixtureGenesisTime + 1, []string{"capabilities"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeSigner(t, "end-to-end")
			tt.fault(f)
			res, log := runAgainst(t, f, "end-to-end", tt.genesisTime)
			if !slices.Equal(res.failed, tt.want) || res.passed != checks-len(tt.want) {
				t.Fatalf("%d passed, failed %q, want failed %q\n%s", res.passed, res.failed, tt.want, log)
			}
		})
	}
}

// TestEveryOneofIsDriven checks that the contract drives each signing oneof
// of qrysm's SignRequest once, under the name it reports, so that a qrysm
// bump that adds a oneof fails here until the contract covers it. The epoch
// oneof has its own check.
func TestEveryOneofIsDriven(t *testing.T) {
	cfg := params.E2ETestConfig()
	undo, err := params.SetActiveWithUndo(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = undo() }()
	cases, err := signRequests(cfg, [32]byte{}, make([]byte, fieldparams.MLDSA87PubkeyLength), fixtureGenesisTime)
	if err != nil {
		t.Fatal(err)
	}
	object := (&validatorpb.SignRequest{}).ProtoReflect().Descriptor().Oneofs().ByName("object")
	driven := map[string]int{}
	for _, c := range cases {
		set := c.req.ProtoReflect().WhichOneof(object)
		if set == nil || string(set.Name()) != c.oneof {
			t.Errorf("case %s sets oneof %v", c.oneof, set)
		}
		driven[c.oneof]++
	}
	fields := object.Fields()
	for i := range fields.Len() {
		name := string(fields.Get(i).Name())
		want := 1
		if name == "epoch" {
			want = 0
		}
		if driven[name] != want {
			t.Errorf("oneof %s is driven %d times, want %d", name, driven[name], want)
		}
	}
	if len(cases) != fields.Len()-1 {
		t.Errorf("%d cases for %d signing oneofs", len(cases), fields.Len()-1)
	}
}

func TestRunRefusesAnUnknownNetwork(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-network", "mainnet", "-vectors", vectorsDir}, &stdout, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), `unknown network "mainnet"`) {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}
}

// TestReplacesMirrorQrysm checks that this module repeats qrysm's replace
// directives exactly: replaces apply only in the main module, so a missing
// or different one would build the keymanager against other code than the
// pinned commit does. CI relies on this check, so it fails rather than
// skips when it cannot run.
func TestReplacesMirrorQrysm(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-json", "github.com/theQRL/qrysm").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var m struct {
		Replace *struct{ GoMod string }
	}
	if err := json.Unmarshal(out, &m); err != nil || m.Replace == nil || m.Replace.GoMod == "" {
		t.Fatalf("go list gave no replaced qrysm go.mod: %v %s", err, out)
	}
	theirs := replaces(t, m.Replace.GoMod)
	ours := replaces(t, "go.mod")
	if len(theirs) == 0 {
		t.Fatal("qrysm's go.mod has no replace directives")
	}
	for path, target := range theirs {
		if ours[path] != target {
			t.Errorf("replace %s => %q here, qrysm has %q", path, ours[path], target)
		}
	}
}

// replaces returns the single-line replace directives of a go.mod file.
func replaces(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for line := range strings.SplitSeq(string(b), "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "replace ")
		if !ok {
			continue
		}
		if from, to, ok := strings.Cut(rest, " => "); ok {
			out[strings.TrimSpace(from)] = strings.TrimSpace(to)
		}
	}
	return out
}
