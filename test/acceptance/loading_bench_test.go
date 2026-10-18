// Copyright 2026 The go-remotesigner Authors.
// SPDX-License-Identifier: Apache-2.0

package acceptance

import (
	"io"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystore/qrlv1"
	"github.com/rgeraldes24/go-remotesigner/internal/keys/keystoretest"
)

// The key-loading benchmarks, against the built binary (docs/benchmarks.md):
//
//   - B11, startup: 10,000 file-raw keys are ready (/upcheck 200) within
//     30 s and /publicKeys (51.9 MB) is served within 5 s; 100 and 1,000
//     standard-KDF keystores are ready within 1.2 × N × t / P, where P is
//     the standard-KDF concurrency the signer chose and t the per-decrypt
//     time of P decrypts run together on this machine (the B10 measure).
//     t is the mean the signer itself measured during the load (the
//     decrypt-time and decrypts of its "Keys loaded" line), so that load
//     from other work on the machine moves the bound with the result; the
//     time of P decrypts run in the test process after the load is logged
//     beside it.
//   - B12, a reload of 100 standard-KDF keystores during the B7 burst: the
//     burst's p99 stays within twice its p99 without a reload.
//
// They run only with REMOTESIGNER_BENCH=1 (make bench-loading). Each also
// logs the signer's peak RSS, for the memory sizing in
// docs/operations/reload.md.

// sizingRE reads the Argon2id sizing from the startup log.
var sizingRE = regexp.MustCompile(`at most (\d+) keystore decrypts at once, (\d+) with the standard KDF`)

// loadedRE reads the decrypt statistics of a "Keys loaded" log line.
var loadedRE = regexp.MustCompile(`msg="Keys loaded".* decrypt-time=(\S+) decrypts=(\d+)`)

// meanDecrypt returns the mean decrypt time the signer logged for its last
// load.
func meanDecrypt(t *testing.T, s *signer) (time.Duration, int) {
	t.Helper()
	all := loadedRE.FindAllStringSubmatch(s.output.String(), -1)
	if len(all) == 0 {
		t.Fatalf("no decrypt statistics in the log:\n%.2000s", s.output.String())
	}
	m := all[len(all)-1]
	total, err := time.ParseDuration(m[1])
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(m[2])
	if n == 0 {
		t.Fatal("the load decrypted nothing")
	}
	return total / time.Duration(n), n
}

func standardConcurrency(t *testing.T, s *signer) int {
	t.Helper()
	m := sizingRE.FindStringSubmatch(s.output.String())
	if m == nil {
		t.Fatalf("no Argon2id sizing in the log:\n%.2000s", s.output.String())
	}
	p, _ := strconv.Atoi(m[2])
	return p
}

// decryptTime returns the mean time of one decrypt when p standard-KDF
// decrypts of the keystore data run together in this process.
func decryptTime(t *testing.T, data []byte, password string, p int) time.Duration {
	t.Helper()
	ks, err := qrlv1.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	pw := qrlv1.NewPassword([]byte(password))
	defer pw.Wipe()
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		total time.Duration
	)
	for range p {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			k, err := ks.Decrypt(pw)
			d := time.Since(start)
			if err != nil {
				t.Error(err)
				return
			}
			k.Zeroize()
			mu.Lock()
			total += d
			mu.Unlock()
		}()
	}
	wg.Wait()
	return total / time.Duration(p)
}

func TestB11StartupFileRaw(t *testing.T) {
	benchEnabled(t)
	keys := t.TempDir()
	writeKeys(t, keys, 10000)
	s := start(t, options{keys: keys})
	stop := make(chan struct{})
	peak := peakRSS(s.cmd.Process.Pid, stop)
	ready := s.waitReadyWithin(time.Minute)
	req, err := http.NewRequest(http.MethodGet, s.base+"/api/v1/consensus/publicKeys", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+s.signToken())
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	served := time.Since(start)
	close(stop)
	peakKiB := <-peak
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("publicKeys: %d %v", resp.StatusCode, err)
	}
	t.Logf("B11: 10,000 file-raw keys ready after %v; publicKeys (%d bytes) in %v; peak RSS %d MiB",
		ready.Round(time.Millisecond), n, served.Round(time.Millisecond), peakKiB>>10)
	if ready > 30*time.Second || served > 5*time.Second {
		t.Errorf("B11 missed: ready %v (≤ 30 s), publicKeys %v (≤ 5 s)", ready, served)
	}
}

func TestB11StartupKeystores(t *testing.T) {
	benchEnabled(t)
	counts := []int{100, 1000}
	if s := os.Getenv("REMOTESIGNER_B11_KEYSTORES"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil {
			t.Fatal(err)
		}
		counts = []int{n}
	}
	for _, n := range counts {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			ks := newKeystoreSet(t, "password", keystoretest.Standard)
			ks.add(t, t.Name(), 0, n, false)
			s := start(t, options{consensus: ks.flags()})
			stop := make(chan struct{})
			peak := peakRSS(s.cmd.Process.Pid, stop)
			ready := s.waitReadyWithin(time.Hour)
			close(stop)
			peakKiB := <-peak
			if got := len(s.publicKeys()); got != n {
				t.Fatalf("%d keys, want %d", got, n)
			}
			p := standardConcurrency(t, s)
			tp, decrypts := meanDecrypt(t, s)
			if decrypts != n {
				t.Fatalf("%d decrypts for %d keystores", decrypts, n)
			}
			s.signal(syscall.SIGTERM)
			<-s.done
			data, err := os.ReadFile(ks.dir + "/" + keystoretest.DepositFileName(0, 1760000000))
			if err != nil {
				t.Fatal(err)
			}
			after := decryptTime(t, data, "password", p)
			bound := time.Duration(1.2 * float64(n) * float64(tp) / float64(p))
			t.Logf("B11: %d standard keystores ready after %v at P=%d; t(P)=%v per decrypt during the load (%v after it); "+
				"bound 1.2·N·t/P = %v; peak RSS %d MiB", n, ready.Round(time.Second), p, tp.Round(time.Millisecond),
				after.Round(time.Millisecond), bound.Round(time.Second), peakKiB>>10)
			if ready > bound {
				t.Errorf("B11 missed: %v > %v", ready, bound)
			}
		})
	}
}

func TestB12ReloadDuringBurst(t *testing.T) {
	benchEnabled(t)
	keys := t.TempDir()
	ids := writeKeys(t, keys, 32)
	ks := newKeystoreSet(t, "password", keystoretest.Standard)
	s := start(t, options{keys: keys, consensus: ks.flags()})
	s.waitReady()
	reqs := b7Requests(t, ids)
	burst(t, s, reqs) // the first burst records the attestations
	var base []time.Duration
	for range 3 {
		lat, _ := burst(t, s, reqs)
		base = append(base, percentile(lat, 0.99))
	}
	slices.Sort(base)
	baseline := base[1]

	ks.add(t, t.Name(), 0, 100, false)
	started := time.Now()
	if code, body, _ := s.do(request{method: "POST", path: "/reload", token: s.adminToken(),
		contentType: "application/json"}); code != 202 {
		t.Fatalf("POST /reload: %d %s", code, body)
	}
	time.Sleep(2 * time.Second) // the decrypts are running
	lat, wall := burst(t, s, reqs)
	during := percentile(lat, 0.99)
	s.waitReloadStatus("completed", time.Hour)
	reload := time.Since(started)
	if got := len(s.publicKeys()); got != 132 {
		t.Fatalf("%d keys after the reload", got)
	}
	tp, _ := meanDecrypt(t, s)
	t.Logf("B12: B7 p99 %v without a reload (median of %v); %v during a reload of 100 standard keystores (last "+
		"response %v); the reload took %v, %v per decrypt", baseline, base, during, wall, reload.Round(time.Second),
		tp.Round(time.Millisecond))
	if during > 2*baseline {
		t.Errorf("B12 missed: p99 %v during the reload > 2 × %v", during, baseline)
	}
}
