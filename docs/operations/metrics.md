# Metrics and alerts

remotesigner exports Prometheus metrics on a listener of its own, separate from the API. This page lists every
metric, the label values that are fixed by the contract, and what to do when one of the shipped alerts fires.

## 1. The metrics listener

| Flag | Default | Meaning |
|---|---|---|
| `--metrics-enabled` | `false` | Start the listener. Without it nothing listens on the metrics port. |
| `--metrics-host` | `127.0.0.1` | Host the listener binds |
| `--metrics-port` | `9001` | Port; `0` picks a free one, written as `metrics-port=<port>` to the ports file |
| `--metrics-host-allowlist` | `localhost,127.0.0.1` | `Host` header names served; `*` or `all` accepts any, `none` refuses all |
| `--metrics-auth-token-file` | unset | Bearer token a scrape must send; generated `0600` when missing, re-read on SIGHUP. Unset leaves `/metrics` open. |

The names and defaults are Web3Signer's, except the token, which Web3Signer does not have. The listener serves
`GET /metrics` in the Prometheus text format and answers 404 to every other path. A `Host` outside the allowlist gets
403 `HOST_NOT_ALLOWED`, which keeps a browser page from reading the metrics through DNS rebinding. With
`--metrics-auth-token-file`, a scrape without the metrics token gets 401 `UNAUTHENTICATED`; the sign and admin
tokens never grant it, and it must differ from both ([`tls.md`](tls.md#7-the-metrics-token) has the Prometheus
configuration). The listener has no TLS, so keep it on loopback, or on a network only Prometheus can reach.

Startup is refused (exit code 1) when the listener is enabled on a non-loopback host and:

- `--metrics-host-allowlist` names only loopback hosts: add the name Prometheus scrapes with, for example
  `--metrics-host-allowlist=signer.internal`;
- slashing protection is disabled: protection can be disabled only when every listener, the metrics listener
  included, is loopback.

```
bin/remotesigner-consensus --data-path=/var/lib/remotesigner --metrics-enabled consensus --network=…
curl -s localhost:9001/metrics | grep -E '^(signing|consensus)_'
```

## 2. Catalogue

Names keep Web3Signer's `<category>_<name>` structure: `bls` becomes `mldsa87`, `eth2_` becomes `consensus_`, and
histograms replace Web3Signer's summaries. No metric carries a public key or a URL.

### Signing

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `signing_requests_total` | counter | `type`, `result` | Sign requests by artifact type and outcome (see section 3), answers from the response cache included |
| `signing_mldsa87_signing_duration_seconds` | histogram | `type` | Time to sign and verify one signature; an answer from the response cache computes none |
| `http_mldsa87_malformed_request_count_total` | counter | | Sign requests refused for a malformed identifier or body, before their type is known |
| `signing_mldsa87_missing_identifier_count_total` | counter | | Sign requests for a key that is not loaded (404 `UNKNOWN_KEY`) |
| `signing_signers_loaded_count` | gauge | | Keys loaded |
| `signing_verify_failures_total` | counter | | Signatures that failed verify-before-release; the bytes were discarded |
| `signing_keys_quarantined` | gauge | | Keys quarantined after a signature fault; they answer 503 `KEY_QUARANTINED` until a reload |

### Slashing protection

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `consensus_slashingprotection_permitted_signings_total` | counter | | Block and attestation checks that allowed signing (a repeat of a recorded message included, unless the response cache answered it) |
| `consensus_slashingprotection_prevented_signings_total` | counter | `reason` | Block and attestation checks that refused signing (412) |
| `consensus_slashingprotection_database_duration_seconds` | histogram | `operation`: `block`, `attestation` | Time in the store's check-and-record transaction |

With `--slashing-protection-enabled=false` no check runs, so neither counter moves. A repeat of a request whose
signature was released within the last two epochs is answered from the response cache with the same bytes
([`../contract.md`](../contract.md#15-selection-proofs-and-signing-modes)), before slashing protection, so it moves
neither counter either.

### RANDAO

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `consensus_randao_reveals_total` | counter | `result` | RANDAO reveal requests by outcome (see section 3) |
| `consensus_randao_new_layer_rate_limited_total` | counter | | Reveals refused because the key's new-layer bucket was empty |
| `consensus_randao_reveal_duration_seconds` | histogram | `path`: `hot`, `scan` | Time to release a reveal: `hot` from the frontier or the precomputed layer, `scan` when a layer was computed from `x_0` |
| `consensus_randao_slow_path_scans_total` | counter | | Scans from `x_0`: first uses, gap advances, deep reorgs and unknown commitments |
| `consensus_randao_min_layers_remaining` | gauge | | Fewest onion layers any loaded key has left; NaN until a key has a frontier |

The frontier rule behind these is described in [`randao.md`](randao.md). 400 and 404 answers of the reveal endpoint
are not counted in `consensus_randao_reveals_total`.

### HTTP and process

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `http_request_duration_seconds` | histogram | `route`, `code` | API requests by route pattern and status |
| `http_requests_in_flight` | gauge | | API requests being served |
| `http_connections_open` | gauge | | Open API connections |
| `http_connections_limit_reached_total` | counter | | Times an accepted connection brought the API listener to `--http-max-connections` |
| `process_release` | gauge | `version` | Always 1; the label is the running release |
| `go_*`, `process_*` | | | The Go runtime and process collectors |

## 3. Label values fixed by the contract

The qrysm e2e evaluator reads these values, so they are part of the HTTP contract
([`../contract.md`](../contract.md#18-metric-label-values)) and change only together with it. Every value exists from
startup, at 0, so a scrape shows it before it first occurs.

| Metric and label | Values |
|---|---|
| `signing_requests_total{type}` | the nine artifact types: `BLOCK_V2`, `ATTESTATION`, `AGGREGATION_SLOT`, `AGGREGATE_AND_PROOF`, `VOLUNTARY_EXIT`, `SYNC_COMMITTEE_MESSAGE`, `SYNC_COMMITTEE_SELECTION_PROOF`, `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF`, `VALIDATOR_REGISTRATION` |
| `signing_requests_total{result}` | `ok` (signed); `refused` (403 policy, 412 clock bound or slashing protection); `bad_request` (any other 4xx, including 404 `UNKNOWN_KEY`); `error` (5xx, including 503 `KEY_QUARANTINED`) |
| `consensus_slashingprotection_prevented_signings_total{reason}` | `slashing_double_proposal`, `slashing_double_vote`, `slashing_surrounding_vote`, `slashing_surrounded_vote`, `slashing_below_watermark`, `slashing_above_high_watermark`, `validator_disabled` |
| `consensus_randao_reveals_total{result}` | `first_use`, `new_layer`, `gap_advanced`, `re_reveal`, `refused` (any 412, 422 or 429), `error` (5xx, including 503 `KEY_QUARANTINED`) |
| `http_request_duration_seconds{route,code}` | `route` is the pattern, such as `/api/v1/consensus/sign/{identifier}`, or `-` for a request refused before routing (a foreign `Host` or an `Origin`); `code` is the numeric status |

A sign request refused before its type is known (a malformed identifier or body) is counted only in
`http_mldsa87_malformed_request_count_total`, not in `signing_requests_total`.

## 4. Alerts

[`deploy/prometheus/alerts.yml`](../../deploy/prometheus/alerts.yml) holds the shipped rules. Load it with
`rule_files:` in `prometheus.yml`.

### RandaoNewLayerRateLimited

`RemoteSignerRandaoNewLayerRateLimited`: `consensus_randao_new_layer_rate_limited_total` increased. A key asked for
more new onion layers than its bucket (`--randao-new-layer-burst`, `--randao-new-layer-refill-epochs`) allows, and the
reveal was refused with 412 `RANDAO_NEW_LAYER_RATE_LIMITED`.

1. Find the key in the signer's WARN log: it names the short key id.
2. An honest validator client asks for one new layer per proposal, so repeated refusals mean another client is
   driving the key, or the bucket is too small for a very small network where one key proposes often. See
   [`randao.md`](randao.md#3-sizing-the-bucket) for sizing.
3. If another client is using the key, stop it: two clients on one key also risk slashing.

### RandaoGapAdvanced

`RemoteSignerRandaoGapAdvanced`: a reveal advanced the frontier over layers this signer never released
(`consensus_randao_reveals_total{result="gap_advanced"}`). Either someone else released reveals for the key (a second
signer, or a key that was used outside this signer), or the slashing-protection store was restored from an older
backup.

1. Check that no other signer or validator client holds the key.
2. If the store was restored, the alert is expected once per key; confirm the restore and acknowledge it.

### SignatureFault

`RemoteSignerSignatureFault`: `signing_verify_failures_total` or `signing_keys_quarantined` is above 0. A signature
failed verification before release. The signer answered 500 `SIGNATURE_FAULT`, discarded the bytes and quarantined
the key, which answers 503 `KEY_QUARANTINED` from then on. A fault is a hardware or memory error, or tampering;
deterministic signing makes it dangerous to keep signing with the key.

1. Read the ERROR log line: it names the key and the artifact type.
2. Check the host: memory errors (ECC logs), CPU throttling or overclocking, and the binary's integrity.
3. `POST /reload` (admin token) re-derives the quarantined key from its key file and lifts the quarantine. If the
   fault repeats, move the key to another host.

`signing_verify_failures_total` counts since the process started, so the alert clears after a restart, and
`signing_keys_quarantined` returns to 0 after a successful reload.

### ConnectionLimitReached

`RemoteSignerConnectionLimitReached`: the API listener reached `--http-max-connections` (default 1,024) and new
connections waited until one closed. Validator clients keep a few connections each, so this means a connection leak
or a misbehaving client.

1. Count the clients and their connections (`ss -tn sport = :9000`).
2. Raise `--http-max-connections` only when the client count explains the load.

## 5. The Grafana dashboard

[`deploy/grafana/remotesigner.json`](../../deploy/grafana/remotesigner.json) charts the metrics above. Import it in
Grafana (Dashboards, New, Import) and pick the Prometheus data source; the `Instance` variable selects one or more
signers. It is adapted from Web3Signer's dashboard and carries its licence notice in its `description`.

| Row | Panels |
|---|---|
| Overview | release, loaded keys, quarantined keys, signature faults, slashing refusals in the time range, fewest RANDAO layers left |
| Signing | sign requests by type and by result, signing time (p50, p99), malformed and unknown-key requests, signature faults and quarantined keys |
| Slashing protection | refusals by reason, permitted signings, store transaction time by operation (p50, p99) |
| RANDAO | reveals by result, new-layer refusals and slow-path scans, reveal time by path (p99), layers left |
| HTTP | API requests by route and status, request time by route (p99), open connections, requests in flight, connection-limit hits |
| Process | CPU, resident and heap memory, goroutines, GC time |

A test (`internal/metrics`) checks that every metric the dashboard queries is registered, so the dashboard cannot
drift from the catalogue.
