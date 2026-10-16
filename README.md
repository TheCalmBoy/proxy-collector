# proxy-collector

Collects public proxy configs, verifies which ones actually work, and publishes them as
ready-to-use subscriptions.

It runs in two places:

- **GitHub Actions** — the pipeline: fetch → probe → geolocate → publish to `gh-pages`.
- **Cloudflare Workers** — serve the subscriptions, wake the pipeline, verify egress.

## Layout

| Path | What it is |
|---|---|
| `main.py`, `tools/` | the pipeline: fetch, probe, classify, publish |
| `tests/`, `run_tests.py` | pipeline tests |
| `.github/workflows/` | the jobs — see [Scheduling](#scheduling) |
| `workers/proxy-chain-subscription/` | the subscription endpoint clients point at |
| `workers/proxy-egress-ip-check/` | measures an exit's public IP and download speed |
| `workers/proxy-pipeline-heartbeat/` | the Worker that wakes the pipeline every 30 min |
| `CODE_MAP.json` | machine-readable map of the above |

Every Worker lives under `workers/`, holding what Cloudflare actually runs.
`proxy-chain-subscription` and `proxy-egress-ip-check` are committed as the esbuild output
Cloudflare executes; `proxy-pipeline-heartbeat` is a small hand-written module, so its
committed file is both source and bundle.

## Scheduling

GitHub's free-tier `schedule:` crons stopped firing for this repo on 2026-10-01 and froze
the pipeline. Nothing here relies on `schedule:` any more.

Every 30 minutes a Cloudflare cron on `workers/proxy-pipeline-heartbeat/` POSTs a
`repository_dispatch` (`update-now`). It runs on a different platform, so GitHub's
best-effort scheduler cannot skip it. `update.yml` receives that event directly: fetch →
verify → publish to `gh-pages`, then chain `probe-egress.yml` with `gh workflow run`, so
the probe measures the pool that was just published. One beat, one pool, measured once.

The beat is 30 minutes rather than 15 because a full chain is update (~6.5 min median,
12.5 max) plus probe (~5.2 min). At a 15-minute beat the next tick landed mid-chain, the
update queued on its concurrency group instead of running, and its chained probe landed
~6 min after the previous probe with no new pool in between.

Every workflow is also runnable by hand via `workflow_dispatch`.

## Published data (`gh-pages`)

| File | Contents |
|---|---|
| `all.txt` | every verified proxy URI, annotated |
| `countries/<CC>.txt` | the same, split by endpoint country |
| `all.txt.base64`, `countries/<CC>.base64.txt` | base64 of the above |
| `manifest.json`, `ATTRIBUTION.txt`, `source_map.json` | index, credits, URI → source |
| `enriched-configs.json` | configs with their probe and country metadata |
| `egress-health.json` | measured egress health per exit, refreshed by `probe-egress` |
| `rejected-endpoints.json` | what the probes rejected, and why |

## Subscription endpoint

`GET /sub` on `workers/proxy-chain-subscription`. The format is detected from the
client's User-Agent; override it when detection gets it wrong.

| Query | Default | Meaning |
|---|---|---|
| `format` | from User-Agent | `mihomo`, `sing-box`, `xray`, `links` (`clash` → `mihomo`) |
| `country` | `ALL` | two-letter ISO code, or `ALL` |
| `entry64` | none | base64 proxy URI for an entrypoint; repeatable |
| `secure=1` | off | keep only exits whose hop is TLS |
| `ech=embed` | off | pin the ECH key into the config instead of leaving it to the client's DNS |

Response headers report pipeline state: `x-health-index` (`fresh` / `aged`),
`x-health-join`, `x-ech-mode`.

**Entrypoints and exits.** `entry64` is the hop that gets out of a filtered network; the
Worker chains the feed's exits behind it with `dialer-proxy`. Exits are handed out
round-robin, so no one entrypoint carries every connection.

**Size.** There is no cap on how many entrypoints you send, how long one may be, or how
large the response grows: the worker renders the whole feed. Per-country exits are still
capped at `COUNTRY_CAP`, which is what keeps the output a sane size.

### ECH

An entrypoint whose edge requires ECH leaks the destination name in its ClientHello
unless the client holds Cloudflare's ECH public key. The default leaves that key to the
client's own DNS (`query-server-name`), because mihomo has no `ECHRejectionError`
recovery: a pinned key that later rotates hard-fails with no fallback. `?ech=embed` pins
it anyway, for clients that cannot resolve it themselves — refresh the subscription
every 30–60 minutes if you use it.

## Tests

```bash
python3 run_tests.py                  # all pipeline tests
python3 run_tests.py classify         # only files whose name matches "classify"
cd workers/proxy-chain-subscription && node --test   # Worker tests
```

CI runs the Python suite on every push and pull request
(`.github/workflows/test.yml`). The Worker tests are not wired into CI — run them with
`node --test` as above.

`workers/proxy-chain-subscription/scripts/verify-chain.sh` is the end-to-end check
against a live Worker: it parses the rendered YAML, starts mihomo on it, fetches through
the chain, and reports the egress country.

```bash
SUB_URL='https://<worker>/sub?format=mihomo&entry64=<base64-uri>' ./scripts/verify-chain.sh
```

## Running the pipeline locally

Needs a DB-IP Lite MMDB named `GeoLite2-Country.mmdb` in the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

Output lands in `output/`. `MMDB_PATH`, `OUTPUT_DIR`, and `IP_API_URL` are overridable by
environment variable.

## How a proxy is classified

The country is the country of the resolved endpoint IP according to DB-IP Lite. It is
not a guarantee about the egress IP a website will see after connecting through the
proxy.

`DC` means ip-api reported `hosting=true`, `RES` means `hosting=false`; a failed lookup
stays `UNKNOWN` rather than being forced into either class. There is deliberately no
country allow-list — every country present in the data gets its own file.

## Upstream sources

Feeds are kept only on measured yield — `main.py` records the numbers behind each
addition and removal, including the ones that were dropped again.

- `0xRadikal/Free-v2ray-Configs` — `verified/configs.txt`; the only feed that has consistently earned its bandwidth
- `hamedcode/port-based-v2ray-configs` — `sub/ss.txt` only; its vless/vmess/trojan files were dropped
- ~~`patterniha/Free-Configs`~~ — dropped 2026-10-16: 0/278 twice, the second time on the repaired tester; its pinned edge is TCP-dead from Iran and its SNI names are dropped at the TLS handshake
- `iampedii/whitedns-sub` — `base64.txt`, added 2026-10-16; 145 candidates → 22 survived (15.17%) on the repaired tester, up from 5.96% before the TLS/transport fixes
