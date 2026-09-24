# proxy-collector prototype

This is the GitHub-side prototype for the proxy database pipeline.

## What it does

1. Downloads the current `verified/configs.txt` from 0xRadikal.
2. Parses supported proxy URIs and extracts their endpoint host.
3. Resolves the endpoint to a public IP.
4. Uses DB-IP Lite MMDB locally to determine the endpoint country.
5. Deduplicates IPs and uses ip-api.com's batch endpoint to add hosting/ISP/ASN metadata.
6. Writes all entries into country-specific text and Base64 files.
7. Publishes the generated `output/` directory to the `gh-pages` branch.

The collector intentionally does **not** hardcode a country allow-list. Every country found in the data gets its own file.

## Generated layout

```text
all.txt
all.txt.base64
countries/US.txt
countries/US.base64.txt
countries/UA.txt
countries/UA.txt.base64
...
manifest.json
ATTRIBUTION.txt
```

`all.txt` and the country files contain annotated proxy URIs. The Base64 variants are Base64 encodings of the corresponding text files.

## Important classification limitation

The country is the country of the resolved proxy endpoint IP according to DB-IP Lite. It is not a guarantee of the public egress IP that a website will see after connecting through the proxy.

`DC` means ip-api reported `hosting=true`; `RES` means `hosting=false`; lookup failures remain `UNKNOWN` rather than being forced into either class.

## Local run

Download a DB-IP Lite MMDB named `GeoLite2-Country.mmdb` into the repository root, then:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python main.py
```

## GitHub Pages

The workflow deploys `output/` to `gh-pages`. In the repository's Pages settings, select GitHub Actions / the `gh-pages` deployment as appropriate for the repository configuration.

## Real proxy egress checks

The separate `Probe proxy egress IPs` workflow fetches the current verified list and tests every supported VLESS, VMess, Shadowsocks, and Trojan link through sing-box. Each test requests `/ip?download_bytes=5000000` through the local SOCKS listener, which returns caller metadata followed by a 5 MB download sample. The larger transfer gives a steadier throughput estimate than the previous 1 MB sample. The workflow measures response latency and download throughput, waits five minutes, then retests the same links. It runs hourly at minute 17 or by manual dispatch, with up to 100 requests active concurrently. The Worker caches FFraud data per egress IP for six hours. Each full result is available as a 14-day Actions artifact named `proxy-egress-report-<run-id>`. A compact `egress-health.json` index is also published to the Pages feed, keyed by the same stable proxy IDs used in country files. It includes only links that returned an egress IP in both rounds and had at least one measured speed of 10 KB/s or higher. For displayed speed it uses the slower valid sample, even when the retests differ, and omits raw egress IPs.

Before running it, add an Actions repository secret named `IP_CHECK_WORKER_TOKEN` containing the Worker bearer token from `.api-bearer-token` in the separate Worker project. Keep that value private. The Worker URL is already configured in the workflow. Unsupported URI schemes and protocol options are counted and skipped rather than guessed. The report includes observed egress IPs, FFraud reputation, measured download speeds, and whether those speeds repeated closely; generated sing-box configs and source proxy credentials are kept out of the artifact. The 5 MB sample is about 240 GB of test data per day at roughly 1,000 configs checked hourly.

## Data attribution

DB-IP Lite is licensed under CC BY 4.0. See `output/ATTRIBUTION.txt` and https://db-ip.com.
