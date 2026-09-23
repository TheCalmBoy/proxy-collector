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

## Data attribution

DB-IP Lite is licensed under CC BY 4.0. See `output/ATTRIBUTION.txt` and https://db-ip.com.
