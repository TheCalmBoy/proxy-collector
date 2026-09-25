from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import socket
import time
import urllib.parse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import geoip2.database
import requests


SOURCE_URL = os.getenv(
    "SOURCE_URL",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
)
IP_API_URL = os.getenv("IP_API_URL", "http://ip-api.com/batch")
MMDB_PATH = os.getenv("MMDB_PATH", "GeoLite2-Country.mmdb")
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "output"))
IP_API_BATCH_SIZE = 100
# Free-tier fields only; see fetch_ip_metadata for why Pro-only fields break it.
DEFAULT_IP_API_FIELDS = "status,countryCode,isp,org,as,asname"
HTTP_TIMEOUT = 30
USER_AGENT = "proxy-collector/1.0 (+https://github.com/your-repo)"


# Protocols whose endpoint can normally be extracted from a URI using urlsplit().
URI_SCHEMES = {
    "vless",
    "vmess",
    "trojan",
    "ss",
    "ssr",
    "socks",
    "socks5",
    "http",
    "https",
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
    "anytls",
    "wg",
    "wireguard",
}


def safe_b64decode(value: str) -> bytes:
    value = value.strip().replace("-", "+").replace("_", "/")
    value += "=" * ((4 - len(value) % 4) % 4)
    return base64.b64decode(value, validate=False)


def parse_vmess(uri: str) -> tuple[str | None, dict[str, Any] | None]:
    try:
        encoded = uri[len("vmess://") :].split("#", 1)[0]
        data = json.loads(safe_b64decode(encoded).decode("utf-8", errors="strict"))
        if not isinstance(data, dict):
            return None, None

        # `add` is the VMess server address. `host` may instead be a transport host.
        host = data.get("add") or data.get("server")
        if not host:
            return None, data
        return str(host).strip(), data
    except Exception:
        return None, None


def parse_endpoint(uri: str) -> tuple[str | None, str | None]:
    """Return (scheme, endpoint host) for a supported proxy URI."""
    uri = uri.strip()
    if not uri:
        return None, None

    if uri.lower().startswith("vmess://"):
        host, _ = parse_vmess(uri)
        return "vmess", host

    try:
        clean = uri.split("#", 1)[0]
        parsed = urllib.parse.urlsplit(clean)
        scheme = parsed.scheme.lower()
        if scheme not in URI_SCHEMES:
            return None, None

        # urlsplit().hostname correctly handles userinfo, IPv6 brackets, etc.
        host = parsed.hostname
        if host:
            return scheme, host

        # A few unusual URI forms can put the endpoint in the path.
        # Keep this conservative rather than guessing arbitrary text is a hostname.
        if parsed.path and "@" in parsed.path:
            candidate = parsed.path.rsplit("@", 1)[-1].split("/", 1)[0]
            try:
                return scheme, urllib.parse.urlsplit(f"//{candidate}").hostname
            except ValueError:
                return scheme, None
    except ValueError:
        return None, None

    return scheme, None


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def resolve_host(host: str) -> str | None:
    """Resolve a hostname and return one public address, preferring IPv4."""
    try:
        ipaddress.ip_address(host)
        return host if is_public_ip(host) else None
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return None

    candidates: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        address = sockaddr[0]
        if is_public_ip(address) and address not in candidates:
            candidates.append(address)

    # Prefer IPv4 for compatibility with downstream APIs and simpler diagnostics.
    candidates.sort(key=lambda value: (":" in value, value))
    return candidates[0] if candidates else None


def fetch_source_configs(session: requests.Session) -> list[str]:
    print(f"Fetching source configs from: {SOURCE_URL}")
    response = session.get(SOURCE_URL, timeout=HTTP_TIMEOUT)
    response.raise_for_status()

    lines: list[str] = []
    seen: set[str] = set()
    for raw_line in response.text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line in seen:
            continue
        seen.add(line)
        lines.append(line)

    return lines


def geoip_country(reader: geoip2.database.Reader, ip: str) -> str | None:
    try:
        result = reader.country(ip)
        return result.country.iso_code
    except Exception:
        return None


def query_ip_api(
    session: requests.Session,
    ips: list[str],
) -> dict[str, dict[str, Any]]:
    """Batch query ip-api, respecting its published 100-IP / 15-requests-minute limits."""
    results: dict[str, dict[str, Any]] = {}

    # ip-api's free tier rejects a batch that asks for Pro-only fields
    # ("hosting", "proxy"): every entry comes back status=fail, so asking for
    # them silently classified the whole corpus as UNKNOWN. We request only free
    # fields and infer hosting from the provider strings instead.
    fields = os.getenv("IP_API_FIELDS", DEFAULT_IP_API_FIELDS)

    for start in range(0, len(ips), IP_API_BATCH_SIZE):
        chunk = ips[start : start + IP_API_BATCH_SIZE]
        payload = [{"query": ip, "fields": fields} for ip in chunk]

        print(
            f"ip-api batch {start // IP_API_BATCH_SIZE + 1} "
            f"({len(chunk)} IPs)..."
        )

        try:
            response = session.post(
                IP_API_URL,
                json=payload,
                timeout=HTTP_TIMEOUT,
            )
        except requests.RequestException as exc:
            print(f"  request failed: {exc}")
            # Do not classify failed lookups as DC/RES.
            for ip in chunk:
                results[ip] = {"status": "error", "message": str(exc)}
            continue

        remaining_raw = response.headers.get("X-Rl")
        reset_raw = response.headers.get("X-Ttl")

        try:
            remaining = int(remaining_raw) if remaining_raw is not None else None
        except ValueError:
            remaining = None
        try:
            reset_seconds = int(reset_raw) if reset_raw is not None else 60
        except ValueError:
            reset_seconds = 60

        if response.status_code == 429:
            sleep_for = max(reset_seconds, 1) + 1
            print(f"  rate limited; sleeping {sleep_for}s")
            time.sleep(sleep_for)
            # Retry the same chunk once after the documented rate-limit window.
            try:
                response = session.post(
                    IP_API_URL,
                    json=payload,
                    timeout=HTTP_TIMEOUT,
                )
            except requests.RequestException as exc:
                print(f"  retry failed: {exc}")
                for ip in chunk:
                    results[ip] = {"status": "error", "message": str(exc)}
                continue

        if response.status_code != 200:
            print(f"  HTTP {response.status_code}; preserving UNKNOWN classification")
            for ip in chunk:
                results[ip] = {
                    "status": "error",
                    "message": f"HTTP {response.status_code}",
                }
        else:
            try:
                batch_results = response.json()
            except ValueError:
                batch_results = []

            if isinstance(batch_results, list):
                for item in batch_results:
                    if isinstance(item, dict) and item.get("query"):
                        results[str(item["query"])] = item

            # ip-api answers status=fail per IP when the batch asks for fields
            # the caller's tier cannot see, and GitHub's runner ranges are
            # frequently rejected outright. Surface why, so a 0-success run is
            # not mistaken for "all residential".
            failed = [
                item
                for item in batch_results
                if isinstance(item, dict) and item.get("status") != "success"
            ]
            if failed:
                sample = failed[0]
                print(
                    f"  {len(failed)}/{len(chunk)} lookups failed: "
                    f"status={sample.get('status')!r} "
                    f"message={str(sample.get('message'))[:120]!r} "
                    f"query={sample.get('query')!r}"
                )
            else:
                print(f"  {len(chunk)}/{len(chunk)} lookups succeeded")
            for ip in chunk:
                results.setdefault(ip, {"status": "error", "message": "missing result"})

        # The public batch API documents X-Rl/X-Ttl; stop sending requests when X-Rl hits 0.
        if remaining == 0 and start + IP_API_BATCH_SIZE < len(ips):
            sleep_for = max(reset_seconds, 1) + 1
            print(f"  rate window exhausted; sleeping {sleep_for}s")
            time.sleep(sleep_for)

    return results


def sanitize_label(value: str, fallback: str = "UNKNOWN", max_len: int = 20) -> str:
    value = value.upper().strip()
    value = re.sub(r"[^A-Z0-9]+", "-", value).strip("-")
    return (value[:max_len] or fallback)


def as_label(result: dict[str, Any]) -> str:
    as_field = str(result.get("as") or "")
    match = re.search(r"\bAS\d+\b", as_field, flags=re.IGNORECASE)
    if match:
        return match.group(0).upper()

    asname = str(result.get("asname") or "")
    if asname:
        return sanitize_label(asname, max_len=16)

    isp = str(result.get("isp") or "")
    return sanitize_label(isp, max_len=16)


HOSTING_HINTS = (
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean", "linode",
    "vultr", "ovh", "hetzner", "cloudflare", "contabo", "leaseweb", "hosting",
    "datacenter", "data center", "server", "cloud", "colocation", "hetzner",
    "scaleway", "oracle", "alibaba", "tencent", "equinix", "leaseweb",
)


def classify(result: dict[str, Any]) -> str:
    if result.get("status") != "success":
        return "UNKNOWN"
    # Preferred signal when a Pro key supplies the real boolean.
    hosting = result.get("hosting")
    if hosting is True:
        return "DC"
    if hosting is False:
        return "RES"
    # Free tier has no "hosting" field, so infer it from provider metadata.
    blob = " ".join(
        str(result.get(k) or "")
        for k in ("isp", "org", "asname", "as")
    ).lower()
    if any(hint in blob for hint in HOSTING_HINTS):
        return "DC"
    if blob.strip():
        return "RES"
    return "UNKNOWN"


def stable_id(uri: str) -> str:
    return hashlib.sha256(uri.encode("utf-8")).hexdigest()[:8].upper()


def annotate_uri(uri: str, country: str | None, api_result: dict[str, Any] | None) -> str:
    base = uri.split("#", 1)[0]
    country_tag = sanitize_label(country or "ZZ", fallback="ZZ", max_len=2)
    result = api_result or {}
    kind = classify(result)
    network = as_label(result)
    return f"{base}#{country_tag}-{kind}-{network}-{stable_id(base)}"


def write_text_and_b64(path: Path, lines: list[str]) -> None:
    text = "\n".join(lines)
    if lines:
        text += "\n"

    path.write_text(text, encoding="utf-8")
    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    b64_path = path.with_name(f"{path.stem}.base64{path.suffix}")
    b64_path.write_text(encoded + ("\n" if encoded else ""), encoding="utf-8")


def build_outputs(records: list[dict[str, Any]], stats: dict[str, Any]) -> None:
    countries_dir = OUTPUT_DIR / "countries"
    countries_dir.mkdir(parents=True, exist_ok=True)

    grouped: defaultdict[str, list[str]] = defaultdict(list)
    all_lines: list[str] = []

    # De-duplicate after annotation using the base URI; a source duplicate should not
    # become multiple public entries merely because metadata changed.
    seen_base: set[str] = set()
    for record in records:
        uri = record["uri"]
        base = uri.split("#", 1)[0]
        if base in seen_base:
            continue
        seen_base.add(base)

        annotated = record["annotated_uri"]
        country = record["country"] or "ZZ"
        bucket = country if country != "ZZ" else "unknown"
        grouped[bucket].append(annotated)
        all_lines.append(annotated)

    # Stable, deterministic output makes diffs and Worker caching easier to reason about.
    all_lines.sort()
    for lines in grouped.values():
        lines.sort()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    write_text_and_b64(OUTPUT_DIR / "all.txt", all_lines)

    for country, lines in sorted(grouped.items()):
        write_text_and_b64(countries_dir / f"{country}.txt", lines)

    country_counts = {country: len(lines) for country, lines in sorted(grouped.items())}
    stats["country_counts"] = country_counts
    stats["output_entries"] = len(all_lines)

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": SOURCE_URL,
        "geoip_database": "DB-IP Lite IP to Country MMDB",
        "geoip_license": "CC BY 4.0 (attribution: https://db-ip.com)",
        "ip_classification": "ip-api.com batch (hosting -> DC/RES)",
        "stats": stats,
        "files": {
            "all": "all.txt",
            "all_base64": "all.base64.txt",
            "countries": "countries/",
        },
    }

    (OUTPUT_DIR / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    (OUTPUT_DIR / "ATTRIBUTION.txt").write_text(
        "This dataset uses DB-IP Lite IP geolocation data.\n"
        "Licensed under CC BY 4.0.\n"
        "Attribution: https://db-ip.com\n",
        encoding="utf-8",
    )

    print(f"Wrote {len(all_lines)} unique annotated entries to {OUTPUT_DIR}/")
    print("Countries:")
    for country, count in country_counts.items():
        print(f"  {country}: {count}")


def main() -> None:
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    if not Path(MMDB_PATH).exists():
        raise FileNotFoundError(
            f"GeoIP database not found: {MMDB_PATH}. "
            "The GitHub Actions workflow should download DB-IP Lite before running main.py."
        )

    source_lines = fetch_source_configs(session)
    print(f"Loaded {len(source_lines)} unique config lines from the source.")

    stats: dict[str, Any] = {
        "source_entries": len(source_lines),
        "parsed_entries": 0,
        "unresolved_entries": 0,
        "unsupported_entries": 0,
        "unique_ips": 0,
        "ip_api_success": 0,
        "ip_api_failed": 0,
        "protocols": {},
        "classifications": {},
    }

    records: list[dict[str, Any]] = []
    protocol_counter: Counter[str] = Counter()
    ip_to_records: defaultdict[str, list[int]] = defaultdict(list)

    with geoip2.database.Reader(MMDB_PATH) as reader:
        for uri in source_lines:
            scheme, host = parse_endpoint(uri)
            if not scheme or not host:
                stats["unsupported_entries"] += 1
                continue

            protocol_counter[scheme] += 1
            ip = resolve_host(host)
            country = geoip_country(reader, ip) if ip else None

            record = {
                "uri": uri,
                "scheme": scheme,
                "host": host,
                "ip": ip,
                "country": country,
            }
            records.append(record)
            stats["parsed_entries"] += 1

            if not ip or not country:
                stats["unresolved_entries"] += 1
            if ip:
                ip_to_records[ip].append(len(records) - 1)

    unique_ips = sorted(ip_to_records)
    stats["unique_ips"] = len(unique_ips)

    print(f"Parsed {stats['parsed_entries']} entries; {len(unique_ips)} unique public IPs.")
    print("Querying hosting/ISP metadata...")
    api_results = query_ip_api(session, unique_ips)

    classifications: Counter[str] = Counter()
    for record in records:
        result = api_results.get(record["ip"], {}) if record["ip"] else {}
        record["api"] = result
        record["annotated_uri"] = annotate_uri(
            record["uri"],
            record["country"],
            result,
        )

        status = result.get("status")
        if status == "success":
            stats["ip_api_success"] += 1
        else:
            stats["ip_api_failed"] += 1

        classifications[classify(result)] += 1

    stats["protocols"] = dict(sorted(protocol_counter.items()))
    stats["classifications"] = dict(sorted(classifications.items()))

    build_outputs(records, stats)


if __name__ == "__main__":
    main()
