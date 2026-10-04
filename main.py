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
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import geoip2.database
import requests


# One upstream, and that is a measured decision rather than a default.
#
# A second source (Epodonios/v2ray-configs) was tried and removed. Measured at
# fixed concurrency, same gates, same thresholds:
#   0xRadikal only   1587 candidates -> 402 final
#   + Epodonios      7027 candidates -> 365 final
# It added 5440 candidates and produced 37 FEWER final configs. 0xRadikal's
# verified set is already the best-filtered pool we can get; Epodonios is a
# pre-filter feed whose extra volume is almost entirely dead endpoints, and
# the extra TCP probing costs more than the good ones are worth.
#
# Endpoint counts for reference (server:port keys, not lines):
#   0xRadikal verified  1173 endpoints
#   Epodonios           3509 endpoints, 559 shared with 0xRadikal
# Shared or not, 0xRadikal's output is the one that survives our gates.
#
# Yield per run, measured on final survivors (not candidates) on 2026-09-29:
#   0xRadikal   256/1326 = 19.3%   <- the only feed that earns its cost
#   Epodonios    30/5153 =  0.6%   <- dropped 2026-09-29 on user request
#   ebrasha       0/4502 =  0.0%   <- dropped 2026-09-29 on user request
# Epodonios was previously re-added on request after 23d4d5f dropped it on the
# same evidence; that verdict held, and this run's per_source table settled it
# with final-survival numbers rather than candidate counts. ebrasha never
# returned a single survivor: 41% of the run's input for nothing.
DEFAULT_SOURCE_URLS = (
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
    # hamedcode/port-based-v2ray-configs, 2026-09-29. Run 36568377510 measured
    # all four per-protocol files end to end. Only the Shadowsocks file is
    # worth keeping; the other three are 5757 candidates for 10 survivors,
    # which is pure run-time cost and the exact dead weight that got ebrasha
    # dropped.
    #   ss.txt     238 candidates ->  32 survived (13.45%)  <- best source now
    #   vless.txt 3760 candidates ->   8 survived ( 0.21%)  <- dropped
    #   vmess.txt 1449 candidates ->   2 survived ( 0.14%)  <- dropped
    #   trojan.txt 548 candidates ->   0 survived ( 0.00%)  <- dropped
    "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/ss.txt",
    # Kept 0xRadikal: 1020 candidates -> 218 survived (21.4%), the only feed
    # that has ever earned its bandwidth.
    # Removed cbusifabcap 2026-09-29 after run 36559202167 measured it:
    #   758 candidates -> 40 survived (5.3%)
    # I added it on a Stage 1 liveness number (58.5%, matching 0xRadikal's
    # 58.7%) and that was the wrong signal. Stage 1 liveness has now
    # mispredicted three sources in a row -- ebrasha, Epodonios, barry-far all
    # looked alive and yielded ~0%, and cbusifabcap did the same. Only an
    # end-to-end run's survival_rate is evidence. Do not re-add a source
    # without a full-run survival number for it.
    # Removed barry-far 2026-09-29 after run 36557357087 measured it:
    #   4169 candidates -> 4 survived (0.1%)
    # It looked fine on the cheap Stage 1 gate (39% of 2891 endpoints alive) and
    # then produced almost nothing, so TCP liveness is not a proxy for yield.
    # Same shape as the two feeds removed in ca59542, four times the volume.
)
# Comma-separated override. A single URL still works.
SOURCE_URLS = tuple(
    url.strip()
    for url in os.getenv("SOURCE_URLS", ",".join(DEFAULT_SOURCE_URLS)).split(",")
    if url.strip()
) or DEFAULT_SOURCE_URLS
SOURCE_URL = os.getenv("SOURCE_URL", DEFAULT_SOURCE_URLS[0])
IP_API_URL = os.getenv("IP_API_URL", "http://ip-api.com/batch")
# The free ip-api tier rate-limits per source IP, and one runner resolving every
# config in the corpus trips it long before the batch/pacing logic can help.
# Routing the lookups through an already-verified proxy keeps the answers
# identical (ip-api reports the queried IP's country, not the caller's) while
# spreading the quota across egress addresses.
IP_API_PROXY_URL = os.getenv("IP_API_PROXY_URL", "").strip()
# Clash-API base of the sing-box pool sidecar (see tools/ipapi_proxy_pool.py).
# When set, each ip-api request is preceded by a switch to the next member so
# the calls spread across egress addresses instead of one.
IP_API_PROXY_POOL = os.getenv("IP_API_PROXY_POOL", "").strip()
MMDB_PATH = os.getenv("MMDB_PATH", "GeoLite2-Country.mmdb")
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "output"))
IP_API_BATCH_SIZE = 100
# Free-tier fields only; see fetch_ip_metadata for why Pro-only fields break it.
DEFAULT_IP_API_FIELDS = "status,countryCode,isp,org,as,asname"
HTTP_TIMEOUT = 30
# Threads for the concurrent DNS pre-warm. 32 sits well under the runner's
# thread/process ceiling and well under the file-descriptor limit, and DNS
# lookups are pure network wait, so this is I/O bound rather than CPU bound.
DNS_WARMUP_WORKERS = 32
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


_DNS_CACHE: dict[str, str | None] = {}


def resolve_host(host: str) -> str | None:
    """Resolve a hostname and return one public address, preferring IPv4.

    Memoized, and that is the whole point of it. The four upstream feeds
    republish the same few thousand hosts, so a 10.6k-config corpus contains
    far fewer distinct names than configs -- but the caller looped over every
    config and paid a blocking getaddrinfo each time. Run 36455487959 spent
    632s of its 22.8 min between "Loaded 16652 unique config lines" and
    "Parsed 10533 entries"; the ip-api pool and the sources were both fast.
    A cache turns that into one lookup per DISTINCT host.

    lru_cache would work but is not used deliberately: callers pass untrusted
    upstream strings, and a bounded cache on an unbounded key space is a
    memory-growth vector on a hostile feed. This dict is bounded the same way
    the input is -- it dies with the process.
    """
    if host in _DNS_CACHE:
        return _DNS_CACHE[host]

    resolved = _resolve_host_uncached(host)
    _DNS_CACHE[host] = resolved
    return resolved


def prewarm_dns(hosts: list[str], workers: int = DNS_WARMUP_WORKERS) -> int:
    """Resolve distinct hosts concurrently so the parse loop never blocks.

    The cache removed duplicate lookups but left the first lookup per host
    serial: run 36459022405 still spent 437s in the parse phase for ~4000
    distinct names, because getaddrinfo blocks and the loop held one at a
    time. Pre-warming collapses that to roughly (distinct / workers) x
    per-lookup latency.

    Only uncached hosts are submitted, so this is a no-op on a warm cache.
    Returns the number of hosts submitted, so a caller can log a
    before/after and prove the warm cache actually did something.
    """
    pending = []
    seen: set[str] = set()
    for host in hosts:
        if host in _DNS_CACHE or host in seen:
            continue
        seen.add(host)
        pending.append(host)

    if not pending:
        return 0

    started = time.monotonic()
    workers = max(1, min(workers, len(pending)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        # map over the CACHED resolver, not _resolve_host_uncached. Calling the
        # uncached function would do every lookup but write none of them to
        # _DNS_CACHE, so the parse loop would immediately repeat all of them --
        # the pre-warm would cost a full extra round of DNS for nothing.
        list(pool.map(resolve_host, pending))

    elapsed = time.monotonic() - started
    print(
        f"DNS pre-warm resolved {len(pending)} distinct hosts "
        f"across {workers} threads in {elapsed:.1f}s."
    )
    return len(pending)


def _resolve_host_uncached(host: str) -> str | None:
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


def fetch_source_configs(
    session: requests.Session,
) -> tuple[list[str], dict[str, str]]:
    """Union every configured upstream, with per-line provenance.

    A source that fails must not take the run down: the others still carry
    volume, and losing one repo is exactly the silent shrinkage this replaces.
    Per-source counts are printed so a drop is visible in the log rather than
    inferred from a smaller total.

    Returns the union plus a map of line -> first source that supplied it, so
    every downstream record can be attributed. First-wins matches the dedup
    order below: a line duplicated across sources is credited to the one that
    was read first, which keeps the per-source counts summing to the total.
    """
    lines: list[str] = []
    seen: set[str] = set()
    provenance: dict[str, str] = {}
    for url in SOURCE_URLS:
        try:
            response = session.get(url, timeout=HTTP_TIMEOUT)
            response.raise_for_status()
        except requests.RequestException as error:
            print(f"Source unavailable, skipping: {url} ({error})")
            continue

        added = 0
        for raw_line in response.text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line in seen:
                continue
            seen.add(line)
            lines.append(line)
            provenance[line] = url
            added += 1
        print(f"  {added:>6} new  {url}")

    if not lines:
        raise RuntimeError("No upstream source returned any configs")
    return lines, provenance


def fetch_previous_verified(session: requests.Session) -> list[str]:
    """Re-seed from our own last published output.

    Upstream repos rotate: a config that passed every gate yesterday can be
    absent from today's source, and a failed probe is not proof the proxy died
    (probe hosts rate-limit, CI runners get throttled). Treating the previous
    run's qualified set as an additional source means a drop in upstream only
    costs us the new candidates, never the known-good ones.

    Read from the published artifact rather than the local OUTPUT_DIR: the
    workflow starts from a clean checkout, so locally there is nothing to reuse.
    """
    url = os.getenv("PREVIOUS_VERIFIED_URL", "").strip()
    if not url:
        return []

    print(f"Re-seeding from previous verified output: {url}")
    try:
        response = session.get(url, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as error:
        # Never fail the run because the carry-over is unavailable; upstream is
        # still a valid source on its own.
        print(f"Previous verified output unavailable ({error}); continuing without it.")
        return []

    # The published file is plain text, but accept the base64 sibling too so a
    # bad guess at the URL degrades to a no-op instead of garbage input. Sniff
    # the WHOLE body, not just line 1: a file whose first line is prose (a
    # header, an error page) would otherwise be decoded as base64 into noise,
    # silently yielding zero configs instead of the real ones.
    text = response.text
    looks_like_plain = sum(1 for line in text.splitlines() if "://" in line)
    looks_like_b64 = text.strip() and not re.search(r"[^A-Za-z0-9+/=\s]", text)
    if looks_like_b64 and looks_like_plain == 0:
        try:
            text = base64.b64decode(text.strip() + "=" * (-len(text.strip()) % 4)).decode("utf-8", "replace")
        except Exception:
            pass

    lines: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "://" not in line:
            continue
        if line in seen:
            continue
        seen.add(line)
        lines.append(line)

    print(f"Loaded {len(lines)} configs from the previous verified output.")
    return lines


def geoip_country(reader: geoip2.database.Reader, ip: str) -> str | None:
    try:
        result = reader.country(ip)
        return result.country.iso_code
    except Exception:
        return None


def build_ip_api_session(base: requests.Session) -> requests.Session:
    """Return a session whose ip-api traffic optionally leaves via a proxy.

    A dedicated session keeps the proxy config from leaking into the source
    downloads, which must always be fetched directly. Falls back to `base`
    unchanged when no proxy is configured or the URL is unusable, so the
    behaviour with no env var set is exactly what it was before.
    """
    if not IP_API_PROXY_URL:
        return base

    parsed = urllib.parse.urlsplit(IP_API_PROXY_URL)
    if not parsed.scheme or not parsed.hostname:
        print(f"  IP_API_PROXY_URL is not a usable proxy URL; using direct route")
        return base

    session = requests.Session()
    session.headers.update(dict(base.headers))
    session.proxies.update(
        {
            "http": IP_API_PROXY_URL,
            "https": IP_API_PROXY_URL,
        }
    )
    print(f"  ip-api lookups routed via proxy {parsed.scheme}://{parsed.hostname}:{parsed.port or ''}")

    if IP_API_PROXY_POOL:
        _attach_pool_rotation(session, IP_API_PROXY_POOL)
    return session


def _attach_pool_rotation(
    session: requests.Session,
    api_url: str,
) -> None:
    """Rotate the sidecar's selected member before each ip-api request.

    The sidecar's pool is a sing-box `selector`, which holds one member until
    something switches it. Rotating here is what makes the calls leave via
    different egress addresses instead of one; without it the free-tier quota
    is still spent by a single caller.
    """
    base = api_url.rstrip("/")
    # The control plane must stay direct: routing sing-box's own Clash API
    # through the proxy it is switching would ask it to proxy a request that
    # tells it which proxy to use.
    control = requests.Session()
    try:
        listing = control.get(f"{base}/proxies/pool", timeout=HTTP_TIMEOUT)
        members = listing.json().get("all", [])
    except Exception as exc:
        print(f"  pool rotation disabled: {exc}")
        return
    if len(members) < 2:
        print("  pool rotation needs at least 2 members; disabled")
        return

    state = {"i": 0}
    original_post = session.post

    def rotating_post(*args: object, **kwargs: object):
        member = members[state["i"] % len(members)]
        state["i"] += 1
        try:
            control.put(
                f"{base}/proxies/pool",
                json={"name": member},
                timeout=HTTP_TIMEOUT,
            )
        except Exception:
            pass
        return original_post(*args, **kwargs)

    session.post = rotating_post  # type: ignore[method-assign]
    print(f"  round-robin across {len(members)} pool members via {base}")


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
    # "query" is an implicit echo field, not a data field: unless it is listed
    # the batch response omits it entirely, so the response cannot be matched
    # back to the requested IP and every lookup looks like a miss.
    fields = default_ip_api_fields()

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


def default_ip_api_fields() -> str:
    """Fields requested from ip-api: free tier only, plus the query echo.

    "query" must be listed or the batch response omits it, which makes entries
    impossible to match back to the requested IP.
    """
    return os.getenv("IP_API_FIELDS", f"query,{DEFAULT_IP_API_FIELDS}")


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
    # 12 hex = 48 bits: long enough that two configs can't share a tail,
    # short enough to keep URI fragments and display names compact. The
    # subscription worker spells these bytes into a per-config name
    # (hash-spelling bijection), so the tail is also the name key.
    return hashlib.sha256(uri.encode("utf-8")).hexdigest()[:12].upper()


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
    per_source_published: Counter[str] = Counter()
    per_source_candidates: Counter[str] = Counter()
    for record in records:
        uri = record["uri"]
        base = uri.split("#", 1)[0]
        per_source_candidates[record.get("source", "unknown")] += 1
        if base in seen_base:
            continue
        seen_base.add(base)
        per_source_published[record.get("source", "unknown")] += 1

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

    # Which source supplies each deduplicated output line, BEFORE verification.
    # Neither column here is a survival rate: "candidates" is everything the
    # source offered, "after_dedup" is what it uniquely contributed to
    # output/all.txt, and the difference is overlap with an earlier feed.
    #
    # This table is deliberately NOT called "published". An earlier version used
    # that word and every row read published == candidates with overlap 0,
    # because both counters incremented over the same pass -- it read like the
    # evidence for dropping a feed while describing nothing. True per-source
    # survival is computed after verification, in tools/verify.py's
    # enriched-configs.json, by joining survivors through source_map.json.
    stats["per_source"] = {
        source: {
            "candidates": per_source_candidates[source],
            "after_dedup": per_source_published[source],
            "overlap": per_source_candidates[source] - per_source_published[source],
        }
        for source in sorted(per_source_published | per_source_candidates)
    }

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

    # A sidecar map from base URI -> source label. output/all.txt stays plain URIs
    # on purpose: the Worker reads the '#' fragment as display metadata, so the
    # source cannot ride along in the URI itself. Without this map, the collector
    # can only ever report per_source counts for PRE-verification candidates, and
    # the per-source "published" number is a synonym for "candidate" -- it cannot
    # tell a source that contributes unique survivors from one that is a subset of
    # a feed already in the list.
    (OUTPUT_DIR / "source_map.json").write_text(
        json.dumps(
            {record["uri"].split("#", 1)[0]: record.get("source", "unknown") for record in records},
            indent=0,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

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

    upstream_lines, line_sources = fetch_source_configs(session)
    carryover_lines = fetch_previous_verified(session)
    print(f"Loaded {len(upstream_lines)} unique config lines from the source.")

    # Union upstream with our own last winners. Dedup on the base URI (the part
    # before "#") because the carry-over file is already annotated, so the same
    # proxy would otherwise enter twice under two names and survive the
    # post-annotation dedup in build_outputs() as two separate entries.
    def base_of(line: str) -> str:
        return line.split("#", 1)[0]

    source_lines: list[str] = []
    seen_bases: set[str] = set()
    CARRYOVER_LABEL = "carry-over"
    base_sources: dict[str, str] = {}
    for line in upstream_lines + carryover_lines:
        key = base_of(line)
        if key in seen_bases:
            continue
        seen_bases.add(key)
        source_lines.append(line)
        # A base may reach us from upstream and from our own last output. The
        # upstream claim wins, because that is the only one that measures
        # whether the source still carries it; carry-over only gets the bases
        # that nothing upstream offered this run. Upstream is iterated first,
        # so setdefault alone already encodes "first source wins".
        base_sources.setdefault(key, line_sources.get(line, CARRYOVER_LABEL))

    # Every carry-over config must be probed again this run. A stale good result
    # is worse than none: it would publish a proxy that no longer works.
    #
    # Report the union, not a difference. len(source_lines) - len(upstream_lines)
    # is NEGATIVE whenever carry-over lines are all already present upstream,
    # which is the normal case once a feed is republished -- so this printed
    # "Carry-over added -5835 configs" and hid the fact that upstream had
    # simply grown. The number that matters is how many bases came only from
    # carry-over, which is the size of the carry-over label.
    carryover_only = sum(1 for label in base_sources.values() if label == CARRYOVER_LABEL)
    print(
        f"Union: {len(source_lines)} configs "
        f"({len(upstream_lines)} upstream, {carryover_only} contributed only by carry-over); "
        f"all {len(source_lines)} will be re-verified from scratch."
    )

    # Warm DNS before parsing. The loop below calls resolve_host() per config
    # and would otherwise block on the first lookup for each distinct name.
    # Collecting hosts first costs one extra cheap pass over the lines and
    # makes the wait a single measurable, concurrent step.
    endpoints = [parse_endpoint(line) for line in source_lines]
    distinct_hosts = {host for _, host in endpoints if host}
    print(f"Collected {len(distinct_hosts)} distinct hosts from {len(source_lines)} lines.")
    prewarm_dns(sorted(distinct_hosts))

    stats: dict[str, Any] = {
        "source_entries": len(source_lines),
        "upstream_entries": len(upstream_lines),
        "carryover_entries": len(carryover_lines),
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
        # zip against the endpoints already parsed for the pre-warm, so the
        # URI text is only parsed once per line for the whole run.
        for uri, (scheme, host) in zip(source_lines, endpoints):
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
                "source": base_sources.get(base_of(uri), CARRYOVER_LABEL),
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
    api_results = query_ip_api(build_ip_api_session(session), unique_ips)

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
