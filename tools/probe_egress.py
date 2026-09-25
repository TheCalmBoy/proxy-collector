#!/usr/bin/env python3
"""
Phase 2 Probe: Stability verification using cloudflare trace
- Reads enriched-configs.json from Phase 1
- 10 x 30s stability checks via cloudflare.com/cdn-cgi/trace
- Dynamic config classification
- Outputs: egress-health.json
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import random
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ENRICHED_PATH = Path(os.getenv("ENRICHED_PATH", "verify-output/enriched-configs.json"))
OUTPUT = Path(os.getenv("PROBE_OUTPUT", "probe-output"))
PORT_BASE = 30000
SPEED_TEST_BYTES = 5_000_000
MIN_DOWNLOAD_MB_S = 0.0005
SPEED_CONSISTENCY_TOLERANCE = 0.25
UTLS_FINGERPRINTS = {
    "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android",
    "random", "randomized",
}
# Stability check config
STABILITY_INTERVALS = 10
STABILITY_INTERVAL_SECONDS = 30
CLOUDFLARE_TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"

# Dynamic config thresholds
DYNAMIC_MIN_SPEED_MB_S = 1.0      # 1 MB/s for dynamic to be "elite"
DYNAMIC_MAX_PING_MS = 100         # Max ping for dynamic elite
DYNAMIC_MAX_FRAUD_SCORE = 30      # Max fraud score for dynamic elite


class UnsupportedConfig(ValueError):
    pass


def _first(params: dict[str, list[str]], *keys: str, default: str = "") -> str:
    for key in keys:
        values = params.get(key)
        if values:
            return values[0]
    return default


def _decode_base64(value: str) -> bytes:
    value = value.strip().replace("-", "+").replace("_", "/")
    value += "=" * ((4 - len(value) % 4) % 4)
    return base64.b64decode(value)


def _host_port(parsed: urllib.parse.SplitResult) -> tuple[str, int]:
    host = parsed.hostname
    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsupportedConfig("invalid_port") from exc
    if not host or not port:
        raise UnsupportedConfig("missing_host_or_port")
    return host, port


def parse_proxy_uri(uri: str) -> dict[str, Any]:
    clean = uri.strip()
    if not clean:
        raise UnsupportedConfig("empty")
    scheme = clean.split(":", 1)[0].lower()

    if scheme == "vmess":
        payload = clean[len("vmess://"):].split("#", 1)[0]
        try:
            vmess = json.loads(_decode_base64(payload))
        except Exception as exc:
            raise UnsupportedConfig("invalid_vmess_payload") from exc
        host = str(vmess.get("add") or vmess.get("server") or "")
        try:
            port = int(vmess.get("port"))
        except (TypeError, ValueError) as exc:
            raise UnsupportedConfig("missing_host_or_port") from exc
        if not host:
            raise UnsupportedConfig("missing_host_or_port")
        outbound = {
            "type": "vmess",
            "server": host,
            "server_port": port,
            "uuid": str(vmess.get("id") or vmess.get("uuid") or ""),
            "alter_id": int(vmess.get("aid") or vmess.get("alterId") or 0),
            "security": str(vmess.get("scy") or vmess.get("security") or "auto"),
        }
        if vmess.get("net"):
            outbound["transport"] = _vmess_transport(vmess)
        return outbound

    parsed = urllib.parse.urlsplit(clean)
    if parsed.scheme not in ("vless", "trojan", "ss", "socks", "socks5", "http", "https"):
        raise UnsupportedConfig(f"unsupported_scheme_{parsed.scheme}")

    host, port = _host_port(parsed)
    params = urllib.parse.parse_qs(parsed.query)

    if parsed.scheme in ("vless", "trojan"):
        uuid = parsed.username or _first(params, "uuid", "id")
        if not uuid:
            raise UnsupportedConfig("missing_uuid")
        outbound = {
            "type": parsed.scheme,
            "server": host,
            "server_port": port,
            "uuid": uuid if parsed.scheme == "vless" else None,
            "password": uuid if parsed.scheme == "trojan" else None,
        }
        if parsed.scheme == "vless":
            outbound["flow"] = _first(params, "flow") or ""
            outbound["tls"] = _first(params, "security", "tls") in ("tls", "reality")
            if outbound["tls"]:
                outbound["server_name"] = _first(params, "sni", "host") or host
                if _first(params, "fp") == "chrome":
                    outbound["utls"] = {"enabled": True, "fingerprint": "chrome"}
        else:
            outbound["tls"] = _first(params, "security", "tls") == "tls"
            if outbound["tls"]:
                outbound["server_name"] = _first(params, "sni", "host") or host
        transport = _common_transport(params)
        if transport:
            outbound["transport"] = transport
        return outbound

    if parsed.scheme == "ss":
        auth = parsed.username
        if not auth:
            raise UnsupportedConfig("missing_ss_auth")
        try:
            method, password = _decode_base64(auth).decode().split(":", 1)
        except Exception as exc:
            raise UnsupportedConfig("invalid_ss_auth") from exc
        outbound = {
            "type": "shadowsocks",
            "server": host,
            "server_port": port,
            "method": method,
            "password": password,
        }
        transport = _common_transport(params)
        if transport:
            outbound["transport"] = transport
        return outbound

    if parsed.scheme in ("socks", "socks5"):
        user = urllib.parse.unquote(parsed.username or "")
        pwd = urllib.parse.unquote(parsed.password or "")
        outbound = {"type": "socks", "server": host, "server_port": port, "version": "5"}
        if user:
            outbound["username"] = user
            outbound["password"] = pwd
        return outbound

    if parsed.scheme in ("http", "https"):
        user = urllib.parse.unquote(parsed.username or "")
        pwd = urllib.parse.unquote(parsed.password or "")
        outbound = {"type": "http", "server": host, "server_port": port}
        if user:
            outbound["username"] = user
            outbound["password"] = pwd
        outbound["tls"] = parsed.scheme == "https"
        return outbound

    raise UnsupportedConfig(f"unsupported_scheme_{parsed.scheme}")


def _vmess_transport(vmess: dict) -> dict[str, Any] | None:
    net = str(vmess.get("net") or "").lower()
    if net == "tcp":
        header_type = str(vmess.get("type") or "none")
        if header_type == "http":
            return {"type": "http", "host": [vmess.get("host", "")]}
        return None
    if net in ("ws", "websocket"):
        path = vmess.get("path", "/")
        host = vmess.get("host", "")
        transport = {"type": "ws", "path": path}
        if host:
            transport["headers"] = {"Host": host}
        return transport
    if net == "grpc":
        service = vmess.get("serviceName", "")
        transport = {"type": "grpc"}
        if service:
            transport["service_name"] = service
        return transport
    return None


def _common_transport(params: dict[str, list[str]]) -> dict[str, Any] | None:
    net = _first(params, "type", "network", "net")
    if not net:
        return None
    if net == "ws":
        path = _first(params, "path") or "/"
        host = _first(params, "host")
        transport = {"type": "ws", "path": path}
        if host:
            transport["headers"] = {"Host": str(host)}
        return transport
    if net == "grpc":
        service = _first(params, "serviceName", "service_name")
        transport = {"type": "grpc"}
        if service:
            transport["service_name"] = service
        return transport
    return None


def _download_rate_mbps(payload_bytes: int, max_payload_bytes: int, starttransfer: float, total: float) -> float | None:
    transfer_seconds = total - starttransfer
    if payload_bytes <= 0 or payload_bytes > max_payload_bytes or transfer_seconds <= 0:
        return None
    return payload_bytes / 1_000_000 / transfer_seconds


def _lowest_speed(*samples: float | None) -> float | None:
    valid = [sample for sample in samples if sample is not None and sample > 0]
    return min(valid) if valid else None


def _speed_is_consistent(first: float | None, second: float | None) -> bool:
    if first is None or second is None or not first or not second:
        return False
    return not (abs(first - second) / max(first, second) > SPEED_CONSISTENCY_TOLERANCE)


def _speed_retests(first: float | None, second: float | None) -> int:
    return sum(sample is not None for sample in (first, second))


def _valid_speed(first: float | None, second: float | None) -> float | None:
    speed = _lowest_speed(first, second)
    if speed is None or speed < MIN_DOWNLOAD_MB_S:
        return None
    return round(speed, 6)


def _tag(uri: str) -> str:
    return hashlib.sha256(uri.encode()).hexdigest()[:8].upper()


def build_sing_box_config(uris: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int]]:
    inbounds: list[dict[str, Any]] = []
    outbounds: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    stats = {"input": len(uris), "supported": 0, "unsupported": 0}
    reasons: dict[str, int] = {}

    for uri in uris:
        try:
            outbound = parse_proxy_uri(uri)
        except UnsupportedConfig as exc:
            stats["unsupported"] += 1
            reasons[str(exc)] = reasons.get(str(exc), 0) + 1
            continue
        identifier = _tag(uri)
        inbound_tag = f"in-{identifier}"
        outbound_tag = f"proxy-{identifier}"
        port = PORT_BASE + len(records)
        inbound = {"type": "socks", "tag": inbound_tag, "listen": "127.0.0.1", "listen_port": port}
        outbound["tag"] = outbound_tag
        inbounds.append(inbound)
        outbounds.append(outbound)
        rules.append({"inbound": [inbound_tag], "action": "route", "outbound": outbound_tag})
        records.append({"id": identifier, "port": port, "scheme": outbound["type"]})
        stats["supported"] += 1

    config = {
        "log": {"level": "error", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds + [{"type": "direct", "tag": "direct"}],
        "route": {"rules": rules, "final": "direct"},
    }
    return config, records, {**stats, **{f"skip_{key}": value for key, value in sorted(reasons.items())}}


async def _cloudflare_trace(proxy_port: int) -> dict[str, Any]:
    """Get IP info from cloudflare.com/cdn-cgi/trace via proxy"""
    config_lines = [
        f'proxy = "socks5h://127.0.0.1:{proxy_port}"',
        f'url = "{CLOUDFLARE_TRACE_URL}"',
        "silent",
        "show-error",
        "fail",
        "connect-timeout = 5",
        "max-time = 10",
    ]
    process = await asyncio.create_subprocess_exec(
        "curl", "--config", "-",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await process.communicate(("\n".join(config_lines) + "\n").encode())

    if process.returncode != 0:
        return {"ok": False, "error": f"curl_exit_{process.returncode}"}

    try:
        text = stdout.decode().strip()
        lines = text.split("\n")
        data = {}
        for line in lines:
            if "=" in line:
                k, v = line.split("=", 1)
                data[k] = v
        return {
            "ok": True,
            "ip": data.get("ip"),
            "country": data.get("loc"),
            "colo": data.get("colo"),
        }
    except Exception:
        return {"ok": False, "error": "parse_failed"}


async def _speed_test(record: dict[str, Any], worker_url: str, token: str, semaphore: asyncio.Semaphore) -> dict[str, Any]:
    body_path = Path("/tmp") / f"speed-{record['id']}.bin"
    config_lines = [
        f'proxy = "socks5h://127.0.0.1:{record["port"]}"',
        f'url = "{worker_url}/ip?download_bytes={SPEED_TEST_BYTES}"',
        f'header = "Authorization: Bearer {token}"',
        "silent",
        "show-error",
        "fail",
        "connect-timeout = 10",
        "max-time = 30",
        f'output = "{body_path}"',
        'write-out = "\\n__SPEED_METRICS__%{size_download} %{time_starttransfer} %{time_total}"',
    ]
    async with semaphore:
        process = await asyncio.create_subprocess_exec(
            "curl", "--config", "-",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate(("\n".join(config_lines) + "\n").encode())

    if not body_path.exists() or process.returncode != 0:
        return {"ok": False, "error": f"curl_exit_{process.returncode}"}

    response_body = body_path.read_bytes()
    body_path.unlink(missing_ok=True)
    metadata_line, separator, downloaded = response_body.partition(b"\n")
    if not separator:
        return {"ok": False, "error": "missing_speed_metrics"}

    try:
        result = json.loads(metadata_line.decode())
    except Exception:
        return {"ok": False, "error": "invalid_worker_response"}

    _, marker, metric = stdout.partition(b"\n__SPEED_METRICS__")
    latency_ms = None
    download_mb_s = None
    if marker:
        try:
            downloaded_size, starttransfer, total = map(float, metric.decode().strip().split())
            latency_ms = round(starttransfer * 1000, 1)
            if total > starttransfer:
                download_mb_s = len(downloaded) / 1_000_000 / (total - starttransfer)
        except (UnicodeDecodeError, ValueError):
            pass

    ok = download_mb_s is not None and download_mb_s >= MIN_DOWNLOAD_MB_S
    return {
        "ok": ok,
        "id": record["id"],
        "ip": result.get("ip"),
        "country": (result.get("cloudflare") or {}).get("country"),
        "colo": (result.get("cloudflare") or {}).get("colo"),
        "fraud_score": (result.get("ffraud") or {}).get("fraud_score"),
        "risk": (result.get("ffraud") or {}).get("risk"),
        "proxy": (result.get("ffraud") or {}).get("proxy"),
        "vpn": (result.get("ffraud") or {}).get("vpn"),
        "tor": (result.get("ffraud") or {}).get("tor"),
        "hosting": (result.get("ffraud") or {}).get("hosting"),
        "connection_type": (result.get("ffraud") or {}).get("connection_type"),
        "latency_ms": latency_ms,
        "download_mb_s": download_mb_s,
        "speed_ok": ok,
    }


async def _run_stability_check(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run one stability check using cloudflare trace"""
    semaphore = asyncio.Semaphore(max(1, int(os.getenv("PROBE_CONCURRENCY", "750"))))

    async def check_one(record):
        async with semaphore:
            return await _cloudflare_trace(record["port"])

    return await asyncio.gather(*[check_one(r) for r in records])


def _classify_dynamic(ip_history: list[str], speed_history: list[float | None], fraud_scores: list[int | None], countries: list[str | None]) -> dict[str, Any]:
    """Classify dynamic config based on IP history and quality metrics"""
    unique_ips = list(dict.fromkeys(ip_history))  # preserve order
    unique_countries = list(dict.fromkeys([c for c in countries if c]))

    # All IPs in same country?
    same_country = len(unique_countries) == 1 and unique_countries[0] is not None
    country = unique_countries[0] if same_country else None

    # Quality metrics
    valid_speeds = [s for s in speed_history if s is not None]
    avg_speed = sum(valid_speeds) / len(valid_speeds) if valid_speeds else 0
    max_speed = max(valid_speeds) if valid_speeds else 0
    valid_fraud = [f for f in fraud_scores if f is not None]
    min_fraud = min(valid_fraud) if valid_fraud else 100

    classification = {
        "unique_ips": unique_ips,
        "ip_count": len(unique_ips),
        "countries": unique_countries,
        "country": country,
        "same_country": same_country,
        "avg_speed_mb_s": round(avg_speed, 3),
        "max_speed_mb_s": round(max_speed, 3),
        "min_fraud_score": min_fraud,
    }

    # Decision logic
    if len(unique_ips) == 1:
        classification["type"] = "stable"
        classification["subgroup"] = "stable"
    elif same_country:
        # Dynamic but same country - check if quality is good enough for country subgroup
        if avg_speed >= DYNAMIC_MIN_SPEED_MB_S and min_fraud <= DYNAMIC_MAX_FRAUD_SCORE:
            classification["type"] = "dynamic-country"
            classification["subgroup"] = f"dynamic-country-{country}"
        else:
            classification["type"] = "dynamic-country"
            classification["subgroup"] = "rejected"
    else:
        # Multiple countries - only keep if elite
        if avg_speed >= DYNAMIC_MIN_SPEED_MB_S and min_fraud <= DYNAMIC_MAX_FRAUD_SCORE:
            classification["type"] = "dynamic-elite"
            classification["subgroup"] = "dynamic-elite"
        else:
            classification["type"] = "dynamic-mixed"
            classification["subgroup"] = "rejected"

    return classification


async def main() -> int:
    ENRICHED_PATH = Path(os.getenv("ENRICHED_PATH", "verify-output/enriched-configs.json"))
    if not ENRICHED_PATH.exists():
        print(f"Enriched configs not found at {ENRICHED_PATH}", file=sys.stderr)
        return 2

    print(f"Loading enriched configs from {ENRICHED_PATH}...")
    with ENRICHED_PATH.open() as f:
        enriched_data = json.load(f)

    enriched = enriched_data.get("configs", [])
    if not enriched:
        print("No enriched configs found", file=sys.stderr)
        return 1

    print(f"Loaded {len(enriched)} enriched configs")

    # Convert to probe format
    uris = [c["uri"] for c in enriched]
    config, records, config_stats = build_sing_box_config(uris)

    # Map enriched data to records by ID
    enriched_by_id = {c["id"]: c for c in enriched}
    for r in records:
        if r["id"] in enriched_by_id:
            r.update(enriched_by_id[r["id"]])

    print(f"Starting sing-box with {len(records)} configs...")
    config_path = Path("/tmp/probe-egress-sing-box.json")
    config_path.write_text(json.dumps(config, separators=(",", ":")))

    check = subprocess.run([SING_BOX, "check", "-c", str(config_path)], capture_output=True, text=True)
    if check.returncode:
        print("sing-box rejected the generated proxy config:", file=sys.stderr)
        print(check.stderr[-4000:], file=sys.stderr)
        return 1

    with Path("/tmp/probe-egress-sing-box.log").open("wb") as log:
        core = subprocess.Popen([SING_BOX, "run", "-c", str(config_path)], stdout=log, stderr=subprocess.STDOUT)

    semaphore = asyncio.Semaphore(max(1, int(os.getenv("PROBE_CONCURRENCY", "750"))))

    try:
        await asyncio.sleep(5)
        if core.poll() is not None:
            print("sing-box exited during startup; see artifact log.", file=sys.stderr)
            return 1

        # Initial speed test via Worker
        print("Running initial speed test via Worker...")
        first = await asyncio.gather(*(_speed_test(r, WORKER_URL, WORKER_TOKEN, semaphore) for r in records))
        ok = sum(1 for r in first if r.get("ok"))
        print(f"Initial: {ok}/{len(records)} returned an IP")

        # Stability checks via cloudflare trace
        ip_history = {r["id"]: [] for r in records}
        speed_history = {r["id"]: [] for r in records}
        fraud_history = {r["id"]: [] for r in records}
        country_history = {r["id"]: [] for r in records}

        # Include initial results
        for r in first:
            if r.get("ok"):
                rid = r["id"]
                ip_history[rid].append(r.get("ip"))
                speed_history[rid].append(r.get("download_mb_s"))
                fraud_history[rid].append(r.get("fraud_score"))
                country_history[rid].append(r.get("country"))

        print(f"Running {STABILITY_INTERVALS} stability checks at {STABILITY_INTERVAL_SECONDS}s intervals...")
        for i in range(STABILITY_INTERVALS):
            await asyncio.sleep(STABILITY_INTERVAL_SECONDS)
            print(f"Stability check {i+1}/{STABILITY_INTERVALS}...")
            results = await _run_stability_check(records)
            for j, r in enumerate(results):
                rid = records[j]["id"]
                if r.get("ok"):
                    ip_history[rid].append(r.get("ip"))
                    country_history[rid].append(r.get("country"))
                    # No speed/fraud from trace, so reuse last known
                    if speed_history[rid]:
                        speed_history[rid].append(speed_history[rid][-1])
                    if fraud_history[rid]:
                        fraud_history[rid].append(fraud_history[rid][-1])

        # Final speed test via Worker
        print("Running final speed test via Worker...")
        final = await asyncio.gather(*(_speed_test(r, WORKER_URL, WORKER_TOKEN, semaphore) for r in records))
        ok = sum(1 for r in final if r.get("ok"))
        print(f"Final: {ok}/{len(records)} returned an IP")

        for r in final:
            if r.get("ok"):
                rid = r["id"]
                ip_history[rid].append(r.get("ip"))
                speed_history[rid].append(r.get("download_mb_s"))
                fraud_history[rid].append(r.get("fraud_score"))
                country_history[rid].append(r.get("country"))

    finally:
        core.terminate()
        try:
            core.wait(timeout=5)
        except subprocess.TimeoutExpired:
            core.kill()
            core.wait()

    # Build egress-health.json with classifications
    print("Classifying configs...")
    health = {}
    for rid in sorted(ip_history.keys()):
        ips = ip_history[rid]
        if not ips:
            continue

        classification = _classify_dynamic(
            ip_history[rid],
            speed_history[rid],
            fraud_history[rid],
            country_history[rid],
        )

        # Only include non-rejected configs
        if classification["subgroup"] == "rejected":
            continue

        # Calculate final metrics
        valid_speeds = [s for s in speed_history[rid] if s is not None]
        avg_speed = sum(valid_speeds) / len(valid_speeds) if valid_speeds else 0

        # Find the record
        record = next((r for r in records if r["id"] == rid), None)
        if not record:
            continue

        health[rid] = {
            "scheme": record["scheme"],
            "server": record["server"],
            "server_port": record.get("server_port"),
            "classification": classification,
            "speed_mb_s": round(avg_speed, 3),
            "ip_count": len(ips),
            "unique_ips": ips,
            "primary_country": classification.get("country"),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

    OUTPUT.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT / "egress-health.json"
    output_path.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "configs": health,
    }, indent=2))

    print(f"Done. Published {len(health)} configs to {output_path}")

    # Stats
    stable = sum(1 for c in health.values() if c["classification"]["type"] == "stable")
    dyn_country = sum(1 for c in health.values() if c["classification"]["type"] == "dynamic-country")
    dyn_elite = sum(1 for c in health.values() if c["classification"]["type"] == "dynamic-elite")
    print(f"  Stable: {stable}")
    print(f"  Dynamic-country: {dyn_country}")
    print(f"  Dynamic-elite: {dyn_elite}")
    print(f"  Rejected: {len(records) - len(health)}")

    return 0 if health else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
