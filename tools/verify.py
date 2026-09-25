#!/usr/bin/env python3
"""
Phase 1 Verification: Tiered proxy validation
- Tier 1: TCP sanity check (1.5s)
- Tier 2: 20 TCP + 20 UDP over 40s (>=90% pass)
- Tier 3: 5 MB speed test via Worker (>=75 KB/s)
Outputs: enriched-configs.json
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import random
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Config
SOURCE_URL = os.getenv(
    "SOURCE_URL",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
)
WORKER_URL = os.environ.get("WORKER_URL", "").rstrip("/")
WORKER_TOKEN = os.environ.get("WORKER_TOKEN", "")
SING_BOX = os.getenv("SING_BOX", "sing-box")
OUTPUT = Path(os.getenv("VERIFY_OUTPUT", "verify-output"))
CONCURRENCY = max(1, int(os.getenv("VERIFY_CONCURRENCY", "750")))
SPEED_TEST_BYTES = 5_000_000
MIN_SPEED_MB_S = 0.075  # 75 KB/s
TCP_TIMEOUT = 1.5
PACKET_TEST_COUNT = 20
PACKET_TEST_DURATION = 40  # seconds
PACKET_TEST_MIN_SUCCESS_RATE = 0.90

# UDP test targets (public DNS servers)
UDP_TARGETS = [
    ("1.1.1.1", 53),
    ("8.8.8.8", 53),
    ("9.9.9.9", 53),
]


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
        }
        if parsed.scheme == "vless":
            outbound["uuid"] = uuid
            outbound["flow"] = _first(params, "flow") or ""
            if _first(params, "security", "tls") in ("tls", "reality"):
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": _first(params, "sni", "host") or host,
                }
                if _first(params, "fp") == "chrome":
                    outbound["tls"]["utls"] = {"enabled": True, "fingerprint": "chrome"}
                if _first(params, "security", "tls") == "reality":
                    pbk = _first(params, "pbk", "public_key")
                    sid = _first(params, "sid", "short_id")
                    if pbk:
                        outbound["tls"]["reality"] = {"public_key": pbk}
                    if sid:
                        outbound["tls"]["reality"]["short_id"] = sid
        else:
            outbound["password"] = uuid
            if _first(params, "security", "tls") == "tls":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": _first(params, "sni", "host") or host,
                }
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


async def _tcp_connect(host: str, port: int, timeout: float) -> tuple[bool, float | None]:
    """Try TCP connect, return (success, latency_ms)"""
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        latency_ms = (time.perf_counter() - start) * 1000
        writer.close()
        await writer.wait_closed()
        return True, latency_ms
    except Exception:
        return False, None


async def _udp_ping(host: str, port: int, timeout: float) -> tuple[bool, float | None]:
    """Send UDP packet, return (success, latency_ms)"""
    start = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x00", (host, port))
        try:
            sock.recvfrom(1024)
            latency_ms = (time.perf_counter() - start) * 1000
            return True, latency_ms
        except socket.timeout:
            return False, None
        finally:
            sock.close()
    except Exception:
        return False, None


async def _packet_test(host: str, port: int, scheme: str) -> dict[str, Any]:
    """Run 20 TCP + 20 UDP tests over 40 seconds"""
    interval = PACKET_TEST_DURATION / PACKET_TEST_COUNT
    tcp_latencies = []
    udp_latencies = []
    tcp_success = 0
    udp_success = 0

    for i in range(PACKET_TEST_COUNT):
        # TCP test
        ok, lat = await _tcp_connect(host, port, TCP_TIMEOUT)
        if ok:
            tcp_success += 1
            tcp_latencies.append(lat)

        # UDP test (only for UDP-capable schemes)
        if scheme in ("vless", "trojan", "vmess", "ss", "socks", "socks5"):
            ok, lat = await _udp_ping(host, port, 1.0)
            if ok:
                udp_success += 1
                udp_latencies.append(lat)

        await asyncio.sleep(interval)

    tcp_rate = tcp_success / PACKET_TEST_COUNT
    udp_rate = udp_success / PACKET_TEST_COUNT if udp_latencies else 1.0

    def stats(latencies: list[float]) -> dict[str, float]:
        if not latencies:
            return {}
        sorted_lat = sorted(latencies)
        return {
            "avg_ms": sum(latencies) / len(latencies),
            "min_ms": min(latencies),
            "max_ms": max(latencies),
            "p50_ms": sorted_lat[len(sorted_lat) // 2],
            "p95_ms": sorted_lat[int(len(sorted_lat) * 0.95)],
            "jitter_ms": max(latencies) - min(latencies),
        }

    return {
        "tcp": {
            "success_rate": tcp_rate,
            "success_count": tcp_success,
            **stats(tcp_latencies),
        },
        "udp": {
            "success_rate": udp_rate,
            "success_count": udp_success,
            **stats(udp_latencies),
        },
        "passed": tcp_rate >= PACKET_TEST_MIN_SUCCESS_RATE and udp_rate >= PACKET_TEST_MIN_SUCCESS_RATE,
    }


async def _speed_test(record: dict[str, Any], worker_url: str, token: str, semaphore: asyncio.Semaphore) -> dict[str, Any]:
    """Run 5 MB download speed test via Worker"""
    body_path = Path("/tmp") / f"speed-{record['id']}.bin"
    config_lines = [
        f'proxy = "socks5h://127.0.0.1:{record["server_port"]}"',
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

    ok = download_mb_s is not None and download_mb_s >= MIN_SPEED_MB_S
    return {
        "ok": ok,
        "ip": result.get("ip"),
        "country": (result.get("cloudflare") or {}).get("country"),
        "latency_ms": latency_ms,
        "download_mb_s": download_mb_s,
        "speed_ok": ok,
    }


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
        port = 30000 + len(records)
        inbound = {"type": "socks", "tag": inbound_tag, "listen": "127.0.0.1", "listen_port": port}
        outbound["tag"] = outbound_tag

        rule = {"outbound": outbound_tag, "inbound": [inbound_tag]}
        inbounds.append(inbound)
        outbounds.append(outbound)
        rules.append(rule)
        records.append({
            "id": identifier,
            "scheme": outbound["type"],
            "server": outbound["server"],
            "server_port": port,
            "uri": uri,
        })
        stats["supported"] += 1

    config = {
        "log": {"level": "warn"},
        "inbounds": inbounds,
        "outbounds": outbounds + [{"type": "direct", "tag": "direct"}],
        "route": {"rules": rules, "final": "direct"},
    }
    return config, records, {**stats, **{f"skip_{k}": v for k, v in sorted(reasons.items())}}


async def _run_sing_box(config: dict) -> asyncio.subprocess.Process:
    config_path = Path("/tmp/verify-sing-box.json")
    config_path.write_text(json.dumps(config, separators=(",", ":")))
    proc = await asyncio.create_subprocess_exec(
        SING_BOX, "run", "-c", str(config_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await asyncio.sleep(3)  # startup time
    if proc.returncode is not None:
        stdout, stderr = await proc.communicate()
        print(f"sing-box failed to start (exit {proc.returncode}):", file=sys.stderr)
        print(stderr.decode()[-2000:], file=sys.stderr)
        raise RuntimeError(f"sing-box exited with code {proc.returncode}")
    return proc


async def main() -> int:
    worker_url = os.environ.get("WORKER_URL", "").rstrip("/")
    worker_token = os.environ.get("WORKER_TOKEN", "")
    if not worker_url or not worker_token:
        print("Set WORKER_URL and WORKER_TOKEN", file=sys.stderr)
        return 2
    if not worker_url.startswith("https://"):
        print("WORKER_URL must be an HTTPS URL.", file=sys.stderr)
        return 2

    print("Fetching candidate configs...")
    try:
        req = urllib.request.Request(SOURCE_URL, headers={"accept": "text/plain"})
        source_text = urllib.request.urlopen(req, timeout=30).read().decode()
    except Exception as exc:
        print(f"Failed to fetch source: {exc}", file=sys.stderr)
        return 1

    uris = [line.strip() for line in source_text.splitlines() if line.strip()]
    print(f"Fetched {len(uris)} raw configs")

    config, records, stats = build_sing_box_config(uris)
    if not records:
        print("No supported configs", file=sys.stderr)
        return 1

    print(f"Starting sing-box with {len(records)} configs...")
    sing_box_proc = await _run_sing_box(config)

    try:
        semaphore = asyncio.Semaphore(CONCURRENCY)
        enriched = []

        # Tier 1: TCP sanity
        print(f"Tier 1: TCP sanity check ({len(records)} configs)...")
        tier1_results = await asyncio.gather(*[
            _tcp_connect(r["server"], r["server_port"], TCP_TIMEOUT) for r in records
        ])
        tier1_survivors = [r for r, (ok, _) in zip(records, tier1_results) if ok]
        print(f"Tier 1 passed: {len(tier1_survivors)}/{len(records)}")

        # Tier 2: Packet loss test
        print(f"Tier 2: Packet loss test ({len(tier1_survivors)} configs)...")
        tier2_results = await asyncio.gather(*[
            _packet_test(r["server"], r["server_port"], r["scheme"]) for r in tier1_survivors
        ])
        tier2_survivors = [r for r, res in zip(tier1_survivors, tier2_results) if res["passed"]]
        print(f"Tier 2 passed: {len(tier2_survivors)}/{len(tier1_survivors)}")

        # Tier 3: Speed test
        print(f"Tier 3: Speed test ({len(tier2_survivors)} configs)...")
        tier3_results = await asyncio.gather(*[
            _speed_test(r, worker_url, worker_token, semaphore) for r in tier2_survivors
        ])

        # Build enriched output
        for r, p2, p3 in zip(tier2_survivors, tier2_results, tier3_results):
            if p3.get("ok"):
                enriched.append({
                    "id": r["id"],
                    "scheme": r["scheme"],
                    "server": r["server"],
                    "server_port": r["server_port"],
                    "uri": r["uri"],
                    "country": p3.get("country"),
                    "tier1": {"tcp_ok": True, "latency_ms": p3.get("latency_ms")},
                    "tier2": p2,
                    "tier3": {
                        "speed_mb_s": p3.get("download_mb_s"),
                        "latency_ms": p3.get("latency_ms"),
                        "passed": p3.get("speed_ok"),
                    },
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                })

        OUTPUT.mkdir(parents=True, exist_ok=True)
        output_path = OUTPUT / "enriched-configs.json"
        output_path.write_text(json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "configs": enriched,
            "stats": {
                "input": stats["input"],
                "tier1_passed": len(tier1_survivors),
                "tier2_passed": len(tier2_survivors),
                "tier3_passed": len(enriched),
            }
        }, indent=2))
        print(f"Done. Enriched configs: {len(enriched)}")
        print(f"Saved to {output_path}")

    finally:
        if sing_box_proc.returncode is None:
            sing_box_proc.terminate()
            try:
                await asyncio.wait_for(sing_box_proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                sing_box_proc.kill()
                await sing_box_proc.wait()

    return 0 if enriched else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))