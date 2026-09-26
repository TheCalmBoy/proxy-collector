#!/usr/bin/env python3
"""
Phase 1 Verification: Tiered proxy validation
- Tier 1: TCP sanity check (1.5s)
- Tier 2: 20 SOCKS CONNECT + 20 HTTPS GET requests (>=90% pass each)
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
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Config
# Config. Multiple independent upstreams give us more diversity and a
# fallback: any one source being down or stale no longer empties the pool.
SOURCE_URLS = [
    url.strip()
    for url in os.getenv(
        "SOURCE_URLS",
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt,"
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    ).split(",")
    if url.strip()
]
WORKER_URL = os.environ.get("WORKER_URL", "").rstrip("/")
WORKER_TOKEN = os.environ.get("WORKER_TOKEN", "")
SING_BOX = os.getenv("SING_BOX", "sing-box")
OUTPUT = Path(os.getenv("VERIFY_OUTPUT", "verify-output"))
TCP_CONCURRENCY = max(1, int(os.getenv("VERIFY_TCP_CONCURRENCY", "750")))
HTTPS_CONCURRENCY = max(1, int(os.getenv("VERIFY_HTTPS_CONCURRENCY", "25")))
# sing-box 1.14 rejects any other value, and the whole process refuses to
# start, so unknown flows must be filtered out during parsing.
SUPPORTED_VLESS_FLOWS = frozenset({"xtls-rprx-vision"})
# sing-box 1.14 shadowsocks ciphers. chacha20-poly1305 and friends appear in
# the upstream source but are not built into the release we run.
SUPPORTED_SS_METHODS = frozenset({
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
})
# The 2022 ciphers derive their key from a base64 PSK and reject wrong lengths.
SS_METHOD_KEY_BYTES = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}
VERIFY_LIMIT = max(0, int(os.getenv("VERIFY_LIMIT", "0")))
SPEED_TEST_BYTES = 5_000_000
MIN_SPEED_MB_S = 0.075  # 75 KB/s
TCP_TIMEOUT = 1.5
PACKET_TEST_COUNT = 20
PACKET_TEST_DURATION = 40  # seconds
PACKET_TEST_MIN_SUCCESS_RATE = 0.90
HTTPS_TEST_URL = os.getenv(
    "VERIFY_HTTPS_URL", "https://www.gstatic.com/generate_204"
)


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
            flow = _first(params, "flow") or ""
            # Every config shares one sing-box process: an outbound with an
            # unrecognised flow makes sing-box abort at startup, zeroing the
            # entire run. Only pass through flows sing-box 1.14 accepts.
            if flow and flow not in SUPPORTED_VLESS_FLOWS:
                raise UnsupportedConfig(f"unsupported_flow:{flow}")
            outbound["flow"] = flow
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
        if method not in SUPPORTED_SS_METHODS:
            # Unrecognised ciphers abort the shared sing-box process, which
            # zeroes the entire run rather than skipping one bad config.
            raise UnsupportedConfig(f"unsupported_ss_method:{method}")
        required_key = SS_METHOD_KEY_BYTES.get(method)
        if required_key is not None:
            try:
                key_len = len(_decode_base64(password))
            except Exception as exc:
                raise UnsupportedConfig("invalid_ss_key") from exc
            if key_len != required_key:
                raise UnsupportedConfig("invalid_ss_key_length")
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
        path = _safe_ws_path(vmess.get("path"))
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


def _safe_ws_path(raw: Any) -> str:
    """Normalise a websocket path, or raise if it is not usable.

    sing-box fails to parse paths containing a bare or invalid percent escape
    (e.g. "/100%"), and a single bad transport aborts the whole process.
    """
    path = str(raw or "/")
    if not path.startswith("/"):
        path = "/" + path
    try:
        # A lone "%" is not a valid escape sequence.
        urllib.parse.unquote(path, errors="strict")
    except (UnicodeDecodeError, ValueError) as exc:
        raise UnsupportedConfig("invalid_ws_path") from exc
    if "%" in path and not re.search(r"%[0-9A-Fa-f]{2}", path):
        raise UnsupportedConfig("invalid_ws_path")
    return path


def _common_transport(params: dict[str, list[str]]) -> dict[str, Any] | None:
    net = _first(params, "type", "network", "net")
    if not net:
        return None
    if net == "ws":
        path = _safe_ws_path(_first(params, "path"))
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


async def _read_socks5_greeting(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> bytes:
    """Negotiate no-auth SOCKS5 with a sing-box inbound."""
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    version, method = await asyncio.wait_for(reader.readexactly(2), timeout=1.5)
    if version != 5:
        raise OSError("invalid_socks5_greeting")
    if method != 0:
        raise OSError("socks5_no_auth_not_selected")
    return b"\x05\x00"


async def _socks5_connect(
    proxy_port: int,
    destination_host: str,
    destination_port: int,
    timeout: float,
) -> tuple[bool, bytes | None]:
    """Require a real SOCKS5 CONNECT response, not only a listening socket."""
    writer: asyncio.StreamWriter | None = None
    try:
        async def exchange() -> bytes:
            nonlocal writer
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            await _read_socks5_greeting(reader, writer)
            host = destination_host.encode("idna")
            request = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", destination_port)
            writer.write(request)
            await writer.drain()
            version, reply, _reserved, address_type = await asyncio.wait_for(reader.readexactly(4), timeout=1.5)
            if version != 5 or reply != 0:
                raise OSError(f"socks5_reply_{reply}")
            if address_type == 1:
                await reader.readexactly(4)
            elif address_type == 4:
                await reader.readexactly(16)
            elif address_type == 3:
                length = (await reader.readexactly(1))[0]
                await reader.readexactly(length)
            else:
                raise OSError("socks5_invalid_bound_address")
            await reader.readexactly(2)
            return b"\x05\x00"

        return True, await asyncio.wait_for(exchange(), timeout=timeout)
    except Exception:
        return False, None
    finally:
        if writer is not None:
            writer.close()


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


async def _https_request(proxy_port: int, url: str, timeout: float) -> tuple[bool, float | None]:
    """Make one real HTTPS GET through a sing-box SOCKS inbound."""
    start = time.perf_counter()
    if os.getenv("VERIFY_DEBUG_HTTPS"):
        try:
            return await _https_request_inner(proxy_port, url, timeout, start)
        except Exception as exc:
            print(f"HTTPS_DEBUG {url} -> {type(exc).__name__}: {exc}", file=sys.stderr)
            return False, None
    return await _https_request_inner(proxy_port, url, timeout, start)


async def _https_request_inner(
    proxy_port: int,
    url: str,
    timeout: float,
    start: float,
) -> tuple[bool, float | None]:
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port or 443
        host = parsed.hostname
        if not host or parsed.scheme != "https":
            return False, None

        async def exchange() -> None:
            nonlocal reader, writer
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            await _read_socks5_greeting(reader, writer)
            encoded_host = host.encode("idna")
            writer.write(
                b"\x05\x01\x00\x03"
                + bytes([len(encoded_host)])
                + encoded_host
                + struct.pack("!H", port)
            )
            await writer.drain()
            version, reply, _reserved, address_type = await reader.readexactly(4)
            if version != 5 or reply != 0:
                raise OSError(f"socks5_reply_{reply}")
            if address_type == 1:
                await reader.readexactly(4)
            elif address_type == 4:
                await reader.readexactly(16)
            elif address_type == 3:
                length = (await reader.readexactly(1))[0]
                await reader.readexactly(length)
            else:
                raise OSError("socks5_invalid_bound_address")
            await reader.readexactly(2)

            ssl_context = ssl.create_default_context()
            await writer.start_tls(
                ssl_context,
                server_hostname=host,
                ssl_handshake_timeout=timeout,
            )
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            writer.write(
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                "User-Agent: proxy-collector/1.0\r\nConnection: close\r\n\r\n".encode()
            )
            await writer.drain()
            status_line = await reader.readline()
            if not status_line.startswith(b"HTTP/1.1 2") and not status_line.startswith(b"HTTP/1.0 2"):
                raise OSError("https_non_2xx")

        await asyncio.wait_for(exchange(), timeout=timeout)
        return True, (time.perf_counter() - start) * 1000
    except Exception as exc:
        if os.getenv("VERIFY_DEBUG_HTTPS"):
            print(f"HTTPS_DEBUG {url} -> {type(exc).__name__}: {exc}", file=sys.stderr)
        return False, None
    finally:
        if writer is not None:
            writer.close()


async def _packet_test(
    record: dict[str, Any],
    tcp_semaphore: asyncio.Semaphore | None = None,
    https_semaphore: asyncio.Semaphore | None = None,
) -> dict[str, Any]:
    """Run 20 concurrent SOCKS CONNECT + HTTPS GET pairs spaced 2s apart."""
    interval = PACKET_TEST_DURATION / PACKET_TEST_COUNT
    tcp_latencies: list[float] = []
    https_latencies: list[float] = []
    tcp_success = 0
    https_success = 0

    async def run_round() -> None:
        nonlocal tcp_success, https_success
        started_at = time.perf_counter()

        async def tcp_check() -> tuple[bool, Any]:
            if tcp_semaphore is None:
                return await _socks5_connect(record["port"], "1.1.1.1", 443, TCP_TIMEOUT)
            async with tcp_semaphore:
                return await _socks5_connect(record["port"], "1.1.1.1", 443, TCP_TIMEOUT)

        async def https_check() -> tuple[bool, float | None]:
            if https_semaphore is None:
                return await _https_request(record["port"], HTTPS_TEST_URL, TCP_TIMEOUT)
            async with https_semaphore:
                return await _https_request(record["port"], HTTPS_TEST_URL, TCP_TIMEOUT)

        tcp_result, https_result = await asyncio.gather(tcp_check(), https_check())
        if tcp_result[0]:
            tcp_success += 1
            tcp_latencies.append((time.perf_counter() - started_at) * 1000)
        if https_result[0] and https_result[1] is not None:
            https_success += 1
            https_latencies.append(https_result[1])

    for _ in range(PACKET_TEST_COUNT):
        await run_round()
        await asyncio.sleep(interval)

    tcp_rate = tcp_success / PACKET_TEST_COUNT
    https_rate = https_success / PACKET_TEST_COUNT

    def stats(latencies: list[float]) -> dict[str, float]:
        if not latencies:
            return {}
        sorted_lat = sorted(latencies)
        return {
            "avg_ms": sum(sorted_lat) / len(sorted_lat),
            "min_ms": min(sorted_lat),
            "max_ms": max(sorted_lat),
            "p50_ms": sorted_lat[len(sorted_lat) // 2],
            "p95_ms": sorted_lat[int(len(sorted_lat) * 0.95)],
            "jitter_ms": max(sorted_lat) - min(sorted_lat),
        }

    return {
        "tcp": {
            "success_rate": tcp_rate,
            "success_count": tcp_success,
            **stats(tcp_latencies),
        },
        "https": {
            "success_rate": https_rate,
            "success_count": https_success,
            **stats(https_latencies),
        },
        "passed": (
            tcp_rate >= PACKET_TEST_MIN_SUCCESS_RATE
            and https_rate >= PACKET_TEST_MIN_SUCCESS_RATE
        ),
    }


async def _speed_test(record: dict[str, Any], worker_url: str, token: str, semaphore: asyncio.Semaphore) -> dict[str, Any]:
    """Run 5 MB download speed test via Worker"""
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
        return {"ok": False, "error": f"curl_exit_{process.returncode}", "curl_code": process.returncode}

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
        "error": None if ok else "speed_below_threshold" if download_mb_s is not None else "no_speed_data",
    }


def _tag(uri: str) -> str:
    # 8 hex chars (32 bits) collides across a few thousand configs, and a
    # duplicate inbound tag makes sing-box refuse to start at all. Use a wider
    # digest; tags are cheap and uniqueness is required.
    return hashlib.sha256(uri.encode()).hexdigest()[:24].upper()


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
        except Exception as exc:
            # A single malformed URI must never abort the run: urlsplit raises
            # bare ValueError on things like unbracketed IPv6 literals.
            stats["unsupported"] += 1
            key = f"unparseable:{type(exc).__name__}"
            reasons[key] = reasons.get(key, 0) + 1
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
            "server_port": outbound["server_port"],
            "port": port,
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

    # Validate first: `check` reports the exact offending field, whereas a
    # failed `run` only exits 1 and hides the cause in a startup race.
    checked = await asyncio.create_subprocess_exec(
        SING_BOX, "check", "-c", str(config_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, check_err = await checked.communicate()
    if checked.returncode != 0:
        print("sing-box rejected the config:", file=sys.stderr)
        print(check_err.decode()[-2000:], file=sys.stderr)
        raise RuntimeError("sing-box check failed")

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


def limit_verification(
    config: dict[str, Any],
    records: list[dict[str, Any]],
    stats: dict[str, int],
    limit: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int]]:
    """Keep only the first `limit` already-parsed records, config stays consistent."""
    if limit <= 0 or len(records) <= limit:
        return config, records, stats

    kept_tags = {record["id"] for record in records[:limit]}
    limited = records[:limit]
    return {
        "log": config["log"],
        "inbounds": [
            inbound
            for inbound in config["inbounds"]
            if inbound["tag"].removeprefix("in-") in kept_tags
        ],
        "outbounds": [
            outbound
            for outbound in config["outbounds"]
            if outbound["tag"] == "direct" or outbound["tag"].removeprefix("proxy-") in kept_tags
        ],
        "route": {
            "rules": [
                rule
                for rule in config["route"]["rules"]
                if rule["inbound"][0].removeprefix("in-") in kept_tags
            ],
            "final": config["route"]["final"],
        },
    }, limited, {**stats, "input": len(limited)}


async def main() -> int:
    worker_url = os.environ.get("WORKER_URL", "").rstrip("/")
    worker_token = os.environ.get("WORKER_TOKEN", "")
    if not worker_url or not worker_token:
        print("Set WORKER_URL and WORKER_TOKEN", file=sys.stderr)
        return 2
    if not worker_url.startswith("https://"):
        print("WORKER_URL must be an HTTPS URL.", file=sys.stderr)
        return 2

    print(f"Fetching candidate configs from {len(SOURCE_URLS)} source(s)...")
    uris: list[str] = []
    seen: set[str] = set()
    failed_sources = 0
    for source_url in SOURCE_URLS:
        try:
            req = urllib.request.Request(source_url, headers={"accept": "text/plain"})
            body = urllib.request.urlopen(req, timeout=30).read().decode()
        except Exception as exc:
            failed_sources += 1
            print(f"Source failed ({source_url}): {exc}", file=sys.stderr)
            continue
        added = 0
        for line in body.splitlines():
            uri = line.strip()
            if uri and uri not in seen:
                seen.add(uri)
                uris.append(uri)
                added += 1
        print(f"  {added} new from {source_url}")
    if not uris:
        print("No configs from any source", file=sys.stderr)
        return 1
    if failed_sources:
        print(f"Warning: {failed_sources}/{len(SOURCE_URLS)} sources failed")
    print(f"Fetched {len(uris)} unique configs")

    config, records, stats = build_sing_box_config(uris)
    config, records, stats = limit_verification(config, records, stats, VERIFY_LIMIT)
    if not records:
        print("No supported configs", file=sys.stderr)
        return 1

    print(f"Starting sing-box with {len(records)} configs...")
    sing_box_proc = await _run_sing_box(config)

    try:
        # TCP is cheap (one CONNECT). HTTPS costs a full TLS handshake, so it
        # gets its own independent limit instead of sharing one with TCP.
        tcp_semaphore = asyncio.Semaphore(TCP_CONCURRENCY)
        https_semaphore = asyncio.Semaphore(HTTPS_CONCURRENCY)
        enriched = []

        # Tier 1: TCP sanity (through sing-box inbounds)
        print(f"Tier 1: TCP sanity check ({len(records)} configs)...")
        tier1_results = await asyncio.gather(*[
            _socks5_connect(r["port"], "1.1.1.1", 443, TCP_TIMEOUT) for r in records
        ])
        tier1_survivors = [r for r, (ok, _) in zip(records, tier1_results) if ok]
        print(f"Tier 1 passed: {len(tier1_survivors)}/{len(records)}")

        # Tier 2: Packet loss test (real SOCKS5 CONNECT + HTTPS through sing-box)
        print(f"Tier 2: Packet loss test ({len(tier1_survivors)} configs)...")
        tier2_results = await asyncio.gather(*[
            _packet_test(r, tcp_semaphore, https_semaphore) for r in tier1_survivors
        ])
        tier2_survivors = [r for r, res in zip(tier1_survivors, tier2_results) if res["passed"]]
        def _rate(result: dict[str, Any], key: str) -> float:
            return float((result.get(key) or {}).get("success_rate", 0.0))

        tcp_ok = sum(1 for res in tier2_results if _rate(res, "tcp") >= PACKET_TEST_MIN_SUCCESS_RATE)
        https_ok = sum(1 for res in tier2_results if _rate(res, "https") >= PACKET_TEST_MIN_SUCCESS_RATE)
        print(
            f"Tier 2 detail: TCP>=90%: {tcp_ok}/{len(tier1_survivors)}, "
            f"HTTPS>=90%: {https_ok}/{len(tier1_survivors)}, both: {len(tier2_survivors)}"
        )
        print(f"Tier 2 passed: {len(tier2_survivors)}/{len(tier1_survivors)}")

        # Tier 3: Speed test
        print(f"Tier 3: Speed test ({len(tier2_survivors)} configs)...")
        tier3_results = await asyncio.gather(*[
            _speed_test(r, worker_url, worker_token, tcp_semaphore) for r in tier2_survivors
        ])

        # Build enriched output from Tier 3 survivors only.
        for r, p2, p3 in zip(tier2_survivors, tier2_results, tier3_results):
            if not p3.get("speed_ok"):
                continue
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
                    "error": p3.get("error"),
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
                "tier3_attempted": len(tier2_survivors),
                "tier3_passed": sum(1 for c in enriched if c["tier3"]["passed"]),
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

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))