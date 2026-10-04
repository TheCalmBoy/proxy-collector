#!/usr/bin/env python3
"""
Phase 2 Probe: egress-IP stability verification
- Reads enriched-configs.json from Phase 1
- 1 initial round + 10 stability rounds at 30s spacing; each round asks the
  egress Worker /ip through the config (egress IP, country, ffraud
  classification) and probes Gemini from that same exit
- Samples are deduped per config into unique IPs; one IP -> stable,
  multi-IP -> dynamic-country / dynamic-elite (quality-gated)
- Rolls the previous health index forward for pool members it did not
  re-measure (merge_previous_health)
- Outputs: egress-health.json
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
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ENRICHED_PATH = Path(os.getenv("ENRICHED_PATH", "verify-output/enriched-configs.json"))
OUTPUT = Path(os.getenv("PROBE_OUTPUT", "probe-output"))
SING_BOX = os.getenv("SING_BOX", "sing-box")
PORT_BASE = 30000
MIN_DOWNLOAD_MB_S = 0.0005
UTLS_FINGERPRINTS = {
    "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android",
    "random", "randomized",
}
# Stability check config
# 20 IP requests in ~114 s (initial round + 19 re-checks at 6 s intervals),
# down from 11 requests in 300 s: the probe now runs off a 5-min heartbeat,
# so a long stability window was the dominant cost and barely added signal -
# an exit that rotates between 5-min probes is caught cross-run by
# `ip_changed` (compared against the previous published health index) instead.
STABILITY_INTERVALS = 19
STABILITY_INTERVAL_SECONDS = 6
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
        # A TLS *object*, not a boolean and not absent: sing-box rejects
        # "tls": true outright, and a vmess link that carries tls=tls but
        # no tls block connects in the clear.
        if str(vmess.get("tls") or "").lower() in ("tls", "reality"):
            tls: dict[str, Any] = {
                "server_name": str(vmess.get("sni") or vmess.get("host") or host)
            }
            if str(vmess.get("fp") or "").lower() == "chrome":
                tls["utls"] = {"enabled": True, "fingerprint": "chrome"}
            outbound["tls"] = tls
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
            "uuid": uuid,
        }
        # Emit only the credential field this scheme actually has. sing-box
        # rejects unknown keys outright, even when they are null:
        #   outbounds[16].password: json: unknown field "password"
        # so a VLESS outbound carrying "password": null aborts the whole
        # sing-box process and every config in the file is lost. Trojan uses
        # the same UUID as its password and takes no uuid field.
        if parsed.scheme == "trojan":
            del outbound["uuid"]
            outbound["password"] = uuid
        # sing-box 1.14.0 wants a TLS *object*, not a boolean. A bare
        # "tls": true is rejected outright when it decodes the config:
        #   outbounds[0].tls: json: cannot unmarshal bool into Go struct
        # field TrojanOutboundOptions.OutboundTLSOptions
        # so every trojan, vless and vmess probe config was being refused
        # before a single packet moved. The tests already expected the
        # object form; they were not in the CI test list, so nothing had
        # noticed the disagreement.
        server_name = _first(params, "sni", "host") or host
        if parsed.scheme == "vless":
            outbound["flow"] = _first(params, "flow") or ""
            security = _first(params, "security", "tls")
            if security in ("tls", "reality"):
                tls_options: dict[str, Any] = {"enabled": True, "server_name": server_name}
                # REALITY is not TLS with a flag on. It needs its own block
                # carrying the server's public key, or the handshake never
                # authenticates and the probe reports a dead proxy.
                if security == "reality":
                    reality: dict[str, Any] = {
                        "enabled": True,
                        "public_key": _first(params, "pbk", "public-key") or "",
                    }
                    short_id = _first(params, "sid", "short-id")
                    if short_id:
                        reality["short_id"] = short_id
                    tls_options["reality"] = reality
                # uTLS is what makes the handshake look like a browser.
                # A missing or unsupported fingerprint falls back to
                # chrome, because omitting utls entirely or sending a value
                # sing-box rejects both fail the handshake outright.
                fingerprint = (_first(params, "fp") or "").lower()
                if fingerprint not in UTLS_FINGERPRINTS:
                    fingerprint = "chrome"
                tls_options["utls"] = {"enabled": True, "fingerprint": fingerprint}
                outbound["tls"] = tls_options
        elif parsed.scheme == "trojan" and _first(params, "security", "tls") != "none":
            # Trojan is TLS by definition - the protocol runs inside TLS
            # and a trojan:// link carries no security= parameter saying
            # so. Treating a missing parameter as "no TLS" built a
            # plaintext outbound for every trojan link that only set sni,
            # which is how a bare trojan:// proxy never got probed at all.
            # An explicit security=none is the only way to ask for that.
            outbound["tls"] = {"server_name": server_name}
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
        # An object, never a boolean - sing-box refuses "tls": true.
        if parsed.scheme == "https":
            outbound["tls"] = {"server_name": host, "enabled": True}
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



def _tag(uri: str) -> str:
    # 12 hex to match main.py's stable_id (fragment tails), so feed-less
    # configs key their health records the same way the rest do.
    return hashlib.sha256(uri.encode()).hexdigest()[:12].upper()


# The published feed tags each config with an id the upstream source already
# put in the URI fragment: "ss://...#HK <flag> | @provider | 0DFD85". The
# subscription worker keys its health lookup on exactly that trailing token,
# while egress-health.json was keyed on a sha256 of the whole URI, so no id
# ever matched and the worker filtered out every proxy as unverified. Reuse the
# upstream id when it is present, and fall back to the hash only for configs
# that carry no fragment id.
_TRAILING_ID_RE = re.compile(r"^(?:[A-F0-9]{6,12})$")


def _feed_id(uri: str) -> str | None:
    """Return the id already present in the URI fragment, if any."""
    if "#" not in uri:
        return None
    tail = uri.split("#", 1)[1].split("|")[-1].strip()
    return tail.upper() if _TRAILING_ID_RE.match(tail) else None


def _record_id(uri: str) -> str:
    return _feed_id(uri) or _tag(uri)


def _previous_last_ips(previous: Any) -> dict[str, str]:
    """rid -> last observed IP in the previously-published health index.

    New rows carry ``last_ip`` directly; older rows fall back to the tail of
    ``unique_ips`` (the per-round observation list). Used for cross-run IP
    change detection. Absent/malformed -> empty mapping, not an error.
    """
    out: dict[str, str] = {}
    if not isinstance(previous, dict):
        return out
    configs = previous.get("configs")
    if not isinstance(configs, dict):
        return out
    for rid, row in configs.items():
        if not isinstance(row, dict):
            continue
        ip = row.get("last_ip")
        if not isinstance(ip, str) or not ip:
            ips = row.get("unique_ips")
            ip = ips[-1] if isinstance(ips, list) and ips else None
        if isinstance(ip, str) and ip:
            out[rid] = ip
    return out


def apply_ip_change_flags(
    health: dict[str, dict[str, Any]],
    previous_last_ips: dict[str, str],
) -> int:
    """Flag rows whose egress IP moved since the previous published run.

    The probe window is ~2 min; an exit that rotates slower than that shows
    up only HERE, run-to-run, so this is the only place a 5-min-cadence
    pipeline can still catch the slow rotators. ``ip_changed`` is None when
    there is nothing to compare (first-ever measurement or a row with no
    previous IP) - "no evidence of a change" is not "proved stable".
    Returns the number of rows flagged changed.
    """
    changed = 0
    for rid, row in health.items():
        if not isinstance(row, dict):
            continue
        last = row.get("last_ip")
        prev = previous_last_ips.get(rid)
        if isinstance(last, str) and last and isinstance(prev, str) and prev:
            if prev != last:
                row["ip_changed"] = True
                row["previous_ip"] = prev
                changed += 1
            else:
                row["ip_changed"] = False
        else:
            row["ip_changed"] = None
    return changed


# Every check reports the egress address, so the family can be read straight
# off it instead of adding another probe round-trip: an IPv4 literal is dotted
# quad, an IPv6 literal is colon-separated (Cloudflare's trace returns v6 in
# its compressed form).
_IPV6_RE = re.compile(r"^[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+$")


def ip_family(value: Any) -> str:
    """Classify an address as 'ipv4', 'ipv6' or 'unknown'."""
    if not isinstance(value, str):
        return "unknown"
    text = value.strip()
    if not text:
        return "unknown"
    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", text):
        return "ipv4"
    # An IPv4-mapped address such as ::ffff:1.2.3.4 is still an IPv4 exit as
    # far as a client is concerned; report it as such.
    mapped = re.match(r"^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$", text, flags=re.IGNORECASE)
    if mapped:
        return "ipv4"
    if _IPV6_RE.match(text):
        return "ipv6"
    return "unknown"


async def _listener_alive(port: int, timeout: float = 5.0) -> bool:
    """True when something accepts a TCP connection on the SOCKS listener.

    sing-box can be alive as a process while its listeners are already closed,
    which is what a mid-session crash looks like from the outside: probes stop
    with curl exit 7 and every remaining proxy is scored as dead. Checking the
    socket catches that before the results are believed.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port), timeout=timeout
        )
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except (OSError, asyncio.TimeoutError):
        pass
    return True


def families_of(ips: list[Any]) -> str:
    """Collapse the observed addresses into a single label."""
    seen = {ip_family(ip) for ip in ips if ip_family(ip) != "unknown"}
    if not seen:
        return "unknown"
    if seen == {"ipv4"}:
        return "ipv4"
    if seen == {"ipv6"}:
        return "ipv6"
    return "dual"


def _ephemeral_bounds() -> tuple[int, int]:
    """Read the kernel's actual ephemeral port range, not a guess."""
    try:
        lo, hi = Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()
        return int(lo), int(hi)
    except (OSError, ValueError):
        return 32768, 60999


def _probe_range_free(base: int, count: int) -> bool:
    """True when every port in base..base+count-1 can be bound right now.

    The probe sockets are closed before sing-box starts, so this is only
    "likely free": the kernel can hand one of these ports to an outbound
    connection in the window between this check and the real bind.
    """
    held: list[socket.socket] = []
    try:
        for port in range(base, base + count):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            held.append(s)
            s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        for s in held:
            s.close()


def _pick_inbound_base(count: int) -> int:
    """Pick a listen-port base clear of the ephemeral range and of anything
    already listening on this host.

    The hardcoded `PORT_BASE + len(records)` this replaces allocated 285
    listeners starting at 30000 while the kernel hands out ephemeral ports
    from 32768. Every listener that lost that race reported curl exit 7 and
    the proxy was recorded as dead, which is why the published health data
    held only the first handful of configs by port order. The scheme split
    that looked like a protocol bug was this, and it moved with the file
    order, not the protocols.
    """
    lo, hi = _ephemeral_bounds()
    candidates = [
        int(os.getenv("PROBE_INBOUND_PORT_BASE", "15000")),
        20000, 25000, 12000, 8000, 6000, 5000, 4000,
    ]
    for base in candidates:
        if base + count > lo and base < hi:
            continue  # overlaps the ephemeral range
        if _probe_range_free(base, count):
            return base
    return int(os.getenv("PROBE_INBOUND_PORT_BASE", "15000"))


def build_sing_box_config(uris: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int]]:
    inbounds: list[dict[str, Any]] = []
    outbounds: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    stats = {"input": len(uris), "supported": 0, "unsupported": 0}
    reasons: dict[str, int] = {}

    # Resolve the base BEFORE allocating any inbound, so every listener is
    # contiguous and outside the ephemeral range.
    base_port = _pick_inbound_base(len(uris))

    for uri in uris:
        try:
            outbound = parse_proxy_uri(uri)
        except UnsupportedConfig as exc:
            stats["unsupported"] += 1
            reasons[str(exc)] = reasons.get(str(exc), 0) + 1
            continue
        identifier = _record_id(uri)
        inbound_tag = f"in-{identifier}"
        outbound_tag = f"proxy-{identifier}"
        port = base_port + len(records)
        inbound = {"type": "socks", "tag": inbound_tag, "listen": "127.0.0.1", "listen_port": port}
        outbound["tag"] = outbound_tag
        inbounds.append(inbound)
        outbounds.append(outbound)
        rules.append({"inbound": [inbound_tag], "action": "route", "outbound": outbound_tag})
        records.append({
            "id": identifier,
            "port": port,
            "scheme": outbound["type"],
            # The classification stage writes scheme/server/server_port into
            # egress-health.json, and it was reading these off the record.
            # They were never stored, so the run raised KeyError: 'server'
            # as soon as a config survived long enough to be classified.
            "server": outbound.get("server"),
            "server_port": outbound.get("server_port"),
        })
        stats["supported"] += 1

    config = {
        "log": {"level": "error", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds + [{"type": "direct", "tag": "direct"}],
        "route": {"rules": rules, "final": "direct"},
    }
    return config, records, {**stats, **{f"skip_{key}": value for key, value in sorted(reasons.items())}}


async def _run_curl(config_lines: list[str]) -> tuple[int, str]:
    process = await asyncio.create_subprocess_exec(
        "curl", "--config", "-",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await process.communicate(("\n".join(config_lines) + "\n").encode())
    return process.returncode, stdout.decode("utf-8", "replace")


async def _cloudflare_trace(proxy_port: int) -> dict[str, Any]:
    """Get IP info from cloudflare.com/cdn-cgi/trace via proxy.

    Exit 7 is "could not connect" and was being reported as a dead proxy.
    On a runner saturated with concurrent sing-box listeners it is really
    local exhaustion: the listener was alive but too busy to accept, or the
    process was out of descriptors. The scheme split in the published data
    (100% of shadowsocks, 0% of vless/vmess/trojan) was this race, not the
    protocols, so a refused connection is retried on its own with nothing
    else in flight before it is believed.
    """
    config_lines = [
        f'proxy = "socks5h://127.0.0.1:{proxy_port}"',
        f'url = "{CLOUDFLARE_TRACE_URL}"',
        "silent",
        "show-error",
        "fail",
        "connect-timeout = 5",
        "max-time = 10",
    ]
    returncode, stdout = await _run_curl(config_lines)
    if returncode != 0:
        # Only a refused connection is ambiguous. Every other exit is the
        # proxy's own answer (35/97 handshake, 56 receive, 28 timeout).
        if returncode == 7:
            await asyncio.sleep(0.5 + (proxy_port % 7) * 0.3)
            returncode, stdout = await _run_curl(config_lines)
        if returncode != 0:
            return {"ok": False, "error": f"curl_exit_{returncode}"}

    try:
        text = stdout.strip()
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


# Gemini's web app gates on IP reputation, not on whether the proxy works. A
# datacenter exit that answers /ip perfectly can still be served a CAPTCHA or a
# 403 by gemini.google.com, which makes the node useless for anything the user
# actually wants it for. s3diag.py already probes this for diagnostics; this is
# the same check in the main pipeline so the answer reaches egress-health.json
# and the worker's ranking.
GEMINI_URL = os.getenv("GEMINI_PROBE_URL", "https://gemini.google.com/")


async def _gemini_probe(proxy_port: int) -> dict[str, Any]:
    """Ask Gemini for a page through the proxy and report the raw verdict.

    Returns ``ok`` only when Gemini actually served content (HTTP 2xx/3xx). A
    403 is the interesting answer, not an error to swallow: it means the egress
    IP is flagged. A curl timeout or a 5xx means we learned nothing and is
    reported as ``ok: False`` with a distinct reason, so the worker can tell
    "flagged" apart from "we did not manage to check".
    """
    config_lines = [
        f'proxy = "socks5h://127.0.0.1:{proxy_port}"',
        f'url = "{GEMINI_URL}"',
        "silent",
        "show-error",
        "fail",
        "connect-timeout = 5",
        "max-time = 15",
    ]
    process = await asyncio.create_subprocess_exec(
        "curl", "--config", "-",
        "--write-out", "\\n%{http_code}",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await process.communicate(("\n".join(config_lines) + "\n").encode())

    if process.returncode != 0:
        return {"ok": False, "error": f"curl_exit_{process.returncode}"}

    try:
        text = stdout.decode(errors="replace").strip()
        body, _, code = text.rpartition("\n")
        status = int(code.strip()) if code.strip().isdigit() else 0
    except Exception:
        return {"ok": False, "error": "parse_failed"}

    if status == 0:
        return {"ok": False, "error": "no_status"}
    # 2xx and 3xx mean Gemini served us. 401/403/429 are the reputation gates:
    # the exit is reachable but flagged, which is exactly what we want to know.
    return {
        "ok": 200 <= status < 400,
        "flagged": status in (401, 403, 429),
        "http_status": status,
    }


async def _speed_test(record: dict[str, Any], worker_url: str, token: str, semaphore: asyncio.Semaphore) -> dict[str, Any]:
    """Ask the Worker which IP this config egresses from.

    Phase 1 already measures real throughput (Stage 3's 5 MB transfer), and
    a config only reaches Phase 2 if it passed. This is deliberately a tiny
    /ip round trip: re-downloading megabytes per config per round is what
    exhausted the proxies, not a property of the configs. The curl metric on
    that small body yields download_mb_s -- a first-byte/throughput figure on
    a few-hundred-byte response, NOT a speed verdict. Phase 1's Stage 3 is
    the only real throughput measurement; the subscription worker labels and
    ranks on Stage 3 and does not read the health index's download_mb_s.
    """
    config_lines = [
        f'proxy = "socks5h://127.0.0.1:{record["port"]}"',
        f'url = "{worker_url}/ip"',
        f'header = "Authorization: Bearer {token}"',
        "silent",
        "show-error",
        "fail",
        "connect-timeout = 10",
        "max-time = 20",
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

    if process.returncode != 0:
        return {"ok": False, "error": f"curl_exit_{process.returncode}"}

    # curl's write-out appends the metrics marker to the same stdout as the
    # response body, so the body has to be split off before parsing. Parsing
    # all of stdout fails on every request that actually succeeded, which is
    # what produced "invalid_worker_response=84" while 84 configs were fine.
    body_bytes, _, metric = stdout.partition(b"\n__SPEED_METRICS__")
    if not body_bytes.strip():
        return {"ok": False, "error": "empty_worker_response"}
    try:
        result = json.loads(body_bytes.decode().strip())
    except Exception:
        return {"ok": False, "error": "invalid_worker_response"}
    latency_ms = None
    download_mb_s = None
    if metric:
        try:
            downloaded_size, starttransfer, total = map(float, metric.decode().strip().split())
            latency_ms = round(starttransfer * 1000, 1)
            if total > starttransfer:
                download_mb_s = downloaded_size / 1_000_000 / (total - starttransfer)
        except (UnicodeDecodeError, ValueError):
            pass

    # Phase 2 succeeds on learning the egress IP, not on hitting a speed
    # threshold. Gating on throughput here meant a healthy proxy that answered
    # correctly was recorded as a failure whenever the small response came back
    # too quickly to satisfy MIN_DOWNLOAD_MB_S.
    ok = bool(result.get("ip"))

    # Ask Gemini from the same exit, on the same SOCKS port we just used. This
    # is one extra request per config per round, and it is the only place we
    # learn whether Google will actually serve this IP. A node we never asked
    # gets None, never True.
    gemini: dict[str, Any] = {}
    if ok:
        try:
            gemini = await _gemini_probe(record["port"])
        except Exception as exc:  # a failed reputation check must not drop a
            # working config; it just leaves the flag unknown.
            gemini = {"ok": None, "error": f"probe_exception_{type(exc).__name__}"}

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
        # ok above means "we learned the egress IP", which says nothing about
        # throughput. Reusing it here published sub-floor numbers -- 0.204
        # MB/s against a 1.0 MB/s Stage 3 floor -- under a key named speed_ok,
        # and the subscription worker reads this document and prints
        # download_mb_s as if it were a verified speed. So a config that
        # answered but crawled got labelled with its own crawl rate.
        # speed_ok now answers only its own question: did this record meet the
        # minimum download rate this stage was asked to measure? It is a
        # separate verdict, not a copy of the egress outcome.
        "speed_ok": (
            download_mb_s is not None
            and download_mb_s >= MIN_DOWNLOAD_MB_S
        ),
        # Gemini reputation, probed through this config's own exit. None means
        # we never managed to check (the probe timed out or the run was cut
        # short) and must stay None: the worker treats a missing flag as
        # "unknown", not as "clean", so an unchecked node is never credited.
        "gemini": gemini.get("ok") if isinstance(gemini, dict) else None,
        "gemini_flagged": gemini.get("flagged") if isinstance(gemini, dict) else None,
        "gemini_http_status": gemini.get("http_status") if isinstance(gemini, dict) else None,
    }


async def _run_stability_check(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run one stability check using cloudflare trace"""
    semaphore = asyncio.Semaphore(max(1, int(os.getenv("PROBE_CONCURRENCY", "25"))))

    async def check_one(record):
        async with semaphore:
            return await _cloudflare_trace(record["port"])

    return await asyncio.gather(*[check_one(r) for r in records])


def _gemini_verdict(history: list[bool | None]) -> dict[str, Any]:
    """Roll per-round Gemini verdicts into one honest answer.

    Three outcomes, kept distinct on purpose:
      clean    - at least one round served us, and no round was flagged
      flagged  - any round came back 401/403/429; the IP is on a reputation list
      unknown  - we never got an answer we can act on

    A config that fails the check on one round and passes on another is
    "flagged", not "clean": a user who hits the 403 has still lost the node, and
    averaging the two would hide exactly the case worth knowing about.
    """
    known = [v for v in history if v is not None]
    if not known:
        return {"status": "unknown", "clean": None, "flagged": None, "rounds": 0}
    flagged = [v for v in known if v is False]
    if flagged:
        return {"status": "flagged", "clean": False, "flagged": True, "rounds": len(known)}
    return {"status": "clean", "clean": True, "flagged": False, "rounds": len(known)}


def _classify_dynamic(ip_history: list[str], speed_history: list[float | None], fraud_scores: list[int | None], countries: list[str | None], hosting_history: list[bool | None] | None = None) -> dict[str, Any]:
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

    # Residential-vs-datacenter, from the per-check "hosting" flag. The worker
    # already collects it (see _build_result) but it was never written into the
    # classification, so the published index carried no connection_type at all
    # and every consumer fell back to a bare risk word.
    hosting_flags = [h for h in (hosting_history or []) if h is not None]
    connection_type = None
    if hosting_flags:
        connection_type = "datacenter" if any(hosting_flags) else "residential"

    classification = {
        "unique_ips": unique_ips,
        "ip_count": len(unique_ips),
        "countries": unique_countries,
        "country": country,
        "same_country": same_country,
        "avg_speed_mb_s": round(avg_speed, 3),
        "max_speed_mb_s": round(max_speed, 3),
        "min_fraud_score": min_fraud,
        "connection_type": connection_type,
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


# How long an endpoint stays on the rejected list before it is re-tested.
# A reject is not a permanent verdict: the source's egress behaviour can
# change, and re-measuring every 48 h is cheap insurance against a stale
# reject pinning a good endpoint out of the pool forever. Below that the
# rolling union keeps it out of Stage 1-3 so the pipeline stops spending
# 8+ min per cycle on endpoints it already knows will rotate.
REJECTED_TTL_HOURS = float(os.getenv("PROBE_REJECTED_TTL_HOURS", "48"))


def _load_previous_rejected(path: str | None) -> dict[str, dict[str, Any]]:
    """Read the previous rejected-endpoints.json; None on any failure.

    Missing/malformed is a no-op: the denylist is an optimisation, so a
    corrupt or absent input must never block a probe. Returns a
    (server, port) -> entry mapping, keyed the same way the writer does,
    so a merge can compare entries by endpoint.
    """
    if not path:
        return {}
    try:
        doc = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    entries = doc.get("endpoints") if isinstance(doc, dict) else doc
    if not isinstance(entries, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for e in entries:
        if not isinstance(e, dict):
            continue
        server = e.get("server")
        port = e.get("server_port")
        if not isinstance(server, str):
            continue
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        out[f"{server}:{port}"] = e
    return out


def merge_rejected(
    previous: dict[str, dict[str, Any]],
    current: dict[str, dict[str, Any]],
    ttl_hours: float = REJECTED_TTL_HOURS,
) -> dict[str, dict[str, Any]]:
    """Union of the previous and current rejects; a current reject always
    wins (its timestamp is fresh) and stale entries drop off.

    Mirrors the health rolling union: a config that got re-measured this
    run and is no longer rejected drops out of the list, one that was
    rejected previously but not this run is kept while its TTL still
    holds, and any entry past the TTL is dropped so the endpoint gets
    re-tested. The union is what stops the pipeline from oscillating -
    an endpoint that is skipped out of the pool would otherwise never
    be measured again, so the memory of its reject would evaporate the
    next cycle and it would be re-tested despite its TTL.
    """
    merged = dict(previous)
    merged.update(current)
    now = datetime.now(timezone.utc)
    cutoff = timedelta(hours=ttl_hours)
    out: dict[str, dict[str, Any]] = {}
    for key, entry in merged.items():
        stamp = entry.get("rejected_at")
        kept = True
        if isinstance(stamp, str):
            try:
                ts = datetime.fromisoformat(stamp)
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                kept = (now - ts) <= cutoff
            except ValueError:
                kept = True  # malformed stamp: trust the entry rather than drop it
        if kept:
            out[key] = entry
    return out


def merge_previous_health(
    previous: dict[str, Any] | None,
    measured: dict[str, Any],
    pool_ids: set[str],
    max_age_hours: int = 24,
) -> tuple[dict[str, Any], int]:
    """Rolling union: carry previously-measured rows forward into this run's
    health index so one thin or skipped probe cannot freeze the index.

    The probe only measures the pool that happens to exist at its own cron
    moment, and the pool churns every hour. Overwriting the index with
    this run's survivors alone means the index permanently trails the feed,
    and the worker's (server, port) join drops every config the index missed.
    Carrying forward closes that gap: a config that passed last run and is
    still in the pool keeps its row even when this run's measurement did not
    return an egress IP.

    Rules (the union must never make things worse):
      - only rows whose id is still in THIS run's pool are carried (a config
        that left the pool is not in the feed either, so dropping its row is
        correct, not loss);
      - a row this run actually measured always wins - fresh beats stale;
      - rows older than max_age_hours are dropped: beyond that the exit may
        have moved and the row would claim a country/speed that no longer
        holds (the worker's own document gate is also 24h);
      - a missing or malformed previous index is a no-op, not an error - the
        probe must still publish this run's measurements.
    """
    merged = dict(measured)
    if not isinstance(previous, dict):
        return merged, 0
    configs = previous.get("configs")
    if not isinstance(configs, dict):
        return merged, 0
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
    carried = 0
    for rid, row in configs.items():
        if rid in merged or rid not in pool_ids:
            continue
        if not isinstance(row, dict):
            continue
        updated_raw = row.get("updated_at")
        if not isinstance(updated_raw, str):
            continue
        try:
            updated = datetime.fromisoformat(updated_raw)
        except ValueError:
            continue
        if updated.tzinfo is None:
            updated = updated.replace(tzinfo=timezone.utc)
        if updated < cutoff:
            continue
        merged[rid] = row
        carried += 1
    return merged, carried


def _record_reject(
    rejected: dict[str, dict[str, Any]],
    records_by_id: dict[str, dict[str, Any]],
    rid: str,
    reason: str,
) -> None:
    """Add a (server, port) to this run's rejected set, deduped by endpoint.

    A source endpoint can appear under several credentials in the same pool,
    so several rids can map to one endpoint; the first reason wins (it is
    cosmetic - verify.py matches on the endpoint key, not the reason) and the
    timestamp is simply the current run. An endpoint that cannot be resolved
    to a concrete server:port is not recorded - a denylist entry that cannot
    be matched is dead weight.
    """
    record = records_by_id.get(rid)
    if not record:
        return
    server = record.get("server")
    port = record.get("server_port")
    if not isinstance(server, str) or not server:
        return
    try:
        port = int(port)
    except (TypeError, ValueError):
        return
    key = f"{server}:{port}"
    entry = rejected.get(key)
    if entry is None:
        rejected[key] = {
            "server": server,
            "server_port": port,
            "scheme": record.get("scheme"),
            "reason": reason,
            "rejected_at": datetime.now(timezone.utc).isoformat(),
        }
    else:
        # Same endpoint rejected under more than one credential this run:
        # refresh the stamp so its TTL tracks the most recent observation.
        entry["rejected_at"] = datetime.now(timezone.utc).isoformat()


def _print_error_breakdown(results: list[dict[str, Any]], label: str) -> None:
    """Log what the failures actually were, so a bad run names its own cause."""
    counts: dict[str, int] = {}
    for r in results:
        if r.get("ok"):
            continue
        counts[str(r.get("error", "unknown"))] = counts.get(str(r.get("error", "unknown")), 0) + 1
    if not counts:
        return
    top = ", ".join(f"{k}={v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1]))
    print(f"{label} failures: {top}")


async def main() -> int:
    # Read these here, not at module import. They are step-level env vars in
    # the workflow, so a module-level read happens before the step's env is
    # applied and yields "", which curl reports as "URL rejected: No host
    # present" for every config. verify.py reads them in main() for the same
    # reason.
    worker_url = os.environ.get("WORKER_URL", "").rstrip("/")
    worker_token = os.environ.get("WORKER_TOKEN", "")
    if not worker_url or not worker_token:
        print("Set WORKER_URL and WORKER_TOKEN", file=sys.stderr)
        return 2
    if not worker_url.startswith("https://"):
        print("WORKER_URL must be an HTTPS URL.", file=sys.stderr)
        return 2

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

    # Phase 2 moves the real payload, so it stays at the conservative value
    # even when PROBE_CONCURRENCY is unset. The 750 this used to default to
    # is what exhausted the runner and turned working proxies into
    # curl_exit_7 rows.
    semaphore = asyncio.Semaphore(max(1, int(os.getenv("PROBE_CONCURRENCY", "25"))))

    try:
        await asyncio.sleep(5)
        if core.poll() is not None:
            print("sing-box exited during startup; see artifact log.", file=sys.stderr)
            return 1

        # sing-box is polled once at startup and then left to run for the
        # whole session, but it died partway through and every later probe
        # came back curl exit 7 (connection refused) because the SOCKS
        # listeners were gone. Restart it if that happens, and say so.
        async def _ensure_core():
            nonlocal core
            if core.poll() is None:
                return
            print(f"sing-box exited ({core.returncode}); restarting it.", file=sys.stderr)
            core = subprocess.Popen(
                [SING_BOX, "run", "-c", str(config_path)],
                stdout=open("/tmp/probe-egress-sing-box.log", "ab"),
                stderr=subprocess.STDOUT,
            )
            await asyncio.sleep(5)
            if core.poll() is not None:
                print("sing-box failed to restart; aborting.", file=sys.stderr)
                raise RuntimeError("sing-box will not stay up")
            # A core can be running while its listeners are already gone, which
            # is what a crash mid-session looks like: every later probe returns
            # curl exit 7. Confirm a listener answers before resuming, so the
            # run does not silently score every remaining proxy as dead.
            # Check a port this run actually allocated, not the old hardcoded
            # 30000, which is no longer where any listener lives.
            probe_port = records[0]["port"] if records else PORT_BASE
            if not await _listener_alive(probe_port):
                print(f"restarted sing-box is not answering on {probe_port}; aborting.", file=sys.stderr)
                raise RuntimeError("sing-box restarted without live listeners")

        # Initial speed test via Worker
        # Timing anchors: the step has taken ~5m40s with no per-phase
        # timestamps, and the process stdout is block-buffered (no -u), so
        # without these the log dumps everything at step end and the
        # bottleneck is invisible. Each phase prints its own elapsed
        # seconds as it finishes.
        phase_started = time.monotonic()
        print(f"[t0] probe step started ({len(records)} configs)", flush=True)
        print("Running initial speed test via Worker...", flush=True)
        first = await asyncio.gather(*(_speed_test(r, worker_url, worker_token, semaphore) for r in records))
        ok = sum(1 for r in first if r.get("ok"))
        print(f"Initial: {ok}/{len(records)} returned an IP", flush=True)
        print(f"[t1] initial round done in {time.monotonic() - phase_started:.0f}s", flush=True)
        # Without this the run only ever reports "0/N returned an IP", which
        # says nothing about why. Print the dominant failure so the cause is
        # visible in the log instead of requiring a local reproduction.
        _print_error_breakdown(first, "Initial")

        # Stability checks via cloudflare trace
        ip_history = {r["id"]: [] for r in records}
        speed_history = {r["id"]: [] for r in records}
        fraud_history = {r["id"]: [] for r in records}
        country_history = {r["id"]: [] for r in records}
        hosting_history = {r["id"]: [] for r in records}
        # Gemini verdicts, same shape as the other per-round histories. A None
        # entry means the probe did not answer this round; it is not a pass.
        gemini_history = {r["id"]: [] for r in records}

        # Include initial results
        for r in first:
            if r.get("ok"):
                rid = r["id"]
                ip_history[rid].append(r.get("ip"))
                speed_history[rid].append(r.get("download_mb_s"))
                fraud_history[rid].append(r.get("fraud_score"))
                country_history[rid].append(r.get("country"))
                hosting_history[rid].append(r.get("hosting"))
                gemini_history[rid].append(r.get("gemini"))

        print(f"Running {STABILITY_INTERVALS} stability checks at {STABILITY_INTERVAL_SECONDS}s intervals...")
        # Only configs that produced an IP are worth re-checking: the others
        # never established a working path, and polling all 174 ten times is
        # 1740 requests through proxies that are already failing.
        # live holds (record, result) pairs: the result has the IP but no
        # "port", and the record has the port but no IP, so either alone
        # raises KeyError.
        live = [(r, res) for r, res in zip(records, first) if res.get("ok")]
        print(f"Stability checks on {len(live)}/{len(records)} configs that returned an IP")
        if not live:
            print("No config returned an IP in the initial round; skipping stability checks.")
            return 1
        round_times = []
        for i in range(STABILITY_INTERVALS):
            round_started = time.monotonic()
            await asyncio.sleep(STABILITY_INTERVAL_SECONDS)
            print(f"Stability check {i+1}/{STABILITY_INTERVALS}...")
            await _ensure_core()
            results = await _run_stability_check([r for r, _ in live])
            round_elapsed = time.monotonic() - round_started
            round_times.append(round_elapsed)
            # Per-round wall time: each round is a full fan-out of Cloudflare
            # trace requests through every live proxy, so its cost is dominated
            # by that work, not the interval sleep. Printing it per round (with
            # -u flushing the step live) makes a slow round visible the moment
            # it happens instead of only in the dumped-at-end log.
            print(f"[round {i+1}] {round_elapsed:.1f}s "
                  f"({len(live)} proxies, {STABILITY_INTERVAL_SECONDS}s wait)",
                  flush=True)
            for j, r in enumerate(results):
                rid = live[j][0]["id"]
                if r.get("ok"):
                    ip_history[rid].append(r.get("ip"))
                    country_history[rid].append(r.get("country"))
                    # No speed/fraud from trace, so reuse last known
                    if speed_history[rid]:
                        speed_history[rid].append(speed_history[rid][-1])
                    if fraud_history[rid]:
                        fraud_history[rid].append(fraud_history[rid][-1])
                    if hosting_history[rid]:
                        hosting_history[rid].append(hosting_history[rid][-1])
        if round_times:
            avg = sum(round_times) / len(round_times)
            print(f"[rounds] {len(round_times)} rounds, avg {avg:.1f}s, "
                  f"min {min(round_times):.1f}s, max {max(round_times):.1f}s, "
                  f"total {sum(round_times):.0f}s", flush=True)

        print(f"[t2] stability loop done in {time.monotonic() - phase_started:.0f}s total", flush=True)

        # Final speed test via Worker
        print("Running final speed test via Worker...", flush=True)
        await _ensure_core()
        final = await asyncio.gather(*(_speed_test(r, worker_url, worker_token, semaphore) for r, _ in live))
        ok = sum(1 for r in final if r.get("ok"))
        print(f"Final: {ok}/{len(live)} returned an IP", flush=True)
        print(f"[t3] final round done in {time.monotonic() - phase_started:.0f}s total", flush=True)
        _print_error_breakdown(final, "Final")

        for r in final:
            if r.get("ok"):
                rid = r["id"]
                ip_history[rid].append(r.get("ip"))
                speed_history[rid].append(r.get("download_mb_s"))
                fraud_history[rid].append(r.get("fraud_score"))
                country_history[rid].append(r.get("country"))
                hosting_history[rid].append(r.get("hosting"))
                gemini_history[rid].append(r.get("gemini"))

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
    records_by_id = {r["id"]: r for r in records}
    rejected: dict[str, dict[str, Any]] = {}
    for rid in sorted(ip_history.keys()):
        ips = ip_history[rid]
        if not ips:
            # No egress IP in any round. This is NOT recorded on the denylist:
            # a "no IP" can be the proxy being dead OR this runner being
            # saturated (descriptor/port race) and the config never actually
            # got a chance. Only a *confirmed* verdict (below) is a safe deny.
            continue

        classification = _classify_dynamic(
            ip_history[rid],
            speed_history[rid],
            fraud_history[rid],
            country_history[rid],
            hosting_history[rid],
        )

        # Only include non-rejected configs. A reject here is a confirmed
        # property of the endpoint (it returned IPs, and they rotated across
        # countries or it carried a high fraud score across the whole
        # 5-minute stability window) - not a runner artifact. Those endpoints
        # pass Phase 1's Stage 3 and get published into the pool only to be
        # rejected again every cycle, so record the endpoint and let Phase 1
        # stop spending Stages 1-3 on it until its TTL expires.
        if classification["subgroup"] == "rejected":
            _record_reject(rejected, records_by_id, rid,
                           f"egress-{classification['type']}")
            continue

        # Calculate final metrics
        valid_speeds = [s for s in speed_history[rid] if s is not None]
        avg_speed = sum(valid_speeds) / len(valid_speeds) if valid_speeds else 0

        # Find the record
        record = next((r for r in records if r["id"] == rid), None)
        if not record:
            continue

        # `rid` (the dict key) is the config's stable name: sha256(uri)-derived,
        # so the same config resolves to the same key on every run - the
        # deterministic, non-random "naming system" used to track a config's
        # egress IP across the 5-min probes (see `ip_changed` below).
        health[rid] = {
            "scheme": record["scheme"],
            "server": record["server"],
            "server_port": record.get("server_port"),
            "classification": classification,
            # download_mb_s is the AVERAGE of the probe's per-round tiny-/ip
            # throughput figure -- a latency-ish number, NOT a verified speed.
            # The subscription worker does NOT read it: it labels and ranks on
            # Phase 1's Stage 3 (stages.download.speed_mb_s) and gates on
            # membership. It is kept here only for a human opening the health
            # index to see "roughly how fast did the IP check feel".
            "download_mb_s": round(avg_speed, 3),
            # Gemini reputation, aggregated over every round this config was
            # probed. status is "clean" | "flagged" | "unknown" -- three
            # distinct answers, because "we could not check" must never be
            # rendered as "clean" downstream.
            "gemini": _gemini_verdict(gemini_history.get(rid, [])),
            "ip_count": len(ips),
            # Every IP observed this run, round by round: the first entry is
            # the initial round, the rest are the stability re-checks.
            # `last_ip` is the most recent observation, the value a cross-run
            # ip_changed flag compares against.
            "ip_history": list(ips),
            "last_ip": ips[-1],
            "unique_ips": ips,
            # Which address family this exit actually presents. A v6-only exit
            # behaves differently from a v4 one behind a dual-stack client, and
            # without this the two are indistinguishable in the index.
            "ip_family": families_of(ips),
            "primary_country": classification.get("country"),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

    # Rolling union: fold the previously-published index back in for any pool
    # member this run did not (re-)measure, so a thin or flaky probe cannot
    # freeze the health index. Loaded from PREVIOUS_HEALTH when the workflow
    # fetches it; absent or malformed is a no-op, and this run's measurements
    # always win on conflict.
    pool_ids = {r["id"] for r in records}
    previous = None
    prev_path = os.getenv("PREVIOUS_HEALTH")
    if prev_path:
        try:
            previous = json.loads(Path(prev_path).read_text())
        except (OSError, json.JSONDecodeError):
            previous = None
    if previous:
        health, carried = merge_previous_health(previous, health, pool_ids)
        print(f"Carried {carried} previously-measured rows still in the pool")

    # Cross-run IP tracking: flag rows whose egress IP moved since the
    # previous published index. The in-run stability window is only ~2 min,
    # so an exit that rotates slower than that (between two 5-min probes) is
    # visible ONLY here, run-to-run - this is the mechanism that keeps the
    # "one bad IP and fail" rule honest at the new cadence. Runs without a
    # previous index (first probe, or fetch failure) leave ip_changed as None
    # rather than claiming "no change".
    changed = apply_ip_change_flags(health, _previous_last_ips(previous))
    if changed:
        print(f"IP changed since last run: {changed} configs")

    OUTPUT.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT / "egress-health.json"
    output_path.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "configs": health,
    }, indent=2))

    # Rolling union of the rejected-endpoint denylist: fold the previous
    # published list back in (loaded from PREVIOUS_REJECTED when the workflow
    # fetches it) so a rejected endpoint stays out of Phase 1's Stage 1-3
    # until its TTL expires, even on a run where it was not re-measured. An
    # endpoint that was re-measured and is no longer rejected drops off
    # automatically because it is absent from this run's `rejected` set and its
    # carried entry ages out. Absent/malformed previous is a no-op.
    prev_rejected_path = os.getenv("PREVIOUS_REJECTED")
    prev_rejected = _load_previous_rejected(prev_rejected_path)
    merged_rejected = merge_rejected(prev_rejected, rejected)
    rejected_path = OUTPUT / "rejected-endpoints.json"
    rejected_path.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "endpoints": [merged_rejected[k] for k in sorted(merged_rejected)],
    }, indent=2))

    carried = sum(1 for k in merged_rejected if k not in rejected)
    print(f"Done. Published {len(health)} configs to {output_path}")
    print(f"  Denied: {len(merged_rejected)} endpoints on the denylist "
          f"({len(rejected)} confirmed this run, {carried} carried forward)")

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
