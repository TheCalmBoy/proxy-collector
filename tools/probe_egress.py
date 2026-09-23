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


SOURCE_URL = os.getenv(
    "SOURCE_URL",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
)
WORKER_URL = os.environ.get("WORKER_URL", "").rstrip("/")
WORKER_TOKEN = os.environ.get("WORKER_TOKEN", "")
SING_BOX = os.getenv("SING_BOX", "sing-box")
OUTPUT = Path(os.getenv("PROBE_OUTPUT", "probe-output"))
PORT_BASE = 30000
UTLS_FINGERPRINTS = {
    "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android",
    "random", "randomized",
}


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


def _tls(params: dict[str, list[str]], security: str) -> dict[str, Any] | None:
    if security not in ("tls", "reality"):
        return None
    tls: dict[str, Any] = {"enabled": True}
    sni = _first(params, "sni", "peer")
    if sni:
        tls["server_name"] = sni
    fingerprint = _first(params, "fp", "fingerprint").lower()
    if fingerprint and fingerprint not in UTLS_FINGERPRINTS:
        fingerprint = ""
    # sing-box requires uTLS for Reality. Many share links omit `fp`; Chrome is
    # the conventional default and avoids generating an invalid outbound.
    if security == "reality" and not fingerprint:
        fingerprint = "chrome"
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if _first(params, "allowInsecure", "insecure") in ("1", "true"):
        tls["insecure"] = True
    if security == "reality":
        public_key = _first(params, "pbk", "publicKey")
        if not public_key:
            raise UnsupportedConfig("reality_missing_public_key")
        tls["reality"] = {
            "enabled": True,
            "public_key": public_key,
            "short_id": _first(params, "sid", "shortId"),
        }
    return tls


def _transport(kind: str, params: dict[str, list[str]], vmess: dict[str, Any] | None = None) -> dict[str, Any] | None:
    kind = (kind or "tcp").lower()
    if kind in ("tcp", "raw", "none"):
        return None
    if kind == "ws":
        path = _first(params, "path") or str((vmess or {}).get("path") or "")
        host = _first(params, "host") or str((vmess or {}).get("host") or "")
        transport: dict[str, Any] = {"type": "ws"}
        if path:
            transport["path"] = path
        if host:
            transport["headers"] = {"Host": host}
        return transport
    if kind == "grpc":
        service = _first(params, "serviceName", "service_name") or str((vmess or {}).get("path") or "")
        transport = {"type": "grpc"}
        if service:
            transport["service_name"] = service
        return transport
    raise UnsupportedConfig(f"unsupported_transport_{kind}")


def parse_proxy_uri(uri: str) -> dict[str, Any]:
    """Map common public share links to sing-box outbounds; reject unknowns explicitly."""
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
        outbound: dict[str, Any] = {
            "type": "vmess",
            "server": host,
            "server_port": port,
            "uuid": str(vmess.get("id") or ""),
            "alter_id": int(vmess.get("aid") or 0),
            "security": str(vmess.get("scy") or "auto"),
        }
        if not outbound["uuid"]:
            raise UnsupportedConfig("missing_uuid")
        params = {key: [str(value)] for key, value in vmess.items() if value is not None}
        security = str(vmess.get("tls") or "").lower()
        if security == "tls":
            tls = _tls(params, "tls")
            if tls:
                outbound["tls"] = tls
        elif security not in ("", "none"):
            raise UnsupportedConfig("unsupported_vmess_security")
        transport = _transport(str(vmess.get("net") or "tcp"), params, vmess)
        if transport:
            outbound["transport"] = transport
        return outbound

    try:
        parsed = urllib.parse.urlsplit(clean)
    except ValueError as exc:
        raise UnsupportedConfig("invalid_uri") from exc
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    host, port = _host_port(parsed)

    if scheme == "vless":
        user = urllib.parse.unquote(parsed.username or "")
        if not user:
            raise UnsupportedConfig("missing_uuid")
        security = _first(params, "security", default="none").lower()
        outbound = {
            "type": "vless",
            "server": host,
            "server_port": port,
            "uuid": user,
            "packet_encoding": "xudp",
        }
        flow = _first(params, "flow")
        if flow:
            outbound["flow"] = flow
        tls = _tls(params, security)
        if tls:
            outbound["tls"] = tls
        transport = _transport(_first(params, "type", "network", default="tcp"), params)
        if transport:
            outbound["transport"] = transport
        return outbound

    if scheme == "trojan":
        password = urllib.parse.unquote(parsed.username or "")
        if not password:
            raise UnsupportedConfig("missing_password")
        outbound = {"type": "trojan", "server": host, "server_port": port, "password": password}
        tls = _tls(params, "tls")
        if tls:
            outbound["tls"] = tls
        transport = _transport(_first(params, "type", "network", default="tcp"), params)
        if transport:
            outbound["transport"] = transport
        return outbound

    if scheme == "ss":
        userinfo = urllib.parse.unquote(parsed.username or "")
        if not userinfo or ":" not in userinfo:
            # SIP002 also permits a base64-encoded method:password@host:port authority.
            raw = userinfo or parsed.netloc.split("@", 1)[0]
            try:
                decoded = _decode_base64(raw).decode("utf-8")
                if ":" in decoded:
                    userinfo = decoded
            except Exception as exc:
                if not userinfo:
                    raise UnsupportedConfig("invalid_shadowsocks_userinfo") from exc
        if ":" not in userinfo:
            raise UnsupportedConfig("invalid_shadowsocks_userinfo")
        method, password = userinfo.split(":", 1)
        if not method or not password:
            raise UnsupportedConfig("invalid_shadowsocks_userinfo")
        plugin = _first(params, "plugin")
        if plugin:
            raise UnsupportedConfig("shadowsocks_plugin_not_supported")
        return {"type": "shadowsocks", "server": host, "server_port": port, "method": method, "password": password}

    raise UnsupportedConfig(f"unsupported_scheme_{scheme}")


def _read_source() -> list[str]:
    request = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "proxy-egress-probe/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        text = response.read().decode("utf-8", errors="replace")
    lines: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and line not in seen:
            lines.append(line)
            seen.add(line)
    return lines


def _tag(uri: str) -> str:
    return hashlib.sha256(uri.encode("utf-8")).hexdigest()[:12]


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

    stats["supported"] = len(records)
    config = {
        "log": {"level": "error", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds + [{"type": "direct", "tag": "direct"}],
        "route": {"rules": rules, "final": "direct"},
    }
    return config, records, {**stats, **{f"skip_{key}": value for key, value in sorted(reasons.items())}}


async def _curl_probe(record: dict[str, Any], worker_url: str, token: str, semaphore: asyncio.Semaphore) -> dict[str, Any]:
    config_lines = [
        f'proxy = "socks5h://127.0.0.1:{record["port"]}"',
        f'url = "{worker_url}/ip"',
        f'header = "Authorization: Bearer {token}"',
        "silent",
        "show-error",
        "fail",
        "connect-timeout = 10",
        "max-time = 25",
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
        return {"id": record["id"], "scheme": record["scheme"], "ok": False, "error": f"curl_exit_{process.returncode}"}
    try:
        result = json.loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"id": record["id"], "scheme": record["scheme"], "ok": False, "error": "invalid_worker_json"}
    ffraud = result.get("ffraud") if isinstance(result, dict) else None
    if not isinstance(ffraud, dict) or not result.get("ip"):
        return {"id": record["id"], "scheme": record["scheme"], "ok": False, "error": "worker_response_incomplete"}
    return {
        "id": record["id"],
        "scheme": record["scheme"],
        "ok": True,
        "ip": result["ip"],
        "family": result.get("family"),
        "country": (result.get("cloudflare") or {}).get("country"),
        "colo": (result.get("cloudflare") or {}).get("colo"),
        "fraud_score": ffraud.get("fraud_score"),
        "risk": ffraud.get("risk"),
        "proxy": ffraud.get("proxy"),
        "vpn": ffraud.get("vpn"),
        "tor": ffraud.get("tor"),
        "hosting": ffraud.get("hosting"),
        "recent_abuse": ffraud.get("recent_abuse"),
        "threat_tags": ffraud.get("threat_tags", []),
        "cache": (result.get("cache") or {}).get("ffraud"),
    }


async def _run_round(records: list[dict[str, Any]], round_name: str, semaphore: asyncio.Semaphore) -> list[dict[str, Any]]:
    results = await asyncio.gather(*(_curl_probe(row, WORKER_URL, WORKER_TOKEN, semaphore) for row in records))
    for row in results:
        row["round"] = round_name
    ok = sum(1 for row in results if row["ok"])
    print(f"{round_name}: {ok}/{len(results)} returned an IP")
    return results


def _summarize(first: list[dict[str, Any]], second: list[dict[str, Any]]) -> dict[str, Any]:
    first_by_id = {row["id"]: row for row in first if row["ok"]}
    second_by_id = {row["id"]: row for row in second if row["ok"]}
    comparable = sorted(first_by_id.keys() & second_by_id.keys())
    changed = [key for key in comparable if first_by_id[key]["ip"] != second_by_id[key]["ip"]]
    return {
        "tested_both_rounds": len(comparable),
        "stable_ip": len(comparable) - len(changed),
        "changed_ip": len(changed),
        "dynamic_configs": [
            {"id": key, "first_ip": first_by_id[key]["ip"], "second_ip": second_by_id[key]["ip"]}
            for key in changed
        ],
    }


async def main() -> int:
    if not WORKER_URL or not WORKER_TOKEN:
        print("Set WORKER_URL and the WORKER_TOKEN GitHub secret.", file=sys.stderr)
        return 2
    if not WORKER_URL.startswith("https://"):
        print("WORKER_URL must be an HTTPS URL.", file=sys.stderr)
        return 2

    print("Fetching candidate configs...")
    source = _read_source()
    candidates: list[tuple[str, dict[str, Any]]] = []
    skipped: dict[str, int] = {}
    for uri in source:
        try:
            parsed = parse_proxy_uri(uri)
        except UnsupportedConfig as exc:
            reason = str(exc)
            skipped[reason] = skipped.get(reason, 0) + 1
            continue
        candidates.append((uri, parsed))
    if not candidates:
        print("No supported proxy links were found.", file=sys.stderr)
        return 1

    batch_size = max(1, int(os.getenv("PROBE_BATCH_SIZE", "100")))
    seed = datetime.now(timezone.utc).strftime("%Y%m%d%H")
    random.Random(seed).shuffle(candidates)
    selected = candidates[:batch_size]
    selected_uris = [uri for uri, _ in selected]
    config, records, config_stats = build_sing_box_config(selected_uris)
    if not records:
        print("Selected batch had no supported configs.", file=sys.stderr)
        return 1

    OUTPUT.mkdir(parents=True, exist_ok=True)
    # Proxy links contain credentials. Keep the generated core config and logs
    # outside the report directory so they are never uploaded as artifacts.
    config_path = Path("/tmp/proxy-egress-sing-box.json")
    config_path.write_text(json.dumps(config, separators=(",", ":")), encoding="utf-8")
    print(f"Selected {len(records)} unique proxy configs; unsupported schemes are skipped.")
    print(f"Supported config mix: {json.dumps({k: v for k, v in config_stats.items() if k in ('input','supported','unsupported')})}")

    check = subprocess.run([SING_BOX, "check", "-c", str(config_path)], capture_output=True, text=True)
    if check.returncode:
        print("sing-box rejected the generated proxy config:", file=sys.stderr)
        print(check.stderr[-4000:], file=sys.stderr)
        return 1

    with Path("/tmp/proxy-egress-sing-box.log").open("wb") as log:
        core = subprocess.Popen([SING_BOX, "run", "-c", str(config_path)], stdout=log, stderr=subprocess.STDOUT)
    semaphore = asyncio.Semaphore(max(1, int(os.getenv("PROBE_CONCURRENCY", "50"))))
    try:
        await asyncio.sleep(5)
        if core.poll() is not None:
            print("sing-box exited during startup; see artifact log.", file=sys.stderr)
            return 1
        first = await _run_round(records, "initial", semaphore)
        delay = max(0, int(os.getenv("RETEST_DELAY_SECONDS", "300")))
        print(f"Waiting {delay} seconds before retesting the same configs...")
        await asyncio.sleep(delay)
        second = await _run_round(records, "delayed", semaphore)
    finally:
        core.terminate()
        try:
            core.wait(timeout=5)
        except subprocess.TimeoutExpired:
            core.kill()
            core.wait()

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": SOURCE_URL,
        "worker": WORKER_URL,
        "sing_box_version": subprocess.run([SING_BOX, "version"], capture_output=True, text=True).stdout.strip(),
        "selection": {"batch_size": batch_size, "seed_hour_utc": seed, "retest_delay_seconds": delay},
        "config_support": {**config_stats, "unsupported_source_schemes": skipped},
        "summary": _summarize(first, second),
        "results": first + second,
    }
    (OUTPUT / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Retest summary: " + json.dumps(report["summary"]))
    print(f"Full results saved to {OUTPUT / 'report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
