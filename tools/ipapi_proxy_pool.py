#!/usr/bin/env python3
"""Build a sing-box sidecar that exposes Phase 2 survivors as SOCKS5.

ip-api rate-limits per caller address, and one runner resolving a 16k-config
corpus trips it. The fix needs a *pool* of egress addresses, not one: the
Phase 2 output is the only list of configs already known to pass TCP+UDP at
run time, so it is the right candidate set.

sing-box does the round-robin itself. A `urltest` outbound group re-tests its
members against a probe URL and prefers live ones, so a dead member is skipped
rather than costing every lookup.

Usage:
    python3 tools/ipapi_proxy_pool.py <verified.txt> <out.json> [--count N]

Reads vmess/vless/ss:// lines, writes a runnable sing-box config whose only
inbound is a SOCKS5 listener. Prints the SOCKS5 URL to pass to the collector as
IP_API_PROXY_URL.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import verify  # noqa: E402  (path insert above is required)

PROBE_URL = "http://www.gstatic.com/generate_204"


def build(pool: list[dict], listen_port: int) -> dict:
    # sing-box resolves a group's members by tag, so every member must be
    # defined before the group that names it -- otherwise it starts with
    # "dependency[p0] not found" and nothing listens at all.
    for rec in pool:
        rec["outbound"]["tag"] = rec["tag"]

    outbounds = [rec["outbound"] for rec in pool]
    # A urltest group picks its *fastest* live member and keeps it, so all
    # traffic collapses onto one egress IP (measured: 11 of 12 requests left
    # via a single address) and the rate limit is not actually spread. A
    # selector holds a fixed member, and the caller rotates the choice between
    # requests, which is what spreading per-caller quota requires.
    outbounds.append(
        {
            "type": "selector",
            "tag": "pool",
            "outbounds": [rec["tag"] for rec in pool],
            "default": pool[0]["tag"],
            "interrupt_exist_connections": False,
        }
    )

    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": listen_port,
            },
            # A selector only changes member when something tells it to. The
            # Clash-compatible API is the supported way to do that, so the
            # collector can PUT a new outbound per request and actually spread
            # the calls across egress addresses.
            {
                "type": "mixed",
                "tag": "api-in",
                "listen": "127.0.0.1",
                "listen_port": listen_port + 1,
            },
        ],
        "outbounds": outbounds,
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{listen_port + 2}",
            }
        },
        "route": {"final": "pool", "auto_detect_interface": True},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("verified", help="file of Phase 2 survivor URIs")
    ap.add_argument("out", help="sing-box config to write")
    ap.add_argument("--count", type=int, default=8)
    ap.add_argument("--port", type=int, default=11080)
    args = ap.parse_args()

    pool: list[dict] = []
    seen: set[str] = set()
    for line in Path(args.verified).read_text().splitlines():
        uri = line.split("#", 1)[0].strip()
        if not uri or uri in seen:
            continue
        seen.add(uri)
        try:
            outbound = verify.parse_proxy_uri(uri)
        except Exception as exc:  # a bad line must not sink the pool
            print(f"skip: {exc}", file=sys.stderr)
            continue
        if not outbound:
            continue
        pool.append({"tag": f"p{len(pool)}", "outbound": outbound})
        if len(pool) >= args.count:
            break

    if not pool:
        print("no usable configs", file=sys.stderr)
        return 1

    Path(args.out).write_text(json.dumps(build(pool, args.port), indent=2))
    schemes: dict[str, int] = {}
    for rec in pool:
        name = str(rec["outbound"].get("type", "?"))
        schemes[name] = schemes.get(name, 0) + 1
    print(f"pool={len(pool)} schemes={schemes}")
    print(f"socks5://127.0.0.1:{args.port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
