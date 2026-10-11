"""Report configs whose published country tag disagrees with measured egress.

main.py writes the country tag from a GeoIP lookup on the proxy's *server* IP
(main.py:853), while tools/probe_egress.py measures where the connection
actually leaves. Those are different facts: an OVH box registered in Frankfurt
can exit in London, and then "DE-DC-AS51167-66D0621B" is a wrong answer to
"give me a German server". The subscription Worker already groups on the egress
country (see references/fixture-keyed-tests-hide-broken-joins.md), so this is
not a publish bug -- it is an upstream drift signal.

Nothing here blocks a run. It prints the disagreement ratio and the worst
offenders so the two geolocation paths can be compared, and exits non-zero only
when the ratio passes --max-mismatch, so a pipeline can gate on it if it wants.

Usage:
    python3 tools/country_consistency.py \
        --feed ../proxy-collector/gh-pages/all.txt \
        --health ../proxy-collector/gh-pages/egress-health.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import unquote

# The tag is the first dash-separated field of the URI fragment:
#   <CC>-<RES|DC|UNKNOWN>-<AS>-<HEXID>
TAG_RE = re.compile(r"^([A-Z]{2}|ZZ)-")

# user:pass@host:port out of ss://, vmess://, vless://, trojan://
ENDPOINT_RE = re.compile(r"^(?:ss|vmess|vless|trojan)://[^@]*@([^:/@]+):(\d+)")


def parse_endpoint(uri: str) -> tuple[str, int] | None:
    match = ENDPOINT_RE.match(uri.split("#", 1)[0])
    if not match:
        return None
    try:
        return match.group(1).strip().lower(), int(match.group(2))
    except ValueError:
        return None


def load(feed_path: Path, health_path: Path) -> tuple[list[str], dict]:
    lines = [l.strip() for l in feed_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    health = json.loads(health_path.read_text(encoding="utf-8"))
    return lines, health


def index_health(health: dict) -> dict[tuple[str, int], dict]:
    """Index the health document by (server, port).

    The health key and the feed's fragment id are NOT the same function -- on
    live data their intersection is empty -- so (server, port) is the only
    join that works. Same reason the Worker uses the same key.
    """
    out: dict[tuple[str, int], dict] = {}
    for row in (health.get("configs") or {}).values():
        server = str(row.get("server") or "").strip().lower()
        port = row.get("server_port") or row.get("port")
        if not server or not port:
            continue
        out[(server, int(port))] = row
    return out


def report(feed_path: Path, health_path: Path, max_mismatch: float) -> int:
    lines, health = load(feed_path, health_path)
    by_endpoint = index_health(health)

    compared = 0
    mismatched: list[tuple[str, str, str, str]] = []
    joined_by_id = 0

    for uri in lines:
        name = unquote(uri.split("#", 1)[1]) if "#" in uri else ""
        tag = (TAG_RE.match(name) or [None, None])[1]
        endpoint = parse_endpoint(uri)
        row = by_endpoint.get(endpoint) if endpoint else None
        if not row:
            continue
        joined_by_id += 1
        egress = row.get("primary_country") or (row.get("classification") or {}).get("country")
        if not tag or not egress or not isinstance(egress, str):
            continue
        compared += 1
        if egress.upper() != tag:
            mismatched.append((name, tag, egress.upper(), str(row.get("server") or "")))

    total = len(lines)
    print(f"feed configs      : {total}")
    print(f"joined on endpoint : {joined_by_id} ({pct(joined_by_id, total)})")
    print(f"compared countries : {compared}")
    print(f"mismatched         : {len(mismatched)} ({pct(len(mismatched), compared)})")
    if mismatched:
        print("\nserver tag -> egress country (worst offenders first):")
        pairs = Counter((tag, eg) for _, tag, eg, _ in mismatched)
        for (tag, eg), count in pairs.most_common(12):
            print(f"  {tag} -> {eg}  x{count}")
        print("\nexamples:")
        for name, tag, eg, server in mismatched[:5]:
            print(f"  {name[:34]:36} {server:16} {tag} -> {eg}")

    ratio = len(mismatched) / compared if compared else 0.0
    if compared and ratio > max_mismatch:
        print(
            f"\nFAIL: {pct(len(mismatched), compared)} of compared configs disagree, "
            f"over the {pct(max_mismatch, 1)} budget."
        )
        return 1
    if compared:
        print(f"\nOK: within the {pct(max_mismatch, 1)} budget.")
    return 0


def pct(part: float, whole: float) -> str:
    if not whole:
        return "n/a"
    return f"{100.0 * part / whole:.1f}%"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--feed", type=Path, required=True)
    parser.add_argument("--health", type=Path, required=True)
    parser.add_argument(
        "--max-mismatch",
        type=float,
        default=0.10,
        help="fail when the disagreement ratio exceeds this (default 0.10)",
    )
    args = parser.parse_args()
    return report(args.feed, args.health, args.max_mismatch)


if __name__ == "__main__":
    sys.exit(main())
