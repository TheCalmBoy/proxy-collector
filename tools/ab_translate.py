#!/usr/bin/env python3
"""A/B: our sing-box translation vs mihomo's own subscription parser.

Arm A -- verify.py's parse_proxy_uri() -> sing-box config -> one socks inbound
          per config.
Arm B -- the *same raw share links* handed to mihomo as a subscription, so
          mihomo's own parser builds the proxy -> one socks listener per config,
          bound to that proxy by name.
Both arms are probed by the SAME prober (verify._https_request) from the same
machine at the same time. A config arm B opens and arm A cannot is therefore a
defect in OUR translation, not a dead server and not a vantage difference.

Two controls make a silently-broken harness impossible to miss:
  * published control group -- configs we already publish; both arms must open
    nearly all of them, or the harness itself is wrong;
  * canary -- a config pointing at TEST-NET-1 (192.0.2.1), which is unroutable
    by definition. Both arms MUST fail it. If a canary "succeeds", that arm is
    bypassing its proxy (this is not hypothetical: a mihomo `type: file`
    provider silently fell back to DIRECT until it was caught).

Usage:
    python3 tools/ab_translate.py --dry-run           # build+validate configs, no probes
    python3 tools/ab_translate.py --sample 30 --control 8 --seed 1337
"""

from __future__ import annotations

import argparse
import asyncio
import functools
import http.server
import json
import os
import pathlib
import random
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import verify  # noqa: E402  (reuse the production parser + prober)

RAD_URL = os.getenv(
    "AB_FEED_URL",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
)
PUBLISHED_URL = os.getenv(
    "AB_PUBLISHED_URL",
    "https://raw.githubusercontent.com/TheCalmBoy/proxy-collector/gh-pages/enriched-configs.json",
)
PROBE_URL = os.getenv("AB_PROBE_URL", "https://www.gstatic.com/generate_204")
PROBE_TIMEOUT = float(os.getenv("AB_PROBE_TIMEOUT", "10"))
CONCURRENCY = int(os.getenv("AB_CONCURRENCY", "24"))
# TEST-NET-1, RFC 5737: guaranteed unroutable. Never openable, by design.
CANARY = ("vless://00000000-0000-0000-0000-000000000000@192.0.2.1:443"
          "?encryption=none&security=tls&sni=example.com&type=ws&path=%2F#canary")

SUSPECT_SECURITY = {"tls", "reality", "xtls"}
SUSPECT_TRANSPORT = {"ws", "grpc", "http", "httpupgrade"}
SECRET_KEYS = {"uuid", "password", "id", "public_key", "private_key", "pbk", "sid", "short_id"}


def _mask(obj):
    """Redact credential-bearing fields before anything is printed or saved."""
    if isinstance(obj, dict):
        return {k: ("<masked>" if k.lower() in SECRET_KEYS else _mask(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask(v) for v in obj]
    return obj


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "ab-translate/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def _base(uri: str) -> str:
    return uri.split("#", 1)[0].strip()


def _params(uri: str) -> dict[str, str]:
    return {k.lower(): v for k, v in urllib.parse.parse_qsl(urllib.parse.urlsplit(uri).query)}


def _is_suspect(uri: str) -> bool:
    """The class we measured dying 7x more often than plain ss: TLS/transport."""
    q = _params(uri)
    sec = (q.get("security") or "").lower()
    if not sec and urllib.parse.urlsplit(uri).scheme in ("trojan", "hysteria2"):
        sec = "tls"
    return sec in SUSPECT_SECURITY or (q.get("type") or "").lower() in SUSPECT_TRANSPORT


def load_sample(n_fail: int, n_control: int, seed: int) -> tuple[list[str], list[str], list[str]]:
    feed = [_base(l) for l in _fetch(RAD_URL).splitlines() if l.strip() and "://" in l]
    try:
        pub = json.loads(_fetch(PUBLISHED_URL))
        live = {_base(c["uri"]) for c in pub.get("configs", []) if "://" in c.get("uri", "")}
    except Exception as exc:  # a control group is mandatory, never silently skip it
        raise SystemExit(f"cannot load published control set: {type(exc).__name__}: {exc}")

    rng = random.Random(seed)
    pool = [u for u in feed if u not in live and _is_suspect(u)]
    pool = sorted(set(pool))          # deterministic before shuffling
    rng.shuffle(pool)
    fails = pool[:n_fail]

    ctrl_pool = sorted({u for u in feed if u in live and _is_suspect(u)})
    rng.shuffle(ctrl_pool)
    controls = ctrl_pool[:n_control]

    print(f"feed={len(feed)} published={len(live)} suspect+dead pool={len(pool)} "
          f"sampled_fails={len(fails)} controls={len(controls)} canary=1")
    return fails, controls, [CANARY]


async def _probe_all(ports: dict[str, int], label: str) -> dict[str, dict]:
    """Probe every uri's socks port with the production prober."""
    sem = asyncio.Semaphore(CONCURRENCY)
    out: dict[str, dict] = {}

    async def one(uri: str):
        async with sem:
            try:
                ok, latency = await verify._https_request(ports[uri], PROBE_URL, PROBE_TIMEOUT)
            except Exception as exc:
                ok, latency = False, None
                out[uri] = {"ok": False, "latency_ms": None, "error": f"{type(exc).__name__}"}
                return
            out[uri] = {"ok": bool(ok), "latency_ms": round(latency, 1) if latency else None}

    await asyncio.gather(*(one(u) for u in ports))
    opened = sum(1 for v in out.values() if v["ok"])
    print(f"   [{label}] opened {opened}/{len(ports)}")
    return out


def arm_a(fails: list[str], controls: list[str], canary: list[str]) -> dict[str, dict]:
    """Our translation: verify.py parser -> sing-box."""
    uris = fails + controls + canary
    config, records, stats = verify.build_sing_box_config(uris)
    ports = {r["uri"]: r["port"] for r in records}
    rejected = [u for u in uris if u not in ports]
    print(f"   [A] our parser: {stats['supported']} built, {stats['unsupported']} rejected "
          f"{[k for k in stats if k.startswith('skip_')]}")

    if os.getenv("AB_DRY_RUN"):
        work = pathlib.Path(os.getcwd()) / "abwork"
        work.mkdir(parents=True, exist_ok=True)
        (work / "singbox.json").write_text(json.dumps(config))
        print("   [A] wrote", work / "singbox.json")
        return {}

    async def run():
        proc = await verify._run_sing_box(config)
        try:
            await asyncio.sleep(1.5)
            return await _probe_all(ports, "A: sing-box / ours")
        finally:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                proc.kill()

    res = asyncio.run(run())
    for u in rejected:
        res[u] = {"ok": False, "latency_ms": None, "error": "our_parser_rejected"}
    return res


class _Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass


def _mihomo_config(uris: list[str], base_port: int, ctrl_port: int, feed_port: int) -> str:
    listeners = "".join(
        f"  - name: ab-{i}\n    type: socks\n    port: {base_port + i}\n    proxy: ab-{i}\n"
        for i in range(len(uris))
    )
    return f"""mode: rule
log-level: warning
allow-lan: false
external-controller: 127.0.0.1:{ctrl_port}
proxy-providers:
  ab:
    type: http
    url: http://127.0.0.1:{feed_port}/subs.txt
    path: ./providers/ab.yaml
    interval: 3600
    health-check: {{enable: false}}
listeners:
{listeners}rules:
  - MATCH,DIRECT
"""


def _wait_port(port: int, deadline: float) -> bool:
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def arm_b(fails: list[str], controls: list[str], canary: list[str], root: pathlib.Path) -> dict[str, dict]:
    """mihomo's own parser, same raw links, same prober."""
    uris = fails + controls + canary
    feed_port, ctrl_port = 8099, 9099
    base_port = 22000
    sub_dir = root / "abwork"
    sub_dir.mkdir(parents=True, exist_ok=True)
    (sub_dir / "subs.txt").write_text(
        "\n".join(f"{u}#ab-{i}" for i, u in enumerate(uris)) + "\n", encoding="utf-8")
    (sub_dir / "mihomo.yaml").write_text(
        _mihomo_config(uris, base_port, ctrl_port, feed_port), encoding="utf-8")

    if os.getenv("AB_DRY_RUN"):
        return {}

    handler = functools.partial(_Quiet, directory=str(sub_dir))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", feed_port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    mihomo = os.getenv("MIHOMO", "mihomo")
    log_path = sub_dir / "mihomo.log"

    def start() -> subprocess.Popen:
        with open(log_path, "a") as log:
            return subprocess.Popen([mihomo, "-f", str(sub_dir / "mihomo.yaml"), "-d", str(sub_dir)],
                                    stdout=log, stderr=subprocess.STDOUT)

    # First start populates the provider cache; second start resolves every
    # listener's proxy synchronously from that cache. A provider that has not
    # finished fetching leaves listeners pointing at nothing, and mihomo then
    # serves them over DIRECT -- measured, not guessed: that is exactly how a
    # `type: file` provider fooled an earlier version of this harness.
    proc = start()
    probe_port = base_port
    deadline = time.time() + 30
    good = False
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{ctrl_port}/providers/proxies", timeout=4) as r:
                providers = json.loads(r.read().decode()).get("providers", {})
            if len(providers.get("ab", {}).get("proxies", [])) >= len(uris):
                good = True
                break
        except Exception:
            pass
        time.sleep(1)
    proc.terminate()
    proc.wait(timeout=10)
    if not good:
        print("   [B] provider never loaded -- arm B is invalid")
        srv.shutdown()
        return {}

    proc = start()
    if not _wait_port(probe_port, time.time() + 30):
        proc.terminate()
        srv.shutdown()
        print("   [B] listeners never came up")
        return {}

    log_text = log_path.read_text(errors="replace")
    not_found = [l for l in log_text.splitlines() if "not found" in l]
    if not_found:
        print(f"   [B] {len(not_found)} 'proxy not found' warnings -- listeners would fall back to DIRECT")

    ports = {u: base_port + i for i, u in enumerate(uris)}

    async def run():
        return await _probe_all(ports, "B: mihomo / its own parser")

    res = asyncio.run(run())
    proc.terminate()
    srv.shutdown()
    return res


def report(a: dict[str, dict], b: dict[str, dict], fails: list[str], controls: list[str],
           canary: list[str]) -> int:
    def ok(d, u):
        return bool(d.get(u, {}).get("ok"))

    print("\n================ CONTROLS (harness validity) ================")
    ca = sum(ok(a, u) for u in controls)
    cb = sum(ok(b, u) for u in controls)
    print(f"  published control: ours {ca}/{len(controls)}  mihomo {cb}/{len(controls)}")
    ka = sum(ok(a, u) for u in canary)
    kb = sum(ok(b, u) for u in canary)
    print(f"  canary (must be 0): ours {ka}/{len(canary)}  mihomo {kb}/{len(canary)}")

    valid = True
    if controls and cb < max(1, int(0.75 * len(controls))):
        print("  !! mihomo arm failed the control group -- harness broken, results below are void")
        valid = False
    if controls and ca < max(1, int(0.75 * len(controls))):
        print("  !! our arm failed the control group -- harness broken")
        valid = False
    if ka or kb:
        print("  !! CANARY passed -- that arm is bypassing its proxy; results void")
        valid = False

    print("\n================ THE ANSWER (configs upstream calls verified) ================")
    aok = sum(ok(a, u) for u in fails)
    bok = sum(ok(b, u) for u in fails)
    mismatch = [u for u in fails if ok(b, u) and not ok(a, u)]
    ours_only = [u for u in fails if ok(a, u) and not ok(b, u)]
    both_dead = [u for u in fails if not ok(a, u) and not ok(b, u)]
    n = len(fails)
    print(f"  sampled dead-on-our-side configs: {n}")
    print(f"    opened by ours   : {aok}/{n}")
    print(f"    opened by mihomo : {bok}/{n}")
    print(f"    BOTH dead (genuinely gone / vantage) : {len(both_dead)}")
    print(f"    >>> mihomo opens, WE cannot (our translation loses these): {len(mismatch)}")
    print(f"    ours opens, mihomo cannot (opposite): {len(ours_only)}")
    if mismatch:
        print("\n  our translation lost these because our parser emitted this outbound:")
        for u in mismatch[:3]:
            try:
                out = _mask(verify.parse_proxy_uri(u))
                print("    -", json.dumps({k: out.get(k) for k in
                                          ("type", "server_port", "tls", "transport", "flow")
                                          if out.get(k) is not None}, separators=(",", ":"))[:400])
            except Exception as exc:
                print("    - parse raised", type(exc).__name__)
    return 0 if valid else 2


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=int, default=int(os.getenv("AB_SAMPLE", "30")))
    ap.add_argument("--control", type=int, default=int(os.getenv("AB_CONTROL", "8")))
    ap.add_argument("--seed", type=int, default=int(os.getenv("AB_SEED", "1337")))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--out", default=os.getenv("AB_OUT", "ab-translate-result.json"))
    args = ap.parse_args()
    if args.dry_run:
        os.environ["AB_DRY_RUN"] = "1"

    root = pathlib.Path(os.getcwd())
    fails, controls, canary = load_sample(args.sample, args.control, args.seed)
    if args.dry_run:
        print("\n-- arm A: building sing-box config --")
        arm_a(fails, controls, canary)
        print("-- arm B: building mihomo config --")
        arm_b(fails, controls, canary, root)
        print("-- validating both configs with their real cores --")
        work = pathlib.Path(os.getcwd()) / "abwork"
        sbc = subprocess.run(
            [os.getenv("SING_BOX", "sing-box"), "check", "-c", str(work / "singbox.json")],
            capture_output=True, text=True)
        print("   sing-box check:", (sbc.stdout + sbc.stderr).strip()[:200] or f"rc={sbc.returncode}")
        mhc = subprocess.run(
            [os.getenv("MIHOMO", "mihomo"), "-t", "-f", str(work / "mihomo.yaml"),
             "-d", str(work)], capture_output=True, text=True)
        tail = (mhc.stdout + mhc.stderr).strip().splitlines()
        print("   mihomo -t :", tail[-1][:200] if tail else f"rc={mhc.returncode}")
        print("\ndry run complete: configs built and validated, nothing probed")
        return 0

    print("\n-- arm A: our translation (sing-box) --")
    a = arm_a(fails, controls, canary)
    print("-- arm B: mihomo's own parser --")
    b = arm_b(fails, controls, canary, root)

    rc = report(a, b, fails, controls, canary)
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "probe_url": PROBE_URL,
        "counts": {"sampled": len(fails), "controls": len(controls)},
        "opened": {
            "ours": sum(1 for u in fails if a.get(u, {}).get("ok")),
            "mihomo": sum(1 for u in fails if b.get(u, {}).get("ok")),
        },
        "mihomo_opens_we_cannot": [
            {"id": verify._tag(u)[:12], "scheme": urllib.parse.urlsplit(u).scheme,
             "params": sorted(_params(u)), "ours": a.get(u), "mihomo": b.get(u)}
            for u in fails if b.get(u, {}).get("ok") and not a.get(u, {}).get("ok")
        ],
        "both_dead": [verify._tag(u)[:12] for u in fails
                      if not a.get(u, {}).get("ok") and not b.get(u, {}).get("ok")],
        "controls": {"ours": sum(1 for u in controls if a.get(u, {}).get("ok")),
                     "mihomo": sum(1 for u in controls if b.get(u, {}).get("ok")),
                     "n": len(controls)},
    }
    pathlib.Path(args.out).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
