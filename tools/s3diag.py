#!/usr/bin/env python3
"""Stage 3 diagnostics: why each candidate fails, and can it reach strict sites?

Run on the GitHub runner, the same host production uses, so the numbers
describe the real pipeline rather than a lab.

Two questions, one script:

1. Why did a config fail the download test? The pipeline collapses every
   failure into "did not pass Stage 3", which hides the distinction that
   matters: a config that was too slow and a config that was never a working
   proxy need different fixes. This classifies every outcome:
     - `refused`        the proxy refused the connection
     - `handshake`      TLS/transport negotiation failed (not a proxy)
     - `midstream`      connected and started, then died partway
     - `too_slow`       completed the transfer but under the threshold
     - `timeout`        killed by max-time, no verdict
     - `ok`             passed

2. Can it reach sites that are strict about IP reputation and geography?
   Reported as a flag only. It never removes a config, because a proxy that
   cannot reach a streaming site is still a working proxy, and treating this
   as a filter would silently shrink the pool for a property the product
   does not promise.

Usage:
    python -u s3diag.py candidates.txt
Env:  PROBE_N, PROBE_MAXTIME, PROBE_BYTES, PROBE_CONC, PROBE_MIN_MB_S
"""
import asyncio, json, os, re, sys, time
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.environ.get("REPO", "."))
import verify  # noqa: E402  the real pipeline module, unmodified

MIN_MB_S = float(os.environ.get("PROBE_MIN_MB_S", verify.MIN_SPEED_MB_S))
BYTES = int(os.environ.get("PROBE_BYTES", verify.SPEED_TEST_BYTES))
MAX_TIME = int(os.environ.get("PROBE_MAXTIME", "50"))
CONC = int(os.environ.get("PROBE_CONC", str(verify.SPEED_CONCURRENCY)))

# Sites chosen for how they treat the client, not for popularity:
#   - strict IP reputation:  Google's CAPTCHA gate on the Gemini web app,
#     YouTube's datacenter blocks
#   - strict geography:     Spotify and ChatGPT are unavailable in some
#     countries, so a 403 here is a geo signal, not a dead proxy
#   - control:              example.com always answers, so a failure there is
#     the proxy rather than the destination
SITE_CHECKS = [
    ("example", "https://example.com/", "control"),
    ("youtube", "https://www.youtube.com/", "ip-reputation"),
    ("gemini", "https://gemini.google.com/", "ip-reputation"),
    ("chatgpt", "https://chatgpt.com/", "geo + ip-reputation"),
    ("spotify", "https://open.spotify.com/", "geo + ip-reputation"),
]


def load(path):
    return [l.strip() for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]


def classify(rc, metric, err, payload, threshold):
    """Turn a curl result into one human-meaningful reason.

    curl's exit codes are coarse; the interesting distinction is whether any
    bytes moved before the failure, which only `%{size_download}` tells us.
    """
    got_bytes = False
    mb_s = None
    if metric:
        parts = metric.decode(errors="replace").strip().split()
        if len(parts) == 3:
            try:
                size, ttfb, total = map(float, parts)
                got_bytes = size > 0
                if total > ttfb:
                    mb_s = size / 1_000_000 / (total - ttfb)
            except ValueError:
                pass

    if rc == 0:
        if mb_s is None:
            return "no_metrics", mb_s, 0
        return ("ok" if mb_s >= threshold else "too_slow"), mb_s, 1
    if rc == 28:
        # Timed out. If bytes arrived it was transferring and merely too slow
        # to finish; if not, it never got going. Those are different problems.
        return ("timeout_slow" if got_bytes else "timeout_stalled"), mb_s, 0
    if rc == 35 or rc == 97:
        return "handshake", mb_s, 0
    if rc in (7, 56, 52):
        return ("refused" if rc == 7 else "midstream"), mb_s, 0
    if rc == 22:
        # `fail` makes curl treat HTTP >=400 as an error. The proxy did its
        # job; the origin refused us. That is a verdict, not a failure.
        return "http_rejected", mb_s, 0
    return f"curl_{rc}", mb_s, 0


async def speed_test(rec):
    cfg = [
        f'proxy = "socks5h://127.0.0.1:{rec["port"]}"',
        f'url = "https://speed.cloudflare.com/__down?bytes={BYTES}"',
        "silent", "show-error", "fail",
        "connect-timeout = 10",
        f"max-time = {MAX_TIME}",
        'output = "/dev/null"',
        # %{size_download} on failure is what separates "died mid-transfer"
        # from "never started". Keep it in the write-out so a killed curl
        # still reports what it managed to pull.
        'write-out = "\\n__M__%{size_download} %{time_starttransfer} %{time_total}"',
    ]
    p = await asyncio.create_subprocess_exec(
        "curl", "--config", "-",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await p.communicate(("\n".join(cfg) + "\n").encode())
    _, mk, metric = out.partition(b"\n__M__")
    reason, mb_s, _ = classify(p.returncode, metric if mk else b"", err,
                               BYTES, MIN_MB_S)
    return reason, mb_s, p.returncode, err.decode(errors="replace")[-200:].strip()


async def site_check(rec):
    """Flag-only: which strict sites this proxy can actually reach."""
    res = {}
    for name, url, kind in SITE_CHECKS:
        cfg = [
            f'proxy = "socks5h://127.0.0.1:{rec["port"]}"',
            f'url = "{url}"', "silent", "show-error", "location",
            "connect-timeout = 8", "max-time = 15",
            'output = "/dev/null"',
            'write-out = "%{http_code}"',
        ]
        p = await asyncio.create_subprocess_exec(
            "curl", "--config", "-",
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await p.communicate(("\n".join(cfg) + "\n").encode())
        code = out.decode(errors="replace").strip()[:3]
        res[name] = {
            "kind": kind,
            "http": code if code.isdigit() else None,
            "rc": p.returncode,
            # 000 means the proxy never delivered an HTTP response at all,
            # which is a proxy failure rather than a site rejection.
            "reachable": code.isdigit() and code != "000" and int(code) < 500,
        }
    return res


async def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "candidates.txt"
    n = int(os.environ.get("PROBE_N", "30"))
    uris = load(src)[:n]
    config, records, _ = verify.build_sing_box_config(uris)
    config, records = verify.dedupe_endpoints(config, records)
    print(f"[diag] configs={len(records)} bytes={BYTES/1e6:.1f}MB "
          f"max-time={MAX_TIME}s conc={CONC} min={MIN_MB_S} MB/s", flush=True)

    proc = await verify._run_sing_box(config)
    sem = asyncio.Semaphore(CONC)
    rows = []
    try:
        async def one(rec):
            async with sem:
                reason, mb_s, rc, err = await speed_test(rec)
            sites = await site_check(rec)
            return {"port": rec["port"], "server": rec.get("server", ""),
                    "scheme": rec.get("scheme", ""), "reason": reason,
                    "mb_s": round(mb_s, 4) if mb_s else None, "curl_rc": rc,
                    "sites": sites, "curl_err": err}

        t0 = time.monotonic()
        rows = await asyncio.gather(*[one(r) for r in records])
        wall = time.monotonic() - t0
    finally:
        proc.terminate()
        try:
            await proc.wait(timeout=10)
        except Exception:
            proc.kill()

    reasons = Counter(r["reason"] for r in rows)
    print(f"\n[diag] === {len(rows)} configs in {wall:.1f}s ===", flush=True)
    for reason, n_ in reasons.most_common():
        print(f"  {reason:<16} {n_:>4}  {'#' * n_}", flush=True)

    ok = [r for r in rows if r["reason"] == "ok"]
    slow = [r for r in rows if r["reason"] == "too_slow"]
    print(f"\n[diag] speeds of the {len(ok)} passing:")
    for r in sorted(ok, key=lambda r: -r["mb_s"]):
        print(f"    {r['mb_s']:>8.3f} MB/s  port={r['port']}", flush=True)
    if slow:
        print(f"[diag] speeds of the {len(slow)} too_slow (measured, below bar):")
        for r in sorted(slow, key=lambda r: -(r["mb_s"] or 0)):
            print(f"    {r['mb_s']:>8.3f} MB/s  port={r['port']}", flush=True)

    print("\n[diag] site reachability (flag only, never a filter):", flush=True)
    for name, _url, kind in SITE_CHECKS:
        got = sum(1 for r in rows if r["sites"][name]["reachable"])
        codes = Counter(str(r["sites"][name]["http"]) for r in rows)
        print(f"  {name:<10} ({kind:<18}) {got:>3}/{len(rows)}  {dict(codes)}", flush=True)

    print("\n[diag] per-config detail:", flush=True)
    for r in rows:
        flags = "".join(
            ("+" if r["sites"][s]["reachable"] else "-") for s, _, _ in SITE_CHECKS)
        print(f"  {r['reason']:<16} {(r['mb_s'] or 0):>8.3f} MB/s "
              f"rc={r['curl_rc']:<3} sites[{flags}] port={r['port']}", flush=True)

    out = Path(os.environ.get("REPORT_PATH", "diag-report.json"))
    out.write_text(json.dumps({"meta": {"configs": len(rows), "bytes": BYTES,
                                       "max_time": MAX_TIME, "conc": CONC,
                                       "min_mb_s": MIN_MB_S, "wall_s": round(wall, 1),
                                       "site_checks": [s[0] for s in SITE_CHECKS]},
                               "rows": rows}, indent=2))
    print(f"\n[diag] wrote {out}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
