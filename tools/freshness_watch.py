"""Freshness watchdog: one decision per tick, computed from two timestamps.

The pipeline is two chained workflows:

    update.yml (every 30 min, :05/:35)  -> publishes gh-pages/enriched-configs.json
      and dispatches probe-egress.yml at the end of a successful build,
      which measures it and publishes gh-pages/egress-health.json.

GitHub's free-tier ``schedule:`` crons are best-effort: a tick can be delayed
or skipped entirely. When an update slot is skipped, nothing re-collects the
pool and the chain (probe after publish) breaks with it - the health index
freezes and the worker's join drops configs the index no longer covers.

This module does not fix the scheduler. It adds a redundant trigger path: a
cheap workflow (freshness-watchdog.yml) evaluates this decision every 10
minutes (GitHub schedule plus the external Cloudflare heartbeat, both feeding
the same gate) and dispatches the expensive workflow when its input is stale.
A missed slot is recovered on the next watchdog tick instead of the next slot.

The decision is a pure function of the two published documents so it can be
unit-tested without a runner:

    "update"  the pool itself is missing or older than --pool-stale-min
              (default 30). The update re-collects AND chains its own probe,
              so one update covers both.
    "probe"   the health index is older than --health-stale-min (default 10)
              while the pool is fresh: the chain probe for the current pool
              never ran.
    "none"    both are fresh; the tick is a no-op.

The two checks are independent: the pool check gates the re-collect, the
health check gates the probe. Update wins when both are stale.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Decision:
    action: str  # "update" | "probe" | "none"
    reason: str
    pool_age_min: float | None
    health_age_min: float | None


def parse_generated_at(doc: Any, key: str = "generated_at") -> datetime | None:
    """Parse an ISO-8601 generated_at stamp; None on anything unexpected.

    Both producers write ``datetime.now(timezone.utc).isoformat()``, so the
    stamps are comparable, but a missing or corrupt document must never crash
    the tick - it degrades to "treat as stale" and lets the workflow make the
    conservative choice.
    """
    if not isinstance(doc, dict):
        return None
    value = doc.get(key)
    if not isinstance(value, str):
        return None
    try:
        produced = datetime.fromisoformat(value)
    except ValueError:
        return None
    if produced.tzinfo is None:
        produced = produced.replace(tzinfo=timezone.utc)
    return produced


def decide(
    pool_doc: Any,
    health_doc: Any,
    now: datetime | None = None,
    pool_stale_min: float = 30.0,
    health_stale_min: float = 10.0,
) -> Decision:
    """Pick the one workflow to run, if any.

    Two independent freshness checks, the watchdog's whole job:

    1. Pool (the published pool document) older than ``pool_stale_min``
       (default 30 min) -> run ``update``. A re-collect publishes a fresh pool
       AND chains the probe at the end of the build, so one update covers
       both the pool and its measurement.

    2. Health (the probe's published output) older than ``health_stale_min``
       (default 10 min) -> run ``probe``. This fires when the pool is fresh
       but the measurement is not: the chain probe for the current pool never
       landed, or the probe simply has not ticked in the last 10 min.

    The two checks are evaluated in order, so a frozen pool always wins (a
    probe of a stale pool would only publish a report about a pool nobody is
    serving). They are independent and both run every tick: a fresh pool with
    a stale health dispatches only the probe; a stale pool dispatches the
    update (which chains its own probe) and the health check is re-evaluated
    on the next tick once the fresh pool is out.

    The previous "pool republished after the last measurement" grace case is
    gone: under a 10-min health threshold, any pool older than its own
    measurement is already >10 min newer than the health index, so the health
    check above catches it directly. There is no separate grace window.

    Args:
        pool_doc:  parsed enriched-configs.json (or None on fetch/parse failure).
        health_doc: parsed egress-health.json (or None).
        now:       the clock to measure age against (injected for tests).
        pool_stale_min: pool age (minutes) at which to re-collect (default 30).
        health_stale_min: health age (minutes) at which to re-probe (default 10).
    """
    now = now or datetime.now(timezone.utc)
    pool_ts = parse_generated_at(pool_doc)
    health_ts = parse_generated_at(health_doc)
    pool_age = (now - pool_ts).total_seconds() / 60 if pool_ts else None
    health_age = (now - health_ts).total_seconds() / 60 if health_ts else None

    if pool_age is None or pool_age > pool_stale_min:
        detail = "missing" if pool_age is None else f"{pool_age:.0f} min old"
        return Decision("update", f"pool {detail}; re-collect before probing",
                        pool_age, health_age)

    if health_age is None or health_age > health_stale_min:
        detail = "missing" if health_age is None else f"{health_age:.0f} min old"
        return Decision("probe", f"health index {detail}",
                        pool_age, health_age)

    return Decision("none", "feed and health index are fresh", pool_age, health_age)


def load(path: str | None) -> Any:
    """Load a published document; missing/unreadable/corrupt -> None."""
    if not path:
        return None
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return None


def heavy_workflow_active() -> bool:
    """True if update.yml or probe-egress.yml has a queued/running instance.

    The watchdog dispatches with ``gh workflow run``; a queued instance is
    not yet in the public branch, so without this check a stuck pipeline
    would pile up duplicate dispatches every 10 minutes. Also true when
    either workflow already completed within the last 30 min - both heavy
    runs take 10-25 minutes and the chain cadence is 30 min, so a completed run inside that window means the pipeline just fired.

    Deliberately NOT true when an update completed >30 min ago but no probe
    followed: on the 30-min chain that is exactly the broken state (the
    dispatch step died after publish) the watchdog must recover.
    """
    try:
        out = subprocess.run(
            ["gh", "run", "list", "--limit", "8", "--json",
             "name", "status", "createdAt"],
            capture_output=True, text=True, timeout=30,
        )
        if out.returncode != 0:
            return False  # fail open: dispatch rather than block recovery
        now = datetime.now(timezone.utc)
        for run in json.loads(out.stdout or "[]"):
            if run.get("name") not in ("Update Proxy Database",
                                       "Probe proxy egress IPs"):
                continue
            if run.get("status") in ("queued", "in_progress"):
                return True
            created = parse_generated_at(run, key="createdAt")
            if created and now - created < timedelta(minutes=30):
                return True
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return False
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "freshness watchdog").splitlines()[0])
    parser.add_argument("--pool", default=None,
                        help="path to the downloaded enriched-configs.json")
    parser.add_argument("--health", default=None,
                        help="path to the downloaded egress-health.json")
    parser.add_argument("--pool-stale-min", type=float, default=30.0)
    parser.add_argument("--health-stale-min", type=float, default=10.0)
    parser.add_argument(
        "--check-active",
        action="store_true",
        help="skip dispatching when update.yml/probe-egress.yml already has a "
             "queued/running instance or one finished in the last hour",
    )
    args = parser.parse_args(argv)

    decision = decide(load(args.pool), load(args.health),
                      pool_stale_min=args.pool_stale_min,
                      health_stale_min=args.health_stale_min)
    if decision.action != "none" and args.check_active and heavy_workflow_active():
        decision = Decision("none",
                            f"(suppressed: heavy workflow active; wanted {decision.action})",
                            decision.pool_age_min, decision.health_age_min)
    # Machine-readable first line: "ACTION reason" - the workflow's shell
    # dispatches on $1.
    print(f"{decision.action} {decision.reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
