"""Freshness watchdog: one decision per tick, computed from two timestamps.

The pipeline is two chained workflows:

    update.yml (hourly :07)  -> publishes gh-pages/enriched-configs.json
    probe-egress.yml (:37)   -> publishes gh-pages/egress-health.json

GitHub's free-tier ``schedule:`` crons are best-effort: an hourly tick can be
delayed or skipped entirely. When update.yml is skipped, the pool freezes and
probe-egress.yml's stale-pool guard refuses to run, so the health index freezes
too - the worker's join then drops every config the index no longer covers and
the served subscription visibly shrinks for hours.

This module does not fix the scheduler. It adds a redundant trigger path: a
cheap workflow (freshness-watchdog.yml) evaluates this decision every ~10
minutes and dispatches the expensive workflow when its input is stale. A
skipped hourly cron is recovered on the next watchdog tick instead of at the
next hourly tick.

The decision is a pure function of the two published documents so it can be
unit-tested without a runner:

    "update"  the pool itself is missing or older than --pool-stale-min.
              Re-collect first; the next tick will dispatch the probe once
              the fresh pool is out.
    "probe"   the pool is fresh but the health index has not measured it yet
              (health.generated_at < pool.generated_at) or the health index is
              older than --health-stale-min.
    "none"    both are fresh; the tick is a no-op.
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
    pool_stale_min: float = 180.0,
    health_stale_min: float = 90.0,
) -> Decision:
    """Pick the one workflow to run, if any.

    Order matters: a frozen pool always wins, because probing a pool that no
    update has produced since would only publish a health report describing
    the same frozen feed. update.yml runs first; the next tick sees the fresh
    pool and dispatches the probe.
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

    # Both exist and are young. The remaining case: the pool was republished
    # AFTER the health index was written - the current pool has not been
    # measured yet. Compare stamps directly; both are tz-aware UTC ISO.
    if pool_ts and health_ts and health_ts < pool_ts:
        return Decision(
            "probe",
            "pool republished after the last health measurement",
            pool_age, health_age,
        )
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
    either workflow already completed within the recent window - both heavy
    runs take 10-25 minutes, so a check inside that window is always
    redundant.
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
            if created and now - created < timedelta(minutes=60):
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
    parser.add_argument("--pool-stale-min", type=float, default=180.0)
    parser.add_argument("--health-stale-min", type=float, default=90.0)
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
