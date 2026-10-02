"""Freshness watchdog: one decision per tick, computed from two timestamps.

The external Cloudflare heartbeat (proxy-pipeline-heartbeat) is the ONLY clock
that fires the pipeline. It POSTs a ``repository_dispatch`` (event_type=
heartbeat) to the watchdog every 5 minutes; this module is the watchdog's brain.
No GitHub ``schedule:`` cron fires update.yml or probe-egress.yml any more -
the GitHub free-tier scheduler stopped ticking on 2026-10-01 and is no longer
trusted as a wake source, so everything is driven off the external beat.

The pipeline is two chained workflows:

    update.yml    -> publishes gh-pages/enriched-configs.json
      and dispatches probe-egress.yml at the end of a successful build,
      which measures the just-published pool and publishes
      gh-pages/egress-health.json.

The heartbeat is a 5-minute pulse; the watchdog turns it into the two-step
cycle the user wants: a database update ~every 20 min, and a probe right after
each update, then a probe on the current pool ~every 5 min until the next
update. That is exactly two freshness thresholds:

    "update"  the pool itself is missing or older than --pool-stale-min
              (default 20). The update re-collects AND chains its own probe,
              so one update covers the pool and its first measurement.
    "probe"   the pool is fresh (< pool_stale) but the health index is older
              than --health-stale-min (default 5): re-measure the current pool.
              Because the beat is 5 min and a probe takes ~5 min, this yields
              the densest probe cadence the heartbeat allows (~every 5-10 min).
    "none"    both are fresh; the tick is a no-op.

The two checks are independent; update wins when both are stale (its chained
probe covers the measurement). In-flight dedup so two beats never stack a
second heavy run lives in heavy_workflow_active() / --check-active, not here.
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
    pool_stale_min: float = 20.0,
    health_stale_min: float = 5.0,
) -> Decision:
    """Pick the one workflow to run, if any.

    Two independent freshness checks, the watchdog's whole job:

    1. Pool (the published pool document) older than ``pool_stale_min``
       (default 20 min) -> run ``update``. A re-collect publishes a fresh pool
       AND chains the probe at the end of the build, so one update covers
       both the pool and its measurement.

    2. Health (the probe's published output) older than ``health_stale_min``
       (default 5 min) -> run ``probe``. This fires when the pool is fresh
       but the measurement is not: the chain probe for the current pool never
       landed, or the probe simply has not ticked in the last 5 min.

    The two checks are evaluated in order, so a frozen pool always wins (a
    probe of a stale pool would only publish a report about a pool nobody is
    serving). They are independent and both run every tick: a fresh pool with
    a stale health dispatches only the probe; a stale pool dispatches the
    update (which chains its own probe) and the health check is re-evaluated
    on the next tick once the fresh pool is out.

    Args:
        pool_doc:  parsed enriched-configs.json (or None on fetch/parse failure).
        health_doc: parsed egress-health.json (or None).
        now:       the clock to measure age against (injected for tests).
        pool_stale_min: pool age (minutes) at which to re-collect (default 20).
        health_stale_min: health age (minutes) at which to re-probe (default 5).
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
    """True if update.yml or probe-egress.yml has a queued or running instance.

    This is the only dedup the watchdog needs. The heartbeat is a 5-minute
    pulse, so the freshness thresholds (pool > 20 -> update, else health > 5
    -> probe) are what set the cadence; a "completed within N minutes" window
    would instead freeze that cadence for N minutes after every run, which is
    exactly wrong for a 5-min probe rhythm. Instead: if a heavy run is already
    queued or in_progress, do not dispatch a second one - the two workflows'
    ``concurrency`` groups (cancel-in-progress: false) serialize any overlap
    anyway, so a queued duplicate just waits behind the live run and no-ops
    once the pool/health is fresh.

    Deliberately NOT true for a run that already completed: a failed or
    finished probe leaves the health index stale, and the very next beat must
    be free to re-dispatch it - that is the recovery path for a broken chain.
    """
    try:
        out = subprocess.run(
            ["gh", "run", "list", "--limit", "8", "--json",
             "name", "status"],
            capture_output=True, text=True, timeout=30,
        )
        if out.returncode != 0:
            return False  # fail open: dispatch rather than block recovery
        for run in json.loads(out.stdout or "[]"):
            if run.get("name") not in ("Update Proxy Database",
                                       "Probe proxy egress IPs"):
                continue
            if run.get("status") in ("queued", "in_progress"):
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
