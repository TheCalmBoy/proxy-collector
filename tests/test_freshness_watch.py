"""Freshness watchdog decision logic.

The watchdog is the non-cron trigger path: it must fire update.yml when the
pool is frozen, probe-egress.yml when the pool is fresh but unmeasured, and
stay silent otherwise. Pure timestamp math, no network.
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import freshness_watch  # noqa: E402

NOW = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)


def _doc(minutes_ago: float) -> dict:
    ts = (NOW - timedelta(minutes=minutes_ago)).isoformat()
    return {"generated_at": ts}


class TestParseGeneratedAt(unittest.TestCase):
    def test_missing_or_garbage_is_none(self):
        self.assertIsNone(freshness_watch.parse_generated_at(None))
        self.assertIsNone(freshness_watch.parse_generated_at({"generated_at": 42}))
        self.assertIsNone(freshness_watch.parse_generated_at({"generated_at": "nope"}))
        self.assertIsNone(freshness_watch.parse_generated_at({}))

    def test_naive_datetime_is_assumed_utc(self):
        ts = (NOW - timedelta(hours=1)).replace(tzinfo=None).isoformat()
        self.assertEqual(NOW - timedelta(hours=1),
                         freshness_watch.parse_generated_at({"generated_at": ts}))


class TestDecide(unittest.TestCase):
    """decide() is pure timestamp math: pool > 20 min -> update, else
    health > 5 min -> probe, else none. Update wins when both are stale.
    (In-flight dedup for a probe that is still running lives in the
    --check-active / heavy_workflow_active() guard, not in decide().)"""

    def test_both_missing_wants_update(self):
        d = freshness_watch.decide(None, None, now=NOW)
        self.assertEqual("update", d.action)

    def test_fresh_pool_and_fresh_health_is_noop(self):
        # pool 10 (<= 20), health 4 (<= 5): both fresh.
        d = freshness_watch.decide(_doc(10), _doc(4), now=NOW)
        self.assertEqual("none", d.action)

    def test_stale_pool_wants_update_even_if_health_is_fresh(self):
        # A probe of a frozen pool would just publish a report about a pool
        # nobody is serving anymore; re-collect first.
        d = freshness_watch.decide(_doc(200), _doc(4), now=NOW)
        self.assertEqual("update", d.action)

    def test_fresh_pool_stale_health_wants_probe(self):
        d = freshness_watch.decide(_doc(15), _doc(120), now=NOW)
        self.assertEqual("probe", d.action)

    def test_fresh_pool_missing_health_wants_probe(self):
        d = freshness_watch.decide(_doc(15), None, now=NOW)
        self.assertEqual("probe", d.action)

    def test_fresh_pool_health_past_5min_wants_probe(self):
        # pool is fresh (5 min) but the measurement is 40 min old: the chain
        # probe for the current pool never ran.
        d = freshness_watch.decide(_doc(5), _doc(40), now=NOW)
        self.assertEqual("probe", d.action)

    def test_stale_pool_wins_over_stale_health(self):
        # Both past threshold: update wins (its chained probe covers the
        # measurement; the probe check re-fires next tick if needed).
        d = freshness_watch.decide(_doc(40), _doc(45), now=NOW)
        self.assertEqual("update", d.action)

    def test_pool_exact_20min_health_exact_5min_is_noop(self):
        # "> limit" is strict: landing exactly on the boundary is fresh.
        d = freshness_watch.decide(_doc(20), _doc(5), now=NOW)
        self.assertEqual("none", d.action)

    def test_pool_just_over_20min_wants_update(self):
        d = freshness_watch.decide(_doc(21), _doc(4), now=NOW)
        self.assertEqual("update", d.action)

    def test_health_just_over_5min_wants_probe(self):
        d = freshness_watch.decide(_doc(15), _doc(6), now=NOW)
        self.assertEqual("probe", d.action)


class TestLoad(unittest.TestCase):
    def test_missing_path_is_none(self):
        self.assertIsNone(freshness_watch.load(None))
        self.assertIsNone(freshness_watch.load("/nonexistent/does-not-exist.json"))


if __name__ == "__main__":
    unittest.main()
