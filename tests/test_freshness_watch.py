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
    def test_both_missing_wants_update(self):
        d = freshness_watch.decide(None, None, now=NOW)
        self.assertEqual("update", d.action)

    def test_fresh_pool_and_fresh_health_is_noop(self):
        d = freshness_watch.decide(_doc(30), _doc(10), now=NOW)
        self.assertEqual("none", d.action)

    def test_stale_pool_wants_update_even_if_health_is_fresh(self):
        # A probe of a frozen pool would just publish a report about a pool
        # nobody is serving anymore; re-collect first.
        d = freshness_watch.decide(_doc(200), _doc(5), now=NOW)
        self.assertEqual("update", d.action)

    def test_fresh_pool_stale_health_wants_probe(self):
        d = freshness_watch.decide(_doc(30), _doc(120), now=NOW)
        self.assertEqual("probe", d.action)

    def test_fresh_pool_missing_health_wants_probe(self):
        d = freshness_watch.decide(_doc(30), None, now=NOW)
        self.assertEqual("probe", d.action)

    def test_pool_republished_after_last_measurement_wants_probe(self):
        # Both are young, but the pool is newer than the health index: the
        # current pool has not been measured yet.
        d = freshness_watch.decide(_doc(20), _doc(40), now=NOW)
        self.assertEqual("probe", d.action)

    def test_health_newer_than_pool_is_noop(self):
        d = freshness_watch.decide(_doc(40), _doc(20), now=NOW)
        self.assertEqual("none", d.action)

    def test_exact_stale_boundary_is_not_stale(self):
        # 180 min pool / 90 min health: "> limit" is strict, a healthy run
        # landing exactly on the boundary must not trigger a duplicate.
        d = freshness_watch.decide(_doc(180), _doc(90), now=NOW)
        self.assertEqual("none", d.action)


class TestLoad(unittest.TestCase):
    def test_missing_path_is_none(self):
        self.assertIsNone(freshness_watch.load(None))
        self.assertIsNone(freshness_watch.load("/nonexistent/does-not-exist.json"))


if __name__ == "__main__":
    unittest.main()
