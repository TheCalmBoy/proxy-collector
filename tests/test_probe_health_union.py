"""Rolling union: the health index must survive a thin or skipped probe run.

The probe measures whatever pool exists at its own cron moment and previously
rewrote egress-health.json from scratch. When the pool churns (or GitHub
skips the run that would have refreshed it), the index drifts out of sync
with the feed and the worker's (server, port) join drops every config the
index missed - the served subscription visibly shrank for hours.

merge_previous_health() carries forward previously-measured rows that are
still in this run's pool, always letting this run's measurements win.
"""

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import probe_egress  # noqa: E402


def _row(rid: str, hours_old: float = 0.0) -> dict:
    ts = (datetime.now(timezone.utc) - timedelta(hours=hours_old)).isoformat()
    return {
        "scheme": "vless",
        "server": f"{rid}.example",
        "server_port": 443,
        "classification": {"type": "stable", "country": "DE"},
        "download_mb_s": 20.0,
        "gemini": {"status": "unknown", "clean": True, "flagged": False, "rounds": 0},
        "ip_count": 1,
        "unique_ips": [f"10.0.0.{rid[-1] if rid[-1].isdigit() else '1'}"],
        "ip_family": "v4",
        "primary_country": "DE",
        "updated_at": ts,
    }


def _prev(*rids: str, hours_old: float = 0.0) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "configs": {r: _row(r, hours_old) for r in rids},
    }


class TestHealthUnion(unittest.TestCase):
    def test_previous_row_in_pool_is_carried_when_missing_from_measured(self):
        measured = {}
        merged, carried = probe_egress.merge_previous_health(
            _prev("AAAA1111"), measured, pool_ids={"AAAA1111", "BBBB2222"}
        )
        self.assertEqual(1, carried)
        self.assertEqual("DE", merged["AAAA1111"]["primary_country"])

    def test_fresh_measurement_beats_stale_previous_row(self):
        # The previous row claims US; this run re-measured and it's DE.
        stale = _prev("AAAA1111", hours_old=3)
        stale["configs"]["AAAA1111"]["primary_country"] = "US"
        measured = {"AAAA1111": _row("AAAA1111")}
        merged, carried = probe_egress.merge_previous_health(
            stale, measured, pool_ids={"AAAA1111"}
        )
        self.assertEqual(0, carried, "fresh measurement must not count as carry-over")
        self.assertEqual("DE", merged["AAAA1111"]["primary_country"])

    def test_previous_row_left_the_pool_is_dropped(self):
        # A config that is no longer in the pool is not in the feed either,
        # so dropping its row is correct, not loss.
        merged, carried = probe_egress.merge_previous_health(
            _prev("GONE0001"), {}, pool_ids={"KEPT0002"}
        )
        self.assertEqual(0, carried)
        self.assertNotIn("GONE0001", merged)

    def test_rows_older_than_24h_are_not_carried(self):
        merged, carried = probe_egress.merge_previous_health(
            _prev("OLD00001", hours_old=25), {}, pool_ids={"OLD00001"}
        )
        self.assertEqual(0, carried)

    def test_missing_previous_index_is_a_noop(self):
        merged, carried = probe_egress.merge_previous_health(
            None, {"KEPT0002": _row("KEPT0002")}, pool_ids={"KEPT0002"}
        )
        self.assertEqual(0, carried)
        self.assertEqual({"KEPT0002"}, set(merged))

    def test_malformed_previous_index_is_a_noop(self):
        for bad in ({}, {"configs": "not-a-dict"}, {"configs": {"X": "not-a-row"}}):
            merged, carried = probe_egress.merge_previous_health(
                bad, {"KEPT0002": _row("KEPT0002")}, pool_ids={"KEPT0002"}
            )
            self.assertEqual(0, carried, f"bad previous shape {bad!r} must not carry")
            self.assertEqual({"KEPT0002"}, set(merged))

    def test_mixed_pool_keeps_both_fresh_and_carried_rows(self):
        prev = _prev("A1111111", "B2222222")
        measured = {"A1111111": _row("A1111111")}  # re-measured this run
        merged, carried = probe_egress.merge_previous_health(
            prev, measured, pool_ids={"A1111111", "B2222222"}
        )
        self.assertEqual(1, carried)
        self.assertEqual(2, len(merged))
        # the carried row is the previous one, untouched
        self.assertEqual(prev["configs"]["B2222222"], merged["B2222222"])


if __name__ == "__main__":
    unittest.main()
