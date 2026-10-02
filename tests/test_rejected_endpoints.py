"""Rejected-endpoint denylist: stop re-testing confirmed-rotating endpoints.

The probe rejects configs whose egress rotates across countries or that
never return an IP; the worker drops them on the missing health row. Before
this, the pipeline re-ran Stages 1-3 on them every 30 min, only to have the
probe reject them again. Now the probe publishes `rejected-endpoints.json`
and verify.py prunes the matching (server, port) before any network testing,
with a 48h TTL so a reject ages out instead of blacklisting forever.

Two safe-by-design invariants this suite pins:
  * only CONFIRMED rejects (rotating egress) are recorded - "no IP at all"
    is NOT, because that conflates a dead proxy with a saturated runner.
  * the TTL drops a stale reject so it gets re-tested.
"""

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import probe_egress  # noqa: E402
import verify  # noqa: E402


def _entry(server="1.2.3.4", port=443, hours_old=0.0) -> dict:
    ts = datetime.now(timezone.utc) - timedelta(hours=hours_old)
    return {
        "server": server,
        "server_port": port,
        "scheme": "vless",
        "reason": "egress-dynamic-mixed",
        "rejected_at": ts.isoformat(),
    }


def _write(tmp_dir, entry_list):
    p = Path(tmp_dir) / "rejected-endpoints.json"
    p.write_text(json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(),
                             "endpoints": entry_list}))
    return p


class TestLoadRejectedEndpoints(unittest.TestCase):
    def test_missing_file_is_empty_set(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(
                verify.load_rejected_endpoints(Path(d) / "nope.json"), set())

    def test_corrupt_file_is_empty_set(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "rejected-endpoints.json"
            p.write_text("not json{{")
            self.assertEqual(verify.load_rejected_endpoints(p), set())

    def test_entry_returns_endpoint_key(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, [_entry("9.8.7.6", 8443)])
            self.assertEqual(verify.load_rejected_endpoints(p),
                             {("9.8.7.6", 8443)})

    def test_malformed_entry_is_ignored_not_trusted(self):
        with tempfile.TemporaryDirectory() as d:
            entries = [
                {"server": "good.example", "server_port": 443,
                 "rejected_at": datetime.now(timezone.utc).isoformat()},
                {"server": "bad"},                                   # no port
                {"server": 42, "server_port": 443},                  # server not str
                {"server_port": 443},                                 # no server
                {"server": "badport.example", "server_port": "not-a-number",
                 "rejected_at": datetime.now(timezone.utc).isoformat()},  # port not int
            ]
            p = _write(d, entries)
            # Only the fully-valid entry survives.
            self.assertEqual(verify.load_rejected_endpoints(p),
                             {("good.example", 443)})

    def test_entry_past_ttl_is_dropped(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, [_entry("old.example", 443, hours_old=49)])
            self.assertEqual(verify.load_rejected_endpoints(p,
                                                            ttl_hours=48), set())

    def test_entry_within_ttl_is_kept(self):
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, [_entry("fresh.example", 443, hours_old=1)])
            self.assertEqual(verify.load_rejected_endpoints(p,
                                                            ttl_hours=48),
                             {("fresh.example", 443)})

    def test_entry_without_timestamp_is_treated_as_in_force(self):
        # A malformed stamp degrades to "still on the list", never to "skip
        # the wrong endpoint" - the probe wrote it, so trust it.
        with tempfile.TemporaryDirectory() as d:
            p = _write(d, [dict(_entry("nostamp.example", 443),
                                rejected_at="garbage")])
            # "garbage" is not ISO-8601 -> parsed as None -> not aged out.
            self.assertEqual(verify.load_rejected_endpoints(p),
                             {("nostamp.example", 443)})


class _FakeConfig:
    """Minimal stand-in for the sing-box config dict."""


def _mini_config(kept_ids):
    return {
        "inbounds": [{"tag": f"in-{i}"} for i in kept_ids],
        "outbounds": [{"tag": f"proxy-{i}"} for i in kept_ids],
        "route": {"final": "direct",
                  "rules": [{"inbound": [f"in-{i}"], "action": "route",
                             "outbound": f"proxy-{i}"} for i in kept_ids]},
    }


def _record(rid, server, port, scheme="vless"):
    return {"id": rid, "scheme": scheme, "server": server,
            "server_port": port, "port": 15000}


class TestFilterRejectedEndpoints(unittest.TestCase):
    def test_empty_rejected_is_noop(self):
        cfg = _mini_config({"A", "B"})
        recs = [_record("A", "1.1.1.1", 443), _record("B", "2.2.2.2", 80)]
        c2, r2 = verify.filter_rejected_endpoints(cfg, recs, set())
        self.assertIs(c2, cfg)
        self.assertIs(r2, recs)

    def test_rejected_endpoint_is_pruned_from_all_lists(self):
        cfg = _mini_config({"A", "B", "C"})
        recs = [_record("A", "bad.example", 443),
                _record("B", "good.example", 443),
                _record("C", "also-good", 80)]
        c2, r2 = verify.filter_rejected_endpoints(cfg, recs,
                                                  {("bad.example", 443)})
        self.assertEqual({r["id"] for r in r2}, {"B", "C"})
        # Order-insensitive: the filter preserves record order, not tag order,
        # and a leftover rule is the real hazard, so membership is the check.
        self.assertCountEqual([ib["tag"] for ib in c2["inbounds"]],
                              ["in-B", "in-C"])
        # The route rule for the removed endpoint must be gone, else sing-box
        # refuses to start.
        self.assertEqual({r["inbound"][0] for r in c2["route"]["rules"]},
                         {"in-B", "in-C"})

    def test_port_mismatch_is_not_pruned(self):
        # Same server, different port -> a different endpoint -> not dropped.
        cfg = _mini_config({"A"})
        recs = [_record("A", "same.example", 443)]
        c2, r2 = verify.filter_rejected_endpoints(cfg, recs,
                                                  {("same.example", 8443)})
        self.assertEqual({r["id"] for r in r2}, {"A"})

    def test_port_is_coerced_from_string(self):
        cfg = _mini_config({"A"})
        recs = [_record("A", "x.example", "443")]  # port as a string
        c2, r2 = verify.filter_rejected_endpoints(cfg, recs,
                                                  {("x.example", 443)})
        self.assertEqual({r["id"] for r in r2}, set())


def _mk_record(**kw):
    # Real probe records are plain dicts; _record_reject uses .get().
    return kw


class TestProbeMergeRejected(unittest.TestCase):
    def test_current_wins_and_stale_is_dropped(self):
        prev = {"1.1.1.1:443": _entry("1.1.1.1", 443, hours_old=60)}
        current = {"2.2.2.2:443": _entry("2.2.2.2", 443)}
        merged = probe_egress.merge_rejected(prev, current, ttl_hours=48)
        # stale (60h) previous entry is dropped; current is kept.
        self.assertEqual(set(merged), {"2.2.2.2:443"})

    def test_fresh_previous_is_carried_when_not_re_rejected(self):
        prev = {"1.1.1.1:443": _entry("1.1.1.1", 443, hours_old=2)}
        merged = probe_egress.merge_rejected(prev, {}, ttl_hours=48)
        # A recent reject that was not re-measured this run stays out.
        self.assertEqual(set(merged), {"1.1.1.1:443"})

    def test_re_recorded_this_run_freshens_stamp(self):
        prev = {"1.1.1.1:443": _entry("1.1.1.1", 443, hours_old=2)}
        current = {"1.1.1.1:443": _entry("1.1.1.1", 443, hours_old=0)}
        merged = probe_egress.merge_rejected(prev, current, ttl_hours=48)
        # current's fresh stamp wins -> well within TTL.
        self.assertEqual(merged["1.1.1.1:443"]["rejected_at"],
                         current["1.1.1.1:443"]["rejected_at"])

    def test_current_entry_with_bad_port_is_not_recorded(self):
        # A record with no resolvable endpoint must not produce a denylist
        # entry - verify.py matches on (server, port) exactly.
        rbad = _mk_record(id="X", scheme="vless", server=None, server_port=443)
        probeset: dict = {}
        probe_egress._record_reject(probeset, {"X": rbad}, "X", "egress-dynamic-mixed")
        self.assertEqual(probeset, {})

    def test_record_reject_stores_endpoint(self):
        good = _mk_record(id="Y", scheme="vless", server="5.6.7.8",
                       server_port=8443)
        probeset: dict = {}
        probe_egress._record_reject(probeset, {"Y": good}, "Y",
                                    "egress-dynamic-mixed")
        self.assertIn("5.6.7.8:8443", probeset)
        self.assertEqual(probeset["5.6.7.8:8443"]["server"], "5.6.7.8")
        self.assertEqual(probeset["5.6.7.8:8443"]["server_port"], 8443)


if __name__ == "__main__":
    unittest.main()
