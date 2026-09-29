"""Tests for the country-consistency join.

The whole point of the tool is a join between two documents whose ids are NOT
the same function: the feed carries an 8-char fragment id and the health index
keys on something else entirely. On live data their intersection is empty, so
a fixture that keys both sides identically -- the default mistake -- makes the
tool look correct while it reports 0 mismatches and 0 joins in production.

These tests pin the two behaviours that must survive refactors:

  1. the join is on (server, port), and it works when the ids are disjoint;
  2. a disagreement is counted, not silently dropped.
"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "country_consistency", Path(__file__).resolve().parents[1] / "tools" / "country_consistency.py"
)
cc = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cc)


def write(tmp: Path, feed: str, health: dict) -> tuple[Path, Path]:
    f, h = tmp / "all.txt", tmp / "health.json"
    f.write_text(feed, encoding="utf-8")
    h.write_text(json.dumps(health), encoding="utf-8")
    return f, h


class TestParseEndpoint(unittest.TestCase):
    def test_reads_host_and_port(self):
        self.assertEqual(
            cc.parse_endpoint("trojan://pw@ge.example:443?sni=x#DE-DC-AS1-AAAA1111"),
            ("ge.example", 443),
        )

    def test_lowercases_host(self):
        self.assertEqual(cc.parse_endpoint("vmess://x@UPPER.Example:80#"), ("upper.example", 80))

    def test_returns_none_without_at_sign(self):
        self.assertIsNone(cc.parse_endpoint("notaproxy"))


class TestIndexHealth(unittest.TestCase):
    def test_indexes_on_endpoint_not_id(self):
        idx = cc.index_health(
            {"configs": {"SOMEOTHERKEY": {"server": "a.example", "server_port": 443}}}
        )
        self.assertIn(("a.example", 443), idx)

    def test_skips_rows_without_endpoint(self):
        idx = cc.index_health({"configs": {"K": {"server": "", "server_port": 443}}})
        self.assertEqual(idx, {})


class TestReport(unittest.TestCase):
    def test_counts_disjoint_id_disagreement(self):
        # Feed fragment id and health key share nothing, exactly as on live data.
        feed = "trojan://pw@ge.example:443?sni=ge.example#DE-DC-AS0-FEED0001\n"
        health = {
            "configs": {
                "HEALTHKEY1": {
                    "server": "ge.example",
                    "server_port": 443,
                    "primary_country": "GB",
                }
            }
        }
        with tempfile.TemporaryDirectory() as d:
            f, h = write(Path(d), feed, health)
            self.assertEqual(cc.report(f, h, max_mismatch=0.10), 1)

    def test_agreeing_country_passes(self):
        feed = "trojan://pw@de.example:443?sni=de.example#DE-DC-AS0-FEED0001\n"
        health = {
            "configs": {
                "HEALTHKEY1": {
                    "server": "de.example",
                    "server_port": 443,
                    "primary_country": "DE",
                }
            }
        }
        with tempfile.TemporaryDirectory() as d:
            f, h = write(Path(d), feed, health)
            self.assertEqual(cc.report(f, h, max_mismatch=0.10), 0)

    def test_unjoinable_feed_does_not_fail_the_run(self):
        # 22/151 live configs never join. That is a known publication skew, not
        # a country regression, so it must not be counted as a mismatch.
        feed = "trojan://pw@missing.example:443#DE-DC-AS0-FEED0001\n"
        health = {"configs": {"HEALTHKEY1": {"server": "other.example", "server_port": 443,
                                            "primary_country": "GB"}}}
        with tempfile.TemporaryDirectory() as d:
            f, h = write(Path(d), feed, health)
            self.assertEqual(cc.report(f, h, max_mismatch=0.10), 0)


if __name__ == "__main__":
    unittest.main()
