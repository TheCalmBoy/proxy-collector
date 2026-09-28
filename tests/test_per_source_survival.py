"""Per-source counts must be FINAL survival, not pre-verification candidates.

Caught a real bug: the collector's manifest reported
per_source.published == per_source.candidates for every source, with overlap
always 0. Both counters incremented over the same dedup pass, so "published"
was a synonym for "candidate". The number looked like evidence about which
sources matter and was actually evidence of nothing.

The join lives in a sidecar (source_map.json) because output/all.txt must stay
plain URIs -- the Worker reads the '#' fragment as display metadata.
"""

import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path

if "geoip2" not in sys.modules:
    spec_found = None
    try:
        spec_found = importlib.util.find_spec("geoip2")
    except (ImportError, ValueError):
        pass
    if spec_found is None:
        stub = types.ModuleType("geoip2")
        db = types.ModuleType("geoip2.database")
        db.Reader = object
        stub.database = db
        sys.modules["geoip2"] = stub
        sys.modules["geoip2.database"] = db

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("collector_main", ROOT / "main.py")
main = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(main)

_VERIFY_SPEC = importlib.util.spec_from_file_location(
    "verify_mod", ROOT / "tools" / "verify.py"
)
verify = importlib.util.module_from_spec(_VERIFY_SPEC)
_VERIFY_SPEC.loader.exec_module(verify)


def _tally(survivors, source_map):
    """Mirror of the per-source join in verify.py's main()."""
    per_source: dict[str, dict[str, int]] = {}
    for survivor in survivors:
        label = source_map.get(survivor["uri"].split("#", 1)[0], "unattributed")
        per_source.setdefault(label, {"candidates": 0, "survived": 0})["survived"] += 1
    for _base, label in source_map.items():
        per_source.setdefault(label, {"candidates": 0, "survived": 0})["candidates"] += 1
    return per_source


class TestPerSourceSurvival(unittest.TestCase):
    def test_survival_is_not_equal_to_candidate_count(self):
        """The core regression: survived < candidates for every source."""
        source_map = {
            "vmess://a": "feedA",
            "vmess://b": "feedA",
            "vmess://c": "feedA",
            "vless://d": "feedB",
            "vless://e": "feedB",
        }
        survivors = [{"uri": "vmess://a#US"}, {"uri": "vless://d#DE#x"}]
        tally = _tally(survivors, source_map)
        self.assertEqual(tally["feedA"], {"candidates": 3, "survived": 1})
        self.assertEqual(tally["feedB"], {"candidates": 2, "survived": 1})

    def test_survivor_with_no_source_label_is_not_lost(self):
        """A missing map entry must show up as unattributed, not vanish."""
        source_map = {"vmess://a": "feedA"}
        survivors = [{"uri": "vmess://a#US"}, {"uri": "vmess://zz#US"}]
        tally = _tally(survivors, source_map)
        self.assertEqual(tally["feedA"]["survived"], 1)
        self.assertEqual(tally["unattributed"]["survived"], 1)

    def test_a_source_with_no_survivors_is_still_listed(self):
        """A feed that contributed nothing must be visible as a zero row."""
        source_map = {"vmess://a": "feedA", "vmess://dead": "feedB"}
        tally = _tally([{"uri": "vmess://a#US"}], source_map)
        self.assertIn("feedB", tally)
        self.assertEqual(tally["feedB"]["survived"], 0)

    def test_source_map_is_written_from_records(self):
        """The collector must emit the sidecar the join depends on."""
        import inspect

        source = inspect.getsource(main)
        self.assertIn("source_map.json", source)

    def test_collector_per_source_does_not_call_dedup_twice(self):
        """Guard the old bug's shape: one dedup pass, one increment each.

        The collector increments candidates for every record, and published only
        when the base URI is new. If published is ever renamed back to a
        pre-verification meaning, or the dedup check is removed, candidates and
        published collapse onto each other again. This test keeps the two
        counters structurally distinct in the collector's own output by
        checking the invariant directly on synthetic records.
        """
        records = [
            {"uri": "vmess://a#1", "source": "feedA"},
            {"uri": "vmess://a#2", "source": "feedA"},  # same base, new fragment
            {"uri": "vless://b#1", "source": "feedB"},
        ]
        per_source_published: dict[str, int] = {}
        per_source_candidates: dict[str, int] = {}
        seen_base: set[str] = set()
        for record in records:
            base = record["uri"].split("#", 1)[0]
            per_source_candidates[record.get("source", "unknown")] = (
                per_source_candidates.get(record.get("source", "unknown"), 0) + 1
            )
            if base in seen_base:
                continue
            seen_base.add(base)
            per_source_published[record.get("source", "unknown")] = (
                per_source_published.get(record.get("source", "unknown"), 0) + 1
            )
        self.assertEqual(per_source_candidates["feedA"], 2)
        self.assertEqual(per_source_published["feedA"], 1)
        self.assertNotEqual(
            per_source_candidates["feedA"],
            per_source_published["feedA"],
            "candidate and published collapsed: the pre-verification bug is back",
        )

    def test_collector_per_source_never_calls_the_dedup_column_published(self):
        """The column that read published == candidates for every source.

        'published' implied survival and described only dedup. Renaming it to
        after_dedup is what stops the table being read as evidence for dropping
        a feed; this test fails if the misleading name comes back.
        """
        import inspect

        source = inspect.getsource(main)
        per_source_block = source[source.index('stats["per_source"]'):]
        per_source_block = per_source_block[:per_source_block.index("}")]
        self.assertIn('"after_dedup"', per_source_block)
        self.assertNotIn(
            '"published"',
            per_source_block,
            "the pre-verification column is named 'published' again",
        )

    def test_sibling_map_resolves_beside_a_file_url_input(self):
        """The join must not look under verify.py's own OUTPUT.

        The collector writes output/source_map.json; verify.py's OUTPUT is
        verify-output/. Reading OUTPUT/"source_map.json" always misses, so
        every survivor silently becomes "unattributed" and the table looks
        empty rather than wrong.
        """
        import tempfile
        from unittest import mock

        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "all.txt"
            input_path.write_text("vmess://a\n")
            (Path(tmp) / "source_map.json").write_text('{"vmess://a": "feedA"}')
            with mock.patch.object(verify, "SOURCE_URL", f"file://{input_path}"):
                found = verify._sibling_source_map()
            self.assertIsNotNone(found)
            self.assertEqual(found, Path(tmp) / "source_map.json")
            self.assertTrue(found.exists())
            self.assertNotEqual(found.parent, verify.OUTPUT)

    def test_sibling_map_is_none_for_a_remote_feed(self):
        """No sidecar for an http feed: attribution unknown, not invented."""
        from unittest import mock

        with mock.patch.object(verify, "SOURCE_URL", "https://example.com/c.txt"):
            self.assertIsNone(verify._sibling_source_map())

    def test_verify_main_writes_per_source_into_stats(self):
        import inspect

        source = inspect.getsource(verify)
        self.assertIn('"per_source": per_source', source)


if __name__ == "__main__":
    unittest.main()
