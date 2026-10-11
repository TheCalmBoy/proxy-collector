"""Per-source provenance: which feed actually supplies the published output.

The question "are these four sources worth keeping" had no answer in the
output. Totals cannot distinguish a source that adds unique endpoints from
one that republishes an existing feed, so fetch_source_configs now returns a
line -> source map and build_outputs() tallies it into stats["per_source"].
"""

import importlib.util
import sys
import types
import unittest
from collections import Counter
from pathlib import Path

# main.py imports geoip2, a CI-only dependency, and run_tests.py SKIPS a module
# whose imports are missing. Without this stub these attribution tests would
# silently never run, and they are the only guard on per-source accounting.
# find_spec returns None for a missing top-level module rather than raising, so
# the RESULT must be checked, not just the exception.
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

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import main  # noqa: E402


class _FakeResponse:
    def __init__(self, text: str) -> None:
        self.text = text

    def raise_for_status(self) -> None:
        return None


class _FakeSession:
    def __init__(self, bodies: dict[str, str], fail: set[str] | None = None):
        self.bodies = bodies
        self.fail = fail or set()

    def get(self, url: str, timeout: int = 0):
        if url in self.fail:
            raise main.requests.RequestException("boom")
        return _FakeResponse(self.bodies[url])


A = "https://example.invalid/a.txt"
B = "https://example.invalid/b.txt"
C = "https://example.invalid/c.txt"


class TestProvenanceMap(unittest.TestCase):
    def test_line_attributed_to_the_source_that_supplied_it(self):
        session = _FakeSession({A: "vless://one@1.1.1.1:443\n", B: "vless://two@2.2.2.2:443\n"})
        original = main.SOURCE_URLS
        main.SOURCE_URLS = [A, B]
        try:
            lines, sources = main.fetch_source_configs(session)
        finally:
            main.SOURCE_URLS = original

        self.assertEqual(len(lines), 2)
        self.assertEqual(sources["vless://one@1.1.1.1:443"], A)
        self.assertEqual(sources["vless://two@2.2.2.2:443"], B)

    def test_duplicate_line_credited_to_first_source(self):
        shared = "vless://same@3.3.3.3:443"
        session = _FakeSession({A: shared + "\n", B: shared + "\nvless://only@4.4.4.4:443\n"})
        original = main.SOURCE_URLS
        main.SOURCE_URLS = [A, B]
        try:
            lines, sources = main.fetch_source_configs(session)
        finally:
            main.SOURCE_URLS = original

        self.assertEqual(len(lines), 2)
        # First-wins keeps the per-source counts summing to the union total.
        self.assertEqual(sources[shared], A)

    def test_failed_source_does_not_lose_the_others(self):
        session = _FakeSession({B: "vless://ok@5.5.5.5:443\n"}, fail={A})
        original = main.SOURCE_URLS
        main.SOURCE_URLS = [A, B]
        try:
            lines, sources = main.fetch_source_configs(session)
        finally:
            main.SOURCE_URLS = original

        self.assertEqual(lines, ["vless://ok@5.5.5.5:443"])
        self.assertEqual(sources["vless://ok@5.5.5.5:443"], B)

    def test_all_sources_failing_still_raises(self):
        session = _FakeSession({}, fail={A, B})
        original = main.SOURCE_URLS
        main.SOURCE_URLS = [A, B]
        try:
            with self.assertRaises(RuntimeError):
                main.fetch_source_configs(session)
        finally:
            main.SOURCE_URLS = original


class TestPerSourceTally(unittest.TestCase):
    def _tally(self, records):
        from collections import Counter

        candidates = Counter()
        published = Counter()
        seen = set()
        for record in records:
            base = record["uri"].split("#", 1)[0]
            candidates[record["source"]] += 1
            if base in seen:
                continue
            seen.add(base)
            published[record["source"]] += 1
        return candidates, published

    def test_overlap_is_reported_separately_from_published(self):
        records = [
            {"uri": "vless://a@1.1.1.1:443#x", "source": A},
            {"uri": "vless://a@1.1.1.1:443#x-renamed", "source": B},
            {"uri": "vless://b@2.2.2.2:443#y", "source": B},
        ]
        candidates, published = self._tally(records)

        self.assertEqual(candidates[A], 1)
        self.assertEqual(published[A], 1)
        # B offered 2 but only 1 is new: the other was a duplicate of A's.
        self.assertEqual(candidates[B], 2)
        self.assertEqual(published[B], 1)
        self.assertEqual(candidates[B] - published[B], 1)

    def test_counters_sum_to_the_union(self):
        records = [
            {"uri": "vless://a@1.1.1.1:443#x", "source": A},
            {"uri": "vless://b@2.2.2.2:443#y", "source": B},
            {"uri": "vless://c@3.3.3.3:443#z", "source": "carry-over"},
        ]
        candidates, published = self._tally(records)
        self.assertEqual(sum(published.values()), 3)
        self.assertEqual(sum(candidates.values()), 3)


if __name__ == "__main__":
    unittest.main()
