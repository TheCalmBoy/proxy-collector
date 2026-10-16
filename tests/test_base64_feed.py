"""Base64-only upstreams are decoded before the per-line dedup -- and nothing else is.

Some feeds publish only a base64 sibling, with no plain URI list, so the feed
body is sniffed and decoded. Sniffing the WHOLE body matters: an HTML or JSON
error page must never be decoded into noise, because that would look like a
source that returned nothing rather than a source that was never readable.
"""

import base64
import importlib.util
import sys
import types
import unittest
from pathlib import Path

# main.py imports geoip2, a CI-only dependency, and run_tests.py SKIPS a module
# whose imports are missing. Without this stub these tests would silently never
# run. find_spec returns None for a missing top-level module rather than raising,
# so the RESULT must be checked, not just the exception.
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

PLAIN = "vless://one@1.1.1.1:443\nvmess://two@2.2.2.2:443\n"


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


class _FakeResponse:
    def __init__(self, text: str) -> None:
        self.text = text

    def raise_for_status(self) -> None:
        return None


class _FakeSession:
    def __init__(self, bodies: dict[str, str]):
        self.bodies = bodies

    def get(self, url: str, timeout: int = 0):
        return _FakeResponse(self.bodies[url])


class TestDecodeBase64Feed(unittest.TestCase):
    def test_base64_only_body_is_decoded(self):
        self.assertEqual(main.decode_base64_feed(_b64(PLAIN)), PLAIN)

    def test_plain_body_is_returned_unchanged(self):
        self.assertEqual(main.decode_base64_feed(PLAIN), PLAIN)

    def test_html_error_page_is_not_decoded(self):
        html = "<html><body>404 not found</body></html>"
        self.assertEqual(main.decode_base64_feed(html), html)

    def test_json_error_page_is_not_decoded(self):
        body = '{"error":"rate limited"}'
        self.assertEqual(main.decode_base64_feed(body), body)

    def test_prose_before_base64_is_not_decoded(self):
        # One prose line means the body is not pure base64. Decoding it anyway
        # yields noise instead of the configs it wraps.
        body = "Refresh: 6h\n" + _b64(PLAIN)
        self.assertEqual(main.decode_base64_feed(body), body)


class TestFetchSourceConfigsIngestsBase64(unittest.TestCase):
    def test_base64_feed_lines_reach_the_union(self):
        url = "https://example.invalid/b64.txt"
        original = main.SOURCE_URLS
        main.SOURCE_URLS = [url]
        try:
            lines, sources = main.fetch_source_configs(_FakeSession({url: _b64(PLAIN)}))
        finally:
            main.SOURCE_URLS = original

        self.assertEqual(lines, [line for line in PLAIN.splitlines() if line])
        self.assertEqual(sources["vless://one@1.1.1.1:443"], url)

    def test_plain_feed_is_unaffected(self):
        url = "https://example.invalid/plain.txt"
        original = main.SOURCE_URLS
        main.SOURCE_URLS = [url]
        try:
            lines, _ = main.fetch_source_configs(_FakeSession({url: PLAIN}))
        finally:
            main.SOURCE_URLS = original

        self.assertEqual(lines, [line for line in PLAIN.splitlines() if line])


if __name__ == "__main__":
    unittest.main()
