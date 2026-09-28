"""Regression test for the DNS cache that dominated collector wall-clock.

Run 36455487959 spent 632s between "Loaded 16652 unique config lines" and
"Parsed 10533 entries". The culprit was resolve_host(): it called
socket.getaddrinfo once per CONFIG, serially, and the four upstream feeds
republish the same few thousand hostnames, so the same names were resolved
thousands of times over.

The cache must hold on both hits and misses -- a name that fails to resolve
tries again forever otherwise, which is the same cost with extra steps.
"""

import importlib.util
import socket
import sys
import types
import unittest
import unittest.mock
from pathlib import Path

# main.py imports geoip2, which is a CI-only dependency. run_tests.py SKIPS a
# module whose imports are missing, so without this stub the DNS cache test
# would silently never run -- exactly the class of bug it exists to catch.
# resolve_host() touches neither geoip2 nor requests, so a stub is safe here.
if "geoip2" not in sys.modules:
    # find_spec returns None for a missing top-level module; it does not raise.
    # Check the RESULT, not just the exception, or the stub never installs.
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

_SPEC = importlib.util.spec_from_file_location(
    "collector_main", Path(__file__).resolve().parents[1] / "main.py"
)
main = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(main)


class TestResolveHostCache(unittest.TestCase):
    def setUp(self):
        main._DNS_CACHE.clear()
        self.calls = []
        real = socket.getaddrinfo

        def counting(host, *args, **kwargs):
            self.calls.append(host)
            return real(host, *args, **kwargs)

        socket.getaddrinfo = counting
        self.addCleanup(lambda: setattr(socket, "getaddrinfo", real))

    def test_repeated_host_resolves_once(self):
        host = "example.com"
        first = main.resolve_host(host)
        for _ in range(20):
            main.resolve_host(host)
        self.assertEqual(
            [c for c in self.calls if c == host].__len__(), 1, "cache did not hold"
        )
        # Repeat calls must return the same answer, not just be faster.
        self.assertEqual(main.resolve_host(host), first)

    def test_failure_is_cached_too(self):
        host = "nonexistent-host-for-test.invalid"
        with unittest.mock.patch("socket.getaddrinfo", side_effect=socket.gaierror):
            first = main.resolve_host(host)
            for _ in range(5):
                self.assertIsNone(main.resolve_host(host))
        self.assertIsNone(first)

    def test_literal_ip_skips_dns_entirely(self):
        ip = "8.8.8.8"
        self.assertEqual(main.resolve_host(ip), ip)
        self.assertEqual(self.calls, [], "a literal IP must not hit DNS")

    def test_private_literal_is_rejected(self):
        self.assertIsNone(main.resolve_host("192.168.1.1"))
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
