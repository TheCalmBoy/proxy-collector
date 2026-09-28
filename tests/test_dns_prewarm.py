"""Concurrent DNS pre-warm must fill the cache before the parse loop runs.

The memoizing cache in test_dns_cache.py fixed duplicate lookups but left the
FIRST lookup per host serial: run 36459022405 still spent 437s inside the
parse phase for ~4000 distinct names, because getaddrinfo blocks and the loop
held one at a time. prewarm_dns() resolves them on a thread pool first.
"""

import importlib.util
import socket
import sys
import threading
import time
import types
import unittest
import unittest.mock
from pathlib import Path

# geoip2 is a CI-only dependency and run_tests.py SKIPS a module whose imports
# are missing, so without this stub the pre-warm tests would silently never run.
# find_spec returns None for a missing top-level module instead of raising, so
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

_SPEC = importlib.util.spec_from_file_location(
    "collector_main_pwarm", Path(__file__).resolve().parents[1] / "main.py"
)
main = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(main)


class TestPrewarmDns(unittest.TestCase):
    def setUp(self):
        main._DNS_CACHE.clear()
        self.calls = []
        real = socket.getaddrinfo

        def counting(host, *args, **kwargs):
            self.calls.append(host)
            return real(host, *args, **kwargs)

        socket.getaddrinfo = counting
        self.addCleanup(lambda: setattr(socket, "getaddrinfo", real))

    def test_prewarm_resolves_every_distinct_host(self):
        hosts = [f"p{i}.invalid-dns-prewarm-test" for i in range(12)]
        submitted = main.prewarm_dns(hosts, workers=4)
        self.assertEqual(submitted, len(hosts))
        # Every host is now cached, so the parse loop's resolve_host() is free.
        for host in hosts:
            self.assertIn(host, main._DNS_CACHE)

    def test_prewarm_deduplicates_repeated_hosts(self):
        host = "dup.invalid-dns-prewarm-test"
        submitted = main.prewarm_dns([host] * 25, workers=4)
        self.assertEqual(submitted, 1, "a repeated host was submitted twice")
        self.assertEqual([c for c in self.calls if c == host].__len__(), 1)

    def test_second_prewarm_is_a_noop(self):
        hosts = [f"q{i}.invalid-dns-prewarm-test" for i in range(6)]
        main.prewarm_dns(hosts, workers=4)
        self.assertEqual(main.prewarm_dns(hosts, workers=4), 0)

    def test_prewarm_runs_concurrently_not_serially(self):
        """The whole point: overlapping blocking lookups, not stacking them."""
        barrier_delay = 0.05
        inflight = 0
        peak = 0
        lock = threading.Lock()
        real = socket.getaddrinfo

        def slow(host, *args, **kwargs):
            nonlocal inflight, peak
            with lock:
                inflight += 1
                peak = max(peak, inflight)
            try:
                return real(host, *args, **kwargs)
            finally:
                time.sleep(barrier_delay)
                with lock:
                    inflight -= 1

        socket.getaddrinfo = slow
        self.addCleanup(lambda: setattr(socket, "getaddrinfo", real))

        hosts = [f"r{i}.invalid-dns-prewarm-test" for i in range(8)]
        started = time.monotonic()
        main.prewarm_dns(hosts, workers=8)
        elapsed = time.monotonic() - started

        self.assertGreater(peak, 1, "lookups never overlapped: this is serial")
        # Serial would be >= 8 * delay. Anything near one delay proves overlap.
        self.assertLess(elapsed, 8 * barrier_delay * 0.75)

    def test_failed_lookups_are_cached_as_misses(self):
        """A name that fails must not be retried once per config."""
        attempts = []
        real = socket.getaddrinfo

        def always_fails(host, *args, **kwargs):
            attempts.append(host)
            raise socket.gaierror("nope")

        socket.getaddrinfo = always_fails
        self.addCleanup(lambda: setattr(socket, "getaddrinfo", real))

        host = "nx.invalid-dns-prewarm-test"
        main.prewarm_dns([host], workers=2)
        for _ in range(10):
            main.resolve_host(host)
        self.assertEqual(len(attempts), 1, "a cached miss was re-looked-up")


if __name__ == "__main__":
    unittest.main()
