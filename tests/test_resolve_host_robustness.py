#!/usr/bin/env python3
"""A malformed host must never abort a run.

Measured: a nine-feed measurement run died inside `Run collector` with
UnicodeEncodeError from socket.getaddrinfo -- one upstream line carried a server
field whose DNS label was over the 63 character limit, and other feeds carry
non-ASCII hosts. resolve_host runs inside a thread pool, so the exception
propagated out of fut.result() and took the whole run with it: 20k candidates
in, zero output out.

resolve_host() needs neither geoip2 nor requests, so the same stub the DNS cache
test uses is safe here (main.py imports geoip2, a CI-only dependency, and the
runner skips a module whose imports are missing).
"""

import importlib.util
import socket
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

if "geoip2" not in sys.modules:
    # find_spec returns None for a missing top-level module; check the RESULT,
    # not just the exception, or the stub never installs.
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
    "collector_main_robustness", Path(__file__).resolve().parents[1] / "main.py"
)
collector = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(collector)


class ResolveHostRejectsGarbageShapes(unittest.TestCase):
    def test_non_ascii_host_is_rejected(self):
        self.assertIsNone(collector._resolve_host_uncached("пример.рф"))

    def test_overlong_label_is_rejected(self):
        self.assertIsNone(collector._resolve_host_uncached("a" * 64 + ".example.com"))

    def test_overlong_host_is_rejected(self):
        self.assertIsNone(collector._resolve_host_uncached(".".join(["abcd"] * 80)))

    def test_empty_host_is_rejected(self):
        self.assertIsNone(collector._resolve_host_uncached(""))


class ResolverErrorsNeverEscape(unittest.TestCase):
    """Whatever the platform raises, it must come back as None.

    The callers are threads: an exception there aborts the run instead of
    dropping one bad candidate.
    """

    def test_each_error_class_becomes_none(self):
        for exc in (socket.gaierror("nope"), UnicodeError("idna"), ValueError("bad"),
                    OSError("network unreachable")):
            with mock.patch.object(socket, "getaddrinfo", side_effect=exc):
                self.assertIsNone(collector._resolve_host_uncached("still.invalid.example"))

    def test_prewarm_survives_garbage_in_the_feed(self):
        hosts = ["пример.рф", "a" * 64 + ".example.com", "", "ok.example.com"]
        with mock.patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("nope")):
            collector.prewarm_dns(hosts)  # must not raise


if __name__ == "__main__":
    unittest.main()
