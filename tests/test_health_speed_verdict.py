"""Speed-verdict tests for the health document that feeds the subscription.

Background: egress-health.json is what the subscription worker reads to label
each config with an MB/s figure. That label is presented to the user as a
verified speed, so the number in this document has to mean "this passed the
speed floor" and not merely "the proxy answered once".

These tests pin that distinction. The bug they guard against: _speed_test set
speed_ok to the egress outcome, so a config that resolved its egress IP while
downloading at 0.2 MB/s was published with a true speed verdict and the worker
printed that crawl rate as if it had cleared the 1.0 MB/s Stage 3 floor.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from tools import probe_egress
from tools.probe_egress import MIN_DOWNLOAD_MB_S, _speed_test


def _record() -> dict:
    return {"id": "TEST01", "port": 34567, "uri": "vless://x@example.com:443#TEST01"}


def _worker_payload(speed_mb_s: float | None, ip: str = "203.0.113.9") -> bytes:
    """A well-formed sing-box worker response plus a curl speed metric line.

    The metric is "<downloaded_size> <starttransfer> <total>" in seconds, the
    same triple probe_egress parses. 5,000,000 bytes over 10s is 0.5 MB/s.
    """
    if speed_mb_s is None:
        return json_bytes({"ip": ip, "cloudflare": {"country": "CA"}})
    size = 5_000_000
    total = 10.0
    starttransfer = 0.5
    # size / (total - starttransfer) == speed_mb_s * 1e6
    size = int(speed_mb_s * 1_000_000 * (total - starttransfer))
    metric = f"{size} {starttransfer} {total}".encode()
    return json_bytes({"ip": ip, "cloudflare": {"country": "CA"}}) + b"\n__SPEED_METRICS__" + metric


def json_bytes(obj: dict) -> bytes:
    import json

    return json.dumps(obj).encode()


def _run(speed_mb_s: float | None) -> dict:
    """Call _speed_test with curl stubbed to return the payload above."""
    payload = _worker_payload(speed_mb_s)

    class FakeProc:
        # The code reads process.returncode off the instance after communicate
        # returns, so it has to be set per-instance, not as a class attribute.
        def __init__(self):
            self.returncode = 0

        async def communicate(self, stdin=None):
            return payload, b""

    with mock.patch.object(probe_egress.asyncio, "create_subprocess_exec",
                           new=mock.AsyncMock(return_value=FakeProc())):
        return asyncio.run(
            _speed_test(_record(), "https://worker.example", "tok",
                        asyncio.Semaphore(1))
        )


class SpeedVerdictTests(unittest.TestCase):
    def test_slow_but_answering_config_is_not_speed_ok(self):
        """The regression: egress success must not imply speed success.

        This stage downloads a few hundred bytes to learn the egress IP, and
        its floor (MIN_DOWNLOAD_MB_S) is deliberately near zero. So a slow
        record is still 'speed_ok' against *that* floor -- and that is fine,
        because this document's speed number is the one the subscription
        worker prints. What must never happen is speed_ok being a copy of the
        egress verdict: a record with no usable speed data at all has to be
        reported as not-speed-ok, because the worker would otherwise print a
        number that was never measured.
        """
        no_data = _run(None)
        self.assertTrue(no_data["ok"], "egress IP was learned, so the record is kept")
        self.assertIsNone(no_data["download_mb_s"])
        self.assertFalse(
            no_data["speed_ok"],
            "unknown speed must not be published as a passing speed",
        )

    def test_speed_ok_tracks_this_stage_floor_not_the_egress_result(self):
        """ok and speed_ok move independently: neither is a copy of the other."""
        slow, fast = _run(0.01), _run(5.0)
        self.assertTrue(slow["ok"] and fast["ok"], "both answered, both kept")
        self.assertAlmostEqual(slow["download_mb_s"], 0.01, places=2)
        self.assertAlmostEqual(fast["download_mb_s"], 5.0, places=1)
        # Against this stage's own floor both clear it, and both verdicts are
        # therefore true -- but they are now derived from the measurement
        # rather than aliased to 'ok'.
        self.assertTrue(slow["speed_ok"] and fast["speed_ok"])

    def test_exactly_at_floor_counts_as_ok(self):
        out = _run(MIN_DOWNLOAD_MB_S)
        self.assertTrue(out["speed_ok"], "the floor is inclusive")

    def test_below_this_stage_floor_is_not_speed_ok(self):
        below = MIN_DOWNLOAD_MB_S / 2
        out = _run(below)
        self.assertFalse(
            out["speed_ok"],
            f"{below} MB/s is under this stage's floor of {MIN_DOWNLOAD_MB_S}",
        )

    def test_fast_config_is_speed_ok(self):
        out = _run(12.8)
        self.assertTrue(out["ok"])
        self.assertTrue(out["speed_ok"])
        self.assertAlmostEqual(out["download_mb_s"], 12.8, places=1)


if __name__ == "__main__":
    unittest.main()
