"""Coverage for the real _speed_test body.

tests/test_verify.py patches _speed_test out entirely, so the function's own
logic was never executed by the suite. A missing result key therefore passed
28 green tests and then raised KeyError on the first config of a real run,
killing the whole job at Stage 3.

These tests drive the real function with a stubbed curl subprocess, so the
verdict logic is actually executed.
"""
import asyncio
import os
import unittest
from pathlib import Path
from unittest import mock

from tools import verify
from tools.verify import _speed_test


class FakeProcess:
    """Stands in for the curl subprocess _speed_test spawns."""

    def __init__(self, stdout: bytes, returncode: int = 0):
        self._stdout = stdout
        self.returncode = returncode

    async def communicate(self, _stdin):
        return self._stdout, b""


def _patched_process(stdout: bytes, returncode: int = 0):
    async def fake_exec(*_args, **_kwargs):
        return FakeProcess(stdout, returncode)

    return mock.patch.object(verify.asyncio, "create_subprocess_exec", fake_exec)


class SpeedTestVerdict(unittest.TestCase):
    def _record(self):
        return {"id": "abc123", "port": 30000, "server": "1.2.3.4", "server_port": 443}

    def _ok_egress(self):
        return mock.patch.object(
            verify, "_egress_ip",
            new=mock.AsyncMock(return_value={"ip": "9.9.9.9", "country": "US", "error": None}),
        )

    def test_fast_transfer_is_accepted(self):
        # 5 MB in 10s of transfer time = 500 KB/s, comfortably over the floor.
        stdout = b"\n__SPEED_METRICS__5000000 1.0 11.0"

        async def scenario():
            with _patched_process(stdout), self._ok_egress():
                with mock.patch.object(verify, "SPEED_TEST_BYTES", 5_000_000):
                    return await _speed_test(
                        self._record(), "https://worker.example", "tok",
                        asyncio.Semaphore(1),
                    )

        result = asyncio.run(scenario())
        self.assertTrue(result["speed_ok"])
        self.assertIsNone(result["error"])
        self.assertIsNotNone(result["download_mb_s"])

    def test_slow_transfer_is_rejected_with_threshold_reason(self):
        # 5 MB in 200s = 25 KB/s, under the 100 KB/s floor.
        stdout = b"\n__SPEED_METRICS__5000000 1.0 201.0"

        async def scenario():
            with _patched_process(stdout), self._ok_egress():
                return await _speed_test(
                    self._record(), "https://worker.example", "tok",
                    asyncio.Semaphore(1),
                )

        result = asyncio.run(scenario())
        self.assertFalse(result["speed_ok"])
        self.assertEqual(result["error"], "speed_below_threshold")

    def test_missing_metrics_are_rejected_not_raised(self):
        """curl dying before write-out must yield a verdict, not an exception."""
        stdout = b"curl: (28) Operation timed out"

        async def scenario():
            with _patched_process(stdout, returncode=28), self._ok_egress():
                return await _speed_test(
                    self._record(), "https://worker.example", "tok",
                    asyncio.Semaphore(1),
                )

        result = asyncio.run(scenario())
        self.assertFalse(result["speed_ok"])
        self.assertEqual(result["error"], "no_speed_data")

    def test_worker_error_takes_precedence(self):
        stdout = b"\n__SPEED_METRICS__5000000 1.0 11.0"

        async def scenario():
            with _patched_process(stdout):
                with mock.patch.object(
                    verify, "_egress_ip",
                    new=mock.AsyncMock(return_value={"ip": None, "country": None, "error": "worker_unauthorized"}),
                ):
                    return await _speed_test(
                        self._record(), "https://worker.example", "bad",
                        asyncio.Semaphore(1),
                    )

        result = asyncio.run(scenario())
        self.assertFalse(result["speed_ok"])
        self.assertEqual(result["error"], "worker_unauthorized")

    def test_result_always_has_every_key_the_caller_reads(self):
        """Every key main() reads back must exist on all paths."""
        for stdout, rc in (
            (b"", 7),
            (b"garbage with no marker", 0),
            (b"\n__SPEED_METRICS__notanumber x y", 0),
        ):
            with self.subTest(stdout=stdout):
                async def scenario():
                    with _patched_process(stdout, rc), self._ok_egress():
                        return await _speed_test(
                            self._record(), "https://worker.example", "tok",
                            asyncio.Semaphore(1),
                        )

                result = asyncio.run(scenario())
                for key in ("ok", "speed_ok", "error", "ip", "country", "download_mb_s"):
                    self.assertIn(key, result, f"missing {key!r} for {stdout!r}")


if __name__ == "__main__":
    unittest.main()
