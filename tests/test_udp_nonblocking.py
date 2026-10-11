"""Regression test: the UDP probe must not block the event loop.

A dead UDP server used to stall every other coroutine for the full
timeout because the probe used a blocking recvfrom. The symptom was a
run that appeared to hang: N configs x M rounds x timeout, serialized.
"""
import asyncio
import time
import unittest

from tools.verify import _udp_ping


class TestUdpPingDoesNotBlockLoop(unittest.TestCase):
    def test_dead_port_times_out_and_others_still_run(self):
        async def scenario():
            # 203.0.113.0/24 is TEST-NET-3, reserved and never routed, so
            # these datagrams are simply dropped and the recv times out.
            dead = _udp_ping("203.0.113.1", 9, 1.5)

            ticks = 0

            async def ticker():
                nonlocal ticks
                while True:
                    await asyncio.sleep(0.01)
                    ticks += 1

            spin = asyncio.create_task(ticker())
            started = time.perf_counter()
            result = await dead
            elapsed = time.perf_counter() - started
            spin.cancel()
            return result, elapsed, ticks

        result, elapsed, ticks = asyncio.run(scenario())

        ok, _latency = result
        self.assertFalse(ok, "a dropped datagram must not report success")
        # A blocking recv would hold the loop for the whole timeout and the
        # ticker could not run at all.
        self.assertGreaterEqual(
            ticks, 50,
            f"event loop was starved: only {ticks} ticks in {elapsed:.2f}s",
        )

    def test_concurrent_probes_overlap(self):
        """Twelve 1.5s dead probes must take ~1.5s total, not ~18s."""
        async def scenario():
            start = time.perf_counter()
            await asyncio.gather(*[
                _udp_ping("203.0.113.1", 9, 1.5) for _ in range(12)
            ])
            return time.perf_counter() - start

        elapsed = asyncio.run(scenario())
        self.assertLess(
            elapsed, 4.0,
            f"probes serialized: 12 x 1.5s took {elapsed:.2f}s",
        )


if __name__ == "__main__":
    unittest.main()
