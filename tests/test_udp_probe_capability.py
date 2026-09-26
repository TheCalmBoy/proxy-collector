"""The UDP probe must actually be capable of succeeding.

Stage 2 has reported "UDP capable: 0/N" in every run so far. That number is
only meaningful if the probe can return True, so these tests exercise it
against a real local responder rather than trusting a negative result.
"""
import asyncio
import unittest

from tools.verify import _udp_ping


class TestUdpProbeCanSucceed(unittest.TestCase):
    def test_probe_succeeds_against_a_live_responder(self):
        async def scenario():
            class Echo(asyncio.DatagramProtocol):
                def connection_made(self, transport):
                    self.transport = transport

                def datagram_received(self, data, addr):
                    self.transport.sendto(b"pong", addr)

            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                Echo, local_addr=("127.0.0.1", 0)
            )
            port = transport.get_extra_info("sockname")[1]
            try:
                return await _udp_ping("127.0.0.1", port, 2.0)
            finally:
                transport.close()

        ok, latency_ms = asyncio.run(scenario())
        self.assertTrue(ok, "probe can never succeed, so UDP capable is always 0")
        self.assertIsNotNone(latency_ms)
        self.assertGreaterEqual(latency_ms, 0.0)

    def test_probe_fails_cleanly_on_a_closed_port(self):
        ok, latency_ms = asyncio.run(_udp_ping("127.0.0.1", 9, 0.5))
        self.assertFalse(ok)
        self.assertIsNone(latency_ms)


if __name__ == "__main__":
    unittest.main()
