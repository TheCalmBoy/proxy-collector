#!/usr/bin/env python3
"""Test SOCKS5 CONNECT helpers used by the Phase 1 verifier."""

import asyncio
import struct
import unittest
from unittest import mock

import tools.verify as verify
from tools.verify import _read_socks5_greeting, _socks5_connect


class Socks5HelpersTests(unittest.IsolatedAsyncioTestCase):
    async def test_read_greeting_requires_supported_auth(self):
        writer = mock.Mock()
        writer.drain = mock.AsyncMock()
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x05\x02")  # server requires username/password
        reader.feed_eof()

        with self.assertRaises(OSError):
            await _read_socks5_greeting(reader, writer)

    async def test_read_greeting_accepts_no_auth(self):
        writer = mock.Mock()
        writer.drain = mock.AsyncMock()
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x05\x00")  # server selects no authentication
        reader.feed_eof()

        self.assertEqual(await _read_socks5_greeting(reader, writer), b"\x05\x00")
        writer.write.assert_called_once_with(b"\x05\x01\x00")

    async def test_tcp_reliability_runs_20_socks_requests(self):
        socks_calls = 0

        async def fake_socks_connect(*_args):
            nonlocal socks_calls
            socks_calls += 1
            return True, b"\x05\x00"

        with (
            mock.patch.object(verify, "PACKET_TEST_ROUND_DELAY", 0),
            mock.patch.object(verify.asyncio, "sleep", new=mock.AsyncMock()),
            mock.patch.object(verify, "_socks5_connect", fake_socks_connect),
        ):
            rate = await verify._tcp_reliability({"port": 30000}, None)

        self.assertEqual(socks_calls, 20)
        self.assertEqual(rate, 1.0)

    async def test_https_reliability_runs_20_https_requests(self):
        https_calls = 0

        async def fake_https_request(*_args):
            nonlocal https_calls
            https_calls += 1
            return True, 1.0

        with (
            mock.patch.object(verify, "PACKET_TEST_ROUND_DELAY", 0),
            mock.patch.object(verify.asyncio, "sleep", new=mock.AsyncMock()),
            mock.patch.object(verify, "_https_request", fake_https_request, create=True),
        ):
            rate = await verify._https_reliability({"port": 30000}, None)

        self.assertEqual(https_calls, 20)
        self.assertEqual(rate, 1.0)

    async def test_https_reliability_reports_below_threshold_rate(self):
        https_calls = {"count": 0}

        async def counted_https_request(*_args):
            https_calls["count"] += 1
            return (https_calls["count"] <= 17, 1.0)

        with (
            mock.patch.object(verify, "PACKET_TEST_ROUND_DELAY", 0),
            mock.patch.object(verify.asyncio, "sleep", new=mock.AsyncMock()),
            mock.patch.object(verify, "_https_request", counted_https_request, create=True),
        ):
            rate = await verify._https_reliability({"port": 30000}, None)

        self.assertAlmostEqual(rate, 17 / 20)
        self.assertLess(rate, verify.HTTPS_MIN_SUCCESS_RATE)

    async def test_udp_reliability_never_raises_on_timeout(self):
        async def fake_udp_ping(*_args):
            raise asyncio.TimeoutError

        with (
            mock.patch.object(verify, "PACKET_TEST_ROUND_DELAY", 0),
            mock.patch.object(verify.asyncio, "sleep", new=mock.AsyncMock()),
            mock.patch.object(verify, "_udp_ping", fake_udp_ping, create=True),
        ):
            rate = await verify._udp_reliability(
                {"server": "example.com", "server_port": 443}, None
            )

        self.assertEqual(rate, 0.0)

    async def test_https_request_closes_stream_without_waiting(self):
        writer = mock.Mock()
        writer.drain = mock.AsyncMock()
        writer.wait_closed = mock.AsyncMock()
        writer.start_tls = mock.AsyncMock(return_value=None)

        socks_reader = asyncio.StreamReader()
        socks_reader.feed_data(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
        socks_reader.feed_eof()
        tls_reader = asyncio.StreamReader()
        tls_reader.feed_data(b"HTTP/1.1 200 OK\r\n\r\n")
        tls_reader.feed_eof()

        async def supported_greeting(_reader, _writer):
            return b"\x05\x00"

        with (
            mock.patch("tools.verify._read_socks5_greeting", supported_greeting),
            mock.patch("tools.verify.asyncio.open_connection", return_value=(socks_reader, writer)),
            mock.patch.object(writer, "start_tls", new=mock.AsyncMock(return_value=None)),
            mock.patch("tools.verify.asyncio.StreamReader.readline", new=mock.AsyncMock(
                return_value=b"HTTP/1.1 200 OK\r\n"
            )),
        ):
            ok, _latency = await verify._https_request(30000, "https://example.com/", 1.5)

        self.assertTrue(ok)
        writer.close.assert_called_once()
        writer.wait_closed.assert_not_awaited()

    async def test_socks5_connect_closes_stream_without_waiting(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
        reader.feed_eof()
        writer = mock.Mock()
        writer.drain = mock.AsyncMock()
        writer.wait_closed = mock.AsyncMock()

        with (
            mock.patch("tools.verify._read_socks5_greeting", return_value=b"\x05\x00"),
            mock.patch("tools.verify.asyncio.open_connection", return_value=(reader, writer)),
        ):
            ok, _reply = await _socks5_connect(30000, "1.1.1.1", 443, 1.5)

        self.assertTrue(ok)
        writer.close.assert_called_once()
        writer.wait_closed.assert_not_awaited()

    async def test_socks5_connect_rejects_non_success_reply(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x05\x05\x00\x01")
        reader.feed_eof()
        writer = mock.Mock()
        writer.drain = mock.AsyncMock()
        writer.close = mock.Mock()
        writer.wait_closed = mock.AsyncMock()

        async def supported_greeting(_reader, _writer):
            return b"\x05\x00"

        with (
            mock.patch("tools.verify._read_socks5_greeting", supported_greeting),
            mock.patch("tools.verify.asyncio.open_connection", return_value=(reader, writer)),
        ):
            ok, _ = await _socks5_connect(30000, "1.1.1.1", 443, 1.0)
        self.assertFalse(ok)

    async def test_reliability_runs_exactly_twenty_rounds(self):
        socks_calls = 0
        https_calls = 0
        sleeps = 0

        async def fake_socks_connect(*_args, **_kwargs):
            nonlocal socks_calls
            socks_calls += 1
            return True, 1.0

        async def fake_https_request(*_args, **_kwargs):
            nonlocal https_calls
            https_calls += 1
            return True, 1.0

        async def counting_sleep(_seconds):
            nonlocal sleeps
            sleeps += 1

        with (
            mock.patch.object(verify, "PACKET_TEST_COUNT", 20),
            mock.patch.object(verify, "PACKET_TEST_ROUND_DELAY", 2.0),
            mock.patch.object(verify.asyncio, "sleep", new=counting_sleep),
            mock.patch.object(verify, "_socks5_connect", fake_socks_connect),
            mock.patch.object(verify, "_https_request", fake_https_request, create=True),
        ):
            tcp_rate = await verify._tcp_reliability({"port": 30000}, None)
            https_rate = await verify._https_reliability({"port": 30000}, None)

        # Each stage runs 20 probes and sleeps 19 times (no sleep before the
        # first round), and the stages are sequential, never concurrent.
        self.assertEqual(socks_calls, 20)
        self.assertEqual(https_calls, 20)
        self.assertEqual(sleeps, 38)
        self.assertEqual(tcp_rate, 1.0)
        self.assertEqual(https_rate, 1.0)

    async def test_socks5_connect_accepts_successful_reply(self):
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
        reader.feed_eof()
        writer = mock.Mock()
        writer.drain = mock.AsyncMock()
        writer.close = mock.Mock()
        writer.wait_closed = mock.AsyncMock()

        async def supported_greeting(_reader, _writer):
            return b"\x05\x00"

        with (
            mock.patch("tools.verify._read_socks5_greeting", supported_greeting),
            mock.patch("tools.verify.asyncio.open_connection", return_value=(reader, writer)),
        ):
            ok, reply = await _socks5_connect(30000, "1.1.1.1", 443, 1.0)
        self.assertTrue(ok)
        self.assertEqual(reply, b"\x05\x00")
        request = writer.write.call_args_list[0].args[0]
        self.assertEqual(request, b"\x05\x01\x00\x03\x071.1.1.1\x01\xbb")


if __name__ == "__main__":
    unittest.main()
