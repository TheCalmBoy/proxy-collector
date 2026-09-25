#!/usr/bin/env python3
"""Test SOCKS5 CONNECT helpers used by the Phase 1 verifier."""

import asyncio
import struct
import unittest
from unittest import mock

import tools.verify as verify
from tools.verify import _packet_test, _read_socks5_greeting, _socks5_connect


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

    async def test_packet_test_runs_20_socks_and_20_https_requests(self):
        socks_calls = 0
        https_calls = 0

        async def fake_socks_connect(*_args):
            nonlocal socks_calls
            socks_calls += 1
            return True, b"\x05\x00"

        async def fake_https_request(*_args):
            nonlocal https_calls
            https_calls += 1
            return True, 1.0

        with (
            mock.patch.object(verify, "PACKET_TEST_DURATION", 40),
            mock.patch.object(verify.asyncio, "sleep", new=mock.AsyncMock()),
            mock.patch.object(verify, "_socks5_connect", fake_socks_connect),
            mock.patch.object(verify, "_https_request", fake_https_request, create=True),
        ):
            result = await verify._packet_test({"port": 30000})

        self.assertEqual(socks_calls, 20)
        self.assertEqual(https_calls, 20)
        self.assertEqual(result["tcp"]["success_count"], 20)
        self.assertEqual(result["https"]["success_count"], 20)
        self.assertTrue(result["passed"])

    async def test_packet_test_requires_both_tcp_and_https_threshold(self):
        async def fake_socks_connect(*_args):
            return True, b"\x05\x00"

        async def fake_https_request(*_args):
            return (https_calls["count"] < 17, 1.0)

        https_calls = {"count": 0}

        async def counted_https_request(*_args):
            result = await fake_https_request()
            https_calls["count"] += 1
            return result

        with (
            mock.patch.object(verify, "PACKET_TEST_DURATION", 40),
            mock.patch.object(verify.asyncio, "sleep", new=mock.AsyncMock()),
            mock.patch.object(verify, "_socks5_connect", fake_socks_connect),
            mock.patch.object(verify, "_https_request", counted_https_request, create=True),
        ):
            result = await verify._packet_test({"port": 30000})

        self.assertEqual(result["tcp"]["success_count"], 20)
        self.assertEqual(result["https"]["success_count"], 17)
        self.assertFalse(result["passed"])

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
