#!/usr/bin/env python3
"""Test SOCKS5 CONNECT helpers used by the Phase 1 verifier."""

import asyncio
import struct
import unittest
from unittest import mock

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
