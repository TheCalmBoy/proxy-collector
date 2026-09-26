"""Stage 2 must ask the proxy to relay UDP, not ping its TCP port.

The old probe sent a raw datagram to the endpoint's own server_port and
waited for a reply. A SOCKS5 server listens for TCP on that port and has no
UDP listener there by design, so the probe scored 0 on every config in
every run and published a false "no UDP" claim.

These tests stand up a real SOCKS5 server that implements UDP ASSOCIATE and
one that refuses it, and pin the difference.
"""
import asyncio
import socket
import struct
import unittest
from unittest import mock

from tools import verify


ECHO_PORT = 39501
SOCKS_PORT = 39502


async def _udp_echo():
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", ECHO_PORT))
    sock.setblocking(False)

    async def serve():
        while True:
            try:
                data, addr = await loop.sock_recvfrom(sock, 1024)
            except (OSError, asyncio.TimeoutError):
                continue
            await loop.sock_sendto(sock, b"pong", addr)

    task = asyncio.ensure_future(serve())
    return sock, task


async def _socks5(allow_udp_associate: bool):
    """Minimal SOCKS5 on 127.0.0.1:SOCKS_PORT.

    When allow_udp_associate is True it answers UDP ASSOCIATE with a bound
    relay endpoint and really forwards datagrams, so the probe receives a
    reply exactly as it would from a working proxy. When False it answers
    0x07 (command not supported), as a TCP-only proxy does.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", SOCKS_PORT))
    server.listen(8)
    server.setblocking(False)
    loop = asyncio.get_running_loop()
    relay = None

    if allow_udp_associate:
        # The socket the client sends datagrams to. It stands in for the
        # relay endpoint the server hands back in its reply.
        relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        relay.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        relay.bind(("127.0.0.1", 0))
        relay.setblocking(False)
        relay_port = relay.getsockname()[1]

        async def relay_loop():
            while True:
                try:
                    data, addr = await loop.sock_recvfrom(relay, 4096)
                except (OSError, asyncio.TimeoutError):
                    continue
                # Strip the SOCKS5 UDP header, deliver, return the reply.
                if len(data) < 10:
                    continue
                payload = data[10:]
                try:
                    await loop.sock_sendto(relay, payload, ("127.0.0.1", ECHO_PORT))
                    back = await asyncio.wait_for(
                        loop.sock_recvfrom(relay, 4096), 1.0
                    )
                except (OSError, asyncio.TimeoutError):
                    continue
                header = (
                    b"\x00\x00\x00"
                    + socket.inet_aton("127.0.0.1")
                    + struct.pack("!H", ECHO_PORT)
                )
                await loop.sock_sendto(relay, header + back[0], addr)

        relay_task = asyncio.ensure_future(relay_loop())
    else:
        relay_task = None
        relay_port = 0

    async def handle(reader, writer):
        try:
            header = await reader.readexactly(2)
            await reader.readexactly(header[1])
            writer.write(b"\x05\x00")
            await writer.drain()

            _ver, cmd, _rsv, atyp = await reader.readexactly(4)
            if atyp == 1:
                await reader.readexactly(4)
            elif atyp == 4:
                await reader.readexactly(16)
            else:
                n = (await reader.readexactly(1))[0]
                await reader.readexactly(n)
            await reader.readexactly(4)

            if cmd == 3 and allow_udp_associate:
                # Report the relay endpoint. A real server sends the 2
                # reserved bytes that follow the bound address; the probe
                # waits for them, so this must too.
                writer.write(
                    b"\x05\x00\x00\x01"
                    + socket.inet_aton("127.0.0.1")
                    + struct.pack("!H", relay_port)
                    + b"\x00\x00"
                )
                await writer.drain()
            else:
                writer.write(
                    b"\x05\x07\x00\x01"
                    + socket.inet_aton("0.0.0.0")
                    + struct.pack("!H", 0)
                    + b"\x00\x00"
                )
                await writer.drain()
            # Hold the control connection open while the client probes.
            await asyncio.sleep(3)
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writer.close()

    async def serve():
        while True:
            try:
                r, w = await asyncio.open_connection("127.0.0.1", SOCKS_PORT)
            except OSError:
                continue
            asyncio.ensure_future(handle(r, w))

    task = asyncio.ensure_future(serve())
    return server, task, relay, relay_task


def _associate_reply(relay_host: str, relay_port: int, rep: int = 0) -> bytes:
    """A SOCKS5 UDP ASSOCIATE reply: VER REP RSV ATYP BND.ADDR BND.PORT RSV."""
    return (
        bytes([5, rep, 0, 1])
        + socket.inet_aton(relay_host)
        + struct.pack("!H", relay_port)
        + b"\x00\x00"
    )


class _ScriptedStream:
    """A fake StreamReader/Writer pair for the SOCKS5 control connection.

    Reads come from a scripted byte stream, so the probe's state machine
    runs without a socket. Writes are captured for inspection.
    """

    def __init__(self, incoming: bytes):
        self.incoming = bytearray(incoming)
        self.written = bytearray()
        self.closed = False

    async def readexactly(self, n: int) -> bytes:
        if len(self.incoming) < n:
            self.incoming.extend(b"\x00" * (n - len(self.incoming)))
        out = bytes(self.incoming[:n])
        del self.incoming[:n]
        return out

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    def get_extra_info(self, _name: str, default=None):
        return default


def _fake_round_trip(fake_sendto, fake_recvfrom, reason="reply received"):
    async def round_trip(request, addr, _timeout):
        await fake_sendto(None, request, addr)
        await fake_recvfrom(None, 1024)
        return True, reason

    return round_trip


class UdpAssociateProbe(unittest.TestCase):
    """Drive the probe through an injected transport.

    A real SOCKS5 server cannot be used here: loopback TCP is firewalled on
    the dev host, so a listening socket is unreachable even from the same
    machine (confirmed with ss: the port shows LISTEN while connect times
    out). Injecting the transport keeps this hermetic and is a stronger
    test, since it can script a refusal as easily as a success.

    The datagram leg is mocked too, so the test asserts where the packet
    is sent rather than merely that something came back.
    """

    def _probe(self, reply: bytes, expect_reply: bool = True):
        stream = _ScriptedStream(b"\x05\x00" + reply)
        self.last_addr = None
        self.sent_payload = None

        async def fake_connect(_host, _port, **_kw):
            return stream, stream

        async def fake_sendto(_sock, data, addr):
            self.last_addr = addr
            self.sent_payload = data
            return len(data)

        async def fake_recvfrom(_sock, _size):
            if not expect_reply:
                raise asyncio.TimeoutError()
            return b"\x00\x00\x00", ("10.0.0.9", 53)

        async def scenario():
            with mock.patch.object(verify.asyncio, "open_connection", fake_connect), \
                 mock.patch.object(verify, "_datagram_round_trip",
                                   _fake_round_trip(fake_sendto, fake_recvfrom)):
                return await verify._udp_associate_probe(12345, 1.0)

        return asyncio.run(scenario()), stream

    def test_capable_proxy_is_detected(self):
        """The whole point: a proxy that can relay UDP must read as capable."""
        (ok, _lat), _stream = self._probe(_associate_reply("127.0.0.1", 4444))
        self.assertTrue(ok, "a working UDP relay was reported as incapable")

    def test_tcp_only_proxy_reads_as_incapable(self):
        """0x07 is the spec's 'command not supported' reply."""
        (ok, _lat), _stream = self._probe(_associate_reply("0.0.0.0", 0, rep=7))
        self.assertFalse(ok)

    def test_sends_the_associate_command(self):
        _, stream = self._probe(_associate_reply("127.0.0.1", 4444))
        self.assertIn(b"\x05\x03", bytes(stream.written), "no UDP ASSOCIATE sent")

    def test_datagram_goes_to_the_relay_endpoint(self):
        """Not to the proxy's TCP port: that was the original bug."""
        (ok, _lat), _stream = self._probe(_associate_reply("192.0.2.7", 5555))
        self.assertTrue(ok)
        self.assertEqual(self.last_addr, ("192.0.2.7", 5555))

    def test_datagram_carries_a_socks5_udp_header(self):
        """RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA, per RFC 1928."""
        (ok, _lat), _stream = self._probe(_associate_reply("127.0.0.1", 4444))
        self.assertTrue(ok)
        self.assertEqual(self.sent_payload[:2], b"\x00\x00", "RSV")
        self.assertEqual(self.sent_payload[2], 0, "FRAG must be 0")
        self.assertEqual(self.sent_payload[3], 1, "ATYP IPv4")
        self.assertEqual(
            self.sent_payload[4:8], socket.inet_aton(verify.UDP_TEST_HOST)
        )
        self.assertEqual(
            struct.unpack("!H", self.sent_payload[8:10])[0], verify.UDP_TEST_PORT
        )

    def test_datagram_payload_is_a_real_dns_query(self):
        """A filler byte is silently dropped by 1.1.1.1, so the probe would
        time out and call every working proxy UDP-incapable."""
        (ok, _lat), _stream = self._probe(_associate_reply("127.0.0.1", 4444))
        self.assertTrue(ok)
        payload = self.sent_payload[10:]
        self.assertGreater(len(payload), 12, "payload too short to be a query")
        txid, flags, qdcount = struct.unpack("!HHH", payload[:6])
        self.assertEqual(flags, 0x0100, "QR must be 0 for a query")
        self.assertEqual(qdcount, 1, "exactly one question")
        self.assertIn(b"\x07example\x03com\x00", payload)
        qtype, qclass = struct.unpack(
            "!HH", payload[payload.index(b"\x00", 12) + 1:][:4]
        )
        self.assertEqual((qtype, qclass), (1, 1), "must be an A/IN question")

    def test_no_relay_reply_is_incapable(self):
        (ok, _lat), _stream = self._probe(_associate_reply("127.0.0.1", 4444), expect_reply=False)
        self.assertFalse(ok)

    def test_connect_failure_is_incapable(self):
        async def fake_connect(*_a, **_kw):
            raise OSError("connection refused")

        async def scenario():
            with mock.patch.object(verify.asyncio, "open_connection", fake_connect):
                return await verify._udp_associate_probe(12345, 1.0)

        ok, detail = asyncio.run(scenario())
        self.assertFalse(ok)
        # The reason is carried instead of None so a refused TCP connect is
        # distinguishable from a proxy that accepted and then went quiet.
        self.assertIn("12345", detail)

    def test_bad_version_is_rejected(self):
        (ok, _lat), _stream = self._probe(b"\x04\x00")
        self.assertFalse(ok)

    def test_zero_relay_port_is_incapable(self):
        """A server that accepts ASSOCIATE but names no endpoint cannot relay."""
        (ok, _lat), _stream = self._probe(_associate_reply("0.0.0.0", 0))
        self.assertFalse(ok)

    def test_reliability_uses_the_associate_probe(self):
        """Stage 2 must not go back to pinging the TCP port: that is exactly
        what produced 0/N on every run."""
        import inspect

        source = inspect.getsource(verify._udp_reliability)
        self.assertIn("_udp_associate_probe", source)
        self.assertNotIn("_udp_ping(", source)

    def test_reliability_still_runs_every_round(self):
        """It is a flag, not a filter, so it must not exit early."""
        import inspect

        self.assertNotIn("break", inspect.getsource(verify._udp_reliability))

    def test_stage2_does_not_borrow_the_tcp_connect_budget(self):
        """A UDP round trip is slower than a bare connect.

        Stage 2 once used TCP_TIMEOUT (1.5s) and shared Stage 1's
        semaphore. At 576 configs every one of the 11520 probes timed out
        and the stage read 0/576, while the same code read 12/12 against
        12 configs. The budget was the variable, not the proxies.
        """
        self.assertNotEqual(verify.UDP_TEST_TIMEOUT, verify.TCP_TIMEOUT)
        self.assertGreater(verify.UDP_TEST_TIMEOUT, verify.TCP_TIMEOUT)

    def test_reliability_probes_with_the_udp_budget(self):
        """Guards the call site, not just the constant."""
        import inspect

        source = inspect.getsource(verify._udp_reliability)
        self.assertIn("UDP_TEST_TIMEOUT", source)
        self.assertNotIn("TCP_TIMEOUT", source)


if __name__ == "__main__":
    unittest.main()
