#!/usr/bin/env python3
"""
Phase 1 Verification: Tiered proxy validation
- Tier 1: TCP sanity check (1.5s)
- Tier 2: 20 SOCKS CONNECT + 20 HTTPS GET requests (>=90% pass each)
- Tier 3: 5 MB speed test via Worker (>=75 KB/s)
Outputs: enriched-configs.json
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable

# Config
# Config. One curated upstream: it already aggregates ~19 sources and applies
# its own verification, so adding a second feed only duplicates entries.
SOURCE_URL = os.getenv(
    "SOURCE_URL",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
)
WORKER_URL = os.environ.get("WORKER_URL", "").rstrip("/")
WORKER_TOKEN = os.environ.get("WORKER_TOKEN", "")
SING_BOX = os.getenv("SING_BOX", "sing-box")
OUTPUT = Path(os.getenv("VERIFY_OUTPUT", "verify-output"))
TCP_CONCURRENCY = max(1, int(os.getenv("VERIFY_TCP_CONCURRENCY", "750")))
HTTPS_CONCURRENCY = max(1, int(os.getenv("VERIFY_HTTPS_CONCURRENCY", "100")))
# sing-box 1.14 rejects any other value, and the whole process refuses to
# start, so unknown flows must be filtered out during parsing.
SUPPORTED_VLESS_FLOWS = frozenset({"xtls-rprx-vision"})
# sing-box 1.14 shadowsocks ciphers. chacha20-poly1305 and friends appear in
# the upstream source but are not built into the release we run.
SUPPORTED_SS_METHODS = frozenset({
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
})
# The 2022 ciphers derive their key from a base64 PSK and reject wrong lengths.
SS_METHOD_KEY_BYTES = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
}
VERIFY_LIMIT = max(0, int(os.getenv("VERIFY_LIMIT", "0")))
SPEED_TEST_BYTES = 5_000_000
# 100 KB/s over a 5 MB body is a 50-second floor, which is why this is worth
# raising rather than lowering: at 200 KB/s a config must sustain roughly a
# quarter of a megabit for 25s to pass, and anything that cannot is not going
# to be useful to a subscriber. Left env-tunable so the threshold can be
# measured against real yield rather than assumed to be free.
MIN_SPEED_MB_S = float(os.getenv("VERIFY_MIN_SPEED_MB_S", "0.100"))
TCP_TIMEOUT = 1.5
# Stage 4 does a full TLS handshake plus an HTTP round trip through the
# proxy, which is far more work than the bare TCP connect Stage 1 performs.
# Reusing the 1.5s connect budget for it made the exit gate depend on proxy
# latency rather than proxy quality, and the gate swung from 137 survivors
# to 0 across runs with identical code.
HTTPS_TIMEOUT = float(os.getenv("VERIFY_HTTPS_TIMEOUT", "8.0"))
PACKET_TEST_COUNT = 20
# Stage 2 needs its own budget for the same reason as Stage 4. A UDP
# round trip through a proxy is an outbound datagram, a remote forward,
# and a reply, so it is slower than a bare TCP connect, and Stage 2 runs
# against every Stage 1 survivor while sharing Stage 1's concurrency
# semaphore. At 576 configs on the 1.5s connect budget all 11520 probes
# timed out and the stage read 0/576; the same code read 12/12 against a
# 12-config set, so the budget, not the proxies, was the variable.
UDP_TEST_TIMEOUT = float(os.getenv("VERIFY_UDP_TIMEOUT", "6.0"))
PACKET_TEST_ROUND_DELAY = float(os.getenv("VERIFY_ROUND_DELAY", "0.5"))
PACKET_TEST_MIN_SUCCESS_RATE = 0.90
# Stage thresholds: TCP is the entry gate at 95%, HTTPS is the exit gate at
# the long-standing 90%.
TCP_MIN_SUCCESS_RATE = 0.95
HTTPS_MIN_SUCCESS_RATE = 0.90
# UDP never rejects; it only sets the supports_udp flag at this rate.
UDP_MIN_SUCCESS_RATE = 0.50
# 400-way contention was the single largest source of lost yield: Stage 3
# measured 172/998 passing at 400 versus 454/904 at 40, because 400 simultaneous
# 5 MB transfers queue behind each other on one runner and the wall-clock cost
# of that queueing eats the 100 KB/s budget. The stage went from 74s to 130s and
# returned 2.6x the configs. Keep this well under the point where throughput,
# not the runner, is the constraint; raise it only with measured evidence.
SPEED_CONCURRENCY = max(1, int(os.getenv("VERIFY_SPEED_CONCURRENCY", "40")))
HTTPS_TEST_URL = os.getenv(
    "VERIFY_HTTPS_URL", "https://www.gstatic.com/generate_204"
)


class UnsupportedConfig(ValueError):
    pass


async def _under(semaphore: asyncio.Semaphore | None, probe: Any) -> Any:
    """Await probe(), optionally under a concurrency semaphore."""
    if semaphore is None:
        return await probe()
    async with semaphore:
        return await probe()


async def _tcp_reliability(record: dict[str, Any], semaphore: asyncio.Semaphore | None) -> float:
    """Run PACKET_TEST_COUNT SOCKS CONNECTs and return the success rate.

    Stops once a perfect run of the remaining rounds cannot reach the
    entry gate. At 95% over 20 rounds a config needs 19 successes, so one
    that loses 2 early is already lost; the remaining probes bought nothing
    and Stage 1 is the largest stage in the funnel.
    """
    successes = 0
    required = int(math.ceil(TCP_MIN_SUCCESS_RATE * PACKET_TEST_COUNT))
    for index in range(PACKET_TEST_COUNT):
        if index:
            await asyncio.sleep(PACKET_TEST_ROUND_DELAY)
        try:
            ok, _ = await _under(
                semaphore,
                lambda: _socks5_connect(record["port"], "1.1.1.1", 443, TCP_TIMEOUT),
            )
        except Exception:
            ok = False
        successes += 1 if ok else 0
        if successes + (PACKET_TEST_COUNT - index - 1) < required:
            break
    return successes / PACKET_TEST_COUNT


async def _https_reliability(
    record: dict[str, Any], semaphore: asyncio.Semaphore | None
) -> float:
    """Run PACKET_TEST_COUNT proxied HTTPS GETs and return the success rate.

    A config that lands just under the gate is retried once. With 20 rounds
    and a 90% bar a config may afford only 2 failures, so a single timeout
    rejects a proxy that would otherwise be fine. One retry costs a second
    of runner time and removes that coin flip, which is what made the gate
    swing from 137 survivors to 0 between runs of identical code.
    """
    rate = await _https_rounds(record, semaphore)
    if rate < HTTPS_MIN_SUCCESS_RATE and rate > 0:
        retried = await _https_rounds(record, semaphore)
        if retried > rate:
            return retried
    return rate


async def _https_rounds(
    record: dict[str, Any], semaphore: asyncio.Semaphore | None
) -> float:
    """One pass of up to PACKET_TEST_COUNT proxied HTTPS GETs.

    Exits as soon as the gate is unreachable. A pass is guaranteed to fail
    once failures exceed the budget, so continuing to probe a dead proxy
    only spends the runner's wall clock, which is the scarce resource:
    Stage 4 was the slowest stage in every run.
    """
    successes = 0
    # Rounds needed to clear the gate, e.g. 18 of 20 at 90%.
    required = int(math.ceil(HTTPS_MIN_SUCCESS_RATE * PACKET_TEST_COUNT))
    for index in range(PACKET_TEST_COUNT):
        if index:
            await asyncio.sleep(PACKET_TEST_ROUND_DELAY)
        try:
            ok, _ = await _under(
                semaphore,
                lambda: _https_request(record["port"], HTTPS_TEST_URL, HTTPS_TIMEOUT),
            )
        except Exception:
            ok = False
        successes += 1 if ok else 0
        # Give up once even a perfect run of the remaining rounds falls
        # short. Probing a dead proxy for the full 20 rounds only burns the
        # runner's wall clock, and Stage 4 is the slowest stage.
        if successes + (PACKET_TEST_COUNT - index - 1) < required:
            break
    return successes / PACKET_TEST_COUNT


def https_failure_summary(results: list[float], threshold: float) -> str:
    """Describe why a stage produced no survivors, so a 0/N run is
    diagnosable from the log instead of looking like a mystery."""
    if not results:
        return "no results"
    if any(rate >= threshold for rate in results):
        return "some passed"
    return (
        f"all {len(results)} below {threshold:.0%}; "
        f"best={max(results):.2f} mean={sum(results) / len(results):.2f} "
        f"zeros={sum(1 for r in results if r == 0)}"
    )


UDP_TEST_HOST = os.getenv("VERIFY_UDP_TEST_HOST", "1.1.1.1")
UDP_TEST_PORT = int(os.getenv("VERIFY_UDP_TEST_PORT", "53"))

class _ProbeTimeout(Exception):
    """A labelled timeout, so the failing step is identifiable in logs.

    A bare TimeoutError cannot distinguish the greeting, the ASSOCIATE
    reply, and the datagram round trip, which is why a whole stage once
    reported 11240 failures under one indistinguishable reason.
    """

    def __init__(self, label: str) -> None:
        super().__init__(label)
        self.label = label


# Why UDP probes failed, tallied across Stage 2. A bare 0/N cannot tell a
# broken probe from a TCP-only fleet; this can. Reset per run so a
# long-lived process does not accumulate across runs.
UDP_FAILURE_REASONS: dict[str, int] = {}


async def _udp_associate_probe(
    proxy_port: int, timeout: float
) -> tuple[bool, float | str | None]:
    """Ask a SOCKS5 server to relay one datagram, per RFC 1928.

    This replaces a raw datagram aimed at the endpoint's own TCP port. That
    earlier probe was guaranteed to score 0: a SOCKS5 server listens for
    TCP on that port and has no UDP listener there by design, so every
    config read as UDP-incapable no matter what it could actually relay.
    Verified directly against a SOCKS5 server that does implement UDP
    ASSOCIATE - the raw ping returned False against it.

    UDP ASSOCIATE is the only correct question: it asks the proxy itself
    to open a relay path, which is what "this proxy carries UDP" means.

    Returns (ok, detail): latency in ms on success, and a short reason
    string on failure. A refused command yields the REP code, which is the
    expected answer for a TCP-only proxy and is distinguishable from a
    relay that accepted the request and then went silent.

    Every await is labelled. A single catch-all TimeoutError made the
    greeting, the ASSOCIATE reply, and the datagram round trip all look
    alike in the stage tally, so 11240 failures with one reason could not
    be told apart - which is what hid the real cause. The label names the
    step that ran out of time.
    """
    async def step(label: str, awaitable: Awaitable[Any]) -> Any:
        try:
            return await asyncio.wait_for(awaitable, timeout=timeout)
        except asyncio.TimeoutError:
            raise _ProbeTimeout(label) from None

    start = time.perf_counter()
    try:
        reader, writer = await step(
            "connect", asyncio.open_connection("127.0.0.1", proxy_port)
        )
    except (OSError, _ProbeTimeout) as exc:
        return False, f"no SOCKS inbound on 127.0.0.1:{proxy_port} ({type(exc).__name__})"

    sock: socket.socket | None = None
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        version, method = await step("greeting", reader.readexactly(2))
        if version != 5 or method != 0:
            return False, f"not SOCKS5 (VER={version} METHOD={method})"

        # Bind the datagram socket first and name its port in the request,
        # which is what RFC 1928 asks the client to do. The earlier
        # version asked for 0.0.0.0:0 and then tried to send from the TCP
        # control connection's own port, because sing-box relays a session
        # keyed on the client's UDP source port. That collided: with 750
        # probes in flight the ephemeral allocator had already handed the
        # same port to another probe, and bind() failed with EADDRINUSE
        # (errno 98), turning a working proxy into a hard failure. Owning
        # the socket from the start makes the collision impossible.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        client_port = sock.getsockname()[1]

        # UDP ASSOCIATE, naming our datagram socket's port.
        writer.write(
            b"\x05\x03\x00\x01"
            + socket.inet_aton("0.0.0.0")
            + struct.pack("!H", client_port)
            + b"\x00\x00"
        )
        await writer.drain()
        # RFC 1928: VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR BND.PORT.
        # sing-box writes exactly 10 bytes for an IPv4 bound address:
        #   05 00 00 01 7f 00 00 01 e9 dc
        # ATYP is the fourth byte, so it arrives inside a 4-byte read.
        # The bug was never the ATYP offset; it was reading exactly 4
        # bytes and then reading more. That left one byte of the reply
        # still in the stream, so the next read consumed the first
        # BND.ADDR byte (0x7f) as ATYP, then a short address, then
        # BND.PORT=1 - and the probe sent its datagram to 127.0.0.1:1,
        # where nothing listens. Splitting a stream on a byte count
        # instead of on the reply's own structure is what broke it.
        header = await step("associate reply", reader.readexactly(4))
        if header[0] != 5 or header[1] != 0:
            # 0x07 is "command not supported": the proxy is TCP-only.
            return False, f"UDP ASSOCIATE refused (REP={header[1]})"
        atyp = header[3]
        if atyp == 1:
            relay_host = socket.inet_ntoa(
                await step("relay address", reader.readexactly(4))
            )
        elif atyp == 4:
            raw = await step("relay address", reader.readexactly(16))
            relay_host = socket.inet_ntop(socket.AF_INET6, raw)
        else:
            length = (await step("relay length", reader.readexactly(1)))[0]
            relay_host = (
                await step("relay address", reader.readexactly(length))
            ).decode(errors="replace")
        relay_port = struct.unpack(
            "!H", await step("relay port", reader.readexactly(2))
        )[0]

        if not relay_host or relay_host == "0.0.0.0":
            relay_host = "127.0.0.1"
        if relay_port == 0:
            return False, "associate returned no relay port"

        # SOCKS5 UDP request header, per RFC 1928:
        #   RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA
        # ATYP 1 is IPv4, so the address is 4 bytes. Getting this wrong
        # shifts every following field and sends the datagram to 1.1.1.0
        # instead of 1.1.1.1, which no proxy would ever answer.
        request = (
            b"\x00\x00"          # RSV, must be zero
            + b"\x00"            # FRAG, 0 = first fragment
            + b"\x01"            # ATYP, 1 = IPv4
            + socket.inet_aton(UDP_TEST_HOST)
            + struct.pack("!H", UDP_TEST_PORT)
            + _dns_query()
        )
        # The socket is already bound, so the round trip uses it as is
        # rather than re-binding to a port number that may be taken.
        ok, reason = await _datagram_round_trip(
            request, (relay_host, relay_port), timeout, sock
        )
        if not ok:
            return False, f"datagram: {reason}"
        return True, (time.perf_counter() - start) * 1000
    except _ProbeTimeout as exc:
        return False, f"timed out during {exc.label}"
    except (OSError, asyncio.TimeoutError, struct.error, IndexError) as exc:
        return False, f"probe aborted: {exc.__class__.__name__}"
    finally:
        # The control connection has to outlive the datagram round trip.
        # sing-box reads the client's first datagram on this same
        # connection - its trace log says "read first packet" - and
        # reports "use of closed network connection" when the client hangs
        # up first. Closing here tore down the relay the moment the
        # request was written, so the probe could never see a reply and
        # every config read as UDP-incapable.
        writer.close()
        # Every early return above bypasses the round trip, which is what
        # owns the datagram socket when it creates one. At 20 rounds across
        # 600 configs an unclosed socket per probe is thousands of leaked
        # descriptors, and the bind collisions this probe just fixed come
        # straight back.
        if sock is not None:
            sock.close()


def _dns_query() -> bytes:
    """A minimal DNS A query for example.com, for the UDP relay probe.

    The payload has to be a real query, not a filler byte. 1.1.1.1 silently
    drops a 1-byte datagram, so a probe built on one gets no reply and
    reports every working proxy as UDP-incapable. Verified: a 1-byte
    payload to 1.1.1.1:53 times out, while this query is answered in
    ~20 ms.
    """
    header = struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)  # ID, flags, 1 question
    question = b"".join(
        bytes([len(label)]) + label for label in b"example.com".split(b".")
    ) + b"\x00"          # end of the name
    return header + question + struct.pack("!HH", 1, 1)  # QTYPE A, QCLASS IN


async def _datagram_round_trip(
    request: bytes,
    addr: tuple[str, int],
    timeout: float,
    sock: socket.socket | None = None,
) -> tuple[bool, str]:
    """Send one datagram through a relay endpoint and wait for a reply.

    Returns (ok, reason). The reason distinguishes the failure modes that
    all look identical as a bare False: the relay is unreachable, or it
    took the datagram and nothing came back.

    sock is a datagram socket the caller has already bound. Pass it when
    the source port matters: sing-box keys a session on the client's UDP
    source port, and the port the ASSOCIATE request named is the one the
    reply returns to. Binding here instead would race other probes for
    the same ephemeral port under concurrency.
    """
    loop = asyncio.get_running_loop()
    # A socket passed in belongs to the caller, which needs it closed only
    # once it is finished with the whole probe. One made here is ours to
    # close either way.
    owned = sock is None
    if sock is None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
    try:
        try:
            await asyncio.wait_for(
                loop.sock_sendto(sock, request, addr), timeout=timeout
            )
        except asyncio.TimeoutError:
            return False, "send to relay timed out"
        except OSError as exc:
            return False, f"relay send failed: {exc.__class__.__name__}"
        try:
            await asyncio.wait_for(loop.sock_recvfrom(sock, 2048), timeout=timeout)
        except asyncio.TimeoutError:
            return False, f"relay accepted the datagram, no reply in {timeout}s"
        except OSError as exc:
            return False, f"relay receive failed: {exc.__class__.__name__}"
        return True, "reply received"
    finally:
        if owned:
            sock.close()


async def _udp_reliability(
    record: dict[str, Any], semaphore: asyncio.Semaphore | None
) -> float:
    """Run PACKET_TEST_COUNT UDP probes and return the success rate.

    This is metadata only: the caller flags the result and never rejects on
    it, because many working configs simply do not carry UDP.

    The probe asks the proxy to relay a datagram via SOCKS5 UDP ASSOCIATE.
    It previously sent a raw datagram to the endpoint's own server_port and
    waited for a reply, which can never succeed: SOCKS5 listens for TCP on
    that port and has no UDP listener there. That produced a 0/N reading on
    every run across every config, publishing a false "no UDP" claim for
    proxies that relay UDP perfectly.

    No early exit here, unlike Stages 1 and 4: this is a flag, not a filter,
    so a partial pass would report a rate that was not measured.

    The failure reasons are tallied into UDP_FAILURE_REASONS and printed
    once for the whole stage. Every mode used to collapse into the same
    0/N, which is why a broken probe and a TCP-only fleet stayed
    indistinguishable in the logs. Printing per record instead would bury
    the signal under hundreds of lines, so this counts and the Stage 2
    summary reports.
    """
    successes = 0
    for index in range(PACKET_TEST_COUNT):
        if index:
            await asyncio.sleep(PACKET_TEST_ROUND_DELAY)
        try:
            ok, detail = await _under(
                semaphore,
                lambda: _udp_associate_probe(record["port"], UDP_TEST_TIMEOUT),
            )
        except Exception as exc:
            ok, detail = False, f"probe raised {exc.__class__.__name__}"
        if ok:
            successes += 1
        else:
            reason = detail if isinstance(detail, str) else "unknown"
            tally = UDP_FAILURE_REASONS.get(reason, 0) + 1
            UDP_FAILURE_REASONS[reason] = tally
    return successes / PACKET_TEST_COUNT


def _first(params: dict[str, list[str]], *keys: str, default: str = "") -> str:
    for key in keys:
        values = params.get(key)
        if values:
            return values[0]
    return default


def _decode_base64(value: str) -> bytes:
    value = value.strip().replace("-", "+").replace("_", "/")
    value += "=" * ((4 - len(value) % 4) % 4)
    return base64.b64decode(value)


def _host_port(parsed: urllib.parse.SplitResult) -> tuple[str, int]:
    host = parsed.hostname
    try:
        port = parsed.port
    except ValueError as exc:
        raise UnsupportedConfig("invalid_port") from exc
    if not host or not port:
        raise UnsupportedConfig("missing_host_or_port")
    return host, port


def parse_proxy_uri(uri: str) -> dict[str, Any]:
    clean = uri.strip()
    if not clean:
        raise UnsupportedConfig("empty")
    scheme = clean.split(":", 1)[0].lower()

    if scheme == "vmess":
        payload = clean[len("vmess://"):].split("#", 1)[0]
        try:
            vmess = json.loads(_decode_base64(payload))
        except Exception as exc:
            raise UnsupportedConfig("invalid_vmess_payload") from exc
        host = str(vmess.get("add") or vmess.get("server") or "")
        try:
            port = int(vmess.get("port"))
        except (TypeError, ValueError) as exc:
            raise UnsupportedConfig("missing_host_or_port") from exc
        if not host:
            raise UnsupportedConfig("missing_host_or_port")
        outbound = {
            "type": "vmess",
            "server": host,
            "server_port": port,
            "uuid": str(vmess.get("id") or vmess.get("uuid") or ""),
            "alter_id": int(vmess.get("aid") or vmess.get("alterId") or 0),
            "security": str(vmess.get("scy") or vmess.get("security") or "auto"),
        }
        if vmess.get("net"):
            outbound["transport"] = _vmess_transport(vmess)
        return outbound

    parsed = urllib.parse.urlsplit(clean)
    if parsed.scheme not in ("vless", "trojan", "ss", "socks", "socks5", "http", "https"):
        raise UnsupportedConfig(f"unsupported_scheme_{parsed.scheme}")

    host, port = _host_port(parsed)
    params = urllib.parse.parse_qs(parsed.query)

    if parsed.scheme in ("vless", "trojan"):
        uuid = parsed.username or _first(params, "uuid", "id")
        if not uuid:
            raise UnsupportedConfig("missing_uuid")
        outbound = {
            "type": parsed.scheme,
            "server": host,
            "server_port": port,
        }
        if parsed.scheme == "vless":
            outbound["uuid"] = uuid
            flow = _first(params, "flow") or ""
            # Every config shares one sing-box process: an outbound with an
            # unrecognised flow makes sing-box abort at startup, zeroing the
            # entire run. Only pass through flows sing-box 1.14 accepts.
            if flow and flow not in SUPPORTED_VLESS_FLOWS:
                raise UnsupportedConfig(f"unsupported_flow:{flow}")
            outbound["flow"] = flow
            if _first(params, "security", "tls") in ("tls", "reality"):
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": _first(params, "sni", "host") or host,
                }
                if _first(params, "fp") == "chrome":
                    outbound["tls"]["utls"] = {"enabled": True, "fingerprint": "chrome"}
                if _first(params, "security", "tls") == "reality":
                    pbk = _first(params, "pbk", "public_key")
                    sid = _first(params, "sid", "short_id")
                    if pbk:
                        outbound["tls"]["reality"] = {"public_key": pbk}
                    if sid:
                        outbound["tls"]["reality"]["short_id"] = sid
        else:
            outbound["password"] = uuid
            if _first(params, "security", "tls") == "tls":
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": _first(params, "sni", "host") or host,
                }
        transport = _common_transport(params)
        if transport:
            outbound["transport"] = transport
        return outbound

    if parsed.scheme == "ss":
        auth = parsed.username
        if not auth:
            raise UnsupportedConfig("missing_ss_auth")
        try:
            method, password = _decode_base64(auth).decode().split(":", 1)
        except Exception as exc:
            raise UnsupportedConfig("invalid_ss_auth") from exc
        if method not in SUPPORTED_SS_METHODS:
            # Unrecognised ciphers abort the shared sing-box process, which
            # zeroes the entire run rather than skipping one bad config.
            raise UnsupportedConfig(f"unsupported_ss_method:{method}")
        required_key = SS_METHOD_KEY_BYTES.get(method)
        if required_key is not None:
            try:
                key_len = len(_decode_base64(password))
            except Exception as exc:
                raise UnsupportedConfig("invalid_ss_key") from exc
            if key_len != required_key:
                raise UnsupportedConfig("invalid_ss_key_length")
        outbound = {
            "type": "shadowsocks",
            "server": host,
            "server_port": port,
            "method": method,
            "password": password,
        }
        transport = _common_transport(params)
        if transport:
            outbound["transport"] = transport
        return outbound

    if parsed.scheme in ("socks", "socks5"):
        user = urllib.parse.unquote(parsed.username or "")
        pwd = urllib.parse.unquote(parsed.password or "")
        outbound = {"type": "socks", "server": host, "server_port": port, "version": "5"}
        if user:
            outbound["username"] = user
            outbound["password"] = pwd
        return outbound

    if parsed.scheme in ("http", "https"):
        user = urllib.parse.unquote(parsed.username or "")
        pwd = urllib.parse.unquote(parsed.password or "")
        outbound = {"type": "http", "server": host, "server_port": port}
        if user:
            outbound["username"] = user
            outbound["password"] = pwd
        outbound["tls"] = parsed.scheme == "https"
        return outbound

    raise UnsupportedConfig(f"unsupported_scheme_{parsed.scheme}")


def _vmess_transport(vmess: dict) -> dict[str, Any] | None:
    net = str(vmess.get("net") or "").lower()
    if net == "tcp":
        header_type = str(vmess.get("type") or "none")
        if header_type == "http":
            return {"type": "http", "host": [vmess.get("host", "")]}
        return None
    if net in ("ws", "websocket"):
        path = _safe_ws_path(vmess.get("path"))
        host = vmess.get("host", "")
        transport = {"type": "ws", "path": path}
        if host:
            transport["headers"] = {"Host": host}
        return transport
    if net == "grpc":
        service = vmess.get("serviceName", "")
        transport = {"type": "grpc"}
        if service:
            transport["service_name"] = service
        return transport
    return None


def _safe_ws_path(raw: Any) -> str:
    """Normalise a websocket path, or raise if it is not usable.

    sing-box fails to parse paths containing a bare or invalid percent escape
    (e.g. "/100%"), and a single bad transport aborts the whole process.
    """
    path = str(raw or "/")
    if not path.startswith("/"):
        path = "/" + path
    try:
        # A lone "%" is not a valid escape sequence.
        urllib.parse.unquote(path, errors="strict")
    except (UnicodeDecodeError, ValueError) as exc:
        raise UnsupportedConfig("invalid_ws_path") from exc
    if "%" in path and not re.search(r"%[0-9A-Fa-f]{2}", path):
        raise UnsupportedConfig("invalid_ws_path")
    return path


def _common_transport(params: dict[str, list[str]]) -> dict[str, Any] | None:
    net = _first(params, "type", "network", "net")
    if not net:
        return None
    if net == "ws":
        path = _safe_ws_path(_first(params, "path"))
        host = _first(params, "host")
        transport = {"type": "ws", "path": path}
        if host:
            transport["headers"] = {"Host": str(host)}
        return transport
    if net == "grpc":
        service = _first(params, "serviceName", "service_name")
        transport = {"type": "grpc"}
        if service:
            transport["service_name"] = service
        return transport
    return None


async def _read_socks5_greeting(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> bytes:
    """Negotiate no-auth SOCKS5 with a sing-box inbound."""
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    version, method = await asyncio.wait_for(reader.readexactly(2), timeout=1.5)
    if version != 5:
        raise OSError("invalid_socks5_greeting")
    if method != 0:
        raise OSError("socks5_no_auth_not_selected")
    return b"\x05\x00"


async def _socks5_connect(
    proxy_port: int,
    destination_host: str,
    destination_port: int,
    timeout: float,
) -> tuple[bool, bytes | None]:
    """Require a real SOCKS5 CONNECT response, not only a listening socket."""
    writer: asyncio.StreamWriter | None = None
    try:
        async def exchange() -> bytes:
            nonlocal writer
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            await _read_socks5_greeting(reader, writer)
            host = destination_host.encode("idna")
            request = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", destination_port)
            writer.write(request)
            await writer.drain()
            version, reply, _reserved, address_type = await asyncio.wait_for(reader.readexactly(4), timeout=1.5)
            if version != 5 or reply != 0:
                raise OSError(f"socks5_reply_{reply}")
            if address_type == 1:
                await reader.readexactly(4)
            elif address_type == 4:
                await reader.readexactly(16)
            elif address_type == 3:
                length = (await reader.readexactly(1))[0]
                await reader.readexactly(length)
            else:
                raise OSError("socks5_invalid_bound_address")
            await reader.readexactly(2)
            return b"\x05\x00"

        return True, await asyncio.wait_for(exchange(), timeout=timeout)
    except Exception:
        return False, None
    finally:
        if writer is not None:
            writer.close()


async def _tcp_connect(host: str, port: int, timeout: float) -> tuple[bool, float | None]:
    """Try TCP connect, return (success, latency_ms)"""
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        latency_ms = (time.perf_counter() - start) * 1000
        writer.close()
        return True, latency_ms
    except Exception:
        return False, None


async def _udp_ping(host: str, port: int, timeout: float) -> tuple[bool, float | None]:
    """Send one UDP datagram and wait for a reply, without blocking the loop.

    This used to use a blocking socket.recvfrom inside a coroutine, which
    stalled every other coroutine in the process for the full timeout: one
    dead server froze all 479 configs at once. loop.sock_recvfrom is the
    async equivalent and yields the loop while waiting.
    """
    start = time.perf_counter()
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await asyncio.wait_for(loop.sock_sendto(sock, b"\x00", (host, port)), timeout)
        await asyncio.wait_for(loop.sock_recvfrom(sock, 1024), timeout)
    except (OSError, asyncio.TimeoutError):
        return False, None
    finally:
        sock.close()
    return True, (time.perf_counter() - start) * 1000


async def _https_request(proxy_port: int, url: str, timeout: float) -> tuple[bool, float | None]:
    """Make one real HTTPS GET through a sing-box SOCKS inbound."""
    start = time.perf_counter()
    if os.getenv("VERIFY_DEBUG_HTTPS"):
        try:
            return await _https_request_inner(proxy_port, url, timeout, start)
        except Exception as exc:
            print(f"HTTPS_DEBUG {url} -> {type(exc).__name__}: {exc}", file=sys.stderr)
            return False, None
    return await _https_request_inner(proxy_port, url, timeout, start)


async def _https_request_inner(
    proxy_port: int,
    url: str,
    timeout: float,
    start: float,
) -> tuple[bool, float | None]:
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port or 443
        host = parsed.hostname
        if not host or parsed.scheme != "https":
            return False, None

        async def exchange() -> None:
            nonlocal reader, writer
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            await _read_socks5_greeting(reader, writer)
            encoded_host = host.encode("idna")
            writer.write(
                b"\x05\x01\x00\x03"
                + bytes([len(encoded_host)])
                + encoded_host
                + struct.pack("!H", port)
            )
            await writer.drain()
            version, reply, _reserved, address_type = await reader.readexactly(4)
            if version != 5 or reply != 0:
                raise OSError(f"socks5_reply_{reply}")
            if address_type == 1:
                await reader.readexactly(4)
            elif address_type == 4:
                await reader.readexactly(16)
            elif address_type == 3:
                length = (await reader.readexactly(1))[0]
                await reader.readexactly(length)
            else:
                raise OSError("socks5_invalid_bound_address")
            await reader.readexactly(2)

            ssl_context = ssl.create_default_context()
            await writer.start_tls(
                ssl_context,
                server_hostname=host,
                ssl_handshake_timeout=timeout,
            )
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            writer.write(
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                "User-Agent: proxy-collector/1.0\r\nConnection: close\r\n\r\n".encode()
            )
            await writer.drain()
            status_line = await reader.readline()
            if not status_line.startswith(b"HTTP/1.1 2") and not status_line.startswith(b"HTTP/1.0 2"):
                # Include the status: 429 from a rate limit and 403 from a
                # block are completely different failures, and the bare
                # https_non_2xx hid which one happened.
                raise OSError(f"https_non_2xx:{status_line.decode(errors='replace').strip()}")

        await asyncio.wait_for(exchange(), timeout=timeout)
        return True, (time.perf_counter() - start) * 1000
    except Exception as exc:
        if os.getenv("VERIFY_DEBUG_HTTPS"):
            print(f"HTTPS_DEBUG {url} -> {type(exc).__name__}: {exc}", file=sys.stderr)
        return False, None
    finally:
        if writer is not None:
            writer.close()


async def _speed_test(record: dict[str, Any], worker_url: str, token: str, semaphore: asyncio.Semaphore) -> dict[str, Any]:
    """Measure download throughput, then resolve the egress IP separately.

    The bulk bytes come from Cloudflare's speed CDN, not the Worker: pushing
    gigabytes of payload through one Worker made it the run's bottleneck and
    burned its request quota. The Worker is only asked for the egress IP,
    which costs a few hundred bytes per surviving config.
    """
    result: dict[str, Any] = {
        "ip": None,
        "country": None,
        "latency_ms": None,
        "download_mb_s": None,
        "speed_ok": False,
        # The verdict key, defaulting to a rejection. It is read back below,
        # so it has to exist before any early path runs.
        "ok": False,
    }

    ip_task = asyncio.create_task(_egress_ip(record, worker_url, token))
    # The byte count comes from curl's %{size_download}, which is identical
    # whether the body is written to disk or discarded. Writing 5 MB per
    # config to /tmp was pure overhead: 458 configs x 5 MB of tmpfs traffic
    # to learn a number curl already reports.
    config_lines = [
        f'proxy = "socks5h://127.0.0.1:{record["port"]}"',
        f'url = "https://speed.cloudflare.com/__down?bytes={SPEED_TEST_BYTES}"',
        "silent",
        "show-error",
        "fail",
        "connect-timeout = 10",
        "max-time = 50",
        'output = "/dev/null"',
        'write-out = "\\n__SPEED_METRICS__%{size_download} %{time_starttransfer} %{time_total}"',
    ]

    async with semaphore:
        process = await asyncio.create_subprocess_exec(
            "curl", "--config", "-",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate(("\n".join(config_lines) + "\n").encode())

    _, marker, metric = stdout.partition(b"\n__SPEED_METRICS__")
    if marker and process.returncode == 0:
        try:
            downloaded_size, starttransfer, total = map(float, metric.decode().strip().split())
            # This is NOT proxy latency. It is time-to-first-byte on a 5 MB
            # transfer issued under SPEED_CONCURRENCY-way contention, so it
            # is dominated by queueing on this runner: medians land near 9s
            # with 84% of records within 1s of the ceiling. The key keeps
            # its published name because consumers read it, but the only
            # trustworthy quality signal here is download_mb_s. Real
            # responsiveness is Stage 1's TCP success_rate.
            result["latency_ms"] = round(starttransfer * 1000, 1)
            if total > starttransfer:
                # The CDN response is pure payload, so its size is the
                # number of bytes actually received.
                result["download_mb_s"] = downloaded_size / 1_000_000 / (total - starttransfer)
        except (UnicodeDecodeError, ValueError):
            pass

    egress = await ip_task
    if egress.get("error"):
        result["error"] = egress["error"]
    elif result["download_mb_s"] is None:
        result["error"] = "no_speed_data"
    elif result["download_mb_s"] < MIN_SPEED_MB_S:
        result["error"] = "speed_below_threshold"
    else:
        result["ok"] = True
        result["error"] = None
    result["speed_ok"] = result["ok"]
    result["ip"] = egress.get("ip")
    result["country"] = egress.get("country")
    return result


async def _egress_ip(record: dict[str, Any], worker_url: str, token: str) -> dict[str, Any]:
    """Ask the Worker which IP the proxy egresses from (a few hundred bytes)."""
    config_lines = [
        f'proxy = "socks5h://127.0.0.1:{record["port"]}"',
        f'url = "{worker_url}/ip"',
        f'header = "Authorization: Bearer {token}"',
        "silent",
        "show-error",
        "fail",
        "connect-timeout = 10",
        "max-time = 15",
    ]
    process = await asyncio.create_subprocess_exec(
        "curl", "--config", "-",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await process.communicate(("\n".join(config_lines) + "\n").encode())
    if process.returncode != 0:
        return {"ip": None, "country": None, "error": f"curl_exit_{process.returncode}"}
    try:
        payload = json.loads(stdout.decode())
    except (UnicodeDecodeError, ValueError):
        return {"ip": None, "country": None, "error": "invalid_worker_response"}
    return {
        "ip": payload.get("ip"),
        "country": (payload.get("cloudflare") or {}).get("country"),
        "error": None,
    }


def _tag(uri: str) -> str:
    # 8 hex chars (32 bits) collides across a few thousand configs, and a
    # duplicate inbound tag makes sing-box refuse to start at all. Use a wider
    # digest; tags are cheap and uniqueness is required.
    return hashlib.sha256(uri.encode()).hexdigest()[:24].upper()


def build_sing_box_config(uris: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int]]:
    inbounds: list[dict[str, Any]] = []
    outbounds: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    stats = {"input": len(uris), "supported": 0, "unsupported": 0}
    reasons: dict[str, int] = {}

    for uri in uris:
        try:
            outbound = parse_proxy_uri(uri)
        except UnsupportedConfig as exc:
            stats["unsupported"] += 1
            reasons[str(exc)] = reasons.get(str(exc), 0) + 1
            continue
        except Exception as exc:
            # A single malformed URI must never abort the run: urlsplit raises
            # bare ValueError on things like unbracketed IPv6 literals.
            stats["unsupported"] += 1
            key = f"unparseable:{type(exc).__name__}"
            reasons[key] = reasons.get(key, 0) + 1
            continue

        identifier = _tag(uri)
        inbound_tag = f"in-{identifier}"
        outbound_tag = f"proxy-{identifier}"
        port = 30000 + len(records)
        inbound = {"type": "socks", "tag": inbound_tag, "listen": "127.0.0.1", "listen_port": port}
        outbound["tag"] = outbound_tag

        rule = {"outbound": outbound_tag, "inbound": [inbound_tag]}
        inbounds.append(inbound)
        outbounds.append(outbound)
        rules.append(rule)
        records.append({
            "id": identifier,
            "scheme": outbound["type"],
            "server": outbound["server"],
            "server_port": outbound["server_port"],
            "port": port,
            "uri": uri,
        })
        stats["supported"] += 1

    config = {
        "log": {"level": "warn"},
        "inbounds": inbounds,
        "outbounds": outbounds + [{"type": "direct", "tag": "direct"}],
        "route": {"rules": rules, "final": "direct"},
    }
    return config, records, {**stats, **{f"skip_{k}": v for k, v in sorted(reasons.items())}}


def dedupe_endpoints(
    config: dict[str, Any], records: list[dict[str, Any]]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Keep one record per (server, server_port), dropping duplicate inbounds.

    Distinct URIs frequently point at the same endpoint with different UUIDs.
    Testing each one repeats identical socket work, so collapse them first.
    """
    seen: set[tuple[str, int]] = set()
    kept: list[dict[str, Any]] = []
    for record in records:
        key = (record["server"], record["server_port"])
        if key in seen:
            continue
        seen.add(key)
        kept.append(record)

    if len(kept) < len(records):
        print(f"Dedup: {len(records)} configs -> {len(kept)} unique endpoints")
        kept_ids = {record["id"] for record in kept}
        config = dict(config)
        # Prune inbounds, outbounds, and route rules together: a route rule
        # pointing at a removed inbound makes sing-box refuse to start.
        config["inbounds"] = [
            ib for ib in config["inbounds"]
            if ib["tag"].removeprefix("in-") in kept_ids
        ]
        config["outbounds"] = [
            ob for ob in config["outbounds"]
            if ob["tag"] == config["route"]["final"]
            or ob["tag"].removeprefix("proxy-") in kept_ids
        ]
        config["route"] = dict(config["route"])
        config["route"]["rules"] = [
            rule for rule in config["route"]["rules"]
            if rule["inbound"][0].removeprefix("in-") in kept_ids
        ]
    return config, kept


async def _run_sing_box(config: dict) -> asyncio.subprocess.Process:
    config_path = Path("/tmp/verify-sing-box.json")
    config_path.write_text(json.dumps(config, separators=(",", ":")))

    # Validate first: `check` reports the exact offending field, whereas a
    # failed `run` only exits 1 and hides the cause in a startup race.
    checked = await asyncio.create_subprocess_exec(
        SING_BOX, "check", "-c", str(config_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, check_err = await checked.communicate()
    if checked.returncode != 0:
        print("sing-box rejected the config:", file=sys.stderr)
        print(check_err.decode()[-2000:], file=sys.stderr)
        raise RuntimeError("sing-box check failed")

    proc = await asyncio.create_subprocess_exec(
        SING_BOX, "run", "-c", str(config_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await asyncio.sleep(3)  # startup time
    if proc.returncode is not None:
        stdout, stderr = await proc.communicate()
        print(f"sing-box failed to start (exit {proc.returncode}):", file=sys.stderr)
        print(stderr.decode()[-2000:], file=sys.stderr)
        raise RuntimeError(f"sing-box exited with code {proc.returncode}")
    return proc


def limit_verification(
    config: dict[str, Any],
    records: list[dict[str, Any]],
    stats: dict[str, int],
    limit: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int]]:
    """Keep only the first `limit` already-parsed records, config stays consistent."""
    if limit <= 0 or len(records) <= limit:
        return config, records, stats

    kept_tags = {record["id"] for record in records[:limit]}
    limited = records[:limit]
    return {
        "log": config["log"],
        "inbounds": [
            inbound
            for inbound in config["inbounds"]
            if inbound["tag"].removeprefix("in-") in kept_tags
        ],
        "outbounds": [
            outbound
            for outbound in config["outbounds"]
            if outbound["tag"] == "direct" or outbound["tag"].removeprefix("proxy-") in kept_tags
        ],
        "route": {
            "rules": [
                rule
                for rule in config["route"]["rules"]
                if rule["inbound"][0].removeprefix("in-") in kept_tags
            ],
            "final": config["route"]["final"],
        },
    }, limited, {**stats, "input": len(limited)}


async def main() -> int:
    worker_url = os.environ.get("WORKER_URL", "").rstrip("/")
    worker_token = os.environ.get("WORKER_TOKEN", "")
    if not worker_url or not worker_token:
        print("Set WORKER_URL and WORKER_TOKEN", file=sys.stderr)
        return 2
    if not worker_url.startswith("https://"):
        print("WORKER_URL must be an HTTPS URL.", file=sys.stderr)
        return 2

    print("Fetching candidate configs...")
    try:
        req = urllib.request.Request(SOURCE_URL, headers={"accept": "text/plain"})
        body = urllib.request.urlopen(req, timeout=30).read().decode()
    except Exception as exc:
        print(f"Failed to fetch source: {exc}", file=sys.stderr)
        return 1

    # Drop exact duplicates before anything is parsed or tested.
    uris: list[str] = []
    seen: set[str] = set()
    for line in body.splitlines():
        uri = line.strip()
        if uri and uri not in seen:
            seen.add(uri)
            uris.append(uri)
    if not uris:
        print("No configs from source", file=sys.stderr)
        return 1
    print(f"Fetched {len(uris)} unique configs")

    config, records, stats = build_sing_box_config(uris)
    config, records, stats = limit_verification(config, records, stats, VERIFY_LIMIT)
    if not records:
        print("No supported configs", file=sys.stderr)
        return 1

    # Deduplicate by endpoint before any network testing: many URIs point at
    # the same server:port with different UUIDs, and testing each one repeats
    # the same socket work.
    config, records = dedupe_endpoints(config, records)

    print(f"Starting sing-box with {len(records)} configs...")
    sing_box_proc = await _run_sing_box(config)

    try:
        # Each stage runs to completion before the next starts, so a stage's
        # wall time is the gap between its start and end lines in the log.
        # Without these, a slow run is indistinguishable from a hung one.
        stage_started = time.monotonic()

        def _mark(label: str) -> None:
            nonlocal stage_started
            now = time.monotonic()
            print(f"[{now - stage_started:7.1f}s] {label}")
            stage_started = now

        # TCP is cheap (one CONNECT). HTTPS costs a full TLS handshake, so it
        # gets its own independent limit instead of sharing one with TCP.
        tcp_semaphore = asyncio.Semaphore(TCP_CONCURRENCY)
        https_semaphore = asyncio.Semaphore(HTTPS_CONCURRENCY)
        speed_semaphore = asyncio.Semaphore(SPEED_CONCURRENCY)

        # ── Stage 1: 20 TCP requests, keep >=95% ──────────────────────────
        _mark(f"Stage 1: TCP x{PACKET_TEST_COUNT} ({len(records)} configs)...")

        tcp_results = await asyncio.gather(*[
            _tcp_reliability(r, tcp_semaphore) for r in records
        ])
        tcp_survivors = [
            r for r, rate in zip(records, tcp_results)
            if rate >= TCP_MIN_SUCCESS_RATE
        ]
        print(
            f"Stage 1 passed: {len(tcp_survivors)}/{len(records)} "
            f"(>={TCP_MIN_SUCCESS_RATE:.0%})"
        )
        if not tcp_survivors:
            print("No configs passed TCP", file=sys.stderr)
            return 1

        # ── Stages 2 and 3 concurrently ───────────────────────────────────
        # Stage 2 (UDP) and Stage 3 (speed) probe the SAME tcp_survivors, and
        # neither result feeds the other: UDP is a flag that never rejects, and
        # speed is an independent measurement. Run back to back they cost the
        # sum -- 215.7s + 176.5s = 392s in run 36455487959, by far the largest
        # block in the job. Launched as tasks they cost the max instead, since
        # the two are bounded by different semaphores (tcp vs speed) and do
        # not contend for the same resource.
        #
        # The stage banners are emitted up front so the log still attributes
        # time to a stage, and each _mark still stamps its own elapsed.
        _mark(f"Stage 2: UDP x{PACKET_TEST_COUNT} ({len(tcp_survivors)} configs)...")
        _mark(f"Stage 3: {SPEED_TEST_BYTES // 1_000_000}MB download ({len(tcp_survivors)} configs)...")
        # asyncio.gather() requires coroutines, so these are launched as
        # ensure_future tasks and gathered together below. Passing the gather
        # objects themselves is a TypeError, not a no-op.
        udp_task = asyncio.ensure_future(asyncio.gather(*[
            _udp_reliability(r, tcp_semaphore) for r in tcp_survivors
        ]))
        speed_task = asyncio.ensure_future(asyncio.gather(*[
            _speed_test(r, worker_url, worker_token, speed_semaphore) for r in tcp_survivors
        ]))
        udp_results, speed_results = await asyncio.gather(udp_task, speed_task)

        udp_flags = dict(zip((r["id"] for r in tcp_survivors), udp_results))
        udp_yes = sum(1 for v in udp_flags.values() if v >= UDP_MIN_SUCCESS_RATE)
        print(f"Stage 2: UDP capable: {udp_yes}/{len(tcp_survivors)} (not a filter)")
        if UDP_FAILURE_REASONS:
            # The reason a probe failed is what separates "these proxies are
            # TCP-only" from "the probe is broken". Without this, both read
            # as 0/N and the two are indistinguishable after the fact.
            ranked = sorted(
                UDP_FAILURE_REASONS.items(), key=lambda kv: -kv[1]
            )
            print("Stage 2: why UDP failed:")
            for reason, count in ranked:
                print(f"  {count:>6}  {reason}")

        speed_by_id = {r["id"]: res for r, res in zip(tcp_survivors, speed_results)}
        speed_survivors = [r for r in tcp_survivors if speed_by_id[r["id"]].get("speed_ok")]
        print(
            f"Stage 3 passed: {len(speed_survivors)}/{len(tcp_survivors)} "
            f"(>={MIN_SPEED_MB_S * 1000:.0f} KB/s)"
        )
        # Stage 3 is the largest filter in the pipeline, so its failure modes
        # are the ones worth knowing about. Without this tally the log shows a
        # bare pass count and a genuinely slow exit is indistinguishable from
        # one whose egress lookup failed: both just vanish.
        # Count the FAILURES, not every candidate. Iterating tcp_survivors here
        # put the 367 configs that downloaded fine into the "unknown" bucket
        # (no error key at all), which made the tally read as if every success
        # were a mystery. Failures are the ones with an error string, or that
        # came back without speed data; anything else genuinely passed.
        speed_reasons: dict[str, int] = {}
        for r in tcp_survivors:
            if speed_by_id[r["id"]].get("speed_ok"):
                continue  # a pass, not a failure
            rec = speed_by_id[r["id"]]
            # No error string and no speed_ok means the record came back
            # empty: the worker never produced a verdict for this config.
            reason = rec.get("error") or "no_speed_data"
            speed_reasons[reason] = speed_reasons.get(reason, 0) + 1
        if sum(speed_reasons.values()):
            print(f"Stage 3: why {sum(speed_reasons.values())} download(s) failed:")
            for reason, count in sorted(speed_reasons.items(), key=lambda kv: -kv[1]):
                print(f"  {count:>6}  {reason}")
        if not speed_survivors:
            print("No configs passed the download test", file=sys.stderr)
            return 1

        # ── Stage 4: 20 HTTPS requests, >=90% ─────────────────────────────
        _mark(f"Stage 4: HTTPS x{PACKET_TEST_COUNT} ({len(speed_survivors)} configs)...")
        https_results = await asyncio.gather(*[
            _https_reliability(r, https_semaphore) for r in speed_survivors
        ])
        tcp_rate_by_id = dict(zip((r["id"] for r in tcp_survivors), tcp_results))
        udp_by_id = udp_flags
        enriched = []
        for r, https_rate in zip(speed_survivors, https_results):
            speed = speed_by_id[r["id"]]
            enriched.append({
                "id": r["id"],
                "scheme": r["scheme"],
                "server": r["server"],
                "server_port": r["server_port"],
                "uri": r["uri"],
                "country": speed.get("country"),
                "stages": {
                    "tcp": {
                        "attempts": PACKET_TEST_COUNT,
                        "success_rate": round(tcp_rate_by_id[r["id"]], 3),
                        "passed": tcp_rate_by_id[r["id"]] >= TCP_MIN_SUCCESS_RATE,
                    },
                    "udp": {
                        "attempts": PACKET_TEST_COUNT,
                        "success_rate": round(udp_by_id[r["id"]], 3),
                        "supports_udp": udp_by_id[r["id"]] >= UDP_MIN_SUCCESS_RATE,
                    },
                    "download": {
                        "speed_mb_s": speed.get("download_mb_s"),
                        "latency_ms": speed.get("latency_ms"),
                        "passed": speed.get("speed_ok"),
                    },
                    "https": {
                        "attempts": PACKET_TEST_COUNT,
                        "success_rate": round(https_rate, 3),
                        "passed": https_rate >= HTTPS_MIN_SUCCESS_RATE,
                    },
                },
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })

        survivors = [c for c in enriched if c["stages"]["https"]["passed"]]
        print(
            f"Stage 4 passed: {len(survivors)}/{len(speed_survivors)} "
            f"(>={HTTPS_MIN_SUCCESS_RATE:.0%})"
        )
        if not survivors:
            # A 0/N run has to be diagnosable. Without this line there is no
            # way to tell a dead target from proxies that cannot reach it.
            print(
                f"HTTPS stage produced no survivors: "
                f"{https_failure_summary(https_results, HTTPS_MIN_SUCCESS_RATE)}",
                file=sys.stderr,
            )

        OUTPUT.mkdir(parents=True, exist_ok=True)
        output_path = OUTPUT / "enriched-configs.json"
        output_path.write_text(json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "configs": survivors,
            "stats": {
                "input": stats["input"],
                "supported": stats["supported"],
                "stage1_tcp_passed": len(tcp_survivors),
                "udp_capable": udp_yes,
                "stage3_download_passed": len(speed_survivors),
                "stage4_https_passed": len(survivors),
            }
        }, indent=2))
        _mark(f"Done. Enriched configs: {len(survivors)}")
        print(f"Saved to {output_path}")

    finally:
        if sing_box_proc.returncode is None:
            sing_box_proc.terminate()
            try:
                await asyncio.wait_for(sing_box_proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                sing_box_proc.kill()
                await sing_box_proc.wait()

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))