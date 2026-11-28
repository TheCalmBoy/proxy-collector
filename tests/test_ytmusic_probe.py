"""Bounded, informational YouTube Music reachability probe tests."""

from __future__ import annotations

import asyncio
import re
import unittest
from unittest import mock

from tools import probe_egress
from tools.probe_egress import (
    YTMUSIC_MAX_BODY_BYTES,
    _attach_probe_signals,
    _ytmusic_probe,
    _ytmusic_verdict,
)


def _curl_result(
    *,
    status: int,
    final_url: str = "https://music.youtube.com/",
    body: bytes = b'{"contentRegion":"US"}',
    returncode: int = 0,
):
    class FakeReader:
        def __init__(self, value):
            self.value = bytearray(value)
            self.read_sizes = []
            self.bytes_read = 0

        async def read(self, size=-1):
            self.read_sizes.append(size)
            if size < 0:
                size = len(self.value)
            chunk = bytes(self.value[:size])
            del self.value[:size]
            self.bytes_read += len(chunk)
            return chunk

    class FakeWriter:
        def __init__(self):
            self.value = bytearray()

        def write(self, value):
            self.value.extend(value)

        async def drain(self):
            return None

        def close(self):
            return None

    class FakeProcess:
        def __init__(self):
            self.returncode = returncode
            self.stdin = FakeWriter()
            self.stdout = FakeReader(body)
            metadata = f"__YTMUSIC_META__{final_url}\t{status}".encode()
            self.stderr = FakeReader(metadata)

        async def wait(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

    return FakeProcess()


def _run_probe(fake_process, *, signatures=None):
    signatures = (
        probe_egress.YTMUSIC_REGION_UNAVAILABLE_SIGNATURES
        if signatures is None
        else signatures
    )
    with mock.patch.object(
        probe_egress.asyncio,
        "create_subprocess_exec",
        new=mock.AsyncMock(return_value=fake_process),
    ) as create_process, mock.patch.object(
        probe_egress,
        "YTMUSIC_REGION_UNAVAILABLE_SIGNATURES",
        signatures,
    ):
        result = asyncio.run(_ytmusic_probe(34567))
    return result, create_process, fake_process


class YouTubeMusicProbeTests(unittest.TestCase):
    def test_supported_shell_is_reachable_but_region_is_unverified(self):
        result, create_process, fake = _run_probe(_curl_result(status=200))
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["region_verified"])
        self.assertEqual(result["final_host"], "music.youtube.com")
        self.assertEqual(result["final_path"], "/")
        self.assertEqual(create_process.call_args.args[0], "curl")
        self.assertIn("--max-redirs", create_process.call_args.args)
        self.assertIn("5", create_process.call_args.args)
        self.assertIn("--range", create_process.call_args.args)
        self.assertIn(f"0-{YTMUSIC_MAX_BODY_BYTES - 1}", create_process.call_args.args)
        self.assertIn("--max-filesize", create_process.call_args.args)
        self.assertIn(str(YTMUSIC_MAX_BODY_BYTES), create_process.call_args.args)
        self.assertIn(b"socks5h://127.0.0.1:34567", fake.stdin.value)

    def test_query_is_not_retained_in_published_metadata(self):
        result, _, _ = _run_probe(_curl_result(
            status=200,
            final_url="https://music.youtube.com/?private=query-value",
        ))
        self.assertEqual(result["final_path"], "/")
        self.assertNotIn("query-value", str(result))

    def test_blocked_region_requires_an_explicit_signature(self):
        # This synthetic marker only exercises the classifier branch. No
        # production region marker is configured because sampled US and RU
        # pages did not expose a region-unavailable message.
        result, _, _ = _run_probe(
            _curl_result(status=200, body=b"TEST_ONLY_REGION_BLOCK_MARKER"),
            signatures=(re.compile("TEST_ONLY_REGION_BLOCK_MARKER"),),
        )
        self.assertEqual(result["status"], "blocked_region")
        self.assertTrue(result["region_verified"])

    def test_google_sorry_redirect_is_flagged(self):
        result, _, _ = _run_probe(_curl_result(
            status=200,
            final_url="https://www.google.com/sorry/index?continue=private",
            body=b"challenge",
        ))
        self.assertEqual(result["status"], "flagged")
        self.assertEqual(result["final_path"], "/sorry/index")
        self.assertNotIn("private", str(result))

    def test_401_and_403_are_flagged(self):
        for code in (401, 403):
            with self.subTest(code=code):
                result, _, _ = _run_probe(_curl_result(status=code, body=b"denied"))
                self.assertEqual(result["status"], "flagged")

    def test_429_and_server_errors_are_unknown_even_on_sorry_url(self):
        for code in (429, 500, 503):
            with self.subTest(code=code):
                result, _, _ = _run_probe(_curl_result(
                    status=code,
                    final_url="https://www.google.com/sorry/index",
                    body=b"challenge",
                ))
                self.assertEqual(result["status"], "unknown")

    def test_curl_errors_and_unrecognised_pages_are_unknown(self):
        error, _, _ = _run_probe(_curl_result(status=0, returncode=28, body=b""))
        unknown, _, _ = _run_probe(_curl_result(status=200, body=b"ordinary html"))
        self.assertEqual(error["status"], "unknown")
        self.assertEqual(unknown["status"], "unknown")

    def test_body_after_64k_is_not_read_for_signatures(self):
        body = b'{"contentRegion":"US"}' + b"x" * YTMUSIC_MAX_BODY_BYTES
        body += b"TEST_ONLY_REGION_BLOCK_MARKER"
        result, _, fake = _run_probe(
            _curl_result(status=200, body=body, returncode=63),
            signatures=(re.compile("TEST_ONLY_REGION_BLOCK_MARKER"),),
        )
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["body_truncated"])
        self.assertEqual(fake.stdout.bytes_read, YTMUSIC_MAX_BODY_BYTES)
        self.assertIn(b"TEST_ONLY_REGION_BLOCK_MARKER", fake.stdout.value)

    def test_probe_verdict_aggregation_ignores_unknown_rounds(self):
        verdict = _ytmusic_verdict([
            {"status": "unknown"},
            {"status": "ok", "http_status": 200, "final_host": "music.youtube.com", "final_path": "/"},
            {"status": "unknown", "http_status": 429},
            {"status": "unknown", "error": "not_probed"},
        ])
        self.assertEqual(verdict["status"], "ok")
        self.assertEqual(verdict["rounds"], 1)
        self.assertFalse(verdict["region_verified"])
        self.assertEqual(verdict["http_status"], 429)

    def test_explicit_region_block_wins_over_clean_rounds(self):
        verdict = _ytmusic_verdict([{"status": "ok"}, {"status": "blocked_region"}])
        self.assertEqual(verdict["status"], "blocked_region")
        self.assertTrue(verdict["region_verified"])

    def test_all_unknown_rounds_stay_unknown(self):
        verdict = _ytmusic_verdict([{"status": "unknown"}, None])
        self.assertEqual(verdict["status"], "unknown")
        self.assertEqual(verdict["rounds"], 0)

    def test_enriched_configs_receive_both_signal_fields(self):
        enriched = [
            {"scheme": "vless", "server": "exit.example", "server_port": 443},
            {"scheme": "trojan", "server": "other.example", "server_port": 443},
        ]
        health = {
            "AAA111": {
                "scheme": "VLESS", "server": "EXIT.EXAMPLE.", "server_port": "443",
                "gemini": {"status": "clean", "clean": True, "flagged": False, "rounds": 1},
                "ytmusic": {"status": "ok", "rounds": 1, "http_status": 200},
            }
        }
        _attach_probe_signals(enriched, health)
        self.assertEqual(enriched[0]["gemini"]["status"], "clean")
        self.assertEqual(enriched[0]["ytmusic"]["status"], "ok")
        self.assertEqual(enriched[1]["gemini"]["status"], "unknown")
        self.assertEqual(enriched[1]["ytmusic"]["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
