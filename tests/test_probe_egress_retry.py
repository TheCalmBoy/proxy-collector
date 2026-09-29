"""A refused connection must not be believed on the first try.

Curl exit 7 means "could not connect". On a runner that is already running
one sing-box process with a listener per config, that is usually local
exhaustion rather than a dead proxy: the published health data showed every
survivor was shadowsocks and every vless/vmess/trojan was reported dead,
which is a race between configs, not a property of the protocols.

These tests pin the retry so the symptom cannot come back.
"""

import asyncio
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import probe_egress  # noqa: E402


class RefusedConnectionRetries(unittest.TestCase):
    def _curl(self, *returncodes):
        calls = iter(returncodes)

        async def run(config_lines):
            code = next(calls)
            body = (
                "fl=123abc\nh=www.cloudflare.com\nip=203.0.113.9\nts=1700000000.1\n"
                "visit_scheme=https\nuag=curl/8.0\ncolo=LHR\nsliver=none\nhttp=http/2\n"
                "loc=GB\ntls=TLSv1.3\nsni=plaintext\nwarp=off\ngateway=off\nrbi=off\nkex=X25519\n"
                if code == 0
                else ""
            )
            return code, body

        return run

    def test_exit_7_is_retried_and_can_succeed(self):
        with mock.patch.object(probe_egress, "_run_curl", self._curl(7, 0)):
            result = asyncio.run(probe_egress._cloudflare_trace(30000))
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["ip"], "203.0.113.9")

    def test_exit_7_twice_still_reports_the_failure(self):
        with mock.patch.object(probe_egress, "_run_curl", self._curl(7, 7)):
            result = asyncio.run(probe_egress._cloudflare_trace(30001))
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "curl_exit_7")

    def test_curl_is_attempted_exactly_twice(self):
        attempts = []

        async def run(config_lines):
            attempts.append(config_lines)
            return 7, ""

        with mock.patch.object(probe_egress, "_run_curl", run):
            with mock.patch.object(probe_egress.asyncio, "sleep", mock.AsyncMock()):
                asyncio.run(probe_egress._cloudflare_trace(30002))
        self.assertEqual(len(attempts), 2)

    def test_a_real_handshake_failure_is_not_retried(self):
        attempts = []

        async def run(config_lines):
            attempts.append(config_lines)
            return 35, ""  # TLS handshake error: the proxy answered.

        with mock.patch.object(probe_egress, "_run_curl", run):
            result = asyncio.run(probe_egress._cloudflare_trace(30003))
        self.assertEqual(len(attempts), 1, "only a refused connection is ambiguous")
        self.assertEqual(result["error"], "curl_exit_35")

    def test_every_other_exit_code_is_also_attempted_once(self):
        for code in (28, 35, 56, 97):
            with self.subTest(exit_code=code):
                attempts = []

                async def run(config_lines, _code=code):
                    attempts.append(config_lines)
                    return _code, ""

                with mock.patch.object(probe_egress, "_run_curl", run):
                    result = asyncio.run(probe_egress._cloudflare_trace(30004))
                self.assertEqual(len(attempts), 1)
                self.assertEqual(result["error"], f"curl_exit_{code}")


class DefaultConcurrencyIsNotTheOldValue(unittest.TestCase):
    def test_phase_one_default_is_below_the_runaway_value(self):
        # 750 was the default before the race was understood. It must not
        # come back by accident, because it is what exhausted descriptors.
        source = (Path(__file__).resolve().parents[1] / "tools" / "probe_egress.py").read_text()
        for line in source.splitlines():
            if 'os.getenv("PROBE_CONCURRENCY"' in line:
                self.assertNotIn('"750"', line, f"concurrency default regressed: {line.strip()}")


if __name__ == "__main__":
    unittest.main()
