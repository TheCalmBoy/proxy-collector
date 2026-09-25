import asyncio
import importlib.util
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify", ROOT / "tools" / "verify.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Unable to load verify.py")
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


class VerifyPortRoutingTests(unittest.TestCase):
    def test_build_preserves_remote_and_local_ports(self):
        config, records, _ = verify.build_sing_box_config(
            ["socks5://user:pass@example.com:1080"]
        )

        self.assertEqual(records[0]["server_port"], 1080)
        self.assertEqual(records[0]["port"], 30000)
        self.assertEqual(config["inbounds"][0]["listen_port"], records[0]["port"])

    def test_all_tiers_use_local_sing_box_inbound(self):
        tcp_calls = []
        packet_calls = []
        speed_calls = []

        async def fake_socks_connect(proxy_port, host, port, timeout):
            tcp_calls.append((proxy_port, host, port, timeout))
            return True, b"\x05\x00"

        async def fake_packet(record):
            packet_calls.append(record["port"])
            return {
                "tcp": {"success_rate": 1.0, "success_count": 20},
                "passed": True,
            }

        async def fake_speed(record, worker_url, token, semaphore):
            speed_calls.append(record["port"])
            return {
                "ok": True,
                "country": "NL",
                "fraud_score": 0,
                "risk": "low",
                "latency_ms": 10.0,
                "download_mb_s": 1.0,
                "speed_ok": True,
                "speed_error": None,
            }

        class FakeProcess:
            returncode = None

            def terminate(self):
                self.returncode = 0

            async def wait(self):
                return self.returncode

        async def fake_run_sing_box(_config):
            return FakeProcess()

        response = io.BytesIO(b"socks5://user:pass@example.com:1080\n")
        response.read = lambda: b"socks5://user:pass@example.com:1080\n"

        with tempfile.TemporaryDirectory() as output_dir:
            env = {
                "WORKER_URL": "https://worker.example",
                "WORKER_TOKEN": "test-token",
            }
            with (
                mock.patch.dict(os.environ, env),
                mock.patch.object(verify, "OUTPUT", Path(output_dir)),
                mock.patch.object(verify, "_run_sing_box", fake_run_sing_box),
                mock.patch.object(verify, "_socks5_connect", fake_socks_connect),
                mock.patch.object(verify, "_packet_test", fake_packet),
                mock.patch.object(verify, "_speed_test", fake_speed),
                mock.patch.object(verify.urllib.request, "urlopen", return_value=response),
            ):
                result = asyncio.run(verify.main())

        self.assertEqual(result, 0)
        self.assertEqual(tcp_calls, [(30000, "1.1.1.1", 443, verify.TCP_TIMEOUT)])
        self.assertEqual(packet_calls, [30000])
        self.assertEqual(speed_calls, [30000])


if __name__ == "__main__":
    unittest.main()
