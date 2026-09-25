import asyncio
import importlib.util
import io
import json
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

    def test_limit_verification_keeps_config_and_records_in_sync(self):
        config, records, stats = verify.build_sing_box_config(
            [
                "socks5://one.example:1080",
                "socks5://two.example:1081",
                "socks5://three.example:1082",
            ]
        )

        limited_config, limited_records, limited_stats = verify.limit_verification(
            config, records, stats, 2
        )

        kept_ids = {record["id"] for record in limited_records}
        self.assertEqual(len(limited_records), 2)
        self.assertEqual(limited_stats["input"], 2)
        self.assertEqual(
            {inbound["tag"].removeprefix("in-") for inbound in limited_config["inbounds"]},
            kept_ids,
        )
        self.assertEqual(
            {
                outbound["tag"].removeprefix("proxy-")
                for outbound in limited_config["outbounds"]
                if outbound["tag"] != "direct"
            },
            kept_ids,
        )
        self.assertEqual(
            {rule["inbound"][0].removeprefix("in-") for rule in limited_config["route"]["rules"]},
            kept_ids,
        )
        self.assertEqual(limited_config["outbounds"][-1]["tag"], "direct")

    def test_all_tiers_use_local_sing_box_inbound(self):
        tcp_calls = []
        packet_calls = []
        speed_calls = []

        async def fake_socks_connect(proxy_port, host, port, timeout):
            tcp_calls.append((proxy_port, host, port, timeout))
            return True, b"\x05\x00"

        async def fake_packet(record, _tcp_sem=None, _https_sem=None):
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

    def test_tcp_and_https_use_independent_concurrency_limits(self):
        active = {"tcp": 0, "https": 0}
        peak = {"tcp": 0, "https": 0}

        async def fake_socks_connect(*_args):
            active["tcp"] += 1
            peak["tcp"] = max(peak["tcp"], active["tcp"])
            await asyncio.sleep(0)
            active["tcp"] -= 1
            return True, b"\x05\x00"

        async def fake_packet(_record, tcp_sem=None, https_sem=None):
            async def run():
                active["https"] += 1
                peak["https"] = max(peak["https"], active["https"])
                await asyncio.sleep(0)
                active["https"] -= 1
                return {
                    "tcp": {"success_rate": 1.0, "success_count": 20},
                    "https": {"success_rate": 1.0, "success_count": 20},
                    "passed": True,
                }

            if https_sem is None:
                return await run()
            async with https_sem:
                return await run()

        async def fake_speed(*_args):
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

        uris = "\n".join(
            f"socks5://user{i}:pass@host{i}.example:1080" for i in range(12)
        )
        response = io.BytesIO(uris.encode())
        response.read = lambda: uris.encode()

        with tempfile.TemporaryDirectory() as output_dir:
            env = {
                "WORKER_URL": "https://worker.example",
                "WORKER_TOKEN": "test-token",
            }
            with (
                mock.patch.dict(os.environ, env),
                mock.patch.object(verify, "OUTPUT", Path(output_dir)),
                mock.patch.object(verify, "TCP_CONCURRENCY", 750),
                mock.patch.object(verify, "HTTPS_CONCURRENCY", 2),
                mock.patch.object(verify, "VERIFY_LIMIT", 0),
                mock.patch.object(verify, "_run_sing_box", fake_run_sing_box),
                mock.patch.object(verify, "_socks5_connect", fake_socks_connect),
                mock.patch.object(verify, "_packet_test", fake_packet),
                mock.patch.object(verify, "_speed_test", fake_speed),
                mock.patch.object(verify.urllib.request, "urlopen", return_value=response),
            ):
                result = asyncio.run(verify.main())

        self.assertEqual(result, 0)
        # TCP is cheap and unthrottled; HTTPS honours its own lower limit.
        self.assertEqual(peak["tcp"], 12)
        self.assertLessEqual(peak["https"], 2)

    def test_slow_configs_are_not_written_to_enriched_output(self):
        async def fake_socks_connect(*_args):
            return True, b"\x05\x00"

        async def fake_packet(_record, _tcp_sem=None, _https_sem=None):
            return {
                "tcp": {"success_rate": 1.0, "success_count": 20},
                "passed": True,
            }

        async def fake_speed(record, _worker_url, _token, _semaphore):
            passed = record["port"] == 30000
            return {
                "ok": passed,
                "country": "NL",
                "fraud_score": 0,
                "risk": "low",
                "latency_ms": 10.0,
                "download_mb_s": 1.0 if passed else 0.01,
                "speed_ok": passed,
                "error": None if passed else "speed_below_threshold",
            }

        class FakeProcess:
            returncode = None

            def terminate(self):
                self.returncode = 0

            async def wait(self):
                return self.returncode

        async def fake_run_sing_box(_config):
            return FakeProcess()

        source = (
            b"socks5://one:pass@example.com:1080\n"
            b"socks5://two:pass@example.net:1081\n"
        )
        response = io.BytesIO(source)

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
            output = json.loads(
                (Path(output_dir) / "enriched-configs.json").read_text()
            )

        self.assertEqual(len(output["configs"]), 1)
        self.assertEqual(output["configs"][0]["server"], "example.com")
        self.assertEqual(output["stats"]["tier3_passed"], 1)


if __name__ == "__main__":
    unittest.main()
