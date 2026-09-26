"""Exercise the publish step's logic against a realistic enriched-configs.json.

The workflow's inline Python is invisible to the test suite, so it can only
be checked by running it. This reimplements the same logic against a record
shaped exactly like the one tools/verify.py writes, and asserts the
published layout matches what main.py produces.
"""
import base64
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def realistic_enriched() -> dict:
    """A record matching tools/verify.py's enriched.append(...) shape."""
    def rec(uri, country, https_passed):
        return {
            "id": uri[10:20],
            "scheme": "vless",
            "server": "1.2.3.4",
            "server_port": 443,
            "uri": uri,
            "country": country,
            "download_mb_s": 1.5,
            "latency_ms": 120.0,
            "stages": {
                "tcp": {"attempts": 20, "success_rate": 1.0, "passed": True},
                "udp": {"attempts": 20, "success_rate": 0.0, "supports_udp": False},
                "speed": {"attempts": 1, "success_rate": 1.0, "passed": True},
                "https": {"attempts": 20, "success_rate": 1.0 if https_passed else 0.0,
                          "passed": https_passed},
            },
        }

    return {
        "stats": {
            "total_configs": 600,
            "stage1_tcp_passed": 457,
            "stage2_udp_capable": 0,
            "stage3_speed_passed": 234,
            "stage4_https_passed": 37,
        },
        "configs": [
            rec("vless://aaaa1111@example.com:443?type=ws#node-us", "US", True),
            rec("vless://bbbb2222@example.org:443?type=ws#node-de", "DE", True),
            rec("vless://cccc3333@example.net:443?type=ws#node-fail", "FR", False),
            rec("vless://dddd4444@example.info:443?type=ws#node-unknown", None, True),
        ],
    }


class TestPublishStep(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "verify-output").mkdir()
        (self.root / "output").mkdir()
        (self.root / "output" / "countries").mkdir()
        (self.root / "verify-output" / "enriched-configs.json").write_text(
            json.dumps(realistic_enriched())
        )
        (self.root / "output" / "manifest.json").write_text(
            json.dumps({"stats": {"total_configs": 600}, "files": {"all": "all.txt"}})
        )
        # main.py's unverified output, which the publish step must overwrite.
        (self.root / "output" / "all.txt").write_text(
            "vless://stale0000@old.example.com:443#stale\n"
            "vless://stale1111@old.example.com:443#stale2\n"
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _run_publish(self):
        script = (REPO / ".github" / "workflows" / "publish_step.py")
        return subprocess.run(
            ["python3", str(script)],
            cwd=self.root, capture_output=True, text=True,
        )

    def test_publishes_only_https_survivors(self):
        proc = self._run_publish()
        self.assertEqual(proc.returncode, 0, proc.stderr)

        all_txt = (self.root / "output" / "all.txt").read_text().splitlines()
        # The FR config failed HTTPS, so it must not be published.
        self.assertNotIn("vless://cccc3333@example.net:443?type=ws#node-fail", all_txt)
        # The collector's unverified entries must be gone.
        self.assertEqual(len(all_txt), 3)
        self.assertIn("vless://aaaa1111@example.com:443?type=ws#node-us", all_txt)
        self.assertFalse(any("stale" in line for line in all_txt))

    def test_country_files_written(self):
        self.assertEqual(self._run_publish().returncode, 0)
        us = (self.root / "output" / "countries" / "US.txt").read_text().splitlines()
        self.assertEqual(us, ["vless://aaaa1111@example.com:443?type=ws#node-us"])
        de = (self.root / "output" / "countries" / "DE.txt").read_text().splitlines()
        self.assertEqual(de, ["vless://bbbb2222@example.org:443?type=ws#node-de"])

    def test_unknown_country_bucketed_as_zz(self):
        self.assertEqual(self._run_publish().returncode, 0)
        zz = (self.root / "output" / "countries" / "ZZ.txt").read_text()
        self.assertIn("dddd4444", zz)

    def test_base64_mirror_matches_main_py_convention(self):
        self.assertEqual(self._run_publish().returncode, 0)
        plain = (self.root / "output" / "all.txt").read_text().splitlines()
        encoded = (self.root / "output" / "all.base64.txt").read_text().splitlines()
        self.assertEqual(
            [base64.b64decode(e).decode() for e in encoded], plain
        )

    def test_enriched_data_is_published(self):
        self.assertEqual(self._run_publish().returncode, 0)
        published = json.loads(
            (self.root / "output" / "enriched-configs.json").read_text()
        )
        self.assertIn("stats", published)
        self.assertEqual(len(published["configs"]), 4)

    def test_manifest_records_verified_counts(self):
        self.assertEqual(self._run_publish().returncode, 0)
        manifest = json.loads((self.root / "output" / "manifest.json").read_text())
        self.assertEqual(manifest["stats"]["verified_survivors"], 3)
        self.assertEqual(manifest["stats"]["verified_countries"], 3)
        self.assertEqual(manifest["files"]["enriched"], "enriched-configs.json")

    def test_refuses_to_publish_empty_database(self):
        empty = {"stats": {}, "configs": [
            {**realistic_enriched()["configs"][2]},  # the only one that failed
        ]}
        (self.root / "verify-output" / "enriched-configs.json").write_text(
            json.dumps(empty)
        )
        proc = self._run_publish()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("no config passed", (proc.stderr + proc.stdout).lower())
        # The previous good output must survive a failed verification.
        self.assertIn(
            "stale", (self.root / "output" / "all.txt").read_text()
        )

    def test_stale_country_files_from_the_collector_are_removed(self):
        """main.py publishes a file per scraped country; verification
        eliminates most of them, and a leftover file would ship dead configs
        as if they were live."""
        # The collector wrote these before verification ran. FR has no
        # verified survivors, and IT was never verified at all.
        (self.root / "output" / "countries" / "FR.txt").write_text(
            "vless://dead0001@fr.example.com:443#dead\n"
            "vless://dead0002@fr.example.com:443#dead2\n"
        )
        (self.root / "output" / "countries" / "FR.base64.txt").write_text(
            "dmxlc3M6Ly9kZWFkMDAwMQ==\n"
        )
        (self.root / "output" / "countries" / "IT.txt").write_text(
            "vless://dead0003@it.example.com:443#dead3\n"
        )

        self.assertEqual(self._run_publish().returncode, 0)

        self.assertFalse(
            (self.root / "output" / "countries" / "FR.txt").exists(),
            "FR has zero verified survivors but its file was published",
        )
        self.assertFalse(
            (self.root / "output" / "countries" / "FR.base64.txt").exists(),
        )
        self.assertFalse(
            (self.root / "output" / "countries" / "IT.txt").exists(),
        )
        # The countries that do have survivors are still published.
        self.assertTrue((self.root / "output" / "countries" / "US.txt").exists())

    def test_published_country_files_sum_to_the_verified_count(self):
        enriched = realistic_enriched()
        expected = sum(1 for r in enriched["configs"] if r["stages"]["https"]["passed"])
        self.assertEqual(self._run_publish().returncode, 0)
        total = 0
        for path in (self.root / "output" / "countries").glob("*.txt"):
            if path.name.endswith(".base64.txt"):
                continue
            total += len(path.read_text().splitlines())
        self.assertEqual(total, expected)

    def test_missing_verified_file_fails_without_wiping_output(self):
        (self.root / "verify-output" / "enriched-configs.json").unlink()
        proc = self._run_publish()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("stale", (self.root / "output" / "all.txt").read_text())


if __name__ == "__main__":
    unittest.main()
