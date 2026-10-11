"""Egress listeners must be allocated outside the kernel's ephemeral range.

The probe used to hardcode `PORT_BASE + len(records)`, which placed every
SOCKS listener starting at 30000 while the kernel hands out ephemeral ports
from 32768. When a listener lost that race the connection was refused, curl
returned exit 7, and the proxy was published as dead.

The symptom looked like a protocol bug - the published health data held
100% shadowsocks and 0% of every other scheme - but it moved with file
order, not with the protocols, and it survived a retry. A local sing-box run
had a vless config answering HTTP 200 on the first try, which is what proved
the protocols were never the problem.

verify.py already solved this for itself with _pick_inbound_base. These tests
pin the same guarantee for probe_egress.py.
"""

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import probe_egress  # noqa: E402


SS = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@203.0.113.10:8388#node"


class InboundBaseAvoidsEphemeralRange(unittest.TestCase):
    def test_chosen_base_does_not_overlap_the_ephemeral_range(self):
        lo, hi = probe_egress._ephemeral_bounds()
        for count in (1, 50, 285, 1000):
            with self.subTest(count=count):
                base = probe_egress._pick_inbound_base(count)
                self.assertFalse(
                    base + count > lo and base < hi,
                    f"ports {base}..{base + count - 1} overlap ephemeral {lo}-{hi}",
                )

    def test_a_fully_blocked_host_still_returns_a_usable_base(self):
        # Best effort by design: it must not raise and abort the run.
        with mock.patch.object(probe_egress, "_probe_range_free", mock.Mock(return_value=False)):
            base = probe_egress._pick_inbound_base(285)
        self.assertTrue(1000 < base < 32000, base)

    def test_a_blocked_candidate_is_skipped(self):
        with mock.patch.object(
            probe_egress, "_probe_range_free", side_effect=lambda b, c: b != 15000
        ):
            base = probe_egress._pick_inbound_base(10)
        self.assertNotEqual(base, 15000)

    def test_env_var_is_honoured(self):
        with mock.patch.dict("os.environ", {"PROBE_INBOUND_PORT_BASE": "11000"}):
            base = probe_egress._pick_inbound_base(4)
        self.assertEqual(base, 11000)

    def test_ephemeral_bounds_reads_the_kernel_and_falls_back(self):
        lo, hi = probe_egress._ephemeral_bounds()
        self.assertLess(lo, hi)
        with mock.patch.object(
            probe_egress.Path, "read_text", side_effect=OSError("no procfs")
        ):
            self.assertEqual(probe_egress._ephemeral_bounds(), (32768, 60999))

    def test_probe_range_free_reports_a_blocked_port(self):
        with mock.patch.object(probe_egress.socket, "socket", side_effect=OSError("in use")):
            self.assertFalse(probe_egress._probe_range_free(15000, 3))


class EveryListenerIsBindable(unittest.TestCase):
    def test_all_ports_are_unique_and_contiguous(self):
        cfg, records, _ = probe_egress.build_sing_box_config([SS] * 12)
        ports = [r["port"] for r in records]
        self.assertEqual(len(records), 12)
        self.assertEqual(len(set(ports)), 12, "duplicate listen_port")
        self.assertEqual(ports, list(range(min(ports), min(ports) + 12)))

    def test_no_listener_sits_in_the_ephemeral_range(self):
        _, records, _ = probe_egress.build_sing_box_config([SS] * 200)
        lo, hi = probe_egress._ephemeral_bounds()
        for rec in records:
            self.assertFalse(lo <= rec["port"] <= hi, rec["port"])

    def test_inbounds_and_records_agree(self):
        cfg, records, _ = probe_egress.build_sing_box_config([SS] * 5)
        inbound_ports = {i["listen_port"] for i in cfg["inbounds"]}
        self.assertEqual(inbound_ports, {r["port"] for r in records})


if __name__ == "__main__":
    unittest.main()
