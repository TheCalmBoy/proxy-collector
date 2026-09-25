"""Regression tests for IP classification.

The collector silently classified every entry as UNKNOWN because the batch
request asked ip-api for Pro-only fields ("hosting", "proxy"). ip-api answers a
batch containing those fields with status=fail for every IP, so classify() hit
its first branch and returned UNKNOWN 978 times out of 978.
"""

import importlib.util
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "collector_main", Path(__file__).resolve().parents[1] / "main.py"
)
main = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(main)


class TestClassify(unittest.TestCase):
    def test_failed_lookups_stay_unknown(self):
        self.assertEqual(main.classify({"status": "fail"}), "UNKNOWN")
        self.assertEqual(main.classify({}), "UNKNOWN")

    def test_pro_hosting_boolean_still_wins(self):
        self.assertEqual(main.classify({"status": "success", "hosting": True}), "DC")
        self.assertEqual(main.classify({"status": "success", "hosting": False}), "RES")

    def test_free_tier_aws_is_datacenter(self):
        result = {
            "status": "success",
            "isp": "Amazon.com, Inc.",
            "as": "AS16509 Amazon.com, Inc.",
        }
        self.assertEqual(main.classify(result), "DC")

    def test_free_tier_consumer_isp_is_residential(self):
        result = {
            "status": "success",
            "isp": "Aria S.p.A.",
            "asname": "ARIA S.p.A.",
        }
        self.assertEqual(main.classify(result), "RES")

    def test_success_with_no_metadata_is_unknown(self):
        self.assertEqual(main.classify({"status": "success"}), "UNKNOWN")

    def test_requested_fields_are_free_tier_only(self):
        """Pro-only fields in the batch request are what broke classification."""
        for pro_only in ("hosting", "proxy"):
            self.assertNotIn(
                pro_only,
                main.DEFAULT_IP_API_FIELDS.split(","),
                f"{pro_only} is Pro-only and fails the whole free-tier batch",
            )


if __name__ == "__main__":
    unittest.main()
