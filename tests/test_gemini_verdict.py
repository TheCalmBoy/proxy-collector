#!/usr/bin/env python3
"""The Gemini flag must be able to say "I don't know".

The whole point of probing gemini.google.com is to learn whether Google will
serve this exit IP. That produces three genuinely different answers, and
collapsing any two of them is a bug that shows up as a bad node being trusted:

  clean   - Gemini served us at least once, never flagged
  flagged - a 401/403/429 came back, so the IP is on a reputation list
  unknown - every round timed out or errored; we have no evidence either way

The dangerous collapse is unknown -> clean, which credits a node we never
managed to check. The other dangerous collapse is clean -> flagged on a single
noisy round, which would throw away working nodes.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from probe_egress import _gemini_verdict  # noqa: E402


class GeminiVerdictTests(unittest.TestCase):
    def test_all_clean_rounds_are_clean(self):
        v = _gemini_verdict([True, True, True])
        self.assertEqual(v["status"], "clean")
        self.assertIs(v["clean"], True)
        self.assertIs(v["flagged"], False)
        self.assertEqual(v["rounds"], 3)

    def test_a_single_403_makes_the_whole_config_flagged(self):
        # One round was refused. The user who meets that 403 has lost the node,
        # so averaging it away would hide the only thing worth knowing.
        v = _gemini_verdict([True, True, False])
        self.assertEqual(v["status"], "flagged")
        self.assertIs(v["clean"], False)
        self.assertIs(v["flagged"], True)

    def test_never_checked_is_unknown_not_clean(self):
        v = _gemini_verdict([None, None])
        self.assertEqual(v["status"], "unknown")
        # The assertions that matter: unknown must not read as clean.
        self.assertIsNot(v["clean"], True)
        self.assertIsNot(v["flagged"], False)

    def test_empty_history_is_unknown(self):
        v = _gemini_verdict([])
        self.assertEqual(v["status"], "unknown")
        self.assertEqual(v["rounds"], 0)
        self.assertIsNone(v["clean"])

    def test_unknown_rounds_do_not_dilute_a_real_flag(self):
        # Two refusals and a timeout is still flagged, not "mostly clean".
        v = _gemini_verdict([False, None, False])
        self.assertEqual(v["status"], "flagged")
        self.assertEqual(v["rounds"], 2, "only the answered rounds count")

    def test_one_clean_answer_with_timeouts_is_clean(self):
        # We did get a real 200; the other rounds are noise, not evidence of
        # a flag, and one working answer is worth having.
        v = _gemini_verdict([None, True, None])
        self.assertEqual(v["status"], "clean")
        self.assertEqual(v["rounds"], 1)


if __name__ == "__main__":
    unittest.main()
