"""Stage 4's gate must measure proxy quality, not timing luck.

Three runs of byte-identical verify.py produced 37, 137 and 0 Stage 4
survivors. The gate was rejecting configs for reasons unrelated to whether
they work: a 1.5s budget that has to cover a TLS handshake, and a 2-failure
budget over 20 rounds that a single timeout could exhaust.
"""
import asyncio
import unittest
from unittest import mock

from tools import verify


class HttpsGateStability(unittest.TestCase):
    def _record(self):
        return {"id": "abc123", "port": 30000, "server": "1.2.3.4", "server_port": 443}

    def _scripted(self, pass_rates):
        """Run _https_reliability against a stubbed request.

        pass_rates gives the success rate of each pass of PACKET_TEST_COUNT
        rounds, so [0.9, 1.0] means the first pass succeeds 18/20 and the
        retry succeeds 20/20.
        """
        self.calls = {"pass": 0, "rounds": 0}

        async def fake_request(_port, _url, _timeout):
            idx = min(self.calls["pass"], len(pass_rates) - 1)
            rate = pass_rates[idx]
            round_index = self.calls["rounds"] % verify.PACKET_TEST_COUNT
            self.calls["rounds"] += 1
            # The first `rate * PACKET_TEST_COUNT` rounds of the pass succeed.
            succeed = round_index < round(rate * verify.PACKET_TEST_COUNT)
            if round_index == verify.PACKET_TEST_COUNT - 1:
                self.calls["pass"] += 1
            return succeed, 1.0

        async def fake_sleep(_):
            return None

        async def scenario():
            with mock.patch.object(verify, "_https_request", fake_request), \
                 mock.patch.object(verify.asyncio, "sleep", fake_sleep):
                return await verify._https_reliability(
                    self._record(), asyncio.Semaphore(1)
                )

        return asyncio.run(scenario())

    def test_https_stage_uses_its_own_timeout_not_the_tcp_one(self):
        """A TLS handshake plus HTTP round trip does not fit in the 1.5s
        budget that Stage 1 uses for a bare TCP connect."""
        self.assertGreater(verify.HTTPS_TIMEOUT, verify.TCP_TIMEOUT)
        self.assertGreaterEqual(verify.HTTPS_TIMEOUT, 5.0)

    def test_passing_config_is_not_retried(self):
        rate = self._scripted([1.0])
        self.assertEqual(rate, 1.0)
        # Exactly one pass of 20 requests.
        self.assertEqual(self.calls["rounds"], verify.PACKET_TEST_COUNT)

    def test_config_just_below_gate_gets_a_second_chance(self):
        """First pass fails two rounds (18/20 = 0.9 is not below the 0.9
        gate, so use 17/20 = 0.85), the retry passes cleanly."""
        self.assertEqual(verify.PACKET_TEST_COUNT, 20)
        # 0.85 is below the gate, so the retry fires; 1.0 is the retry.
        rate = self._scripted([0.85, 1.0])
        self.assertEqual(rate, 1.0)
        self.assertEqual(self.calls["rounds"], verify.PACKET_TEST_COUNT * 2)

    def test_dead_config_is_not_retried(self):
        rate = self._scripted([0.0, 0.0])
        self.assertEqual(rate, 0.0)
        # A config with zero successes is not retried: there is nothing to
        # rescue, and retrying would double the cost of every dead proxy.
        # The early exit also cuts this single pass short, so it costs the
        # failure budget (3 rounds at a 90% gate over 20), not 20.
        self.assertEqual(self.calls["rounds"], 3)

    def test_retry_never_lowers_a_rate(self):
        rate = self._scripted([0.95, 0.5])
        # 0.95 already clears the gate, so there is no retry and the first
        # pass stands.
        self.assertEqual(rate, 0.95)
        self.assertEqual(self.calls["rounds"], verify.PACKET_TEST_COUNT)

    def test_retry_result_is_kept_only_when_better(self):
        """A first pass below the gate followed by a worse retry must keep
        the better of the two, never the worse one."""
        rate = self._scripted([0.85, 0.5])
        self.assertEqual(rate, 0.85)


class FailureSummary(unittest.TestCase):
    def test_summary_explains_an_all_fail_run(self):
        summary = verify.https_failure_summary([0.0, 0.0, 0.05], 0.90)
        self.assertIn("all 3 below 90%", summary)
        self.assertIn("best=0.05", summary)
        self.assertIn("zeros=2", summary)

    def test_summary_reports_success_without_noise(self):
        self.assertEqual(verify.https_failure_summary([1.0, 0.5], 0.90), "some passed")

    def test_summary_handles_no_results(self):
        self.assertEqual(verify.https_failure_summary([], 0.90), "no results")


class EarlyExit(unittest.TestCase):
    """A pass that cannot reach the gate must stop early, but the rate it
    reports must stay identical to the rate a full pass would report."""

    def _record(self):
        return {"id": "abc123", "port": 30000, "server": "1.2.3.4", "server_port": 443}

    def _run(self, outcomes):
        """outcomes is a list of booleans, one per round; the last entry
        repeats once the list runs out."""
        self.calls = {"n": 0}

        async def fake_request(_port, _url, _timeout):
            idx = min(self.calls["n"], len(outcomes) - 1)
            self.calls["n"] += 1
            return outcomes[idx], 1.0

        async def fake_sleep(_):
            return None

        async def scenario():
            from unittest import mock

            with mock.patch.object(verify, "_https_request", fake_request), \
                 mock.patch.object(verify.asyncio, "sleep", fake_sleep):
                return await verify._https_rounds(self._record(), None)

        return asyncio.run(scenario())

    def test_dead_proxy_stops_after_roughly_the_budget(self):
        # 90% of 20 needs 18 successes, so a pass that fails its first
        # 3 rounds can never recover and should stop there.
        rate = self._run([False, False, False])
        self.assertEqual(rate, 0.0)
        self.assertLessEqual(
            self.calls["n"], verify.PACKET_TEST_COUNT,
            "a hopeless pass must not run all 20 rounds",
        )
        self.assertEqual(self.calls["n"], 3)

    def test_working_proxy_still_runs_every_round(self):
        rate = self._run([True] * 20)
        self.assertEqual(rate, 1.0)
        self.assertEqual(self.calls["n"], verify.PACKET_TEST_COUNT)

    def test_early_exit_does_not_change_the_reported_rate(self):
        # 17 successes then 3 failures: 17 < 18 required, so the pass ends
        # at 17/20 = 0.85, which is the same value a full 20-round pass
        # would have reported.
        rate = self._run([True] * 17 + [False] * 3)
        self.assertAlmostEqual(rate, 0.85, places=3)
        self.assertEqual(self.calls["n"], 20)

    def test_exactly_meeting_the_gate_is_not_cut_short(self):
        # 18 of 20 = 0.90 clears the gate and must survive the early exit.
        rate = self._run([True] * 18 + [False] * 2)
        self.assertAlmostEqual(rate, 0.90, places=3)


if __name__ == "__main__":
    unittest.main()
