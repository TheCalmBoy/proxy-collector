"""Stage 2 (UDP) and Stage 3 (speed) must run concurrently, not back to back.

Run 36455487959 spent 215.7s on Stage 2 then 176.5s on Stage 3, sequentially,
even though both probe the identical tcp_survivors set and neither result
feeds the other -- UDP is a flag that never rejects. The two are bounded by
different semaphores, so overlapping them costs max(215.7, 176.5) instead of
the 392s sum.

The contract worth protecting is behavioural, not timing: both stages must
still finish, and the pairing between records and their results must survive
the restructure. asyncio.gather preserves order, so results are still
positionally zipped with tcp_survivors.
"""

import ast
import pathlib
import unittest

VERIFY = pathlib.Path(__file__).resolve().parents[1] / "tools" / "verify.py"
SOURCE = VERIFY.read_text()


class TestStageConcurrency(unittest.TestCase):
    def _main_coroutine_source(self):
        """Return the source of the function containing the stage 2/3 block."""
        tree = ast.parse(SOURCE)
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef):
                seg = ast.get_source_segment(SOURCE, node) or ""
                if "Stage 2: UDP" in seg and "Stage 3:" in seg:
                    return seg
        self.fail("could not find the async main() holding the stage 2/3 block")

    def test_both_stages_are_launched_before_awaiting(self):
        seg = self._main_coroutine_source()
        launch_udp = seg.index("_udp_reliability")
        launch_speed = seg.index("_speed_test")
        # The join must come after BOTH launches, otherwise the stages are
        # still serial and only look concurrent.
        self.assertLess(
            launch_udp, launch_speed,
            "UDP stage is not launched before the speed stage",
        )
        join = seg.index("await asyncio.gather(udp_task, speed_task)")
        self.assertLess(launch_speed, join, "the join precedes the speed launch")

    def test_results_are_joined_together(self):
        seg = self._main_coroutine_source()
        self.assertIn(
            "udp_results, speed_results = await asyncio.gather(udp_task, speed_task)",
            seg,
            "stage 2 and 3 must be awaited together, not independently",
        )

    def test_udp_results_still_map_to_survivors_by_id(self):
        seg = self._main_coroutine_source()
        self.assertIn(
            'udp_flags = dict(zip((r["id"] for r in tcp_survivors), udp_results))',
            seg,
            "udp flags must stay keyed by record id",
        )
        self.assertIn(
            'speed_by_id = {r["id"]: res for r, res in zip(tcp_survivors, speed_results)}',
            seg,
            "speed results must stay keyed by record id",
        )

    def test_udp_never_filters(self):
        """UDP is informational: a config must not be dropped for failing it."""
        seg = self._main_coroutine_source()
        self.assertNotIn(
            "speed_survivors = [r for r in tcp_survivors if udp",
            seg,
            "UDP capability must not be used as a filter",
        )


if __name__ == "__main__":
    unittest.main()
