"""Guard the scheduled pipeline against restating code defaults in the workflow.

The bug this exists for: tools/verify.py's speed floor was raised from 0.100 to
1.0 MB/s in d2a19fd, and update.yml kept passing VERIFY_MIN_SPEED_MB_S='0.100'
as an explicit env override. The override won, so every scheduled run verified
at 0.1 MB/s while the code and the commit message said 1.0. 31 of 286 published
configs were under the floor they were supposed to be held to, and the
subscription worker printed those rates into config names.

Nothing failed. The commit that "raised the floor" never ran at that floor.

So: for every VERIFY_*_default that verify.py reads from the environment, the
workflow must not restate a different literal. Passing the input through, or
omitting the key entirely, both satisfy this; overriding to a conflicting
value does not.
"""

from __future__ import annotations

import os
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOW = REPO / ".github/workflows/update.yml"
VERIFY = REPO / "tools/verify.py"


def workflow_env_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def verify_env_defaults() -> dict[str, str]:
    """Map VERIFY_* env var -> the literal default verify.py falls back to."""
    text = VERIFY.read_text(encoding="utf-8")
    out: dict[str, str] = {}
    for m in re.finditer(
        r'os\.getenv\(\s*"(VERIFY_[A-Z0-9_]+)"\s*,\s*"([^"]*)"\s*\)', text
    ):
        out[m.group(1)] = m.group(2)
    return out


def workflow_overrides() -> dict[str, str]:
    """Map VERIFY_* -> the literal the workflow pins it to, if any.

    Workflow values look like ``${{ inputs.min_speed_mb_s || '1.0' }}``, so the
    literal is nested inside an expression and is not at the end of the line.
    Match the last quoted numeric literal anywhere in the value. A value with
    no numeric literal at all is not a pinned default and is skipped.
    """
    out: dict[str, str] = {}
    for m in re.finditer(
        r"^\s*(VERIFY_[A-Z0-9_]+):\s*(.+?)\s*$", workflow_env_text(), re.M
    ):
        name, value = m.group(1), m.group(2)
        lits = re.findall(r"['\"](\d*\.?\d+)['\"]", value)
        if lits:
            out[name] = lits[-1]
    return out


class WorkflowDoesNotRestateCodeDefaultsTests(unittest.TestCase):
    def test_workflow_exists(self):
        self.assertTrue(WORKFLOW.is_file(), f"missing {WORKFLOW}")

    def test_workflow_floor_matches_code_floor(self):
        """The specific regression: 0.100 here overrode 1.0 in the code."""
        defaults = verify_env_defaults()
        self.assertIn("VERIFY_MIN_SPEED_MB_S", defaults, "verify.py lost its floor env")
        code_floor = float(defaults["VERIFY_MIN_SPEED_MB_S"])
        self.assertGreaterEqual(
            code_floor, 1.0,
            "the published speed floor is the user-visible contract; do not lower it",
        )
        pinned = workflow_overrides().get("VERIFY_MIN_SPEED_MB_S")
        if pinned is not None:
            self.assertEqual(
                float(pinned), code_floor,
                "update.yml pins VERIFY_MIN_SPEED_MB_S to a different value than "
                "verify.py defaults to; the workflow wins at runtime, so the code "
                "default is what never gets used",
            )

    def test_no_verify_env_is_pinned_to_a_conflicting_literal(self):
        """General form of the same guard across every VERIFY_* knob."""
        defaults = verify_env_defaults()
        pinned = workflow_overrides()
        conflicts = []
        for name, workflow_value in sorted(pinned.items()):
            if name not in defaults:
                continue  # not a verify.py default; outside this guard's scope
            try:
                if float(workflow_value) != float(defaults[name]):
                    conflicts.append(
                        f"{name}: workflow={workflow_value} verify.py={defaults[name]}"
                    )
            except ValueError:
                continue  # non-numeric default (e.g. a URL); not comparable
        self.assertEqual(
            conflicts, [],
            "workflow env conflicts with verify.py defaults; the workflow wins:\n  "
            + "\n  ".join(conflicts),
        )

    def test_concurrency_knobs_keep_their_proven_values(self):
        """Regression guard for values chosen by measurement, not defaults."""
        text = workflow_env_text()
        self.assertIn("VERIFY_SPEED_CONCURRENCY", text)
        # 40 came out of a seven-arm sweep; 0 means verify every survivor.
        self.assertRegex(text, r"VERIFY_SPEED_CONCURRENCY:.*\|\|\s*'40'")
        self.assertRegex(text, r"VERIFY_LIMIT:.*\|\|\s*'0'")


def dispatch_input_defaults() -> dict[str, str]:
    """Map workflow_dispatch input name -> its declared default.

    This is the layer that actually decides the value. A bare `gh workflow run`
    passes no inputs, so ``${{ inputs.X || 'literal' }}`` resolves to the input's
    OWN default and the `||` fallback is dead code. Checking only the env line
    is what let 0.100 survive on line 55 while line 320 read 1.0, so run
    36557357087 logged ">=100 KB/s" and published 38 configs under the floor.
    """
    out: dict[str, str] = {}
    text = workflow_env_text()
    start = text.find("workflow_dispatch:")
    block = text[start:] if start != -1 else text
    # Indentation-driven, not pattern-driven: keys sit at 6 spaces and their
    # attributes at 8, and a key may be followed by comment lines, so a single
    # multiline regex over (key + attributes) silently matches nothing.
    current = None
    for line in block.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if indent == 6 and stripped.endswith(":"):
            current = stripped[:-1].strip()
            continue
        if current and indent >= 8:
            m = re.match(r"default:\s*['\"]?([^'\"\n]+?)['\"]?\s*$", stripped)
            if m:
                out[current] = m.group(1).strip()
                current = None
    return out


class DispatchInputDefaultsMatchCodeTests(unittest.TestCase):
    """The input default is the effective floor, so it must match verify.py."""

    def test_min_speed_input_default_matches_verify_floor(self):
        defaults = verify_env_defaults()
        self.assertIn("VERIFY_MIN_SPEED_MB_S", defaults)
        code_floor = float(defaults["VERIFY_MIN_SPEED_MB_S"])
        inputs = dispatch_input_defaults()
        self.assertIn(
            "min_speed_mb_s", inputs,
            "workflow_dispatch lost its min_speed_mb_s input",
        )
        self.assertEqual(
            float(inputs["min_speed_mb_s"]), code_floor,
            f"workflow_dispatch default min_speed_mb_s={inputs['min_speed_mb_s']} "
            f"but verify.py floors at {code_floor}; with no inputs supplied the "
            "default wins and the `||` fallback on the env line never runs",
        )

    def test_floor_is_never_below_one_mb_s_in_either_layer(self):
        code_floor = float(verify_env_defaults()["VERIFY_MIN_SPEED_MB_S"])
        input_floor = float(dispatch_input_defaults()["min_speed_mb_s"])
        for label, value in (("verify.py", code_floor), ("workflow_dispatch", input_floor)):
            self.assertGreaterEqual(
                value, 1.0,
                f"{label} floor {value} is below the published 1.0 MB/s contract",
            )

    def test_no_dispatch_input_default_contradicts_its_env_line(self):
        """Every numeric input default must equal the value its env line uses."""
        env_pins = workflow_overrides()
        problems = []
        for input_name, default in sorted(dispatch_input_defaults().items()):
            env_name = "VERIFY_" + input_name.upper()
            if env_name not in env_pins:
                continue
            try:
                if float(default) != float(env_pins[env_name]):
                    problems.append(
                        f"{input_name}: input default={default} env line={env_pins[env_name]}"
                    )
            except ValueError:
                continue
        self.assertEqual(
            problems, [],
            "an input default contradicts the env line reading it:\n  "
            + "\n  ".join(problems),
        )


class ScheduleOrderingTests(unittest.TestCase):
    """update.yml must publish the pool BEFORE probe-egress.yml reads it.

    probe-egress.yml has no inputs and no shared state. It fetches
    gh-pages/enriched-configs.json, which only update.yml writes. So the two
    crons ARE the contract, and cron cannot express "after".

    What went wrong (2026-09-29): the crons were "7,37" and "5,35". Both ran
    twice an hour, the probe landed 2 min BEFORE each update, and the two
    concurrency groups differ, so nothing serialized them. Every probe measured
    the previous hour's pool and the :35 one raced the :37 publish.
    """

    WORKFLOWS = REPO / ".github/workflows"
    PRODUCER = WORKFLOWS / "update.yml"
    CONSUMER = WORKFLOWS / "probe-egress.yml"

    def schedule_crons(self, path: Path) -> list[int]:
        """The minute-of-hour for every schedule entry, in file order.

        Only the minute field is read; the rest of the expression (hour, day of
        month, month, day of week) is fixed to ``*`` in every cron in this repo.
        """
        minutes = []
        in_schedule = False
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped == "on:":
                in_schedule = False
            if stripped == "schedule:":
                in_schedule = True
                continue
            if in_schedule:
                if stripped and not stripped.startswith(("#", "-")):
                    break  # next key: workflow_dispatch:, permissions:, ...
                if (m := re.search(r'cron:\s*"?([^"\n]+?)"?\s*$', stripped)):
                    fields = m.group(1).split()
                    self.assertEqual(
                        len(fields), 5,
                        f"{path.name}: cron {m.group(1)!r} is not a 5-field "
                        "expression; this test only understands 'min * * * *'",
                    )
                    for part in fields[0].split(","):
                        self.assertRegex(
                            part.strip(), r"^\d+$",
                            f"{path.name}: minute field {part!r} is not a literal",
                        )
                        minutes.append(int(part))
        return minutes

    def test_both_workflows_still_have_schedules(self):
        self.assertTrue(self.PRODUCER.is_file(), f"missing {self.PRODUCER}")
        self.assertTrue(self.CONSUMER.is_file(), f"missing {self.CONSUMER}")
        for path in (self.PRODUCER, self.CONSUMER):
            self.assertTrue(
                self.schedule_crons(path),
                f"{path.name} has no cron; the pipeline stopped running unattended",
            )

    def test_update_runs_exactly_once_per_hour(self):
        self.assertEqual(
            self.schedule_crons(self.PRODUCER), [7],
            "update.yml must publish the pool exactly once an hour",
        )

    def test_probe_runs_exactly_once_per_hour(self):
        self.assertEqual(
            self.schedule_crons(self.CONSUMER), [37],
            "probe-egress.yml must run exactly once an hour, after the update",
        )

    def test_probe_never_fires_before_or_with_the_update(self):
        """The regression itself: probe minute must be strictly after update's."""
        update_minutes = self.schedule_crons(self.PRODUCER)
        probe_minutes = self.schedule_crons(self.CONSUMER)
        for probe in probe_minutes:
            for update in update_minutes:
                self.assertGreater(
                    probe, update,
                    f"probe-egress.yml fires at :{probe}02 before update.yml at "
                    f":{update}02. It reads the pool update.yml publishes, so it "
                    "measures the previous hour instead of this one",
                )

    def test_gap_covers_a_full_update_run(self):
        """30 min must exceed a 10-23 min run, or the two jobs overlap.

        The 10-23 min figure is measured: GH Actions run 36570401322 took
        12:46:41 -> 12:53:14.
        """
        update_minutes = self.schedule_crons(self.PRODUCER)
        probe_minutes = self.schedule_crons(self.CONSUMER)
        worst_case_run_minutes = 25
        for probe in probe_minutes:
            for update in update_minutes:
                gap = (probe - update) % 60
                self.assertGreaterEqual(
                    gap, worst_case_run_minutes,
                    f"only {gap} min between update :{update}02 and probe :{probe}02; "
                    f"an update can run {worst_case_run_minutes} min, so a slow run "
                    "makes the probe measure the previous hour again",
                )

    def test_probe_notes_a_stale_pool_but_keeps_probing(self):
        """A stale pool is a *note*, not a kill (2026-10-01 incident).

        The old contract hard-refused to probe when the pool was >120 min old
        (MAX_POOL_AGE_MINUTES + sys.exit). That guard is what killed the run in
        the incident (age=337 min -> probe aborted -> health index frozen for
        hours -> the worker's join dropped configs and the subscription shrank).

        Refusing was wrong once two things landed:
          1. the probe does a rolling union (PREVIOUS_HEALTH) - the pool fetched
             from gh-pages IS the last-published, still-served feed, so probing
             it is the correct action even when hourly updates were skipped;
          2. freshness-watchdog.yml re-collects a frozen pool on its own path,
             so a genuinely stuck pipeline is recovered by dispatch, not by this
             guard tripping.

        So the probe must still *report* pool age (an unparseable pool is fatal
        - the heredoc crashes on it regardless), but it must no longer sys.exit
        on age. Refusing a stale pool is now a regression.
        """
        text = self.CONSUMER.read_text(encoding="utf-8")
        # Age is still computed and reported...
        self.assertIn("age=", text, "the pool-age note was removed; keep it")
        self.assertIn("enriched-configs.json", text)
        # ...but it no longer aborts the run.
        self.assertNotIn(
            "REFUSING TO PROBE", text,
            "probe-egress.yml must not hard-refuse a stale pool; the rolling "
            "union plus the watchdog make refusing a foot-gun (2026-10-01)",
        )
        self.assertNotIn(
            "sys.exit", text,
            "the staleness step must not sys.exit; only an unparseable pool may "
            "crash the run, and that is a parse error, not an age gate",
        )

    def test_probe_carry_over_is_wired(self):
        """The rolling union needs its input: the previously-published index.

        Without PREVIOUS_HEALTH the probe would still rewrite the index from
        this run's pool alone and the incident (index freezing on churn) would
        repeat. The Fetch step must download egress-health.json and the probe
        step must point PREVIOUS_HEALTH at it.
        """
        text = self.CONSUMER.read_text(encoding="utf-8")
        self.assertIn(
            "egress-health.json", text,
            "the Fetch step must download the previous health index for the union",
        )
        self.assertRegex(
            text, r"PREVIOUS_HEALTH:\s*verify-output/previous-egress-health.json",
            "the probe step must point PREVIOUS_HEALTH at the fetched index",
        )

    def test_watchdog_exists_and_dispatches_the_heavy_workflows(self):
        """The non-cron trigger path: a cheap watchdog wakes the heavy jobs.

        This is the actual skip-combat. A skipped hourly cron is recovered on
        the next watchdog tick (~10 min) instead of the next hourly tick.
        """
        watchdog = self.WORKFLOWS / "freshness-watchdog.yml"
        self.assertTrue(watchdog.is_file(), "freshness-watchdog.yml is missing")
        text = watchdog.read_text(encoding="utf-8")
        # Fires on a sub-hourly heartbeat, not hourly.
        self.assertRegex(
            text, r'cron:\s*"?\*/10 \* \* \* \*"?',
            "the watchdog must tick every 10 minutes, not hourly",
        )
        # And it dispatches both heavy workflows by name.
        self.assertIn("gh workflow run update.yml", text)
        self.assertIn("gh workflow run probe-egress.yml", text)
        self.assertIn("actions: write", text,
                      "the watchdog needs the 'actions' permission to dispatch")


if __name__ == "__main__":
    unittest.main()
