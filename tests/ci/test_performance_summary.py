#!/usr/bin/env python3
"""Execute the release workflow's bounded performance summary without Actions."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"
MAXIMUM_REPORT_BYTES = 512 * 1024


def summary_step() -> tuple[str, str]:
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    start = lines.index("      - name: Add the bounded report to the job summary")
    end = next(
        index
        for index in range(start + 1, len(lines))
        if lines[index].startswith("      - ")
    )
    step = lines[start:end]
    script_start = step.index("        run: |") + 1
    script = "\n".join(line[10:] if line else "" for line in step[script_start:])
    return "\n".join(step), script


class PerformanceSummaryTests(unittest.TestCase):
    def run_summary(
        self, root: Path, report: Path, outcome: str, *, path: str | None = None
    ) -> str:
        _, script = summary_step()
        summary = root / "step-summary.md"
        environment = dict(os.environ)
        environment.update(
            REPORT=str(report),
            PERFORMANCE_OUTCOME=outcome,
            GITHUB_STEP_SUMMARY=str(summary),
        )
        if path is not None:
            environment["PATH"] = path
        result = subprocess.run(
            ["bash", "-c", script],
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return summary.read_text(encoding="utf-8")

    def test_step_runs_after_success_or_failure_but_not_cancellation(self) -> None:
        step, _ = summary_step()
        condition = next(line.strip() for line in step.splitlines() if "if:" in line)
        self.assertEqual(
            condition,
            "if: ${{ !cancelled() && (steps.performance_smoke.outcome == 'success' "
            "|| steps.performance_smoke.outcome == 'failure') }}",
        )
        self.assertIn(
            "REPORT: ${{ runner.temp }}/openshield-performance-report/report.md", step
        )
        self.assertNotIn("continue-on-error:", step)

    def test_passed_and_failed_reports_are_visible_with_their_outcomes(self) -> None:
        for outcome, verdict in (("success", "PASS"), ("failure", "FAIL")):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                report = root / "report.md"
                payload = f"Performance gate: {verdict}\nFailure reasons: example\n"
                report.write_text(payload, encoding="utf-8")
                summary = self.run_summary(root, report, outcome)
                self.assertIn(f"Performance smoke result: **{outcome}**.", summary)
                self.assertTrue(summary.endswith(payload), summary)

    def test_missing_empty_directory_and_symlink_reports_use_fallback(self) -> None:
        for kind in ("missing", "empty", "directory", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                report = root / "report.md"
                if kind == "empty":
                    report.touch()
                elif kind == "directory":
                    report.mkdir()
                elif kind == "symlink":
                    target = root / "private.md"
                    target.write_text("MUST NOT APPEAR", encoding="utf-8")
                    report.symlink_to(target)
                summary = self.run_summary(root, report, "failure")
                self.assertIn("Report is missing, empty, unsafe, or larger than 512 KiB", summary)
                self.assertNotIn("MUST NOT APPEAR", summary)

    def test_exact_limit_is_accepted_and_oversize_report_uses_fallback(self) -> None:
        for size in (MAXIMUM_REPORT_BYTES, MAXIMUM_REPORT_BYTES + 1):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                report = root / "report.md"
                payload = "x" * size
                report.write_text(payload, encoding="ascii")
                summary = self.run_summary(root, report, "failure")
                if size == MAXIMUM_REPORT_BYTES:
                    self.assertTrue(summary.endswith(payload))
                else:
                    self.assertIn("larger than 512 KiB", summary)
                    self.assertNotIn("x" * 100, summary)

    def test_report_growth_after_size_check_cannot_exceed_the_read_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.md"
            report.write_text("x", encoding="ascii")
            command_directory = root / "commands"
            command_directory.mkdir()
            real_head = shutil.which("head")
            self.assertIsNotNone(real_head)
            head = command_directory / "head"
            head.write_text(
                f"#!{sys.executable}\n"
                "import os, sys\n"
                "with open(sys.argv[-1], 'ab') as report:\n"
                f"    report.write(b'x' * {MAXIMUM_REPORT_BYTES * 2})\n"
                f"os.execv({real_head!r}, [{real_head!r}, *sys.argv[1:]])\n",
                encoding="utf-8",
            )
            head.chmod(0o755)
            summary = self.run_summary(
                root,
                report,
                "failure",
                path=f"{command_directory}{os.pathsep}{os.environ['PATH']}",
            )
            prefix = (
                "## OpenShield performance smoke\n\n"
                "Performance smoke result: **failure**.\n\n"
            )
            self.assertEqual(summary, prefix + "x" * MAXIMUM_REPORT_BYTES)
            self.assertGreater(report.stat().st_size, MAXIMUM_REPORT_BYTES)


if __name__ == "__main__":
    unittest.main()
