#!/usr/bin/env python3
"""Keep the performance producer and both wrapper manifest checks synchronized."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest


PERF_ROOT = Path(__file__).resolve().parents[1] / "perf"


def literal_tuple(source: str, name: str) -> tuple[str, ...]:
    assignments = [
        node.value
        for node in ast.parse(source).body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
    ]
    if len(assignments) != 1:
        raise AssertionError(f"expected exactly one assignment to {name}")
    value = ast.literal_eval(assignments[0])
    if not isinstance(value, tuple) or not value or not all(
        isinstance(path, str) and path for path in value
    ):
        raise AssertionError(f"{name} must be a nonempty literal tuple of paths")
    return value


class PerformanceManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.wrapper = (PERF_ROOT / "ci-smoke.sh").read_text(encoding="utf-8")
        cls.paths = literal_tuple(
            (PERF_ROOT / "run.py").read_text(encoding="utf-8"),
            "HARNESS_COMPONENT_PATHS",
        )
        embedded_python = re.findall(r"<<'PY'\n(.*?)\nPY\n", cls.wrapper, re.DOTALL)
        if len(embedded_python) != 1:
            raise AssertionError("expected exactly one embedded Python validator")
        cls.wrapper_paths = literal_tuple(embedded_python[0], "harness_paths")
        fragments = re.findall(
            r"^    and (\.harness\.schema == .*?)\n    and \(\.environments",
            cls.wrapper,
            re.MULTILINE | re.DOTALL,
        )
        if len(fragments) != 1:
            raise AssertionError("expected exactly one jq harness validation fragment")
        cls.jq_fragment = fragments[0]

    def fixture(self) -> dict:
        return {
            "harness": {
                "schema": "openshield.perf.harness-evidence.v1",
                "manifest_sha256": hashlib.sha256(b"synthetic manifest").hexdigest(),
                "components": [
                    {
                        "path": path,
                        "size": len(path.encode("ascii")),
                        "sha256": hashlib.sha256(path.encode("ascii")).hexdigest(),
                    }
                    for path in self.paths
                ],
            }
        }

    def assert_jq_result(self, document: dict, accepted: bool) -> None:
        jq = shutil.which("jq")
        self.assertIsNotNone(jq, "jq is required on the offline CI runner")
        result = subprocess.run(
            [jq, "-e", self.jq_fragment],
            input=json.dumps(document),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(result.returncode, 0 if accepted else 1, result.stderr)
        self.assertEqual(result.stdout.strip(), "true" if accepted else "false")

    def test_producer_and_python_validator_use_the_same_unique_ordered_paths(self) -> None:
        self.assertEqual(self.paths, self.wrapper_paths)
        for paths in (self.paths, self.wrapper_paths):
            self.assertEqual(len(paths), len(set(paths)))

    def test_jq_component_count_matches_the_manifest_plan(self) -> None:
        counts = re.findall(
            r'\(\.harness\.components\s*\|\s*type == "array" and length == (\d+)\)',
            self.jq_fragment,
        )
        self.assertEqual(len(counts), 1)
        self.assertEqual(int(counts[0]), len(self.paths))

    def test_exact_jq_fragment_accepts_all_current_manifest_components(self) -> None:
        self.assert_jq_result(self.fixture(), True)

    def test_exact_jq_fragment_rejects_missing_and_extra_components(self) -> None:
        for mutation in ("missing", "extra"):
            with self.subTest(mutation=mutation):
                document = self.fixture()
                components = document["harness"]["components"]
                if mutation == "missing":
                    components.pop()
                else:
                    extra = copy.deepcopy(components[-1])
                    extra["path"] = "tests/perf/unexpected.py"
                    components.append(extra)
                self.assert_jq_result(document, False)

    def test_exact_jq_fragment_rejects_malformed_component_and_manifest_sha256(self) -> None:
        # jq verifies the digest shape; the embedded Python validator later
        # authenticates the digest against the actual source file contents.
        for target in ("manifest", "component"):
            for digest in ("0" * 63, "0" * 65, "G" * 64, "A" * 64, None):
                with self.subTest(target=target, digest=digest):
                    document = self.fixture()
                    if target == "manifest":
                        document["harness"]["manifest_sha256"] = digest
                    else:
                        document["harness"]["components"][0]["sha256"] = digest
                    self.assert_jq_result(document, False)


if __name__ == "__main__":
    unittest.main()
