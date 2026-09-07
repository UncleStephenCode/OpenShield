#!/usr/bin/env python3
"""Exercise the CI wrapper's actual bounded output command through pipes."""

from __future__ import annotations

import os
from pathlib import Path
import re
import selectors
import shlex
import subprocess
import time
import unittest


WRAPPER = Path(__file__).resolve().parent / "ci-smoke.sh"
MARKER = b"[performance CI smoke: output truncated]\n"


def bounded_output_command(limit: int) -> list[str]:
    source = WRAPPER.read_text(encoding="utf-8")
    helpers = re.findall(r'^output_filter="\$script_directory/([^"/]+)"$', source, re.MULTILINE)
    matches = re.findall(
        r'\| (python3 -I -B -S "\$output_filter" --limit-bytes "\$MAX_LOG_BYTES") \\\n'
        r'\s*\| tee "\$run_log"',
        source,
    )
    if len(matches) != 1 or len(helpers) != 1:
        raise AssertionError("expected one bounded output-to-tee filter in ci-smoke.sh")
    substitutions = {
        "$output_filter": str(WRAPPER.parent / helpers[0]),
        "$MAX_LOG_BYTES": str(limit),
    }
    return [substitutions.get(argument, argument) for argument in shlex.split(matches[0])]


class BoundedCIOutputTests(unittest.TestCase):
    def start_filter(self, limit: int) -> subprocess.Popen[bytes]:
        process = subprocess.Popen(
            bounded_output_command(limit),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        self.addCleanup(self.close_filter, process)
        return process

    @staticmethod
    def close_filter(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=3)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()

    def assert_emitted_before_eof(
        self, process: subprocess.Popen[bytes], expected: bytes,
    ) -> None:
        self.assertIsNotNone(process.stdout)
        output = bytearray()
        deadline = time.monotonic() + 2.0
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while len(output) < len(expected):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    self.fail(f"filter buffered output before EOF: {bytes(output)!r}")
                chunk = os.read(process.stdout.fileno(), 4096)
                self.assertTrue(chunk, "filter exited before its input was closed")
                output.extend(chunk)
        self.assertEqual(bytes(output), expected)
        self.assertIsNone(process.poll(), "filter must still be consuming input")

    def test_each_progress_line_is_visible_without_closing_input(self) -> None:
        process = self.start_filter(1024)
        self.assertIsNotNone(process.stdin)
        for line in (b"preparing nftables\n", b"starting bounded phase\n"):
            process.stdin.write(line)
            process.stdin.flush()
            self.assert_emitted_before_eof(process, line)
        remaining, errors = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 0, errors.decode())
        self.assertEqual(remaining, b"")

    def test_truncation_marker_is_visible_without_closing_input(self) -> None:
        limit = 128
        process = self.start_filter(limit)
        self.assertIsNotNone(process.stdin)
        process.stdin.write(b"x" * limit + b"\n")
        process.stdin.flush()
        self.assert_emitted_before_eof(process, MARKER)
        remaining, errors = process.communicate(input=b"y" * limit + b"\n", timeout=3)
        self.assertEqual(process.returncode, 0, errors.decode())
        self.assertEqual(remaining, b"")

    def test_byte_cap_and_single_marker_survive_multibyte_output(self) -> None:
        limit = 256
        process = self.start_filter(limit)
        first_line = b"starting bounded smoke\n"
        payload = first_line + (("\u0416" * 24 + "\n").encode("utf-8") * 1000)
        output, errors = process.communicate(input=payload, timeout=3)
        self.assertEqual(process.returncode, 0, errors.decode())
        self.assertTrue(output.startswith(first_line))
        self.assertEqual(output.count(MARKER), 1)
        self.assertLessEqual(len(output), limit)
        self.assertGreater(len(output), len(first_line) + len(MARKER))
        output.decode("utf-8")

    def test_oversized_unterminated_line_is_bounded_before_eof_and_input_is_drained(self) -> None:
        process = self.start_filter(128)
        self.assertIsNotNone(process.stdin)
        process.stdin.write(b"x" * 1024)
        process.stdin.flush()
        self.assert_emitted_before_eof(process, MARKER)
        # More than a pipe buffer must still be consumed after truncation.
        remaining, errors = process.communicate(input=b"y" * (1024 * 1024), timeout=3)
        self.assertEqual(process.returncode, 0, errors.decode())
        self.assertEqual(remaining, b"")

    def test_exact_content_boundary_reserves_room_for_one_marker(self) -> None:
        line = b"x" * 63 + b"\n"
        limit = len(line) + len(MARKER)
        process = self.start_filter(limit)
        output, errors = process.communicate(input=line + b"one more line\n", timeout=3)
        self.assertEqual(process.returncode, 0, errors.decode())
        self.assertEqual(output, line + MARKER)
        self.assertEqual(len(output), limit)

    def test_unterminated_final_line_receives_one_newline(self) -> None:
        process = self.start_filter(128)
        output, errors = process.communicate(input=b"complete\npartial", timeout=3)
        self.assertEqual(process.returncode, 0, errors.decode())
        self.assertEqual(output, b"complete\npartial\n")

    def test_empty_input_emits_nothing(self) -> None:
        process = self.start_filter(128)
        output, errors = process.communicate(input=b"", timeout=3)
        self.assertEqual(process.returncode, 0, errors.decode())
        self.assertEqual(output, b"")

    def test_invalid_byte_limits_are_rejected(self) -> None:
        for limit in (-1, 0, len(MARKER) - 1, 16 * 1024 * 1024 + 1):
            with self.subTest(limit=limit):
                process = self.start_filter(limit)
                output, errors = process.communicate(input=b"", timeout=3)
                self.assertNotEqual(process.returncode, 0)
                self.assertIn(b"byte limit", errors)
                self.assertEqual(output, b"")


if __name__ == "__main__":
    unittest.main()
