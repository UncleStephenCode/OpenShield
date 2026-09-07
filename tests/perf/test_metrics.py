#!/usr/bin/env python3
"""Protocol tests for the standalone performance metric collector."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time
import unittest


PERF_ROOT = Path(__file__).resolve().parent
METRICS_PATH = PERF_ROOT / "metrics.py"


def load_metrics_module():
    specification = importlib.util.spec_from_file_location(
        "openshield_perf_metrics_protocol_test", METRICS_PATH
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load performance metrics module")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


metrics = load_metrics_module()


class MetricCollectorProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.output_buffers: dict[int, bytearray] = {}

    def start_collector(
        self, nfqueue_number: int = metrics.DEFAULT_NFQUEUE_NUMBER
    ) -> subprocess.Popen[bytes]:
        return subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-B",
                "-S",
                os.fspath(METRICS_PATH),
                "--pid",
                "0",
                "--interface",
                "lo",
                "--duration",
                "3",
                "--interval",
                "0.02",
                "--nfqueue-number",
                str(nfqueue_number),
                "--synchronize",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def read_json_line(
        self, process: subprocess.Popen[bytes], timeout: float = 2.0
    ) -> dict:
        self.assertIsNotNone(process.stdout)
        buffer = self.output_buffers.setdefault(process.pid, bytearray())
        deadline = time.monotonic() + timeout
        while b"\n" not in buffer:
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    self.fail("metric collector did not emit a protocol line in time")
                chunk = os.read(process.stdout.fileno(), 64 * 1_024)
            finally:
                selector.close()
            if not chunk:
                self.fail("metric collector closed stdout unexpectedly")
            buffer.extend(chunk)
            self.assertLessEqual(len(buffer), 1024 * 1024)
        raw_line, separator, remainder = buffer.partition(b"\n")
        self.assertEqual(separator, b"\n")
        buffer[:] = remainder
        line = raw_line.decode("utf-8", errors="strict")
        self.assertTrue(line, "metric collector closed stdout unexpectedly")
        document = json.loads(line)
        self.assertIsInstance(document, dict)
        return document

    def write_command(self, process: subprocess.Popen[bytes], command: str) -> None:
        self.assertIsNotNone(process.stdin)
        process.stdin.write(f"{command}\n".encode("ascii"))
        process.stdin.flush()

    @staticmethod
    def close_stdin(process: subprocess.Popen[bytes]) -> None:
        if process.stdin is not None:
            process.stdin.close()
            process.stdin = None

    def reap(self, process: subprocess.Popen[bytes]) -> tuple[str, str]:
        try:
            stdout, stderr = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=1)
            self.fail("metric collector did not terminate in time")
        buffered = bytes(self.output_buffers.pop(process.pid, bytearray()))
        return (buffered + stdout).decode("utf-8"), stderr.decode("utf-8")

    def test_split_uses_one_shared_boundary_without_a_counter_gap(self) -> None:
        process = self.start_collector()
        try:
            ready = self.read_json_line(process)
            self.assertEqual(ready["schema"], metrics.CONTROL_SCHEMA)
            self.assertEqual(ready["event"], "ready")
            self.assertEqual(ready["pid"], process.pid)
            self.assertGreater(ready["starttime"], 0)
            self.assertTrue(ready["executable"].startswith("/"))
            self.assertEqual(ready["uid"], os.getuid())

            self.write_command(process, "start")
            start = self.read_json_line(process)
            self.assertEqual(start["schema"], metrics.CONTROL_SCHEMA)
            self.assertEqual(start["event"], "start")
            self.assertGreater(start["boundary_monotonic_ns"], 0)
            time.sleep(0.03)
            self.write_command(process, "split")
            acknowledgement = self.read_json_line(process)
            first = self.read_json_line(process)

            self.assertEqual(acknowledgement["schema"], metrics.CONTROL_SCHEMA)
            self.assertEqual(acknowledgement["event"], "split")
            boundary = acknowledgement["boundary_monotonic_ns"]
            self.assertIsInstance(boundary, int)
            self.assertGreater(boundary, 0)
            self.assertEqual(first["schema"], metrics.METRICS_SCHEMA)
            self.assertEqual(first["nfqueue"]["queue_number"], 1337)
            self.assertEqual(first["stop_reason"], "split_boundary")
            self.assertEqual(
                first["started_at_monotonic_ns"],
                start["boundary_monotonic_ns"],
            )
            self.assertEqual(first["finished_at_monotonic_ns"], boundary)

            time.sleep(0.03)
            self.write_command(process, "stop")
            self.close_stdin(process)
            second = self.read_json_line(process)
            remaining_stdout, stderr = self.reap(process)

            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(remaining_stdout, "")
            self.assertEqual(second["schema"], metrics.METRICS_SCHEMA)
            self.assertEqual(second["stop_reason"], "requested")
            self.assertEqual(second["started_at_monotonic_ns"], boundary)
            self.assertGreaterEqual(second["finished_at_monotonic_ns"], boundary)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=1)

    def test_start_stop_without_split_keeps_the_single_window_protocol(self) -> None:
        process = self.start_collector()
        try:
            ready = self.read_json_line(process)
            self.assertEqual(ready["schema"], metrics.CONTROL_SCHEMA)
            self.assertEqual(ready["event"], "ready")
            self.write_command(process, "start")
            start = self.read_json_line(process)
            time.sleep(0.03)
            self.write_command(process, "stop")
            self.close_stdin(process)
            document = self.read_json_line(process)
            remaining_stdout, stderr = self.reap(process)

            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(remaining_stdout, "")
            self.assertEqual(document["schema"], metrics.METRICS_SCHEMA)
            self.assertEqual(document["nfqueue"]["queue_number"], 1337)
            self.assertEqual(document["stop_reason"], "requested")
            self.assertEqual(
                document["started_at_monotonic_ns"],
                start["boundary_monotonic_ns"],
            )
            self.assertLessEqual(
                document["started_at_monotonic_ns"],
                document["finished_at_monotonic_ns"],
            )
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=1)

    def test_explicit_learning_queue_is_recorded_in_the_metric_document(self) -> None:
        process = self.start_collector(1338)
        try:
            self.read_json_line(process)
            self.write_command(process, "start")
            self.read_json_line(process)
            self.write_command(process, "stop")
            self.close_stdin(process)
            document = self.read_json_line(process)
            remaining_stdout, stderr = self.reap(process)

            self.assertEqual(process.returncode, 0, stderr)
            self.assertEqual(remaining_stdout, "")
            self.assertEqual(document["nfqueue"]["queue_number"], 1338)
            self.assertIn("NFQUEUE 1338", document["scope_notes"]["nfqueue"])
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=1)

    def test_second_split_is_rejected(self) -> None:
        process = self.start_collector()
        try:
            self.read_json_line(process)
            self.write_command(process, "start")
            self.read_json_line(process)
            self.write_command(process, "split")
            self.read_json_line(process)
            self.read_json_line(process)
            self.write_command(process, "split")
            self.close_stdin(process)
            stdout, stderr = self.reap(process)

            self.assertNotEqual(process.returncode, 0)
            self.assertEqual(stdout, "")
            self.assertIn("permits at most one split", stderr)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=1)

    def test_control_commands_are_exact_ascii_bounded_lines(self) -> None:
        self.assertEqual(
            metrics.decode_control_command(b"start\n", frozenset({"start"})),
            "start",
        )
        for payload in (
            b"stop\r\n",
            b"split ",
            "splït\n".encode("utf-8"),
            b"x" * (metrics.MAX_CONTROL_COMMAND_CHARACTERS + 1) + b"\n",
            b"",
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(RuntimeError):
                    metrics.decode_control_command(
                        payload, frozenset({"start", "split", "stop"})
                    )

    def test_nfqueue_snapshot_selects_only_the_requested_queue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "nfnetlink_queue"
            source.write_text(
                "1337 10 2 2 65535 3 4 100 1\n"
                "1338 11 7 2 65535 5 6 200 1\n",
                encoding="ascii",
            )
            enforcing = metrics.nfqueue_counters(1337, source)
            learning = metrics.nfqueue_counters(1338, source)

        self.assertEqual(enforcing["queue_number"], 1337)
        self.assertEqual(enforcing["depth"], 2)
        self.assertEqual(enforcing["sequence"], 100)
        self.assertEqual(learning["queue_number"], 1338)
        self.assertEqual(learning["depth"], 7)
        self.assertEqual(learning["sequence"], 200)

    def test_nfqueue_number_rejects_noncanonical_or_out_of_range_values(self) -> None:
        for value in (-1, 65_536, True, 1.0, "1337"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    metrics.validate_nfqueue_number(value)
        for value in ("-1", "65536", "01337", "+1337", "١٣٣٧"):
            with self.subTest(value=value):
                with self.assertRaises(metrics.argparse.ArgumentTypeError):
                    metrics.parse_nfqueue_number(value)
        self.assertEqual(metrics.parse_nfqueue_number("1338"), 1338)


if __name__ == "__main__":
    unittest.main()
