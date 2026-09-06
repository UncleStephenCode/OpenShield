#!/usr/bin/env python3
"""Validate report conclusions; real packet execution remains container-only."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location("scheduler_generation", HERE / "scheduler-generation.py")
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SchedulerGenerationReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="openshield-scheduler-report-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.rows = {"peer.jsonl": [], "known.jsonl": [], "unknown.jsonl": [], "controller.jsonl": []}
        for phase in ("before", "restored", "resumed"):
            for transport in ("tcp", "udp"):
                self.rows["peer.jsonl"].append({"event": "peer_received", "role": "known", "phase": phase, "transport": transport, "index": 0})
        for phase in ("pending_revoke", "pending_block"):
            self.rows["controller.jsonl"].append({"event": "pending_before_mutation", "phase": phase, "queue_depth": 8})
        for phase in ("revoked", "block_all"):
            for event in ("send_attempt", "connect_attempt"):
                self.rows["known.jsonl"].append({"event": event, "role": "known", "phase": phase})
        self.rows["controller.jsonl"].append({"event": "controller_complete", "status": {"mode": "enforcing", "nfqueue": {"attribution_timeout": 0, "queue_overflow": 0, "terminal_queue_error": 0}}})

    def analyze(self):
        for name, rows in self.rows.items():
            (self.directory / name).write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                MODULE.analyze(self.directory)
            except RuntimeError:
                pass
        return json.loads((self.directory / "report.json").read_text(encoding="utf-8"))

    def test_proven_positive_and_negative_phases_pass(self):
        self.assertTrue(self.analyze()["passed"])

    def test_pre_ack_packet_is_not_misclassified_as_stale_admission(self):
        self.rows["peer.jsonl"].append({"event": "peer_received", "role": "known", "phase": "pending_revoke", "transport": "udp", "index": 5, "monotonic": 999999})
        self.assertTrue(self.analyze()["passed"])

    def test_post_ack_receipt_fails_even_without_client_reply(self):
        self.rows["peer.jsonl"].append({"event": "peer_received", "role": "known", "phase": "revoked", "transport": "udp", "index": 5})
        self.assertFalse(self.analyze()["passed"])

    def test_unknown_tcp_connect_fails_even_without_application_payload(self):
        self.rows["unknown.jsonl"].append({"event": "connected", "role": "unknown", "phase": "before", "transport": "tcp", "index": 0})
        self.assertFalse(self.analyze()["passed"])

    def test_missing_real_queue_overlap_is_not_a_pass(self):
        self.rows["controller.jsonl"][0]["queue_depth"] = 0
        self.assertFalse(self.analyze()["passed"])

    def test_missing_recovery_positive_is_not_a_pass(self):
        self.rows["peer.jsonl"] = [row for row in self.rows["peer.jsonl"] if row["phase"] != "resumed"]
        self.assertFalse(self.analyze()["passed"])

    def test_block_all_payload_is_not_allowed(self):
        self.rows["peer.jsonl"].append({"event": "peer_received", "role": "known", "phase": "block_all", "transport": "held_tcp", "index": 0})
        self.assertFalse(self.analyze()["passed"])

    def test_queue_error_is_not_a_pass(self):
        self.rows["controller.jsonl"][-1]["status"]["nfqueue"]["terminal_queue_error"] = 1
        self.assertFalse(self.analyze()["passed"])


if __name__ == "__main__":
    unittest.main()
