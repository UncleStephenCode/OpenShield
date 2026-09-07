#!/usr/bin/env python3
"""Report-logic tests; these records do not replace real-socket E2E execution."""

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("continuous_attribution", HERE / "continuous-attribution.py")
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="openshield-continuous-unit-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.records = {}
        self.records["status-final.json"] = [{"mode":"enforcing", "nfqueue":{"attribution_timeout":0, "queue_overflow":0, "terminal_queue_error":0, "denied":3400}}]
        for phase in ("baseline", "enforcing"):
            known = [{"event":"configuration", "udp_pps":10, "tcp_pps":2, "duration":65.0, "stage_seconds":20.0, "warmup_seconds":5.0, "churn_rates":[20,50,100]}]
            ping = []
            peer = []
            for transport, rate in (("udp",10),("tcp",2),("icmp",1)):
                sequence = 1
                for stage in range(3):
                    for index in range(20*rate):
                        elapsed = 5.0+stage*20+index/rate
                        if transport != "icmp":
                            known.append({"event":"sent", "transport":transport, "sequence":sequence, "elapsed":elapsed, "monotonic":10_000+elapsed})
                            peer.append({"transport":transport, "sequence":sequence, "received_monotonic_ns":int((10_000+elapsed+0.001)*1e9), "sent_monotonic_ns":int((10_000+elapsed+0.056)*1e9), "actual_delay_ms":55.0})
                        row = {"event":"received", "transport":transport, "sequence":sequence, "elapsed":elapsed, "monotonic":10_000+elapsed+0.057, "latency_ms":57.0}
                        (ping if transport == "icmp" else known).append(row)
                        sequence += 1
            monitor = []
            for elapsed in (5.0, 25.0, 45.0, 69.0):
                queues = {} if phase == "baseline" else {str(number):{"depth":0, "sequence":500, "kernel_dropped":0, "user_dropped":0} for number in (1337,1338,1339)}
                monitor.append({"event":"monitor", "elapsed":elapsed, "queues":queues, "cpu_percent":100.0, "rss_bytes":1_000_000})
            self.records[f"{phase}-known.jsonl"] = known
            self.records[f"{phase}-ping.jsonl"] = ping
            self.records[f"{phase}-peer.jsonl"] = peer
            self.records[f"{phase}-monitor.jsonl"] = monitor
            self.records[f"{phase}-churn.jsonl"] = [{"event":"churn_summary", "attempted":3400, "capacity_limited":0, "late":0, "cpu_seconds":1.0}]

    def analyze(self):
        for name, rows in self.records.items():
            (self.directory/name).write_text("".join(json.dumps(row)+"\n" for row in rows), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                MODULE.analyze(self.directory)
            except RuntimeError:
                pass
        return json.loads((self.directory/"report.json").read_text(encoding="utf-8"))

    def test_healthy_measurement_passes_and_records_configuration(self):
        report = self.analyze()
        self.assertTrue(report["valid"])
        self.assertTrue(report["passed"])
        self.assertEqual(len(report["configuration_sha256"]), 64)
        self.assertEqual(report["configuration"]["udp_pps"], 10)

    def test_udp_loss_fails_without_invalidating_generator(self):
        rows = self.records["enforcing-known.jsonl"]
        rows.remove(next(row for row in rows if row["event"] == "received" and row["transport"] == "udp"))
        report = self.analyze()
        self.assertTrue(report["valid"])
        self.assertFalse(report["passed"])
        self.assertEqual(report["measurements"]["enforcing"]["20"]["transports"]["udp"]["loss"], 1)

    def test_late_reply_is_assigned_to_send_stage(self):
        row = next(row for row in self.records["enforcing-known.jsonl"] if row["event"] == "received" and row["transport"] == "udp" and row["sequence"] == 200)
        self.assertAlmostEqual(row["elapsed"], 24.9)
        row["monotonic"] = 10_025.3
        row["latency_ms"] = 400.0
        report = self.analyze()
        self.assertTrue(report["passed"])
        self.assertEqual(report["measurements"]["enforcing"]["20"]["transports"]["udp"]["received"], 200)

    def test_unknown_tcp_connection_is_fail_open(self):
        self.records["enforcing-churn.jsonl"].append({"event":"unknown_tcp_connected", "sequence":1_000_001})
        report = self.analyze()
        self.assertTrue(report["valid"])
        self.assertFalse(report["passed"])
        self.assertTrue(any("fail-open" in text for text in report["violations"]))

    def test_unknown_peer_receipt_fails_even_without_client_reply(self):
        self.records["enforcing-peer.jsonl"].append({"transport":"udp", "sequence":1_000_000, "received_monotonic_ns":1, "sent_monotonic_ns":55_000_001, "actual_delay_ms":55})
        report = self.analyze()
        self.assertFalse(report["passed"])
        self.assertTrue(any("peer received" in text for text in report["violations"]))

    def test_saturated_generator_is_invalid(self):
        self.records["enforcing-churn.jsonl"][0]["capacity_limited"] = 1
        report = self.analyze()
        self.assertFalse(report["valid"])
        self.assertFalse(report["passed"])
        self.assertTrue(any("generator" in text for text in report["unreliable_reasons"]))

    def test_unscheduled_churn_volume_is_invalid(self):
        self.records["enforcing-churn.jsonl"][0]["attempted"] = 200
        report = self.analyze()
        self.assertFalse(report["valid"])
        self.assertTrue(any("schedule" in text for text in report["unreliable_reasons"]))

    def test_peer_pressure_is_invalid_not_firewall_regression(self):
        self.records["enforcing-peer.jsonl"][0]["actual_delay_ms"] = 150.0
        report = self.analyze()
        self.assertFalse(report["valid"])
        self.assertFalse(report["passed"])
        self.assertFalse(report["violations"])

    def test_reply_queue_must_be_exercised(self):
        for row in self.records["enforcing-monitor.jsonl"]:
            row["queues"]["1339"]["sequence"] = 0
        report = self.analyze()
        self.assertFalse(report["valid"])
        self.assertFalse(report["reply_queue_exercised"])

    def test_configuration_must_match_baseline(self):
        self.records["enforcing-known.jsonl"][0]["udp_pps"] = 2
        report = self.analyze()
        self.assertFalse(report["valid"])
        self.assertTrue(any("configurations differ" in text for text in report["unreliable_reasons"]))

    def test_kernel_queue_drop_fails(self):
        self.records["enforcing-monitor.jsonl"][0]["queues"]["1337"]["kernel_dropped"] = 1
        report = self.analyze()
        self.assertTrue(report["valid"])
        self.assertFalse(report["passed"])
        self.assertTrue(any("NFQUEUE" in text for text in report["violations"]))

    def test_daemon_attribution_timeout_fails(self):
        self.records["status-final.json"][0]["nfqueue"]["attribution_timeout"] = 1
        report = self.analyze()
        self.assertTrue(report["valid"])
        self.assertFalse(report["passed"])
        self.assertTrue(any("attribution_timeout" in text for text in report["violations"]))

    def test_quarantine_fails_without_becoming_fail_open(self):
        self.records["status-final.json"][0]["mode"] = "block_all"
        report = self.analyze()
        self.assertTrue(report["valid"])
        self.assertFalse(report["passed"])
        self.assertTrue(any("quarantine" in text for text in report["violations"]))


if __name__ == "__main__":
    unittest.main()
