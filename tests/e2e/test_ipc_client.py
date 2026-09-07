#!/usr/bin/env python3
"""Bounded IPC and Learning queue checks, including Python 3.9 compatibility."""

import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "e2e_ipc_client", Path(__file__).with_name("ipc_client.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class IpcClientTests(unittest.TestCase):
    def test_annotations_are_deferred_for_python39(self):
        self.assertEqual(
            MODULE.matching_application_template.__annotations__["return"],
            "dict | None",
        )

    def test_missing_template_is_none(self):
        with mock.patch.object(MODULE, "all_rules", return_value=[]):
            self.assertIsNone(MODULE.matching_application_template("/usr/bin/python3"))

    def test_control_requires_acknowledgement(self):
        for response in (
            {"type": "error", "data": {"code": "conflict"}},
            {"type": "status", "data": {"revision": 2, "mode": "enforcing"}},
        ):
            with self.subTest(response=response), \
                    mock.patch.object(MODULE, "exchange", return_value=response) as exchange, \
                    mock.patch.object(MODULE, "status") as status:
                with self.assertRaisesRegex(RuntimeError, "control request failed"):
                    MODULE.control({"type": "set_mode"})
                exchange.assert_called_once_with(
                    MODULE.CONTROL, {"type": "control", "data": {"type": "set_mode"}}
                )
                status.assert_not_called()

    @staticmethod
    def delayed_response(response, now, first_delay):
        payload = json.dumps(response).encode("utf-8")
        wire = bytearray(len(payload).to_bytes(4, "big") + payload)
        stream = mock.MagicMock()
        stream.__enter__.return_value = stream

        def receive(size):
            if stream.recv.call_count == 1:
                now[0] += first_delay
            result = bytes(wire[:size])
            del wire[:size]
            return result

        stream.recv.side_effect = receive
        return stream

    def test_control_accepts_delayed_ack_on_original_socket_without_retry(self):
        now = [0.0]
        acknowledgement = {"revision": 2, "affected_rule": None}
        stream = self.delayed_response({"type": "ack", "data": acknowledgement}, now, 6.0)
        with mock.patch.object(MODULE.time, "monotonic", side_effect=lambda: now[0]), \
                mock.patch.object(MODULE.socket, "socket", return_value=stream) as socket_factory, \
                mock.patch.object(MODULE, "status") as status:
            self.assertEqual(MODULE.control({"type": "set_mode"}), acknowledgement)
        socket_factory.assert_called_once()
        stream.connect.assert_called_once_with(MODULE.CONTROL)
        stream.sendall.assert_called_once()
        status.assert_not_called()
        self.assertEqual(stream.settimeout.call_args_list[-1], mock.call(24.0))

    def test_delayed_observation_retains_five_second_absolute_deadline(self):
        now = [0.0]
        stream = self.delayed_response({"type": "status", "data": {"revision": 2}}, now, 6.0)
        with mock.patch.object(MODULE.time, "monotonic", side_effect=lambda: now[0]), \
                mock.patch.object(MODULE.socket, "socket", return_value=stream):
            with self.assertRaisesRegex(
                TimeoutError, r"IPC status on /run/openshield/observe.sock.*5-second absolute deadline"
            ):
                MODULE.status()
        stream.sendall.assert_called_once()

    def test_control_trickle_cannot_renew_thirty_second_deadline_or_retry_mutation(self):
        now = [0.0]
        stream = mock.MagicMock()
        stream.__enter__.return_value = stream

        def fragment(size):
            now[0] += 10.0
            return b"\x00"

        stream.recv.side_effect = fragment
        with mock.patch.object(MODULE.time, "monotonic", side_effect=lambda: now[0]), \
                mock.patch.object(MODULE.socket, "socket", return_value=stream) as socket_factory, \
                mock.patch.object(MODULE, "status") as status:
            with self.assertRaisesRegex(
                TimeoutError, r"IPC set_mode on /run/openshield/control.sock.*30-second absolute deadline"
            ):
                MODULE.control({"type": "set_mode"})
        socket_factory.assert_called_once()
        stream.sendall.assert_called_once()
        status.assert_not_called()
        self.assertEqual(stream.recv.call_count, 3)
        self.assertEqual(stream.settimeout.call_args_list[-1], mock.call(10.0))

    def test_socket_timeouts_report_operation_socket_and_budget_without_retry(self):
        for path, operation, budget in (
            (MODULE.OBSERVE, "status", 5),
            (MODULE.CONTROL, "set_mode", 30),
        ):
            for phase in ("connect", "sendall", "recv"):
                with self.subTest(path=path, phase=phase):
                    stream = mock.MagicMock()
                    stream.__enter__.return_value = stream
                    getattr(stream, phase).side_effect = MODULE.socket.timeout("timed out")
                    with mock.patch.object(MODULE.socket, "socket", return_value=stream) as factory:
                        with self.assertRaises(TimeoutError) as caught:
                            MODULE.exchange(path, {"type": "request", "data": {"type": operation}})
                    self.assertIn(f"IPC {operation} on {path}", str(caught.exception))
                    self.assertIn(f"{budget}-second absolute deadline", str(caught.exception))
                    factory.assert_called_once()
                    self.assertEqual(stream.sendall.call_count, 0 if phase == "connect" else 1)

    def check_queue_health(self, current, rows=b"1338 123 0 2 512 0 0 100 1\n", expected=None):
        with mock.patch.object(MODULE, "status", return_value=current), \
                mock.patch.object(MODULE, "QUEUE_PATH") as queue_path:
            queue_path.open.return_value.__enter__.return_value = io.BytesIO(rows)
            return MODULE.learning_queue_health(expected)

    def test_learning_queue_health_accepts_present_queue_and_unchanged_counter(self):
        for counter in (0, 7):
            with self.subTest(counter=counter):
                current = {"mode": "learning", "nfqueue": {"terminal_queue_error": counter}}
                self.assertEqual(self.check_queue_health(current), counter)
                self.assertEqual(self.check_queue_health(current, expected=counter), counter)

    def test_learning_queue_health_does_not_default_missing_or_malformed_counter_to_zero(self):
        invalid_counters = [{}, None, {"terminal_queue_error": None}]
        invalid_counters.extend({"terminal_queue_error": value} for value in (
            False, True, -1, "0", 0.0, 0x10000000000000000,
        ))
        for counters in invalid_counters:
            with self.subTest(counters=counters):
                with self.assertRaisesRegex(RuntimeError, "missing or invalid"):
                    self.check_queue_health({"mode": "learning", "nfqueue": counters}, expected=0)

    def test_learning_queue_health_rejects_changed_or_reset_counter(self):
        for counter in (0, 2):
            with self.subTest(counter=counter):
                with self.assertRaisesRegex(RuntimeError, "counter|changed"):
                    self.check_queue_health(
                        {"mode": "learning", "nfqueue": {"terminal_queue_error": counter}},
                        expected=1,
                    )

    def test_learning_queue_health_requires_learning_mode(self):
        for mode in (None, "enforcing", "block_all"):
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(RuntimeError, "requires Learning mode"):
                    self.check_queue_health({"mode": mode, "nfqueue": {"terminal_queue_error": 0}})

    def test_learning_queue_health_rejects_missing_duplicate_or_unbound_queue(self):
        current = {"mode": "learning", "nfqueue": {"terminal_queue_error": 0}}
        for rows in (
            b"",
            b"1337 123 0 2 512 0 0 100 1\n",
            b"1338 123 0 2 512 0 0 100 1\n" * 2,
            b"1338 0 0 2 512 0 0 100 1\n",
            b"1338 123 0 2 512 0 0 100\n",
            b"1338 -1 0 2 512 0 0 100 1\n",
        ):
            with self.subTest(rows=rows):
                with self.assertRaisesRegex(RuntimeError, "Learning queue 1338"):
                    self.check_queue_health(current, rows=rows, expected=0)

    def test_learning_queue_health_rejects_oversized_procfs_read(self):
        current = {"mode": "learning", "nfqueue": {"terminal_queue_error": 0}}
        with self.assertRaisesRegex(RuntimeError, "read bound"):
            self.check_queue_health(current, rows=b" " * (MODULE.MAX_FRAME + 1))

    def test_learning_queue_health_rejects_invalid_expected_counter(self):
        for expected in (-1, False, "0", 0x10000000000000000):
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(RuntimeError, "invalid expected"):
                    self.check_queue_health({}, expected=expected)

    def test_fragmented_ipc_response_cannot_renew_five_second_deadline(self):
        now = [0.0]
        stream = mock.MagicMock()
        stream.__enter__.return_value = stream

        def fragment(size):
            now[0] += 2.0
            return b"\x00"

        stream.recv.side_effect = fragment
        with mock.patch.object(MODULE.time, "monotonic", side_effect=lambda: now[0]), \
                mock.patch.object(MODULE.socket, "socket", return_value=stream):
            with self.assertRaisesRegex(TimeoutError, "5-second absolute deadline"):
                MODULE.exchange(MODULE.OBSERVE, {"type": "read", "data": {"type": "status"}})
        self.assertEqual(stream.recv.call_count, 3)
        self.assertEqual(stream.settimeout.call_args_list[-1], mock.call(1.0))


if __name__ == "__main__":
    unittest.main()
