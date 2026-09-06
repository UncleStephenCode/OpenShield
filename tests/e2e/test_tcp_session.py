#!/usr/bin/env python3
"""Exercise TCP fixture coordination with fake time and sockets only."""

import importlib.util
from pathlib import Path
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("tcp_session", HERE / "tcp-session.py")
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class EchoStream:
    def __init__(self, clock):
        self.clock = clock
        self.sent = []
        self.pending = b""
        self.timeout = None
        self.on_receive = None

    def settimeout(self, seconds):
        self.timeout = seconds

    def sendall(self, payload):
        if self.pending:
            raise AssertionError("sent another exchange before consuming its echo")
        self.sent.append((self.clock.now, payload))
        self.pending = payload

    def recv(self, size):
        if self.on_receive is not None:
            self.on_receive()
        # Deliberately fragment every echo to verify complete consumption.
        chunk = self.pending[: min(size, 2)]
        self.pending = self.pending[len(chunk) :]
        return chunk


class TcpSessionTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.stream = EchoStream(self.clock)
        self.markers = []
        self.idle_at = float("inf")
        self.first_at = float("inf")
        self.fast_at = float("inf")
        for patcher in (
            mock.patch.object(MODULE.time, "monotonic", self.clock.monotonic),
            mock.patch.object(MODULE.time, "sleep", self.clock.sleep),
            mock.patch.object(MODULE.Path, "is_file", autospec=True, side_effect=self.is_marker),
            mock.patch.object(MODULE, "mark_ready", self.mark_ready),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def is_marker(self, path):
        at = {
            "openshield-l2-learning-idle": self.idle_at,
            "openshield-l2-enforcing-first": self.first_at,
            "openshield-l2-enforcing-fast": self.fast_at,
        }.get(path.name, float("inf"))
        return self.clock.now >= at

    def mark_ready(self, path):
        self.assertEqual(self.stream.pending, b"")
        self.markers.append((self.clock.now, path.name))

    def test_learning_repeats_beyond_attribution_debounce_then_becomes_idle(self):
        self.idle_at = 1.5
        MODULE.learn_until_idle(self.stream)
        self.assertGreaterEqual(len(self.stream.sent), 5)
        self.assertTrue(any(at > 1.0 for at, _ in self.stream.sent))
        self.assertTrue(all(payload == b"learning" for _, payload in self.stream.sent))
        self.assertEqual(
            [name for _, name in self.markers],
            ["openshield-l2-learning-ready", "openshield-l2-learning-idle-ready"],
        )
        self.assertEqual(self.stream.timeout, MODULE.SOCKET_TIMEOUT_SECONDS)

    def test_idle_request_during_echo_waits_for_every_byte(self):
        self.stream.on_receive = lambda: setattr(self, "idle_at", self.clock.now)
        MODULE.learn_until_idle(self.stream)
        self.assertEqual(len(self.stream.sent), 1)
        self.assertEqual(self.stream.pending, b"")
        self.assertEqual(self.markers[-1][1], "openshield-l2-learning-idle-ready")

    def test_idle_phase_sends_nothing_until_enforcing_triggers(self):
        self.idle_at = 1.5
        self.first_at = 2.0
        self.fast_at = 3.0
        context = mock.MagicMock()
        context.__enter__.return_value = self.stream
        self.stream.connect = mock.Mock()
        with (
            mock.patch.object(MODULE.socket, "socket", return_value=context) as factory,
            mock.patch.object(MODULE.sys, "argv", ["tcp-session.py", "192.0.2.1", "18083"]),
        ):
            self.assertEqual(MODULE.main(), 0)
        factory.assert_called_once()
        self.stream.connect.assert_called_once_with(("192.0.2.1", 18083))
        idle_time = next(at for at, name in self.markers if name.endswith("idle-ready"))
        later = [(at, payload) for at, payload in self.stream.sent if at >= idle_time]
        self.assertEqual([payload for _, payload in later], [b"enforcing-first", b"enforcing-fast"])
        self.assertGreaterEqual(later[0][0], self.first_at)
        self.assertGreaterEqual(later[1][0], self.fast_at)

    def test_successful_heartbeats_do_not_extend_total_learning_deadline(self):
        with self.assertRaisesRegex(TimeoutError, "learning-idle"):
            MODULE.learn_until_idle(self.stream)
        self.assertEqual(self.clock.now, MODULE.TRIGGER_TIMEOUT_SECONDS)
        self.assertTrue(all(at < MODULE.TRIGGER_TIMEOUT_SECONDS for at, _ in self.stream.sent))
        self.assertEqual([name for _, name in self.markers], ["openshield-l2-learning-ready"])

    def test_fragmented_echo_cannot_extend_learning_deadline(self):
        def delayed_receive():
            self.clock.now += min(4.0, self.stream.timeout)

        self.stream.on_receive = delayed_receive
        with self.assertRaisesRegex(TimeoutError, "deadline expired"):
            MODULE.learn_until_idle(self.stream)
        self.assertEqual(self.clock.now, MODULE.TRIGGER_TIMEOUT_SECONDS)
        self.assertNotIn("openshield-l2-learning-idle-ready", [name for _, name in self.markers])

    def test_socket_errors_and_invalid_echo_are_not_retried_or_acknowledged(self):
        for result in (OSError("socket failed"), TimeoutError("socket timed out"), b"", b"wrong"):
            with self.subTest(result=result):
                self.stream = EchoStream(self.clock)
                self.markers.clear()
                self.stream.recv = mock.Mock(
                    side_effect=result if isinstance(result, Exception) else None,
                    return_value=result,
                )
                with self.assertRaises((OSError, RuntimeError)):
                    MODULE.learn_until_idle(self.stream)
                self.assertEqual(len(self.stream.sent), 1)
                self.assertEqual(self.markers, [])


if __name__ == "__main__":
    unittest.main()
