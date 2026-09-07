#!/usr/bin/env python3
"""Deterministic framed-socket tests; never connect to a real daemon."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import socket
import struct
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "openshield_perf_control_tested", Path(__file__).with_name("control.py")
)
assert SPEC is not None and SPEC.loader is not None
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)


def frame(document: dict) -> bytes:
    payload = json.dumps(document).encode("utf-8")
    return struct.pack(">I", len(payload)) + payload


def status_response(revision=7) -> dict:
    return {
        "type": "status_v2",
        "data": {"revision": revision, "runtime_compatibility": {"level": "nfqueue"}},
    }


def rejection(code: str = "conflict") -> dict:
    return {"type": "error", "data": {"code": code, "message": "request was rejected"}}


def ack(revision: int = 8) -> dict:
    return {"type": "ack", "data": {"revision": revision, "affected_rule": None}}


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class FramedSocket:
    def __init__(
        self, *documents: dict, raw: bytes | None = None,
        fail_at: str | None = None, error: Exception | None = None,
        chunk_size: int | None = None, receive_seconds: float = 0.0,
    ) -> None:
        self.remaining = b"".join(map(frame, documents)) if raw is None else raw
        self.fail_at = fail_at
        self.error = error or socket.timeout("missing response")
        self.chunk_size = chunk_size
        self.receive_seconds = receive_seconds
        self.clock: FakeClock | None = None
        self.sent: list[dict] = []
        self.timeouts: list[float] = []
        self.path: str | None = None
        self.closed = False
        self.receive_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True
        return False

    def settimeout(self, seconds: float) -> None:
        if seconds <= 0:
            raise AssertionError("socket timeout must remain positive")
        self.timeouts.append(seconds)

    def connect(self, path: str) -> None:
        self.path = path
        if self.fail_at == "connect":
            raise self.error

    def sendall(self, payload: bytes) -> None:
        size = struct.unpack(">I", payload[:4])[0]
        if size != len(payload[4:]):
            raise AssertionError("request has an invalid frame")
        self.sent.append(json.loads(payload[4:]))
        if self.fail_at == "send":
            raise self.error

    def recv(self, size: int) -> bytes:
        self.receive_calls += 1
        if self.fail_at == "receive":
            raise self.error
        assert self.clock is not None
        elapsed = min(self.receive_seconds, self.timeouts[-1])
        self.clock.now += elapsed
        if self.receive_seconds >= self.timeouts[-1]:
            raise socket.timeout("bounded receive timed out")
        if self.chunk_size is not None:
            size = min(size, self.chunk_size)
        chunk, self.remaining = self.remaining[:size], self.remaining[size:]
        return chunk


def snapshot(revision: int, rules: list[dict]) -> FramedSocket:
    return FramedSocket(
        {"type": "status", "data": {"revision": revision}},
        {"type": "rules_page", "data": {
            "revision": revision, "rules": rules, "next_after": None,
        }},
    )


class ControlConflictTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.pending: list[FramedSocket] = []
        self.opened: list[FramedSocket] = []
        self.patch(mock.patch.object(control.time, "monotonic", self.clock.monotonic))
        self.patch(mock.patch.object(control.time, "sleep", self.clock.sleep))
        self.patch(mock.patch.object(control.socket, "socket", self.open_socket))

    def patch(self, patcher):
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def open_socket(self, family, kind) -> FramedSocket:
        self.assertEqual((family, kind), (socket.AF_UNIX, socket.SOCK_STREAM))
        self.assertTrue(self.pending, "unexpected request/retry beyond the fixture")
        stream = self.pending.pop(0)
        stream.clock = self.clock
        self.opened.append(stream)
        return stream

    def mutations(self) -> list[dict]:
        return [request["data"] for stream in self.opened for request in stream.sent
                if request["type"] == "control"]

    def test_conflict_refreshes_revision_before_set_mode_retry(self) -> None:
        self.pending = [
            FramedSocket(status_response(7)), FramedSocket(rejection()),
            FramedSocket(status_response(9)), FramedSocket(ack(10)),
        ]
        self.assertEqual(control.set_mode("enforcing"), ack(10)["data"])
        self.assertEqual(self.mutations(), [
            {"type": "set_mode", "data": {"mode": "enforcing", "expected_revision": 7}},
            {"type": "set_mode", "data": {"mode": "enforcing", "expected_revision": 9}},
        ])
        self.assertEqual(self.clock.sleeps, [control.CONTROL_RETRY_DELAY_SECONDS])
        self.assertTrue(all(stream.closed for stream in self.opened))

    def test_learning_persistence_can_finish_without_a_new_revision(self) -> None:
        self.pending = [
            FramedSocket(status_response()), FramedSocket(rejection()),
            FramedSocket(status_response()), FramedSocket(ack()),
        ]
        control.set_mode("learning")
        self.assertEqual([item["data"]["expected_revision"] for item in self.mutations()], [7, 7])

    def test_create_retry_preserves_intent_and_refreshes_only_revision(self) -> None:
        arguments = control.build_parser().parse_args([
            "create-rule", "--name", "perf", "--direction", "outbound",
            "--protocol", "tcp", "--peer", "192.0.2.7", "--port", "18082",
            "--application-executable", "/usr/bin/python3",
        ])
        self.pending = [
            FramedSocket(status_response(1)), FramedSocket(rejection()),
            FramedSocket(status_response(2)), FramedSocket(ack(3)),
        ]
        control.create_rule(arguments)
        first, second = self.mutations()
        self.assertEqual(first["type"], "create_rule")
        self.assertEqual(first["data"]["rule"], second["data"]["rule"])
        self.assertEqual(first["data"]["expected_revision"], 1)
        self.assertEqual(second["data"]["expected_revision"], 2)

    def test_non_conflict_rejections_are_never_retried(self) -> None:
        for code in ("invalid_request", "unauthorized", "not_found", "backend_unavailable", "internal"):
            with self.subTest(code=code):
                self.opened.clear()
                self.pending = [FramedSocket(status_response()), FramedSocket(rejection(code))]
                with self.assertRaises(control.RequestRejected):
                    control.set_mode("enforcing")
                self.assertEqual(len(self.mutations()), 1)
                self.assertFalse(self.clock.sleeps)

    def test_ambiguous_io_is_never_retried(self) -> None:
        for stage in ("connect", "send", "receive"):
            for error in (socket.timeout("lost ACK"), ConnectionResetError("lost ACK")):
                with self.subTest(stage=stage, error=type(error).__name__):
                    self.opened.clear()
                    self.pending = [FramedSocket(status_response()), FramedSocket(
                        fail_at=stage, error=error,
                    )]
                    with self.assertRaises(OSError):
                        control.set_mode("enforcing")
                    self.assertEqual(len(self.opened), 2)
                    self.assertLessEqual(len(self.mutations()), 1)
                    self.assertFalse(self.clock.sleeps)

    def test_truncated_malformed_or_unexpected_ack_is_never_retried(self) -> None:
        responses = (
            b"", struct.pack(">I", 20) + b"{}", struct.pack(">I", 0),
            struct.pack(">I", 1) + b"!", frame({"type": "status", "data": {}}),
            frame({"type": "ack", "data": {}}),
            frame({"type": "error", "data": {"code": "conflict"}}),
        )
        for response in responses:
            with self.subTest(response=response):
                self.opened.clear()
                self.pending = [FramedSocket(status_response()), FramedSocket(raw=response)]
                with self.assertRaises((RuntimeError, ValueError)):
                    control.set_mode("enforcing")
                self.assertEqual(len(self.mutations()), 1)
                self.assertFalse(self.clock.sleeps)

    def test_status_conflict_is_not_a_negative_control_ack(self) -> None:
        self.pending = [FramedSocket(rejection())]
        with self.assertRaises(control.RequestRejected):
            control.set_mode("enforcing")
        self.assertEqual(self.mutations(), [])
        self.assertFalse(self.clock.sleeps)

    def test_duplicate_response_fields_never_authorize_a_retry(self) -> None:
        responses = (
            b'{"type":"ack","type":"error","data":{"code":"conflict","message":"x"}}',
            b'{"type":"error","data":{"code":"internal","code":"conflict","message":"x"}}',
            b'{"type":"error","data":{"code":"conflict","message":"x"},"data":{"code":"conflict","message":"y"}}',
        )
        for response in responses:
            with self.subTest(response=response):
                self.opened.clear()
                self.pending = [FramedSocket(status_response()), FramedSocket(
                    raw=struct.pack(">I", len(response)) + response,
                )]
                with self.assertRaisesRegex(RuntimeError, "duplicate JSON"):
                    control.set_mode("enforcing")
                self.assertEqual(len(self.mutations()), 1)
                self.assertFalse(self.clock.sleeps)

    def test_invalid_revision_is_rejected_before_any_mutation(self) -> None:
        for revision in (True, False, None, -1, 1 << 64, "7"):
            with self.subTest(revision=revision):
                self.opened.clear()
                self.pending = [FramedSocket(status_response(revision))]
                with self.assertRaisesRegex(RuntimeError, "numeric revision"):
                    control.set_mode("enforcing")
                self.assertFalse(self.mutations())

    def test_retry_attempt_bound_is_independent_of_deadline(self) -> None:
        self.patch(mock.patch.object(control, "MAX_CONTROL_ATTEMPTS", 3))
        self.pending = [stream for revision in (1, 2, 3) for stream in (
            FramedSocket(status_response(revision)), FramedSocket(rejection()),
        )]
        with self.assertRaisesRegex(RuntimeError, "retry limit"):
            control.set_mode("enforcing")
        self.assertEqual(len(self.mutations()), 3)
        self.assertEqual(len(self.clock.sleeps), 2)

    def test_deadline_bounds_wait_and_prevents_a_later_retry(self) -> None:
        self.patch(mock.patch.object(control, "CONTROL_TIMEOUT_SECONDS", 0.1))
        self.pending = [FramedSocket(status_response()), FramedSocket(rejection())]
        with self.assertRaisesRegex(TimeoutError, "deadline"):
            control.set_mode("enforcing")
        self.assertEqual(len(self.mutations()), 1)
        self.assertAlmostEqual(sum(self.clock.sleeps), 0.1)

    def test_retry_socket_timeouts_share_one_monotonic_deadline(self) -> None:
        self.pending = [
            FramedSocket(status_response()), FramedSocket(rejection()),
            FramedSocket(status_response(8)), FramedSocket(ack(9)),
        ]
        control.set_mode("enforcing")
        self.assertLess(self.opened[2].timeouts[0], self.opened[0].timeouts[0])
        self.assertAlmostEqual(self.opened[2].timeouts[0],
                               control.CONTROL_TIMEOUT_SECONDS - control.CONTROL_RETRY_DELAY_SECONDS)

    def test_trickled_ack_does_not_reset_receive_deadline_or_retry(self) -> None:
        self.patch(mock.patch.object(control, "CONTROL_TIMEOUT_SECONDS", 0.5))
        slow_ack = FramedSocket(ack(), chunk_size=1, receive_seconds=0.2)
        self.pending = [FramedSocket(status_response()), slow_ack]
        with self.assertRaises(TimeoutError):
            control.set_mode("enforcing")
        self.assertEqual(slow_ack.receive_calls, 3)
        self.assertEqual(len(self.mutations()), 1)
        self.assertFalse(self.clock.sleeps)
        self.assertAlmostEqual(self.clock.now, 100.5)

    def test_clear_rules_retries_only_unchanged_original_rules(self) -> None:
        original = {"id": "original-rule", "spec": {"enabled": True}}
        newly_learned = {"id": "new-rule", "spec": {"enabled": True}}
        self.pending = [
            snapshot(1, [original]), snapshot(1, [original]), FramedSocket(rejection()),
            snapshot(2, [original, newly_learned]), FramedSocket(ack(3)),
        ]
        self.assertEqual(control.clear_rules(), 1)
        self.assertEqual([item["data"] for item in self.mutations()], [
            {"id": "original-rule", "expected_revision": 1},
            {"id": "original-rule", "expected_revision": 2},
        ])

    def test_clear_rules_refuses_changed_or_missing_original_after_conflict(self) -> None:
        original = {"id": "original-rule", "spec": {"enabled": True}}
        changed = copy.deepcopy(original)
        changed["spec"]["enabled"] = False
        for current_rules in ([], [changed], [original, original]):
            with self.subTest(current_rules=current_rules):
                self.opened.clear()
                self.pending = [
                    snapshot(1, [original]), snapshot(1, [original]), FramedSocket(rejection()),
                    snapshot(2, current_rules),
                ]
                with self.assertRaisesRegex(RuntimeError, "rule changed"):
                    control.clear_rules()
                self.assertEqual(len(self.mutations()), 1)

    def test_clear_rules_checks_each_target_with_its_snapshot_revision(self) -> None:
        self.pending = [
            snapshot(1, [{"id": "first"}, {"id": "second"}]),
            snapshot(1, [{"id": "first"}, {"id": "second"}]), FramedSocket(ack(2)),
            snapshot(2, [{"id": "second"}]), FramedSocket(ack(3)),
        ]
        self.assertEqual(control.clear_rules(), 2)
        self.assertEqual([item["data"]["expected_revision"] for item in self.mutations()], [1, 2])
        self.assertEqual(len(self.opened), 5)

    def test_conflict_on_first_delete_cannot_authorize_deleting_an_edited_later_target(self) -> None:
        first = {"id": "first", "spec": {"enabled": True}}
        second = {"id": "second", "spec": {"enabled": True}}
        edited_second = {"id": "second", "spec": {"enabled": False}}
        self.pending = [
            snapshot(1, [first, second]),
            snapshot(1, [first, second]), FramedSocket(rejection()),
            snapshot(2, [first, edited_second]), FramedSocket(ack(3)),
            snapshot(3, [edited_second]),
        ]
        with self.assertRaisesRegex(RuntimeError, "rule changed"):
            control.clear_rules()
        self.assertEqual([item["data"] for item in self.mutations()], [
            {"id": "first", "expected_revision": 1},
            {"id": "first", "expected_revision": 2},
        ])

    def test_clear_rules_has_one_deadline_for_all_deletions(self) -> None:
        self.patch(mock.patch.object(control, "CONTROL_TIMEOUT_SECONDS", 0.5))
        self.pending = [
            snapshot(1, [{"id": "first"}, {"id": "second"}, {"id": "third"}]),
            snapshot(1, [{"id": "first"}, {"id": "second"}, {"id": "third"}]),
            FramedSocket(ack(2), receive_seconds=0.15),
            snapshot(2, [{"id": "second"}, {"id": "third"}]),
            FramedSocket(ack(3), receive_seconds=0.15),
        ]
        with self.assertRaises(TimeoutError):
            control.clear_rules()
        self.assertEqual([item["data"]["id"] for item in self.mutations()], ["first", "second"])
        self.assertFalse(self.clock.sleeps)
        self.assertAlmostEqual(self.clock.now, 100.5)

    def test_clear_rules_ack_loss_is_not_reinterpreted_as_a_conflict(self) -> None:
        self.pending = [
            snapshot(1, [{"id": "original"}]),
            snapshot(1, [{"id": "original"}]), FramedSocket(raw=b""),
        ]
        with self.assertRaisesRegex(RuntimeError, "truncated"):
            control.clear_rules()
        self.assertEqual(len(self.mutations()), 1)
        self.assertFalse(self.clock.sleeps)

    def test_clear_rules_does_not_retry_an_inconsistent_snapshot(self) -> None:
        self.pending = [FramedSocket(
            {"type": "status", "data": {"revision": 1}},
            {"type": "rules_page", "data": {"revision": 2, "rules": [], "next_after": None}},
        )]
        with self.assertRaisesRegex(RuntimeError, "policy changed"):
            control.clear_rules()
        self.assertFalse(self.mutations())
        self.assertFalse(self.clock.sleeps)

    def test_rules_listing_also_has_a_shared_deadline(self) -> None:
        self.patch(mock.patch.object(control, "IO_TIMEOUT_SECONDS", 0.5))
        pages = FramedSocket(
            {"type": "status", "data": {"revision": 1}},
            {"type": "rules_page", "data": {"revision": 1, "rules": [], "next_after": "x"}},
            {"type": "rules_page", "data": {"revision": 1, "rules": [], "next_after": "x"}},
            receive_seconds=0.1,
        )
        self.pending = [pages]
        with self.assertRaises(TimeoutError):
            control.rules()
        self.assertEqual(len(self.opened), 1)
        self.assertFalse(self.mutations())
        self.assertFalse(self.clock.sleeps)
        self.assertAlmostEqual(self.clock.now, 100.5)


if __name__ == "__main__":
    unittest.main()
