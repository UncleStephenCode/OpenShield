#!/usr/bin/env python3
"""Pure checks for the separate Strict/Fast real-socket E2E harness."""

import errno
import importlib.util
import io
import json
from pathlib import Path
import sys
import time
import types
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "enforcement_strategy", Path(__file__).with_name("enforcement-strategy.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
IPC = types.ModuleType("ipc_client")
IPC.OBSERVE = "/not-a-real-observe-socket"
IPC.exchange = mock.Mock()
IPC.control = mock.Mock()
with mock.patch.dict(sys.modules, {"ipc_client": IPC}):
    SPEC.loader.exec_module(MODULE)


class EnforcementStrategyHarnessTests(unittest.TestCase):
    def setUp(self):
        IPC.exchange.reset_mock()
        IPC.control.reset_mock()

    def test_status_v4_is_required_and_strategy_is_explicit(self):
        IPC.exchange.return_value = {"type": "status_v4", "data": {"enforcement_strategy": "fast"}}
        self.assertEqual(MODULE.status()["enforcement_strategy"], "fast")
        IPC.exchange.assert_called_once_with(IPC.OBSERVE, {
            "type": "read", "data": {"type": "status_v4"},
        })
        for response in [{"type": "status_v3", "data": {}},
                         {"type": "status_v4", "data": {}},
                         {"type": "status_v4", "data": {"enforcement_strategy": "unknown"}}]:
            IPC.exchange.return_value = response
            with self.assertRaises(RuntimeError):
                MODULE.status()

    def test_atomic_set_enforcement_payload_and_epoch_checks(self):
        IPC.control.return_value = {"revision": 8}
        with mock.patch.object(MODULE, "status", side_effect=[{"revision": 7}, {"revision": 8}]), \
             mock.patch.object(MODULE, "state", side_effect=[
                 {"revision": 7, "flow_generation": 3}, {"revision": 8, "flow_generation": 4}]):
            MODULE.mutation("set_enforcement", strategy="fast")
        IPC.control.assert_called_once_with({"type": "set_enforcement", "data": {
            "expected_revision": 7, "strategy": "fast",
        }})
        with mock.patch.object(MODULE, "status", side_effect=[{"revision": 7}, {"revision": 8}]), \
             mock.patch.object(MODULE, "state", side_effect=[
                 {"revision": 7, "flow_generation": 3}, {"revision": 8, "flow_generation": 3}]):
            with self.assertRaisesRegex(RuntimeError, "invalidate"):
                MODULE.mutation("set_enforcement", strategy="fast")

    def test_enabling_accept_preserves_generation_but_advances_revision(self):
        IPC.control.return_value = {"revision": 8}
        before = {"revision": 7, "flow_generation": 3,
                  "rules": {"tcp-id": {"spec": {"enabled": False}}}}
        with mock.patch.object(MODULE, "status", side_effect=[{"revision": 7}, {"revision": 8}]), \
             mock.patch.object(MODULE, "state", side_effect=[before, {"revision": 8, "flow_generation": 3}]):
            MODULE.mutation("set_rule_enabled", id="tcp-id", enabled=True)
        for revision, generation in [(7, 3), (8, 2)]:
            IPC.control.return_value = {"revision": revision}
            with self.subTest(revision=revision, generation=generation), \
                 mock.patch.object(MODULE, "status", side_effect=[{"revision": 7}, {"revision": revision}]), \
                 mock.patch.object(MODULE, "state", side_effect=[before, {"revision": revision, "flow_generation": generation}]):
                with self.assertRaises(RuntimeError):
                    MODULE.mutation("set_rule_enabled", id="tcp-id", enabled=True)

    def test_revocations_and_enabling_deny_still_require_epoch_rotation(self):
        for kind, data, spec in [
            ("set_rule_enabled", {"id": "rule-id", "enabled": False}, {"enabled": True}),
            ("set_rule_enabled", {"id": "rule-id", "enabled": True}, {"enabled": False, "action": "drop"}),
            ("set_rule_enabled", {"id": "rule-id", "enabled": True}, {"enabled": False, "action": "reject"}),
            ("delete_rule", {"id": "rule-id"}, {"enabled": True}),
        ]:
            before = {"revision": 7, "flow_generation": 3, "rules": {"rule-id": {"spec": spec}}}
            IPC.control.return_value = {"revision": 8}
            with self.subTest(kind=kind, data=data, spec=spec), \
                 mock.patch.object(MODULE, "status", side_effect=[{"revision": 7}, {"revision": 8}]), \
                 mock.patch.object(MODULE, "state", side_effect=[before, {"revision": 8, "flow_generation": 3}]):
                with self.assertRaisesRegex(RuntimeError, "invalidate"):
                    MODULE.mutation(kind, **data)

    def test_peer_audit_requires_all_allowed_and_no_forbidden_tokens(self):
        events = [{"token": token} for token in MODULE.allowed_tokens()]
        with mock.patch.object(Path, "read_text", return_value="\n".join(map(json.dumps, events))), \
             mock.patch.object(MODULE.Q, "emit"):
            MODULE.audit("/not-a-real-peer-log")
        for bad in [events[:-1], events + [{"token": "fast-forbidden-established-tcp"}],
                    events + [{"token": "unexpected-token"}]]:
            with mock.patch.object(Path, "read_text", return_value="\n".join(map(json.dumps, bad))):
                with self.assertRaises(RuntimeError):
                    MODULE.audit("/not-a-real-peer-log")

    def test_repeat_uses_the_same_held_socket_without_reconnect(self):
        stream = mock.Mock()
        commands = [
            {"operation": "probe", "protocol": "tcp", "token": "allowed"},
            {"operation": "repeat", "protocol": "tcp", "token": "forbidden"},
            {"operation": "close"},
        ]
        incoming = io.StringIO("".join(json.dumps(command) + "\n" for command in commands))
        with mock.patch.object(MODULE.socket, "socket", return_value=stream) as create, \
             mock.patch.object(MODULE.sys, "stdin", incoming), \
             mock.patch.object(MODULE, "exchange", side_effect=[None, PermissionError(errno.EPERM, "denied")]) as exchange, \
             mock.patch.object(MODULE.Q, "emit") as output:
            MODULE.worker("192.0.2.1")
        create.assert_called_once()
        self.assertEqual(exchange.call_args_list[0].args, (stream, "tcp", "192.0.2.1", "allowed", True))
        self.assertEqual(exchange.call_args_list[1].args, (stream, "tcp", "192.0.2.1", "forbidden", False))
        self.assertTrue(output.call_args_list[0].kwargs["success"])
        self.assertFalse(output.call_args_list[1].kwargs["success"])
        stream.close.assert_called_once()

    def test_tcp_read_handles_fragmentation_and_clean_eof(self):
        stream = mock.Mock()
        stream.recv.side_effect = [b"a", b"bc", b"d"]
        self.assertEqual(MODULE.receive_exact(stream, 4, time.monotonic() + 2), b"abcd")
        stream.recv.side_effect = [b"a", b""]
        with self.assertRaises(EOFError):
            MODULE.receive_exact(stream, 4, time.monotonic() + 2)


if __name__ == "__main__":
    unittest.main()
