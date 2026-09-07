#!/usr/bin/env python3
"""Pure quota E2E matcher tests; no daemon, real state, processes or sockets."""

import copy
import errno
import importlib.util
import io
import json
from pathlib import Path
import sys
import types
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "learning_quota", Path(__file__).with_name("learning-quota.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
# None of these tests uses IPC. Fail-closed test isolation does not import or
# call a live client, nor does it shadow another test's imported IPC module.
with mock.patch.dict(sys.modules, {"ipc_client": types.ModuleType("ipc_client")}):
    SPEC.loader.exec_module(MODULE)


PEER = "192.0.2.42"
FILE_ID = {"device": 8, "inode": 123, "size": 456,
           "ctime_seconds": 1788782400, "ctime_nanoseconds": 0}


def rule(protocol):
    # Accept is intentionally absent, matching RuleAction's default-skipping
    # serde representation in an actual daemon-written state.json.
    return {"id": "00000000-0000-0000-0000-000000000001", "spec": {
        "origin": "learned", "direction": "outbound", "protocol": protocol,
        "peer_network": f"{PEER}/32", "port": {
            "start": MODULE.PORTS[protocol], "end": MODULE.PORTS[protocol]},
        "application": {"executable": MODULE.ALLOWED, "uid": 0,
                        "executable_file": copy.deepcopy(FILE_ID)},
        "enabled": True,
    }}


class LearningQuotaMatcherTests(unittest.TestCase):
    def match(self, candidate, protocol="tcp"):
        with mock.patch.object(MODULE, "persisted", return_value={candidate["id"]: candidate}), \
             mock.patch.object(MODULE, "identity", return_value=FILE_ID):
            return MODULE.learned(PEER, protocol)

    def test_actual_serialized_default_accept_matches_tcp_and_udp(self):
        for protocol in MODULE.PORTS:
            with self.subTest(protocol=protocol):
                candidate = rule(protocol)
                self.assertNotIn("action", candidate["spec"])
                self.assertEqual(self.match(candidate, protocol), [candidate])

    def test_explicit_accept_also_matches(self):
        candidate = rule("tcp")
        candidate["spec"]["action"] = "accept"
        self.assertEqual(self.match(candidate), [candidate])

    def test_drop_reject_and_invalid_actions_never_match(self):
        for action in ["drop", "reject", None, "unknown"]:
            with self.subTest(action=action):
                candidate = rule("tcp")
                candidate["spec"]["action"] = action
                self.assertEqual(self.match(candidate), [])

    def test_disabled_rule_never_matches(self):
        candidate = rule("tcp")
        candidate["spec"]["enabled"] = False
        self.assertEqual(self.match(candidate), [])

    def test_wrong_executable_identity_never_matches(self):
        for key in FILE_ID:
            with self.subTest(field=key):
                candidate = rule("tcp")
                candidate["spec"]["application"]["executable_file"][key] += 1
                self.assertEqual(self.match(candidate), [])

    def test_wrong_uid_path_or_missing_application_never_matches(self):
        for application in [None, {}, {"executable": MODULE.DENIED},
                            {"executable": MODULE.ALLOWED, "uid": 1, "executable_file": FILE_ID}]:
            with self.subTest(application=application):
                candidate = rule("tcp")
                candidate["spec"]["application"] = application
                self.assertEqual(self.match(candidate), [])

    def test_other_endpoint_and_origin_never_match(self):
        for field, value in [("origin", "manual"), ("direction", "inbound"),
                             ("protocol", "udp"), ("peer_network", "192.0.2.43/32"),
                             ("port", {"start": 1, "end": 65535})]:
            with self.subTest(field=field):
                candidate = rule("tcp")
                candidate["spec"][field] = value
                self.assertEqual(self.match(candidate), [])


class LearningQuotaWorkerTests(unittest.TestCase):
    def run_worker(self, error=None, *, operation="sendall"):
        stream = mock.Mock()
        stream.recv.return_value = b"unit-token"
        if error is not None:
            getattr(stream, operation).side_effect = error
        commands = [
            {"operation": "probe", "protocol": "udp", "token": "unit-token"},
            {"operation": "close"},
        ]
        incoming = io.StringIO("".join(json.dumps(command) + "\n" for command in commands))
        with mock.patch.object(MODULE.socket, "socket", return_value=stream), \
             mock.patch.object(MODULE.sys, "stdin", incoming), \
             mock.patch.object(MODULE, "emit") as output:
            MODULE.worker(PEER)
        return stream, output

    def test_eperm_and_eacces_are_explicit_socket_denials(self):
        for code in [errno.EPERM, errno.EACCES]:
            for operation in ["connect", "sendall", "recv"]:
                with self.subTest(errno=code, operation=operation):
                    stream, output = self.run_worker(PermissionError(code, "fixture denial"), operation=operation)
                    self.assertEqual(output.call_args_list[0].kwargs, {
                        "success": False, "token": "unit-token", "error": "PermissionError", "errno": code,
                    })
                    self.assertEqual(output.call_args_list[1].kwargs, {"closed": True})
                    stream.close.assert_called_once()

    def test_unexpected_socket_errors_are_not_denial_evidence(self):
        for error in [OSError(errno.ENETUNREACH, "fixture broken route"),
                      OSError(errno.EBADF, "fixture bad descriptor"),
                      PermissionError(errno.EIO, "fixture unexpected permission error")]:
            with self.subTest(error=repr(error)):
                with self.assertRaises(type(error)):
                    self.run_worker(error)

    def test_successful_udp_echo_remains_success(self):
        stream, output = self.run_worker()
        self.assertEqual(output.call_args_list[0].kwargs, {"success": True, "token": "unit-token"})
        self.assertEqual(output.call_args_list[1].kwargs, {"closed": True})
        stream.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
