#!/usr/bin/env python3
"""Bounded OpenShield control client used only inside the perf DUT container."""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import struct
import sys
import time
from typing import Any


MAX_FRAME_BYTES = 64 * 1024
MAX_RULES = 10_000
CONTROL_SOCKET = "/run/openshield/control.sock"
OBSERVE_SOCKET = "/run/openshield/observe.sock"
IO_TIMEOUT_SECONDS = 5.0
CONTROL_TIMEOUT_SECONDS = 5.0
MAX_CONTROL_ATTEMPTS = 20
CONTROL_RETRY_DELAY_SECONDS = 0.25


class RequestRejected(RuntimeError):
    """A complete negative acknowledgement, never an ambiguous I/O failure."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.code = data["code"]
        super().__init__(f"OpenShield rejected request: {data!r}")


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("OpenShield control deadline exceeded")
    return remaining


def _arm_timeout(stream: socket.socket, deadline: float | None) -> None:
    stream.settimeout(
        IO_TIMEOUT_SECONDS if deadline is None else min(IO_TIMEOUT_SECONDS, _remaining(deadline))
    )


def _send(
    stream: socket.socket, request: dict[str, Any], *, deadline: float | None = None
) -> None:
    payload = json.dumps(request, separators=(",", ":")).encode("utf-8")
    if not payload or len(payload) > MAX_FRAME_BYTES:
        raise RuntimeError("request is outside the protocol frame bound")
    _arm_timeout(stream, deadline)
    stream.sendall(struct.pack(">I", len(payload)) + payload)


def _receive_exact(
    stream: socket.socket, size: int, *, deadline: float | None = None
) -> bytes:
    result = bytearray()
    while len(result) < size:
        _arm_timeout(stream, deadline)
        chunk = stream.recv(size - len(result))
        if not chunk:
            raise RuntimeError("truncated OpenShield response")
        result.extend(chunk)
    return bytes(result)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError("OpenShield response contains duplicate JSON fields")
        result[key] = value
    return result


def _receive(
    stream: socket.socket, *, deadline: float | None = None
) -> dict[str, Any]:
    size = struct.unpack(">I", _receive_exact(stream, 4, deadline=deadline))[0]
    if not 0 < size <= MAX_FRAME_BYTES:
        raise RuntimeError(f"invalid OpenShield response size {size}")
    response = json.loads(
        _receive_exact(stream, size, deadline=deadline), object_pairs_hook=_unique_object
    )
    if not isinstance(response, dict):
        raise RuntimeError("OpenShield response is not an object")
    if response.get("type") == "error":
        data = response.get("data")
        if not isinstance(data, dict) or not isinstance(data.get("code"), str) or not isinstance(
            data.get("message"), str
        ):
            raise RuntimeError(f"malformed OpenShield rejection: {response!r}")
        raise RequestRejected(data)
    return response


def exchange(
    path: str, request: dict[str, Any], *, deadline: float | None = None
) -> dict[str, Any]:
    if deadline is None:
        deadline = time.monotonic() + IO_TIMEOUT_SECONDS
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        _arm_timeout(stream, deadline)
        stream.connect(path)
        _send(stream, request, deadline=deadline)
        return _receive(stream, deadline=deadline)


def status(*, deadline: float | None = None) -> dict[str, Any]:
    response = exchange(
        OBSERVE_SOCKET, {"type": "read", "data": {"type": "status_v2"}}, deadline=deadline
    )
    if response.get("type") != "status_v2" or not isinstance(
        response.get("data"), dict
    ):
        raise RuntimeError(f"unexpected status response: {response!r}")
    data = response["data"]
    if not isinstance(data.get("runtime_compatibility"), dict):
        raise RuntimeError("status-v2 has no runtime compatibility evidence")
    return data


def _revision(data: dict[str, Any]) -> int:
    revision = data.get("revision")
    if type(revision) is not int or not 0 <= revision <= (1 << 64) - 1:
        raise RuntimeError("OpenShield response has no valid numeric revision")
    return revision


def _rules_snapshot(*, deadline: float | None = None) -> tuple[int, list[dict[str, Any]]]:
    if deadline is None:
        deadline = time.monotonic() + IO_TIMEOUT_SECONDS
    result: list[dict[str, Any]] = []
    cursor: str | None = None
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        _arm_timeout(stream, deadline)
        stream.connect(OBSERVE_SOCKET)
        # The observation protocol requires synchronization through Status
        # before the first rules page on each connection.
        _send(stream, {"type": "read", "data": {"type": "status"}}, deadline=deadline)
        initial = _receive(stream, deadline=deadline)
        status_data = initial.get("data")
        if initial.get("type") != "status" or not isinstance(status_data, dict):
            raise RuntimeError(f"unexpected initial status response: {initial!r}")
        revision = _revision(status_data)
        while True:
            _send(
                stream,
                {
                    "type": "read",
                    "data": {
                        "type": "rules_page",
                        "data": {"after": cursor, "limit": 128},
                    },
                },
                deadline=deadline,
            )
            response = _receive(stream, deadline=deadline)
            if response.get("type") != "rules_page":
                raise RuntimeError(f"unexpected rules response: {response!r}")
            page = response.get("data")
            if not isinstance(page, dict) or not isinstance(page.get("rules"), list):
                raise RuntimeError("malformed rules page")
            page_revision = _revision(page)
            if revision != page_revision:
                raise RuntimeError("policy changed while rules were paginated")
            result.extend(page["rules"])
            if len(result) > MAX_RULES:
                raise RuntimeError("daemon returned more rules than the model bound")
            cursor = page.get("next_after")
            if cursor is None:
                return revision, result
            if not isinstance(cursor, str):
                raise RuntimeError("rules page has an invalid cursor")


def rules() -> list[dict[str, Any]]:
    return _rules_snapshot()[1]


def control(
    payload: dict[str, Any], *, deadline: float | None = None
) -> dict[str, Any]:
    response = exchange(
        CONTROL_SOCKET, {"type": "control", "data": payload}, deadline=deadline
    )
    if response.get("type") != "ack" or not isinstance(response.get("data"), dict):
        raise RuntimeError(f"unexpected control response: {response!r}")
    _revision(response["data"])
    return response["data"]


def _control_with_revision(
    request_type: str,
    data: dict[str, Any],
    *,
    expected_rule: dict[str, Any] | None = None,
    deadline: float | None = None,
) -> dict[str, Any]:
    if deadline is None:
        deadline = time.monotonic() + CONTROL_TIMEOUT_SECONDS
    for attempt in range(MAX_CONTROL_ATTEMPTS):
        _remaining(deadline)
        if expected_rule is None:
            revision = _revision(status(deadline=deadline))
        else:
            # Clear only the original snapshot. A concurrent edit, deletion,
            # or replacement must not turn a rejected delete into a new intent.
            revision, current_rules = _rules_snapshot(deadline=deadline)
            matches = [rule for rule in current_rules if rule.get("id") == data["id"]]
            if matches != [expected_rule]:
                raise RuntimeError("rule changed while preparing deletion; refusing to delete it")
        try:
            return control(
                {"type": request_type, "data": {**data, "expected_revision": revision}},
                deadline=deadline,
            )
        except RequestRejected as error:
            # The daemon rejects Conflict before committing the request. No
            # retry is safe after timeout, EOF, malformed ACK, or another error.
            if error.code != "conflict":
                raise
            if attempt + 1 == MAX_CONTROL_ATTEMPTS:
                raise RuntimeError("OpenShield control conflict retry limit exceeded") from error
            time.sleep(min(CONTROL_RETRY_DELAY_SECONDS, _remaining(deadline)))
    raise RuntimeError("OpenShield control has no configured attempts")


def set_mode(mode: str) -> dict[str, Any]:
    return _control_with_revision("set_mode", {"mode": mode})


def clear_rules() -> int:
    deadline = time.monotonic() + CONTROL_TIMEOUT_SECONDS
    _, original_rules = _rules_snapshot(deadline=deadline)
    removed = 0
    for rule in original_rules:
        identifier = rule.get("id")
        if not isinstance(identifier, str):
            raise RuntimeError("rule without a UUID")
        # Each target needs its own content check. A refreshed revision after
        # deleting an earlier target says nothing about edits to later targets.
        _control_with_revision(
            "delete_rule", {"id": identifier}, expected_rule=rule,
            deadline=deadline,
        )
        removed += 1
    return removed


def create_rule(arguments: argparse.Namespace) -> dict[str, Any]:
    peer = str(ipaddress.ip_network(arguments.peer, strict=False))
    if not 1 <= arguments.port <= 65_535:
        raise RuntimeError("port is outside 1..65535")
    application = None
    if arguments.application_executable:
        if arguments.direction != "outbound":
            raise RuntimeError("application selectors are outbound-only")
        if not arguments.application_executable.startswith("/"):
            raise RuntimeError("application executable must be absolute")
        application = {
            "executable": arguments.application_executable,
            "executable_file": None,
            "command_line": None,
            "uid": None,
            "cgroup": None,
            "metadata_redacted": False,
        }
    specification = {
        "name": arguments.name,
        "direction": arguments.direction,
        "protocol": arguments.protocol,
        "peer_network": peer,
        "port": {"start": arguments.port, "end": arguments.port},
        "interface": arguments.interface,
        "application": application,
        "origin": "manual",
        "enabled": True,
    }
    return _control_with_revision("create_rule", {"rule": specification})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    commands.add_parser("rules")
    commands.add_parser("clear-rules")
    mode = commands.add_parser("set-mode")
    mode.add_argument("mode", choices=("block_all", "learning", "enforcing"))
    create = commands.add_parser("create-rule")
    create.add_argument("--name", required=True)
    create.add_argument("--direction", choices=("inbound", "outbound"), required=True)
    create.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    create.add_argument("--peer", required=True)
    create.add_argument("--port", type=int, required=True)
    create.add_argument("--interface", default="eth0")
    create.add_argument("--application-executable")
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    if arguments.command == "status":
        output: Any = status()
    elif arguments.command == "rules":
        output = rules()
    elif arguments.command == "clear-rules":
        output = {"removed": clear_rules()}
    elif arguments.command == "set-mode":
        output = set_mode(arguments.mode)
    elif arguments.command == "create-rule":
        output = create_rule(arguments)
    else:
        raise RuntimeError("unknown command")
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"openshield-perf-control: {error}", file=sys.stderr)
        raise SystemExit(1)
