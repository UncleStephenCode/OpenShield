#!/usr/bin/env python3
"""Minimal bounded OpenShield IPC client for isolated end-to-end tests."""

import argparse
import json
import socket
import struct
import sys

MAX_FRAME = 64 * 1024
CONTROL = "/run/openshield/control.sock"
OBSERVE = "/run/openshield/observe.sock"


def exchange(path: str, request: dict) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5)
        stream.connect(path)
        send_request(stream, request)
        return receive_response(stream)


def send_request(stream: socket.socket, request: dict) -> None:
    payload = json.dumps(request, separators=(",", ":")).encode("utf-8")
    if not payload or len(payload) > MAX_FRAME:
        raise RuntimeError("outbound frame is outside the protocol bound")
    stream.sendall(struct.pack(">I", len(payload)) + payload)


def receive_response(stream: socket.socket) -> dict:
    header = receive_exact(stream, 4)
    size = struct.unpack(">I", header)[0]
    if size == 0 or size > MAX_FRAME:
        raise RuntimeError(f"invalid response frame size {size}")
    response = json.loads(receive_exact(stream, size))
    if not isinstance(response, dict):
        raise RuntimeError("IPC response is not a JSON object")
    return response


def receive_exact(stream: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError("truncated IPC response")
        chunks.extend(chunk)
    return bytes(chunks)


def status() -> dict:
    response = exchange(OBSERVE, {"type": "read", "data": {"type": "status"}})
    if response.get("type") != "status":
        raise RuntimeError(f"unexpected status response: {response}")
    return response["data"]


def status_v2() -> dict:
    response = exchange(OBSERVE, {"type": "read", "data": {"type": "status_v2"}})
    if response.get("type") != "status_v2":
        raise RuntimeError(f"unexpected status-v2 response: {response}")
    data = response.get("data")
    if not isinstance(data, dict) or not isinstance(
        data.get("runtime_compatibility"), dict
    ):
        raise RuntimeError(f"malformed status-v2 response: {response}")
    return data


def all_rules() -> list[dict]:
    rules: list[dict] = []
    after = None
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5)
        stream.connect(OBSERVE)
        send_request(stream, {"type": "read", "data": {"type": "status"}})
        initial = receive_response(stream)
        if initial.get("type") != "status":
            raise RuntimeError(f"unexpected pagination status: {initial}")
        revision = initial["data"]["revision"]
        while True:
            send_request(
                stream,
                {
                    "type": "read",
                    "data": {
                        "type": "rules_page",
                        "data": {"after": after, "limit": 128},
                    },
                },
            )
            response = receive_response(stream)
            if response.get("type") != "rules_page":
                raise RuntimeError(f"unexpected rules response: {response}")
            page = response["data"]
            if revision != page["revision"]:
                raise RuntimeError("policy changed during E2E pagination")
            rules.extend(page["rules"])
            after = page["next_after"]
            if after is None:
                return rules


def control(payload: dict) -> dict:
    response = exchange(CONTROL, {"type": "control", "data": payload})
    if response.get("type") != "ack":
        raise RuntimeError(f"control request failed: {response}")
    return response["data"]


def matching_application_template(executable: str) -> dict | None:
    for rule in all_rules():
        spec = rule.get("spec", {})
        application = spec.get("application") or {}
        if (
            spec.get("origin") == "template"
            and spec.get("direction") == "outbound"
            and spec.get("action", "accept") == "accept"
            and spec.get("protocol") == "any"
            and spec.get("peer_network") is None
            and spec.get("port") is None
            and spec.get("interface") is None
            and application.get("executable") == executable
            and application.get("command_line") is None
            and application.get("uid") is None
            and application.get("metadata_redacted") is False
            and (
                application.get("cgroup") is None
                or (
                    isinstance(application.get("cgroup"), str)
                    and application["cgroup"].startswith("/")
                )
            )
        ):
            return rule
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("status")
    runtime = subcommands.add_parser("assert-runtime")
    runtime.add_argument("mode", choices=("block_all", "learning", "enforcing"))
    runtime.add_argument("backend", choices=("nftables", "iptables"))
    runtime.add_argument(
        "level", choices=("kernel_native", "conntrack_hybrid", "nfqueue")
    )
    runtime.add_argument(
        "reason",
        choices=(
            "block_all",
            "network_only",
            "learning",
            "application_tcp",
            "application_per_packet",
        ),
    )
    mode = subcommands.add_parser("set-mode")
    mode.add_argument("mode", choices=("block_all", "learning", "enforcing"))
    inbound = subcommands.add_parser("allow-inbound-tcp")
    inbound.add_argument("port", type=int)
    subcommands.add_parser("rules")
    learned = subcommands.add_parser("assert-learned")
    learned.add_argument("executable")
    learned.add_argument("address")
    learned.add_argument("port", type=int)
    learned.add_argument("protocol", choices=("tcp", "udp"))
    no_learned = subcommands.add_parser("assert-no-learned")
    no_learned.add_argument("executable")
    no_learned.add_argument("address")
    no_learned.add_argument("port", type=int)
    no_learned.add_argument("protocol", choices=("tcp", "udp"))
    template = subcommands.add_parser("assert-template")
    template.add_argument("executable")
    template.add_argument("state", choices=("enabled", "disabled"))
    enable_template = subcommands.add_parser("enable-template")
    enable_template.add_argument("executable")
    disable_template = subcommands.add_parser("disable-template")
    disable_template.add_argument("executable")
    application_rule = subcommands.add_parser("create-app-tcp-rule")
    application_rule.add_argument("name")
    application_rule.add_argument("executable")
    application_rule.add_argument("address")
    application_rule.add_argument("port", type=int)
    application_rule.add_argument("action", choices=("accept", "drop", "reject"))
    network_rule = subcommands.add_parser("create-network-tcp-rule")
    network_rule.add_argument("name")
    network_rule.add_argument("address")
    network_rule.add_argument("port", type=int)
    network_rule.add_argument("action", choices=("accept", "drop", "reject"))
    named_rule = subcommands.add_parser("set-named-rule-enabled")
    named_rule.add_argument("name")
    named_rule.add_argument("state", choices=("enabled", "disabled"))
    arguments = parser.parse_args()

    if arguments.command == "status":
        print(json.dumps(status(), sort_keys=True))
    elif arguments.command == "assert-runtime":
        current = status_v2()
        compatibility = current["runtime_compatibility"]
        expected = {
            "mode": arguments.mode,
            "backend": arguments.backend,
            "level": arguments.level,
            "reason": arguments.reason,
        }
        actual = {
            "mode": current.get("mode"),
            "backend": current.get("backend"),
            "level": compatibility.get("level"),
            "reason": compatibility.get("reason"),
        }
        if actual != expected:
            raise RuntimeError(
                f"unexpected runtime compatibility: expected {expected}, received {actual}"
            )
        print(json.dumps(current, sort_keys=True))
    elif arguments.command == "rules":
        print(json.dumps(all_rules(), sort_keys=True))
    elif arguments.command == "set-mode":
        current = status()
        print(
            json.dumps(
                control(
                    {
                        "type": "set_mode",
                        "data": {
                            "expected_revision": current["revision"],
                            "mode": arguments.mode,
                        },
                    }
                ),
                sort_keys=True,
            )
        )
    elif arguments.command == "allow-inbound-tcp":
        if not 1 <= arguments.port <= 65535:
            raise RuntimeError("port is outside 1..65535")
        current = status()
        rule = {
            "name": f"E2E inbound TCP {arguments.port}",
            "direction": "inbound",
            "protocol": "tcp",
            "peer_network": None,
            "port": {"start": arguments.port, "end": arguments.port},
            "interface": "eth0",
            "application": None,
            "origin": "manual",
            "action": "accept",
            "enabled": True,
        }
        print(
            json.dumps(
                control(
                    {
                        "type": "create_rule",
                        "data": {"expected_revision": current["revision"], "rule": rule},
                    }
                ),
                sort_keys=True,
            )
        )
    elif arguments.command == "assert-learned":
        for rule in all_rules():
            spec = rule.get("spec", {})
            application = spec.get("application") or {}
            executable_file = application.get("executable_file") or {}
            command_line = application.get("command_line") or {}
            command_arguments = command_line.get("arguments")
            cgroup = application.get("cgroup")
            port = spec.get("port") or {}
            if (
                spec.get("origin") == "learned"
                and spec.get("enabled") is True
                and spec.get("action", "accept") == "accept"
                and spec.get("protocol") == arguments.protocol
                and application.get("executable") == arguments.executable
                and application.get("uid") is not None
                and application.get("metadata_redacted") is False
                and all(
                    field in executable_file
                    for field in (
                        "device",
                        "inode",
                        "size",
                        "ctime_seconds",
                        "ctime_nanoseconds",
                    )
                )
                and command_line.get("kind") == "exact"
                and isinstance(command_arguments, list)
                and len(command_arguments) > 0
                and (cgroup is None or (isinstance(cgroup, str) and cgroup.startswith("/")))
                and spec.get("peer_network") in (arguments.address, f"{arguments.address}/32")
                and port.get("start") == arguments.port
                and port.get("end") == arguments.port
            ):
                return 0
        raise RuntimeError("expected learned application rule was not found")
    elif arguments.command == "assert-no-learned":
        for rule in all_rules():
            spec = rule.get("spec", {})
            application = spec.get("application") or {}
            port = spec.get("port") or {}
            if (
                spec.get("origin") == "learned"
                and spec.get("protocol") == arguments.protocol
                and application.get("executable") == arguments.executable
                and spec.get("peer_network")
                in (arguments.address, f"{arguments.address}/32")
                and port.get("start") == arguments.port
                and port.get("end") == arguments.port
            ):
                raise RuntimeError(
                    "an attribution failure unexpectedly created a learned rule"
                )
    elif arguments.command == "assert-template":
        rule = matching_application_template(arguments.executable)
        if rule is None:
            raise RuntimeError("expected application-group template was not found")
        spec = rule["spec"]
        expected_enabled = arguments.state == "enabled"
        if spec.get("enabled") is not expected_enabled:
            raise RuntimeError(
                f"template enabled state is not {expected_enabled}: {spec}"
            )
        executable_file = (spec.get("application") or {}).get("executable_file")
        if expected_enabled:
            if not isinstance(executable_file, dict) or not all(
                field in executable_file
                for field in (
                    "device",
                    "inode",
                    "size",
                    "ctime_seconds",
                    "ctime_nanoseconds",
                )
            ):
                raise RuntimeError("enabled template has no complete executable pin")
        elif executable_file is not None:
            raise RuntimeError("disabled template unexpectedly has an executable pin")
    elif arguments.command == "enable-template":
        rule = matching_application_template(arguments.executable)
        if rule is None:
            raise RuntimeError("application-group template was not found")
        if rule.get("spec", {}).get("enabled") is not False:
            raise RuntimeError("application-group template is not disabled")
        current = status()
        print(
            json.dumps(
                control(
                    {
                        "type": "set_rule_enabled",
                        "data": {
                            "expected_revision": current["revision"],
                            "id": rule["id"],
                            "enabled": True,
                        },
                    }
                ),
                sort_keys=True,
            )
        )
    elif arguments.command == "disable-template":
        rule = matching_application_template(arguments.executable)
        if rule is None:
            raise RuntimeError("application-group template was not found")
        if rule.get("spec", {}).get("enabled") is not True:
            raise RuntimeError("application-group template is not enabled")
        current = status()
        print(
            json.dumps(
                control(
                    {
                        "type": "set_rule_enabled",
                        "data": {
                            "expected_revision": current["revision"],
                            "id": rule["id"],
                            "enabled": False,
                        },
                    }
                ),
                sort_keys=True,
            )
        )
    elif arguments.command == "create-app-tcp-rule":
        if not 1 <= arguments.port <= 65535:
            raise RuntimeError("port is outside 1..65535")
        current = status()
        rule = {
            "name": arguments.name,
            "direction": "outbound",
            "action": arguments.action,
            "protocol": "tcp",
            "peer_network": f"{arguments.address}/32",
            "port": {"start": arguments.port, "end": arguments.port},
            "interface": None,
            "application": {
                "executable": arguments.executable,
                "executable_file": None,
                "command_line": None,
                "uid": None,
                "cgroup": None,
                "metadata_redacted": False,
            },
            "origin": "manual",
            "enabled": True,
        }
        print(
            json.dumps(
                control(
                    {
                        "type": "create_rule",
                        "data": {"expected_revision": current["revision"], "rule": rule},
                    }
                ),
                sort_keys=True,
            )
        )
    elif arguments.command == "create-network-tcp-rule":
        if not 1 <= arguments.port <= 65535:
            raise RuntimeError("port is outside 1..65535")
        current = status()
        rule = {
            "name": arguments.name,
            "direction": "outbound",
            "action": arguments.action,
            "protocol": "tcp",
            "peer_network": f"{arguments.address}/32",
            "port": {"start": arguments.port, "end": arguments.port},
            "interface": None,
            "application": None,
            "origin": "manual",
            "enabled": True,
        }
        print(
            json.dumps(
                control(
                    {
                        "type": "create_rule",
                        "data": {"expected_revision": current["revision"], "rule": rule},
                    }
                ),
                sort_keys=True,
            )
        )
    elif arguments.command == "set-named-rule-enabled":
        matches = [
            rule
            for rule in all_rules()
            if rule.get("spec", {}).get("name") == arguments.name
        ]
        if len(matches) != 1:
            raise RuntimeError(
                f"expected one rule named {arguments.name!r}, found {len(matches)}"
            )
        current = status()
        print(
            json.dumps(
                control(
                    {
                        "type": "set_rule_enabled",
                        "data": {
                            "expected_revision": current["revision"],
                            "id": matches[0]["id"],
                            "enabled": arguments.state == "enabled",
                        },
                    }
                ),
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"openshield-e2e-client: {error}", file=sys.stderr)
        raise SystemExit(1)
