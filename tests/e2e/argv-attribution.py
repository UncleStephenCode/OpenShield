#!/usr/bin/env python3
"""Exact long/control-character argv regression inside the short-lived E2E client."""

from __future__ import annotations

import argparse
import importlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import time

import ipc_client


short_sockets = importlib.import_module("short-lived-sockets")
EXECUTABLE = "/tmp/short-argv"
SCRIPT = "/opt/argv-attribution.py"
TIMEOUT_EXIT = 10


def fixture_argument() -> str:
    # These are argument data, never shell commands or executable Python text.
    return "argument=" + "x" * 2048 + "\nnext\t\x1b[31m\u202ename\\n\\u202e"


def command(protocol: str, address: str, port: int, argument: str) -> list[str]:
    return [EXECUTABLE, SCRIPT, "socket", protocol, address, str(port), argument]


def emit(value: dict) -> None:
    # ensure_ascii also neutralizes bidi and other formatting characters.
    print(json.dumps(value, ensure_ascii=True, sort_keys=True), flush=True)


def set_mode(mode: str) -> None:
    for _attempt in range(32):
        current = ipc_client.status()
        response = ipc_client.exchange(
            ipc_client.CONTROL,
            {
                "type": "control",
                "data": {
                    "type": "set_mode",
                    "data": {"expected_revision": current["revision"], "mode": mode},
                },
            },
        )
        if response.get("type") == "ack":
            return
        if (
            response.get("type") != "error"
            or response.get("data", {}).get("code") != "conflict"
        ):
            raise RuntimeError(f"mode transition failed: {response}")
        time.sleep(0.1)
    raise TimeoutError("policy did not stabilize for the argv regression mode transition")


def invoke(protocol: str, address: str, port: int, argument: str, allowed: bool) -> dict:
    completed = subprocess.run(
        ["runuser", "-u", "shortapp", "--", *command(protocol, address, port, argument)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=12,
        check=False,
    )
    expected_status = 0 if allowed else TIMEOUT_EXIT
    if completed.returncode != expected_status:
        raise RuntimeError(
            f"argv {protocol} probe expected status {expected_status}, "
            f"received {completed.returncode}; stderr={completed.stderr!r}"
        )
    result = json.loads(completed.stdout)
    if result.get("result") != ("allowed" if allowed else "timeout"):
        raise RuntimeError(f"unexpected argv probe evidence: {result}")
    if not allowed and result.get("elapsed_seconds", 0) < 0.5:
        raise RuntimeError("unmatched argv failed immediately instead of a firewall drop")
    return result


def exact_counts(address: str, tcp_port: int, uid: int, argument: str) -> dict[str, int]:
    rules = ipc_client.all_rules()
    return {
        protocol: sum(
            short_sockets.exact_application_rule(
                rule,
                EXECUTABLE,
                uid,
                command(protocol, address, tcp_port, argument),
                address,
                tcp_port if protocol == "tcp" else 53,
                protocol,
            )
            for rule in rules
        )
        for protocol in ("tcp", "udp")
    }


def exercise(address: str, tcp_port: int, uid: int) -> None:
    if os.geteuid() != 0:
        raise PermissionError("argv regression driver requires container root")
    if not Path("/.dockerenv").is_file() or Path(__file__).resolve() != Path(SCRIPT):
        raise RuntimeError("refusing mode changes outside the isolated Docker fixture")
    if pwd.getpwnam("shortapp").pw_uid != uid or not Path(EXECUTABLE).is_file():
        raise RuntimeError("argv regression executable or fixture UID is missing")
    raw = fixture_argument()
    literal = (
        raw.replace("\n", "\\n")
        .replace("\t", "\\t")
        .replace("\x1b", "\\u001b")
        .replace("\u202e", "\\u202e")
    )
    if raw == literal or not 1024 < len(raw.encode("utf-8")) < 4096:
        raise RuntimeError("argv fixture no longer covers the former per-argument bound")
    set_mode("learning")
    for protocol in ("tcp", "udp"):
        emit({"stage": "learning", **invoke(protocol, address, tcp_port, raw, True)})
    deadline = time.monotonic() + 15
    while True:
        counts = exact_counts(address, tcp_port, uid, raw)
        if counts == {"tcp": 1, "udp": 1}:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError(f"exact long/control argv was not learned: {counts}")
        time.sleep(0.1)
    emit({
        "stage": "learned_rule_audit",
        "exact_counts": counts,
        "raw_argument_bytes": len(raw.encode("utf-8")),
    })
    set_mode("enforcing")
    for protocol in ("tcp", "udp"):
        emit({
            "stage": "enforcing_exact",
            **invoke(protocol, address, tcp_port, raw, True),
        })
        emit({
            "stage": "enforcing_changed_argument",
            **invoke(protocol, address, tcp_port, literal, False),
        })
    if exact_counts(address, tcp_port, uid, raw) != {"tcp": 1, "udp": 1}:
        raise RuntimeError("Enforcing changed the learned exact argv rules")
    if exact_counts(address, tcp_port, uid, literal) != {"tcp": 0, "udp": 0}:
        raise RuntimeError("Enforcing unexpectedly learned the negative argv fixture")
    if ipc_client.status()["mode"] != "enforcing":
        raise RuntimeError("argv regression left the expected Enforcing mode")
    emit({"stage": "complete", "passed": True})


def audit_peer(path: Path, address: str) -> None:
    expected = {("tcp", "argv-regression"), ("udp-dns", "argv.e2e.openshield.test")}
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    counts = {f"{protocol}:{profile}": 0 for protocol, profile in expected}
    for event in events:
        key = (event.get("protocol"), event.get("profile"))
        if key not in expected:
            continue
        if str(event.get("source", "")).rsplit(":", 1)[0] != address:
            raise RuntimeError("argv peer evidence has an unexpected client address")
        counts[f"{key[0]}:{key[1]}"] += 1
    # Exactly one Learning and one Enforcing exchange per protocol. A timeout
    # in the negative client is insufficient: no negative request may reach the
    # peer even if a separate INPUT policy would have hidden its response.
    emit({"stage": "peer_audit", "counts": counts})
    if any(count != 2 for count in counts.values()):
        raise RuntimeError("argv peer saw a missing, retransmitted, or unauthorized request")


def socket_exchange(protocol: str, address: str, tcp_port: int, argument: str) -> int:
    # Keep both raw and escaped values as real argv with the same executable,
    # socket operation, UID, cgroup, and every other argument unchanged.
    if not argument.startswith("argument="):
        raise ValueError("missing argv fixture data")
    started = time.monotonic()
    try:
        if protocol == "tcp":
            short_sockets.tcp_once(address, tcp_port, "argv-regression")
        else:
            resolved = socket.getaddrinfo(
                "argv.e2e.openshield.test", tcp_port, socket.AF_INET, socket.SOCK_STREAM
            )
            if not resolved or any(result[4][0] != address for result in resolved):
                raise RuntimeError("DNS peer returned an unexpected answer")
    except TimeoutError:
        emit({
            "protocol": protocol,
            "result": "timeout",
            "elapsed_seconds": time.monotonic() - started,
        })
        return TIMEOUT_EXIT
    except socket.gaierror as error:
        if error.errno != socket.EAI_AGAIN:
            raise
        emit({
            "protocol": protocol,
            "result": "timeout",
            "elapsed_seconds": time.monotonic() - started,
        })
        return TIMEOUT_EXIT
    emit({
        "protocol": protocol,
        "result": "allowed",
        "elapsed_seconds": time.monotonic() - started,
    })
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    driver = subparsers.add_parser("exercise")
    driver.add_argument("address")
    driver.add_argument("port", type=short_sockets.checked_port)
    driver.add_argument("uid", type=int)
    child = subparsers.add_parser("socket")
    child.add_argument("protocol", choices=("tcp", "udp"))
    child.add_argument("address")
    child.add_argument("port", type=short_sockets.checked_port)
    child.add_argument("argument")
    audit = subparsers.add_parser("audit-peer")
    audit.add_argument("log", type=Path)
    audit.add_argument("address")
    arguments = parser.parse_args()
    ipaddress.IPv4Address(arguments.address)
    if arguments.operation == "audit-peer":
        audit_peer(arguments.log, arguments.address)
        return 0
    if arguments.operation == "exercise":
        exercise(arguments.address, arguments.port, arguments.uid)
        return 0
    return socket_exchange(
        arguments.protocol, arguments.address, arguments.port, arguments.argument
    )


if __name__ == "__main__":
    raise SystemExit(main())
