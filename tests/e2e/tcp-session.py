#!/usr/bin/env python3
"""Bounded real-socket client for the application TCP conntrack E2E path."""

from __future__ import annotations

import ipaddress
from pathlib import Path
import socket
import sys
import time


TRIGGER_TIMEOUT_SECONDS = 20.0
SOCKET_TIMEOUT_SECONDS = 5.0
LEARNING_EXCHANGE_INTERVAL_SECONDS = 0.25


def wait_for_trigger(path: Path) -> None:
    deadline = time.monotonic() + TRIGGER_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if path.is_file():
            return
        time.sleep(0.05)
    raise TimeoutError(f"timed out waiting for {path}")


def mark_ready(path: Path) -> None:
    path.write_text("ready\n", encoding="ascii")


def set_exchange_timeout(stream: socket.socket, deadline: float | None) -> None:
    remaining = SOCKET_TIMEOUT_SECONDS
    if deadline is not None:
        remaining = min(remaining, deadline - time.monotonic())
        if remaining <= 0:
            raise TimeoutError("Learning exchange deadline expired")
    stream.settimeout(remaining)


def receive_exact(
    stream: socket.socket, size: int, deadline: float | None = None
) -> bytes:
    received = bytearray()
    while len(received) < size:
        set_exchange_timeout(stream, deadline)
        chunk = stream.recv(size - len(received))
        if not chunk:
            raise ConnectionError("TCP echo peer closed the established connection")
        received.extend(chunk)
    return bytes(received)


def round_trip(
    stream: socket.socket, payload: bytes, deadline: float | None = None
) -> None:
    set_exchange_timeout(stream, deadline)
    stream.sendall(payload)
    if receive_exact(stream, len(payload), deadline) != payload:
        raise RuntimeError("TCP echo peer returned an unexpected payload")


def learn_until_idle(stream: socket.socket) -> None:
    deadline = time.monotonic() + TRIGGER_TIMEOUT_SECONDS
    idle = Path("/tmp/openshield-l2-learning-idle")
    ready = False
    while time.monotonic() < deadline:
        # Acknowledge only between complete exchanges. The controller waits
        # for this marker before changing policy, so no Learning heartbeat can
        # race the transition to Enforcing on this same socket.
        if ready and idle.is_file():
            stream.settimeout(SOCKET_TIMEOUT_SECONDS)
            mark_ready(Path("/tmp/openshield-l2-learning-idle-ready"))
            return
        round_trip(stream, b"learning", deadline)
        if not ready:
            mark_ready(Path("/tmp/openshield-l2-learning-ready"))
            ready = True
        # Learning retries attribution after its bounded debounce interval.
        # Keep the flow observable when its initial SYN attribution raced,
        # without renewing the total deadline or replacing its owning socket.
        time.sleep(
            min(LEARNING_EXCHANGE_INTERVAL_SECONDS, max(0, deadline - time.monotonic()))
        )
    raise TimeoutError(f"timed out waiting for {idle}")


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} IPV4 PORT", file=sys.stderr)
        return 2
    address = str(ipaddress.IPv4Address(sys.argv[1]))
    port = int(sys.argv[2], 10)
    if not 1 <= port <= 65_535:
        raise ValueError("port is outside 1..65535")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
        stream.settimeout(SOCKET_TIMEOUT_SECONDS)
        stream.connect((address, port))

        learn_until_idle(stream)

        wait_for_trigger(Path("/tmp/openshield-l2-enforcing-first"))
        round_trip(stream, b"enforcing-first")
        mark_ready(Path("/tmp/openshield-l2-enforcing-first-ready"))

        wait_for_trigger(Path("/tmp/openshield-l2-enforcing-fast"))
        round_trip(stream, b"enforcing-fast")
        mark_ready(Path("/tmp/openshield-l2-enforcing-fast-ready"))

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, TimeoutError, ValueError) as error:
        print(f"openshield TCP session: {error}", file=sys.stderr)
        raise SystemExit(1)
