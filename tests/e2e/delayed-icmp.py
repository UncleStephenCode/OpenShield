#!/usr/bin/env python3
"""Real-socket delayed-reply workloads for the OpenShield E2E fixture."""

from __future__ import annotations

import argparse
import concurrent.futures
import heapq
import ipaddress
import json
import math
import os
import re
import select
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

MAGIC = b"OSD1"
UDP_PAYLOAD_SIZE = 128
TCP_REQUEST = struct.Struct("!4sIHB")
TCP_RESPONSE = struct.Struct("!4sI")
MAX_PENDING_REPLIES = 4_096
MAX_TCP_DELAY_MS = 2_000
MAX_P95_OVERHEAD_MS = 500.0
MAX_P99_OVERHEAD_MS = 500.0
MAX_TAIL_OVERHEAD_MS = 1_000.0
NFQUEUE_NUMBERS = (1_337, 1_338, 1_339)
HELD_RELEASE_PATH = Path("/tmp/delayed-held.release")
HELD_SENT_PATH = Path("/tmp/delayed-held.sent")


def checked_ipv4(value: str) -> str:
    address = ipaddress.ip_address(value)
    if address.version != 4:
        raise argparse.ArgumentTypeError("an IPv4 address is required")
    return str(address)


def checked_port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port is outside 1..65535")
    return port


def checked_count(value: str) -> int:
    count = int(value)
    if not 1 <= count <= 128:
        raise argparse.ArgumentTypeError("count is outside 1..128")
    return count


def checked_interval(value: str) -> float:
    interval = float(value)
    if not 0.05 <= interval <= 2.0:
        raise argparse.ArgumentTypeError("interval is outside 0.05..2.0 seconds")
    return interval


def checked_delay(value: str) -> int:
    delay = int(value)
    if not 1 <= delay <= MAX_TCP_DELAY_MS:
        raise argparse.ArgumentTypeError(
            f"delay is outside 1..{MAX_TCP_DELAY_MS} milliseconds"
        )
    return delay


def percentile(values: list[float], percentage: int) -> float:
    if not values:
        raise ValueError("cannot calculate a percentile of no values")
    index = max(0, math.ceil(len(values) * percentage / 100.0) - 1)
    return sorted(values)[index]


def checksum(payload: bytes) -> int:
    if len(payload) % 2:
        payload += b"\x00"
    total = sum(struct.unpack(f"!{len(payload) // 2}H", payload))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


class EventLog:
    def __init__(self, path: Path) -> None:
        path.unlink(missing_ok=True)
        self._stream = path.open("a", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()

    def write(self, event: dict[str, object]) -> None:
        with self._lock:
            self._stream.write(json.dumps(event, sort_keys=True) + "\n")


def receive_exact(stream: socket.socket, size: int) -> bytes | None:
    result = bytearray()
    while len(result) < size:
        part = stream.recv(size - len(result))
        if not part:
            if not result:
                return None
            raise ConnectionError("TCP peer closed a partial frame")
        result.extend(part)
    return bytes(result)


class DelayedTcpHandler(socketserver.BaseRequestHandler):
    server: "DelayedTcpServer"

    def handle(self) -> None:
        self.request.settimeout(10.0)
        while True:
            frame = receive_exact(self.request, TCP_REQUEST.size)
            if frame is None:
                return
            magic, sequence, delay_ms, close_after = TCP_REQUEST.unpack(frame)
            if (
                magic != MAGIC
                or not 1 <= delay_ms <= MAX_TCP_DELAY_MS
                or close_after not in (0, 1, 2)
            ):
                raise ValueError("invalid delayed TCP request")
            received_ns = time.monotonic_ns()
            self.server.events.write(
                {
                    "transport": "tcp",
                    "phase": "received",
                    "sequence": sequence,
                    "source": self.client_address[0],
                    "received_monotonic_ns": received_ns,
                    "configured_delay_ms": delay_ms,
                }
            )
            delay_started_ns = received_ns
            gate_wait_ms = None
            if close_after == 2:
                deadline = time.monotonic() + 10.0
                while not HELD_RELEASE_PATH.exists():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("held TCP release barrier timed out")
                    time.sleep(0.01)
                delay_started_ns = time.monotonic_ns()
                gate_wait_ms = round(
                    (delay_started_ns - received_ns) / 1_000_000, 6
                )
            time.sleep(delay_ms / 1_000.0)
            self.request.sendall(TCP_RESPONSE.pack(MAGIC, sequence))
            sent_ns = time.monotonic_ns()
            self.server.events.write(
                {
                    "transport": "tcp",
                    "phase": "sent",
                    "sequence": sequence,
                    "source": self.client_address[0],
                    "received_monotonic_ns": received_ns,
                    "sent_monotonic_ns": sent_ns,
                    "configured_delay_ms": delay_ms,
                    "actual_delay_ms": round(
                        (sent_ns - delay_started_ns) / 1_000_000, 6
                    ),
                    "gate_wait_ms": gate_wait_ms,
                }
            )
            if close_after == 2:
                HELD_SENT_PATH.write_text("sent\n", encoding="ascii")
                return
            if close_after:
                return


class DelayedTcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address: tuple[str, int], events: EventLog) -> None:
        self.events = events
        super().__init__(address, DelayedTcpHandler)


def parse_icmp_request(packet: bytes, address: str) -> tuple[bytes, str, int, int] | None:
    if len(packet) < 28 or packet[0] >> 4 != 4:
        return None
    header_size = (packet[0] & 0x0F) * 4
    if header_size < 20 or len(packet) < header_size + 8:
        return None
    if socket.inet_ntoa(packet[16:20]) != address:
        return None
    request = bytearray(packet[header_size:])
    if request[0] != 8 or request[1] != 0:
        return None
    identifier, sequence = struct.unpack("!HH", request[4:8])
    request[0] = 0
    request[2:4] = b"\x00\x00"
    request[2:4] = struct.pack("!H", checksum(bytes(request)))
    return bytes(request), socket.inet_ntoa(packet[12:16]), identifier, sequence


def udp_payload(sequence: int) -> bytes:
    prefix = MAGIC + struct.pack("!I", sequence)
    suffix = bytes(
        (sequence + index) % 251 for index in range(UDP_PAYLOAD_SIZE - len(prefix))
    )
    return prefix + suffix


def parse_udp_payload(payload: bytes) -> int:
    if len(payload) != UDP_PAYLOAD_SIZE or payload[:4] != MAGIC:
        raise ValueError("invalid delayed UDP payload")
    sequence = struct.unpack("!I", payload[4:8])[0]
    if payload != udp_payload(sequence):
        raise ValueError("corrupted delayed UDP payload")
    return sequence


def serve(
    address: str,
    udp_port: int,
    tcp_port: int,
    delay_ms: int,
    log_path: Path,
    ready_path: Path,
) -> None:
    ready_path.unlink(missing_ok=True)
    HELD_RELEASE_PATH.unlink(missing_ok=True)
    HELD_SENT_PATH.unlink(missing_ok=True)
    events = EventLog(log_path)
    tcp = DelayedTcpServer((address, tcp_port), events)
    tcp_thread = threading.Thread(target=tcp.serve_forever, daemon=True)
    tcp_thread.start()
    with (
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as raw,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp,
    ):
        raw.bind((address, 0))
        raw.setblocking(False)
        udp.bind((address, udp_port))
        udp.setblocking(False)
        ready_path.write_text("ready\n", encoding="ascii")
        pending: list[
            tuple[int, int, str, bytes, tuple[str, int], dict[str, object]]
        ] = []
        ordinal = 0
        while True:
            now_ns = time.monotonic_ns()
            timeout = (
                None
                if not pending
                else max(0.0, (pending[0][0] - now_ns) / 1_000_000_000.0)
            )
            readable, _, _ = select.select([raw, udp], [], [], timeout)
            for stream in readable:
                while True:
                    try:
                        packet, peer = stream.recvfrom(65_535)
                    except BlockingIOError:
                        break
                    received_ns = time.monotonic_ns()
                    if stream is raw:
                        parsed = parse_icmp_request(packet, address)
                        if parsed is None:
                            continue
                        reply, source, identifier, sequence = parsed
                        kind = "icmp"
                        target = (source, 0)
                        event: dict[str, object] = {
                            "transport": kind,
                            "source": source,
                            "identifier": identifier,
                            "sequence": sequence,
                            "payload_bytes": len(reply) - 8,
                        }
                    else:
                        try:
                            sequence = parse_udp_payload(packet)
                        except ValueError:
                            continue
                        kind = "udp"
                        reply = packet
                        target = peer
                        event = {
                            "transport": kind,
                            "source": f"{peer[0]}:{peer[1]}",
                            "sequence": sequence,
                            "payload_bytes": len(reply),
                        }
                    deadline_ns = received_ns + delay_ms * 1_000_000
                    event.update(
                        {
                            "received_monotonic_ns": received_ns,
                            "scheduled_monotonic_ns": deadline_ns,
                            "configured_delay_ms": delay_ms,
                        }
                    )
                    heapq.heappush(
                        pending,
                        (deadline_ns, ordinal, kind, reply, target, event),
                    )
                    ordinal += 1
                    if len(pending) > MAX_PENDING_REPLIES:
                        raise RuntimeError("delayed reply queue exceeded its safety bound")
            now_ns = time.monotonic_ns()
            while pending and pending[0][0] <= now_ns:
                _, _, kind, reply, target, event = heapq.heappop(pending)
                (raw if kind == "icmp" else udp).sendto(reply, target)
                sent_ns = time.monotonic_ns()
                event["sent_monotonic_ns"] = sent_ns
                event["actual_delay_ms"] = round(
                    (sent_ns - int(event["received_monotonic_ns"])) / 1_000_000,
                    6,
                )
                event["pending_after_send"] = len(pending)
                events.write(event)


def ping_measure(executable: str, address: str, count: int, interval: float) -> None:
    command = [
        executable,
        "-n",
        "-c",
        str(count),
        "-i",
        str(interval),
        "-W",
        "3",
        address,
    ]
    started = time.monotonic()
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "LC_ALL": "C"},
        timeout=count * (interval + 3.0) + 5.0,
        check=False,
        text=True,
    )
    elapsed = time.monotonic() - started
    latencies = [
        float(value)
        for value in re.findall(r"time[=<]([0-9]+(?:\.[0-9]+)?) ms", completed.stdout)
    ]
    loss_match = re.search(r"([0-9]+(?:\.[0-9]+)?)% packet loss", completed.stdout)
    loss = None if loss_match is None else float(loss_match.group(1))
    result = measurement_result(
        "icmp", count, latencies, completed.returncode, elapsed, loss
    )
    result.update(
        {
            "argv": command,
            "received_sequences": [
                int(value)
                for value in re.findall(r"icmp_seq=([0-9]+)", completed.stdout)
            ],
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        }
    )
    print(json.dumps(result, sort_keys=True))
    if completed.returncode != 0 or loss != 0.0 or len(latencies) != count:
        raise RuntimeError(f"ICMP loss or execution failure: {result}")


def measurement_result(
    transport: str,
    sent: int,
    latencies: list[float],
    returncode: int,
    elapsed: float,
    loss: float | None = None,
) -> dict[str, object]:
    return {
        "transport": transport,
        "returncode": returncode,
        "wall_seconds": round(elapsed, 6),
        "sent": sent,
        "received": len(latencies),
        "loss_percent": (
            round(100.0 * (sent - len(latencies)) / sent, 6) if loss is None else loss
        ),
        "p50_ms": None if not latencies else percentile(latencies, 50),
        "p95_ms": None if not latencies else percentile(latencies, 95),
        "p99_ms": None if not latencies else percentile(latencies, 99),
        "max_ms": None if not latencies else max(latencies),
    }


def udp_measure(
    address: str, port: int, count: int, interval: float, burst_size: int
) -> None:
    if not 1 <= burst_size <= 16 or count % burst_size != 0:
        raise ValueError("UDP burst size must divide count and be inside 1..16")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.connect((address, port))
        stream.setblocking(False)
        started = time.monotonic()
        sent_at: dict[int, float] = {}
        received_at: dict[int, float] = {}
        unexpected: list[int] = []
        next_sequence = 1
        final_deadline: float | None = None
        while True:
            now = time.monotonic()
            while (
                next_sequence <= count
                and now
                >= started
                + ((next_sequence - 1) // burst_size) * interval * burst_size
            ):
                stream.send(udp_payload(next_sequence))
                sent_at[next_sequence] = time.monotonic()
                next_sequence += 1
                now = time.monotonic()
            if next_sequence > count and final_deadline is None:
                final_deadline = sent_at[count] + 3.0
            if len(received_at) == count or (
                final_deadline is not None and now >= final_deadline
            ):
                break
            wakeup = (
                started
                + ((next_sequence - 1) // burst_size) * interval * burst_size
                if next_sequence <= count
                else final_deadline
            )
            if wakeup is None:
                raise RuntimeError("UDP workload has no wakeup deadline")
            readable, _, _ = select.select([stream], [], [], max(0.0, wakeup - now))
            if not readable:
                continue
            while True:
                try:
                    payload = stream.recv(UDP_PAYLOAD_SIZE + 1)
                except BlockingIOError:
                    break
                sequence = parse_udp_payload(payload)
                if sequence not in sent_at or sequence in received_at:
                    unexpected.append(sequence)
                    continue
                received_at[sequence] = time.monotonic()
        elapsed = time.monotonic() - started
    latencies = [
        round((received_at[index] - sent_at[index]) * 1_000.0, 6)
        for index in sorted(received_at)
    ]
    result = measurement_result("udp", count, latencies, 0, elapsed)
    result.update(
        {
            "interval_seconds": interval,
            "burst_size": burst_size,
            "received_sequences": sorted(received_at),
            "unexpected_sequences": unexpected,
        }
    )
    print(json.dumps(result, sort_keys=True))
    if len(received_at) != count or unexpected:
        raise RuntimeError(f"UDP loss, duplicate, or corruption: {result}")


def tcp_keepalive(
    address: str, port: int, count: int, interval: float, delay_ms: int
) -> None:
    connect_started = time.monotonic()
    with socket.create_connection((address, port), timeout=3.0) as stream:
        connect_ms = (time.monotonic() - connect_started) * 1_000.0
        stream.settimeout(3.0)
        started = time.monotonic()
        sent_at: dict[int, float] = {}
        received_at: dict[int, float] = {}
        buffer = bytearray()
        next_sequence = 1
        deadline: float | None = None
        while True:
            now = time.monotonic()
            while next_sequence <= count and now >= started + (next_sequence - 1) * interval:
                stream.sendall(TCP_REQUEST.pack(MAGIC, next_sequence, delay_ms, 0))
                sent_at[next_sequence] = time.monotonic()
                next_sequence += 1
                now = time.monotonic()
            if next_sequence > count and deadline is None:
                deadline = sent_at[count] + 3.0
            while len(buffer) >= TCP_RESPONSE.size:
                magic, sequence = TCP_RESPONSE.unpack(buffer[: TCP_RESPONSE.size])
                del buffer[: TCP_RESPONSE.size]
                if magic != MAGIC or sequence not in sent_at or sequence in received_at:
                    raise RuntimeError("invalid TCP keep-alive response")
                received_at[sequence] = time.monotonic()
            if len(received_at) == count:
                break
            if deadline is not None and now >= deadline:
                break
            wakeup = (
                started + (next_sequence - 1) * interval
                if next_sequence <= count
                else deadline
            )
            if wakeup is None:
                raise RuntimeError("TCP workload has no wakeup deadline")
            readable, _, _ = select.select([stream], [], [], max(0.0, wakeup - now))
            if readable:
                part = stream.recv(4_096)
                if not part:
                    break
                buffer.extend(part)
        elapsed = time.monotonic() - started
    latencies = [
        round((received_at[index] - sent_at[index]) * 1_000.0, 6)
        for index in sorted(received_at)
    ]
    result = measurement_result("tcp_keepalive", count, latencies, 0, elapsed)
    result.update(
        {
            "connect_ms": round(connect_ms, 6),
            "interval_seconds": interval,
            "received_sequences": sorted(received_at),
        }
    )
    print(json.dumps(result, sort_keys=True))
    if len(received_at) != count:
        raise RuntimeError(f"TCP keep-alive loss: {result}")


def tcp_short_once(address: str, port: int, sequence: int, delay_ms: int) -> float:
    started = time.monotonic()
    with socket.create_connection((address, port), timeout=3.0) as stream:
        stream.settimeout(3.0)
        stream.sendall(TCP_REQUEST.pack(MAGIC, sequence, delay_ms, 1))
        response = receive_exact(stream, TCP_RESPONSE.size)
        if response != TCP_RESPONSE.pack(MAGIC, sequence):
            raise RuntimeError("invalid short-connection TCP response")
    return (time.monotonic() - started) * 1_000.0


def tcp_short(
    address: str, port: int, count: int, concurrency: int, delay_ms: int
) -> None:
    if not 1 <= concurrency <= 16:
        raise ValueError("TCP concurrency is outside 1..16")
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        latencies = list(
            executor.map(
                lambda sequence: tcp_short_once(address, port, sequence, delay_ms),
                range(1, count + 1),
            )
        )
    result = measurement_result(
        "tcp_short", count, latencies, 0, time.monotonic() - started
    )
    result["concurrency"] = concurrency
    print(json.dumps(result, sort_keys=True))


def tcp_held(
    address: str, port: int, delay_ms: int, ready_path: Path, sequence: int
) -> None:
    ready_path.unlink(missing_ok=True)
    with socket.create_connection((address, port), timeout=3.0) as stream:
        stream.settimeout(max(10.0, delay_ms / 1_000.0 + 5.0))
        stream.sendall(TCP_REQUEST.pack(MAGIC, sequence, delay_ms, 2))
        ready_path.write_text("ready\n", encoding="ascii")
        started = time.monotonic()
        try:
            response = receive_exact(stream, TCP_RESPONSE.size)
        except TimeoutError:
            print(
                json.dumps(
                    {
                        "blocked": True,
                        "reason": "generation_change",
                        "elapsed_seconds": round(time.monotonic() - started, 6),
                        "sequence": sequence,
                    },
                    sort_keys=True,
                )
            )
            return
        raise RuntimeError(f"pre-switch TCP flow survived generation change: {response!r}")


def tcp_blocked(address: str, port: int) -> None:
    started = time.monotonic()
    try:
        socket.create_connection((address, port), timeout=2.0).close()
    except TimeoutError:
        print(
            json.dumps(
                {"blocked": True, "elapsed_seconds": time.monotonic() - started},
                sort_keys=True,
            )
        )
        return
    except OSError as error:
        raise RuntimeError(
            f"TCP was actively rejected instead of silently dropped: {error}"
        ) from error
    raise RuntimeError("unmatched application crossed TCP Enforcing")


def udp_blocked(address: str, port: int) -> None:
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.connect((address, port))
        stream.settimeout(2.0)
        stream.send(udp_payload(1))
        try:
            response = stream.recv(UDP_PAYLOAD_SIZE + 1)
        except TimeoutError:
            elapsed = time.monotonic() - started
            if elapsed < 1.5:
                raise RuntimeError("UDP failed before the silent-drop interval")
            print(json.dumps({"blocked": True, "elapsed_seconds": elapsed}, sort_keys=True))
            return
        raise RuntimeError(f"unmatched application received UDP data: {response!r}")


def executable_file_identity(executable: str) -> dict[str, int]:
    metadata = os.stat(executable, follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_ino == 0:
        raise ValueError("application executable is not a regular file")
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": metadata.st_size,
        "ctime_seconds": metadata.st_ctime_ns // 1_000_000_000,
        "ctime_nanoseconds": metadata.st_ctime_ns % 1_000_000_000,
    }


def create_rule(
    name: str,
    protocol: str,
    executable: str,
    uid: int,
    address: str,
    port: int | None,
    arguments: list[str],
) -> None:
    import ipc_client

    if protocol == "icmp" and port is not None:
        raise ValueError("ICMP rule must not have a port")
    if protocol in ("tcp", "udp") and port is None:
        raise ValueError(f"{protocol} rule requires a port")
    if port is not None and not 1 <= port <= 65_535:
        raise ValueError("rule port is outside 1..65535")
    if not 0 <= uid <= 4_294_967_295:
        raise ValueError("rule UID is outside the u32 range")
    command_line = None if not arguments else {"kind": "exact", "arguments": arguments}
    current = ipc_client.status()
    rule = {
        "name": name,
        "direction": "outbound",
        "action": "accept",
        "protocol": protocol,
        "peer_network": f"{address}/32",
        "port": None if port is None else {"start": port, "end": port},
        "interface": None,
        "application": {
            "executable": executable,
            "executable_file": None,
            "command_line": command_line,
            "uid": uid,
            "cgroup": None,
            "metadata_redacted": False,
        },
        "origin": "manual",
        "enabled": True,
    }
    result = ipc_client.control(
        {
            "type": "create_rule",
            "data": {"expected_revision": current["revision"], "rule": rule},
        }
    )
    expected = dict(rule)
    expected["application"] = dict(rule["application"])
    expected["application"]["executable_file"] = executable_file_identity(executable)
    affected = result.get("affected_rule") or {}
    affected_spec = dict(affected.get("spec") or {})
    affected_spec.setdefault("action", "accept")
    if result.get("revision") != current["revision"] + 1:
        raise RuntimeError(f"rule ACK revision mismatch: {result}")
    if affected_spec != expected or not isinstance(affected.get("id"), str):
        raise RuntimeError(f"rule ACK broadened or changed its selector: {result}")
    exact = []
    for candidate in ipc_client.all_rules():
        specification = dict(candidate.get("spec") or {})
        specification.setdefault("action", "accept")
        if candidate.get("id") == affected["id"] and specification == expected:
            exact.append(candidate)
    if len(exact) != 1:
        raise RuntimeError("exact application rule was not persisted exactly once")
    print(json.dumps({"ack": result, "verified": True}, sort_keys=True))


def assert_rule_count(count: int) -> None:
    import ipc_client

    rules = ipc_client.all_rules()
    if len(rules) != count:
        raise RuntimeError(f"expected {count} exact rules, found {len(rules)}")
    if any((rule.get("spec") or {}).get("application") is None for rule in rules):
        raise RuntimeError("network-only rule would mask application attribution")
    print(json.dumps({"rule_count": count, "application_only": True}, sort_keys=True))


def latency_regression(
    baseline: dict[str, object], enforcing: dict[str, object]
) -> tuple[dict[str, float], list[str]]:
    deltas: dict[str, float] = {}
    limits = {
        "p95_ms": MAX_P95_OVERHEAD_MS,
        "p99_ms": MAX_P99_OVERHEAD_MS,
        "max_ms": MAX_TAIL_OVERHEAD_MS,
    }
    violations = []
    for name, limit in limits.items():
        first = baseline.get(name)
        second = enforcing.get(name)
        if (
            isinstance(first, bool)
            or not isinstance(first, (int, float))
            or not math.isfinite(first)
            or isinstance(second, bool)
            or not isinstance(second, (int, float))
            or not math.isfinite(second)
        ):
            raise RuntimeError(f"comparison has invalid {name} values")
        delta = float(second) - float(first)
        deltas[name] = delta
        if delta > limit:
            violations.append(f"{name} overhead {delta:.6f}ms exceeded {limit:.6f}ms")
    return deltas, violations


def compare_measurements(baseline: Path, enforcing: Path) -> None:
    first = json.loads(baseline.read_text(encoding="utf-8"))
    second = json.loads(enforcing.read_text(encoding="utf-8"))
    deltas, violations = latency_regression(first, second)
    summary = {
        "baseline": first,
        "enforcing": second,
        "latency_overhead_ms": {
            name: round(value, 6) for name, value in deltas.items()
        },
        "limits_ms": {
            "p95_ms": MAX_P95_OVERHEAD_MS,
            "p99_ms": MAX_P99_OVERHEAD_MS,
            "max_ms": MAX_TAIL_OVERHEAD_MS,
        },
        "violations": violations,
    }
    print(json.dumps(summary, sort_keys=True))
    if violations:
        raise RuntimeError(f"delayed transport latency regression: {summary}")


def self_test_comparison() -> None:
    baseline = {"p95_ms": 55.0, "p99_ms": 55.0, "max_ms": 55.0}
    boundary = {
        "p95_ms": 55.0 + MAX_P95_OVERHEAD_MS,
        "p99_ms": 55.0 + MAX_P99_OVERHEAD_MS,
        "max_ms": 55.0 + MAX_TAIL_OVERHEAD_MS,
    }
    _, violations = latency_regression(baseline, boundary)
    if violations:
        raise RuntimeError(f"latency boundary was rejected: {violations}")
    for name in boundary:
        over = dict(boundary)
        over[name] += 0.001
        _, violations = latency_regression(baseline, over)
        if len(violations) != 1 or not violations[0].startswith(name):
            raise RuntimeError(f"latency threshold did not reject {name}: {violations}")
    print(json.dumps({"comparison_boundaries_verified": True}, sort_keys=True))


def nfqueue_snapshot(path: Path = Path("/proc/net/netfilter/nfnetlink_queue")) -> None:
    queues: dict[str, dict[str, int]] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        fields = line.split()
        if len(fields) < 9:
            continue
        try:
            values = [int(value, 10) for value in fields[:9]]
        except ValueError:
            continue
        queue_number = values[0]
        if queue_number not in NFQUEUE_NUMBERS:
            continue
        key = str(queue_number)
        if key in queues:
            raise RuntimeError(f"NFQUEUE {queue_number} appears more than once")
        queues[key] = {
            "peer_port_id": values[1],
            "depth": values[2],
            "copy_mode": values[3],
            "copy_range": values[4],
            "kernel_dropped": values[5],
            "user_dropped": values[6],
            "sequence": values[7],
            "reserved": values[8],
        }
    print(json.dumps({"queues": queues}, sort_keys=True))


def assert_nfqueue_health(before_path: Path, after_path: Path, reply_hit: bool) -> None:
    before_document = json.loads(before_path.read_text(encoding="utf-8"))
    after_document = json.loads(after_path.read_text(encoding="utf-8"))
    before = before_document.get("queues")
    after = after_document.get("queues")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise RuntimeError("NFQUEUE snapshot has no queues object")
    expected = {str(number) for number in NFQUEUE_NUMBERS}
    if set(before) != expected or set(after) != expected:
        raise RuntimeError(
            f"NFQUEUE set changed: expected {sorted(expected)}, "
            f"before={sorted(before)}, after={sorted(after)}"
        )
    deltas: dict[str, dict[str, int]] = {}
    for number in NFQUEUE_NUMBERS:
        key = str(number)
        first = before[key]
        second = after[key]
        if not isinstance(first, dict) or not isinstance(second, dict):
            raise RuntimeError(f"NFQUEUE {number} snapshot has an invalid shape")
        for snapshot, label in ((first, "before"), (second, "after")):
            if snapshot.get("copy_mode") != 2 or snapshot.get("copy_range") != 512:
                raise RuntimeError(
                    f"NFQUEUE {number} has unsafe copy settings in {label}: {snapshot}"
                )
            for field in ("depth", "kernel_dropped", "user_dropped", "sequence"):
                value = snapshot.get(field)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise RuntimeError(
                        f"NFQUEUE {number}.{field} is invalid in {label}: {snapshot}"
                    )
        if first["depth"] != 0 or second["depth"] != 0:
            raise RuntimeError(f"NFQUEUE {number} did not drain: {first}, {second}")
        if (
            first["kernel_dropped"] != 0
            or second["kernel_dropped"] != 0
            or first["user_dropped"] != 0
            or second["user_dropped"] != 0
        ):
            raise RuntimeError(f"NFQUEUE {number} reported packet loss: {first}, {second}")
        if second["sequence"] < first["sequence"]:
            raise RuntimeError(f"NFQUEUE {number} sequence went backwards")
        deltas[key] = {"sequence": second["sequence"] - first["sequence"]}
    if deltas["1337"]["sequence"] == 0:
        raise RuntimeError("the Enforcing application queue observed no packets")
    if reply_hit and deltas["1339"]["sequence"] == 0:
        raise RuntimeError("the delayed-reply retry queue was not exercised")
    print(
        json.dumps(
            {
                "before": before,
                "after": after,
                "sequence_deltas": deltas,
                "reply_queue_exercised": deltas["1339"]["sequence"] > 0,
            },
            sort_keys=True,
        )
    )


def assert_held_counters(path: Path) -> None:
    counters = json.loads(path.read_text(encoding="utf-8"))
    dropped_in = counters.get("dropped_in")
    if not isinstance(dropped_in, dict):
        raise RuntimeError("held-flow counter snapshot has no dropped_in object")
    packets = dropped_in.get("packets")
    if isinstance(packets, bool) or not isinstance(packets, int) or packets < 1:
        raise RuntimeError(
            f"pre-switch TCP reply was not denied by fresh Enforcing policy: {counters}"
        )
    print(json.dumps({"dropped_in": dropped_in}, sort_keys=True))


def assert_counter_delta(before_path: Path, after_path: Path) -> None:
    before = json.loads(before_path.read_text(encoding="utf-8"))
    after = json.loads(after_path.read_text(encoding="utf-8"))
    delta: dict[str, dict[str, int]] = {}
    for name in (
        "accepted_in",
        "dropped_in",
        "accepted_out",
        "dropped_out",
        "learned_out",
    ):
        first_counter = before.get(name)
        second_counter = after.get(name)
        if not isinstance(first_counter, dict) or not isinstance(second_counter, dict):
            raise RuntimeError(f"counter snapshot has no {name} object")
        values = {}
        for unit in ("packets", "bytes"):
            first = first_counter.get(unit)
            second = second_counter.get(unit)
            if (
                isinstance(first, bool)
                or not isinstance(first, int)
                or isinstance(second, bool)
                or not isinstance(second, int)
                or second < first
            ):
                raise RuntimeError(f"non-monotonic {name}.{unit} counter")
            values[unit] = second - first
        delta[name] = values
    print(json.dumps(delta, sort_keys=True))
    for name in ("accepted_in", "accepted_out"):
        if delta[name]["packets"] <= 0 or delta[name]["bytes"] <= 0:
            raise RuntimeError(f"allowed window has no positive {name} traffic: {delta}")
    for name in ("dropped_in", "dropped_out", "learned_out"):
        if delta[name]["packets"] != 0 or delta[name]["bytes"] != 0:
            raise RuntimeError(f"unexpected {name} traffic in allowed window: {delta}")


def audit_peer(
    log_path: Path,
    client_address: str,
    expected_icmp: int,
    expected_udp: int,
    expected_tcp: int,
    expected_delay_ms: int,
) -> None:
    events = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    icmp = [event for event in events if event.get("transport") == "icmp"]
    udp = [event for event in events if event.get("transport") == "udp"]
    tcp_received = [
        event
        for event in events
        if event.get("transport") == "tcp" and event.get("phase") == "received"
    ]
    tcp_sent = [
        event
        for event in events
        if event.get("transport") == "tcp" and event.get("phase") == "sent"
    ]
    counts = {
        "icmp": len(icmp),
        "udp": len(udp),
        "tcp_received": len(tcp_received),
        "tcp_sent": len(tcp_sent),
    }
    expected = {
        "icmp": expected_icmp,
        "udp": expected_udp,
        "tcp_received": expected_tcp,
        "tcp_sent": expected_tcp,
    }
    wrong_source = [
        event
        for event in events
        if str(event.get("source", "")).split(":", 1)[0] != client_address
    ]
    delayed_events = [
        event
        for event in events
        if "actual_delay_ms" in event and event.get("sequence") != 9_001
    ]
    delayed = [
        float(event["actual_delay_ms"])
        for event in delayed_events
    ]
    held_delays = [
        float(event["actual_delay_ms"])
        for event in tcp_sent
        if event.get("sequence") == 9_001
    ]
    held_gate_waits = [
        float(event["gate_wait_ms"])
        for event in tcp_sent
        if event.get("sequence") == 9_001 and event.get("gate_wait_ms") is not None
    ]
    summary = {
        "actual": counts,
        "expected": expected,
        "wrong_source_count": len(wrong_source),
        "normal_delay_samples": len(delayed),
        "normal_delay_min_ms": None if not delayed else min(delayed),
        "normal_delay_max_ms": None if not delayed else max(delayed),
        "held_delay_ms": held_delays,
        "held_gate_wait_ms": held_gate_waits,
    }
    print(json.dumps(summary, sort_keys=True))
    if counts != expected or wrong_source:
        raise RuntimeError(f"peer event inventory mismatch: {summary}")
    expected_delay_samples = expected_icmp + expected_udp + expected_tcp - 1
    wrong_configured_delay = [
        event
        for event in delayed_events
        if event.get("configured_delay_ms") != expected_delay_ms
    ]
    if (
        len(delayed) != expected_delay_samples
        or wrong_configured_delay
        or min(delayed) < expected_delay_ms - 1.0
        or max(delayed) > 200.0
    ):
        raise RuntimeError(f"peer became a delayed-response bottleneck: {summary}")
    if len(held_delays) != 1 or not 900.0 <= held_delays[0] <= 1_500.0:
        raise RuntimeError(f"held TCP response timing is invalid: {summary}")
    if len(held_gate_waits) != 1 or not 0.0 < held_gate_waits[0] <= 10_000.0:
        raise RuntimeError(f"held TCP release barrier was not exercised: {summary}")


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    server = commands.add_parser("serve")
    server.add_argument("address", type=checked_ipv4)
    server.add_argument("udp_port", type=checked_port)
    server.add_argument("tcp_port", type=checked_port)
    server.add_argument("delay_ms", type=checked_delay)
    server.add_argument("log", type=Path)
    server.add_argument("ready", type=Path)
    ping = commands.add_parser("ping-measure")
    ping.add_argument("executable")
    ping.add_argument("address", type=checked_ipv4)
    ping.add_argument("count", type=checked_count)
    ping.add_argument("interval", type=checked_interval)
    udp = commands.add_parser("udp-measure")
    udp.add_argument("address", type=checked_ipv4)
    udp.add_argument("port", type=checked_port)
    udp.add_argument("count", type=checked_count)
    udp.add_argument("interval", type=checked_interval)
    udp.add_argument("burst_size", type=int)
    keepalive = commands.add_parser("tcp-keepalive")
    keepalive.add_argument("address", type=checked_ipv4)
    keepalive.add_argument("port", type=checked_port)
    keepalive.add_argument("count", type=checked_count)
    keepalive.add_argument("interval", type=checked_interval)
    keepalive.add_argument("delay_ms", type=checked_delay)
    short = commands.add_parser("tcp-short")
    short.add_argument("address", type=checked_ipv4)
    short.add_argument("port", type=checked_port)
    short.add_argument("count", type=checked_count)
    short.add_argument("concurrency", type=int)
    short.add_argument("delay_ms", type=checked_delay)
    held = commands.add_parser("tcp-held")
    held.add_argument("address", type=checked_ipv4)
    held.add_argument("port", type=checked_port)
    held.add_argument("delay_ms", type=checked_delay)
    held.add_argument("ready", type=Path)
    held.add_argument("sequence", type=int)
    tcp_denied = commands.add_parser("tcp-blocked")
    tcp_denied.add_argument("address", type=checked_ipv4)
    tcp_denied.add_argument("port", type=checked_port)
    udp_denied = commands.add_parser("udp-blocked")
    udp_denied.add_argument("address", type=checked_ipv4)
    udp_denied.add_argument("port", type=checked_port)
    rule = commands.add_parser("create-rule")
    rule.add_argument("name")
    rule.add_argument("protocol", choices=("icmp", "tcp", "udp"))
    rule.add_argument("executable")
    rule.add_argument("uid", type=int)
    rule.add_argument("address", type=checked_ipv4)
    rule.add_argument("port", type=int)
    rule.add_argument("arguments", nargs=argparse.REMAINDER)
    count = commands.add_parser("assert-rule-count")
    count.add_argument("count", type=int)
    comparison = commands.add_parser("compare")
    comparison.add_argument("baseline", type=Path)
    comparison.add_argument("enforcing", type=Path)
    commands.add_parser("self-test-comparison")
    commands.add_parser("nfqueue-snapshot")
    queue_health = commands.add_parser("assert-nfqueue-health")
    queue_health.add_argument("before", type=Path)
    queue_health.add_argument("after", type=Path)
    queue_health.add_argument("--require-reply-hit", action="store_true")
    held_counters = commands.add_parser("assert-held-counters")
    held_counters.add_argument("snapshot", type=Path)
    counter_delta = commands.add_parser("assert-counter-delta")
    counter_delta.add_argument("before", type=Path)
    counter_delta.add_argument("after", type=Path)
    audit = commands.add_parser("audit-peer")
    audit.add_argument("log", type=Path)
    audit.add_argument("client_address", type=checked_ipv4)
    audit.add_argument("expected_icmp", type=int)
    audit.add_argument("expected_udp", type=int)
    audit.add_argument("expected_tcp", type=int)
    audit.add_argument("expected_delay_ms", type=checked_delay)
    arguments = parser.parse_args()
    if arguments.command == "serve":
        serve(
            arguments.address,
            arguments.udp_port,
            arguments.tcp_port,
            arguments.delay_ms,
            arguments.log,
            arguments.ready,
        )
    elif arguments.command == "ping-measure":
        ping_measure(
            arguments.executable, arguments.address, arguments.count, arguments.interval
        )
    elif arguments.command == "udp-measure":
        udp_measure(
            arguments.address,
            arguments.port,
            arguments.count,
            arguments.interval,
            arguments.burst_size,
        )
    elif arguments.command == "tcp-keepalive":
        tcp_keepalive(
            arguments.address,
            arguments.port,
            arguments.count,
            arguments.interval,
            arguments.delay_ms,
        )
    elif arguments.command == "tcp-short":
        tcp_short(
            arguments.address,
            arguments.port,
            arguments.count,
            arguments.concurrency,
            arguments.delay_ms,
        )
    elif arguments.command == "tcp-held":
        tcp_held(
            arguments.address,
            arguments.port,
            arguments.delay_ms,
            arguments.ready,
            arguments.sequence,
        )
    elif arguments.command == "tcp-blocked":
        tcp_blocked(arguments.address, arguments.port)
    elif arguments.command == "udp-blocked":
        udp_blocked(arguments.address, arguments.port)
    elif arguments.command == "create-rule":
        create_rule(
            arguments.name,
            arguments.protocol,
            arguments.executable,
            arguments.uid,
            arguments.address,
            None if arguments.port == 0 else arguments.port,
            arguments.arguments,
        )
    elif arguments.command == "assert-rule-count":
        assert_rule_count(arguments.count)
    elif arguments.command == "compare":
        compare_measurements(arguments.baseline, arguments.enforcing)
    elif arguments.command == "self-test-comparison":
        self_test_comparison()
    elif arguments.command == "nfqueue-snapshot":
        nfqueue_snapshot()
    elif arguments.command == "assert-nfqueue-health":
        assert_nfqueue_health(
            arguments.before, arguments.after, arguments.require_reply_hit
        )
    elif arguments.command == "assert-held-counters":
        assert_held_counters(arguments.snapshot)
    elif arguments.command == "assert-counter-delta":
        assert_counter_delta(arguments.before, arguments.after)
    elif arguments.command == "audit-peer":
        audit_peer(
            arguments.log,
            arguments.client_address,
            arguments.expected_icmp,
            arguments.expected_udp,
            arguments.expected_tcp,
            arguments.expected_delay_ms,
        )


if __name__ == "__main__":
    try:
        main()
    except (
        OSError,
        RuntimeError,
        ValueError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"delayed transport E2E: {error}", file=sys.stderr)
        raise SystemExit(1)
