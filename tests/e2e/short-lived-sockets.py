#!/usr/bin/env python3
"""Real-socket short-process and ICMP workloads for targeted E2E tests."""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time


SOCKET_TIMEOUT_SECONDS = 5.0
MAX_FRAME_BYTES = 4096
MAX_CHILDREN = 64


def checked_port(text: str) -> int:
    port = int(text, 10)
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port is outside 1..65535")
    return port


class EventLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.Lock()

    def write(self, event: dict[str, object]) -> None:
        encoded = json.dumps(event, sort_keys=True, separators=(",", ":"))
        with self.lock, self.path.open("a", encoding="utf-8") as output:
            output.write(encoded + "\n")
            output.flush()


def receive_exact(stream: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = stream.recv(size - len(result))
        if not chunk:
            raise ConnectionError("TCP peer closed a framed exchange")
        result.extend(chunk)
    return bytes(result)


class TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(SOCKET_TIMEOUT_SECONDS)
        size = struct.unpack("!I", receive_exact(self.request, 4))[0]
        if size == 0 or size > MAX_FRAME_BYTES:
            raise ValueError("invalid TCP frame length")
        payload = receive_exact(self.request, size)
        self.request.sendall(struct.pack("!I", size) + payload)
        server = self.server
        if not isinstance(server, TcpServer):
            raise RuntimeError("unexpected TCP server")
        server.events.write(
            {
                "protocol": "tcp",
                "profile": payload.decode("ascii"),
                "source": f"{self.client_address[0]}:{self.client_address[1]}",
            }
        )


class TcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address: tuple[str, int], events: EventLog) -> None:
        self.events = events
        super().__init__(address, TcpHandler)


def dns_question_end(packet: bytes) -> int:
    cursor = 12
    while True:
        if cursor >= len(packet):
            raise ValueError("truncated DNS question")
        label_size = packet[cursor]
        cursor += 1
        if label_size == 0:
            break
        if label_size > 63 or cursor + label_size > len(packet):
            raise ValueError("invalid DNS label")
        cursor += label_size
    if cursor + 4 > len(packet):
        raise ValueError("truncated DNS type/class")
    return cursor + 4


def dns_name(packet: bytes) -> str:
    labels = []
    cursor = 12
    while packet[cursor] != 0:
        size = packet[cursor]
        cursor += 1
        labels.append(packet[cursor : cursor + size].decode("ascii"))
        cursor += size
    return ".".join(labels)


class DnsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        request, transport = self.request
        server = self.server
        if not isinstance(server, DnsServer):
            raise RuntimeError("unexpected DNS server")
        end = dns_question_end(request)
        identifier, flags, questions = struct.unpack("!HHH", request[:6])
        if flags & 0x8000 or questions != 1:
            raise ValueError("unexpected DNS query")
        response = (
            struct.pack("!HHHHHH", identifier, 0x8180, 1, 1, 0, 0)
            + request[12:end]
            + b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 1, 0, 4)
            + socket.inet_aton(server.answer)
        )
        transport.sendto(response, self.client_address)
        server.events.write(
            {
                "protocol": "udp-dns",
                "profile": dns_name(request),
                "source": f"{self.client_address[0]}:{self.client_address[1]}",
            }
        )


class DnsServer(socketserver.UDPServer):
    allow_reuse_address = True

    def __init__(
        self, address: tuple[str, int], answer: str, events: EventLog
    ) -> None:
        self.answer = answer
        self.events = events
        super().__init__(address, DnsHandler)


class FireHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        payload, _transport = self.request
        server = self.server
        if not isinstance(server, FireServer):
            raise RuntimeError("unexpected fire-and-forget server")
        server.events.write(
            {
                "protocol": "udp-fire-and-forget",
                "profile": payload.decode("ascii"),
                "source": f"{self.client_address[0]}:{self.client_address[1]}",
            }
        )


class FireServer(socketserver.UDPServer):
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], events: EventLog) -> None:
        self.events = events
        super().__init__(address, FireHandler)


def serve(
    answer: str, tcp_port: int, fire_port: int, log_path: Path, ready_path: Path
) -> None:
    socket.inet_aton(answer)
    log_path.unlink(missing_ok=True)
    ready_path.unlink(missing_ok=True)
    events = EventLog(log_path)
    servers = [
        TcpServer((answer, tcp_port), events),
        DnsServer((answer, 53), answer, events),
        FireServer((answer, fire_port), events),
    ]
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in servers
    ]
    for thread in threads:
        thread.start()
    ready_path.write_text("ready\n", encoding="ascii")
    for thread in threads:
        thread.join()


def tcp_once(address: str, port: int, profile: str) -> None:
    payload = profile.encode("ascii")
    frame = struct.pack("!I", len(payload)) + payload
    with socket.create_connection((address, port), timeout=SOCKET_TIMEOUT_SECONDS) as stream:
        stream.settimeout(SOCKET_TIMEOUT_SECONDS)
        stream.sendall(frame)
        if receive_exact(stream, len(frame)) != frame:
            raise RuntimeError("TCP echo mismatch")


def dns_tcp_once(host: str, port: int, profile: str) -> None:
    addresses = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    if not addresses:
        raise RuntimeError("DNS resolution returned no IPv4 address")
    tcp_once(addresses[0][4][0], port, profile)


def fire_and_forget(address: str, port: int, profile: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
        datagram.connect((address, port))
        datagram.send(profile.encode("ascii"))


def held_tcp(address: str, port: int, ready: Path, release: Path) -> None:
    ready.unlink(missing_ok=True)
    release.unlink(missing_ok=True)
    payload = b"held-control"
    frame = struct.pack("!I", len(payload)) + payload
    with socket.create_connection((address, port), timeout=SOCKET_TIMEOUT_SECONDS) as stream:
        stream.settimeout(SOCKET_TIMEOUT_SECONDS)
        stream.sendall(frame)
        if receive_exact(stream, len(frame)) != frame:
            raise RuntimeError("held TCP echo mismatch")
        ready.write_text("ready\n", encoding="ascii")
        deadline = time.monotonic() + 30.0
        while not release.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("held TCP control was not released")
            time.sleep(0.05)


def spawn_children(command: list[str], count: int, concurrency: int) -> None:
    if not 1 <= count <= MAX_CHILDREN or not 1 <= concurrency <= count:
        raise ValueError("child workload dimensions are invalid")

    def invoke(_index: int) -> float:
        started = time.monotonic()
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"short child exited {completed.returncode}: "
                f"{completed.stderr.decode(errors='replace')}"
            )
        return (time.monotonic() - started) * 1000.0

    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        durations = list(executor.map(invoke, range(count)))
    ordered = sorted(durations)
    print(
        json.dumps(
            {
                "argv": command,
                "children": count,
                "concurrency": concurrency,
                "elapsed_ms": round((time.monotonic() - started) * 1000.0, 3),
                "child_p50_ms": round(percentile(ordered, 50), 3),
                "child_p95_ms": round(percentile(ordered, 95), 3),
                "child_max_ms": round(max(ordered), 3),
            },
            sort_keys=True,
        )
    )


def percentile(values: list[float], percentage: int) -> float:
    if not values:
        raise ValueError("cannot calculate a percentile of no values")
    index = max(0, math.ceil(len(values) * percentage / 100.0) - 1)
    return sorted(values)[index]


def executable_file_identity(executable: str) -> dict[str, int]:
    stat = os.stat(executable, follow_symlinks=False)
    return {
        "device": stat.st_dev,
        "inode": stat.st_ino,
        "size": stat.st_size,
        "ctime_seconds": stat.st_ctime_ns // 1_000_000_000,
        "ctime_nanoseconds": stat.st_ctime_ns % 1_000_000_000,
    }


def unified_cgroup() -> str:
    cgroups = [
        line.split("::", 1)[1]
        for line in Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
        if "::" in line
    ]
    if len(cgroups) != 1 or not cgroups[0].startswith("/"):
        raise RuntimeError("fixture requires one unified cgroup-v2 path")
    return cgroups[0]


def exact_application_rule(
    rule: dict,
    executable: str,
    uid: int,
    arguments: list[str],
    address: str,
    port: int | None,
    protocol: str,
) -> bool:
    specification = rule.get("spec", {})
    application = specification.get("application") or {}
    command_line = application.get("command_line") or {}
    executable_file = application.get("executable_file") or {}
    port_range = specification.get("port")
    expected_port = None if port is None else {"start": port, "end": port}
    return (
        specification.get("origin") == "learned"
        and specification.get("enabled") is True
        and specification.get("action", "accept") == "accept"
        and specification.get("direction") == "outbound"
        and specification.get("protocol") == protocol
        and specification.get("peer_network") == f"{address}/32"
        and port_range == expected_port
        and specification.get("interface") == "eth0"
        and application.get("executable") == executable
        and application.get("uid") == uid
        and application.get("metadata_redacted") is False
        and command_line.get("kind") == "exact"
        and command_line.get("arguments") == arguments
        and application.get("cgroup") == unified_cgroup()
        and executable_file == executable_file_identity(executable)
    )


def endpoint_rules(
    rules: list[dict], address: str, port: int, protocol: str
) -> list[dict]:
    result = []
    for rule in rules:
        specification = rule.get("spec", {})
        port_range = specification.get("port") or {}
        try:
            network = ipaddress.ip_network(specification.get("peer_network"), strict=False)
            contains_address = ipaddress.ip_address(address) in network
        except (TypeError, ValueError):
            contains_address = False
        if (
            specification.get("origin") == "learned"
            and specification.get("protocol") == protocol
            and contains_address
            and port_range.get("start") == port
            and port_range.get("end") == port
        ):
            result.append(rule)
    return result


def held_expectation(address: str, tcp_port: int) -> tuple[str, list[str], str, int, str]:
    executable = "/tmp/short-held"
    return (
        executable,
        [
            executable,
            "/opt/short-lived-sockets.py",
            "held-tcp",
            address,
            str(tcp_port),
            "/tmp/held.ready",
            "/tmp/held.release",
        ],
        address,
        tcp_port,
        "tcp",
    )


def audit_held_rule(address: str, tcp_port: int, uid: int) -> None:
    import ipc_client

    rules = ipc_client.all_rules()
    expected = held_expectation(address, tcp_port)
    executable, argv, endpoint, port, protocol = expected
    learned = endpoint_rules(rules, address, tcp_port, "tcp")
    valid = [
        rule
        for rule in learned
        if exact_application_rule(
            rule, executable, uid, argv, endpoint, port, protocol
        )
    ]
    invalid = [
        (rule.get("spec", {}).get("application") or {}).get("executable")
        for rule in learned
        if not exact_application_rule(
            rule, executable, uid, argv, endpoint, port, protocol
        )
    ]
    result = {"valid_rule_count": len(valid), "unexpected_bindings": invalid}
    print(json.dumps(result, sort_keys=True))
    if len(valid) != 1 or invalid:
        raise SystemExit(1)


def audit_rules(address: str, tcp_port: int, fire_port: int, uid: int) -> None:
    import ipc_client

    helper = "/opt/short-lived-sockets.py"
    expected = {
        "tcp_a": (
            "/tmp/short-tcp-a",
            ["/tmp/short-tcp-a", helper, "tcp-once", address, str(tcp_port), "tcp-a"],
            address,
            tcp_port,
            "tcp",
        ),
        "tcp_b": (
            "/tmp/short-tcp-b",
            ["/tmp/short-tcp-b", helper, "tcp-once", address, str(tcp_port), "tcp-b"],
            address,
            tcp_port,
            "tcp",
        ),
        "dns_a_udp": (
            "/tmp/short-dns-a",
            [
                "/tmp/short-dns-a",
                helper,
                "dns-tcp-once",
                "dns-a.e2e.openshield.test",
                str(tcp_port),
                "dns-a",
            ],
            address,
            53,
            "udp",
        ),
        "dns_a_tcp": (
            "/tmp/short-dns-a",
            [
                "/tmp/short-dns-a",
                helper,
                "dns-tcp-once",
                "dns-a.e2e.openshield.test",
                str(tcp_port),
                "dns-a",
            ],
            address,
            tcp_port,
            "tcp",
        ),
        "dns_b_udp": (
            "/tmp/short-dns-b",
            [
                "/tmp/short-dns-b",
                helper,
                "dns-tcp-once",
                "dns-b.e2e.openshield.test",
                str(tcp_port),
                "dns-b",
            ],
            address,
            53,
            "udp",
        ),
        "dns_b_tcp": (
            "/tmp/short-dns-b",
            [
                "/tmp/short-dns-b",
                helper,
                "dns-tcp-once",
                "dns-b.e2e.openshield.test",
                str(tcp_port),
                "dns-b",
            ],
            address,
            tcp_port,
            "tcp",
        ),
    }
    rules = ipc_client.all_rules()
    counts = {
        name: sum(
            exact_application_rule(rule, executable, uid, argv, endpoint, port, protocol)
            for rule in rules
        )
        for name, (executable, argv, endpoint, port, protocol) in expected.items()
    }
    held = held_expectation(address, tcp_port)
    held_count = sum(
        exact_application_rule(rule, held[0], uid, held[1], held[2], held[3], held[4])
        for rule in rules
    )
    tcp_expectations = [held] + [
        value for value in expected.values() if value[4] == "tcp"
    ]
    dns_expectations = [value for value in expected.values() if value[4] == "udp"]
    unexpected_tcp_bindings = [
        (rule.get("spec", {}).get("application") or {}).get("executable")
        for rule in endpoint_rules(rules, address, tcp_port, "tcp")
        if not any(
            exact_application_rule(rule, executable, uid, argv, endpoint, port, protocol)
            for executable, argv, endpoint, port, protocol in tcp_expectations
        )
    ]
    unexpected_dns_bindings = [
        (rule.get("spec", {}).get("application") or {}).get("executable")
        for rule in endpoint_rules(rules, address, 53, "udp")
        if not any(
            exact_application_rule(rule, executable, uid, argv, endpoint, port, protocol)
            for executable, argv, endpoint, port, protocol in dns_expectations
        )
    ]
    fire_executable = "/tmp/short-udp-fire"
    fire_argv = [
        fire_executable,
        helper,
        "fire-and-forget",
        address,
        str(fire_port),
        "fire",
    ]
    fire_endpoint_rules = endpoint_rules(rules, address, fire_port, "udp")
    fire_valid = sum(
        exact_application_rule(
            rule, fire_executable, uid, fire_argv, address, fire_port, "udp"
        )
        for rule in fire_endpoint_rules
    )
    false_fire_bindings = [
        (rule.get("spec", {}).get("application") or {}).get("executable")
        for rule in fire_endpoint_rules
        if not exact_application_rule(
            rule, fire_executable, uid, fire_argv, address, fire_port, "udp"
        )
    ]
    missing = sorted(name for name, count in counts.items() if count == 0)
    duplicates = sorted(name for name, count in counts.items() if count > 1)
    result = {
        "required_rule_counts": counts,
        "held_rule_count": held_count,
        "missing_required": missing,
        "duplicate_required": duplicates,
        "unexpected_tcp_bindings": unexpected_tcp_bindings,
        "unexpected_dns_bindings": unexpected_dns_bindings,
        "fire_and_forget": {
            "learned": fire_valid > 0,
            "valid_rule_count": fire_valid,
            "false_bindings": false_fire_bindings,
        },
    }
    print(json.dumps(result, sort_keys=True))
    if (
        held_count != 1
        or missing
        or duplicates
        or unexpected_tcp_bindings
        or unexpected_dns_bindings
        or false_fire_bindings
        or fire_valid > 1
    ):
        raise SystemExit(1)


def audit_peer(log_path: Path, client_address: str) -> None:
    events = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]
    expected = {
        ("tcp", "held-control"): 1,
        ("tcp", "tcp-a"): 8,
        ("tcp", "tcp-b"): 8,
        ("tcp", "dns-a"): 8,
        ("tcp", "dns-b"): 8,
        ("udp-dns", "dns-a.e2e.openshield.test"): 8,
        ("udp-dns", "dns-b.e2e.openshield.test"): 8,
        ("udp-fire-and-forget", "fire"): 16,
    }
    counts = {
        f"{protocol}:{profile}": sum(
            event.get("protocol") == protocol and event.get("profile") == profile
            for event in events
        )
        for (protocol, profile) in expected
    }
    mismatches = {
        f"{protocol}:{profile}": {"expected": count, "actual": counts[f"{protocol}:{profile}"]}
        for (protocol, profile), count in expected.items()
        if counts[f"{protocol}:{profile}"] != count
    }
    expected_keys = set(expected)
    unexpected = [
        event
        for event in events
        if (event.get("protocol"), event.get("profile")) not in expected_keys
        or str(event.get("source", "")).rsplit(":", 1)[0] != client_address
    ]
    print(
        json.dumps(
            {"counts": counts, "mismatches": mismatches, "unexpected": unexpected},
            sort_keys=True,
        )
    )
    if mismatches or unexpected or len(events) != sum(expected.values()):
        raise SystemExit(1)


def create_icmp_rule(executable: str, uid: int, address: str) -> None:
    import ipc_client

    current = ipc_client.status()
    rule = {
        "name": "short-lived E2E application ICMP",
        "direction": "outbound",
        "action": "accept",
        "protocol": "icmp",
        "peer_network": f"{address}/32",
        "port": None,
        "interface": None,
        "application": {
            "executable": executable,
            "executable_file": None,
            "command_line": None,
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
    # Accept is the protocol's omitted wire default for backward compatibility.
    affected_spec.setdefault("action", "accept")
    if result.get("revision") != current["revision"] + 1:
        raise RuntimeError(f"ICMP rule ACK revision mismatch: {result}")
    if affected_spec != expected or not isinstance(affected.get("id"), str):
        raise RuntimeError(f"ICMP rule ACK broadened or changed its selector: {result}")
    rules = ipc_client.all_rules()
    stored = []
    for candidate in rules:
        candidate_spec = dict(candidate.get("spec") or {})
        candidate_spec.setdefault("action", "accept")
        if candidate.get("id") == affected["id"] and candidate_spec == expected:
            stored.append(candidate)
    if len(stored) != 1:
        raise RuntimeError("exact ICMP rule was not persisted exactly once")
    competing = []
    for candidate in rules:
        specification = candidate.get("spec") or {}
        if candidate.get("id") == affected["id"] or not specification.get("enabled"):
            continue
        if specification.get("direction") != "outbound":
            continue
        if specification.get("action", "accept") != "accept":
            continue
        if specification.get("protocol") not in ("any", "icmp"):
            continue
        peer_network = specification.get("peer_network")
        if peer_network is None:
            covers_peer = True
        else:
            try:
                network = ipaddress.ip_network(peer_network, strict=False)
                covers_peer = ipaddress.ip_address(address) in network
            except (TypeError, ValueError):
                covers_peer = False
        if covers_peer:
            competing.append(candidate.get("id"))
    if competing:
        raise RuntimeError(f"competing outbound ICMP permits exist: {competing}")
    print(json.dumps({"ack": result, "verified": True}, sort_keys=True))


def measure_ping(executable: str, address: str, count: int) -> None:
    command = [executable, "-n", "-c", str(count), "-i", "0.2", "-W", "3", address]
    started = time.monotonic()
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "LC_ALL": "C"},
        timeout=count * 4 + 5,
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
    result = {
        "argv": command,
        "returncode": completed.returncode,
        "wall_seconds": round(elapsed, 6),
        "sent": count,
        "received": len(latencies),
        "loss_percent": loss,
        "first_ms": None if not latencies else latencies[0],
        "p50_ms": None if not latencies else percentile(latencies, 50),
        "p95_ms": None if not latencies else percentile(latencies, 95),
        "p99_ms": None if not latencies else percentile(latencies, 99),
        "max_ms": None if not latencies else max(latencies),
        "stderr": completed.stderr.strip(),
    }
    print(json.dumps(result, sort_keys=True))
    if completed.returncode != 0 or loss != 0.0 or len(latencies) != count:
        raise RuntimeError(f"ping loss or execution failure: {result}")


def compare_ping(baseline_path: Path, enforcing_path: Path) -> None:
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    enforcing = json.loads(enforcing_path.read_text(encoding="utf-8"))
    comparison = {
        "baseline": baseline,
        "enforcing": enforcing,
        "wall_delta_seconds": round(
            enforcing["wall_seconds"] - baseline["wall_seconds"], 6
        ),
        "p95_delta_ms": round(enforcing["p95_ms"] - baseline["p95_ms"], 6),
        "p99_delta_ms": round(enforcing["p99_ms"] - baseline["p99_ms"], 6),
    }
    print(json.dumps(comparison, sort_keys=True))


def capture_counters() -> None:
    import ipc_client

    revision = ipc_client.status()["revision"]
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(5.0)
        stream.connect(ipc_client.OBSERVE)
        ipc_client.send_request(
            stream,
            {
                "type": "read",
                "data": {
                    "type": "subscribe",
                    "data": {"after_revision": revision},
                },
            },
        )
        deadline = time.monotonic() + 5.0
        first_counter_event_time = None
        while time.monotonic() < deadline:
            response = ipc_client.receive_response(stream)
            if response.get("type") != "event":
                raise RuntimeError(f"unexpected subscription response: {response}")
            event = response.get("data") or {}
            kind = event.get("kind") or {}
            if kind.get("type") != "counters_updated":
                continue
            counters = (kind.get("data") or {}).get("counters")
            required = (
                "accepted_in",
                "dropped_in",
                "accepted_out",
                "dropped_out",
                "learned_out",
            )
            if not isinstance(counters, dict) or any(
                not isinstance(counters.get(name), dict) for name in required
            ):
                raise RuntimeError(f"malformed counter event: {response}")
            occurred_at = event.get("occurred_at")
            if not isinstance(occurred_at, str):
                raise RuntimeError(f"counter event has no timestamp: {response}")
            if first_counter_event_time is None:
                # EventBus may replay its cached latest counter sample at
                # subscription time. A distinct second timestamp proves that
                # at least one backend poll happened after this call began.
                first_counter_event_time = occurred_at
                continue
            if occurred_at == first_counter_event_time:
                continue
            print(json.dumps(counters, sort_keys=True))
            return
    raise TimeoutError("firewall counter event did not arrive")


def compare_counter_delta(before_path: Path, after_path: Path) -> None:
    before = json.loads(before_path.read_text(encoding="utf-8"))
    after = json.loads(after_path.read_text(encoding="utf-8"))
    delta = {}
    for name in (
        "accepted_in",
        "dropped_in",
        "accepted_out",
        "dropped_out",
        "learned_out",
    ):
        before_counter = before.get(name) or {}
        after_counter = after.get(name) or {}
        values = {}
        for unit in ("packets", "bytes"):
            first = before_counter.get(unit)
            second = after_counter.get(unit)
            if not isinstance(first, int) or not isinstance(second, int) or second < first:
                raise RuntimeError(f"non-monotonic {name}.{unit} counter")
            values[unit] = second - first
        delta[name] = values
    print(json.dumps(delta, sort_keys=True))
    if delta["dropped_in"]["packets"] or delta["dropped_out"]["packets"]:
        raise RuntimeError(f"allowed ping encountered firewall drops: {delta}")


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
        raise RuntimeError(f"unexpected TCP failure instead of silent drop: {error}") from error
    raise RuntimeError("unknown executable crossed application-only Enforcing")


def dns_blocked(host: str, port: int) -> None:
    started = time.monotonic()
    try:
        socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as error:
        elapsed = time.monotonic() - started
        if elapsed < 0.5:
            raise RuntimeError(f"DNS failed immediately instead of a silent drop: {error}")
        print(json.dumps({"blocked": True, "elapsed_seconds": elapsed}, sort_keys=True))
        return
    raise RuntimeError("unknown executable resolved DNS through application-only Enforcing")


def ping_blocked(executable: str, address: str) -> None:
    started = time.monotonic()
    completed = subprocess.run(
        [executable, "-n", "-c", "1", "-W", "2", address],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "LC_ALL": "C"},
        timeout=5,
        check=False,
        text=True,
    )
    elapsed = time.monotonic() - started
    diagnostic = f"{completed.stdout}\n{completed.stderr}"
    active_error = re.search(
        r"Destination .* Unreachable|\+[0-9]+ errors?", diagnostic, re.IGNORECASE
    )
    if (
        completed.returncode != 1
        or "100% packet loss" not in completed.stdout
        or elapsed < 1.5
        or active_error is not None
    ):
        raise RuntimeError(
            "unknown ping did not encounter a silent policy drop: "
            f"returncode={completed.returncode}, elapsed={elapsed:.3f}, "
            f"stdout={completed.stdout!r}, "
            f"stderr={completed.stderr!r}"
        )
    print(
        json.dumps(
            {
                "blocked": True,
                "elapsed_seconds": round(elapsed, 6),
                "returncode": completed.returncode,
            },
            sort_keys=True,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    server = commands.add_parser("serve")
    server.add_argument("answer")
    server.add_argument("tcp_port", type=checked_port)
    server.add_argument("fire_port", type=checked_port)
    server.add_argument("log", type=Path)
    server.add_argument("ready", type=Path)
    tcp = commands.add_parser("tcp-once")
    tcp.add_argument("address")
    tcp.add_argument("port", type=checked_port)
    tcp.add_argument("profile")
    dns = commands.add_parser("dns-tcp-once")
    dns.add_argument("host")
    dns.add_argument("port", type=checked_port)
    dns.add_argument("profile")
    fire = commands.add_parser("fire-and-forget")
    fire.add_argument("address")
    fire.add_argument("port", type=checked_port)
    fire.add_argument("profile")
    held = commands.add_parser("held-tcp")
    held.add_argument("address")
    held.add_argument("port", type=checked_port)
    held.add_argument("ready", type=Path)
    held.add_argument("release", type=Path)
    spawn = commands.add_parser("spawn")
    spawn.add_argument("count", type=int)
    spawn.add_argument("concurrency", type=int)
    spawn.add_argument("child", nargs=argparse.REMAINDER)
    audit = commands.add_parser("audit-rules")
    audit.add_argument("address")
    audit.add_argument("tcp_port", type=checked_port)
    audit.add_argument("fire_port", type=checked_port)
    audit.add_argument("uid", type=int)
    held_audit = commands.add_parser("audit-held-rule")
    held_audit.add_argument("address")
    held_audit.add_argument("tcp_port", type=checked_port)
    held_audit.add_argument("uid", type=int)
    peer_audit = commands.add_parser("audit-peer")
    peer_audit.add_argument("log", type=Path)
    peer_audit.add_argument("client_address")
    icmp = commands.add_parser("create-icmp-rule")
    icmp.add_argument("executable")
    icmp.add_argument("uid", type=int)
    icmp.add_argument("address")
    ping = commands.add_parser("ping-measure")
    ping.add_argument("executable")
    ping.add_argument("address")
    ping.add_argument("count", type=int)
    comparison = commands.add_parser("compare-ping")
    comparison.add_argument("baseline", type=Path)
    comparison.add_argument("enforcing", type=Path)
    commands.add_parser("capture-counters")
    counter_delta = commands.add_parser("compare-counter-delta")
    counter_delta.add_argument("before", type=Path)
    counter_delta.add_argument("after", type=Path)
    blocked = commands.add_parser("tcp-blocked")
    blocked.add_argument("address")
    blocked.add_argument("port", type=checked_port)
    dns_denied = commands.add_parser("dns-blocked")
    dns_denied.add_argument("host")
    dns_denied.add_argument("port", type=checked_port)
    ping_denied = commands.add_parser("ping-blocked")
    ping_denied.add_argument("executable")
    ping_denied.add_argument("address")
    arguments = parser.parse_args()
    if arguments.command == "serve":
        serve(
            arguments.answer,
            arguments.tcp_port,
            arguments.fire_port,
            arguments.log,
            arguments.ready,
        )
    elif arguments.command == "tcp-once":
        tcp_once(arguments.address, arguments.port, arguments.profile)
    elif arguments.command == "dns-tcp-once":
        dns_tcp_once(arguments.host, arguments.port, arguments.profile)
    elif arguments.command == "fire-and-forget":
        fire_and_forget(arguments.address, arguments.port, arguments.profile)
    elif arguments.command == "held-tcp":
        held_tcp(arguments.address, arguments.port, arguments.ready, arguments.release)
    elif arguments.command == "spawn":
        if not arguments.child:
            raise ValueError("spawn requires a child command")
        spawn_children(arguments.child, arguments.count, arguments.concurrency)
    elif arguments.command == "audit-rules":
        audit_rules(arguments.address, arguments.tcp_port, arguments.fire_port, arguments.uid)
    elif arguments.command == "audit-held-rule":
        audit_held_rule(arguments.address, arguments.tcp_port, arguments.uid)
    elif arguments.command == "audit-peer":
        audit_peer(arguments.log, arguments.client_address)
    elif arguments.command == "create-icmp-rule":
        create_icmp_rule(arguments.executable, arguments.uid, arguments.address)
    elif arguments.command == "ping-measure":
        measure_ping(arguments.executable, arguments.address, arguments.count)
    elif arguments.command == "compare-ping":
        compare_ping(arguments.baseline, arguments.enforcing)
    elif arguments.command == "capture-counters":
        capture_counters()
    elif arguments.command == "compare-counter-delta":
        compare_counter_delta(arguments.before, arguments.after)
    elif arguments.command == "tcp-blocked":
        tcp_blocked(arguments.address, arguments.port)
    elif arguments.command == "dns-blocked":
        dns_blocked(arguments.host, arguments.port)
    elif arguments.command == "ping-blocked":
        ping_blocked(arguments.executable, arguments.address)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"short-lived socket E2E: {error}", file=sys.stderr)
        raise SystemExit(1)
