#!/usr/bin/env python3
"""Real TCP large-write regression, executed only in the GSO test containers.

Payload is ordinary application data, not handcrafted TCP packets. An AF_PACKET
observer verifies that large offloaded skbs actually traverse the DUT device.
For nftables, a non-verdict trace rule additionally proves queue traversal.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import random
import re
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time

SIZES = (128, 65_536, 262_144, 1_048_576)
SEED = 0x6F7367
SCRIPT = "/opt/gso-sockets.py"
ALLOWED = "/tmp/gso-allowed"
UNKNOWN = "/tmp/gso-unknown"
TIMEOUT_EXIT = 10
LIMIT_SECONDS = 30


def receive_exact(stream: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        block = stream.recv(size - len(result))
        if not block:
            raise ConnectionError("peer closed a partial TCP frame")
        result.extend(block)
    return bytes(result)


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(LIMIT_SECONDS)
        try:
            while True:
                header = self.request.recv(4, socket.MSG_WAITALL)
                if not header:
                    return
                if len(header) != 4:
                    raise ConnectionError("partial frame header")
                size = struct.unpack("!I", header)[0]
                if size not in SIZES:
                    raise ValueError("unexpected frame size")
                data = receive_exact(self.request, size)
                digest = hashlib.sha256(data).digest()
                with self.server.events_lock:
                    self.server.events.write(json.dumps({"bytes": size, "sha256": digest.hex()}) + "\n")
                self.request.sendall(digest)
        except (OSError, ValueError) as error:
            with self.server.events_lock:
                self.server.events.write(json.dumps({"error": str(error)}) + "\n")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int]) -> None:
        self.events_lock = threading.Lock()
        self.events = Path("/tmp/gso-peer.jsonl").open("w", buffering=1)
        super().__init__(address, Handler)


def exchange_frame(stream: socket.socket, data: bytes) -> None:
    # One large application write allows Linux to produce genuine GSO skbs.
    if len(data) > 1500:
        stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 1)
    try:
        stream.sendall(struct.pack("!I", len(data)) + data)
    finally:
        if len(data) > 1500:
            stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_CORK, 0)
    if receive_exact(stream, 32) != hashlib.sha256(data).digest():
        raise RuntimeError("TCP payload digest mismatch")


def client(address: str, port: int) -> int:
    started = time.monotonic()
    frames = 0
    octets = 0
    generator = random.Random(SEED)
    payloads = [generator.randbytes(size) for size in SIZES]
    try:
        with socket.create_connection((address, port), timeout=3.0) as stream:
            stream.settimeout(10.0)
            exchange_frame(stream, payloads[0])
            frames += 1
            octets += len(payloads[0])
            if os.environ.get("GSO_HELD") == "1":
                # Let the ACK of the small Learning exchange settle before
                # rotating the generation. The first post-transition write
                # must be bulk data, not an old delayed ACK warming the path.
                time.sleep(0.15)
                Path("/tmp/gso-held.ready").touch()
                deadline = time.monotonic() + LIMIT_SECONDS
                while not Path("/tmp/gso-held.release").exists():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("mode-switch barrier timed out")
                    time.sleep(0.01)
            for _ in range(3):
                for data in payloads[1:]:
                    exchange_frame(stream, data)
                    frames += 1
                    octets += len(data)
        # Also exercise new connections after the keep-alive bulk transfer.
        for _ in range(4):
            with socket.create_connection((address, port), timeout=3.0) as stream:
                exchange_frame(stream, payloads[1])
                frames += 1
                octets += len(payloads[1])
    except TimeoutError:
        print(json.dumps({"result": "timeout", "frames": frames, "bytes": octets,
                          "seconds": time.monotonic() - started}), flush=True)
        return TIMEOUT_EXIT
    print(json.dumps({"result": "ok", "frames": frames, "bytes": octets,
                      "seconds": time.monotonic() - started}), flush=True)
    return 0


class OffloadObserver:
    def __init__(self, address: str, port: int) -> None:
        self.address = socket.inet_aton(address)
        self.port = port
        self.largest = 0
        self.large_skbs = 0
        self.error = None
        self.stop = threading.Event()
        # ETH_P_ALL is necessary for outgoing device taps; an ETH_P_IP-only
        # packet socket is not on the kernel's ptype_all transmit tap list.
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        self.socket.bind(("eth0", 0))
        self.socket.settimeout(0.1)
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self) -> None:
        try:
            while not self.stop.is_set():
                try:
                    packet, origin = self.socket.recvfrom(1_048_576)
                except TimeoutError:
                    continue
                if (origin[2] != socket.PACKET_OUTGOING or len(packet) < 54
                        or packet[12:14] != b"\x08\x00"):
                    continue
                ip = packet[14:]
                offset = (ip[0] & 15) * 4
                if (ip[0] >> 4 != 4 or ip[9] != 6 or ip[16:20] != self.address
                        or len(ip) < offset + 20
                        or int.from_bytes(ip[offset + 2:offset + 4], "big") != self.port):
                    continue
                self.largest = max(self.largest, len(ip))
                self.large_skbs += int(len(ip) > 1500)
        except OSError as error:
            self.error = str(error)

    def finish(self) -> dict:
        self.stop.set()
        self.thread.join(timeout=2.0)
        self.socket.close()
        if self.thread.is_alive() or self.error:
            raise RuntimeError(f"offload observer failed: {self.error}")
        return {"largest_skb_bytes": self.largest, "large_skbs": self.large_skbs}


def command(address: str, port: int, executable: str = ALLOWED, label: str = "allowed") -> list[str]:
    return ["runuser", "-u", "gsoapp", "--", executable, SCRIPT, "client", address, str(port), label]


def queue_snapshot() -> dict[int, list[int]]:
    result = {}
    for line in Path("/proc/self/net/netfilter/nfnetlink_queue").read_text().splitlines():
        fields = [int(field) for field in line.split()]
        if fields and fields[0] in (1337, 1338, 1339):
            if len(fields) != 9 or fields[0] in result:
                raise RuntimeError("invalid NFQUEUE metadata")
            result[fields[0]] = fields
    if set(result) != {1337, 1338, 1339}:
        raise RuntimeError("one or more daemon queues are missing")
    return result


def mutate(kind: str, data: dict) -> None:
    import ipc_client

    for _ in range(40):
        current = ipc_client.status()
        response = ipc_client.exchange(ipc_client.CONTROL, {
            "type": "control", "data": {"type": kind, "data": {
                "expected_revision": current["revision"], **data}}})
        if response.get("type") == "ack":
            return
        if response.get("data", {}).get("code") != "conflict":
            raise RuntimeError(f"control mutation failed: {response}")
        time.sleep(0.1)
    raise TimeoutError("policy revision did not stabilize")


def invoke(address: str, port: int, name: str, expected: int = 0,
           executable: str = ALLOWED, label: str = "allowed", held: bool = False,
           after_mode_switch=None) -> dict:
    queues_start = queue_snapshot()
    observer = OffloadObserver(address, port)
    environment = dict(os.environ)
    if held:
        environment["GSO_HELD"] = "1"
    child = subprocess.Popen(command(address, port, executable, label), env=environment,
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if held:
            deadline = time.monotonic() + LIMIT_SECONDS
            while not Path("/tmp/gso-held.ready").exists():
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("held TCP did not reach its Learning barrier")
                time.sleep(0.02)
            mutate("set_mode", {"mode": "enforcing"})
            if after_mode_switch is not None:
                after_mode_switch()
            Path("/tmp/gso-held.release").touch()
        stdout, stderr = child.communicate(timeout=60)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        offload = observer.finish()
    if child.returncode != expected:
        raise RuntimeError(f"{name}: status={child.returncode}, stderr={stderr!r}, stdout={stdout!r}")
    result = json.loads(stdout)
    if expected == 0 and (result["frames"] != 14 or result["bytes"] <= 4_000_000):
        raise RuntimeError(f"{name}: incomplete TCP exchange: {result}")
    if expected == TIMEOUT_EXIT and (result["frames"] != 0 or result["seconds"] < 0.5):
        raise RuntimeError(f"{name}: negative probe did not fail closed: {result}")
    if expected == 0 and offload["large_skbs"] == 0:
        raise RuntimeError(f"{name}: no offloaded skb observed; GSO test is inconclusive")
    queues_end = queue_snapshot()
    queue_deltas = {str(number): (queues_end[number][7] - start[7]) & 0xFFFFFFFF
                    for number, start in queues_start.items()}
    return {"name": name, **result, **offload, "queue_deltas": queue_deltas}


def exercise(backend: str, address: str, port: int) -> None:
    import ipc_client

    if os.geteuid() != 0 or not Path("/.dockerenv").is_file() or Path(__file__).resolve() != Path(SCRIPT):
        raise PermissionError("GSO exercise requires the dedicated test container")
    if int(Path("/sys/class/net/eth0/mtu").read_text()) != 1500:
        raise RuntimeError("GSO fixture requires MTU 1500")
    results = []
    queues_before = queue_snapshot()
    counters_before = ipc_client.status()["nfqueue"]
    mutate("set_mode", {"mode": "learning"})
    # Pin all actual argv fields. Altered argv and another executable remain
    # independent negative probes, including when learned rules also exist.
    mutate("create_rule", {"rule": {
        "name": "GSO real TCP exact application", "direction": "outbound",
        "protocol": "tcp", "peer_network": f"{address}/32",
        "port": {"start": port, "end": port}, "interface": None,
        "application": {"executable": ALLOWED, "executable_file": None,
                        "command_line": {"kind": "exact", "arguments": command(address, port)[4:]},
                        "uid": pwd.getpwnam("gsoapp").pw_uid, "cgroup": None,
                        "metadata_redacted": False},
        "origin": "manual", "action": "accept", "enabled": True}})
    trace = None
    trace_stream = None
    trace_paths = []

    def restart_trace(name: str) -> None:
        nonlocal trace, trace_stream
        if trace is not None:
            trace.terminate()
            trace.wait(timeout=5)
            trace_stream.close()
        path = Path(f"/tmp/gso-trace-{name}.log")
        trace_paths.append(path)
        trace_stream = path.open("w")
        trace = subprocess.Popen(["nft", "monitor", "trace"], stdout=trace_stream, stderr=subprocess.STDOUT)
        time.sleep(0.2)

    if backend == "nftables":
        rules = ("add table inet gso_probe\n"
                 "add chain inet gso_probe output { type filter hook output priority -301; }\n"
                 f"add rule inet gso_probe output ip daddr {address} tcp dport {port} "
                 "meta length > 1500 meta nftrace set 1\n")
        subprocess.run(["nft", "-f", "-"], input=rules, text=True, check=True, timeout=5)
        restart_trace("learning")
    try:
        results.append(invoke(address, port, "learning"))
        # nft monitor's cached rule-handle descriptions can become stale after
        # atomic policy replacement. Restart before releasing the held socket.
        after_switch = (lambda: restart_trace("enforcing")) if backend == "nftables" else None
        results.append(invoke(address, port, "learning_to_enforcing", held=True, after_mode_switch=after_switch))
        results.append(invoke(address, port, "enforcing_new_connections"))
        results.append(invoke(address, port, "wrong_executable", TIMEOUT_EXIT, executable=UNKNOWN))
        results.append(invoke(address, port, "wrong_argv", TIMEOUT_EXIT, label="denied"))
        results.append(invoke(address, port, "post_denial_liveness"))
        if ipc_client.status()["mode"] != "enforcing":
            raise RuntimeError("daemon left Enforcing during the GSO regression")
    finally:
        if trace is not None:
            trace.terminate()
            trace.wait(timeout=5)
            trace_stream.close()
            Path("/tmp/gso-trace.log").write_text("\n".join(path.read_text() for path in trace_paths))
            subprocess.run(["nft", "delete", "table", "inet", "gso_probe"], check=True, timeout=5)
    queue_trace_proven = None
    trace_scope = {"learning_large_queue": None, "enforcing_large_queue": None}
    if backend == "nftables":
        trace_text = Path("/tmp/gso-trace.log").read_text()
        for field, number in (("learning_large_queue", 1338), ("enforcing_large_queue", 1337)):
            trace_scope[field] = bool(re.search(
                rf"\bqueue\b[^\n]*\b(?:to|num)\s+{number}\b[^\n]*\(verdict queue\)", trace_text))
        if not trace_scope["learning_large_queue"]:
            raise RuntimeError("large-skb trace did not prove Learning NFQUEUE traversal")
        queue_trace_proven = all(trace_scope.values())
        if not trace_scope["enforcing_large_queue"]:
            print("GSO scope: large Enforcing NFQUEUE subcase was not exercised; "
                  "this is not a PASS for that subcase. The live TCP kernel fast-path "
                  "and new-connection NFQUEUE path are checked separately.", file=sys.stderr)
    trace_scope["enforcing_handshake_queue"] = any(
        item["name"] == "enforcing_new_connections" and item["queue_deltas"]["1337"] > 0
        for item in results)
    if not trace_scope["enforcing_handshake_queue"]:
        raise RuntimeError("Enforcing new connections did not exercise their application queue")
    queues_after = queue_snapshot()
    for number, before in queues_before.items():
        after = queues_after[number]
        if after[1] != before[1] or after[3:7] != before[3:7]:
            raise RuntimeError(f"NFQUEUE {number} owner/configuration changed or drops increased")
    if queues_after[1337][7] == queues_before[1337][7] or queues_after[1338][7] == queues_before[1338][7]:
        raise RuntimeError("both Enforcing and Learning application queues must be exercised")
    counters_after = ipc_client.status()["nfqueue"]
    for key in ("queue_overflow", "attribution_timeout", "terminal_queue_error"):
        if counters_after.get(key, 0) != counters_before.get(key, 0):
            raise RuntimeError(f"daemon NFQUEUE error counter increased: {key}")
    report = {"schema": "openshield.gso.e2e.v1", "backend": backend, "seed": SEED,
              "sizes": SIZES, "queue_trace_proven": queue_trace_proven,
              "trace_scope": trace_scope,
              "queues_before": queues_before, "queues_after": queues_after,
              "nfqueue_before": counters_before, "nfqueue_after": counters_after,
              "results": results, "expected_peer_frames": sum(item["frames"] for item in results)}
    Path("/tmp/gso-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("serve", "client", "exercise"):
        command_parser = commands.add_parser(name)
        if name == "exercise":
            command_parser.add_argument("backend", choices=("nftables", "iptables"))
        command_parser.add_argument("address", type=lambda value: str(ipaddress.IPv4Address(value)))
        command_parser.add_argument("port", type=int)
        if name == "client":
            command_parser.add_argument("label", choices=("allowed", "denied"))
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port is outside 1..65535")
    if args.action == "serve":
        with Server((args.address, args.port)) as server:
            Path("/tmp/gso-peer.ready").touch()
            server.serve_forever()
    elif args.action == "exercise":
        exercise(args.backend, args.address, args.port)
    else:
        return client(args.address, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
