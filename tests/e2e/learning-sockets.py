#!/usr/bin/env python3
"""Bounded real-socket workloads for transparent Learning E2E coverage."""

import concurrent.futures
import ipaddress
import os
from pathlib import Path
import socket
import socketserver
import struct
import sys
import threading
import time


SOCKET_TIMEOUT_SECONDS = 5.0
MAX_FRAME_BYTES = 4096
DNS_ANSWER = b"\xc0\x00\x02\x7b"


def parse_port(text):
    port = int(text, 10)
    if not 1 <= port <= 65535:
        raise ValueError("port is outside 1..65535")
    return port


def receive_exact(stream, size):
    received = bytearray()
    while len(received) < size:
        chunk = stream.recv(size - len(received))
        if not chunk:
            raise ConnectionError("peer closed a framed TCP exchange")
        received.extend(chunk)
    return bytes(received)


class TcpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(SOCKET_TIMEOUT_SECONDS)
        while True:
            header = self.request.recv(4)
            if not header:
                return
            if len(header) != 4:
                header += receive_exact(self.request, 4 - len(header))
            size = struct.unpack("!I", header)[0]
            if size == 0 or size > MAX_FRAME_BYTES:
                raise ValueError("invalid TCP workload frame")
            payload = receive_exact(self.request, size)
            self.request.sendall(header + payload)


class ThreadingTcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 256


def dns_question(name):
    encoded = bytearray()
    for label in name.split("."):
        octets = label.encode("ascii")
        if not octets or len(octets) > 63:
            raise ValueError("invalid DNS label")
        encoded.append(len(octets))
        encoded.extend(octets)
    encoded.append(0)
    encoded.extend(struct.pack("!HH", 1, 1))
    return bytes(encoded)


def dns_query(transaction, suffix):
    question = dns_question("flow%s.e2e.openshield.test" % suffix)
    return struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + question


class DnsHandler(socketserver.BaseRequestHandler):
    def handle(self):
        request, transport = self.request
        if len(request) < 17:
            return
        transaction, _flags, questions, _answers, _authority, _additional = (
            struct.unpack("!HHHHHH", request[:12])
        )
        if questions != 1:
            return
        cursor = 12
        while cursor < len(request):
            label_size = request[cursor]
            cursor += 1
            if label_size == 0:
                break
            if label_size > 63 or cursor + label_size > len(request):
                return
            cursor += label_size
        if cursor + 4 > len(request):
            return
        question = request[12 : cursor + 4]
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + DNS_ANSWER
        response = (
            struct.pack("!HHHHHH", transaction, 0x8180, 1, 1, 0, 0)
            + question
            + answer
        )
        transport.sendto(response, self.client_address)


class ThreadingUdpServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(tcp_port, udp_port):
    tcp = ThreadingTcpServer(("0.0.0.0", tcp_port), TcpHandler)
    udp = ThreadingUdpServer(("0.0.0.0", udp_port), DnsHandler)
    threads = [
        threading.Thread(target=tcp.serve_forever, name="e2e-tcp", daemon=True),
        threading.Thread(target=udp.serve_forever, name="e2e-udp", daemon=True),
    ]
    for thread in threads:
        thread.start()
    Path(
        "/tmp/openshield-learning-sockets-%s-%s.ready" % (tcp_port, udp_port)
    ).write_text("ready\n", encoding="ascii")
    for thread in threads:
        thread.join()


def tcp_exchange(stream, payload):
    frame = struct.pack("!I", len(payload)) + payload
    stream.sendall(frame)
    if receive_exact(stream, len(frame)) != frame:
        raise RuntimeError("TCP workload reply did not match its request")


def tcp_round_trips(address, port, payloads):
    with socket.create_connection((address, port), timeout=SOCKET_TIMEOUT_SECONDS) as stream:
        stream.settimeout(SOCKET_TIMEOUT_SECONDS)
        for payload in payloads:
            tcp_exchange(stream, payload)


def dns_exchange(datagram, transaction):
    request = dns_query(transaction, "%04x" % transaction)
    datagram.send(request)
    response = datagram.recv(MAX_FRAME_BYTES)
    if len(response) < 16 or response[:2] != request[:2]:
        raise RuntimeError("DNS-like reply has the wrong transaction ID")
    flags, questions, answers = struct.unpack("!HHH", response[2:8])
    if not flags & 0x8000 or questions != 1 or answers != 1:
        raise RuntimeError("DNS-like reply has invalid flags or counts")
    if not response.endswith(DNS_ANSWER):
        raise RuntimeError("DNS-like reply has the wrong address")


def dns_round_trips(address, port, exchanges, base_transaction):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
        datagram.settimeout(SOCKET_TIMEOUT_SECONDS)
        datagram.connect((address, port))
        for offset in range(exchanges):
            dns_exchange(datagram, base_transaction + offset)


def http_exchange(address, port, path, timeout_millis, hold_millis):
    if (
        not path.startswith("/")
        or len(path) > 256
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in path)
    ):
        raise ValueError("HTTP workload path is invalid")
    if not 100 <= timeout_millis <= 60_000 or not 0 <= hold_millis <= 5_000:
        raise ValueError("HTTP workload timing is outside its E2E bounds")
    timeout = timeout_millis / 1000.0
    with socket.create_connection((address, port), timeout=timeout) as stream:
        stream.settimeout(timeout)
        request = (
            "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n"
            % (path, address)
        ).encode("ascii")
        stream.sendall(request)
        response = stream.recv(MAX_FRAME_BYTES)
        if not response.startswith(b"HTTP/"):
            raise RuntimeError("HTTP workload reply is invalid")
        # The daemon deliberately attributes after returning the packet
        # verdict. Retain the owning process and descriptor for a bounded
        # interval so this exact-rule E2E is independent of scheduler timing.
        time.sleep(hold_millis / 1000.0)


def hold_observable_flows(address, tcp_port, udp_port):
    ready_path = Path(
        "/tmp/openshield-learning-hold-%s-%s.ready" % (tcp_port, udp_port)
    )
    release_path = Path(
        "/tmp/openshield-learning-hold-%s-%s.release" % (tcp_port, udp_port)
    )
    ready_path.unlink(missing_ok=True)
    release_path.unlink(missing_ok=True)
    with socket.create_connection(
        (address, tcp_port), timeout=SOCKET_TIMEOUT_SECONDS
    ) as stream, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
        stream.settimeout(SOCKET_TIMEOUT_SECONDS)
        datagram.settimeout(SOCKET_TIMEOUT_SECONDS)
        datagram.connect((address, udp_port))
        transaction = 0x6000
        tcp_exchange(stream, b"observable-learning-flow")
        dns_exchange(datagram, transaction)
        ready_path.write_text("ready\n", encoding="ascii")
        deadline = time.monotonic() + 30.0
        while not release_path.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("observable Learning flow was not released")
            transaction += 1
            tcp_exchange(stream, b"observable-learning-keepalive")
            dns_exchange(datagram, transaction)
            time.sleep(0.1)


def run_transparent_client(address, tcp_port, udp_port):
    # Sequential short-lived TCP connections exercise distinct NEW flows.
    for index in range(4):
        tcp_round_trips(address, tcp_port, [("sequential-%s" % index).encode("ascii")])

    # Concurrent persistent sockets exercise both NEW attribution and repeated
    # application payloads on established keep-alive flows.
    def persistent_tcp(index):
        payloads = [
            ("keepalive-%s-%s" % (index, request)).encode("ascii")
            for request in range(6)
        ]
        tcp_round_trips(address, tcp_port, payloads)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(persistent_tcp, index) for index in range(8)]
        for future in futures:
            future.result()

    # One connected UDP socket models repeated DNS exchanges; the following
    # short and parallel sockets exercise distinct UDP flows and replies.
    dns_round_trips(address, udp_port, 6, 0x1000)
    for index in range(4):
        dns_round_trips(address, udp_port, 1, 0x2000 + index)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [
            executor.submit(dns_round_trips, address, udp_port, 2, 0x3000 + index * 4)
            for index in range(8)
        ]
        for future in futures:
            future.result()


def run_burst_client(address, tcp_port, udp_port):
    started = time.monotonic()
    # Sequential exchanges make synchronous per-packet attribution latency
    # accumulate; parallel exchanges then exercise queue head-of-line behavior.
    for index in range(12):
        tcp_round_trips(address, tcp_port, [("burst-short-%s" % index).encode("ascii")])
    with concurrent.futures.ThreadPoolExecutor(max_workers=96) as executor:
        futures = [
            executor.submit(
                tcp_round_trips,
                address,
                tcp_port,
                [
                    ("burst-keepalive-%s-%s" % (index, request)).encode("ascii")
                    for request in range(3)
                ],
            )
            for index in range(96)
        ]
        for future in futures:
            future.result()

    for index in range(12):
        dns_round_trips(address, udp_port, 1, 0x4000 + index)
    with concurrent.futures.ThreadPoolExecutor(max_workers=96) as executor:
        futures = [
            executor.submit(dns_round_trips, address, udp_port, 2, 0x5000 + index * 2)
            for index in range(96)
        ]
        for future in futures:
            future.result()

    elapsed = time.monotonic() - started
    if elapsed > 6.0:
        raise TimeoutError(
            "transparent Learning burst took %.3fs, expected at most 6.000s" % elapsed
        )
    print("transparent Learning burst passed in %.3fs" % elapsed)


def hold_procfs_pressure(thread_count, descriptor_count, ready_path):
    if not 1 <= thread_count <= 256 or not 1 <= descriptor_count <= 2048:
        raise ValueError("procfs pressure is outside its E2E bounds")
    descriptors = [
        os.open("/dev/null", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        for _ in range(descriptor_count)
    ]
    blocker = threading.Event()
    threads = [
        threading.Thread(target=blocker.wait, name="procfs-pressure-%s" % index, daemon=True)
        for index in range(thread_count)
    ]
    for thread in threads:
        thread.start()
    Path(ready_path).write_text(
        "%s threads, %s descriptors\n" % (thread_count, len(descriptors)),
        encoding="ascii",
    )
    blocker.wait()


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "serve":
        serve(parse_port(sys.argv[2]), parse_port(sys.argv[3]))
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == "client":
        address = str(ipaddress.IPv4Address(sys.argv[2]))
        run_transparent_client(address, parse_port(sys.argv[3]), parse_port(sys.argv[4]))
        print("transparent Learning socket workload passed")
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == "burst":
        address = str(ipaddress.IPv4Address(sys.argv[2]))
        run_burst_client(address, parse_port(sys.argv[3]), parse_port(sys.argv[4]))
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == "hold":
        address = str(ipaddress.IPv4Address(sys.argv[2]))
        hold_observable_flows(address, parse_port(sys.argv[3]), parse_port(sys.argv[4]))
        return 0
    if len(sys.argv) == 7 and sys.argv[1] == "http":
        address = str(ipaddress.IPv4Address(sys.argv[2]))
        http_exchange(
            address,
            parse_port(sys.argv[3]),
            sys.argv[4],
            int(sys.argv[5], 10),
            int(sys.argv[6], 10),
        )
        return 0
    if len(sys.argv) == 5 and sys.argv[1] == "procfs-pressure":
        hold_procfs_pressure(int(sys.argv[2], 10), int(sys.argv[3], 10), sys.argv[4])
        return 0
    print(
        "usage: learning-sockets.py serve TCP_PORT UDP_PORT\n"
        "       learning-sockets.py client IPV4 TCP_PORT UDP_PORT\n"
        "       learning-sockets.py burst IPV4 TCP_PORT UDP_PORT\n"
        "       learning-sockets.py hold IPV4 TCP_PORT UDP_PORT\n"
        "       learning-sockets.py http IPV4 PORT PATH TIMEOUT_MS HOLD_MS\n"
        "       learning-sockets.py procfs-pressure THREADS FDS READY_PATH",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ConnectionError, OSError, RuntimeError, TimeoutError, ValueError) as error:
        print("OpenShield Learning socket workload: %s" % error, file=sys.stderr)
        raise SystemExit(1)
