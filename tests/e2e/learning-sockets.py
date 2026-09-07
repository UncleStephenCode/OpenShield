#!/usr/bin/env python3
"""Bounded real-socket workloads for transparent Learning E2E coverage."""

import concurrent.futures
import contextlib
import errno
import ipaddress
import os
from pathlib import Path
import selectors
import socket
import socketserver
import struct
import sys
import threading
import time


SOCKET_TIMEOUT_SECONDS = 5.0
BURST_NEW_FLOW_SECONDS = 1.0
BURST_PHASE_SECONDS = 6.0
BURST_ACTIVE_FLOWS = 64
BURST_SETUP_SECONDS = 5.0
MAX_FRAME_BYTES = 4096
MAX_PEER_CONNECTIONS = 256
DNS_ANSWER = b"\xc0\x00\x02\x7b"


def parse_port(text):
    port = int(text, 10)
    if not 1 <= port <= 65535:
        raise ValueError("port is outside 1..65535")
    return port


def remaining_time(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Learning workload deadline expired")
    return remaining


@contextlib.contextmanager
def workload_context(label, deadline=None):
    before = time.monotonic()
    try:
        yield
    except (OSError, RuntimeError, TimeoutError) as error:
        budget = "" if deadline is None else "; %.3fs deadline remaining" % (
            deadline - time.monotonic(),
        )
        message = "%s failed after %.3fs%s: %s" % (
            label, time.monotonic() - before, budget, error,
        )
        failure = TimeoutError if isinstance(error, (TimeoutError, socket.timeout)) else RuntimeError
        raise failure(message) from error


def receive_exact(stream, size, deadline=None):
    received = bytearray()
    while len(received) < size:
        if deadline is not None:
            stream.settimeout(remaining_time(deadline))
        chunk = stream.recv(size - len(received))
        if not chunk:
            raise ConnectionError("peer closed a framed TCP exchange")
        received.extend(chunk)
    return bytes(received)


class TcpPeerConnection:
    def __init__(self, stream, now):
        self.stream = stream
        self.incoming = bytearray()
        self.outgoing = bytearray()
        self.deadline = now + SOCKET_TIMEOUT_SECONDS
        self.closed = False

    def prepare_reply(self):
        if self.outgoing or len(self.incoming) < 4:
            return
        size = struct.unpack("!I", self.incoming[:4])[0]
        if size == 0 or size > MAX_FRAME_BYTES:
            raise ValueError("invalid TCP workload frame")
        if len(self.incoming) >= size + 4:
            self.outgoing.extend(self.incoming[:size + 4])
            del self.incoming[:size + 4]

    def handle(self, events, now):
        if now >= self.deadline:
            raise TimeoutError("TCP workload peer frame/idle deadline expired")
        # Do not read while a reply is backpressured. Each user-space buffer is
        # bounded by one maximum frame, even for coalesced or malicious input.
        if events & selectors.EVENT_READ and not self.outgoing:
            try:
                received = self.stream.recv(MAX_FRAME_BYTES + 4 - len(self.incoming))
            except BlockingIOError:
                received = None
            if received == b"":
                if self.incoming:
                    raise ConnectionError("truncated TCP workload frame")
                self.closed = True
                return
            if received:
                self.incoming.extend(received)
                self.prepare_reply()
        # Try a newly prepared reply immediately; no extra selector round trip
        # or per-operation task is needed for the normal small echo.
        if self.outgoing:
            try:
                sent = self.stream.send(self.outgoing)
            except BlockingIOError:
                return
            if sent == 0:
                raise ConnectionError("peer closed a TCP workload reply")
            del self.outgoing[:sent]
            if not self.outgoing:
                # A partial read/write cannot renew the frame deadline.
                self.deadline = now + SOCKET_TIMEOUT_SECONDS
                self.prepare_reply()

    def interest(self):
        return selectors.EVENT_WRITE if self.outgoing else selectors.EVENT_READ


class SelectorTcpServer:
    # One selector thread handles bounded real streams; there is no native
    # thread or coroutine/task allocation per connection, frame or I/O operation.
    def __init__(self, address):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(address)
        self.socket.listen(MAX_PEER_CONNECTIONS)
        self.socket.setblocking(False)
        self.clients = {}
        self.ready = threading.Event()
        self.startup_error = None

    def accept_ready(self, selector):
        # Bound each accept batch so existing replies cannot be starved.
        for _ in range(BURST_ACTIVE_FLOWS + 1):
            try:
                stream, _address = self.socket.accept()
            except BlockingIOError:
                return
            if len(self.clients) >= MAX_PEER_CONNECTIONS:
                stream.close()
                continue
            try:
                stream.setblocking(False)
                stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                connection = TcpPeerConnection(stream, time.monotonic())
                selector.register(stream, selectors.EVENT_READ, connection)
                self.clients[stream] = connection
            except BaseException:
                stream.close()
                raise

    def discard(self, selector, connection):
        self.clients.pop(connection.stream, None)
        selector.unregister(connection.stream)
        connection.stream.close()

    def run(self, selector):
        selector.register(self.socket, selectors.EVENT_READ)
        self.ready.set()
        while True:
            now = time.monotonic()
            for connection in list(self.clients.values()):
                if now >= connection.deadline:
                    self.discard(selector, connection)
            for key, events in selector.select(0.05):
                if key.data is None:
                    self.accept_ready(selector)
                    continue
                connection = key.data
                try:
                    connection.handle(events, time.monotonic())
                    if connection.closed:
                        self.discard(selector, connection)
                    else:
                        selector.modify(connection.stream, connection.interest(), connection)
                except (OSError, RuntimeError, ValueError) as error:
                    print("TCP workload peer: %s" % error, file=sys.stderr, flush=True)
                    self.discard(selector, connection)

    def serve_forever(self):
        try:
            with selectors.DefaultSelector() as selector:
                self.run(selector)
        except BaseException as error:
            self.startup_error = error
            self.ready.set()
            raise
        finally:
            for stream in self.clients:
                stream.close()
            self.clients.clear()
            self.socket.close()


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


class DatagramServer(socketserver.UDPServer):
    # A DNS-like echo is short and does not wait for another request. Starting a
    # native thread for every datagram makes peer scheduling, not packet HOL,
    # dominate the burst on slower machines; service these bounded replies inline.
    allow_reuse_address = True


def serve(tcp_port, udp_port):
    tcp = SelectorTcpServer(("0.0.0.0", tcp_port))
    udp = DatagramServer(("0.0.0.0", udp_port), DnsHandler)
    threads = [
        threading.Thread(target=tcp.serve_forever, name="e2e-tcp", daemon=True),
        threading.Thread(target=udp.serve_forever, name="e2e-udp", daemon=True),
    ]
    for thread in threads:
        thread.start()
    if not tcp.ready.wait(SOCKET_TIMEOUT_SECONDS):
        raise TimeoutError("TCP workload peer startup exceeded %.3fs" % SOCKET_TIMEOUT_SECONDS)
    if tcp.startup_error is not None:
        raise RuntimeError("TCP workload peer startup failed: %s" % tcp.startup_error)
    Path(
        "/tmp/openshield-learning-sockets-%s-%s.ready" % (tcp_port, udp_port)
    ).write_text("ready\n", encoding="ascii")
    for thread in threads:
        thread.join()


def tcp_exchange(stream, payload, deadline=None):
    frame = struct.pack("!I", len(payload)) + payload
    with workload_context("TCP send", deadline):
        if deadline is not None:
            stream.settimeout(remaining_time(deadline))
        stream.sendall(frame)
    with workload_context("TCP reply", deadline):
        if receive_exact(stream, len(frame), deadline) != frame:
            raise RuntimeError("TCP workload reply did not match its request")
    if deadline is not None:
        remaining_time(deadline)


def connect_ipv4(address, port, deadline=None):
    # CLI callers already normalized a numeric IPv4 address. Avoid per-NEW
    # getaddrinfo work while preserving the same socket and absolute deadline.
    stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        stream.settimeout(SOCKET_TIMEOUT_SECONDS if deadline is None else remaining_time(deadline))
        stream.connect((address, port))
        if deadline is not None:
            remaining_time(deadline)
        return stream
    except BaseException:
        stream.close()
        raise


def tcp_round_trips(address, port, payloads, deadline=None):
    with workload_context("TCP connect", deadline):
        stream = connect_ipv4(address, port, deadline)
    with stream:
        stream.settimeout(SOCKET_TIMEOUT_SECONDS)
        for payload in payloads:
            tcp_exchange(stream, payload, deadline)


def dns_exchange(datagram, transaction, deadline=None):
    request = dns_query(transaction, "%04x" % transaction)
    with workload_context("UDP send", deadline):
        if deadline is not None:
            datagram.settimeout(remaining_time(deadline))
        datagram.send(request)
    with workload_context("UDP reply", deadline):
        if deadline is not None:
            datagram.settimeout(remaining_time(deadline))
        response = datagram.recv(MAX_FRAME_BYTES)
    verify_dns_reply(request, response)
    if deadline is not None:
        remaining_time(deadline)


def verify_dns_reply(request, response):
    if len(response) < 16 or response[:2] != request[:2]:
        raise RuntimeError("DNS-like reply has the wrong transaction ID")
    flags, questions, answers = struct.unpack("!HHH", response[2:8])
    if not flags & 0x8000 or questions != 1 or answers != 1:
        raise RuntimeError("DNS-like reply has invalid flags or counts")
    if not response.endswith(DNS_ANSWER):
        raise RuntimeError("DNS-like reply has the wrong address")


def dns_round_trips(address, port, exchanges, base_transaction, deadline=None):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
        datagram.settimeout(SOCKET_TIMEOUT_SECONDS)
        datagram.connect((address, port))
        for offset in range(exchanges):
            dns_exchange(datagram, base_transaction + offset, deadline)


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


def run_sequential_burst(address, tcp_port, udp_port):
    # Each unseen flow may legitimately wait for the 250 ms capture opportunity.
    # Keep the original sequential NEW coverage, with a separate absolute bound
    # per flow; its 24 intentional waits do not measure queue head-of-line blocking.
    started = time.monotonic()
    for index in range(12):
        tcp_round_trips(
            address, tcp_port, [("burst-short-%s" % index).encode("ascii")],
            deadline=time.monotonic() + BURST_NEW_FLOW_SECONDS,
        )
    tcp_elapsed = time.monotonic() - started
    started = time.monotonic()
    for index in range(12):
        dns_round_trips(
            address, udp_port, 1, 0x4000 + index,
            deadline=time.monotonic() + BURST_NEW_FLOW_SECONDS,
        )
    print("Learning sequential NEW flows: TCP %.3fs, UDP %.3fs (12 each)" % (
        tcp_elapsed, time.monotonic() - started,
    ), flush=True)


def tcp_frame(payload):
    return struct.pack("!I", len(payload)) + payload


def prepare_burst_jobs():
    before = time.monotonic()
    deadline = before + BURST_SETUP_SECONDS
    jobs = []
    for index in range(96):
        jobs.append(("tcp", index, tuple(tcp_frame(
            ("burst-keepalive-%s-%s" % (index, request)).encode("ascii")
        ) for request in range(3))))
        jobs.append(("udp", index, tuple(dns_query(
            0x5000 + index * 2 + request, "%04x" % (0x5000 + index * 2 + request)
        ) for request in range(2))))
        remaining_time(deadline)
    print("Learning burst preparation: %.3fs (192 jobs, 64 active NEW socket limit)" % (
        time.monotonic() - before,
    ), flush=True)
    return jobs


class BurstFlow:
    def __init__(self, stream, protocol, requests, started, deadline, label, probe=None):
        self.stream = stream
        self.protocol = protocol
        self.requests = requests
        self.started = started
        self.deadline = deadline
        self.label = label
        self.probe = probe
        self.connecting = False
        self.exchange = 0
        self.sent = 0
        self.response = bytearray()
        self.done = False

    @classmethod
    def open_new(cls, address, tcp_port, udp_port, job, phase_deadline):
        protocol, index, requests = job
        # Begin the immutable one-second budget BEFORE allocating/opening a
        # socket, not when connect becomes writable or its first reply arrives.
        started = time.monotonic()
        deadline = min(phase_deadline, started + BURST_NEW_FLOW_SECONDS)
        label = "Learning burst NEW %s job %s" % (protocol, index)
        with workload_context(label + " open/connect", deadline):
            stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp"
                                   else socket.SOCK_DGRAM)
            try:
                stream.setblocking(False)
                flow = cls(stream, protocol, requests, started, deadline, label)
                if protocol == "tcp":
                    result = stream.connect_ex((address, tcp_port))
                    if result not in (0, errno.EISCONN):
                        if result not in (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, errno.EINTR):
                            raise OSError(result, os.strerror(result))
                        flow.connecting = True
                else:
                    stream.connect((address, udp_port))
                remaining_time(deadline)
                return flow
            except BaseException:
                stream.close()
                raise

    def interest(self):
        return selectors.EVENT_WRITE if self.connecting or self.sent < len(self.requests[self.exchange]) \
            else selectors.EVENT_READ

    def step(self, events):
        operation = "connect" if self.connecting else (
            "send" if self.sent < len(self.requests[self.exchange]) else "reply"
        )
        with workload_context("%s exchange %s %s" % (self.label, self.exchange, operation), self.deadline):
            remaining_time(self.deadline)
            if self.connecting:
                if not events & selectors.EVENT_WRITE:
                    return
                error = self.stream.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if error:
                    raise OSError(error, os.strerror(error))
                self.connecting = False
            request = self.requests[self.exchange]
            if self.sent < len(request):
                if not events & selectors.EVENT_WRITE:
                    return
                try:
                    count = self.stream.send(request[self.sent:])
                except BlockingIOError:
                    return
                if count == 0 or (self.protocol == "udp" and count != len(request)):
                    raise ConnectionError("incomplete %s workload send" % self.protocol)
                self.sent += count
                remaining_time(self.deadline)
                return
            if not events & selectors.EVENT_READ:
                return
            try:
                response = self.stream.recv(len(request) - len(self.response) if self.protocol == "tcp"
                                            else MAX_FRAME_BYTES)
            except BlockingIOError:
                return
            if self.protocol == "tcp":
                if not response:
                    raise ConnectionError("peer closed a framed TCP exchange")
                self.response.extend(response)
                if len(self.response) < len(request):
                    return
                if self.response != request:
                    raise RuntimeError("TCP workload reply did not match its request")
            else:
                verify_dns_reply(request, response)
            # Validation and delayed scheduling cannot credit an overdue reply.
            remaining_time(self.deadline)
            self.exchange += 1
            self.sent = 0
            self.response.clear()
            self.done = self.exchange == len(self.requests)


class BurstProbe:
    def __init__(self, stream, protocol):
        self.stream = stream
        self.protocol = protocol
        self.exchanges = 0
        self.maximum = 0.0
        self.next_due = 0.0
        self.active = False

    def start(self, phase_deadline):
        started = time.monotonic()
        deadline = min(phase_deadline, started + BURST_NEW_FLOW_SECONDS)
        transaction = 0x7001 + self.exchanges
        request = tcp_frame(b"burst-probe") if self.protocol == "tcp" else dns_query(
            transaction, "%04x" % transaction,
        )
        self.active = True
        return BurstFlow(self.stream, self.protocol, (request,), started, deadline,
                         "Learning burst %s probe" % self.protocol, self)

    def finish(self, flow):
        now = time.monotonic()
        if now >= flow.deadline:
            raise TimeoutError("%s exceeded its one-second exchange deadline" % flow.label)
        self.maximum = max(self.maximum, now - flow.started)
        self.exchanges += 1
        self.next_due = now + 0.01
        self.active = False


def finish_burst_phase(started, deadline):
    finished = time.monotonic()
    if finished > deadline:
        raise TimeoutError("Learning concurrent phase exceeded its six-second deadline")
    return finished - started


def measure_concurrent_burst(address, tcp_port, udp_port, stream, datagram, jobs):
    if len(jobs) != 192:
        raise RuntimeError("Learning burst must contain all 192 NEW jobs")
    probes = (BurstProbe(stream, "tcp"), BurstProbe(datagram, "udp"))
    stream.setblocking(False)
    datagram.setblocking(False)
    active = {}
    next_job = completed = new_active = peak_active = 0
    with selectors.DefaultSelector() as selector:
        before = time.monotonic()
        deadline = before + BURST_PHASE_SECONDS

        def register(flow):
            try:
                selector.register(flow.stream, flow.interest(), flow)
                active[flow.stream] = flow
            except BaseException:
                if flow.probe is None:
                    flow.stream.close()
                raise

        with workload_context("Learning concurrent phase (192 NEW jobs, 64 active sockets, 6s limit)", deadline):
            try:
                while completed < len(jobs) or active:
                    remaining_time(deadline)
                    now = time.monotonic()
                    # Probes have independent timers and are offered before NEW
                    # sockets. Already-started probes are drained even after the
                    # final NEW job completes; an overdue/corrupt probe must fail.
                    for probe in probes:
                        if completed < len(jobs) and not probe.active and now >= probe.next_due:
                            register(probe.start(deadline))
                    while next_job < len(jobs) and new_active < BURST_ACTIVE_FLOWS:
                        register(BurstFlow.open_new(address, tcp_port, udp_port, jobs[next_job], deadline))
                        next_job += 1
                        new_active += 1
                        peak_active = max(peak_active, new_active)
                    timeout = remaining_time(deadline)
                    for flow in active.values():
                        with workload_context(flow.label + " deadline", flow.deadline):
                            timeout = min(timeout, remaining_time(flow.deadline))
                    if completed < len(jobs):
                        for probe in probes:
                            if not probe.active:
                                timeout = min(timeout, max(0.0, probe.next_due - time.monotonic()))
                    events = selector.select(timeout)
                    remaining_time(deadline)
                    # Never let a ready NEW batch starve ready persistent probes.
                    for key, mask in sorted(events, key=lambda event: event[0].data.probe is None):
                        flow = key.data
                        flow.step(mask)
                        if flow.done:
                            selector.unregister(flow.stream)
                            del active[flow.stream]
                            if flow.probe is None:
                                flow.stream.close()
                                completed += 1
                                new_active -= 1
                            else:
                                flow.probe.finish(flow)
                        else:
                            selector.modify(flow.stream, flow.interest(), flow)
                remaining_time(deadline)
                if completed != 192 or any(probe.exchanges == 0 for probe in probes):
                    raise RuntimeError("Learning burst did not complete every job and both probes")
                elapsed = finish_burst_phase(before, deadline)
            finally:
                for flow in active.values():
                    if flow.probe is None:
                        flow.stream.close()
    return elapsed, [(probe.exchanges, probe.maximum) for probe in probes], peak_active


def run_burst_client(address, tcp_port, udp_port):
    run_sequential_burst(address, tcp_port, udp_port)
    jobs = prepare_burst_jobs()
    # Warm both persistent probes before measuring concurrent NEW load. These
    # two initial captures are bounded too, but are not repeat-packet latency.
    deadline = time.monotonic() + BURST_NEW_FLOW_SECONDS
    with workload_context("Learning TCP probe connect", deadline):
        stream = connect_ipv4(address, tcp_port, deadline)
    with stream, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
        with workload_context("Learning TCP probe warmup", deadline):
            tcp_exchange(stream, b"burst-probe-warmup", deadline)
        with workload_context("Learning UDP probe warmup"):
            datagram.connect((address, udp_port))
            dns_exchange(datagram, 0x7000, time.monotonic() + BURST_NEW_FLOW_SECONDS)
        elapsed, stats, peak = measure_concurrent_burst(
            address, tcp_port, udp_port, stream, datagram, jobs,
        )

    print("transparent Learning concurrent burst passed in %.3fs; "
          "TCP probe %s exchanges, max %.3fs; UDP probe %s exchanges, max %.3fs; "
          "peak %s active NEW flows" % (
              elapsed, stats[0][0], stats[0][1], stats[1][0], stats[1][1], peak,
          ))


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
