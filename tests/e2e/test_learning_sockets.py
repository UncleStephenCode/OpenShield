#!/usr/bin/env python3
"""Bounded Learning workload checks using fake sockets, time, and scheduling."""

import contextlib
import importlib.util
import io
from pathlib import Path
import struct
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "learning_sockets", Path(__file__).with_name("learning-sockets.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Clock:
    def __init__(self):
        self.now = 0.0

    def advance(self, seconds):
        self.now += seconds


class EchoSocket:
    def __init__(self, clock, delay=0.0, corrupt=False):
        self.clock = clock
        self.delay = delay
        self.corrupt = corrupt
        self.frame = b""
        self.timeouts = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def connect(self, address):
        pass

    def sendall(self, frame):
        self.frame = frame

    def send(self, query):
        self.frame = (
            query[:2] + struct.pack("!HHH", 0x8180, 1, 1)
            + b"\x00" * 8 + MODULE.DNS_ANSWER
        )

    def recv(self, size):
        self.clock.advance(self.delay)
        frame, self.frame = self.frame[:size], self.frame[size:]
        return b"!" * len(frame) if self.corrupt else frame


class BurstEchoSocket:
    def __init__(self, clock, protocol, probe=False):
        self.clock, self.protocol, self.probe = clock, protocol, probe
        self.closed = False
        self.connect_code = MODULE.errno.EINPROGRESS
        self.connect_error = 0
        self.read_limit = self.send_limit = None
        self.recv_delay = 0.0
        self.corrupt = False
        self.block_send = self.block_recv = False
        self.pending = bytearray()
        self.reply = bytearray()
        self.frames = []
        self.calls = []

    def setblocking(self, value):
        self.calls.append(("setblocking", value))

    def connect_ex(self, address):
        self.calls.append(("connect", self.clock.now))
        return self.connect_code

    def connect(self, address):
        self.calls.append(("connect", self.clock.now))

    def getsockopt(self, level, option):
        self.calls.append(("SO_ERROR", self.clock.now))
        return self.connect_error

    def send(self, data):
        self.calls.append(("send", self.clock.now))
        if self.block_send:
            self.block_send = False
            raise BlockingIOError()
        count = min(len(data), self.send_limit) if self.send_limit is not None else len(data)
        piece = bytes(data[:count])
        if self.protocol == "udp":
            if count == len(data):
                self.frames.append(piece)
                response = piece[:2] + struct.pack("!HHH", 0x8180, 1, 1) + b"\x00" * 8 + MODULE.DNS_ANSWER
                self.reply.extend(b"!" * len(response) if self.corrupt else response)
        else:
            self.pending.extend(piece)
            if len(self.pending) >= 4:
                size = struct.unpack("!I", self.pending[:4])[0] + 4
                if len(self.pending) >= size:
                    frame = bytes(self.pending[:size])
                    del self.pending[:size]
                    self.frames.append(frame)
                    self.reply.extend(b"!" * len(frame) if self.corrupt else frame)
        return count

    def recv(self, size):
        self.calls.append(("recv", self.clock.now))
        self.clock.advance(self.recv_delay)
        if self.block_recv:
            self.block_recv = False
            raise BlockingIOError()
        if not self.reply:
            raise BlockingIOError()
        size = min(size, self.read_limit) if self.read_limit is not None else size
        result = bytes(self.reply[:size])
        del self.reply[:size]
        return result

    def close(self):
        self.closed = True


class FakeBurstSelector:
    def __init__(self, harness):
        self.harness = harness
        self.entries = {}
        self.closed = False
        self.peak = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True
        self.harness.clock.advance(self.harness.teardown_seconds)

    def register(self, stream, events, data):
        if self.harness.registration_error and data.probe is None:
            raise RuntimeError("registration failed")
        self.entries[stream] = (events, data)
        self.peak = max(self.peak, sum(flow.probe is None for _event, flow in self.entries.values()))

    def modify(self, stream, events, data):
        self.entries[stream] = (events, data)

    def unregister(self, stream):
        del self.entries[stream]

    def select(self, timeout):
        self.harness.clock.advance(self.harness.select_seconds)
        all_new_closed = len(self.harness.sockets) == 192 and all(s.closed for s in self.harness.sockets)
        events = []
        for stream, (mask, flow) in reversed(list(self.entries.items())):
            if self.harness.hold_probe_reply and flow.probe is not None and mask == MODULE.selectors.EVENT_READ:
                if not all_new_closed:
                    continue
                if self.harness.late_probe:
                    self.harness.clock.now = max(self.harness.clock.now, flow.deadline + 0.01)
            key = mock.Mock(fileobj=stream, events=mask, data=flow)
            events.append((key, mask))
        return events


class BurstHarness:
    def __init__(self, clock):
        self.clock = clock
        self.sockets = []
        self.probes = (BurstEchoSocket(clock, "tcp", True), BurstEchoSocket(clock, "udp", True))
        self.select_seconds = 0.002
        self.teardown_seconds = 0.0
        self.hold_probe_reply = self.late_probe = self.registration_error = False
        self.corrupt_new = False
        self.selector = FakeBurstSelector(self)

    def allocate(self, family, kind):
        stream = BurstEchoSocket(self.clock, "tcp" if kind == MODULE.socket.SOCK_STREAM else "udp")
        stream.corrupt = self.corrupt_new
        self.sockets.append(stream)
        return stream

    def run(self):
        with contextlib.redirect_stdout(io.StringIO()):
            jobs = MODULE.prepare_burst_jobs()
        with mock.patch.object(MODULE.socket, "socket", side_effect=self.allocate), \
                mock.patch.object(MODULE.selectors, "DefaultSelector", return_value=self.selector):
            return MODULE.measure_concurrent_burst("192.0.2.1", 18086, 18087, *self.probes, jobs)


class BurstWorkloadTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.time_patch = mock.patch.object(MODULE.time, "monotonic", lambda: self.clock.now)
        self.time_patch.start()
        self.addCleanup(self.time_patch.stop)

    def test_valid_sequential_first_capture_waits_do_not_consume_concurrent_budget(self):
        flows = []

        def first_capture(*args, deadline):
            flows.append(deadline)
            self.clock.advance(0.25)
            MODULE.remaining_time(deadline)

        stream, datagram = EchoSocket(self.clock, 0.25), EchoSocket(self.clock, 0.25)
        with mock.patch.object(MODULE, "tcp_round_trips", side_effect=first_capture), \
                mock.patch.object(MODULE, "dns_round_trips", side_effect=first_capture), \
                mock.patch.object(MODULE, "connect_ipv4", return_value=stream), \
                mock.patch.object(MODULE.socket, "socket", return_value=datagram), \
                mock.patch.object(MODULE, "measure_concurrent_burst",
                                  return_value=(0.75, [(5, 0.01), (5, 0.01)], 64)) as concurrent, \
                contextlib.redirect_stdout(io.StringIO()):
            MODULE.run_burst_client("192.0.2.1", 18086, 18087)
        self.assertEqual(len(flows), 24)
        self.assertEqual(self.clock.now, 6.5)
        concurrent.assert_called_once()

    def test_sequential_new_flow_deadline_is_not_renewed(self):
        with mock.patch.object(MODULE, "connect_ipv4", return_value=EchoSocket(self.clock, 1.01)):
            with self.assertRaisesRegex(TimeoutError, "deadline expired"):
                MODULE.run_sequential_burst("192.0.2.1", 18086, 18087)

    def test_payload_corruption_and_socket_timeout_are_not_masked(self):
        for protocol in ("tcp", "udp"):
            with self.subTest(protocol=protocol):
                stream = EchoSocket(self.clock, corrupt=True)
                exchange = MODULE.tcp_exchange if protocol == "tcp" else MODULE.dns_exchange
                payload = b"probe" if protocol == "tcp" else 0x7000
                with self.assertRaises(RuntimeError):
                    exchange(stream, payload, 1.0)
                with mock.patch.object(stream, "recv", side_effect=TimeoutError("socket stalled")):
                    with self.assertRaisesRegex(TimeoutError, "socket stalled"):
                        exchange(stream, payload, 1.0)

    def test_fragmented_reply_cannot_renew_absolute_deadline(self):
        stream = EchoSocket(self.clock)

        def fragment(size):
            self.clock.advance(0.4)
            return b"x"

        with mock.patch.object(stream, "recv", side_effect=fragment):
            with self.assertRaisesRegex(TimeoutError, "deadline expired"):
                MODULE.receive_exact(stream, 4, 1.0)
        self.assertEqual(len(stream.timeouts), 3)

    def test_python39_socket_timeout_preserves_timeout_classification(self):
        class LegacySocketTimeout(OSError):
            pass
        with mock.patch.object(MODULE.socket, "timeout", LegacySocketTimeout):
            with self.assertRaisesRegex(TimeoutError, "UDP reply.*timed out"):
                with MODULE.workload_context("UDP reply", 1.0):
                    raise LegacySocketTimeout("timed out")

    def test_direct_ipv4_connect_avoids_resolution_and_keeps_absolute_budget(self):
        stream = mock.Mock()

        def allocate(*args):
            self.clock.advance(0.3)
            return stream

        with mock.patch.object(MODULE.socket, "socket", side_effect=allocate) as factory, \
                mock.patch.object(MODULE.socket, "getaddrinfo", side_effect=AssertionError("DNS lookup")):
            self.assertIs(MODULE.connect_ipv4("192.0.2.1", 18086, 1.0), stream)
        factory.assert_called_once_with(MODULE.socket.AF_INET, MODULE.socket.SOCK_STREAM)
        self.assertAlmostEqual(stream.settimeout.call_args.args[0], 0.7)

    def test_direct_ipv4_connect_cannot_succeed_after_deadline(self):
        stream = mock.Mock()
        stream.connect.side_effect = lambda address: self.clock.advance(1.01)
        with mock.patch.object(MODULE.socket, "socket", return_value=stream):
            with self.assertRaises(TimeoutError):
                MODULE.connect_ipv4("192.0.2.1", 18086, 1.0)
        stream.close.assert_called_once()

    def test_direct_ipv4_connect_failure_closes_socket(self):
        stream = mock.Mock()
        stream.connect.side_effect = ConnectionError("connect failed")
        with mock.patch.object(MODULE.socket, "socket", return_value=stream):
            with self.assertRaises(ConnectionError):
                MODULE.connect_ipv4("192.0.2.1", 18086, 1.0)
        stream.close.assert_called_once()

    def test_preparation_has_all_192_jobs_and_sends_no_packets(self):
        with mock.patch.object(MODULE.socket, "socket", side_effect=AssertionError("socket in setup")), \
                contextlib.redirect_stdout(io.StringIO()):
            jobs = MODULE.prepare_burst_jobs()
        self.assertEqual({(protocol, index) for protocol, index, _frames in jobs},
                         {(protocol, index) for protocol in ("tcp", "udp") for index in range(96)})
        self.assertTrue(all(len(frames) == (3 if protocol == "tcp" else 2)
                            for protocol, _index, frames in jobs))

    def test_selector_completes_all_jobs_with_64_new_slots_and_repeated_probes(self):
        harness = BurstHarness(self.clock)
        elapsed, stats, peak = harness.run()
        self.assertLess(elapsed, 6.0)
        self.assertEqual(peak, 64)
        self.assertEqual(harness.selector.peak, 64)
        self.assertEqual(len(harness.sockets), 192)
        self.assertTrue(all(stream.closed for stream in harness.sockets))
        self.assertTrue(all(len(stream.frames) == (3 if stream.protocol == "tcp" else 2)
                            for stream in harness.sockets))
        self.assertTrue(all(count > 1 and maximum < 1.0 for count, maximum in stats))
        for probe in harness.probes:
            sends = [value for name, value in probe.calls if name == "send"]
            self.assertTrue(all(later - earlier >= 0.01 for earlier, later in zip(sends, sends[1:])))

    def test_preparation_and_selector_teardown_are_outside_active_clock(self):
        self.clock.advance(4.5)
        harness = BurstHarness(self.clock)
        harness.teardown_seconds = 10.0
        elapsed, _stats, _peak = harness.run()
        self.assertLess(elapsed, 1.0)
        self.assertGreater(self.clock.now, 14.5)
        self.assertTrue(all(value >= 4.5 for stream in harness.sockets
                            for name, value in stream.calls if name in ("connect", "send")))

    def test_phase_and_finished_boundary_are_still_strictly_bounded(self):
        harness = BurstHarness(self.clock)
        harness.select_seconds = 6.01
        with self.assertRaisesRegex(TimeoutError, "phase"):
            harness.run()
        self.assertTrue(all(stream.closed for stream in harness.sockets))
        self.clock.now = 6.0
        self.assertEqual(MODULE.finish_burst_phase(0.0, 6.0), 6.0)
        self.clock.now = 6.0001
        with self.assertRaises(TimeoutError):
            MODULE.finish_burst_phase(0.0, 6.0)

    def test_corrupt_inflight_probe_cannot_be_discarded_after_last_new_job(self):
        harness = BurstHarness(self.clock)
        harness.hold_probe_reply = True
        harness.probes[0].corrupt = True
        with self.assertRaisesRegex(RuntimeError, "tcp probe.*reply did not match"):
            harness.run()
        self.assertEqual(len(harness.sockets), 192)
        self.assertTrue(all(stream.closed for stream in harness.sockets))

    def test_overdue_inflight_probe_fails_after_last_new_job_before_six_seconds(self):
        harness = BurstHarness(self.clock)
        harness.hold_probe_reply = harness.late_probe = True
        with self.assertRaisesRegex(TimeoutError, "probe"):
            harness.run()
        self.assertEqual(len(harness.sockets), 192)
        self.assertLess(self.clock.now, 6.0)

    def test_new_socket_and_registration_failures_close_every_owned_socket(self):
        for registration in (False, True):
            harness = BurstHarness(self.clock)
            harness.registration_error = registration
            harness.corrupt_new = not registration
            with self.assertRaises(RuntimeError):
                harness.run()
            self.assertTrue(all(stream.closed for stream in harness.sockets))
            self.assertTrue(harness.selector.closed)
            self.assertTrue(all(not stream.closed for stream in harness.probes))

    def test_new_deadline_starts_before_socket_allocation(self):
        stream = BurstEchoSocket(self.clock, "tcp")

        def allocate(*args):
            self.clock.advance(1.01)
            return stream

        with mock.patch.object(MODULE.socket, "socket", side_effect=allocate):
            with self.assertRaisesRegex(TimeoutError, "NEW tcp job 4.*deadline"):
                MODULE.BurstFlow.open_new("192.0.2.1", 18086, 18087,
                    ("tcp", 4, (MODULE.tcp_frame(b"x"),) * 3), 6.0)
        self.assertTrue(stream.closed)

    def test_connect_writability_checks_so_error_before_sending(self):
        stream = BurstEchoSocket(self.clock, "tcp")
        stream.connect_error = MODULE.errno.ECONNREFUSED
        with mock.patch.object(MODULE.socket, "socket", return_value=stream):
            flow = MODULE.BurstFlow.open_new("192.0.2.1", 18086, 18087,
                ("tcp", 4, (MODULE.tcp_frame(b"x"),) * 3), 6.0)
        with self.assertRaisesRegex(RuntimeError, "connect"):
            flow.step(MODULE.selectors.EVENT_WRITE)
        self.assertTrue(any(name == "SO_ERROR" for name, _value in stream.calls))
        self.assertEqual(stream.frames, [])

    def test_partial_tcp_io_and_would_block_keep_every_exchange(self):
        stream = BurstEchoSocket(self.clock, "tcp")
        stream.send_limit = 2
        stream.read_limit = 1
        stream.block_send = stream.block_recv = True
        requests = (MODULE.tcp_frame(b"one"), MODULE.tcp_frame(b"two"), MODULE.tcp_frame(b"three"))
        flow = MODULE.BurstFlow(stream, "tcp", requests, 0.0, 1.0, "NEW tcp job 0")
        for _ in range(100):
            if flow.done:
                break
            flow.step(flow.interest())
        self.assertTrue(flow.done)
        self.assertEqual(tuple(stream.frames), requests)
        self.assertEqual(flow.deadline, 1.0)

    def test_three_tcp_replies_share_one_absolute_deadline_including_validation(self):
        stream = BurstEchoSocket(self.clock, "tcp")
        stream.recv_delay = 0.4
        flow = MODULE.BurstFlow(stream, "tcp", (MODULE.tcp_frame(b"x"),) * 3,
                                0.0, 1.0, "NEW tcp job 0")
        with self.assertRaisesRegex(TimeoutError, "exchange 2 reply"):
            for _ in range(6):
                flow.step(flow.interest())
        self.assertEqual(flow.deadline, 1.0)

    def test_short_udp_send_and_wrong_transaction_are_failures(self):
        for short_send in (False, True):
            stream = BurstEchoSocket(self.clock, "udp")
            stream.send_limit = 1 if short_send else None
            stream.corrupt = not short_send
            request = MODULE.dns_query(0x5000, "5000")
            flow = MODULE.BurstFlow(stream, "udp", (request,) * 2, 0.0, 1.0, "NEW udp job 0")
            with self.assertRaises(RuntimeError):
                flow.step(MODULE.selectors.EVENT_WRITE)
                flow.step(MODULE.selectors.EVENT_READ)

    def test_probe_latency_and_pause_use_one_checked_finish_timestamp(self):
        probe = MODULE.BurstProbe(BurstEchoSocket(self.clock, "tcp"), "tcp")
        flow = probe.start(6.0)
        self.clock.now = 1.01
        with self.assertRaisesRegex(TimeoutError, "one-second"):
            probe.finish(flow)
        self.assertEqual(probe.exchanges, 0)

    def test_udp_peer_does_not_start_a_thread_for_each_datagram(self):
        self.assertFalse(issubclass(MODULE.DatagramServer, MODULE.socketserver.ThreadingMixIn))


class PeerSocket:
    def __init__(self, chunks=(), sends=()):
        self.chunks = list(chunks)
        self.sends = list(sends)
        self.written = bytearray()
        self.read_sizes = []

    def recv(self, size):
        self.read_sizes.append(size)
        if not self.chunks or self.chunks[0] is None:
            if self.chunks:
                self.chunks.pop(0)
            raise BlockingIOError()
        chunk = self.chunks.pop(0)
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
        return chunk[:size]

    def send(self, data):
        size = self.sends.pop(0) if self.sends else len(data)
        if size is None:
            raise BlockingIOError()
        size = min(size, len(data))
        self.written.extend(data[:size])
        return size


class TcpPeerTests(unittest.TestCase):
    READ = MODULE.selectors.EVENT_READ
    WRITE = MODULE.selectors.EVENT_WRITE

    def test_fragmented_and_coalesced_frames_are_echoed_exactly(self):
        first = struct.pack("!I", 5) + b"first"
        second = struct.pack("!I", 6) + b"second"
        stream = PeerSocket((first[:2], first[2:6], first[6:] + second, b""))
        connection = MODULE.TcpPeerConnection(stream, 0.0)
        for _ in range(3):
            connection.handle(self.READ, 0.1)
        self.assertEqual(bytes(stream.written), first)
        self.assertEqual(connection.interest(), self.WRITE)
        connection.handle(self.WRITE, 0.2)
        self.assertEqual(bytes(stream.written), first + second)
        connection.handle(self.READ, 0.3)
        self.assertTrue(connection.closed)

    def test_invalid_and_truncated_frames_do_not_produce_a_reply(self):
        for data, error in ((struct.pack("!I", 0), ValueError),
                            (struct.pack("!I", MODULE.MAX_FRAME_BYTES + 1), ValueError),
                            (b"\x00\x00", ConnectionError),
                            (struct.pack("!I", 5) + b"x", ConnectionError)):
            with self.subTest(data=data):
                stream = PeerSocket((data, b""))
                connection = MODULE.TcpPeerConnection(stream, 0.0)
                with self.assertRaises(error):
                    connection.handle(self.READ, 0.1)
                    connection.handle(self.READ, 0.2)
                self.assertEqual(stream.written, b"")

    def test_partial_send_and_would_block_preserve_the_complete_reply(self):
        frame = struct.pack("!I", 5) + b"hello"
        stream = PeerSocket((None, frame), sends=(3, None, 6))
        connection = MODULE.TcpPeerConnection(stream, 0.0)
        connection.handle(self.READ, 0.1)
        self.assertEqual(stream.written, b"")
        connection.handle(self.READ, 0.2)
        self.assertEqual(bytes(stream.written), frame[:3])
        connection.handle(self.WRITE, 0.3)
        self.assertEqual(bytes(connection.outgoing), frame[3:])
        connection.handle(self.WRITE, 0.4)
        self.assertEqual(bytes(stream.written), frame)
        self.assertEqual(connection.interest(), self.READ)

    def test_backpressured_reply_bounds_both_buffers_and_stops_reading(self):
        frame = struct.pack("!I", MODULE.MAX_FRAME_BYTES) + b"x" * MODULE.MAX_FRAME_BYTES
        stream = PeerSocket((frame + frame,), sends=(None, None))
        connection = MODULE.TcpPeerConnection(stream, 0.0)
        connection.handle(self.READ, 0.1)
        connection.handle(self.READ, 0.2)
        self.assertEqual(stream.read_sizes, [MODULE.MAX_FRAME_BYTES + 4])
        self.assertEqual(len(connection.outgoing), MODULE.MAX_FRAME_BYTES + 4)
        self.assertLessEqual(len(connection.incoming), MODULE.MAX_FRAME_BYTES + 4)
        self.assertEqual(stream.written, b"")

    def test_partial_progress_does_not_renew_frame_or_write_deadline(self):
        for chunks, sends in (((b"\x00",), ()),
                               ((struct.pack("!I", 1) + b"x",), (1,))):
            connection = MODULE.TcpPeerConnection(PeerSocket(chunks, sends), 0.0)
            connection.handle(self.READ, 4.9)
            self.assertEqual(connection.deadline, 5.0)
            with self.assertRaisesRegex(TimeoutError, "frame/idle deadline"):
                connection.handle(connection.interest(), 5.0)

    def test_zero_length_send_is_a_connection_failure(self):
        connection = MODULE.TcpPeerConnection(PeerSocket((struct.pack("!I", 1) + b"x",), (0,)), 0.0)
        with self.assertRaises(ConnectionError):
            connection.handle(self.READ, 0.1)

    def test_peer_connection_limit_closes_excess_without_registering(self):
        server = object.__new__(MODULE.SelectorTcpServer)
        server.clients = {index: object() for index in range(MODULE.MAX_PEER_CONNECTIONS)}
        stream = mock.Mock()
        server.socket = mock.Mock()
        server.socket.accept.side_effect = [(stream, ("192.0.2.1", 10000)), BlockingIOError()]
        selector = mock.Mock()
        server.accept_ready(selector)
        stream.close.assert_called_once()
        selector.register.assert_not_called()

    def test_accepted_socket_is_nonblocking_and_keeps_tcp_nodelay(self):
        server = object.__new__(MODULE.SelectorTcpServer)
        server.clients = {}
        stream = mock.Mock()
        server.socket = mock.Mock()
        server.socket.accept.side_effect = [(stream, ("192.0.2.1", 10000)), BlockingIOError()]
        selector = mock.Mock()
        server.accept_ready(selector)
        stream.setblocking.assert_called_once_with(False)
        stream.setsockopt.assert_called_once_with(MODULE.socket.IPPROTO_TCP, MODULE.socket.TCP_NODELAY, 1)
        self.assertIn(stream, server.clients)
        selector.register.assert_called_once_with(stream, self.READ, server.clients[stream])

    def test_tcp_ready_is_set_only_after_listener_registration(self):
        server = object.__new__(MODULE.SelectorTcpServer)
        server.socket = object()
        server.clients = {}
        server.ready = mock.Mock()
        selector = mock.Mock()
        selector.register.side_effect = lambda *args: server.ready.set.assert_not_called()
        selector.select.side_effect = RuntimeError("stop test loop")
        with self.assertRaisesRegex(RuntimeError, "stop test loop"):
            server.run(selector)
        selector.register.assert_called_once_with(server.socket, self.READ)
        server.ready.set.assert_called_once()

    def test_expired_idle_connection_is_unregistered_and_closed(self):
        stream = mock.Mock()
        connection = MODULE.TcpPeerConnection(stream, 0.0)
        server = object.__new__(MODULE.SelectorTcpServer)
        server.socket = object()
        server.clients = {stream: connection}
        server.ready = mock.Mock()
        selector = mock.Mock()
        selector.select.side_effect = RuntimeError("stop test loop")
        with mock.patch.object(MODULE.time, "monotonic", return_value=5.0):
            with self.assertRaisesRegex(RuntimeError, "stop test loop"):
                server.run(selector)
        selector.unregister.assert_called_once_with(stream)
        stream.close.assert_called_once()
        self.assertEqual(server.clients, {})


if __name__ == "__main__":
    unittest.main()
