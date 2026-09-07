#!/usr/bin/env python3
"""Bounded TCP request/response server and production-like workload client."""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import math
import random
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from common import (  # type: ignore
        MAX_CONCURRENCY,
        MAX_CPS,
        MAX_INFLIGHT_MEMORY_BYTES,
        MAX_MBPS,
        MAX_PPS,
        MAX_SERVER_WORKERS,
        MAX_TCP_BODY_BYTES,
        AsyncMultiRateLimiter,
        WeightedMix,
        WorkBudget,
        WorkloadStats,
        apply_config_file,
        announce_control_process,
        base_client_arguments,
        base_server_arguments,
        bounded_mix_converter,
        bounded_float,
        bounded_int,
        deterministic_payload,
        emit_json,
        endpoint_port,
        install_stop_handlers,
        mix_converter,
        recv_exact,
        require_safe_bind,
        safe_error,
        socket_address,
        wait_for_start_gate,
        wait_for_release_gate,
    )
else:
    from .common import (
        MAX_CONCURRENCY,
        MAX_CPS,
        MAX_INFLIGHT_MEMORY_BYTES,
        MAX_MBPS,
        MAX_PPS,
        MAX_SERVER_WORKERS,
        MAX_TCP_BODY_BYTES,
        AsyncMultiRateLimiter,
        WeightedMix,
        WorkBudget,
        WorkloadStats,
        apply_config_file,
        announce_control_process,
        base_client_arguments,
        base_server_arguments,
        bounded_mix_converter,
        bounded_float,
        bounded_int,
        deterministic_payload,
        emit_json,
        endpoint_port,
        install_stop_handlers,
        mix_converter,
        recv_exact,
        require_safe_bind,
        safe_error,
        socket_address,
        wait_for_start_gate,
        wait_for_release_gate,
    )


VERSION = 1
REQUEST_MAGIC = b"OSPF"
RESPONSE_MAGIC = b"OSPR"
FLAG_CLOSE = 0x01
REQUEST_HEADER = struct.Struct("!4sBBHIIQQ")
RESPONSE_HEADER = struct.Struct("!4sBBHIQQQQ")
LISTEN_POLL_SECONDS = 0.2
ERROR_BACKOFF_SECONDS = 0.01
MAX_HTTP_HEADER_BYTES = 8 * 1024
MIN_CONNECTION_LIFETIME_MS = 50
MAX_CONNECTION_LIFETIME_MS = 3_600_000
CONNECTION_LIFETIME_SEED_DOMAIN = 0x434F4E4E4C494645
HTTP_TOKEN_CHARACTERS = frozenset(
    "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
TCP_CLIENT_CONFIG_FIELDS = (
    "host",
    "port",
    "duration",
    "operations",
    "seed",
    "pps",
    "cps",
    "mbps",
    "io_timeout",
    "latency_samples",
    "concurrency",
    "mode",
    "keepalive_ratio",
    "connection_lifetime_ms_mix",
    "request_bytes",
    "response_bytes",
    "response_mix",
    "protocol",
    "mss",
)


@dataclass(frozen=True)
class TcpServerConfig:
    host: str
    port: int
    duration: float
    seed: int
    io_timeout: float
    processing_delay_ms: float
    workers: int
    backlog: int
    max_request_bytes: int
    max_response_bytes: int
    protocol: str = "http1"
    allow_non_loopback: bool = False


@dataclass(frozen=True)
class TcpClientConfig:
    host: str
    port: int
    duration: float
    operations: int
    seed: int
    pps: float
    cps: float
    mbps: float
    io_timeout: float
    latency_samples: int
    concurrency: int
    mode: str
    keepalive_ratio: float
    request_bytes: int
    response_mix: WeightedMix
    protocol: str = "http1"
    mss: int = 1460
    connection_lifetime_ms_mix: WeightedMix = field(
        default_factory=lambda: WeightedMix.fixed(MAX_CONNECTION_LIFETIME_MS)
    )


def _recv_header_or_eof(connection: socket.socket) -> Optional[bytes]:
    first = connection.recv(1)
    if not first:
        return None
    return first + recv_exact(connection, REQUEST_HEADER.size - 1)


def _recv_http_header(
    connection: socket.socket, buffered: bytes
) -> tuple[Optional[bytes], bytes]:
    delimiter = b"\r\n\r\n"
    while delimiter not in buffered:
        if len(buffered) >= MAX_HTTP_HEADER_BYTES:
            raise ValueError("HTTP request header is too large")
        chunk = connection.recv(min(4096, MAX_HTTP_HEADER_BYTES - len(buffered)))
        if not chunk:
            if buffered:
                raise ConnectionError("peer closed during the HTTP request header")
            return None, b""
        buffered += chunk
    header, remainder = buffered.split(delimiter, 1)
    if len(header) + len(delimiter) > MAX_HTTP_HEADER_BYTES:
        raise ValueError("HTTP request header is too large")
    return header, remainder


def _parse_http_head(encoded: bytes) -> tuple[str, dict[str, str]]:
    try:
        lines = encoded.decode("ascii").split("\r\n")
    except UnicodeDecodeError as error:
        raise ValueError("HTTP header must be ASCII") from error
    if not lines or not lines[0]:
        raise ValueError("HTTP start line is missing")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            raise ValueError("malformed HTTP header")
        name, value = line.split(":", 1)
        name = name.strip().lower()
        value = value.strip()
        if not name or any(
            character not in HTTP_TOKEN_CHARACTERS for character in name
        ):
            raise ValueError("invalid HTTP header name")
        if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
            raise ValueError("invalid HTTP header value")
        if name in headers:
            raise ValueError("empty or duplicate HTTP header")
        headers[name] = value
    return lines[0], headers


def _bounded_decimal(headers: dict[str, str], name: str, maximum: int) -> int:
    value = headers.get(name)
    if value is None or not value.isascii() or not value.isdecimal() or len(value) > 20:
        raise ValueError(f"missing or invalid HTTP header: {name}")
    parsed = int(value, 10)
    if parsed > maximum:
        raise ValueError(f"HTTP header exceeds its bound: {name}")
    return parsed


def _http_request_header(
    host: str,
    request_size: int,
    response_size: int,
    request_id: int,
    client_send_ns: int,
    close: bool,
) -> bytes:
    connection = "close" if close else "keep-alive"
    authority = f"[{host}]" if ":" in host else host
    return (
        f"POST /bytes/{response_size} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        f"Connection: {connection}\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"Content-Length: {request_size}\r\n"
        f"X-OpenShield-Request-Id: {request_id:020d}\r\n"
        f"X-OpenShield-Sent-Ns: {client_send_ns:020d}\r\n"
        "\r\n"
    ).encode("ascii")


def _http_response_header(
    response_size: int,
    request_id: int,
    client_send_ns: int,
    server_receive_ns: int,
    server_send_ns: int,
    close: bool,
) -> bytes:
    connection = "close" if close else "keep-alive"
    return (
        "HTTP/1.1 200 OK\r\n"
        f"Content-Length: {response_size}\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"Connection: {connection}\r\n"
        f"X-OpenShield-Request-Id: {request_id:020d}\r\n"
        f"X-OpenShield-Sent-Ns: {client_send_ns:020d}\r\n"
        f"X-OpenShield-Server-Receive-Ns: {server_receive_ns:020d}\r\n"
        f"X-OpenShield-Server-Send-Ns: {server_send_ns:020d}\r\n"
        "\r\n"
    ).encode("ascii")


class TcpWorkloadServer:
    """A bounded real-socket TCP server suitable for a separate process."""

    def __init__(self, config: TcpServerConfig, stop: Optional[threading.Event] = None):
        require_safe_bind(config.host, config.allow_non_loopback)
        estimated_request_memory = config.workers * config.max_request_bytes * 2
        if (
            estimated_request_memory + config.max_response_bytes
            > MAX_INFLIGHT_MEMORY_BYTES
        ):
            raise ValueError("TCP server in-flight body memory exceeds the safety bound")
        if config.protocol not in ("http1", "framed"):
            raise ValueError("unsupported TCP workload protocol")
        self.config = config
        self.stop = stop or threading.Event()
        self.ready = threading.Event()
        self.bound_port: Optional[int] = None
        self.fatal_error: Optional[BaseException] = None
        self.stats = WorkloadStats(config.seed)
        self._slots = threading.BoundedSemaphore(config.workers)
        self._connections: set[socket.socket] = set()
        self._connections_lock = threading.Lock()
        self._response_payload = deterministic_payload(
            config.max_response_bytes, config.seed, 0x54504353
        )

    def run(self, on_ready: Optional[Callable[[int], None]] = None) -> dict:
        family, address = socket_address(self.config.host, self.config.port)
        deadline = time.monotonic() + self.config.duration
        listener: Optional[socket.socket] = None
        try:
            listener = socket.socket(family, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(address)
            listener.listen(self.config.backlog)
            listener.settimeout(LISTEN_POLL_SECONDS)
            self.bound_port = endpoint_port(listener)
            self.ready.set()
            if on_ready is not None:
                on_ready(self.bound_port)
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.config.workers,
                thread_name_prefix="openshield-perf-tcp",
            ) as executor:
                try:
                    while not self.stop.is_set() and time.monotonic() < deadline:
                        try:
                            connection, _peer = listener.accept()
                        except socket.timeout:
                            continue
                        except OSError:
                            if self.stop.is_set():
                                break
                            raise
                        if not self._slots.acquire(blocking=False):
                            self.stats.add(connections_rejected=1)
                            connection.close()
                            continue
                        with self._connections_lock:
                            self._connections.add(connection)
                        self.stats.add(connections=1)
                        self.stats.active_change(1)
                        try:
                            executor.submit(self._serve_connection, connection)
                        except BaseException:
                            with self._connections_lock:
                                self._connections.discard(connection)
                            connection.close()
                            self.stats.active_change(-1)
                            self._slots.release()
                            raise
                finally:
                    self.stop.set()
                    self._shutdown_connections()
        except BaseException as error:
            self.fatal_error = error
            raise
        finally:
            self.stop.set()
            self.ready.set()
            if listener is not None:
                listener.close()
        return self.stats.summary()

    def _shutdown_connections(self) -> None:
        with self._connections_lock:
            connections = tuple(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _serve_connection(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(self.config.io_timeout)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self.config.protocol == "http1":
                self._serve_http_connection(connection)
            else:
                self._serve_framed_connection(connection)
        except Exception:
            # Futures are intentionally not retained, so make unexpected worker
            # failures visible in the bounded summary rather than losing them.
            self.stats.add(internal_errors=1)
        finally:
            connection.close()
            with self._connections_lock:
                self._connections.discard(connection)
            self.stats.add(connections_closed=1)
            self.stats.active_change(-1)
            self._slots.release()

    def _serve_framed_connection(self, connection: socket.socket) -> None:
        while not self.stop.is_set():
            try:
                encoded_header = _recv_header_or_eof(connection)
            except socket.timeout:
                self.stats.add(idle_timeouts=1)
                break
            except (ConnectionError, OSError, ValueError):
                if not self.stop.is_set():
                    self.stats.add(protocol_errors=1)
                break
            if encoded_header is None:
                break
            request_started = time.monotonic()
            try:
                (
                    magic,
                    version,
                    flags,
                    reserved,
                    request_size,
                    response_size,
                    request_id,
                    client_send_ns,
                ) = REQUEST_HEADER.unpack(encoded_header)
                if (
                    magic != REQUEST_MAGIC
                    or version != VERSION
                    or reserved != 0
                    or flags & ~FLAG_CLOSE
                    or request_size > self.config.max_request_bytes
                    or response_size > self.config.max_response_bytes
                ):
                    raise ValueError("invalid or oversized TCP workload request")
                recv_exact(connection, request_size)
                server_receive_ns = time.monotonic_ns()
                self.stats.add(bytes_received=REQUEST_HEADER.size + request_size)
                if self.config.processing_delay_ms > 0 and self.stop.wait(
                    self.config.processing_delay_ms / 1_000.0
                ):
                    break
                server_send_ns = time.monotonic_ns()
                response_header = RESPONSE_HEADER.pack(
                    RESPONSE_MAGIC,
                    VERSION,
                    0,
                    0,
                    response_size,
                    request_id,
                    client_send_ns,
                    server_receive_ns,
                    server_send_ns,
                )
                connection.sendall(response_header)
                if response_size:
                    connection.sendall(memoryview(self._response_payload)[:response_size])
                self.stats.add(
                    operations=1,
                    bytes_sent=RESPONSE_HEADER.size + response_size,
                )
                self.stats.latency_ms.record(
                    (time.monotonic() - request_started) * 1_000.0
                )
                if flags & FLAG_CLOSE:
                    break
            except (ConnectionError, OSError, ValueError, struct.error):
                if not self.stop.is_set():
                    self.stats.add(protocol_errors=1)
                break

    def _serve_http_connection(self, connection: socket.socket) -> None:
        buffered = b""
        while not self.stop.is_set():
            try:
                encoded_header, buffered = _recv_http_header(connection, buffered)
            except socket.timeout:
                self.stats.add(idle_timeouts=1)
                break
            except (ConnectionError, OSError, ValueError):
                if not self.stop.is_set():
                    self.stats.add(protocol_errors=1)
                break
            if encoded_header is None:
                break
            request_started = time.monotonic()
            try:
                start_line, headers = _parse_http_head(encoded_header)
                components = start_line.split(" ")
                if len(components) != 3 or components[0] != "POST" or components[2] != "HTTP/1.1":
                    raise ValueError("unsupported HTTP request line")
                prefix = "/bytes/"
                raw_size = components[1][len(prefix):] if components[1].startswith(prefix) else ""
                if not raw_size.isascii() or not raw_size.isdecimal() or len(raw_size) > 10:
                    raise ValueError("invalid HTTP response-size endpoint")
                response_size = int(raw_size, 10)
                request_size = _bounded_decimal(
                    headers, "content-length", self.config.max_request_bytes
                )
                request_id = _bounded_decimal(
                    headers, "x-openshield-request-id", 2**64 - 1
                )
                client_send_ns = _bounded_decimal(
                    headers, "x-openshield-sent-ns", 2**64 - 1
                )
                if response_size > self.config.max_response_bytes:
                    raise ValueError("HTTP response size exceeds the server bound")
                connection_header = headers.get("connection", "").lower()
                if connection_header not in ("close", "keep-alive"):
                    raise ValueError("HTTP Connection must be close or keep-alive")
                if not headers.get("host"):
                    raise ValueError("HTTP Host is required")
                if "transfer-encoding" in headers:
                    raise ValueError("HTTP Transfer-Encoding is not supported")
                if len(buffered) >= request_size:
                    buffered = buffered[request_size:]
                else:
                    remaining = request_size - len(buffered)
                    buffered = b""
                    while remaining:
                        chunk = connection.recv(min(64 * 1024, remaining))
                        if not chunk:
                            raise ConnectionError(
                                "peer closed during HTTP request body"
                            )
                        remaining -= len(chunk)
                server_receive_ns = time.monotonic_ns()
                self.stats.add(
                    bytes_received=len(encoded_header) + 4 + request_size
                )
                close = connection_header == "close"
                if self.config.processing_delay_ms > 0 and self.stop.wait(
                    self.config.processing_delay_ms / 1_000.0
                ):
                    break
                server_send_ns = time.monotonic_ns()
                response_header = _http_response_header(
                    response_size,
                    request_id,
                    client_send_ns,
                    server_receive_ns,
                    server_send_ns,
                    close,
                )
                connection.sendall(response_header)
                if response_size:
                    connection.sendall(memoryview(self._response_payload)[:response_size])
                self.stats.add(
                    operations=1,
                    bytes_sent=len(response_header) + response_size,
                )
                self.stats.latency_ms.record(
                    (time.monotonic() - request_started) * 1_000.0
                )
                if close:
                    break
            except (ConnectionError, OSError, ValueError, struct.error):
                if not self.stop.is_set():
                    self.stats.add(protocol_errors=1)
                break


class TcpWorkloadClient:
    """One-thread event-loop client with many independent real TCP sockets."""

    def __init__(self, config: TcpClientConfig, stop: Optional[threading.Event] = None):
        if config.mode not in ("keepalive", "short", "mixed"):
            raise ValueError("TCP client workload mode is unsupported")
        if (
            not isinstance(config.concurrency, int)
            or isinstance(config.concurrency, bool)
            or not 1 <= config.concurrency <= MAX_CONCURRENCY
        ):
            raise ValueError("TCP client concurrency is outside the safety bound")
        for name, value, maximum in (
            ("pps", config.pps, MAX_PPS),
            ("cps", config.cps, MAX_CPS),
            ("mbps", config.mbps, MAX_MBPS),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or not 0.0 <= float(value) <= maximum
            ):
                raise ValueError(f"TCP client {name} is outside the safety bound")
        if (
            isinstance(config.keepalive_ratio, bool)
            or not isinstance(config.keepalive_ratio, (int, float))
            or not math.isfinite(float(config.keepalive_ratio))
            or not 0.0 <= float(config.keepalive_ratio) <= 1.0
        ):
            raise ValueError("TCP client keepalive ratio is outside the safety bound")
        estimated_flow_memory = (
            config.request_bytes + config.response_mix.maximum_value * 2
        )
        if config.concurrency * estimated_flow_memory > MAX_INFLIGHT_MEMORY_BYTES:
            raise ValueError("TCP client in-flight body memory exceeds the safety bound")
        if config.protocol not in ("http1", "framed"):
            raise ValueError("unsupported TCP workload protocol")
        if any(
            isinstance(entry.value, bool)
            or not isinstance(entry.value, int)
            or not MIN_CONNECTION_LIFETIME_MS
            <= entry.value
            <= MAX_CONNECTION_LIFETIME_MS
            for entry in config.connection_lifetime_ms_mix.entries
        ):
            raise ValueError(
                "connection lifetime must be an integer between "
                f"{MIN_CONNECTION_LIFETIME_MS} and {MAX_CONNECTION_LIFETIME_MS} ms"
            )
        self.config = config
        self.stop = stop or threading.Event()
        self.stats = WorkloadStats(config.seed, config.latency_samples)
        self.budget = WorkBudget(config.operations)
        self.deadline = time.monotonic() + config.duration
        self.limiter = AsyncMultiRateLimiter(
            {
                "packets": config.pps,
                "connections": config.cps,
                "bytes": config.mbps * 1_000_000.0 / 8.0,
            },
            self.stats.scheduler_lag_ms,
        )
        self._family, _address = socket_address(config.host, config.port)

    def arm(self) -> int:
        """Reset time-based state after the external measurement gate opens."""

        self.deadline = time.monotonic() + self.config.duration
        self.limiter.arm()
        return self.stats.arm()

    def _connection_lifetime_generator(self, worker_id: int) -> random.Random:
        """Return a deterministic RNG isolated from payload/response selection."""

        seed = (
            self.config.seed
            ^ CONNECTION_LIFETIME_SEED_DOMAIN
            ^ ((worker_id + 1) * 0x9E3779B97F4A7C15)
        ) & ((1 << 64) - 1)
        return random.Random(seed)

    def _new_connection_expiry(
        self, generator: random.Random, connected_at: float
    ) -> tuple[float, int]:
        lifetime_ms = self.config.connection_lifetime_ms_mix.choose(generator)
        return connected_at + lifetime_ms / 1_000.0, lifetime_ms

    @staticmethod
    def _connection_expired(expiry: float | None, now: float) -> bool:
        return expiry is not None and now >= expiry

    def run(self) -> dict:
        asyncio.run(self._run())
        return self.stats.summary()

    async def _run(self) -> None:
        tasks = [
            asyncio.create_task(self._worker(worker_id))
            for worker_id in range(self.config.concurrency)
        ]
        await asyncio.gather(*tasks)
        self.stop.set()

    async def _new_connection(self):
        self.stats.add(connection_attempts=1)
        started = time.monotonic_ns()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=self.config.host,
                port=self.config.port,
                family=self._family,
                limit=MAX_HTTP_HEADER_BYTES,
            ),
            timeout=self.config.io_timeout,
        )
        raw_socket = writer.get_extra_info("socket")
        try:
            if raw_socket is not None:
                raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                raw_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            await self._finish_connection(
                writer, time.monotonic() + self.config.io_timeout, abort=True
            )
            raise
        self.stats.connect_latency_ms.record(
            (time.monotonic_ns() - started) / 1_000_000.0
        )
        self.stats.add(connections=1)
        self.stats.active_change(1)
        return reader, writer

    @staticmethod
    async def _finish_connection(writer, deadline: float, *, abort: bool = False) -> bool:
        """Release a transport without extending the caller's close deadline."""

        try:
            if abort:
                writer.transport.abort()
            else:
                writer.close()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError
            await asyncio.wait_for(writer.wait_closed(), timeout=remaining)
            return True
        except (asyncio.TimeoutError, ConnectionError, OSError, RuntimeError):
            # A timed-out close must not leave a buffering transport alive as
            # the worker moves on or the phase publishes its finished event.
            try:
                writer.transport.abort()
            except (ConnectionError, OSError, RuntimeError):
                pass
            return False

    async def _close_connection(self, channel) -> None:
        """Finish a successful exchange with a bounded peer-EOF handshake.

        Local wait_closed() alone does not establish that the peer finished
        the connection. Keep the read side alive until its FIN is observed,
        accounting for this close inside the worker's measured lifetime.
        """

        if channel is None:
            return
        reader, writer = channel
        deadline = time.monotonic() + self.config.io_timeout
        peer_finished = False
        try:
            writer.write_eof()
            await asyncio.wait_for(
                writer.drain(), timeout=max(0.0, deadline - time.monotonic())
            )
            trailing = await asyncio.wait_for(
                reader.read(1), timeout=max(0.0, deadline - time.monotonic())
            )
            if trailing:
                raise ValueError("unexpected TCP data after the complete response")
            peer_finished = True
        except (asyncio.TimeoutError, ConnectionError, OSError, RuntimeError, ValueError):
            pass
        finally:
            try:
                locally_closed = await self._finish_connection(writer, deadline)
                if not peer_finished or not locally_closed:
                    self.stats.add(errors=1)
            finally:
                self.stats.active_change(-1)

    async def _abort_connection(self, channel) -> None:
        """Discard an already failed exchange without counting a second error."""

        if channel is None:
            return
        _reader, writer = channel
        deadline = time.monotonic() + self.config.io_timeout
        try:
            await self._finish_connection(writer, deadline, abort=True)
        finally:
            self.stats.active_change(-1)

    def _wire_sizes(
        self, response_size: int, request_id: int, use_keepalive: bool
    ) -> tuple[int, int]:
        if self.config.protocol == "framed":
            return (
                REQUEST_HEADER.size + self.config.request_bytes,
                RESPONSE_HEADER.size + response_size,
            )
        request_header = _http_request_header(
            self.config.host,
            self.config.request_bytes,
            response_size,
            request_id,
            0,
            not use_keepalive,
        )
        response_header = _http_response_header(
            response_size, request_id, 0, 0, 0, not use_keepalive
        )
        return (
            len(request_header) + self.config.request_bytes,
            len(response_header) + response_size,
        )

    def _estimated_packets(
        self, request_wire: int, response_wire: int, new_connection: bool, close: bool
    ) -> int:
        request_segments = max(1, (request_wire + self.config.mss - 1) // self.config.mss)
        response_segments = max(1, (response_wire + self.config.mss - 1) // self.config.mss)
        delayed_acks = (request_segments + 1) // 2 + (response_segments + 1) // 2
        return (
            request_segments
            + response_segments
            + delayed_acks
            + (3 if new_connection else 0)
            + (4 if close else 0)
        )

    def _expected_lifetime_expiration_rate(
        self, application_ops_per_second: float, keepalive_probability: float
    ) -> float:
        """Estimate persistent-connection renewal under a steady offered rate.

        Each worker receives an equal share of the aggregate operation stream.
        Treating those worker-local arrivals as a Poisson process gives a
        closed-form competing-risk model: a short request can retire a
        persistent connection before its selected lifetime, while the first
        operation after an elapsed lifetime renews it only when that operation
        is keep-alive.  This includes mixed-mode renewal without double-counting
        the short and short-to-keepalive connections already present in the
        per-operation cost model.
        """

        rate = float(application_ops_per_second)
        keepalive = float(keepalive_probability)
        if rate <= 0.0 or keepalive <= 0.0:
            return 0.0
        mean_lifetime_seconds = (
            self.config.connection_lifetime_ms_mix.weighted_mean() / 1_000.0
        )
        worker_rate = rate / self.config.concurrency
        if keepalive >= 1.0:
            # With no competing short request, a renewal cycle is its selected
            # lifetime plus the residual wait for the next worker-local
            # operation.  E[residual] is 1 / worker_rate.
            return rate / (1.0 + worker_rate * mean_lifetime_seconds)

        short = 1.0 - keepalive
        # Probability that no short request arrives before the selected
        # lifetime, averaged over the configured discrete lifetime mix.
        no_short_before_expiry = sum(
            entry.weight
            * math.exp(
                -worker_rate * short * (entry.value / 1_000.0)
            )
            for entry in self.config.connection_lifetime_ms_mix.entries
        ) / self.config.connection_lifetime_ms_mix.total_weight
        expires_and_renews = keepalive * no_short_before_expiry
        # A persistent cycle begins after S->K or after a lifetime renewal.  If
        # B is the S->K rate and q its lifetime-renewal probability, the renewal
        # rate X satisfies X = q * (B + X).
        cycle_denominator = 1.0 - expires_and_renews
        short_to_keepalive_rate = rate * short * keepalive
        return (
            short_to_keepalive_rate
            * expires_and_renews
            / cycle_denominator
        )

    @staticmethod
    def _bounded_rate_candidate(
        cap: float, linear_cost: float, total_cost: Callable[[float], float]
    ) -> float | None:
        """Return the greatest steady rate satisfying one monotone wire cap."""

        if cap <= 0.0:
            return None
        if linear_cost <= 0.0:
            raise ValueError("rate-model linear cost must be positive")
        lower = 0.0
        upper = cap / linear_cost
        if total_cost(upper) <= cap:
            return upper
        # Fixed iterations make the result deterministic and comfortably more
        # precise than its serialized binary64 workload evidence.
        for _ in range(80):
            midpoint = (lower + upper) / 2.0
            if total_cost(midpoint) <= cap:
                lower = midpoint
            else:
                upper = midpoint
        return lower

    def target_rate_model(self) -> dict:
        """Translate independent wire caps into an expected steady-state op rate."""

        if self.config.mode == "keepalive":
            keepalive_probability = 1.0
        elif self.config.mode == "short":
            keepalive_probability = 0.0
        else:
            keepalive_probability = self.config.keepalive_ratio
        short_probability = 1.0 - keepalive_probability
        # Mixed workers keep at most one socket. A short request closes any idle
        # persistent socket, and the next keep-alive request then reconnects.
        new_connection_probability = 1.0 - keepalive_probability**2
        expected_packets = 0.0
        expected_bytes = 0.0
        for entry in self.config.response_mix.entries:
            fraction = entry.weight / self.config.response_mix.total_weight
            keepalive_request, keepalive_response = self._wire_sizes(
                entry.value, 1, True
            )
            short_request, short_response = self._wire_sizes(entry.value, 1, False)
            keepalive_packets = self._estimated_packets(
                keepalive_request, keepalive_response, False, False
            )
            reconnecting_keepalive_packets = self._estimated_packets(
                keepalive_request, keepalive_response, True, False
            )
            short_packets = self._estimated_packets(
                short_request, short_response, True, True
            )
            expected_packets += fraction * (
                keepalive_probability
                * (
                    keepalive_probability * keepalive_packets
                    + short_probability * reconnecting_keepalive_packets
                )
                + short_probability
                * (short_packets + keepalive_probability * 4.0)
            )
            expected_bytes += fraction * (
                keepalive_probability * (keepalive_request + keepalive_response)
                + short_probability * (short_request + short_response)
            )

        candidates = []
        packets_per_turnover = 7.0
        if self.config.pps > 0 and expected_packets > 0:
            packet_candidate = self._bounded_rate_candidate(
                self.config.pps,
                expected_packets,
                lambda rate: expected_packets * rate
                + packets_per_turnover
                * self._expected_lifetime_expiration_rate(
                    rate, keepalive_probability
                ),
            )
            if packet_candidate is not None:
                candidates.append(packet_candidate)
        if self.config.mbps > 0 and expected_bytes > 0:
            candidates.append(
                self.config.mbps * 1_000_000.0 / 8.0 / expected_bytes
            )
        if self.config.cps > 0:
            if new_connection_probability > 0:
                connection_candidate = self._bounded_rate_candidate(
                    self.config.cps,
                    new_connection_probability,
                    lambda rate: new_connection_probability * rate
                    + self._expected_lifetime_expiration_rate(
                        rate, keepalive_probability
                    ),
                )
                if connection_candidate is not None:
                    candidates.append(connection_candidate)
            elif keepalive_probability > 0:
                mean_lifetime_seconds = (
                    self.config.connection_lifetime_ms_mix.weighted_mean()
                    / 1_000.0
                )
                maximum_expiration_rate = (
                    self.config.concurrency / mean_lifetime_seconds
                )
                if self.config.cps < maximum_expiration_rate:
                    # X = r / (1 + r E[L] / concurrency).  Solve X = CPS.
                    # Use the representable distance from the asymptote instead
                    # of 1-CPS/asymptote, which can round to zero one ULP below
                    # the limit.
                    candidates.append(
                        self.config.cps
                        * maximum_expiration_rate
                        / (maximum_expiration_rate - self.config.cps)
                    )
        target = min(candidates) if candidates else None
        lifetime_expiration_rate = (
            None
            if target is None
            else self._expected_lifetime_expiration_rate(target, keepalive_probability)
        )
        lifetime_turnover_packets_per_second = (
            None
            if lifetime_expiration_rate is None
            else packets_per_turnover * lifetime_expiration_rate
        )
        return {
            # Keep full finite binary64 precision so the raw model remains
            # algebraically consistent at the maximum supported CPS/PPS rates;
            # rounding a per-operation probability before multiplying it by a
            # large target can otherwise manufacture a cap violation.
            "target_application_ops_per_second": target,
            "expected_packets_per_operation": expected_packets,
            "expected_application_bytes_per_operation": expected_bytes,
            "expected_new_connections_per_operation": new_connection_probability,
            "expected_lifetime_expirations_per_second": lifetime_expiration_rate,
            "expected_lifetime_turnover_packets_per_second": (
                lifetime_turnover_packets_per_second
            ),
            "scope": (
                "steady-state worker-local Poisson-arrival estimate; initial "
                "persistent connections are excluded; finite keep-alive lifetime "
                "turnover and competing short connections are included"
            ),
        }

    async def _worker(self, worker_id: int) -> None:
        generator = random.Random(self.config.seed + worker_id * 0x9E3779B1)
        lifetime_generator = self._connection_lifetime_generator(worker_id)
        request_payload = deterministic_payload(
            self.config.request_bytes, self.config.seed, worker_id + 1
        )
        persistent = None
        persistent_expiry: float | None = None
        sequence = 0
        try:
            while not self.stop.is_set() and time.monotonic() < self.deadline:
                if not self.budget.claim():
                    break
                response_size = self.config.response_mix.choose(generator)
                use_keepalive = self.config.mode == "keepalive" or (
                    self.config.mode == "mixed"
                    and generator.random() < self.config.keepalive_ratio
                )
                lifetime_expired = (
                    use_keepalive
                    and persistent is not None
                    and self._connection_expired(
                        persistent_expiry, time.monotonic()
                    )
                )
                close_persistent = persistent is not None and (
                    not use_keepalive or lifetime_expired
                )
                needs_connection = (
                    not use_keepalive or persistent is None or lifetime_expired
                )
                sequence += 1
                request_id = ((worker_id & 0xFFFF) << 48) | (
                    sequence & 0x0000FFFFFFFFFFFF
                )
                request_wire, response_wire = self._wire_sizes(
                    response_size, request_id, use_keepalive
                )
                estimated_packets = self._estimated_packets(
                    request_wire, response_wire, needs_connection, not use_keepalive
                )
                if close_persistent:
                    estimated_packets += 4
                if not await self.limiter.acquire(
                    {
                        "packets": float(estimated_packets),
                        "connections": 1.0 if needs_connection else 0.0,
                        "bytes": float(request_wire + response_wire),
                    },
                    self.stop,
                    self.deadline,
                ):
                    break
                if close_persistent:
                    closing = persistent
                    persistent = None
                    persistent_expiry = None
                    await self._close_connection(closing)
                    if lifetime_expired:
                        self.stats.add(connection_lifetime_expirations=1)

                # A rate-cap wait can cross the selected lifetime deadline. Recheck
                # immediately before using the socket and account for the real FIN
                # plus replacement handshake in the aggregate packet/CPS caps.
                if (
                    use_keepalive
                    and persistent is not None
                    and self._connection_expired(
                        persistent_expiry, time.monotonic()
                    )
                ):
                    closing = persistent
                    persistent = None
                    persistent_expiry = None
                    await self._close_connection(closing)
                    self.stats.add(connection_lifetime_expirations=1)
                    if not await self.limiter.acquire(
                        {"packets": 7.0, "connections": 1.0, "bytes": 0.0},
                        self.stop,
                        self.deadline,
                    ):
                        break
                channel = persistent if use_keepalive else None
                try:
                    if channel is None:
                        channel = await self._new_connection()
                        if use_keepalive:
                            persistent = channel
                            persistent_expiry, _lifetime_ms = (
                                self._new_connection_expiry(
                                    lifetime_generator, time.monotonic()
                                )
                            )
                    client_send_ns = time.monotonic_ns()
                    reader, writer = channel
                    if self.config.protocol == "http1":
                        request_header = _http_request_header(
                            self.config.host,
                            self.config.request_bytes,
                            response_size,
                            request_id,
                            client_send_ns,
                            not use_keepalive,
                        )
                    else:
                        request_header = REQUEST_HEADER.pack(
                            REQUEST_MAGIC,
                            VERSION,
                            0 if use_keepalive else FLAG_CLOSE,
                            0,
                            self.config.request_bytes,
                            response_size,
                            request_id,
                            client_send_ns,
                        )
                    writer.write(request_header)
                    if request_payload:
                        writer.write(request_payload)
                    await asyncio.wait_for(writer.drain(), timeout=self.config.io_timeout)
                    self.stats.add(bytes_sent=len(request_header) + len(request_payload))
                    if self.config.protocol == "http1":
                        received_bytes = await self._read_http_response(
                            reader, response_size, request_id, client_send_ns
                        )
                    else:
                        received_bytes = await self._read_framed_response(
                            reader, response_size, request_id, client_send_ns
                        )
                    self.stats.latency_ms.record(
                        (time.monotonic_ns() - client_send_ns) / 1_000_000.0
                    )
                    self.stats.add(
                        operations=1,
                        bytes_received=received_bytes,
                        **{f"response_size_{response_size}_operations": 1},
                    )
                except (
                    asyncio.IncompleteReadError,
                    asyncio.LimitOverrunError,
                    asyncio.TimeoutError,
                    ConnectionError,
                    OSError,
                    ValueError,
                    struct.error,
                ):
                    self.stats.add(errors=1)
                    if persistent is not None:
                        closing = persistent
                        persistent = None
                        persistent_expiry = None
                        channel = None
                        await self._abort_connection(closing)
                    elif channel is not None:
                        closing = channel
                        channel = None
                        await self._abort_connection(closing)
                    await asyncio.sleep(ERROR_BACKOFF_SECONDS)
                finally:
                    if channel is not None and not use_keepalive:
                        await self._close_connection(channel)
        finally:
            if persistent is not None:
                closing = persistent
                persistent = None
                persistent_expiry = None
                await self._close_connection(closing)

    async def _read_framed_response(
        self,
        reader: asyncio.StreamReader,
        response_size: int,
        request_id: int,
        client_send_ns: int,
    ) -> int:
        encoded = await asyncio.wait_for(
            reader.readexactly(RESPONSE_HEADER.size), timeout=self.config.io_timeout
        )
        (
            magic,
            version,
            status,
            reserved,
            received_size,
            received_id,
            echoed_send_ns,
            _server_receive_ns,
            _server_send_ns,
        ) = RESPONSE_HEADER.unpack(encoded)
        if (
            magic != RESPONSE_MAGIC
            or version != VERSION
            or status != 0
            or reserved != 0
            or received_size != response_size
            or received_id != request_id
            or echoed_send_ns != client_send_ns
        ):
            raise ValueError("invalid TCP workload response")
        await asyncio.wait_for(
            reader.readexactly(received_size), timeout=self.config.io_timeout
        )
        return RESPONSE_HEADER.size + received_size

    async def _read_http_response(
        self,
        reader: asyncio.StreamReader,
        response_size: int,
        request_id: int,
        client_send_ns: int,
    ) -> int:
        encoded = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"), timeout=self.config.io_timeout
        )
        if len(encoded) > MAX_HTTP_HEADER_BYTES:
            raise ValueError("HTTP response header is too large")
        start_line, headers = _parse_http_head(encoded[:-4])
        if start_line != "HTTP/1.1 200 OK":
            raise ValueError("unexpected HTTP response status")
        received_size = _bounded_decimal(headers, "content-length", MAX_TCP_BODY_BYTES)
        received_id = _bounded_decimal(headers, "x-openshield-request-id", 2**64 - 1)
        echoed_send_ns = _bounded_decimal(headers, "x-openshield-sent-ns", 2**64 - 1)
        if (
            received_size != response_size
            or received_id != request_id
            or echoed_send_ns != client_send_ns
        ):
            raise ValueError("invalid HTTP workload response")
        await asyncio.wait_for(
            reader.readexactly(received_size), timeout=self.config.io_timeout
        )
        return len(encoded) + received_size


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="OpenShield bounded real-socket TCP performance workload"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    server = commands.add_parser("server", help="run the TCP response server")
    base_server_arguments(server)
    server.add_argument(
        "--workers",
        type=bounded_int("workers", 1, MAX_SERVER_WORKERS),
        default=128,
    )
    server.add_argument("--backlog", type=bounded_int("backlog", 1, 4_096), default=256)
    server.add_argument(
        "--max-request-bytes",
        type=bounded_int("max-request-bytes", 0, MAX_TCP_BODY_BYTES),
        default=64 * 1024,
    )
    server.add_argument(
        "--max-response-bytes",
        type=bounded_int("max-response-bytes", 0, MAX_TCP_BODY_BYTES),
        default=1024 * 1024,
    )
    server.add_argument("--protocol", choices=("http1", "framed"), default="http1")

    client = commands.add_parser("client", help="run concurrent TCP clients")
    base_client_arguments(client)
    client.add_argument(
        "--concurrency",
        type=bounded_int("concurrency", 1, MAX_CONCURRENCY),
        default=8,
    )
    client.add_argument(
        "--cps",
        type=bounded_float("cps", 0.0, MAX_CPS),
        default=0.0,
        help="aggregate new-connection rate cap; zero disables this cap",
    )
    client.add_argument(
        "--mode", choices=("keepalive", "short", "mixed"), default="mixed"
    )
    client.add_argument(
        "--keepalive-ratio",
        type=bounded_float("keepalive-ratio", 0.0, 1.0),
        default=0.8,
    )
    client.add_argument(
        "--connection-lifetime-ms-mix",
        type=bounded_mix_converter(
            MIN_CONNECTION_LIFETIME_MS,
            MAX_CONNECTION_LIFETIME_MS,
            "connection lifetime (ms)",
        ),
        default=WeightedMix.fixed(MAX_CONNECTION_LIFETIME_MS),
        help=(
            "deterministic LIFETIME_MS:WEIGHT list selected for each persistent "
            "connection"
        ),
    )
    client.add_argument(
        "--request-bytes",
        type=bounded_int("request-bytes", 0, MAX_TCP_BODY_BYTES),
        default=128,
    )
    client.add_argument(
        "--response-bytes",
        type=bounded_int("response-bytes", 0, MAX_TCP_BODY_BYTES),
        default=1024,
    )
    client.add_argument(
        "--response-mix",
        type=mix_converter(MAX_TCP_BODY_BYTES),
        help="deterministic SIZE:WEIGHT list, for example 1024:70,16384:25,262144:5",
    )
    client.add_argument("--protocol", choices=("http1", "framed"), default="http1")
    client.add_argument(
        "--mss",
        type=bounded_int("mss", 536, 9_000),
        default=1460,
        help="MSS estimate used only to pace approximate packet rate",
    )
    return parser


def server_config(arguments: argparse.Namespace) -> TcpServerConfig:
    return TcpServerConfig(
        host=arguments.bind,
        port=arguments.port,
        duration=arguments.duration,
        seed=arguments.seed,
        io_timeout=arguments.io_timeout,
        processing_delay_ms=arguments.processing_delay_ms,
        workers=arguments.workers,
        backlog=arguments.backlog,
        max_request_bytes=arguments.max_request_bytes,
        max_response_bytes=arguments.max_response_bytes,
        protocol=arguments.protocol,
        allow_non_loopback=arguments.allow_non_loopback,
    )


def client_config(arguments: argparse.Namespace) -> TcpClientConfig:
    if arguments.port is None:
        raise ValueError("client port is required through CLI or config-file")
    response_mix = arguments.response_mix or WeightedMix.fixed(arguments.response_bytes)
    return TcpClientConfig(
        host=arguments.host,
        port=arguments.port,
        duration=arguments.duration,
        operations=arguments.operations,
        seed=arguments.seed,
        pps=arguments.pps,
        cps=arguments.cps,
        mbps=arguments.mbps,
        io_timeout=arguments.io_timeout,
        latency_samples=arguments.latency_samples,
        concurrency=arguments.concurrency,
        mode=arguments.mode,
        keepalive_ratio=arguments.keepalive_ratio,
        request_bytes=arguments.request_bytes,
        response_mix=response_mix,
        protocol=arguments.protocol,
        mss=arguments.mss,
        connection_lifetime_ms_mix=arguments.connection_lifetime_ms_mix,
    )


def run_server(config: TcpServerConfig) -> int:
    stop = threading.Event()
    install_stop_handlers(stop)
    server = TcpWorkloadServer(config, stop)
    try:
        summary = server.run(
            lambda port: emit_json(
                "ready",
                role="server",
                transport="tcp",
                protocol=config.protocol,
                host=config.host,
                port=port,
                pid=__import__("os").getpid(),
            )
        )
    except BaseException as error:
        emit_json(
            "error", role="server", transport="tcp", error=safe_error(error)
        )
        return 2
    emit_json(
        "summary",
        role="server",
        transport="tcp",
        protocol=config.protocol,
        host=config.host,
        port=server.bound_port,
        seed=config.seed,
        metrics=summary,
    )
    return 0


def run_client(config: TcpClientConfig, start_gate_stdin: bool = False) -> int:
    stop = threading.Event()
    control_stop = threading.Event()
    install_stop_handlers(stop, control_stop)
    identity = announce_control_process(start_gate_stdin, "tcp")
    client = TcpWorkloadClient(config, stop)
    wait_for_start_gate(
        start_gate_stdin,
        control_stop,
        "tcp",
        on_start=client.arm,
        identity=identity,
    )
    summary = client.run()
    summary["request_ops_per_second"] = summary["application_ops_per_second"]
    rate_model = client.target_rate_model()
    succeeded = summary.get("operations", 0) > 0 and summary.get("errors", 0) == 0
    summary_document = emit_json(
        "summary",
        role="client",
        transport="tcp",
        host=config.host,
        port=config.port,
        seed=config.seed,
        config={
            "duration": config.duration,
            "operations": config.operations,
            "target_approximate_pps": config.pps,
            "cps": config.cps,
            "mbps": config.mbps,
            "packet_rate_basis": (
                "estimated TCP data, delayed ACK, handshake and close packets; "
                "validate NIC PPS externally"
            ),
            "bandwidth_rate_basis": (
                "TCP application bytes in both directions, including workload headers"
            ),
            "connect_latency_basis": "TCP connect handshake completion",
            "request_latency_basis": (
                "request send through complete response body, excluding connect"
            ),
            "concurrency": config.concurrency,
            "execution_model": "one-thread asyncio event loop",
            "mode": config.mode,
            "keepalive_ratio": config.keepalive_ratio,
            "connection_lifetime_ms_mix": (
                config.connection_lifetime_ms_mix.as_json("milliseconds")
            ),
            "connection_lifetime_basis": (
                "selected once per persistent connection; expiry is enforced "
                "between completed exchanges"
            ),
            "request_bytes": config.request_bytes,
            "response_mix": config.response_mix.as_json(),
            "protocol": config.protocol,
            "mss": config.mss,
            **rate_model,
        },
        ok=succeeded,
        metrics=summary,
    )
    exit_code = 0 if summary.get("operations", 0) > 0 else 2
    wait_for_release_gate(
        start_gate_stdin,
        control_stop,
        "tcp",
        summary_document,
        exit_code,
    )
    return exit_code


def main(argv=None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "client":
            apply_config_file(arguments, parser, TCP_CLIENT_CONFIG_FIELDS)
        if arguments.command == "server":
            return run_server(server_config(arguments))
        return run_client(
            client_config(arguments),
            start_gate_stdin=arguments.start_gate_stdin,
        )
    except (ValueError, OSError, RuntimeError) as error:
        emit_json(
            "error", role=arguments.command, transport="tcp", error=safe_error(error)
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
