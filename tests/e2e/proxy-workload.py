#!/usr/bin/env python3
"""Bounded real-socket workload for the Privoxy Learning regression test."""

from __future__ import annotations

import argparse
import concurrent.futures
import http.server
import ipaddress
import json
import multiprocessing
import os
from pathlib import Path
import queue
import socket
import threading
import time
from urllib.parse import parse_qs, urlsplit


SOCKET_TIMEOUT_SECONDS = 5.0
MAX_HEADER_BYTES = 64 * 1024
MAX_BODY_BYTES = 64 * 1024
MAX_REQUESTS = 256
MAX_CONCURRENCY = 64


def parse_port(value: str) -> int:
    port = int(value, 10)
    if not 1 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port is outside 1..65535")
    return port


def parse_count(value: str) -> int:
    count = int(value, 10)
    if not 1 <= count <= MAX_REQUESTS:
        raise argparse.ArgumentTypeError(f"count is outside 1..{MAX_REQUESTS}")
    return count


def parse_concurrency(value: str) -> int:
    concurrency = int(value, 10)
    if not 1 <= concurrency <= MAX_CONCURRENCY:
        raise argparse.ArgumentTypeError(
            f"concurrency is outside 1..{MAX_CONCURRENCY}"
        )
    return concurrency


def parse_delay(value: str) -> int:
    delay = int(value, 10)
    if not 0 <= delay <= 2_000:
        raise argparse.ArgumentTypeError("delay is outside 0..2000 milliseconds")
    return delay


def parse_noise_dimension(value: str) -> int:
    dimension = int(value, 10)
    if not 1 <= dimension <= 64:
        raise argparse.ArgumentTypeError("noise dimension is outside 1..64")
    return dimension


def checked_ipv4(value: str) -> str:
    address = ipaddress.ip_address(value)
    if address.version != 4:
        raise argparse.ArgumentTypeError("the E2E topology requires IPv4")
    return str(address)


class RecordingHttpServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address: tuple[str, int], log_path: Path) -> None:
        super().__init__(address, RecordingHandler)
        self.log_path = log_path
        self.log_lock = threading.Lock()

    def record(self, event: dict[str, object]) -> None:
        encoded = json.dumps(event, sort_keys=True, separators=(",", ":"))
        with self.log_lock, self.log_path.open("a", encoding="utf-8") as output:
            output.write(encoded + "\n")
            output.flush()


class RecordingHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "OpenShieldProxyPeer/1"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlsplit(self.path)
        path = parsed.path
        if not path.startswith("/") or len(path) > 512:
            self.send_error(400)
            return
        parameters = parse_qs(parsed.query, strict_parsing=False)
        delay_values = parameters.get("delay_ms", ["0"])
        try:
            delay_millis = parse_delay(delay_values[-1])
        except (argparse.ArgumentTypeError, ValueError):
            self.send_error(400)
            return
        if delay_millis:
            time.sleep(delay_millis / 1000.0)
        body = (f"openshield-proxy-peer:{path}\n").encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        server = self.server
        if not isinstance(server, RecordingHttpServer):
            raise RuntimeError("unexpected HTTP server implementation")
        server.record(
            {
                "event": "request",
                "path": path,
                "connection": f"{self.client_address[0]}:{self.client_address[1]}",
                "thread": threading.get_native_id(),
            }
        )

    def log_message(self, _format: str, *_arguments: object) -> None:
        return


class ProxySession:
    def __init__(
        self,
        proxy_address: str,
        proxy_port: int,
        peer_address: str,
        peer_port: int,
    ) -> None:
        self._proxy_address = proxy_address
        self._proxy_port = proxy_port
        self._peer_address = peer_address
        self._peer_port = peer_port
        self._socket: socket.socket | None = None
        self._buffer = bytearray()

    def __enter__(self) -> "ProxySession":
        deadline = time.monotonic() + SOCKET_TIMEOUT_SECONDS
        last_error: OSError | None = None
        while time.monotonic() < deadline:
            try:
                stream = socket.create_connection(
                    (self._proxy_address, self._proxy_port),
                    timeout=SOCKET_TIMEOUT_SECONDS,
                )
                stream.settimeout(SOCKET_TIMEOUT_SECONDS)
                self._socket = stream
                return self
            except OSError as error:
                last_error = error
                time.sleep(0.05)
        raise ConnectionError(f"cannot connect to Privoxy: {last_error}")

    def __exit__(self, *_arguments: object) -> None:
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def request(self, path: str, *, close: bool = False) -> bytes:
        if self._socket is None:
            raise RuntimeError("proxy session is not connected")
        if not path.startswith("/") or any(
            ord(character) < 0x21 or ord(character) > 0x7E for character in path
        ):
            raise ValueError("unsafe request path")
        connection = "close" if close else "keep-alive"
        request = (
            f"GET http://{self._peer_address}:{self._peer_port}{path} HTTP/1.1\r\n"
            f"Host: {self._peer_address}:{self._peer_port}\r\n"
            f"Connection: {connection}\r\n"
            f"Proxy-Connection: {connection}\r\n"
            "Accept: text/plain\r\n"
            "\r\n"
        ).encode("ascii")
        self._socket.sendall(request)
        header = self._read_until(b"\r\n\r\n", MAX_HEADER_BYTES)
        lines = header[:-4].split(b"\r\n")
        if not lines or not lines[0].startswith(b"HTTP/1.1 200 "):
            raise RuntimeError(f"unexpected proxy response status: {lines[:1]!r}")
        headers: dict[bytes, bytes] = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            if not separator:
                raise RuntimeError("malformed proxy response header")
            headers[name.strip().lower()] = value.strip().lower()
        try:
            content_length = int(headers[b"content-length"], 10)
        except (KeyError, ValueError) as error:
            raise RuntimeError("proxy response has no valid Content-Length") from error
        if not 0 < content_length <= MAX_BODY_BYTES:
            raise RuntimeError("proxy response body is outside the E2E bound")
        body = self._read_exact(content_length)
        expected = f"openshield-proxy-peer:{urlsplit(path).path}\n".encode("ascii")
        if body != expected:
            raise RuntimeError(f"unexpected proxy response body: {body!r}")
        if not close and headers.get(b"connection") == b"close":
            raise RuntimeError("Privoxy closed a requested keep-alive connection")
        return body

    def _read_until(self, marker: bytes, limit: int) -> bytes:
        if self._socket is None:
            raise RuntimeError("proxy session is not connected")
        while True:
            marker_index = self._buffer.find(marker)
            if marker_index >= 0:
                end = marker_index + len(marker)
                result = bytes(self._buffer[:end])
                del self._buffer[:end]
                return result
            if len(self._buffer) >= limit:
                raise RuntimeError("proxy response headers exceed the E2E bound")
            chunk = self._socket.recv(min(4096, limit - len(self._buffer)))
            if not chunk:
                raise ConnectionError("proxy closed before completing a response")
            self._buffer.extend(chunk)

    def _read_exact(self, size: int) -> bytes:
        if self._socket is None:
            raise RuntimeError("proxy session is not connected")
        while len(self._buffer) < size:
            chunk = self._socket.recv(size - len(self._buffer))
            if not chunk:
                raise ConnectionError("proxy closed before completing a body")
            self._buffer.extend(chunk)
        result = bytes(self._buffer[:size])
        del self._buffer[:size]
        return result


def serve(port: int, log_path: Path, ready_path: Path) -> None:
    log_path.unlink(missing_ok=True)
    ready_path.unlink(missing_ok=True)
    server = RecordingHttpServer(("0.0.0.0", port), log_path)
    ready_path.write_text("ready\n", encoding="ascii")
    server.serve_forever(poll_interval=0.1)


def hold(
    proxy_port: int,
    peer_address: str,
    peer_port: int,
    ready_path: Path,
    continue_path: Path,
) -> None:
    ready_path.unlink(missing_ok=True)
    continue_path.unlink(missing_ok=True)
    with ProxySession("127.0.0.1", proxy_port, peer_address, peer_port) as session:
        session.request("/pre-daemon")
        ready_path.write_text("ready\n", encoding="ascii")
        deadline = time.monotonic() + 90.0
        while not continue_path.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("daemon did not release the held proxy connection")
            time.sleep(0.05)
        for index in range(12):
            session.request(f"/post-daemon-{index}")
    print(json.dumps({"held_requests": 13}, sort_keys=True))


def one_cold_request(
    proxy_port: int,
    peer_address: str,
    peer_port: int,
    prefix: str,
    index: int,
    delay_millis: int,
) -> None:
    query = "" if delay_millis == 0 else f"?delay_ms={delay_millis}"
    with ProxySession("127.0.0.1", proxy_port, peer_address, peer_port) as session:
        session.request(f"/{prefix}-{index}{query}", close=True)


def cold(
    proxy_port: int,
    peer_address: str,
    peer_port: int,
    prefix: str,
    count: int,
    concurrency: int,
    delay_millis: int,
) -> None:
    if not prefix.replace("-", "").isalnum() or len(prefix) > 32:
        raise ValueError("unsafe workload prefix")
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(
                one_cold_request,
                proxy_port,
                peer_address,
                peer_port,
                prefix,
                index,
                delay_millis,
            )
            for index in range(count)
        ]
        for future in futures:
            future.result()
    print(
        json.dumps(
            {
                "requests": count,
                "concurrency": concurrency,
                "delay_millis": delay_millis,
                "elapsed_seconds": round(time.monotonic() - started, 6),
            },
            sort_keys=True,
        )
    )


def audit(log_path: Path, cold_count: int, thread_count: int) -> None:
    events = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    by_path = {event["path"]: event for event in events}
    pre_connection = by_path["/pre-daemon"]["connection"]
    post_connections = {
        by_path[f"/post-daemon-{index}"]["connection"] for index in range(12)
    }
    if post_connections != {pre_connection}:
        raise RuntimeError(
            "the upstream Privoxy connection did not survive daemon activation: "
            f"pre={pre_connection}, post={sorted(post_connections)}"
        )
    cold = [event for event in events if str(event["path"]).startswith("/cold-")]
    if len(cold) != cold_count:
        raise RuntimeError(f"expected {cold_count} cold requests, observed {len(cold)}")
    cold_connections = {event["connection"] for event in cold}
    if len(cold_connections) != cold_count:
        raise RuntimeError(
            "cold requests did not create distinct upstream TCP connections: "
            f"requests={cold_count}, connections={len(cold_connections)}"
        )
    threaded = [
        event for event in events if str(event["path"]).startswith("/threaded-")
    ]
    if len(threaded) != thread_count:
        raise RuntimeError(
            f"expected {thread_count} threaded requests, observed {len(threaded)}"
        )
    print(
        json.dumps(
            {
                "preexisting_upstream_connection": pre_connection,
                "post_daemon_requests_on_same_connection": 12,
                "cold_requests": len(cold),
                "distinct_cold_upstream_connections": len(cold_connections),
                "threaded_requests": len(threaded),
            },
            sort_keys=True,
        )
    )


def allow_loopback(port: int) -> None:
    # This command is diagnostic-only.  The normal regression path must work
    # without it; it exists to isolate loopback ingress from upstream
    # attribution when exercising an older release binary.
    import ipc_client

    current = ipc_client.status()
    rule = {
        "name": "Privoxy E2E diagnostic loopback",
        "direction": "inbound",
        "action": "accept",
        "protocol": "tcp",
        "peer_network": "127.0.0.0/8",
        "port": {"start": port, "end": port},
        "interface": "lo",
        "application": None,
        "origin": "manual",
        "enabled": True,
    }
    result = ipc_client.control(
        {
            "type": "create_rule",
            "data": {"expected_revision": current["revision"], "rule": rule},
        }
    )
    print(json.dumps(result, sort_keys=True))


def assert_network_accept(
    name: str, address: str, port: int, *, enabled: bool = True
) -> None:
    import ipc_client

    matches = []
    for rule in ipc_client.all_rules():
        specification = rule.get("spec", {})
        if specification.get("name") == name:
            matches.append(specification)
    if len(matches) != 1:
        raise RuntimeError(f"expected one network Accept rule, found {len(matches)}")
    rule = matches[0]
    expected = {
        "direction": "outbound",
        "action": "accept",
        "protocol": "tcp",
        "peer_network": f"{address}/32",
        "port": {"start": port, "end": port},
        "application": None,
        "origin": "manual",
        "enabled": enabled,
    }
    actual = {key: rule.get(key) for key in expected}
    # Accept is the wire-format default for backward compatibility and may be
    # omitted from a serialized v0.2.0-compatible rule.
    actual["action"] = rule.get("action", "accept")
    if actual != expected:
        raise RuntimeError(
            f"network Accept rule mismatch: expected {expected}, received {actual}"
        )
    print(json.dumps(actual, sort_keys=True))


def assert_nfqueue_clean(require_denied: bool) -> None:
    import ipc_client

    current = ipc_client.status()
    counters = current.get("nfqueue")
    expected = {
        "attribution_timeout": 0,
        "queue_overflow": 0,
        "terminal_queue_error": 0,
    }
    if not isinstance(counters, dict):
        raise RuntimeError(f"status has no NFQUEUE counters: {current}")
    actual = {key: counters.get(key) for key in expected}
    if actual != expected:
        raise RuntimeError(
            f"NFQUEUE errors occurred: expected {expected}, received {actual}"
        )
    denied = counters.get("denied")
    if not isinstance(denied, int) or denied < int(require_denied):
        raise RuntimeError(
            "explicit application Drop was not confirmed by the NFQUEUE denied counter"
        )
    actual["denied"] = denied
    print(json.dumps(actual, sort_keys=True))


def identity_hold(
    endpoint_address: str,
    endpoint_port: int,
    peer_address: str,
    peer_port: int,
    prefix: str,
    flows: int,
    ready_path: Path,
    release_path: Path,
) -> None:
    if not prefix.replace("-", "").isalnum() or len(prefix) > 32:
        raise ValueError("unsafe identity prefix")
    ready_path.unlink(missing_ok=True)
    release_path.unlink(missing_ok=True)
    condition = threading.Condition()
    release = threading.Event()
    ready_count = 0

    def worker(index: int) -> None:
        nonlocal ready_count
        with ProxySession(
            endpoint_address, endpoint_port, peer_address, peer_port
        ) as session:
            session.request(f"/{prefix}-{index}-initial")
            with condition:
                ready_count += 1
                condition.notify_all()
            if not release.wait(60.0):
                raise TimeoutError("identity workload was not released")
            session.request(f"/{prefix}-{index}-final")

    with concurrent.futures.ThreadPoolExecutor(max_workers=flows) as executor:
        futures = [executor.submit(worker, index) for index in range(flows)]
        deadline = time.monotonic() + 30.0
        with condition:
            while ready_count < flows:
                for future in futures:
                    if future.done():
                        try:
                            future.result()
                        except Exception:
                            release.set()
                            raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    release.set()
                    raise TimeoutError("identity sockets did not become ready")
                condition.wait(min(0.05, remaining))
        ready_path.write_text("ready\n", encoding="ascii")
        deadline = time.monotonic() + 60.0
        while not release_path.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("identity process was not released")
            time.sleep(0.05)
        release.set()
        for future in futures:
            future.result()
    print(json.dumps({"flows": flows, "prefix": prefix}, sort_keys=True))


def assert_browser_identities(
    direct_executable: str,
    proxy_executable: str,
    application_uid: int,
    privoxy_executable: str,
    privoxy_uid: int,
    peer_address: str,
    peer_port: int,
    proxy_port: int,
) -> None:
    import ipc_client

    rules = ipc_client.all_rules()

    def matching(
        executable: str,
        uid: int,
        address: str,
        port: int,
        argument_marker: str | None,
    ) -> list[dict]:
        result = []
        for rule in rules:
            specification = rule.get("spec", {})
            application = specification.get("application") or {}
            port_range = specification.get("port") or {}
            command_line = application.get("command_line") or {}
            arguments = command_line.get("arguments")
            if (
                specification.get("origin") == "learned"
                and specification.get("enabled") is True
                and specification.get("action", "accept") == "accept"
                and specification.get("protocol") == "tcp"
                and specification.get("peer_network") == f"{address}/32"
                and port_range.get("start") == port
                and port_range.get("end") == port
                and application.get("executable") == executable
                and application.get("uid") == uid
                and application.get("metadata_redacted") is False
                and command_line.get("kind") == "exact"
                and isinstance(arguments, list)
                and (argument_marker is None or argument_marker in arguments)
            ):
                result.append(rule)
        return result

    expected = (
        (
            "direct_one",
            direct_executable,
            application_uid,
            peer_address,
            peer_port,
            "direct-one",
        ),
        (
            "direct_two",
            direct_executable,
            application_uid,
            peer_address,
            peer_port,
            "direct-two",
        ),
        (
            "proxied",
            proxy_executable,
            application_uid,
            "127.0.0.1",
            proxy_port,
            "proxied",
        ),
        (
            "privoxy",
            privoxy_executable,
            privoxy_uid,
            peer_address,
            peer_port,
            None,
        ),
    )
    counts = {}
    identities = {}
    for label, executable, uid, address, port, argument_marker in expected:
        matches = matching(executable, uid, address, port, argument_marker)
        if not matches:
            raise RuntimeError(
                f"missing {label} identity: executable={executable}, uid={uid}, "
                f"destination={address}:{port}, argv marker={argument_marker}"
            )
        counts[label] = len(matches)
        identities[label] = [
            {
                "executable": match["spec"]["application"]["executable"],
                "uid": match["spec"]["application"]["uid"],
                "argv": match["spec"]["application"]["command_line"]["arguments"],
                "destination": match["spec"]["peer_network"],
                "port": match["spec"]["port"],
            }
            for match in matches
        ]
    if direct_executable == proxy_executable or application_uid == privoxy_uid:
        raise RuntimeError("browser identity fixture does not contain distinct applications")
    learned_executables = sorted(
        {
            application["executable"]
            for rule in rules
            if rule.get("spec", {}).get("origin") == "learned"
            if (application := rule.get("spec", {}).get("application"))
            if isinstance(application.get("executable"), str)
        }
    )
    print(
        json.dumps(
            {
                "matching_rule_counts": counts,
                "learned_executables": learned_executables,
                "identities": identities,
            },
            sort_keys=True,
        )
    )


def audit_identity_round(log_path: Path, direct_flows: int, proxy_flows: int) -> None:
    events = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]
    paths: dict[str, list[dict]] = {}
    for event in events:
        path = event.get("path")
        if isinstance(path, str):
            paths.setdefault(path, []).append(event)

    summary = {}
    for prefix, flows in (
        ("direct-one", direct_flows),
        ("direct-two", direct_flows),
        ("proxied", proxy_flows),
    ):
        connections = set()
        for index in range(flows):
            initial_path = f"/{prefix}-{index}-initial"
            final_path = f"/{prefix}-{index}-final"
            initial = paths.get(initial_path, [])
            final = paths.get(final_path, [])
            if len(initial) != 1 or len(final) != 1:
                raise RuntimeError(
                    f"identity round did not complete exactly once: "
                    f"{initial_path}={len(initial)}, {final_path}={len(final)}"
                )
            if initial[0].get("connection") != final[0].get("connection"):
                raise RuntimeError(
                    f"identity flow did not retain its established TCP connection: "
                    f"{prefix}-{index}"
                )
            connections.add(initial[0]["connection"])
        if len(connections) != flows:
            raise RuntimeError(
                f"identity round did not use distinct initial TCP flows for {prefix}: "
                f"expected {flows}, observed {len(connections)}"
            )
        summary[prefix] = {
            "flows": flows,
            "requests": flows * 2,
            "distinct_connections": len(connections),
        }
    print(json.dumps(summary, sort_keys=True))


def noise_child(
    thread_count: int,
    file_descriptor_count: int,
    release: multiprocessing.synchronize.Event,
    ready: multiprocessing.queues.Queue,
) -> None:
    descriptors = [open("/dev/null", "rb", buffering=0) for _index in range(file_descriptor_count)]
    threads = [
        threading.Thread(target=release.wait, args=(90.0,), daemon=False)
        for _index in range(thread_count)
    ]
    for thread in threads:
        thread.start()
    ready.put(os.getpid())
    release.wait(90.0)
    for thread in threads:
        thread.join()
    for descriptor in descriptors:
        descriptor.close()


def procfs_noise(
    process_count: int,
    thread_count: int,
    file_descriptor_count: int,
    ready_path: Path,
    release_path: Path,
) -> None:
    if process_count * thread_count > 2_048:
        raise ValueError("procfs noise exceeds the 2048-task per-process bound")
    if not 1 <= file_descriptor_count <= 512:
        raise ValueError("procfs noise file-descriptor count is outside 1..512")
    if process_count * file_descriptor_count > 32_768:
        raise ValueError("procfs noise exceeds its file-descriptor safety bound")
    ready_path.unlink(missing_ok=True)
    release_path.unlink(missing_ok=True)
    context = multiprocessing.get_context("fork")
    release = context.Event()
    ready = context.Queue()
    processes = [
        context.Process(
            target=noise_child,
            args=(thread_count, file_descriptor_count, release, ready),
        )
        for _index in range(process_count)
    ]
    try:
        for process in processes:
            process.start()
        observed = set()
        deadline = time.monotonic() + 30.0
        while len(observed) < process_count:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("procfs noise children did not become ready")
            try:
                observed.add(ready.get(timeout=min(0.25, remaining)))
            except queue.Empty:
                failed = [process.exitcode for process in processes if process.exitcode]
                if failed:
                    raise RuntimeError(f"procfs noise child failed: {failed}")
        ready_path.write_text("ready\n", encoding="ascii")
        deadline = time.monotonic() + 60.0
        while not release_path.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("procfs noise was not released")
            time.sleep(0.05)
    finally:
        release.set()
        for process in processes:
            process.join(timeout=10.0)
        alive = [process.pid for process in processes if process.is_alive()]
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=2.0)
        ready.close()
        ready.join_thread()
    if alive:
        raise RuntimeError(f"procfs noise children did not exit: {alive}")
    failures = [process.exitcode for process in processes if process.exitcode]
    if failures:
        raise RuntimeError(f"procfs noise children exited unsuccessfully: {failures}")
    print(
        json.dumps(
            {
                "processes": process_count,
                "threads_per_process": thread_count,
                "file_descriptors_per_process": file_descriptor_count,
                "worker_threads": process_count * thread_count,
            },
            sort_keys=True,
        )
    )


def direct_http(address: str, port: int) -> None:
    with socket.create_connection((address, port), timeout=SOCKET_TIMEOUT_SECONDS) as stream:
        stream.settimeout(SOCKET_TIMEOUT_SECONDS)
        stream.sendall(b"GET /external-probe HTTP/1.0\r\nHost: e2e\r\n\r\n")
        if not stream.recv(4096).startswith(b"HTTP/"):
            raise RuntimeError("direct HTTP probe received an invalid response")


def direct_blocked(address: str, port: int) -> None:
    try:
        direct_http(address, port)
    except TimeoutError:
        print(json.dumps({"blocked": True, "mechanism": "timeout"}, sort_keys=True))
        return
    except OSError as error:
        raise RuntimeError(
            f"external probe failed without the expected drop timeout: {error}"
        ) from error
    raise RuntimeError("external inbound HTTP unexpectedly crossed the firewall")


def main() -> None:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)

    server = subcommands.add_parser("serve")
    server.add_argument("port", type=parse_port)
    server.add_argument("log", type=Path)
    server.add_argument("ready", type=Path)

    held = subcommands.add_parser("hold")
    held.add_argument("proxy_port", type=parse_port)
    held.add_argument("peer_address", type=checked_ipv4)
    held.add_argument("peer_port", type=parse_port)
    held.add_argument("ready", type=Path)
    held.add_argument("continue_marker", type=Path)

    load = subcommands.add_parser("cold")
    load.add_argument("proxy_port", type=parse_port)
    load.add_argument("peer_address", type=checked_ipv4)
    load.add_argument("peer_port", type=parse_port)
    load.add_argument("prefix")
    load.add_argument("count", type=parse_count)
    load.add_argument("concurrency", type=parse_concurrency)
    load.add_argument("delay_millis", type=parse_delay)

    log_audit = subcommands.add_parser("audit")
    log_audit.add_argument("log", type=Path)
    log_audit.add_argument("cold_count", type=parse_count)
    log_audit.add_argument("thread_count", type=parse_count)

    loopback = subcommands.add_parser("allow-loopback")
    loopback.add_argument("port", type=parse_port)

    network = subcommands.add_parser("assert-network-accept")
    network.add_argument("name")
    network.add_argument("address", type=checked_ipv4)
    network.add_argument("port", type=parse_port)
    network.add_argument(
        "state", choices=("enabled", "disabled"), nargs="?", default="enabled"
    )

    nfqueue = subcommands.add_parser("assert-nfqueue-clean")
    nfqueue.add_argument("--require-denied", action="store_true")

    identity = subcommands.add_parser("identity-hold")
    identity.add_argument("endpoint_address", type=checked_ipv4)
    identity.add_argument("endpoint_port", type=parse_port)
    identity.add_argument("peer_address", type=checked_ipv4)
    identity.add_argument("peer_port", type=parse_port)
    identity.add_argument("prefix")
    identity.add_argument("flows", type=parse_count)
    identity.add_argument("ready", type=Path)
    identity.add_argument("release", type=Path)

    identities = subcommands.add_parser("assert-browser-identities")
    identities.add_argument("direct_executable")
    identities.add_argument("proxy_executable")
    identities.add_argument("application_uid", type=int)
    identities.add_argument("privoxy_executable")
    identities.add_argument("privoxy_uid", type=int)
    identities.add_argument("peer_address", type=checked_ipv4)
    identities.add_argument("peer_port", type=parse_port)
    identities.add_argument("proxy_port", type=parse_port)

    identity_audit = subcommands.add_parser("audit-identity-round")
    identity_audit.add_argument("log", type=Path)
    identity_audit.add_argument("direct_flows", type=parse_count)
    identity_audit.add_argument("proxy_flows", type=parse_count)

    noise = subcommands.add_parser("procfs-noise")
    noise.add_argument("processes", type=parse_noise_dimension)
    noise.add_argument("threads", type=parse_noise_dimension)
    noise.add_argument("file_descriptors", type=int)
    noise.add_argument("ready", type=Path)
    noise.add_argument("release", type=Path)

    direct = subcommands.add_parser("direct")
    direct.add_argument("address", type=checked_ipv4)
    direct.add_argument("port", type=parse_port)

    blocked = subcommands.add_parser("direct-blocked")
    blocked.add_argument("address", type=checked_ipv4)
    blocked.add_argument("port", type=parse_port)

    arguments = parser.parse_args()
    if arguments.command == "serve":
        serve(arguments.port, arguments.log, arguments.ready)
    elif arguments.command == "hold":
        hold(
            arguments.proxy_port,
            arguments.peer_address,
            arguments.peer_port,
            arguments.ready,
            arguments.continue_marker,
        )
    elif arguments.command == "cold":
        cold(
            arguments.proxy_port,
            arguments.peer_address,
            arguments.peer_port,
            arguments.prefix,
            arguments.count,
            arguments.concurrency,
            arguments.delay_millis,
        )
    elif arguments.command == "audit":
        audit(arguments.log, arguments.cold_count, arguments.thread_count)
    elif arguments.command == "allow-loopback":
        allow_loopback(arguments.port)
    elif arguments.command == "assert-network-accept":
        assert_network_accept(
            arguments.name,
            arguments.address,
            arguments.port,
            enabled=arguments.state == "enabled",
        )
    elif arguments.command == "assert-nfqueue-clean":
        assert_nfqueue_clean(arguments.require_denied)
    elif arguments.command == "identity-hold":
        identity_hold(
            arguments.endpoint_address,
            arguments.endpoint_port,
            arguments.peer_address,
            arguments.peer_port,
            arguments.prefix,
            arguments.flows,
            arguments.ready,
            arguments.release,
        )
    elif arguments.command == "assert-browser-identities":
        assert_browser_identities(
            arguments.direct_executable,
            arguments.proxy_executable,
            arguments.application_uid,
            arguments.privoxy_executable,
            arguments.privoxy_uid,
            arguments.peer_address,
            arguments.peer_port,
            arguments.proxy_port,
        )
    elif arguments.command == "audit-identity-round":
        audit_identity_round(
            arguments.log, arguments.direct_flows, arguments.proxy_flows
        )
    elif arguments.command == "procfs-noise":
        procfs_noise(
            arguments.processes,
            arguments.threads,
            arguments.file_descriptors,
            arguments.ready,
            arguments.release,
        )
    elif arguments.command == "direct":
        direct_http(arguments.address, arguments.port)
    elif arguments.command == "direct-blocked":
        direct_blocked(arguments.address, arguments.port)
    else:
        raise RuntimeError("unreachable command")


if __name__ == "__main__":
    main()
