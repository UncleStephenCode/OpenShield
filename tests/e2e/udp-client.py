#!/usr/bin/env python3
"""Supervise a real nc/Ncat UDP owner; never open Python sockets."""
from __future__ import annotations

import argparse
import ipaddress
import os
import selectors
import signal
import subprocess
import sys
import time

NETWORK_SECONDS = 2.0
RETENTION_SECONDS = 1.0
MAX_PAYLOAD = 4096
MAX_STDERR = 65536
STDERR_PREVIEW = 4096
POLL_SECONDS = 0.05


def supervise(executable, peer, source_port, payload, *, clock=time.monotonic,
              popen=subprocess.Popen, selector_factory=selectors.DefaultSelector,
              read=os.read, write=os.write, set_blocking=os.set_blocking,
              cancellation=None):
    """Return exact echoed bytes only after timely validation and live retention.

    Deadline starts before Popen and is never renewed. stdin remains open until
    the child is terminated after retention (or on any failure). Bounded pipe
    drains continue during retention and after reaping, rejecting trailing data.
    """
    if not os.path.isabs(executable):
        raise ValueError("nc/Ncat executable must be an absolute path")
    if str(ipaddress.IPv4Address(peer)) != peer:
        raise ValueError("peer must be a canonical numeric IPv4 address")
    if not 1 <= source_port <= 65535:
        raise ValueError("source port must be between 1 and 65535")
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_PAYLOAD:
        raise ValueError("payload must contain 1..4096 bytes")
    argv = [executable, "-u", "-w", "2", "-p", str(source_port), peer, "18082"]
    child = selector = None
    received, stderr_preview = bytearray(), bytearray()
    stderr_bytes = 0
    sent = 0
    echoed_at = None
    stage = "spawn"
    started = clock()
    network_deadline = started + NETWORK_SECONDS
    error = None
    cleanup_error = None

    def check_deadline():
        if cancellation is not None and cancellation():
            raise SystemExit(128 + signal.SIGTERM)
        now = clock()
        if echoed_at is None and now >= network_deadline:
            raise TimeoutError("UDP network deadline expired before a complete exact echo")
        return now

    def accept_stdout(data):
        nonlocal echoed_at
        received.extend(data)
        if len(received) > len(payload) or bytes(received) != payload[:len(received)]:
            raise RuntimeError("UDP stdout was corrupt or contained trailing bytes")
        now = check_deadline()  # Includes read/validation and scheduler delay.
        if len(received) == len(payload) and echoed_at is None:
            if sent != len(payload):
                raise RuntimeError("UDP echo arrived before the complete payload was written")
            echoed_at = now

    def accept_stderr(data):
        nonlocal stderr_bytes
        stderr_bytes += len(data)
        stderr_preview.extend(data[:max(0, STDERR_PREVIEW - len(stderr_preview))])
        if stderr_bytes > MAX_STDERR:
            raise RuntimeError("nc/Ncat stderr exceeded the bounded drain limit")

    try:
        check_deadline()
        child = popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                      stderr=subprocess.PIPE, bufsize=0, close_fds=True)
        check_deadline()
        selector = selector_factory()
        for stream, events, name in (
                (child.stdin, selectors.EVENT_WRITE, "stdin"),
                (child.stdout, selectors.EVENT_READ, "stdout"),
                (child.stderr, selectors.EVENT_READ, "stderr")):
            set_blocking(stream.fileno(), False)
            selector.register(stream, events, name)
        while True:
            stage = "echo" if echoed_at is None else "retention"
            now = check_deadline()
            if child.poll() is not None:
                raise RuntimeError("nc/Ncat exited before completing live retention")
            if echoed_at is not None and now >= echoed_at + RETENTION_SECONDS:
                break
            deadline = network_deadline if echoed_at is None else echoed_at + RETENTION_SECONDS
            events = selector.select(min(POLL_SECONDS, max(0.0, deadline - now)))
            check_deadline()
            for key, _events in events:
                check_deadline()
                stream, name = key.fileobj, key.data
                try:
                    if name == "stdin":
                        count = write(stream.fileno(), payload[sent:])
                        if count <= 0 or count > len(payload) - sent:
                            raise RuntimeError("nc/Ncat stdin write made invalid progress")
                        sent += count
                        if sent == len(payload):
                            selector.unregister(stream)
                            # Do not close stdin: no producer-side EOF while nc starts.
                    else:
                        data = read(stream.fileno(), min(MAX_PAYLOAD, len(payload) + 1)
                                    if name == "stdout" else MAX_PAYLOAD)
                        if not data:
                            if name == "stdout":
                                raise RuntimeError("nc/Ncat stdout EOF before live retention completed")
                            selector.unregister(stream)
                        elif name == "stdout":
                            accept_stdout(data)
                        else:
                            accept_stderr(data)
                except (BlockingIOError, InterruptedError):
                    continue
                check_deadline()
    except BaseException as caught:
        error = caught
    finally:
        if selector is not None:
            try:
                selector.close()
            except BaseException as caught:
                cleanup_error = caught
        if child is not None:
            try:
                # Keep stdin open through termination; closing it earlier is the
                # lifecycle fault this prototype is intended to avoid.
                if child.poll() is None:
                    try:
                        child.terminate()
                    except ProcessLookupError:
                        pass
                try:
                    code = child.wait(timeout=0.25)
                except subprocess.TimeoutExpired:
                    try:
                        child.kill()
                    except ProcessLookupError:
                        pass
                    code = child.wait(timeout=1.0)
                if error is None and code not in (0, -signal.SIGTERM, -signal.SIGKILL):
                    raise RuntimeError("nc/Ncat exited with unexpected status %s" % code)
                # The real executable was launched without a shell. After it is
                # reaped, bounded final drains must reach EOF; no orphan writer
                # or already-buffered trailing bytes can count as success.
                for stream, name in ((child.stdout, "stdout"), (child.stderr, "stderr")):
                    set_blocking(stream.fileno(), False)
                    for _ in range(MAX_STDERR // MAX_PAYLOAD + 2):
                        data = read(stream.fileno(), MAX_PAYLOAD)
                        if not data:
                            break
                        if name == "stdout":
                            accept_stdout(data)
                        else:
                            accept_stderr(data)
                    else:
                        raise RuntimeError("nc/Ncat final pipe drain exceeded its bound")
            except BaseException as caught:
                if cleanup_error is None:
                    cleanup_error = caught
            finally:
                for stream in (child.stdin, child.stdout, child.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except BaseException as caught:
                            if cleanup_error is None:
                                cleanup_error = caught
    if error is not None or cleanup_error is not None:
        original = error if error is not None else cleanup_error
        details = "UDP nc supervisor stage=%s elapsed=%.3fs: %s" % (stage, clock() - started, original)
        if cleanup_error is not None and error is not None:
            details += "; cleanup: %s" % cleanup_error
        if stderr_preview:
            details += "; stderr: %r" % bytes(stderr_preview)
        if isinstance(original, (KeyboardInterrupt, SystemExit)):
            raise original
        error_type = TimeoutError if isinstance(original, TimeoutError) else RuntimeError
        raise error_type(details) from original
    if echoed_at is None or bytes(received) != payload:
        raise RuntimeError("UDP supervisor finished without an exact timely echo")
    return bytes(received)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--source-port", type=int, default=19000)
    parser.add_argument("--payload", required=True)
    parser.add_argument("--timeout-ms", type=int, choices=(2000,), default=2000)
    parser.add_argument("--hold-ms", type=int, choices=(1000,), default=1000)
    args = parser.parse_args()

    terminated = [False]

    def terminate(_signum, _frame):
        # Never raise during Popen's fork/assignment window or child cleanup.
        terminated[0] = True

    previous = signal.signal(signal.SIGTERM, terminate)
    try:
        try:
            response = supervise(args.executable, args.peer, args.source_port,
                                 args.payload.encode("utf-8"), cancellation=lambda: terminated[0])
        except (OSError, ValueError, RuntimeError, TimeoutError) as error:
            print(str(error), file=sys.stderr)
            return 1
        if terminated[0]:
            return 128 + signal.SIGTERM
        sys.stdout.buffer.write(response)
        return 128 + signal.SIGTERM if terminated[0] else 0
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
