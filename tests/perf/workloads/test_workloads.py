#!/usr/bin/env python3
"""Self-tests for the dependency-free OpenShield socket workloads."""

from __future__ import annotations

import argparse
import asyncio
import errno
import json
import math
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock


WORKLOAD_DIRECTORY = Path(__file__).resolve().parent
sys.path.insert(0, str(WORKLOAD_DIRECTORY))

import common  # noqa: E402
import tcp  # noqa: E402
import udp  # noqa: E402


class RunningServer:
    """Start a workload server in a test thread and surface its failures."""

    def __init__(self, server):
        self.server = server
        self.summary = None
        self.error = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        try:
            self.summary = self.server.run()
        except BaseException as error:  # surfaced to the test thread below
            self.error = error

    def start(self) -> int:
        self.thread.start()
        if not self.server.ready.wait(3.0):
            if self.error is not None:
                raise self.error
            raise RuntimeError("workload server did not signal readiness")
        if self.error is not None:
            raise self.error
        if self.server.bound_port is None:
            raise RuntimeError("workload server did not publish its port")
        return self.server.bound_port

    def close(self) -> dict:
        self.server.stop.set()
        self.thread.join(5.0)
        if self.thread.is_alive():
            raise RuntimeError("workload server did not stop within its bound")
        if self.error is not None:
            raise self.error
        if self.summary is None:
            raise RuntimeError("workload server produced no summary")
        return self.summary


def require_network(test: unittest.TestCase) -> None:
    """Skip only environments whose syscall sandbox forbids real sockets."""

    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except PermissionError as error:
        test.skipTest(f"environment forbids socket(): {error}")
    else:
        probe.close()


def tcp_server(protocol: str) -> RunningServer:
    return RunningServer(
        tcp.TcpWorkloadServer(
            tcp.TcpServerConfig(
                host="127.0.0.1",
                port=0,
                duration=10.0,
                seed=101,
                io_timeout=0.5,
                processing_delay_ms=0.0,
                workers=16,
                backlog=64,
                max_request_bytes=8 * 1024,
                max_response_bytes=16 * 1024,
                protocol=protocol,
            )
        )
    )


def udp_server() -> RunningServer:
    return RunningServer(
        udp.UdpWorkloadServer(
            udp.UdpServerConfig(
                host="127.0.0.1",
                port=0,
                duration=10.0,
                seed=202,
                io_timeout=0.2,
                processing_delay_ms=0.0,
                max_request_bytes=8 * 1024,
                max_response_bytes=16 * 1024,
                socket_buffer_bytes=64 * 1024,
            )
        )
    )


def udp_request(
    flow_id: int,
    sequence: int,
    *,
    flags: int = 0,
    client_send_ns: int | None = None,
) -> bytes:
    sent_ns = time.monotonic_ns() if client_send_ns is None else client_send_ns
    return udp.REQUEST_HEADER.pack(
        udp.REQUEST_MAGIC,
        udp.VERSION,
        flags,
        0,
        0,
        0,
        flow_id,
        sequence,
        sent_ns,
    )


class CommonUnitTests(unittest.TestCase):
    def test_bounded_converters_reject_nonfinite_and_out_of_range(self) -> None:
        integer = common.bounded_int("workers", 1, 4)
        floating = common.bounded_float("rate", 0.0, 10.0)
        self.assertEqual(integer("4"), 4)
        self.assertEqual(floating("2.5"), 2.5)
        for value in ("0", "5", "not-a-number"):
            with self.assertRaises(argparse.ArgumentTypeError):
                integer(value)
        for value in ("-1", "11", "nan", "inf"):
            with self.assertRaises(argparse.ArgumentTypeError):
                floating(value)

    def test_response_mix_is_bounded_unique_and_reproducible(self) -> None:
        mixture = common.parse_weighted_mix("0:2,1024:3,4096:1", 4096)
        first = __import__("random").Random(71)
        second = __import__("random").Random(71)
        selections = [mixture.choose(first) for _ in range(100)]
        self.assertEqual(selections, [mixture.choose(second) for _ in range(100)])
        self.assertEqual(set(selections), {0, 1024, 4096})
        self.assertEqual(mixture.maximum_value, 4096)
        for invalid in ("", "1", "1:0", "1:1,1:2", "4097:1", "-1:1"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(argparse.ArgumentTypeError):
                    common.parse_weighted_mix(invalid, 4096)

    def test_connection_lifetime_mix_is_bounded_and_reproducible(self) -> None:
        mixture = common.parse_bounded_weighted_mix(
            "50:2,250:3,3600000:1",
            tcp.MIN_CONNECTION_LIFETIME_MS,
            tcp.MAX_CONNECTION_LIFETIME_MS,
            "connection lifetime (ms)",
        )
        first = __import__("random").Random(73)
        second = __import__("random").Random(73)
        selections = [mixture.choose(first) for _ in range(100)]
        self.assertEqual(selections, [mixture.choose(second) for _ in range(100)])
        self.assertEqual(set(selections), {50, 250, 3_600_000})
        self.assertEqual(
            mixture.as_json("milliseconds"),
            [
                {"milliseconds": 50, "weight": 2},
                {"milliseconds": 250, "weight": 3},
                {"milliseconds": 3_600_000, "weight": 1},
            ],
        )
        for invalid in (
            "",
            "49:1",
            "3600001:1",
            "50:0",
            "50:1,50:2",
            "50",
            "-1:1",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(argparse.ArgumentTypeError):
                    common.parse_bounded_weighted_mix(
                        invalid,
                        tcp.MIN_CONNECTION_LIFETIME_MS,
                        tcp.MAX_CONNECTION_LIFETIME_MS,
                        "connection lifetime (ms)",
                    )

    def test_payload_and_reservoir_are_deterministic_and_bounded(self) -> None:
        first = common.deterministic_payload(1024, 4, 9)
        self.assertEqual(first, common.deterministic_payload(1024, 4, 9))
        self.assertNotEqual(first, common.deterministic_payload(1024, 4, 10))
        reservoir = common.SampleReservoir(8, 55)
        for value in range(100):
            reservoir.record(float(value))
        snapshot = reservoir.snapshot()
        self.assertEqual(snapshot["count"], 100)
        self.assertEqual(snapshot["sampled"], 8)
        self.assertEqual(snapshot["min"], 0.0)
        self.assertEqual(snapshot["max"], 99.0)
        self.assertEqual(snapshot["mean"], 49.5)

    def test_active_flow_integral_and_cpu_metrics(self) -> None:
        with mock.patch.object(
            common.time, "monotonic", side_effect=(0.0, 1.0, 3.0, 4.0)
        ):
            stats = common.WorkloadStats(1, 8)
            stats.active_change(1)
            stats.active_change(-1)
            summary = stats.summary()
        self.assertEqual(summary["active_flows_current"], 0)
        self.assertEqual(summary["active_flows_peak"], 1)
        self.assertEqual(summary["active_flows_time_weighted_mean"], 0.5)
        self.assertIn("process_cpu_seconds", summary)
        self.assertIn("wall_cpu_ratio", summary)
        for counter in (
            "errors",
            "operations",
            "packets_received",
            "barriers_expected",
            "barriers_sent",
            "barrier_acks_received",
            "barrier_errors",
            "barriers_received",
            "barrier_acks_sent",
        ):
            self.assertEqual(summary[counter], 0)

    def test_work_budget_is_an_exact_concurrent_cap(self) -> None:
        budget = common.WorkBudget(1000)
        claims: list[int] = []

        def consume() -> None:
            accepted = 0
            while budget.claim():
                accepted += 1
            claims.append(accepted)

        threads = [threading.Thread(target=consume) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(claims), 1000)

    def test_async_limiter_paces_and_records_scheduler_lag(self) -> None:
        async def exercise() -> tuple[float, dict, float]:
            samples = common.SampleReservoir(16, 1)
            limiter = common.AsyncMultiRateLimiter({"packets": 50.0}, samples)
            stop = threading.Event()
            started = time.monotonic()
            deadline = started + 1.0
            for _ in range(3):
                self.assertTrue(
                    await limiter.acquire({"packets": 1.0}, stop, deadline)
                )
            elapsed = time.monotonic() - started

            slow = common.AsyncMultiRateLimiter({"packets": 1.0}, samples)
            slow_started = time.monotonic()
            slow_deadline = slow_started + 0.05
            self.assertTrue(
                await slow.acquire({"packets": 1.0}, stop, slow_deadline)
            )
            self.assertFalse(
                await slow.acquire({"packets": 1.0}, stop, slow_deadline)
            )
            return elapsed, samples.snapshot(), time.monotonic() - slow_started

        elapsed, snapshot, bounded_wait = asyncio.run(exercise())
        self.assertGreaterEqual(elapsed, 0.03)
        self.assertEqual(snapshot["count"], 4)
        self.assertGreaterEqual(bounded_wait, 0.04)

    def test_nonloopback_bind_requires_explicit_authorization(self) -> None:
        common.require_safe_bind("127.0.0.1", False)
        with self.assertRaises(ValueError):
            common.require_safe_bind("0.0.0.0", False)
        common.require_safe_bind("0.0.0.0", True)


class ConfigFileTests(unittest.TestCase):
    def _write(self, directory: str, name: str, contents: str) -> Path:
        path = Path(directory) / name
        path.write_text(contents, encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_tcp_config_uses_same_validators_and_overrides_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                "phase.json",
                json.dumps(
                    {
                        "host": "127.0.0.1",
                        "port": 18080,
                        "duration": 0.5,
                        "operations": 20,
                        "concurrency": 3,
                        "protocol": "http1",
                        "response_mix": "16:3,128:1",
                        "connection_lifetime_ms_mix": "50:3,250:1",
                    }
                ),
            )
            parser = tcp.build_parser()
            arguments = parser.parse_args(["client", "--config-file", str(path)])
            common.apply_config_file(
                arguments, parser, tcp.TCP_CLIENT_CONFIG_FIELDS
            )
            config = tcp.client_config(arguments)
            self.assertEqual(config.port, 18080)
            self.assertEqual(config.concurrency, 3)
            self.assertEqual(config.response_mix.maximum_value, 128)
            self.assertEqual(
                config.connection_lifetime_ms_mix.as_json("milliseconds"),
                [
                    {"milliseconds": 50, "weight": 3},
                    {"milliseconds": 250, "weight": 1},
                ],
            )

    def test_tcp_server_accepts_bounded_full_turnover_worker_capacity(self) -> None:
        arguments = tcp.build_parser().parse_args(
            ["server", "--workers", str(common.MAX_SERVER_WORKERS)]
        )
        self.assertEqual(arguments.workers, 1024)

    def test_tcp_config_rejects_out_of_range_connection_lifetime(self) -> None:
        parser = tcp.build_parser()
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                "invalid-lifetime.json",
                '{"port":18080,"connection_lifetime_ms_mix":"49:1"}',
            )
            arguments = parser.parse_args(["client", "--config-file", str(path)])
            with self.assertRaisesRegex(
                ValueError, "invalid config field connection_lifetime_ms_mix"
            ):
                common.apply_config_file(
                    arguments, parser, tcp.TCP_CLIENT_CONFIG_FIELDS
                )

    def test_udp_config_rejects_unknown_duplicate_and_unsafe_files(self) -> None:
        parser = udp.build_parser()
        with tempfile.TemporaryDirectory() as directory:
            unknown = self._write(directory, "unknown.json", '{"port":9,"cps":1}')
            arguments = parser.parse_args(
                ["client", "--config-file", str(unknown)]
            )
            with self.assertRaisesRegex(ValueError, "forbidden"):
                common.apply_config_file(
                    arguments, parser, udp.UDP_CLIENT_CONFIG_FIELDS
                )

            duplicate = self._write(
                directory, "duplicate.json", '{"port":9,"port":10}'
            )
            with self.assertRaisesRegex(ValueError, "duplicate"):
                common.load_trusted_config(str(duplicate))

            writable = self._write(directory, "writable.json", '{"port":9}')
            writable.chmod(0o622)
            with self.assertRaisesRegex(ValueError, "owner-controlled"):
                common.load_trusted_config(str(writable))

            target = self._write(directory, "target.json", '{"port":9}')
            link = Path(directory) / "link.json"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                common.load_trusted_config(str(link))

            fifo = Path(directory) / "phase.fifo"
            os.mkfifo(fifo, 0o600)
            with self.assertRaisesRegex(ValueError, "regular file"):
                common.load_trusted_config(str(fifo))

    def test_udp_config_accepts_request_mix_and_retains_fixed_fallback(self) -> None:
        parser = udp.build_parser()
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                "udp.json",
                '{"port":18080,"request_bytes":64,'
                '"request_mix":"0:1,64:2,512:1"}',
            )
            arguments = parser.parse_args(["client", "--config-file", str(path)])
            common.apply_config_file(
                arguments, parser, udp.UDP_CLIENT_CONFIG_FIELDS
            )
            configured = udp.UdpWorkloadClient(udp.client_config(arguments))
            self.assertEqual(configured.request_mix.maximum_value, 512)

        fallback_arguments = parser.parse_args(
            ["client", "--port", "18080", "--request-bytes", "321"]
        )
        fallback = udp.UdpWorkloadClient(udp.client_config(fallback_arguments))
        self.assertEqual(fallback.request_mix.as_json(), [{"bytes": 321, "weight": 1}])

    def test_config_path_must_be_absolute_and_bounded(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            common.config_path("relative.json")
        with self.assertRaises(argparse.ArgumentTypeError):
            common.config_path("/" + "a" * common.MAX_PATH_BYTES)


class ProtocolUnitTests(unittest.TestCase):
    def test_http_headers_round_trip_and_reject_ambiguous_input(self) -> None:
        encoded = tcp._http_request_header(
            "127.0.0.1", 12, 4096, 7, 123456, False
        )
        start, headers = tcp._parse_http_head(encoded[:-4])
        self.assertEqual(start, "POST /bytes/4096 HTTP/1.1")
        self.assertEqual(headers["connection"], "keep-alive")
        self.assertEqual(tcp._bounded_decimal(headers, "content-length", 12), 12)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            tcp._parse_http_head(b"GET / HTTP/1.1\r\nA: 1\r\na: 2")
        with self.assertRaisesRegex(ValueError, "value"):
            tcp._parse_http_head(b"GET / HTTP/1.1\r\nA: bad\x01value")

    def test_wire_protocol_structures_are_stable(self) -> None:
        self.assertEqual(tcp.REQUEST_HEADER.size, 32)
        self.assertEqual(tcp.RESPONSE_HEADER.size, 44)
        self.assertEqual(udp.REQUEST_HEADER.size, 40)
        self.assertEqual(udp.RESPONSE_HEADER.size, 52)

    def test_udp_send_failures_have_explicit_errno_classes(self) -> None:
        client = udp.UdpWorkloadClient(
            udp.UdpClientConfig(
                host="127.0.0.1",
                port=9,
                duration=1.0,
                operations=1,
                seed=17,
                pps=0.0,
                mbps=0.0,
                io_timeout=0.1,
                latency_samples=8,
                flows=1,
                reply_every=0,
                request_bytes=16,
                response_mix=common.WeightedMix.fixed(0),
                socket_buffer_bytes=64 * 1024,
            )
        )
        client._record_send_failure("data", asyncio.TimeoutError())
        client._record_send_failure("data", OSError(errno.ENOBUFS, "full"))
        client._record_send_failure("barrier", OSError(errno.EAGAIN, "wait"))
        client._record_send_failure("barrier", OSError(errno.EIO, "I/O"))
        summary = client.stats.summary()
        self.assertEqual(summary["data_send_failures"], 2)
        self.assertEqual(summary["data_send_timeouts"], 1)
        self.assertEqual(summary["data_send_enobufs"], 1)
        self.assertEqual(summary["data_send_would_block"], 0)
        self.assertEqual(summary["barrier_send_failures"], 2)
        self.assertEqual(summary["barrier_send_would_block"], 1)
        self.assertEqual(summary["barrier_send_other_os_errors"], 1)
        with self.assertRaisesRegex(ValueError, "scope"):
            client._record_send_failure("unknown", OSError(errno.EIO, "I/O"))

    def test_target_rate_models_convert_wire_caps_to_application_ops(self) -> None:
        tcp_client = tcp.TcpWorkloadClient(
            tcp.TcpClientConfig(
                host="127.0.0.1",
                port=9,
                duration=1.0,
                operations=1,
                seed=1,
                pps=100.0,
                cps=10.0,
                mbps=10.0,
                io_timeout=0.1,
                latency_samples=8,
                concurrency=1,
                mode="short",
                keepalive_ratio=0.0,
                request_bytes=16,
                response_mix=common.WeightedMix.fixed(128),
            )
        )
        tcp_model = tcp_client.target_rate_model()
        self.assertEqual(tcp_model["expected_new_connections_per_operation"], 1.0)
        expected_tcp_target = min(
            100.0 / tcp_model["expected_packets_per_operation"],
            10.0,
            10.0
            * 1_000_000.0
            / 8.0
            / tcp_model["expected_application_bytes_per_operation"],
        )
        self.assertAlmostEqual(
            tcp_model["target_application_ops_per_second"],
            expected_tcp_target,
            places=5,
        )

        udp_client = udp.UdpWorkloadClient(
            udp.UdpClientConfig(
                host="127.0.0.1",
                port=9,
                duration=1.0,
                operations=1,
                seed=1,
                pps=100.0,
                mbps=0.0,
                io_timeout=0.1,
                latency_samples=8,
                flows=1,
                reply_every=10,
                request_bytes=16,
                response_mix=common.WeightedMix.fixed(128),
                socket_buffer_bytes=64 * 1024,
                request_mix=common.parse_weighted_mix("16:1,2000:1", 2000),
            )
        )
        udp_model = udp_client.target_rate_model()
        self.assertAlmostEqual(udp_model["expected_reply_probability"], 0.1)
        self.assertGreater(udp_model["expected_packets_per_operation"], 1.5)
        self.assertAlmostEqual(
            udp_model["target_application_ops_per_second"],
            100.0 / udp_model["expected_packets_per_operation"],
            places=5,
        )

    def test_tcp_keepalive_target_includes_finite_lifetime_turnover(self) -> None:
        client = tcp.TcpWorkloadClient(
            tcp.TcpClientConfig(
                host="127.0.0.1",
                port=9,
                duration=1.0,
                operations=1,
                seed=1,
                pps=1280.0,
                cps=160.0,
                mbps=0.0,
                io_timeout=0.1,
                latency_samples=8,
                concurrency=16,
                mode="keepalive",
                keepalive_ratio=1.0,
                request_bytes=64,
                response_mix=common.parse_weighted_mix("512:80,4096:20", 4096),
                connection_lifetime_ms_mix=common.parse_bounded_weighted_mix(
                    "100:1,250:2,500:1",
                    50,
                    3_600_000,
                    "connection lifetime (ms)",
                ),
            )
        )

        model = client.target_rate_model()
        # X(r) = r / (1 + r E[L] / concurrency).  Solve
        # packets_per_op*r + 7*X(r) = PPS independently of the implementation.
        lifetime_per_worker = 0.275 / 16.0
        packets_per_op = model["expected_packets_per_operation"]
        quadratic = packets_per_op * lifetime_per_worker
        linear = packets_per_op + 7.0 - 1280.0 * lifetime_per_worker
        expected_target = (
            -linear + math.sqrt(linear * linear + 4.0 * quadratic * 1280.0)
        ) / (2.0 * quadratic)
        renewal_rate = expected_target / (
            1.0 + expected_target * lifetime_per_worker
        )
        self.assertAlmostEqual(
            model["expected_lifetime_expirations_per_second"],
            renewal_rate,
            places=5,
        )
        self.assertAlmostEqual(
            model["expected_lifetime_turnover_packets_per_second"],
            7.0 * renewal_rate,
            places=5,
        )
        self.assertAlmostEqual(
            model["target_application_ops_per_second"], expected_target, places=5
        )
        self.assertAlmostEqual(
            model["target_application_ops_per_second"], 200.874426, places=5
        )

    def test_tcp_keepalive_low_rate_turnover_is_bounded_by_operations(self) -> None:
        client = tcp.TcpWorkloadClient(
            tcp.TcpClientConfig(
                host="127.0.0.1",
                port=9,
                duration=1.0,
                operations=1,
                seed=1,
                pps=100.0,
                cps=0.0,
                mbps=0.0,
                io_timeout=0.1,
                latency_samples=8,
                concurrency=16,
                mode="keepalive",
                keepalive_ratio=1.0,
                request_bytes=64,
                response_mix=common.parse_weighted_mix("512:80,4096:20", 4096),
                connection_lifetime_ms_mix=common.parse_bounded_weighted_mix(
                    "100:1,250:2,500:1",
                    50,
                    3_600_000,
                    "connection lifetime (ms)",
                ),
            )
        )

        model = client.target_rate_model()
        lifetime_per_worker = 0.275 / 16.0
        packets_per_op = model["expected_packets_per_operation"]
        quadratic = packets_per_op * lifetime_per_worker
        linear = packets_per_op + 7.0 - 100.0 * lifetime_per_worker
        expected_target = (
            -linear + math.sqrt(linear * linear + 4.0 * quadratic * 100.0)
        ) / (2.0 * quadratic)
        expected_renewals = expected_target / (
            1.0 + expected_target * lifetime_per_worker
        )
        self.assertAlmostEqual(
            model["target_application_ops_per_second"], expected_target, places=5
        )
        self.assertAlmostEqual(
            model["expected_lifetime_expirations_per_second"],
            expected_renewals,
            places=5,
        )

    def test_tcp_mixed_target_models_competing_short_and_lifetime_turnover(
        self,
    ) -> None:
        config = tcp.TcpClientConfig(
            host="127.0.0.1",
            port=9,
            duration=1.0,
            operations=1,
            seed=1,
            pps=1600.0,
            cps=400.0,
            mbps=0.0,
            io_timeout=0.1,
            latency_samples=8,
            concurrency=32,
            mode="mixed",
            keepalive_ratio=0.75,
            request_bytes=64,
            response_mix=common.parse_weighted_mix(
                "512:70,4096:25,16384:5", 16384
            ),
            connection_lifetime_ms_mix=common.parse_bounded_weighted_mix(
                "100:1,250:2,500:1",
                50,
                3_600_000,
                "connection lifetime (ms)",
            ),
        )
        client = tcp.TcpWorkloadClient(config)

        model = client.target_rate_model()
        self.assertAlmostEqual(
            model["target_application_ops_per_second"], 153.097558, places=5
        )
        self.assertAlmostEqual(
            model["expected_lifetime_expirations_per_second"],
            34.738985,
            places=5,
        )
        self.assertAlmostEqual(
            model["expected_lifetime_turnover_packets_per_second"],
            243.172892,
            places=5,
        )
        base_connections = (
            model["target_application_ops_per_second"]
            * model["expected_new_connections_per_operation"]
        )
        self.assertLess(
            base_connections + model["expected_lifetime_expirations_per_second"],
            400.0,
        )

        cps_limited = tcp.TcpWorkloadClient(
            tcp.TcpClientConfig(**{**config.__dict__, "cps": 90.0})
        ).target_rate_model()
        self.assertAlmostEqual(
            cps_limited["target_application_ops_per_second"],
            130.739567,
            places=5,
        )

        # A simultaneous byte cap equivalent to 120 application operations/s
        # must win over both the independently solved PPS and CPS candidates.
        byte_limited_mbps = (
            120.0
            * model["expected_application_bytes_per_operation"]
            * 8.0
            / 1_000_000.0
        )
        all_caps = tcp.TcpWorkloadClient(
            tcp.TcpClientConfig(
                **{
                    **config.__dict__,
                    "cps": 90.0,
                    "mbps": byte_limited_mbps,
                }
            )
        ).target_rate_model()
        self.assertAlmostEqual(
            all_caps["target_application_ops_per_second"], 120.0, places=5
        )

    def test_tcp_keepalive_cps_only_uses_finite_renewal_limit(self) -> None:
        base = tcp.TcpClientConfig(
            host="127.0.0.1",
            port=9,
            duration=1.0,
            operations=1,
            seed=1,
            pps=0.0,
            cps=40.0,
            mbps=0.0,
            io_timeout=0.1,
            latency_samples=8,
            concurrency=16,
            mode="keepalive",
            keepalive_ratio=1.0,
            request_bytes=64,
            response_mix=common.WeightedMix.fixed(512),
            connection_lifetime_ms_mix=common.WeightedMix.fixed(275),
        )
        model = tcp.TcpWorkloadClient(base).target_rate_model()
        expected_target = 40.0 / (1.0 - 40.0 * 0.275 / 16.0)
        self.assertAlmostEqual(
            model["target_application_ops_per_second"], expected_target, places=5
        )
        self.assertAlmostEqual(
            model["expected_lifetime_expirations_per_second"], 40.0, places=5
        )

        # A CPS cap at the asymptotic renewal rate does not bound application
        # operations. Undefined per-second target evidence must remain null,
        # rather than being misreported as zero turnover.
        asymptotic_cps = 16.0 / 0.275
        unbounded = tcp.TcpWorkloadClient(
            tcp.TcpClientConfig(**{**base.__dict__, "cps": asymptotic_cps})
        ).target_rate_model()
        self.assertIsNone(unbounded["target_application_ops_per_second"])
        self.assertIsNone(unbounded["expected_lifetime_expirations_per_second"])
        self.assertIsNone(
            unbounded["expected_lifetime_turnover_packets_per_second"]
        )

        # The greatest representable CPS below the renewal asymptote remains a
        # finite (very high) rate rather than a divide-by-zero edge case.
        edge_lifetime_ms = 1_063_130
        edge_concurrency = 265
        edge_asymptote = edge_concurrency / (edge_lifetime_ms / 1_000.0)
        edge_cps = math.nextafter(edge_asymptote, 0.0)
        edge = tcp.TcpWorkloadClient(
            tcp.TcpClientConfig(
                **{
                    **base.__dict__,
                    "concurrency": edge_concurrency,
                    "cps": edge_cps,
                    "connection_lifetime_ms_mix": common.WeightedMix.fixed(
                        edge_lifetime_ms
                    ),
                }
            )
        ).target_rate_model()
        self.assertTrue(math.isfinite(edge["target_application_ops_per_second"]))
        self.assertGreater(edge["target_application_ops_per_second"], 0.0)
        self.assertAlmostEqual(
            edge["expected_lifetime_expirations_per_second"], edge_cps
        )

    def test_tcp_rate_model_retains_cap_consistency_at_high_rates(self) -> None:
        client = tcp.TcpWorkloadClient(
            tcp.TcpClientConfig(
                host="127.0.0.1",
                port=9,
                duration=1.0,
                operations=1,
                seed=1,
                pps=0.0,
                cps=68_256.77693882461,
                mbps=0.0,
                io_timeout=0.1,
                latency_samples=8,
                concurrency=16,
                mode="mixed",
                keepalive_ratio=0.9590575403064787,
                request_bytes=2546,
                response_mix=common.WeightedMix.fixed(1024),
                connection_lifetime_ms_mix=common.parse_bounded_weighted_mix(
                    "100:1,5000:2",
                    50,
                    3_600_000,
                    "connection lifetime (ms)",
                ),
            )
        )
        model = client.target_rate_model()
        target = model["target_application_ops_per_second"]
        total_connections = (
            target * model["expected_new_connections_per_operation"]
            + model["expected_lifetime_expirations_per_second"]
        )
        self.assertLessEqual(total_connections, client.config.cps * (1.0 + 1e-12))
        self.assertAlmostEqual(total_connections, client.config.cps, places=6)

    def test_tcp_client_rejects_invalid_direct_rate_model_inputs(self) -> None:
        base = tcp.TcpClientConfig(
            host="127.0.0.1",
            port=9,
            duration=1.0,
            operations=1,
            seed=1,
            pps=1.0,
            cps=1.0,
            mbps=1.0,
            io_timeout=0.1,
            latency_samples=8,
            concurrency=1,
            mode="mixed",
            keepalive_ratio=0.5,
            request_bytes=1,
            response_mix=common.WeightedMix.fixed(1),
        )
        for field, value in (
            ("pps", -1.0),
            ("cps", math.nan),
            ("mbps", math.inf),
            ("keepalive_ratio", -0.1),
            ("concurrency", 0),
            ("concurrency", True),
            ("mode", "invalid"),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(ValueError, "TCP client"):
                    tcp.TcpWorkloadClient(
                        tcp.TcpClientConfig(**{**base.__dict__, field: value})
                    )

    def test_tcp_cross_product_memory_limit_rejects_unsafe_concurrency(self) -> None:
        with self.assertRaisesRegex(ValueError, "memory"):
            tcp.TcpWorkloadClient(
                tcp.TcpClientConfig(
                    host="127.0.0.1",
                    port=9,
                    duration=1.0,
                    operations=1,
                    seed=1,
                    pps=1.0,
                    cps=1.0,
                    mbps=0.0,
                    io_timeout=0.1,
                    latency_samples=8,
                    concurrency=common.MAX_CONCURRENCY,
                    mode="short",
                    keepalive_ratio=0.0,
                    request_bytes=common.MAX_TCP_BODY_BYTES,
                    response_mix=common.WeightedMix.fixed(
                        common.MAX_TCP_BODY_BYTES
                    ),
                )
            )

    def test_tcp_connection_lifetime_deadline_and_rng_are_deterministic(self) -> None:
        config = tcp.TcpClientConfig(
            host="127.0.0.1",
            port=9,
            duration=1.0,
            operations=1,
            seed=97,
            pps=0.0,
            cps=0.0,
            mbps=0.0,
            io_timeout=0.1,
            latency_samples=8,
            concurrency=1,
            mode="keepalive",
            keepalive_ratio=1.0,
            request_bytes=16,
            response_mix=common.WeightedMix.fixed(128),
            connection_lifetime_ms_mix=common.parse_bounded_weighted_mix(
                "50:2,250:3,500:1", 50, 3_600_000, "connection lifetime (ms)"
            ),
        )
        first = tcp.TcpWorkloadClient(config)
        second = tcp.TcpWorkloadClient(config)
        first_generator = first._connection_lifetime_generator(3)
        second_generator = second._connection_lifetime_generator(3)
        first_lifetimes = [
            first._new_connection_expiry(first_generator, 10.0)[1]
            for _ in range(64)
        ]
        second_lifetimes = [
            second._new_connection_expiry(second_generator, 10.0)[1]
            for _ in range(64)
        ]
        self.assertEqual(first_lifetimes, second_lifetimes)
        deadline, lifetime_ms = first._new_connection_expiry(
            first._connection_lifetime_generator(0), 10.0
        )
        self.assertIn(lifetime_ms, (50, 250, 500))
        self.assertAlmostEqual(deadline, 10.0 + lifetime_ms / 1_000.0)
        self.assertFalse(first._connection_expired(deadline, deadline - 1e-9))
        self.assertTrue(first._connection_expired(deadline, deadline))

        invalid = common.WeightedMix.fixed(49)
        with self.assertRaisesRegex(ValueError, "connection lifetime"):
            tcp.TcpWorkloadClient(
                tcp.TcpClientConfig(
                    **{
                        **config.__dict__,
                        "connection_lifetime_ms_mix": invalid,
                    }
                )
            )


class TcpConnectionCloseTests(unittest.TestCase):
    """Exercise close ordering and budgets without creating real sockets."""

    class ScriptedClock:
        def __init__(self, costs=None):
            self.now = 100.0
            self.costs = costs or {}
            self.timeouts = []
            self.active_timeout = None

        def monotonic(self):
            return self.now

        async def wait_for(self, awaitable, timeout):
            self.timeouts.append(timeout)
            self.active_timeout = timeout
            try:
                return await awaitable
            finally:
                self.active_timeout = None

        def consume(self, stage):
            cost = self.costs.get(stage, 0.0)
            if self.active_timeout is not None and cost >= self.active_timeout:
                self.now += max(0.0, self.active_timeout)
                raise asyncio.TimeoutError
            self.now += cost

    class Reader:
        def __init__(self, events, *, result=b"", error=None, clock=None):
            self.events = events
            self.result = result
            self.error = error
            self.clock = clock

        async def read(self, size):
            self.events.append(("read", size))
            if self.clock is not None:
                self.clock.consume("read")
            if self.error is not None:
                raise self.error
            return self.result

    class Writer:
        def __init__(self, events, *, errors=None, clock=None):
            self.events = events
            self.errors = errors or {}
            self.clock = clock
            self.transport = SimpleNamespace(abort=self.abort)

        def _stage(self, stage):
            self.events.append(stage)
            if self.clock is not None:
                self.clock.consume(stage)
            if stage in self.errors:
                raise self.errors[stage]

        def write_eof(self):
            self._stage("write_eof")

        def write(self, data):
            self.events.append(("write", len(data)))

        async def drain(self):
            self._stage("drain")

        def close(self):
            self._stage("close")

        async def wait_closed(self):
            self._stage("wait_closed")

        def abort(self):
            self._stage("abort")

    def _client(self, *, io_timeout=1.0, mode="keepalive"):
        client = tcp.TcpWorkloadClient(
            tcp.TcpClientConfig(
                host="127.0.0.1",
                port=18080,
                duration=2.0,
                operations=1,
                seed=315,
                pps=0.0,
                cps=0.0,
                mbps=0.0,
                io_timeout=io_timeout,
                latency_samples=16,
                concurrency=1,
                mode=mode,
                keepalive_ratio=0.0 if mode == "short" else 1.0,
                request_bytes=8,
                response_mix=common.WeightedMix.fixed(8),
            )
        )
        client.stats.active_change(1)
        return client

    def _run_with_clock(self, client, channel, clock, *, abort=False):
        async def exercise():
            # Replace only tcp's clock reference: the event loop and the
            # thread-safe statistics continue to use the real monotonic clock.
            with mock.patch.object(
                tcp, "time", SimpleNamespace(monotonic=clock.monotonic)
            ), mock.patch.object(tcp.asyncio, "wait_for", clock.wait_for):
                if abort:
                    await client._abort_connection(channel)
                else:
                    await client._close_connection(channel)

        asyncio.run(exercise())

    def _assert_closed(self, client, *, errors):
        summary = client.stats.summary()
        self.assertEqual(summary["errors"], errors)
        self.assertEqual(summary["active_flows_current"], 0)

    def test_normal_close_observes_peer_eof_before_local_close(self):
        events = []
        client = self._client()
        clock = self.ScriptedClock(
            {"drain": 0.25, "read": 0.35, "wait_closed": 0.15}
        )
        self._run_with_clock(
            client,
            (self.Reader(events, clock=clock), self.Writer(events, clock=clock)),
            clock,
        )
        self.assertEqual(
            events, ["write_eof", "drain", ("read", 1), "close", "wait_closed"]
        )
        self.assertEqual(len(clock.timeouts), 3)
        for actual, expected in zip(clock.timeouts, (1.0, 0.75, 0.40)):
            self.assertAlmostEqual(actual, expected)
        self.assertAlmostEqual(clock.now, 100.75)
        self._assert_closed(client, errors=0)

    def test_delayed_peer_eof_keeps_close_task_and_flow_live(self):
        async def exercise():
            events = []
            waiting = asyncio.Event()
            release = asyncio.Event()

            class DelayedReader:
                async def read(self, size):
                    events.append(("read", size))
                    waiting.set()
                    await release.wait()
                    return b""

            client = self._client(io_timeout=2.0)
            writer = self.Writer(events)
            task = asyncio.create_task(
                client._close_connection((DelayedReader(), writer))
            )
            try:
                await asyncio.wait_for(waiting.wait(), timeout=1.0)
                self.assertFalse(task.done())
                self.assertNotIn("close", events)
                self.assertEqual(client.stats.summary()["active_flows_current"], 1)
                release.set()
                await asyncio.wait_for(task, timeout=1.0)
            finally:
                release.set()
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
            self.assertEqual(
                events,
                ["write_eof", "drain", ("read", 1), "close", "wait_closed"],
            )
            self._assert_closed(client, errors=0)

        asyncio.run(exercise())

    def test_all_close_stages_share_one_timeout_budget(self):
        cases = (
            {"drain": 1.25},
            {"drain": 0.25, "read": 0.80},
            {"drain": 0.25, "read": 0.50, "wait_closed": 0.50},
        )
        for costs in cases:
            with self.subTest(costs=costs):
                events = []
                client = self._client()
                clock = self.ScriptedClock(costs)
                self._run_with_clock(
                    client,
                    (
                        self.Reader(events, clock=clock),
                        self.Writer(events, clock=clock),
                    ),
                    clock,
                )
                self.assertAlmostEqual(clock.now, 101.0)
                self.assertTrue(all(0.0 < value <= 1.0 for value in clock.timeouts))
                self.assertEqual(events.count("close"), 1)
                self.assertEqual(events.count("abort"), 1)
                self._assert_closed(client, errors=1)

    def test_reset_or_unexpected_trailing_data_fails_close_once(self):
        cases = (
            (b"", ConnectionResetError("peer reset")),
            (b"x", None),
        )
        for result, error in cases:
            with self.subTest(result=result, error=type(error).__name__):
                events = []
                client = self._client()
                clock = self.ScriptedClock()
                self._run_with_clock(
                    client,
                    (
                        self.Reader(events, result=result, error=error, clock=clock),
                        self.Writer(events, clock=clock),
                    ),
                    clock,
                )
                self.assertEqual(events.count(("read", 1)), 1)
                self.assertEqual(events.count("close"), 1)
                self.assertEqual(events.count("wait_closed"), 1)
                self._assert_closed(client, errors=1)

    def test_local_close_failure_counts_once_even_when_peer_eof_also_failed(self):
        for trailing in (b"", b"x"):
            with self.subTest(trailing=trailing):
                events = []
                client = self._client()
                clock = self.ScriptedClock()
                self._run_with_clock(
                    client,
                    (
                        self.Reader(events, result=trailing, clock=clock),
                        self.Writer(
                            events,
                            errors={"wait_closed": ConnectionResetError("close reset")},
                            clock=clock,
                        ),
                    ),
                    clock,
                )
                self.assertEqual(events.count("close"), 1)
                self.assertEqual(events.count("wait_closed"), 1)
                self.assertEqual(events.count("abort"), 1)
                self._assert_closed(client, errors=1)

    def test_write_eof_or_drain_failure_still_releases_flow_once(self):
        for stage in ("write_eof", "drain"):
            with self.subTest(stage=stage):
                events = []
                client = self._client()
                clock = self.ScriptedClock()
                self._run_with_clock(
                    client,
                    (
                        self.Reader(events, clock=clock),
                        self.Writer(
                            events,
                            errors={stage: BrokenPipeError("peer closed")},
                            clock=clock,
                        ),
                    ),
                    clock,
                )
                self.assertNotIn(("read", 1), events)
                self.assertEqual(events.count("close"), 1)
                self.assertEqual(events.count("wait_closed"), 1)
                self._assert_closed(client, errors=1)

    def test_abort_skips_eof_and_preserves_original_exchange_error(self):
        for close_cost in (0.0, 2.0):
            with self.subTest(close_cost=close_cost):
                events = []
                client = self._client()
                client.stats.add(errors=1)
                clock = self.ScriptedClock({"wait_closed": close_cost})
                self._run_with_clock(
                    client,
                    (self.Reader(events, clock=clock), self.Writer(events, clock=clock)),
                    clock,
                    abort=True,
                )
                self.assertNotIn("write_eof", events)
                self.assertNotIn("drain", events)
                self.assertNotIn(("read", 1), events)
                self.assertNotIn("close", events)
                self.assertEqual(events[0], "abort")
                self.assertEqual(events.count("wait_closed"), 1)
                self.assertEqual(events.count("abort"), 1 if close_cost == 0.0 else 2)
                self.assertLessEqual(clock.now, 101.0)
                self._assert_closed(client, errors=1)

    def test_failed_worker_exchange_aborts_short_and_persistent_channels_once(self):
        for mode in ("short", "keepalive"):
            with self.subTest(mode=mode):
                events = []
                client = self._client(mode=mode)
                channel = self.Reader(events), self.Writer(events)
                connect = mock.AsyncMock(return_value=channel)
                response = mock.AsyncMock(side_effect=ConnectionResetError("response reset"))

                async def exercise():
                    with mock.patch.object(
                        client, "_new_connection", connect
                    ), mock.patch.object(
                        client, "_read_http_response", response
                    ), mock.patch.object(tcp.asyncio, "sleep", mock.AsyncMock()):
                        await client._worker(0)

                asyncio.run(exercise())
                connect.assert_awaited_once()
                response.assert_awaited_once()
                self.assertEqual(events.count("abort"), 1)
                self.assertEqual(events.count("wait_closed"), 1)
                self.assertEqual(events.count("drain"), 1)
                self.assertNotIn("write_eof", events)
                self.assertNotIn(("read", 1), events)
                self.assertNotIn("close", events)
                self._assert_closed(client, errors=1)


class SocketIntegrationTests(unittest.TestCase):
    def _assert_tcp_naturally_drained(self, running):
        # A client's observed FIN may precede the server thread's bookkeeping.
        # Permit that bounded scheduling race, but never force stop to satisfy
        # a successful client's claim that all connections are finished.
        deadline = time.monotonic() + 1.0
        while True:
            snapshot = running.server.stats.summary()
            drained = snapshot["active_flows_current"] == 0 and snapshot.get(
                "connections_closed", 0
            ) == snapshot.get("connections", 0)
            if drained or time.monotonic() >= deadline:
                break
            time.sleep(0.005)
        self.assertFalse(running.server.stop.is_set())
        self.assertTrue(drained, f"TCP peer did not finish naturally: {snapshot}")

    def test_tcp_http1_and_framed_keepalive_short_and_mixed(self) -> None:
        require_network(self)
        mixture = common.parse_weighted_mix("0:1,128:3,4096:1", 4096)
        for protocol in ("http1", "framed"):
            with self.subTest(protocol=protocol):
                running = tcp_server(protocol)
                port = running.start()
                completed = 0
                try:
                    for mode in ("keepalive", "short", "mixed"):
                        client = tcp.TcpWorkloadClient(
                            tcp.TcpClientConfig(
                                host="127.0.0.1",
                                port=port,
                                duration=2.0,
                                operations=8,
                                seed=303,
                                pps=0.0,
                                cps=0.0,
                                mbps=0.0,
                                io_timeout=1.0,
                                latency_samples=128,
                                concurrency=3,
                                mode=mode,
                                keepalive_ratio=0.5,
                                request_bytes=32,
                                response_mix=mixture,
                                protocol=protocol,
                                connection_lifetime_ms_mix=(
                                    common.WeightedMix.fixed(50)
                                    if mode == "short"
                                    else common.WeightedMix.fixed(
                                        tcp.MAX_CONNECTION_LIFETIME_MS
                                    )
                                ),
                            )
                        )
                        summary = client.run()
                        self._assert_tcp_naturally_drained(running)
                        completed += summary["operations"]
                        self.assertEqual(summary.get("errors", 0), 0)
                        self.assertEqual(summary["operations"], 8)
                        self.assertEqual(summary["latency_ms"]["count"], 8)
                        self.assertEqual(
                            summary["connect_latency_ms"]["count"],
                            summary["connections"],
                        )
                        self.assertGreaterEqual(summary["active_flows_peak"], 1)
                        self.assertLessEqual(summary["active_flows_peak"], 3)
                        self.assertEqual(summary["active_flows_current"], 0)
                        if mode == "short":
                            self.assertEqual(summary["connections"], 8)
                            self.assertEqual(
                                summary.get("connection_lifetime_expirations", 0), 0
                            )
                        distribution = sum(
                            value
                            for key, value in summary.items()
                            if key.startswith("response_size_")
                        )
                        self.assertEqual(distribution, 8)
                finally:
                    server_summary = running.close()
                self.assertEqual(server_summary.get("internal_errors", 0), 0)
                self.assertEqual(server_summary["operations"], completed)

    def test_tcp_keepalive_lifetime_forces_real_reconnects(self) -> None:
        require_network(self)
        running = RunningServer(
            tcp.TcpWorkloadServer(
                tcp.TcpServerConfig(
                    host="127.0.0.1",
                    port=0,
                    duration=10.0,
                    seed=311,
                    io_timeout=1.0,
                    processing_delay_ms=75.0,
                    workers=4,
                    backlog=16,
                    max_request_bytes=1024,
                    max_response_bytes=1024,
                    protocol="http1",
                )
            )
        )
        port = running.start()
        try:
            client = tcp.TcpWorkloadClient(
                tcp.TcpClientConfig(
                    host="127.0.0.1",
                    port=port,
                    duration=2.0,
                    operations=4,
                    seed=312,
                    pps=0.0,
                    cps=0.0,
                    mbps=0.0,
                    io_timeout=1.0,
                    latency_samples=16,
                    concurrency=1,
                    mode="keepalive",
                    keepalive_ratio=1.0,
                    request_bytes=32,
                    response_mix=common.WeightedMix.fixed(128),
                    connection_lifetime_ms_mix=common.WeightedMix.fixed(50),
                )
            )
            summary = client.run()
            self._assert_tcp_naturally_drained(running)
        finally:
            server_summary = running.close()
        self.assertEqual(summary.get("errors", 0), 0)
        self.assertEqual(summary["operations"], 4)
        self.assertEqual(summary["connections"], 4)
        self.assertEqual(summary["connection_lifetime_expirations"], 3)
        self.assertEqual(summary["active_flows_current"], 0)
        self.assertEqual(server_summary.get("internal_errors", 0), 0)
        self.assertEqual(server_summary["operations"], 4)

    def test_tcp_turnover_headroom_avoids_peer_connection_refusal(self) -> None:
        require_network(self)
        # Mirrors the CI burst: base concurrency 32 scaled by 1.5.
        concurrency = 48
        running = RunningServer(
            tcp.TcpWorkloadServer(
                tcp.TcpServerConfig(
                    host="127.0.0.1",
                    port=0,
                    duration=10.0,
                    seed=313,
                    io_timeout=1.0,
                    processing_delay_ms=0.0,
                    workers=concurrency * 2,
                    backlog=64,
                    max_request_bytes=1024,
                    max_response_bytes=1024,
                    protocol="http1",
                )
            )
        )
        port = running.start()
        try:
            client = tcp.TcpWorkloadClient(
                tcp.TcpClientConfig(
                    host="127.0.0.1",
                    port=port,
                    duration=3.0,
                    operations=512,
                    seed=314,
                    pps=0.0,
                    cps=0.0,
                    mbps=0.0,
                    io_timeout=1.0,
                    latency_samples=128,
                    concurrency=concurrency,
                    mode="mixed",
                    keepalive_ratio=0.5,
                    request_bytes=32,
                    response_mix=common.WeightedMix.fixed(128),
                    connection_lifetime_ms_mix=common.WeightedMix.fixed(50),
                )
            )
            summary = client.run()
            self._assert_tcp_naturally_drained(running)
        finally:
            server_summary = running.close()
        self.assertEqual(summary["operations"], 512)
        self.assertEqual(summary.get("errors", 0), 0)
        self.assertEqual(server_summary["operations"], 512)
        self.assertEqual(server_summary.get("connections_rejected", 0), 0)
        self.assertEqual(server_summary.get("protocol_errors", 0), 0)
        self.assertEqual(server_summary.get("internal_errors", 0), 0)

    def test_udp_stream_and_sampled_echo_use_multiple_real_flows(self) -> None:
        require_network(self)
        running = udp_server()
        port = running.start()
        try:
            client = udp.UdpWorkloadClient(
                udp.UdpClientConfig(
                    host="127.0.0.1",
                    port=port,
                    duration=2.0,
                    operations=80,
                    seed=404,
                    pps=0.0,
                    mbps=0.0,
                    io_timeout=1.0,
                    latency_samples=128,
                    flows=4,
                    reply_every=4,
                    request_bytes=128,
                    request_mix=common.parse_weighted_mix(
                        "0:1,128:2,512:1", 512
                    ),
                    response_mix=common.parse_weighted_mix("64:3,512:1", 512),
                    socket_buffer_bytes=64 * 1024,
                )
            )
            summary = client.run()
        finally:
            server_summary = running.close()
        self.assertEqual(summary.get("errors", 0), 0)
        self.assertEqual(summary["packets_sent"], 80)
        expected = summary["replies_expected"]
        self.assertGreaterEqual(expected, 17)
        self.assertLessEqual(expected, 20)
        self.assertEqual(summary["packets_replied"], expected)
        self.assertEqual(summary["latency_ms"]["count"], expected)
        self.assertEqual(summary["connect_latency_ms"]["count"], 4)
        self.assertEqual(summary["active_flows_peak"], 4)
        self.assertEqual(summary["active_flows_current"], 0)
        self.assertEqual(summary["barriers_expected"], 4)
        self.assertEqual(summary["barriers_sent"], 4)
        self.assertEqual(summary["barrier_acks_received"], 4)
        self.assertEqual(summary["barrier_errors"], 0)
        request_distribution = sum(
            value
            for key, value in summary.items()
            if key.startswith("request_size_")
        )
        self.assertEqual(request_distribution, 80)
        self.assertEqual(server_summary["packets_received"], 80)
        self.assertEqual(server_summary["operations"], 80)
        self.assertEqual(server_summary["barriers_received"], 4)
        self.assertEqual(server_summary["barrier_acks_sent"], 4)

    def test_udp_deadline_does_not_create_a_sequence_hole_before_barrier(self) -> None:
        require_network(self)
        running = udp_server()
        port = running.start()
        try:
            client = udp.UdpWorkloadClient(
                udp.UdpClientConfig(
                    host="127.0.0.1",
                    port=port,
                    duration=0.15,
                    operations=0,
                    seed=405,
                    pps=1.0,
                    mbps=0.0,
                    io_timeout=0.5,
                    latency_samples=16,
                    flows=4,
                    reply_every=0,
                    request_bytes=128,
                    response_mix=common.WeightedMix.fixed(0),
                    socket_buffer_bytes=64 * 1024,
                )
            )
            summary = client.run()
        finally:
            server_summary = running.close()
        self.assertEqual(summary["packets_sent"], 1)
        self.assertEqual(summary.get("errors", 0), 0)
        self.assertEqual(summary["barriers_expected"], 4)
        self.assertEqual(summary["barrier_acks_received"], 4)
        self.assertEqual(summary["barrier_errors"], 0)
        self.assertEqual(server_summary["packets_received"], 1)
        self.assertEqual(server_summary["barriers_received"], 4)
        self.assertEqual(server_summary["barrier_acks_sent"], 4)
        self.assertEqual(server_summary.get("protocol_errors", 0), 0)
        self.assertEqual(server_summary.get("incomplete_drain_flows", 0), 0)

    def test_udp_barrier_waits_for_the_exact_contiguous_prefix(self) -> None:
        require_network(self)
        running = udp_server()
        port = running.start()
        connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        connection.settimeout(0.15)
        try:
            connection.connect(("127.0.0.1", port))
            connection.sendall(udp_request(17, 1))
            connection.sendall(udp_request(17, 3))
            barrier_sent_ns = time.monotonic_ns()
            connection.sendall(
                udp_request(
                    17,
                    4,
                    flags=udp.FLAG_BARRIER,
                    client_send_ns=barrier_sent_ns,
                )
            )
            with self.assertRaises(socket.timeout):
                connection.recv(udp.MAX_DATAGRAM_BYTES)

            connection.sendall(udp_request(17, 2))
            response = connection.recv(udp.MAX_DATAGRAM_BYTES)
            fields = udp.RESPONSE_HEADER.unpack(response)
            self.assertEqual(fields[0], udp.RESPONSE_MAGIC)
            self.assertEqual(fields[5], 17)
            self.assertEqual(fields[6], 4)
            self.assertEqual(fields[7], barrier_sent_ns)
        finally:
            connection.close()
            server_summary = running.close()
        self.assertEqual(server_summary["operations"], 3)
        self.assertEqual(server_summary["barriers_received"], 1)
        self.assertEqual(server_summary["barrier_acks_sent"], 1)
        self.assertEqual(server_summary.get("protocol_errors", 0), 0)
        self.assertEqual(server_summary.get("incomplete_drain_flows", 0), 0)

    def test_udp_missing_or_duplicate_sequence_never_becomes_clean_evidence(self) -> None:
        require_network(self)
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                running = udp_server()
                port = running.start()
                connection = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                connection.settimeout(0.15)
                try:
                    connection.connect(("127.0.0.1", port))
                    connection.sendall(udp_request(23, 1))
                    if duplicate:
                        connection.sendall(udp_request(23, 1))
                        barrier_sequence = 2
                    else:
                        barrier_sequence = 3
                    connection.sendall(
                        udp_request(23, barrier_sequence, flags=udp.FLAG_BARRIER)
                    )
                    if duplicate:
                        response = connection.recv(udp.MAX_DATAGRAM_BYTES)
                        self.assertEqual(
                            udp.RESPONSE_HEADER.unpack(response)[6], barrier_sequence
                        )
                    else:
                        with self.assertRaises(socket.timeout):
                            connection.recv(udp.MAX_DATAGRAM_BYTES)
                finally:
                    connection.close()
                    server_summary = running.close()
                self.assertGreater(server_summary.get("protocol_errors", 0), 0)
                if not duplicate:
                    self.assertEqual(server_summary.get("barrier_acks_sent", 0), 0)
                    self.assertEqual(server_summary.get("incomplete_drain_flows", 0), 1)

    def test_udp_reorder_window_is_strictly_bounded(self) -> None:
        state = udp._FlowDrainState()
        with self.assertRaisesRegex(ValueError, "reordering exceeded"):
            udp.UdpWorkloadServer._record_data_sequence(
                state, udp.MAX_UDP_REORDER_WINDOW + 2
            )


class IdentityProbeIntegrationTests(unittest.TestCase):
    def _probe_binary(self, directory: str) -> str:
        provided = os.environ.get("OPENSHIELD_IDENTITY_PROBE")
        if provided:
            return provided
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("no C compiler and OPENSHIELD_IDENTITY_PROBE is unset")
        output = str(Path(directory) / "openshield-identity-probe")
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pedantic",
                str(WORKLOAD_DIRECTORY / "identity_probe.c"),
                "-o",
                output,
            ],
            check=True,
            timeout=30,
        )
        return output

    def _run_probe(self, executable: str, mode: str, port: int) -> dict:
        completed = subprocess.run(
            [executable, mode, "127.0.0.1", str(port), "1000", "128"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["event"], "probe")
        self.assertTrue(result["success"])
        self.assertGreaterEqual(result["latency_ms"], 0.0)
        return result

    def test_distinct_executable_identity_supports_tcp_and_udp(self) -> None:
        require_network(self)
        with tempfile.TemporaryDirectory() as directory:
            executable = self._probe_binary(directory)
            self.assertNotEqual(os.path.realpath(executable), os.path.realpath(sys.executable))

            for protocol, mode in (("http1", "tcp"), ("framed", "tcp-framed")):
                with self.subTest(mode=mode):
                    running = tcp_server(protocol)
                    port = running.start()
                    try:
                        result = self._run_probe(executable, mode, port)
                    finally:
                        running.close()
                    self.assertEqual(result["protocol"], protocol)

            running = udp_server()
            port = running.start()
            server_summary = None
            try:
                result = self._run_probe(executable, "udp", port)
            finally:
                server_summary = running.close()
            self.assertEqual(result["transport"], "udp")
            self.assertEqual(server_summary.get("protocol_errors", 0), 0)
            self.assertEqual(server_summary.get("incomplete_drain_flows", 0), 0)
            self.assertEqual(server_summary.get("barriers_received", 0), 1)
            self.assertEqual(server_summary.get("barrier_acks_sent", 0), 1)


class StandaloneProcessTests(unittest.TestCase):
    def _start_server(self, script: Path, arguments: list[str]):
        process = subprocess.Popen(
            [sys.executable, "-B", str(script), "server", *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        readable, _, _ = select.select([process.stdout], [], [], 3.0)
        if not readable:
            process.terminate()
            _stdout, stderr = process.communicate(timeout=3.0)
            self.fail(f"standalone server did not become ready: {stderr}")
        line = process.stdout.readline()
        if not line:
            _stdout, stderr = process.communicate(timeout=3.0)
            self.fail(f"standalone server exited before readiness: {stderr}")
        ready = json.loads(line)
        self.assertEqual(ready["event"], "ready")
        return process, int(ready["port"])

    def _stop_server(self, process: subprocess.Popen) -> dict:
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=3.0)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=3.0)
            self.fail(f"standalone server ignored its bounded shutdown: {stderr}")
        self.assertEqual(process.returncode, 0, stderr)
        lines = [json.loads(line) for line in stdout.splitlines() if line]
        self.assertTrue(lines, "standalone server emitted no final summary")
        self.assertEqual(lines[-1]["event"], "summary")
        return lines[-1]

    def _client(self, script: Path, config_path: Path) -> tuple[list[str], dict]:
        command = [
            sys.executable,
            "-B",
            str(script),
            "client",
            "--config-file",
            str(config_path),
        ]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(result["event"], "summary")
        self.assertTrue(result["ok"])
        return command, result

    def test_tcp_phase_config_changes_without_changing_process_argv(self) -> None:
        require_network(self)
        server, port = self._start_server(
            WORKLOAD_DIRECTORY / "tcp.py",
            ["--duration", "10", "--protocol", "http1"],
        )
        try:
            with tempfile.TemporaryDirectory() as directory:
                config_path = Path(directory) / "openshield-perf-phase.json"
                phase = {
                    "port": port,
                    "duration": 0.5,
                    "operations": 12,
                    "pps": 0,
                    "cps": 0,
                    "mbps": 0,
                    "concurrency": 2,
                    "mode": "mixed",
                    "keepalive_ratio": 0.5,
                    "connection_lifetime_ms_mix": "50:3,250:1",
                    "request_bytes": 32,
                    "response_mix": "128:3,4096:1",
                    "protocol": "http1",
                }
                config_path.write_text(json.dumps(phase), encoding="utf-8")
                config_path.chmod(0o600)
                first_argv, first = self._client(
                    WORKLOAD_DIRECTORY / "tcp.py", config_path
                )
                phase["operations"] = 6
                config_path.write_text(json.dumps(phase), encoding="utf-8")
                second_argv, second = self._client(
                    WORKLOAD_DIRECTORY / "tcp.py", config_path
                )
                self.assertEqual(first_argv, second_argv)
                self.assertEqual(first["metrics"]["operations"], 12)
                self.assertEqual(second["metrics"]["operations"], 6)
                self.assertEqual(
                    first["config"]["connection_lifetime_ms_mix"],
                    [
                        {"milliseconds": 50, "weight": 3},
                        {"milliseconds": 250, "weight": 1},
                    ],
                )
        finally:
            self._stop_server(server)

    def test_udp_server_and_client_are_standalone_processes(self) -> None:
        require_network(self)
        server, port = self._start_server(
            WORKLOAD_DIRECTORY / "udp.py", ["--duration", "10"]
        )
        try:
            with tempfile.TemporaryDirectory() as directory:
                config_path = Path(directory) / "openshield-perf-phase.json"
                config_path.write_text(
                    json.dumps(
                        {
                            "port": port,
                            "duration": 0.5,
                            "operations": 40,
                            "pps": 0,
                            "mbps": 0,
                            "flows": 3,
                            "reply_every": 2,
                            "request_bytes": 64,
                            "request_mix": "0:1,64:2,512:1",
                            "response_mix": "64:1,512:1",
                            "socket_buffer_bytes": 65536,
                        }
                    ),
                    encoding="utf-8",
                )
                config_path.chmod(0o600)
                _argv, result = self._client(
                    WORKLOAD_DIRECTORY / "udp.py", config_path
                )
                self.assertEqual(result["metrics"]["packets_sent"], 40)
                self.assertEqual(result["metrics"].get("errors", 0), 0)
        finally:
            self._stop_server(server)

    def test_tcp_and_udp_clients_offer_a_bounded_explicit_start_gate(self) -> None:
        require_network(self)
        cases = (
            (
                WORKLOAD_DIRECTORY / "tcp.py",
                ["--duration", "10", "--protocol", "framed"],
                {
                    "duration": 0.5,
                    "operations": 1,
                    "pps": 0,
                    "cps": 0,
                    "mbps": 0,
                    "concurrency": 1,
                    "mode": "short",
                    "keepalive_ratio": 0,
                    "connection_lifetime_ms_mix": "50:1",
                    "request_bytes": 8,
                    "response_mix": "8:1",
                    "protocol": "framed",
                },
            ),
            (
                WORKLOAD_DIRECTORY / "udp.py",
                ["--duration", "10"],
                {
                    "duration": 0.5,
                    "operations": 1,
                    "pps": 0,
                    "mbps": 0,
                    "flows": 1,
                    "reply_every": 1,
                    "request_bytes": 8,
                    "request_mix": "8:1",
                    "response_mix": "8:1",
                    "socket_buffer_bytes": 65536,
                },
            ),
        )
        for script, server_arguments, payload in cases:
            with self.subTest(script=script.name):
                server, port = self._start_server(script, server_arguments)
                process = None
                metric = None
                try:
                    with tempfile.TemporaryDirectory() as directory:
                        config_path = Path(directory) / "start-gated-client.json"
                        config_path.write_text(
                            json.dumps({**payload, "port": port}), encoding="utf-8"
                        )
                        config_path.chmod(0o600)
                        process = subprocess.Popen(
                            [
                                sys.executable,
                                "-B",
                                str(script),
                                "client",
                                "--config-file",
                                str(config_path),
                                "--start-gate-stdin",
                            ],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            bufsize=1,
                        )
                        assert process.stdout is not None
                        assert process.stdin is not None
                        readable, _, _ = select.select([process.stdout], [], [], 3.0)
                        self.assertTrue(readable, "client did not publish start readiness")
                        spawned = json.loads(process.stdout.readline())
                        self.assertEqual(spawned["event"], "spawned")
                        self.assertEqual(spawned["role"], "client")
                        self.assertEqual(
                            spawned["control_protocol"],
                            "stdin_start_finish_release_v2",
                        )
                        ready = json.loads(process.stdout.readline())
                        self.assertEqual(ready["event"], "ready")
                        self.assertEqual(ready["role"], "client")
                        self.assertEqual(
                            ready["control_protocol"],
                            "stdin_start_finish_release_v2",
                        )
                        for field in ("pid", "starttime", "executable", "uid"):
                            self.assertEqual(ready[field], spawned[field])
                        self.assertIsNone(process.poll())
                        metric = subprocess.Popen(
                            [
                                sys.executable,
                                "-I",
                                "-B",
                                "-S",
                                str(WORKLOAD_DIRECTORY.parent / "metrics.py"),
                                "--pid",
                                "0",
                                "--workload-pid",
                                str(ready["pid"]),
                                "--interface",
                                "lo",
                                "--duration",
                                "10",
                                "--interval",
                                "0.02",
                                "--synchronize",
                            ],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            bufsize=1,
                        )
                        assert metric.stdin is not None
                        assert metric.stdout is not None
                        metric_ready = json.loads(metric.stdout.readline())
                        self.assertEqual(metric_ready["event"], "ready")
                        metric.stdin.write("start\n")
                        metric.stdin.flush()
                        metric_started = json.loads(metric.stdout.readline())
                        self.assertEqual(metric_started["event"], "start")
                        process.stdin.write("start\n")
                        process.stdin.flush()
                        started = json.loads(process.stdout.readline())
                        self.assertEqual(started["event"], "started")
                        self.assertGreater(started["boundary_monotonic_ns"], 0)
                        summary = json.loads(process.stdout.readline())
                        finished = json.loads(process.stdout.readline())
                        self.assertEqual(finished["event"], "finished")
                        self.assertEqual(finished["hold"], "awaiting_release")
                        self.assertIsNone(process.poll())
                        metric.stdin.write("stop\n")
                        metric.stdin.flush()
                        metric.stdin.close()
                        metric.stdin = None
                        metric_document = json.loads(metric.stdout.readline())
                        _metric_stdout, metric_stderr = metric.communicate(timeout=5.0)
                        self.assertEqual(metric.returncode, 0, metric_stderr)
                        self.assertEqual(
                            metric_document["workload_process"]["pid"], ready["pid"]
                        )
                        self.assertTrue(
                            metric_document["workload_process"]["alive_end"]
                        )
                        self.assertIsNotNone(
                            metric_document["workload_process"]["cpu_seconds"]
                        )
                        self.assertGreater(
                            metric_document["workload_process"]["rss_bytes_peak"], 0
                        )
                        process.stdin.write("release\n")
                        process.stdin.flush()
                        released = json.loads(process.stdout.readline())
                        self.assertEqual(released["event"], "released")
                        stdout, stderr = process.communicate(timeout=5.0)
                        self.assertEqual(process.returncode, 0, stderr)
                        self.assertEqual(stdout, "")
                        self.assertEqual(summary["event"], "summary")
                        self.assertTrue(summary["ok"])
                finally:
                    for child in (metric, process):
                        if child is not None and child.poll() is None:
                            child.kill()
                            child.communicate(timeout=2.0)
                    self._stop_server(server)


if __name__ == "__main__":
    unittest.main(verbosity=2)
