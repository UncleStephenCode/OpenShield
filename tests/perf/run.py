#!/usr/bin/env python3
"""Run reproducible OpenShield host-firewall benchmarks in isolated containers."""

from __future__ import annotations

import os
import sys

# Re-exec before importing any workspace-resolvable module.  This makes direct
# invocations as strict as the CI wrapper: no cwd/script-directory import path,
# no PYTHON* influence, no user site, and no bytecode writes.
if __name__ == "__main__" and (
    not sys.flags.isolated or not sys.dont_write_bytecode or not sys.flags.no_site
):
    os.execv(
        sys.executable,
        [
            sys.executable,
            "-I",
            "-B",
            "-S",
            os.path.realpath(__file__),
            *sys.argv[1:],
        ],
    )

import argparse
import csv
import errno
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import secrets
import selectors
import shlex
import signal
import stat
import subprocess
import tempfile
import time
from typing import Any, Iterable, TextIO


# One-sided 95% Student-t critical values for 2..19 degrees of freedom.  The
# configuration bounds steady repetitions to 20, so this table covers every
# supported paired sample set without adding a mutable scientific dependency
# to the release gate.
ONE_SIDED_T_95 = {
    2: 2.919986,
    3: 2.353363,
    4: 2.131847,
    5: 2.015048,
    6: 1.943180,
    7: 1.894579,
    8: 1.859548,
    9: 1.833113,
    10: 1.812461,
    11: 1.795885,
    12: 1.782288,
    13: 1.770933,
    14: 1.761310,
    15: 1.753050,
    16: 1.745884,
    17: 1.739607,
    18: 1.734064,
    19: 1.729133,
}
MINIMUM_RELATIVE_PAIRED_SAMPLES = 3
RELATIVE_CONFIDENCE_LEVEL = 0.95
# cgroup-v2 reports usage_usec.  A paired CPU percentage cannot support a
# threshold claim when two one-microsecond endpoint quantization errors are as
# large as that threshold relative to the baseline.  Such evidence is invalid,
# never silently passed; real workload CPU is normally orders of magnitude
# above this floor.
CGROUP_CPU_ACCOUNTING_RESOLUTION_SECONDS = 1e-6

def _load_environment_source(
    source_path: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Compile the pinned helper from source, never from unchecked bytecode."""

    path = (
        Path(__file__).resolve().with_name("environment.py")
        if source_path is None
        else source_path
    )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    payload = bytearray()
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > 4 * 1024 * 1024
        ):
            raise RuntimeError("environment helper is not a bounded regular source file")
        while chunk := os.read(descriptor, 1024 * 1024):
            payload.extend(chunk)
            if len(payload) > 4 * 1024 * 1024:
                raise RuntimeError("environment helper exceeds its source byte bound")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or len(payload) != before.st_size
    ):
        raise RuntimeError("environment helper changed while loading")
    namespace: dict[str, Any] = {
        "__builtins__": __builtins__,
        "__file__": str(path),
        "__name__": "openshield_perf_environment_source",
        "__package__": None,
    }
    exec(compile(bytes(payload), str(path), "exec", dont_inherit=True), namespace)
    return namespace, {
        "path": "tests/perf/environment.py",
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


_ENVIRONMENT_SOURCE, _ENVIRONMENT_SOURCE_EVIDENCE = _load_environment_source()
EnvironmentEvidenceError = _ENVIRONMENT_SOURCE["EnvironmentEvidenceError"]
parse_os_release = _ENVIRONMENT_SOURCE["parse_os_release"]
parse_rpm_nevra_records = _ENVIRONMENT_SOURCE["parse_rpm_nevra_records"]
validate_docker_image_id = _ENVIRONMENT_SOURCE["validate_docker_image_id"]
validate_machine = _ENVIRONMENT_SOURCE["validate_machine"]
validate_sha256_digest = _ENVIRONMENT_SOURCE["validate_sha256_digest"]
validate_uname = _ENVIRONMENT_SOURCE["validate_uname"]


CONFIG_SCHEMA = "openshield.perf.config.v2"
REPORT_SCHEMA = "openshield.perf.report.v2"
OVERLOAD_SCHEMA = "openshield.perf.overload.v2"
BASELINE_PAIRING_SCHEMA = "openshield.perf.baseline-pairing.v2"
WORKLOAD_SCHEMA = "openshield.perf.workload.v1"
METRICS_SCHEMA = "openshield.perf.metrics.v3"
METRICS_CONTROL_SCHEMA = "openshield.perf.metrics.control.v2"
WORKLOAD_CONTROL_PROTOCOL = "stdin_start_finish_release_v2"
# The inner client/collector waits are deliberately longer than every bounded
# controller pre-start operation. A delayed controller therefore fails and
# cancels the exact inner process before the inner protocol can time out alone.
INNER_CONTROL_WAIT_SECONDS = 120.0
CONTROLLER_PRESTART_BOUND_SECONDS = 60.0
CONTROLLER_FINISH_RELEASE_BOUND_SECONDS = 45.0
PROCESS_TERMINATION_GRACE_SECONDS = 3.0
MAX_CONFIG_BYTES = 512 * 1024
MAX_PROFILES = 32
MAX_LOAD_LEVELS = 32
# The production matrix may span more than one day once every statistical
# sample is an independent AB/BA pair.  Keep the bound explicit and finite.
MAX_ESTIMATED_WORKLOAD_SECONDS = 172_800.0
MIN_TCP_CONNECTION_LIFETIME_MS = 50
MAX_TCP_CONNECTION_LIFETIME_MS = 3_600_000
MAX_TCP_CLIENT_CONCURRENCY = 512
TCP_SERVER_TURNOVER_HEADROOM = 2
MAX_TCP_SERVER_WORKERS = (
    MAX_TCP_CLIENT_CONCURRENCY * TCP_SERVER_TURNOVER_HEADROOM
)
NFQUEUE_DRAIN_POLL_SECONDS = 0.01
ENFORCING_NFQUEUE_NUMBER = 1_337
LEARNING_NFQUEUE_NUMBER = 1_338
# Keep these synchronized with the bounded established-flow Learning observer
# in the nftables/iptables compilers. Initial SYNs remain independently queued.
LEARNING_ESTABLISHED_OBSERVATIONS_PER_SECOND = 64
LEARNING_ESTABLISHED_OBSERVATION_BURST = 32
PERFORMANCE_NFQUEUE_NUMBERS = frozenset(
    {ENFORCING_NFQUEUE_NUMBER, LEARNING_NFQUEUE_NUMBER}
)
MAX_SUBPROCESS_OUTPUT = 4 * 1024 * 1024
MAX_HARNESS_COMPONENT_BYTES = 4 * 1024 * 1024
U64_MAX = (1 << 64) - 1
NFQUEUE_RUNTIME_COUNTER_FIELDS = (
    "queue_overflow",
    "attribution_timeout",
    "terminal_queue_error",
    "denied",
)
NFQUEUE_RUNTIME_ERROR_FIELDS = NFQUEUE_RUNTIME_COUNTER_FIELDS[:3]
EXPECTED_NFTABLES_ONLY_PACKAGE_NAMES = frozenset(
    {"libedit0", "libjansson4", "libnftables1", "nftables"}
)
HARNESS_COMPONENT_PATHS = (
    "tests/perf/bounded_output.py",
    "tests/perf/ci-smoke.sh",
    "tests/perf/control.py",
    "tests/perf/environment.py",
    "tests/perf/metrics.py",
    "tests/perf/run.py",
    "tests/perf/runtime_launcher.py",
    "tests/perf/validate_report.py",
    "tests/perf/workloads/common.py",
    "tests/perf/workloads/identity_probe.c",
    "tests/perf/workloads/tcp.py",
    "tests/perf/workloads/udp.py",
)
RUNTIME_BUNDLE_COMPONENTS = (
    ("tests/perf/runtime_launcher.py", "runtime_launcher.py"),
    ("tests/perf/control.py", "control.py"),
    ("tests/perf/metrics.py", "metrics.py"),
    ("tests/perf/workloads/common.py", "workloads/common.py"),
    ("tests/perf/workloads/identity_probe.c", "workloads/identity_probe.c"),
    ("tests/perf/workloads/tcp.py", "workloads/tcp.py"),
    ("tests/perf/workloads/udp.py", "workloads/udp.py"),
)
RUNTIME_PYTHON_ENTRYPOINTS = frozenset(
    {"control.py", "metrics.py", "workloads/tcp.py", "workloads/udp.py"}
)
RUNTIME_BUNDLE_SCHEMA = "openshield.perf.runtime-bundle.v1"
RUNTIME_BUNDLE_MANIFEST = ".manifest.json"
RUNTIME_VERIFY_ONLY = "--verify-only"
NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,47}$")
RUN_TOKEN_PATTERN = re.compile(r"^[0-9a-f]{32}$")
IMAGE_PATTERN = re.compile(r"^[A-Za-z0-9._/:@-]+@sha256:[0-9a-f]{64}$")
# Linux IFNAMSIZ includes the terminating NUL, so an interface name contains
# at most 15 bytes.  Docker bridge devices use this conservative ASCII subset.
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")
RUN_LABEL_KEY = "org.openshield.perf.run"
CONTAINER_PERF_ROOT = "/opt/openshield-perf"
CONTAINER_RUNTIME_LAUNCHER = f"{CONTAINER_PERF_ROOT}/runtime_launcher.py"
CONTAINER_DAEMON = "/opt/openshield-daemon"
DAEMON_RUNTIME_DIRECTORY = "/run/openshield-perf"
DAEMON_PID_FILE = f"{DAEMON_RUNTIME_DIRECTORY}/daemon.pid"
WORKLOAD_UID = 65_532
WORKLOAD_GID = 65_532
WORKLOAD_IDENTITY = f"{WORKLOAD_UID}:{WORKLOAD_GID}"
CONTAINER_WORKLOAD_STATE = "/tmp/openshield-perf-runtime"
CONTAINER_WORKLOAD_CONFIG = f"{CONTAINER_WORKLOAD_STATE}/config"
CONTAINER_WORKLOAD_HOMES = f"{CONTAINER_WORKLOAD_STATE}/users"
CONTAINER_WORKLOAD_HOME = f"{CONTAINER_WORKLOAD_HOMES}/{WORKLOAD_UID}"
RUNTIME_MANIFEST_DIGEST_ENV = "OPENSHIELD_PERF_RUNTIME_MANIFEST_SHA256"
MAX_RUNTIME_COMMAND_ARGUMENT_BYTES = 1024
MAX_RUNTIME_COMMAND_ARGUMENTS = 64
CAPABILITY_ARGUMENTS = [
    "--regid",
    "root",
    "--groups",
    "openshield",
    "--bounding-set=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search",
    "--inh-caps=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search",
    "--ambient-caps=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search",
    "--",
]
CONTAINER_WORKLOAD_PREPARER = r"""
import os
import stat
import sys

if len(sys.argv) != 4:
    raise SystemExit("workload identity preparer requires STATE UID GID")
state = sys.argv[1]
try:
    workload_uid = int(sys.argv[2], 10)
    workload_gid = int(sys.argv[3], 10)
except ValueError as error:
    raise SystemExit("workload UID/GID must be decimal integers") from error
if not 1 <= workload_uid < (1 << 31) or not 1 <= workload_gid < (1 << 31):
    raise SystemExit("workload UID/GID must be non-root 31-bit identifiers")
parent, state_name = os.path.split(state)
if not os.path.isabs(state) or not parent or state_name in ("", ".", ".."):
    raise SystemExit("workload state must be a bounded absolute child path")

directory_flags = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)

def ensure_directory(parent_fd, name, mode):
    if not name.isascii() or not name.replace("-", "").isalnum():
        raise SystemExit("unsafe workload state directory name")
    try:
        os.mkdir(name, mode, dir_fd=parent_fd)
        created = True
    except FileExistsError:
        created = False
    descriptor = os.open(name, directory_flags, dir_fd=parent_fd)
    try:
        if created:
            os.fchmod(descriptor, mode)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != mode
        ):
            raise SystemExit("workload state directory has unsafe ownership or mode")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise

parent_fd = os.open(parent, directory_flags)
try:
    state_fd = ensure_directory(parent_fd, state_name, 0o711)
finally:
    os.close(parent_fd)
try:
    config_fd = ensure_directory(state_fd, "config", 0o711)
    os.close(config_fd)
    homes_fd = ensure_directory(state_fd, "users", 0o1733)
    os.close(homes_fd)
finally:
    os.close(state_fd)
"""
CONTAINER_WORKLOAD_HOME_PREPARER = r"""
import os
import stat
import sys

if len(sys.argv) != 2:
    raise SystemExit("workload home preparer requires HOME")
home = sys.argv[1]
parent, name = os.path.split(home)
if (
    not os.path.isabs(home)
    or not parent
    or not name.isascii()
    or not name.isdecimal()
):
    raise SystemExit("workload home must be an absolute numeric child path")
parent_flags = (
    getattr(os, "O_PATH", os.O_RDONLY)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
child_flags = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
parent_descriptor = os.open(parent, parent_flags)
try:
    try:
        os.mkdir(name, 0o700, dir_fd=parent_descriptor)
        created = True
    except FileExistsError:
        created = False
    descriptor = os.open(name, child_flags, dir_fd=parent_descriptor)
    try:
        if created:
            os.fchmod(descriptor, 0o700)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise SystemExit("workload home has unsafe ownership or mode")
    finally:
        os.close(descriptor)
finally:
    os.close(parent_descriptor)
"""
CONTAINER_CONFIG_INSTALLER = r"""
import os
import stat
import sys

if len(sys.argv) != 5:
    raise SystemExit("configuration installer requires PATH UID GID DIRECTORY")
path = sys.argv[1]
try:
    workload_uid = int(sys.argv[2], 10)
    workload_gid = int(sys.argv[3], 10)
except ValueError as error:
    raise SystemExit("configuration UID/GID must be decimal integers") from error
directory = sys.argv[4]
if not 1 <= workload_uid < (1 << 31) or not 1 <= workload_gid < (1 << 31):
    raise SystemExit("configuration UID/GID must be non-root 31-bit identifiers")
parent, name = os.path.split(path)
allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
if (
    not os.path.isabs(path)
    or parent != directory
    or not name.endswith(".json")
    or not 1 <= len(name) <= 240
    or any(character not in allowed for character in name)
):
    raise SystemExit("configuration target is outside the protected directory")
payload = sys.stdin.buffer.read(65537)
if len(payload) == 0 or len(payload) > 65536:
    raise SystemExit("configuration input is outside the 64 KiB bound")
directory_flags = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
parent_descriptor = os.open(directory, directory_flags)
try:
    parent_metadata = os.fstat(parent_descriptor)
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or parent_metadata.st_gid != os.getegid()
        or stat.S_IMODE(parent_metadata.st_mode) != 0o711
    ):
        raise SystemExit("configuration directory is not supervisor-controlled")
    flags = (
        os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        expected_uid = os.geteuid()
        expected_gid = os.getegid()
    except FileNotFoundError:
        descriptor = os.open(
            name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=parent_descriptor
        )
        expected_uid = os.geteuid()
        expected_gid = os.getegid()
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
        ):
            raise SystemExit(
                "configuration target is not a singly linked owner-controlled regular file"
            )
        # Keep ownership with the capability-free root supervisor. The workload
        # receives read-only access and cannot rewrite its future phase input.
        os.fchmod(descriptor, 0o644)
        os.ftruncate(descriptor, 0)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
finally:
    os.close(parent_descriptor)
"""

def isolated_python_inline(script: str, *arguments: str) -> list[str]:
    """Run a fixed inline helper without cwd, environment, user-site, or bytecode."""

    return ["python3", "-I", "-B", "-S", "-c", script, *arguments]


def runtime_python_command(entrypoint: str, *arguments: str) -> list[str]:
    """Run one source-only entrypoint after verifying the mounted allowlist."""

    if entrypoint != RUNTIME_VERIFY_ONLY and entrypoint not in RUNTIME_PYTHON_ENTRYPOINTS:
        raise HarnessError("runtime Python entrypoint is not allowlisted")
    command = [
        "python3",
        "-I",
        "-B",
        "-S",
        CONTAINER_RUNTIME_LAUNCHER,
        entrypoint,
        *arguments,
    ]
    if len(command) > MAX_RUNTIME_COMMAND_ARGUMENTS:
        raise HarnessError("runtime Python command exceeds the argument-count bound")
    for argument in command:
        if not isinstance(argument, str) or "\0" in argument:
            raise HarnessError("runtime Python command contains an invalid argument")
        if len(os.fsencode(argument)) > MAX_RUNTIME_COMMAND_ARGUMENT_BYTES:
            raise HarnessError("runtime Python command argument exceeds its byte bound")
    return command


def workload_exec_arguments(container: str) -> list[str]:
    """Build a Docker exec prefix for a capability-free non-root workload."""

    if not isinstance(container, str) or not container:
        raise HarnessError("workload container identifier is unavailable")
    return [
        "exec",
        "--user",
        WORKLOAD_IDENTITY,
        "--env",
        f"HOME={CONTAINER_WORKLOAD_HOME}",
        "--env",
        f"TMPDIR={CONTAINER_WORKLOAD_HOME}",
        "--workdir",
        CONTAINER_WORKLOAD_HOME,
        container,
    ]


class HarnessError(RuntimeError):
    """A deterministic harness, workload, or environment failure."""


class HarnessInterrupted(RuntimeError):
    """The harness received a cooperative termination signal."""


class BackendUnsupported(HarnessError):
    """The local kernel cannot execute one explicitly optional backend."""


def _json_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HarnessError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise HarnessError(f"configuration is not a regular non-symlink file: {path}")
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise HarnessError("configuration exceeds the bounded input size")
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_json_without_duplicate_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HarnessError(f"cannot read configuration: {error}") from error
    if not isinstance(document, dict):
        raise HarnessError("configuration root must be an object")
    return document


def require_keys(document: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(document).difference(allowed))
    if unknown:
        raise HarnessError(f"unknown {context} keys: {', '.join(unknown)}")


def finite_number(value: Any, name: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise HarnessError(f"{name} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise HarnessError(f"{name} must be in [{minimum}, {maximum}]")
    return result


def integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise HarnessError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise HarnessError(f"{name} must be a boolean")
    return value


def parse_mix(
    value: str,
    maximum: int,
    *,
    minimum: int = 0,
    field_name: str = "response_mix",
) -> list[tuple[int, int]]:
    if (
        isinstance(minimum, bool)
        or not isinstance(minimum, int)
        or isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or minimum < 0
        or maximum < minimum
    ):
        raise HarnessError("weighted mix bounds are invalid")
    if not isinstance(value, str) or not value or len(value) > 1_024:
        raise HarnessError(f"{field_name} must be a non-empty bounded string")
    result: list[tuple[int, int]] = []
    seen: set[int] = set()
    for item in value.split(","):
        fields = item.split(":")
        if len(fields) != 2 or not all(field.isascii() and field.isdecimal() for field in fields):
            raise HarnessError(
                f"{field_name} entries must use decimal VALUE:WEIGHT"
            )
        size, weight = (int(field, 10) for field in fields)
        if (
            not minimum <= size <= maximum
            or not 1 <= weight <= 1_000_000
            or size in seen
        ):
            raise HarnessError(
                f"{field_name} contains an invalid or duplicate entry"
            )
        seen.add(size)
        result.append((size, weight))
    if not 1 <= len(result) <= 32:
        raise HarnessError(f"{field_name} must contain 1..32 entries")
    return result


TOP_LEVEL_KEYS = {
    "schema",
    "description",
    "capacity_certification",
    "seed",
    "backends",
    "modes",
    "learning_variants",
    "allow_unsupported_iptables",
    "images",
    "platform",
    "max_total_workload_seconds",
    "load_levels",
    "phases",
    "criteria",
    "overload",
    "profiles",
}
PHASE_KEYS = {"warmup", "ramp", "steady", "burst", "cooldown_seconds"}
CRITERIA_KEYS = {
    "minimum_target_ratio",
    "maximum_error_ratio",
    "maximum_udp_reply_loss_ratio",
    "maximum_tcp_retransmits_per_tx_packet",
    "maximum_latency_p99_ms",
    "maximum_daemon_cpu_percent_one_core",
    "maximum_daemon_rss_bytes",
    "maximum_generator_wall_cpu_ratio",
    "maximum_peer_wall_cpu_ratio",
    "maximum_scheduler_lag_p99_ms",
    "require_zero_nic_errors",
    "require_zero_nfqueue_drops",
    "network_only_maximum_queue_hits",
    "application_tcp_minimum_queue_hits_per_connection",
    "application_tcp_maximum_queue_hits_per_connection",
    "application_tcp_keepalive_maximum_queue_hits_per_operation",
    "application_udp_minimum_queue_hits_per_datagram",
    "application_udp_maximum_queue_hits_per_datagram",
    "require_burst_capacity",
    "maximum_throughput_reduction_vs_baseline_percent",
    "maximum_dut_pps_reduction_vs_baseline_percent",
    "maximum_latency_increase_vs_baseline_percent",
    "maximum_cgroup_cpu_increase_vs_baseline_percent",
    "cpu_latency_relative_regressions_are_advisory",
    "maximum_comparison_gap_seconds",
}
PROFILE_KEYS = {
    "name",
    "direction",
    "transport",
    "port",
    "policy_cases",
    "client",
    "server",
}
TCP_CLIENT_KEYS = {
    "protocol",
    "mode",
    "concurrency",
    "cps",
    "pps",
    "mbps",
    "keepalive_ratio",
    "connection_lifetime_ms_mix",
    "request_bytes",
    "response_mix",
    "reply_every",
    "io_timeout",
    "latency_samples",
    "operations",
}
UDP_CLIENT_KEYS = {
    "flows",
    "pps",
    "mbps",
    "request_bytes",
    "request_mix",
    "response_mix",
    "reply_every",
    "io_timeout",
    "latency_samples",
    "socket_buffer_bytes",
    "operations",
}
TCP_SERVER_KEYS = {
    "workers",
    "backlog",
    "processing_delay_ms",
    "max_request_bytes",
    "max_response_bytes",
}
UDP_SERVER_KEYS = {
    "processing_delay_ms",
    "socket_buffer_bytes",
    "max_request_bytes",
    "max_response_bytes",
}
OVERLOAD_KEYS = {
    "enabled",
    "pause_seconds",
    "client_duration_seconds",
    "tcp_connections",
    "tcp_concurrency",
    "udp_datagrams",
    "udp_flows",
    "probe_attempts",
    "probe_timeout_ms",
    "recovery_operations",
    "recovery_duration_seconds",
    "minimum_nfqueue_drops",
    "tcp_canary_port",
    "udp_canary_port",
    "tcp_liveness_port",
    "udp_liveness_port",
}


def validate_config(document: dict[str, Any]) -> dict[str, Any]:
    require_keys(document, TOP_LEVEL_KEYS, "top-level")
    if document.get("schema") != CONFIG_SCHEMA:
        raise HarnessError(f"configuration schema must be {CONFIG_SCHEMA}")
    boolean(
        document.get("capacity_certification"),
        "capacity_certification",
    )
    integer(document.get("seed"), "seed", 0, (1 << 63) - 1)
    backends = document.get("backends")
    if not isinstance(backends, list) or not backends or len(set(backends)) != len(backends):
        raise HarnessError("backends must be a non-empty unique array")
    if any(backend not in {"nftables", "iptables"} for backend in backends):
        raise HarnessError("only nftables and iptables backends are supported")
    modes = document.get("modes")
    if not isinstance(modes, list) or set(modes) != {"enforcing", "learning"}:
        raise HarnessError("modes must contain enforcing and learning exactly once")
    variants = document.get("learning_variants")
    if not isinstance(variants, list) or not variants or len(set(variants)) != len(variants):
        raise HarnessError("learning_variants must be a non-empty unique array")
    if any(item not in {"known_endpoint", "discovery_churn"} for item in variants):
        raise HarnessError("invalid learning variant")
    boolean(document.get("allow_unsupported_iptables"), "allow_unsupported_iptables")
    if document.get("platform") != "linux/amd64":
        raise HarnessError("the release performance gate supports exactly linux/amd64")

    images = document.get("images")
    if not isinstance(images, dict):
        raise HarnessError("images must be an object")
    require_keys(images, {"dut", "peer"}, "images")
    if set(images) != {"dut", "peer"} or any(
        not isinstance(value, str) or not IMAGE_PATTERN.fullmatch(value)
        for value in images.values()
    ):
        raise HarnessError("dut and peer images must both be SHA-256 pinned")

    limit = finite_number(
        document.get("max_total_workload_seconds"),
        "max_total_workload_seconds",
        1.0,
        MAX_ESTIMATED_WORKLOAD_SECONDS,
    )
    levels = document.get("load_levels")
    if not isinstance(levels, list) or not 1 <= len(levels) <= MAX_LOAD_LEVELS:
        raise HarnessError("load_levels must contain 1..32 entries")
    normalized_levels = [
        finite_number(value, "load level", 0.01, 100.0) for value in levels
    ]
    if normalized_levels != sorted(set(normalized_levels)):
        raise HarnessError("load_levels must be strictly increasing")

    phases = document.get("phases")
    if not isinstance(phases, dict) or set(phases) != PHASE_KEYS:
        raise HarnessError("phases object has missing or unknown keys")
    for name in ("warmup", "ramp", "steady", "burst"):
        if not isinstance(phases[name], dict):
            raise HarnessError(f"phase {name} must be an object")
    require_keys(phases["warmup"], {"duration_seconds", "scale"}, "warmup")
    require_keys(phases["ramp"], {"duration_seconds", "scales"}, "ramp")
    require_keys(phases["steady"], {"duration_seconds", "repetitions"}, "steady")
    require_keys(phases["burst"], {"duration_seconds", "scale"}, "burst")
    for name in ("warmup", "ramp", "steady", "burst"):
        finite_number(phases[name].get("duration_seconds"), f"{name} duration", 0.1, 3_600)
    finite_number(phases["warmup"].get("scale"), "warmup scale", 0.01, 10)
    finite_number(phases["burst"].get("scale"), "burst scale", 0.01, 100)
    ramp_scales = phases["ramp"].get("scales")
    if not isinstance(ramp_scales, list) or not 1 <= len(ramp_scales) <= 20:
        raise HarnessError("ramp scales must contain 1..20 entries")
    normalized_ramp = [finite_number(value, "ramp scale", 0.01, 10) for value in ramp_scales]
    if normalized_ramp != sorted(set(normalized_ramp)):
        raise HarnessError("ramp scales must be strictly increasing")
    integer(
        phases["steady"].get("repetitions"),
        "steady repetitions",
        MINIMUM_RELATIVE_PAIRED_SAMPLES,
        20,
    )
    finite_number(phases.get("cooldown_seconds"), "cooldown", 0, 300)
    active_seconds = (
        float(phases["warmup"]["duration_seconds"])
        + len(ramp_scales) * float(phases["ramp"]["duration_seconds"])
        + int(phases["steady"]["repetitions"])
        * float(phases["steady"]["duration_seconds"])
        + float(phases["burst"]["duration_seconds"])
    )
    if active_seconds + 30 > 3_600:
        raise HarnessError(
            "one workload server lifetime exceeds its fixed 3600-second bound"
        )

    criteria = document.get("criteria")
    if not isinstance(criteria, dict) or set(criteria) != CRITERIA_KEYS:
        raise HarnessError("criteria object has missing or unknown keys")
    for key in (
        "minimum_target_ratio",
        "maximum_error_ratio",
        "maximum_udp_reply_loss_ratio",
        "maximum_tcp_retransmits_per_tx_packet",
        "maximum_generator_wall_cpu_ratio",
        "maximum_peer_wall_cpu_ratio",
    ):
        finite_number(criteria[key], key, 0, 1)
    for key in (
        "maximum_latency_p99_ms",
        "maximum_daemon_cpu_percent_one_core",
        "maximum_scheduler_lag_p99_ms",
        "application_tcp_minimum_queue_hits_per_connection",
        "application_tcp_maximum_queue_hits_per_connection",
        "application_tcp_keepalive_maximum_queue_hits_per_operation",
        "application_udp_minimum_queue_hits_per_datagram",
        "application_udp_maximum_queue_hits_per_datagram",
        "maximum_throughput_reduction_vs_baseline_percent",
        "maximum_dut_pps_reduction_vs_baseline_percent",
        "maximum_latency_increase_vs_baseline_percent",
        "maximum_cgroup_cpu_increase_vs_baseline_percent",
    ):
        finite_number(criteria[key], key, 0, 1_000_000)
    finite_number(
        criteria["maximum_comparison_gap_seconds"],
        "maximum_comparison_gap_seconds",
        0.1,
        300.0,
    )
    integer(criteria["maximum_daemon_rss_bytes"], "maximum_daemon_rss_bytes", 1, 1 << 50)
    integer(
        criteria["network_only_maximum_queue_hits"],
        "network_only_maximum_queue_hits",
        0,
        1_000_000,
    )
    for key in (
        "require_zero_nic_errors",
        "require_zero_nfqueue_drops",
        "require_burst_capacity",
        "cpu_latency_relative_regressions_are_advisory",
    ):
        boolean(criteria[key], key)
    if (
        criteria["application_tcp_minimum_queue_hits_per_connection"]
        > criteria["application_tcp_maximum_queue_hits_per_connection"]
        or criteria["application_udp_minimum_queue_hits_per_datagram"]
        > criteria["application_udp_maximum_queue_hits_per_datagram"]
    ):
        raise HarnessError("queue-hit ratio criteria are reversed")

    overload = document.get("overload")
    if not isinstance(overload, dict) or set(overload) != OVERLOAD_KEYS:
        raise HarnessError("overload object has missing or unknown keys")
    boolean(overload["enabled"], "overload enabled")
    finite_number(overload["pause_seconds"], "overload pause_seconds", 0.05, 10)
    finite_number(
        overload["client_duration_seconds"],
        "overload client_duration_seconds",
        0.2,
        30,
    )
    integer(overload["tcp_connections"], "overload tcp_connections", 257, 100_000)
    integer(overload["tcp_concurrency"], "overload tcp_concurrency", 1, 512)
    integer(overload["udp_datagrams"], "overload udp_datagrams", 257, 1_000_000)
    integer(overload["udp_flows"], "overload udp_flows", 1, 512)
    integer(overload["probe_attempts"], "overload probe_attempts", 1, 100)
    integer(overload["probe_timeout_ms"], "overload probe_timeout_ms", 50, 5_000)
    integer(overload["recovery_operations"], "overload recovery_operations", 1, 100)
    finite_number(
        overload["recovery_duration_seconds"],
        "overload recovery_duration_seconds",
        0.2,
        10,
    )
    integer(
        overload["minimum_nfqueue_drops"],
        "overload minimum_nfqueue_drops",
        1,
        1_000_000,
    )
    tcp_canary_port = integer(
        overload["tcp_canary_port"], "overload tcp_canary_port", 1_024, 65_535
    )
    udp_canary_port = integer(
        overload["udp_canary_port"], "overload udp_canary_port", 1_024, 65_535
    )
    tcp_liveness_port = integer(
        overload["tcp_liveness_port"], "overload tcp_liveness_port", 1_024, 65_535
    )
    udp_liveness_port = integer(
        overload["udp_liveness_port"], "overload udp_liveness_port", 1_024, 65_535
    )
    overload_ports = {
        tcp_canary_port,
        udp_canary_port,
        tcp_liveness_port,
        udp_liveness_port,
    }
    if len(overload_ports) != 4:
        raise HarnessError("overload canary and liveness ports must all be distinct")

    profiles = document.get("profiles")
    if not isinstance(profiles, list) or not 1 <= len(profiles) <= MAX_PROFILES:
        raise HarnessError("profiles must contain 1..32 entries")
    names: set[str] = set()
    ports: set[int] = set()
    for profile in profiles:
        validate_profile(profile, names, ports)
        validate_tcp_server_capacity(document, profile)
    if overload_ports.intersection(ports):
        raise HarnessError(
            "overload canary and liveness ports must not overlap workload profile ports"
        )
    if overload["enabled"]:
        covered = {
            profile["transport"]
            for profile in profiles
            if profile["direction"] == "outbound"
            and f"application_{profile['transport']}" in profile["policy_cases"]
        }
        if covered != {"tcp", "udp"}:
            raise HarnessError(
                "enabled overload testing requires outbound application TCP and UDP profiles"
            )

    estimated = estimate_workload_seconds(document)
    if estimated > limit:
        raise HarnessError(
            f"estimated workload time {estimated:.1f}s exceeds configured bound {limit:.1f}s"
        )
    document["estimated_workload_seconds"] = estimated
    return document


def validate_profile(profile: Any, names: set[str], ports: set[int]) -> None:
    if not isinstance(profile, dict):
        raise HarnessError("each profile must be an object")
    require_keys(profile, PROFILE_KEYS, "profile")
    if set(profile) != PROFILE_KEYS:
        raise HarnessError("profile has missing required keys")
    name = profile.get("name")
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name) or name in names:
        raise HarnessError("profile names must be unique safe identifiers")
    names.add(name)
    direction = profile.get("direction")
    transport = profile.get("transport")
    if direction not in {"inbound", "outbound"} or transport not in {"tcp", "udp"}:
        raise HarnessError(f"profile {name} has an invalid direction or transport")
    if direction == "inbound" and transport != "tcp":
        raise HarnessError("the production ingress profile currently supports TCP only")
    port = integer(profile.get("port"), f"{name} port", 1_024, 65_535)
    if port in ports:
        raise HarnessError("profile ports must be unique")
    ports.add(port)
    cases = profile.get("policy_cases")
    if not isinstance(cases, list) or not cases or len(set(cases)) != len(cases):
        raise HarnessError(f"profile {name} policy_cases must be unique and non-empty")
    allowed_cases = {"baseline", "network_only"}
    if direction == "outbound":
        allowed_cases.add("application_tcp" if transport == "tcp" else "application_udp")
    if any(case not in allowed_cases for case in cases):
        raise HarnessError(f"profile {name} has an inapplicable policy case")
    if "baseline" not in cases or "network_only" not in cases:
        raise HarnessError(f"profile {name} must retain baseline and network_only comparisons")
    client = profile.get("client")
    server = profile.get("server")
    if not isinstance(client, dict) or not isinstance(server, dict):
        raise HarnessError(f"profile {name} client and server must be objects")
    require_keys(client, TCP_CLIENT_KEYS if transport == "tcp" else UDP_CLIENT_KEYS, f"{name} client")
    require_keys(server, TCP_SERVER_KEYS if transport == "tcp" else UDP_SERVER_KEYS, f"{name} server")
    required_client = (
        {"protocol", "mode", "concurrency", "cps", "pps", "mbps", "keepalive_ratio", "connection_lifetime_ms_mix", "request_bytes", "response_mix", "io_timeout", "latency_samples"}
        if transport == "tcp"
        else {"flows", "pps", "mbps", "request_bytes", "response_mix", "reply_every", "io_timeout", "latency_samples", "socket_buffer_bytes"}
    )
    missing = required_client.difference(client)
    if missing:
        raise HarnessError(f"profile {name} client is missing: {', '.join(sorted(missing))}")
    if transport == "tcp":
        if client["protocol"] not in {"http1", "framed"} or client["mode"] not in {"keepalive", "short", "mixed"}:
            raise HarnessError(f"profile {name} has an invalid TCP protocol or mode")
        integer(client["concurrency"], "concurrency", 1, 512)
        finite_number(client["cps"], "cps", 0, 100_000)
        finite_number(client["keepalive_ratio"], "keepalive_ratio", 0, 1)
        parse_mix(
            client["connection_lifetime_ms_mix"],
            MAX_TCP_CONNECTION_LIFETIME_MS,
            minimum=MIN_TCP_CONNECTION_LIFETIME_MS,
            field_name="connection_lifetime_ms_mix",
        )
        integer(client["request_bytes"], "request_bytes", 0, 8 * 1024 * 1024)
        parse_mix(client["response_mix"], 8 * 1024 * 1024)
    else:
        integer(client["flows"], "flows", 1, 512)
        integer(client["request_bytes"], "request_bytes", 0, 60_000)
        parse_mix(
            client.get("request_mix", f"{client['request_bytes']}:1"),
            60_000,
        )
        integer(client["reply_every"], "reply_every", 0, 1_000_000)
        integer(client["socket_buffer_bytes"], "socket_buffer_bytes", 65_536, 16 * 1024 * 1024)
        parse_mix(client["response_mix"], 60_000)
    finite_number(client["pps"], "pps", 0, 1_000_000)
    finite_number(client["mbps"], "mbps", 0, 100_000)
    finite_number(client["io_timeout"], "io_timeout", 0.05, 60)
    integer(client["latency_samples"], "latency_samples", 1, 100_000)
    if "operations" in client:
        integer(client["operations"], "operations", 0, 10_000_000)
    finite_number(
        server.get("processing_delay_ms", 0),
        f"{name} server processing_delay_ms",
        0,
        60_000,
    )
    if transport == "tcp":
        integer(
            server.get("workers", 128),
            f"{name} server workers",
            1,
            MAX_TCP_SERVER_WORKERS,
        )
        integer(server.get("backlog", 256), f"{name} server backlog", 1, 65_535)
        maximum_request = integer(
            server.get("max_request_bytes", client["request_bytes"]),
            f"{name} server max_request_bytes",
            0,
            8 * 1024 * 1024,
        )
        maximum_response = integer(
            server.get(
                "max_response_bytes",
                max(size for size, _weight in parse_mix(client["response_mix"], 8 * 1024 * 1024)),
            ),
            f"{name} server max_response_bytes",
            0,
            8 * 1024 * 1024,
        )
        if maximum_request < client["request_bytes"] or maximum_response < max(
            size for size, _weight in parse_mix(client["response_mix"], 8 * 1024 * 1024)
        ):
            raise HarnessError(f"profile {name} server bounds are smaller than its workload")
    else:
        request_maximum = max(
            size
            for size, _weight in parse_mix(
                client.get("request_mix", f"{client['request_bytes']}:1"), 60_000
            )
        )
        response_maximum = max(
            size for size, _weight in parse_mix(client["response_mix"], 60_000)
        )
        maximum_request = integer(
            server.get("max_request_bytes", request_maximum),
            f"{name} server max_request_bytes",
            0,
            60_000,
        )
        maximum_response = integer(
            server.get("max_response_bytes", response_maximum),
            f"{name} server max_response_bytes",
            0,
            60_000,
        )
        integer(
            server.get("socket_buffer_bytes", 4 * 1024 * 1024),
            f"{name} server socket_buffer_bytes",
            65_536,
            16 * 1024 * 1024,
        )
        if maximum_request < request_maximum or maximum_response < response_maximum:
            raise HarnessError(f"profile {name} server bounds are smaller than its workload")


def maximum_tcp_client_concurrency(
    document: dict[str, Any], profile: dict[str, Any]
) -> int:
    """Return the exact maximum concurrency produced by ``client_config``."""

    phase_scales = [
        float(document["phases"]["warmup"]["scale"]),
        *(float(value) for value in document["phases"]["ramp"]["scales"]),
        1.0,
        float(document["phases"]["burst"]["scale"]),
    ]
    maximum_scale = max(phase_scales) * max(
        float(value) for value in document["load_levels"]
    )
    return max(
        1,
        min(
            MAX_TCP_CLIENT_CONCURRENCY,
            round(int(profile["client"]["concurrency"]) * maximum_scale),
        ),
    )


def validate_tcp_server_capacity(
    document: dict[str, Any], profile: dict[str, Any]
) -> None:
    """Keep the peer out of the measured path's saturation envelope.

    A client worker can open its replacement socket immediately after closing a
    persistent socket, before the server worker has observed EOF and released
    its slot.  Two server slots per maximum client flow therefore bound this
    normal turnover without silently accepting peer-side connection refusal.
    """

    if profile.get("transport") != "tcp":
        return
    maximum_concurrency = maximum_tcp_client_concurrency(document, profile)
    required_workers = maximum_concurrency * TCP_SERVER_TURNOVER_HEADROOM
    workers = int(profile["server"].get("workers", 128))
    if workers < required_workers:
        raise HarnessError(
            f"profile {profile['name']} server workers must be at least "
            f"{required_workers} for peak TCP concurrency {maximum_concurrency} "
            "and connection-turnover headroom"
        )
    backlog = int(profile["server"].get("backlog", 256))
    if backlog < maximum_concurrency:
        raise HarnessError(
            f"profile {profile['name']} server backlog must be at least "
            f"peak TCP concurrency {maximum_concurrency}"
        )


def estimate_workload_seconds(config: dict[str, Any]) -> float:
    total = 0.0
    for backend in config["backends"]:
        for scenario, _load_level in paired_load_plan(config, backend):
            total += sum(
                float(phase["duration"])
                for phase in comparison_phase_plan(config, scenario)
            )
            total += float(config["phases"]["cooldown_seconds"])
    overload = config.get("overload", {})
    if overload.get("enabled"):
        overload_window = (
            float(overload["client_duration_seconds"])
            + float(overload["pause_seconds"])
            + (
                int(overload["probe_attempts"])
                * (
                    2 * float(overload["recovery_duration_seconds"])
                    + int(overload["probe_timeout_ms"]) / 1_000.0
                )
            )
            + 2 * float(overload["recovery_duration_seconds"])
            + int(overload["probe_timeout_ms"]) / 1_000.0
            + float(overload["recovery_duration_seconds"])
        )
        total += overload_window * 2 * len(config["backends"])
    return total


def phase_plan(config: dict[str, Any]) -> list[dict[str, Any]]:
    phases = config["phases"]
    plan = [
        {
            "name": "warmup",
            "role": "warmup",
            "duration": float(phases["warmup"]["duration_seconds"]),
            "scale": float(phases["warmup"]["scale"]),
            "repetition": None,
        }
    ]
    for index, scale in enumerate(phases["ramp"]["scales"], 1):
        plan.append(
            {
                "name": f"ramp_{index}",
                "role": "ramp",
                "duration": float(phases["ramp"]["duration_seconds"]),
                "scale": float(scale),
                "repetition": None,
            }
        )
    for repetition in range(1, int(phases["steady"]["repetitions"]) + 1):
        plan.append(
            {
                "name": f"steady_{repetition}",
                "role": "steady",
                "duration": float(phases["steady"]["duration_seconds"]),
                "scale": 1.0,
                "repetition": repetition,
            }
        )
    plan.append(
        {
            "name": "burst",
            "role": "burst",
            "duration": float(phases["burst"]["duration_seconds"]),
            "scale": float(phases["burst"]["scale"]),
            "repetition": None,
        }
    )
    return plan


def comparison_phase_plan(
    config: dict[str, Any], scenario: dict[str, Any]
) -> list[dict[str, Any]]:
    """Return the bounded phases for one independent comparison block.

    ``steady.repetitions`` is the number of independent baseline/protected
    pairs, not a set of adjacent windows inside one long-lived load block.
    Every pair gets its own warm-up and one steady window.  The first pair
    performs the configured ramp and the last pair performs the mandatory
    burst, keeping all four phase roles while avoiding redundant bursts and a
    threefold CI runtime expansion.
    """

    repetition = scenario.get("comparison_repetition")
    repetitions = int(config["phases"]["steady"]["repetitions"])
    if (
        not isinstance(repetition, int)
        or isinstance(repetition, bool)
        or not 1 <= repetition <= repetitions
    ):
        raise HarnessError("comparison repetition is missing or invalid")
    phases = phase_plan(config)
    selected: list[dict[str, Any]] = []
    for phase in phases:
        role = phase["role"]
        if role == "steady":
            if phase["repetition"] == repetition:
                selected.append(phase)
        elif role == "ramp":
            if repetition == 1:
                selected.append(phase)
        elif role == "burst":
            if repetition == repetitions:
                selected.append(phase)
        else:
            selected.append(phase)
    return selected


def scenario_plan(config: dict[str, Any], policy_filter: str) -> Iterable[dict[str, Any]]:
    for profile in config["profiles"]:
        if policy_filter not in profile["policy_cases"]:
            continue
        if policy_filter == "baseline":
            yield {"profile": profile, "policy": "baseline", "mode": None, "learning_variant": None}
        elif policy_filter == "network_only":
            for mode in config["modes"]:
                yield {"profile": profile, "policy": "network_only", "mode": mode, "learning_variant": None}
        else:
            yield {"profile": profile, "policy": policy_filter, "mode": "enforcing", "learning_variant": None}
            for variant in config["learning_variants"]:
                yield {"profile": profile, "policy": policy_filter, "mode": "learning", "learning_variant": variant}


def protected_scenarios_for_profile(
    config: dict[str, Any], profile: dict[str, Any]
) -> list[dict[str, Any]]:
    """Return the deterministic protected policy order for one profile."""

    scenarios: list[dict[str, Any]] = []
    if "network_only" in profile["policy_cases"]:
        scenarios.extend(
            {
                "profile": profile,
                "policy": "network_only",
                "mode": mode,
                "learning_variant": None,
            }
            for mode in config["modes"]
        )
    application_policy = f"application_{profile['transport']}"
    if application_policy in profile["policy_cases"]:
        scenarios.append(
            {
                "profile": profile,
                "policy": application_policy,
                "mode": "enforcing",
                "learning_variant": None,
            }
        )
        scenarios.extend(
            {
                "profile": profile,
                "policy": application_policy,
                "mode": "learning",
                "learning_variant": variant,
            }
            for variant in config["learning_variants"]
        )
    return scenarios


def nfqueue_number_for_mode(mode: Any) -> int:
    """Select the one daemon queue whose counters describe this DUT mode.

    A pristine baseline has no daemon queue, but retaining the enforcing queue
    as its explicit default keeps the collector contract deterministic.  Any
    unexpected mode is rejected instead of silently measuring the wrong queue.
    """

    if mode is None or mode == "enforcing":
        return ENFORCING_NFQUEUE_NUMBER
    if mode == "learning":
        return LEARNING_NFQUEUE_NUMBER
    raise HarnessError("scenario has no defined NFQUEUE metrics queue")


def expected_runtime_compatibility(scenario: dict[str, Any]) -> dict[str, str]:
    """Return the exact policy-derived runtime level required by a scenario."""

    mode = scenario.get("mode")
    policy = scenario.get("policy")
    if mode == "learning":
        return {"level": "nfqueue", "reason": "learning"}
    if mode != "enforcing":
        raise HarnessError("protected runtime compatibility requires a policy mode")
    if policy == "network_only":
        return {"level": "kernel_native", "reason": "network_only"}
    if policy == "application_tcp":
        return {"level": "conntrack_hybrid", "reason": "application_tcp"}
    if policy == "application_udp":
        return {"level": "nfqueue", "reason": "application_per_packet"}
    raise HarnessError("scenario has no defined runtime compatibility level")


def validate_runtime_compatibility(
    status: Any, scenario: dict[str, Any]
) -> dict[str, str]:
    """Validate daemon evidence instead of inferring a benchmark packet path."""

    if not isinstance(status, dict):
        raise HarnessError("daemon runtime status is unavailable")
    actual = status.get("runtime_compatibility")
    if not isinstance(actual, dict):
        raise HarnessError("daemon omitted runtime compatibility evidence")
    expected = expected_runtime_compatibility(scenario)
    observed = {"level": actual.get("level"), "reason": actual.get("reason")}
    if observed != expected:
        raise HarnessError(
            f"daemon selected runtime compatibility {observed!r}, expected {expected!r}"
        )
    return expected


def paired_load_plan(
    config: dict[str, Any], backend: str
) -> Iterable[tuple[dict[str, Any], float]]:
    """Yield independent, order-balanced baseline/protected comparison pairs.

    Each exact backend/policy/mode/profile/load group gets at least three
    independent pairs.  A baseline block belongs to exactly one protected
    block, both carry a unique pair identity, and the deterministic AB/BA order
    alternates within the group.  Alternating the starting order between
    groups also balances the complete matrix when the repetition count is odd.
    """

    sequence = 0
    sample_index = 0

    def sample_id() -> str:
        nonlocal sample_index
        value = f"b{sample_index:05d}"
        sample_index += 1
        return value

    pair_index = 0

    def next_pair_id() -> str:
        nonlocal pair_index
        value = f"p{pair_index:05d}"
        pair_index += 1
        return value

    def baseline(
        profile: dict[str, Any], sample: str, pair: str, repetition: int
    ) -> dict[str, Any]:
        return {
            "profile": profile,
            "policy": "baseline",
            "mode": None,
            "learning_variant": None,
            "backend": backend,
            "baseline_sample_id": sample,
            "comparison_pair_id": pair,
            "comparison_repetition": repetition,
            "comparison_order": None,
            "topology_role": "baseline",
        }

    group_index = 0
    repetitions = int(config["phases"]["steady"]["repetitions"])
    for profile in config["profiles"]:
        protected = protected_scenarios_for_profile(config, profile)
        for load_level_value in config["load_levels"]:
            load_level = float(load_level_value)
            for original in protected:
                for repetition in range(1, repetitions + 1):
                    sample = sample_id()
                    pair = next_pair_id()
                    order = (
                        "ab"
                        if (group_index + repetition - 1) % 2 == 0
                        else "ba"
                    )
                    scenario = dict(original)
                    scenario.update(
                        {
                            "backend": backend,
                            "topology_role": "protected",
                            "baseline_sample_id": sample,
                            "comparison_pair_id": pair,
                            "comparison_repetition": repetition,
                            "comparison_order": order,
                        }
                    )
                    pristine = baseline(profile, sample, pair, repetition)
                    first, second = (
                        (pristine, scenario)
                        if order == "ab"
                        else (scenario, pristine)
                    )
                    first["execution_sequence"] = sequence
                    sequence += 1
                    yield first, load_level
                    second["execution_sequence"] = sequence
                    sequence += 1
                    yield second, load_level
                group_index += 1


def safe_tail(value: str, maximum: int = 4_096) -> str:
    value = "".join(character if character.isprintable() or character == "\n" else " " for character in value)
    return value[-maximum:]


def parse_json_event(output: str, event: str, schema: str) -> dict[str, Any]:
    if len(output.encode("utf-8", errors="replace")) > MAX_SUBPROCESS_OUTPUT:
        raise HarnessError("subprocess output exceeded the bounded parser size")
    matches: list[dict[str, Any]] = []
    for line in output.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("schema") == schema and value.get("event") == event:
            matches.append(value)
    if len(matches) != 1:
        raise HarnessError(f"expected exactly one {schema} {event} event, found {len(matches)}")
    return matches[0]


def nested(document: dict[str, Any], *path: str, default: Any = None) -> Any:
    current: Any = document
    for component in path:
        if not isinstance(current, dict) or component not in current:
            return default
        current = current[component]
    return current


def numeric(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    result = float(value)
    return result if math.isfinite(result) else None


def nfqueue_drop_delta(
    before: dict[str, Any], after: dict[str, Any]
) -> dict[str, int | None]:
    """Return monotonic queue-drop deltas, including the documented u32 wrap."""

    output: dict[str, int | None] = {}
    for name in ("kernel_dropped", "user_dropped"):
        first = before.get(name)
        second = after.get(name)
        if (
            isinstance(first, bool)
            or isinstance(second, bool)
            or not isinstance(first, int)
            or not isinstance(second, int)
            or first < 0
            or second < 0
            or first >= 1 << 32
            or second >= 1 << 32
        ):
            output[name] = None
        elif second >= first:
            output[name] = second - first
        else:
            output[name] = (1 << 32) - first + second
    kernel = output["kernel_dropped"]
    userspace = output["user_dropped"]
    output["total"] = (
        None if kernel is None or userspace is None else kernel + userspace
    )
    return output


def nfqueue_runtime_counter_evidence(
    status_before: Any,
    status_after: Any,
    identity_before: Any,
    identity_after: Any,
) -> dict[str, Any]:
    """Validate and delta process-lifetime saturating NFQUEUE counters."""

    reasons: list[str] = []

    def validated_identity(value: Any, label: str) -> tuple[int, int, str] | None:
        if not isinstance(value, dict):
            reasons.append(f"daemon identity {label} is unavailable")
            return None
        pid = value.get("pid")
        starttime = value.get("starttime")
        executable = value.get("exe")
        if (
            isinstance(pid, bool)
            or not isinstance(pid, int)
            or pid <= 0
            or isinstance(starttime, bool)
            or not isinstance(starttime, int)
            or starttime <= 0
            or executable != CONTAINER_DAEMON
        ):
            reasons.append(f"daemon identity {label} is invalid")
            return None
        return pid, starttime, executable

    first_identity = validated_identity(identity_before, "before phase")
    second_identity = validated_identity(identity_after, "after phase")
    if (
        first_identity is not None
        and second_identity is not None
        and first_identity != second_identity
    ):
        reasons.append("daemon identity changed during phase")

    def validated_counters(value: Any, label: str) -> dict[str, int] | None:
        if not isinstance(value, dict):
            reasons.append(f"daemon status {label} is unavailable")
            return None
        counters = value.get("nfqueue")
        if not isinstance(counters, dict):
            reasons.append(f"NFQUEUE counter snapshot {label} is unavailable")
            return None
        output: dict[str, int] = {}
        for name in NFQUEUE_RUNTIME_COUNTER_FIELDS:
            counter = counters.get(name)
            if (
                isinstance(counter, bool)
                or not isinstance(counter, int)
                or counter < 0
                or counter > U64_MAX
            ):
                reasons.append(f"NFQUEUE counter {name} {label} is not a u64")
                continue
            output[name] = counter
        return output if len(output) == len(NFQUEUE_RUNTIME_COUNTER_FIELDS) else None

    before = validated_counters(status_before, "before phase")
    after = validated_counters(status_after, "after phase")
    delta: dict[str, int | None] = {
        name: None for name in NFQUEUE_RUNTIME_COUNTER_FIELDS
    }
    if before is not None and after is not None:
        for name in NFQUEUE_RUNTIME_COUNTER_FIELDS:
            first = before[name]
            second = after[name]
            if first == U64_MAX or second == U64_MAX:
                reasons.append(
                    f"NFQUEUE counter {name} reached saturated u64::MAX; delta is ambiguous"
                )
            elif second < first:
                reasons.append(f"NFQUEUE counter {name} regressed during phase")
            else:
                delta[name] = second - first
    return {
        "measurement": "daemon_status_process_lifetime_saturating_u64_delta",
        "identity_before": identity_before,
        "identity_after": identity_after,
        "before": before,
        "after": after,
        "delta": delta,
        "valid": not reasons,
        "invalid_reasons": sorted(set(reasons)),
    }


def overload_evidence_timestamps_ordered(
    metric_starts: tuple[dict[str, Any], ...],
    before_stop: dict[str, Any],
    stopped_at_ns: int,
    saturation: dict[str, Any] | None,
    probes: list[dict[str, Any]],
    pressure_reaped_at_ns: int,
    before_continue: dict[str, Any],
    continued_at_ns: int,
    metric_boundary_ns: int,
) -> bool:
    """Verify the stopped-pressure, resume, and metric-boundary ordering.

    Metric collectors are released together and acknowledge independently, so
    their start boundaries have no causal order relative to one another.  Each
    start must instead precede the first queue observation.  Everything after
    that observation is a single controller-driven causal sequence and remains
    subject to the stronger pairwise ordering check below.
    """

    if saturation is None:
        return False
    metric_start_boundaries = [
        start.get("boundary_monotonic_ns") for start in metric_starts
    ]
    before_stop_ns = before_stop.get("observed_at_monotonic_ns")
    def valid_timestamp(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value > 0

    if not valid_timestamp(before_stop_ns) or not all(
        valid_timestamp(start_ns) and start_ns <= before_stop_ns
        for start_ns in metric_start_boundaries
    ):
        return False
    values: list[Any] = [
        before_stop_ns,
        stopped_at_ns,
        saturation.get("observed_at_monotonic_ns"),
    ]
    for probe in probes:
        values.extend(
            [
                nested(
                    probe,
                    "liveness_before",
                    "started_at_monotonic_ns",
                ),
                nested(
                    probe,
                    "liveness_before",
                    "completed_at_monotonic_ns",
                ),
                nested(probe, "nfqueue_before", "observed_at_monotonic_ns"),
                probe.get("started_at_monotonic_ns"),
                probe.get("completed_at_monotonic_ns"),
                nested(probe, "nfqueue_after", "observed_at_monotonic_ns"),
                nested(
                    probe,
                    "liveness_after",
                    "started_at_monotonic_ns",
                ),
                nested(
                    probe,
                    "liveness_after",
                    "completed_at_monotonic_ns",
                ),
            ]
        )
    values.extend(
        [
            pressure_reaped_at_ns,
            before_continue.get("observed_at_monotonic_ns"),
            continued_at_ns,
            metric_boundary_ns,
        ]
    )
    return all(valid_timestamp(value) for value in values) and all(
        first <= second for first, second in zip(values, values[1:])
    )


def workload_summary_passed(
    exit_code: int | None,
    summary: dict[str, Any] | None,
    transport: str,
    minimum_operations: int,
) -> bool:
    metrics = nested(summary or {}, "metrics", default={})
    if not isinstance(metrics, dict):
        return False
    operations = numeric(
        metrics.get("operations" if transport == "tcp" else "packets_sent")
    )
    errors = numeric(metrics.get("errors"))
    return (
        exit_code == 0
        and summary is not None
        and summary.get("ok") is True
        and operations is not None
        and operations >= minimum_operations
        and errors == 0
    )


def overload_recovery_passed(
    requested_mode: bool,
    queue_drain: dict[str, Any],
    exit_code: int | None,
    summary: dict[str, Any] | None,
    transport: str,
    minimum_operations: int,
) -> bool:
    """Require both an empty resumed queue and a clean application exchange."""

    return (
        requested_mode
        and queue_drain.get("drained") is True
        and workload_summary_passed(
            exit_code, summary, transport, minimum_operations
        )
    )


def controlled_udp_send_backpressure_evidence(
    transport: str,
    saturation_proven: bool,
    stall_drop_delta: dict[str, int | None],
    minimum_nfqueue_drops: int,
    pressure_summary: dict[str, Any] | None,
    dut_sndbuf_errors: float | None,
) -> dict[str, Any]:
    """Prove that a DUT UDP send error came from the controlled stall.

    The kernel counter is container-wide, so a direct NFQUEUE drop alone is
    insufficient.  The exception is authorized only when the pressure
    workload reports the same number of explicitly classified send failures,
    every failure is timeout/EAGAIN/ENOBUFS backpressure, and that count does
    not exceed the directly observed kernel NFQUEUE drops.
    """

    kernel_drops = numeric(stall_drop_delta.get("kernel_dropped"))
    metrics = nested(pressure_summary or {}, "metrics", default={})
    counter_names = (
        "data_send_failures",
        "data_send_timeouts",
        "data_send_enobufs",
        "data_send_would_block",
        "data_send_other_os_errors",
        "barrier_send_failures",
        "barrier_send_timeouts",
        "barrier_send_enobufs",
        "barrier_send_would_block",
        "barrier_send_other_os_errors",
    )
    counters: dict[str, int | None] = {}
    for name in counter_names:
        value = metrics.get(name) if isinstance(metrics, dict) else None
        counters[name] = (
            value
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            else None
        )
    counters_valid = all(value is not None for value in counters.values())
    data_failures = counters["data_send_failures"]
    barrier_failures = counters["barrier_send_failures"]
    total_send_failures = (
        None
        if data_failures is None or barrier_failures is None
        else data_failures + barrier_failures
    )
    data_classified = (
        counters["data_send_timeouts"],
        counters["data_send_enobufs"],
        counters["data_send_would_block"],
        counters["data_send_other_os_errors"],
    )
    barrier_classified = (
        counters["barrier_send_timeouts"],
        counters["barrier_send_enobufs"],
        counters["barrier_send_would_block"],
        counters["barrier_send_other_os_errors"],
    )
    classification_exact = (
        counters_valid
        and data_failures == sum(value for value in data_classified if value is not None)
        and barrier_failures
        == sum(value for value in barrier_classified if value is not None)
    )
    only_backpressure_classes = (
        counters_valid
        and counters["data_send_other_os_errors"] == 0
        and counters["barrier_send_other_os_errors"] == 0
    )
    exact_kernel_workload_match = (
        dut_sndbuf_errors is not None
        and float(dut_sndbuf_errors).is_integer()
        and total_send_failures is not None
        and int(dut_sndbuf_errors) == total_send_failures
    )
    within_direct_drop_bound = (
        kernel_drops is not None
        and total_send_failures is not None
        and total_send_failures <= kernel_drops
    )
    eligible = (
        transport == "udp"
        and saturation_proven
        and dut_sndbuf_errors is not None
        and dut_sndbuf_errors > 0
        and kernel_drops is not None
        and kernel_drops >= minimum_nfqueue_drops
        and counters_valid
        and classification_exact
        and only_backpressure_classes
        and exact_kernel_workload_match
        and within_direct_drop_bound
    )
    return {
        "applicable": transport == "udp",
        "exception_eligible": eligible,
        "exception_applied": bool(
            eligible and dut_sndbuf_errors is not None and dut_sndbuf_errors > 0
        ),
        "dut_sndbuf_errors": dut_sndbuf_errors,
        "stall_kernel_drop_delta": kernel_drops,
        "workload_send_counters": counters,
        "total_send_failures": total_send_failures,
        "classification_exact": classification_exact,
        "only_backpressure_classes": only_backpressure_classes,
        "exact_kernel_workload_match": exact_kernel_workload_match,
        "within_direct_drop_bound": within_direct_drop_bound,
        "scope": (
            "DUT UDP send-side timeout/EAGAIN/ENOBUFS failures during the "
            "timestamp-ordered controlled SIGSTOP NFQUEUE pressure window; "
            "the atomically adjacent resume window must remain clean"
        ),
    }


def overload_metric_validity_reasons(
    metrics: dict[str, Any] | None,
    *,
    label: str,
    transport: str,
    maximum_process_cpu_ratio: float | None = None,
    process_sections: tuple[str, ...] = (),
    allow_controlled_udp_send_backpressure: bool = False,
    expected_stop_reason: str = "requested",
    require_clean_dut_recovery: bool = False,
    expected_daemon_pid: int | None = None,
) -> list[str]:
    """Reject overload evidence when a measured endpoint was itself saturated.

    ``allow_controlled_udp_send_backpressure`` is deliberately narrower than a
    generic socket-error exception.  The overload caller may enable it only
    after the stopped NFQUEUE consumer has produced a timestamp-ordered,
    direct kernel-drop delta and the stopped-window workload has terminated.
    In that one experiment an exactly reconstructed local UDP send timeout,
    ``EAGAIN``, or ``ENOBUFS`` is an expected consequence of the fail-closed
    queue pressure being proved, rather than evidence that the remote peer
    became the bottleneck. Receive errors and every recovery, peer, or canary
    socket error remain invalidating.

    A clean DUT recovery window additionally requires an alive authenticated
    daemon, an empty queue, zero late NFQUEUE drops, and zero TCP retransmits.
    These checks close the tail after the last status RPC; missing evidence is
    never interpreted as zero.
    """

    reasons: list[str] = []
    if (
        not isinstance(metrics, dict)
        or metrics.get("stop_reason") != expected_stop_reason
    ):
        return [f"{label} metric collection was unavailable or unsynchronized"]
    network = metrics.get("network")
    if not isinstance(network, dict):
        reasons.append(f"{label} network metrics are unavailable")
    else:
        for name in ("rx_pps", "tx_pps", "rx_mbps", "tx_mbps"):
            value = numeric(network.get(name))
            if value is None or value < 0:
                reasons.append(f"{label} network {name} is unavailable")
        for name in ("rx_dropped", "tx_dropped", "rx_errors", "tx_errors"):
            value = numeric(network.get(name))
            if value is None or value < 0:
                reasons.append(f"{label} network {name} is unavailable")
            elif value > 0:
                reasons.append(f"{label} network {name} was nonzero")
    softirq = metrics.get("softirq")
    for name in ("net_rx", "net_tx"):
        value = numeric(softirq.get(name)) if isinstance(softirq, dict) else None
        if value is None or value < 0:
            reasons.append(f"{label} softirq {name} is unavailable")
    conntrack_start = numeric(metrics.get("conntrack_count_start"))
    conntrack_peak = numeric(metrics.get("conntrack_count_peak"))
    if (
        conntrack_start is None
        or conntrack_start < 0
        or conntrack_peak is None
        or conntrack_peak < conntrack_start
    ):
        reasons.append(f"{label} conntrack start/peak evidence is unavailable")
    listen = metrics.get("tcp_listen")
    for name in ("listen_drops", "listen_overflows"):
        value = numeric(listen.get(name)) if isinstance(listen, dict) else None
        if value is None or value < 0:
            reasons.append(f"{label} TCP {name} is unavailable")
        elif value > 0:
            reasons.append(f"{label} TCP {name} was nonzero")
    udp_errors = metrics.get("udp_errors")
    for name in ("in_errors", "rcvbuf_errors", "sndbuf_errors"):
        value = (
            numeric(udp_errors.get(name))
            if isinstance(udp_errors, dict)
            else None
        )
        if value is None or value < 0:
            reasons.append(f"{label} UDP {name} is unavailable")
        elif (
            value > 0
            and not (
                transport == "udp"
                and name == "sndbuf_errors"
                and allow_controlled_udp_send_backpressure
            )
        ):
            reasons.append(f"{label} UDP {name} was nonzero")
    if require_clean_dut_recovery:
        nfqueue = metrics.get("nfqueue")
        if not isinstance(nfqueue, dict):
            reasons.append(f"{label} NFQUEUE metrics are unavailable")
        else:
            for name in ("kernel_dropped", "user_dropped"):
                value = numeric(nfqueue.get(name))
                if value is None or value < 0:
                    reasons.append(f"{label} NFQUEUE {name} is unavailable")
                elif value > 0:
                    reasons.append(f"{label} NFQUEUE {name} was nonzero")
            depth_end = numeric(nfqueue.get("depth_end"))
            if depth_end is None or depth_end < 0:
                reasons.append(f"{label} NFQUEUE final depth is unavailable")
            elif depth_end > 0:
                reasons.append(f"{label} NFQUEUE final depth was nonzero")
        retransmits = numeric(metrics.get("tcp_retransmits"))
        if retransmits is None or retransmits < 0:
            reasons.append(f"{label} TCP retransmits are unavailable")
        elif retransmits > 0:
            reasons.append(f"{label} TCP retransmits were nonzero")
        daemon = metrics.get("daemon")
        daemon_pid = daemon.get("pid") if isinstance(daemon, dict) else None
        daemon_alive = (
            daemon.get("alive_end") if isinstance(daemon, dict) else None
        )
        if (
            isinstance(expected_daemon_pid, bool)
            or not isinstance(expected_daemon_pid, int)
            or expected_daemon_pid <= 0
            or daemon_pid != expected_daemon_pid
        ):
            reasons.append(f"{label} daemon identity is unavailable or changed")
        if daemon_alive is not True:
            reasons.append(f"{label} daemon exited during measurement")
    if maximum_process_cpu_ratio is not None:
        for section_name in process_sections:
            section = metrics.get(section_name)
            cpu = (
                numeric(section.get("cpu_percent_one_core"))
                if isinstance(section, dict)
                else None
            )
            alive = section.get("alive_end") if isinstance(section, dict) else None
            if cpu is None or cpu < 0:
                reasons.append(f"{label} {section_name} CPU is unavailable")
            elif cpu / 100.0 > maximum_process_cpu_ratio:
                reasons.append(f"{label} {section_name} CPU saturated")
            if alive is not True:
                reasons.append(f"{label} {section_name} exited during measurement")
    return sorted(set(reasons))


def overload_process_validity_reasons(
    summary: dict[str, Any] | None,
    *,
    label: str,
    maximum_cpu_ratio: float,
    maximum_scheduler_lag_ms: float,
) -> list[str]:
    """Validate resource counters emitted by one bounded workload process."""

    metrics = nested(summary or {}, "metrics", default={})
    if not isinstance(metrics, dict):
        return [f"{label} workload metrics are unavailable"]
    reasons: list[str] = []
    cpu = numeric(metrics.get("wall_cpu_ratio"))
    lag = numeric(nested(metrics, "scheduler_lag_ms", "p99"))
    if cpu is None or cpu < 0:
        reasons.append(f"{label} workload CPU is unavailable")
    elif cpu > maximum_cpu_ratio:
        reasons.append(f"{label} workload CPU saturated")
    if lag is None or lag < 0:
        reasons.append(f"{label} scheduler lag is unavailable")
    elif lag > maximum_scheduler_lag_ms:
        reasons.append(f"{label} scheduler lag exceeded the reliability bound")
    return sorted(set(reasons))


def identity_probe_transport(profile: dict[str, Any]) -> str:
    """Select the probe wire protocol used by the configured workload server."""

    transport = profile.get("transport")
    if transport == "udp":
        return "udp"
    if transport == "tcp":
        return (
            "tcp-framed"
            if nested(profile, "client", "protocol") == "framed"
            else "tcp"
        )
    raise HarnessError("identity probe requires a TCP or UDP profile")


_NFT_BLOCK_ALL_CHAINS = {
    "input": ("input", 0, "drop"),
    "output_sanitize": ("output", -1, "accept"),
    "output": ("output", 0, "drop"),
    "output_authorize": ("output", 1, "drop"),
    "forward": ("forward", 0, "drop"),
}
_NFT_BLOCK_ALL_COUNTERS = {
    "openshield_owner_v1",
    "accepted_in",
    "accepted_out",
    "dropped_in",
    "dropped_out",
    "learned_out",
}
_NFT_BLOCK_ALL_DROP_COUNTERS = {
    "input": "dropped_in",
    "output": "dropped_out",
    "output_authorize": "dropped_out",
}
_XTABLES_FILTER_DROP_COUNTERS = {
    "OPENSHIELD_IN": "dropped_in",
    "OPENSHIELD_OUT": "dropped_out",
    "OPENSHIELD_FWD": "dropped_out",
    "OPENSHIELD_APP_TCP": "dropped_out",
    "OPENSHIELD_APP_PKT": "dropped_out",
}
_XTABLES_FILTER_DISPATCHERS = {
    "INPUT": "OPENSHIELD_IN",
    "OUTPUT": "OPENSHIELD_OUT",
    "FORWARD": "OPENSHIELD_FWD",
}
_XTABLES_COUNTERED_RULE = re.compile(r"^\[([0-9]+):([0-9]+)\] (.+)$")
_XTABLES_CHAIN_DECLARATION = re.compile(
    r"^:([^\s]+) ([^\s]+) \[([0-9]+):([0-9]+)\]$"
)
_XTABLES_SAVE_CANDIDATES = {
    family: tuple(
        f"{directory}/{program}{suffix}-save"
        for directory in ("/usr/sbin", "/sbin", "/usr/bin", "/bin")
        for suffix in ("-legacy", "-nft", "")
    )
    for family, program in (("ipv4", "iptables"), ("ipv6", "ip6tables"))
}
_XTABLES_VERSION = re.compile(
    r"^(?P<program>ip6?tables(?:-nft)?-save) "
    r"v(?P<version>[0-9]+(?:\.[0-9]+)+)"
    r"(?: \((?P<world>legacy|nf_tables)\))?$"
)
_XTABLES_LEGACY_RESOLVED_NAMES = {
    "xtables-multi",
    "xtables-legacy-multi",
    "iptables-legacy-save",
    "ip6tables-legacy-save",
}
_XTABLES_NFT_RESOLVED_NAMES = {
    "xtables-compat-multi",
    "xtables-nft-multi",
    "iptables-compat-save",
    "ip6tables-compat-save",
    "iptables-nft-save",
    "ip6tables-nft-save",
}
_XTABLES_CANDIDATE_METADATA = r"""
import json
import os
import stat
import sys

def trusted_parent_chain(path, allow_symlinks):
    parent = os.path.dirname(path)
    while True:
        metadata = os.lstat(parent)
        if metadata.st_uid != 0:
            raise ValueError("parent is not owned by root")
        if not (allow_symlinks and stat.S_ISLNK(metadata.st_mode)):
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("parent is not a directory")
            if metadata.st_mode & 0o022:
                raise ValueError("parent is writable by group or other users")
        next_parent = os.path.dirname(parent)
        if next_parent == parent:
            return
        parent = next_parent

def inspect(path):
    try:
        link_metadata = os.lstat(path)
    except FileNotFoundError:
        return {"path": path, "present": False}
    try:
        if link_metadata.st_uid != 0:
            raise ValueError("candidate path is not owned by root")
        trusted_parent_chain(path, True)
        resolved = os.path.realpath(path, strict=True)
        if not os.path.isabs(resolved):
            raise ValueError("resolved path is not absolute")
        metadata = os.stat(resolved)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("resolved target is not a regular file")
        if metadata.st_uid != 0:
            raise ValueError("resolved target is not owned by root")
        if metadata.st_mode & 0o022:
            raise ValueError("resolved target is writable by group or other users")
        if not metadata.st_mode & 0o111:
            raise ValueError("resolved target is not executable")
        trusted_parent_chain(resolved, False)
        return {
            "path": path,
            "present": True,
            "trusted": True,
            "resolved": resolved,
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "size": metadata.st_size,
            "mtime_ns": metadata.st_mtime_ns,
        }
    except (OSError, ValueError) as error:
        return {
            "path": path,
            "present": True,
            "trusted": False,
            "reason": str(error),
        }

print(json.dumps([inspect(path) for path in sys.argv[1:]], sort_keys=True))
"""


def _nonnegative_integer(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= U64_MAX
    )


def _nft_scoped_object(
    value: Any,
    required: set[str],
    optional: set[str],
) -> bool:
    if not isinstance(value, dict):
        return False
    keys = set(value)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        return False
    if value.get("family") != "inet" or value.get("table") != "openshield":
        return False
    return "handle" not in value or _nonnegative_integer(value["handle"])


def _nft_mark_expression(mask: int) -> dict[str, Any]:
    return {"&": [{"meta": {"key": "mark"}}, mask]}


def _nft_sanitize_expression() -> list[dict[str, Any]]:
    return [
        {
            "match": {
                "op": "!=",
                "left": _nft_mark_expression(0xC000_0000),
                "right": 0,
            }
        },
        {
            "mangle": {
                "key": {"meta": {"key": "mark"}},
                "value": _nft_mark_expression(0x3FFF_FFFF),
            }
        },
    ]


def _nft_counted_drop_expression(expression: Any, counter: str | None) -> bool:
    if not isinstance(expression, list) or len(expression) != 2:
        return False
    counter_statement, drop_statement = expression
    if drop_statement != {"drop": None} or not isinstance(counter_statement, dict):
        return False
    if set(counter_statement) != {"counter"}:
        return False
    counter_value = counter_statement["counter"]
    if counter is not None:
        return counter_value == counter
    return (
        isinstance(counter_value, dict)
        and set(counter_value) == {"packets", "bytes"}
        and _nonnegative_integer(counter_value.get("packets"))
        and _nonnegative_integer(counter_value.get("bytes"))
    )


def inspect_nft_block_all(document: Any) -> dict[str, Any]:
    """Verify the exact kernel semantics emitted for nftables BlockAll."""

    if not isinstance(document, dict) or set(document) != {"nftables"}:
        return {
            "inspected": False,
            "block_all": False,
            "reason": "nftables JSON has an invalid top-level shape",
        }
    objects = document.get("nftables")
    if not isinstance(objects, list):
        return {
            "inspected": False,
            "block_all": False,
            "reason": "nftables JSON has no object array",
        }

    failures: list[str] = []
    tables: list[dict[str, Any]] = []
    chains: list[dict[str, Any]] = []
    counters: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    for item in objects:
        if not isinstance(item, dict) or len(item) != 1:
            failures.append("malformed nftables object")
            continue
        kind, value = next(iter(item.items()))
        if kind == "metainfo":
            if not isinstance(value, dict):
                failures.append("malformed nftables metainfo")
            continue
        destination = {
            "table": tables,
            "chain": chains,
            "counter": counters,
            "rule": rules,
        }.get(kind)
        if destination is None:
            failures.append("unexpected object in OpenShield nftables table")
        elif not isinstance(value, dict):
            failures.append(f"malformed nftables {kind} object")
        else:
            destination.append(value)

    if len(tables) != 1:
        failures.append("OpenShield nftables table is missing or duplicated")
    elif set(tables[0]) - {"family", "name", "handle"} or not {
        "family",
        "name",
    }.issubset(tables[0]):
        failures.append("OpenShield nftables table metadata is not canonical")
    elif tables[0].get("family") != "inet" or tables[0].get("name") != "openshield":
        failures.append("unexpected nftables table identity")
    elif "handle" in tables[0] and not _nonnegative_integer(tables[0]["handle"]):
        failures.append("OpenShield nftables table handle is invalid")

    observed_chains: dict[str, dict[str, Any]] = {}
    for chain in chains:
        if not _nft_scoped_object(
            chain,
            {"family", "table", "name", "type", "hook", "prio", "policy"},
            {"handle"},
        ):
            failures.append("OpenShield nftables chain metadata is not canonical")
            continue
        name = chain.get("name")
        if not isinstance(name, str) or name in observed_chains:
            failures.append("OpenShield nftables chain name is invalid or duplicated")
            continue
        observed_chains[name] = chain
    if set(observed_chains) != set(_NFT_BLOCK_ALL_CHAINS):
        failures.append("OpenShield nftables chain set is not canonical BlockAll")
    for name, (hook, priority, policy) in _NFT_BLOCK_ALL_CHAINS.items():
        chain = observed_chains.get(name)
        if chain is None:
            continue
        if (
            chain.get("type") != "filter"
            or chain.get("hook") != hook
            or chain.get("prio") != priority
            or chain.get("policy") != policy
        ):
            failures.append("OpenShield nftables hook, priority, or policy was altered")

    observed_counters: dict[str, dict[str, Any]] = {}
    for counter in counters:
        if not _nft_scoped_object(
            counter,
            {"family", "table", "name", "packets", "bytes"},
            {"handle"},
        ):
            failures.append("OpenShield nftables counter metadata is not canonical")
            continue
        name = counter.get("name")
        if (
            not isinstance(name, str)
            or name in observed_counters
            or not _nonnegative_integer(counter.get("packets"))
            or not _nonnegative_integer(counter.get("bytes"))
        ):
            failures.append("OpenShield nftables counter is invalid or duplicated")
            continue
        observed_counters[name] = counter
    if set(observed_counters) != _NFT_BLOCK_ALL_COUNTERS:
        failures.append("OpenShield nftables named-counter set is not canonical BlockAll")
    owner = observed_counters.get("openshield_owner_v1")
    if owner is not None and (owner.get("packets") != 0 or owner.get("bytes") != 0):
        failures.append("OpenShield nftables ownership sentinel was referenced")

    observed_rules: dict[str, list[Any]] = {}
    for rule in rules:
        if not _nft_scoped_object(
            rule,
            {"family", "table", "chain", "expr"},
            {"handle"},
        ):
            failures.append("OpenShield nftables rule metadata is not canonical")
            continue
        chain = rule.get("chain")
        if not isinstance(chain, str):
            failures.append("OpenShield nftables rule chain is invalid")
            continue
        observed_rules.setdefault(chain, []).append(rule.get("expr"))
    if set(observed_rules) != set(_NFT_BLOCK_ALL_CHAINS) or any(
        len(expressions) != 1 for expressions in observed_rules.values()
    ):
        failures.append("OpenShield nftables rule set is not canonical BlockAll")
    for chain, counter in _NFT_BLOCK_ALL_DROP_COUNTERS.items():
        expressions = observed_rules.get(chain)
        if not (
            isinstance(expressions, list)
            and len(expressions) == 1
            and _nft_counted_drop_expression(expressions[0], counter)
        ):
            failures.append("OpenShield nftables counted-drop rule was altered")
    forward_rules = observed_rules.get("forward")
    if not (
        isinstance(forward_rules, list)
        and len(forward_rules) == 1
        and _nft_counted_drop_expression(forward_rules[0], None)
    ):
        failures.append("OpenShield nftables forward drop rule was altered")
    if observed_rules.get("output_sanitize") != [_nft_sanitize_expression()]:
        failures.append("OpenShield nftables packet-mark sanitizer was altered")

    unique_failures = list(dict.fromkeys(failures))
    block_all = not unique_failures
    return {
        "inspected": True,
        "block_all": block_all,
        "chains": sorted(observed_chains),
        "counters": sorted(observed_counters),
        "rule_counts": {
            name: len(expressions)
            for name, expressions in sorted(observed_rules.items())
        },
        "reason": None if block_all else "; ".join(unique_failures),
    }


def _parse_xtables_save(text: str, table: str) -> dict[str, Any]:
    """Parse one counter-preserving xtables-save table without shell syntax."""

    if table not in {"filter", "mangle"}:
        raise HarnessError("unsupported xtables table")
    if not isinstance(text, str) or "\x00" in text:
        raise HarnessError("xtables-save output is not valid text")
    declarations: set[str] = set()
    rules: list[list[str]] = []
    started = False
    committed = False
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line == f"*{table}":
            if started or committed:
                raise HarnessError("xtables-save table is duplicated")
            started = True
            continue
        if line.startswith("*"):
            raise HarnessError("xtables-save returned an unexpected table")
        if line == "COMMIT":
            if not started or committed:
                raise HarnessError("xtables-save COMMIT is misplaced or duplicated")
            committed = True
            continue
        if not started or committed:
            raise HarnessError("xtables-save data is outside its table")
        declaration = _XTABLES_CHAIN_DECLARATION.fullmatch(line)
        if declaration is not None:
            chain = declaration.group(1)
            if chain in declarations:
                raise HarnessError("xtables-save chain declaration is duplicated")
            declarations.add(chain)
            continue
        counted_rule = _XTABLES_COUNTERED_RULE.fullmatch(line)
        if counted_rule is None:
            raise HarnessError("xtables-save rule has no mandatory counters")
        try:
            tokens = shlex.split(counted_rule.group(3), comments=False, posix=True)
        except ValueError as error:
            raise HarnessError("xtables-save rule has invalid quoting") from error
        if len(tokens) < 3 or tokens[0] != "-A":
            raise HarnessError("xtables-save contains a malformed rule")
        rules.append(tokens)
    if not started or not committed:
        raise HarnessError("xtables-save table is incomplete")
    if any(tokens[1] not in declarations for tokens in rules):
        raise HarnessError("xtables-save rule refers to an undeclared chain")
    return {"declarations": declarations, "rules": rules}


def _xtables_rules_for(snapshot: dict[str, Any], chain: str) -> list[list[str]]:
    return [tokens for tokens in snapshot["rules"] if tokens[1] == chain]


def _xtables_owned_references(
    snapshot: dict[str, Any], owned_chains: set[str]
) -> list[tuple[str, str, str, list[str]]]:
    references: list[tuple[str, str, str, list[str]]] = []
    for tokens in snapshot["rules"]:
        for index, token in enumerate(tokens):
            if token not in {"-j", "--jump", "-g", "--goto"}:
                continue
            if index + 1 >= len(tokens):
                raise HarnessError("xtables-save jump or goto has no target")
            target = tokens[index + 1]
            if target in owned_chains:
                references.append((tokens[1], token, target, tokens))
    return references


def _mark_mask(value: str) -> tuple[int, int] | None:
    parts = value.split("/")
    if len(parts) != 2 or any(
        re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+)", part) is None
        for part in parts
    ):
        return None
    return int(parts[0], 0), int(parts[1], 0)


def _canonical_mark_clear_rule(tokens: list[str], chain: str) -> bool:
    return (
        len(tokens) == 11
        and tokens[:6] == ["-A", chain, "-m", "mark", "!", "--mark"]
        and _mark_mask(tokens[6]) == (0, 0xC000_0000)
        and tokens[7:10] == ["-j", "MARK", "--set-xmark"]
        and _mark_mask(tokens[10]) == (0, 0xC000_0000)
    )


def inspect_xtables_block_all(filter_text: str, mangle_text: str) -> dict[str, Any]:
    """Verify exact IPv4 or IPv6 xtables BlockAll filter/mangle topology."""

    try:
        filter_snapshot = _parse_xtables_save(filter_text, "filter")
        mangle_snapshot = _parse_xtables_save(mangle_text, "mangle")
    except HarnessError as error:
        return {"inspected": False, "block_all": False, "reason": str(error)}

    failures: list[str] = []
    filter_owned = set(_XTABLES_FILTER_DROP_COUNTERS)
    observed_filter_owned = {
        chain
        for chain in filter_snapshot["declarations"]
        if chain.startswith("OPENSHIELD")
    }
    if observed_filter_owned != filter_owned:
        failures.append("OpenShield filter-chain set is not canonical BlockAll")
    for chain, counter in _XTABLES_FILTER_DROP_COUNTERS.items():
        expected = [
            [
                "-A",
                chain,
                "-m",
                "comment",
                "--comment",
                "openshield:owner:v1",
            ],
            [
                "-A",
                chain,
                "-m",
                "comment",
                "--comment",
                f"openshield:{counter}",
                "-j",
                "DROP",
            ],
        ]
        if _xtables_rules_for(filter_snapshot, chain) != expected:
            failures.append("OpenShield filter chain has non-canonical rules")
    try:
        filter_references = _xtables_owned_references(filter_snapshot, filter_owned)
    except HarnessError as error:
        failures.append(str(error))
        filter_references = []
    expected_filter_references = []
    for built_in, target in _XTABLES_FILTER_DISPATCHERS.items():
        expected = ["-A", built_in, "-j", target]
        rules = _xtables_rules_for(filter_snapshot, built_in)
        if not rules or rules[0] != expected:
            failures.append("OpenShield filter dispatcher is not the exact first rule")
        expected_filter_references.append((built_in, "-j", target, expected))
    if sorted(filter_references, key=lambda reference: reference[0]) != sorted(
        expected_filter_references, key=lambda reference: reference[0]
    ):
        failures.append("OpenShield filter dispatchers are missing, duplicated, or redirected")

    mangle_owned = {"OPENSHIELD_MARK", "OPENSHIELD_OBSERVE"}
    observed_mangle_owned = {
        chain
        for chain in mangle_snapshot["declarations"]
        if chain.startswith("OPENSHIELD")
    }
    if observed_mangle_owned != mangle_owned:
        failures.append("OpenShield mangle-chain set is not canonical BlockAll")
    for chain, description in (
        ("OPENSHIELD_MARK", "packet-mark sanitizer"),
        ("OPENSHIELD_OBSERVE", "observation sanitizer"),
    ):
        rules = _xtables_rules_for(mangle_snapshot, chain)
        canonical_rules = (
            len(rules) == 3
            and rules[0]
            == [
                "-A",
                chain,
                "-m",
                "comment",
                "--comment",
                "openshield:owner:v1",
            ]
            and _canonical_mark_clear_rule(rules[1], chain)
            and rules[2] == ["-A", chain, "-j", "RETURN"]
        )
        if not canonical_rules:
            failures.append(f"OpenShield {description} is not canonical")
    expected_first_dispatcher = ["-A", "OUTPUT", "-j", "OPENSHIELD_MARK"]
    expected_last_dispatcher = ["-A", "OUTPUT", "-j", "OPENSHIELD_OBSERVE"]
    output_rules = _xtables_rules_for(mangle_snapshot, "OUTPUT")
    if not output_rules or output_rules[0] != expected_first_dispatcher:
        failures.append("OpenShield mangle mark dispatcher is not the exact first rule")
    if not output_rules or output_rules[-1] != expected_last_dispatcher:
        failures.append(
            "OpenShield mangle observation dispatcher is not the exact last rule"
        )
    try:
        mangle_references = _xtables_owned_references(mangle_snapshot, mangle_owned)
    except HarnessError as error:
        failures.append(str(error))
        mangle_references = []
    if mangle_references != [
        ("OUTPUT", "-j", "OPENSHIELD_MARK", expected_first_dispatcher),
        ("OUTPUT", "-j", "OPENSHIELD_OBSERVE", expected_last_dispatcher),
    ]:
        failures.append(
            "OpenShield mangle dispatchers are missing, duplicated, or redirected"
        )

    unique_failures = list(dict.fromkeys(failures))
    block_all = not unique_failures
    return {
        "inspected": True,
        "block_all": block_all,
        "filter_owned_chains": sorted(observed_filter_owned),
        "mangle_owned_chains": sorted(observed_mangle_owned),
        "reason": None if block_all else "; ".join(unique_failures),
    }


def _parse_xtables_version(
    family: str,
    resolved: str,
    stdout: bytes,
    stderr: bytes,
    returncode: int,
) -> tuple[str, str]:
    """Return a fail-closed (world, exact version line) executable identity."""

    if family not in _XTABLES_SAVE_CANDIDATES:
        raise HarnessError("unsupported xtables family")
    if returncode != 0 or stderr:
        raise HarnessError("xtables-save --version did not complete without diagnostics")
    try:
        output = stdout.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise HarnessError("xtables-save version is not ASCII") from error
    if output.endswith("\r\n"):
        line = output[:-2]
    elif output.endswith(("\n", "\r")):
        line = output[:-1]
    else:
        line = output
    if not line or "\n" in line or "\r" in line:
        raise HarnessError("xtables-save version is not one exact line")
    match = _XTABLES_VERSION.fullmatch(line)
    if match is None:
        raise HarnessError("xtables-save version has an unknown format")
    expected_programs = (
        {"iptables-save", "iptables-nft-save"}
        if family == "ipv4"
        else {"ip6tables-save", "ip6tables-nft-save"}
    )
    if match.group("program") not in expected_programs:
        raise HarnessError("xtables-save version names the wrong address family")
    components = tuple(int(component, 10) for component in match.group("version").split("."))
    basename = os.path.basename(resolved)
    resolved_world = (
        "legacy"
        if basename in _XTABLES_LEGACY_RESOLVED_NAMES
        else "nft"
        if basename in _XTABLES_NFT_RESOLVED_NAMES
        else None
    )
    marker = match.group("world")
    if marker is not None:
        world = "nft" if marker == "nf_tables" else marker
        if resolved_world is not None and resolved_world != world:
            raise HarnessError("xtables backend marker conflicts with its resolved target")
        return world, line
    if components[:2] >= (1, 8):
        raise HarnessError("iptables 1.8 or newer omitted its backend marker")
    if resolved_world is None:
        raise HarnessError("markerless xtables-save has an unknown resolved target")
    return resolved_world, line


def _parse_combined_xtables_save(text: str) -> dict[str, str]:
    """Split one `*-save -c` snapshot while rejecting ambiguous framing."""

    if not isinstance(text, str) or "\x00" in text:
        raise HarnessError("combined xtables-save output is not valid text")
    tables: dict[str, str] = {}
    current_name: str | None = None
    current_lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("*"):
            if current_name is not None:
                raise HarnessError("combined xtables-save contains a nested table")
            name = line[1:]
            if re.fullmatch(r"[a-z0-9_]{1,32}", name) is None or name in tables:
                raise HarnessError("combined xtables-save has an invalid or duplicate table")
            current_name = name
            current_lines = [line]
            continue
        if line == "COMMIT":
            if current_name is None:
                raise HarnessError("combined xtables-save COMMIT has no table")
            current_lines.append(line)
            tables[current_name] = "\n".join(current_lines) + "\n"
            current_name = None
            current_lines = []
            continue
        if current_name is None:
            if line and not line.startswith(
                ("# Generated by ", "# Completed ", "# Warning: ")
            ):
                raise HarnessError(
                    "combined xtables-save has an unknown diagnostic outside a table"
                )
        else:
            current_lines.append(line)
    if current_name is not None:
        raise HarnessError("combined xtables-save contains an unterminated table")
    return tables


def inspect_xtables_world_save(text: str) -> dict[str, Any]:
    """Classify one complete xtables world as canonical, clean, or stale."""

    try:
        tables = _parse_combined_xtables_save(text)
        for name in ("filter", "mangle"):
            if name in tables:
                _parse_xtables_save(tables[name], name)
    except HarnessError as error:
        return {"inspected": False, "state": "invalid", "reason": str(error)}

    unsupported_artifacts = any(
        "openshield" in line.lower()
        for name, table in tables.items()
        if name not in {"filter", "mangle"}
        for line in table.splitlines()
        if line and not line.startswith("#")
    )
    supported_artifacts = any(
        "openshield" in line.lower()
        for name in ("filter", "mangle")
        for line in tables.get(name, "").splitlines()
        if line and not line.startswith("#")
    )
    if not supported_artifacts and not unsupported_artifacts:
        return {
            "inspected": True,
            "state": "clean",
            "tables": sorted(tables),
            "reason": None,
        }
    if "filter" in tables and "mangle" in tables and not unsupported_artifacts:
        canonical = inspect_xtables_block_all(tables["filter"], tables["mangle"])
        if canonical.get("inspected") is True and canonical.get("block_all") is True:
            return {
                "inspected": True,
                "state": "canonical",
                "tables": sorted(tables),
                "reason": None,
            }
        reason = canonical.get("reason")
    else:
        reason = "OpenShield artifacts are outside a complete filter/mangle policy"
    return {
        "inspected": True,
        "state": "stale",
        "tables": sorted(tables),
        "reason": reason or "non-canonical OpenShield artifacts are present",
    }


def _xtables_expected_legacy_warning(family: str, stderr: bytes) -> bool:
    program = "iptables" if family == "ipv4" else "ip6tables"
    line = (
        f"# Warning: {program}-legacy tables present, "
        f"use {program}-legacy-save to see them"
    ).encode("ascii")
    return stderr in {line + b"\n", line + b"\r\n"}


def _xtables_proven_absent(
    *,
    world: str,
    resolved: str,
    version_line: str,
    returncode: int,
    stdout: bytes,
    stderr: bytes,
) -> bool:
    if (
        world != "legacy"
        or returncode != 1
        or stdout
        or os.path.basename(resolved) not in _XTABLES_LEGACY_RESOLVED_NAMES
    ):
        return False
    endings = (b"\r\n\r\n", b"\n\n", b"\r\n", b"\n", b"\r")
    diagnostic = next(
        (stderr[: -len(ending)] for ending in endings if stderr.endswith(ending)),
        stderr,
    )
    if b"\n" in diagnostic or b"\r" in diagnostic:
        return False
    prefix = version_line.encode("ascii")
    return diagnostic in {
        prefix + b": Cannot initialize: iptables who? (do you need to insmod?)",
        prefix + b": Cannot initialize: Protocol not supported",
    }


def classify_xtables_world_capture(
    *,
    family: str,
    world: str,
    resolved: str,
    version_line: str,
    returncode: int,
    stdout: bytes,
    stderr: bytes,
) -> dict[str, Any]:
    """Classify one bounded command result without treating errors as absence."""

    if len(stdout) > MAX_SUBPROCESS_OUTPUT or len(stderr) > 64 * 1024:
        return {
            "inspected": False,
            "state": "invalid",
            "reason": "xtables-save output exceeded its evidence bound",
        }
    if returncode != 0:
        if _xtables_proven_absent(
            world=world,
            resolved=resolved,
            version_line=version_line,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        ):
            return {"inspected": True, "state": "absent", "reason": None}
        return {
            "inspected": False,
            "state": "invalid",
            "reason": "xtables-save failed without proving that its backend is absent",
        }
    program = "iptables" if family == "ipv4" else "ip6tables"
    expected_warning_line = (
        f"# Warning: {program}-legacy tables present, "
        f"use {program}-legacy-save to see them"
    ).encode("ascii")
    stdout_warning_lines = [
        line for line in stdout.splitlines() if line.startswith(b"# Warning:")
    ]
    stdout_warning = stdout_warning_lines == [expected_warning_line]
    stderr_warning = bool(stderr) and _xtables_expected_legacy_warning(family, stderr)
    warning_is_ambiguous = (
        bool(stdout_warning_lines) and not stdout_warning
    ) or (stdout_warning and stderr_warning)
    legacy_warning = stdout_warning or stderr_warning
    if warning_is_ambiguous or (stderr and not stderr_warning) or (
        world != "nft" and legacy_warning
    ):
        return {
            "inspected": False,
            "state": "invalid",
            "reason": "xtables-save emitted an unexpected diagnostic",
        }
    try:
        text = stdout.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return {
            "inspected": False,
            "state": "invalid",
            "reason": "xtables-save output is not ASCII",
        }
    return {
        **inspect_xtables_world_save(text),
        "legacy_present_warning": legacy_warning,
    }


def _deduplicate_xtables_identities(
    snapshot: dict[str, dict[str, Any] | None],
) -> list[dict[str, Any]]:
    """Collapse aliases while retaining every path used to prove stability."""

    identities: dict[tuple[Any, ...], dict[str, Any]] = {}
    for path, record in snapshot.items():
        if record is None:
            continue
        key = (
            record["resolved"],
            record["world"],
            record["device"],
            record["inode"],
        )
        identity = identities.setdefault(
            key,
            {
                "resolved": record["resolved"],
                "world": record["world"],
                "device": record["device"],
                "inode": record["inode"],
                "paths": [],
            },
        )
        identity["paths"].append(path)
    for identity in identities.values():
        identity["paths"].sort()
    return sorted(
        identities.values(),
        key=lambda identity: (identity["world"], identity["resolved"]),
    )


def evaluate_xtables_family_worlds(
    family: str, identities: list[dict[str, Any]]
) -> dict[str, Any]:
    """Require one BlockAll world and clean/absent state everywhere else."""

    failures: list[str] = []
    world_states: dict[str, set[str]] = {}
    world_details: dict[str, list[dict[str, Any]]] = {}
    for identity in identities:
        rounds = identity.get("rounds")
        valid_rounds = (
            isinstance(rounds, list)
            and len(rounds) == 2
            and all(
                isinstance(observation, dict)
                and observation.get("inspected") is True
                and observation.get("state")
                in {"canonical", "clean", "absent", "stale"}
                for observation in rounds
            )
        )
        states = (
            {observation["state"] for observation in rounds}
            if valid_rounds
            else set()
        )
        if not valid_rounds or len(states) != 1:
            failures.append("an xtables identity was inaccessible or changed state")
            stable_state = "invalid"
        else:
            stable_state = next(iter(states))
        world = identity.get("world")
        if world not in {"legacy", "nft"}:
            failures.append("an xtables identity has an unknown backend world")
            continue
        world_states.setdefault(world, set()).add(stable_state)
        world_details.setdefault(world, []).append(
            {
                "resolved": identity.get("resolved"),
                "paths": identity.get("paths"),
                "state": stable_state,
            }
        )

    collapsed: dict[str, str] = {}
    for world, states in world_states.items():
        if len(states) != 1:
            failures.append(f"{world} xtables identities disagree about kernel state")
            collapsed[world] = "invalid"
        else:
            collapsed[world] = next(iter(states))
    legacy_active = collapsed.get("legacy") in {"clean", "canonical"}
    for identity in identities:
        if identity.get("world") != "nft":
            continue
        for observation in identity.get("rounds", []):
            if (
                isinstance(observation, dict)
                and observation.get("legacy_present_warning") is True
                and not legacy_active
            ):
                failures.append(
                    "nft xtables reported legacy tables but that world was not inspectable"
                )
    canonical_worlds = sorted(
        world for world, state in collapsed.items() if state == "canonical"
    )
    if len(canonical_worlds) != 1:
        failures.append("exactly one canonical BlockAll xtables world is required")
    for world, state in collapsed.items():
        if world not in canonical_worlds and state not in {"clean", "absent"}:
            failures.append(f"alternate {world} xtables world is not clean or proven absent")
    unique_failures = list(dict.fromkeys(failures))
    return {
        "family": family,
        "inspected": not unique_failures,
        "block_all": not unique_failures,
        "canonical_world": canonical_worlds[0] if len(canonical_worlds) == 1 else None,
        "worlds": {
            world: {"state": collapsed[world], "identities": world_details[world]}
            for world in sorted(collapsed)
        },
        "reason": None if not unique_failures else "; ".join(unique_failures),
    }


class DockerBackendRun:
    """One disposable DUT/peer topology for one backend and its paired baseline."""

    def __init__(
        self,
        repository: Path,
        daemon: Path,
        output: Path,
        runtime_bundle: Path,
        runtime_manifest_sha256: str,
        config: dict[str, Any],
        backend: str,
        token: str,
        topology_role: str = "protected",
    ) -> None:
        if topology_role not in {"baseline", "protected"}:
            raise HarnessError("topology role must be baseline or protected")
        self.repository = repository
        self.daemon = daemon
        self.output = output
        self.runtime_bundle = runtime_bundle
        self.runtime_manifest_sha256 = runtime_manifest_sha256
        self.config = config
        self.backend = backend
        self.token = token
        self.topology_role = topology_role
        role_suffix = "base" if topology_role == "baseline" else "prot"
        self.label = f"{RUN_LABEL_KEY}={token}"
        self.network_name = f"openshield-perf-{backend[:3]}-{role_suffix}-{token}"
        self.client_name = f"openshield-perf-dut-{backend[:3]}-{role_suffix}-{token}"
        self.peer_name = f"openshield-perf-peer-{backend[:3]}-{role_suffix}-{token}"
        self.canary_name = f"openshield-perf-canary-{backend[:3]}-{role_suffix}-{token}"
        self.canary_network_name = (
            f"openshield-perf-canary-{backend[:3]}-{role_suffix}-{token}"
        )
        self.network_id: str | None = None
        self.canary_network_id: str | None = None
        self.client_id: str | None = None
        self.peer_id: str | None = None
        self.canary_id: str | None = None
        self.client_ip: str | None = None
        self.peer_ip: str | None = None
        self.canary_client_ip: str | None = None
        self.canary_ip: str | None = None
        self.client_interface: str | None = None
        self.peer_interface: str | None = None
        self.canary_client_interface: str | None = None
        self.canary_peer_interface: str | None = None
        self.daemon_pid: int = 0
        self.daemon_starttime: int = 0
        self.daemon_started = False
        self.daemon_log_seen = ""
        self.environment_evidence: dict[str, Any] | None = None
        self.raw = output / "raw" / backend / topology_role
        self.raw.mkdir(parents=True, mode=0o700, exist_ok=True)

    def docker(
        self,
        arguments: list[str],
        *,
        check: bool = True,
        timeout: float = 120,
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        command = ["docker", *arguments]
        completed = subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        if check and completed.returncode != 0:
            stderr = safe_tail(completed.stderr.decode("utf-8", errors="replace"))
            stdout = safe_tail(completed.stdout.decode("utf-8", errors="replace"))
            raise HarnessError(
                f"docker {' '.join(arguments[:3])} failed ({completed.returncode}): {stderr or stdout}"
            )
        return completed

    def docker_text(self, arguments: list[str], **kwargs: Any) -> str:
        completed = self.docker(arguments, **kwargs)
        return completed.stdout.decode("utf-8", errors="strict").strip()

    def provision_dut(self) -> None:
        """Install bounded test prerequisites for the pinned DUT family."""

        if not self.client_id:
            raise HarnessError("DUT is unavailable during provisioning")
        image = self.config["images"]["dut"]
        if image.startswith("opensuse/tumbleweed@sha256:"):
            repository = "repo-oss"
            refresh: subprocess.CompletedProcess[bytes] | None = None
            for attempt in range(1, 4):
                refresh = self.docker(
                    [
                        "exec",
                        self.client_id,
                        "zypper",
                        "--non-interactive",
                        "refresh",
                        repository,
                    ],
                    check=False,
                    timeout=300,
                )
                if refresh.returncode == 0:
                    break
                if refresh.returncode != 4 or attempt == 3:
                    diagnostic = safe_tail(
                        (refresh.stderr or refresh.stdout).decode(
                            "utf-8", errors="replace"
                        )
                    )
                    raise HarnessError(
                        f"zypper refresh failed with status {refresh.returncode}: {diagnostic}"
                    )
                time.sleep(attempt * 5)
            packages = [
                "iptables",
                "python3",
                "shadow",
                "util-linux",
                "conntrack-tools",
                "gcc",
                "glibc-devel",
            ]
            if self.backend == "nftables":
                packages.insert(0, "nftables")
            self.docker(
                [
                    "exec",
                    self.client_id,
                    "zypper",
                    "--non-interactive",
                    "--no-refresh",
                    "install",
                    "--no-recommends",
                    "--repo",
                    repository,
                    *packages,
                ],
                timeout=600,
            )
            return

        if image.startswith("rust:") or image.startswith("debian:"):
            packages = [
                "iptables",
                "python3",
                "passwd",
                "util-linux",
                "conntrack",
                "gcc",
                "libc6-dev",
            ]
            if self.backend == "nftables":
                packages.insert(0, "nftables")
            self.docker(
                [
                    "exec",
                    "-e",
                    "DEBIAN_FRONTEND=noninteractive",
                    self.client_id,
                    "apt-get",
                    "update",
                ],
                timeout=300,
            )
            self.docker(
                [
                    "exec",
                    "-e",
                    "DEBIAN_FRONTEND=noninteractive",
                    self.client_id,
                    "apt-get",
                    "install",
                    "-y",
                    "--no-install-recommends",
                    *packages,
                ],
                timeout=300,
            )
            return
        raise HarnessError("the pinned DUT image family has no trusted provisioner")

    def capture_environment_evidence(self) -> dict[str, Any]:
        """Capture the exact live package/repository state used by this topology."""

        if not self.client_id:
            raise HarnessError("DUT is unavailable during environment capture")
        image_reference = self.config["images"]["dut"]
        try:
            image_id = validate_docker_image_id(
                self.docker(
                    [
                        "image",
                        "inspect",
                        "--format",
                        "{{.Id}}",
                        image_reference,
                    ],
                    timeout=15,
                ).stdout
            )
            os_release = parse_os_release(
                self.docker(
                    ["exec", self.client_id, "cat", "/etc/os-release"],
                    timeout=10,
                ).stdout
            )
            uname = validate_uname(
                self.docker(
                    ["exec", self.client_id, "uname", "-srvm"], timeout=10
                ).stdout
            )
            machine = validate_machine(
                self.docker(
                    ["exec", self.client_id, "uname", "-m"], timeout=10
                ).stdout
            )
            if uname.rsplit(" ", 1)[-1] != machine:
                raise EnvironmentEvidenceError(
                    "uname -srvm machine does not match uname -m evidence"
                )
            if machine != "x86_64":
                raise EnvironmentEvidenceError(
                    f"release performance stand must be x86_64, got {machine}"
                )
            if os_release.get("ID") != "opensuse-tumbleweed":
                raise EnvironmentEvidenceError(
                    "release performance stand must be openSUSE Tumbleweed"
                )
            rpm_inventory_raw = self.docker(
                [
                    "exec",
                    self.client_id,
                    "rpm",
                    "-qa",
                    "--qf",
                    "%{NAME}|%{EPOCHNUM}|%{VERSION}|%{RELEASE}|%{ARCH}\\n",
                ],
                timeout=30,
            ).stdout
            rpm_inventory = parse_rpm_nevra_records(rpm_inventory_raw)
            repomd_raw = self.docker(
                [
                    "exec",
                    self.client_id,
                    "cat",
                    "/var/cache/zypp/raw/repo-oss/repodata/repomd.xml",
                ],
                timeout=10,
            ).stdout
            if not repomd_raw or len(repomd_raw) > 4 * 1024 * 1024:
                raise EnvironmentEvidenceError(
                    "repo-oss repomd.xml is empty or exceeds its byte bound"
                )
            repomd_sha256 = validate_sha256_digest(
                hashlib.sha256(repomd_raw).hexdigest()
            )
        except (EnvironmentEvidenceError, UnicodeError) as error:
            raise HarnessError(f"environment evidence is invalid: {error}") from error
        manifest_document = ("\n".join(rpm_inventory) + "\n").encode("ascii")
        evidence = {
            "schema": "openshield.perf.environment.v1",
            "backend": self.backend,
            "image_reference": image_reference,
            "image_id": image_id,
            "os_release": os_release,
            "uname": uname,
            "machine": machine,
            "repo_oss_repomd_sha256": repomd_sha256,
            "rpm_manifest_sha256": hashlib.sha256(manifest_document).hexdigest(),
            "rpm_nevra": list(rpm_inventory),
            "reproducibility": {
                "image_content_pinned": True,
                "repository_metadata_recorded": True,
                "cross_run_package_set_immutable": False,
                "reason": (
                    "repo-oss is a live signed Tumbleweed repository; this run "
                    "records, but cannot freeze, the resolved package set"
                ),
            },
        }
        write_json(self.raw / "environment.json", evidence)
        return evidence

    def prepare_workload_identity(self, container: str) -> None:
        """Create private runtime state for the fixed numeric workload identity."""

        self.docker(
            [
                "exec",
                container,
                *isolated_python_inline(
                    CONTAINER_WORKLOAD_PREPARER,
                    CONTAINER_WORKLOAD_STATE,
                    str(WORKLOAD_UID),
                    str(WORKLOAD_GID),
                ),
            ],
            timeout=10,
        )
        self.docker(
            [
                "exec",
                "--user",
                WORKLOAD_IDENTITY,
                container,
                *isolated_python_inline(
                    CONTAINER_WORKLOAD_HOME_PREPARER,
                    CONTAINER_WORKLOAD_HOME,
                ),
            ],
            timeout=10,
        )

    def verify_container_runtime_bundle(self, container: str) -> None:
        """Prove the mounted tree contains only the manifest-pinned source set."""

        completed = self.docker(
            ["exec", container, *runtime_python_command(RUNTIME_VERIFY_ONLY)],
            timeout=15,
        )
        try:
            document = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise HarnessError("runtime bundle verifier returned malformed JSON") from error
        if document != {"schema": RUNTIME_BUNDLE_SCHEMA, "verified": True}:
            raise HarnessError("runtime bundle verifier returned unexpected evidence")

    def setup(self) -> None:
        for image in (self.config["images"]["dut"], self.config["images"]["peer"]):
            self.docker(
                ["pull", "--platform", self.config["platform"], image], timeout=300
            )
        self.network_id = self.docker_text(
            ["network", "create", "--internal", "--label", self.label, self.network_name]
        )
        self.canary_network_id = self.docker_text(
            [
                "network",
                "create",
                "--internal",
                "--label",
                self.label,
                self.canary_network_name,
            ]
        )
        mounts = [
            "--mount",
            f"type=bind,src={self.daemon},dst={CONTAINER_DAEMON},readonly",
            "--mount",
            f"type=bind,src={self.runtime_bundle},dst={CONTAINER_PERF_ROOT},readonly",
        ]
        client_arguments = [
            "create",
            "--platform",
            self.config["platform"],
            "--name",
            self.client_name,
            "--label",
            self.label,
            "--network",
            self.network_id,
            "--cap-add",
            "NET_ADMIN",
            "--cap-add",
            "NET_RAW",
            "--cap-add",
            "SYS_PTRACE",
            "--cap-add",
            "DAC_READ_SEARCH",
            "--security-opt",
            "no-new-privileges",
            "--security-opt",
            "label=disable",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--env",
            f"{RUNTIME_MANIFEST_DIGEST_ENV}={self.runtime_manifest_sha256}",
            "--tmpfs",
            "/run:rw,nosuid,nodev,noexec,size=32m",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,exec,size=256m",
            *mounts,
            self.config["images"]["dut"],
            "sleep",
            "infinity",
        ]
        self.client_id = self.docker_text(client_arguments)
        self.docker(["network", "connect", "bridge", self.client_id])
        self.docker(["start", self.client_id])
        self.provision_dut()
        self.verify_container_runtime_bundle(self.client_id)
        self.environment_evidence = self.capture_environment_evidence()
        # Keep daemon state on the container's writable overlay rather than a
        # tmpfs.  Learning therefore includes the production persistence and
        # fsync path while the disposable container still scopes cleanup.
        self.docker(
            ["exec", self.client_id, "install", "-d", "-m", "0700", "/var/lib/openshield"]
        )
        self.docker(
            [
                "exec",
                self.client_id,
                "install",
                "-d",
                "-m",
                "0700",
                DAEMON_RUNTIME_DIRECTORY,
            ]
        )
        self.docker(["exec", self.client_id, "groupadd", "--system", "openshield"])
        self.prepare_workload_identity(self.client_id)
        probe_source = f"{CONTAINER_PERF_ROOT}/workloads/identity_probe.c"
        self.docker(
            [
                "exec",
                self.client_id,
                "gcc",
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                probe_source,
                "-o",
                "/usr/local/bin/openshield-perf-identity-probe",
            ]
        )
        self.docker(
            [
                "exec",
                self.client_id,
                "chmod",
                "0555",
                "/usr/local/bin/openshield-perf-identity-probe",
            ]
        )
        self.docker(["network", "disconnect", "bridge", self.client_id])
        self.docker(
            ["network", "connect", self.canary_network_id, self.client_id]
        )

        peer_arguments = [
            "create",
            "--platform",
            self.config["platform"],
            "--name",
            self.peer_name,
            "--label",
            self.label,
            "--network",
            self.network_id,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--security-opt",
            "label=disable",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--env",
            f"{RUNTIME_MANIFEST_DIGEST_ENV}={self.runtime_manifest_sha256}",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=64m",
            "--mount",
            f"type=bind,src={self.runtime_bundle},dst={CONTAINER_PERF_ROOT},readonly",
            self.config["images"]["peer"],
            "sleep",
            "infinity",
        ]
        self.peer_id = self.docker_text(peer_arguments)
        self.docker(["start", self.peer_id])
        self.verify_container_runtime_bundle(self.peer_id)
        self.prepare_workload_identity(self.peer_id)
        canary_arguments = [
            "create",
            "--platform",
            self.config["platform"],
            "--name",
            self.canary_name,
            "--label",
            self.label,
            "--network",
            self.canary_network_id,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--security-opt",
            "label=disable",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--env",
            f"{RUNTIME_MANIFEST_DIGEST_ENV}={self.runtime_manifest_sha256}",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=64m",
            "--mount",
            f"type=bind,src={self.runtime_bundle},dst={CONTAINER_PERF_ROOT},readonly",
            self.config["images"]["peer"],
            "sleep",
            "infinity",
        ]
        self.canary_id = self.docker_text(canary_arguments)
        self.docker(["start", self.canary_id])
        self.verify_container_runtime_bundle(self.canary_id)
        self.prepare_workload_identity(self.canary_id)
        self.client_ip = self.container_ip(self.client_id)
        self.peer_ip = self.container_ip(self.peer_id)
        self.canary_client_ip = self.container_ip(
            self.client_id, self.canary_network_name
        )
        self.canary_ip = self.container_ip(
            self.canary_id, self.canary_network_name
        )
        self.client_interface = self.container_interface(self.client_id)
        self.peer_interface = self.container_interface(self.peer_id)
        self.canary_client_interface = self.container_interface(
            self.client_id, self.canary_network_name
        )
        self.canary_peer_interface = self.container_interface(
            self.canary_id, self.canary_network_name
        )
        if self.client_ip == self.peer_ip or self.canary_client_ip == self.canary_ip:
            raise HarnessError("a DUT and its peer received the same address")

    def container_ip(self, identifier: str, network_name: str | None = None) -> str:
        output = self.docker_text(["inspect", identifier])
        try:
            document = json.loads(output)
            networks = document[0]["NetworkSettings"]["Networks"]
            address = networks[network_name or self.network_name]["IPAddress"]
            return str(ipaddress.ip_address(address))
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise HarnessError("cannot determine isolated container address") from error

    def container_interface(
        self, identifier: str, network_name: str | None = None
    ) -> str:
        output = self.docker_text(["inspect", identifier])
        try:
            document = json.loads(output)
            address = document[0]["NetworkSettings"]["Networks"][network_name or self.network_name][
                "MacAddress"
            ]
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as error:
            raise HarnessError("cannot determine isolated container MAC address") from error
        if not isinstance(address, str) or not re.fullmatch(
            r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", address
        ):
            raise HarnessError("Docker returned an invalid isolated-network MAC address")
        result = self.docker(
            [
                "exec",
                identifier,
                *isolated_python_inline(
                    "import pathlib,sys; target=sys.argv[1]; matches=[p.parent.name "
                    "for p in pathlib.Path('/sys/class/net').glob('*/address') "
                    "if p.read_text(encoding='ascii').strip()==target]; "
                    "print(matches[0]) if len(matches)==1 else sys.exit(2)",
                    address,
                ),
            ],
            timeout=10,
        )
        interface = result.stdout.decode("ascii", errors="strict").strip()
        if not INTERFACE_PATTERN.fullmatch(interface):
            raise HarnessError("cannot map the isolated-network MAC to one safe interface")
        return interface

    def cleanup(self) -> None:
        for identifier in (self.canary_id, self.peer_id, self.client_id):
            if identifier:
                self.docker(["rm", "--force", identifier], check=False, timeout=30)
        if self.network_id:
            self.docker(["network", "rm", self.network_id], check=False, timeout=30)
        if self.canary_network_id:
            self.docker(
                ["network", "rm", self.canary_network_id], check=False, timeout=30
            )

    def control(self, arguments: list[str], *, check: bool = True) -> Any:
        if not self.client_id:
            raise HarnessError("DUT is not initialized")
        result = self.docker(
            ["exec", self.client_id, *runtime_python_command("control.py", *arguments)],
            check=check,
            timeout=30,
        )
        if result.returncode != 0:
            return None
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise HarnessError("control helper returned invalid JSON") from error

    def observe_daemon_status(self) -> dict[str, Any] | None:
        """Capture one status snapshot, representing transport failure as missing."""

        try:
            candidate = self.control(["status"], check=False)
        except (HarnessError, subprocess.TimeoutExpired, OSError):
            return None
        return candidate if isinstance(candidate, dict) else None

    def poll_daemon_status(
        self, attempts: int = 20, delay_seconds: float = 0.05
    ) -> dict[str, Any] | None:
        """Return a bounded status observation after transient control failures."""

        if attempts < 1 or delay_seconds < 0:
            raise HarnessError("daemon status poll bounds are invalid")
        for attempt in range(attempts):
            candidate = self.observe_daemon_status()
            if candidate is not None:
                return candidate
            if attempt + 1 < attempts:
                time.sleep(delay_seconds)
        return None

    def start_daemon(self) -> dict[str, Any]:
        if self.topology_role != "protected":
            raise HarnessError("the daemon must never start in a baseline topology")
        if self.daemon_started or not self.client_id:
            raise HarnessError("daemon lifecycle is invalid")
        exact = ["setpriv", *CAPABILITY_ARGUMENTS, CONTAINER_DAEMON]
        self.docker(["exec", self.client_id, *exact, "--install-fail-closed"], timeout=30)
        launch = (
            f"umask 077; echo $$ >{DAEMON_PID_FILE}; "
            "exec setpriv --regid root --groups openshield "
            "--bounding-set=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search "
            "--inh-caps=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search "
            "--ambient-caps=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search "
            "-- /opt/openshield-daemon >/tmp/openshield-daemon.log 2>&1"
        )
        self.docker(["exec", "--detach", self.client_id, "/bin/sh", "-c", launch])
        deadline = time.monotonic() + 15.0
        last_error = ""
        while time.monotonic() < deadline:
            status_result = self.docker(
                [
                    "exec",
                    self.client_id,
                    *runtime_python_command("control.py", "status"),
                ],
                check=False,
                timeout=10,
            )
            if status_result.returncode == 0:
                try:
                    status_document = json.loads(status_result.stdout)
                except json.JSONDecodeError:
                    status_document = None
                if isinstance(status_document, dict):
                    expected = "nftables" if self.backend == "nftables" else "iptables"
                    if status_document.get("backend") != expected:
                        raise HarnessError(
                            f"daemon selected {status_document.get('backend')!r}, expected {expected}"
                        )
                    pid_text = self.docker_text(
                        ["exec", self.client_id, "cat", DAEMON_PID_FILE]
                    )
                    self.daemon_pid = integer(int(pid_text), "daemon pid", 1, 1 << 31)
                    identity = self.daemon_process_identity()
                    self.daemon_starttime = integer(
                        identity.get("starttime"), "daemon starttime", 1, 1 << 63
                    )
                    self.daemon_started = True
                    return status_document
            last_error = safe_tail(status_result.stderr.decode("utf-8", errors="replace"), 1_024)
            time.sleep(0.1)
        log = self.read_daemon_log()
        if self.backend == "iptables" and any(
            marker in log.lower()
            for marker in ("protocol not supported", "cannot initialize", "nfqueue is unavailable")
        ):
            raise BackendUnsupported(safe_tail(log))
        raise HarnessError(f"daemon did not become ready: {last_error}\n{safe_tail(log)}")

    def read_daemon_log(self) -> str:
        if not self.client_id:
            return ""
        result = self.docker(
            ["exec", self.client_id, "cat", "/tmp/openshield-daemon.log"],
            check=False,
            timeout=10,
        )
        return result.stdout.decode("utf-8", errors="replace")[-MAX_SUBPROCESS_OUTPUT:]

    def daemon_log_delta(self) -> dict[str, Any]:
        current = self.read_daemon_log()
        delta = current[len(self.daemon_log_seen) :] if current.startswith(self.daemon_log_seen) else current
        self.daemon_log_seen = current
        lowered = delta.lower()
        categories = {
            "queue_overflow_lower_bound": lowered.count("queue overflowed"),
            "attribution_timeout_lower_bound": lowered.count("timed out"),
            "packet_denied_lower_bound": lowered.count("application packet denied"),
            "terminal_queue_error_lower_bound": lowered.count("application packet queue failed")
            + lowered.count("cannot return fail-closed packet verdict"),
        }
        return {
            **categories,
            "measurement": "lower_bound_due_to_daemon_log_throttling",
            "excerpt": safe_tail(delta, 2_048),
        }

    def _xtables_candidate_snapshot(
        self, family: str
    ) -> dict[str, dict[str, Any] | None]:
        """Resolve and identify every fixed, trusted save candidate."""

        if not self.client_id or family not in _XTABLES_SAVE_CANDIDATES:
            raise HarnessError("xtables candidate snapshot has invalid context")
        candidates = _XTABLES_SAVE_CANDIDATES[family]
        metadata_result = self.docker(
            [
                "exec",
                self.client_id,
                *isolated_python_inline(
                    _XTABLES_CANDIDATE_METADATA, *candidates
                ),
            ],
            check=False,
            timeout=10,
        )
        if (
            metadata_result.returncode != 0
            or metadata_result.stderr
            or len(metadata_result.stdout) > 64 * 1024
        ):
            raise HarnessError("cannot obtain bounded xtables executable metadata")
        try:
            metadata = json.loads(metadata_result.stdout)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise HarnessError("xtables executable metadata is malformed") from error
        if not isinstance(metadata, list) or len(metadata) != len(candidates):
            raise HarnessError("xtables executable metadata is incomplete")

        snapshot: dict[str, dict[str, Any] | None] = {}
        for expected_path, record in zip(candidates, metadata, strict=True):
            if not isinstance(record, dict) or record.get("path") != expected_path:
                raise HarnessError("xtables executable metadata changed candidate order")
            present = record.get("present")
            if present is False and set(record) == {"path", "present"}:
                snapshot[expected_path] = None
                continue
            trusted_keys = {
                "path",
                "present",
                "trusted",
                "resolved",
                "device",
                "inode",
                "size",
                "mtime_ns",
            }
            if (
                present is not True
                or record.get("trusted") is not True
                or set(record) != trusted_keys
            ):
                raise HarnessError(
                    f"present xtables candidate is not trusted: {expected_path}"
                )
            resolved = record.get("resolved")
            numeric_fields = ("device", "inode", "size", "mtime_ns")
            if (
                not isinstance(resolved, str)
                or not os.path.isabs(resolved)
                or "\x00" in resolved
                or "\n" in resolved
                or any(
                    not isinstance(record.get(name), int)
                    or isinstance(record.get(name), bool)
                    or record[name] < 0
                    for name in numeric_fields
                )
                or record["inode"] == 0
            ):
                raise HarnessError("xtables executable metadata has an invalid identity")
            version_result = self.docker(
                ["exec", self.client_id, expected_path, "--version"],
                check=False,
                timeout=10,
            )
            if len(version_result.stdout) > 1_024 or len(version_result.stderr) > 1_024:
                raise HarnessError("xtables-save version output exceeded its bound")
            world, version_line = _parse_xtables_version(
                family,
                resolved,
                version_result.stdout,
                version_result.stderr,
                version_result.returncode,
            )
            snapshot[expected_path] = {
                "resolved": resolved,
                "world": world,
                "version_line": version_line,
                **{name: record[name] for name in numeric_fields},
            }
        return snapshot

    def _capture_xtables_identity(
        self,
        family: str,
        identity: dict[str, Any],
        snapshot: dict[str, dict[str, Any] | None],
    ) -> dict[str, Any]:
        if not self.client_id:
            raise HarnessError("DUT is unavailable during xtables inspection")
        path = identity["paths"][0]
        record = snapshot.get(path)
        if not isinstance(record, dict):
            raise HarnessError("xtables identity disappeared before capture")
        result = self.docker(
            ["exec", self.client_id, path, "-c"],
            check=False,
            timeout=10,
        )
        return classify_xtables_world_capture(
            family=family,
            world=identity["world"],
            resolved=identity["resolved"],
            version_line=record["version_line"],
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    def _xtables_family_block_all_observation(self, family: str) -> dict[str, Any]:
        try:
            before = self._xtables_candidate_snapshot(family)
            identities = _deduplicate_xtables_identities(before)
            for identity in identities:
                identity["rounds"] = [
                    self._capture_xtables_identity(family, identity, before)
                ]
            # Inspect all alternate/ambiguous identities again before the final
            # canonical capture, so the selected policy brackets their evidence.
            confirmation_order = sorted(
                identities,
                key=lambda identity: identity["rounds"][0].get("state")
                == "canonical",
            )
            for identity in confirmation_order:
                identity["rounds"].append(
                    self._capture_xtables_identity(family, identity, before)
                )
            after = self._xtables_candidate_snapshot(family)
            if before != after:
                return {
                    "family": family,
                    "inspected": False,
                    "block_all": False,
                    "reason": "trusted xtables executable identities changed during inspection",
                }
            return evaluate_xtables_family_worlds(family, identities)
        except (HarnessError, OSError, subprocess.TimeoutExpired) as error:
            return {
                "family": family,
                "inspected": False,
                "block_all": False,
                "reason": f"xtables world inspection failed: {error}",
            }

    def kernel_block_all_observation(self) -> dict[str, Any]:
        """Independently verify a reported quarantine in the kernel backend."""

        if not self.client_id:
            return {
                "backend": self.backend,
                "inspected": False,
                "block_all": False,
                "reason": "DUT container is unavailable",
            }
        if self.backend == "nftables":
            result = self.docker(
                [
                    "exec",
                    self.client_id,
                    "/usr/sbin/nft",
                    "--json",
                    "list",
                    "table",
                    "inet",
                    "openshield",
                ],
                check=False,
                timeout=10,
            )
            if result.returncode != 0:
                return {
                    "backend": self.backend,
                    "inspected": False,
                    "block_all": False,
                    "reason": safe_tail(
                        result.stderr.decode("utf-8", errors="replace"), 1_024
                    ),
                }
            try:
                document = json.loads(result.stdout)
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                return {
                    "backend": self.backend,
                    "inspected": False,
                    "block_all": False,
                    "reason": f"malformed nftables JSON: {error}",
                }
            return {"backend": self.backend, **inspect_nft_block_all(document)}

        family_observations = {
            family: self._xtables_family_block_all_observation(family)
            for family in ("ipv4", "ipv6")
        }
        inspected = len(family_observations) == 2 and all(
            item.get("inspected") is True for item in family_observations.values()
        )
        block_all = inspected and all(
            item.get("block_all") is True for item in family_observations.values()
        )
        return {
            "backend": self.backend,
            "inspected": inspected,
            "block_all": block_all,
            "families": family_observations,
            "reason": None
            if block_all
            else "; ".join(
                f"{family}: {observation.get('reason') or 'not canonical BlockAll'}"
                for family, observation in family_observations.items()
                if observation.get("block_all") is not True
            ),
        }

    def prepare_policy(self, scenario: dict[str, Any]) -> dict[str, Any] | None:
        expected_role = (
            "baseline" if scenario.get("policy") == "baseline" else "protected"
        )
        if self.topology_role != expected_role:
            raise HarnessError("scenario policy does not match its topology role")
        self.docker(["exec", self.client_id, "conntrack", "-F"], timeout=30)
        if scenario["policy"] == "baseline":
            return None
        if not self.daemon_started:
            self.start_daemon()
        self.control(["set-mode", "learning"])
        self.control(["clear-rules"])
        profile = scenario["profile"]
        policy = scenario["policy"]
        peer = self.peer_ip
        if peer is None:
            raise HarnessError("peer address is unavailable")
        if policy == "network_only":
            self.control(
                [
                    "create-rule",
                    "--name",
                    f"perf-{profile['name']}",
                    "--direction",
                    profile["direction"],
                    "--protocol",
                    profile["transport"],
                    "--peer",
                    f"{peer}/32",
                    "--port",
                    str(profile["port"]),
                    "--interface",
                    self.client_interface,
                ]
            )
        elif scenario["mode"] == "enforcing":
            executable = self.docker_text(
                ["exec", self.client_id, "readlink", "-f", "/usr/bin/python3"]
            )
            self.control(
                [
                    "create-rule",
                    "--name",
                    f"perf-{profile['name']}",
                    "--direction",
                    "outbound",
                    "--protocol",
                    profile["transport"],
                    "--peer",
                    f"{peer}/32",
                    "--port",
                    str(profile["port"]),
                    "--interface",
                    self.client_interface,
                    "--application-executable",
                    executable,
                ]
            )
        self.control(["set-mode", scenario["mode"]])
        status_document = self.control(["status"])
        if not isinstance(status_document, dict) or status_document.get("mode") != scenario["mode"]:
            raise HarnessError("daemon did not enter the requested benchmark mode")
        validate_runtime_compatibility(status_document, scenario)
        return status_document

    def start_server(
        self,
        profile: dict[str, Any],
        seed: int,
        maximum_duration: float,
        server_container: str | None = None,
    ) -> tuple[subprocess.Popen[str], int, str]:
        if not self.client_id or not self.peer_id or not self.client_ip or not self.peer_ip:
            raise HarnessError("container topology is incomplete")
        server_container = server_container or (
            self.client_id if profile["direction"] == "inbound" else self.peer_id
        )
        if not server_container:
            raise HarnessError("workload server container is unavailable")
        command = [
            "docker",
            *workload_exec_arguments(server_container),
            *runtime_python_command(
                f"workloads/{profile['transport']}.py",
                "server",
                "--bind",
                "0.0.0.0",
                "--allow-non-loopback",
                "--port",
                str(profile["port"]),
                "--duration",
                str(maximum_duration),
                "--seed",
                str(seed),
                "--io-timeout",
                str(profile["client"]["io_timeout"]),
                "--processing-delay-ms",
                str(profile["server"].get("processing_delay_ms", 0)),
            ),
        ]
        if profile["transport"] == "tcp":
            maximum_response = max(size for size, _ in parse_mix(profile["client"]["response_mix"], 8 * 1024 * 1024))
            command.extend(
                [
                    "--protocol",
                    profile["client"]["protocol"],
                    "--workers",
                    str(profile["server"].get("workers", 128)),
                    "--backlog",
                    str(profile["server"].get("backlog", 256)),
                    "--max-request-bytes",
                    str(profile["server"].get("max_request_bytes", profile["client"]["request_bytes"])),
                    "--max-response-bytes",
                    str(profile["server"].get("max_response_bytes", maximum_response)),
                ]
            )
        else:
            maximum_request = max(
                size
                for size, _ in parse_mix(
                    profile["client"].get(
                        "request_mix", f"{profile['client']['request_bytes']}:1"
                    ),
                    60_000,
                )
            )
            maximum_response = max(size for size, _ in parse_mix(profile["client"]["response_mix"], 60_000))
            command.extend(
                [
                    "--max-request-bytes",
                    str(profile["server"].get("max_request_bytes", maximum_request)),
                    "--max-response-bytes",
                    str(profile["server"].get("max_response_bytes", maximum_response)),
                    "--socket-buffer-bytes",
                    str(profile["server"].get("socket_buffer_bytes", 4 * 1024 * 1024)),
                ]
            )
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        first_lines: list[str] = []
        selector = selectors.DefaultSelector()
        if process.stdout is None:
            selector.close()
            process.kill()
            process.wait(timeout=5)
            raise HarnessError("cannot capture server readiness")
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + 10
        try:
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                events = selector.select(
                    max(0.0, min(0.2, deadline - time.monotonic()))
                )
                if not events:
                    continue
                line = process.stdout.readline()
                if not line:
                    continue
                first_lines.append(line)
                try:
                    ready = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if (
                    ready.get("schema") == WORKLOAD_SCHEMA
                    and ready.get("event") == "ready"
                ):
                    return (
                        process,
                        integer(ready.get("pid"), "server pid", 1, 1 << 31),
                        "".join(first_lines),
                    )
        finally:
            selector.close()
        if process.poll() is not None:
            remaining = process.communicate(timeout=5)[0]
        else:
            process.terminate()
            try:
                remaining = process.communicate(timeout=5)[0]
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    remaining = process.communicate(timeout=5)[0]
                except subprocess.TimeoutExpired:
                    remaining = ""
        raise HarnessError(f"workload server did not become ready: {safe_tail(''.join(first_lines) + remaining)}")

    def stop_server(
        self, process: subprocess.Popen[str], pid: int, prefix: str, container: str
    ) -> dict[str, Any]:
        def send_signal(signum: int) -> subprocess.CompletedProcess[bytes]:
            return self.docker(
                [
                    *workload_exec_arguments(container),
                    *isolated_python_inline(
                        "import os,sys; os.kill(int(sys.argv[1]),int(sys.argv[2]))",
                        str(pid),
                        str(signum),
                    ),
                ],
                check=False,
                timeout=10,
            )

        termination = None
        if process.poll() is None:
            termination = send_signal(int(signal.SIGTERM))
        try:
            # A failed signal may simply race a naturally completed server. Give
            # that case a short opportunity to publish its summary and be reaped.
            timeout = 10 if termination is None or termination.returncode == 0 else 1
            suffix = process.communicate(timeout=timeout)[0]
        except subprocess.TimeoutExpired as error:
            forced = send_signal(int(signal.SIGKILL))
            try:
                suffix = process.communicate(timeout=5)[0]
            except subprocess.TimeoutExpired as reap_error:
                process.kill()
                try:
                    process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                raise HarnessError(
                    "workload server and its docker exec process could not be reaped"
                ) from reap_error
            if forced.returncode != 0:
                diagnostic = safe_tail(
                    (forced.stderr or forced.stdout).decode("utf-8", errors="replace")
                )
                raise HarnessError(
                    f"cannot force-stop workload server with os.kill: {diagnostic}"
                ) from error
            raise HarnessError("workload server ignored SIGTERM and was force-stopped") from error
        if termination is not None and termination.returncode != 0:
            # Reaching here means the attached process exited during the os.kill
            # race. Only a clean exit carrying a valid summary is acceptable.
            if process.returncode != 0:
                diagnostic = safe_tail(
                    (termination.stderr or termination.stdout).decode(
                        "utf-8", errors="replace"
                    )
                )
                raise HarnessError(
                    f"cannot stop workload server with os.kill: {diagnostic}"
                )
        if process.returncode != 0:
            raise HarnessError(
                f"workload server exited with status {process.returncode}: {safe_tail(prefix + suffix)}"
            )
        return parse_json_event(prefix + suffix, "summary", WORKLOAD_SCHEMA)

    def client_config(
        self,
        profile: dict[str, Any],
        phase: dict[str, Any],
        load_level: float,
        seed: int,
    ) -> dict[str, Any]:
        client = dict(profile["client"])
        scale = float(phase["scale"]) * load_level
        client.update(
            {
                "host": self.client_ip if profile["direction"] == "inbound" else self.peer_ip,
                "port": profile["port"],
                "duration": phase["duration"],
                "seed": seed,
                "operations": client.get("operations", 0),
                "pps": float(client.get("pps", 0)) * scale,
                "mbps": float(client.get("mbps", 0)) * scale,
            }
        )
        if profile["transport"] == "tcp":
            client["cps"] = float(client.get("cps", 0)) * scale
            client["concurrency"] = max(
                1,
                min(
                    MAX_TCP_CLIENT_CONCURRENCY,
                    round(int(client["concurrency"]) * scale),
                ),
            )
            client.pop("reply_every", None)
        else:
            client["flows"] = max(1, min(512, round(int(client["flows"]) * scale)))
        return client

    def copy_client_config(
        self,
        container: str,
        profile: dict[str, Any],
        scenario: dict[str, Any],
        phase: dict[str, Any],
        load_level: float,
        payload: dict[str, Any],
    ) -> str:
        stable = scenario.get("learning_variant") != "discovery_churn"
        container_path = (
            f"{CONTAINER_WORKLOAD_CONFIG}/openshield-perf-client.json"
            if stable
            else (
                f"{CONTAINER_WORKLOAD_CONFIG}/"
                f"openshield-perf-client-{load_level:g}-{phase['name']}.json"
            )
        )
        local_name = (
            f"client-{profile['name']}-{scenario['policy']}-{scenario.get('mode') or 'none'}-"
            f"{scenario.get('learning_variant') or 'none'}-{load_level:g}-{phase['name']}.json"
        )
        local_path = self.raw / local_name
        write_json(local_path, payload)
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        self.docker(
            [
                "exec",
                "--interactive",
                container,
                *isolated_python_inline(
                    CONTAINER_CONFIG_INSTALLER,
                    container_path,
                    str(WORKLOAD_UID),
                    str(WORKLOAD_GID),
                    CONTAINER_WORKLOAD_CONFIG,
                ),
            ],
            input_bytes=encoded,
            timeout=10,
        )
        return container_path

    def metric_process(
        self,
        container: str,
        pid: int,
        duration: float,
        interface_override: str | None = None,
        workload_pid: int = 0,
        nfqueue_number: int = ENFORCING_NFQUEUE_NUMBER,
    ) -> subprocess.Popen[str]:
        if (
            isinstance(nfqueue_number, bool)
            or not isinstance(nfqueue_number, int)
            or nfqueue_number not in PERFORMANCE_NFQUEUE_NUMBERS
        ):
            raise HarnessError("metric collector NFQUEUE number is not allowlisted")
        interval = min(0.1, max(0.02, duration / 5.0))
        interface = interface_override
        if interface is None:
            if container == self.client_id:
                interface = self.client_interface
            elif container == self.peer_id:
                interface = self.peer_interface
            elif container == self.canary_id:
                interface = self.canary_peer_interface
        if interface is None:
            raise HarnessError("measurement interface is unavailable")
        return subprocess.Popen(
            [
                "docker",
                "exec",
                "--interactive",
                container,
                *runtime_python_command(
                    "metrics.py",
                    "--pid",
                    str(pid),
                    "--workload-pid",
                    str(workload_pid),
                    "--interface",
                    interface,
                    "--duration",
                    str(duration),
                    "--interval",
                    str(interval),
                    "--nfqueue-number",
                    str(nfqueue_number),
                    "--synchronize",
                ),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    @staticmethod
    def read_canonical_protocol_document(
        process: subprocess.Popen[str],
        *,
        timeout: float,
        label: str,
        buffer_attribute: str,
    ) -> dict[str, Any]:
        """Read one bounded canonical JSONL document without `readline()` hangs."""

        if process.stdout is None:
            raise HarnessError(f"{label} stdout is unavailable")
        if timeout <= 0 or not math.isfinite(timeout):
            raise HarnessError(f"{label} timeout is invalid")
        buffered = getattr(process, buffer_attribute, None)
        if buffered is None:
            buffered = bytearray()
            setattr(process, buffer_attribute, buffered)
        if not isinstance(buffered, bytearray):
            raise HarnessError(f"{label} protocol buffer is invalid")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout.fileno(), selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                if b"\n" in buffered:
                    raw_line, _, remainder = buffered.partition(b"\n")
                    buffered[:] = remainder
                    if not raw_line or len(raw_line) > MAX_SUBPROCESS_OUTPUT:
                        raise HarnessError(f"{label} line is outside its bound")
                    try:
                        document = json.loads(raw_line.decode("utf-8", errors="strict"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as error:
                        raise HarnessError(f"{label} is not canonical JSON text") from error
                    if not isinstance(document, dict):
                        raise HarnessError(f"{label} is not a JSON object")
                    canonical = json.dumps(
                        document,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode("utf-8")
                    if canonical != raw_line:
                        raise HarnessError(f"{label} is not canonical JSON")
                    return document
                events = selector.select(
                    max(0.0, min(0.2, deadline - time.monotonic()))
                )
                if not events:
                    if process.poll() is not None:
                        break
                    continue
                chunk = os.read(process.stdout.fileno(), 64 * 1024)
                if not chunk:
                    if process.poll() is not None:
                        break
                    continue
                buffered.extend(chunk)
                if len(buffered) > MAX_SUBPROCESS_OUTPUT:
                    raise HarnessError(f"{label} output exceeds its bound")
        finally:
            selector.close()
        raise HarnessError(f"{label} was not received before its bounded deadline")

    @staticmethod
    def pinned_process_identity(
        event: dict[str, Any], *, expected_uid: int, label: str
    ) -> dict[str, Any]:
        pid = integer(event.get("pid"), f"{label} pid", 1, 1 << 31)
        starttime = integer(
            event.get("starttime"), f"{label} starttime", 1, U64_MAX
        )
        uid = integer(event.get("uid"), f"{label} uid", 0, (1 << 32) - 1)
        executable = event.get("executable")
        if uid != expected_uid:
            raise HarnessError(f"{label} uid is not the expected isolated identity")
        if (
            not isinstance(executable, str)
            or not executable.startswith("/")
            or len(os.fsencode(executable)) > 4096
            or "\0" in executable
        ):
            raise HarnessError(f"{label} executable identity is invalid")
        return {
            "pid": pid,
            "starttime": starttime,
            "executable": executable,
            "uid": uid,
        }

    @classmethod
    def await_metric_ready(
        cls, process: subprocess.Popen[str], timeout: float = 10.0
    ) -> dict[str, Any]:
        event = cls.read_canonical_protocol_document(
            process,
            timeout=timeout,
            label="metric collector readiness",
            buffer_attribute="_openshield_metric_protocol_buffer",
        )
        expected = {
            "schema",
            "event",
            "pid",
            "starttime",
            "executable",
            "uid",
        }
        if (
            set(event) != expected
            or event.get("schema") != METRICS_CONTROL_SCHEMA
            or event.get("event") != "ready"
        ):
            raise HarnessError("metric collector readiness is malformed")
        return cls.pinned_process_identity(
            event, expected_uid=0, label="metric collector"
        )

    @staticmethod
    def read_metric_protocol_documents(
        process: subprocess.Popen[str],
        count: int,
        *,
        timeout: float,
        label: str,
    ) -> list[dict[str, Any]]:
        """Read an exact bounded number of line-delimited control documents."""

        if process.stdout is None:
            raise HarnessError("metric collector stdout is unavailable")
        if count <= 0:
            raise HarnessError("metric protocol document count is invalid")
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        documents: list[dict[str, Any]] = []
        buffered = bytearray()
        try:
            while len(documents) < count and time.monotonic() < deadline:
                events = selector.select(
                    max(0.0, min(0.2, deadline - time.monotonic()))
                )
                if not events:
                    if process.poll() is not None:
                        break
                    continue
                chunk = os.read(process.stdout.fileno(), 64 * 1024)
                if not chunk:
                    continue
                buffered.extend(chunk)
                if len(buffered) > count * MAX_SUBPROCESS_OUTPUT:
                    raise HarnessError(
                        f"metric collector {label} exceeds its aggregate bound"
                    )
                while b"\n" in buffered and len(documents) < count:
                    raw_line, _, remainder = buffered.partition(b"\n")
                    buffered[:] = remainder
                    if not raw_line or len(raw_line) > MAX_SUBPROCESS_OUTPUT:
                        raise HarnessError(
                            f"metric collector {label} line is invalid"
                        )
                    try:
                        line = raw_line.decode("utf-8", errors="strict")
                        document = json.loads(line)
                    except (UnicodeDecodeError, json.JSONDecodeError) as error:
                        raise HarnessError(
                            f"metric collector {label} is not canonical JSON text"
                        ) from error
                    if not isinstance(document, dict):
                        raise HarnessError(
                            f"metric collector {label} is not an object"
                        )
                    documents.append(document)
        finally:
            selector.close()
        if len(documents) != count or buffered:
            raise HarnessError(
                f"metric collector did not produce exactly {count} {label} "
                f"document{'s' if count != 1 else ''}"
            )
        return documents

    @classmethod
    def start_metric(
        cls, process: subprocess.Popen[str], timeout: float = 10.0
    ) -> dict[str, Any]:
        """Start a metric window and authenticate its exact initial boundary."""

        if process.stdin is None:
            raise HarnessError("metric collector stdin is unavailable")
        process.stdin.write("start\n")
        process.stdin.flush()
        acknowledgement = cls.read_metric_protocol_documents(
            process, 1, timeout=timeout, label="start acknowledgement"
        )[0]
        if set(acknowledgement) != {
            "schema",
            "event",
            "boundary_monotonic_ns",
        } or acknowledgement.get("schema") != METRICS_CONTROL_SCHEMA or acknowledgement.get(
            "event"
        ) != "start":
            raise HarnessError("metric collector start acknowledgement is malformed")
        boundary = acknowledgement.get("boundary_monotonic_ns")
        if (
            isinstance(boundary, bool)
            or not isinstance(boundary, int)
            or boundary <= 0
        ):
            raise HarnessError("metric collector start boundary is invalid")
        return acknowledgement

    @staticmethod
    def begin_metric(process: subprocess.Popen[str]) -> None:
        if process.stdin is None:
            raise HarnessError("metric collector stdin is unavailable")
        process.stdin.write("start\n")
        process.stdin.flush()

    @classmethod
    def authenticate_metric_start(
        cls, process: subprocess.Popen[str], timeout: float
    ) -> dict[str, Any]:
        acknowledgement = cls.read_metric_protocol_documents(
            process, 1, timeout=timeout, label="start acknowledgement"
        )[0]
        if set(acknowledgement) != {
            "schema",
            "event",
            "boundary_monotonic_ns",
        } or acknowledgement.get("schema") != METRICS_CONTROL_SCHEMA or acknowledgement.get(
            "event"
        ) != "start":
            raise HarnessError("metric collector start acknowledgement is malformed")
        boundary = acknowledgement.get("boundary_monotonic_ns")
        if isinstance(boundary, bool) or not isinstance(boundary, int) or boundary <= 0:
            raise HarnessError("metric collector start boundary is invalid")
        return acknowledgement

    @classmethod
    def start_metrics_together(
        cls,
        processes: Iterable[tuple[str, subprocess.Popen[str]]],
        *,
        deadline: float,
    ) -> dict[str, dict[str, Any]]:
        items = list(processes)
        for _label, process in items:
            cls.begin_metric(process)
        acknowledgements: dict[str, dict[str, Any]] = {}
        for label, process in items:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HarnessError("metric collectors exceeded the shared pre-start bound")
            acknowledgements[label] = cls.authenticate_metric_start(
                process, remaining
            )
        return acknowledgements

    @classmethod
    def split_metric(
        cls, process: subprocess.Popen[str], timeout: float = 10.0
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Read an acknowledged, gap-free metric-window boundary."""

        if process.stdin is None or process.stdout is None:
            raise HarnessError("metric collector control streams are unavailable")
        process.stdin.write("split\n")
        process.stdin.flush()
        documents = cls.read_metric_protocol_documents(
            process, 2, timeout=timeout, label="split response"
        )
        acknowledgement, first_metrics = documents
        if set(acknowledgement) != {
            "schema",
            "event",
            "boundary_monotonic_ns",
        } or acknowledgement.get("schema") != METRICS_CONTROL_SCHEMA or acknowledgement.get(
            "event"
        ) != "split":
            raise HarnessError("metric collector split acknowledgement is malformed")
        boundary = acknowledgement.get("boundary_monotonic_ns")
        if (
            isinstance(boundary, bool)
            or not isinstance(boundary, int)
            or boundary <= 0
            or first_metrics.get("schema") != METRICS_SCHEMA
            or first_metrics.get("stop_reason") != "split_boundary"
            or first_metrics.get("finished_at_monotonic_ns") != boundary
        ):
            raise HarnessError("metric collector split boundary evidence is inconsistent")
        started = first_metrics.get("started_at_monotonic_ns")
        elapsed = numeric(first_metrics.get("elapsed_seconds"))
        if (
            isinstance(started, bool)
            or not isinstance(started, int)
            or started <= 0
            or started > boundary
            or elapsed is None
            or elapsed <= 0
        ):
            raise HarnessError("first split metric window is invalid")
        return acknowledgement, first_metrics

    @staticmethod
    def stop_metric(process: subprocess.Popen[str]) -> None:
        if process.stdin is None:
            raise HarnessError("metric collector stdin closed before stop")
        process.stdin.write("stop\n")
        process.stdin.flush()
        process.stdin.close()
        process.stdin = None

    def run_identity_probe(
        self, transport: str, address: str, port: int, timeout_ms: int
    ) -> dict[str, Any]:
        result = self.docker(
            [
                *workload_exec_arguments(self.client_id),
                "/usr/local/bin/openshield-perf-identity-probe",
                transport,
                address,
                str(port),
                str(timeout_ms),
            ],
            check=False,
            timeout=max(5.0, timeout_ms / 1_000.0 + 2.0),
        )
        output = result.stdout.decode("utf-8", errors="replace") + result.stderr.decode(
            "utf-8", errors="replace"
        )
        try:
            event = parse_json_event(output, "probe", WORKLOAD_SCHEMA)
        except HarnessError:
            event = {"schema": WORKLOAD_SCHEMA, "event": "probe", "parse_error": safe_tail(output)}
        expected_transport = "udp" if transport == "udp" else "tcp"
        expected_protocol = (
            "framed" if transport in {"udp", "tcp-framed"} else "http1"
        )
        latency_ms = numeric(event.get("latency_ms"))
        error_number = event.get("errno")
        event_valid = (
            event.get("schema") == WORKLOAD_SCHEMA
            and event.get("event") == "probe"
            and event.get("role") == "identity_probe"
            and event.get("transport") == expected_transport
            and event.get("protocol") == expected_protocol
            and isinstance(event.get("success"), bool)
            and isinstance(error_number, int)
            and not isinstance(error_number, bool)
            and latency_ms is not None
            and latency_ms >= 0
        )
        timeout_observed = (
            event_valid
            and event.get("success") is False
            and error_number in {errno.EAGAIN, errno.EWOULDBLOCK, errno.ETIMEDOUT}
            and latency_ms is not None
            and latency_ms >= timeout_ms * 0.8
        )
        event["exit_code"] = result.returncode
        event["probe_event_valid"] = event_valid
        event["timeout_observed"] = timeout_observed
        event["blocked"] = result.returncode == 2 and timeout_observed
        event["fail_open"] = result.returncode == 0
        event["indeterminate"] = not event["blocked"] and not event["fail_open"]
        return event

    def run_phase(
        self,
        scenario: dict[str, Any],
        load_level: float,
        phase: dict[str, Any],
        server_pid: int,
        seed: int,
    ) -> dict[str, Any]:
        profile = scenario["profile"]
        dut_nfqueue_number = nfqueue_number_for_mode(scenario.get("mode"))
        client_container = self.peer_id if profile["direction"] == "inbound" else self.client_id
        server_container = self.client_id if profile["direction"] == "inbound" else self.peer_id
        if not client_container or not server_container or not self.peer_ip:
            raise HarnessError("phase container topology is unavailable")
        payload = self.client_config(profile, phase, load_level, seed)
        config_path = self.copy_client_config(
            client_container, profile, scenario, phase, load_level, payload
        )
        protected_phase = scenario["policy"] != "baseline"
        # Potentially slow daemon RPC/proc/log reads precede the inner client.
        # This makes the ready->start controller budget a closed invariant.
        log_before = self.read_daemon_log() if self.daemon_started else ""
        identity_before = (
            self.observe_daemon_process_identity() if protected_phase else None
        )
        status_before = self.observe_daemon_status() if protected_phase else None
        client_command = self.workload_client_command(
            client_container,
            profile["transport"],
            config_path,
            start_gated=True,
        )
        metric_duration = min(
            3_600.0,
            float(phase["duration"])
            + float(profile["client"]["io_timeout"])
            + CONTROLLER_FINISH_RELEASE_BOUND_SECONDS,
        )
        client_process: subprocess.Popen[str] | None = None
        client_identity: dict[str, Any] | None = None
        dut_metric: subprocess.Popen[str] | None = None
        peer_metric: subprocess.Popen[str] | None = None
        dut_metric_identity: dict[str, Any] | None = None
        peer_metric_identity: dict[str, Any] | None = None
        collectors_finished = False
        client_released = False
        primary_error: BaseException | None = None
        try:
            client_process = subprocess.Popen(
                client_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            workload_start_gate = self.await_workload_ready(
                client_process, profile["transport"], timeout=15.0
            )
            client_identity = self.pinned_process_identity(
                workload_start_gate,
                expected_uid=WORKLOAD_UID,
                label="normal workload",
            )
            client_pid = client_identity["pid"]
            prestart_deadline = time.monotonic() + CONTROLLER_PRESTART_BOUND_SECONDS
            dut_metric = self.metric_process(
                self.client_id,
                self.daemon_pid,
                metric_duration,
                workload_pid=(
                    server_pid
                    if profile["direction"] == "inbound"
                    else client_pid
                ),
                nfqueue_number=dut_nfqueue_number,
            )
            peer_metric = self.metric_process(
                self.peer_id,
                0,
                metric_duration,
                workload_pid=(
                    server_pid
                    if profile["direction"] == "outbound"
                    else client_pid
                ),
            )
            remaining = prestart_deadline - time.monotonic()
            dut_metric_identity = self.await_metric_ready(
                dut_metric, timeout=remaining
            )
            remaining = prestart_deadline - time.monotonic()
            peer_metric_identity = self.await_metric_ready(
                peer_metric, timeout=remaining
            )
            metric_starts = self.start_metrics_together(
                (("dut", dut_metric), ("peer", peer_metric)),
                deadline=prestart_deadline,
            )
            remaining = prestart_deadline - time.monotonic()
            if remaining <= 0:
                raise HarnessError("normal workload exceeded the shared pre-start bound")
            workload_started = self.start_workload(
                client_process,
                profile["transport"],
                client_identity,
                timeout=remaining,
            )
            workload_started_ns = integer(
                workload_started.get("boundary_monotonic_ns"),
                "normal workload start boundary",
                1,
                U64_MAX,
            )
            if any(
                integer(
                    evidence.get("boundary_monotonic_ns"),
                    f"{label} metric start boundary",
                    1,
                    U64_MAX,
                )
                > workload_started_ns
                for label, evidence in metric_starts.items()
            ):
                raise HarnessError("workload started before both metric boundaries")
            timeout = (
                float(phase["duration"])
                + float(profile["client"]["io_timeout"])
                + 10.0
            )
            workload, workload_finished = self.await_workload_finished(
                client_process,
                profile["transport"],
                client_identity,
                timeout=timeout,
            )
            finished_ns = integer(
                workload_finished.get("boundary_monotonic_ns"),
                "normal workload finish boundary",
                1,
                U64_MAX,
            )
            if finished_ns < workload_started_ns:
                raise HarnessError("workload finish boundary precedes its start")
            finish_release_deadline = (
                time.monotonic() + CONTROLLER_FINISH_RELEASE_BOUND_SECONDS
            )
            collected = self.finish_metric_collectors(
                (
                    (
                        "dut",
                        dut_metric,
                        self.client_id,
                        dut_metric_identity,
                    ),
                    (
                        "peer",
                        peer_metric,
                        self.peer_id,
                        peer_metric_identity,
                    ),
                )
            )
            collectors_finished = True
            dut_metrics = collected["dut"]
            peer_metrics = collected["peer"]
            client_side_metrics = (
                dut_metrics
                if profile["direction"] == "outbound"
                else peer_metrics
            )
            workload_process_metrics = client_side_metrics.get("workload_process")
            if (
                not isinstance(workload_process_metrics, dict)
                or workload_process_metrics.get("pid") != client_pid
                or workload_process_metrics.get("alive_end") is not True
                or numeric(workload_process_metrics.get("cpu_seconds")) is None
                or numeric(workload_process_metrics.get("rss_bytes_peak")) is None
            ):
                raise HarnessError(
                    "metric boundary did not capture the live workload process"
                )
            expected_exit_code = integer(
                workload_finished.get("exit_code"),
                "normal workload expected exit code",
                0,
                255,
            )
            release_timeout = min(
                10.0, finish_release_deadline - time.monotonic()
            )
            if release_timeout <= 0:
                raise HarnessError(
                    "normal workload finish-to-release interval exceeded its bound"
                )
            workload_released = self.release_workload(
                client_process,
                profile["transport"],
                client_identity,
                expected_exit_code,
                timeout=release_timeout,
            )
            client_released = True
        except BaseException as error:
            primary_error = error
            raise
        finally:
            cleanup_errors: list[str] = []
            if not collectors_finished:
                for label, process, container, identity in (
                    (
                        "DUT metric collector",
                        dut_metric,
                        self.client_id,
                        dut_metric_identity,
                    ),
                    (
                        "peer metric collector",
                        peer_metric,
                        self.peer_id,
                        peer_metric_identity,
                    ),
                ):
                    if process is None:
                        continue
                    try:
                        if identity is not None:
                            self.cancel_pinned_attached_process(
                                process, container, identity, label=label
                            )
                        else:
                            if process.stdin is not None:
                                process.stdin.close()
                                process.stdin = None
                            try:
                                process.communicate(timeout=3)[0]
                            except subprocess.TimeoutExpired:
                                process.kill()
                                process.communicate(timeout=5)
                    except BaseException as cleanup_error:
                        cleanup_errors.append(f"cleanup {label}: {cleanup_error}")
            if client_process is not None and not client_released:
                cleanup_identity = client_identity or getattr(
                    client_process, "_openshield_pinned_identity", None
                )
                try:
                    if cleanup_identity is not None:
                        self.cancel_pinned_attached_process(
                            client_process,
                            client_container,
                            cleanup_identity,
                            label="normal workload",
                        )
                    else:
                        if client_process.stdin is not None:
                            client_process.stdin.close()
                            client_process.stdin = None
                        try:
                            client_process.communicate(timeout=3)[0]
                        except subprocess.TimeoutExpired:
                            client_process.kill()
                            client_process.communicate(timeout=5)
                except BaseException as cleanup_error:
                    cleanup_errors.append(f"cleanup normal workload: {cleanup_error}")
            if cleanup_errors:
                cleanup_failure = HarnessError("; ".join(cleanup_errors))
                if primary_error is not None:
                    raise cleanup_failure from primary_error
                raise cleanup_failure
        if (
            dut_metrics.get("stop_reason") != "requested"
            or peer_metrics.get("stop_reason") != "requested"
        ):
            raise HarnessError("metric collector reached its safety deadline before phase stop")
        workload_wall = numeric(nested(workload, "metrics", "wall_seconds"))
        if workload_wall is not None and workload_wall > 0:
            for collected in (dut_metrics, peer_metrics):
                network = collected.get("network")
                if not isinstance(network, dict):
                    continue
                network["collector_elapsed_seconds"] = collected.get("elapsed_seconds")
                network["rate_denominator_seconds"] = workload_wall
                for prefix in ("rx", "tx"):
                    packets = numeric(network.get(f"{prefix}_packets"))
                    octets = numeric(network.get(f"{prefix}_bytes"))
                    network[f"{prefix}_pps"] = (
                        None if packets is None else packets / workload_wall
                    )
                    network[f"{prefix}_mbps"] = (
                        None
                        if octets is None
                        else octets * 8.0 / workload_wall / 1_000_000.0
                    )
        if self.daemon_started:
            self.daemon_log_seen = log_before
            daemon_log = self.daemon_log_delta()
            status_document = self.observe_daemon_status()
            identity_after = (
                self.observe_daemon_process_identity()
                if protected_phase
                else None
            )
            kernel_block_all = (
                self.kernel_block_all_observation()
                if not isinstance(status_document, dict)
                or status_document.get("mode") == "block_all"
                else None
            )
        else:
            daemon_log = {
                "measurement": "not_applicable_without_daemon",
                "queue_overflow_lower_bound": 0,
                "attribution_timeout_lower_bound": 0,
                "packet_denied_lower_bound": 0,
                "terminal_queue_error_lower_bound": 0,
                "excerpt": "",
            }
            status_document = None
            identity_after = None
            kernel_block_all = None
        result = {
            "backend": self.backend,
            "policy": scenario["policy"],
            "mode": scenario["mode"],
            "learning_variant": scenario.get("learning_variant"),
            "profile": profile["name"],
            "direction": profile["direction"],
            "transport": profile["transport"],
            "dut_interface": self.client_interface,
            "peer_interface": self.peer_interface,
            "load_level": load_level,
            "phase": phase["name"],
            "phase_role": phase["role"],
            "phase_scale": phase["scale"],
            "repetition": phase["repetition"],
            "baseline_sample_id": scenario["baseline_sample_id"],
            "comparison_pair_id": scenario["comparison_pair_id"],
            "comparison_repetition": scenario["comparison_repetition"],
            "comparison_order": scenario["comparison_order"],
            "execution_sequence": scenario["execution_sequence"],
            "topology_role": self.topology_role,
            "block_started_monotonic_ns": scenario[
                "block_started_monotonic_ns"
            ],
            "block_finished_monotonic_ns": None,
            "comparison_gap_seconds": None,
            "seed": seed,
            "offered": payload,
            "workload_start_gate": workload_start_gate,
            "workload_started": workload_started,
            "workload_finished": workload_finished,
            "workload_released": workload_released,
            "metric_starts": metric_starts,
            "metric_collectors": {
                "dut": dut_metric_identity,
                "peer": peer_metric_identity,
            },
            "workload": workload,
            "dut_metrics": dut_metrics,
            "peer_metrics": peer_metrics,
            "daemon_log_events": daemon_log,
            "status_before": status_before,
            "status_after": status_document,
            "daemon_identity_before": identity_before,
            "daemon_identity_after": identity_after,
            "kernel_block_all_after": kernel_block_all,
            # Wrong-executable fail-closed probes run only in the isolated
            # controlled-overload gate. Keeping normal burst traffic identical
            # to baseline makes its relative performance comparison valid.
            "identity_probe": None,
        }
        evaluate_result(result, self.config["criteria"])
        write_json(
            raw_result_path(self.output, result),
            result,
        )
        return result

    def run_load_block(
        self,
        scenario: dict[str, Any],
        load_level: float,
        results: list[dict[str, Any]],
    ) -> None:
        """Run one load point whose temporal pairing was fixed in advance."""

        profile = scenario["profile"]
        self.prepare_policy(scenario)
        phases = comparison_phase_plan(self.config, scenario)
        total_phase_time = sum(float(phase["duration"]) for phase in phases)
        maximum_duration = total_phase_time + 30
        start_index = len(results)
        scenario["block_started_monotonic_ns"] = time.monotonic_ns()
        seed = deterministic_seed(
            self.config["seed"],
            profile["name"],
            f"{load_level:g}",
            f"comparison-{scenario['comparison_repetition']}",
        )
        process, server_pid, prefix = self.start_server(profile, seed, maximum_duration)
        server_container = (
            self.client_id if profile["direction"] == "inbound" else self.peer_id
        )
        try:
            for phase in phases:
                phase_seed = deterministic_seed(seed, phase["name"])
                result = self.run_phase(
                    scenario, float(load_level), phase, server_pid, phase_seed
                )
                results.append(result)
                if (
                    scenario["mode"] == "learning"
                    and scenario.get("learning_variant") == "known_endpoint"
                    and phase["role"] == "warmup"
                ):
                    learned = self.control(["rules"])
                    if not isinstance(learned, list) or not any(
                        rule.get("spec", {}).get("origin") == "learned"
                        for rule in learned
                    ):
                        result["valid"] = False
                        result["passed"] = False
                        result.setdefault("unreliable_reasons", []).append(
                            "warmup did not persist an application-learning rule"
                        )
        finally:
            server_summary = self.stop_server(
                process, server_pid, prefix, server_container
            )
        apply_server_reliability(
            results,
            scenario,
            float(load_level),
            server_summary,
            self.config["criteria"],
        )
        finished = time.monotonic_ns()
        for result in results[start_index:]:
            result["block_finished_monotonic_ns"] = finished
        cooldown = float(self.config["phases"]["cooldown_seconds"])
        if cooldown:
            time.sleep(cooldown)

    def run_scenario(
        self, scenario: dict[str, Any], results: list[dict[str, Any]]
    ) -> None:
        """Run every configured load point using the same bounded block path."""

        for load_level in self.config["load_levels"]:
            self.run_load_block(scenario, float(load_level), results)

    def daemon_process_identity(self) -> dict[str, Any]:
        """Read and authenticate the daemon PID identity from procfs."""

        if not self.client_id or self.daemon_pid <= 0:
            raise HarnessError("daemon process is unavailable for identity inspection")
        script = r"""
import json
import os
import sys

pid = int(sys.argv[1], 10)
raw = open(f"/proc/{pid}/stat", "r", encoding="ascii").read()
close = raw.rfind(")")
fields = raw[close + 2:].split() if close >= 0 else []
if len(fields) <= 19:
    raise SystemExit("malformed daemon proc stat")
print(json.dumps({
    "pid": pid,
    "state": fields[0],
    "starttime": int(fields[19], 10),
    "exe": os.readlink(f"/proc/{pid}/exe"),
}, sort_keys=True, separators=(",", ":")))
"""
        completed = self.docker(
            [
                "exec",
                self.client_id,
                *isolated_python_inline(script, str(self.daemon_pid)),
            ],
            check=False,
            timeout=10,
        )
        if completed.returncode != 0:
            diagnostic = safe_tail(
                (completed.stderr or completed.stdout).decode(
                    "utf-8", errors="replace"
                )
            )
            raise HarnessError(f"cannot inspect daemon process identity: {diagnostic}")
        try:
            identity = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise HarnessError("daemon process identity is malformed") from error
        if (
            not isinstance(identity, dict)
            or identity.get("pid") != self.daemon_pid
            or identity.get("exe") != CONTAINER_DAEMON
            or identity.get("state") not in {"R", "S", "D", "T", "t", "W", "X", "Z", "P", "I"}
        ):
            raise HarnessError("daemon PID does not identify the expected executable")
        starttime = identity.get("starttime")
        if (
            isinstance(starttime, bool)
            or not isinstance(starttime, int)
            or starttime <= 0
            or (self.daemon_starttime > 0 and starttime != self.daemon_starttime)
        ):
            raise HarnessError("daemon PID was reused or has an invalid start time")
        return identity

    def observe_daemon_process_identity(self) -> dict[str, Any] | None:
        """Capture identity evidence without losing a normal-phase result."""

        try:
            return self.daemon_process_identity()
        except (HarnessError, subprocess.TimeoutExpired, OSError):
            return None

    def signal_daemon(self, signum: int) -> dict[str, Any]:
        """Signal only the authenticated daemon and wait for the requested state."""

        if signum not in {int(signal.SIGSTOP), int(signal.SIGCONT)}:
            raise HarnessError("only SIGSTOP and SIGCONT are permitted for overload control")
        identity = self.daemon_process_identity()
        expected_starttime = integer(
            identity.get("starttime"), "daemon starttime", 1, 1 << 63
        )
        if self.daemon_starttime <= 0:
            raise HarnessError("daemon start time was not pinned before overload control")
        script = r"""
import os
import signal
import sys

pid = int(sys.argv[1], 10)
expected_starttime = int(sys.argv[2], 10)
expected_exe = sys.argv[3]
signum = int(sys.argv[4], 10)
descriptor = os.pidfd_open(pid, 0)
try:
    raw = open(f"/proc/{pid}/stat", "r", encoding="ascii").read()
    close = raw.rfind(")")
    fields = raw[close + 2:].split() if close >= 0 else []
    if len(fields) <= 19 or int(fields[19], 10) != expected_starttime:
        raise SystemExit("daemon PID identity changed before signal")
    if os.readlink(f"/proc/{pid}/exe") != expected_exe:
        raise SystemExit("daemon executable changed before signal")
    signal.pidfd_send_signal(descriptor, signum)
finally:
    os.close(descriptor)
"""
        self.docker(
            [
                "exec",
                self.client_id,
                *isolated_python_inline(
                    script,
                    str(self.daemon_pid),
                    str(expected_starttime),
                    CONTAINER_DAEMON,
                    str(signum),
                ),
            ],
            timeout=10,
        )
        deadline = time.monotonic() + 2.0
        expected_stopped = signum == int(signal.SIGSTOP)
        last_identity = identity
        while time.monotonic() < deadline:
            last_identity = self.daemon_process_identity()
            stopped = last_identity["state"] in {"T", "t"}
            if stopped == expected_stopped:
                return last_identity
            time.sleep(0.01)
        target = "stopped" if expected_stopped else "running"
        raise HarnessError(f"daemon did not reach the {target} state after signal")

    @staticmethod
    def workload_client_command(
        container: str,
        transport: str,
        config_path: str,
        *,
        start_gated: bool = False,
    ) -> list[str]:
        exec_arguments = workload_exec_arguments(container)
        if start_gated:
            # Keep stdin attached only for the explicit bounded ready/start
            # protocol. Normal phase clients remain non-interactive.
            exec_arguments.insert(1, "--interactive")
        command = [
            "docker",
            *exec_arguments,
            *runtime_python_command(
                f"workloads/{transport}.py",
                "client",
                "--config-file",
                config_path,
            ),
        ]
        if start_gated:
            command.append("--start-gate-stdin")
        return command

    @staticmethod
    def await_workload_ready(
        process: subprocess.Popen[str], transport: str, timeout: float = 10.0
    ) -> dict[str, Any]:
        """Read one exact ready event and pin the inner process identity."""

        deadline = time.monotonic() + timeout
        spawned = DockerBackendRun.read_canonical_protocol_document(
            process,
            timeout=timeout,
            label="start-gated workload spawn identity",
            buffer_attribute="_openshield_workload_protocol_buffer",
        )
        spawned_expected = {
            "schema",
            "event",
            "role",
            "transport",
            "control_protocol",
            "pid",
            "starttime",
            "executable",
            "uid",
            "boundary_monotonic_ns",
        }
        if (
            set(spawned) != spawned_expected
            or spawned.get("schema") != WORKLOAD_SCHEMA
            or spawned.get("event") != "spawned"
            or spawned.get("role") != "client"
            or spawned.get("transport") != transport
            or spawned.get("control_protocol") != WORKLOAD_CONTROL_PROTOCOL
        ):
            raise HarnessError("start-gated workload spawn identity is malformed")
        identity = DockerBackendRun.pinned_process_identity(
            spawned, expected_uid=WORKLOAD_UID, label="start-gated workload"
        )
        setattr(process, "_openshield_pinned_identity", identity)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise HarnessError("start-gated workload preparation exceeded its bound")
        event = DockerBackendRun.read_canonical_protocol_document(
            process,
            timeout=remaining,
            label="start-gated workload readiness",
            buffer_attribute="_openshield_workload_protocol_buffer",
        )
        ready_expected = spawned_expected - {"boundary_monotonic_ns"}
        if (
            set(event) != ready_expected
            or event.get("schema") != WORKLOAD_SCHEMA
            or event.get("event") != "ready"
            or event.get("role") != "client"
            or event.get("transport") != transport
            or event.get("control_protocol") != WORKLOAD_CONTROL_PROTOCOL
            or DockerBackendRun.pinned_process_identity(
                event, expected_uid=WORKLOAD_UID, label="ready workload"
            )
            != identity
        ):
            raise HarnessError("start-gated workload readiness is malformed")
        return {**event, "spawned": spawned}

    @classmethod
    def start_workload(
        cls,
        process: subprocess.Popen[str],
        transport: str,
        identity: dict[str, Any],
        *,
        timeout: float,
    ) -> dict[str, Any]:
        if process.stdin is None:
            raise HarnessError("start-gated workload stdin is unavailable")
        process.stdin.write("start\n")
        process.stdin.flush()
        event = cls.read_canonical_protocol_document(
            process,
            timeout=timeout,
            label="workload start acknowledgement",
            buffer_attribute="_openshield_workload_protocol_buffer",
        )
        expected = {
            "schema",
            "event",
            "role",
            "transport",
            "control_protocol",
            "pid",
            "starttime",
            "executable",
            "uid",
            "boundary_monotonic_ns",
        }
        if (
            set(event) != expected
            or event.get("schema") != WORKLOAD_SCHEMA
            or event.get("event") != "started"
            or event.get("role") != "client"
            or event.get("transport") != transport
            or event.get("control_protocol") != WORKLOAD_CONTROL_PROTOCOL
            or cls.pinned_process_identity(
                event, expected_uid=WORKLOAD_UID, label="started workload"
            )
            != identity
        ):
            raise HarnessError("workload start acknowledgement is malformed")
        integer(
            event.get("boundary_monotonic_ns"),
            "workload start boundary",
            1,
            U64_MAX,
        )
        return event

    @classmethod
    def await_workload_finished(
        cls,
        process: subprocess.Popen[str],
        transport: str,
        identity: dict[str, Any],
        *,
        timeout: float,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        summary = cls.read_canonical_protocol_document(
            process,
            timeout=timeout,
            label="workload summary",
            buffer_attribute="_openshield_workload_protocol_buffer",
        )
        if (
            summary.get("schema") != WORKLOAD_SCHEMA
            or summary.get("event") != "summary"
            or summary.get("role") != "client"
            or summary.get("transport") != transport
        ):
            raise HarnessError("workload did not publish its expected summary")
        finished = cls.read_canonical_protocol_document(
            process,
            timeout=min(10.0, timeout),
            label="workload finished acknowledgement",
            buffer_attribute="_openshield_workload_protocol_buffer",
        )
        expected = {
            "schema",
            "event",
            "role",
            "transport",
            "control_protocol",
            "pid",
            "starttime",
            "executable",
            "uid",
            "boundary_monotonic_ns",
            "summary_sha256",
            "exit_code",
            "hold",
        }
        digest = hashlib.sha256(
            json.dumps(
                summary,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        if (
            set(finished) != expected
            or finished.get("schema") != WORKLOAD_SCHEMA
            or finished.get("event") != "finished"
            or finished.get("role") != "client"
            or finished.get("transport") != transport
            or finished.get("control_protocol") != WORKLOAD_CONTROL_PROTOCOL
            or finished.get("hold") != "awaiting_release"
            or finished.get("summary_sha256") != digest
            or cls.pinned_process_identity(
                finished, expected_uid=WORKLOAD_UID, label="finished workload"
            )
            != identity
        ):
            raise HarnessError("workload finished acknowledgement is malformed")
        integer(
            finished.get("boundary_monotonic_ns"),
            "workload finish boundary",
            1,
            U64_MAX,
        )
        integer(finished.get("exit_code"), "workload exit code", 0, 255)
        if process.poll() is not None:
            raise HarnessError("workload exited instead of holding for metric release")
        return summary, finished

    @classmethod
    def release_workload(
        cls,
        process: subprocess.Popen[str],
        transport: str,
        identity: dict[str, Any],
        expected_exit_code: int,
        *,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        if process.stdin is None:
            raise HarnessError("workload stdin closed before release")
        process.stdin.write("release\n")
        process.stdin.flush()
        released = cls.read_canonical_protocol_document(
            process,
            timeout=timeout,
            label="workload release acknowledgement",
            buffer_attribute="_openshield_workload_protocol_buffer",
        )
        expected = {
            "schema",
            "event",
            "role",
            "transport",
            "control_protocol",
            "pid",
            "starttime",
            "executable",
            "uid",
            "boundary_monotonic_ns",
        }
        if (
            set(released) != expected
            or released.get("schema") != WORKLOAD_SCHEMA
            or released.get("event") != "released"
            or released.get("role") != "client"
            or released.get("transport") != transport
            or released.get("control_protocol") != WORKLOAD_CONTROL_PROTOCOL
            or cls.pinned_process_identity(
                released, expected_uid=WORKLOAD_UID, label="released workload"
            )
            != identity
        ):
            raise HarnessError("workload release acknowledgement is malformed")
        integer(
            released.get("boundary_monotonic_ns"),
            "workload release boundary",
            1,
            U64_MAX,
        )
        process.stdin.close()
        process.stdin = None
        buffered = getattr(process, "_openshield_workload_protocol_buffer", bytearray())
        suffix = process.communicate(timeout=timeout)[0]
        if buffered or suffix:
            raise HarnessError("workload emitted unexpected output after release")
        if process.returncode != expected_exit_code:
            raise HarnessError(
                f"workload exited with status {process.returncode}, expected {expected_exit_code}"
            )
        return released

    def signal_pinned_inner_process(
        self,
        container: str,
        identity: dict[str, Any],
        signum: int,
        *,
        label: str,
    ) -> dict[str, Any]:
        """Signal one exact container process through a verified pidfd."""

        script = r"""
import json, os, signal, sys
pid, starttime, executable, uid, signum = (
    int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
)
def observe():
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="ascii") as source:
            value = source.read(4096)
        closing = value.rfind(")")
        fields = value[closing + 2:].split() if closing >= 0 else []
        if len(fields) <= 19:
            raise RuntimeError("short stat")
        return (int(fields[19], 10), os.readlink(f"/proc/{pid}/exe"), os.stat(f"/proc/{pid}").st_uid)
    except FileNotFoundError:
        return None
expected = (starttime, executable, uid)
before = observe()
if before is None:
    print(json.dumps({"state":"gone"}, sort_keys=True, separators=(",",":")))
    raise SystemExit(0)
if before != expected:
    print(json.dumps({"state":"identity_mismatch"}, sort_keys=True, separators=(",",":")))
    raise SystemExit(42)
try:
    descriptor = os.pidfd_open(pid, 0)
except ProcessLookupError:
    print(json.dumps({"state":"gone"}, sort_keys=True, separators=(",",":")))
    raise SystemExit(0)
try:
    after = observe()
    if after is None:
        print(json.dumps({"state":"gone"}, sort_keys=True, separators=(",",":")))
        raise SystemExit(0)
    if after != expected:
        print(json.dumps({"state":"identity_mismatch"}, sort_keys=True, separators=(",",":")))
        raise SystemExit(42)
    try:
        signal.pidfd_send_signal(descriptor, signum)
    except ProcessLookupError:
        print(json.dumps({"state":"gone"}, sort_keys=True, separators=(",",":")))
        raise SystemExit(0)
finally:
    os.close(descriptor)
print(json.dumps({"state":"signaled","signal":signum}, sort_keys=True, separators=(",",":")))
"""
        result = self.docker(
            [
                "exec",
                container,
                *isolated_python_inline(
                    script,
                    str(identity["pid"]),
                    str(identity["starttime"]),
                    str(identity["executable"]),
                    str(identity["uid"]),
                    str(signum),
                ),
            ],
            check=False,
            timeout=10,
        )
        try:
            output = result.stdout.decode("utf-8", errors="strict")
            document = json.loads(output)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise HarnessError(f"cannot control {label}: invalid helper response") from error
        if not isinstance(document, dict):
            raise HarnessError(f"cannot control {label}: invalid helper response")
        if result.returncode == 42 or document.get("state") == "identity_mismatch":
            raise HarnessError(
                f"refusing to signal {label}: pinned process identity changed"
            )
        state = document.get("state")
        response_valid = (
            state == "gone" and set(document) == {"state"}
        ) or (
            state == "signaled"
            and set(document) == {"state", "signal"}
            and document.get("signal") == signum
        )
        if result.returncode != 0 or not response_valid:
            diagnostic = safe_tail(
                output + result.stderr.decode("utf-8", errors="replace")
            )
            raise HarnessError(f"cannot signal {label}: {diagnostic}")
        return document

    def cancel_pinned_attached_process(
        self,
        process: subprocess.Popen[str],
        container: str,
        identity: dict[str, Any],
        *,
        label: str,
    ) -> str:
        """Boundedly terminate both the exact inner process and attached CLI."""

        errors: list[str] = []
        output = ""

        def communicate_once(stage: str, timeout: float) -> bool:
            """Attempt one bounded reap without preventing later escalation."""

            nonlocal output
            try:
                observed = process.communicate(timeout=timeout)[0]
                if isinstance(observed, str):
                    output = observed
                return True
            except subprocess.TimeoutExpired:
                return False
            except BaseException as error:
                errors.append(f"{stage}: {error}")
                return False

        if process.poll() is None:
            try:
                self.signal_pinned_inner_process(
                    container, identity, int(signal.SIGTERM), label=label
                )
            except BaseException as error:
                errors.append(f"signal SIGTERM: {error}")
        reaped = communicate_once(
            "reap after SIGTERM", PROCESS_TERMINATION_GRACE_SECONDS
        )
        if not reaped:
            try:
                self.signal_pinned_inner_process(
                    container, identity, int(signal.SIGKILL), label=label
                )
            except BaseException as error:
                errors.append(f"signal SIGKILL: {error}")
            reaped = communicate_once(
                "reap after SIGKILL", PROCESS_TERMINATION_GRACE_SECONDS
            )
        if not reaped:
            # This kills only the local attached Docker CLI. The exact inner
            # process was addressed above; never use a broad pkill.
            try:
                process.kill()
            except BaseException as error:
                errors.append(f"kill local attached process: {error}")
            reaped = communicate_once("reap local attached process", 5.0)
        if not reaped or process.poll() is None:
            errors.append(f"local attached process for {label} is still alive")
        if errors:
            raise HarnessError("; ".join(errors))
        return output

    def finish_metric_collectors(
        self,
        collectors: Iterable[
            tuple[str, subprocess.Popen[str], str, dict[str, Any]]
        ],
    ) -> dict[str, dict[str, Any]]:
        """Stop and reap every collector independently before reporting errors."""

        items = list(collectors)
        stop_errors: dict[str, BaseException] = {}
        for label, process, _container, _identity in items:
            try:
                self.stop_metric(process)
            except BaseException as error:
                stop_errors[label] = error
        documents: dict[str, dict[str, Any]] = {}
        errors: list[str] = []
        for label, process, container, identity in items:
            output = ""
            if label in stop_errors:
                errors.append(f"stop {label}: {stop_errors[label]}")
                try:
                    output = self.cancel_pinned_attached_process(
                        process, container, identity, label=label
                    )
                except BaseException as error:
                    errors.append(f"cancel {label}: {error}")
                continue
            try:
                output = process.communicate(timeout=10)[0]
            except BaseException as error:
                errors.append(f"reap {label}: {error}")
                try:
                    output = self.cancel_pinned_attached_process(
                        process, container, identity, label=label
                    )
                except BaseException as cleanup_error:
                    errors.append(f"cancel {label}: {cleanup_error}")
                continue
            try:
                documents[label] = parse_json_line_document(output, METRICS_SCHEMA)
            except BaseException as error:
                errors.append(f"validate {label}: {error}")
        if errors:
            raise HarnessError("; ".join(errors))
        return documents

    def overload_payload(
        self,
        profile: dict[str, Any],
        *,
        seed: int,
        recovery: bool,
    ) -> dict[str, Any]:
        overload = self.config["overload"]
        duration_key = (
            "recovery_duration_seconds" if recovery else "client_duration_seconds"
        )
        phase = {
            "duration": float(overload[duration_key]),
            "scale": 1.0,
        }
        payload = self.client_config(profile, phase, 1.0, seed)
        payload["pps"] = 0.0
        payload["mbps"] = 0.0
        payload["duration"] = float(overload[duration_key])
        payload["operations"] = int(
            overload["recovery_operations"]
            if recovery
            else (
                overload["tcp_connections"]
                if profile["transport"] == "tcp"
                else overload["udp_datagrams"]
            )
        )
        if profile["transport"] == "tcp":
            payload["cps"] = 0.0
            payload["mode"] = "short"
            payload["keepalive_ratio"] = 0.0
            payload["concurrency"] = (
                min(payload["operations"], 8)
                if recovery
                else int(overload["tcp_concurrency"])
            )
        else:
            payload["flows"] = (
                min(payload["operations"], 4)
                if recovery
                else int(overload["udp_flows"])
            )
            # The pressure half must not wait for replies; the recovery half
            # deliberately requires a real response for every datagram.
            payload["reply_every"] = 1 if recovery else 0
        return payload

    def nfqueue_snapshot(self) -> dict[str, Any]:
        """Take a direct enforcing-queue procfs snapshot for overload proof."""

        if not self.client_id:
            raise HarnessError("DUT is unavailable for NFQUEUE inspection")
        script = r"""
import json
import pathlib
import sys

queue_number = int(sys.argv[1], 10)

result = {
    "present": False,
    "depth": None,
    "copy_mode": None,
    "copy_range": None,
    "kernel_dropped": None,
    "user_dropped": None,
    "sequence": None,
}
try:
    lines = pathlib.Path("/proc/net/netfilter/nfnetlink_queue").read_text(
        encoding="ascii"
    ).splitlines()
except OSError:
    lines = []
for line in lines:
    fields = line.split()
    if len(fields) < 9:
        continue
    try:
        values = [int(value, 10) for value in fields[:9]]
    except ValueError:
        continue
    if values[0] != queue_number:
        continue
    result.update({
        "present": True,
        "depth": values[2],
        "copy_mode": values[3],
        "copy_range": values[4],
        "kernel_dropped": values[5],
        "user_dropped": values[6],
        "sequence": values[7],
    })
    break
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
"""
        completed = self.docker(
            [
                "exec",
                self.client_id,
                *isolated_python_inline(
                    script, str(ENFORCING_NFQUEUE_NUMBER)
                ),
            ],
            timeout=10,
        )
        observed_at = time.monotonic_ns()
        try:
            snapshot = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise HarnessError("direct NFQUEUE snapshot is malformed") from error
        if not isinstance(snapshot, dict) or set(snapshot) != {
            "present",
            "depth",
            "copy_mode",
            "copy_range",
            "kernel_dropped",
            "user_dropped",
            "sequence",
        }:
            raise HarnessError("direct NFQUEUE snapshot has an invalid shape")
        snapshot["observed_at_monotonic_ns"] = observed_at
        return snapshot

    def await_nfqueue_drain(self, timeout_seconds: float) -> dict[str, Any]:
        """Wait for the resumed consumer to drain pre-recovery queue entries.

        Pressure sockets may already have timed out while the daemon is stopped.
        Starting the recovery probe while those stale entries are still ahead of
        it only measures queue backlog, and attribution then correctly fails once
        the owning pressure processes exit.  Recovery is tested only after a
        directly observed empty queue, within this bounded interval.
        """

        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise HarnessError("NFQUEUE drain timeout must be finite and positive")
        started_at_ns = time.monotonic_ns()
        deadline = time.monotonic() + timeout_seconds
        first: dict[str, Any] | None = None
        last: dict[str, Any] | None = None
        samples = 0
        while True:
            snapshot = self.nfqueue_snapshot()
            samples += 1
            if first is None:
                first = snapshot
            last = snapshot
            depth = snapshot.get("depth")
            drained = (
                snapshot.get("present") is True
                and isinstance(depth, int)
                and not isinstance(depth, bool)
                and depth == 0
            )
            if drained:
                return {
                    "measurement": "direct_procfs_nfqueue_depth_after_resume",
                    "timeout_seconds": timeout_seconds,
                    "started_at_monotonic_ns": started_at_ns,
                    "completed_at_monotonic_ns": time.monotonic_ns(),
                    "samples": samples,
                    "first": first,
                    "last": last,
                    "drained": True,
                }
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return {
                    "measurement": "direct_procfs_nfqueue_depth_after_resume",
                    "timeout_seconds": timeout_seconds,
                    "started_at_monotonic_ns": started_at_ns,
                    "completed_at_monotonic_ns": time.monotonic_ns(),
                    "samples": samples,
                    "first": first,
                    "last": last,
                    "drained": False,
                }
            time.sleep(min(NFQUEUE_DRAIN_POLL_SECONDS, remaining))

    def run_canary_workload(
        self,
        profile: dict[str, Any],
        scenario: dict[str, Any],
        *,
        host: str,
        seed: int,
        phase_name: str,
        operations: int,
        container: str | None = None,
    ) -> tuple[int, dict[str, Any]]:
        """Run a bounded allowed-executable round trip against the canary."""

        target_container = self.client_id if container is None else container
        if not target_container:
            raise HarnessError("workload container is unavailable for the canary workload")
        overload = self.config["overload"]
        phase = {
            "name": phase_name,
            "role": "overload",
            "duration": float(overload["recovery_duration_seconds"]),
            "scale": 1.0,
            "repetition": None,
        }
        payload = self.overload_payload(profile, seed=seed, recovery=True)
        payload["host"] = host
        payload["operations"] = operations
        if profile["transport"] == "tcp":
            payload["concurrency"] = min(operations, 8)
        else:
            payload["flows"] = min(operations, 4)
            payload["reply_every"] = 1
        path = self.copy_client_config(
            target_container, profile, scenario, phase, 1.0, payload
        )
        completed = self.docker(
            self.workload_client_command(target_container, profile["transport"], path)[
                1:
            ],
            check=False,
            timeout=(
                float(overload["recovery_duration_seconds"])
                + float(profile["client"]["io_timeout"])
                + 10.0
            ),
        )
        output = completed.stdout.decode(
            "utf-8", errors="replace"
        ) + completed.stderr.decode("utf-8", errors="replace")
        try:
            summary = parse_json_event(output, "summary", WORKLOAD_SCHEMA)
        except HarnessError:
            summary = {
                "schema": WORKLOAD_SCHEMA,
                "event": "summary",
                "parse_error": safe_tail(output),
            }
        return completed.returncode, summary

    def run_out_of_band_server_health_observation(
        self,
        profile: dict[str, Any],
        scenario: dict[str, Any],
        server_process: subprocess.Popen[str],
        *,
        seed: int,
        label: str,
    ) -> dict[str, Any]:
        """Prove peer-server health without traversing the DUT firewall."""

        if not self.canary_id:
            raise HarnessError("canary container is unavailable for out-of-band health")
        started_at_ns = time.monotonic_ns()
        exit_code, summary = self.run_canary_workload(
            profile,
            scenario,
            host="127.0.0.1",
            seed=seed,
            phase_name=label,
            operations=1,
            container=self.canary_id,
        )
        completed_at_ns = time.monotonic_ns()
        server_alive = server_process.poll() is None
        return {
            "path": "canary-container-loopback",
            "started_at_monotonic_ns": started_at_ns,
            "completed_at_monotonic_ns": completed_at_ns,
            "exit_code": exit_code,
            "workload": summary,
            "server_alive": server_alive,
            "passed": server_alive
            and workload_summary_passed(exit_code, summary, profile["transport"], 1),
        }

    def run_liveness_observation(
        self,
        profile: dict[str, Any],
        scenario: dict[str, Any],
        server_process: subprocess.Popen[str],
        *,
        seed: int,
        label: str,
    ) -> dict[str, Any]:
        """Prove that the same-transport canary path is live around a probe."""

        started_at_ns = time.monotonic_ns()
        exit_code, summary = self.run_canary_workload(
            profile,
            scenario,
            host=self.canary_ip or "",
            seed=seed,
            phase_name=label,
            operations=1,
        )
        completed_at_ns = time.monotonic_ns()
        server_alive = server_process.poll() is None
        return {
            "started_at_monotonic_ns": started_at_ns,
            "completed_at_monotonic_ns": completed_at_ns,
            "exit_code": exit_code,
            "workload": summary,
            "server_alive": server_alive,
            "passed": server_alive
            and workload_summary_passed(exit_code, summary, profile["transport"], 1),
        }

    @staticmethod
    def server_summary_validity_reasons(
        summary: dict[str, Any] | None,
        *,
        label: str,
        maximum_cpu_ratio: float,
        allow_protocol_errors: bool = False,
    ) -> list[str]:
        metrics = nested(summary or {}, "metrics", default={})
        if not isinstance(metrics, dict):
            return [f"{label} server metrics are unavailable"]
        reasons: list[str] = []
        cpu = numeric(metrics.get("wall_cpu_ratio"))
        if cpu is None or cpu < 0:
            reasons.append(f"{label} server CPU is unavailable")
        elif cpu > maximum_cpu_ratio:
            reasons.append(f"{label} server CPU saturated")
        names = ["internal_errors"]
        if not allow_protocol_errors:
            names.extend(("connections_rejected", "protocol_errors"))
        for name in names:
            value = numeric(metrics.get(name))
            if value is None or value < 0:
                reasons.append(f"{label} server {name} is unavailable")
            elif value > 0:
                reasons.append(f"{label} server {name} was nonzero")
        return sorted(set(reasons))

    def quarantine_black_box_observation(
        self,
        liveness_profiles: dict[str, dict[str, Any]],
        liveness_servers: dict[
            str, tuple[subprocess.Popen[str], int, str, str]
        ],
        preflight_probes: dict[str, dict[str, Any]],
        timeout_ms: int,
        scenario: dict[str, Any],
        seed: int,
    ) -> dict[str, Any]:
        """Require real TCP and UDP timeouts across a canonical BlockAll policy."""

        bracket_started_at_ns = time.monotonic_ns()
        status_before = self.poll_daemon_status()
        kernel_before = self.kernel_block_all_observation()
        ipv4: dict[str, Any] = {}
        for transport in ("tcp", "udp"):
            profile = liveness_profiles[transport]
            resource = liveness_servers[transport]
            peer_health_before = self.run_out_of_band_server_health_observation(
                profile,
                scenario,
                resource[0],
                seed=deterministic_seed(seed, "quarantine-health-before", transport),
                label=f"quarantine_health_before_{transport}",
            )
            probe_started_at_ns = time.monotonic_ns()
            probe = self.run_identity_probe(
                identity_probe_transport(profile),
                self.canary_ip or "",
                int(profile["port"]),
                timeout_ms,
            )
            probe_completed_at_ns = time.monotonic_ns()
            peer_health_after = self.run_out_of_band_server_health_observation(
                profile,
                scenario,
                resource[0],
                seed=deterministic_seed(seed, "quarantine-health-after", transport),
                label=f"quarantine_health_after_{transport}",
            )
            probe["server_alive"] = resource[0].poll() is None
            probe["preflight_reachable"] = (
                preflight_probes.get(transport, {}).get("fail_open") is True
            )
            probe["started_at_monotonic_ns"] = probe_started_at_ns
            probe["completed_at_monotonic_ns"] = probe_completed_at_ns
            probe["peer_health_before"] = peer_health_before
            probe["peer_health_after"] = peer_health_after
            ipv4[transport] = probe
        kernel_after = self.kernel_block_all_observation()
        status_after = self.poll_daemon_status()
        bracket_completed_at_ns = time.monotonic_ns()
        ordered_timestamps: list[Any] = [bracket_started_at_ns]
        for transport in ("tcp", "udp"):
            probe = ipv4[transport]
            ordered_timestamps.extend(
                (
                    nested(probe, "peer_health_before", "started_at_monotonic_ns"),
                    nested(probe, "peer_health_before", "completed_at_monotonic_ns"),
                    probe.get("started_at_monotonic_ns"),
                    probe.get("completed_at_monotonic_ns"),
                    nested(probe, "peer_health_after", "started_at_monotonic_ns"),
                    nested(probe, "peer_health_after", "completed_at_monotonic_ns"),
                )
            )
        ordered_timestamps.append(bracket_completed_at_ns)
        timestamps_ordered = all(
            isinstance(value, int) and not isinstance(value, bool) and value > 0
            for value in ordered_timestamps
        ) and all(
            first <= second
            for first, second in zip(ordered_timestamps, ordered_timestamps[1:])
        )
        ipv4_passed = all(
            probe.get("preflight_reachable") is True
            and probe.get("server_alive") is True
            and nested(probe, "peer_health_before", "passed") is True
            and nested(probe, "peer_health_after", "passed") is True
            and probe.get("blocked") is True
            and probe.get("fail_open") is False
            for probe in ipv4.values()
        )
        structural_passed = all(
            isinstance(snapshot, dict)
            and snapshot.get("inspected") is True
            and snapshot.get("block_all") is True
            for snapshot in (kernel_before, kernel_after)
        ) and all(
            isinstance(status, dict) and status.get("mode") == "block_all"
            for status in (status_before, status_after)
        )
        # The current Docker topology is explicitly IPv4-only. Record that
        # scope rather than silently claiming dual-stack BlockAll coverage.
        ipv6 = {
            "available": False,
            "valid": False,
            "passed": False,
            "reason": "the configured isolated Docker topology has no IPv6 address",
        }
        valid = ipv4_passed and structural_passed and timestamps_ordered
        return {
            "measurement": "preflight-reachable-real-socket-block-all",
            "ipv4": {
                "available": True,
                "valid": True,
                "passed": ipv4_passed,
                "probes": ipv4,
            },
            "ipv6": ipv6,
            "status_before": status_before,
            "status_after": status_after,
            "kernel_before": kernel_before,
            "kernel_after": kernel_after,
            "bracket_started_at_monotonic_ns": bracket_started_at_ns,
            "bracket_completed_at_monotonic_ns": bracket_completed_at_ns,
            "timestamps_ordered": timestamps_ordered,
            "structural_passed": structural_passed,
            "coverage_complete": False,
            "coverage_policy": "all address families present in the topology",
            "valid": valid,
            "passed": valid,
        }

    def run_overload_safety(self, profile: dict[str, Any]) -> dict[str, Any]:
        """Prove closed verdicts inside a directly observed stopped-consumer window."""

        if (
            not self.client_id
            or not self.peer_id
            or not self.canary_id
            or not self.peer_ip
            or not self.canary_ip
            or not self.client_interface
            or not self.canary_client_interface
            or profile["direction"] != "outbound"
        ):
            raise HarnessError("overload topology requires an outbound DUT and isolated canary")
        transport = profile["transport"]
        probe_transport = identity_probe_transport(profile)
        policy = f"application_{transport}"
        scenario = {
            "profile": profile,
            "policy": policy,
            "mode": "enforcing",
            "learning_variant": None,
            "backend": self.backend,
        }
        self.prepare_policy(scenario)
        canary_profile = {
            **profile,
            "name": f"overload_{transport}_canary",
            "port": int(self.config["overload"][f"{transport}_canary_port"]),
        }
        liveness_profiles: dict[str, dict[str, Any]] = {}
        for liveness_transport in ("tcp", "udp"):
            source_profile = next(
                candidate
                for candidate in self.config["profiles"]
                if candidate["direction"] == "outbound"
                and candidate["transport"] == liveness_transport
                and f"application_{liveness_transport}"
                in candidate["policy_cases"]
            )
            liveness_profiles[liveness_transport] = {
                **source_profile,
                "name": f"overload_{liveness_transport}_liveness",
                "port": int(
                    self.config["overload"][f"{liveness_transport}_liveness_port"]
                ),
            }
        executable = self.docker_text(
            ["exec", self.client_id, "readlink", "-f", "/usr/bin/python3"]
        )
        self.control(
            [
                "create-rule",
                "--name",
                f"perf-overload-canary-{transport}",
                "--direction",
                "outbound",
                "--protocol",
                transport,
                "--peer",
                f"{self.canary_ip}/32",
                "--port",
                str(canary_profile["port"]),
                "--interface",
                self.canary_client_interface,
                "--application-executable",
                executable,
            ]
        )
        for liveness_transport, liveness_profile in liveness_profiles.items():
            # This exact network-only allow is intentionally independent of
            # executable attribution. It proves that a timed-out wrong-exe
            # probe is caused by fail-closed application handling, rather than
            # a dead canary, broken veth, or saturated same-transport socket.
            self.control(
                [
                    "create-rule",
                    "--name",
                    f"perf-overload-liveness-{liveness_transport}",
                    "--direction",
                    "outbound",
                    "--protocol",
                    liveness_transport,
                    "--peer",
                    f"{self.canary_ip}/32",
                    "--port",
                    str(liveness_profile["port"]),
                    "--interface",
                    self.canary_client_interface,
                ]
            )
        overload = self.config["overload"]
        seed = deterministic_seed(
            self.config["seed"], "overload", transport, profile["name"]
        )
        server_lifetime = (
            float(overload["client_duration_seconds"])
            + 2 * float(overload["recovery_duration_seconds"])
            + float(overload["pause_seconds"])
            + 2
            * int(overload["probe_attempts"])
            * int(overload["probe_timeout_ms"])
            / 1_000.0
            + 30.0
        )

        pressure_server: tuple[subprocess.Popen[str], int, str, str] | None = None
        canary_server: tuple[subprocess.Popen[str], int, str, str] | None = None
        liveness_servers: dict[
            str, tuple[subprocess.Popen[str], int, str, str]
        ] = {}
        pressure_process: subprocess.Popen[str] | None = None
        pressure_identity: dict[str, Any] | None = None
        dut_metric: subprocess.Popen[str] | None = None
        peer_metric: subprocess.Popen[str] | None = None
        canary_metric: subprocess.Popen[str] | None = None
        dut_metric_identity: dict[str, Any] | None = None
        peer_metric_identity: dict[str, Any] | None = None
        canary_metric_identity: dict[str, Any] | None = None
        daemon_may_be_stopped = False
        primary_error: BaseException | None = None

        def finish_metric(
            process: subprocess.Popen[str],
            container: str,
            identity: dict[str, Any],
        ) -> dict[str, Any]:
            if process.poll() is None and process.stdin is not None:
                self.stop_metric(process)
            try:
                output = process.communicate(timeout=10)[0]
            except subprocess.TimeoutExpired as error:
                try:
                    self.cancel_pinned_attached_process(
                        process,
                        container,
                        identity,
                        label="overload metric collector",
                    )
                except BaseException as cleanup_error:
                    raise HarnessError(
                        "overload metric collector timed out and exact cleanup failed"
                    ) from cleanup_error
                raise HarnessError(
                    "overload metric collector exceeded its bounded deadline"
                ) from error
            return parse_json_line_document(output, METRICS_SCHEMA)

        try:
            server = self.start_server(profile, seed, server_lifetime, self.peer_id)
            pressure_server = (*server, self.peer_id)
            server = self.start_server(
                canary_profile,
                deterministic_seed(seed, "canary"),
                server_lifetime,
                self.canary_id,
            )
            canary_server = (*server, self.canary_id)
            canary_process = canary_server[0]
            for liveness_transport, liveness_profile in liveness_profiles.items():
                server = self.start_server(
                    liveness_profile,
                    deterministic_seed(seed, "liveness", liveness_transport),
                    server_lifetime,
                    self.canary_id,
                )
                liveness_servers[liveness_transport] = (*server, self.canary_id)

            liveness_preflight: dict[str, dict[str, Any]] = {}
            liveness_preflight_probes: dict[str, dict[str, Any]] = {}
            for liveness_transport, liveness_profile in liveness_profiles.items():
                liveness_preflight[liveness_transport] = (
                    self.run_liveness_observation(
                        liveness_profile,
                        scenario,
                        liveness_servers[liveness_transport][0],
                        seed=deterministic_seed(
                            seed, "liveness-preflight", liveness_transport
                        ),
                        label=f"liveness_preflight_{liveness_transport}",
                    )
                )
                # The exact probe executable used for post-quarantine evidence
                # must first complete a round trip while the endpoint is live.
                liveness_preflight_probes[liveness_transport] = (
                    self.run_identity_probe(
                        identity_probe_transport(liveness_profile),
                        self.canary_ip,
                        int(liveness_profile["port"]),
                        int(overload["probe_timeout_ms"]),
                    )
                )

            preflight_exit_code, preflight_summary = self.run_canary_workload(
                canary_profile,
                scenario,
                host=self.canary_ip,
                seed=deterministic_seed(seed, "allowed-preflight"),
                phase_name=f"allowed_preflight_{transport}",
                operations=1,
            )
            preflight_allowed = workload_summary_passed(
                preflight_exit_code, preflight_summary, transport, 1
            )
            preflight_liveness_before = self.run_liveness_observation(
                liveness_profiles[transport],
                scenario,
                liveness_servers[transport][0],
                seed=deterministic_seed(seed, "preflight-liveness-before"),
                label=f"preflight_liveness_before_{transport}",
            )
            preflight_wrong = self.run_identity_probe(
                probe_transport,
                self.canary_ip,
                canary_profile["port"],
                int(overload["probe_timeout_ms"]),
            )
            preflight_liveness_after = self.run_liveness_observation(
                liveness_profiles[transport],
                scenario,
                liveness_servers[transport][0],
                seed=deterministic_seed(seed, "preflight-liveness-after"),
                label=f"preflight_liveness_after_{transport}",
            )
            preflight_canary_alive = canary_process.poll() is None

            # Remove every preflight conntrack entry. Pressure and recovery
            # therefore exercise fresh application attribution decisions.
            self.docker(["exec", self.client_id, "conntrack", "-F"], timeout=30)
            pressure_phase = {
                "name": f"overload_{transport}",
                "role": "overload",
                "duration": float(overload["client_duration_seconds"]),
                "scale": 1.0,
                "repetition": None,
            }
            pressure_payload = self.overload_payload(
                profile, seed=seed, recovery=False
            )
            pressure_path = self.copy_client_config(
                self.client_id,
                profile,
                scenario,
                pressure_phase,
                1.0,
                pressure_payload,
            )
            pressure_process = subprocess.Popen(
                self.workload_client_command(
                    self.client_id,
                    transport,
                    pressure_path,
                    start_gated=True,
                ),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            pressure_readiness = self.await_workload_ready(
                pressure_process, transport
            )
            pressure_identity = self.pinned_process_identity(
                pressure_readiness,
                expected_uid=WORKLOAD_UID,
                label="overload pressure workload",
            )
            metric_duration = min(
                3_600.0,
                server_lifetime - 5.0,
            )
            dut_metric = self.metric_process(
                self.client_id,
                self.daemon_pid,
                metric_duration,
                interface_override=self.client_interface,
                nfqueue_number=ENFORCING_NFQUEUE_NUMBER,
            )
            peer_metric = self.metric_process(
                self.peer_id, pressure_server[1], metric_duration
            )
            canary_metric = self.metric_process(
                self.canary_id,
                canary_server[1],
                metric_duration,
                interface_override=self.canary_peer_interface,
                workload_pid=liveness_servers[transport][1],
            )
            metric_deadline = time.monotonic() + CONTROLLER_PRESTART_BOUND_SECONDS
            dut_metric_identity = self.await_metric_ready(
                dut_metric, timeout=metric_deadline - time.monotonic()
            )
            peer_metric_identity = self.await_metric_ready(
                peer_metric, timeout=metric_deadline - time.monotonic()
            )
            canary_metric_identity = self.await_metric_ready(
                canary_metric, timeout=metric_deadline - time.monotonic()
            )
            metric_starts = self.start_metrics_together(
                (
                    ("dut", dut_metric),
                    ("peer", peer_metric),
                    ("canary", canary_metric),
                ),
                deadline=metric_deadline,
            )
            dut_metric_start = metric_starts["dut"]
            peer_metric_start = metric_starts["peer"]
            canary_metric_start = metric_starts["canary"]

            log_before = self.read_daemon_log()
            queue_before_stop = self.nfqueue_snapshot()
            daemon_may_be_stopped = True
            stopped_identity = self.signal_daemon(int(signal.SIGSTOP))
            stopped_at_ns = time.monotonic_ns()
            pressure_started = self.start_workload(
                pressure_process,
                transport,
                pressure_identity,
                timeout=10.0,
            )

            saturation_snapshot: dict[str, Any] | None = None
            saturation_delta: dict[str, int | None] = {
                "kernel_dropped": None,
                "user_dropped": None,
                "total": None,
            }
            saturation_deadline = time.monotonic() + float(
                overload["pause_seconds"]
            )
            while time.monotonic() < saturation_deadline:
                candidate = self.nfqueue_snapshot()
                candidate_delta = nfqueue_drop_delta(queue_before_stop, candidate)
                if (
                    candidate.get("present") is True
                    and candidate_delta["total"] is not None
                    and candidate_delta["total"]
                    >= int(overload["minimum_nfqueue_drops"])
                ):
                    saturation_snapshot = candidate
                    saturation_delta = candidate_delta
                    break
                if pressure_process.poll() is not None:
                    break
                time.sleep(0.01)

            observations: list[dict[str, Any]] = []
            if saturation_snapshot is not None:
                for attempt in range(1, int(overload["probe_attempts"]) + 1):
                    identity = self.daemon_process_identity()
                    if identity["state"] not in {"T", "t"}:
                        raise HarnessError(
                            "daemon resumed before the overload probe window completed"
                        )
                    liveness_before = self.run_liveness_observation(
                        liveness_profiles[transport],
                        scenario,
                        liveness_servers[transport][0],
                        seed=deterministic_seed(
                            seed, "stall-liveness-before", str(attempt)
                        ),
                        label=f"stall_liveness_before_{transport}_{attempt}",
                    )
                    snapshot_before_probe = self.nfqueue_snapshot()
                    started_at_ns = time.monotonic_ns()
                    observation = self.run_identity_probe(
                        probe_transport,
                        self.canary_ip,
                        canary_profile["port"],
                        int(overload["probe_timeout_ms"]),
                    )
                    completed_at_ns = time.monotonic_ns()
                    snapshot_after_probe = self.nfqueue_snapshot()
                    liveness_after = self.run_liveness_observation(
                        liveness_profiles[transport],
                        scenario,
                        liveness_servers[transport][0],
                        seed=deterministic_seed(
                            seed, "stall-liveness-after", str(attempt)
                        ),
                        label=f"stall_liveness_after_{transport}_{attempt}",
                    )
                    observation.update(
                        {
                            "attempt": attempt,
                            "started_at_monotonic_ns": started_at_ns,
                            "completed_at_monotonic_ns": completed_at_ns,
                            "nfqueue_before": snapshot_before_probe,
                            "nfqueue_after": snapshot_after_probe,
                            "liveness_before": liveness_before,
                            "liveness_after": liveness_after,
                            "isolated_canary_server_alive": (
                                canary_process.poll() is None
                            ),
                        }
                    )
                    observations.append(observation)

            if pressure_process is None:
                raise HarnessError("overload pressure process was not started")
            active_pressure = pressure_process
            pressure_summary, pressure_finished = self.await_workload_finished(
                active_pressure,
                transport,
                pressure_identity,
                timeout=(
                    float(overload["client_duration_seconds"])
                    + float(profile["client"]["io_timeout"])
                    + 10.0
                ),
            )
            pressure_exit_code = integer(
                pressure_finished.get("exit_code"),
                "overload pressure exit code",
                0,
                255,
            )
            pressure_released = self.release_workload(
                active_pressure,
                transport,
                pressure_identity,
                pressure_exit_code,
            )
            pressure_process = None
            # This upper-bound timestamp is captured only after the pressure
            # process has exited. Consequently every classified send failure
            # in its summary belongs to the stopped-consumer metric window.
            pressure_reaped_at_ns = time.monotonic_ns()

            queue_before_continue = self.nfqueue_snapshot()
            stall_drop_delta = nfqueue_drop_delta(
                queue_before_stop, queue_before_continue
            )
            identity_before_continue = self.daemon_process_identity()
            if identity_before_continue["state"] not in {"T", "t"}:
                raise HarnessError("daemon was not stopped immediately before SIGCONT")
            self.signal_daemon(int(signal.SIGCONT))
            daemon_may_be_stopped = False
            continued_at_ns = time.monotonic_ns()

            # Resume first, then split one continuous collector. Its exact
            # boundary snapshot closes the stopped-pressure/resume-transition
            # interval and opens a clean recovery interval. No counter can
            # disappear in a process-launch hand-off, and the second window
            # never starts while the NFQUEUE consumer is deliberately stopped.
            metric_boundary, dut_metrics = self.split_metric(dut_metric)

            recovery_queue_drain = self.await_nfqueue_drain(
                min(
                    10.0,
                    float(overload["recovery_duration_seconds"])
                    + float(profile["client"]["io_timeout"]),
                )
            )
            status_before_recovery = self.poll_daemon_status()
            recovery_exit_code: int | None = None
            recovery_summary: dict[str, Any] | None = None
            recovery_liveness_before: dict[str, Any] | None = None
            recovery_liveness_after: dict[str, Any] | None = None
            if (
                isinstance(status_before_recovery, dict)
                and status_before_recovery.get("mode") == "block_all"
            ):
                recovery_probe = {
                    "skipped_due_to_reported_quarantine": True,
                    "blocked": None,
                    "fail_open": False,
                    "indeterminate": False,
                }
            else:
                self.docker(["exec", self.client_id, "conntrack", "-F"], timeout=30)
                recovery_exit_code, recovery_summary = self.run_canary_workload(
                    canary_profile,
                    scenario,
                    host=self.canary_ip,
                    seed=deterministic_seed(seed, "recovery"),
                    phase_name=f"recovery_{transport}",
                    operations=int(overload["recovery_operations"]),
                )
                recovery_liveness_before = self.run_liveness_observation(
                    liveness_profiles[transport],
                    scenario,
                    liveness_servers[transport][0],
                    seed=deterministic_seed(seed, "recovery-liveness-before"),
                    label=f"recovery_liveness_before_{transport}",
                )
                recovery_probe = self.run_identity_probe(
                    probe_transport,
                    self.canary_ip,
                    canary_profile["port"],
                    int(overload["probe_timeout_ms"]),
                )
                recovery_liveness_after = self.run_liveness_observation(
                    liveness_profiles[transport],
                    scenario,
                    liveness_servers[transport][0],
                    seed=deterministic_seed(seed, "recovery-liveness-after"),
                    label=f"recovery_liveness_after_{transport}",
                )
            canary_alive_after_recovery = canary_process.poll() is None
            status_document = self.poll_daemon_status()
            quarantine_black_box = (
                self.quarantine_black_box_observation(
                    liveness_profiles,
                    liveness_servers,
                    liveness_preflight_probes,
                    int(overload["probe_timeout_ms"]),
                    scenario,
                    seed,
                )
                if isinstance(status_document, dict)
                and status_document.get("mode") == "block_all"
                else None
            )
            kernel_block_all = (
                quarantine_black_box.get("kernel_after")
                if isinstance(quarantine_black_box, dict)
                else (
                    self.kernel_block_all_observation()
                    if status_document is None
                    else None
                )
            )
            active_metric = dut_metric
            dut_metric = None
            post_resume_dut_metrics = finish_metric(
                active_metric, self.client_id, dut_metric_identity
            )
            # Keep observing the dedicated pressure peer through the complete
            # drain and recovery interval. A packet can reach its socket after
            # NFQUEUE depth first becomes zero; stopping at that instant would
            # leave a receive/listen-overflow race outside the validity proof.
            active_metric = peer_metric
            peer_metric = None
            peer_metrics = finish_metric(
                active_metric, self.peer_id, peer_metric_identity
            )
            active_metric = canary_metric
            canary_metric = None
            canary_metrics = finish_metric(
                active_metric, self.canary_id, canary_metric_identity
            )
            self.daemon_log_seen = log_before
            daemon_log = self.daemon_log_delta()

            temporal_ordering = overload_evidence_timestamps_ordered(
                (dut_metric_start, peer_metric_start, canary_metric_start),
                queue_before_stop,
                stopped_at_ns,
                saturation_snapshot,
                observations,
                pressure_reaped_at_ns,
                queue_before_continue,
                continued_at_ns,
                metric_boundary["boundary_monotonic_ns"],
            )
            saturation_proven = (
                saturation_snapshot is not None
                and saturation_delta["total"] is not None
                and saturation_delta["total"]
                >= int(overload["minimum_nfqueue_drops"])
                and stall_drop_delta["total"] is not None
                and stall_drop_delta["total"]
                >= int(overload["minimum_nfqueue_drops"])
                and stopped_identity["state"] in {"T", "t"}
                and temporal_ordering
            )
            dut_udp_sndbuf_errors = numeric(
                nested(dut_metrics, "udp_errors", "sndbuf_errors")
            )
            controlled_udp_send_backpressure = (
                controlled_udp_send_backpressure_evidence(
                    transport,
                    saturation_proven,
                    stall_drop_delta,
                    int(overload["minimum_nfqueue_drops"]),
                    pressure_summary,
                    dut_udp_sndbuf_errors,
                )
            )
            during_fail_open = any(
                item.get("fail_open") is True for item in observations
            )
            during_blocked = (
                len(observations) == int(overload["probe_attempts"])
                and all(
                    item.get("blocked") is True
                    and item.get("isolated_canary_server_alive") is True
                    and nested(item, "liveness_before", "passed") is True
                    and nested(item, "liveness_after", "passed") is True
                    for item in observations
                )
            )
            stall_liveness_passed = (
                len(observations) == int(overload["probe_attempts"])
                and all(
                    nested(item, "liveness_before", "passed") is True
                    and nested(item, "liveness_after", "passed") is True
                    for item in observations
                )
            )
            recovery_liveness_passed = (
                isinstance(recovery_liveness_before, dict)
                and recovery_liveness_before.get("passed") is True
                and isinstance(recovery_liveness_after, dict)
                and recovery_liveness_after.get("passed") is True
            )
            after_blocked = recovery_probe.get("blocked") is True
            verified_block_all = (
                isinstance(quarantine_black_box, dict)
                and quarantine_black_box.get("structural_passed") is True
            )
            quarantine_reported = (
                isinstance(status_document, dict)
                and status_document.get("mode") == "block_all"
            )
            quarantine = (
                quarantine_reported
                and verified_block_all
                and isinstance(quarantine_black_box, dict)
                and quarantine_black_box.get("valid") is True
                and quarantine_black_box.get("passed") is True
            )
            requested_mode = (
                isinstance(status_document, dict)
                and status_document.get("mode") == "enforcing"
            )
            recovery_pass = overload_recovery_passed(
                requested_mode,
                recovery_queue_drain,
                recovery_exit_code,
                recovery_summary,
                transport,
                int(overload["recovery_operations"]),
            )

            pressure_resource = pressure_server
            pressure_server = None
            pressure_server_summary = self.stop_server(*pressure_resource)
            canary_resource = canary_server
            canary_server = None
            canary_server_summary = self.stop_server(*canary_resource)
            liveness_server_summaries: dict[str, dict[str, Any]] = {}
            for liveness_transport in ("tcp", "udp"):
                liveness_resource = liveness_servers.pop(liveness_transport)
                liveness_server_summaries[liveness_transport] = self.stop_server(
                    *liveness_resource
                )

            safety_failures: list[str] = []
            validity_failures: list[str] = []
            recovery_failures: list[str] = []
            resource_failure_reasons: list[str] = []
            if not preflight_allowed or not preflight_canary_alive:
                validity_failures.append(
                    "allowed-executable canary preflight did not complete"
                )
            if (
                not all(
                    evidence.get("passed") is True
                    for evidence in liveness_preflight.values()
                )
                or not all(
                    evidence.get("fail_open") is True
                    for evidence in liveness_preflight_probes.values()
                )
                or preflight_liveness_before.get("passed") is not True
                or preflight_liveness_after.get("passed") is not True
            ):
                validity_failures.append(
                    "preflight did not prove live TCP/UDP network-only canary endpoints"
                )
            if preflight_wrong.get("fail_open") is True:
                safety_failures.append(
                    "wrong-executable canary completed before overload"
                )
            elif preflight_wrong.get("blocked") is not True:
                validity_failures.append(
                    "wrong-executable preflight was not conclusively blocked"
                )
            if not saturation_proven:
                validity_failures.append(
                    "NFQUEUE saturation was not proven before fail-closed probes"
                )
            criteria = self.config["criteria"]
            resource_failure_reasons.extend(
                overload_metric_validity_reasons(
                    dut_metrics,
                    label="overload DUT",
                    transport=transport,
                    allow_controlled_udp_send_backpressure=(
                        controlled_udp_send_backpressure["exception_applied"]
                    ),
                    expected_stop_reason="split_boundary",
                )
            )
            resource_failure_reasons.extend(
                overload_metric_validity_reasons(
                    post_resume_dut_metrics,
                    label="overload DUT after NFQUEUE consumer resume",
                    transport=transport,
                    require_clean_dut_recovery=True,
                    expected_daemon_pid=self.daemon_pid,
                )
            )
            resource_failure_reasons.extend(
                overload_metric_validity_reasons(
                    peer_metrics,
                    label="overload peer",
                    transport=transport,
                    maximum_process_cpu_ratio=float(
                        criteria["maximum_peer_wall_cpu_ratio"]
                    ),
                    process_sections=("daemon",),
                )
            )
            resource_failure_reasons.extend(
                overload_metric_validity_reasons(
                    canary_metrics,
                    label="overload canary",
                    transport=transport,
                    maximum_process_cpu_ratio=float(
                        criteria["maximum_peer_wall_cpu_ratio"]
                    ),
                    process_sections=("daemon", "workload_process"),
                )
            )
            if pressure_exit_code is None or not isinstance(pressure_summary, dict):
                validity_failures.append("overload pressure workload has no summary")
            else:
                resource_failure_reasons.extend(
                    overload_process_validity_reasons(
                        pressure_summary,
                        label="overload pressure",
                        maximum_cpu_ratio=float(
                            criteria["maximum_generator_wall_cpu_ratio"]
                        ),
                        maximum_scheduler_lag_ms=float(
                            criteria["maximum_scheduler_lag_p99_ms"]
                        ),
                    )
                )
            if not stall_liveness_passed:
                validity_failures.append(
                    "same-transport network-only liveness failed around a saturated probe"
                )
            if during_fail_open:
                safety_failures.append(
                    "a wrong-executable probe completed in the saturated stopped window"
                )
            elif stall_liveness_passed and not during_blocked:
                safety_failures.append(
                    "a wrong-executable probe was not conclusively blocked in the saturated stopped window"
                )
            if status_document is None:
                safety_failures.append(
                    "daemon status was unavailable after controlled overload"
                )
            elif not requested_mode and not quarantine:
                safety_failures.append(
                    "daemon neither recovered Enforcing nor established a reported, kernel-verified BlockAll quarantine"
                )
            if requested_mode:
                if recovery_queue_drain.get("drained") is not True:
                    recovery_failures.append(
                        "NFQUEUE did not drain within the bounded post-resume interval"
                    )
                if not recovery_liveness_passed:
                    validity_failures.append(
                        "same-transport network-only liveness failed around the recovery probe"
                    )
                if recovery_probe.get("fail_open") is True:
                    safety_failures.append(
                        "wrong-executable canary completed after recovery"
                    )
                elif recovery_liveness_passed and not after_blocked:
                    safety_failures.append(
                        "wrong-executable canary was not conclusively blocked after recovery"
                    )
                if not recovery_pass:
                    recovery_failures.append(
                        "allowed application traffic did not recover after the consumer resumed"
                    )
            elif quarantine_reported and not quarantine:
                safety_failures.append(
                    "reported BlockAll quarantine lacked complete structural and black-box proof"
                )
            if not canary_alive_after_recovery:
                validity_failures.append("isolated canary server exited during overload")
            resource_failure_reasons.extend(
                self.server_summary_validity_reasons(
                    pressure_server_summary,
                    label="pressure",
                    maximum_cpu_ratio=float(
                        criteria["maximum_peer_wall_cpu_ratio"]
                    ),
                    allow_protocol_errors=True,
                )
            )
            resource_failure_reasons.extend(
                self.server_summary_validity_reasons(
                    canary_server_summary,
                    label="application canary",
                    maximum_cpu_ratio=float(
                        criteria["maximum_peer_wall_cpu_ratio"]
                    ),
                )
            )
            for liveness_transport, summary in liveness_server_summaries.items():
                resource_failure_reasons.extend(
                    self.server_summary_validity_reasons(
                        summary,
                        label=f"{liveness_transport} liveness",
                        maximum_cpu_ratio=float(
                            criteria["maximum_peer_wall_cpu_ratio"]
                        ),
                    )
                )
            validity_failures.extend(resource_failure_reasons)

            measured_kernel_drops = numeric(
                nested(dut_metrics, "nfqueue", "kernel_dropped")
            )
            measured_user_drops = numeric(
                nested(dut_metrics, "nfqueue", "user_dropped")
            )
            measured_total_drops = (
                None
                if measured_kernel_drops is None or measured_user_drops is None
                else measured_kernel_drops + measured_user_drops
            )
            result = {
                "schema": OVERLOAD_SCHEMA,
                "backend": self.backend,
                "policy": policy,
                "mode": "enforcing",
                "profile": profile["name"],
                "canary_profile": canary_profile["name"],
                "canary_port": canary_profile["port"],
                "liveness_profiles": {
                    name: {
                        "name": item["name"],
                        "port": item["port"],
                        "transport": item["transport"],
                    }
                    for name, item in liveness_profiles.items()
                },
                "canary_address": self.canary_ip,
                "canary_interface": self.canary_client_interface,
                "transport": transport,
                "probe_transport": probe_transport,
                "seed": seed,
                "config": dict(overload),
                "daemon_identity": {
                    "pid": stopped_identity["pid"],
                    "starttime": stopped_identity["starttime"],
                    "exe": stopped_identity["exe"],
                },
                "pressure_exit_code": pressure_exit_code,
                "pressure_start_gate": pressure_readiness,
                "pressure_started": pressure_started,
                "pressure_finished": pressure_finished,
                "pressure_released": pressure_released,
                "pressure_workload": pressure_summary,
                "metric_starts": {
                    **metric_starts,
                },
                "metric_collectors": {
                    "dut": dut_metric_identity,
                    "peer": peer_metric_identity,
                    "canary": canary_metric_identity,
                },
                "dut_metrics": dut_metrics,
                "dut_metric_boundary": metric_boundary,
                "post_resume_dut_metrics": post_resume_dut_metrics,
                "peer_metrics": peer_metrics,
                "canary_metrics": canary_metrics,
                "allowed_preflight": {
                    "exit_code": preflight_exit_code,
                    "workload": preflight_summary,
                    "passed": preflight_allowed,
                },
                "network_liveness_preflight": {
                    "workloads": liveness_preflight,
                    "identity_probes": liveness_preflight_probes,
                    "application_probe_before": preflight_liveness_before,
                    "application_probe_after": preflight_liveness_after,
                    "passed": all(
                        evidence.get("passed") is True
                        for evidence in liveness_preflight.values()
                    )
                    and all(
                        evidence.get("fail_open") is True
                        for evidence in liveness_preflight_probes.values()
                    )
                    and preflight_liveness_before.get("passed") is True
                    and preflight_liveness_after.get("passed") is True,
                },
                "identity_probe_preflight": preflight_wrong,
                "identity_probe_during_stall": {
                    "attempts": observations,
                    "blocked_all": during_blocked,
                    "fail_open": during_fail_open,
                    "liveness_passed": stall_liveness_passed,
                },
                "identity_probe_after_resume": recovery_probe,
                "network_liveness_after_resume": {
                    "before": recovery_liveness_before,
                    "after": recovery_liveness_after,
                    "passed": recovery_liveness_passed
                    if requested_mode
                    else None,
                },
                "recovery_exit_code": recovery_exit_code,
                "recovery_workload": recovery_summary,
                "recovery_nfqueue_drain": recovery_queue_drain,
                "pressure_server_summary": pressure_server_summary,
                "canary_server_summary": canary_server_summary,
                "liveness_server_summaries": liveness_server_summaries,
                "status_before_recovery": status_before_recovery,
                "status_after": status_document,
                "kernel_block_all_after": kernel_block_all,
                "daemon_log_events": daemon_log,
                "saturation": {
                    "minimum_nfqueue_drops": int(
                        overload["minimum_nfqueue_drops"]
                    ),
                    "snapshot_before_stop": queue_before_stop,
                    "snapshot_at_barrier": saturation_snapshot,
                    "snapshot_before_continue": queue_before_continue,
                    "stopped_at_monotonic_ns": stopped_at_ns,
                    "pressure_reaped_at_monotonic_ns": pressure_reaped_at_ns,
                    "metric_boundary_monotonic_ns": metric_boundary[
                        "boundary_monotonic_ns"
                    ],
                    "continued_at_monotonic_ns": continued_at_ns,
                    "threshold_drop_delta": saturation_delta,
                    "stall_drop_delta": stall_drop_delta,
                    "timestamps_ordered": temporal_ordering,
                    "observed_kernel_drops": measured_kernel_drops,
                    "observed_user_drops": measured_user_drops,
                    "observed_total_drops": measured_total_drops,
                    "nfqueue_depth_peak": nested(
                        dut_metrics, "nfqueue", "depth_peak"
                    ),
                    "proven": saturation_proven,
                },
                "quarantine": {
                    "reported": quarantine_reported,
                    "occurred": quarantine,
                    "kernel_block_all": verified_block_all
                    if quarantine_reported
                    else None,
                    "black_box": quarantine_black_box,
                },
                "resource_validity": {
                    "valid": not resource_failure_reasons,
                    "failure_reasons": sorted(set(resource_failure_reasons)),
                    "controlled_udp_send_backpressure": (
                        controlled_udp_send_backpressure
                    ),
                },
                "validity_failure_reasons": sorted(set(validity_failures)),
                "safety_failure_reasons": sorted(set(safety_failures)),
                "recovery_failure_reasons": sorted(set(recovery_failures)),
                "valid": not validity_failures,
                "safety_pass": not safety_failures,
                "recovery_pass": recovery_pass if requested_mode else None,
                "passed": not validity_failures
                and not safety_failures
                and not recovery_failures,
            }
            write_json(self.raw / f"overload-{transport}.json", result)
            return result
        except BaseException as error:
            primary_error = error
            raise
        finally:
            cleanup_errors: list[str] = []
            if daemon_may_be_stopped:
                try:
                    self.signal_daemon(int(signal.SIGCONT))
                except BaseException as cleanup_error:
                    cleanup_errors.append(f"resume daemon: {cleanup_error}")
            for label, process, is_metric, container, identity in (
                (
                    "DUT metric collector",
                    dut_metric,
                    True,
                    self.client_id,
                    dut_metric_identity,
                ),
                (
                    "peer metric collector",
                    peer_metric,
                    True,
                    self.peer_id,
                    peer_metric_identity,
                ),
                (
                    "canary metric collector",
                    canary_metric,
                    True,
                    self.canary_id,
                    canary_metric_identity,
                ),
                (
                    "pressure workload",
                    pressure_process,
                    False,
                    self.client_id,
                    pressure_identity,
                ),
            ):
                if process is None:
                    continue
                try:
                    if (
                        is_metric
                        and process.poll() is None
                        and process.stdin is not None
                    ):
                        self.stop_metric(process)
                    try:
                        process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        if identity is None or container is None:
                            process.kill()
                            process.communicate(timeout=5)
                            raise HarnessError(
                                f"cannot safely pin timed-out {label}"
                            )
                        self.cancel_pinned_attached_process(
                            process, container, identity, label=label
                        )
                except BaseException as cleanup_error:
                    cleanup_errors.append(f"reap {label}: {cleanup_error}")
            for label, resource in (
                ("pressure server", pressure_server),
                ("canary server", canary_server),
                ("TCP liveness server", liveness_servers.get("tcp")),
                ("UDP liveness server", liveness_servers.get("udp")),
            ):
                if resource is None:
                    continue
                try:
                    self.stop_server(*resource)
                except BaseException as cleanup_error:
                    cleanup_errors.append(f"stop {label}: {cleanup_error}")
            if cleanup_errors:
                cleanup_failure = HarnessError("; ".join(cleanup_errors))
                if primary_error is not None:
                    raise cleanup_failure from primary_error
                raise cleanup_failure


def parse_json_line_document(output: str, schema: str) -> dict[str, Any]:
    if len(output.encode("utf-8", errors="replace")) > MAX_SUBPROCESS_OUTPUT:
        raise HarnessError("JSON subprocess output exceeded its bound")
    documents = []
    for line in output.splitlines():
        try:
            document = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(document, dict) and document.get("schema") == schema:
            documents.append(document)
    if len(documents) != 1:
        raise HarnessError(f"expected one {schema} document, found {len(documents)}: {safe_tail(output)}")
    return documents[0]


def deterministic_seed(seed: int, *components: str) -> int:
    digest = hashlib.sha256(str(seed).encode("ascii"))
    for component in components:
        digest.update(b"\0")
        digest.update(str(component).encode("utf-8"))
    return int.from_bytes(digest.digest()[:8], "big") & ((1 << 63) - 1)


def expected_ops_per_second(offered: dict[str, Any], transport: str) -> float | None:
    caps: list[float] = []
    pps = numeric(offered.get("pps"))
    if pps and pps > 0:
        caps.append(pps)
    mix = parse_mix(offered["response_mix"], 8 * 1024 * 1024 if transport == "tcp" else 60_000)
    total_weight = sum(weight for _, weight in mix)
    average_response = sum(size * weight for size, weight in mix) / total_weight
    request_bytes = float(offered["request_bytes"])
    approximate_bytes = request_bytes + average_response + (512 if transport == "tcp" else 128)
    mbps = numeric(offered.get("mbps"))
    if mbps and mbps > 0 and approximate_bytes > 0:
        caps.append(mbps * 1_000_000 / 8 / approximate_bytes)
    if transport == "tcp":
        cps = numeric(offered.get("cps"))
        mode = offered.get("mode")
        if cps and cps > 0 and mode == "short":
            caps.append(cps)
        elif cps and cps > 0 and mode == "mixed":
            short_fraction = max(0.001, 1.0 - float(offered.get("keepalive_ratio", 0)))
            caps.append(cps / short_fraction)
    return min(caps) if caps else None


def evaluate_result(result: dict[str, Any], criteria: dict[str, Any]) -> None:
    metrics = nested(result, "workload", "metrics", default={})
    if not isinstance(metrics, dict):
        raise HarnessError("workload summary has no metrics object")
    transport = result["transport"]
    operations = numeric(
        metrics.get("operations" if transport == "tcp" else "packets_sent")
    )
    errors = numeric(metrics.get("errors"))
    error_ratio = (
        None
        if operations is None
        or operations < 0
        or errors is None
        or errors < 0
        else errors / max(operations + errors, 1)
    )
    result["derived"] = {
        "actual_application_ops_per_second": numeric(metrics.get("application_ops_per_second")),
        "actual_application_mbps": numeric(metrics.get("application_mbps")),
        "actual_cps": numeric(metrics.get("actual_cps")),
        "active_flows_peak": numeric(metrics.get("active_flows_peak")),
        "active_flows_mean": numeric(
            metrics.get("active_flows_time_weighted_mean")
        ),
        "error_ratio": error_ratio,
        "udp_reply_loss_ratio": numeric(metrics.get("reply_loss_ratio")),
        "latency_p50_ms": numeric(nested(metrics, "latency_ms", "p50")),
        "latency_p95_ms": numeric(nested(metrics, "latency_ms", "p95")),
        "latency_p99_ms": numeric(nested(metrics, "latency_ms", "p99")),
        "connect_latency_p50_ms": numeric(
            nested(metrics, "connect_latency_ms", "p50")
        ),
        "connect_latency_p95_ms": numeric(
            nested(metrics, "connect_latency_ms", "p95")
        ),
        "connect_latency_p99_ms": numeric(
            nested(metrics, "connect_latency_ms", "p99")
        ),
        "scheduler_lag_p99_ms": numeric(nested(metrics, "scheduler_lag_ms", "p99")),
    }
    dut_rx_pps = numeric(nested(result, "dut_metrics", "network", "rx_pps"))
    dut_tx_pps = numeric(nested(result, "dut_metrics", "network", "tx_pps"))
    result["derived"]["aggregate_dut_pps"] = (
        None
        if dut_rx_pps is None or dut_tx_pps is None
        else dut_rx_pps + dut_tx_pps
    )
    result["derived"]["cgroup_cpu_percent_one_core"] = numeric(
        nested(result, "dut_metrics", "cgroup", "cpu_percent_one_core")
    )
    expected = numeric(
        nested(
            result,
            "workload",
            "config",
            "target_application_ops_per_second",
        )
    )
    if expected is None:
        # Compatibility fallback for older workload summaries. Current
        # generators publish the exact cost-model target they paced against.
        expected = expected_ops_per_second(result["offered"], transport)
    actual = result["derived"]["actual_application_ops_per_second"]
    attainment = None if expected is None or actual is None else actual / expected
    result["derived"]["expected_application_ops_per_second"] = expected
    result["derived"]["target_attainment_ratio"] = attainment
    retransmit_ratios: dict[str, float | None] = {}
    for side, label in (("dut_metrics", "dut"), ("peer_metrics", "peer")):
        tx_packets = numeric(nested(result, side, "network", "tx_packets"))
        retransmits = numeric(nested(result, side, "tcp_retransmits"))
        ratio = (
            None
            if tx_packets is None or tx_packets <= 0 or retransmits is None
            else retransmits / tx_packets
        )
        retransmit_ratios[label] = ratio
        result["derived"][f"{label}_tcp_retransmits_per_tx_packet"] = ratio
    available_retransmit_ratios = [
        ratio for ratio in retransmit_ratios.values() if ratio is not None
    ]
    # Preserve the aggregate field consumed by existing CSV/report readers. It
    # is the worst endpoint ratio, not a DUT-only value.
    result["derived"]["tcp_retransmits_per_tx_packet"] = (
        max(available_retransmit_ratios) if available_retransmit_ratios else None
    )
    conntrack_start = numeric(nested(result, "dut_metrics", "conntrack_count_start"))
    conntrack_peak = numeric(nested(result, "dut_metrics", "conntrack_count_peak"))
    result["derived"]["conntrack_active_peak"] = (
        None
        if conntrack_start is None or conntrack_peak is None
        else max(0.0, conntrack_peak - conntrack_start)
    )
    queue_hits = numeric(nested(result, "dut_metrics", "nfqueue", "hits"))
    identity_probe = result.get("identity_probe")
    probe_attempts = (
        0.0
        if identity_probe is None
        else numeric(nested(identity_probe, "attempts_completed"))
    )
    workload_queue_hits = (
        None
        if queue_hits is None or probe_attempts is None
        else max(0.0, queue_hits - probe_attempts)
    )
    connections = numeric(metrics.get("connection_attempts"))
    if connections is None:
        connections = numeric(metrics.get("connections"))
    packets = numeric(metrics.get("packets_sent"))
    barriers_sent = numeric(metrics.get("barriers_sent")) if transport == "udp" else 0.0
    wire_datagrams = (
        None
        if packets is None or barriers_sent is None
        else packets + barriers_sent
    )
    result["derived"]["nfqueue_hits_raw"] = queue_hits
    result["derived"]["nfqueue_probe_hits_estimate"] = probe_attempts
    result["derived"]["nfqueue_workload_hits"] = workload_queue_hits
    result["derived"]["nfqueue_hits_per_connection"] = (
        None
        if not connections or workload_queue_hits is None
        else workload_queue_hits / connections
    )
    result["derived"]["nfqueue_hits_per_datagram"] = (
        None
        if not wire_datagrams or workload_queue_hits is None
        else workload_queue_hits / wire_datagrams
    )
    result["derived"]["nfqueue_hits_per_operation"] = (
        None
        if not operations or workload_queue_hits is None
        else workload_queue_hits / operations
    )

    unreliable: list[str] = []
    failures: list[str] = []
    safety_failures: list[str] = []
    expected_nfqueue_number = nfqueue_number_for_mode(result.get("mode"))
    observed_nfqueue_number = nested(
        result, "dut_metrics", "nfqueue", "queue_number"
    )
    if (
        isinstance(observed_nfqueue_number, bool)
        or observed_nfqueue_number != expected_nfqueue_number
    ):
        reason = (
            "DUT NFQUEUE metrics did not use the queue selected for the "
            f"scenario mode (expected {expected_nfqueue_number})"
        )
        unreliable.append(reason)
        if result["policy"] != "baseline":
            safety_failures.append(reason)
    if result["policy"] == "baseline":
        result["nfqueue_runtime_counters"] = None
    else:
        counter_evidence = nfqueue_runtime_counter_evidence(
            result.get("status_before"),
            result.get("status_after"),
            result.get("daemon_identity_before"),
            result.get("daemon_identity_after"),
        )
        result["nfqueue_runtime_counters"] = counter_evidence
        if counter_evidence["valid"] is not True:
            for detail in counter_evidence["invalid_reasons"]:
                reason = f"authoritative NFQUEUE counters are invalid: {detail}"
                unreliable.append(reason)
                safety_failures.append(reason)
        else:
            # These counters live for the daemon process.  A non-zero delta is
            # a failure for this window.  Absolute values cannot be used here:
            # one earlier event would otherwise poison every later window.
            # apply_nfqueue_counter_continuity() separately checks the first
            # snapshot and every unmeasured gap between adjacent phases.
            for name in NFQUEUE_RUNTIME_COUNTER_FIELDS:
                delta = nested(counter_evidence, "delta", name)
                if delta != 0:
                    reason = (
                        f"authoritative NFQUEUE {name} counter increased "
                        "during a normal phase"
                    )
                    failures.append(reason)
                    safety_failures.append(reason)
    required_workload_metrics = {
        "completed operations": operations,
        "errors": errors,
        "application operations per second": result["derived"][
            "actual_application_ops_per_second"
        ],
        "application throughput": result["derived"]["actual_application_mbps"],
        "active flow peak": result["derived"]["active_flows_peak"],
        "latency p50": result["derived"]["latency_p50_ms"],
        "latency p95": result["derived"]["latency_p95_ms"],
        "latency p99": result["derived"]["latency_p99_ms"],
    }
    if transport == "tcp":
        required_workload_metrics["actual CPS"] = result["derived"]["actual_cps"]
        for percentile in ("p50", "p95", "p99"):
            required_workload_metrics[
                f"TCP connect latency {percentile}"
            ] = result["derived"][f"connect_latency_{percentile}_ms"]
    for description, value in required_workload_metrics.items():
        if value is None or value < 0:
            unreliable.append(
                f"required workload metric is unavailable or invalid: {description}"
            )
    if expected is None or expected <= 0 or attainment is None:
        unreliable.append("workload target or target-attainment metric is unavailable")
    if identity_probe is not None and (
        probe_attempts is None or probe_attempts < 0
    ):
        unreliable.append("identity-probe attempt count is unavailable or invalid")
    generator_cpu = numeric(metrics.get("wall_cpu_ratio"))
    if generator_cpu is None or generator_cpu > criteria["maximum_generator_wall_cpu_ratio"]:
        unreliable.append("generator CPU saturation or missing generator CPU metric")
    scheduler_lag = result["derived"]["scheduler_lag_p99_ms"]
    if scheduler_lag is None or scheduler_lag > criteria["maximum_scheduler_lag_p99_ms"]:
        unreliable.append("generator scheduler lag exceeded the reliability bound")
    server_metric_side = (
        "dut_metrics" if result.get("direction") == "inbound" else "peer_metrics"
    )
    server_phase_cpu = numeric(
        nested(
            result,
            server_metric_side,
            "workload_process",
            "cpu_percent_one_core",
        )
    )
    if (
        server_phase_cpu is None
        or server_phase_cpu < 0
        or server_phase_cpu / 100.0
        > criteria["maximum_peer_wall_cpu_ratio"]
    ):
        unreliable.append("per-phase workload server CPU saturation or missing metric")

    metric_sides = (("dut_metrics", "DUT"), ("peer_metrics", "peer"))
    for side, description in metric_sides:
        metric_document = result.get(side)
        cgroup = nested(result, side, "cgroup", default={})
        elapsed_seconds = (
            numeric(metric_document.get("elapsed_seconds"))
            if isinstance(metric_document, dict)
            else None
        )
        raw_cgroup_cpu = (
            numeric(cgroup.get("raw_cpu_seconds"))
            if isinstance(cgroup, dict)
            else None
        )
        excluded_collector_cpu = (
            numeric(cgroup.get("collector_cpu_seconds_excluded"))
            if isinstance(cgroup, dict)
            else None
        )
        authoritative_cgroup_cpu = (
            numeric(cgroup.get("cpu_seconds"))
            if isinstance(cgroup, dict)
            else None
        )
        authoritative_cgroup_percent = (
            numeric(cgroup.get("cpu_percent_one_core"))
            if isinstance(cgroup, dict)
            else None
        )
        if (
            not isinstance(metric_document, dict)
            or metric_document.get("schema") != METRICS_SCHEMA
            or elapsed_seconds is None
            or elapsed_seconds <= 0
            or not isinstance(cgroup, dict)
            or cgroup.get("accounting")
            != "container_cgroup_minus_metric_collector"
            or raw_cgroup_cpu is None
            or excluded_collector_cpu is None
            or authoritative_cgroup_cpu is None
            or authoritative_cgroup_percent is None
            or min(
                raw_cgroup_cpu,
                excluded_collector_cpu,
                authoritative_cgroup_cpu,
                authoritative_cgroup_percent,
            )
            < 0
            or excluded_collector_cpu > raw_cgroup_cpu + 1e-6
            or not math.isclose(
                authoritative_cgroup_cpu,
                max(0.0, raw_cgroup_cpu - excluded_collector_cpu),
                rel_tol=1e-9,
                abs_tol=1e-9,
            )
            or not math.isclose(
                authoritative_cgroup_percent,
                authoritative_cgroup_cpu * 100.0 / elapsed_seconds,
                rel_tol=1e-9,
                abs_tol=1e-9,
            )
        ):
            unreliable.append(
                f"{description} authoritative collector-excluded cgroup CPU evidence is invalid"
            )
        for name in ("rx_pps", "tx_pps", "rx_mbps", "tx_mbps"):
            value = numeric(nested(result, side, "network", name))
            if value is None or value < 0:
                reason = f"{description} network {name} metric is unavailable"
                unreliable.append(reason)
                safety_failures.append(reason)
        for name in ("net_rx", "net_tx"):
            value = numeric(nested(result, side, "softirq", name))
            if value is None or value < 0:
                reason = f"{description} softirq {name} delta is unavailable"
                unreliable.append(reason)
                safety_failures.append(reason)
        conntrack_values = {
            name: numeric(nested(result, side, name))
            for name in ("conntrack_count_start", "conntrack_count_peak")
        }
        if any(value is None or value < 0 for value in conntrack_values.values()):
            reason = f"{description} conntrack start/peak metrics are unavailable"
            unreliable.append(reason)
            safety_failures.append(reason)
        elif conntrack_values["conntrack_count_peak"] < conntrack_values["conntrack_count_start"]:
            reason = f"{description} conntrack peak is lower than its starting count"
            unreliable.append(reason)
            safety_failures.append(reason)
    if transport == "tcp":
        for side, description in metric_sides:
            ratio = result["derived"][
                f"{'dut' if side == 'dut_metrics' else 'peer'}_tcp_retransmits_per_tx_packet"
            ]
            if ratio is None:
                unreliable.append(
                    f"{description} TCP retransmit or transmitted-packet metric is unavailable"
                )
            elif ratio > criteria["maximum_tcp_retransmits_per_tx_packet"]:
                reason = f"{description} TCP retransmit ratio exceeded the bound"
                failures.append(reason)
                safety_failures.append(reason)

            listen = nested(result, side, "tcp_listen", default={})
            listen_drops = (
                numeric(listen.get("listen_drops"))
                if isinstance(listen, dict)
                else None
            )
            listen_overflows = (
                numeric(listen.get("listen_overflows"))
                if isinstance(listen, dict)
                else None
            )
            if (
                listen_drops is None
                or listen_drops < 0
                or listen_overflows is None
                or listen_overflows < 0
            ):
                unreliable.append(
                    f"{description} TCP listen-queue counters are unavailable"
                )
            elif listen_drops > 0 or listen_overflows > 0:
                unreliable.append(f"{description} TCP listen-queue saturation")
                reason = f"{description} TCP listen drops or overflows were observed"
                failures.append(reason)
                safety_failures.append(reason)
    else:
        for side, description in metric_sides:
            udp_errors = nested(result, side, "udp_errors", default={})
            values = {
                name: numeric(udp_errors.get(name))
                if isinstance(udp_errors, dict)
                else None
                for name in ("in_errors", "rcvbuf_errors", "sndbuf_errors")
            }
            if any(value is None or value < 0 for value in values.values()):
                unreliable.append(
                    f"{description} UDP input/socket-buffer counters are unavailable"
                )
                continue
            if values["in_errors"] > 0:
                reason = f"{description} UDP input errors were observed"
                failures.append(reason)
                safety_failures.append(reason)
            if values["rcvbuf_errors"] > 0 or values["sndbuf_errors"] > 0:
                unreliable.append(f"{description} UDP socket-buffer saturation")
                reason = (
                    f"{description} UDP receive/send buffer errors were observed"
                )
                failures.append(reason)
                safety_failures.append(reason)

    if attainment is not None and attainment < criteria["minimum_target_ratio"]:
        failures.append("offered workload target was not sustained")
        if result["policy"] == "baseline" and result["phase_role"] in {
            "steady",
            "burst",
        }:
            unreliable.append("baseline generator did not attain its configured target")
    if error_ratio is not None and error_ratio > criteria["maximum_error_ratio"]:
        reason = "workload error ratio exceeded the bound"
        failures.append(reason)
        safety_failures.append(reason)
    udp_loss = result["derived"]["udp_reply_loss_ratio"]
    if transport == "udp" and int(result["offered"].get("reply_every", 0)) > 0:
        if udp_loss is None or udp_loss < 0:
            unreliable.append("UDP sampled-reply loss metric is unavailable")
        elif udp_loss > criteria["maximum_udp_reply_loss_ratio"]:
            reason = "UDP sampled-reply loss exceeded the bound"
            failures.append(reason)
            safety_failures.append(reason)
    latency_p99 = result["derived"]["latency_p99_ms"]
    if latency_p99 is None or latency_p99 > criteria["maximum_latency_p99_ms"]:
        failures.append("p99 latency is missing or exceeded the bound")

    verified_quarantine = False
    if result["policy"] != "baseline":
        expected_mode = result["mode"]
        status_after = result.get("status_after")
        kernel_observation = result.get("kernel_block_all_after")
        if not isinstance(status_after, dict):
            kernel_closed = (
                isinstance(kernel_observation, dict)
                and kernel_observation.get("inspected") is True
                and kernel_observation.get("block_all") is True
            )
            result["quarantine"] = {
                "occurred": False,
                "mode": None,
                "kernel_block_all": None,
                "observation": kernel_observation,
            }
            failures.append("daemon status became unavailable")
            safety_failures.append(
                "daemon status was unavailable; kernel state alone cannot establish a reported quarantine"
                if kernel_closed
                else "daemon status was unavailable and kernel BlockAll was not verified"
            )
        else:
            current_mode = status_after.get("mode")
            quarantined = current_mode == "block_all"
            kernel_closed = (
                isinstance(kernel_observation, dict)
                and kernel_observation.get("inspected") is True
                and kernel_observation.get("block_all") is True
            )
            result["quarantine"] = {
                "occurred": quarantined,
                "mode": current_mode,
                "kernel_block_all": kernel_closed if quarantined else None,
                "observation": kernel_observation,
            }
            verified_quarantine = quarantined and kernel_closed
            if current_mode != expected_mode:
                failures.append("daemon left the requested mode")
            if quarantined and not kernel_closed:
                safety_failures.append(
                    "daemon reported quarantine but kernel BlockAll was not verified"
                )
        daemon_cpu = numeric(nested(result, "dut_metrics", "daemon", "cpu_percent_one_core"))
        daemon_rss = numeric(nested(result, "dut_metrics", "daemon", "rss_bytes_peak"))
        if daemon_cpu is None or daemon_cpu > criteria["maximum_daemon_cpu_percent_one_core"]:
            failures.append("daemon CPU exceeded the configured sustainable bound")
        if daemon_rss is None or daemon_rss > criteria["maximum_daemon_rss_bytes"]:
            failures.append("daemon RSS is missing or exceeded the bound")

        queue_kernel_drop = numeric(nested(result, "dut_metrics", "nfqueue", "kernel_dropped"))
        queue_user_drop = numeric(nested(result, "dut_metrics", "nfqueue", "user_dropped"))
        if (
            queue_kernel_drop is None
            or queue_kernel_drop < 0
            or queue_user_drop is None
            or queue_user_drop < 0
        ):
            reason = "NFQUEUE drop counters are unavailable"
            unreliable.append(reason)
            safety_failures.append(reason)
        elif criteria["require_zero_nfqueue_drops"] and (
            queue_kernel_drop > 0 or queue_user_drop > 0
        ):
            reason = "NFQUEUE kernel/user drops were observed"
            failures.append(reason)
            safety_failures.append(reason)
        if nested(result, "daemon_log_events", "terminal_queue_error_lower_bound", default=0):
            reason = "a terminal NFQUEUE error was logged"
            failures.append(reason)
            safety_failures.append(reason)
        if nested(
            result,
            "daemon_log_events",
            "queue_overflow_lower_bound",
            default=0,
        ):
            reason = "an NFQUEUE overflow was logged"
            failures.append(reason)
            safety_failures.append(reason)
        if nested(
            result,
            "daemon_log_events",
            "attribution_timeout_lower_bound",
            default=0,
        ):
            reason = "an NFQUEUE attribution timeout was logged"
            failures.append(reason)
            safety_failures.append(reason)

        # A verified BlockAll transition is fail-closed.  Normal-path shape is
        # no longer observable after quarantine and must not be mislabeled as
        # a safety failure.  The mode transition still fails capacity above.
        if not verified_quarantine:
            if result["mode"] == "learning":
                # Learning observes outbound traffic even when an existing
                # network Accept permits it. Established TCP is also sampled
                # so applications with pre-existing connections can be learned;
                # its queue shape is therefore not the Enforcing fast-path.
                if workload_queue_hits is None:
                    failures.append("Learning observer queue hits are unavailable")
                elif result.get("direction") == "outbound":
                    if transport == "tcp":
                        ratio = result["derived"]["nfqueue_hits_per_connection"]
                        elapsed = numeric(nested(result, "dut_metrics", "elapsed_seconds"))
                        # nft has one inet limiter; xtables has one per family.
                        limiters = 2 if result["backend"] == "iptables" else 1
                        sample_allowance = (
                            None if elapsed is None or elapsed <= 0
                            else limiters * (
                                math.ceil(elapsed * LEARNING_ESTABLISHED_OBSERVATIONS_PER_SECOND)
                                + LEARNING_ESTABLISHED_OBSERVATION_BURST
                            )
                        )
                        maximum_hits = (
                            None if connections is None or sample_allowance is None
                            else connections * criteria["application_tcp_maximum_queue_hits_per_connection"]
                            + sample_allowance
                        )
                        if (
                            ratio is None
                            or ratio < criteria["application_tcp_minimum_queue_hits_per_connection"]
                            or maximum_hits is None
                            or workload_queue_hits > maximum_hits
                        ):
                            failures.append("Learning TCP queue hits do not track new connections and bounded established observations")
                    else:
                        ratio = result["derived"]["nfqueue_hits_per_datagram"]
                        if ratio is None or not (
                            criteria["application_udp_minimum_queue_hits_per_datagram"]
                            <= ratio
                            <= criteria["application_udp_maximum_queue_hits_per_datagram"]
                        ):
                            failures.append("Learning UDP queue hits do not track outbound datagrams")
                # Ingress workloads exercise local reply packets, which do not
                # require positive ORIGINAL-direction learning observations.
            elif result["policy"] == "network_only":
                if (
                    workload_queue_hits is None
                    or workload_queue_hits > criteria["network_only_maximum_queue_hits"]
                ):
                    failures.append("network-only traffic unexpectedly entered NFQUEUE")
            elif result["policy"] == "application_tcp":
                ratio = result["derived"]["nfqueue_hits_per_connection"]
                if ratio is None or not (
                    criteria["application_tcp_minimum_queue_hits_per_connection"]
                    <= ratio
                    <= criteria["application_tcp_maximum_queue_hits_per_connection"]
                ):
                    failures.append("application TCP queue hits do not track new connections")
                if result["offered"].get("mode") == "keepalive":
                    operation_ratio = result["derived"]["nfqueue_hits_per_operation"]
                    if operation_ratio is None or operation_ratio > criteria["application_tcp_keepalive_maximum_queue_hits_per_operation"]:
                        failures.append("established TCP did not demonstrate the conntrack fast-path")
            elif result["policy"] == "application_udp":
                ratio = result["derived"]["nfqueue_hits_per_datagram"]
                if ratio is None or not (
                    criteria["application_udp_minimum_queue_hits_per_datagram"]
                    <= ratio
                    <= criteria["application_udp_maximum_queue_hits_per_datagram"]
                ):
                    failures.append("application UDP queue hits do not track outbound datagrams")

        if result.get("identity_probe") is not None:
            if result["identity_probe"].get("fail_open"):
                safety_failures.append("unauthorized executable completed a round trip under load")
            elif not result["identity_probe"].get(
                "blocked_all", result["identity_probe"].get("blocked")
            ):
                safety_failures.append("unauthorized executable probe result was indeterminate")

    if criteria["require_zero_nic_errors"]:
        for side in ("dut_metrics", "peer_metrics"):
            network = nested(result, side, "network", default={})
            for key in ("rx_dropped", "tx_dropped", "rx_errors", "tx_errors"):
                value = numeric(network.get(key)) if isinstance(network, dict) else None
                if value is None:
                    reason = f"{side} {key} is unavailable"
                    unreliable.append(reason)
                    safety_failures.append(reason)
                elif value > 0:
                    reason = f"{side} {key} increased"
                    failures.append(reason)
                    safety_failures.append(reason)

    result["unreliable_reasons"] = sorted(set(unreliable))
    result["failure_reasons"] = sorted(set(failures))
    result["safety_failure_reasons"] = sorted(set(safety_failures))
    result["valid"] = not unreliable
    result["safety_pass"] = not safety_failures
    result["capacity_pass"] = not failures
    capacity_required = result["phase_role"] == "steady" or (
        result["phase_role"] == "burst" and criteria["require_burst_capacity"]
    )
    result["passed"] = result["safety_pass"] and (
        result["capacity_pass"] if capacity_required else True
    )


def apply_nfqueue_counter_continuity(
    results: list[dict[str, Any]], criteria: dict[str, Any]
) -> None:
    """Account for cumulative daemon counters exactly once across phase gaps.

    A phase-local before/after delta cannot see a verdict completed after its
    final status RPC and before the next phase's initial RPC.  Conversely,
    requiring every absolute process-lifetime counter to remain zero repeats a
    single event against every later phase.  The protected topology uses one
    freshly started daemon per backend, so check the first observed snapshot
    against zero and then compare each adjacent pair of status snapshots.
    """

    previous_by_backend: dict[str, dict[str, Any] | None] = {}
    seen_backends: set[str] = set()

    def identity_key(value: Any) -> tuple[int, int, str] | None:
        if not isinstance(value, dict):
            return None
        pid = value.get("pid")
        starttime = value.get("starttime")
        executable = value.get("exe")
        if (
            isinstance(pid, bool)
            or not isinstance(pid, int)
            or pid <= 0
            or isinstance(starttime, bool)
            or not isinstance(starttime, int)
            or starttime <= 0
            or executable != CONTAINER_DAEMON
        ):
            return None
        return pid, starttime, executable

    for result in results:
        if result.get("policy") == "baseline":
            continue
        backend = result.get("backend")
        if not isinstance(backend, str):
            continue
        counter_evidence = result.get("nfqueue_runtime_counters")
        continuity: dict[str, Any] = {
            "measurement": "adjacent_daemon_status_snapshots",
            "initial_snapshot": backend not in seen_backends,
            "previous_phase": None,
            "previous_after": None,
            "current_before": None,
            "delta": {name: None for name in NFQUEUE_RUNTIME_COUNTER_FIELDS},
            "valid": False,
            "invalid_reasons": [],
        }
        result["nfqueue_counter_continuity"] = continuity

        if not isinstance(counter_evidence, dict) or counter_evidence.get("valid") is not True:
            continuity["invalid_reasons"] = [
                "phase-local NFQUEUE counter evidence is invalid"
            ]
            previous_by_backend[backend] = None
            seen_backends.add(backend)
            continue

        before = counter_evidence.get("before")
        after = counter_evidence.get("after")
        before_identity = identity_key(counter_evidence.get("identity_before"))
        after_identity = identity_key(counter_evidence.get("identity_after"))
        if (
            not isinstance(before, dict)
            or not isinstance(after, dict)
            or before_identity is None
            or after_identity is None
        ):
            # This is defensive: valid phase evidence currently guarantees all
            # four values, but a report schema change must fail closed.
            continuity["invalid_reasons"] = [
                "phase-local NFQUEUE continuity inputs are unavailable"
            ]
            result.setdefault("unreliable_reasons", []).append(
                "authoritative NFQUEUE counter continuity is unavailable"
            )
            result.setdefault("safety_failure_reasons", []).append(
                "authoritative NFQUEUE counter continuity is unavailable"
            )
            previous_by_backend[backend] = None
            seen_backends.add(backend)
            recompute_result_outcome(result, criteria)
            continue

        continuity["current_before"] = dict(before)
        invalid_reasons: list[str] = []
        increments: dict[str, int] = {}
        previous = previous_by_backend.get(backend)
        if backend not in seen_backends:
            reference = {name: 0 for name in NFQUEUE_RUNTIME_COUNTER_FIELDS}
            reference_identity = before_identity
        elif previous is None:
            reference = None
            reference_identity = None
            invalid_reasons.append(
                "the preceding normal phase has no valid terminal counter snapshot"
            )
        else:
            reference = previous["after"]
            reference_identity = previous["identity"]
            continuity["previous_phase"] = previous["phase"]
            continuity["previous_after"] = dict(reference)

        if reference is not None:
            if reference_identity != before_identity:
                invalid_reasons.append(
                    "daemon identity changed between adjacent normal phases"
                )
            else:
                for name in NFQUEUE_RUNTIME_COUNTER_FIELDS:
                    first = reference.get(name)
                    second = before.get(name)
                    if (
                        isinstance(first, bool)
                        or not isinstance(first, int)
                        or isinstance(second, bool)
                        or not isinstance(second, int)
                        or not 0 <= first < U64_MAX
                        or not 0 <= second < U64_MAX
                    ):
                        invalid_reasons.append(
                            f"NFQUEUE counter {name} cannot establish gap continuity"
                        )
                    elif second < first:
                        invalid_reasons.append(
                            f"NFQUEUE counter {name} regressed between normal phases"
                        )
                    else:
                        delta = second - first
                        continuity["delta"][name] = delta
                        if delta:
                            increments[name] = delta

        continuity["valid"] = not invalid_reasons
        continuity["invalid_reasons"] = sorted(set(invalid_reasons))
        for detail in continuity["invalid_reasons"]:
            reason = f"authoritative NFQUEUE counter continuity is invalid: {detail}"
            result.setdefault("unreliable_reasons", []).append(reason)
            result.setdefault("safety_failure_reasons", []).append(reason)
        for name, delta in increments.items():
            reason = (
                f"authoritative NFQUEUE {name} counter was already {delta} "
                "at the first normal phase"
                if continuity["initial_snapshot"]
                else f"authoritative NFQUEUE {name} counter increased by {delta} "
                "between adjacent normal phases"
            )
            result.setdefault("failure_reasons", []).append(reason)
            result.setdefault("safety_failure_reasons", []).append(reason)

        previous_by_backend[backend] = {
            "after": dict(after),
            "identity": after_identity,
            "phase": result.get("phase"),
        }
        seen_backends.add(backend)
        recompute_result_outcome(result, criteria)


def udp_scenario_accounting(
    results: list[dict[str, Any]], server_metrics: Any
) -> dict[str, Any]:
    """Reconcile workload datagrams and per-flow drain barriers end to end."""

    invalid_reasons: list[str] = []
    barrier_invalid_reasons: list[str] = []

    def count(
        value: Any, description: str, *, barrier: bool = False
    ) -> int | None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            reason = f"{description} is unavailable or invalid"
            invalid_reasons.append(reason)
            if barrier:
                barrier_invalid_reasons.append(reason)
            return None
        return value

    sent_by_phase: list[int | None] = []
    barrier_phase_evidence: list[dict[str, Any]] = []
    for result in results:
        phase = str(result.get("phase", "<unknown>"))
        metrics = nested(result, "workload", "metrics", default={})
        sent_by_phase.append(
            count(
                metrics.get("packets_sent") if isinstance(metrics, dict) else None,
                f"client packets_sent for phase {phase}",
            )
        )
        phase_barriers = {
            name: count(
                metrics.get(name) if isinstance(metrics, dict) else None,
                f"client {name} for phase {phase}",
                barrier=True,
            )
            for name in (
                "flows_opened",
                "barriers_expected",
                "barriers_sent",
                "barrier_acks_received",
                "barrier_errors",
            )
        }
        barrier_phase_evidence.append({"phase": phase, **phase_barriers})
        if all(value is not None for value in phase_barriers.values()) and not (
            phase_barriers["flows_opened"]
            == phase_barriers["barriers_expected"]
            == phase_barriers["barriers_sent"]
            == phase_barriers["barrier_acks_received"]
            and phase_barriers["barrier_errors"] == 0
        ):
            barrier_invalid_reasons.append(
                f"client drain barrier did not complete on every flow for phase {phase}"
            )
    packets_received = count(
        server_metrics.get("packets_received")
        if isinstance(server_metrics, dict)
        else None,
        "server packets_received",
    )
    server_operations = count(
        server_metrics.get("operations")
        if isinstance(server_metrics, dict)
        else None,
        "server operations",
    )
    server_barriers_received = count(
        server_metrics.get("barriers_received")
        if isinstance(server_metrics, dict)
        else None,
        "server barriers_received",
        barrier=True,
    )
    server_barrier_acks_sent = count(
        server_metrics.get("barrier_acks_sent")
        if isinstance(server_metrics, dict)
        else None,
        "server barrier_acks_sent",
        barrier=True,
    )
    packets_sent = (
        sum(sent_by_phase)
        if all(value is not None for value in sent_by_phase)
        else None
    )
    packet_evidence_available = all(
        value is not None
        for value in (packets_sent, packets_received, server_operations)
    )
    packet_matched = (
        packets_sent == packets_received == server_operations
        if packet_evidence_available
        else None
    )
    barrier_totals: dict[str, int | None] = {}
    for name in (
        "flows_opened",
        "barriers_expected",
        "barriers_sent",
        "barrier_acks_received",
        "barrier_errors",
    ):
        values = [evidence[name] for evidence in barrier_phase_evidence]
        barrier_totals[name] = (
            sum(values) if all(value is not None for value in values) else None
        )
    barrier_evidence_available = all(
        value is not None
        for value in (
            *barrier_totals.values(),
            server_barriers_received,
            server_barrier_acks_sent,
        )
    )
    barriers_matched = (
        barrier_totals["flows_opened"]
        == barrier_totals["barriers_expected"]
        == barrier_totals["barriers_sent"]
        == server_barriers_received
        == server_barrier_acks_sent
        == barrier_totals["barrier_acks_received"]
        and barrier_totals["barrier_errors"] == 0
        if barrier_evidence_available
        else None
    )
    if barriers_matched is False:
        barrier_invalid_reasons.append(
            "aggregate UDP drain-barrier send/receive/ack counts do not match"
        )
    invalid_reasons.extend(barrier_invalid_reasons)
    valid = not invalid_reasons
    matched = (
        packet_matched is True and barriers_matched is True
        if packet_matched is not None and barriers_matched is not None
        else None
    )
    loss_packets = (
        max(0, packets_sent - packets_received)
        if valid and packets_sent is not None and packets_received is not None
        else None
    )
    unexpected_packets = (
        max(0, packets_received - packets_sent)
        if valid and packets_sent is not None and packets_received is not None
        else None
    )
    loss_ratio = (
        loss_packets / packets_sent
        if loss_packets is not None and packets_sent is not None and packets_sent > 0
        else (0.0 if loss_packets == 0 and packets_sent == 0 else None)
    )
    return {
        "measurement": "exact_client_send_to_dedicated_server_receive_accounting",
        "phase_count": len(results),
        "client_packets_sent_by_phase": sent_by_phase,
        "client_packets_sent": packets_sent,
        "server_packets_received": packets_received,
        "server_operations": server_operations,
        "packet_matched": packet_matched,
        "packet_loss": loss_packets,
        "packet_loss_ratio": loss_ratio,
        "unexpected_packets": unexpected_packets,
        "barrier_phases": barrier_phase_evidence,
        "client_flows_opened": barrier_totals.get("flows_opened"),
        "client_barriers_expected": barrier_totals.get("barriers_expected"),
        "client_barriers_sent": barrier_totals.get("barriers_sent"),
        "server_barriers_received": server_barriers_received,
        "server_barrier_acks_sent": server_barrier_acks_sent,
        "client_barrier_acks_received": barrier_totals.get(
            "barrier_acks_received"
        ),
        "client_barrier_errors": barrier_totals.get("barrier_errors"),
        "barriers_matched": barriers_matched,
        "barrier_evidence_valid": not barrier_invalid_reasons,
        "barrier_invalid_reasons": sorted(set(barrier_invalid_reasons)),
        "matched": matched,
        "valid": valid,
        "invalid_reasons": sorted(set(invalid_reasons)),
    }


def apply_server_reliability(
    results: list[dict[str, Any]],
    scenario: dict[str, Any],
    load_level: float,
    server_summary: dict[str, Any],
    criteria: dict[str, Any],
) -> None:
    metrics = server_summary.get("metrics")
    cpu = numeric(metrics.get("wall_cpu_ratio")) if isinstance(metrics, dict) else None
    error_counters = (
        {
            name: numeric(metrics.get(name))
            for name in (
                "connections_rejected",
                "protocol_errors",
                "internal_errors",
            )
        }
        if isinstance(metrics, dict)
        else {}
    )
    affected = [
        result
        for result in results
        if result["backend"] == scenario.get("backend", result["backend"])
        and result["profile"] == scenario["profile"]["name"]
        and result["policy"] == scenario["policy"]
        and result["mode"] == scenario["mode"]
        and result["learning_variant"] == scenario.get("learning_variant")
        and result["load_level"] == load_level
        and "server_summary" not in result
    ]
    udp_accounting = (
        udp_scenario_accounting(affected, metrics)
        if scenario["profile"].get("transport") == "udp"
        else None
    )
    for result in affected:
        result["server_summary"] = server_summary
        result["udp_scenario_accounting"] = udp_accounting
        if cpu is None or cpu > criteria["maximum_peer_wall_cpu_ratio"]:
            result["unreliable_reasons"].append("workload server CPU saturation or missing metric")
        server_metric_side = (
            "dut_metrics"
            if result.get("direction") == "inbound"
            else "peer_metrics"
        )
        server_phase_cpu = numeric(
            nested(
                result,
                server_metric_side,
                "workload_process",
                "cpu_percent_one_core",
            )
        )
        if (
            server_phase_cpu is None
            or server_phase_cpu < 0
            or server_phase_cpu / 100.0
            > criteria["maximum_peer_wall_cpu_ratio"]
        ):
            result["unreliable_reasons"].append(
                "per-phase workload server CPU saturation or missing metric"
            )
        if not error_counters or any(
            value is None or value < 0 for value in error_counters.values()
        ):
            result["unreliable_reasons"].append(
                "workload server error counters are unavailable"
            )
        elif any(value > 0 for value in error_counters.values()):
            result["unreliable_reasons"].append(
                "workload server rejected, malformed, or internally failed traffic"
            )
        if isinstance(udp_accounting, dict):
            if udp_accounting["valid"] is not True:
                result["unreliable_reasons"].extend(
                    f"UDP scenario accounting is invalid: {reason}"
                    for reason in udp_accounting["invalid_reasons"]
                )
            if udp_accounting["barrier_evidence_valid"] is not True:
                reason = "UDP drain-barrier evidence is incomplete or invalid"
                result["failure_reasons"].append(reason)
                result["safety_failure_reasons"].append(reason)
            # Packet delivery and drain-barrier evidence are independent
            # dimensions. A failed barrier makes the scenario unsafe and
            # invalid, but must not be misreported as packet loss when the
            # exact send/receive/operation counters themselves match.
            if udp_accounting["packet_matched"] is not True:
                reason = (
                    "UDP client/server aggregate packet accounting mismatch "
                    f"(sent={udp_accounting['client_packets_sent']}, "
                    f"received={udp_accounting['server_packets_received']}, "
                    f"operations={udp_accounting['server_operations']})"
                )
                result["failure_reasons"].append(reason)
                result["safety_failure_reasons"].append(reason)
        recompute_result_outcome(result, criteria)


def write_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def raw_result_path(output: Path, result: dict[str, Any]) -> Path:
    """Return the unique raw evidence path for one validated matrix row."""

    components = {
        "backend": result.get("backend"),
        "profile": result.get("profile"),
        "policy": result.get("policy"),
        "mode": result.get("mode") or "none",
        "variant": result.get("learning_variant") or "none",
        "phase": result.get("phase"),
        "sample": result.get("baseline_sample_id"),
        "topology": result.get("topology_role"),
    }
    if any(
        not isinstance(value, str) or not NAME_PATTERN.fullmatch(value)
        for value in components.values()
    ):
        raise HarnessError("result contains an unsafe raw-evidence path component")
    load_level = finite_number(result.get("load_level"), "result load level", 0.01, 100.0)
    filename = (
        f"result-{components['sample']}-{components['profile']}-"
        f"{components['policy']}-{components['mode']}-"
        f"{components['variant']}-{load_level:g}-{components['phase']}.json"
    )
    return (
        output
        / "raw"
        / components["backend"]
        / components["topology"]
        / filename
    )


def rewrite_canonical_raw_results(output: Path, results: list[dict[str, Any]]) -> None:
    """Persist post-processed rows so raw JSON and aggregate reports agree."""

    seen: set[Path] = set()
    for result in results:
        path = raw_result_path(output, result)
        if path in seen:
            raise HarnessError(f"duplicate raw result path: {path.name}")
        seen.add(path)
        write_json(path, result)


def relative_increase_percent(baseline: Any, current: Any) -> float | None:
    baseline_value = numeric(baseline)
    current_value = numeric(current)
    if baseline_value is None or baseline_value <= 0 or current_value is None:
        return None
    return (current_value - baseline_value) * 100.0 / baseline_value


def relative_reduction_percent(baseline: Any, current: Any) -> float | None:
    increase = relative_increase_percent(baseline, current)
    return None if increase is None else -increase


def steady_measurement_intervals(
    result: dict[str, Any],
) -> tuple[tuple[int, int], tuple[int, int], tuple[int, int]] | None:
    """Return bounded DUT, peer, and authenticated-workload steady intervals.

    Pair proximity must be measured between the windows which contribute the
    paired delta, not between the outer workload blocks.  The latter include
    policy preparation, warm-up, ramp, burst, server teardown, and cooldown and
    can therefore make a distant comparison look adjacent.  The DUT and peer
    collectors intentionally bracket the workload; retaining all three
    intervals prevents a wider envelope from understating controller delay
    between real workloads.
    """

    if result.get("phase_role") != "steady":
        return None
    dut_metrics = result.get("dut_metrics")
    peer_metrics = result.get("peer_metrics")
    if not isinstance(dut_metrics, dict) or not isinstance(peer_metrics, dict):
        return None
    dut_started = dut_metrics.get("started_at_monotonic_ns")
    dut_finished = dut_metrics.get("finished_at_monotonic_ns")
    peer_started = peer_metrics.get("started_at_monotonic_ns")
    peer_finished = peer_metrics.get("finished_at_monotonic_ns")
    workload_started = nested(
        result, "workload_started", "boundary_monotonic_ns"
    )
    workload_finished = nested(
        result, "workload_finished", "boundary_monotonic_ns"
    )
    block_started = result.get("block_started_monotonic_ns")
    block_finished = result.get("block_finished_monotonic_ns")
    values = (
        dut_started,
        peer_started,
        workload_started,
        workload_finished,
        dut_finished,
        peer_finished,
        block_started,
        block_finished,
    )
    if not all(
        isinstance(value, int) and not isinstance(value, bool) and value > 0
        for value in values
    ):
        return None
    dut_bounded = (
        block_started
        <= dut_started
        <= workload_started
        < workload_finished
        <= dut_finished
        <= block_finished
    )
    peer_bounded = (
        block_started
        <= peer_started
        <= workload_started
        < workload_finished
        <= peer_finished
        <= block_finished
    )
    if not dut_bounded or not peer_bounded:
        return None
    return (
        (dut_started, dut_finished),
        (peer_started, peer_finished),
        (workload_started, workload_finished),
    )


def paired_steady_measurement_gap_seconds(
    baseline: dict[str, Any], current: dict[str, Any], order: Any
) -> float | None:
    """Return the conservative gap between actual paired steady windows."""

    baseline_intervals = steady_measurement_intervals(baseline)
    current_intervals = steady_measurement_intervals(current)
    if baseline_intervals is None or current_intervals is None:
        return None
    gaps: list[int] = []
    for baseline_interval, current_interval in zip(
        baseline_intervals, current_intervals, strict=True
    ):
        baseline_started, baseline_finished = baseline_interval
        current_started, current_finished = current_interval
        if order == "ab" and baseline_finished <= current_started:
            gaps.append(current_started - baseline_finished)
        elif order == "ba" and current_finished <= baseline_started:
            gaps.append(baseline_started - current_finished)
        else:
            return None
    # The collector envelope is deliberately wider than the workload interval.
    # Max is fail-closed if later instrumentation adds a differently bracketed
    # interval, and today equals the real workload-to-workload gap.
    return max(gaps) / 1_000_000_000.0


def cgroup_cpu_relative_increase_percent(
    baseline_result: dict[str, Any],
    current_result: dict[str, Any],
    maximum_increase_percent: float,
) -> float | None:
    """Return CPU overhead only when its baseline resolves the threshold.

    Both endpoints can contribute one ``usage_usec`` unit.  If that bounded
    quantization alone could equal the configured relative limit, treating the
    percentage as evidence would turn a near-zero denominator into a false
    regression.  The caller consequently marks this pair incomplete/invalid.
    """

    baseline_seconds = numeric(
        nested(baseline_result, "dut_metrics", "cgroup", "cpu_seconds")
    )
    baseline_percent = nested(
        baseline_result, "derived", "cgroup_cpu_percent_one_core"
    )
    current_percent = nested(
        current_result, "derived", "cgroup_cpu_percent_one_core"
    )
    threshold = numeric(maximum_increase_percent)
    if baseline_seconds is None or threshold is None or threshold <= 0:
        return None
    minimum_resolved_baseline = (
        2.0
        * CGROUP_CPU_ACCOUNTING_RESOLUTION_SECONDS
        * 100.0
        / threshold
    )
    if baseline_seconds < minimum_resolved_baseline:
        return None
    return relative_increase_percent(baseline_percent, current_percent)


def relative_metric_specs(transport: Any) -> tuple[tuple[str, str, str], ...]:
    """Return (measurement, criterion, human description) gate definitions."""

    common = (
        (
            "throughput_reduction_percent",
            "maximum_throughput_reduction_vs_baseline_percent",
            "application throughput reduction",
        ),
        (
            "aggregate_dut_pps_reduction_percent",
            "maximum_dut_pps_reduction_vs_baseline_percent",
            "aggregate DUT PPS reduction",
        ),
        (
            "cgroup_cpu_increase_percent",
            "maximum_cgroup_cpu_increase_vs_baseline_percent",
            "DUT cgroup CPU increase",
        ),
        *(
            (
                f"latency_{percentile}_increase_percent",
                "maximum_latency_increase_vs_baseline_percent",
                f"latency {percentile} increase",
            )
            for percentile in ("p50", "p95", "p99")
        ),
    )
    if transport != "tcp":
        return common
    return (
        *common,
        *(
            (
                f"connect_latency_{percentile}_increase_percent",
                "maximum_latency_increase_vs_baseline_percent",
                f"TCP connect latency {percentile} increase",
            )
            for percentile in ("p50", "p95", "p99")
        ),
    )


def relative_metric_is_advisory(
    criterion_name: str, criteria: dict[str, Any]
) -> bool:
    """Return whether this relative crossing is deliberately non-blocking.

    The short shared-runner smoke keeps the original ten-percent observation
    thresholds, but may classify CPU and latency deltas as advisory while an
    operator evaluates usability. Throughput and PPS regressions are never
    covered by this exception, and absolute resource/safety limits remain
    independent hard gates.
    """

    return bool(criteria["cpu_latency_relative_regressions_are_advisory"]) and (
        criterion_name
        in {
            "maximum_latency_increase_vs_baseline_percent",
            "maximum_cgroup_cpu_increase_vs_baseline_percent",
        }
    )


def one_sided_mean_lower_bound(values: list[float]) -> float | None:
    """Return a one-sided 95% lower bound for independent paired deltas."""

    if len(values) < MINIMUM_RELATIVE_PAIRED_SAMPLES:
        return None
    critical = ONE_SIDED_T_95.get(len(values) - 1)
    if critical is None:
        raise HarnessError("paired relative sample count exceeds the supported bound")
    mean = sum(values) / len(values)
    squared_error = sum((value - mean) ** 2 for value in values)
    sample_deviation = math.sqrt(squared_error / (len(values) - 1))
    return mean - critical * sample_deviation / math.sqrt(len(values))


def apply_confirmed_relative_gates(
    results: list[dict[str, Any]], criteria: dict[str, Any]
) -> None:
    """Gate only regressions confirmed across repeated adjacent AB/BA pairs.

    Per-window deltas remain in ``overhead_vs_baseline`` and threshold
    crossings remain in ``relative_performance_observation_reasons``. A
    group becomes a release failure when the arithmetic mean of at least three
    independent steady paired deltas exceeds the unchanged configured
    threshold, except for criteria explicitly assigned the ``observe`` action.
    The one-sided 95% lower confidence bound is retained as stronger
    confirmation, not as a loophole through which a high-variance blocking
    mean regression can pass. A single burst cannot establish a statistical
    regression claim, but its direct threshold crossing still blocks metrics
    assigned the ``fail`` action.
    """

    groups: dict[
        tuple[str, str, str | None, str | None, str, float],
        list[dict[str, Any]],
    ] = {}
    for result in results:
        if result.get("policy") == "baseline" or result.get("phase_role") != "steady":
            continue
        key = (
            result["backend"],
            result["policy"],
            result.get("mode"),
            result.get("learning_variant"),
            result["profile"],
            float(result["load_level"]),
        )
        groups.setdefault(key, []).append(result)

    for rows in groups.values():
        eligible_rows = [
            row
            for row in rows
            if row.get("baseline", {}).get("eligible") is True
            and row.get("valid") is True
        ]
        pair_ids = [row.get("comparison_pair_id") for row in eligible_rows]
        baseline_ids = [row.get("baseline_sample_id") for row in eligible_rows]
        repetitions = [row.get("comparison_repetition") for row in eligible_rows]
        orders = [row.get("comparison_order") for row in eligible_rows]
        independent_pairs_valid = (
            len(eligible_rows) >= MINIMUM_RELATIVE_PAIRED_SAMPLES
            and all(
                isinstance(value, str) and NAME_PATTERN.fullmatch(value)
                for value in (*pair_ids, *baseline_ids)
            )
            and len(set(pair_ids)) == len(pair_ids)
            and len(set(baseline_ids)) == len(baseline_ids)
            and all(
                isinstance(value, int)
                and not isinstance(value, bool)
                and value > 0
                for value in repetitions
            )
            and len(set(repetitions)) == len(repetitions)
            and set(orders) == {"ab", "ba"}
            and abs(orders.count("ab") - orders.count("ba")) <= 1
        )
        if not independent_pairs_valid:
            for row in rows:
                row.setdefault("unreliable_reasons", []).append(
                    "independent paired relative-performance evidence is "
                    "insufficient, duplicated, or not AB/BA balanced"
                )
        evidence: list[dict[str, Any]] = []
        for metric_name, criterion_name, description in relative_metric_specs(
            rows[0].get("transport")
        ):
            values = [
                numeric(row.get("overhead_vs_baseline", {}).get(metric_name))
                for row in eligible_rows
            ]
            paired_values = [value for value in values if value is not None]
            metric_evidence_complete = (
                independent_pairs_valid
                and len(paired_values) == len(eligible_rows)
            )
            if not metric_evidence_complete:
                for row in rows:
                    row.setdefault("unreliable_reasons", []).append(
                        f"independent paired evidence for {description} is incomplete"
                    )
            lower_bound = (
                one_sided_mean_lower_bound(paired_values)
                if metric_evidence_complete
                else None
            )
            threshold = float(criteria[criterion_name])
            mean_percent = (
                sum(paired_values) / len(paired_values)
                if paired_values
                else None
            )
            mean_exceeded = (
                metric_evidence_complete
                and mean_percent is not None
                and mean_percent > threshold
            )
            confirmed = lower_bound is not None and lower_bound > threshold
            evidence.append(
                {
                    "metric": metric_name,
                    "description": description,
                    "threshold_percent": threshold,
                    "sample_count": len(paired_values),
                    "minimum_sample_count": MINIMUM_RELATIVE_PAIRED_SAMPLES,
                    "confidence_level": RELATIVE_CONFIDENCE_LEVEL,
                    "method": "arithmetic_mean_of_independent_paired_deltas",
                    "confirmation_method": (
                        "one_sided_paired_student_t_mean_lower_bound"
                    ),
                    "independent_pair_ids": pair_ids,
                    "baseline_sample_ids": baseline_ids,
                    "comparison_orders": orders,
                    "independent_pairs_valid": metric_evidence_complete,
                    "mean_percent": mean_percent,
                    "mean_exceeded_threshold": mean_exceeded,
                    "lower_confidence_bound_percent": lower_bound,
                    "confirmed_regression": confirmed,
                    "release_action": (
                        "observe"
                        if relative_metric_is_advisory(criterion_name, criteria)
                        else "fail"
                    ),
                }
            )
            if mean_exceeded:
                reason = (
                    "independent paired mean for "
                    f"{description} exceeded the configured bound"
                )
                for row in rows:
                    if not relative_metric_is_advisory(criterion_name, criteria):
                        row["relative_performance_failure_reasons"].append(reason)
        for row in rows:
            row["relative_performance_evidence"] = evidence
            recompute_result_outcome(row, criteria)

    for result in results:
        if result.get("policy") == "baseline" or result.get("phase_role") != "burst":
            continue
        burst_evidence: list[dict[str, Any]] = []
        for metric_name, criterion_name, description in relative_metric_specs(
            result.get("transport")
        ):
            observed = numeric(
                result.get("overhead_vs_baseline", {}).get(metric_name)
            )
            threshold = float(criteria[criterion_name])
            mean_exceeded = observed is not None and observed > threshold
            release_action = (
                "observe"
                if relative_metric_is_advisory(criterion_name, criteria)
                else "fail"
            )
            burst_evidence.append(
                {
                "metric": metric_name,
                "description": description,
                "threshold_percent": threshold,
                "sample_count": 1 if observed is not None else 0,
                "minimum_sample_count": MINIMUM_RELATIVE_PAIRED_SAMPLES,
                "confidence_level": RELATIVE_CONFIDENCE_LEVEL,
                "method": "single_paired_burst_threshold_gate",
                "mean_percent": observed,
                "mean_exceeded_threshold": mean_exceeded,
                "lower_confidence_bound_percent": None,
                "confirmed_regression": False,
                "release_action": release_action,
                }
            )
            if mean_exceeded and release_action == "fail":
                result["relative_performance_failure_reasons"].append(
                    "single paired burst for "
                    f"{description} exceeded the configured bound"
                )
        result["relative_performance_evidence"] = burst_evidence
        recompute_result_outcome(result, criteria)


def recompute_result_outcome(
    result: dict[str, Any], criteria: dict[str, Any]
) -> None:
    """Recompute a row after paired-baseline gates mutate its decisions."""

    unreliable = sorted(set(result.get("unreliable_reasons", [])))
    failures = sorted(set(result.get("failure_reasons", [])))
    safety_failures = sorted(set(result.get("safety_failure_reasons", [])))
    relative_failures = sorted(
        set(result.get("relative_performance_failure_reasons", []))
    )
    result["unreliable_reasons"] = unreliable
    result["failure_reasons"] = failures
    result["safety_failure_reasons"] = safety_failures
    result["relative_performance_failure_reasons"] = relative_failures
    result["valid"] = not unreliable
    result["safety_pass"] = not safety_failures
    result["capacity_pass"] = not failures
    result["relative_performance_pass"] = not relative_failures
    capacity_required = result["phase_role"] == "steady" or (
        result["phase_role"] == "burst" and criteria["require_burst_capacity"]
    )
    # Normal protected burst windows contain the same workload as baseline;
    # wrong-executable probes live in the separate controlled-overload gate.
    # Relative regressions therefore gate both steady and burst windows.
    relative_required = result["phase_role"] in {"steady", "burst"}
    result["passed"] = (
        result["safety_pass"]
        and (result["capacity_pass"] if capacity_required else True)
        and (
            result["relative_performance_pass"]
            if relative_required
            else True
        )
    )


def add_baseline_comparisons(
    results: list[dict[str, Any]], criteria: dict[str, Any]
) -> None:
    baselines: dict[
        tuple[str, str, str, float, str], list[dict[str, Any]]
    ] = {}
    for result in results:
        if result["policy"] == "baseline":
            key = (
                result["backend"],
                result.get("baseline_sample_id"),
                result["profile"],
                result["load_level"],
                result["phase"],
            )
            baselines.setdefault(key, []).append(result)
    steady_blocks: dict[
        tuple[str, str | None, str | None, str], list[dict[str, Any]]
    ] = {}
    for result in results:
        if result.get("phase_role") != "steady":
            continue
        key = (
            result["backend"],
            result.get("baseline_sample_id"),
            result.get("comparison_pair_id"),
            result.get("topology_role"),
        )
        steady_blocks.setdefault(key, []).append(result)
    for result in results:
        if result["policy"] == "baseline":
            continue
        previous_relative_failures = set(
            result.pop("relative_performance_failure_reasons", [])
        )
        result["failure_reasons"] = [
            reason
            for reason in result.get("failure_reasons", [])
            if reason not in previous_relative_failures
        ]
        result["unreliable_reasons"] = [
            reason
            for reason in result.get("unreliable_reasons", [])
            if reason
            not in {
                "paired baseline is missing",
                "paired baseline is ambiguous",
                "paired baseline is saturated or invalid",
                "paired baseline is not the predetermined adjacent sample",
                "paired baseline comparison gap exceeded the configured bound",
                "paired steady measurement boundaries are missing, invalid, or out of AB/BA order",
                "paired baseline has a mismatched independent-pair identity",
                "independent paired relative-performance evidence is insufficient, duplicated, or not AB/BA balanced",
            }
            and not reason.startswith("independent paired evidence for ")
        ]
        result["relative_performance_failure_reasons"] = []
        result["relative_performance_observation_reasons"] = []
        result.pop("relative_performance_evidence", None)
        baseline_candidates = baselines.get(
            (
                result["backend"],
                result.get("baseline_sample_id"),
                result["profile"],
                result["load_level"],
                result["phase"],
            ),
            [],
        )
        gated_phase = result["phase_role"] in {"steady", "burst"}
        if len(baseline_candidates) != 1:
            result["unreliable_reasons"].append(
                "paired baseline is missing"
                if not baseline_candidates
                else "paired baseline is ambiguous"
            )
            recompute_result_outcome(result, criteria)
            continue
        baseline = baseline_candidates[0]
        baseline_sequence = baseline.get("execution_sequence")
        current_sequence = result.get("execution_sequence")
        baseline_started = baseline.get("block_started_monotonic_ns")
        baseline_finished = baseline.get("block_finished_monotonic_ns")
        current_started = result.get("block_started_monotonic_ns")
        current_finished = result.get("block_finished_monotonic_ns")
        order = result.get("comparison_order")
        temporal_values = (
            baseline_sequence,
            current_sequence,
            baseline_started,
            baseline_finished,
            current_started,
            current_finished,
        )
        temporal_valid = all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in temporal_values
        )
        gap_seconds: float | None = None
        if temporal_valid and order == "ab":
            temporal_valid = (
                current_sequence == baseline_sequence + 1
                and baseline_started <= baseline_finished <= current_started
                and current_started <= current_finished
            )
        elif temporal_valid and order == "ba":
            temporal_valid = (
                baseline_sequence == current_sequence + 1
                and current_started <= current_finished <= baseline_started
                and baseline_started <= baseline_finished
            )
        else:
            temporal_valid = False
        if not temporal_valid:
            result["unreliable_reasons"].append(
                "paired baseline is not the predetermined adjacent sample"
            )

        steady_key = (
            result["backend"],
            result.get("baseline_sample_id"),
            result.get("comparison_pair_id"),
        )
        baseline_steady = steady_blocks.get((*steady_key, "baseline"), [])
        current_steady = steady_blocks.get((*steady_key, "protected"), [])
        steady_temporal_valid = len(baseline_steady) == 1 and len(current_steady) == 1
        if steady_temporal_valid:
            gap_seconds = paired_steady_measurement_gap_seconds(
                baseline_steady[0], current_steady[0], order
            )
            steady_temporal_valid = gap_seconds is not None
        result["comparison_gap_seconds"] = gap_seconds
        if not steady_temporal_valid:
            result["unreliable_reasons"].append(
                "paired steady measurement boundaries are missing, invalid, or out of AB/BA order"
            )
        elif gap_seconds > float(criteria["maximum_comparison_gap_seconds"]):
            steady_temporal_valid = False
            result["unreliable_reasons"].append(
                "paired baseline comparison gap exceeded the configured bound"
            )
        baseline_eligible = baseline.get("valid") is True and (
            not gated_phase
            or (
                baseline.get("capacity_pass") is True
                and baseline.get("safety_pass") is True
            )
        ) and temporal_valid and steady_temporal_valid
        if not baseline_eligible:
            result["unreliable_reasons"].append("paired baseline is saturated or invalid")
        result["baseline"] = {
            "sample_id": baseline.get("baseline_sample_id"),
            "comparison_pair_id": baseline.get("comparison_pair_id"),
            "comparison_repetition": baseline.get("comparison_repetition"),
            "comparison_order": order,
            "execution_sequence": baseline_sequence,
            "comparison_gap_seconds": gap_seconds,
            "valid": baseline.get("valid"),
            "capacity_pass": baseline.get("capacity_pass"),
            "safety_pass": baseline.get("safety_pass"),
            "eligible": baseline_eligible,
            "actual_application_ops_per_second": nested(
                baseline, "derived", "actual_application_ops_per_second"
            ),
            "actual_application_mbps": nested(
                baseline, "derived", "actual_application_mbps"
            ),
            "aggregate_dut_pps": nested(
                baseline, "derived", "aggregate_dut_pps"
            ),
            "cgroup_cpu_percent_one_core": nested(
                baseline, "derived", "cgroup_cpu_percent_one_core"
            ),
            "latency_p50_ms": nested(baseline, "derived", "latency_p50_ms"),
            "latency_p95_ms": nested(baseline, "derived", "latency_p95_ms"),
            "latency_p99_ms": nested(baseline, "derived", "latency_p99_ms"),
            "connect_latency_p50_ms": nested(
                baseline, "derived", "connect_latency_p50_ms"
            ),
            "connect_latency_p95_ms": nested(
                baseline, "derived", "connect_latency_p95_ms"
            ),
            "connect_latency_p99_ms": nested(
                baseline, "derived", "connect_latency_p99_ms"
            ),
        }
        if (
            baseline.get("comparison_pair_id")
            != result.get("comparison_pair_id")
            or baseline.get("comparison_repetition")
            != result.get("comparison_repetition")
        ):
            result["unreliable_reasons"].append(
                "paired baseline has a mismatched independent-pair identity"
            )
            result["baseline"]["eligible"] = False
            baseline_eligible = False
        baseline_rate = nested(baseline, "derived", "actual_application_ops_per_second")
        current_rate = nested(result, "derived", "actual_application_ops_per_second")
        baseline_throughput = nested(baseline, "derived", "actual_application_mbps")
        current_throughput = nested(result, "derived", "actual_application_mbps")
        baseline_pps = nested(baseline, "derived", "aggregate_dut_pps")
        current_pps = nested(result, "derived", "aggregate_dut_pps")
        overhead: dict[str, Any] = {
            "application_ops_reduction_percent": relative_reduction_percent(
                baseline_rate, current_rate
            ),
            "throughput_reduction_percent": relative_reduction_percent(
                baseline_throughput, current_throughput
            ),
            "aggregate_dut_pps_reduction_percent": relative_reduction_percent(
                baseline_pps, current_pps
            ),
            "cgroup_cpu_increase_percent": cgroup_cpu_relative_increase_percent(
                baseline,
                result,
                float(criteria["maximum_cgroup_cpu_increase_vs_baseline_percent"]),
            ),
        }
        for percentile in ("p50", "p95", "p99"):
            baseline_latency = nested(
                baseline, "derived", f"latency_{percentile}_ms"
            )
            current_latency = nested(
                result, "derived", f"latency_{percentile}_ms"
            )
            overhead[f"latency_{percentile}_increase_percent"] = (
                relative_increase_percent(baseline_latency, current_latency)
            )
            if result.get("transport") == "tcp":
                baseline_connect_latency = nested(
                    baseline, "derived", f"connect_latency_{percentile}_ms"
                )
                current_connect_latency = nested(
                    result, "derived", f"connect_latency_{percentile}_ms"
                )
                overhead[f"connect_latency_{percentile}_increase_percent"] = (
                    relative_increase_percent(
                        baseline_connect_latency, current_connect_latency
                    )
                )
        result["overhead_vs_baseline"] = overhead
        observations = result["relative_performance_observation_reasons"]
        if gated_phase and baseline_eligible:
            for metric_name, criterion_name, description in relative_metric_specs(
                result.get("transport")
            ):
                value = numeric(overhead.get(metric_name))
                if value is None:
                    result["unreliable_reasons"].append(
                        f"paired-baseline {description} is unavailable"
                    )
                elif value > criteria[criterion_name]:
                    observations.append(
                        f"single paired window observed {description} above the configured bound"
                    )
        # Relative overhead is an independent release dimension.  Keep it out
        # of capacity failures so reports can distinguish an unsustainable
        # offered point from a valid point whose firewall overhead is too high.
        recompute_result_outcome(result, criteria)
    apply_confirmed_relative_gates(results, criteria)


def baseline_pairing_evidence(
    results: list[dict[str, Any]],
    config: dict[str, Any],
    baseline_environments: list[dict[str, Any]],
    protected_environments: list[dict[str, Any]],
    generation_pairs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Validate independent, predetermined and order-balanced comparison pairs."""

    failures: list[str] = []
    expected_backends = list(config["backends"])
    if len(baseline_environments) != len(expected_backends):
        failures.append("baseline environment evidence count does not match backends")
    if len(protected_environments) != len(expected_backends):
        failures.append("protected environment evidence count does not match backends")
    if len(generation_pairs) != len(expected_backends):
        failures.append("DUT generation evidence count does not match backends")
    baseline_by_backend = {
        item.get("backend"): item
        for item in baseline_environments
        if isinstance(item, dict)
    }
    protected_by_backend = {
        item.get("backend"): item
        for item in protected_environments
        if isinstance(item, dict)
    }
    generations_by_backend = {
        item.get("backend"): item
        for item in generation_pairs
        if isinstance(item, dict)
    }
    environment_pairs: list[dict[str, Any]] = []
    if len(baseline_by_backend) != len(baseline_environments):
        failures.append("baseline environment evidence has duplicate backend identities")
    if len(protected_by_backend) != len(protected_environments):
        failures.append("protected environment evidence has duplicate backend identities")
    if len(generations_by_backend) != len(generation_pairs):
        failures.append("DUT generation evidence has duplicate backend identities")
    for backend in expected_backends:
        baseline_environment = baseline_by_backend.get(backend)
        protected_environment = protected_by_backend.get(backend)
        generation = generations_by_backend.get(backend)
        pair_failures: list[str] = []
        if baseline_environment is None or protected_environment is None:
            pair_failures.append("baseline or protected environment evidence is missing")
        elif baseline_environment != protected_environment:
            pair_failures.append("baseline and protected environments differ")
        if not isinstance(generation, dict):
            pair_failures.append("DUT generation evidence is missing")
            baseline_client_id = None
            protected_client_id = None
            baseline_daemon_started = None
        else:
            baseline_client_id = generation.get("baseline_client_id")
            protected_client_id = generation.get("protected_client_id")
            baseline_daemon_started = generation.get("baseline_daemon_started")
            if (
                not isinstance(baseline_client_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", baseline_client_id) is None
                or not isinstance(protected_client_id, str)
                or re.fullmatch(r"[0-9a-f]{64}", protected_client_id) is None
                or baseline_client_id == protected_client_id
            ):
                pair_failures.append("baseline and protected DUT identities are invalid")
            if baseline_daemon_started is not False:
                pair_failures.append("baseline DUT started the OpenShield daemon")
        environment_pairs.append(
            {
                "backend": backend,
                "valid": not pair_failures,
                "failure_reasons": sorted(set(pair_failures)),
                "baseline_client_id": baseline_client_id,
                "protected_client_id": protected_client_id,
                "baseline_daemon_started": baseline_daemon_started,
            }
        )
        failures.extend(f"{backend}: {reason}" for reason in pair_failures)

    block_rows: dict[tuple[str, int], list[dict[str, Any]]] = {}
    observed_block_order: dict[str, list[int]] = {}
    last_sequence: dict[str, int] = {}
    closed_blocks: set[tuple[str, int]] = set()
    for result in results:
        backend = result.get("backend")
        sequence = result.get("execution_sequence")
        if (
            not isinstance(backend, str)
            or backend not in expected_backends
            or not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence < 0
        ):
            failures.append("a result has invalid block identity")
            continue
        block_key = (backend, sequence)
        if last_sequence.get(backend) != sequence:
            previous = last_sequence.get(backend)
            if previous is not None:
                closed_blocks.add((backend, previous))
            if block_key in closed_blocks:
                failures.append(f"{backend}: block {sequence} is not contiguous")
            observed_block_order.setdefault(backend, []).append(sequence)
            last_sequence[backend] = sequence
        block_rows.setdefault(block_key, []).append(result)

    comparison_count = 0
    baseline_sample_count = 0
    order_counts = {"ab": 0, "ba": 0}
    gaps: list[float] = []
    protected_groups: dict[
        tuple[str, str, str | None, str | None, str, float],
        list[tuple[int, str, str, str]],
    ] = {}
    baseline_ids: set[tuple[str, str]] = set()
    pair_ids: set[tuple[str, str]] = set()
    for backend in config["backends"]:
        actual_sequences = observed_block_order.get(backend, [])
        if not actual_sequences:
            continue
        expected = list(paired_load_plan(config, backend))
        if actual_sequences != list(range(len(expected))):
            failures.append(f"{backend}: execution sequence is incomplete or non-canonical")
            continue
        for sequence, (expected_scenario, expected_load) in enumerate(expected):
            rows = block_rows[(backend, sequence)]
            first = rows[0]
            identity = (
                first.get("profile"),
                first.get("policy"),
                first.get("mode"),
                first.get("learning_variant"),
                first.get("load_level"),
                first.get("baseline_sample_id"),
                first.get("comparison_pair_id"),
                first.get("comparison_repetition"),
                first.get("comparison_order"),
                first.get("topology_role"),
                first.get("block_started_monotonic_ns"),
                first.get("block_finished_monotonic_ns"),
            )
            if any(
                (
                    row.get("profile"),
                    row.get("policy"),
                    row.get("mode"),
                    row.get("learning_variant"),
                    row.get("load_level"),
                    row.get("baseline_sample_id"),
                    row.get("comparison_pair_id"),
                    row.get("comparison_repetition"),
                    row.get("comparison_order"),
                    row.get("topology_role"),
                    row.get("block_started_monotonic_ns"),
                    row.get("block_finished_monotonic_ns"),
                )
                != identity
                for row in rows
            ):
                failures.append(f"{backend}: block {sequence} has inconsistent rows")
            expected_identity = (
                expected_scenario["profile"]["name"],
                expected_scenario["policy"],
                expected_scenario["mode"],
                expected_scenario.get("learning_variant"),
                expected_load,
                expected_scenario["baseline_sample_id"],
                expected_scenario["comparison_pair_id"],
                expected_scenario["comparison_repetition"],
                expected_scenario["comparison_order"],
                expected_scenario["topology_role"],
            )
            if identity[:10] != expected_identity:
                failures.append(f"{backend}: block {sequence} differs from the AB/BA plan")
            expected_phases = [
                phase["name"]
                for phase in comparison_phase_plan(config, expected_scenario)
            ]
            phases = [row.get("phase") for row in rows]
            if sorted(phases) != sorted(expected_phases) or len(phases) != len(
                set(phases)
            ):
                failures.append(f"{backend}: block {sequence} has an incomplete phase set")
            started, finished = identity[10:]
            if (
                not isinstance(started, int)
                or isinstance(started, bool)
                or not isinstance(finished, int)
                or isinstance(finished, bool)
                or started <= 0
                or finished <= started
            ):
                failures.append(f"{backend}: block {sequence} timestamps are invalid")
            if first.get("policy") == "baseline":
                baseline_sample_count += 1
                sample = first.get("baseline_sample_id")
                pair = first.get("comparison_pair_id")
                sample_key = (backend, sample) if isinstance(sample, str) else None
                pair_key = (backend, pair) if isinstance(pair, str) else None
                if sample_key is None or sample_key in baseline_ids:
                    failures.append(f"{backend}: baseline sample identity is duplicated")
                else:
                    baseline_ids.add(sample_key)
                if pair_key is None or pair_key in pair_ids:
                    failures.append(f"{backend}: comparison pair identity is duplicated")
                else:
                    pair_ids.add(pair_key)
                if any(row.get("comparison_gap_seconds") is not None for row in rows):
                    failures.append(f"{backend}: baseline block exposes a comparison gap")
            else:
                comparison_count += 1
                order = first.get("comparison_order")
                if order in order_counts:
                    order_counts[order] += 1
                else:
                    failures.append(f"{backend}: protected block has invalid pair order")
                repetition = first.get("comparison_repetition")
                pair = first.get("comparison_pair_id")
                sample = first.get("baseline_sample_id")
                if (
                    not isinstance(repetition, int)
                    or isinstance(repetition, bool)
                    or not isinstance(pair, str)
                    or not isinstance(sample, str)
                ):
                    failures.append(
                        f"{backend}: protected block has invalid independent-pair identity"
                    )
                else:
                    group = (
                        backend,
                        first.get("policy"),
                        first.get("mode"),
                        first.get("learning_variant"),
                        first.get("profile"),
                        float(first.get("load_level")),
                    )
                    protected_groups.setdefault(group, []).append(
                        (repetition, pair, sample, order)
                    )
                block_gaps = [row.get("comparison_gap_seconds") for row in rows]
                reported_gap = block_gaps[0] if block_gaps else None
                if (
                    any(value != reported_gap for value in block_gaps[1:])
                    or not isinstance(reported_gap, (int, float))
                    or isinstance(reported_gap, bool)
                    or not math.isfinite(float(reported_gap))
                    or float(reported_gap) < 0
                ):
                    failures.append(f"{backend}: protected block gap is invalid")
                else:
                    baseline_sequence = sequence - 1 if order == "ab" else sequence + 1
                    baseline_rows = block_rows.get((backend, baseline_sequence), [])
                    adjacent = baseline_rows[0] if baseline_rows else None
                    if (
                        not isinstance(adjacent, dict)
                        or adjacent.get("policy") != "baseline"
                        or adjacent.get("topology_role") != "baseline"
                        or adjacent.get("baseline_sample_id")
                        != first.get("baseline_sample_id")
                        or adjacent.get("comparison_pair_id")
                        != first.get("comparison_pair_id")
                        or adjacent.get("comparison_repetition")
                        != first.get("comparison_repetition")
                    ):
                        failures.append(
                            f"{backend}: protected block {sequence} lacks its adjacent baseline"
                        )
                    else:
                        baseline_started = adjacent.get("block_started_monotonic_ns")
                        baseline_finished = adjacent.get("block_finished_monotonic_ns")
                        block_order_valid = (
                            isinstance(started, int)
                            and not isinstance(started, bool)
                            and isinstance(finished, int)
                            and not isinstance(finished, bool)
                            and isinstance(baseline_started, int)
                            and not isinstance(baseline_started, bool)
                            and isinstance(baseline_finished, int)
                            and not isinstance(baseline_finished, bool)
                            and (
                                baseline_finished <= started
                                if order == "ab"
                                else finished <= baseline_started
                            )
                        )
                        if not block_order_valid:
                            failures.append(
                                f"{backend}: protected block {sequence} has invalid adjacent timestamps"
                            )
                        else:
                            baseline_steady = [
                                row
                                for row in baseline_rows
                                if row.get("phase_role") == "steady"
                            ]
                            protected_steady = [
                                row
                                for row in rows
                                if row.get("phase_role") == "steady"
                            ]
                            expected_gap = (
                                paired_steady_measurement_gap_seconds(
                                    baseline_steady[0], protected_steady[0], order
                                )
                                if len(baseline_steady) == 1
                                and len(protected_steady) == 1
                                else None
                            )
                            if expected_gap is None:
                                failures.append(
                                    f"{backend}: protected block {sequence} has invalid paired steady measurement boundaries"
                                )
                            elif not math.isclose(
                                float(reported_gap),
                                expected_gap,
                                rel_tol=0.0,
                                abs_tol=1e-9,
                            ):
                                failures.append(
                                    f"{backend}: protected block {sequence} gap differs from steady measurement timestamps"
                                )
                            else:
                                gaps.append(float(reported_gap))
                                if float(reported_gap) > float(
                                    config["criteria"][
                                        "maximum_comparison_gap_seconds"
                                    ]
                                ):
                                    failures.append(
                                        f"{backend}: protected block {sequence} "
                                        "comparison gap exceeds the configured bound"
                                    )

    repetitions = int(config["phases"]["steady"]["repetitions"])
    expected_repetitions = set(range(1, repetitions + 1))
    for group, samples in protected_groups.items():
        label = "/".join(str(component) for component in group)
        observed_repetitions = {sample[0] for sample in samples}
        observed_pairs = {sample[1] for sample in samples}
        observed_baselines = {sample[2] for sample in samples}
        observed_orders = [sample[3] for sample in samples]
        if (
            len(samples) != repetitions
            or observed_repetitions != expected_repetitions
            or len(observed_pairs) != repetitions
            or len(observed_baselines) != repetitions
        ):
            failures.append(f"{label}: independent comparison pair set is incomplete")
        ab_count = observed_orders.count("ab")
        ba_count = observed_orders.count("ba")
        if {"ab", "ba"} - set(observed_orders) or abs(ab_count - ba_count) > 1:
            failures.append(f"{label}: comparison pair order is not AB/BA balanced")

    return {
        "schema": BASELINE_PAIRING_SCHEMA,
        "strategy": "independent_order_balanced_ab_ba",
        "valid": not failures,
        "failure_reasons": sorted(set(failures)),
        "baseline_environments": baseline_environments,
        "environment_pairs": environment_pairs,
        "baseline_sample_count": baseline_sample_count,
        "comparison_count": comparison_count,
        "orders": order_counts,
        "maximum_gap_seconds": max(gaps) if gaps else None,
    }


def maximum_sustainable(
    results: list[dict[str, Any]],
    steady_repetitions: int,
    *,
    capacity_certification: bool,
    require_burst_capacity: bool,
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str | None, str | None, str], dict[float, list[dict[str, Any]]]] = {}
    bursts: dict[
        tuple[str, str, str | None, str | None, str, float],
        list[dict[str, Any]],
    ] = {}
    for result in results:
        if result["policy"] == "baseline":
            continue
        key = (
            result["backend"],
            result["policy"],
            result["mode"],
            result["learning_variant"],
            result["profile"],
        )
        level = float(result["load_level"])
        if result["phase_role"] == "steady":
            groups.setdefault(key, {}).setdefault(level, []).append(result)
        elif result["phase_role"] == "burst":
            bursts.setdefault((*key, level), []).append(result)
    output = []
    for key, levels in sorted(groups.items(), key=lambda item: tuple(str(part) for part in item[0])):
        sustainable: dict[str, Any] | None = None
        first_failing_level: float | None = None
        first_failing_reasons: list[str] = []
        for level in sorted(levels):
            windows = levels[level]
            application_rates = [
                numeric(
                    nested(
                        window,
                        "derived",
                        "actual_application_ops_per_second",
                    )
                )
                for window in windows
            ]
            cps_values = [
                numeric(nested(window, "derived", "actual_cps"))
                for window in windows
            ]
            rx_pps_values = [
                numeric(nested(window, "dut_metrics", "network", "rx_pps"))
                for window in windows
            ]
            tx_pps_values = [
                numeric(nested(window, "dut_metrics", "network", "tx_pps"))
                for window in windows
            ]
            flow_peaks = [
                numeric(nested(window, "derived", "active_flows_peak"))
                for window in windows
            ]
            transport = windows[0].get("transport") if windows else None
            required_measurements = [
                *application_rates,
                *rx_pps_values,
                *tx_pps_values,
                *flow_peaks,
            ]
            if transport == "tcp":
                required_measurements.extend(cps_values)
            measurements_available = all(
                value is not None and value >= 0
                for value in required_measurements
            )
            level_reasons: list[str] = []
            if len(windows) != steady_repetitions:
                level_reasons.append("steady repetition set is incomplete")
            if not measurements_available:
                level_reasons.append("required sustainable-capacity metric is unavailable")
            if any(window.get("valid") is not True for window in windows):
                level_reasons.append("one or more windows are invalid")
            if any(window.get("capacity_pass") is not True for window in windows):
                level_reasons.append("one or more windows failed capacity criteria")
            if any(window.get("safety_pass") is not True for window in windows):
                level_reasons.append("one or more windows failed safety criteria")
            if any(
                window.get("relative_performance_pass") is not True
                for window in windows
            ):
                level_reasons.append(
                    "one or more windows failed paired-baseline relative criteria"
                )
            if capacity_certification and require_burst_capacity:
                burst_windows = bursts.get((*key, level), [])
                if len(burst_windows) != 1:
                    level_reasons.append("required burst set is incomplete or duplicated")
                else:
                    burst = burst_windows[0]
                    if burst.get("valid") is not True:
                        level_reasons.append("required burst is invalid")
                    if burst.get("capacity_pass") is not True:
                        level_reasons.append("required burst failed capacity criteria")
                    if burst.get("safety_pass") is not True:
                        level_reasons.append("required burst failed safety criteria")
                    if burst.get("relative_performance_pass") is not True:
                        level_reasons.append(
                            "required burst failed paired-baseline relative criteria"
                        )
            if level_reasons:
                # Capacity is a contiguous sweep: once a lower offered level
                # fails, a later isolated pass cannot be called sustainable.
                first_failing_level = level
                first_failing_reasons = sorted(set(level_reasons))
                break
            sustainable = {
                "load_level": level,
                "actual_application_ops_per_second": min(application_rates),
                "actual_cps": min(cps_values)
                if transport == "tcp"
                else None,
                "dut_rx_pps": min(rx_pps_values),
                "dut_tx_pps": min(tx_pps_values),
                "active_flows_peak": max(flow_peaks),
            }
        backend, policy, mode, variant, profile = key
        output.append(
            {
                "backend": backend,
                "policy": policy,
                "mode": mode,
                "learning_variant": variant,
                "profile": profile,
                "steady_repetitions_required": steady_repetitions,
                "capacity_certification_requested": capacity_certification,
                "burst_capacity_required": (
                    capacity_certification and require_burst_capacity
                ),
                "capacity_qualified": (
                    capacity_certification
                    and steady_repetitions >= 3
                    and sustainable is not None
                ),
                "maximum_sustainable": sustainable,
                "first_failing_level": first_failing_level,
                "first_failing_reasons": first_failing_reasons,
            }
        )
    return output


CSV_FIELDS = [
    "backend",
    "policy",
    "mode",
    "learning_variant",
    "profile",
    "direction",
    "transport",
    "load_level",
    "phase",
    "phase_role",
    "phase_scale",
    "baseline_sample_id",
    "comparison_pair_id",
    "comparison_repetition",
    "comparison_order",
    "execution_sequence",
    "topology_role",
    "block_started_monotonic_ns",
    "block_finished_monotonic_ns",
    "comparison_gap_seconds",
    "valid",
    "passed",
    "safety_pass",
    "capacity_pass",
    "relative_performance_pass",
    "unreliable_reasons",
    "failure_reasons",
    "safety_failure_reasons",
    "relative_performance_failure_reasons",
    "target_ops_per_second",
    "actual_application_ops_per_second",
    "actual_application_mbps",
    "target_attainment_ratio",
    "actual_cps",
    "active_flows_peak",
    "latency_p50_ms",
    "latency_p95_ms",
    "latency_p99_ms",
    "connect_latency_p50_ms",
    "connect_latency_p95_ms",
    "connect_latency_p99_ms",
    "error_ratio",
    "udp_reply_loss_ratio",
    "udp_scenario_accounting_valid",
    "udp_scenario_packets_sent",
    "udp_scenario_packets_received",
    "udp_scenario_packet_loss",
    "udp_scenario_packet_loss_ratio",
    "udp_scenario_unexpected_packets",
    "udp_scenario_packet_matched",
    "udp_barriers_expected",
    "udp_barriers_sent",
    "udp_server_barriers_received",
    "udp_server_barrier_acks_sent",
    "udp_barrier_acks_received",
    "udp_barrier_errors",
    "udp_barriers_matched",
    "tcp_retransmits",
    "tcp_retransmits_per_tx_packet",
    "dut_rx_pps",
    "dut_tx_pps",
    "dut_rx_mbps",
    "dut_tx_mbps",
    "aggregate_dut_pps",
    "daemon_cpu_percent_one_core",
    "cgroup_cpu_percent_one_core",
    "daemon_rss_bytes_peak",
    "softirq_net_rx",
    "softirq_net_tx",
    "conntrack_count_peak",
    "nfqueue_hits",
    "nfqueue_depth_peak",
    "nfqueue_kernel_dropped",
    "nfqueue_user_dropped",
    "nfqueue_runtime_counters_valid",
    "nfqueue_queue_overflow_delta",
    "nfqueue_attribution_timeout_delta",
    "nfqueue_terminal_queue_error_delta",
    "nfqueue_denied_delta",
    "nfqueue_hits_per_connection",
    "nfqueue_hits_per_datagram",
    "identity_probe_fail_open",
    "quarantine_occurred",
    "application_ops_reduction_percent",
    "throughput_reduction_percent",
    "aggregate_dut_pps_reduction_percent",
    "latency_p50_increase_percent",
    "latency_p95_increase_percent",
    "latency_p99_increase_percent",
    "connect_latency_p50_increase_percent",
    "connect_latency_p95_increase_percent",
    "connect_latency_p99_increase_percent",
    "cgroup_cpu_increase_percent",
]

OVERLOAD_CSV_FIELDS = [
    "backend",
    "policy",
    "mode",
    "profile",
    "canary_profile",
    "transport",
    "probe_transport",
    "valid",
    "passed",
    "safety_pass",
    "recovery_pass",
    "pressure_start_gate_ready",
    "resource_valid",
    "allowed_preflight_pass",
    "network_liveness_preflight_pass",
    "wrong_executable_preflight_blocked",
    "saturation_proven",
    "stall_kernel_drops",
    "stall_user_drops",
    "stall_total_drops",
    "timestamps_ordered",
    "during_stall_blocked_all",
    "during_stall_fail_open",
    "during_stall_liveness_pass",
    "after_resume_blocked",
    "after_resume_liveness_pass",
    "quarantine_reported",
    "quarantine_occurred",
    "kernel_block_all",
    "quarantine_black_box_pass",
    "validity_failure_reasons",
    "safety_failure_reasons",
    "recovery_failure_reasons",
]


def csv_row(result: dict[str, Any]) -> dict[str, Any]:
    row = {key: result.get(key) for key in CSV_FIELDS}
    mappings = {
        "target_ops_per_second": ("derived", "expected_application_ops_per_second"),
        "actual_application_ops_per_second": ("derived", "actual_application_ops_per_second"),
        "actual_application_mbps": ("derived", "actual_application_mbps"),
        "target_attainment_ratio": ("derived", "target_attainment_ratio"),
        "actual_cps": ("derived", "actual_cps"),
        "active_flows_peak": ("derived", "active_flows_peak"),
        "latency_p50_ms": ("derived", "latency_p50_ms"),
        "latency_p95_ms": ("derived", "latency_p95_ms"),
        "latency_p99_ms": ("derived", "latency_p99_ms"),
        "connect_latency_p50_ms": ("derived", "connect_latency_p50_ms"),
        "connect_latency_p95_ms": ("derived", "connect_latency_p95_ms"),
        "connect_latency_p99_ms": ("derived", "connect_latency_p99_ms"),
        "error_ratio": ("derived", "error_ratio"),
        "udp_reply_loss_ratio": ("derived", "udp_reply_loss_ratio"),
        "udp_scenario_accounting_valid": (
            "udp_scenario_accounting",
            "valid",
        ),
        "udp_scenario_packets_sent": (
            "udp_scenario_accounting",
            "client_packets_sent",
        ),
        "udp_scenario_packets_received": (
            "udp_scenario_accounting",
            "server_packets_received",
        ),
        "udp_scenario_packet_loss": (
            "udp_scenario_accounting",
            "packet_loss",
        ),
        "udp_scenario_packet_loss_ratio": (
            "udp_scenario_accounting",
            "packet_loss_ratio",
        ),
        "udp_scenario_unexpected_packets": (
            "udp_scenario_accounting",
            "unexpected_packets",
        ),
        "udp_scenario_packet_matched": (
            "udp_scenario_accounting",
            "packet_matched",
        ),
        "udp_barriers_expected": (
            "udp_scenario_accounting",
            "client_barriers_expected",
        ),
        "udp_barriers_sent": (
            "udp_scenario_accounting",
            "client_barriers_sent",
        ),
        "udp_server_barriers_received": (
            "udp_scenario_accounting",
            "server_barriers_received",
        ),
        "udp_server_barrier_acks_sent": (
            "udp_scenario_accounting",
            "server_barrier_acks_sent",
        ),
        "udp_barrier_acks_received": (
            "udp_scenario_accounting",
            "client_barrier_acks_received",
        ),
        "udp_barrier_errors": (
            "udp_scenario_accounting",
            "client_barrier_errors",
        ),
        "udp_barriers_matched": (
            "udp_scenario_accounting",
            "barriers_matched",
        ),
        "tcp_retransmits": ("dut_metrics", "tcp_retransmits"),
        "tcp_retransmits_per_tx_packet": ("derived", "tcp_retransmits_per_tx_packet"),
        "dut_rx_pps": ("dut_metrics", "network", "rx_pps"),
        "dut_tx_pps": ("dut_metrics", "network", "tx_pps"),
        "dut_rx_mbps": ("dut_metrics", "network", "rx_mbps"),
        "dut_tx_mbps": ("dut_metrics", "network", "tx_mbps"),
        "aggregate_dut_pps": ("derived", "aggregate_dut_pps"),
        "daemon_cpu_percent_one_core": ("dut_metrics", "daemon", "cpu_percent_one_core"),
        "cgroup_cpu_percent_one_core": ("dut_metrics", "cgroup", "cpu_percent_one_core"),
        "daemon_rss_bytes_peak": ("dut_metrics", "daemon", "rss_bytes_peak"),
        "softirq_net_rx": ("dut_metrics", "softirq", "net_rx"),
        "softirq_net_tx": ("dut_metrics", "softirq", "net_tx"),
        "conntrack_count_peak": ("dut_metrics", "conntrack_count_peak"),
        "nfqueue_hits": ("dut_metrics", "nfqueue", "hits"),
        "nfqueue_depth_peak": ("dut_metrics", "nfqueue", "depth_peak"),
        "nfqueue_kernel_dropped": ("dut_metrics", "nfqueue", "kernel_dropped"),
        "nfqueue_user_dropped": ("dut_metrics", "nfqueue", "user_dropped"),
        "nfqueue_runtime_counters_valid": ("nfqueue_runtime_counters", "valid"),
        "nfqueue_queue_overflow_delta": (
            "nfqueue_runtime_counters",
            "delta",
            "queue_overflow",
        ),
        "nfqueue_attribution_timeout_delta": (
            "nfqueue_runtime_counters",
            "delta",
            "attribution_timeout",
        ),
        "nfqueue_terminal_queue_error_delta": (
            "nfqueue_runtime_counters",
            "delta",
            "terminal_queue_error",
        ),
        "nfqueue_denied_delta": (
            "nfqueue_runtime_counters",
            "delta",
            "denied",
        ),
        "nfqueue_hits_per_connection": ("derived", "nfqueue_hits_per_connection"),
        "nfqueue_hits_per_datagram": ("derived", "nfqueue_hits_per_datagram"),
        "identity_probe_fail_open": ("identity_probe", "fail_open"),
        "quarantine_occurred": ("quarantine", "occurred"),
        "application_ops_reduction_percent": ("overhead_vs_baseline", "application_ops_reduction_percent"),
        "throughput_reduction_percent": ("overhead_vs_baseline", "throughput_reduction_percent"),
        "aggregate_dut_pps_reduction_percent": ("overhead_vs_baseline", "aggregate_dut_pps_reduction_percent"),
        "latency_p50_increase_percent": ("overhead_vs_baseline", "latency_p50_increase_percent"),
        "latency_p95_increase_percent": ("overhead_vs_baseline", "latency_p95_increase_percent"),
        "latency_p99_increase_percent": ("overhead_vs_baseline", "latency_p99_increase_percent"),
        "connect_latency_p50_increase_percent": ("overhead_vs_baseline", "connect_latency_p50_increase_percent"),
        "connect_latency_p95_increase_percent": ("overhead_vs_baseline", "connect_latency_p95_increase_percent"),
        "connect_latency_p99_increase_percent": ("overhead_vs_baseline", "connect_latency_p99_increase_percent"),
        "cgroup_cpu_increase_percent": ("overhead_vs_baseline", "cgroup_cpu_increase_percent"),
    }
    for key, path in mappings.items():
        row[key] = nested(result, *path)
    for key in (
        "unreliable_reasons",
        "failure_reasons",
        "safety_failure_reasons",
        "relative_performance_failure_reasons",
    ):
        row[key] = " | ".join(result.get(key, []))
    return row


def write_csv(path: Path, results: list[dict[str, Any]]) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for result in results:
                writer.writerow(csv_row(result))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def overload_csv_row(result: dict[str, Any]) -> dict[str, Any]:
    row = {key: result.get(key) for key in OVERLOAD_CSV_FIELDS}
    mappings = {
        "pressure_start_gate_ready": ("pressure_start_gate", "event"),
        "resource_valid": ("resource_validity", "valid"),
        "allowed_preflight_pass": ("allowed_preflight", "passed"),
        "network_liveness_preflight_pass": (
            "network_liveness_preflight",
            "passed",
        ),
        "wrong_executable_preflight_blocked": (
            "identity_probe_preflight",
            "blocked",
        ),
        "saturation_proven": ("saturation", "proven"),
        "stall_kernel_drops": (
            "saturation",
            "stall_drop_delta",
            "kernel_dropped",
        ),
        "stall_user_drops": (
            "saturation",
            "stall_drop_delta",
            "user_dropped",
        ),
        "stall_total_drops": ("saturation", "stall_drop_delta", "total"),
        "timestamps_ordered": ("saturation", "timestamps_ordered"),
        "during_stall_blocked_all": (
            "identity_probe_during_stall",
            "blocked_all",
        ),
        "during_stall_fail_open": (
            "identity_probe_during_stall",
            "fail_open",
        ),
        "during_stall_liveness_pass": (
            "identity_probe_during_stall",
            "liveness_passed",
        ),
        "after_resume_blocked": ("identity_probe_after_resume", "blocked"),
        "after_resume_liveness_pass": (
            "network_liveness_after_resume",
            "passed",
        ),
        "quarantine_reported": ("quarantine", "reported"),
        "quarantine_occurred": ("quarantine", "occurred"),
        "kernel_block_all": ("quarantine", "kernel_block_all"),
        "quarantine_black_box_pass": ("quarantine", "black_box", "passed"),
    }
    for key, path in mappings.items():
        row[key] = nested(result, *path)
    row["pressure_start_gate_ready"] = (
        row["pressure_start_gate_ready"] == "ready"
    )
    for key in (
        "validity_failure_reasons",
        "safety_failure_reasons",
        "recovery_failure_reasons",
    ):
        row[key] = " | ".join(result.get(key, []))
    return row


def write_overload_csv(path: Path, results: list[dict[str, Any]]) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(
                stream, fieldnames=OVERLOAD_CSV_FIELDS, extrasaction="ignore"
            )
            writer.writeheader()
            for result in results:
                writer.writerow(overload_csv_row(result))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def markdown_report(report: dict[str, Any]) -> str:
    outcome = "PASS" if report["passed"] and report["valid"] else "FAIL"
    cpu_latency_action = nested(
        report,
        "relative_performance_methodology",
        "cpu_latency_release_action",
        default="fail",
    )
    pairing = report.get("baseline_pairing", {})
    pairing_gap = numeric(pairing.get("maximum_gap_seconds"))
    pairing_gap_display = (
        "unavailable" if pairing_gap is None else f"{pairing_gap:.6f} s"
    )
    lines = [
        "# OpenShield performance report",
        "",
        f"Overall result: **{outcome}**",
        "",
        f"- Run ID: `{report['run_id']}`",
        f"- Seed: `{report['seed']}`",
        f"- Daemon SHA-256: `{report.get('daemon', {}).get('sha256', 'unavailable')}`",
        f"- Harness manifest SHA-256: `{nested(report, 'harness', 'manifest_sha256', default='unavailable')}`",
        f"- Runtime source bundle SHA-256: `{nested(report, 'harness', 'runtime_bundle', 'manifest_sha256', default='unavailable')}`",
        f"- Results: {len(report['results'])}",
        f"- Controlled overload proofs: {len(report.get('overload_results', []))}",
        f"- Controlled overload plan complete: {report.get('overload_plan_complete', False)}",
        f"- Environment consistency: {nested(report, 'environment_consistency', 'valid', default=False)}",
        f"- Pristine AB/BA pairing: {pairing.get('valid', False)}",
        f"- Baseline samples/protected comparisons: {pairing.get('baseline_sample_count', 0)}/{pairing.get('comparison_count', 0)}",
        f"- Maximum paired steady-window gap: {pairing_gap_display}",
        f"- Estimated configured workload time: {report['estimated_workload_seconds']:.1f} s",
        f"- Relative performance method: adjacent independent AB/BA paired deltas; the arithmetic mean from at least three steady pairs gates metrics assigned `fail`. CPU/latency action for this profile: `{cpu_latency_action}`; throughput/PPS remain blocking. A one-sided 95% Student-t lower confidence bound records stronger confirmation.",
        "",
        "## Environment evidence",
        "",
        "The image is content-pinned. The signed live Tumbleweed repository can change between runs, so the exact repo metadata digest and sorted RPM NEVRA manifest are recorded for each backend; publish-grade numeric comparisons require a prebuilt pinned performance image and a dedicated runner.",
        "",
        "| Backend | Image ID | uname/kernel | repo-oss repomd SHA-256 | RPM manifest SHA-256 |",
        "|---|---|---|---|---|",
    ]
    for environment in report.get("environments", []):
        lines.append(
            "| {backend} | `{image}` | `{uname}` | `{repo}` | `{rpm}` |".format(
                backend=environment.get("backend", "—"),
                image=environment.get("image_id", "unavailable"),
                uname=environment.get("uname", "unavailable"),
                repo=environment.get("repo_oss_repomd_sha256", "unavailable"),
                rpm=environment.get("rpm_manifest_sha256", "unavailable"),
            )
        )
    lines.extend(
        [
        "",
        "## Pristine baseline pairing",
        "",
        "Protected blocks are paired only with the predetermined adjacent sample from a separate pristine DUT generation. The OpenShield daemon is never started on that baseline DUT; exact environment equality and distinct Docker identities are mandatory.",
        "",
        "| Backend | Strategy | Pair valid | Baseline DUT daemon started | Baseline DUT ID | Protected DUT ID |",
        "|---|---|---:|---:|---|---|",
        ]
    )
    environment_pairs = pairing.get("environment_pairs", [])
    if not environment_pairs:
        lines.append("| — | — | no | — | — | — |")
    for environment_pair in environment_pairs:
        lines.append(
            "| {backend} | {strategy} | {valid} | {started} | `{baseline}` | `{protected}` |".format(
                backend=environment_pair.get("backend", "—"),
                strategy=pairing.get("strategy", "—"),
                valid="yes" if environment_pair.get("valid") else "no",
                started=(
                    "yes"
                    if environment_pair.get("baseline_daemon_started") is True
                    else "no"
                    if environment_pair.get("baseline_daemon_started") is False
                    else "unknown"
                ),
                baseline=environment_pair.get("baseline_client_id", "unavailable"),
                protected=environment_pair.get("protected_client_id", "unavailable"),
            )
        )
    lines.extend(
        [
        "",
        "## Backend gates",
        "",
        "| Backend | Status | Reason |",
        "|---|---|---|",
        ]
    )
    for backend in report["backends"]:
        lines.append(
            f"| {backend['name']} | {backend['status']} | {backend.get('reason') or ''} |"
        )
    lines.extend(
        [
            "",
            "## Controlled NFQUEUE overload safety",
            "",
            "The consumer is paused only inside the disposable DUT. Real application sockets fill the bounded queue; a valid proof requires observed queue drops and no successful wrong-executable round trip.",
            "",
            "| Backend | Transport | Saturation | Queue drops | Fail-closed | Quarantine | Recovery |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
    )
    overload_results = report.get("overload_results", [])
    if not overload_results:
        lines.append("| — | — | no | — | no | — | — |")
    for result in overload_results:
        lines.append(
            "| {backend} | {transport} | {saturation} | {drops} | {closed} | {quarantine} | {recovery} |".format(
                backend=result.get("backend", "—"),
                transport=result.get("transport", "—"),
                saturation="yes" if nested(result, "saturation", "proven") else "no",
                drops=nested(
                    result,
                    "saturation",
                    "stall_drop_delta",
                    "total",
                    default="—",
                ),
                closed="yes" if result.get("safety_pass") else "no",
                quarantine="yes" if nested(result, "quarantine", "occurred") else "no",
                recovery=(
                    "safe BlockAll"
                    if result.get("recovery_pass") is None
                    and nested(result, "quarantine", "kernel_block_all") is True
                    else ("yes" if result.get("recovery_pass") else "no")
                ),
            )
        )
    lines.extend(
        [
            "",
            "## Maximum sustainable configured points",
            "",
            "A point is capacity-qualified only when capacity certification is enabled, "
            "at least three steady windows pass, and any required matching burst passes. "
            "The CI smoke validates paths and safety but does not certify a capacity maximum.",
            "",
            "| Backend | Policy | Mode | Profile | Qualified | Load | DUT RX/TX PPS | App ops/s | CPS | Flows |",
            "|---|---|---|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for item in report["maximum_sustainable"]:
        point = item["maximum_sustainable"] or {}
        rx = point.get("dut_rx_pps")
        tx = point.get("dut_tx_pps")
        pps = "—" if rx is None else f"{rx:.1f}/{tx:.1f}"
        lines.append(
            "| {backend} | {policy} | {mode} | {profile} | {qualified} | {load} | {pps} | {ops} | {cps} | {flows} |".format(
                backend=item["backend"],
                policy=item["policy"],
                mode=item["mode"] or "—",
                profile=item["profile"],
                qualified="yes" if item["capacity_qualified"] else "no",
                load=point.get("load_level", "—"),
                pps=pps,
                ops="—" if point.get("actual_application_ops_per_second") is None else f"{point['actual_application_ops_per_second']:.1f}",
                cps="—" if point.get("actual_cps") is None else f"{point['actual_cps']:.1f}",
                flows="—" if point.get("active_flows_peak") is None else f"{point['active_flows_peak']:.0f}",
            )
        )
    failed = [result for result in report["results"] if not result["passed"] or not result["valid"]]
    lines.extend(
        [
            "",
            "## Invalid or failed windows",
            "",
        ]
    )
    if not failed:
        lines.append("None.")
    else:
        for result in failed[:100]:
            reasons = sorted(
                set(
                    result["safety_failure_reasons"]
                    + result["failure_reasons"]
                    + result.get("relative_performance_failure_reasons", [])
                    + result["unreliable_reasons"]
                )
            )
            lines.append(
                f"- `{result['backend']}/{result['policy']}/{result['mode'] or 'baseline'}/"
                f"{result['profile']}/{result['phase']}`: {'; '.join(reasons) or 'failed'}"
            )
        if len(failed) > 100:
            lines.append(f"- … {len(failed) - 100} additional rows are available in CSV/JSON.")
    observed = [
        result
        for result in report["results"]
        if result.get("relative_performance_observation_reasons")
    ]
    lines.extend(
        [
            "",
            "## Per-window relative observations",
            "",
            "These paired windows crossed a configured threshold. They remain visible; an independent steady-pair mean blocks only metrics assigned `fail` (throughput/PPS are always blocking, while CPU/latency follow this profile's explicit action). The 95% lower confidence bound records stronger confirmation. A single burst cannot establish statistical confidence, but directly blocks every threshold crossing assigned `fail` and remains a capacity and safety gate.",
            "",
        ]
    )
    if not observed:
        lines.append("None.")
    else:
        for result in observed[:100]:
            lines.append(
                f"- `{result['backend']}/{result['policy']}/{result['mode'] or 'baseline'}/"
                f"{result['profile']}/{result['phase']}`: "
                f"{'; '.join(result['relative_performance_observation_reasons'])}"
            )
        if len(observed) > 100:
            lines.append(
                f"- … {len(observed) - 100} additional observations are available in CSV/JSON."
            )
    failed_overload = [
        result
        for result in overload_results
        if result.get("valid") is not True or result.get("passed") is not True
    ]
    for result in failed_overload:
        reasons = (
            result.get("validity_failure_reasons", [])
            + result.get("safety_failure_reasons", [])
            + result.get("recovery_failure_reasons", [])
        )
        lines.append(
            f"- `{result.get('backend')}/overload/{result.get('transport')}`: "
            f"{'; '.join(reasons) or 'failed'}"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- TCP/UDP use real sockets and processes across two container network namespaces; no handcrafted TCP packets are injected.",
            "- NIC PPS/Mbps come from interface counters. Workload operations/s and application bytes/s are reported separately and are not called packet rate.",
            "- DUT NFQUEUE hits and exact kernel/user drops come from the explicitly selected queue in `/proc/net/netfilter/nfnetlink_queue`: 1337 for baseline/Enforcing and 1338 for observational Learning; controlled overload remains on enforcing queue 1337.",
            "- Daemon attribution/error messages are rate-limited, so parsed log counts are explicitly lower bounds.",
            "- Softirq counters are host-wide and require paired-baseline interpretation on a quiet runner.",
            "- TCP connect p50/p95/p99 are paired separately so SYN/NFQUEUE attribution latency cannot hide behind request latency.",
            "- Generator or peer saturation invalidates the affected result instead of being attributed to OpenShield.",
            "",
        ]
    )
    return "\n".join(lines)


def write_text(path: Path, value: str) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def validate_daemon(path: Path) -> dict[str, Any]:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise HarnessError("daemon must be an absolute regular non-symlink file")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode != 0o755:
        raise HarnessError(f"daemon mode must be exactly 0755, got {mode:04o}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return {"path": str(path), "sha256": digest.hexdigest(), "size": path.stat().st_size}


def capture_harness_evidence(repository: Path) -> dict[str, Any]:
    """Hash the exact bounded source set that generated the measurements."""

    components: list[dict[str, Any]] = []
    manifest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    for relative in HARNESS_COMPONENT_PATHS:
        path = repository / relative
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise HarnessError(f"cannot open harness component {relative}: {error}") from error
        digest = hashlib.sha256()
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > MAX_HARNESS_COMPONENT_BYTES
            ):
                raise HarnessError(
                    f"harness component is not a bounded singly linked file: {relative}"
                )
            observed = 0
            while chunk := os.read(descriptor, 1024 * 1024):
                observed += len(chunk)
                if observed > MAX_HARNESS_COMPONENT_BYTES:
                    raise HarnessError(f"harness component grew beyond its bound: {relative}")
                digest.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        if identity_before != identity_after or observed != before.st_size:
            raise HarnessError(f"harness component changed while hashing: {relative}")
        component_digest = digest.hexdigest()
        manifest.update(relative.encode("ascii"))
        manifest.update(b"\0")
        manifest.update(str(observed).encode("ascii"))
        manifest.update(b"\0")
        manifest.update(component_digest.encode("ascii"))
        manifest.update(b"\n")
        components.append(
            {"path": relative, "size": observed, "sha256": component_digest}
        )
    environment_component = next(
        (
            component
            for component in components
            if component["path"] == "tests/perf/environment.py"
        ),
        None,
    )
    if environment_component != _ENVIRONMENT_SOURCE_EVIDENCE:
        raise HarnessError(
            "loaded environment source differs from the harness manifest"
        )
    return {
        "schema": "openshield.perf.harness-evidence.v1",
        "manifest_sha256": manifest.hexdigest(),
        "components": components,
    }


def stage_runtime_bundle(
    repository: Path,
    bundle_root: Path,
    harness_evidence: dict[str, Any],
) -> dict[str, Any]:
    """Create the exact source-only tree mounted into workload containers."""

    if not bundle_root.is_absolute() or bundle_root.exists() or bundle_root.is_symlink():
        raise HarnessError("runtime bundle path must be a new absolute path")
    component_evidence = {
        component.get("path"): component
        for component in harness_evidence.get("components", [])
        if isinstance(component, dict)
    }
    if set(component_evidence) != set(HARNESS_COMPONENT_PATHS):
        raise HarnessError("harness evidence cannot seed the runtime bundle")
    bundle_root.mkdir(mode=0o700)
    workload_root = bundle_root / "workloads"
    workload_root.mkdir(mode=0o700)
    components: list[dict[str, Any]] = []
    source_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for source_relative, runtime_relative in RUNTIME_BUNDLE_COMPONENTS:
        source = repository / source_relative
        try:
            source_descriptor = os.open(source, source_flags)
        except OSError as error:
            raise HarnessError(
                f"cannot open runtime component {source_relative}: {error}"
            ) from error
        payload = bytearray()
        try:
            before = os.fstat(source_descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size <= 0
                or before.st_size > MAX_HARNESS_COMPONENT_BYTES
            ):
                raise HarnessError(
                    f"runtime component is not a bounded singly linked file: {source_relative}"
                )
            while chunk := os.read(source_descriptor, 1024 * 1024):
                payload.extend(chunk)
                if len(payload) > MAX_HARNESS_COMPONENT_BYTES:
                    raise HarnessError(
                        f"runtime component grew beyond its bound: {source_relative}"
                    )
            after = os.fstat(source_descriptor)
        finally:
            os.close(source_descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or len(payload) != before.st_size
        ):
            raise HarnessError(
                f"runtime component changed while staging: {source_relative}"
            )
        digest = hashlib.sha256(payload).hexdigest()
        expected = component_evidence[source_relative]
        if expected != {
            "path": source_relative,
            "size": len(payload),
            "sha256": digest,
        }:
            raise HarnessError(
                f"runtime component differs from harness evidence: {source_relative}"
            )
        destination = bundle_root / runtime_relative
        destination_descriptor = os.open(
            destination, destination_flags, 0o444
        )
        try:
            offset = 0
            while offset < len(payload):
                offset += os.write(destination_descriptor, payload[offset:])
            os.fchmod(destination_descriptor, 0o444)
            os.fsync(destination_descriptor)
        finally:
            os.close(destination_descriptor)
        components.append(
            {
                "path": runtime_relative,
                "source_path": source_relative,
                "size": len(payload),
                "sha256": digest,
            }
        )
    manifest_document = {
        "schema": RUNTIME_BUNDLE_SCHEMA,
        "container_root": CONTAINER_PERF_ROOT,
        "python_flags": ["-I", "-B", "-S"],
        "source_only": True,
        "entrypoints": sorted(RUNTIME_PYTHON_ENTRYPOINTS),
        "components": components,
    }
    manifest_payload = json.dumps(
        manifest_document,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    manifest_path = bundle_root / RUNTIME_BUNDLE_MANIFEST
    manifest_descriptor = os.open(manifest_path, destination_flags, 0o444)
    try:
        offset = 0
        while offset < len(manifest_payload):
            offset += os.write(manifest_descriptor, manifest_payload[offset:])
        os.fchmod(manifest_descriptor, 0o444)
        os.fsync(manifest_descriptor)
    finally:
        os.close(manifest_descriptor)
    os.chmod(workload_root, 0o555)
    os.chmod(bundle_root, 0o555)
    return {
        **manifest_document,
        "manifest_path": RUNTIME_BUNDLE_MANIFEST,
        "manifest_sha256": hashlib.sha256(manifest_payload).hexdigest(),
    }


def validate_output_directory(path: Path) -> None:
    if not path.is_absolute() or path.is_symlink():
        raise HarnessError("output directory must be absolute and must not be a symlink")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    if not path.is_dir():
        raise HarnessError("output path is not a directory")
    for name in ("report.json", "report.csv", "overload.csv", "report.md"):
        target = path / name
        if target.exists() or target.is_symlink():
            raise HarnessError(f"refusing to overwrite existing report: {target}")


def verify_docker() -> dict[str, Any]:
    context = subprocess.run(
        ["docker", "context", "inspect", "--format", '{{(index .Endpoints "docker").Host}}'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=False,
    )
    if context.returncode != 0 or not context.stdout.strip().startswith("unix:///"):
        raise HarnessError("a local Unix-socket Docker context is required")
    version = subprocess.run(
        ["docker", "version", "--format", "{{json .Server}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=15,
        check=False,
    )
    if version.returncode != 0:
        raise HarnessError("local Docker engine is unavailable")
    try:
        server = json.loads(version.stdout)
    except json.JSONDecodeError as error:
        raise HarnessError("Docker returned malformed version metadata") from error
    return {"context": context.stdout.strip(), "server": server}


def backend_passed(results: list[dict[str, Any]], criteria: dict[str, Any]) -> bool:
    steady = [result for result in results if result["phase_role"] == "steady"]
    bursts = [result for result in results if result["phase_role"] == "burst"]
    if not steady or not bursts:
        return False
    # The release wrapper requires every executed sample to be valid and
    # passing. Keep the runner's own exit status identical: a malformed or
    # saturated warm-up/ramp sample must not produce report.valid=true only to
    # be rejected by the independent validator afterwards.
    if any(not result["valid"] or not result["passed"] for result in results):
        return False
    return True


def overload_backend_passed(
    results: list[dict[str, Any]], enabled: bool
) -> bool:
    if not enabled:
        return not results
    transports = [result.get("transport") for result in results]
    return len(transports) == 2 and set(transports) == {"tcp", "udp"} and all(
        result.get("valid") is True
        and result.get("safety_pass") is True
        and result.get("passed") is True
        for result in results
    )


def overload_plan_is_exact(
    results: list[dict[str, Any]],
    backends: list[dict[str, Any]],
    enabled: bool,
) -> bool:
    if not enabled:
        return not results
    expected = {
        (backend.get("name"), transport)
        for backend in backends
        if backend.get("status") != "unsupported"
        for transport in ("tcp", "udp")
    }
    actual = [
        (result.get("backend"), result.get("transport")) for result in results
    ]
    return len(actual) == len(expected) and set(actual) == expected


def environment_consistency_evidence(
    environments: list[dict[str, Any]], required_backends: list[str]
) -> dict[str, Any]:
    """Compare topology identity while retaining intentional package differences."""

    reasons: list[str] = []
    by_backend: dict[str, dict[str, Any]] = {}
    for evidence in environments:
        backend = evidence.get("backend") if isinstance(evidence, dict) else None
        if not isinstance(backend, str) or backend in by_backend:
            reasons.append("environment backend identity is missing or duplicated")
            continue
        by_backend[backend] = evidence
    if set(by_backend) != set(required_backends) or len(environments) != len(
        required_backends
    ):
        reasons.append("environment evidence does not cover every configured backend exactly once")
    compared_fields = (
        "image_reference",
        "image_id",
        "os_release",
        "uname",
        "machine",
        "repo_oss_repomd_sha256",
    )
    for field in compared_fields:
        values = [
            json.dumps(by_backend[backend].get(field), sort_keys=True)
            for backend in required_backends
            if backend in by_backend
        ]
        if len(values) != len(required_backends) or len(set(values)) != 1:
            reasons.append(f"backend environments disagree on {field}")

    rpm_sets: dict[str, set[str]] = {}
    package_names: dict[str, set[str]] = {}
    for backend, evidence in by_backend.items():
        records = evidence.get("rpm_nevra")
        if (
            not isinstance(records, list)
            or not records
            or any(not isinstance(record, str) for record in records)
        ):
            reasons.append(f"{backend} RPM manifest is unavailable")
            continue
        rpm_sets[backend] = set(records)
        package_names[backend] = {record.split("|", 1)[0] for record in records}
    nft_names = package_names.get("nftables", set())
    iptables_names = package_names.get("iptables", set())
    nft_only_nevra = sorted(
        rpm_sets.get("nftables", set()) - rpm_sets.get("iptables", set())
    )
    iptables_only_nevra = sorted(
        rpm_sets.get("iptables", set()) - rpm_sets.get("nftables", set())
    )
    nft_only_names = {record.split("|", 1)[0] for record in nft_only_nevra}
    exact_nft_delta = (
        len(nft_only_nevra) == len(EXPECTED_NFTABLES_ONLY_PACKAGE_NAMES)
        and nft_only_names == EXPECTED_NFTABLES_ONLY_PACKAGE_NAMES
        and not iptables_only_nevra
    )
    if (
        set(required_backends) == {"nftables", "iptables"}
        and not exact_nft_delta
    ):
        reasons.append(
            "backend RPM manifests differ outside the exact nftables dependency allowlist"
        )
    for backend in required_backends:
        if backend in package_names and "iptables" not in package_names[backend]:
            reasons.append(f"{backend} topology lacks the required iptables package")
    package_delta = {
        "expectation": (
            "only the pinned nftables dependency closure may differ between topologies"
        ),
        "expected_nftables_only_package_names": sorted(
            EXPECTED_NFTABLES_ONLY_PACKAGE_NAMES
        ),
        "observed_nftables_only_package_names": sorted(nft_only_names),
        "expected_nftables_delta_observed": exact_nft_delta,
        "nftables_only_nevra": nft_only_nevra,
        "iptables_only_nevra": iptables_only_nevra,
        "full_manifest_equality_required": False,
    }
    return {
        "schema": "openshield.perf.environment-consistency.v1",
        "required_backends": list(required_backends),
        "compared_equal_fields": list(compared_fields),
        "package_delta": package_delta,
        "valid": not reasons,
        "failure_reasons": sorted(set(reasons)),
    }


def resolve_run_token(value: str | None) -> str:
    """Return one unguessable label token or validate an orchestrator token."""

    token = secrets.token_hex(16) if value is None else value
    if not RUN_TOKEN_PATTERN.fullmatch(token):
        raise HarnessError("run token must be exactly 32 lowercase hexadecimal characters")
    return token


def run_harness(
    config: dict[str, Any],
    daemon: Path,
    output: Path,
    run_token: str | None = None,
) -> dict[str, Any]:
    repository = Path(__file__).resolve().parents[2]
    token = resolve_run_token(run_token)
    daemon_metadata = validate_daemon(daemon)
    harness_evidence = capture_harness_evidence(repository)
    runtime_bundle = output / "runtime-bundle"
    runtime_bundle_evidence = stage_runtime_bundle(
        repository, runtime_bundle, harness_evidence
    )
    harness_evidence["runtime_bundle"] = runtime_bundle_evidence
    docker_metadata = verify_docker()
    run_id = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{token}"
    canonical_config = json.dumps(
        config, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    all_results: list[dict[str, Any]] = []
    all_overload_results: list[dict[str, Any]] = []
    backend_results: list[dict[str, Any]] = []
    environments: list[dict[str, Any]] = []
    baseline_environments: list[dict[str, Any]] = []
    generation_pairs: list[dict[str, Any]] = []
    for backend in config["backends"]:
        baseline_topology = DockerBackendRun(
            repository,
            daemon,
            output,
            runtime_bundle,
            runtime_bundle_evidence["manifest_sha256"],
            config,
            backend,
            token,
            "baseline",
        )
        topology = DockerBackendRun(
            repository,
            daemon,
            output,
            runtime_bundle,
            runtime_bundle_evidence["manifest_sha256"],
            config,
            backend,
            token,
            "protected",
        )
        current: list[dict[str, Any]] = []
        current_overload: list[dict[str, Any]] = []
        generation_pair: dict[str, Any] | None = None
        try:
            print(
                f"==> OpenShield perf: prepare {backend} pristine baseline topology",
                flush=True,
            )
            baseline_topology.setup()
            print(
                f"==> OpenShield perf: prepare {backend} protected topology",
                flush=True,
            )
            topology.setup()
            if not isinstance(
                baseline_topology.environment_evidence, dict
            ) or not isinstance(topology.environment_evidence, dict):
                raise HarnessError("paired topologies did not capture environment evidence")
            baseline_environments.append(baseline_topology.environment_evidence)
            environments.append(topology.environment_evidence)
            generation_pair = {
                "backend": backend,
                "baseline_client_id": baseline_topology.client_id,
                "protected_client_id": topology.client_id,
                "baseline_daemon_started": baseline_topology.daemon_started,
            }
            generation_pairs.append(generation_pair)
            # Detect an unsupported backend before emitting a partial AB/BA
            # matrix.  The separate pristine topology remains daemon-free.
            topology.start_daemon()
            for scenario, load_level in paired_load_plan(config, backend):
                target = (
                    baseline_topology
                    if scenario["topology_role"] == "baseline"
                    else topology
                )
                print(
                    f"==> OpenShield perf: {backend} seq={scenario['execution_sequence']} "
                    f"{scenario['topology_role']} {scenario['policy']} "
                    f"{scenario['mode'] or 'none'} {scenario['profile']['name']} "
                    f"load={load_level:g} pair={scenario['comparison_pair_id']} "
                    f"repeat={scenario['comparison_repetition']} "
                    f"baseline={scenario['baseline_sample_id']}",
                    flush=True,
                )
                target.run_load_block(scenario, load_level, current)
            # Attribute process-lifetime NFQUEUE counter changes either to the
            # measured phase or to the one adjacent unmeasured gap.  This must
            # run before overload intentionally exercises queue failures.
            apply_nfqueue_counter_continuity(current, config["criteria"])
            if config["overload"]["enabled"]:
                for transport in ("tcp", "udp"):
                    profile = next(
                        profile
                        for profile in config["profiles"]
                        if profile["direction"] == "outbound"
                        and profile["transport"] == transport
                        and f"application_{transport}" in profile["policy_cases"]
                    )
                    print(
                        f"==> OpenShield perf: {backend} controlled NFQUEUE overload {transport}",
                        flush=True,
                    )
                    current_overload.append(topology.run_overload_safety(profile))
            status = (
                "passed"
                if backend_passed(current, config["criteria"])
                and overload_backend_passed(
                    current_overload, config["overload"]["enabled"]
                )
                else "failed"
            )
            backend_results.append({"name": backend, "status": status, "reason": None})
        except BackendUnsupported as error:
            allowed = backend == "iptables" and config["allow_unsupported_iptables"]
            backend_results.append(
                {"name": backend, "status": "unsupported" if allowed else "failed", "reason": safe_tail(str(error))}
            )
        except (HarnessError, OSError, subprocess.SubprocessError) as error:
            backend_results.append({"name": backend, "status": "failed", "reason": safe_tail(str(error))})
        finally:
            if generation_pair is not None:
                generation_pair["baseline_daemon_started"] = (
                    baseline_topology.daemon_started
                )
            all_results.extend(current)
            all_overload_results.extend(current_overload)
            topology.cleanup()
            baseline_topology.cleanup()
    environment_consistency = environment_consistency_evidence(
        environments, list(config["backends"])
    )
    add_baseline_comparisons(all_results, config["criteria"])
    baseline_pairing = baseline_pairing_evidence(
        all_results,
        config,
        baseline_environments,
        environments,
        generation_pairs,
    )
    # Baseline propagation and server reliability mutate rows after the phase
    # snapshot.  Rewrite raw evidence now so all three report formats describe
    # the same final decisions.
    rewrite_canonical_raw_results(output, all_results)
    for backend_result in backend_results:
        if backend_result.get("reason") is not None:
            continue
        backend_current = [
            result
            for result in all_results
            if result.get("backend") == backend_result["name"]
        ]
        backend_overload = [
            result
            for result in all_overload_results
            if result.get("backend") == backend_result["name"]
        ]
        backend_result["status"] = (
            "passed"
            if backend_passed(backend_current, config["criteria"])
            and overload_backend_passed(
                backend_overload, config["overload"]["enabled"]
            )
            and next(
                (
                    pair.get("valid") is True
                    for pair in baseline_pairing["environment_pairs"]
                    if pair.get("backend") == backend_result["name"]
                ),
                False,
            )
            else "failed"
        )
    steady_repetitions = int(config["phases"]["steady"]["repetitions"])
    maxima = maximum_sustainable(
        all_results,
        steady_repetitions,
        capacity_certification=config["capacity_certification"],
        require_burst_capacity=config["criteria"]["require_burst_capacity"],
    )
    required_backends_pass = all(
        backend["status"] == "passed"
        or (
            backend["name"] == "iptables"
            and backend["status"] == "unsupported"
            and config["allow_unsupported_iptables"]
        )
        for backend in backend_results
    )
    required_valid_results = list(all_results)
    # Per-backend checks above correctly account for an explicitly optional,
    # unsupported iptables fallback.  Here every executed overload proof must
    # still be valid and closed.
    executed_overload_valid = all(
        result.get("valid") is True for result in all_overload_results
    )
    overload_plan_complete = overload_plan_is_exact(
        all_overload_results,
        backend_results,
        config["overload"]["enabled"],
    )
    valid = (
        bool(required_valid_results)
        and all(result["valid"] for result in required_valid_results)
        and executed_overload_valid
        and overload_plan_complete
        and environment_consistency["valid"] is True
        and baseline_pairing["valid"] is True
    )
    passed = (
        baseline_pairing["valid"] is True
        and environment_consistency["valid"] is True
        and required_backends_pass
        and all(result.get("passed") is True for result in required_valid_results)
        and all(result.get("passed") is True for result in all_overload_results)
    )
    return {
        "schema": REPORT_SCHEMA,
        "run_id": run_id,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seed": config["seed"],
        "description": config.get("description"),
        "configuration_sha256": hashlib.sha256(canonical_config).hexdigest(),
        "configuration": config,
        "valid": valid,
        "passed": passed,
        "daemon": daemon_metadata,
        "harness": harness_evidence,
        "docker": docker_metadata,
        "environments": environments,
        "environment_consistency": environment_consistency,
        "baseline_pairing": baseline_pairing,
        "estimated_workload_seconds": config["estimated_workload_seconds"],
        "criteria": config["criteria"],
        "relative_performance_methodology": {
            "pairing": "independent_order_balanced_adjacent_ab_ba",
            "gate_phase": "steady",
            "burst_relative_role": "single_sample_threshold_gate",
            "minimum_paired_samples": MINIMUM_RELATIVE_PAIRED_SAMPLES,
            "confidence_level": RELATIVE_CONFIDENCE_LEVEL,
            "method": "arithmetic_mean_of_independent_paired_deltas",
            "confirmation_method": (
                "one_sided_paired_student_t_mean_lower_bound"
            ),
            "thresholds_unchanged": True,
            "cpu_latency_release_action": (
                "observe"
                if config["criteria"][
                    "cpu_latency_relative_regressions_are_advisory"
                ]
                else "fail"
            ),
        },
        "backends": backend_results,
        "maximum_sustainable": maxima,
        "overload_plan_complete": overload_plan_complete,
        "results": all_results,
        "overload_results": all_overload_results,
        "limitations": [
            "softirq counters are host-wide and are interpreted only against paired baselines",
            "daemon rate-limits NFQUEUE attribution error logs; categorized log counts are lower bounds",
            "capacity is certified only when at least three steady windows and any required matching burst pass",
            "controlled overload uses SIGSTOP/SIGCONT only inside the disposable DUT namespace",
            "daemon state uses the disposable container writable layer so learning includes persistence and fsync",
            "the protected daemon remains resident during pristine-baseline measurements, so shared-host scheduling may bias throughput and latency despite separate DUT-cgroup accounting",
            "the signed live Tumbleweed repository is recorded per run but is not immutable across runs",
            "publish-grade numeric comparisons require a prebuilt pinned performance image and dedicated runner",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--daemon", type=Path)
    parser.add_argument(
        "--run-token",
        help=(
            "32 lowercase hexadecimal characters used as the exact Docker "
            "resource label value"
        ),
    )
    arguments = parser.parse_args()
    if not arguments.output_dir.is_absolute():
        parser.error("--output-dir must be absolute")
    output = arguments.output_dir
    validate_output_directory(output)
    daemon_argument = arguments.daemon or (
        Path(os.environ["OPENSHIELD_DAEMON"])
        if "OPENSHIELD_DAEMON" in os.environ
        else None
    )
    if daemon_argument is None:
        parser.error("--daemon or OPENSHIELD_DAEMON is required")
    if daemon_argument.is_symlink():
        parser.error("the daemon path must not be a symlink")
    if arguments.config.is_symlink():
        parser.error("the configuration path must not be a symlink")
    config = validate_config(load_json_object(arguments.config.resolve(strict=True)))
    environment_run_token = os.environ.get("OPENSHIELD_PERF_RUN_TOKEN")
    if (
        arguments.run_token is not None
        and environment_run_token is not None
        and arguments.run_token != environment_run_token
    ):
        parser.error("--run-token conflicts with OPENSHIELD_PERF_RUN_TOKEN")
    try:
        supplied_run_token = (
            arguments.run_token
            if arguments.run_token is not None
            else environment_run_token
        )
        run_token = resolve_run_token(supplied_run_token)
    except HarnessError as error:
        parser.error(str(error))

    def interrupted(signum: int, _frame: Any) -> None:
        try:
            signal_name = signal.Signals(signum).name
        except ValueError:
            signal_name = str(signum)
        raise HarnessInterrupted(f"performance harness interrupted by {signal_name}")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    report: dict[str, Any]
    try:
        report = run_harness(
            config,
            daemon_argument.resolve(strict=True),
            output,
            run_token=run_token,
        )
    except (HarnessError, HarnessInterrupted, OSError, subprocess.SubprocessError) as error:
        report = {
            "schema": REPORT_SCHEMA,
            "run_id": f"failed-{int(time.time())}",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "seed": config["seed"],
            "description": config.get("description"),
            "configuration_sha256": hashlib.sha256(
                json.dumps(
                    config, sort_keys=True, separators=(",", ":"), allow_nan=False
                ).encode("utf-8")
            ).hexdigest(),
            "configuration": config,
            "valid": False,
            "passed": False,
            "daemon": {"path": str(daemon_argument)},
            "docker": None,
            "environments": [],
            "environment_consistency": {
                "schema": "openshield.perf.environment-consistency.v1",
                "valid": False,
                "failure_reasons": ["harness terminated before environment comparison"],
            },
            "baseline_pairing": {
                "schema": BASELINE_PAIRING_SCHEMA,
                "strategy": "independent_order_balanced_ab_ba",
                "valid": False,
                "failure_reasons": ["harness terminated before baseline pairing"],
                "baseline_environments": [],
                "environment_pairs": [],
                "baseline_sample_count": 0,
                "comparison_count": 0,
                "orders": {"ab": 0, "ba": 0},
                "maximum_gap_seconds": None,
            },
            "estimated_workload_seconds": config["estimated_workload_seconds"],
            "criteria": config["criteria"],
            "backends": [
                {"name": backend, "status": "failed", "reason": safe_tail(str(error))}
                for backend in config["backends"]
            ],
            "maximum_sustainable": [],
            "results": [],
            "overload_results": [],
            "limitations": [],
            "fatal_error": safe_tail(str(error)),
        }
    write_json(output / "report.json", report)
    write_csv(output / "report.csv", report["results"])
    write_overload_csv(output / "overload.csv", report["overload_results"])
    write_text(output / "report.md", markdown_report(report))
    print(f"OpenShield perf report: {output / 'report.md'}", flush=True)
    return 0 if report["valid"] and report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
