#!/usr/bin/env python3
"""Collect one bounded metric window from an OpenShield DUT namespace."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import selectors
import sys
import time
from typing import Any, BinaryIO, Callable


DEFAULT_NFQUEUE_NUMBER = 1_337
MAX_NFQUEUE_NUMBER = (1 << 16) - 1
CONTROL_SCHEMA = "openshield.perf.metrics.control.v2"
METRICS_SCHEMA = "openshield.perf.metrics.v3"
U32_MODULUS = 1 << 32
MAX_DURATION_SECONDS = 3_600.0
MIN_INTERVAL_SECONDS = 0.02
MAX_CONTROL_COMMAND_CHARACTERS = 16
MAX_CONTROL_START_WAIT_SECONDS = 120.0
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.:-]{0,14})$")
MAX_COUNTER_VALUE = (1 << 64) - 1


def self_process_identity() -> dict[str, int | str]:
    """Return identity fields used for exact, PID-reuse-safe cleanup."""

    pid = os.getpid()
    try:
        stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        closing = stat_text.rfind(")")
        fields = stat_text[closing + 2 :].split() if closing >= 0 else []
        starttime = int(fields[19], 10)
        executable = os.readlink(f"/proc/{pid}/exe")
    except (OSError, UnicodeError, ValueError, IndexError) as error:
        raise RuntimeError("cannot pin metric collector process identity") from error
    if starttime <= 0 or not executable.startswith("/"):
        raise RuntimeError("metric collector process identity is invalid")
    return {
        "pid": pid,
        "starttime": starttime,
        "executable": executable,
        "uid": os.getuid(),
    }


def read_int(path: Path) -> int | None:
    try:
        value = int(path.read_text(encoding="ascii").strip())
    except (OSError, UnicodeError, ValueError):
        return None
    return value if value >= 0 else None


def read_named_int(path: Path, name: str) -> int | None:
    """Read one non-negative, unique counter from a bounded key/value file."""

    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return None
    values: list[int] = []
    for line in lines:
        fields = line.split()
        if len(fields) != 2 or fields[0] != name:
            continue
        try:
            value = int(fields[1], 10)
        except ValueError:
            return None
        if not 0 <= value <= MAX_COUNTER_VALUE:
            return None
        values.append(value)
    return values[0] if len(values) == 1 else None


def safe_cgroup_relative_path(value: str) -> Path | None:
    """Convert a kernel-provided cgroup path without permitting traversal."""

    if not value.startswith("/") or len(value) > 4_096 or "\x00" in value:
        return None
    parts = PurePosixPath(value).parts[1:]
    if any(part in {"", ".", ".."} for part in parts):
        return None
    return Path(*parts)


def cgroup_cpu_usage(
    cgroup_root: Path = Path("/sys/fs/cgroup"),
    proc_cgroup: Path = Path("/proc/self/cgroup"),
) -> dict[str, Any] | None:
    """Read this container's CPU usage from cgroup v2 or a safe v1 fallback.

    Docker normally exposes the container cgroup as the cgroup filesystem root.
    Older cgroup-v1 hosts can instead expose a controller hierarchy plus the
    process-relative cgroup path.  Only controller names and traversal-free
    paths supplied by the kernel are considered.
    """

    usage_usec = read_named_int(cgroup_root / "cpu.stat", "usage_usec")
    if usage_usec is not None:
        return {
            "usage_seconds": usage_usec / 1_000_000.0,
            "source": "cgroup-v2/cpu.stat:usage_usec",
        }

    candidates: list[Path] = []
    try:
        lines = proc_cgroup.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        lines = []
    for line in lines:
        fields = line.split(":", 2)
        if len(fields) != 3:
            continue
        controllers = fields[1].split(",")
        if "cpuacct" not in controllers or any(
            not controller.isascii()
            or not controller
            or not controller.replace("_", "").isalnum()
            for controller in controllers
        ):
            continue
        relative = safe_cgroup_relative_path(fields[2])
        if relative is None:
            continue
        controller_names = [
            fields[1],
            ",".join(sorted(controllers)),
            "cpuacct",
            "cpu",
        ]
        for controller_name in controller_names:
            candidates.append(
                cgroup_root / controller_name / relative / "cpuacct.usage"
            )
        candidates.append(cgroup_root / relative / "cpuacct.usage")

    seen: set[Path] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        usage_nsec = read_int(candidate)
        if usage_nsec is None or usage_nsec > MAX_COUNTER_VALUE:
            continue
        return {
            "usage_seconds": usage_nsec / 1_000_000_000.0,
            "source": (
                "cgroup-v1/cpuacct.usage:"
                + candidate.relative_to(cgroup_root).as_posix()
            ),
        }
    return None


def process_cpu_ticks(pid: int) -> int | None:
    if pid <= 0:
        return None
    try:
        value = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None
    close = value.rfind(")")
    if close < 0:
        return None
    fields = value[close + 2 :].split()
    try:
        # fields starts at proc(5) field 3; utime/stime are fields 14 and 15.
        return int(fields[11]) + int(fields[12])
    except (IndexError, ValueError):
        return None


def process_rss_bytes(pid: int) -> int | None:
    if pid <= 0:
        return None
    try:
        lines = Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        if line.startswith("VmRSS:"):
            fields = line.split()
            try:
                return int(fields[1]) * 1_024
            except (IndexError, ValueError):
                return None
    return None


def softirq_totals() -> dict[str, int | None]:
    # An unavailable or malformed procfs counter is not an observed zero.
    # Keeping the sentinel lets the harness invalidate incomplete evidence.
    result: dict[str, int | None] = {"net_rx": None, "net_tx": None}
    try:
        lines = Path("/proc/softirqs").read_text(encoding="ascii").splitlines()
    except OSError:
        return result
    names = {"NET_RX": "net_rx", "NET_TX": "net_tx"}
    for line in lines:
        label, separator, values = line.partition(":")
        target = names.get(label.strip())
        if not separator or target is None:
            continue
        try:
            result[target] = sum(int(value) for value in values.split())
        except ValueError:
            result[target] = None
    return result


def protocol_counters(
    path: Path, section: str, requested: tuple[str, ...]
) -> dict[str, int | None]:
    result: dict[str, int | None] = {name: None for name in requested}
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except OSError:
        return result
    marker = f"{section}:"
    for index in range(len(lines) - 1):
        if not lines[index].startswith(marker) or not lines[index + 1].startswith(marker):
            continue
        names = lines[index].split()[1:]
        values = lines[index + 1].split()[1:]
        try:
            counters = dict(zip(names, values, strict=True))
        except ValueError:
            return result
        for name in requested:
            try:
                value = int(counters[name])
            except (KeyError, ValueError):
                continue
            result[name] = value if value >= 0 else None
        return result
    return result


def transport_counters() -> dict[str, Any]:
    snmp = Path("/proc/net/snmp")
    netstat = Path("/proc/net/netstat")
    return {
        "tcp": protocol_counters(snmp, "Tcp", ("RetransSegs",)),
        "udp": protocol_counters(
            snmp, "Udp", ("InErrors", "RcvbufErrors", "SndbufErrors")
        ),
        "tcp_ext": protocol_counters(
            netstat, "TcpExt", ("ListenDrops", "ListenOverflows")
        ),
    }


def interface_counters(interface: str) -> dict[str, int | None]:
    root = Path("/sys/class/net") / interface / "statistics"
    return {
        name: read_int(root / name)
        for name in (
            "rx_packets",
            "tx_packets",
            "rx_bytes",
            "tx_bytes",
            "rx_dropped",
            "tx_dropped",
            "rx_errors",
            "tx_errors",
        )
    }


def validate_nfqueue_number(queue_number: int) -> int:
    """Accept only a real NFQUEUE u16, never a bool or a wrapped integer."""

    if (
        isinstance(queue_number, bool)
        or not isinstance(queue_number, int)
        or not 0 <= queue_number <= MAX_NFQUEUE_NUMBER
    ):
        raise ValueError("NFQUEUE number must be an integer in [0, 65535]")
    return queue_number


def parse_nfqueue_number(value: str) -> int:
    """Parse one canonical decimal NFQUEUE number for argparse."""

    if not value.isascii() or not value.isdecimal() or (len(value) > 1 and value[0] == "0"):
        raise argparse.ArgumentTypeError(
            "NFQUEUE number must be a canonical decimal integer in [0, 65535]"
        )
    try:
        return validate_nfqueue_number(int(value, 10))
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def nfqueue_counters(
    queue_number: int = DEFAULT_NFQUEUE_NUMBER,
    path: Path = Path("/proc/net/netfilter/nfnetlink_queue"),
) -> dict[str, int | None]:
    queue_number = validate_nfqueue_number(queue_number)
    result: dict[str, int | None] = {
        "queue_number": queue_number,
        "depth": None,
        "copy_mode": None,
        "copy_range": None,
        "kernel_dropped": None,
        "user_dropped": None,
        "sequence": None,
    }
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except OSError:
        return result
    for line in lines:
        fields = line.split()
        if len(fields) < 9:
            continue
        try:
            if int(fields[0]) != queue_number:
                continue
            values = [int(value) for value in fields[:9]]
        except ValueError:
            continue
        result.update(
            {
                "depth": values[2],
                "copy_mode": values[3],
                "copy_range": values[4],
                "kernel_dropped": values[5],
                "user_dropped": values[6],
                "sequence": values[7],
            }
        )
        return result
    return result


def counter_delta(before: int | None, after: int | None) -> int | None:
    if before is None or after is None:
        return None
    if after >= before:
        return after - before
    return (after - before) % U32_MODULUS


def ordinary_delta(before: int | None, after: int | None) -> int | None:
    if before is None or after is None or after < before:
        return None
    return after - before


def counter_group_delta(
    before: dict[str, int | None], after: dict[str, int | None]
) -> dict[str, int | None]:
    return {
        name: ordinary_delta(before.get(name), after.get(name)) for name in before
    }


def cgroup_cpu_delta(
    before: Any,
    after: Any,
    elapsed: float,
    collector_cpu_seconds: float | None = None,
) -> dict[str, Any]:
    result = {
        "source": None,
        "accounting": "container_cgroup_minus_metric_collector",
        "raw_cpu_seconds": None,
        "collector_cpu_seconds_excluded": None,
        "cpu_seconds": None,
        "cpu_percent_one_core": None,
    }
    if (
        not isinstance(before, dict)
        or not isinstance(after, dict)
        or before.get("source") != after.get("source")
        or not isinstance(elapsed, (int, float))
        or isinstance(elapsed, bool)
        or elapsed <= 0
    ):
        return result
    before_seconds = before.get("usage_seconds")
    after_seconds = after.get("usage_seconds")
    if (
        not isinstance(before_seconds, (int, float))
        or isinstance(before_seconds, bool)
        or not isinstance(after_seconds, (int, float))
        or isinstance(after_seconds, bool)
        or after_seconds < before_seconds
    ):
        return result
    raw_cpu_seconds = float(after_seconds - before_seconds)
    if (
        not isinstance(collector_cpu_seconds, (int, float))
        or isinstance(collector_cpu_seconds, bool)
        or collector_cpu_seconds < 0
        or collector_cpu_seconds > raw_cpu_seconds + 1e-6
    ):
        return {
            **result,
            "source": after.get("source"),
            "raw_cpu_seconds": raw_cpu_seconds,
            "collector_cpu_seconds_excluded": collector_cpu_seconds,
        }
    cpu_seconds = max(0.0, raw_cpu_seconds - float(collector_cpu_seconds))
    return {
        "source": after.get("source"),
        "accounting": "container_cgroup_minus_metric_collector",
        "raw_cpu_seconds": raw_cpu_seconds,
        "collector_cpu_seconds_excluded": float(collector_cpu_seconds),
        "cpu_seconds": cpu_seconds,
        "cpu_percent_one_core": cpu_seconds * 100.0 / float(elapsed),
    }


def snapshot(
    interface: str,
    nfqueue_number: int = DEFAULT_NFQUEUE_NUMBER,
) -> tuple[dict[str, Any], float, float]:
    transport = transport_counters()
    observed_at_monotonic_ns = time.monotonic_ns()
    collector_cpu_before_cgroup = time.process_time()
    cgroup_cpu = cgroup_cpu_usage()
    collector_cpu_after_cgroup = time.process_time()
    observation = {
        "monotonic": observed_at_monotonic_ns / 1_000_000_000.0,
        "monotonic_ns": observed_at_monotonic_ns,
        "cgroup_cpu": cgroup_cpu,
        "interface": interface_counters(interface),
        "softirq": softirq_totals(),
        "tcp_retransmits": transport["tcp"]["RetransSegs"],
        "udp_errors": {
            "in_errors": transport["udp"]["InErrors"],
            "rcvbuf_errors": transport["udp"]["RcvbufErrors"],
            "sndbuf_errors": transport["udp"]["SndbufErrors"],
        },
        "tcp_listen": {
            "listen_drops": transport["tcp_ext"]["ListenDrops"],
            "listen_overflows": transport["tcp_ext"]["ListenOverflows"],
        },
        "conntrack_count": read_int(
            Path("/proc/sys/net/netfilter/nf_conntrack_count")
        ),
        "nfqueue": nfqueue_counters(nfqueue_number),
    }
    return (
        observation,
        collector_cpu_before_cgroup,
        collector_cpu_after_cgroup,
    )


def measurement_boundary(
    pid: int,
    workload_pid: int,
    interface: str,
    nfqueue_number: int = DEFAULT_NFQUEUE_NUMBER,
) -> dict[str, Any]:
    """Capture one boundary object that adjacent windows can share exactly."""

    (
        observation,
        collector_cpu_before_cgroup,
        collector_cpu_after_cgroup,
    ) = snapshot(interface, nfqueue_number)
    return {
        "snapshot": observation,
        "process_cpu_ticks": process_cpu_ticks(pid),
        "workload_cpu_ticks": process_cpu_ticks(workload_pid),
        # Each shared boundary brackets the cgroup read with the collector's
        # CLOCK_PROCESS_CPUTIME_ID.  A window subtracts only the interior
        # interval: after the initial cgroup read through before the final
        # cgroup read.  That interval is contained in the cgroup interval, so
        # boundary bookkeeping cannot be subtracted from unrelated daemon or
        # child work and low-activity windows cannot fail merely because the
        # collector timestamp was sampled after the final cgroup snapshot.
        "collector_cpu_before_cgroup": collector_cpu_before_cgroup,
        "collector_cpu_after_cgroup": collector_cpu_after_cgroup,
        "process_rss_bytes": process_rss_bytes(pid),
        "workload_rss_bytes": process_rss_bytes(workload_pid),
    }


def _append_sample(values: list[int], value: Any) -> None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        values.append(value)


def _new_window_samples(boundary: dict[str, Any]) -> dict[str, list[int]]:
    samples: dict[str, list[int]] = {
        "rss": [],
        "workload_rss": [],
        "conntrack": [],
        "queue_depth": [],
    }
    _append_boundary_samples(samples, boundary)
    return samples


def _append_boundary_samples(
    samples: dict[str, list[int]], boundary: dict[str, Any]
) -> None:
    observation = boundary["snapshot"]
    _append_sample(samples["rss"], boundary.get("process_rss_bytes"))
    _append_sample(
        samples["workload_rss"], boundary.get("workload_rss_bytes")
    )
    _append_sample(samples["conntrack"], observation.get("conntrack_count"))
    _append_sample(samples["queue_depth"], observation["nfqueue"].get("depth"))


def _append_periodic_samples(
    samples: dict[str, list[int]],
    pid: int,
    workload_pid: int,
    nfqueue_number: int,
) -> None:
    _append_sample(samples["rss"], process_rss_bytes(pid))
    _append_sample(samples["workload_rss"], process_rss_bytes(workload_pid))
    _append_sample(
        samples["conntrack"],
        read_int(Path("/proc/sys/net/netfilter/nf_conntrack_count")),
    )
    _append_sample(
        samples["queue_depth"], nfqueue_counters(nfqueue_number)["depth"]
    )


def _metrics_document(
    pid: int,
    workload_pid: int,
    started: dict[str, Any],
    finished: dict[str, Any],
    samples: dict[str, list[int]],
    stop_reason: str,
) -> dict[str, Any]:
    started_snapshot = started["snapshot"]
    finished_snapshot = finished["snapshot"]
    started_ns = started_snapshot["monotonic_ns"]
    finished_ns = finished_snapshot["monotonic_ns"]
    if (
        isinstance(started_ns, bool)
        or not isinstance(started_ns, int)
        or isinstance(finished_ns, bool)
        or not isinstance(finished_ns, int)
        or started_ns <= 0
        or finished_ns < started_ns
    ):
        raise RuntimeError("metric boundary monotonic timestamps are invalid")
    elapsed = max((finished_ns - started_ns) / 1_000_000_000.0, 1e-9)
    clock_ticks = os.sysconf("SC_CLK_TCK")
    ticks_after = finished.get("process_cpu_ticks")
    workload_ticks_after = finished.get("workload_cpu_ticks")
    cpu_ticks = ordinary_delta(started.get("process_cpu_ticks"), ticks_after)
    cpu_seconds = None if cpu_ticks is None else cpu_ticks / clock_ticks
    workload_cpu_ticks = ordinary_delta(
        started.get("workload_cpu_ticks"), workload_ticks_after
    )
    workload_cpu_seconds = (
        None
        if workload_cpu_ticks is None
        else workload_cpu_ticks / clock_ticks
    )
    collector_cpu_before = started.get("collector_cpu_after_cgroup")
    collector_cpu_after = finished.get("collector_cpu_before_cgroup")
    collector_cpu_seconds = (
        None
        if not isinstance(collector_cpu_before, (int, float))
        or isinstance(collector_cpu_before, bool)
        or not isinstance(collector_cpu_after, (int, float))
        or isinstance(collector_cpu_after, bool)
        or collector_cpu_after < collector_cpu_before
        else float(collector_cpu_after - collector_cpu_before)
    )
    cgroup = cgroup_cpu_delta(
        started_snapshot.get("cgroup_cpu"),
        finished_snapshot.get("cgroup_cpu"),
        elapsed,
        collector_cpu_seconds,
    )
    network = {
        name: ordinary_delta(
            started_snapshot["interface"].get(name),
            finished_snapshot["interface"].get(name),
        )
        for name in started_snapshot["interface"]
    }
    queue_before = started_snapshot["nfqueue"]
    queue_after = finished_snapshot["nfqueue"]
    queue = {
        "queue_number": queue_after.get("queue_number"),
        "hits": counter_delta(
            queue_before.get("sequence"), queue_after.get("sequence")
        ),
        "kernel_dropped": ordinary_delta(
            queue_before.get("kernel_dropped"), queue_after.get("kernel_dropped")
        ),
        "user_dropped": ordinary_delta(
            queue_before.get("user_dropped"), queue_after.get("user_dropped")
        ),
        "depth_peak": max(samples["queue_depth"], default=None),
        "depth_end": queue_after.get("depth"),
        "copy_mode": queue_after.get("copy_mode"),
        "copy_range": queue_after.get("copy_range"),
    }
    return {
        "schema": METRICS_SCHEMA,
        "started_at_monotonic_ns": started_ns,
        "finished_at_monotonic_ns": finished_ns,
        "elapsed_seconds": elapsed,
        "stop_reason": stop_reason,
        "daemon": {
            "pid": pid if pid > 0 else None,
            "alive_end": ticks_after is not None if pid > 0 else None,
            "cpu_seconds": cpu_seconds,
            "cpu_percent_one_core": None
            if cpu_seconds is None
            else cpu_seconds * 100.0 / elapsed,
            "rss_bytes_mean": None
            if not samples["rss"]
            else sum(samples["rss"]) / len(samples["rss"]),
            "rss_bytes_peak": max(samples["rss"], default=None),
        },
        "workload_process": {
            "pid": workload_pid if workload_pid > 0 else None,
            "alive_end": workload_ticks_after is not None
            if workload_pid > 0
            else None,
            "cpu_seconds": workload_cpu_seconds,
            "cpu_percent_one_core": None
            if workload_cpu_seconds is None
            else workload_cpu_seconds * 100.0 / elapsed,
            "rss_bytes_mean": None
            if not samples["workload_rss"]
            else sum(samples["workload_rss"])
            / len(samples["workload_rss"]),
            "rss_bytes_peak": max(samples["workload_rss"], default=None),
        },
        "cgroup": cgroup,
        "network": {
            **network,
            "rx_pps": None
            if network.get("rx_packets") is None
            else network["rx_packets"] / elapsed,
            "tx_pps": None
            if network.get("tx_packets") is None
            else network["tx_packets"] / elapsed,
            "rx_mbps": None
            if network.get("rx_bytes") is None
            else network["rx_bytes"] * 8.0 / elapsed / 1_000_000.0,
            "tx_mbps": None
            if network.get("tx_bytes") is None
            else network["tx_bytes"] * 8.0 / elapsed / 1_000_000.0,
        },
        "softirq": {
            name: ordinary_delta(
                started_snapshot["softirq"].get(name),
                finished_snapshot["softirq"].get(name),
            )
            for name in started_snapshot["softirq"]
        },
        "tcp_retransmits": ordinary_delta(
            started_snapshot.get("tcp_retransmits"),
            finished_snapshot.get("tcp_retransmits"),
        ),
        "udp_errors": counter_group_delta(
            started_snapshot["udp_errors"], finished_snapshot["udp_errors"]
        ),
        "tcp_listen": counter_group_delta(
            started_snapshot["tcp_listen"], finished_snapshot["tcp_listen"]
        ),
        "conntrack_count_start": started_snapshot.get("conntrack_count"),
        "conntrack_count_end": finished_snapshot.get("conntrack_count"),
        "conntrack_count_peak": max(samples["conntrack"], default=None),
        "nfqueue": queue,
        "scope_notes": {
            "softirq": "host-wide kernel counters; compare paired baselines",
            "cgroup_cpu": (
                "container-wide CPU minus the cgroup-boundary-bracketed interior "
                "metric-collector process CPU; boundary bookkeeping, daemon children, "
                "and kernel work remain included"
            ),
            "nfqueue_log_errors": "not included; daemon throttling makes log counts lower bounds",
            "nfqueue": (
                "kernel queue counters for explicitly selected NFQUEUE "
                f"{queue_after.get('queue_number')}"
            ),
        },
    }


def decode_control_command(
    line: bytes, allowed_commands: frozenset[str]
) -> str:
    """Decode one small, newline-terminated ASCII command with an exact allowlist."""

    if (
        not line
        or len(line) > MAX_CONTROL_COMMAND_CHARACTERS
        or not line.endswith(b"\n")
        or line.count(b"\n") != 1
    ):
        raise RuntimeError("metric control command is malformed or oversized")
    try:
        command = line[:-1].decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise RuntimeError("metric control command must be ASCII") from error
    if command not in allowed_commands:
        raise RuntimeError("metric control command is not allowed in this state")
    return command


class ControlChannel:
    """Bounded, non-buffering command reader for the synchronized protocol."""

    def __init__(self, stream: BinaryIO) -> None:
        self._descriptor = stream.fileno()
        self._buffer = bytearray()
        self._eof = False
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._descriptor, selectors.EVENT_READ)

    def close(self) -> None:
        self._selector.close()

    def _buffered_command(
        self, allowed_commands: frozenset[str]
    ) -> str | None:
        newline = self._buffer.find(b"\n")
        if newline >= 0:
            end = newline + 1
            raw = bytes(self._buffer[:end])
            del self._buffer[:end]
            return decode_control_command(raw, allowed_commands)
        if len(self._buffer) >= MAX_CONTROL_COMMAND_CHARACTERS:
            raise RuntimeError("metric control command is malformed or oversized")
        if self._eof:
            if self._buffer:
                raise RuntimeError("metric control command is not newline terminated")
            raise RuntimeError("metric control channel closed before a command")
        return None

    def read_command(
        self, allowed_commands: frozenset[str], timeout: float | None
    ) -> str | None:
        """Return one command, or ``None`` after the bounded polling interval."""

        if timeout is not None and timeout < 0:
            raise RuntimeError("metric control timeout must be nonnegative")
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            command = self._buffered_command(allowed_commands)
            if command is not None:
                return command
            wait = (
                None
                if deadline is None
                else max(0.0, deadline - time.monotonic())
            )
            if wait == 0.0 or not self._selector.select(wait):
                return None
            try:
                chunk = os.read(
                    self._descriptor, MAX_CONTROL_COMMAND_CHARACTERS + 1
                )
            except BlockingIOError:
                continue
            if chunk:
                self._buffer.extend(chunk)
            else:
                self._eof = True


def collect(
    pid: int,
    workload_pid: int,
    interface: str,
    duration: float,
    interval: float,
    control_channel: ControlChannel | None = None,
    split_callback: Callable[[int, dict[str, Any]], None] | None = None,
    initial_boundary: dict[str, Any] | None = None,
    *,
    nfqueue_number: int = DEFAULT_NFQUEUE_NUMBER,
) -> dict[str, Any]:
    nfqueue_number = validate_nfqueue_number(nfqueue_number)
    started = (
        measurement_boundary(pid, workload_pid, interface, nfqueue_number)
        if initial_boundary is None
        else initial_boundary
    )
    samples = _new_window_samples(started)
    started_ns = started.get("snapshot", {}).get("monotonic_ns")
    if (
        isinstance(started_ns, bool)
        or not isinstance(started_ns, int)
        or started_ns <= 0
    ):
        raise RuntimeError("initial metric boundary has no valid monotonic timestamp")
    deadline = started_ns / 1_000_000_000.0 + duration
    stop_reason = "duration_limit"
    split_seen = False
    while True:
        _append_periodic_samples(samples, pid, workload_pid, nfqueue_number)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        wait = min(interval, remaining)
        if control_channel is None:
            time.sleep(wait)
            continue
        command = control_channel.read_command(
            frozenset({"split", "stop"}), wait
        )
        if command is None:
            continue
        if command == "stop":
            stop_reason = "requested"
            break
        if split_seen:
            raise RuntimeError("synchronized collector permits at most one split")
        if split_callback is None:
            raise RuntimeError("synchronized collector has no split handler")
        boundary = measurement_boundary(
            pid, workload_pid, interface, nfqueue_number
        )
        _append_boundary_samples(samples, boundary)
        first_document = _metrics_document(
            pid,
            workload_pid,
            started,
            boundary,
            samples,
            "split_boundary",
        )
        boundary_ns = boundary["snapshot"]["monotonic_ns"]
        split_callback(boundary_ns, first_document)
        # The exact same object is both the finished state above and the
        # started state below. No counter read or timestamp can fall into a
        # hand-off gap between the adjacent measurement windows.
        started = boundary
        samples = _new_window_samples(boundary)
        split_seen = True
    finished = measurement_boundary(
        pid, workload_pid, interface, nfqueue_number
    )
    _append_boundary_samples(samples, finished)
    return _metrics_document(
        pid,
        workload_pid,
        started,
        finished,
        samples,
        stop_reason,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, default=0)
    parser.add_argument("--workload-pid", type=int, default=0)
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--duration", type=float, required=True)
    parser.add_argument("--interval", type=float, default=0.1)
    parser.add_argument(
        "--nfqueue-number",
        type=parse_nfqueue_number,
        default=DEFAULT_NFQUEUE_NUMBER,
        help="NFQUEUE whose kernel counters are measured (default: 1337)",
    )
    parser.add_argument(
        "--synchronize",
        action="store_true",
        help="announce readiness and wait for a bounded start line on stdin",
    )
    arguments = parser.parse_args()
    if not 0 < arguments.duration <= MAX_DURATION_SECONDS:
        parser.error(f"duration must be in (0, {MAX_DURATION_SECONDS}]")
    if not MIN_INTERVAL_SECONDS <= arguments.interval <= arguments.duration:
        parser.error("interval is outside the safe measurement range")
    if not INTERFACE_PATTERN.fullmatch(arguments.interface):
        parser.error("invalid interface")
    if arguments.pid < 0 or arguments.workload_pid < 0:
        parser.error("process identifiers must be nonnegative")
    split_callback: Callable[[int, dict[str, Any]], None] | None = None
    control_channel: ControlChannel | None = None
    initial_boundary: dict[str, Any] | None = None
    if arguments.synchronize:
        control_channel = ControlChannel(sys.stdin.buffer)
        print(
            json.dumps(
                {
                    "schema": CONTROL_SCHEMA,
                    "event": "ready",
                    **self_process_identity(),
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            flush=True,
        )
        try:
            start_command = control_channel.read_command(
                frozenset({"start"}), MAX_CONTROL_START_WAIT_SECONDS
            )
            if start_command is None:
                raise RuntimeError(
                    "metric control start command exceeded its bounded deadline"
                )
            initial_boundary = measurement_boundary(
                arguments.pid,
                arguments.workload_pid,
                arguments.interface,
                arguments.nfqueue_number,
            )
            boundary_monotonic_ns = initial_boundary["snapshot"]["monotonic_ns"]
            print(
                json.dumps(
                    {
                        "schema": CONTROL_SCHEMA,
                        "event": "start",
                        "boundary_monotonic_ns": boundary_monotonic_ns,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                flush=True,
            )
        except RuntimeError as error:
            control_channel.close()
            parser.error(str(error))

        def emit_split(
            boundary_monotonic_ns: int, first_document: dict[str, Any]
        ) -> None:
            print(
                json.dumps(
                    {
                        "schema": CONTROL_SCHEMA,
                        "event": "split",
                        "boundary_monotonic_ns": boundary_monotonic_ns,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                flush=True,
            )
            print(
                json.dumps(
                    first_document,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                flush=True,
            )

        split_callback = emit_split
    try:
        document = collect(
            arguments.pid,
            arguments.workload_pid,
            arguments.interface,
            arguments.duration,
            arguments.interval,
            control_channel,
            split_callback,
            initial_boundary,
            nfqueue_number=arguments.nfqueue_number,
        )
    finally:
        if control_channel is not None:
            control_channel.close()
    print(
        json.dumps(document, sort_keys=True, separators=(",", ":")), flush=True
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
