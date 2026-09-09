#!/usr/bin/env python3
"""Independently validate OpenShield performance comparison evidence.

This module deliberately does not import the performance runner.  It verifies
the immutable configuration identity and recomputes paired steady-window
overhead, arithmetic means, confidence evidence, and decision linkage from the
primary workload and metric documents in ``report.json``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterable


CONFIG_SCHEMA = "openshield.perf.config.v2"
REPORT_SCHEMA = "openshield.perf.report.v2"
VALIDATION_SCHEMA = "openshield.perf.independent-validation.v1"
METRICS_SCHEMA = "openshield.perf.metrics.v3"
WORKLOAD_SCHEMA = "openshield.perf.workload.v1"
ENFORCING_NFQUEUE_NUMBER = 1_337
LEARNING_NFQUEUE_NUMBER = 1_338
MINIMUM_PAIRED_SAMPLES = 3
CONFIDENCE_LEVEL = 0.95
CGROUP_CPU_ACCOUNTING_RESOLUTION_SECONDS = 1e-6
MAX_CONFIG_BYTES = 512 * 1024
MAX_REPORT_BYTES = 20 * 1024 * 1024
IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
PAIR_PATTERN = re.compile(r"^p[0-9]{5}$")
BASELINE_PATTERN = re.compile(r"^b[0-9]{5}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

# One-sided 95% Student-t critical values for 2..19 degrees of freedom.  The
# configuration contract permits 3..20 independent steady pairs.
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

# name, direction, criterion, human-readable description, derived field
COMMON_GATE_SPECS = (
    (
        "throughput_reduction_percent",
        "reduction",
        "maximum_throughput_reduction_vs_baseline_percent",
        "application throughput reduction",
        "actual_application_mbps",
    ),
    (
        "aggregate_dut_pps_reduction_percent",
        "reduction",
        "maximum_dut_pps_reduction_vs_baseline_percent",
        "aggregate DUT PPS reduction",
        "aggregate_dut_pps",
    ),
    (
        "cgroup_cpu_increase_percent",
        "increase",
        "maximum_cgroup_cpu_increase_vs_baseline_percent",
        "DUT cgroup CPU increase",
        "cgroup_cpu_percent_one_core",
    ),
    *(
        (
            f"latency_{percentile}_increase_percent",
            "increase",
            "maximum_latency_increase_vs_baseline_percent",
            f"latency {percentile} increase",
            f"latency_{percentile}_ms",
        )
        for percentile in ("p50", "p95", "p99")
    ),
)
TCP_GATE_SPECS = tuple(
    (
        f"connect_latency_{percentile}_increase_percent",
        "increase",
        "maximum_latency_increase_vs_baseline_percent",
        f"TCP connect latency {percentile} increase",
        f"connect_latency_{percentile}_ms",
    )
    for percentile in ("p50", "p95", "p99")
)
DIAGNOSTIC_SPEC = (
    "application_ops_reduction_percent",
    "reduction",
    None,
    "application operation-rate reduction",
    "actual_application_ops_per_second",
)


def _criterion_is_advisory(criterion: str, criteria: dict[str, Any]) -> bool:
    advisory = criteria.get("cpu_latency_relative_regressions_are_advisory")
    if not isinstance(advisory, bool):
        _reject("cpu_latency_relative_regressions_are_advisory must be boolean")
    return advisory and criterion in {
        "maximum_latency_increase_vs_baseline_percent",
        "maximum_cgroup_cpu_increase_vs_baseline_percent",
    }


class ValidationError(RuntimeError):
    """The report does not satisfy the independent evidence contract."""


def _reject(message: str) -> None:
    raise ValidationError(message)


def _object_without_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_constant(value: str) -> None:
    _reject(f"non-finite JSON constant is forbidden: {value}")


def _strict_json_object(payload: bytes, context: str) -> dict[str, Any]:
    try:
        text = payload.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
        )
    except ValidationError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValidationError(f"{context} is not strict bounded JSON: {error}") from error
    if not isinstance(document, dict):
        _reject(f"{context} root must be an object")
    return document


def load_json_object(
    path: Path | str, *, maximum_bytes: int, context: str
) -> dict[str, Any]:
    """Read one stable, singly-linked, non-symlink JSON object."""

    source = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as error:
        raise ValidationError(f"cannot open {context}: {error}") from error
    chunks: list[bytes] = []
    observed = 0
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > maximum_bytes
        ):
            _reject(f"{context} is not a bounded singly-linked regular file")
        while chunk := os.read(descriptor, min(1024 * 1024, maximum_bytes + 1)):
            observed += len(chunk)
            if observed > maximum_bytes:
                _reject(f"{context} exceeded its size bound while being read")
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or observed != before.st_size
    ):
        _reject(f"{context} changed while being read")
    return _strict_json_object(b"".join(chunks), context)


def _canonical_json(document: Any) -> bytes:
    try:
        return json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise ValidationError(f"document cannot be canonically encoded: {error}") from error


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _reject(f"{label} must be an object")
    return value


def _array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        _reject(f"{label} must be an array")
    return value


def _number(
    value: Any,
    label: str,
    *,
    minimum: float | None = None,
    strictly_positive: bool = False,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _reject(f"{label} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        _reject(f"{label} must be a finite number")
    if strictly_positive and result <= 0:
        _reject(f"{label} must be positive")
    if minimum is not None and result < minimum:
        _reject(f"{label} is below its minimum")
    return result


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        _reject(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def _path(document: Any, *components: str, label: str) -> Any:
    current = document
    for component in components:
        if not isinstance(current, dict) or component not in current:
            _reject(f"{label} is missing")
        current = current[component]
    return current


def _same_number(observed: Any, expected: float, label: str) -> None:
    value = _number(observed, label)
    if not math.isclose(value, expected, rel_tol=1e-12, abs_tol=1e-9):
        _reject(f"{label} differs from the independently recomputed value")


def _unique_strings(value: Any, label: str) -> list[str]:
    items = _array(value, label)
    if not all(isinstance(item, str) for item in items):
        _reject(f"{label} must contain only strings")
    if len(items) != len(set(items)):
        _reject(f"{label} contains duplicate values")
    return items


def _config_sequence(value: Any, label: str) -> list[Any]:
    items = _array(value, label)
    if not items:
        _reject(f"{label} must not be empty")
    return items


def _profile_scenarios(
    config: dict[str, Any], profile: dict[str, Any]
) -> list[tuple[str, str, str | None]]:
    transport = profile.get("transport")
    if transport not in {"tcp", "udp"}:
        _reject("profile transport must be tcp or udp")
    cases = _unique_strings(profile.get("policy_cases"), "profile policy_cases")
    scenarios: list[tuple[str, str, str | None]] = []
    if "network_only" in cases:
        for mode in _config_sequence(config.get("modes"), "config modes"):
            if mode not in {"enforcing", "learning"}:
                _reject("config contains an unknown mode")
            scenarios.append(("network_only", mode, None))
    application_policy = f"application_{transport}"
    if application_policy in cases:
        scenarios.append((application_policy, "enforcing", None))
        for variant in _config_sequence(
            config.get("learning_variants"), "config learning_variants"
        ):
            if variant not in {"known_endpoint", "discovery_churn"}:
                _reject("config contains an unknown learning variant")
            scenarios.append((application_policy, "learning", variant))
    if not scenarios:
        _reject("profile contains no protected performance scenario")
    return scenarios


def _expected_group_contract(
    config: dict[str, Any], active_backends: Iterable[str]
) -> dict[
    tuple[str, str, str, str | None, str, float], tuple[str, str, int]
]:
    levels = _config_sequence(config.get("load_levels"), "config load_levels")
    numeric_levels = [
        _number(level, "config load level", strictly_positive=True) for level in levels
    ]
    if numeric_levels != sorted(set(numeric_levels)):
        _reject("config load_levels must be strictly increasing")
    profiles = _config_sequence(config.get("profiles"), "config profiles")
    seen_profiles: set[str] = set()
    groups: dict[
        tuple[str, str, str, str | None, str, float], tuple[str, str, int]
    ] = {}
    for profile_value in profiles:
        profile = _mapping(profile_value, "config profile")
        name = profile.get("name")
        if (
            not isinstance(name, str)
            or not IDENTIFIER_PATTERN.fullmatch(name)
            or name in seen_profiles
        ):
            _reject("config profile name is invalid or duplicated")
        seen_profiles.add(name)
        transport = profile.get("transport")
        direction = profile.get("direction")
        if direction not in {"inbound", "outbound"}:
            _reject("profile direction must be inbound or outbound")
        port = _integer(profile.get("port"), "profile port", 1, 65_535)
        for backend in active_backends:
            for load_level in numeric_levels:
                for policy, mode, variant in _profile_scenarios(config, profile):
                    key = (backend, policy, mode, variant, name, load_level)
                    if key in groups:
                        _reject("config creates a duplicate steady comparison group")
                    groups[key] = (transport, direction, port)
    return groups


def _phase_duration(config: dict[str, Any], role: str) -> float:
    phases = _mapping(config.get("phases"), "config phases")
    phase = _mapping(phases.get(role), f"config phase {role}")
    return _number(
        phase.get("duration_seconds"),
        f"config {role} duration",
        strictly_positive=True,
    )


def estimate_workload_seconds(config: dict[str, Any]) -> float:
    """Independently reproduce the runner's configured active-time estimate."""

    backends = _unique_strings(config.get("backends"), "config backends")
    if not backends or any(item not in {"nftables", "iptables"} for item in backends):
        _reject("config backends are missing, duplicated, or unsupported")
    repetitions = _integer(
        _path(config, "phases", "steady", "repetitions", label="steady repetitions"),
        "steady repetitions",
        MINIMUM_PAIRED_SAMPLES,
        20,
    )
    warmup = _phase_duration(config, "warmup")
    ramp = _phase_duration(config, "ramp")
    steady = _phase_duration(config, "steady")
    burst = _phase_duration(config, "burst")
    ramp_scales = _config_sequence(
        _path(config, "phases", "ramp", "scales", label="ramp scales"),
        "ramp scales",
    )
    cooldown = _number(
        _path(config, "phases", "cooldown_seconds", label="cooldown"),
        "cooldown",
        minimum=0.0,
    )
    profiles = _config_sequence(config.get("profiles"), "config profiles")
    levels = _config_sequence(config.get("load_levels"), "config load_levels")
    total = 0.0
    for _backend in backends:
        for profile_value in profiles:
            profile = _mapping(profile_value, "config profile")
            scenarios = _profile_scenarios(config, profile)
            for _level in levels:
                for _scenario in scenarios:
                    for repetition in range(1, repetitions + 1):
                        phase_durations = [warmup]
                        if repetition == 1:
                            phase_durations.extend(ramp for _ in ramp_scales)
                        phase_durations.append(steady)
                        if repetition == repetitions:
                            phase_durations.append(burst)
                        duration = sum(phase_durations)
                        # One independently prepared pristine block and one
                        # protected block exist in every AB/BA pair.
                        for _block in range(2):
                            total += duration
                            total += cooldown
    overload = _mapping(config.get("overload"), "config overload")
    enabled = overload.get("enabled")
    if not isinstance(enabled, bool):
        _reject("config overload.enabled must be boolean")
    if enabled:
        pause = _number(overload.get("pause_seconds"), "overload pause", minimum=0.0)
        client_duration = _number(
            overload.get("client_duration_seconds"),
            "overload client duration",
            strictly_positive=True,
        )
        attempts = _integer(
            overload.get("probe_attempts"), "overload probe attempts", 1, 100
        )
        timeout_seconds = _integer(
            overload.get("probe_timeout_ms"), "overload probe timeout", 1, 60_000
        ) / 1000.0
        recovery = _number(
            overload.get("recovery_duration_seconds"),
            "overload recovery duration",
            strictly_positive=True,
        )
        overload_window = (
            client_duration
            + pause
            + attempts * (2.0 * recovery + timeout_seconds)
            + 2.0 * recovery
            + timeout_seconds
            + recovery
        )
        total += overload_window * 2 * len(backends)
    return total


def _validate_configuration_identity(
    config: dict[str, Any], report: dict[str, Any]
) -> str:
    if config.get("schema") != CONFIG_SCHEMA:
        _reject(f"configuration schema must be {CONFIG_SCHEMA}")
    if report.get("schema") != REPORT_SCHEMA:
        _reject(f"report schema must be {REPORT_SCHEMA}")
    if "estimated_workload_seconds" in config:
        _reject("input configuration must not contain a derived workload estimate")
    reported = _mapping(report.get("configuration"), "report configuration")
    expected_keys = set(config) | {"estimated_workload_seconds"}
    if set(reported) != expected_keys:
        _reject("report configuration does not contain the exact checked-in key set")
    stripped = dict(reported)
    reported_estimate = stripped.pop("estimated_workload_seconds")
    if _canonical_json(stripped) != _canonical_json(config):
        _reject("report configuration differs from the checked-in configuration")
    expected_estimate = estimate_workload_seconds(config)
    _same_number(
        reported_estimate,
        expected_estimate,
        "report configuration workload estimate",
    )
    _same_number(
        report.get("estimated_workload_seconds"),
        expected_estimate,
        "report top-level workload estimate",
    )
    if report.get("seed") != config.get("seed"):
        _reject("report seed differs from the checked-in configuration")
    if report.get("description") != config.get("description"):
        _reject("report description differs from the checked-in configuration")
    if report.get("criteria") != config.get("criteria"):
        _reject("report criteria differ from the checked-in configuration")
    expected_reported = dict(config)
    expected_reported["estimated_workload_seconds"] = expected_estimate
    if _canonical_json(reported) != _canonical_json(expected_reported):
        _reject("report configuration is not the exact independently enriched configuration")
    digest = hashlib.sha256(_canonical_json(expected_reported)).hexdigest()
    recorded_digest = report.get("configuration_sha256")
    if (
        not isinstance(recorded_digest, str)
        or not SHA256_PATTERN.fullmatch(recorded_digest)
        or recorded_digest != digest
    ):
        _reject("report configuration SHA-256 is invalid")
    return digest


def _gate_specs(transport: str) -> tuple[tuple[str, str, str, str, str], ...]:
    if transport == "tcp":
        return (*COMMON_GATE_SPECS, *TCP_GATE_SPECS)
    if transport == "udp":
        return COMMON_GATE_SPECS
    _reject("steady result transport must be tcp or udp")


def _validate_metric_elapsed(metrics: dict[str, Any], label: str) -> float:
    if metrics.get("schema") != METRICS_SCHEMA:
        _reject(f"{label} metrics schema is invalid")
    started = _integer(
        metrics.get("started_at_monotonic_ns"),
        f"{label} metric start timestamp",
        1,
        (1 << 63) - 1,
    )
    finished = _integer(
        metrics.get("finished_at_monotonic_ns"),
        f"{label} metric finish timestamp",
        started,
        (1 << 63) - 1,
    )
    elapsed = _number(
        metrics.get("elapsed_seconds"), f"{label} metric elapsed time", strictly_positive=True
    )
    _same_number(
        elapsed,
        max((finished - started) / 1_000_000_000.0, 1e-9),
        f"{label} metric elapsed time",
    )
    return elapsed


def _validate_dut_nfqueue_selection(row: dict[str, Any], label: str) -> None:
    """Authenticate the mode-specific kernel queue used by DUT metrics."""

    mode = row.get("mode")
    if mode is None or mode == "enforcing":
        expected = ENFORCING_NFQUEUE_NUMBER
    elif mode == "learning":
        expected = LEARNING_NFQUEUE_NUMBER
    else:
        _reject(f"{label} has no defined NFQUEUE metrics queue")
    metrics = _mapping(row.get("dut_metrics"), f"{label} DUT metrics")
    nfqueue = _mapping(metrics.get("nfqueue"), f"{label} DUT NFQUEUE metrics")
    observed = _integer(
        nfqueue.get("queue_number"),
        f"{label} DUT NFQUEUE number",
        0,
        (1 << 16) - 1,
    )
    if observed != expected:
        _reject(
            f"{label} DUT NFQUEUE number {observed} does not match mode {mode!r}"
        )


def _validate_cgroup_cpu(row: dict[str, Any], label: str) -> tuple[float, float]:
    metrics = _mapping(row.get("dut_metrics"), f"{label} DUT metrics")
    elapsed = _validate_metric_elapsed(metrics, f"{label} DUT")
    cgroup = _mapping(metrics.get("cgroup"), f"{label} cgroup CPU")
    if cgroup.get("accounting") != "container_cgroup_minus_metric_collector":
        _reject(f"{label} cgroup CPU accounting mode is invalid")
    raw = _number(cgroup.get("raw_cpu_seconds"), f"{label} raw cgroup CPU", minimum=0.0)
    excluded = _number(
        cgroup.get("collector_cpu_seconds_excluded"),
        f"{label} excluded collector CPU",
        minimum=0.0,
    )
    adjusted = _number(cgroup.get("cpu_seconds"), f"{label} adjusted cgroup CPU", minimum=0.0)
    percent = _number(
        cgroup.get("cpu_percent_one_core"),
        f"{label} cgroup CPU percentage",
        minimum=0.0,
    )
    if excluded > raw + 1e-6:
        _reject(f"{label} excluded collector CPU exceeds raw cgroup CPU")
    _same_number(adjusted, max(0.0, raw - excluded), f"{label} adjusted cgroup CPU")
    _same_number(percent, adjusted * 100.0 / elapsed, f"{label} cgroup CPU percentage")
    return adjusted, percent


def _validate_workload_rates(row: dict[str, Any], label: str) -> tuple[float, float]:
    workload = _mapping(row.get("workload"), f"{label} workload")
    if workload.get("schema") != WORKLOAD_SCHEMA:
        _reject(f"{label} workload schema is invalid")
    metrics = _mapping(workload.get("metrics"), f"{label} workload metrics")
    wall = _number(
        metrics.get("wall_seconds"),
        f"{label} workload wall time",
        strictly_positive=True,
    )
    operations = _integer(
        metrics.get("operations"),
        f"{label} workload operations",
        0,
        (1 << 63) - 1,
    )
    bytes_sent = _integer(
        metrics.get("bytes_sent", 0),
        f"{label} workload bytes sent",
        0,
        (1 << 63) - 1,
    )
    bytes_received = _integer(
        metrics.get("bytes_received", 0),
        f"{label} workload bytes received",
        0,
        (1 << 63) - 1,
    )

    def rounded_rate_is_possible(observed: Any, numerator: float, field: str) -> float:
        value = _number(observed, f"{label} {field}", minimum=0.0)
        # The workload serializes wall time and rates independently to six
        # decimals.  Accept exactly the interval induced by that rounding,
        # rather than trusting either recorded rate as a primary measurement.
        wall_error = 0.5e-6
        value_error = 0.5e-6 + 1e-12
        lower_wall = max(wall - wall_error, 1e-9)
        upper_wall = wall + wall_error
        minimum_rate = numerator / upper_wall - value_error
        maximum_rate = numerator / lower_wall + value_error
        if not minimum_rate <= value <= maximum_rate:
            _reject(f"{label} {field} is inconsistent with raw counters and wall time")
        return value

    operation_rate = rounded_rate_is_possible(
        metrics.get("application_ops_per_second"),
        float(operations),
        "application operation rate",
    )
    throughput = rounded_rate_is_possible(
        metrics.get("application_mbps"),
        float(bytes_sent + bytes_received) * 8.0 / 1_000_000.0,
        "application throughput",
    )
    return operation_rate, throughput


def _validate_network_rates(
    row: dict[str, Any], side: str, label: str
) -> tuple[float, float]:
    """Authenticate collector and workload intervals used by network rates."""

    metrics = _mapping(row.get(side), f"{label} metrics")
    collector_elapsed = _validate_metric_elapsed(metrics, label)
    network = _mapping(metrics.get("network"), f"{label} network metrics")
    recorded_collector_elapsed = _number(
        network.get("collector_elapsed_seconds"),
        f"{label} recorded collector elapsed time",
        strictly_positive=True,
    )
    _same_number(
        recorded_collector_elapsed,
        collector_elapsed,
        f"{label} recorded collector elapsed time",
    )
    workload = _mapping(row.get("workload"), f"{label} workload")
    workload_metrics = _mapping(
        workload.get("metrics"), f"{label} workload metrics"
    )
    workload_wall = _number(
        workload_metrics.get("wall_seconds"),
        f"{label} workload wall time",
        strictly_positive=True,
    )
    rate_denominator = _number(
        network.get("rate_denominator_seconds"),
        f"{label} network-rate denominator",
        strictly_positive=True,
    )
    _same_number(
        rate_denominator,
        workload_wall,
        f"{label} network-rate denominator",
    )

    pps: list[float] = []
    mbps: list[float] = []
    for direction in ("rx", "tx"):
        packets = _integer(
            network.get(f"{direction}_packets"),
            f"{label} {direction.upper()} packets",
            0,
            (1 << 63) - 1,
        )
        octets = _integer(
            network.get(f"{direction}_bytes"),
            f"{label} {direction.upper()} bytes",
            0,
            (1 << 63) - 1,
        )
        packet_rate = packets / rate_denominator
        bit_rate = octets * 8.0 / rate_denominator / 1_000_000.0
        _same_number(
            network.get(f"{direction}_pps"),
            packet_rate,
            f"{label} {direction.upper()} PPS",
        )
        _same_number(
            network.get(f"{direction}_mbps"),
            bit_rate,
            f"{label} {direction.upper()} Mbps",
        )
        pps.append(packet_rate)
        mbps.append(bit_rate)
    return sum(pps), sum(mbps)


def _absolute_capacity_violations(
    row: dict[str, Any], criteria: dict[str, Any], label: str
) -> list[str]:
    """Recompute release-critical absolute limits from primary evidence.

    This deliberately does not trust ``capacity_pass`` or a runner-produced
    failure string.  It covers the absolute dimensions that remain hard gates
    when relative CPU and latency comparisons are advisory.
    """

    operation_rate, _throughput = _validate_workload_rates(row, label)
    _validate_network_rates(row, "dut_metrics", f"{label} DUT")
    _validate_network_rates(row, "peer_metrics", f"{label} peer")
    workload = _mapping(row.get("workload"), f"{label} workload")
    workload_config = _mapping(workload.get("config"), f"{label} workload config")
    target = _number(
        workload_config.get("target_application_ops_per_second"),
        f"{label} target application operation rate",
        strictly_positive=True,
    )
    derived = _mapping(row.get("derived"), f"{label} derived metrics")
    _same_number(
        derived.get("expected_application_ops_per_second"),
        target,
        f"{label} derived target application operation rate",
    )
    attainment = operation_rate / target
    _same_number(
        derived.get("target_attainment_ratio"),
        attainment,
        f"{label} derived target attainment ratio",
    )
    latency_p99 = _primary_metric(row, "latency_p99_ms", label)

    violations: list[str] = []
    if attainment < _number(
        criteria.get("minimum_target_ratio"),
        "minimum_target_ratio",
        minimum=0.0,
    ):
        violations.append("target attainment is below the configured minimum")
    if latency_p99 > _number(
        criteria.get("maximum_latency_p99_ms"),
        "maximum_latency_p99_ms",
        minimum=0.0,
    ):
        violations.append("absolute p99 latency exceeds the configured maximum")

    if row.get("policy") != "baseline":
        dut_metrics = _mapping(row.get("dut_metrics"), f"{label} DUT metrics")
        daemon = _mapping(dut_metrics.get("daemon"), f"{label} daemon metrics")
        daemon_cpu = _number(
            daemon.get("cpu_percent_one_core"),
            f"{label} daemon CPU",
            minimum=0.0,
        )
        daemon_rss = _number(
            daemon.get("rss_bytes_peak"),
            f"{label} daemon RSS",
            minimum=0.0,
        )
        cpu_criterion = (
            "maximum_burst_daemon_cpu_percent_one_core"
            if row.get("phase_role") == "burst"
            else "maximum_daemon_cpu_percent_one_core"
        )
        if daemon_cpu > _number(
            criteria.get(cpu_criterion),
            cpu_criterion,
            minimum=0.0,
        ):
            violations.append("absolute daemon CPU exceeds the configured maximum")
        if daemon_rss > _number(
            criteria.get("maximum_daemon_rss_bytes"),
            "maximum_daemon_rss_bytes",
            minimum=0.0,
        ):
            violations.append("absolute daemon RSS exceeds the configured maximum")
    return violations


def _validate_workload_identity(
    row: dict[str, Any], transport: str, port: int, label: str
) -> None:
    workload = _mapping(row.get("workload"), f"{label} workload")
    if workload.get("schema") != WORKLOAD_SCHEMA:
        _reject(f"{label} workload schema is invalid")
    if workload.get("event") != "summary" or workload.get("role") != "client":
        _reject(f"{label} workload is not a client summary")
    if workload.get("transport") != transport:
        _reject(f"{label} workload transport differs from its configured profile")
    if workload.get("port") != port:
        _reject(f"{label} workload port differs from its configured profile")


def _primary_metric(row: dict[str, Any], derived_field: str, label: str) -> float:
    if derived_field == "actual_application_ops_per_second":
        value, _throughput = _validate_workload_rates(row, label)
    elif derived_field == "actual_application_mbps":
        _operation_rate, value = _validate_workload_rates(row, label)
    elif derived_field == "aggregate_dut_pps":
        value, _network_mbps = _validate_network_rates(
            row, "dut_metrics", f"{label} DUT"
        )
    elif derived_field == "cgroup_cpu_percent_one_core":
        _adjusted, value = _validate_cgroup_cpu(row, label)
    elif derived_field.startswith("connect_latency_"):
        percentile = derived_field.removeprefix("connect_latency_").removesuffix("_ms")
        value = _path(
            row,
            "workload",
            "metrics",
            "connect_latency_ms",
            percentile,
            label=f"{label} TCP connect latency {percentile}",
        )
    elif derived_field.startswith("latency_"):
        percentile = derived_field.removeprefix("latency_").removesuffix("_ms")
        value = _path(
            row,
            "workload",
            "metrics",
            "latency_ms",
            percentile,
            label=f"{label} latency {percentile}",
        )
    else:
        _reject(f"unknown independent metric field: {derived_field}")
    result = _number(value, f"{label} {derived_field}", minimum=0.0)
    recorded = _path(row, "derived", derived_field, label=f"{label} derived {derived_field}")
    _same_number(recorded, result, f"{label} derived {derived_field}")
    return result


def _relative_percent(baseline: float, current: float, direction: str) -> float:
    if baseline <= 0:
        _reject("a paired relative metric has a zero or negative baseline")
    increase = (current - baseline) * 100.0 / baseline
    if not math.isfinite(increase):
        _reject("a paired relative metric produced a non-finite delta")
    if direction == "increase":
        return increase
    if direction == "reduction":
        return -increase
    _reject("a relative metric has an unknown direction")


def _comparison_key(row: dict[str, Any]) -> tuple[str, str, str, str | None, str, float]:
    backend = row.get("backend")
    policy = row.get("policy")
    mode = row.get("mode")
    variant = row.get("learning_variant")
    profile = row.get("profile")
    if not all(isinstance(value, str) for value in (backend, policy, mode, profile)):
        _reject("protected steady comparison identity is malformed")
    if variant is not None and not isinstance(variant, str):
        _reject("protected steady learning variant is malformed")
    load = _number(row.get("load_level"), "protected steady load level", strictly_positive=True)
    return backend, policy, mode, variant, profile, load


def _steady_measurement_intervals(
    row: dict[str, Any], label: str
) -> tuple[tuple[int, int], tuple[int, int], tuple[int, int]]:
    """Return independently checked DUT, peer, and workload intervals."""

    if row.get("phase_role") != "steady":
        _reject(f"{label} is not a steady result")
    dut = _mapping(row.get("dut_metrics"), f"{label} DUT metrics")
    peer = _mapping(row.get("peer_metrics"), f"{label} peer metrics")
    if dut.get("schema") != METRICS_SCHEMA or peer.get("schema") != METRICS_SCHEMA:
        _reject(f"{label} metric schema is invalid")

    def timestamp(value: Any, field: str) -> int:
        return _integer(value, f"{label} {field}", 1, (1 << 63) - 1)

    dut_started = timestamp(dut.get("started_at_monotonic_ns"), "DUT metric start")
    dut_finished = timestamp(dut.get("finished_at_monotonic_ns"), "DUT metric finish")
    peer_started = timestamp(peer.get("started_at_monotonic_ns"), "peer metric start")
    peer_finished = timestamp(peer.get("finished_at_monotonic_ns"), "peer metric finish")
    workload_started = timestamp(
        _path(
            row,
            "workload_started",
            "boundary_monotonic_ns",
            label=f"{label} workload start",
        ),
        "workload start",
    )
    workload_finished = timestamp(
        _path(
            row,
            "workload_finished",
            "boundary_monotonic_ns",
            label=f"{label} workload finish",
        ),
        "workload finish",
    )
    block_started = timestamp(row.get("block_started_monotonic_ns"), "block start")
    block_finished = timestamp(row.get("block_finished_monotonic_ns"), "block finish")
    if not (
        block_started
        <= dut_started
        <= workload_started
        < workload_finished
        <= dut_finished
        <= block_finished
    ):
        _reject(f"{label} DUT/workload intervals are not properly nested")
    if not (
        block_started
        <= peer_started
        <= workload_started
        < workload_finished
        <= peer_finished
        <= block_finished
    ):
        _reject(f"{label} peer/workload intervals are not properly nested")
    return (
        (dut_started, dut_finished),
        (peer_started, peer_finished),
        (workload_started, workload_finished),
    )


def _paired_measurement_gap_seconds(
    baseline: dict[str, Any], current: dict[str, Any], order: str
) -> float:
    """Recompute the conservative max(DUT, peer, workload) steady gap."""

    baseline_intervals = _steady_measurement_intervals(baseline, "baseline")
    current_intervals = _steady_measurement_intervals(current, "protected")
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
            _reject("paired steady intervals overlap or contradict their AB/BA order")
    return max(gaps) / 1_000_000_000.0


def _validate_pair_identity(
    baseline: dict[str, Any], current: dict[str, Any], repetitions: int
) -> tuple[int, str, str, str]:
    repetition = _integer(
        current.get("comparison_repetition"),
        "comparison repetition",
        1,
        repetitions,
    )
    if current.get("repetition") != repetition or current.get("phase") != f"steady_{repetition}":
        _reject("steady phase and comparison repetition disagree")
    pair_id = current.get("comparison_pair_id")
    sample_id = current.get("baseline_sample_id")
    if not isinstance(pair_id, str) or not PAIR_PATTERN.fullmatch(pair_id):
        _reject("comparison pair ID is malformed")
    if not isinstance(sample_id, str) or not BASELINE_PATTERN.fullmatch(sample_id):
        _reject("baseline sample ID is malformed")
    order = current.get("comparison_order")
    if order not in {"ab", "ba"}:
        _reject("comparison order must be ab or ba")
    if (
        baseline.get("backend") != current.get("backend")
        or baseline.get("profile") != current.get("profile")
        or baseline.get("load_level") != current.get("load_level")
        or baseline.get("phase") != current.get("phase")
        or baseline.get("repetition") != repetition
        or baseline.get("comparison_repetition") != repetition
        or baseline.get("comparison_pair_id") != pair_id
        or baseline.get("baseline_sample_id") != sample_id
        or baseline.get("policy") != "baseline"
        or baseline.get("mode") is not None
        or baseline.get("learning_variant") is not None
        or baseline.get("topology_role") != "baseline"
        or baseline.get("comparison_order") is not None
        or current.get("topology_role") != "protected"
    ):
        _reject("protected steady row does not match its pristine baseline identity")
    baseline_sequence = _integer(
        baseline.get("execution_sequence"), "baseline execution sequence", 0, 1 << 31
    )
    current_sequence = _integer(
        current.get("execution_sequence"), "protected execution sequence", 0, 1 << 31
    )
    if (order == "ab" and current_sequence != baseline_sequence + 1) or (
        order == "ba" and baseline_sequence != current_sequence + 1
    ):
        _reject("protected steady row is not adjacent to its predetermined baseline")
    baseline_started = _integer(
        baseline.get("block_started_monotonic_ns"), "baseline block start", 1, (1 << 63) - 1
    )
    baseline_finished = _integer(
        baseline.get("block_finished_monotonic_ns"),
        "baseline block finish",
        baseline_started,
        (1 << 63) - 1,
    )
    current_started = _integer(
        current.get("block_started_monotonic_ns"), "protected block start", 1, (1 << 63) - 1
    )
    current_finished = _integer(
        current.get("block_finished_monotonic_ns"),
        "protected block finish",
        current_started,
        (1 << 63) - 1,
    )
    if (order == "ab" and baseline_finished > current_started) or (
        order == "ba" and current_finished > baseline_started
    ):
        _reject("paired outer workload blocks overlap or contradict their AB/BA order")
    return repetition, pair_id, sample_id, order


def _validate_embedded_baseline(
    current: dict[str, Any], baseline: dict[str, Any], transport: str
) -> None:
    evidence = _mapping(current.get("baseline"), "embedded baseline evidence")
    expected_scalars = {
        "sample_id": baseline.get("baseline_sample_id"),
        "comparison_pair_id": baseline.get("comparison_pair_id"),
        "comparison_repetition": baseline.get("comparison_repetition"),
        "comparison_order": current.get("comparison_order"),
        "execution_sequence": baseline.get("execution_sequence"),
        "comparison_gap_seconds": current.get("comparison_gap_seconds"),
        "valid": baseline.get("valid"),
        "capacity_pass": baseline.get("capacity_pass"),
        "safety_pass": baseline.get("safety_pass"),
        "eligible": True,
    }
    for key, expected in expected_scalars.items():
        if evidence.get(key) != expected:
            _reject(f"embedded baseline {key} is inconsistent")
    fields = [DIAGNOSTIC_SPEC, *COMMON_GATE_SPECS]
    if transport == "tcp":
        fields.extend(TCP_GATE_SPECS)
    # Embedded evidence intentionally contains only primary baseline metrics,
    # not the names of their eventual percentage deltas.
    checked: set[str] = set()
    for _name, _direction, _criterion, _description, derived_field in fields:
        if derived_field in checked:
            continue
        checked.add(derived_field)
        value = _primary_metric(baseline, derived_field, "baseline")
        embedded_name = derived_field
        _same_number(
            evidence.get(embedded_name),
            value,
            f"embedded baseline {embedded_name}",
        )


def _validate_recorded_evidence(
    observed: Any, expected: list[dict[str, Any]], label: str
) -> None:
    records = _array(observed, label)
    if len(records) != len(expected):
        _reject(f"{label} has the wrong metric count")
    numeric_fields = {
        "threshold_percent",
        "confidence_level",
        "mean_percent",
        "lower_confidence_bound_percent",
    }
    for index, (actual_value, expected_value) in enumerate(
        zip(records, expected, strict=True)
    ):
        actual = _mapping(actual_value, f"{label}[{index}]")
        if set(actual) != set(expected_value):
            _reject(f"{label}[{index}] has missing or extra fields")
        for key, wanted in expected_value.items():
            if key in numeric_fields:
                if wanted is None:
                    if actual.get(key) is not None:
                        _reject(f"{label}[{index}].{key} must be null")
                else:
                    _same_number(
                        actual.get(key), float(wanted), f"{label}[{index}].{key}"
                    )
            elif actual.get(key) != wanted:
                _reject(f"{label}[{index}].{key} is inconsistent")


def _lower_confidence_bound(values: list[float]) -> float:
    if not MINIMUM_PAIRED_SAMPLES <= len(values) <= 20:
        _reject("paired sample count is outside the supported confidence table")
    mean = sum(values) / len(values)
    squared_error = sum((value - mean) ** 2 for value in values)
    deviation = math.sqrt(squared_error / (len(values) - 1))
    return mean - ONE_SIDED_T_95[len(values) - 1] * deviation / math.sqrt(len(values))


def validate_documents(
    config: dict[str, Any],
    report: dict[str, Any],
    *,
    require_passing: bool = True,
) -> dict[str, Any]:
    """Validate documents and return a small deterministic success summary.

    ``require_passing=False`` is intended for unit tests of correctly linked
    regression evidence.  The command-line release gate always requires a
    passing report.
    """

    if not isinstance(require_passing, bool):
        _reject("require_passing must be boolean")
    configuration_digest = _validate_configuration_identity(config, report)
    if require_passing and (
        report.get("valid") is not True or report.get("passed") is not True
    ):
        _reject("release report is not valid and passing")

    configured_backends = _unique_strings(config.get("backends"), "config backends")
    backend_records = _array(report.get("backends"), "report backends")
    status_by_backend: dict[str, str] = {}
    for item_value in backend_records:
        item = _mapping(item_value, "report backend")
        name = item.get("name")
        status = item.get("status")
        if name not in configured_backends or name in status_by_backend:
            _reject("report backend identity is missing, extra, or duplicated")
        if status not in {"passed", "failed", "unsupported"}:
            _reject("report backend status is invalid")
        status_by_backend[name] = status
    if set(status_by_backend) != set(configured_backends):
        _reject("report does not cover every configured backend")
    allow_unsupported = config.get("allow_unsupported_iptables")
    if not isinstance(allow_unsupported, bool):
        _reject("allow_unsupported_iptables must be boolean")
    active_backends: list[str] = []
    for backend in configured_backends:
        status = status_by_backend[backend]
        if status == "unsupported":
            if backend != "iptables" or not allow_unsupported:
                _reject("a required performance backend is unsupported")
            continue
        if require_passing and status != "passed":
            _reject("a required performance backend did not pass")
        active_backends.append(backend)
    if not active_backends:
        _reject("report contains no active performance backend")

    expected_groups = _expected_group_contract(config, active_backends)
    if not expected_groups:
        _reject("configuration produces no required steady comparison groups")
    repetitions = _integer(
        _path(config, "phases", "steady", "repetitions", label="steady repetitions"),
        "steady repetitions",
        MINIMUM_PAIRED_SAMPLES,
        20,
    )
    criteria = _mapping(config.get("criteria"), "config criteria")
    results = _array(report.get("results"), "report results")
    if not results:
        _reject("report has no normal performance results")

    for index, value in enumerate(results):
        row = _mapping(value, f"performance result {index}")
        if row.get("backend") in active_backends:
            _validate_dut_nfqueue_selection(row, f"performance result {index}")
        if (
            row.get("backend") not in active_backends
            or row.get("phase_role") not in {"steady", "burst"}
        ):
            continue
        violations = _absolute_capacity_violations(
            row, criteria, f"performance result {index}"
        )
        if violations and row.get("capacity_pass") is True:
            _reject(
                "capacity_pass ignored independently recomputed absolute gate(s): "
                + "; ".join(violations)
            )
        if require_passing and (
            violations
            or row.get("valid") is not True
            or row.get("safety_pass") is not True
            or row.get("capacity_pass") is not True
            or row.get("passed") is not True
        ):
            _reject("a release gate row is invalid, unsafe, or over an absolute limit")

    baseline_rows: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    protected_rows: list[dict[str, Any]] = []
    active_baseline_count = 0
    for value in results:
        row = _mapping(value, "performance result")
        if row.get("phase_role") != "steady":
            continue
        backend = row.get("backend")
        if row.get("policy") == "baseline":
            if backend not in active_backends:
                continue
            key = (
                str(backend),
                str(row.get("baseline_sample_id")),
                str(row.get("comparison_pair_id")),
                str(row.get("phase")),
            )
            baseline_rows.setdefault(key, []).append(row)
            active_baseline_count += 1
        else:
            if backend not in active_backends:
                _reject("unsupported backend emitted a protected steady row")
            protected_rows.append(row)

    groups: dict[
        tuple[str, str, str, str | None, str, float],
        list[tuple[dict[str, Any], dict[str, Any], dict[str, float], tuple[int, str, str, str]]],
    ] = {}
    used_pairs: set[tuple[str, str]] = set()
    used_baselines: set[tuple[str, str]] = set()
    for current in protected_rows:
        key = _comparison_key(current)
        profile_shape = expected_groups.get(key)
        if profile_shape is None:
            _reject(f"unexpected protected steady group: {key!r}")
        transport, direction, port = profile_shape
        sample_id = current.get("baseline_sample_id")
        pair_id = current.get("comparison_pair_id")
        phase = current.get("phase")
        candidate_key = (str(current.get("backend")), str(sample_id), str(pair_id), str(phase))
        candidates = baseline_rows.get(candidate_key, [])
        if len(candidates) != 1:
            _reject("protected steady row has no unique pristine baseline")
        baseline = candidates[0]
        identity = _validate_pair_identity(baseline, current, repetitions)
        repetition, validated_pair, validated_sample, _order = identity
        if baseline.get("transport") != transport or current.get("transport") != transport:
            _reject("steady pair transport differs from its configured profile")
        if baseline.get("direction") != direction or current.get("direction") != direction:
            _reject("steady pair direction differs from its configured profile")
        _validate_workload_identity(baseline, transport, port, "baseline")
        _validate_workload_identity(current, transport, port, "protected")
        if baseline.get("comparison_gap_seconds") is not None:
            _reject("pristine baseline row must not carry a comparison gap")
        expected_gap = _paired_measurement_gap_seconds(baseline, current, _order)
        _same_number(
            current.get("comparison_gap_seconds"),
            expected_gap,
            "paired steady comparison gap",
        )
        maximum_gap = _number(
            criteria.get("maximum_comparison_gap_seconds"),
            "maximum_comparison_gap_seconds",
            strictly_positive=True,
        )
        if expected_gap > maximum_gap:
            _reject("paired steady comparison gap exceeded the configured bound")
        qualified_pair = (str(current.get("backend")), validated_pair)
        qualified_sample = (str(current.get("backend")), validated_sample)
        if qualified_pair in used_pairs or qualified_sample in used_baselines:
            _reject("a comparison pair or pristine baseline was reused")
        used_pairs.add(qualified_pair)
        used_baselines.add(qualified_sample)
        if (
            baseline.get("valid") is not True
            or baseline.get("capacity_pass") is not True
            or baseline.get("safety_pass") is not True
            or current.get("valid") is not True
            or current.get("capacity_pass") is not True
            or current.get("safety_pass") is not True
        ):
            _reject("a steady pair is invalid, unsafe, or capacity-ineligible")
        _validate_embedded_baseline(current, baseline, transport)

        all_specs = (DIAGNOSTIC_SPEC, *_gate_specs(transport))
        expected_overhead: dict[str, float] = {}
        for name, direction, criterion, _description, derived_field in all_specs:
            baseline_value = _primary_metric(
                baseline, derived_field, f"baseline repetition {repetition}"
            )
            current_value = _primary_metric(
                current, derived_field, f"protected repetition {repetition}"
            )
            if name == "cgroup_cpu_increase_percent":
                threshold = _number(
                    criteria.get(str(criterion)), str(criterion), strictly_positive=True
                )
                baseline_cpu_seconds = _number(
                    _path(
                        baseline,
                        "dut_metrics",
                        "cgroup",
                        "cpu_seconds",
                        label="baseline adjusted cgroup CPU",
                    ),
                    "baseline adjusted cgroup CPU",
                    minimum=0.0,
                )
                minimum_resolved = (
                    2.0
                    * CGROUP_CPU_ACCOUNTING_RESOLUTION_SECONDS
                    * 100.0
                    / threshold
                )
                if baseline_cpu_seconds < minimum_resolved:
                    _reject("baseline cgroup CPU cannot resolve the configured threshold")
            expected_overhead[name] = _relative_percent(
                baseline_value, current_value, direction
            )
        observed_overhead = _mapping(
            current.get("overhead_vs_baseline"), "paired overhead evidence"
        )
        if set(observed_overhead) != set(expected_overhead):
            _reject("paired overhead evidence has missing or extra metrics")
        for name, expected in expected_overhead.items():
            _same_number(
                observed_overhead.get(name), expected, f"paired overhead {name}"
            )

        expected_observations = [
            f"single paired window observed {description} above the configured bound"
            for name, _direction, criterion, description, _derived in _gate_specs(transport)
            if expected_overhead[name]
            > _number(criteria.get(criterion), criterion, minimum=0.0)
        ]
        observations = _unique_strings(
            current.get("relative_performance_observation_reasons"),
            "relative observation reasons",
        )
        if observations != expected_observations:
            _reject("relative observation reasons do not match per-pair threshold crossings")
        groups.setdefault(key, []).append(
            (current, baseline, expected_overhead, identity)
        )

    if set(groups) != set(expected_groups):
        missing = len(set(expected_groups) - set(groups))
        extra = len(set(groups) - set(expected_groups))
        _reject(f"steady comparison group coverage mismatch (missing={missing}, extra={extra})")
    if active_baseline_count != len(protected_rows):
        _reject("pristine steady baseline count does not match protected comparisons")

    regressed_groups = 0
    metric_evidence_count = 0
    for key, records in groups.items():
        transport, _direction, _port = expected_groups[key]
        records.sort(key=lambda item: item[3][0])
        observed_repetitions = [item[3][0] for item in records]
        pair_ids = [item[3][1] for item in records]
        baseline_ids = [item[3][2] for item in records]
        orders = [item[3][3] for item in records]
        if (
            len(records) != repetitions
            or observed_repetitions != list(range(1, repetitions + 1))
            or len(set(pair_ids)) != repetitions
            or len(set(baseline_ids)) != repetitions
            or set(orders) != {"ab", "ba"}
            or abs(orders.count("ab") - orders.count("ba")) > 1
        ):
            _reject(f"steady comparison group is incomplete or unbalanced: {key!r}")

        expected_evidence: list[dict[str, Any]] = []
        expected_failure_reasons: list[str] = []
        for name, _direction, criterion, description, _derived in _gate_specs(transport):
            values = [item[2][name] for item in records]
            mean = sum(values) / len(values)
            lower_bound = _lower_confidence_bound(values)
            threshold = _number(criteria.get(criterion), criterion, minimum=0.0)
            mean_exceeded = mean > threshold
            confirmed = lower_bound > threshold
            if confirmed and not mean_exceeded:
                _reject("confidence evidence exceeds a mean that did not exceed its threshold")
            release_action = (
                "observe" if _criterion_is_advisory(criterion, criteria) else "fail"
            )
            if confirmed and release_action == "fail":
                expected_failure_reasons.append(
                    "independent paired confidence bound for "
                    f"{description} exceeded the configured bound"
                )
            expected_evidence.append(
                {
                    "metric": name,
                    "description": description,
                    "threshold_percent": threshold,
                    "sample_count": repetitions,
                    "minimum_sample_count": MINIMUM_PAIRED_SAMPLES,
                    "confidence_level": CONFIDENCE_LEVEL,
                    "method": "arithmetic_mean_of_independent_paired_deltas",
                    "confirmation_method": "one_sided_paired_student_t_mean_lower_bound",
                    "independent_pair_ids": pair_ids,
                    "baseline_sample_ids": baseline_ids,
                    "comparison_orders": orders,
                    "independent_pairs_valid": True,
                    "mean_percent": mean,
                    "mean_exceeded_threshold": mean_exceeded,
                    "lower_confidence_bound_percent": lower_bound,
                    "confirmed_regression": confirmed,
                    "release_action": release_action,
                }
            )
        expected_failure_reasons.sort()
        metric_evidence_count += len(expected_evidence)
        if expected_failure_reasons:
            regressed_groups += 1
        for current, _baseline, _overhead, _identity in records:
            _validate_recorded_evidence(
                current.get("relative_performance_evidence"),
                expected_evidence,
                "steady relative-performance evidence",
            )
            failures = _unique_strings(
                current.get("relative_performance_failure_reasons"),
                "relative performance failure reasons",
            )
            if failures != expected_failure_reasons:
                _reject(
                    "relative performance failure reasons are not linked to "
                    "confirmed group regressions"
                )
            expected_relative_pass = not expected_failure_reasons
            if current.get("relative_performance_pass") is not expected_relative_pass:
                _reject(
                    "relative_performance_pass is not linked to recomputed "
                    "confidence bounds"
                )
            expected_pass = (
                current.get("safety_pass") is True
                and current.get("capacity_pass") is True
                and expected_relative_pass
            )
            if current.get("passed") is not expected_pass:
                _reject(
                    "steady passed flag is not linked to safety, capacity, "
                    "and relative gates"
                )

    burst_baselines: dict[
        tuple[str, str, str, str, float, str], list[dict[str, Any]]
    ] = {}
    protected_bursts: list[dict[str, Any]] = []
    for value in results:
        row = _mapping(value, "performance result")
        if row.get("phase_role") != "burst":
            continue
        backend = row.get("backend")
        if backend not in active_backends:
            if row.get("policy") != "baseline":
                _reject("unsupported backend emitted a protected burst row")
            continue
        load = _number(row.get("load_level"), "burst load level", strictly_positive=True)
        sample_id = row.get("baseline_sample_id")
        pair_id = row.get("comparison_pair_id")
        profile = row.get("profile")
        phase = row.get("phase")
        if (
            not isinstance(sample_id, str)
            or not BASELINE_PATTERN.fullmatch(sample_id)
            or not isinstance(pair_id, str)
            or not PAIR_PATTERN.fullmatch(pair_id)
            or not isinstance(profile, str)
            or phase != "burst"
        ):
            _reject("burst comparison identity is malformed")
        if row.get("policy") == "baseline":
            key = (str(backend), sample_id, pair_id, profile, load, phase)
            burst_baselines.setdefault(key, []).append(row)
        else:
            protected_bursts.append(row)

    burst_group_keys: set[tuple[str, str, str, str | None, str, float]] = set()
    regressed_bursts = 0
    for current in protected_bursts:
        group_key = _comparison_key(current)
        profile_shape = expected_groups.get(group_key)
        if profile_shape is None or group_key in burst_group_keys:
            _reject("protected burst group is unexpected or duplicated")
        burst_group_keys.add(group_key)
        transport, direction, port = profile_shape
        if current.get("transport") != transport or current.get("direction") != direction:
            _reject("protected burst shape differs from its configured profile")
        repetition = _integer(
            current.get("comparison_repetition"),
            "burst comparison repetition",
            1,
            repetitions,
        )
        if repetition != repetitions or current.get("repetition") is not None:
            _reject("burst is not attached to the final independent comparison pair")
        sample_id = str(current.get("baseline_sample_id"))
        pair_id = str(current.get("comparison_pair_id"))
        load = _number(current.get("load_level"), "burst load level", strictly_positive=True)
        candidate_key = (
            str(current.get("backend")),
            sample_id,
            pair_id,
            str(current.get("profile")),
            load,
            "burst",
        )
        candidates = burst_baselines.get(candidate_key, [])
        if len(candidates) != 1:
            _reject("protected burst row has no unique pristine burst baseline")
        baseline = candidates[0]
        order = current.get("comparison_order")
        if (
            order not in {"ab", "ba"}
            or baseline.get("comparison_order") is not None
            or baseline.get("comparison_repetition") != repetition
            or baseline.get("repetition") is not None
            or baseline.get("topology_role") != "baseline"
            or current.get("topology_role") != "protected"
            or baseline.get("transport") != transport
            or baseline.get("direction") != direction
        ):
            _reject("protected burst row does not match its pristine baseline identity")
        baseline_sequence = _integer(
            baseline.get("execution_sequence"),
            "burst baseline execution sequence",
            0,
            1 << 31,
        )
        current_sequence = _integer(
            current.get("execution_sequence"),
            "protected burst execution sequence",
            0,
            1 << 31,
        )
        if (order == "ab" and current_sequence != baseline_sequence + 1) or (
            order == "ba" and baseline_sequence != current_sequence + 1
        ):
            _reject("protected burst is not adjacent to its predetermined baseline")
        steady_records = groups.get(group_key, [])
        final_steady = [
            record
            for record in steady_records
            if record[3][0] == repetitions
        ]
        if (
            len(final_steady) != 1
            or final_steady[0][3][1] != pair_id
            or final_steady[0][3][2] != sample_id
            or final_steady[0][3][3] != order
        ):
            _reject("burst does not reuse the final authenticated steady pair")
        if (
            baseline.get("valid") is not True
            or baseline.get("capacity_pass") is not True
            or baseline.get("safety_pass") is not True
            or current.get("valid") is not True
            or current.get("capacity_pass") is not True
            or current.get("safety_pass") is not True
        ):
            _reject("a burst pair is invalid, unsafe, or capacity-ineligible")
        _validate_workload_identity(baseline, transport, port, "burst baseline")
        _validate_workload_identity(current, transport, port, "protected burst")
        _validate_embedded_baseline(current, baseline, transport)

        expected_overhead: dict[str, float] = {}
        for name, direction_name, criterion, _description, derived_field in (
            DIAGNOSTIC_SPEC,
            *_gate_specs(transport),
        ):
            baseline_value = _primary_metric(
                baseline, derived_field, "burst baseline"
            )
            current_value = _primary_metric(
                current, derived_field, "protected burst"
            )
            if name == "cgroup_cpu_increase_percent":
                threshold = _number(
                    criteria.get(str(criterion)),
                    str(criterion),
                    strictly_positive=True,
                )
                baseline_cpu_seconds = _number(
                    _path(
                        baseline,
                        "dut_metrics",
                        "cgroup",
                        "cpu_seconds",
                        label="burst baseline adjusted cgroup CPU",
                    ),
                    "burst baseline adjusted cgroup CPU",
                    minimum=0.0,
                )
                minimum_resolved = (
                    2.0
                    * CGROUP_CPU_ACCOUNTING_RESOLUTION_SECONDS
                    * 100.0
                    / threshold
                )
                if baseline_cpu_seconds < minimum_resolved:
                    _reject("burst baseline cgroup CPU cannot resolve the configured threshold")
            expected_overhead[name] = _relative_percent(
                baseline_value, current_value, direction_name
            )
        observed_overhead = _mapping(
            current.get("overhead_vs_baseline"), "burst paired overhead evidence"
        )
        if set(observed_overhead) != set(expected_overhead):
            _reject("burst paired overhead evidence has missing or extra metrics")
        for name, expected in expected_overhead.items():
            _same_number(
                observed_overhead.get(name), expected, f"burst paired overhead {name}"
            )

        expected_observations = [
            f"single paired window observed {description} above the configured bound"
            for name, _direction, criterion, description, _derived in _gate_specs(transport)
            if expected_overhead[name]
            > _number(criteria.get(criterion), criterion, minimum=0.0)
        ]
        if _unique_strings(
            current.get("relative_performance_observation_reasons"),
            "burst relative observation reasons",
        ) != expected_observations:
            _reject("burst relative observations do not match threshold crossings")

        expected_evidence: list[dict[str, Any]] = []
        expected_failure_reasons: list[str] = []
        for name, _direction, criterion, description, _derived in _gate_specs(transport):
            observed = expected_overhead[name]
            threshold = _number(criteria.get(criterion), criterion, minimum=0.0)
            mean_exceeded = observed > threshold
            # One burst pair cannot establish a relative regression. Its
            # crossing is authenticated below, while absolute capacity and
            # fail-closed safety remain mandatory independently.
            release_action = "observe"
            expected_evidence.append(
                {
                    "metric": name,
                    "description": description,
                    "threshold_percent": threshold,
                    "sample_count": 1,
                    "minimum_sample_count": MINIMUM_PAIRED_SAMPLES,
                    "confidence_level": CONFIDENCE_LEVEL,
                    "method": "single_paired_burst_observation",
                    "mean_percent": observed,
                    "mean_exceeded_threshold": mean_exceeded,
                    "lower_confidence_bound_percent": None,
                    "confirmed_regression": False,
                    "release_action": release_action,
                }
            )
        expected_failure_reasons.sort()
        _validate_recorded_evidence(
            current.get("relative_performance_evidence"),
            expected_evidence,
            "burst relative-performance evidence",
        )
        if _unique_strings(
            current.get("relative_performance_failure_reasons"),
            "burst relative performance failure reasons",
        ) != expected_failure_reasons:
            _reject("burst relative failure reasons are not linked to raw evidence")
        expected_relative_pass = not expected_failure_reasons
        if current.get("relative_performance_pass") is not expected_relative_pass:
            _reject("burst relative_performance_pass is not linked to raw evidence")
        expected_pass = (
            current.get("safety_pass") is True
            and current.get("capacity_pass") is True
            and expected_relative_pass
        )
        if current.get("passed") is not expected_pass:
            _reject("burst passed flag is not linked to safety, capacity, and relative gates")
        if expected_failure_reasons:
            regressed_bursts += 1

    if burst_group_keys != set(expected_groups):
        _reject("burst comparison group coverage does not match the configured matrix")

    if require_passing and (regressed_groups or regressed_bursts):
        _reject(
            f"{regressed_groups} steady group(s) and {regressed_bursts} burst(s) "
            "exceed a blocking relative threshold"
        )
    return {
        "schema": VALIDATION_SCHEMA,
        "valid": True,
        "configuration_sha256": configuration_digest,
        "group_count": len(groups),
        "pair_count": len(protected_rows),
        "metric_evidence_count": metric_evidence_count,
        "regressed_group_count": regressed_groups,
        "regressed_burst_count": regressed_bursts,
    }


def validate_files(
    config_path: Path | str,
    report_path: Path | str,
    *,
    require_passing: bool = True,
) -> dict[str, Any]:
    """Load and independently validate a config/report pair."""

    config = load_json_object(
        config_path, maximum_bytes=MAX_CONFIG_BYTES, context="performance configuration"
    )
    report = load_json_object(
        report_path, maximum_bytes=MAX_REPORT_BYTES, context="performance report"
    )
    return validate_documents(config, report, require_passing=require_passing)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("report", type=Path)
    arguments = parser.parse_args(argv)
    try:
        summary = validate_files(arguments.config, arguments.report)
    except (ValidationError, OSError, OverflowError, ValueError, TypeError) as error:
        message = str(error).replace("\x00", " ")[-4096:]
        print(
            f"independent performance validation failed: {message}",
            file=sys.stderr,
        )
        return 1
    print(
        json.dumps(summary, sort_keys=True, separators=(",", ":"), allow_nan=False),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
