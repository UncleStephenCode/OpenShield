#!/usr/bin/env python3
"""Bounded, real-socket attribution contention reproduction (not a throughput gate)."""

from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import json
import math
import multiprocessing
import os
import queue
import re
import resource
import select
import socket
import subprocess
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("delayed_transport", HERE / "delayed-icmp.py")
assert SPEC is not None and SPEC.loader is not None
DELAYED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DELAYED)
STAGE_SECONDS = 20.0
WARMUP_SECONDS = 5.0
RATES = (20, 50, 100)
DURATION = WARMUP_SECONDS + len(RATES) * STAGE_SECONDS
UNKNOWN_SEQUENCE = 1_000_000
MAX_PENDING = 128
UDP_PPS = int(os.environ.get("CONTINUOUS_UDP_PPS", "2"))
if not 1 <= UDP_PPS <= 20:
    raise ValueError("CONTINUOUS_UDP_PPS must be inside 1..20")
TCP_PPS = 2


def emit(event: str, **fields: object) -> None:
    print(json.dumps({"event": event, "monotonic": time.monotonic(), **fields}, sort_keys=True), flush=True)


def barrier(path: Path) -> float:
    deadline = time.monotonic() + 30.0
    while not path.exists():
        if time.monotonic() >= deadline:
            raise TimeoutError("workload start barrier missing")
        time.sleep(0.02)
    start = float(path.read_text(encoding="ascii"))
    if not math.isfinite(start) or abs(start - time.monotonic()) > 10.0:
        raise ValueError("invalid workload start timestamp")
    while time.monotonic() < start:
        time.sleep(min(0.02, start - time.monotonic()))
    return start


def known(address: str, udp_port: int, tcp_port: int, start_file: Path) -> None:
    start = barrier(start_file)
    emit("configuration", udp_pps=UDP_PPS, tcp_pps=TCP_PPS, duration=DURATION, stage_seconds=STAGE_SECONDS, warmup_seconds=WARMUP_SECONDS, churn_rates=list(RATES))
    sent: dict[tuple[str, int], float] = {}
    received: set[tuple[str, int]] = set()
    streams: dict[socket.socket, str] = {}
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.connect((address, udp_port))
    udp.setblocking(False)
    streams[udp] = "udp"
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setblocking(False)
    connect_start = time.monotonic()
    outcome = tcp.connect_ex((address, tcp_port))
    if outcome not in (0, errno.EINPROGRESS):
        raise OSError(outcome, "TCP connect failed")
    _, connected, _ = select.select([], [tcp], [], 3.0)
    if not connected or tcp.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR):
        emit("connect_error", transport="tcp")
        tcp.close()
    else:
        emit("connected", transport="tcp", latency_ms=(time.monotonic() - connect_start) * 1000)
        streams[tcp] = "tcp"
    next_sequences = {"udp":1, "tcp":1}
    rates = {"udp":UDP_PPS, "tcp":TCP_PPS}
    tcp_buffer = bytearray()
    try:
        while time.monotonic() < start + DURATION + 4.0:
            now = time.monotonic()
            for stream, transport in list(streams.items()):
                sequence = next_sequences[transport]
                if sequence <= int(DURATION * rates[transport]) and now >= start + (sequence - 1) / rates[transport]:
                    payload = DELAYED.udp_payload(sequence) if transport == "udp" else DELAYED.TCP_REQUEST.pack(DELAYED.MAGIC, sequence, 55, 0)
                    sent_at = time.monotonic()
                    try:
                        written = stream.send(payload)
                        if written != len(payload):
                            raise RuntimeError("short nonblocking write")
                        sent[(transport, sequence)] = sent_at
                        emit("sent", transport=transport, sequence=sequence, elapsed=sent_at-start)
                    except OSError as error:
                        emit("send_error", transport=transport, sequence=sequence, error=str(error))
                    next_sequences[transport] += 1
            readable, _, _ = select.select(list(streams), [], [], 0.01)
            for stream in readable:
                transport = streams[stream]
                try:
                    payload = stream.recv(4096)
                except OSError as error:
                    emit("receive_error", transport=transport, error=str(error))
                    continue
                if transport == "tcp":
                    if not payload:
                        emit("closed", transport="tcp")
                        del streams[stream]
                        continue
                    tcp_buffer.extend(payload)
                    sequences = []
                    while len(tcp_buffer) >= DELAYED.TCP_RESPONSE.size:
                        magic, number = DELAYED.TCP_RESPONSE.unpack(tcp_buffer[:DELAYED.TCP_RESPONSE.size])
                        del tcp_buffer[:DELAYED.TCP_RESPONSE.size]
                        if magic != DELAYED.MAGIC:
                            raise RuntimeError("invalid TCP response")
                        sequences.append(number)
                else:
                    sequences = [DELAYED.parse_udp_payload(payload)]
                for number in sequences:
                    key = (transport, number)
                    if key not in sent or key in received:
                        raise RuntimeError("unknown or duplicate response")
                    received.add(key)
                    emit("received", transport=transport, sequence=number, elapsed=sent[key]-start, latency_ms=(time.monotonic()-sent[key])*1000)
        for transport, number in sorted(set(sent) - received):
            emit("lost", transport=transport, sequence=number, elapsed=sent[(transport, number)]-start)
        usage = resource.getrusage(resource.RUSAGE_SELF)
        emit("summary", sent=len(sent), received=len(received), cpu_seconds=usage.ru_utime+usage.ru_stime, duration=DURATION)
    finally:
        udp.close()
        tcp.close()


def churn(address: str, udp_port: int, tcp_port: int, start_file: Path) -> None:
    start = barrier(start_file)
    pending: dict[socket.socket, tuple[str, int, float, bool]] = {}
    attempted = admitted = capacity_limited = late = 0
    sequence = UNKNOWN_SEQUENCE
    next_attempt = start + WARMUP_SECONDS
    try:
        while time.monotonic() < start + DURATION + 0.5:
            now = time.monotonic()
            stage = int(max(0.0, now-start-WARMUP_SECONDS) // STAGE_SECONDS)
            if now >= next_attempt and stage < len(RATES):
                rate = RATES[stage]
                if now-next_attempt > 0.05:
                    late += 1
                next_attempt += 1.0/rate
                if len(pending) >= MAX_PENDING:
                    capacity_limited += 1
                    continue
                protocol = "udp" if sequence % 2 == 0 else "tcp"
                stream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM)
                stream.setblocking(False)
                attempted += 1
                if protocol == "udp":
                    stream.connect((address, udp_port))
                    stream.send(DELAYED.udp_payload(sequence))
                    # Some sockets vanish before attribution; others remain long
                    # enough to force a complete, negative identity scan.
                    if sequence % 4 == 0:
                        stream.close()
                    else:
                        pending[stream] = (protocol, sequence, now+0.4, True)
                else:
                    result = stream.connect_ex((address, tcp_port))
                    if result not in (0, errno.EINPROGRESS):
                        emit("churn_socket_error", error=os.strerror(result))
                        stream.close()
                    else:
                        pending[stream] = (protocol, sequence, now+0.4, False)
                emit("attempt", transport=protocol, sequence=sequence, elapsed=now-start, rate=rate)
                sequence += 1
            readable, writable, _ = select.select(list(pending), [s for s, item in pending.items() if item[0] == "tcp" and not item[3]], [], 0.002)
            for stream in writable:
                protocol, number, deadline, _ = pending[stream]
                error = stream.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if error:
                    emit("churn_connect_error", sequence=number, error=os.strerror(error))
                    stream.close()
                    del pending[stream]
                    continue
                admitted += 1
                emit("unknown_tcp_connected", sequence=number)
                stream.send(DELAYED.TCP_REQUEST.pack(DELAYED.MAGIC, number, 55, 1))
                pending[stream] = (protocol, number, deadline, True)
            for stream in readable:
                if stream not in pending:
                    continue
                protocol, number, _, _ = pending[stream]
                try:
                    payload = stream.recv(4096)
                    if payload:
                        emit("unknown_received", transport=protocol, sequence=number)
                except OSError as error:
                    emit("churn_receive_error", transport=protocol, error=str(error))
                stream.close()
                del pending[stream]
            for stream, (_, _, deadline, _) in list(pending.items()):
                if time.monotonic() >= deadline:
                    stream.close()
                    del pending[stream]
        usage = resource.getrusage(resource.RUSAGE_SELF)
        emit("churn_summary", attempted=attempted, connected=admitted, capacity_limited=capacity_limited, late=late, cpu_seconds=usage.ru_utime+usage.ru_stime, duration=DURATION)
    finally:
        for stream in pending:
            stream.close()


def ping(address: str, start_file: Path) -> None:
    start = barrier(start_file)
    command = ["/tmp/continuous-ping", "-n", "-c", str(int(DURATION)), "-i", "1", "-W", "3", address]
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env={**os.environ, "LC_ALL":"C"}) as process:
        assert process.stdout is not None
        for line in process.stdout:
            match = re.search(r"icmp_seq=(\d+).*time[=<]([0-9.]+) ms", line)
            if match:
                number = int(match.group(1))
                emit("received", transport="icmp", sequence=number, elapsed=float(number-1), latency_ms=float(match.group(2)))
            else:
                emit("ping_output", text=line.rstrip(), elapsed=time.monotonic()-start)
        emit("ping_summary", returncode=process.wait(), sent=int(DURATION))


def monitor(pid: int, start_file: Path) -> None:
    start = barrier(start_file)
    ticks = os.sysconf("SC_CLK_TCK")
    previous: tuple[float, int] | None = None
    while time.monotonic() < start+DURATION+5.0:
        now = time.monotonic()
        data: dict[str, object] = {"elapsed": now-start, "queues": {}}
        path = Path("/proc/net/netfilter/nfnetlink_queue")
        if path.exists():
            queues = {}
            for line in path.read_text(encoding="ascii").splitlines():
                fields = [int(field) for field in line.split()]
                if len(fields) >= 9 and fields[0] in DELAYED.NFQUEUE_NUMBERS:
                    queues[str(fields[0])] = dict(zip(("depth", "copy_mode", "copy_range", "kernel_dropped", "user_dropped", "sequence"), fields[2:8]))
            data["queues"] = queues
        if pid:
            try:
                fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
                cpu_ticks = int(fields[11])+int(fields[12])
                if previous:
                    data["cpu_percent"] = 100*(cpu_ticks-previous[1])/ticks/(now-previous[0])
                previous = (now, cpu_ticks)
                data["threads"] = int(fields[17])
                data["rss_bytes"] = int(fields[21])*os.sysconf("SC_PAGE_SIZE")
            except (FileNotFoundError, ProcessLookupError):
                data["daemon_missing"] = True
        emit("monitor", **data)
        time.sleep(0.1)


def noise_child(release: object, ready: object) -> None:
    descriptors = [open("/dev/null", "rb", buffering=0) for _ in range(256)]
    threads = [threading.Thread(target=release.wait, args=(120.0,)) for _ in range(32)]
    for thread in threads:
        thread.start()
    ready.put(os.getpid())
    release.wait(120.0)
    release.set()
    for thread in threads:
        thread.join()
    for descriptor in descriptors:
        descriptor.close()


def noise(ready_path: Path, release_path: Path) -> None:
    context = multiprocessing.get_context("fork")
    release = context.Event()
    ready = context.Queue()
    children = [context.Process(target=noise_child, args=(release, ready)) for _ in range(16)]
    try:
        for child in children:
            child.start()
        deadline = time.monotonic()+20
        observed = set()
        while len(observed) < len(children):
            if time.monotonic() >= deadline:
                raise TimeoutError("static noise startup timed out")
            try:
                observed.add(ready.get(timeout=0.1))
            except queue.Empty:
                if any(child.exitcode for child in children):
                    raise RuntimeError("static noise child exited early")
        ready_path.write_text("ready\n", encoding="ascii")
        deadline = time.monotonic()+100
        while not release_path.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("static noise was not released")
            if any(child.exitcode is not None for child in children):
                raise RuntimeError("static noise did not remain active")
            time.sleep(0.05)
    finally:
        release.set()
        for child in children:
            child.join(timeout=3.0)
            if child.is_alive():
                child.terminate()
                child.join(timeout=2.0)
        ready.close()
        ready.join_thread()
    if any(child.exitcode != 0 for child in children):
        raise RuntimeError("static noise failed")
    emit("noise_summary", processes=16, worker_threads=512, file_descriptors=4096)


def analyze(directory: Path) -> None:
    def documents(name: str) -> list[dict]:
        return [json.loads(line) for line in (directory/name).read_text().splitlines() if line]

    baseline_config = next((row for row in documents("baseline-known.jsonl") if row["event"] == "configuration"), None)
    if baseline_config is None:
        raise RuntimeError("baseline workload has no recorded configuration")
    frozen_config = {key:value for key,value in baseline_config.items() if key not in ("event", "monotonic")}
    stage_seconds = frozen_config.get("stage_seconds")
    warmup_seconds = frozen_config.get("warmup_seconds")
    duration = frozen_config.get("duration")
    rates = frozen_config.get("churn_rates")
    for field, value, maximum in (("stage_seconds",stage_seconds,30), ("warmup_seconds",warmup_seconds,10), ("duration",duration,100)):
        if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or not 0 < value <= maximum:
            raise RuntimeError(f"invalid recorded {field}")
    if not isinstance(rates,list) or len(rates) != 3 or any(isinstance(rate,bool) or not isinstance(rate,int) or not 1 <= rate <= 100 for rate in rates):
        raise RuntimeError("invalid recorded churn rates")
    if duration != warmup_seconds+len(rates)*stage_seconds:
        raise RuntimeError("recorded duration does not match the stage schedule")
    for field, maximum in (("udp_pps",20),("tcp_pps",5)):
        value = frozen_config.get(field)
        if isinstance(value,bool) or not isinstance(value,int) or not 1 <= value <= maximum:
            raise RuntimeError(f"invalid recorded {field}")
    configuration_sha256 = hashlib.sha256(json.dumps(frozen_config, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    report: dict[str, object] = {"schema":"openshield.continuous-attribution.v1", "rates":rates, "stage_seconds":stage_seconds, "configuration":frozen_config, "configuration_sha256":configuration_sha256, "measurements":{}}
    violations = []
    unreliable = []
    status = json.loads((directory/"status-final.json").read_text(encoding="utf-8"))
    report["daemon_status_final"] = status
    if status.get("mode") != "enforcing":
        violations.append("daemon is not Enforcing after the workload (quarantine or mode transition)")
    nfqueue_status = status.get("nfqueue", {})
    for name in ("attribution_timeout", "queue_overflow", "terminal_queue_error"):
        value = nfqueue_status.get(name)
        if isinstance(value,bool) or not isinstance(value,int) or value < 0:
            unreliable.append(f"daemon NFQUEUE {name} counter is missing or invalid")
        elif value:
            violations.append(f"daemon NFQUEUE {name} counter is {value}")
    for phase in ("baseline", "enforcing"):
        known_records = documents(f"{phase}-known.jsonl")+documents(f"{phase}-ping.jsonl")
        monitor_records = documents(f"{phase}-monitor.jsonl")
        churn_records = documents(f"{phase}-churn.jsonl")
        peer_records = documents(f"{phase}-peer.jsonl")
        peer_sent = {
            (row["transport"], row["sequence"]): row
            for row in peer_records
            if row.get("transport") in ("udp", "tcp")
            and row.get("sequence", UNKNOWN_SEQUENCE) < UNKNOWN_SEQUENCE
            and "sent_monotonic_ns" in row
        }
        known_sent = {
            (row["transport"], row["sequence"]): row
            for row in known_records if row["event"] == "sent"
        }
        config = next((row for row in known_records if row["event"] == "configuration"), None)
        if config is None:
            raise RuntimeError("known workload has no recorded configuration")
        if report["configuration"] != {key:value for key,value in config.items() if key not in ("event", "monotonic")}:
            unreliable.append("baseline and Enforcing configurations differ")
        summary = next((row for row in churn_records if row["event"] == "churn_summary"), None)
        if not summary or summary["capacity_limited"] or summary["late"] > 100 or summary["cpu_seconds"] > duration*0.8:
            unreliable.append(f"{phase}: churn generator invalid or saturated")
        if summary and abs(summary["attempted"]-sum(rates)*stage_seconds) > 3:
            unreliable.append(f"{phase}: churn attempts did not follow the recorded schedule")
        if phase == "enforcing" and any(row["event"] in ("unknown_received", "unknown_tcp_connected") for row in churn_records):
            violations.append("enforcing: unknown application received or established TCP (fail-open)")
        measurements = {}
        for stage, rate in enumerate(rates):
            begin = warmup_seconds+stage*stage_seconds
            end = begin+stage_seconds
            sample = [row for row in monitor_records if begin <= row["elapsed"] < end]
            group = {"transports": {}, "queue_max_depth":{}, "queue_nonempty_fraction":{}}
            for transport, expected in (("icmp",int(stage_seconds)),("udp",int(stage_seconds*config["udp_pps"])),("tcp",int(stage_seconds*config["tcp_pps"]))):
                responses = [row for row in known_records if row["event"] == "received" and row["transport"] == transport and begin <= row["elapsed"] < end]
                times = [row["latency_ms"] for row in responses]
                result = {"expected":expected, "received":len(times), "loss":expected-len(times), "p50_ms":None, "p95_ms":None, "p99_ms":None, "max_ms":None}
                if times:
                    for percentile in (50,95,99):
                        result[f"p{percentile}_ms"] = DELAYED.percentile(times, percentile)
                    result["max_ms"] = max(times)
                # Containers share the kernel monotonic clock (no time namespace).
                # These are pipeline timings, not pure /proc attribution time:
                # send->peer-receive includes outgoing queueing and verdict work;
                # peer-send->receive includes input deferral and socket delivery.
                components = {"outbound_pipeline_ms": [], "inbound_pipeline_ms": []}
                for row in responses:
                    key = (transport, row["sequence"])
                    if key in peer_sent and key in known_sent:
                        peer_event = peer_sent[key]
                        sent_event = known_sent[key]
                        components["outbound_pipeline_ms"].append(peer_event["received_monotonic_ns"]/1_000_000-sent_event["monotonic"]*1000)
                        components["inbound_pipeline_ms"].append(row["monotonic"]*1000-peer_event["sent_monotonic_ns"]/1_000_000)
                for component, values in components.items():
                    if values:
                        result[component] = {f"p{percentile}":DELAYED.percentile(values, percentile) for percentile in (50,95,99)}
                group["transports"][transport] = result
            for number in ("1337","1339"):
                depths = [row["queues"][number]["depth"] for row in sample if number in row["queues"]]
                group["queue_max_depth"][number] = max(depths, default=0)
                group["queue_nonempty_fraction"][number] = sum(value>0 for value in depths)/len(depths) if depths else 0
            cpu = [row["cpu_percent"] for row in sample if "cpu_percent" in row]
            group["mean_cpu_percent"] = sum(cpu)/len(cpu) if cpu else None
            group["max_rss_bytes"] = max((row.get("rss_bytes",0) for row in sample), default=0)
            measurements[str(rate)] = group
        report["measurements"][phase] = measurements
        report[f"{phase}_churn"] = summary
        for row in known_records:
            if row["event"] in ("connect_error", "send_error", "receive_error", "closed"):
                violations.append(f"{phase}: known {row.get('transport','transport')} {row['event']}")
        if phase == "enforcing":
            queue_final = monitor_records[-1]["queues"]
            report["reply_queue_exercised"] = queue_final.get("1339",{}).get("sequence",0)>0
            report["queue_final"] = queue_final
            if config["udp_pps"] >= 10 and not report["reply_queue_exercised"]:
                unreliable.append("continuous-reply target not exercised: q1339 sequence remains zero")
            for row in monitor_records:
                if row.get("daemon_missing"):
                    violations.append("enforcing: daemon exited")
                    break
                if any(item["kernel_dropped"] or item["user_dropped"] for item in row["queues"].values()):
                    violations.append("enforcing: NFQUEUE kernel/user drop")
                    break
    for phase, measurements in report["measurements"].items():
        for rate, group in measurements.items():
            for transport, result in group["transports"].items():
                if result["loss"]:
                    violations.append(f"{phase} {rate}/s {transport}: {result['loss']} missing responses")
                    if phase == "baseline":
                        unreliable.append(f"baseline {rate}/s {transport}: comparison has missing responses")
                if phase == "enforcing":
                    baseline = report["measurements"]["baseline"][rate]["transports"][transport]
                    if result["p99_ms"] is not None and baseline["p99_ms"] is not None and result["p99_ms"]-baseline["p99_ms"] > 500:
                        violations.append(f"enforcing {rate}/s {transport}: p99 overhead exceeds 500ms")
    peer = documents("enforcing-peer.jsonl")
    forbidden = [row for row in peer if row.get("sequence",0) >= UNKNOWN_SEQUENCE]
    if forbidden:
        violations.append(f"enforcing peer received {len(forbidden)} unknown-application records (fail-open)")
    for phase in ("baseline", "enforcing"):
        delays = [row["actual_delay_ms"] for row in documents(f"{phase}-peer.jsonl") if "actual_delay_ms" in row]
        report[f"{phase}_peer_actual_delay_max_ms"] = max(delays, default=None)
        if not delays or max(delays) > 105:
            unreliable.append(f"{phase} peer timing invalid: reply processing exceeds configured55ms +50ms allowance")
    report["violations"] = violations
    report["unreliable_reasons"] = unreliable
    report["valid"] = not unreliable
    report["passed"] = not violations and not unreliable
    (directory/"report.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    lines = ["# Continuous attribution reproduction", "", "Real sockets; 55ms delayed peer; 1024 sleeping worker threads /8192 FDs across same and other UID.", "", f"Known UDP: {frozen_config['udp_pps']} PPS; TCP: {frozen_config['tcp_pps']} requests/s; ICMP: 1 PPS.", f"Frozen configuration SHA-256: `{configuration_sha256}`.", "", "| Phase | Churn /s | Transport | Received | p50 ms | p99 ms | q1337 / q1339 max | CPU % |", "|---|---:|---|---:|---:|---:|---:|---:|"]
    def rounded(value: object) -> str:
        return "—" if value is None else f"{value:.2f}"
    for phase, measurements in report["measurements"].items():
        for rate, group in measurements.items():
            for transport, result in group["transports"].items():
                lines.append(f"| {phase} | {rate} | {transport} | {result['received']}/{result['expected']} | {rounded(result['p50_ms'])} | {rounded(result['p99_ms'])} | {group['queue_max_depth']['1337']} / {group['queue_max_depth']['1339']} | {rounded(group['mean_cpu_percent'])} |")
    lines.extend(["", f"Valid measurement: {not unreliable}. NFQUEUE1339 exercised: {report.get('reply_queue_exercised')}."])
    lines.extend(["", "## Findings", ""]+[f"- {item}" for item in violations] if violations else ["", "No loss, fail-open or >500ms p99 regression detected in these bounded conditions."])
    if unreliable:
        lines.extend(["", "## Measurement limitations", ""]+[f"- {item}" for item in unreliable])
    (directory/"report.md").write_text("\n".join(lines)+"\n")
    print(json.dumps(report, sort_keys=True))
    if violations or unreliable:
        raise RuntimeError("continuous attribution regression reproduced; see report.json")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("known", "churn"):
        command = commands.add_parser(name)
        command.add_argument("address", type=DELAYED.checked_ipv4)
        command.add_argument("udp_port", type=DELAYED.checked_port)
        command.add_argument("tcp_port", type=DELAYED.checked_port)
        command.add_argument("start_file", type=Path)
    command = commands.add_parser("ping")
    command.add_argument("address", type=DELAYED.checked_ipv4)
    command.add_argument("start_file", type=Path)
    command = commands.add_parser("monitor")
    command.add_argument("pid", type=int)
    command.add_argument("start_file", type=Path)
    command = commands.add_parser("noise")
    command.add_argument("ready_path", type=Path)
    command.add_argument("release_path", type=Path)
    command = commands.add_parser("analyze")
    command.add_argument("directory", type=Path)
    arguments = vars(parser.parse_args())
    command = arguments.pop("command")
    globals()[command](**arguments)


if __name__ == "__main__":
    main()
