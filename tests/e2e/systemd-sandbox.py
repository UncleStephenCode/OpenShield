#!/usr/bin/env python3
"""Real socket and mount-namespace probes for the packaged systemd unit.

The brief SIGSTOP is restricted to the daemon PID inside the private test
container. It makes a real delayed UDP reply enter q1339 while a later original
packet waits in q1337, without raw packet injection or changing firewall rules.
"""

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import subprocess
import sys
import threading
import time

OUTPUT = Path("/run/openshield-sandbox")
QUEUE_PATH = Path("/proc/self/net/netfilter/nfnetlink_queue")
UNIT = "openshield-daemon.service"
ALLOWED = "/usr/libexec/openshield-sandbox-allowed"
UNKNOWN = "/usr/libexec/openshield-sandbox-unknown"
SCRIPT = "/opt/systemd-sandbox.py"
TCP_PORT = 18271
UDP_PORT = 18272


def record(name, data, directory=OUTPUT):
    directory.joinpath(name).write_text(json.dumps(data, indent=2) + "\n")
    print(json.dumps({"report": str(directory / name), "passed": data.get("passed")}), flush=True)


def queues():
    result = {}
    for line in QUEUE_PATH.read_text().splitlines():
        fields = [int(value) for value in line.split()]
        if len(fields) != 9:
            raise RuntimeError("unexpected NFQUEUE metadata layout")
        result[fields[0]] = fields
    return result


def probe(expectation):
    direct = Path("/proc/self/net/tcp").read_text()
    if "local_address" not in direct:
        raise RuntimeError("direct per-process network metadata is unavailable")
    mounts = Path("/proc/self/mountinfo").read_text()
    caught_errno = None
    visible = None
    try:
        visible = queues()
    except OSError as error:
        caught_errno = error.errno
    if expectation == "hidden":
        if caught_errno != errno.ENOENT or "subset=pid" not in mounts:
            raise RuntimeError("ProcSubset=pid did not reproduce nested procfs ENOENT")
    elif caught_errno is not None or not {1337, 1338, 1339} <= visible.keys():
        raise RuntimeError("the packaged service mount namespace cannot inspect its queues")
    if expectation == "visible" and "subset=pid" in mounts:
        raise RuntimeError("the fixed packaged unit still uses ProcSubset=pid")
    if expectation == "visible":
        proc_mounts = [line.split() for line in mounts.splitlines() if line.split()[4] == "/proc"]
        if not proc_mounts or "ro" not in proc_mounts[-1][5].split(","):
            raise RuntimeError("the packaged service does not retain read-only procfs")
    record(f"proc-{expectation}.json", {
        "expected": expectation, "errno": caught_errno, "queues": visible,
        "mountinfo": mounts, "net_namespace": os.readlink("/proc/self/ns/net"),
    }, Path("/run/openshield") if expectation == "visible" else OUTPUT)


def properties():
    text = subprocess.check_output(["systemctl", "show", UNIT], text=True, timeout=5)
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def unit_proof():
    props = properties()
    required = {
        "User": "root", "Group": "root", "SupplementaryGroups": "openshield",
        "ProtectSystem": "strict", "ProtectHome": "yes", "ProtectProc": "invisible",
        "ProcSubset": "all", "SystemCallErrorNumber": "1",
    }
    for key, value in required.items():
        if props.get(key) != value:
            raise RuntimeError(f"packaged unit property {key}: {props.get(key)!r} != {value!r}")
    for key in ("NoNewPrivileges", "PrivateTmp", "PrivateDevices", "PrivateMounts",
                "ProtectControlGroups", "ProtectKernelTunables", "ProtectKernelModules",
                "ProtectKernelLogs", "ProtectClock", "ProtectHostname", "RestrictRealtime",
                "RestrictSUIDSGID", "LockPersonality", "MemoryDenyWriteExecute", "RemoveIPC"):
        if props.get(key) not in {"yes", "true"}:
            raise RuntimeError(f"packaged unit hardening {key} is not enabled: {props.get(key)}")
    if props.get("DropInPaths"):
        raise RuntimeError("packaged unit was changed with a drop-in")
    if "/proc" not in props.get("ReadOnlyPaths", "").split():
        raise RuntimeError("the packaged unit does not declare read-only procfs")
    for key in ("RestrictAddressFamilies", "RestrictNamespaces", "SystemCallArchitectures", "SystemCallFilter"):
        if not props.get(key):
            raise RuntimeError(f"missing packaged unit hardening {key}")
    pid = int(props["MainPID"])
    if pid <= 1 or Path("/proc/1/comm").read_text().strip() != "systemd":
        raise RuntimeError("the daemon is not running under real systemd PID 1")
    status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
    for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        if int(status[key].strip(), 16) != 0x83004:
            raise RuntimeError(f"packaged capability restriction mismatch: {key}")
    if status["NoNewPrivs"].strip() != "1" or status["Seccomp"].strip() != "2":
        raise RuntimeError("packaged no-new-privileges/seccomp restrictions are inactive")
    init_status = dict(line.split(":", 1) for line in Path("/proc/1/status").read_text().splitlines() if ":" in line)
    if "Seccomp_filters" in status and int(status["Seccomp_filters"]) <= int(init_status.get("Seccomp_filters", "0")):
        raise RuntimeError("the daemon has no additional service seccomp filter beyond systemd PID 1")
    if os.readlink(f"/proc/{pid}/ns/mnt") == os.readlink("/proc/1/ns/mnt"):
        raise RuntimeError("the daemon did not receive its sandbox mount namespace")
    if os.readlink(f"/proc/{pid}/ns/net") != os.readlink("/proc/1/ns/net"):
        raise RuntimeError("daemon queue and container network namespaces differ")
    installed = Path("/usr/lib/systemd/system/openshield-daemon.service")
    subprocess.run(["rpm", "-V", "openshield"], check=True, timeout=10)
    record("unit-proof.json", {
        "properties": props, "process_status": status,
        "unit_sha256": hashlib.sha256(installed.read_bytes()).hexdigest(),
        "daemon_sha256": hashlib.sha256(Path("/usr/bin/openshield-daemon").read_bytes()).hexdigest(),
        "pid1": Path("/proc/1/comm").read_text().strip(),
    })


def peer():
    lock = threading.Lock()

    def event(protocol, payload):
        with lock:
            print(json.dumps({"protocol": protocol, "token": payload.decode("ascii"), "time": time.monotonic()}), flush=True)

    def udp_server():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
            stream.bind(("0.0.0.0", UDP_PORT))
            while True:
                data, address = stream.recvfrom(4096)
                event("udp", data)
                if data == b"barrier-prime":
                    stream.sendto(b"prime-ack", address)
                    threading.Timer(0.25, stream.sendto, (data, address)).start()
                else:
                    stream.sendto(data, address)

    threading.Thread(target=udp_server, daemon=True).start()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", TCP_PORT))
        listener.listen(32)
        while True:
            stream, _address = listener.accept()
            with stream:
                stream.settimeout(3)
                data = stream.recv(4096)
                if data:
                    event("tcp", data)
                    stream.sendall(data)


def socket_client(protocol, address, token):
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    port = TCP_PORT if protocol == "tcp" else UDP_PORT
    with socket.socket(socket.AF_INET, kind) as stream:
        stream.settimeout(3)
        stream.connect((address, port))
        if protocol == "tcp" and token.startswith(("unknown", "startup-blocked")):
            raise RuntimeError("a forbidden TCP handshake succeeded, even before payload transfer")
        if token == "barrier":
            stream.sendall(b"barrier-prime")
            if stream.recv(4096) != b"prime-ack":
                raise RuntimeError("independent peer did not acknowledge the authorized original")
            print("BARRIER_READY", flush=True)
            time.sleep(0.1)
            stream.sendall(b"barrier-second")
            replies = {stream.recv(4096), stream.recv(4096)}
            if replies != {b"barrier-prime", b"barrier-second"}:
                raise RuntimeError(f"reply barrier lost a real UDP response: {replies}")
        else:
            payload = token.encode("ascii")
            stream.sendall(payload)
            if stream.recv(4096) != payload:
                raise RuntimeError("real socket reply is corrupted")


def invoke(protocol, address, token, executable=ALLOWED, expected=0):
    result = subprocess.run(["runuser", "-u", "sandboxapp", "--", executable, SCRIPT,
                             "client", protocol, address, token], capture_output=True, text=True, timeout=8)
    expected_codes = expected if isinstance(expected, tuple) else (expected,)
    if result.returncode not in expected_codes:
        raise RuntimeError(f"{token}: status {result.returncode}, expected {expected}: {result.stderr}")
    return {"token": token, "status": result.returncode}


def mutate(kind, data):
    import ipc_client

    for _ in range(30):
        current = ipc_client.status()
        response = ipc_client.exchange(ipc_client.CONTROL, {
            "type": "control", "data": {"type": kind, "data": {
                "expected_revision": current["revision"], **data,
            }},
        })
        if response.get("type") == "ack":
            return
        if response.get("data", {}).get("code") != "conflict":
            raise RuntimeError(f"control mutation failed: {response}")
        time.sleep(0.1)
    raise RuntimeError("control mutation exceeded its bounded conflict retry")


def startup_negative(address):
    if properties().get("ProcSubset") != "all":
        raise RuntimeError("candidate package has not corrected ProcSubset")
    drop_directory = Path("/etc/systemd/system/openshield-daemon.service.d")
    drop_directory.mkdir(parents=True, exist_ok=False)
    override = drop_directory / "90-openshield-sandbox-negative.conf"
    start = None
    state = None
    journal = None
    results = []
    try:
        override.write_text("[Service]\nProcSubset=pid\n")
        subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=10)
        start = subprocess.run(["systemctl", "start", UNIT], capture_output=True, text=True, timeout=15)
        if start.returncode == 0:
            raise RuntimeError("daemon reached systemd READY despite unreadable queue-progress procfs")
        # Cancel Restart=on-failure before inspecting and probing BlockAll.
        subprocess.run(["systemctl", "stop", UNIT], check=True, timeout=15)
        state = properties()
        if int(state.get("MainPID", "0")) != 0 or state.get("ActiveState") == "active":
            raise RuntimeError("negative startup unexpectedly left an active daemon")
        journal = subprocess.check_output(["journalctl", "-u", UNIT, "--no-pager", "-o", "cat"], text=True, timeout=5)
        if not all(message in journal for message in (
            "cannot initialize application reply scheduling", "network procfs must be readable",
            "nfnetlink_queue", "No such file or directory",
        )):
            raise RuntimeError(f"negative startup failed for the wrong reason: {journal}")
        for protocol in ("tcp", "udp"):
            results.append(invoke(protocol, address, f"startup-blocked-{protocol}", expected=(42, 43)))
        ping = subprocess.run(["runuser", "-u", "sandboxapp", "--", "/usr/bin/ping", "-n", "-c", "1", "-W", "1", address],
                              capture_output=True, text=True, timeout=5)
        if ping.returncode != 1 or "100% packet loss" not in ping.stdout:
            raise RuntimeError(f"bootstrap BlockAll failed the ICMP probe: {ping.stdout} {ping.stderr}")
        results.append({"token": "startup-blocked-icmp", "status": ping.returncode, "ping": ping.stdout})
    finally:
        subprocess.run(["systemctl", "stop", UNIT], check=False, timeout=15)
        if override.is_file():
            override.unlink()
        drop_directory.rmdir()
        subprocess.run(["systemctl", "daemon-reload"], check=True, timeout=10)
        reset = subprocess.run(["systemctl", "reset-failed", UNIT], capture_output=True, text=True, timeout=5)
        # An inactive unit may already have been garbage-collected after reload.
        # That has no failed/start-limit state left to reset.
        if reset.returncode and "not loaded" not in reset.stderr:
            raise RuntimeError(f"cannot reset the negative test unit: {reset.stderr}")
    cursor_text = subprocess.check_output(["journalctl", "-n", "1", "--show-cursor", "--no-pager", "-o", "cat"], text=True, timeout=5)
    cursors = [line.removeprefix("-- cursor: ") for line in cursor_text.splitlines() if line.startswith("-- cursor: ")]
    if len(cursors) != 1:
        raise RuntimeError("cannot capture the positive-startup journal boundary")
    OUTPUT.joinpath("positive-journal-cursor").write_text(cursors[0] + "\n")
    record("negative-startup.json", {"passed": True, "start_status": start.returncode,
                                    "state": state, "journal": journal, "probes": results,
                                    "override_removed": not drop_directory.exists()})


def exercise(backend, address):
    import ipc_client

    initial = ipc_client.status()
    if initial["mode"] != "learning":
        raise RuntimeError("packaged daemon did not start in Learning")
    if initial.get("backend") != backend:
        raise RuntimeError(f"wrong runtime backend: {initial}")
    uid = pwd.getpwnam("sandboxapp").pw_uid
    for protocol, executable, port in (
        ("tcp", ALLOWED, TCP_PORT), ("udp", ALLOWED, UDP_PORT),
        ("icmp", os.path.realpath("/usr/bin/ping"), None),
    ):
        mutate("create_rule", {"rule": {
            "name": f"Packaged systemd {protocol}", "direction": "outbound", "protocol": protocol,
            "peer_network": f"{address}/32", "port": None if port is None else {"start": port, "end": port},
            "interface": None, "application": {"executable": executable, "executable_file": None,
                "command_line": None, "uid": uid, "cgroup": None, "metadata_redacted": False},
            "origin": "manual", "action": "accept", "enabled": True,
        }})
    results = []
    before = queues()
    counters_before = ipc_client.status()["nfqueue"]
    for mode in ("learning", "enforcing"):
        if mode == "enforcing":
            mutate("set_mode", {"mode": mode})
        for protocol in ("tcp", "udp"):
            results.append(invoke(protocol, address, f"{mode}-{protocol}"))
        ping = subprocess.run(["runuser", "-u", "sandboxapp", "--", "/usr/bin/ping", "-n", "-c", "3", "-W", "3", address],
                              capture_output=True, text=True, timeout=15)
        if ping.returncode != 0 or " 0% packet loss" not in ping.stdout:
            raise RuntimeError(f"{mode} ICMP replies failed: {ping.stdout} {ping.stderr}")
        results.append({"token": f"{mode}-icmp", "status": 0, "ping": ping.stdout})
    daemon_pid = int(properties()["MainPID"])
    child = subprocess.Popen(["runuser", "-u", "sandboxapp", "--", ALLOWED, SCRIPT, "client", "udp", address, "barrier"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stopped = False
    overlap = None
    try:
        import select
        ready, _, _ = select.select([child.stdout], [], [], 5)
        if not ready or child.stdout.readline().strip() != "BARRIER_READY":
            raise RuntimeError("controlled real UDP overlap did not become ready")
        os.kill(daemon_pid, signal.SIGSTOP)
        stopped = True
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            sample = queues()
            if sample[1337][2] > 0 and sample[1339][2] > 0:
                overlap = sample
                break
            time.sleep(0.01)
    finally:
        if stopped:
            os.kill(daemon_pid, signal.SIGCONT)
    try:
        stdout, stderr = child.communicate(timeout=8)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate()
        raise
    if overlap is None or child.returncode != 0:
        raise RuntimeError(f"real UDP q1337/q1339 overlap failed: {overlap}, {stdout}, {stderr}")
    results.append({"token": "barrier", "status": 0, "overlap": overlap})
    for protocol in ("tcp", "udp"):
        results.append(invoke(protocol, address, f"unknown-{protocol}", UNKNOWN, (42, 43)))
        results.append(invoke(protocol, address, f"post-denial-{protocol}"))
    after = queues()
    final = ipc_client.status()
    if final["mode"] != "enforcing":
        raise RuntimeError("daemon unexpectedly left Enforcing")
    for number in (1337, 1338, 1339):
        if after[number][1] != before[number][1] or after[number][3:7] != before[number][3:7]:
            raise RuntimeError(f"queue {number} owner/configuration changed or drops increased")
        if after[number][7] <= before[number][7]:
            raise RuntimeError(f"queue {number} was not exercised")
    for key in ("queue_overflow", "attribution_timeout", "terminal_queue_error"):
        if final["nfqueue"].get(key, 0) != counters_before.get(key, 0):
            raise RuntimeError(f"unexpected NFQUEUE error growth: {key}")
    record("report.json", {"schema": "openshield.systemd-sandbox.e2e.v1", "backend": backend,
                           "passed": True, "queues_before": before, "queues_after": after,
                           "nfqueue_before": counters_before, "nfqueue_after": final["nfqueue"],
                           "results": results})


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("peer")
    sub.add_parser("unit-proof")
    negative = sub.add_parser("startup-negative")
    negative.add_argument("address")
    inspection = sub.add_parser("probe")
    inspection.add_argument("expectation", choices=("hidden", "visible"))
    client = sub.add_parser("client")
    client.add_argument("protocol", choices=("tcp", "udp"))
    client.add_argument("address")
    client.add_argument("token")
    run = sub.add_parser("exercise")
    run.add_argument("backend", choices=("nftables", "iptables"))
    run.add_argument("address")
    args = parser.parse_args()
    if args.action == "peer":
        peer()
    elif args.action == "unit-proof":
        unit_proof()
    elif args.action == "startup-negative":
        startup_negative(args.address)
    elif args.action == "probe":
        probe(args.expectation)
    elif args.action == "exercise":
        exercise(args.backend, args.address)
    else:
        try:
            socket_client(args.protocol, args.address, args.token)
        except TimeoutError:
            return 42
        except PermissionError as error:
            if args.token.startswith(("unknown", "startup-blocked")) and error.errno in {errno.EPERM, errno.EACCES}:
                # A local OUTPUT DROP can synchronously fail sendmsg. The
                # independent peer audit still must prove zero delivery.
                print(f"negative socket operation denied: errno={error.errno}", file=sys.stderr)
                return 43
            raise
    return 0


if __name__ == "__main__":
    sys.exit(main())
