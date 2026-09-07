#!/usr/bin/env python3
"""Real-socket quota regression; only run through learning-quota.sh in a VM."""

import argparse
import errno
import json
import os
from pathlib import Path
import select
import selectors
import shutil
import socket
import struct
import subprocess
import sys
import time
import uuid

import ipc_client

STATE = Path("/var/lib/openshield/state.json")
EVIDENCE = Path("/tmp/learning-quota")
ALLOWED = "/usr/bin/openshield-quota-allowed"
DENIED = "/usr/bin/openshield-quota-denied"
PORTS = {"tcp": 18301, "udp": 18302}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def emit(**fields):
    print(json.dumps(fields, sort_keys=True), flush=True)


def identity(path):
    metadata = os.stat(path, follow_symlinks=False)
    return {
        "device": metadata.st_dev, "inode": metadata.st_ino,
        "size": metadata.st_size,
        "ctime_seconds": metadata.st_ctime_ns // 1_000_000_000,
        "ctime_nanoseconds": metadata.st_ctime_ns % 1_000_000_000,
    }


def seed(profile, peer):
    require(not STATE.exists(), "refusing to replace existing DUT policy")
    executable = str(Path(sys.executable).resolve())
    paths = [ALLOWED, DENIED] + [f"/usr/bin/openshield-quota-old-{i}" for i in range(3)]
    for path in paths:
        require(not Path(path).exists(), "fixture executable already exists")
        shutil.copyfile(executable, path)
        os.chmod(path, 0o755)
    EVIDENCE.mkdir(mode=0o700)
    if profile == "small":
        config = Path("/etc/openshield/learning-limits.json")
        config.parent.mkdir(mode=0o755, exist_ok=True)
        require(not config.exists(), "fixture learning config already exists")
        config.write_text('{"per_uid":2,"per_application":1}\n')
        config.chmod(0o600)
        return
    rules = {}
    for i in range(512):
        path = ([ALLOWED] + paths[2:])[i // 128]
        rule_id = str(uuid.UUID(int=i + 1))
        rules[rule_id] = {
            "id": rule_id,
            "created_at": "2026-09-07T00:00:00Z",
            "updated_at": "2026-09-07T00:00:00Z",
            "spec": {
                "name": f"historical endpoint {i}", "direction": "outbound",
                "action": "accept", "protocol": "tcp", "peer_network": f"{peer}/32",
                "port": {"start": 20000 + i, "end": 20000 + i},
                "interface": "eth0", "origin": "learned", "enabled": True,
                "application": {"executable": path, "executable_file": identity(path),
                                "command_line": None, "uid": 0, "cgroup": None,
                                "metadata_redacted": False},
            },
        }
    state = {"revision": 512, "flow_generation": 1, "mode": "learning", "rules": rules}
    STATE.write_text(json.dumps(state))
    STATE.chmod(0o600)
    (EVIDENCE / "historical-state.json").write_text(json.dumps(state, indent=2))


def serve():
    with selectors.DefaultSelector() as selector:
        for protocol, port in PORTS.items():
            stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM)
            stream.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            stream.bind(("0.0.0.0", port))
            if protocol == "tcp":
                stream.listen(32)
            stream.setblocking(False)
            selector.register(stream, selectors.EVENT_READ, protocol)
        Path("/tmp/quota-peer.ready").touch()
        while True:
            for key, _ in selector.select(0.5):
                stream = key.fileobj
                if key.data == "tcp":
                    connection, _ = stream.accept()
                    connection.settimeout(5)
                    selector.register(connection, selectors.EVENT_READ, bytearray())
                elif key.data == "udp":
                    data, address = stream.recvfrom(1024)
                    emit(protocol="udp", token=data.decode("ascii"))
                    stream.sendto(data, address)
                else:
                    try:
                        data = stream.recv(1024)
                    except ConnectionResetError:
                        data = b""
                    if not data:
                        require(not key.data, "peer received an incomplete TCP frame")
                        selector.unregister(stream)
                        stream.close()
                    else:
                        key.data.extend(data)
                        require(len(key.data) <= 1028, "oversized TCP frame")
                        if len(key.data) >= 4:
                            length = struct.unpack("!I", key.data[:4])[0]
                            require(0 < length <= 1024, "invalid TCP frame size")
                            if len(key.data) >= 4 + length:
                                require(len(key.data) == 4 + length, "unexpected extra TCP frame")
                                emit(protocol="tcp", token=bytes(key.data[4:]).decode("ascii"))
                                stream.sendall(key.data)
                                key.data.clear()


def receive_exact(stream, size, deadline):
    data = bytearray()
    while len(data) < size:
        remaining = deadline - time.monotonic()
        require(remaining > 0, "TCP receive deadline expired")
        stream.settimeout(remaining)
        chunk = stream.recv(size - len(data))
        require(chunk, "peer closed an incomplete TCP response")
        data.extend(chunk)
    return bytes(data)


def worker(peer):
    held = None
    try:
        for line in sys.stdin:
            command = json.loads(line)
            if command["operation"] == "close":
                if held is not None:
                    held.close()
                    held = None
                emit(closed=True)
                continue
            require(held is None, "previous socket was not released")
            protocol = command["protocol"]
            token = command["token"].encode("ascii")
            held = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM)
            held.settimeout(3)
            try:
                deadline = time.monotonic() + 3
                held.connect((peer, PORTS[protocol]))
                remaining = deadline - time.monotonic()
                require(remaining > 0, "socket connection exceeded workload deadline")
                held.settimeout(remaining)
                if protocol == "tcp":
                    held.sendall(struct.pack("!I", len(token)) + token)
                    length = struct.unpack("!I", receive_exact(held, 4, deadline))[0]
                    require(length == len(token), "incorrect TCP response frame size")
                    response = receive_exact(held, length, deadline)
                else:
                    held.sendall(token)
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, "UDP send exceeded workload deadline")
                    held.settimeout(remaining)
                    response = held.recv(1024)
                require(response == token, "incorrect peer echo")
                emit(success=True, token=command["token"])
            except PermissionError as error:
                # A local OUTPUT drop/reject can return EPERM/EACCES directly
                # from connect/send rather than waiting for a peer timeout.
                # Do not reinterpret unrelated socket errors as proof of deny.
                if error.errno not in (errno.EPERM, errno.EACCES):
                    raise
                emit(success=False, token=command["token"],
                     error=type(error).__name__, errno=error.errno)
            except (TimeoutError, ConnectionRefusedError, ConnectionResetError) as error:
                emit(success=False, token=command["token"], error=type(error).__name__)
    finally:
        if held is not None:
            held.close()


def status():
    response = ipc_client.exchange(ipc_client.OBSERVE, {"type": "read", "data": {"type": "status_v3"}})
    require(response.get("type") == "status_v3", f"no learning telemetry: {response}")
    return response["data"]


def persisted():
    with STATE.open("rb") as stream:
        data = stream.read(8 * 1024 * 1024 + 1)
    require(len(data) <= 8 * 1024 * 1024, "persisted policy exceeded bound")
    return json.loads(data)["rules"]


def learned(peer, protocol):
    return [rule for rule in persisted().values()
            if rule["spec"]["origin"] == "learned"
            and rule["spec"]["direction"] == "outbound"
            and rule["spec"]["protocol"] == protocol
            and rule["spec"]["peer_network"] == f"{peer}/32"
            and rule["spec"]["port"] == {"start": PORTS[protocol], "end": PORTS[protocol]}
            and (rule["spec"].get("application") or {}).get("executable") == ALLOWED
            and rule["spec"]["application"].get("uid") == 0
            and rule["spec"]["application"].get("executable_file") == identity(ALLOWED)
            and rule["spec"]["enabled"] and rule["spec"].get("action", "accept") == "accept"]


def wait(predicate, description):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise TimeoutError(description)


def ask(process, command):
    process.stdin.write(json.dumps(command) + "\n")
    process.stdin.flush()
    ready, _, _ = select.select([process.stdout], [], [], 10)
    require(ready, "real-socket worker timed out")
    line = process.stdout.readline(8192)
    require(line.endswith("\n"), f"worker exited or returned malformed output: {line!r}")
    result = json.loads(line)
    emit(worker=process.pid, **result)
    return result


def probe(process, protocol, token, expected):
    result = ask(process, {"operation": "probe", "protocol": protocol, "token": token})
    require(result["success"] is expected, f"unexpected probe result: {result}")


def release(process):
    require(ask(process, {"operation": "close"}).get("closed"), "socket release failed")


def run(profile, peer, backend):
    initial = status()
    require(initial["mode"] == "learning" and initial["backend"] == backend, f"incorrect initial runtime: {initial}")
    expected_limits = (4096, 1024) if profile == "historical" else (2, 1)
    require((initial["learning"]["per_uid_limit"], initial["learning"]["per_application_limit"]) == expected_limits,
            f"incorrect startup budgets: {initial}")
    (EVIDENCE / "status-initial.json").write_text(json.dumps(initial, indent=2))
    processes = []
    try:
        for executable in [ALLOWED, DENIED]:
            processes.append(subprocess.Popen([executable, __file__, "worker", peer],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1))
        allowed, denied = processes
        probe(allowed, "tcp", f"{profile}-learning-tcp", True)
        wait(lambda: learned(peer, "tcp"), "TCP allow was not persisted while socket was alive")
        release(allowed)
        probe(allowed, "udp", f"{profile}-learning-udp", True)
        if profile == "historical":
            wait(lambda: learned(peer, "udp"), "UDP allow was not persisted after historical UID saturation")
            rules = persisted()
            require(all(str(uuid.UUID(int=i + 1)) in rules for i in range(512)), "historical rules were lost")
            require(sum(r["spec"]["origin"] == "learned" for r in rules.values()) >= 514, "historical quota did not recover")
        else:
            wait(lambda: status()["learning"]["quota_skipped_observations"] > 0,
                 "skipped Learning observation is not visible")
            small = status()["learning"]
            require(small["saturated_applications"] == 1, f"incorrect saturation: {small}")
            require(not learned(peer, "udp"), "quota silently admitted an extra automatic rule")
        release(allowed)
        (EVIDENCE / "status-learned.json").write_text(json.dumps(status(), indent=2))
        # No traffic producer is active now: one original CAS command, no
        # mutation retry or substitute observation after an ambiguous ACK.
        revision = ipc_client.status()["revision"]
        ipc_client.control({"type": "set_mode", "data": {"mode": "enforcing", "expected_revision": revision}})
        require(status()["mode"] == "enforcing", "root was unable to select Enforcing")
        for protocol in PORTS:
            probe(allowed, protocol, f"{profile}-enforcing-{protocol}", profile == "historical" or protocol == "tcp")
            release(allowed)
            probe(denied, protocol, f"{profile}-forbidden-{protocol}", False)
            release(denied)
        if profile == "small":
            require(not learned(peer, "udp"), "Enforcing created an unapproved UDP allowance")
            log = Path("/tmp/openshield.log").read_text()
            require("application learning quota reached" in log, "missing quota warning")
            require("Enforcing selected with learning quota warnings" in log, "missing incomplete-learning mode warning")
        (EVIDENCE / "status-final.json").write_text(json.dumps(status(), indent=2))
        (EVIDENCE / "state-final.json").write_text(json.dumps(persisted(), indent=2))
        emit(result="PASS", profile=profile, backend=backend)
    finally:
        for process in processes:
            process.stdin.close()
        for process in processes:
            try:
                require(process.wait(timeout=5) == 0, "worker exited unsuccessfully")
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise


def audit(path, profile):
    events = [json.loads(line) for line in Path(path).read_text().splitlines()]
    tokens = {event["token"] for event in events}
    require(not any("forbidden" in token for token in tokens), "FAIL-OPEN: peer received a forbidden application token")
    expected = {f"{profile}-learning-tcp", f"{profile}-learning-udp", f"{profile}-enforcing-tcp"}
    if profile == "historical":
        expected.add(f"{profile}-enforcing-udp")
    require(tokens == expected, f"unexpected peer receipts: {tokens}; expected {expected}")
    emit(result="PASS", peer_receipts=sorted(tokens))


def main():
    require(os.environ.get("OPENSHIELD_LEARNING_QUOTA_E2E") == "1", "run only through learning-quota.sh")
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["seed", "serve", "worker", "run", "audit"])
    parser.add_argument("arguments", nargs="*")
    arguments = parser.parse_args()
    operations = {"seed": seed, "serve": serve, "worker": worker, "run": run, "audit": audit}
    operations[arguments.operation](*arguments.arguments)


if __name__ == "__main__":
    main()
