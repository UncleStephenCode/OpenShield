#!/usr/bin/env python3
"""Real-socket, peer-audited policy revocation under an attribution backlog.

Run only through scheduler-generation.sh in private containers. Post-revocation
payloads are emitted after the control ACK, not classified using peer arrival
timestamps: an earlier authorized packet can legitimately arrive after an ACK.
"""

import argparse
import errno
import json
from pathlib import Path
import selectors
import socket
import struct
import subprocess
import time

import ipc_client

UDP_PORT = 18142
TCP_PORT = 18143
PHASES = ("before", "pending_revoke", "revoked", "restored", "pending_block", "block_all", "resumed")
FORBIDDEN = {"revoked", "block_all"}
ROOT = Path("/tmp/scheduler-generation")


def emit(event, **fields):
    print(json.dumps({"event": event, "monotonic": time.monotonic(), **fields}, sort_keys=True), flush=True)


def payload(role, phase, transport, index):
    return f"scheduler-v1|{role}|{phase}|{transport}|{index}\n".encode("ascii")


def decode(data):
    fields = data.decode("ascii").strip().split("|")
    if len(fields) != 5 or fields[0] != "scheduler-v1" or fields[1] not in ("known", "unknown") or fields[2] not in PHASES or fields[3] not in ("tcp", "udp", "held_tcp"):
        raise ValueError("unexpected peer payload")
    return {"role": fields[1], "phase": fields[2], "transport": fields[3], "index": int(fields[4])}


def serve(address):
    selector = selectors.DefaultSelector()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((address, UDP_PORT))
    udp.setblocking(False)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((address, TCP_PORT))
    tcp.listen(128)
    tcp.setblocking(False)
    selector.register(udp, selectors.EVENT_READ, None)
    selector.register(tcp, selectors.EVENT_READ, None)
    Path("/tmp/scheduler-peer.ready").touch()
    deadline = time.monotonic() + 240
    try:
        while time.monotonic() < deadline:
            for key, _ in selector.select(0.1):
                stream = key.fileobj
                if stream is udp:
                    data, remote = udp.recvfrom(512)
                    emit("peer_received", **decode(data))
                    udp.sendto(data, remote)
                elif stream is tcp:
                    connection, _ = tcp.accept()
                    if len(selector.get_map()) >= 258:
                        connection.close()
                        raise RuntimeError("peer connection capacity exhausted")
                    connection.setblocking(False)
                    selector.register(connection, selectors.EVENT_READ, bytearray())
                else:
                    try:
                        data = stream.recv(4096)
                    except ConnectionResetError:
                        data = b""
                    if not data:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    key.data.extend(data)
                    if len(key.data) > 8192:
                        raise RuntimeError("peer framing bound exceeded")
                    while b"\n" in key.data:
                        line, _, remainder = key.data.partition(b"\n")
                        key.data[:] = remainder
                        emit("peer_received", **decode(line))
                        try:
                            stream.sendall(line + b"\n")
                        except (BrokenPipeError, ConnectionResetError):
                            pass
    finally:
        for key in list(selector.get_map().values()):
            key.fileobj.close()
        selector.close()


def wait_file(path, seconds=30):
    deadline = time.monotonic() + seconds
    while not path.is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError(f"missing workload barrier: {path}")
        time.sleep(0.005)
    return json.loads(path.read_text(encoding="utf-8"))


def workload(role, address):
    held = None
    directory = ROOT / role
    directory.joinpath("ready.json").write_text("{}", encoding="ascii")
    for phase in PHASES:
        barrier = wait_file(ROOT / f"{phase}.gate")
        emit("phase_start", role=role, phase=phase, barrier=barrier)
        selector = selectors.DefaultSelector()
        if held is not None:
            try:
                held.sendall(payload(role, phase, "held_tcp", 0))
                emit("sent", role=role, phase=phase, transport="held_tcp", index=0)
            except OSError as error:
                emit("held_send_error", role=role, phase=phase, error=str(error))
                held.close()
                held = None
        for index in range(16):
            stream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            stream.connect((address, UDP_PORT))
            stream.setblocking(False)
            emit("send_attempt", role=role, phase=phase, transport="udp", index=index)
            try:
                stream.send(payload(role, phase, "udp", index))
            except OSError as error:
                # A synchronous kernel DROP can report EPERM immediately.
                emit("send_error", role=role, phase=phase, transport="udp", index=index, error=str(error))
                stream.close()
                continue
            selector.register(stream, selectors.EVENT_READ, ("udp", index, False))
            emit("sent", role=role, phase=phase, transport="udp", index=index)
        for index in range(8):
            stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            stream.setblocking(False)
            emit("connect_attempt", role=role, phase=phase, transport="tcp", index=index)
            outcome = stream.connect_ex((address, TCP_PORT))
            if outcome not in (0, errno.EINPROGRESS):
                emit("connect_error", role=role, phase=phase, transport="tcp", index=index, errno=outcome)
                stream.close()
                continue
            selector.register(stream, selectors.EVENT_WRITE, ("tcp", index, True))
        received = {"udp": 0, "tcp": 0}
        tcp_buffers = {}
        deadline = time.monotonic() + 3.0
        try:
            while time.monotonic() < deadline and selector.get_map():
                for key, _ in selector.select(0.05):
                    transport, index, connecting = key.data
                    stream = key.fileobj
                    if connecting:
                        outcome = stream.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                        if outcome:
                            selector.unregister(stream)
                            stream.close()
                            continue
                        emit("connected", role=role, phase=phase, transport="tcp", index=index)
                        stream.sendall(payload(role, phase, "tcp", index))
                        selector.modify(stream, selectors.EVENT_READ, (transport, index, False))
                        continue
                    try:
                        data = stream.recv(512)
                    except OSError:
                        data = b""
                    if data and transport == "tcp":
                        buffered = tcp_buffers.setdefault(index, bytearray())
                        buffered.extend(data)
                        if len(buffered) > 512:
                            raise RuntimeError("client framing bound exceeded")
                        if b"\n" not in buffered:
                            continue
                        data = bytes(buffered)
                    selector.unregister(stream)
                    if data:
                        received[transport] += 1
                        emit("received", **decode(data))
                        if role == "known" and phase in ("before", "restored") and transport == "tcp" and held is None:
                            held = stream
                            continue
                    stream.close()
        finally:
            for key in list(selector.get_map().values()):
                key.fileobj.close()
            selector.close()
        if held is not None and phase in FORBIDDEN:
            # Do not replay TCP application bytes legitimately buffered during
            # a denial after permissions are restored in a later test phase.
            held.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            held.close()
            held = None
        directory.joinpath(f"{phase}.done").write_text(json.dumps(received), encoding="ascii")
    if held is not None:
        held.close()


def set_mode(mode):
    current = ipc_client.status()
    return ipc_client.control({"type": "set_mode", "data": {"expected_revision": current["revision"], "mode": mode}})


def set_rules(enabled):
    for name in ("scheduler-tcp", "scheduler-udp"):
        matches = [rule for rule in ipc_client.all_rules() if rule["spec"]["name"] == name]
        if len(matches) != 1:
            raise RuntimeError(f"expected one {name} rule")
        current = ipc_client.status()
        ipc_client.control({"type": "set_rule_enabled", "data": {"expected_revision": current["revision"], "id": matches[0]["id"], "enabled": enabled}})
    return ipc_client.status()


def depth():
    for line in Path("/proc/self/net/netfilter/nfnetlink_queue").read_text(encoding="ascii").splitlines():
        fields = line.split()
        if fields[0] == "1337":
            return int(fields[2])
    raise RuntimeError("enforcing queue missing")


def control_run(address):
    processes = []
    outputs = []
    for role in ("known", "unknown"):
        output = ROOT.joinpath(f"{role}.jsonl").open("w", encoding="utf-8")
        outputs.append(output)
        processes.append(subprocess.Popen(["runuser", "-u", "schedulerapp", "--", f"/tmp/scheduler-{role}", __file__, "workload", role, address], stdout=output, stderr=subprocess.STDOUT))
    try:
        for role in ("known", "unknown"):
            wait_file(ROOT / role / "ready.json")
        for phase in PHASES:
            if phase == "restored":
                ack = set_rules(True)
            elif phase == "resumed":
                ack = set_mode("enforcing")
            else:
                ack = ipc_client.status()
            barrier = {"phase": phase, "ack_completed_monotonic": time.monotonic(), "revision": ack.get("revision")}
            ROOT.joinpath(f"{phase}.gate").write_text(json.dumps(barrier), encoding="ascii")
            emit("phase_released", **barrier)
            if phase in ("pending_revoke", "pending_block"):
                deadline = time.monotonic() + 3
                observed = 0
                while time.monotonic() < deadline:
                    observed = depth()
                    if observed >= 8:
                        break
                    time.sleep(0.002)
                if observed < 8:
                    raise RuntimeError("inconclusive: policy transition did not overlap a real queue backlog")
                emit("pending_before_mutation", phase=phase, queue_depth=observed)
                result = set_rules(False) if phase == "pending_revoke" else set_mode("block_all")
                emit("mutation_ack", phase=phase, revision=result.get("revision"), queue_depth=depth())
            for role in ("known", "unknown"):
                result = wait_file(ROOT / role / f"{phase}.done", 12)
                if role == "known" and phase in ("before", "restored", "resumed") and not all(result[name] > 0 for name in ("tcp", "udp")):
                    raise RuntimeError(f"known real TCP/UDP did not work in {phase}: {result}")
        for process in processes:
            if process.wait(timeout=5):
                raise RuntimeError("socket workload failed")
        emit("controller_complete", status=ipc_client.status())
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        for output in outputs:
            output.close()


def analyze(directory):
    def records(name):
        return [json.loads(line) for line in directory.joinpath(name).read_text(encoding="utf-8").splitlines() if line]

    peer = records("peer.jsonl")
    known = records("known.jsonl")
    unknown = records("unknown.jsonl")
    controller = records("controller.jsonl")
    violations = []
    for record in peer:
        if record["role"] == "unknown" or record["phase"] in FORBIDDEN:
            violations.append(f"peer received forbidden payload: {record}")
    for record in known + unknown:
        if record["event"] in ("connected", "received") and (record["role"] == "unknown" or record["phase"] in FORBIDDEN):
            violations.append(f"forbidden connect/reply: {record}")
    for phase in ("before", "restored", "resumed"):
        for transport in ("tcp", "udp"):
            if not any(record["role"] == "known" and record["phase"] == phase and record["transport"] == transport for record in peer):
                violations.append(f"no known {transport} peer receipt in {phase}")
    for phase in FORBIDDEN:
        for event in ("send_attempt", "connect_attempt"):
            if not any(record["event"] == event and record["phase"] == phase for record in known):
                violations.append(f"missing post-ACK {event} in {phase}")
    pending = [record for record in controller if record["event"] == "pending_before_mutation"]
    if {record["phase"] for record in pending if record["queue_depth"] >= 8} != {"pending_revoke", "pending_block"}:
        violations.append("missing proven queue backlog at both mutations")
    completed = [record for record in controller if record["event"] == "controller_complete"]
    if len(completed) != 1 or completed[0]["status"]["mode"] != "enforcing":
        violations.append("controller did not finish in Enforcing")
    elif any(completed[0]["status"]["nfqueue"][name] for name in ("attribution_timeout", "queue_overflow", "terminal_queue_error")):
        violations.append("NFQUEUE timeout/overflow/terminal error during bounded regression")
    report = {"schema": "openshield.scheduler-generation.v1", "passed": not violations, "violations": violations, "pending": pending, "peer_records": len(peer), "note": "Only payloads emitted after acknowledged revocation/BlockAll are forbidden; pre-ACK packets are not misclassified by peer arrival time."}
    directory.joinpath("report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    if violations:
        raise RuntimeError("scheduler generation regression failed")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve").add_argument("address")
    client = commands.add_parser("workload")
    client.add_argument("role", choices=("known", "unknown"))
    client.add_argument("address")
    commands.add_parser("control").add_argument("address")
    commands.add_parser("analyze").add_argument("directory", type=Path)
    arguments = parser.parse_args()
    if arguments.command == "serve":
        serve(arguments.address)
    elif arguments.command == "workload":
        workload(arguments.role, arguments.address)
    elif arguments.command == "control":
        control_run(arguments.address)
    else:
        analyze(arguments.directory)


if __name__ == "__main__":
    main()
