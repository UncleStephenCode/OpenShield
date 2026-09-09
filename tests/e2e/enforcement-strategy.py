#!/usr/bin/env python3
"""Strict/Fast IPC, current rules and real TCP/UDP in an isolated test DUT."""

import argparse
import errno
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import time

import ipc_client

SPEC = importlib.util.spec_from_file_location(
    "strategy_quota_helpers", Path(__file__).with_name("learning-quota.py")
)
Q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(Q)
EVIDENCE = Path("/tmp/enforcement-strategy")
WARM_ROUNDS = 3
# A normal desktop browser can exceed the historical 4,096-descriptor scan
# bound. Keep this below the daemon's new fixed ceiling while making the old
# regression deterministic in the otherwise minimal CI container.
DESKTOP_FD_COUNT = 5_000


def status():
    response = ipc_client.exchange(ipc_client.OBSERVE, {
        "type": "read", "data": {"type": "status_v4"},
    })
    Q.require(response.get("type") == "status_v4", f"no strategy telemetry: {response}")
    current = response["data"]
    Q.require(current.get("enforcement_strategy") in ("strict", "fast"),
              f"invalid strategy telemetry: {current}")
    return current


def state():
    with Q.STATE.open("rb") as stream:
        data = stream.read(8 * 1024 * 1024 + 1)
    Q.require(len(data) <= 8 * 1024 * 1024, "persisted state exceeds byte limit")
    return json.loads(data)


def mutation(kind, **data):
    current = status()
    before = state()
    Q.require(before["revision"] == current["revision"], "policy changed before mutation")
    ack = ipc_client.control({
        "type": kind, "data": {"expected_revision": current["revision"], **data},
    })
    after = state()
    reported = status()
    Q.require(ack["revision"] == after["revision"] == reported["revision"],
              "ACK, durable state and observed revision disagree")
    Q.require(after["revision"] > before["revision"], "control change did not advance revision")
    rotates_epoch = True
    if kind == "set_rule_enabled":
        old = before["rules"][data["id"]]["spec"]
        rotates_epoch = (old["enabled"] and not data["enabled"]) or (
            not old["enabled"] and data["enabled"] and old.get("action", "accept") != "accept")
    if rotates_epoch:
        Q.require(after["flow_generation"] > before["flow_generation"],
                  "control change did not invalidate the attribution/conntrack epoch")
    else:
        # Enabling an Accept rule expands permission monotonically. The core
        # intentionally preserves the generation; current rules are still
        # evaluated, and there is no retained Fast deny/allow verdict cache.
        Q.require(after["flow_generation"] >= before["flow_generation"],
                  "non-revoking control change rolled back the flow generation")
    return reported, after


def enforce(strategy):
    current, saved = mutation("set_enforcement", strategy=strategy)
    Q.require(current["mode"] == "enforcing" and current["enforcement_strategy"] == strategy,
              f"incorrect active enforcement strategy: {current}")
    Q.require(saved["mode"] == "enforcing" and saved.get("enforcement_strategy", "strict") == strategy,
              "strategy is not persisted")
    (EVIDENCE / f"status-{strategy}-{saved['revision']}.json").write_text(json.dumps(current, indent=2))


def seed():
    Q.require(not Q.STATE.exists(), "refusing to replace an existing policy")
    source = str(Path(sys.executable).resolve())
    for executable in (Q.ALLOWED, Q.DENIED):
        Q.require(not Path(executable).exists(), "fixture executable already exists")
        shutil.copyfile(source, executable)
        os.chmod(executable, 0o755)
    EVIDENCE.mkdir(mode=0o700)


def receive_exact(stream, size, deadline):
    received = bytearray()
    while len(received) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("TCP response deadline expired")
        stream.settimeout(remaining)
        chunk = stream.recv(size - len(received))
        if not chunk:
            raise EOFError("TCP peer closed before its complete response")
        received.extend(chunk)
    return bytes(received)


def exchange(stream, protocol, peer, token, connect):
    deadline = time.monotonic() + 3
    stream.settimeout(3)
    if connect:
        stream.connect((peer, Q.PORTS[protocol]))
    remaining = deadline - time.monotonic()
    Q.require(remaining > 0, "connection exceeded workload deadline")
    stream.settimeout(remaining)
    payload = token.encode("ascii")
    if protocol == "tcp":
        stream.sendall(struct.pack("!I", len(payload)) + payload)
        length = struct.unpack("!I", receive_exact(stream, 4, deadline))[0]
        Q.require(length == len(payload), "incorrect TCP response frame length")
        response = receive_exact(stream, length, deadline)
    else:
        stream.sendall(payload)
        remaining = deadline - time.monotonic()
        Q.require(remaining > 0, "UDP send exceeded workload deadline")
        stream.settimeout(remaining)
        response = stream.recv(1024)
    Q.require(response == payload, "incorrect peer echo")


def worker(peer, *_identity_variant):
    held = None
    held_protocol = None
    try:
        for line in sys.stdin:
            command = json.loads(line)
            if command["operation"] == "close":
                if held is not None:
                    held.close()
                    held = None
                Q.emit(closed=True)
                continue
            connect = command["operation"] == "probe"
            protocol = command["protocol"]
            if connect:
                Q.require(held is None, "previous socket was not released")
                held_protocol = protocol
                held = socket.socket(socket.AF_INET,
                                     socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM)
            else:
                Q.require(command["operation"] == "repeat" and held is not None
                          and protocol == held_protocol, "repeat requires a held socket of the same protocol")
            try:
                exchange(held, protocol, peer, command["token"], connect)
                Q.emit(success=True, token=command["token"])
            except PermissionError as error:
                if error.errno not in (errno.EPERM, errno.EACCES):
                    raise
                Q.emit(success=False, token=command["token"], error=type(error).__name__, errno=error.errno)
            except (TimeoutError, ConnectionRefusedError, ConnectionResetError, BrokenPipeError, EOFError) as error:
                Q.emit(success=False, token=command["token"], error=type(error).__name__)
    finally:
        if held is not None:
            held.close()


def fd_holder(count):
    descriptors = []
    try:
        for _ in range(int(count)):
            descriptors.append(os.open("/dev/null", os.O_RDONLY | os.O_CLOEXEC))
        Q.emit(ready=True, descriptors=len(descriptors))
        for _line in sys.stdin:
            break
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def repeat(process, protocol, token, expected):
    response = Q.ask(process, {"operation": "repeat", "protocol": protocol, "token": token})
    Q.require(response["success"] is expected, f"unexpected retained-socket result: {response}")


def fresh(process, protocol, token, expected):
    Q.probe(process, protocol, token, expected)
    Q.release(process)


def allowed_tokens():
    tokens = {"learning-tcp", "learning-udp", "learning-fast-tcp", "learning-fast-udp",
              "learning-churn-tcp", "learning-churn-udp", "strict-tcp", "strict-udp",
              "learning-variant-tcp", "fast-variant-udp", "fast-held-tcp",
              "fast-restored-tcp", "fast-held-udp", "strict-restored-tcp"}
    for i in range(WARM_ROUNDS):
        for protocol in Q.PORTS:
            tokens.add(f"fast-warm-{i}-{protocol}")
    return tokens


def audit(path):
    events = [json.loads(line) for line in Path(path).read_text().splitlines()]
    tokens = {event["token"] for event in events}
    Q.require(not any("forbidden" in token for token in tokens),
              "FAIL-OPEN: independent peer received forbidden traffic")
    Q.require(tokens == allowed_tokens(), f"incorrect independent peer receipts: {tokens}")
    Q.emit(result="PASS", peer_receipts=sorted(tokens))


def run(peer, backend):
    current = status()
    Q.require(current["mode"] == "learning" and current["backend"] == backend
              and current["enforcement_strategy"] == "strict", f"incorrect fresh runtime: {current}")
    processes = []
    try:
        holder = subprocess.Popen(
            [Q.ALLOWED, __file__, "fd-holder", str(DESKTOP_FD_COUNT)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        holder_ready = json.loads(holder.stdout.readline(8192))
        Q.require(holder_ready == {"ready": True, "descriptors": DESKTOP_FD_COUNT},
                  f"large-fd fixture did not initialize: {holder_ready}")
        processes.append(holder)
        for executable in (Q.ALLOWED, Q.DENIED):
            processes.append(subprocess.Popen([executable, __file__, "worker", peer],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1))
        allowed, denied = processes[1:]
        rule_ids = {}
        for protocol in Q.PORTS:
            Q.probe(allowed, protocol, f"learning-{protocol}", True)
            Q.wait(lambda: Q.learned(peer, protocol), f"no durable {protocol} learned allow")
            matches = Q.learned(peer, protocol)
            Q.require(len(matches) == 1, f"unexpected duplicate {protocol} allow")
            rule_ids[protocol] = matches[0]["id"]
            Q.release(allowed)
        # A multi-process browser commonly starts another instance of the
        # same executable with volatile argv/cgroup identity. Teach only its
        # TCP endpoint so UDP below can prove that Fast reuses an automatic
        # learned endpoint by stable executable identity, while Strict still
        # requires the complete original selector.
        variant = subprocess.Popen(
            [Q.ALLOWED, __file__, "worker", peer, "runtime-variant"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        processes.append(variant)
        original_tcp_ids = {rule["id"] for rule in Q.learned(peer, "tcp")}
        fresh(variant, "tcp", "learning-variant-tcp", True)
        Q.wait(lambda: len(Q.learned(peer, "tcp")) >= 2,
               "no distinct learned selector for the argv variant")
        variant_tcp_ids = [rule["id"] for rule in Q.learned(peer, "tcp")
                           if rule["id"] not in original_tcp_ids]
        Q.require(len(variant_tcp_ids) == 1, "variant TCP rule is not uniquely identifiable")
        # Seed a second recent process hint, then let that process disappear.
        # Fast must omit this stale candidate without flushing the live owner
        # and falling back to a UID-wide scan. The unrelated large-fd process
        # makes such an accidental fallback observable and deterministic.
        transient = subprocess.Popen(
            [Q.ALLOWED, __file__, "worker", peer],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        for protocol in Q.PORTS:
            fresh(transient, protocol, f"learning-churn-{protocol}", True)
        transient.stdin.close()
        Q.require(transient.wait(timeout=5) == 0, "transient learning worker did not exit")
        initial_rules = state()["rules"]
        Q.require(all(not rule["spec"]["enabled"] for rule in initial_rules.values()
                      if rule["spec"]["origin"] == "template"), "auto-template unexpectedly enabled")
        # A busy production host cannot afford a cold exhaustive owner scan
        # under the shorter Enforcing deadline. Exercise the direct handoff of
        # positive, twice-checked Learning owner hints to Fast.
        enforce("fast")
        fresh(variant, "udp", "fast-variant-udp", True)
        for protocol in Q.PORTS:
            fresh(allowed, protocol, f"learning-fast-{protocol}", True)
        enforce("strict")
        fresh(variant, "udp", "strict-forbidden-variant-udp", False)
        mutation("delete_rule", id=variant_tcp_ids[0])
        for protocol in Q.PORTS:
            fresh(allowed, protocol, f"strict-{protocol}", True)
            fresh(denied, protocol, f"strict-forbidden-{protocol}", False)
        enforce("fast")
        for i in range(WARM_ROUNDS):
            for protocol in Q.PORTS:
                fresh(allowed, protocol, f"fast-warm-{i}-{protocol}", True)
        for protocol in Q.PORTS:
            fresh(denied, protocol, f"fast-forbidden-{protocol}", False)
        # Revoke a live established TCP connection, not just the next SYN.
        Q.probe(allowed, "tcp", "fast-held-tcp", True)
        mutation("set_rule_enabled", id=rule_ids["tcp"], enabled=False)
        repeat(allowed, "tcp", "fast-forbidden-established-tcp", False)
        Q.release(allowed)
        fresh(allowed, "tcp", "fast-forbidden-new-tcp", False)
        mutation("set_rule_enabled", id=rule_ids["tcp"], enabled=True)
        fresh(allowed, "tcp", "fast-restored-tcp", True)
        # A still-open UDP socket must not keep an old decision after deletion.
        Q.probe(allowed, "udp", "fast-held-udp", True)
        mutation("delete_rule", id=rule_ids["udp"])
        repeat(allowed, "udp", "fast-forbidden-held-udp", False)
        Q.release(allowed)
        fresh(allowed, "udp", "fast-forbidden-new-udp", False)
        Q.require(rule_ids["udp"] not in state()["rules"], "deleted UDP rule remains durable")
        enforce("strict")
        fresh(allowed, "tcp", "strict-restored-tcp", True)
        fresh(allowed, "udp", "strict-forbidden-deleted-udp", False)
        for protocol in Q.PORTS:
            fresh(denied, protocol, f"strict-final-forbidden-{protocol}", False)
        (EVIDENCE / "state-final.json").write_text(json.dumps(state(), indent=2))
        (EVIDENCE / "status-final.json").write_text(json.dumps(status(), indent=2))
        Q.emit(result="PASS", backend=backend, strategies=["strict", "fast", "strict"])
    finally:
        for process in processes:
            process.stdin.close()
        for process in processes:
            try:
                Q.require(process.wait(timeout=5) == 0, "network worker exited unsuccessfully")
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise


def main():
    Q.require(os.environ.get("OPENSHIELD_STRATEGY_E2E") == "1", "run only through enforcement-strategy.sh")
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "operation", choices=["seed", "serve", "worker", "fd-holder", "run", "audit"]
    )
    parser.add_argument("arguments", nargs="*")
    arguments = parser.parse_args()
    operations = {
        "seed": seed,
        "serve": Q.serve,
        "worker": worker,
        "fd-holder": fd_holder,
        "run": run,
        "audit": audit,
    }
    operations[arguments.operation](*arguments.arguments)


if __name__ == "__main__":
    main()
