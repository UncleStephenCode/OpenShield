#!/usr/bin/env python3
"""Atomic group IPC and real network-only TCP/UDP checks in private containers.

Run through outbound-group.sh. Application fixtures test IPC membership only;
they do not claim application attribution coverage. Every network probe uses a
fresh socket and a phase token that the independent peer records before echoing.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import copy
import errno
import json
import os
from pathlib import Path
import selectors
import socket
import threading
import time

import ipc_client

PORTS = {"tcp": 18243, "udp": 18242}
STATE = Path("/var/lib/openshield/state.json")
EVIDENCE = Path("/tmp/outbound-group")
OUTPUT_LOCK = threading.Lock()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def emit(event, **fields):
    with OUTPUT_LOCK:
        print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def normalized(rules):
    result = {}
    for rule in rules:
        item = copy.deepcopy(rule)
        item.pop("updated_at")
        item["spec"].setdefault("action", "accept")
        result[item["id"]] = item
    return result


def snapshot_attempt(timeout):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(timeout)
        stream.connect(ipc_client.OBSERVE)
        ipc_client.send_request(stream, {"type": "read", "data": {"type": "status"}})
        response = ipc_client.receive_response(stream)
        if response.get("type") != "status":
            return response
        ipc_client.send_request(stream, {"type": "read", "data": {
            "type": "rules_page", "data": {"after": None, "limit": 128}}})
        return ipc_client.receive_response(stream)


def snapshot():
    # The fixtures fit in one frame. The page itself carries the authoritative
    # revision even if a transaction occurs between the status and page reads.
    # Concurrent observers can legitimately exhaust the page-build permit.
    # Retry only read-side Conflict responses, on a fresh connection, within
    # this deadline. Privileged mutations are never retried by this helper.
    deadline = time.monotonic() + 2.0
    while True:
        remaining = deadline - time.monotonic()
        require(remaining > 0, "observation retry deadline exceeded")
        response = snapshot_attempt(min(1.0, remaining))
        if response.get("type") == "rules_page":
            page = response["data"]
            require(page["next_after"] is None, "fixtures no longer fit in one atomic page")
            return page
        require(response.get("type") == "error" and response.get("data", {}).get("code") == "conflict",
                f"snapshot read failed: {response}")
        remaining = deadline - time.monotonic()
        require(remaining > 0, f"observation retry deadline exceeded: {response}")
        time.sleep(min(0.05, remaining))


def mutate(kind, **data):
    revision = ipc_client.status()["revision"]
    return ipc_client.control({"type": kind, "data": {"expected_revision": revision, **data}})


def group_selector(kind, **data):
    return {"type": kind, "data": data}


def group_request(group, action, revision):
    return {"type": "control", "data": {"type": "manage_outbound_group", "data": {
        "expected_revision": revision, "group": group, "action": action}}}


def check_error(group, action, code, *, revision=None, path=ipc_client.CONTROL):
    before = snapshot()
    persisted = STATE.read_bytes()
    response = ipc_client.exchange(path, group_request(
        group, action, before["revision"] if revision is None else revision))
    require(response.get("type") == "error" and response["data"]["code"] == code,
            f"expected {code}, got {response}")
    require(snapshot() == before, f"{code} request changed live policy")
    require(STATE.read_bytes() == persisted, f"{code} request changed persisted policy")
    emit("rejected_control", group=group, action=action, code=code, path=path)


def manage(group, action, names):
    before = snapshot()
    old = normalized(before["rules"])
    selected = {key for key, rule in old.items() if rule["spec"]["name"] in names}
    require(len(selected) == len(names) and selected, f"missing group fixture: {names}")
    expected = copy.deepcopy(old)
    for key in selected:
        if action == "delete":
            del expected[key]
        elif action in ("enable", "disable"):
            expected[key]["spec"]["enabled"] = action == "enable"
        else:
            expected[key]["spec"]["action"] = action

    # Observe during the privileged operation. A one-page read may show either
    # complete policy; a partial group or unrelated edit must never appear.
    samples = []
    errors = []
    ready = threading.Event()
    stop = threading.Event()

    def observe():
        try:
            while not stop.is_set():
                samples.append(snapshot())
                ready.set()
                stop.wait(0.05)
        except Exception as error:
            errors.append(error)
            ready.set()

    observer = threading.Thread(target=observe, daemon=True)
    observer.start()
    try:
        require(ready.wait(6), "observer failed to reach the transaction barrier")
        require(not errors, f"observer failed: {errors}")
        response = ipc_client.exchange(ipc_client.CONTROL, group_request(group, action, before["revision"]))
        require(response.get("type") == "ack", f"group control failed: {response}")
        after = snapshot()
        samples.append(after)
    finally:
        stop.set()
        observer.join(timeout=6)
    require(not observer.is_alive() and not errors, f"observer failed: {errors}")
    ack = response["data"]
    require(ack["affected_rule"] is None, "group ACK identifies one rule instead of the transaction")
    require(ack["revision"] == after["revision"], "ACK does not identify the final policy")
    require(after["revision"] >= before["revision"], "policy revision moved backwards")
    if old != expected:
        require(after["revision"] > before["revision"], "changed group did not advance revision")
    require(normalized(after["rules"]) == expected, f"incorrect final group membership/action: {group} {action}")
    for sample in samples:
        require(sample["revision"] in (before["revision"], after["revision"]),
                "observation exposed an intermediate transaction revision")
        require(normalized(sample["rules"]) in (old, expected), "observation exposed a partial group transaction")
    # Unselected rules must retain even their update timestamps and file pins.
    unchanged = {rule["id"]: rule for rule in before["rules"] if rule["id"] not in selected}
    require({rule["id"]: rule for rule in after["rules"] if rule["id"] not in selected} == unchanged,
            "group action modified an unrelated rule")
    persisted = json.loads(STATE.read_text(encoding="utf-8"))
    require(persisted["revision"] == after["revision"], "ACK preceded policy persistence")
    require(normalized(persisted["rules"].values()) == expected, "persisted policy differs from group ACK")
    emit("group_changed", group=group, action=action, members=sorted(names),
         previous_revision=before["revision"], revision=after["revision"],
         idempotent=old == expected, observed_snapshots=len(samples))
    return before["revision"]


def create(name, address, protocol="tcp", *, enabled=True, application=None,
           direction="outbound", port=None):
    spec = {"name": name, "direction": direction, "action": "accept", "protocol": protocol,
            "peer_network": f"{address}/32" if address else None,
            "port": {"start": port or PORTS[protocol], "end": port or PORTS[protocol]},
            "interface": None, "application": application, "origin": "manual", "enabled": enabled}
    mutate("create_rule", rule=spec)


def application(executable, cgroup=None):
    return {"executable": executable, "executable_file": None, "command_line": None,
            "uid": None, "cgroup": cgroup, "metadata_redacted": False}


def probe(address, role, phase, protocol, allowed):
    token = f"outbound-group-v1|{role}|{phase}|{protocol}"
    payload = (token + "\n").encode("ascii")
    received = False
    failure = None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM) as stream:
        stream.settimeout(1.5)
        try:
            stream.connect((address, PORTS[protocol]))
            stream.sendall(payload)
            data = bytearray()
            while b"\n" not in data:
                chunk = stream.recv(512)
                if not chunk:
                    break
                data.extend(chunk)
                require(len(data) <= 512, "probe echo exceeded frame bound")
            require(bytes(data) in (b"", payload), f"unexpected echo for {token}: {data!r}")
            received = bytes(data) == payload
        except OSError as error:
            require(error.errno in (None, errno.EACCES, errno.EPERM, errno.ECONNREFUSED,
                                    errno.ECONNRESET, errno.EPIPE, errno.ETIMEDOUT,
                                    errno.EHOSTUNREACH, errno.ENETUNREACH),
                    f"unexpected socket failure: {error}")
            failure = str(error)
    emit("probe", token=token, allowed=allowed, received=received, error=failure)
    require(received == allowed, f"{token}: received={received}, expected={allowed}")


def traffic(target, other, phase, allowed):
    status = ipc_client.status_v2()
    require(status["mode"] == "enforcing" and status["runtime_compatibility"] == {
        "level": "kernel_native", "reason": "network_only"}, "traffic phase is not network-only Enforcing")
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(probe, address, role, phase, protocol, expected)
                   for role, address, expected in (("target", target, allowed), ("other", other, True))
                   for protocol in PORTS]
        for future in futures:
            future.result(timeout=5)


def run(target, other, backend):
    EVIDENCE.mkdir(exist_ok=True)
    require(ipc_client.status()["backend"] == backend, "daemon selected the wrong firewall backend")
    mutate("set_mode", mode="enforcing")
    require(not snapshot()["rules"], "group E2E requires a fresh private daemon state")
    for role, address in (("target", target), ("other", other)):
        for protocol in PORTS:
            create(f"{role}-{protocol}", address, protocol)
    create("inbound-sentinel", target, direction="inbound")
    destination = group_selector("destination", peer_network=f"{target}/32")
    members = {"target-tcp", "target-udp"}
    traffic(target, other, "baseline", True)
    check_error(destination, "delete", "unauthorized", path=ipc_client.OBSERVE)
    old_revision = manage(destination, "reject", members)
    traffic(target, other, "reject", False)
    check_error(destination, "delete", "conflict", revision=old_revision)
    manage(destination, "reject", members)  # Idempotent verdict; revisions may still advance.
    for action, allowed in (("accept", True), ("drop", False), ("disable", False),
                            ("enable", False), ("accept", True), ("delete", False)):
        manage(destination, action, members)
        traffic(target, other, f"{action}-{ipc_client.status()['revision']}", allowed)
    check_error(destination, "delete", "not_found")

    # Synthetic cgroups and pinned executable files exercise selection and
    # property preservation only. BlockAll keeps this separate from traffic.
    mutate("set_mode", mode="block_all")
    executable_a = str(Path("/usr/bin/true").resolve(strict=True))
    executable_b = str(Path("/usr/bin/false").resolve(strict=True))
    require(executable_a != executable_b, "application fixtures require two distinct canonical executable paths")
    cgroup = "/outbound-group-e2e/alpha"
    for protocol in PORTS:
        create(f"cgroup-a-{protocol}", target, protocol, application=application(executable_a, cgroup))
        create(f"fallback-a-{protocol}", target, protocol, application=application(executable_a))
    create("cgroup-b", target, application=application(executable_b, cgroup), enabled=False)
    create("cgroup-descendant", target, application=application(executable_a, cgroup + "/child"))
    create("cgroup-other", target, application=application(executable_a, "/outbound-group-e2e/beta"))
    create("fallback-b", target, application=application(executable_b))
    create("destination-fixture", target)
    create("any-destination-tcp", None)
    create("any-destination-udp", None, "udp")
    create("inbound-any-sentinel", None, direction="inbound")
    child = group_selector("cgroup", cgroup=cgroup, executable=executable_a)
    parent = group_selector("cgroup", cgroup=cgroup, executable=None)
    fallback = group_selector("executable", executable=executable_a)
    manage(child, "drop", {"cgroup-a-tcp", "cgroup-a-udp"})
    manage(parent, "reject", {"cgroup-a-tcp", "cgroup-a-udp", "cgroup-b"})
    manage(parent, "enable", {"cgroup-a-tcp", "cgroup-a-udp", "cgroup-b"})
    manage(child, "disable", {"cgroup-a-tcp", "cgroup-a-udp"})
    manage(child, "disable", {"cgroup-a-tcp", "cgroup-a-udp"})
    manage(fallback, "drop", {"fallback-a-tcp", "fallback-a-udp"})
    manage(fallback, "delete", {"fallback-a-tcp", "fallback-a-udp"})
    check_error(fallback, "enable", "not_found")
    manage(destination, "drop", {"destination-fixture"})
    manage(group_selector("destination", peer_network=None), "delete", {"any-destination-tcp", "any-destination-udp"})
    manage(parent, "delete", {"cgroup-a-tcp", "cgroup-a-udp", "cgroup-b"})
    check_error(parent, "delete", "not_found")
    EVIDENCE.joinpath("rules-final.json").write_text(json.dumps(snapshot(), indent=2) + "\n", encoding="utf-8")
    emit("completed", backend=backend, coverage="network-only TCP/UDP and application IPC membership")


def serve(address):
    selector = selectors.DefaultSelector()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((address, PORTS["udp"]))
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind((address, PORTS["tcp"]))
    tcp.listen(16)
    for stream in (udp, tcp):
        stream.setblocking(False)
        selector.register(stream, selectors.EVENT_READ, None)
    Path("/tmp/outbound-group-peer.ready").touch()
    deadline = time.monotonic() + 240
    try:
        while time.monotonic() < deadline:
            for key, _ in selector.select(0.1):
                stream = key.fileobj
                if stream is udp:
                    data, remote = udp.recvfrom(512)
                    emit("peer_received", token=data.decode("ascii").strip())
                    udp.sendto(data, remote)
                elif stream is tcp:
                    connection, _ = tcp.accept()
                    require(len(selector.get_map()) < 34, "peer connection bound exceeded")
                    connection.setblocking(False)
                    selector.register(connection, selectors.EVENT_READ, bytearray())
                else:
                    try:
                        data = stream.recv(512)
                    except ConnectionResetError:
                        data = b""
                    if not data:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    key.data.extend(data)
                    require(len(key.data) <= 512, "peer frame bound exceeded")
                    if b"\n" in key.data:
                        emit("peer_received", token=key.data.decode("ascii").strip())
                        try:
                            stream.sendall(key.data)
                        except (BrokenPipeError, ConnectionResetError):
                            pass
                        selector.unregister(stream)
                        stream.close()
    finally:
        for key in list(selector.get_map().values()):
            key.fileobj.close()
        selector.close()


def analyze(directory):
    records = [json.loads(line) for line in directory.joinpath("controller.jsonl").read_text().splitlines()]
    require(any(item["event"] == "completed" for item in records), "controller did not complete")
    probes = {item["token"]: item for item in records if item["event"] == "probe"}
    received = set()
    for role in ("target", "other"):
        require(not directory.joinpath(f"{role}-peer.error").read_text(), f"{role} peer failed")
        for line in directory.joinpath(f"{role}-peer.jsonl").read_text().splitlines():
            event = json.loads(line)
            require(event["event"] == "peer_received", "unexpected peer event")
            token = event["token"]
            require(token in probes and probes[token]["allowed"], f"peer received forbidden/unknown payload: {token}")
            require(token.split("|")[1] == role, f"payload reached wrong peer: {token}")
            received.add(token)
    expected = {token for token, probe in probes.items() if probe["allowed"]}
    require(received == expected, f"peer receipts differ from allowed probes: {received ^ expected}")
    require(all(item["received"] == item["allowed"] for item in probes.values()), "probe outcome mismatch")
    emit("audit_passed", probes=len(probes), allowed=len(expected), denied=len(probes) - len(expected),
         group_transactions=sum(item["event"] == "group_changed" for item in records))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    peer = commands.add_parser("serve")
    peer.add_argument("address")
    controller = commands.add_parser("run")
    controller.add_argument("target")
    controller.add_argument("other")
    controller.add_argument("backend", choices=("nftables", "iptables"))
    audit = commands.add_parser("analyze")
    audit.add_argument("directory", type=Path)
    arguments = parser.parse_args()
    if arguments.command in ("serve", "run"):
        require(Path("/.dockerenv").is_file() and os.environ.get("OPENSHIELD_OUTBOUND_GROUP_E2E") == "1",
                "socket workloads and control mutations must run through outbound-group.sh in its private containers")
    if arguments.command == "serve":
        serve(arguments.address)
    elif arguments.command == "run":
        run(arguments.target, arguments.other, arguments.backend)
    else:
        analyze(arguments.directory)


if __name__ == "__main__":
    main()
