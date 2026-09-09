#!/usr/bin/env python3
"""Read-only OpenVPN socket/UID evidence for OpenShield attribution failures.

Run on the affected host, preferably while OpenShield remains in Learning:
    sudo python3 scripts/diagnose-vpn-attribution.py

Reads bounded /proc files and /var/lib/openshield/state.json, then prints JSON.
Does not change firewall rules, mode, routes, services, or files. Command-line
arguments, cgroup paths, rule names, and VPN credentials are never printed.
Socket addresses and executable paths ARE printed. This is a momentary
diagnostic, not a proof of unique ownership or authorization. A different
network namespace, a disappearing process, or a read limit is reported.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import sys
import time


DEADLINE_SECONDS = 20
MAX_PROCESSES = 16384
MAX_VPN_PROCESSES = 32
MAX_FDS = 4096
MAX_SOCKET_ROWS = 65536
MAX_RULES = 10000
MAX_REPORTED_RULES = 256
FILE_ID_FIELDS = ("device", "inode", "size", "ctime_seconds", "ctime_nanoseconds")


class ReadLimit(Exception):
    pass


class Reader:
    def __init__(self):
        self.deadline = time.monotonic() + DEADLINE_SECONDS

    def check(self):
        if time.monotonic() >= self.deadline:
            raise ReadLimit("diagnostic time limit reached")

    def read(self, path, limit):
        self.check()
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
        self.check()
        if len(data) > limit:
            raise ReadLimit("file size limit reached")
        return data

    def entries(self, path, limit):
        self.check()
        names = []
        with os.scandir(path) as entries:
            for entry in entries:
                self.check()
                if len(names) >= limit:
                    raise ReadLimit("directory entry limit reached")
                names.append(entry.name)
        return names


def error_code(error):
    # Never include exception text: malformed JSON/UTF-8 can contain secrets.
    if isinstance(error, ReadLimit):
        return str(error)
    if isinstance(error, OSError):
        return "os_error_errno_%s" % error.errno
    return type(error).__name__


def metadata(reader, process):
    status = reader.read(process / "status", 65536).decode("utf-8")
    uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
    fsuid = int(uid_line.split()[4])
    stat = reader.read(process / "stat", 65536).decode("utf-8")
    start = int(stat[stat.rindex(")") + 1:].split()[19])
    executable = os.readlink(process / "exe")
    file_stat = (process / "exe").stat()
    file_id = dict(zip(FILE_ID_FIELDS, (
        file_stat.st_dev, file_stat.st_ino, file_stat.st_size,
        file_stat.st_ctime_ns // 1000000000, file_stat.st_ctime_ns % 1000000000,
    )))
    return {"fsuid": fsuid, "start_time_ticks": start,
            "executable": executable, "executable_file": file_id}


def address(value, ipv6):
    host, port = value.split(":")
    raw = bytes.fromhex(host)
    if sys.byteorder == "little":
        raw = b"".join(raw[index:index + 4][::-1] for index in range(0, len(raw), 4))
    if len(raw) != (16 if ipv6 else 4):
        raise ValueError("invalid address size")
    return str(ipaddress.ip_address(raw)), int(port, 16)


def socket_rows(reader, proc, inodes, errors):
    result = {}
    for table in ("udp", "udp6", "tcp", "tcp6"):
        try:
            lines = reader.read(proc / "net" / table, 16 * 1024 * 1024).decode("ascii").splitlines()
            if len(lines) > MAX_SOCKET_ROWS + 1:
                raise ReadLimit("socket row limit reached")
            for line in lines[1:]:
                reader.check()
                fields = line.split()
                inode = int(fields[9])
                if inode not in inodes:
                    continue
                local, local_port = address(fields[1], table.endswith("6"))
                peer, peer_port = address(fields[2], table.endswith("6"))
                result.setdefault(inode, []).append({
                    "protocol": table.rstrip("6"), "family": "ipv6" if table.endswith("6") else "ipv4",
                    "local_address": local, "local_port": local_port,
                    "peer_address": peer, "peer_port": peer_port,
                    "socket_uid": int(fields[7]), "state_hex": fields[3],
                })
        except (OSError, ValueError, IndexError, ReadLimit) as error:
            errors.append({"stage": "socket_table_" + table, "error": error_code(error)})
    return result


def command_matches(selector, arguments):
    if selector is None:
        return True
    if arguments is None or not isinstance(selector, dict):
        return None
    expected = selector.get("arguments")
    if not isinstance(expected, list):
        return None
    if selector.get("kind") == "exact":
        return arguments == expected
    if selector.get("kind") == "prefix":
        return arguments[:len(expected)] == expected
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, default=Path("/var/lib/openshield/state.json"))
    args = parser.parse_args()
    proc = Path("/proc")
    reader = Reader()
    report = {"diagnostic": "openshield_openvpn_attribution_v1", "read_only": True,
              "running_as_root": os.geteuid() == 0, "processes": [], "errors": []}
    private = {}
    rules = []
    try:
        current_netns = os.readlink(proc / "self/ns/net")
        pids = sorted(int(name) for name in reader.entries(proc, MAX_PROCESSES) if name.isdecimal())
        for pid in pids:
            process = proc / str(pid)
            try:
                if reader.read(process / "comm", 256).strip() != b"openvpn":
                    continue
                if len(report["processes"]) >= MAX_VPN_PROCESSES:
                    raise ReadLimit("OpenVPN process limit reached")
                item = {"pid": pid, "errors": [], "sockets": [], "enabled_rules": []}
                report["processes"].append(item)
                before = metadata(reader, process)
                item.update(before)
                item["same_network_namespace"] = os.readlink(process / "ns/net") == current_netns
                fds = {}
                for name in reader.entries(process / "fd", MAX_FDS):
                    try:
                        link = os.readlink(process / "fd" / name)
                        if link.startswith("socket:[") and link.endswith("]"):
                            fds.setdefault(int(link[8:-1]), []).append(int(name))
                    except FileNotFoundError:
                        continue
                arguments = cgroups = None
                for field in ("cmdline", "cgroup"):
                    try:
                        data = reader.read(process / field, 65536).decode("utf-8")
                        if field == "cmdline":
                            arguments = data.split("\0") if data else []
                            if data.endswith("\0"):
                                arguments.pop()
                        else:
                            cgroups = [line.split(":", 2)[2] for line in data.splitlines()]
                    except (OSError, ValueError, IndexError, ReadLimit) as error:
                        item["errors"].append({"stage": field, "error": error_code(error)})
                item["process_metadata_stable"] = metadata(reader, process) == before
                private[pid] = (fds, arguments, cgroups)
            except FileNotFoundError:
                # Normal exit between process enumeration and metadata capture.
                continue
            except (OSError, ValueError, IndexError, StopIteration, ReadLimit) as error:
                report["errors"].append({"pid": pid, "stage": "process", "error": error_code(error)})
                if isinstance(error, ReadLimit):
                    break

        inodes = {inode for fds, _, _ in private.values() for inode in fds}
        rows = socket_rows(reader, proc, inodes, report["errors"])
        for item in report["processes"]:
            if item["pid"] not in private:
                continue
            fds, _, _ = private[item["pid"]]
            for inode in sorted(fds):
                for row in rows.get(inode, []) if item["same_network_namespace"] else []:
                    socket = dict(row, inode=inode, fds=sorted(fds[inode]))
                    socket["socket_uid_matches_process_fsuid"] = row["socket_uid"] == item["fsuid"]
                    item["sockets"].append(socket)
            item["socket_fds_missing_from_host_inet_tables"] = sum(inode not in rows for inode in fds)

        state = json.loads(reader.read(args.state, 8 * 1024 * 1024))
        report["state"] = {key: state.get(key) for key in ("mode", "revision", "flow_generation")}
        raw_rules = state.get("rules", [])
        if not isinstance(raw_rules, (list, dict)) or len(raw_rules) > MAX_RULES:
            raise ReadLimit("state rule limit or format invalid")
        if isinstance(raw_rules, dict):
            raw_rules = raw_rules.values()
        for rule in raw_rules:
            reader.check()
            spec = rule.get("spec", {})
            application = spec.get("application") or {}
            executable = application.get("executable") or ""
            if spec.get("enabled") and Path(executable).name == "openvpn":
                if len(rules) >= MAX_REPORTED_RULES:
                    raise ReadLimit("reported OpenVPN rule limit reached")
                rules.append(rule)
        report["enabled_openvpn_rule_count"] = len(rules)
        for item in report["processes"]:
            if item["pid"] not in private:
                continue
            _, arguments, cgroups = private[item["pid"]]
            for rule in sorted(rules, key=lambda value: str(value.get("id", ""))):
                spec = rule["spec"]
                app = spec["application"]
                expected_uid = app.get("uid")
                expected_file = app.get("executable_file")
                item["enabled_rules"].append({
                    "id": rule.get("id"), "direction": spec.get("direction"),
                    "action": spec.get("action", "accept"), "protocol": spec.get("protocol"),
                    "peer_network": spec.get("peer_network"), "port": spec.get("port"),
                    "interface": spec.get("interface"), "uid": expected_uid,
                    "executable_file": expected_file,
                    "executable_matches": app.get("executable") == item["executable"],
                    "executable_file_matches": expected_file is None or expected_file == item["executable_file"],
                    "uid_matches_process_fsuid": expected_uid is None or expected_uid == item["fsuid"],
                    "command_line_constrained": app.get("command_line") is not None,
                    "command_line_matches": command_matches(app.get("command_line"), arguments),
                    "cgroup_constrained": app.get("cgroup") is not None,
                    "cgroup_matches": (True if app.get("cgroup") is None else
                                       None if cgroups is None else app["cgroup"] in cgroups),
                })
    except (OSError, ValueError, IndexError, TypeError, AttributeError, ReadLimit) as error:
        report["errors"].append({"stage": "diagnostic", "error": error_code(error)})
    report["socket_uid_mismatch_count"] = sum(
        not socket["socket_uid_matches_process_fsuid"]
        for item in report["processes"] for socket in item["sockets"]
    )
    json.dump(report, sys.stdout, indent=2, sort_keys=True, ensure_ascii=True)
    sys.stdout.write("\n")
    return 1 if report["errors"] or any(item["errors"] for item in report["processes"]) else 0


if __name__ == "__main__":
    sys.exit(main())
