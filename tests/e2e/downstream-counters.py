#!/usr/bin/env python3
"""Verify the exact, fresh downstream DROP rules from bounded kernel output."""

import ipaddress
import json
import re
import shlex
import sys


MAX_INPUT_BYTES = 1024 * 1024
CHAIN = "OPENSHIELD_E2E_DOWNSTREAM"
TABLE = "openshield_e2e_downstream"
PREFIX = "openshield-e2e-downstream-"
RULE_IDS = ("syn", "tcp", "udp")
TCP_FLAGS = {"fin": 1, "syn": 2, "rst": 4, "psh": 8, "ack": 16, "urg": 32,
             "ecn": 64, "cwr": 128}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def host_address(value):
    if isinstance(value, dict) and set(value) == {"prefix"}:
        prefix = value["prefix"]
        require(isinstance(prefix, dict) and set(prefix) == {"addr", "len"}
                and type(prefix["len"]) is int and prefix["len"] == 32,
                "downstream address must be an exact IPv4 host")
        value = prefix["addr"]
    require(isinstance(value, str), "downstream address is not a string")
    network = ipaddress.IPv4Network(value, strict=True)
    require(network.prefixlen == 32, "downstream address must be /32")
    return str(network.network_address)


def counter(value):
    require(isinstance(value, dict) and set(value) == {"packets", "bytes"},
            "missing or nonliteral downstream kernel counter")
    require(all(type(number) is int and 0 <= number < 2 ** 64 for number in value.values()),
            "invalid downstream kernel counter value")
    return value["packets"]


def finish(counters):
    require(list(counters) == list(RULE_IDS), "missing, reordered or ambiguous downstream rules")
    # A stale FIN may hit the generic TCP rule. Only a NEW handshake SYN is
    # evidence that this TCP probe passed OpenShield and reached downstream.
    require(counters["syn"] > 0, "downstream TCP SYN DROP received no packets")
    require(counters["udp"] > 0, "downstream UDP DROP received no packets")
    return {"tcp_syn_packets": counters["syn"], "udp_packets": counters["udp"]}


def verify_iptables(text, source, destination):
    table = None
    filter_tables = commits = hooks = declarations = 0
    counters = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            require(table is None, "nested iptables table")
            table = line[1:]
            filter_tables += table == "filter"
            continue
        if line == "COMMIT":
            commits += table == "filter"
            table = None
            continue
        if table != "filter":
            continue
        if line.startswith(":" + CHAIN + " "):
            require(re.fullmatch(r":" + CHAIN + r" - \[\d+:\d+\]", line) is not None,
                    "downstream chain is not a user chain")
            declarations += 1
            continue
        match = re.fullmatch(r"\[(\d+):(\d+)\] (.*)", line)
        words = shlex.split(match[3] if match else line)
        if words[:2] == ["-A", "OUTPUT"] and CHAIN in words:
            require(words == ["-A", "OUTPUT", "-j", CHAIN], "unexpected downstream OUTPUT hook")
            hooks += 1
        if words[:2] != ["-A", CHAIN]:
            continue
        require(match is not None, "downstream rule has no kernel counter")
        require(words[-2:] == ["-j", "DROP"], "downstream verdict is not terminal DROP")
        options = {}
        modules = []
        index = 2
        while index < len(words) - 2:
            option = words[index]
            width = 2 if option == "--tcp-flags" else 1
            require(option in ("-s", "-d", "-p", "-m", "--dport", "--comment", "--tcp-flags")
                    and index + width < len(words) - 2, "unexpected downstream rule option")
            values = words[index + 1:index + 1 + width]
            if option == "-m":
                modules.extend(values)
            else:
                require(option not in options, "duplicate downstream rule option")
                options[option] = values[0] if width == 1 else values
            index += width + 1
        identifier = str(options.get("--comment", ""))
        require(identifier.startswith(PREFIX), "downstream rule has wrong identity")
        identifier = identifier[len(PREFIX):]
        require(identifier in RULE_IDS and identifier not in counters, "ambiguous downstream rule identity")
        protocol = "udp" if identifier == "udp" else "tcp"
        expected = {"-s", "-d", "-p", "--dport", "--comment"}
        if identifier == "syn":
            expected.add("--tcp-flags")
            require(options.get("--tcp-flags") == ["FIN,SYN,RST,ACK", "SYN"],
                    "TCP evidence rule is not SYN-only")
        require(set(options) == expected and sorted(modules) == sorted((protocol, "comment")),
                "unexpected downstream rule selectors")
        require(host_address(options["-s"]) == source and host_address(options["-d"]) == destination
                and options["-p"] == protocol and options["--dport"] == ("18082" if protocol == "udp" else "18081"),
                "wrong downstream source, destination, protocol or port")
        counters[identifier] = counter({"packets": int(match[1]), "bytes": int(match[2])})
    require(table is None and filter_tables == commits == hooks == declarations == 1,
            "missing or ambiguous committed downstream filter chain/hook")
    return finish(counters)


def flags(value):
    if type(value) is int:
        require(0 <= value <= 255, "invalid TCP flag value")
        return value
    if isinstance(value, dict) and set(value) in ({"set"}, {"|"}):
        # nft emits a symbolic mask as an explicit bitwise-OR expression.
        value = next(iter(value.values()))
        require(isinstance(value, list), "invalid TCP flag collection")
    values = value if isinstance(value, list) else [value]
    require(values and all(isinstance(flag, str) and flag in TCP_FLAGS for flag in values)
            and len(set(values)) == len(values), "invalid TCP flags")
    return sum(TCP_FLAGS[flag] for flag in values)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def verify_nftables(text, source, destination):
    document = json.loads(text, object_pairs_hook=unique_object)
    require(isinstance(document, dict) and isinstance(document.get("nftables"), list), "invalid nft JSON")
    chains = 0
    counters = {}
    for item in document["nftables"]:
        require(isinstance(item, dict), "invalid nft object")
        chain = item.get("chain")
        if isinstance(chain, dict) and chain.get("family") == "inet" and chain.get("table") == TABLE:
            require(chain.get("name") == "output" and chain.get("type") == "filter"
                    and chain.get("hook") == "output" and chain.get("prio") == 10
                    and chain.get("policy") == "accept", "unexpected downstream nft hook")
            chains += 1
        rule = item.get("rule")
        if not isinstance(rule, dict) or rule.get("family") != "inet" or rule.get("table") != TABLE:
            continue
        require(rule.get("chain") == "output", "unexpected downstream nft chain")
        identifier = str(rule.get("comment", ""))
        require(identifier.startswith(PREFIX), "downstream nft rule has wrong identity")
        identifier = identifier[len(PREFIX):]
        require(identifier in RULE_IDS and identifier not in counters, "ambiguous downstream nft rule identity")
        protocol = "udp" if identifier == "udp" else "tcp"
        expressions = rule.get("expr")
        require(isinstance(expressions, list) and len(expressions) >= 5
                and expressions[-1] == {"drop": None} and set(expressions[-2]) == {"counter"},
                "downstream nft rule lacks counter and terminal DROP")
        expected = {("ip", "saddr"): source, ("ip", "daddr"): destination,
                    (protocol, "dport"): 18082 if protocol == "udp" else 18081}
        if identifier == "syn":
            expected[("tcp", "flags")] = (23, 2)
        observed = {}
        for expression in expressions[:-2]:
            require(isinstance(expression, dict) and set(expression) == {"match"}, "unexpected nft statement")
            match = expression["match"]
            require(isinstance(match, dict) and set(match) == {"op", "left", "right"}
                    and match["op"] == "==", "unexpected nft comparison")
            left, value = match["left"], match["right"]
            if isinstance(left, dict) and set(left) == {"&"}:
                parts = left["&"]
                require(isinstance(parts, list) and len(parts) == 2
                        and parts[0] == {"payload": {"protocol": "tcp", "field": "flags"}}, "unexpected nft flag mask")
                key, value = ("tcp", "flags"), (flags(parts[1]), flags(value))
            else:
                require(isinstance(left, dict) and set(left) == {"payload"}
                        and isinstance(left["payload"], dict) and set(left["payload"]) == {"protocol", "field"},
                        "unexpected nft selector")
                payload = left["payload"]
                key = (payload["protocol"], payload["field"])
                if key in (("ip", "saddr"), ("ip", "daddr")):
                    value = host_address(value)
                elif key == (protocol, "dport"):
                    require(type(value) is int, "nft port is not numeric")
            require(key not in observed, "duplicate nft selector")
            observed[key] = value
        require(observed == expected, "wrong downstream nft endpoint, protocol, port or SYN mask")
        counters[identifier] = counter(expressions[-2]["counter"])
    require(chains == 1, "missing or ambiguous downstream nft hook")
    return finish(counters)


def main(arguments, stream):
    require(len(arguments) == 3 and arguments[0] in ("iptables", "nftables"),
            "usage: downstream-counters.py {iptables|nftables} SOURCE_IPV4 DESTINATION_IPV4")
    backend, source, destination = arguments
    source, destination = host_address(source), host_address(destination)
    data = stream.read(MAX_INPUT_BYTES + 1)
    require(len(data) <= MAX_INPUT_BYTES, "downstream kernel output exceeds its fixed bound")
    text = data.decode("utf-8", errors="strict")
    verifier = verify_iptables if backend == "iptables" else verify_nftables
    return verifier(text, source, destination)


if __name__ == "__main__":
    try:
        print(json.dumps(main(sys.argv[1:], sys.stdin.buffer), sort_keys=True))
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        print("downstream DROP evidence failed: %s" % error, file=sys.stderr)
        raise SystemExit(1)
