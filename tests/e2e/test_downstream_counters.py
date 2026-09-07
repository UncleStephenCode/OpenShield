#!/usr/bin/env python3
"""Strict downstream kernel-evidence checks; no network or firewall access."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "downstream_counters", Path(__file__).with_name("downstream-counters.py")
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
SOURCE = "172.19.0.2"
DESTINATION = "172.19.0.3"


def iptables_rules(syn=1, tcp=0, udp=1):
    lines = ["*filter", ":OUTPUT ACCEPT [1:60]",
             ":%s - [0:0]" % MODULE.CHAIN,
             "[9:540] -A OUTPUT -j OPENSHIELD_OUT",
             "[2:120] -A OUTPUT -j %s" % MODULE.CHAIN]
    for identifier, packets in (("syn", syn), ("tcp", tcp), ("udp", udp)):
        protocol = "udp" if identifier == "udp" else "tcp"
        line = ("[%d:%d] -A %s -s %s/32 -d %s/32 -p %s -m %s --dport %d"
                % (packets, packets * 60, MODULE.CHAIN, SOURCE, DESTINATION,
                   protocol, protocol, 18082 if protocol == "udp" else 18081))
        if identifier == "syn":
            line += " --tcp-flags FIN,SYN,RST,ACK SYN"
        line += ' -m comment --comment "%s%s" -j DROP' % (MODULE.PREFIX, identifier)
        lines.append(line)
    return "\n".join(lines + ["COMMIT", ""])


def match(protocol, field, value):
    return {"match": {"op": "==", "left": {"payload": {
        "protocol": protocol, "field": field}}, "right": value}}


def nft_rules(syn=1, tcp=0, udp=1):
    entries = [{"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
               {"chain": {"family": "inet", "table": MODULE.TABLE, "name": "output",
                          "handle": 1, "type": "filter", "hook": "output",
                          "prio": 10, "policy": "accept"}}]
    for index, (identifier, packets) in enumerate((("syn", syn), ("tcp", tcp), ("udp", udp))):
        protocol = "udp" if identifier == "udp" else "tcp"
        expressions = [match("ip", "saddr", SOURCE), match("ip", "daddr", DESTINATION),
                       match(protocol, "dport", 18082 if protocol == "udp" else 18081)]
        if identifier == "syn":
            expressions.append({"match": {"op": "==", "left": {"&": [
                {"payload": {"protocol": "tcp", "field": "flags"}},
                ["fin", "syn", "rst", "ack"]]}, "right": "syn"}})
        expressions.extend([{"counter": {"packets": packets, "bytes": packets * 60}}, {"drop": None}])
        entries.append({"rule": {"family": "inet", "table": MODULE.TABLE, "chain": "output",
                                 "handle": index + 2, "comment": MODULE.PREFIX + identifier,
                                 "expr": expressions}})
    return {"nftables": entries}


class IptablesEvidenceTests(unittest.TestCase):
    def verify(self, text):
        return MODULE.verify_iptables(text, SOURCE, DESTINATION)

    def test_exact_positive_syn_and_udp(self):
        self.assertEqual(self.verify(iptables_rules(syn=3, tcp=0, udp=2)),
                         {"tcp_syn_packets": 3, "udp_packets": 2})

    def test_generic_tcp_counter_cannot_replace_syn(self):
        with self.assertRaisesRegex(ValueError, "SYN DROP received no packets"):
            self.verify(iptables_rules(syn=0, tcp=50))

    def test_udp_must_reach_drop(self):
        with self.assertRaisesRegex(ValueError, "UDP DROP received no packets"):
            self.verify(iptables_rules(udp=0))

    def test_missing_duplicate_and_reordered_rules_fail(self):
        original = iptables_rules().splitlines()
        mutations = [original[:5] + original[6:], original[:6] + [original[5]] + original[6:],
                     original[:5] + [original[6], original[5]] + original[7:]]
        for lines in mutations:
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                self.verify("\n".join(lines))

    def test_wrong_endpoint_port_protocol_or_flags_fail(self):
        original = iptables_rules()
        for old, new in ((SOURCE + "/32", "172.19.0.4/32"),
                         (SOURCE + "/32", "172.19.0.0/24"),
                         (DESTINATION + "/32", "172.19.0.5/32"),
                         ("--dport 18081", "--dport 18080"),
                         ("-p tcp", "-p udp"),
                         ("FIN,SYN,RST,ACK SYN", "SYN SYN"),
                         ("FIN,SYN,RST,ACK SYN", "FIN,SYN,RST,ACK ACK")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.verify(original.replace(old, new, 1))

    def test_nonterminal_or_wrong_verdict_fails(self):
        for replacement in ("-j ACCEPT", "-j OPENSHIELD_APP_TCP", "-g DROP", "-j DROP --log-prefix test"):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                self.verify(iptables_rules().replace("-j DROP", replacement, 1))

    def test_missing_counter_wrong_identity_and_extra_selector_fail(self):
        for old, new in (("[1:60] -A " + MODULE.CHAIN, "-A " + MODULE.CHAIN),
                         (MODULE.PREFIX + "syn", MODULE.PREFIX + "unknown"),
                         ("--dport 18081", "--dport 18081 --sport 50000"),
                         ("--dport 18081", "--dport 18081 --dport 18081"),
                         ("-m tcp", "-m tcp -m tcp")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.verify(iptables_rules().replace(old, new, 1))

    def test_hook_chain_and_committed_table_are_required(self):
        original = iptables_rules()
        for old, new in (("[2:120] -A OUTPUT -j " + MODULE.CHAIN, ""),
                         ("-A OUTPUT -j " + MODULE.CHAIN, "-A OUTPUT -p tcp -j " + MODULE.CHAIN),
                         (":" + MODULE.CHAIN + " - [0:0]", ""),
                         (":" + MODULE.CHAIN + " - [0:0]", ":" + MODULE.CHAIN + " ACCEPT [0:0]"),
                         ("COMMIT", ""), ("*filter", "*nat")):
            with self.subTest(new=new), self.assertRaises(ValueError):
                self.verify(original.replace(old, new, 1))

    def test_duplicate_hook_chain_and_table_fail(self):
        original = iptables_rules()
        for line in ("[2:120] -A OUTPUT -j " + MODULE.CHAIN, ":" + MODULE.CHAIN + " - [0:0]"):
            with self.subTest(line=line), self.assertRaises(ValueError):
                self.verify(original.replace(line, line + "\n" + line))
        with self.assertRaises(ValueError):
            self.verify(original + original)

    def test_counter_overflow_fails(self):
        with self.assertRaises(ValueError):
            self.verify(iptables_rules(syn=2 ** 64))


class NftEvidenceTests(unittest.TestCase):
    def verify(self, document):
        return MODULE.verify_nftables(json.dumps(document), SOURCE, DESTINATION)

    def test_exact_positive_syn_and_udp(self):
        self.assertEqual(self.verify(nft_rules(syn=3, tcp=0, udp=2)),
                         {"tcp_syn_packets": 3, "udp_packets": 2})

    def test_generic_tcp_counter_cannot_replace_syn(self):
        with self.assertRaisesRegex(ValueError, "SYN DROP received no packets"):
            self.verify(nft_rules(syn=0, tcp=50))

    def test_udp_must_reach_drop(self):
        with self.assertRaisesRegex(ValueError, "UDP DROP received no packets"):
            self.verify(nft_rules(udp=0))

    def test_literal_prefix_and_flag_encodings(self):
        for mask, value in ((23, 2), (["fin", "syn", "rst", "ack"], "syn"),
                            ({"|": ["fin", "syn", "rst", "ack"]}, "syn"),
                            ({"set": ["fin", "syn", "rst", "ack"]}, {"set": ["syn"]})):
            document = nft_rules()
            rule = document["nftables"][2]["rule"]
            rule["expr"][0]["match"]["right"] = {"prefix": {"addr": SOURCE, "len": 32}}
            rule["expr"][3]["match"]["left"]["&"][1] = mask
            rule["expr"][3]["match"]["right"] = value
            with self.subTest(mask=mask):
                self.verify(document)

    def test_missing_duplicate_and_reordered_rules_fail(self):
        original = nft_rules()["nftables"]
        for entries in (original[:2] + original[3:], original[:3] + [original[2]] + original[3:],
                        original[:2] + [original[3], original[2]] + original[4:]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                self.verify({"nftables": entries})

    def test_exact_endpoint_protocol_and_port_required(self):
        replacements = [(0, match("ip", "saddr", "172.19.0.4")),
                        (0, match("ip", "saddr", {"prefix": {"addr": "172.19.0.0", "len": 24}})),
                        (1, match("ip", "daddr", "172.19.0.5")),
                        (2, match("tcp", "dport", 18080)),
                        (2, match("tcp", "dport", "18081")),
                        (2, match("udp", "dport", 18081))]
        for index, expression in replacements:
            document = nft_rules()
            document["nftables"][2]["rule"]["expr"][index] = expression
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                self.verify(document)

    def test_wrong_syn_mask_or_synack_fails(self):
        for mask, value in ((2, 2), (23, 18), (23, 16), (256, 2), (True, 2),
                            ({"|": ["syn", "ack"]}, "syn"), ({"|": "syn"}, "syn"),
                            ({"|": ["fin", "syn", "rst", "ack", "syn"]}, "syn")):
            document = nft_rules()
            expression = document["nftables"][2]["rule"]["expr"][3]["match"]
            expression["left"]["&"][1], expression["right"] = mask, value
            with self.subTest(mask=mask, value=value), self.assertRaises(ValueError):
                self.verify(document)

    def test_drop_must_be_terminal_and_not_accept_or_jump(self):
        for verdict in ({"accept": None}, {"jump": {"target": "other"}}, {"drop": {}}):
            document = nft_rules()
            document["nftables"][2]["rule"]["expr"][-1] = verdict
            with self.subTest(verdict=verdict), self.assertRaises(ValueError):
                self.verify(document)
        document = nft_rules()
        document["nftables"][2]["rule"]["expr"].append({"counter": {"packets": 1, "bytes": 60}})
        with self.assertRaises(ValueError):
            self.verify(document)

    def test_counter_must_be_literal_unsigned_integers(self):
        for counter in (None, "named", {}, {"packets": 1}, {"packets": True, "bytes": 60},
                        {"packets": -1, "bytes": 60}, {"packets": 1, "bytes": -1},
                        {"packets": 2 ** 64, "bytes": 60}, {"packets": 1.5, "bytes": 60}):
            document = nft_rules()
            document["nftables"][2]["rule"]["expr"][-2] = {"counter": counter}
            with self.subTest(counter=counter), self.assertRaises(ValueError):
                self.verify(document)

    def test_selector_cannot_be_missing_duplicate_extra_or_inequality(self):
        for mutation in ("missing", "duplicate", "extra", "inequality"):
            document = nft_rules()
            expressions = document["nftables"][2]["rule"]["expr"]
            if mutation == "missing":
                del expressions[0]
            elif mutation == "duplicate":
                expressions.insert(1, copy.deepcopy(expressions[0]))
            elif mutation == "extra":
                expressions.insert(1, match("tcp", "sport", 50000))
            else:
                expressions[0]["match"]["op"] = "!="
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.verify(document)

    def test_exact_unique_hook_is_required(self):
        for key, value in (("name", "input"), ("hook", "input"), ("type", "nat"),
                           ("prio", 0), ("policy", "drop"), ("table", "other")):
            document = nft_rules()
            document["nftables"][1]["chain"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.verify(document)
        document = nft_rules()
        document["nftables"].append(copy.deepcopy(document["nftables"][1]))
        with self.assertRaises(ValueError):
            self.verify(document)

    def test_rule_identity_and_chain_are_required(self):
        for key, value in (("chain", "input"), ("comment", MODULE.PREFIX + "unknown"),
                           ("comment", MODULE.PREFIX + "udp"), ("table", "other")):
            document = nft_rules()
            document["nftables"][2]["rule"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.verify(document)

    def test_duplicate_json_keys_fail(self):
        text = json.dumps(nft_rules()).replace('"packets": 1', '"packets": 0, "packets": 1', 1)
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            MODULE.verify_nftables(text, SOURCE, DESTINATION)


class BoundedInputAndIntegrationTests(unittest.TestCase):
    def test_both_backends_use_bounded_byte_input(self):
        for backend, text in (("iptables", iptables_rules()), ("nftables", json.dumps(nft_rules()))):
            with self.subTest(backend=backend):
                self.assertEqual(MODULE.main([backend, SOURCE, DESTINATION], io.BytesIO(text.encode())),
                                 {"tcp_syn_packets": 1, "udp_packets": 1})

    def test_oversized_or_invalid_utf8_input_fails(self):
        for data in (b"x" * (MODULE.MAX_INPUT_BYTES + 1), b"\xff"):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                MODULE.main(["iptables", SOURCE, DESTINATION], io.BytesIO(data))

    def test_cli_arguments_are_exact_ipv4_hosts(self):
        for arguments in ([], ["other", SOURCE, DESTINATION], ["iptables", "::1", DESTINATION],
                          ["iptables", "172.19.0.0/24", DESTINATION]):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                MODULE.main(arguments, io.BytesIO(b""))

    def test_downstream_uses_same_learned_tcp_identity_and_both_evidence_checks(self):
        script = Path(__file__).with_name("server-learning-enforcing.sh").read_text(encoding="utf-8")
        region = script.split("begin_stage 'verify downstream firewall DROP precedence'", 1)[1]
        region = region.split("begin_stage 'verify application and connmark isolation'", 1)[0]
        self.assertEqual(region.count("run_tcp_client 5"), 3)
        self.assertNotIn("run_tcp_client 2", region)
        self.assertEqual(region.count("python3 /opt/downstream-counters.py"), 2)
        for identifier in MODULE.RULE_IDS:
            self.assertEqual(region.count(MODULE.PREFIX + identifier), 2)
        self.assertIn("--syn", region)
        self.assertIn("tcp flags '&' '(fin|syn|rst|ack)' '==' syn", region)
        self.assertEqual(script.count("src=$script_directory/downstream-counters.py,"
                                      "dst=/opt/downstream-counters.py,readonly"), 2)


if __name__ == "__main__":
    unittest.main()
