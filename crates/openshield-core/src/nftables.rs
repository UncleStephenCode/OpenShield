use ipnet::IpNet;
use thiserror::Error;

use crate::{
    ApplicationInterception, CoreError, Direction, MAX_FLOW_GENERATION, Mode, Rule, RuleAction,
    Snapshot, TransportProtocol,
};

pub const TABLE_NAME: &str = "openshield";
pub const LEARNED_TCP_V4_SET: &str = "learned_tcp_v4";
pub const LEARNED_TCP_V6_SET: &str = "learned_tcp_v6";
pub const LEARNED_UDP_V4_SET: &str = "learned_udp_v4";
pub const LEARNED_UDP_V6_SET: &str = "learned_udp_v6";
pub const LEARNED_ICMP_V4_SET: &str = "learned_icmp_v4";
pub const LEARNED_ICMP_V6_SET: &str = "learned_icmp_v6";
pub const COUNTER_ACCEPTED_IN: &str = "accepted_in";
pub const COUNTER_ACCEPTED_OUT: &str = "accepted_out";
pub const COUNTER_DROPPED_IN: &str = "dropped_in";
pub const COUNTER_DROPPED_OUT: &str = "dropped_out";
pub const COUNTER_LEARNED_OUT: &str = "learned_out";
pub const NFT_OWNERSHIP_COUNTER: &str = "openshield_owner_v1";
/// Fail-closed queue used only by Enforcing application decisions.
pub const APPLICATION_QUEUE_NUMBER: u16 = 1_337;
/// Overflow-bypassing observational queue used only by Learning.
pub const APPLICATION_LEARNING_QUEUE_NUMBER: u16 = 1_338;
/// Fail-closed, bounded deferral of replies during a non-TCP authorization.
/// Its consumer can only drop or repeat the current INPUT hook, never accept.
pub const APPLICATION_REPLY_QUEUE_NUMBER: u16 = 1_339;
const APPLICATION_MARK_GENERATION_MASK: u32 = MAX_FLOW_GENERATION;
const APPLICATION_MARK_DOMAIN_MASK: u32 = 0xc000_0000;
const APPLICATION_MARK_PAYLOAD_MASK: u32 = 0x3fff_ffff;
const APPLICATION_PENDING_DOMAIN: u32 = 0x8000_0000;
const APPLICATION_HANDOFF_DOMAIN: u32 = 0xc000_0000;
const APPLICATION_REJECT_DOMAIN: u32 = 0x4000_0000;
const APPLICATION_FLOW_DOMAIN: u32 = 0x4000_0000;
// OpenShield owns the low 31 connmark bits. Keep bit 31 available to an
// existing host firewall and mask it out of every generation comparison.
const APPLICATION_CONNMARK_MASK: u32 = 0x7fff_ffff;
const APPLICATION_CONNMARK_FOREIGN_MASK: u32 = 0x8000_0000;

const APPLICATION_REPLY_PROTOCOL_MATCHES: [&str; 4] = [
    "meta l4proto tcp",
    "meta l4proto udp",
    "meta nfproto ipv4 meta l4proto icmp",
    "meta nfproto ipv6 meta l4proto icmpv6",
];
const APPLICATION_NON_TCP_PROTOCOL_MATCHES: [&str; 3] = [
    "meta l4proto udp",
    "meta nfproto ipv4 meta l4proto icmp",
    "meta nfproto ipv6 meta l4proto icmpv6",
];

/// Adds the private pending domain while retaining the unreserved packet-mark bits.
#[must_use]
pub const fn application_pending_mark(packet_mark: u32) -> u32 {
    APPLICATION_PENDING_DOMAIN | (packet_mark & APPLICATION_MARK_PAYLOAD_MASK)
}

/// Adds the private post-NFQUEUE handoff domain while retaining unreserved bits.
#[must_use]
pub const fn application_handoff_mark(packet_mark: u32) -> u32 {
    APPLICATION_HANDOFF_DOMAIN | (packet_mark & APPLICATION_MARK_PAYLOAD_MASK)
}

/// Adds the private application-reject domain while retaining unreserved bits.
#[must_use]
pub const fn application_reject_mark(packet_mark: u32) -> u32 {
    APPLICATION_REJECT_DOMAIN | (packet_mark & APPLICATION_MARK_PAYLOAD_MASK)
}

/// Counts an INPUT retry while retaining the unreserved packet-mark bits.
///
/// The two reserved bits saturate after three retries. In INPUT they only
/// bound deferral; they never substitute for a current-generation conntrack
/// mark or an explicit network rule. OUTPUT strips these bits before making
/// any decision, as for all reserved marks.
#[must_use]
pub const fn application_reply_retry_mark(packet_mark: u32) -> u32 {
    let attempts = packet_mark >> 30;
    let next_attempt = if attempts < 3 { attempts + 1 } else { 3 };
    (next_attempt << 30) | (packet_mark & APPLICATION_MARK_PAYLOAD_MASK)
}

/// Conntrack mark that binds both directions of an authorized application flow.
#[must_use]
pub const fn application_flow_mark(flow_generation: u32) -> u32 {
    APPLICATION_FLOW_DOMAIN | (flow_generation & APPLICATION_MARK_GENERATION_MASK)
}

/// A complete, atomically loadable nftables policy.
///
/// The script is generated exclusively from validated typed values.  Callers
/// must pass it to `nft -f -` on standard input, never through a shell.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NftablesPolicy {
    script: String,
}

impl NftablesPolicy {
    #[must_use]
    pub fn render(&self) -> &str {
        &self.script
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.script
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.script.as_bytes()
    }

    #[must_use]
    pub fn into_string(self) -> String {
        self.script
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NftablesCompiler;

impl NftablesCompiler {
    /// Compiles a complete deterministic policy from a validated snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError`] when the snapshot violates a state invariant.
    pub fn compile(snapshot: &Snapshot) -> Result<NftablesPolicy, CompileError> {
        snapshot.validate()?;
        let interception = snapshot.application_interception();

        // `add` is idempotent and makes the following `delete` valid on both
        // first boot and reload. Recreating the dedicated table in one netlink
        // batch removes stale objects and resets runtime counters without any
        // externally visible interval lacking policy. This works on nftables
        // versions predating the newer `destroy` command.
        let mut script = String::from("add table inet openshield\n");
        script.push_str("delete table inet openshield\n");
        script.push_str("table inet openshield {\n");
        append_named_counters(&mut script);

        append_chain(&mut script, snapshot, Direction::Inbound, interception);
        append_application_mark_sanitization_chain(&mut script);
        append_chain(&mut script, snapshot, Direction::Outbound, interception);
        // Keep the base-chain topology constant in every mode so integrity
        // observation can enforce one exact structure. In BlockAll, the
        // earlier output chain drops every packet before this chain.
        append_application_authorization_chain(&mut script, snapshot, interception);
        append_forward_chain(&mut script, snapshot.mode);
        script.push_str("}\n");

        Ok(NftablesPolicy { script })
    }
}

fn append_forward_chain(script: &mut String, mode: Mode) {
    // BlockAll covers forwarded traffic as well as host traffic. Other modes
    // leave forwarding to the existing host firewall until OpenShield exposes
    // an explicit forwarding-rule API. An nft `accept` verdict remains subject
    // to later base chains on the same hook.
    script.push_str(
        "  chain forward {\n    type filter hook forward priority filter; policy drop;\n",
    );
    if mode == Mode::BlockAll {
        script.push_str("    counter drop\n");
    } else {
        script.push_str("    accept\n");
    }
    script.push_str("  }\n");
}

fn append_named_counters(script: &mut String) {
    for name in [
        NFT_OWNERSHIP_COUNTER,
        COUNTER_ACCEPTED_IN,
        COUNTER_ACCEPTED_OUT,
        COUNTER_DROPPED_IN,
        COUNTER_DROPPED_OUT,
        COUNTER_LEARNED_OUT,
    ] {
        script.push_str("  counter ");
        script.push_str(name);
        script.push_str(" {\n    packets 0 bytes 0\n  }\n");
    }
}

#[allow(clippy::too_many_lines)]
fn append_chain(
    script: &mut String,
    snapshot: &Snapshot,
    direction: Direction,
    interception: ApplicationInterception,
) {
    let chain_name = match direction {
        Direction::Inbound => "input",
        Direction::Outbound => "output",
    };
    script.push_str("  chain ");
    script.push_str(chain_name);
    script.push_str(" {\n    type filter hook ");
    script.push_str(chain_name);
    script.push_str(" priority filter; policy drop;\n");

    let (accepted_counter, dropped_counter) = match direction {
        Direction::Inbound => (COUNTER_ACCEPTED_IN, COUNTER_DROPPED_IN),
        Direction::Outbound => (COUNTER_ACCEPTED_OUT, COUNTER_DROPPED_OUT),
    };

    if snapshot.mode != Mode::BlockAll {
        if has_enabled_outbound_reject(snapshot) {
            append_generated_reject_reply_accept(
                script,
                direction,
                accepted_counter,
                application_reject_connmark(snapshot.flow_generation),
            );
        }

        // Learning is an explicit allow-all policy for locally originated
        // traffic. It must not turn conntrack's INVALID classification into
        // an outbound deny. Inbound INVALID packets remain denied.
        if direction == Direction::Inbound {
            append_dhcp_bootstrap_accepts(script, accepted_counter);
        }
        if direction == Direction::Inbound || snapshot.mode == Mode::Enforcing {
            script.push_str("    ct state invalid counter name ");
            script.push_str(dropped_counter);
            script.push_str(" drop\n");
        }
        if direction == Direction::Inbound {
            append_ipv6_host_control_plane_accepts(script, accepted_counter);
        }

        // Network deny rules run before the application fast path, so an old
        // authorized conntrack generation cannot bypass a newly enabled deny.
        if direction == Direction::Outbound {
            append_direct_rules(
                script,
                snapshot,
                direction,
                &[RuleAction::Drop, RuleAction::Reject],
                dropped_counter,
            );
        }

        // If the queue consumer is absent in Learning, queue bypass admits the
        // outbound packet without adding a generation mark. Replies to that
        // locally initiated conntrack flow must still work; NEW inbound flows
        // continue to the default-drop path.
        if direction == Direction::Inbound && snapshot.mode == Mode::Learning {
            // A locally initiated loopback flow traverses both OUTPUT and
            // INPUT in its ORIGINAL direction. Its output policy has already
            // checked explicit denies; do not block local proxies at INPUT.
            // A physical ingress interface can never match this exception.
            script.push_str("    iifname \"lo\" ct direction original counter name ");
            script.push_str(accepted_counter);
            script.push_str(" accept\n");
            script.push_str("    ct direction reply ct state established,related counter name ");
            script.push_str(accepted_counter);
            script.push_str(" accept\n");
        }

        if interception != ApplicationInterception::None {
            append_application_loopback_accept(
                script,
                snapshot,
                direction,
                accepted_counter,
                interception,
            );
            append_application_flow_accept(
                script,
                snapshot,
                direction,
                accepted_counter,
                interception,
            );
            if direction == Direction::Outbound
                && interception == ApplicationInterception::PerPacket
            {
                append_application_non_tcp_connmark_reset(script);
            }
        }

        // Replies to explicitly accepted inbound connections are not new
        // application-originated flows and retain their stateful allow path.
        if direction == Direction::Outbound {
            append_reverse_rules(script, snapshot, direction, accepted_counter);
        }

        if direction == Direction::Outbound && snapshot.mode == Mode::Enforcing {
            // An application deny whose network envelope overlaps a broad
            // network accept must reach userspace first. Only packets outside
            // every enabled application envelope reach direct network accepts.
            append_application_rule_queues(
                script,
                snapshot,
                &[RuleAction::Drop, RuleAction::Reject, RuleAction::Accept],
            );
            append_application_candidate_guard_drops(
                script,
                snapshot,
                dropped_counter,
                &[RuleAction::Drop, RuleAction::Reject, RuleAction::Accept],
            );
            append_direct_rules(
                script,
                snapshot,
                direction,
                &[RuleAction::Accept],
                accepted_counter,
            );
        } else if direction == Direction::Outbound && snapshot.mode == Mode::Learning {
            // Explicit application denies use the fail-closed enforcement
            // queue even in Learning. The generic observational queue below
            // therefore remains a pure immediate-accept path.
            append_application_rule_queues(
                script,
                snapshot,
                &[RuleAction::Drop, RuleAction::Reject],
            );
            append_application_candidate_guard_drops(
                script,
                snapshot,
                dropped_counter,
                &[RuleAction::Drop, RuleAction::Reject],
            );
            // Network accepts must not hide their applications from Learning.
            // The observational queue and the final allow-all verdict below
            // admit this traffic after the explicit denies have been checked.
        } else {
            append_direct_rules(
                script,
                snapshot,
                direction,
                &[RuleAction::Accept],
                accepted_counter,
            );
        }

        // Outside Learning, replies are accepted only for an explicit Accept
        // in the opposite direction. A deny rule can never create a reverse
        // allow path.
        if direction == Direction::Inbound {
            append_reverse_rules(script, snapshot, direction, accepted_counter);
            if snapshot.mode == Mode::Enforcing
                && interception == ApplicationInterception::PerPacket
            {
                append_application_reply_queues(script, snapshot);
            }
        }

        if interception != ApplicationInterception::None
            && direction == Direction::Outbound
            && snapshot.mode == Mode::Learning
        {
            append_learning_queue(script);
            // NOTRACK, reply-direction, and other ct-less local traffic does
            // not match the observational queue. Learning is still an
            // explicit outbound allow-all mode, so accept it here and in the
            // later base chain instead of reaching either terminal drop.
            script.push_str("    counter name ");
            script.push_str(accepted_counter);
            script.push_str(" accept\n");
        }
    }

    script.push_str("    counter name ");
    script.push_str(dropped_counter);
    script.push_str(" drop\n");
    script.push_str("  }\n");
}

fn append_ipv6_host_control_plane_accepts(script: &mut String, accepted_counter: &str) {
    // RFC 4890 host policy: admit only ICMPv6 errors required for PMTU and
    // reachability, and the exact local-link control messages required by an
    // IPv6 host. Router-only RS/Redirect and inbound MLD reports remain denied.
    for selector in [
        "ct state related meta nfproto ipv6 ip6 saddr != :: ip6 saddr != ff00::/8 meta l4proto icmpv6 icmpv6 type 1",
        "ct state related meta nfproto ipv6 ip6 saddr != :: ip6 saddr != ff00::/8 meta l4proto icmpv6 icmpv6 type 2 icmpv6 code 0",
        "ct state related meta nfproto ipv6 ip6 saddr != :: ip6 saddr != ff00::/8 meta l4proto icmpv6 icmpv6 type 3 icmpv6 code 0",
        "ct state related meta nfproto ipv6 ip6 saddr != :: ip6 saddr != ff00::/8 meta l4proto icmpv6 icmpv6 type 4 icmpv6 code 1",
        "ct state related meta nfproto ipv6 ip6 saddr != :: ip6 saddr != ff00::/8 meta l4proto icmpv6 icmpv6 type 4 icmpv6 code 2",
        "meta nfproto ipv6 ip6 saddr fe80::/10 ip6 hoplimit 255 meta l4proto icmpv6 icmpv6 type 134 icmpv6 code 0",
        "meta nfproto ipv6 ip6 saddr != ff00::/8 ip6 hoplimit 255 meta l4proto icmpv6 icmpv6 type 135 icmpv6 code 0",
        "meta nfproto ipv6 ip6 saddr != :: ip6 saddr != ff00::/8 ip6 hoplimit 255 meta l4proto icmpv6 icmpv6 type 136 icmpv6 code 0",
        "meta nfproto ipv6 ip6 saddr fe80::/10 ip6 daddr ff02::/16 ip6 hoplimit 1 meta l4proto icmpv6 icmpv6 type 130 icmpv6 code 0",
    ] {
        script.push_str("    ");
        script.push_str(selector);
        script.push_str(" counter name ");
        script.push_str(accepted_counter);
        script.push_str(" accept\n");
    }
}

fn append_dhcp_bootstrap_accepts(script: &mut String, accepted_counter: &str) {
    // Bootstrap replies may not share the multicast/broadcast request tuple
    // and can therefore be classified NEW or INVALID. Keep these exceptions
    // before the generic INVALID drop and constrain them to exact client
    // reply ports plus the protocol-mandated source/destination scope.
    for selector in [
        "meta nfproto ipv6 ip6 saddr fe80::/10 meta l4proto udp udp sport 547 udp dport 546",
        "meta nfproto ipv4 ip daddr 255.255.255.255 meta l4proto udp udp sport 67 udp dport 68",
    ] {
        script.push_str("    ");
        script.push_str(selector);
        script.push_str(" counter name ");
        script.push_str(accepted_counter);
        script.push_str(" accept\n");
    }
}

fn append_generated_reject_reply_accept(
    script: &mut String,
    direction: Direction,
    accepted_counter: &str,
    reject_connmark: u32,
) {
    for selector in [
        "ct state related ct direction reply meta l4proto tcp tcp flags & rst == rst",
        "ct state related ct direction reply meta nfproto ipv4 meta l4proto icmp icmp type destination-unreachable icmp code port-unreachable",
        "ct state related ct direction reply meta nfproto ipv6 meta l4proto icmpv6 icmpv6 type destination-unreachable icmpv6 code port-unreachable",
    ] {
        script.push_str("    ");
        script.push_str(selector);
        script.push_str(" ct mark & 0x");
        append_hex_u32(script, APPLICATION_CONNMARK_MASK);
        script.push_str(" == 0x");
        append_hex_u32(script, reject_connmark);
        if direction == Direction::Outbound {
            script.push(' ');
            append_packet_mark_domain_set(script, APPLICATION_HANDOFF_DOMAIN);
        }
        script.push_str(" counter name ");
        script.push_str(accepted_counter);
        script.push_str(" accept\n");
    }
}

const fn application_reject_connmark(flow_generation: u32) -> u32 {
    flow_generation & APPLICATION_MARK_GENERATION_MASK
}

fn has_enabled_outbound_reject(snapshot: &Snapshot) -> bool {
    snapshot.rules.iter().any(|rule| {
        rule.spec.enabled
            && rule.spec.direction == Direction::Outbound
            && rule.spec.action == RuleAction::Reject
    })
}

fn append_direct_rules(
    script: &mut String,
    snapshot: &Snapshot,
    direction: Direction,
    actions: &[RuleAction],
    counter: &str,
) {
    let mut rules: Vec<&Rule> = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.spec.enabled
                && rule.spec.direction == direction
                && rule.spec.application.is_none()
                && actions.contains(&rule.spec.action)
        })
        .collect();
    rules.sort_unstable_by_key(|rule| (rule_action_priority(rule.spec.action), rule.id));
    for rule in rules {
        append_rule_verdict(
            script,
            rule,
            direction,
            false,
            counter,
            rule.spec.action,
            snapshot.mode != Mode::Learning,
            application_reject_connmark(snapshot.flow_generation),
        );
    }
}

fn append_reverse_rules(
    script: &mut String,
    snapshot: &Snapshot,
    direction: Direction,
    accepted_counter: &str,
) {
    let mut rules: Vec<&Rule> = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.spec.enabled
                && rule.spec.direction != direction
                && rule.spec.application.is_none()
                && rule.spec.action == RuleAction::Accept
        })
        .collect();
    rules.sort_unstable_by_key(|rule| rule.id);
    for rule in rules {
        append_rule_verdict(
            script,
            rule,
            direction,
            true,
            accepted_counter,
            RuleAction::Accept,
            snapshot.mode != Mode::Learning,
            application_reject_connmark(snapshot.flow_generation),
        );
    }
}

const fn rule_action_priority(action: RuleAction) -> u8 {
    match action {
        RuleAction::Drop => 0,
        RuleAction::Reject => 1,
        RuleAction::Accept => 2,
    }
}

fn append_application_flow_accept(
    script: &mut String,
    snapshot: &Snapshot,
    direction: Direction,
    accepted_counter: &str,
    interception: ApplicationInterception,
) {
    // A UDP/ICMP conntrack tuple can outlive its owning socket and then be
    // reused by another process. Outbound caching is consequently TCP-only;
    // inbound replies may use the generation mark for the explicit protocol
    // allowlist because every new non-TCP original packet clears and refreshes
    // that mark after successful attribution.
    let protocol_matches: &[&str] = match (direction, interception) {
        (_, ApplicationInterception::None) => return,
        (Direction::Inbound, ApplicationInterception::PerPacket) => {
            &APPLICATION_REPLY_PROTOCOL_MATCHES
        }
        (Direction::Inbound, ApplicationInterception::TcpInitial)
        | (
            Direction::Outbound,
            ApplicationInterception::TcpInitial | ApplicationInterception::PerPacket,
        ) => &APPLICATION_REPLY_PROTOCOL_MATCHES[..1],
    };
    for protocol_match in protocol_matches {
        script.push_str("    ct direction ");
        match direction {
            Direction::Inbound => script.push_str("reply ct state established "),
            Direction::Outbound => script.push_str("original ct state established "),
        }
        script.push_str(protocol_match);
        script.push_str(" ct mark & 0x");
        append_hex_u32(script, APPLICATION_CONNMARK_MASK);
        script.push_str(" == 0x");
        append_hex_u32(script, application_flow_mark(snapshot.flow_generation));
        if direction == Direction::Outbound {
            script.push(' ');
            append_packet_mark_domain_set(script, APPLICATION_HANDOFF_DOMAIN);
        }
        script.push_str(" counter name ");
        script.push_str(accepted_counter);
        script.push_str(" accept\n");
    }
}

fn append_application_loopback_accept(
    script: &mut String,
    snapshot: &Snapshot,
    direction: Direction,
    accepted_counter: &str,
    interception: ApplicationInterception,
) {
    if snapshot.mode != Mode::Enforcing {
        return;
    }
    let protocols: &[&str] = match interception {
        ApplicationInterception::None => return,
        ApplicationInterception::TcpInitial => &APPLICATION_REPLY_PROTOCOL_MATCHES[..1],
        ApplicationInterception::PerPacket => &APPLICATION_REPLY_PROTOCOL_MATCHES,
    };
    for protocol in protocols {
        // The local ORIGINAL packet has already passed OUTPUT attribution and
        // output_authorize before it reaches INPUT. Its peer's local REPLY
        // traverses OUTPUT as well; neither half needs a second inbound rule.
        // Only the current authenticated application generation authorizes
        // this local delivery, never a user-supplied packet mark or RELATED.
        script.push_str(match direction {
            Direction::Inbound => {
                "    iifname \"lo\" ct direction original ct state new,established "
            }
            Direction::Outbound => "    oifname \"lo\" ct direction reply ct state established ",
        });
        script.push_str(protocol);
        script.push_str(" ct mark & 0x");
        append_hex_u32(script, APPLICATION_CONNMARK_MASK);
        script.push_str(" == 0x");
        append_hex_u32(script, application_flow_mark(snapshot.flow_generation));
        if direction == Direction::Outbound {
            script.push(' ');
            append_packet_mark_domain_set(script, APPLICATION_HANDOFF_DOMAIN);
        }
        script.push_str(" counter name ");
        script.push_str(accepted_counter);
        script.push_str(" accept\n");
    }
}

fn append_application_non_tcp_connmark_reset(script: &mut String) {
    for protocol_match in APPLICATION_NON_TCP_PROTOCOL_MATCHES {
        script.push_str("    ct direction original ");
        script.push_str(protocol_match);
        script.push_str(" ct mark set ct mark & 0x");
        append_hex_u32(script, APPLICATION_CONNMARK_FOREIGN_MASK);
        script.push('\n');
    }
}

fn append_application_reply_queues(script: &mut String, snapshot: &Snapshot) {
    for rule in application_reply_candidates(snapshot) {
        script.push_str("    ");
        append_rule_selectors(script, &rule, Direction::Inbound, true);
        match rule.spec.protocol {
            TransportProtocol::Icmp => script.push_str("icmp type echo-reply icmp code 0 "),
            TransportProtocol::IcmpV6 => {
                script.push_str("icmpv6 type echo-reply icmpv6 code 0 ");
            }
            _ => {}
        }
        script.push_str("meta mark & 0xc0000000 != 0xc0000000 queue to ");
        script.push_str(&APPLICATION_REPLY_QUEUE_NUMBER.to_string());
        script.push('\n');
    }
}

/// Network envelopes only: these rules never authorize an inbound packet.
/// A reverse interface constraint is intentionally absent, like the existing
/// authenticated reply fast path, so asymmetric routing can still retry.
pub(crate) fn application_reply_candidates(snapshot: &Snapshot) -> Vec<Rule> {
    let mut rules: Vec<&Rule> = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.spec.enabled
                && rule.spec.direction == Direction::Outbound
                && rule.spec.application.is_some()
                && rule.spec.action == RuleAction::Accept
        })
        .collect();
    rules.sort_unstable_by_key(|rule| rule.id);
    let mut candidates = Vec::new();
    for rule in rules {
        for protocol in [
            TransportProtocol::Udp,
            TransportProtocol::Icmp,
            TransportProtocol::IcmpV6,
        ] {
            if !matches!(rule.spec.protocol, TransportProtocol::Any)
                && rule.spec.protocol != protocol
            {
                continue;
            }
            if matches!(
                (protocol, rule.spec.peer_network),
                (TransportProtocol::Icmp, Some(IpNet::V6(_)))
                    | (TransportProtocol::IcmpV6, Some(IpNet::V4(_)))
            ) {
                continue;
            }
            let mut candidate = rule.clone();
            candidate.spec.protocol = protocol;
            candidate.spec.interface = None;
            candidates.push(candidate);
        }
    }
    candidates
}

fn append_learning_queue(script: &mut String) {
    for selector in [
        "meta l4proto tcp ct state new tcp flags & (syn | ack) == syn",
        // Retry attribution for active connections opened before Learning or
        // whose initial SYN raced process/socket discovery. Sampling is bounded
        // and never changes their authorization or conntrack generation.
        "meta l4proto tcp ct state established tcp flags & (fin | rst) == 0 limit rate 64/second burst 32 packets",
        "meta l4proto != tcp",
    ] {
        script.push_str("    ct direction original ");
        script.push_str(selector);
        // Count packets offered to Learning observation, independently of
        // whether userspace attributes/persists them or the queue bypasses.
        script.push_str(" counter name ");
        script.push_str(COUNTER_LEARNED_OUT);
        script.push_str(" queue num ");
        script.push_str(&APPLICATION_LEARNING_QUEUE_NUMBER.to_string());
        // `bypass` is the portable nftables 1.0.x rule-language spelling.
        script.push_str(" bypass\n");
    }
}

fn append_application_rule_queues(
    script: &mut String,
    snapshot: &Snapshot,
    actions: &[RuleAction],
) {
    let mut rules: Vec<&Rule> = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.spec.enabled
                && rule.spec.direction == Direction::Outbound
                && rule.spec.application.is_some()
                && actions.contains(&rule.spec.action)
        })
        .collect();
    rules.sort_unstable_by_key(|rule| (rule_action_priority(rule.spec.action), rule.id));
    for rule in rules {
        script.push_str("    ct direction original ");
        append_rule_selectors(script, rule, Direction::Outbound, false);
        append_packet_mark_domain_set(script, APPLICATION_PENDING_DOMAIN);
        script.push_str(" queue num ");
        script.push_str(&APPLICATION_QUEUE_NUMBER.to_string());
        // Enforcing deliberately has no bypass: an absent/overloaded consumer
        // cannot turn an application constraint into an allow.
        script.push('\n');
    }
}

fn append_application_candidate_guard_drops(
    script: &mut String,
    snapshot: &Snapshot,
    dropped_counter: &str,
    actions: &[RuleAction],
) {
    let mut rules: Vec<&Rule> = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.spec.enabled
                && rule.spec.direction == Direction::Outbound
                && rule.spec.application.is_some()
                && actions.contains(&rule.spec.action)
        })
        .collect();
    rules.sort_unstable_by_key(|rule| (rule_action_priority(rule.spec.action), rule.id));
    for rule in rules {
        // A successful nft queue verdict terminates this base-chain traversal
        // and resumes at the later authorization chain. Repeating the network
        // envelope here therefore catches only candidates which could not be
        // queued (notably UNTRACKED traffic) before a broad network accept.
        script.push_str("    ");
        append_rule_selectors(script, rule, Direction::Outbound, false);
        script.push_str("counter name ");
        script.push_str(dropped_counter);
        script.push_str(" drop\n");

        if rule.spec.peer_network.is_none() && rule.spec.port.is_none() {
            continue;
        }
        // The ordinary selector above is evaluated after local DNAT. Also
        // guard the conntrack original destination/port, while retaining the
        // final output-interface constraint after rerouting.
        script.push_str("    ");
        if let Some(interface) = &rule.spec.interface {
            script.push_str("oifname \"");
            script.push_str(interface.as_str());
            script.push_str("\" ");
        }
        match rule.spec.protocol {
            TransportProtocol::Any => {}
            TransportProtocol::Tcp => script.push_str("meta l4proto tcp "),
            TransportProtocol::Udp => script.push_str("meta l4proto udp "),
            TransportProtocol::Icmp => {
                script.push_str("meta nfproto ipv4 meta l4proto icmp ");
            }
            TransportProtocol::IcmpV6 => {
                script.push_str("meta nfproto ipv6 meta l4proto icmpv6 ");
            }
        }
        if let Some(network) = rule.spec.peer_network {
            match network {
                IpNet::V4(network) => {
                    script.push_str("ct original ip daddr ");
                    script.push_str(&network.to_string());
                }
                IpNet::V6(network) => {
                    script.push_str("ct original ip6 daddr ");
                    script.push_str(&network.to_string());
                }
            }
            script.push(' ');
        }
        if let Some(port) = rule.spec.port {
            script.push_str("ct original proto-dst ");
            script.push_str(&port.start().to_string());
            if port.end() != port.start() {
                script.push('-');
                script.push_str(&port.end().to_string());
            }
            script.push(' ');
        }
        script.push_str("counter name ");
        script.push_str(dropped_counter);
        script.push_str(" drop\n");
    }
}

fn append_application_mark_sanitization_chain(script: &mut String) {
    // CAP_NET_RAW can use SO_MARK on modern Linux. Strip the two reserved bits
    // in an earlier hook before any allow decision. The remaining 30 bits are
    // retained for policy routing and QoS.
    script.push_str(
        "  chain output_sanitize {\n    type filter hook output priority -1; policy accept;\n",
    );
    script.push_str("    meta mark & 0x");
    append_hex_u32(script, APPLICATION_MARK_DOMAIN_MASK);
    script.push_str(" != 0x00000000 meta mark set meta mark & 0x");
    append_hex_u32(script, APPLICATION_MARK_PAYLOAD_MASK);
    script.push_str("\n  }\n");
}

fn append_packet_mark_domain_set(script: &mut String, domain: u32) {
    script.push_str("meta mark set (meta mark & 0x");
    append_hex_u32(script, APPLICATION_MARK_PAYLOAD_MASK);
    script.push_str(") | 0x");
    append_hex_u32(script, domain);
}

fn append_hex_u32(script: &mut String, value: u32) {
    use std::fmt::Write as _;

    // Formatting into String is infallible; keep generation allocation-free.
    let _infallible = write!(script, "{value:08x}");
}

fn append_application_authorization_chain(
    script: &mut String,
    snapshot: &Snapshot,
    interception: ApplicationInterception,
) {
    let flow = application_flow_mark(snapshot.flow_generation);
    let reject_connmark = application_reject_connmark(snapshot.flow_generation);
    script.push_str(
        "  chain output_authorize {\n    type filter hook output priority 1; policy drop;\n",
    );
    let authorization_protocols: &[&str] = match interception {
        ApplicationInterception::None => &[],
        ApplicationInterception::TcpInitial => &APPLICATION_REPLY_PROTOCOL_MATCHES[..1],
        ApplicationInterception::PerPacket => &APPLICATION_REPLY_PROTOCOL_MATCHES,
    };
    if interception != ApplicationInterception::None {
        script.push_str("    meta l4proto tcp meta mark & 0x");
        append_hex_u32(script, APPLICATION_MARK_DOMAIN_MASK);
        script.push_str(" == 0x");
        append_hex_u32(script, APPLICATION_REJECT_DOMAIN);
        script.push_str(" ct mark set (ct mark & 0x");
        append_hex_u32(script, APPLICATION_CONNMARK_FOREIGN_MASK);
        script.push_str(") | 0x");
        append_hex_u32(script, reject_connmark);
        script.push_str(" counter name ");
        script.push_str(COUNTER_DROPPED_OUT);
        script.push_str(" reject with tcp reset\n");

        script.push_str("    meta mark & 0x");
        append_hex_u32(script, APPLICATION_MARK_DOMAIN_MASK);
        script.push_str(" == 0x");
        append_hex_u32(script, APPLICATION_REJECT_DOMAIN);
        script.push_str(" ct mark set (ct mark & 0x");
        append_hex_u32(script, APPLICATION_CONNMARK_FOREIGN_MASK);
        script.push_str(") | 0x");
        append_hex_u32(script, reject_connmark);
        script.push_str(" counter name ");
        script.push_str(COUNTER_DROPPED_OUT);
        script.push_str(" reject\n");

        // All attributable protocols receive the current generation so a
        // reply can be recognized. Only TCP uses that mark as an outbound
        // cache; UDP/ICMP clear it before every original packet and are queued
        // again. Restricting this branch to the parser's explicit allowlist
        // makes an accidental NF_ACCEPT for another protocol fail closed.
        for protocol_match in authorization_protocols {
            script.push_str("    ");
            script.push_str(protocol_match);
            script.push_str(" meta mark & 0x");
            append_hex_u32(script, APPLICATION_MARK_DOMAIN_MASK);
            script.push_str(" == 0x");
            append_hex_u32(script, APPLICATION_PENDING_DOMAIN);
            script.push_str(" ct mark set (ct mark & 0x");
            append_hex_u32(script, APPLICATION_CONNMARK_FOREIGN_MASK);
            script.push_str(") | 0x");
            append_hex_u32(script, flow);
            script.push_str(" meta mark set meta mark & 0x");
            append_hex_u32(script, APPLICATION_MARK_PAYLOAD_MASK);
            if snapshot.mode == Mode::Learning {
                script.push_str(" counter name ");
                script.push_str(COUNTER_LEARNED_OUT);
            }
            script.push_str(" counter name ");
            script.push_str(COUNTER_ACCEPTED_OUT);
            script.push_str(" accept\n");
        }
    }
    if snapshot.mode != Mode::BlockAll {
        script.push_str("    meta mark & 0x");
        append_hex_u32(script, APPLICATION_MARK_DOMAIN_MASK);
        script.push_str(" == 0x");
        append_hex_u32(script, APPLICATION_HANDOFF_DOMAIN);
        script.push_str(" meta mark set meta mark & 0x");
        append_hex_u32(script, APPLICATION_MARK_PAYLOAD_MASK);
        script.push_str(" accept\n");
    }
    if snapshot.mode == Mode::Learning {
        // Queue 1338 is observational and carries no private packet mark.
        // Its NF_ACCEPT, kernel overflow fail-open, and packets accepted by
        // the earlier Learning catch-all all converge here. An nft accept
        // remains subject to later third-party base chains on this hook.
        script.push_str("    counter name ");
        script.push_str(COUNTER_ACCEPTED_OUT);
        script.push_str(" accept\n");
    }
    script.push_str("    counter name ");
    script.push_str(COUNTER_DROPPED_OUT);
    script.push_str(" drop\n");
    script.push_str("  }\n");
}

#[allow(clippy::too_many_arguments)]
fn append_rule_verdict(
    script: &mut String,
    rule: &Rule,
    chain_direction: Direction,
    stateful_reverse: bool,
    counter: &str,
    action: RuleAction,
    outbound_handoff: bool,
    reject_connmark: u32,
) {
    script.push_str("    ");

    append_rule_selectors(script, rule, chain_direction, stateful_reverse);

    if chain_direction == Direction::Outbound && action == RuleAction::Accept && outbound_handoff {
        append_packet_mark_domain_set(script, APPLICATION_HANDOFF_DOMAIN);
        script.push(' ');
    }
    if action == RuleAction::Reject {
        script.push_str("ct mark set (ct mark & 0x");
        append_hex_u32(script, APPLICATION_CONNMARK_FOREIGN_MASK);
        script.push_str(") | 0x");
        append_hex_u32(script, reject_connmark);
        script.push(' ');
    }
    script.push_str("counter name ");
    script.push_str(counter);
    match action {
        RuleAction::Accept => script.push_str(" accept\n"),
        RuleAction::Drop => script.push_str(" drop\n"),
        RuleAction::Reject if rule.spec.protocol == TransportProtocol::Tcp => {
            script.push_str(" reject with tcp reset\n");
        }
        RuleAction::Reject => script.push_str(" reject\n"),
    }
}

fn append_rule_selectors(
    script: &mut String,
    rule: &Rule,
    chain_direction: Direction,
    stateful_reverse: bool,
) {
    if stateful_reverse {
        // `related` packets may have a different L4 protocol/port (for example
        // ICMP errors) and therefore cannot safely use these exact reverse
        // selectors. They require an explicit allow rule.
        script.push_str("ct direction reply ct state established ");
    }

    if let Some(interface) = &rule.spec.interface {
        match chain_direction {
            Direction::Inbound => script.push_str("iifname \""),
            Direction::Outbound => script.push_str("oifname \""),
        }
        script.push_str(interface.as_str());
        script.push_str("\" ");
    }

    if let Some(network) = rule.spec.peer_network {
        match (chain_direction, network) {
            (Direction::Inbound, IpNet::V4(network)) => {
                script.push_str("ip saddr ");
                script.push_str(&network.to_string());
                script.push(' ');
            }
            (Direction::Inbound, IpNet::V6(network)) => {
                script.push_str("ip6 saddr ");
                script.push_str(&network.to_string());
                script.push(' ');
            }
            (Direction::Outbound, IpNet::V4(network)) => {
                script.push_str("ip daddr ");
                script.push_str(&network.to_string());
                script.push(' ');
            }
            (Direction::Outbound, IpNet::V6(network)) => {
                script.push_str("ip6 daddr ");
                script.push_str(&network.to_string());
                script.push(' ');
            }
        }
    }

    match rule.spec.protocol {
        TransportProtocol::Any => {}
        TransportProtocol::Tcp => script.push_str("meta l4proto tcp "),
        TransportProtocol::Udp => script.push_str("meta l4proto udp "),
        TransportProtocol::Icmp => {
            script.push_str("meta nfproto ipv4 meta l4proto icmp ");
        }
        TransportProtocol::IcmpV6 => {
            script.push_str("meta nfproto ipv6 meta l4proto icmpv6 ");
        }
    }

    if let Some(port) = rule.spec.port {
        match (rule.spec.protocol, stateful_reverse) {
            (TransportProtocol::Tcp, false) => script.push_str("tcp dport "),
            (TransportProtocol::Tcp, true) => script.push_str("tcp sport "),
            (TransportProtocol::Udp, false) => script.push_str("udp dport "),
            (TransportProtocol::Udp, true) => script.push_str("udp sport "),
            _ => {}
        }
        script.push_str(&port.start().to_string());
        if port.end() != port.start() {
            script.push('-');
            script.push_str(&port.end().to_string());
        }
        script.push(' ');
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CompileError {
    #[error(transparent)]
    InvalidState(#[from] CoreError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::{
        ApplicationPath, ApplicationSelector, Direction, ExecutableFileId, InterfaceName, Mode,
        PortRange, RuleName, RuleOrigin, RuleSpec, State,
    };

    fn add_https_rule(
        state: &mut State,
        direction: Direction,
        network: &str,
    ) -> Result<(), Box<dyn Error>> {
        let now = Utc
            .with_ymd_and_hms(2026, 8, 20, 12, 0, 0)
            .single()
            .ok_or("invalid test time")?;
        let id = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001")?;
        let spec = RuleSpec::new(
            RuleName::new("https")?,
            direction,
            TransportProtocol::Tcp,
            Some(network.parse()?),
            Some(PortRange::single(443)?),
            Some(InterfaceName::new("eth0")?),
            RuleOrigin::Manual,
            true,
        )?;
        state.create_rule_at(id, spec, now)?;
        Ok(())
    }

    fn add_udp_rule(
        state: &mut State,
        direction: Direction,
        network: &str,
    ) -> Result<(), Box<dyn Error>> {
        let now = Utc
            .with_ymd_and_hms(2026, 8, 20, 12, 0, 0)
            .single()
            .ok_or("invalid test time")?;
        let id = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000002")?;
        let spec = RuleSpec::new(
            RuleName::new("dns")?,
            direction,
            TransportProtocol::Udp,
            Some(network.parse()?),
            Some(PortRange::single(53)?),
            Some(InterfaceName::new("eth0")?),
            RuleOrigin::Manual,
            true,
        )?;
        state.create_rule_at(id, spec, now)?;
        Ok(())
    }

    fn add_application_rule(
        state: &mut State,
        protocol: TransportProtocol,
        enabled: bool,
    ) -> Result<uuid::Uuid, Box<dyn Error>> {
        let now = Utc
            .with_ymd_and_hms(2026, 8, 20, 12, 0, 0)
            .single()
            .ok_or("invalid test time")?;
        let port = match protocol {
            TransportProtocol::Tcp => Some(PortRange::single(443)?),
            TransportProtocol::Udp => Some(PortRange::single(53)?),
            TransportProtocol::Any | TransportProtocol::Icmp | TransportProtocol::IcmpV6 => None,
        };
        let network = if protocol == TransportProtocol::IcmpV6 {
            "2001:db8::7/128".parse()?
        } else {
            "203.0.113.7/32".parse()?
        };
        let mut spec = RuleSpec::new(
            RuleName::new("application")?,
            Direction::Outbound,
            protocol,
            Some(network),
            port,
            Some(InterfaceName::new("eth0")?),
            RuleOrigin::Manual,
            enabled,
        )?;
        spec.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new("/usr/bin/openshield-nft-test")?),
            Some(ExecutableFileId {
                device: 1,
                inode: 2,
                size: 3,
                ctime_seconds: 4,
                ctime_nanoseconds: 5,
            }),
            None,
            Some(1_000),
            None,
        )?);
        let id = uuid::Uuid::new_v4();
        state.create_rule_at(id, spec, now)?;
        Ok(id)
    }

    #[test]
    fn deferred_datagram_replies_repeat_policy_instead_of_getting_an_allow()
    -> Result<(), Box<dyn Error>> {
        for protocol in [
            TransportProtocol::Udp,
            TransportProtocol::Icmp,
            TransportProtocol::IcmpV6,
        ] {
            let mut state = State::new();
            add_application_rule(&mut state, protocol, true)?;
            state.set_mode(Mode::Enforcing)?;
            let script = NftablesCompiler::compile(&state.snapshot())?.into_string();
            let input = script
                .split("  chain output_sanitize")
                .next()
                .ok_or("input")?;
            let retry = input
                .lines()
                .find(|line| line.ends_with("queue to 1339"))
                .ok_or("missing bounded reply queue")?;
            assert!(retry.contains("ct direction reply ct state established "));
            assert!(retry.contains("meta mark & 0xc0000000 != 0xc0000000"));
            assert!(!retry.contains(" bypass"));
            assert!(!retry.contains(" accept"));
            assert!(!retry.contains("iifname"));
            match protocol {
                TransportProtocol::Udp => assert!(
                    retry.contains("ip saddr 203.0.113.7/32 meta l4proto udp udp sport 53 ")
                ),
                TransportProtocol::Icmp => {
                    assert!(retry.contains("icmp type echo-reply icmp code 0 "));
                }
                TransportProtocol::IcmpV6 => {
                    assert!(retry.contains("ip6 saddr 2001:db8::7/128 "));
                    assert!(retry.contains("icmpv6 type echo-reply icmpv6 code 0 "));
                }
                _ => return Err("unexpected test protocol".into()),
            }
            let retry_offset = input.find(retry).ok_or("retry offset")?;
            assert!(input.find("ct mark & 0x7fffffff ==").ok_or("generation")? < retry_offset);
            assert!(
                input
                    .rfind("counter name dropped_in drop")
                    .ok_or("default drop")?
                    > retry_offset
            );
            assert!(script.contains("ct mark set ct mark & 0x80000000"));
        }
        assert_eq!(application_reply_retry_mark(0xffff_1234), 0xffff_1234);
        for payload in [0, 0x1234, APPLICATION_MARK_PAYLOAD_MASK] {
            let mut mark = payload;
            for domain in [0x4000_0000, 0x8000_0000, 0xc000_0000, 0xc000_0000] {
                mark = application_reply_retry_mark(mark);
                assert_eq!(mark, domain | payload);
            }
        }
        assert_ne!(application_reply_retry_mark(0), application_handoff_mark(0));
        assert_ne!(application_reply_retry_mark(0), application_pending_mark(0));
        Ok(())
    }

    #[test]
    fn reply_deferral_is_absent_for_tcp_disabled_denies_and_other_modes()
    -> Result<(), Box<dyn Error>> {
        for protocol in [TransportProtocol::Tcp, TransportProtocol::Udp] {
            for mode in [Mode::BlockAll, Mode::Learning, Mode::Enforcing] {
                for enabled in [false, true] {
                    for action in [RuleAction::Accept, RuleAction::Drop, RuleAction::Reject] {
                        let mut state = State::new();
                        let id = add_application_rule(&mut state, protocol, enabled)?;
                        let mut spec = state
                            .rules()
                            .find(|rule| rule.id == id)
                            .ok_or("rule")?
                            .spec
                            .clone();
                        spec.action = action;
                        state.update_rule(id, spec)?;
                        state.set_mode(mode)?;
                        let script = NftablesCompiler::compile(&state.snapshot())?.into_string();
                        assert_eq!(
                            script.contains("queue to 1339"),
                            protocol == TransportProtocol::Udp
                                && mode == Mode::Enforcing
                                && enabled
                                && action == RuleAction::Accept
                        );
                    }
                }
            }
        }
        let mut state = State::new();
        add_application_rule(&mut state, TransportProtocol::Any, true)?;
        state.set_mode(Mode::Enforcing)?;
        let candidates = application_reply_candidates(&state.snapshot());
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].spec.protocol, TransportProtocol::Udp);
        assert_eq!(candidates[1].spec.protocol, TransportProtocol::Icmp);
        Ok(())
    }

    #[test]
    fn block_all_has_no_accept_path_even_with_rules() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        add_https_rule(&mut state, Direction::Outbound, "203.0.113.0/24")?;
        let policy = NftablesCompiler::compile(&state.snapshot())?;
        assert!(
            policy
                .as_str()
                .starts_with("add table inet openshield\ndelete table inet openshield\n")
        );
        assert!(!policy.as_str().contains("destroy table"));
        assert!(!policy.as_str().contains(" accept\n"));
        assert!(policy.as_str().contains("policy drop"));
        for counter in [
            NFT_OWNERSHIP_COUNTER,
            COUNTER_ACCEPTED_IN,
            COUNTER_ACCEPTED_OUT,
            COUNTER_DROPPED_IN,
            COUNTER_DROPPED_OUT,
            COUNTER_LEARNED_OUT,
        ] {
            assert!(policy.as_str().contains(&format!("counter {counter} {{")));
        }
        assert!(policy.as_str().contains("counter name dropped_in drop"));
        assert!(policy.as_str().contains("counter name dropped_out drop"));
        assert!(!policy.as_str().contains("icmpv6 type 134"));
        assert!(!policy.as_str().contains("udp sport 547 udp dport 546"));
        assert!(!policy.as_str().contains("udp sport 67 udp dport 68"));
        assert!(policy.as_str().contains(
            "chain forward {\n    type filter hook forward priority filter; policy drop;"
        ));
        assert!(!policy.as_str().contains(LEARNED_TCP_V4_SET));
        Ok(())
    }

    #[test]
    fn non_block_modes_leave_forwarding_to_other_base_chains() -> Result<(), Box<dyn Error>> {
        for mode in [Mode::Learning, Mode::Enforcing] {
            let mut state = State::new();
            state.set_mode(mode)?;
            let script = NftablesCompiler::compile(&state.snapshot())?.into_string();
            assert!(script.contains(
                "chain forward {\n    type filter hook forward priority filter; policy drop;\n    accept\n  }"
            ));
            assert!(!script.contains(
                "chain forward {\n    type filter hook forward priority filter; policy drop;\n    counter drop"
            ));
        }
        Ok(())
    }

    #[test]
    fn enforcing_has_default_drop_and_typed_outbound_allow() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_https_rule(&mut state, Direction::Outbound, "203.0.113.0/24")?;
        let snapshot = state.snapshot();
        let script = NftablesCompiler::compile(&snapshot)?.into_string();
        let invalid = script
            .find("ct state invalid counter name dropped_in drop")
            .ok_or("missing invalid drop")?;
        let reverse = script
            .find(
                "ct direction reply ct state established iifname \"eth0\" ip saddr 203.0.113.0/24 meta l4proto tcp tcp sport 443 counter name accepted_in accept",
            )
            .ok_or("missing selector-bound reverse accept")?;
        assert!(invalid < reverse);
        assert!(!script.contains("ct state established,related counter name"));
        assert!(script.contains(
            "oifname \"eth0\" ip daddr 203.0.113.0/24 meta l4proto tcp tcp dport 443 meta mark set (meta mark & 0x3fffffff) | 0xc0000000 counter name accepted_out accept"
        ));
        assert!(script.contains(
            "chain forward {\n    type filter hook forward priority filter; policy drop;\n    accept\n  }"
        ));
        Ok(())
    }

    #[test]
    fn inbound_network_is_matched_as_source() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_https_rule(&mut state, Direction::Inbound, "2001:db8::/32")?;
        let snapshot = state.snapshot();
        let script = NftablesCompiler::compile(&snapshot)?.into_string();
        assert!(script.contains(
            "iifname \"eth0\" ip6 saddr 2001:db8::/32 meta l4proto tcp tcp dport 443 counter name accepted_in accept"
        ));
        assert!(script.contains(
            "ct direction reply ct state established oifname \"eth0\" ip6 daddr 2001:db8::/32 meta l4proto tcp tcp sport 443 meta mark set (meta mark & 0x3fffffff) | 0xc0000000 counter name accepted_out accept"
        ));
        Ok(())
    }

    #[test]
    fn disabled_rule_has_neither_direct_nor_reverse_accept() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_https_rule(&mut state, Direction::Outbound, "203.0.113.0/24")?;
        let id = state.rules().next().ok_or("missing test rule")?.id;
        state.set_rule_enabled(id, false)?;

        let script = NftablesCompiler::compile(&state.snapshot())?.into_string();
        assert!(!script.contains("203.0.113.0/24"));
        assert!(!script.contains("ct state established,related counter name"));
        Ok(())
    }

    #[test]
    fn learning_queues_without_private_marks_and_has_end_to_end_allow_paths()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let snapshot = state.snapshot();
        let flow = format!("{:08x}", application_flow_mark(snapshot.flow_generation));
        let script = NftablesCompiler::compile(&snapshot)?.into_string();
        assert!(script.contains(
            "ct direction original meta l4proto tcp ct state new tcp flags & (syn | ack) == syn counter name learned_out queue num 1338 bypass\n"
        ));
        assert!(script.contains(
            "ct direction original meta l4proto tcp ct state established tcp flags & (fin | rst) == 0 limit rate 64/second burst 32 packets counter name learned_out queue num 1338 bypass\n"
        ));
        assert!(script.contains(
            "ct direction original meta l4proto != tcp counter name learned_out queue num 1338 bypass\n"
        ));
        assert!(!script.contains("queue num 1337"));
        assert!(script.contains(
            "ct direction reply ct state established,related counter name accepted_in accept"
        ));
        assert!(script.contains(
            "ip6 saddr fe80::/10 ip6 hoplimit 255 meta l4proto icmpv6 icmpv6 type 134 icmpv6 code 0"
        ));
        assert!(
            script.contains("ip6 saddr fe80::/10 meta l4proto udp udp sport 547 udp dport 546")
        );
        assert!(
            script.contains("ip daddr 255.255.255.255 meta l4proto udp udp sport 67 udp dport 68")
        );
        let dhcp = script
            .find("udp sport 67 udp dport 68")
            .ok_or("missing DHCPv4 bootstrap allow")?;
        let invalid = script
            .find("ct state invalid counter name dropped_in drop")
            .ok_or("missing inbound INVALID drop")?;
        assert!(dhcp < invalid);
        assert!(script.contains(&format!(
            "ct direction reply ct state established meta l4proto tcp ct mark & 0x7fffffff == 0x{flow} counter name accepted_in accept"
        )));
        assert!(
            script.contains(
                "ct direction original meta l4proto udp ct mark set ct mark & 0x80000000"
            )
        );
        assert!(script.contains(&format!(
            "ct direction reply ct state established meta l4proto udp ct mark & 0x7fffffff == 0x{flow} counter name accepted_in accept"
        )));
        assert!(
            !script.contains("ct direction original ct state established meta l4proto udp ct mark")
        );
        let queue = script
            .find("queue num 1338 bypass")
            .ok_or("missing Learning queue")?;
        let catch_all = script[queue..]
            .find("counter name accepted_out accept")
            .map(|offset| queue + offset)
            .ok_or("missing Learning catch-all")?;
        assert!(queue < catch_all);
        let authorization_chain = script
            .find("chain output_authorize")
            .ok_or("missing output authorization chain")?;
        assert!(script[authorization_chain..].contains("counter name accepted_out accept"));
        assert!(script.contains(
            "chain output_sanitize {\n    type filter hook output priority -1; policy accept;"
        ));
        assert!(
            script.contains(
                "meta mark & 0xc0000000 != 0x00000000 meta mark set meta mark & 0x3fffffff"
            )
        );
        assert!(script.contains(
            "chain output_authorize {\n    type filter hook output priority 1; policy drop;"
        ));
        assert!(!script.contains("set learned_"));
        Ok(())
    }

    #[test]
    fn enforcing_tcp_application_policy_has_no_non_tcp_nfqueue_path() -> Result<(), Box<dyn Error>>
    {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_application_rule(&mut state, TransportProtocol::Tcp, true)?;
        let snapshot = state.snapshot();
        assert_eq!(
            snapshot.application_interception(),
            ApplicationInterception::TcpInitial
        );

        let flow = format!("{:08x}", application_flow_mark(snapshot.flow_generation));
        let script = NftablesCompiler::compile(&snapshot)?.into_string();
        assert_eq!(script.matches("queue num 1337").count(), 1);
        assert!(script.contains(
            "ct direction original oifname \"eth0\" ip daddr 203.0.113.7/32 meta l4proto tcp tcp dport 443 meta mark set (meta mark & 0x3fffffff) | 0x80000000 queue num 1337\n"
        ));
        assert!(!script.contains(
            "ct direction original meta mark set (meta mark & 0x3fffffff) | 0x80000000 queue num 1337\n"
        ));
        assert!(script.contains(&format!(
            "ct direction reply ct state established meta l4proto tcp ct mark & 0x7fffffff == 0x{flow} counter name accepted_in accept"
        )));
        assert!(!script.contains(&format!(
            "ct direction reply ct state established meta l4proto udp ct mark & 0x7fffffff == 0x{flow}"
        )));
        assert!(script.contains(&format!(
            "meta l4proto tcp meta mark & 0xc0000000 == 0x80000000 ct mark set (ct mark & 0x80000000) | 0x{flow}"
        )));
        assert!(!script.contains("meta l4proto udp meta mark & 0xc0000000 == 0x80000000"));
        assert!(
            !script.contains(
                "ct direction original meta l4proto udp ct mark set ct mark & 0x80000000"
            )
        );
        assert!(
            script.contains(
                "meta mark & 0xc0000000 != 0x00000000 meta mark set meta mark & 0x3fffffff"
            )
        );
        assert!(script.contains("counter name dropped_out drop"));
        Ok(())
    }

    #[test]
    fn disabled_per_packet_rule_does_not_promote_mixed_policy_until_enabled()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_application_rule(&mut state, TransportProtocol::Tcp, true)?;
        let disabled_udp = add_application_rule(&mut state, TransportProtocol::Udp, false)?;
        add_udp_rule(&mut state, Direction::Outbound, "192.0.2.53/32")?;

        let tcp_only = state.snapshot();
        assert_eq!(
            tcp_only.application_interception(),
            ApplicationInterception::TcpInitial
        );
        let tcp_only_script = NftablesCompiler::compile(&tcp_only)?.into_string();
        assert!(tcp_only_script.contains(
            "ct direction original oifname \"eth0\" ip daddr 203.0.113.7/32 meta l4proto tcp tcp dport 443 meta mark set (meta mark & 0x3fffffff) | 0x80000000 queue num 1337"
        ));
        assert!(
            !tcp_only_script.contains(
                "ct direction original meta l4proto udp ct mark set ct mark & 0x80000000"
            )
        );
        assert!(!tcp_only_script.contains("meta l4proto udp meta mark & 0xc0000000 == 0x80000000"));

        state.set_rule_enabled(disabled_udp, true)?;
        let mixed = state.snapshot();
        assert_eq!(
            mixed.application_interception(),
            ApplicationInterception::PerPacket
        );
        let mixed_script = NftablesCompiler::compile(&mixed)?.into_string();
        assert!(mixed_script.contains(
            "ct direction original oifname \"eth0\" ip daddr 203.0.113.7/32 meta l4proto udp udp dport 53 meta mark set (meta mark & 0x3fffffff) | 0x80000000 queue num 1337"
        ));
        assert!(
            mixed_script.contains(
                "ct direction original meta l4proto udp ct mark set ct mark & 0x80000000"
            )
        );
        assert!(mixed_script.contains("meta l4proto udp meta mark & 0xc0000000 == 0x80000000"));
        Ok(())
    }

    #[test]
    fn non_tcp_application_reply_allowlist_is_explicit_and_refreshed_before_observation()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        add_udp_rule(&mut state, Direction::Outbound, "192.0.2.53/32")?;
        let snapshot = state.snapshot();
        let flow = format!("{:08x}", application_flow_mark(snapshot.flow_generation));
        let script = NftablesCompiler::compile(&snapshot)?.into_string();

        for protocol_match in APPLICATION_REPLY_PROTOCOL_MATCHES {
            assert!(script.contains(&format!(
                "ct direction reply ct state established {protocol_match} ct mark & 0x7fffffff == 0x{flow} counter name accepted_in accept"
            )));
        }
        for protocol_match in APPLICATION_NON_TCP_PROTOCOL_MATCHES {
            assert!(script.contains(&format!(
                "ct direction original {protocol_match} ct mark set ct mark & 0x80000000"
            )));
        }

        let reset = script
            .find("ct direction original meta l4proto udp ct mark set ct mark & 0x80000000")
            .ok_or("missing UDP connmark reset")?;
        assert!(
            !script
                .contains("oifname \"eth0\" ip daddr 192.0.2.53/32 meta l4proto udp udp dport 53")
        );
        let queue = script
            .find("queue num 1338")
            .ok_or("missing application queue")?;
        assert!(reset < queue);
        assert!(!script.contains("ct direction original ct state established meta l4proto udp"));
        assert!(!script.contains("meta l4proto sctp ct mark & 0x7fffffff"));
        Ok(())
    }

    #[test]
    fn learning_network_accept_does_not_hide_applications_but_denies_still_precede_observation()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        add_https_rule(&mut state, Direction::Outbound, "203.0.113.0/24")?;
        let deny = add_application_rule(&mut state, TransportProtocol::Tcp, true)?;
        let mut spec = state
            .rule(deny)
            .ok_or("missing application rule")?
            .spec
            .clone();
        spec.action = RuleAction::Reject;
        state.update_rule(deny, spec)?;
        for mode in [Mode::Learning, Mode::Enforcing, Mode::BlockAll] {
            state.set_mode(mode)?;
            let script = NftablesCompiler::compile(&state.snapshot())?.into_string();
            let direct_accept =
                "ip daddr 203.0.113.0/24 meta l4proto tcp tcp dport 443 meta mark set";
            if mode == Mode::Learning {
                assert!(script.contains(
                    "iifname \"lo\" ct direction original counter name accepted_in accept"
                ));
                let invalid = script
                    .find("ct state invalid counter name dropped_in drop")
                    .ok_or("missing invalid ingress guard")?;
                let loopback = script
                    .find("iifname \"lo\" ct direction original")
                    .ok_or("missing loopback rule")?;
                assert!(invalid < loopback);
                assert!(!script.contains(direct_accept));
                let deny_queue = script.find("queue num 1337").ok_or("missing deny queue")?;
                let observer = script
                    .find("queue num 1338 bypass")
                    .ok_or("missing observer")?;
                assert!(deny_queue < observer);
                assert!(script.contains("counter name dropped_out reject"));
            } else {
                assert!(!script.contains(
                    "iifname \"lo\" ct direction original counter name accepted_in accept"
                ));
                assert!(!script.contains("queue num 1338"));
                assert!(!script.contains("limit rate 64/second"));
                assert_eq!(script.contains(direct_accept), mode == Mode::Enforcing);
            }
        }
        Ok(())
    }

    #[test]
    fn enforcing_loopback_uses_authenticated_application_generation_and_protocols()
    -> Result<(), Box<dyn Error>> {
        for (protocol, expected_protocols) in
            [(TransportProtocol::Tcp, 1), (TransportProtocol::Any, 4)]
        {
            let mut state = State::new();
            add_application_rule(&mut state, protocol, true)?;
            state.set_mode(Mode::Enforcing)?;
            let flow = application_flow_mark(state.flow_generation());
            let script = NftablesCompiler::compile(&state.snapshot())?.into_string();
            let incoming: Vec<_> = script
                .lines()
                .filter(|line| line.contains("iifname \"lo\""))
                .collect();
            let replies: Vec<_> = script
                .lines()
                .filter(|line| line.contains("oifname \"lo\""))
                .collect();
            assert_eq!(incoming.len(), expected_protocols);
            assert_eq!(replies.len(), expected_protocols);
            for line in incoming.iter().chain(&replies) {
                assert!(line.contains(&format!("ct mark & 0x7fffffff == 0x{flow:08x}")));
                assert!(!line.contains("related"));
                assert!(!line.contains("sctp"));
            }
            assert!(
                incoming
                    .iter()
                    .all(|line| line.contains("ct direction original ct state new,established"))
            );
            assert!(
                replies
                    .iter()
                    .all(|line| line.contains("ct direction reply ct state established"))
            );
            assert!(
                replies.iter().all(
                    |line| line.contains("meta mark set (meta mark & 0x3fffffff) | 0xc0000000")
                )
            );
            let invalid = script
                .find("ct state invalid counter name dropped_in drop")
                .ok_or("missing invalid guard")?;
            let loopback = script
                .find("iifname \"lo\"")
                .ok_or("missing loopback guard")?;
            assert!(invalid < loopback);
        }
        Ok(())
    }

    #[test]
    fn enforcing_loopback_preserves_denies_revocation_and_block_all() -> Result<(), Box<dyn Error>>
    {
        let mut state = State::new();
        let application = add_application_rule(&mut state, TransportProtocol::Tcp, true)?;
        add_https_rule(&mut state, Direction::Outbound, "127.0.0.0/8")?;
        let network = state
            .rules()
            .find(|rule| rule.spec.application.is_none())
            .ok_or("missing network rule")?;
        let id = network.id;
        let mut spec = network.spec.clone();
        spec.action = RuleAction::Drop;
        state.update_rule(id, spec)?;
        state.set_mode(Mode::Enforcing)?;
        let old_flow = application_flow_mark(state.flow_generation());
        let script = NftablesCompiler::compile(&state.snapshot())?.into_string();
        let deny = script
            .find(
                "ip daddr 127.0.0.0/8 meta l4proto tcp tcp dport 443 counter name dropped_out drop",
            )
            .ok_or("missing explicit network deny")?;
        let reply = script
            .find("oifname \"lo\" ct direction reply")
            .ok_or("missing local reply")?;
        assert!(deny < reply);

        // Every policy revocation changes the generation accepted at INPUT.
        state.set_mode(Mode::Learning)?;
        state.set_mode(Mode::Enforcing)?;
        let new_flow = application_flow_mark(state.flow_generation());
        assert_ne!(old_flow, new_flow);
        let script = NftablesCompiler::compile(&state.snapshot())?.into_string();
        for line in script.lines().filter(|line| line.contains("ifname \"lo\"")) {
            assert!(line.contains(&format!("== 0x{new_flow:08x}")));
            assert!(!line.contains(&format!("== 0x{old_flow:08x}")));
        }
        state.set_rule_enabled(application, false)?;
        let script = NftablesCompiler::compile(&state.snapshot())?.into_string();
        assert!(!script.contains("ifname \"lo\""));
        state.set_rule_enabled(application, true)?;
        state.set_mode(Mode::BlockAll)?;
        let script = NftablesCompiler::compile(&state.snapshot())?.into_string();
        assert!(!script.contains("ifname \"lo\""));
        Ok(())
    }

    #[test]
    fn network_actions_compile_drop_then_reject_then_accept() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        for (suffix, action) in [
            (1_u128, RuleAction::Accept),
            (2, RuleAction::Reject),
            (3, RuleAction::Drop),
        ] {
            let mut spec = RuleSpec::new(
                RuleName::new(format!("action {suffix}"))?,
                Direction::Outbound,
                TransportProtocol::Tcp,
                Some("203.0.113.0/24".parse()?),
                Some(PortRange::single(443)?),
                None,
                RuleOrigin::Manual,
                true,
            )?;
            spec.action = action;
            state.create_rule_at(uuid::Uuid::from_u128(suffix), spec, Utc::now())?;
        }

        let snapshot = state.snapshot();
        let reject_connmark = format!(
            "{:08x}",
            application_reject_connmark(snapshot.flow_generation)
        );
        let script = NftablesCompiler::compile(&snapshot)?.into_string();
        let drop_rule = script
            .find("ip daddr 203.0.113.0/24 meta l4proto tcp tcp dport 443 counter name dropped_out drop")
            .ok_or("missing native drop rule")?;
        let reject_rule = script
            .find(&format!("ip daddr 203.0.113.0/24 meta l4proto tcp tcp dport 443 ct mark set (ct mark & 0x80000000) | 0x{reject_connmark} counter name dropped_out reject"))
            .ok_or("missing native reject rule")?;
        let accept_rule = script
            .find("ip daddr 203.0.113.0/24 meta l4proto tcp tcp dport 443 meta mark set")
            .ok_or("missing native accept rule")?;
        assert!(drop_rule < reject_rule && reject_rule < accept_rule);
        Ok(())
    }

    #[test]
    fn application_deny_candidate_precedes_broad_network_accept_and_reject_is_native()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_https_rule(&mut state, Direction::Outbound, "203.0.113.0/24")?;
        let application = add_application_rule(&mut state, TransportProtocol::Tcp, true)?;
        let mut application_spec = state
            .rule(application)
            .ok_or("missing app rule")?
            .spec
            .clone();
        application_spec.action = RuleAction::Reject;
        state.update_rule(application, application_spec)?;

        let snapshot = state.snapshot();
        let reject_connmark = format!(
            "{:08x}",
            application_reject_connmark(snapshot.flow_generation)
        );
        let script = NftablesCompiler::compile(&snapshot)?.into_string();
        let queue = script
            .find("ip daddr 203.0.113.7/32 meta l4proto tcp tcp dport 443 meta mark set")
            .ok_or("missing application candidate queue")?;
        let broad_accept = script
            .find("ip daddr 203.0.113.0/24 meta l4proto tcp tcp dport 443 meta mark set")
            .ok_or("missing broad network accept")?;
        let candidate_guard = script
            .find("ip daddr 203.0.113.7/32 meta l4proto tcp tcp dport 443 counter name dropped_out drop")
            .ok_or("missing ct-less application candidate guard")?;
        assert!(queue < candidate_guard && candidate_guard < broad_accept);
        assert!(
            script.contains(&format!("meta l4proto tcp meta mark & 0xc0000000 == 0x40000000 ct mark set (ct mark & 0x80000000) | 0x{reject_connmark} counter name dropped_out reject with tcp reset"))
        );
        assert!(
            script.contains(&format!("meta mark & 0xc0000000 == 0x40000000 ct mark set (ct mark & 0x80000000) | 0x{reject_connmark} counter name dropped_out reject"))
        );
        assert!(script.contains(
            &format!("ct state related ct direction reply meta l4proto tcp tcp flags & rst == rst ct mark & 0x7fffffff == 0x{reject_connmark} meta mark set (meta mark & 0x3fffffff) | 0xc0000000 counter name accepted_out accept")
        ));
        assert!(script.contains(
            &format!("ct state related ct direction reply meta nfproto ipv4 meta l4proto icmp icmp type destination-unreachable icmp code port-unreachable ct mark & 0x7fffffff == 0x{reject_connmark} counter name accepted_in accept")
        ));
        assert!(script.contains(
            "oifname \"eth0\" meta l4proto tcp ct original ip daddr 203.0.113.7/32 ct original proto-dst 443 counter name dropped_out drop"
        ));
        Ok(())
    }

    #[test]
    fn compilation_is_independent_of_snapshot_order() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_https_rule(&mut state, Direction::Outbound, "203.0.113.0/24")?;
        let mut reversed = state.snapshot();
        reversed.rules.reverse();
        assert_eq!(
            NftablesCompiler::compile(&state.snapshot())?,
            NftablesCompiler::compile(&reversed)?
        );
        Ok(())
    }
}
