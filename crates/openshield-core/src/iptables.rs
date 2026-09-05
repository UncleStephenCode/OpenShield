use std::fmt::Write as _;

use ipnet::IpNet;

use crate::{
    ApplicationInterception, CompileError, Direction, MAX_FLOW_GENERATION, Mode, Rule, RuleAction,
    Snapshot, TransportProtocol, application_flow_mark,
};

pub const IPTABLES_INPUT_CHAIN: &str = "OPENSHIELD_IN";
pub const IPTABLES_OUTPUT_CHAIN: &str = "OPENSHIELD_OUT";
pub const IPTABLES_FORWARD_CHAIN: &str = "OPENSHIELD_FWD";
pub const IPTABLES_APPLICATION_TCP_CHAIN: &str = "OPENSHIELD_APP_TCP";
pub const IPTABLES_APPLICATION_PACKET_CHAIN: &str = "OPENSHIELD_APP_PKT";
pub const IPTABLES_OWNERSHIP_COMMENT: &str = "openshield:owner:v1";
pub const IPTABLES_MARK_SANITIZE_CHAIN: &str = "OPENSHIELD_MARK";
pub const IPTABLES_LEARNING_OBSERVE_CHAIN: &str = "OPENSHIELD_OBSERVE";

const APPLICATION_MARK_DOMAIN_MASK: u32 = 0xc000_0000;
const APPLICATION_PENDING_DOMAIN: u32 = 0x8000_0000;
const APPLICATION_HANDOFF_DOMAIN: u32 = 0xc000_0000;
const APPLICATION_REJECT_DOMAIN: u32 = 0x4000_0000;
// OpenShield's application flow identity occupies the low 31 connmark bits.
// Keep bit 31 intact for firewalls which use it independently.  Using a mask
// here is also important for the fast path: comparing the unmasked value would
// reject an otherwise valid OpenShield generation when that foreign bit is set.
const APPLICATION_CONNMARK_MASK: u32 = 0x7fff_ffff;

/// A pair of complete `iptables-restore` programs for the IPv4 and IPv6
/// compatibility backends.
///
/// The programs only flush and repopulate OpenShield-owned chains. They are
/// intended for `iptables-restore --noflush`; they never flush a system table
/// or alter a built-in chain. All interpolated values originate in validated
/// domain types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IptablesPolicy {
    ipv4: String,
    ipv6: String,
}

impl IptablesPolicy {
    #[must_use]
    pub fn ipv4(&self) -> &str {
        &self.ipv4
    }

    #[must_use]
    pub fn ipv6(&self) -> &str {
        &self.ipv6
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct IptablesCompiler;

impl IptablesCompiler {
    /// Compiles deterministic IPv4 and IPv6 restore programs.
    ///
    /// # Errors
    ///
    /// Returns [`CompileError`] when the snapshot violates a state invariant.
    pub fn compile(snapshot: &Snapshot) -> Result<IptablesPolicy, CompileError> {
        snapshot.validate()?;
        let interception = snapshot.application_interception();
        Ok(IptablesPolicy {
            ipv4: compile_family(snapshot, AddressFamily::Ipv4, interception),
            ipv6: compile_family(snapshot, AddressFamily::Ipv6, interception),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

fn compile_family(
    snapshot: &Snapshot,
    family: AddressFamily,
    interception: ApplicationInterception,
) -> String {
    let mut mangle = String::from("*mangle\n");
    for chain in owned_mangle_chains() {
        let _infallible = writeln!(mangle, "-F {chain}");
    }
    let _infallible = writeln!(
        mangle,
        "-A {IPTABLES_MARK_SANITIZE_CHAIN} -m comment --comment {IPTABLES_OWNERSHIP_COMMENT}"
    );
    append_reserved_mark_sanitizer(&mut mangle, IPTABLES_MARK_SANITIZE_CHAIN);
    let _infallible = writeln!(mangle, "-A {IPTABLES_MARK_SANITIZE_CHAIN} -j RETURN");

    let _infallible = writeln!(
        mangle,
        "-A {IPTABLES_LEARNING_OBSERVE_CHAIN} -m comment --comment {IPTABLES_OWNERSHIP_COMMENT}"
    );
    // Re-sanitize after existing host mangle rules. The first sanitizer
    // protects against process-supplied SO_MARK; this one prevents a
    // conflicting late QoS/policy-routing mark from entering the private
    // application-verdict domains.
    append_reserved_mark_sanitizer(&mut mangle, IPTABLES_LEARNING_OBSERVE_CHAIN);
    if snapshot.mode == Mode::Learning {
        append_learning_observer_kernel_guards(&mut mangle, snapshot, family);
        // This chain is dispatched last from mangle/OUTPUT. NF_ACCEPT,
        // --queue-bypass, and kernel queue-overflow fail-open therefore skip
        // no host mangle rules and continue into the ordinary filter hook.
        for selector in [
            "-p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW --ctdir ORIGINAL",
            "! -p tcp -m conntrack --ctdir ORIGINAL",
        ] {
            let _infallible = writeln!(
                mangle,
                "-A {IPTABLES_LEARNING_OBSERVE_CHAIN} {selector} -m comment --comment openshield:learned_out -j NFQUEUE --queue-num {} --queue-bypass",
                crate::APPLICATION_LEARNING_QUEUE_NUMBER
            );
        }
    }
    let _infallible = writeln!(mangle, "-A {IPTABLES_LEARNING_OBSERVE_CHAIN} -j RETURN");
    mangle.push_str("COMMIT\n");

    let mut filter = String::from("*filter\n");
    for chain in owned_chains() {
        let _infallible = writeln!(filter, "-F {chain}");
    }
    for chain in owned_chains() {
        let _infallible = writeln!(
            filter,
            "-A {chain} -m comment --comment {IPTABLES_OWNERSHIP_COMMENT}"
        );
    }

    append_input_chain(&mut filter, snapshot, family, interception);
    append_output_chain(&mut filter, snapshot, family, interception);
    append_application_chains(&mut filter, snapshot, interception);
    append_forward_chain(&mut filter, snapshot.mode);
    filter.push_str("COMMIT\n");

    if snapshot.mode == Mode::BlockAll {
        // A partial emergency apply must already be fail-closed if the later
        // mangle COMMIT fails. Active policies use the reverse order so their
        // queue/sanitizer topology exists before the filter starts relying on
        // authenticated packet marks.
        filter.push_str(&mangle);
        filter
    } else {
        mangle.push_str(&filter);
        mangle
    }
}

fn append_forward_chain(script: &mut String, mode: Mode) {
    if mode == Mode::BlockAll {
        append_counted_verdict(script, IPTABLES_FORWARD_CHAIN, "dropped_out", "DROP");
    } else {
        let _infallible = writeln!(script, "-A {IPTABLES_FORWARD_CHAIN} -j RETURN");
    }
}

#[must_use]
pub const fn owned_chains() -> [&'static str; 5] {
    [
        IPTABLES_INPUT_CHAIN,
        IPTABLES_OUTPUT_CHAIN,
        IPTABLES_FORWARD_CHAIN,
        IPTABLES_APPLICATION_TCP_CHAIN,
        IPTABLES_APPLICATION_PACKET_CHAIN,
    ]
}

#[must_use]
pub const fn owned_mangle_chains() -> [&'static str; 2] {
    [
        IPTABLES_MARK_SANITIZE_CHAIN,
        IPTABLES_LEARNING_OBSERVE_CHAIN,
    ]
}

fn append_reserved_mark_sanitizer(script: &mut String, chain: &str) {
    let _infallible = writeln!(
        script,
        "-A {chain} -m mark ! --mark 0x00000000/0x{APPLICATION_MARK_DOMAIN_MASK:08x} -j MARK --set-xmark 0x00000000/0x{APPLICATION_MARK_DOMAIN_MASK:08x}"
    );
}

fn append_learning_observer_kernel_guards(
    script: &mut String,
    snapshot: &Snapshot,
    family: AddressFamily,
) {
    let mut rules: Vec<&Rule> = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.spec.enabled
                && rule.spec.direction == Direction::Outbound
                && (rule.spec.application.is_none()
                    || matches!(rule.spec.action, RuleAction::Drop | RuleAction::Reject))
                && supports_family(rule, family)
        })
        .collect();
    rules.sort_unstable_by_key(|rule| (rule_action_priority(rule.spec.action), rule.id));
    for rule in rules {
        // Network-only rules remain kernel-only, matching nftables behavior.
        // Application deny envelopes continue to fail-closed queue 1337 in
        // filter; a successfully resolved non-matching process is learned
        // there without a second /proc scan.
        append_rule_match_in_chain(
            script,
            rule,
            IPTABLES_LEARNING_OBSERVE_CHAIN,
            Direction::Outbound,
            false,
        );
        script.push_str(" -m conntrack --ctdir ORIGINAL -j RETURN\n");
    }
}

fn append_input_chain(
    script: &mut String,
    snapshot: &Snapshot,
    family: AddressFamily,
    interception: ApplicationInterception,
) {
    if snapshot.mode != Mode::BlockAll {
        append_dhcp_bootstrap_accepts(script, family);
        append_invalid_drop(script, IPTABLES_INPUT_CHAIN, "dropped_in");
        append_ipv6_host_control_plane_accepts(script, family);

        // xt_REJECT synthesizes the local error packet by attaching it as a
        // RELATED reply to the rejected packet and sending it through the
        // local hooks again. Admit only the exact kernel error shapes, or the
        // daemon's inbound default-deny would suppress the local refusal.
        if has_enabled_outbound_reject(snapshot) {
            append_generated_reject_reply_accept(
                script,
                IPTABLES_INPUT_CHAIN,
                family,
                "accepted_in",
                application_reject_connmark(snapshot.flow_generation),
            );
        }

        if snapshot.mode == Mode::Learning {
            let _infallible = writeln!(
                script,
                "-A {IPTABLES_INPUT_CHAIN} -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -m comment --comment openshield:accepted_in -j RETURN"
            );
        }

        if interception != ApplicationInterception::None {
            let flow = application_flow_mark(snapshot.flow_generation);
            let reply_protocols = application_reply_protocols(family);
            let reply_protocols: &[&str] = match interception {
                ApplicationInterception::None => &[],
                ApplicationInterception::TcpInitial => &reply_protocols[..1],
                ApplicationInterception::PerPacket => &reply_protocols,
            };
            for protocol in reply_protocols {
                let _infallible = writeln!(
                    script,
                    "-A {IPTABLES_INPUT_CHAIN} -p {protocol} -m conntrack --ctstate ESTABLISHED --ctdir REPLY -m connmark --mark 0x{flow:08x}/0x{APPLICATION_CONNMARK_MASK:08x} -m comment --comment openshield:accepted_in -j RETURN"
                );
            }
        }

        append_direct_rules(script, snapshot, family, Direction::Inbound);
        append_reverse_rules(script, snapshot, family, Direction::Inbound);
    }
    append_counted_verdict(script, IPTABLES_INPUT_CHAIN, "dropped_in", "DROP");
}

fn append_ipv6_host_control_plane_accepts(script: &mut String, family: AddressFamily) {
    if family != AddressFamily::Ipv6 {
        return;
    }
    let selectors = [
        "-p ipv6-icmp -m conntrack --ctstate RELATED -m addrtype ! --src-type UNSPEC,MULTICAST -m icmp6 --icmpv6-type 1",
        "-p ipv6-icmp -m conntrack --ctstate RELATED -m addrtype ! --src-type UNSPEC,MULTICAST -m icmp6 --icmpv6-type 2/0",
        "-p ipv6-icmp -m conntrack --ctstate RELATED -m addrtype ! --src-type UNSPEC,MULTICAST -m icmp6 --icmpv6-type 3/0",
        "-p ipv6-icmp -m conntrack --ctstate RELATED -m addrtype ! --src-type UNSPEC,MULTICAST -m icmp6 --icmpv6-type 4/1",
        "-p ipv6-icmp -m conntrack --ctstate RELATED -m addrtype ! --src-type UNSPEC,MULTICAST -m icmp6 --icmpv6-type 4/2",
        "-s fe80::/10 -p ipv6-icmp -m hl --hl-eq 255 -m icmp6 --icmpv6-type 134/0",
        "-p ipv6-icmp -m addrtype ! --src-type MULTICAST -m hl --hl-eq 255 -m icmp6 --icmpv6-type 135/0",
        "-p ipv6-icmp -m addrtype ! --src-type UNSPEC,MULTICAST -m hl --hl-eq 255 -m icmp6 --icmpv6-type 136/0",
        "-s fe80::/10 -d ff02::/16 -p ipv6-icmp -m hl --hl-eq 1 -m icmp6 --icmpv6-type 130/0",
    ];
    for selector in selectors {
        let _infallible = writeln!(
            script,
            "-A {IPTABLES_INPUT_CHAIN} {selector} -m comment --comment openshield:accepted_in -j RETURN"
        );
    }
}

fn append_dhcp_bootstrap_accepts(script: &mut String, family: AddressFamily) {
    let selector = match family {
        AddressFamily::Ipv4 => "-d 255.255.255.255/32 -p udp -m udp --sport 67 --dport 68",
        AddressFamily::Ipv6 => "-s fe80::/10 -p udp -m udp --sport 547 --dport 546",
    };
    let _infallible = writeln!(
        script,
        "-A {IPTABLES_INPUT_CHAIN} {selector} -m comment --comment openshield:accepted_in -j RETURN"
    );
}

#[allow(clippy::too_many_lines)]
fn append_output_chain(
    script: &mut String,
    snapshot: &Snapshot,
    family: AddressFamily,
    interception: ApplicationInterception,
) {
    if snapshot.mode != Mode::BlockAll {
        if snapshot.mode == Mode::Enforcing {
            append_invalid_drop(script, IPTABLES_OUTPUT_CHAIN, "dropped_out");
        }
        if has_enabled_outbound_reject(snapshot) {
            append_generated_reject_reply_accept(
                script,
                IPTABLES_OUTPUT_CHAIN,
                family,
                "accepted_out",
                application_reject_connmark(snapshot.flow_generation),
            );
        }
        if snapshot.mode == Mode::Enforcing || snapshot.mode == Mode::Learning {
            // Deny-overrides is global rather than backend-order-dependent:
            // a kernel-only deny must run before an authenticated application
            // Reject/Accept mark or an established application fast path.
            append_direct_rules_for_actions(
                script,
                snapshot,
                family,
                Direction::Outbound,
                &[RuleAction::Drop],
                false,
            );
            append_direct_rules_for_actions(
                script,
                snapshot,
                family,
                Direction::Outbound,
                &[RuleAction::Reject],
                false,
            );
        }
        if interception != ApplicationInterception::None {
            let reject_connmark = application_reject_connmark(snapshot.flow_generation);
            let _infallible = writeln!(
                script,
                "-A {IPTABLES_OUTPUT_CHAIN} -m mark --mark 0x{APPLICATION_REJECT_DOMAIN:08x}/0x{APPLICATION_MARK_DOMAIN_MASK:08x} -j CONNMARK --set-xmark 0x{reject_connmark:08x}/0x{APPLICATION_CONNMARK_MASK:08x}"
            );
            let _infallible = writeln!(
                script,
                "-A {IPTABLES_OUTPUT_CHAIN} -p tcp -m mark --mark 0x{APPLICATION_REJECT_DOMAIN:08x}/0x{APPLICATION_MARK_DOMAIN_MASK:08x} -m comment --comment openshield:dropped_out -j REJECT --reject-with tcp-reset"
            );
            let _infallible = writeln!(
                script,
                "-A {IPTABLES_OUTPUT_CHAIN} -m mark --mark 0x{APPLICATION_REJECT_DOMAIN:08x}/0x{APPLICATION_MARK_DOMAIN_MASK:08x} -m comment --comment openshield:dropped_out -j {}",
                reject_verdict(family)
            );
            // The compatibility queue is in this filter hook and returns
            // NF_REPEAT with a kernel-supplied verdict mark. These rules
            // consume it on the repeated traversal, after stricter network
            // denies and before any allow decision.
            let _infallible = writeln!(
                script,
                "-A {IPTABLES_OUTPUT_CHAIN} -p tcp -m mark --mark 0x{APPLICATION_HANDOFF_DOMAIN:08x}/0x{APPLICATION_MARK_DOMAIN_MASK:08x} -g {IPTABLES_APPLICATION_TCP_CHAIN}"
            );
            if interception == ApplicationInterception::PerPacket {
                for protocol in application_non_tcp_protocols(family) {
                    let _infallible = writeln!(
                        script,
                        "-A {IPTABLES_OUTPUT_CHAIN} -p {protocol} -m mark --mark 0x{APPLICATION_HANDOFF_DOMAIN:08x}/0x{APPLICATION_MARK_DOMAIN_MASK:08x} -g {IPTABLES_APPLICATION_PACKET_CHAIN}"
                    );
                }
                if snapshot.mode == Mode::Learning {
                    // Learning queues every outbound protocol. Userspace may
                    // therefore return an allow verdict for a packet outside
                    // its attribution parser's protocol allowlist. Consume
                    // that authenticated handoff in the generic application
                    // chain after the typed fast paths, avoiding both a
                    // requeue loop and an accidental drop.
                    let _infallible = writeln!(
                        script,
                        "-A {IPTABLES_OUTPUT_CHAIN} -m mark --mark 0x{APPLICATION_HANDOFF_DOMAIN:08x}/0x{APPLICATION_MARK_DOMAIN_MASK:08x} -g {IPTABLES_APPLICATION_PACKET_CHAIN}"
                    );
                }
            }
        }
        if interception != ApplicationInterception::None {
            let flow = application_flow_mark(snapshot.flow_generation);
            let _infallible = writeln!(
                script,
                "-A {IPTABLES_OUTPUT_CHAIN} -p tcp -m conntrack --ctstate ESTABLISHED --ctdir ORIGINAL -m connmark --mark 0x{flow:08x}/0x{APPLICATION_CONNMARK_MASK:08x} -m comment --comment openshield:accepted_out -j RETURN"
            );

            // UDP and ICMP conntrack tuples can outlive their owning socket.
            // Clear only OpenShield's low 31 bits before every new outbound
            // packet so another process cannot inherit a cached application
            // decision. The authenticated NFQUEUE handoff restores the
            // current generation for the corresponding inbound reply.
            if interception == ApplicationInterception::PerPacket {
                for protocol in application_non_tcp_protocols(family) {
                    let _infallible = writeln!(
                        script,
                        "-A {IPTABLES_OUTPUT_CHAIN} -p {protocol} -m conntrack --ctdir ORIGINAL -j CONNMARK --set-xmark 0x00000000/0x{APPLICATION_CONNMARK_MASK:08x}"
                    );
                }
            }
        }

        // Replies to accepted inbound connections precede application
        // candidate queues because they are not new locally initiated flows.
        append_reverse_rules(script, snapshot, family, Direction::Outbound);

        if snapshot.mode == Mode::Enforcing {
            // Queue application candidates before direct network accepts, so
            // a broad kernel allow cannot bypass a narrower application Drop
            // or Reject. The queue has no bypass and is fail-closed.
            append_application_rule_queues(
                script,
                snapshot,
                family,
                &[RuleAction::Drop, RuleAction::Reject, RuleAction::Accept],
            );
            append_application_candidate_guard_drops(
                script,
                snapshot,
                family,
                &[RuleAction::Drop, RuleAction::Reject, RuleAction::Accept],
            );
        } else if snapshot.mode == Mode::Learning {
            append_application_rule_queues(
                script,
                snapshot,
                family,
                &[RuleAction::Drop, RuleAction::Reject],
            );
            append_application_candidate_guard_drops(
                script,
                snapshot,
                family,
                &[RuleAction::Drop, RuleAction::Reject],
            );
        }

        if snapshot.mode == Mode::Learning {
            append_direct_rules_for_actions(
                script,
                snapshot,
                family,
                Direction::Outbound,
                &[RuleAction::Accept],
                false,
            );
            let _infallible = writeln!(
                script,
                "-A {IPTABLES_OUTPUT_CHAIN} -m comment --comment openshield:accepted_out -j RETURN"
            );
        } else {
            append_direct_rules_for_actions(
                script,
                snapshot,
                family,
                Direction::Outbound,
                &[RuleAction::Accept],
                false,
            );
        }
    }
    append_counted_verdict(script, IPTABLES_OUTPUT_CHAIN, "dropped_out", "DROP");
}

fn append_application_chains(
    script: &mut String,
    snapshot: &Snapshot,
    interception: ApplicationInterception,
) {
    if interception != ApplicationInterception::None {
        let flow = application_flow_mark(snapshot.flow_generation & MAX_FLOW_GENERATION);
        let _infallible = writeln!(
            script,
            "-A {IPTABLES_APPLICATION_TCP_CHAIN} -j CONNMARK --set-xmark 0x{flow:08x}/0x{APPLICATION_CONNMARK_MASK:08x}"
        );
        append_clear_reserved_mark(script, IPTABLES_APPLICATION_TCP_CHAIN);
        append_application_accept(script, IPTABLES_APPLICATION_TCP_CHAIN, snapshot.mode);

        if interception == ApplicationInterception::PerPacket {
            let _infallible = writeln!(
                script,
                "-A {IPTABLES_APPLICATION_PACKET_CHAIN} -j CONNMARK --set-xmark 0x{flow:08x}/0x{APPLICATION_CONNMARK_MASK:08x}"
            );
            append_clear_reserved_mark(script, IPTABLES_APPLICATION_PACKET_CHAIN);
            append_application_accept(script, IPTABLES_APPLICATION_PACKET_CHAIN, snapshot.mode);
        }
    }

    // Inactive application chains and any path which reaches their terminal
    // rule remain fail-closed. Active guarded `--goto` paths return directly
    // to the built-in OUTPUT chain after the reserved packet mark is cleared.
    append_counted_verdict(
        script,
        IPTABLES_APPLICATION_TCP_CHAIN,
        "dropped_out",
        "DROP",
    );
    append_counted_verdict(
        script,
        IPTABLES_APPLICATION_PACKET_CHAIN,
        "dropped_out",
        "DROP",
    );
}

fn application_reply_protocols(family: AddressFamily) -> [&'static str; 3] {
    match family {
        AddressFamily::Ipv4 => ["tcp", "udp", "icmp"],
        AddressFamily::Ipv6 => ["tcp", "udp", "ipv6-icmp"],
    }
}

fn application_non_tcp_protocols(family: AddressFamily) -> [&'static str; 2] {
    match family {
        AddressFamily::Ipv4 => ["udp", "icmp"],
        AddressFamily::Ipv6 => ["udp", "ipv6-icmp"],
    }
}

fn append_clear_reserved_mark(script: &mut String, chain: &str) {
    let _infallible = writeln!(
        script,
        "-A {chain} -j MARK --set-xmark 0x00000000/0x{APPLICATION_MARK_DOMAIN_MASK:08x}"
    );
}

fn append_application_accept(script: &mut String, chain: &str, mode: Mode) {
    let comment = if mode == Mode::Learning {
        "openshield:accepted_out+learned_out"
    } else {
        "openshield:accepted_out"
    };
    let _infallible = writeln!(
        script,
        "-A {chain} -m comment --comment {comment} -j RETURN"
    );
}

fn append_invalid_drop(script: &mut String, chain: &str, counter: &str) {
    let _infallible = writeln!(
        script,
        "-A {chain} -m conntrack --ctstate INVALID -m comment --comment openshield:{counter} -j DROP"
    );
}

fn append_generated_reject_reply_accept(
    script: &mut String,
    chain: &str,
    family: AddressFamily,
    counter: &str,
    reject_connmark: u32,
) {
    let _infallible = writeln!(
        script,
        "-A {chain} -p tcp -m tcp --tcp-flags RST RST -m conntrack --ctstate RELATED --ctdir REPLY -m connmark --mark 0x{reject_connmark:08x}/0x{APPLICATION_CONNMARK_MASK:08x} -m comment --comment openshield:{counter} -j RETURN"
    );
    match family {
        AddressFamily::Ipv4 => {
            let _infallible = writeln!(
                script,
                "-A {chain} -p icmp -m icmp --icmp-type 3/3 -m conntrack --ctstate RELATED --ctdir REPLY -m connmark --mark 0x{reject_connmark:08x}/0x{APPLICATION_CONNMARK_MASK:08x} -m comment --comment openshield:{counter} -j RETURN"
            );
        }
        AddressFamily::Ipv6 => {
            let _infallible = writeln!(
                script,
                "-A {chain} -p ipv6-icmp -m icmp6 --icmpv6-type 1/4 -m conntrack --ctstate RELATED --ctdir REPLY -m connmark --mark 0x{reject_connmark:08x}/0x{APPLICATION_CONNMARK_MASK:08x} -m comment --comment openshield:{counter} -j RETURN"
            );
        }
    }
}

const fn application_reject_connmark(flow_generation: u32) -> u32 {
    // Accepted flows set bit 30; Reject attestation keeps it clear and uses
    // the current nonzero generation. Policy generation rotation therefore
    // invalidates stale rejected conntrack tuples while preserving bit 31.
    flow_generation & MAX_FLOW_GENERATION
}

fn has_enabled_outbound_reject(snapshot: &Snapshot) -> bool {
    snapshot.rules.iter().any(|rule| {
        rule.spec.enabled
            && rule.spec.direction == Direction::Outbound
            && rule.spec.action == RuleAction::Reject
    })
}

fn append_counted_verdict(script: &mut String, chain: &str, counter: &str, verdict: &str) {
    let _infallible = writeln!(
        script,
        "-A {chain} -m comment --comment openshield:{counter} -j {verdict}"
    );
}

fn append_direct_rules(
    script: &mut String,
    snapshot: &Snapshot,
    family: AddressFamily,
    direction: Direction,
) {
    append_direct_rules_for_actions(
        script,
        snapshot,
        family,
        direction,
        &[RuleAction::Accept],
        false,
    );
}

fn append_direct_rules_for_actions(
    script: &mut String,
    snapshot: &Snapshot,
    family: AddressFamily,
    direction: Direction,
    actions: &[RuleAction],
    learning_accept: bool,
) {
    let mut rules: Vec<&Rule> = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.spec.enabled
                && rule.spec.direction == direction
                && rule.spec.application.is_none()
                && supports_family(rule, family)
                && actions.contains(&rule.spec.action)
        })
        .collect();
    rules.sort_unstable_by_key(|rule| (rule_action_priority(rule.spec.action), rule.id));
    for rule in rules {
        let action = if learning_accept {
            RuleAction::Accept
        } else {
            rule.spec.action
        };
        append_rule_verdict(
            script,
            rule,
            family,
            direction,
            false,
            action,
            application_reject_connmark(snapshot.flow_generation),
        );
    }
}

fn append_reverse_rules(
    script: &mut String,
    snapshot: &Snapshot,
    family: AddressFamily,
    chain_direction: Direction,
) {
    let mut rules: Vec<&Rule> = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.spec.enabled
                && rule.spec.direction != chain_direction
                && rule.spec.application.is_none()
                && supports_family(rule, family)
                && rule.spec.action == RuleAction::Accept
        })
        .collect();
    rules.sort_unstable_by_key(|rule| rule.id);
    for rule in rules {
        append_rule_verdict(
            script,
            rule,
            family,
            chain_direction,
            true,
            RuleAction::Accept,
            application_reject_connmark(snapshot.flow_generation),
        );
    }
}

fn append_application_rule_queues(
    script: &mut String,
    snapshot: &Snapshot,
    family: AddressFamily,
    actions: &[RuleAction],
) {
    let mut rules: Vec<&Rule> = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.spec.enabled
                && rule.spec.direction == Direction::Outbound
                && rule.spec.application.is_some()
                && supports_family(rule, family)
                && actions.contains(&rule.spec.action)
        })
        .collect();
    rules.sort_unstable_by_key(|rule| (rule_action_priority(rule.spec.action), rule.id));
    for rule in rules {
        append_rule_match_in_chain(
            script,
            rule,
            IPTABLES_OUTPUT_CHAIN,
            Direction::Outbound,
            false,
        );
        let _infallible = writeln!(
            script,
            " -m conntrack --ctdir ORIGINAL -j MARK --set-xmark 0x{APPLICATION_PENDING_DOMAIN:08x}/0x{APPLICATION_MARK_DOMAIN_MASK:08x}"
        );
        append_rule_match_in_chain(
            script,
            rule,
            IPTABLES_OUTPUT_CHAIN,
            Direction::Outbound,
            false,
        );
        let _infallible = writeln!(
            script,
            " -m conntrack --ctdir ORIGINAL -j NFQUEUE --queue-num {}",
            crate::APPLICATION_QUEUE_NUMBER
        );
    }
}

fn append_application_candidate_guard_drops(
    script: &mut String,
    snapshot: &Snapshot,
    family: AddressFamily,
    actions: &[RuleAction],
) {
    let mut rules: Vec<&Rule> = snapshot
        .rules
        .iter()
        .filter(|rule| {
            rule.spec.enabled
                && rule.spec.direction == Direction::Outbound
                && rule.spec.application.is_some()
                && supports_family(rule, family)
                && actions.contains(&rule.spec.action)
        })
        .collect();
    rules.sort_unstable_by_key(|rule| (rule_action_priority(rule.spec.action), rule.id));
    for rule in rules {
        // UNTRACKED packets cannot satisfy --ctdir ORIGINAL and therefore
        // cannot enter the fail-closed queue above. Match their current tuple
        // explicitly before a broad network Accept can admit them.
        append_rule_match_in_chain(
            script,
            rule,
            IPTABLES_OUTPUT_CHAIN,
            Direction::Outbound,
            false,
        );
        script.push_str(
            " -m conntrack --ctstate UNTRACKED -m comment --comment openshield:dropped_out -j DROP\n",
        );

        if rule.spec.peer_network.is_none() && rule.spec.port.is_none() {
            continue;
        }
        // filter/OUTPUT observes the tuple after optional local DNAT. The
        // original conntrack destination closes the corresponding tracked
        // gap without weakening application attribution. `-o` remains the
        // final/rerouted interface and keeps interface-scoped rules scoped.
        let _infallible = write!(script, "-A {IPTABLES_OUTPUT_CHAIN}");
        if let Some(interface) = &rule.spec.interface {
            let _infallible = write!(script, " -o {}", interface.as_str());
        }
        match rule.spec.protocol {
            TransportProtocol::Any => {}
            TransportProtocol::Tcp => script.push_str(" -p tcp"),
            TransportProtocol::Udp => script.push_str(" -p udp"),
            TransportProtocol::Icmp => script.push_str(" -p icmp"),
            TransportProtocol::IcmpV6 => script.push_str(" -p ipv6-icmp"),
        }
        script.push_str(" -m conntrack");
        if let Some(network) = rule.spec.peer_network {
            let original_destination = match network {
                IpNet::V4(network) if network.prefix_len() == 32 => network.addr().to_string(),
                IpNet::V6(network) if network.prefix_len() == 128 => network.addr().to_string(),
                network => network.to_string(),
            };
            let _infallible = write!(script, " --ctorigdst {original_destination}");
        }
        if let Some(port) = rule.spec.port {
            let _infallible = write!(script, " --ctorigdstport {}", port.start());
            if port.end() != port.start() {
                let _infallible = write!(script, ":{}", port.end());
            }
        }
        script.push_str(" --ctdir ORIGINAL -m comment --comment openshield:dropped_out -j DROP\n");
    }
}

const fn rule_action_priority(action: RuleAction) -> u8 {
    match action {
        RuleAction::Drop => 0,
        RuleAction::Reject => 1,
        RuleAction::Accept => 2,
    }
}

fn supports_family(rule: &Rule, family: AddressFamily) -> bool {
    !matches!(
        (rule.spec.protocol, rule.spec.peer_network, family),
        (TransportProtocol::Icmp, _, AddressFamily::Ipv6)
            | (TransportProtocol::IcmpV6, _, AddressFamily::Ipv4)
            | (_, Some(IpNet::V4(_)), AddressFamily::Ipv6)
            | (_, Some(IpNet::V6(_)), AddressFamily::Ipv4)
    )
}

fn append_rule_verdict(
    script: &mut String,
    rule: &Rule,
    family: AddressFamily,
    chain_direction: Direction,
    stateful_reverse: bool,
    action: RuleAction,
    reject_connmark: u32,
) {
    if action == RuleAction::Reject {
        append_rule_match(script, rule, chain_direction, stateful_reverse);
        let _infallible = writeln!(
            script,
            " -j CONNMARK --set-xmark 0x{reject_connmark:08x}/0x{APPLICATION_CONNMARK_MASK:08x}"
        );
    }
    append_rule_match(script, rule, chain_direction, stateful_reverse);

    let counter = match (chain_direction, action) {
        (Direction::Inbound, RuleAction::Accept) => "accepted_in",
        (Direction::Outbound, RuleAction::Accept) => "accepted_out",
        (_, RuleAction::Drop | RuleAction::Reject) => "dropped_out",
    };
    let verdict = match action {
        RuleAction::Accept => "RETURN",
        RuleAction::Drop => "DROP",
        RuleAction::Reject if rule.spec.protocol == TransportProtocol::Tcp => {
            "REJECT --reject-with tcp-reset"
        }
        RuleAction::Reject => reject_verdict(family),
    };
    let _infallible = writeln!(
        script,
        " -m comment --comment openshield:{counter} -j {verdict}"
    );
}

const fn reject_verdict(family: AddressFamily) -> &'static str {
    match family {
        AddressFamily::Ipv4 => "REJECT --reject-with icmp-port-unreachable",
        AddressFamily::Ipv6 => "REJECT --reject-with icmp6-port-unreachable",
    }
}

fn append_rule_match(
    script: &mut String,
    rule: &Rule,
    chain_direction: Direction,
    stateful_reverse: bool,
) {
    let chain = match chain_direction {
        Direction::Inbound => IPTABLES_INPUT_CHAIN,
        Direction::Outbound => IPTABLES_OUTPUT_CHAIN,
    };
    append_rule_match_in_chain(script, rule, chain, chain_direction, stateful_reverse);
}

fn append_rule_match_in_chain(
    script: &mut String,
    rule: &Rule,
    chain: &str,
    chain_direction: Direction,
    stateful_reverse: bool,
) {
    let _infallible = write!(script, "-A {chain}");

    if let Some(network) = rule.spec.peer_network {
        let option = if chain_direction == Direction::Inbound {
            "-s"
        } else {
            "-d"
        };
        let _infallible = write!(script, " {option} {network}");
    }
    if let Some(interface) = &rule.spec.interface {
        let option = if chain_direction == Direction::Inbound {
            "-i"
        } else {
            "-o"
        };
        let _infallible = write!(script, " {option} {}", interface.as_str());
    }

    match rule.spec.protocol {
        TransportProtocol::Any => {}
        TransportProtocol::Tcp => script.push_str(" -p tcp"),
        TransportProtocol::Udp => script.push_str(" -p udp"),
        TransportProtocol::Icmp => script.push_str(" -p icmp"),
        TransportProtocol::IcmpV6 => script.push_str(" -p ipv6-icmp"),
    }
    if stateful_reverse {
        script.push_str(" -m conntrack --ctstate ESTABLISHED --ctdir REPLY");
    }
    if let Some(port) = rule.spec.port {
        let option = if stateful_reverse {
            "--sport"
        } else {
            "--dport"
        };
        let _infallible = write!(script, " {option} {}", port.start());
        if port.end() != port.start() {
            let _infallible = write!(script, ":{}", port.end());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::{
        ApplicationPath, ApplicationSelector, ExecutableFileId, InterfaceName, PortRange, RuleName,
        RuleOrigin, RuleSpec, State,
    };

    fn add_rule(
        state: &mut State,
        direction: Direction,
        network: &str,
        application: bool,
    ) -> Result<(), Box<dyn Error>> {
        let now = Utc
            .with_ymd_and_hms(2026, 8, 20, 12, 0, 0)
            .single()
            .ok_or("invalid test time")?;
        let mut spec = RuleSpec::new(
            RuleName::new("https")?,
            direction,
            TransportProtocol::Tcp,
            Some(network.parse()?),
            Some(PortRange::single(443)?),
            Some(InterfaceName::new("eth0")?),
            RuleOrigin::Manual,
            true,
        )?;
        if application {
            spec.application = Some(ApplicationSelector::new(
                Some(ApplicationPath::new("/usr/bin/curl")?),
                Some(ExecutableFileId {
                    device: 1,
                    inode: 2,
                    size: 3,
                    ctime_seconds: 4,
                    ctime_nanoseconds: 5,
                }),
                None,
                None,
                None,
            )?);
        }
        state.create_rule_at(uuid::Uuid::new_v4(), spec, now)?;
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
        state.create_rule_at(uuid::Uuid::new_v4(), spec, now)?;
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
            Some(ApplicationPath::new("/usr/bin/openshield-iptables-test")?),
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
    fn block_all_has_only_terminal_drop_paths() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        add_rule(&mut state, Direction::Outbound, "203.0.113.0/24", false)?;
        let policy = IptablesCompiler::compile(&state.snapshot())?;
        for script in [policy.ipv4(), policy.ipv6()] {
            assert!(script.starts_with("*filter\n-F OPENSHIELD_IN\n"));
            assert!(script.contains("COMMIT\n*mangle\n-F OPENSHIELD_MARK\n"));
            assert!(script.ends_with("COMMIT\n"));
            assert!(!script.contains("-j ACCEPT"));
            assert!(!script.contains("-j NFQUEUE"));
            assert!(!script.contains("-F INPUT"));
            assert!(!script.contains("-P INPUT"));
            assert!(!script.contains("--icmpv6-type 134/0"));
            assert!(!script.contains("--sport 547 --dport 546"));
            assert!(!script.contains("--sport 67 --dport 68"));
        }
        Ok(())
    }

    #[test]
    fn learning_uses_bypass_nfqueue_allows_replies_and_retains_generation_when_observed()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let snapshot = state.snapshot();
        let policy = IptablesCompiler::compile(&snapshot)?;
        let flow = application_flow_mark(snapshot.flow_generation);
        assert!(
            policy
                .ipv4()
                .contains("-d 255.255.255.255/32 -p udp -m udp --sport 67 --dport 68")
        );
        assert!(
            policy.ipv6().contains(
                "-s fe80::/10 -p ipv6-icmp -m hl --hl-eq 255 -m icmp6 --icmpv6-type 134/0"
            )
        );
        assert!(
            policy
                .ipv6()
                .contains("-s fe80::/10 -p udp -m udp --sport 547 --dport 546")
        );
        for script in [policy.ipv4(), policy.ipv6()] {
            let dhcp = script
                .find(if script == policy.ipv4() {
                    "--sport 67 --dport 68"
                } else {
                    "--sport 547 --dport 546"
                })
                .ok_or("missing DHCP bootstrap allow")?;
            let invalid = script
                .find("--ctstate INVALID")
                .ok_or("missing inbound INVALID drop")?;
            assert!(dhcp < invalid);
        }
        for script in [policy.ipv4(), policy.ipv6()] {
            assert!(script.contains("-j NFQUEUE --queue-num 1338"));
            assert!(script.contains("-j NFQUEUE --queue-num 1338 --queue-bypass"));
            assert!(script.contains(
                "-A OPENSHIELD_OBSERVE -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW --ctdir ORIGINAL -m comment --comment openshield:learned_out -j NFQUEUE --queue-num 1338 --queue-bypass"
            ));
            assert!(script.contains(
                "-A OPENSHIELD_OBSERVE ! -p tcp -m conntrack --ctdir ORIGINAL -m comment --comment openshield:learned_out -j NFQUEUE --queue-num 1338 --queue-bypass"
            ));
            assert!(!script.contains("-A OPENSHIELD_MARK -m conntrack"));
            assert!(!script.contains("-j NFQUEUE --queue-num 1337"));
            assert!(script.contains(
                "--ctstate RELATED,ESTABLISHED --ctdir REPLY -m comment --comment openshield:accepted_in -j RETURN"
            ));
            assert!(script.contains(&format!("-j CONNMARK --set-xmark 0x{flow:08x}/0x7fffffff")));
            assert!(script.contains(&format!("-m connmark --mark 0x{flow:08x}/0x7fffffff")));
            assert!(!script.contains("CONNMARK --set-xmark 0x00000000/0xffffffff"));
            assert!(script.contains("openshield:accepted_out+learned_out"));
            assert!(script.contains(
                "-m mark ! --mark 0x00000000/0xc0000000 -j MARK --set-xmark 0x00000000/0xc0000000"
            ));
            let handoff = script
                .find("-m mark --mark 0xc0000000/0xc0000000 -g OPENSHIELD_APP_TCP")
                .ok_or("missing repeated-filter TCP handoff")?;
            let generic_handoff = script
                .find(
                    "-A OPENSHIELD_OUT -m mark --mark 0xc0000000/0xc0000000 -g OPENSHIELD_APP_PKT",
                )
                .ok_or("missing repeated-filter fallback handoff")?;
            let queue = script
                .find("-j NFQUEUE --queue-num 1338")
                .ok_or("missing application queue")?;
            let catch_all = script
                .rfind("-A OPENSHIELD_OUT -m comment --comment openshield:accepted_out -j RETURN")
                .ok_or("missing Learning catch-all")?;
            assert!(queue < handoff && handoff < generic_handoff && generic_handoff < catch_all);
            let mangle = script
                .split_once("COMMIT\n*filter\n")
                .map(|(mangle, _filter)| mangle)
                .ok_or("missing table boundary")?;
            assert!(!mangle.contains("--set-xmark 0x80000000/0xc0000000"));
        }
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
        let flow = application_flow_mark(snapshot.flow_generation);
        let policy = IptablesCompiler::compile(&snapshot)?;

        for (script, icmp, queue_count) in
            [(policy.ipv4(), "icmp", 1), (policy.ipv6(), "ipv6-icmp", 0)]
        {
            assert_eq!(
                script.matches("-j NFQUEUE --queue-num 1337").count(),
                queue_count
            );
            assert_eq!(
                script.contains(
                    "-A OPENSHIELD_OUT -d 203.0.113.7/32 -o eth0 -p tcp --dport 443 -m conntrack --ctdir ORIGINAL -j NFQUEUE --queue-num 1337"
                ),
                queue_count == 1
            );
            let established_fast_path = script
                .find(&format!(
                    "-A OPENSHIELD_OUT -p tcp -m conntrack --ctstate ESTABLISHED --ctdir ORIGINAL -m connmark --mark 0x{flow:08x}/0x7fffffff"
                ))
                .ok_or("missing established TCP filter fast path")?;
            if queue_count == 1 {
                let queue = script
                    .find("-A OPENSHIELD_OUT -d 203.0.113.7/32 -o eth0 -p tcp --dport 443 -m conntrack --ctdir ORIGINAL -j NFQUEUE --queue-num 1337")
                    .ok_or("missing filter application queue")?;
                assert!(established_fast_path < queue);
            }
            assert!(!script.contains(
                "-A OPENSHIELD_OUT -m conntrack --ctdir ORIGINAL -j NFQUEUE --queue-num 1337"
            ));
            assert!(!script.contains("-A OPENSHIELD_OBSERVE -d 203.0.113.7/32"));
            assert!(script.contains(&format!(
                "-A OPENSHIELD_IN -p tcp -m conntrack --ctstate ESTABLISHED --ctdir REPLY -m connmark --mark 0x{flow:08x}/0x7fffffff"
            )));
            assert!(!script.contains(&format!(
                "-A OPENSHIELD_IN -p udp -m conntrack --ctstate ESTABLISHED --ctdir REPLY -m connmark --mark 0x{flow:08x}/0x7fffffff"
            )));
            assert!(!script.contains(&format!(
                "-A OPENSHIELD_IN -p {icmp} -m conntrack --ctstate ESTABLISHED --ctdir REPLY -m connmark --mark 0x{flow:08x}/0x7fffffff"
            )));
            assert!(!script.contains(
                "-A OPENSHIELD_OUT -p udp -m mark --mark 0xc0000000/0xc0000000 -g OPENSHIELD_APP_PKT"
            ));
            assert!(!script.contains(&format!(
                "-A OPENSHIELD_OUT -p {icmp} -m mark --mark 0xc0000000/0xc0000000 -g OPENSHIELD_APP_PKT"
            )));
            assert!(!script.contains(
                "-A OPENSHIELD_OUT -p udp -m conntrack --ctdir ORIGINAL -j CONNMARK --set-xmark 0x00000000/0x7fffffff"
            ));
            assert!(script.contains(&format!(
                "-A OPENSHIELD_APP_TCP -j CONNMARK --set-xmark 0x{flow:08x}/0x7fffffff"
            )));
            assert!(!script.contains(&format!(
                "-A OPENSHIELD_APP_PKT -j CONNMARK --set-xmark 0x{flow:08x}/0x7fffffff"
            )));
            assert!(script.contains(
                "-m mark ! --mark 0x00000000/0xc0000000 -j MARK --set-xmark 0x00000000/0xc0000000"
            ));
            assert!(script.contains(
                "-A OPENSHIELD_APP_PKT -m comment --comment openshield:dropped_out -j DROP"
            ));
            assert!(!script.contains("queue-bypass"));
        }
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
        let tcp_only_policy = IptablesCompiler::compile(&tcp_only)?;
        for (script, has_ipv4_candidate) in [
            (tcp_only_policy.ipv4(), true),
            (tcp_only_policy.ipv6(), false),
        ] {
            assert_eq!(
                script.contains(
                    "-p tcp --dport 443 -m conntrack --ctdir ORIGINAL -j NFQUEUE --queue-num 1337"
                ),
                has_ipv4_candidate
            );
            assert!(!script.contains(
                "-A OPENSHIELD_OUT -m conntrack --ctdir ORIGINAL -j NFQUEUE --queue-num 1337"
            ));
            assert!(!script.contains(
                "-A OPENSHIELD_OUT -p udp -m mark --mark 0xc0000000/0xc0000000 -g OPENSHIELD_APP_PKT"
            ));
        }

        state.set_rule_enabled(disabled_udp, true)?;
        let mixed = state.snapshot();
        assert_eq!(
            mixed.application_interception(),
            ApplicationInterception::PerPacket
        );
        let mixed_policy = IptablesCompiler::compile(&mixed)?;
        for (script, has_ipv4_candidate) in
            [(mixed_policy.ipv4(), true), (mixed_policy.ipv6(), false)]
        {
            assert_eq!(
                script.contains(
                    "-p udp --dport 53 -m conntrack --ctdir ORIGINAL -j NFQUEUE --queue-num 1337"
                ),
                has_ipv4_candidate
            );
            assert!(script.contains(
                "-A OPENSHIELD_OUT -p udp -m conntrack --ctdir ORIGINAL -j CONNMARK --set-xmark 0x00000000/0x7fffffff"
            ));
            assert!(script.contains(
                "-A OPENSHIELD_OUT -p udp -m mark --mark 0xc0000000/0xc0000000 -g OPENSHIELD_APP_PKT"
            ));
        }
        Ok(())
    }

    #[test]
    fn allowed_packets_return_to_the_calling_firewall() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        add_rule(&mut state, Direction::Outbound, "203.0.113.0/24", false)?;
        let policy = IptablesCompiler::compile(&state.snapshot())?;

        for script in [policy.ipv4(), policy.ipv6()] {
            assert!(!script.contains("-j ACCEPT"));
            assert!(script.contains("openshield:accepted_out -j RETURN"));
            assert!(script.contains(&format!("-g {IPTABLES_APPLICATION_TCP_CHAIN}")));
            assert!(script.contains(&format!("-g {IPTABLES_APPLICATION_PACKET_CHAIN}")));
            assert!(script.contains("openshield:accepted_out+learned_out -j RETURN"));
        }
        Ok(())
    }

    #[test]
    fn non_tcp_application_replies_use_an_explicit_allowlist_and_masked_generation()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        add_udp_rule(&mut state, Direction::Outbound, "192.0.2.53/32")?;
        let snapshot = state.snapshot();
        let flow = application_flow_mark(snapshot.flow_generation);
        let policy = IptablesCompiler::compile(&snapshot)?;

        for (script, icmp, other_icmp) in [
            (policy.ipv4(), "icmp", "ipv6-icmp"),
            (policy.ipv6(), "ipv6-icmp", "icmp"),
        ] {
            for protocol in ["tcp", "udp", icmp] {
                assert!(script.contains(&format!(
                    "-A OPENSHIELD_IN -p {protocol} -m conntrack --ctstate ESTABLISHED --ctdir REPLY -m connmark --mark 0x{flow:08x}/0x7fffffff"
                )));
            }
            assert!(!script.contains(&format!("-A OPENSHIELD_IN -p {other_icmp}")));

            for protocol in ["udp", icmp] {
                assert!(script.contains(&format!(
                    "-A OPENSHIELD_OUT -p {protocol} -m conntrack --ctdir ORIGINAL -j CONNMARK --set-xmark 0x00000000/0x7fffffff"
                )));
                assert!(script.contains(&format!(
                    "-A OPENSHIELD_OUT -p {protocol} -m mark --mark 0xc0000000/0xc0000000 -g OPENSHIELD_APP_PKT"
                )));
            }
            assert!(script.contains(&format!(
                "-A OPENSHIELD_APP_PKT -j CONNMARK --set-xmark 0x{flow:08x}/0x7fffffff"
            )));
            assert!(!script.contains(
                "-A OPENSHIELD_OUT -p udp -m conntrack --ctstate ESTABLISHED --ctdir ORIGINAL"
            ));
            assert!(script.contains(
                "-A OPENSHIELD_OUT -m mark --mark 0xc0000000/0xc0000000 -g OPENSHIELD_APP_PKT"
            ));
            assert!(!script.contains("CONNMARK --set-xmark 0x00000000/0xffffffff"));

            let reset = script
                .find("-A OPENSHIELD_OUT -p udp -m conntrack --ctdir ORIGINAL -j CONNMARK --set-xmark 0x00000000/0x7fffffff")
                .ok_or("missing UDP connmark reset")?;
            let direct = script
                .find("-A OPENSHIELD_OUT -d 192.0.2.53/32 -o eth0 -p udp --dport 53")
                .unwrap_or(usize::MAX);
            let queue = script
                .find("-j NFQUEUE --queue-num 1338")
                .ok_or("missing application queue")?;
            assert!(reset < direct);
            assert!(queue < reset);
        }
        Ok(())
    }

    #[test]
    fn non_block_modes_leave_forwarding_to_the_existing_firewall() -> Result<(), Box<dyn Error>> {
        for mode in [Mode::Learning, Mode::Enforcing] {
            let mut state = State::new();
            state.set_mode(mode)?;
            let policy = IptablesCompiler::compile(&state.snapshot())?;
            for script in [policy.ipv4(), policy.ipv6()] {
                assert!(script.contains("-A OPENSHIELD_FWD -j RETURN"));
                assert!(!script.contains(
                    "-A OPENSHIELD_FWD -m comment --comment openshield:dropped_out -j DROP"
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn family_specific_rules_are_not_cross_compiled() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_rule(&mut state, Direction::Inbound, "2001:db8::/32", false)?;
        let policy = IptablesCompiler::compile(&state.snapshot())?;
        assert!(!policy.ipv4().contains("2001:db8"));
        assert!(policy.ipv6().contains("-s 2001:db8::/32"));
        assert!(policy.ipv6().contains("--dport 443"));
        assert!(policy.ipv6().contains("--sport 443"));
        Ok(())
    }

    #[test]
    fn application_rule_is_queued_instead_of_rendered_as_direct_allow() -> Result<(), Box<dyn Error>>
    {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_rule(&mut state, Direction::Outbound, "203.0.113.7/32", true)?;
        let policy = IptablesCompiler::compile(&state.snapshot())?;
        assert!(policy.ipv4().contains("-j NFQUEUE --queue-num 1337"));
        assert!(policy.ipv4().contains(
            "-d 203.0.113.7/32 -o eth0 -p tcp --dport 443 -m conntrack --ctdir ORIGINAL -j NFQUEUE"
        ));
        assert!(!policy.ipv4().contains(
            "-d 203.0.113.7/32 -o eth0 -p tcp --dport 443 -m comment --comment openshield:accepted_out -j RETURN"
        ));
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
        add_application_rule(&mut state, TransportProtocol::Tcp, true)?;

        let snapshot = state.snapshot();
        let flow = application_flow_mark(snapshot.flow_generation);
        let script = IptablesCompiler::compile(&snapshot)?.ipv4().to_owned();
        let drop_rule = script
            .find("-d 203.0.113.0/24 -p tcp --dport 443 -m comment --comment openshield:dropped_out -j DROP")
            .ok_or("missing native drop rule")?;
        let reject_rule = script
            .find("-d 203.0.113.0/24 -p tcp --dport 443 -m comment --comment openshield:dropped_out -j REJECT")
            .ok_or("missing native reject rule")?;
        let accept_rule = script
            .find("-d 203.0.113.0/24 -p tcp --dport 443 -m comment --comment openshield:accepted_out -j RETURN")
            .ok_or("missing native accept rule")?;
        let application_handoff = script
            .find("-p tcp -m mark --mark 0xc0000000/0xc0000000 -g OPENSHIELD_APP_TCP")
            .ok_or("missing application handoff")?;
        let application_fast_path = script
            .find(&format!(
                "-A OPENSHIELD_OUT -p tcp -m conntrack --ctstate ESTABLISHED --ctdir ORIGINAL -m connmark --mark 0x{flow:08x}/0x7fffffff"
            ))
            .ok_or("missing application fast path")?;
        assert!(
            drop_rule < reject_rule
                && reject_rule < application_handoff
                && application_handoff < application_fast_path
                && application_fast_path < accept_rule
        );
        Ok(())
    }

    #[test]
    fn application_deny_candidate_precedes_broad_network_accept_and_reject_is_native()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_rule(&mut state, Direction::Outbound, "203.0.113.0/24", false)?;
        let application = add_application_rule(&mut state, TransportProtocol::Tcp, true)?;
        let mut application_spec = state
            .rule(application)
            .ok_or("missing app rule")?
            .spec
            .clone();
        application_spec.action = RuleAction::Reject;
        state.update_rule(application, application_spec)?;

        let snapshot = state.snapshot();
        let reject_connmark = application_reject_connmark(snapshot.flow_generation);
        let script = IptablesCompiler::compile(&snapshot)?.ipv4().to_owned();
        let queue = script
            .find("-d 203.0.113.7/32 -o eth0 -p tcp --dport 443 -m conntrack --ctdir ORIGINAL -j NFQUEUE")
            .ok_or("missing application candidate queue")?;
        let untracked_guard = script
            .find("-d 203.0.113.7/32 -o eth0 -p tcp --dport 443 -m conntrack --ctstate UNTRACKED -m comment --comment openshield:dropped_out -j DROP")
            .ok_or("missing untracked application candidate guard")?;
        let original_tuple_guard = script
            .find("-p tcp -m conntrack --ctorigdst 203.0.113.7 --ctorigdstport 443 --ctdir ORIGINAL -m comment --comment openshield:dropped_out -j DROP")
            .ok_or("missing original-tuple application candidate guard")?;
        let broad_accept = script
            .find("-d 203.0.113.0/24 -o eth0 -p tcp --dport 443 -m comment --comment openshield:accepted_out -j RETURN")
            .ok_or("missing broad network accept")?;
        assert!(
            queue < untracked_guard
                && untracked_guard < original_tuple_guard
                && original_tuple_guard < broad_accept
        );
        assert!(script.contains(
            "-p tcp -m mark --mark 0x40000000/0xc0000000 -m comment --comment openshield:dropped_out -j REJECT --reject-with tcp-reset"
        ));
        assert!(script.contains(
            "-m mark --mark 0x40000000/0xc0000000 -m comment --comment openshield:dropped_out -j REJECT --reject-with icmp-port-unreachable"
        ));
        assert!(script.contains(&format!(
            "-m mark --mark 0x40000000/0xc0000000 -j CONNMARK --set-xmark 0x{reject_connmark:08x}/0x7fffffff"
        )));
        let generated_reply = script
            .find("-A OPENSHIELD_OUT -p tcp -m tcp --tcp-flags RST RST -m conntrack --ctstate RELATED --ctdir REPLY")
            .ok_or("missing narrow generated TCP reset reply path")?;
        let reject_consumer = script
            .find("-A OPENSHIELD_OUT -p tcp -m mark --mark 0x40000000/0xc0000000")
            .ok_or("missing application reject consumer")?;
        assert!(generated_reply < reject_consumer);
        assert!(script.contains(&format!(
            "-A OPENSHIELD_IN -p icmp -m icmp --icmp-type 3/3 -m conntrack --ctstate RELATED --ctdir REPLY -m connmark --mark 0x{reject_connmark:08x}/0x7fffffff"
        )));
        Ok(())
    }

    #[test]
    fn output_is_deterministic_across_snapshot_order() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        add_rule(&mut state, Direction::Outbound, "203.0.113.0/24", false)?;
        add_rule(&mut state, Direction::Outbound, "198.51.100.0/24", false)?;
        let mut reversed = state.snapshot();
        reversed.rules.reverse();
        assert_eq!(
            IptablesCompiler::compile(&state.snapshot())?,
            IptablesCompiler::compile(&reversed)?
        );
        Ok(())
    }
}
