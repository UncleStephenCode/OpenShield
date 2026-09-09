use std::{fmt, net::IpAddr};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;
use uuid::Uuid;

use crate::ApplicationSelector;

pub const MAX_RULE_NAME_BYTES: usize = 128;
pub const MAX_INTERFACE_NAME_BYTES: usize = 15;
pub(crate) const REDACTED_APPLICATION_RULE_NAME: &str = "application rule (redacted)";

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Mode {
    #[default]
    BlockAll,
    Learning,
    Enforcing,
}

/// Userspace application-attribution strategy; kernel policy is unchanged.
///
/// Strict is the compatibility default for persisted state and legacy mode
/// controls. Selecting Fast never creates a rule or relaxes a kernel verdict.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum EnforcementStrategy {
    #[default]
    Strict,
    Fast,
}

impl EnforcementStrategy {
    #[must_use]
    pub const fn is_strict(&self) -> bool {
        matches!(self, Self::Strict)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum TransportProtocol {
    Any,
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Any => "any",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::IcmpV6 => "icmpv6",
        };
        formatter.write_str(value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum RuleOrigin {
    Manual,
    Learned,
    /// Disabled application-wide rule skeleton created by automatic learning.
    Template,
}

/// Verdict applied when an enabled rule matches.
///
/// Rule activation is intentionally represented by [`RuleSpec::enabled`]
/// rather than by another action variant: a disabled reject rule, for
/// example, is inert instead of becoming an implicit accept rule.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum RuleAction {
    /// Permit the matching traffic.
    #[default]
    Accept,
    /// Silently discard the matching packet.
    Drop,
    /// Refuse the matching traffic with the backend's native reject verdict.
    Reject,
}

impl RuleAction {
    // serde's `skip_serializing_if` callback ABI always borrows the field,
    // including Copy types.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    const fn is_accept(action: &Self) -> bool {
        matches!(action, Self::Accept)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RuleName(String);

impl RuleName {
    /// Validates and constructs a bounded display-only rule name.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when the name is empty, too long, padded,
    /// or contains a control character.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ValidationError::EmptyRuleName);
        }
        if value.len() > MAX_RULE_NAME_BYTES {
            return Err(ValidationError::RuleNameTooLong {
                actual: value.len(),
                maximum: MAX_RULE_NAME_BYTES,
            });
        }
        if value.trim() != value || value.chars().any(is_unsafe_rule_name_character) {
            return Err(ValidationError::InvalidRuleName);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_unsafe_rule_name_character(character: char) -> bool {
    character.is_control()
        || (character.is_whitespace() && character != ' ')
        || matches!(
            character,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
        )
}

impl fmt::Display for RuleName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RuleName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct InterfaceName(String);

impl InterfaceName {
    /// Constructs a Linux interface name from a conservative ASCII subset.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when the value is empty, longer than the
    /// Linux interface-name limit, or contains a non-allowlisted byte.
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_INTERFACE_NAME_BYTES {
            return Err(ValidationError::InvalidInterfaceName);
        }
        let valid = value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
        if !valid {
            return Err(ValidationError::InvalidInterfaceName);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for InterfaceName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    /// Constructs an inclusive, nonzero port range.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for port zero or an inverted range.
    pub fn new(start: u16, end: u16) -> Result<Self, ValidationError> {
        if start == 0 || end == 0 || start > end {
            return Err(ValidationError::InvalidPortRange { start, end });
        }
        Ok(Self { start, end })
    }

    /// Constructs a range containing one nonzero port.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when `port` is zero.
    pub fn single(port: u16) -> Result<Self, ValidationError> {
        Self::new(port, port)
    }

    #[must_use]
    pub const fn start(self) -> u16 {
        self.start
    }

    #[must_use]
    pub const fn end(self) -> u16 {
        self.end
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WirePortRange {
            start: u16,
            end: u16,
        }

        let wire = WirePortRange::deserialize(deserializer)?;
        Self::new(wire.start, wire.end).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuleSpec {
    pub name: RuleName,
    pub direction: Direction,
    /// Verdict and activation are independent policy dimensions.
    // Accept is the wire default and is omitted deliberately. Besides keeping
    // existing clients compatible with ordinary allow rules, this prevents a
    // valid legacy state near the fixed persistence ceiling from expanding
    // beyond that ceiling solely because v0.2.1 introduced this field.
    #[serde(skip_serializing_if = "RuleAction::is_accept")]
    pub action: RuleAction,
    pub protocol: TransportProtocol,
    pub peer_network: Option<IpNet>,
    pub port: Option<PortRange>,
    pub interface: Option<InterfaceName>,
    /// Optional userspace-enforced identity constraint for outbound traffic.
    /// Rules without this field remain kernel-only network rules.
    pub application: Option<ApplicationSelector>,
    pub origin: RuleOrigin,
    pub enabled: bool,
}

impl RuleSpec {
    /// Constructs and validates all selectors for an Accept rule.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for incompatible selector combinations or
    /// a completely unrestricted any-protocol rule.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: RuleName,
        direction: Direction,
        protocol: TransportProtocol,
        peer_network: Option<IpNet>,
        port: Option<PortRange>,
        interface: Option<InterfaceName>,
        origin: RuleOrigin,
        enabled: bool,
    ) -> Result<Self, ValidationError> {
        let spec = Self {
            name,
            direction,
            action: RuleAction::Accept,
            protocol,
            peer_network,
            port,
            interface,
            application: None,
            origin,
            enabled,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Revalidates semantic relationships between the public typed fields.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for incompatible selector combinations or
    /// a completely unrestricted any-protocol rule.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.direction == Direction::Inbound && self.action != RuleAction::Accept {
            return Err(ValidationError::DenyActionOnInboundRule);
        }
        if self.protocol == TransportProtocol::Any
            && self.peer_network.is_none()
            && self.port.is_none()
            && self.interface.is_none()
            && self.application.is_none()
        {
            return Err(ValidationError::UnrestrictedRule);
        }
        if self.port.is_some()
            && !matches!(
                self.protocol,
                TransportProtocol::Tcp | TransportProtocol::Udp
            )
        {
            return Err(ValidationError::PortWithIncompatibleProtocol);
        }
        match (self.protocol, self.peer_network) {
            (TransportProtocol::Icmp, Some(IpNet::V6(_)))
            | (TransportProtocol::IcmpV6, Some(IpNet::V4(_))) => {
                return Err(ValidationError::ProtocolNetworkFamilyMismatch);
            }
            _ => {}
        }
        if self.direction == Direction::Inbound && self.application.is_some() {
            return Err(ValidationError::ApplicationSelectorOnInboundRule);
        }
        if let Some(application) = &self.application {
            application.validate()?;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for RuleSpec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireRuleSpec {
            name: RuleName,
            direction: Direction,
            #[serde(default)]
            action: RuleAction,
            protocol: TransportProtocol,
            peer_network: Option<IpNet>,
            port: Option<PortRange>,
            interface: Option<InterfaceName>,
            #[serde(default)]
            application: Option<ApplicationSelector>,
            origin: RuleOrigin,
            enabled: bool,
        }

        let wire = WireRuleSpec::deserialize(deserializer)?;
        let specification = Self {
            name: wire.name,
            direction: wire.direction,
            action: wire.action,
            protocol: wire.protocol,
            peer_network: wire.peer_network,
            port: wire.port,
            interface: wire.interface,
            application: wire.application,
            origin: wire.origin,
            enabled: wire.enabled,
        };
        specification.validate().map_err(de::Error::custom)?;
        Ok(specification)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: Uuid,
    pub spec: RuleSpec,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Rule {
    /// Creates a rule with a cryptographically random identifier and current time.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when `spec` is invalid.
    pub fn new(spec: RuleSpec) -> Result<Self, ValidationError> {
        Self::with_id_and_time(Uuid::new_v4(), spec, Utc::now())
    }

    /// Creates a rule with caller-supplied deterministic identity and time.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for a nil identifier or invalid rule spec.
    pub fn with_id_and_time(
        id: Uuid,
        spec: RuleSpec,
        now: DateTime<Utc>,
    ) -> Result<Self, ValidationError> {
        spec.validate()?;
        if id.is_nil() {
            return Err(ValidationError::NilRuleId);
        }
        Ok(Self {
            id,
            spec,
            created_at: now,
            updated_at: now,
        })
    }

    /// Validates identity, timestamps, and all selectors.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] when any persisted invariant is violated.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.id.is_nil() {
            return Err(ValidationError::NilRuleId);
        }
        if self.updated_at < self.created_at {
            return Err(ValidationError::InvalidRuleTimestamps);
        }
        self.spec.validate()
    }

    #[must_use]
    pub fn redacted_for_observer(&self) -> Self {
        let mut redacted = self.clone();
        if redacted.spec.application.is_some() {
            // Names frequently contain executable/service names, so they are
            // treated as sensitive together with argv/path/cgroup metadata.
            redacted.spec.name = RuleName(REDACTED_APPLICATION_RULE_NAME.to_owned());
            redacted.spec.application = Some(ApplicationSelector::redacted());
        }
        redacted
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LearnedEndpoint {
    pub address: IpAddr,
    pub protocol: TransportProtocol,
    pub port: Option<PortRange>,
    pub interface: Option<InterfaceName>,
}

impl LearnedEndpoint {
    /// Validates that a captured endpoint can become a typed allow rule.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] for a missing interface or transport port,
    /// an incompatible address family, or a protocol that cannot be persisted
    /// exactly.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.interface.is_none() {
            return Err(ValidationError::LearnedEndpointNeedsInterface);
        }
        match self.protocol {
            TransportProtocol::Tcp | TransportProtocol::Udp => {
                if self.port.is_none() {
                    return Err(ValidationError::LearnedTransportNeedsPort);
                }
            }
            TransportProtocol::Icmp if self.address.is_ipv6() => {
                return Err(ValidationError::ProtocolNetworkFamilyMismatch);
            }
            TransportProtocol::IcmpV6 if self.address.is_ipv4() => {
                return Err(ValidationError::ProtocolNetworkFamilyMismatch);
            }
            // Learning must never turn one unknown L4 packet into a persistent
            // all-protocol authorization for the same host.
            TransportProtocol::Any => return Err(ValidationError::UnsupportedLearnedProtocol),
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CounterValue {
    pub packets: u64,
    pub bytes: u64,
}

/// Aggregate values from the five fixed nftables named counters.
///
/// Values are runtime observations and are not part of [`crate::State`]. They
/// reset to zero whenever a complete policy is recompiled and atomically
/// replaces the dedicated table, so consumers must treat decreases as resets.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallCounters {
    pub accepted_in: CounterValue,
    pub accepted_out: CounterValue,
    pub dropped_in: CounterValue,
    pub dropped_out: CounterValue,
    pub learned_out: CounterValue,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ValidationError {
    #[error("rule name must not be empty")]
    EmptyRuleName,
    #[error("rule name is {actual} bytes; maximum is {maximum}")]
    RuleNameTooLong { actual: usize, maximum: usize },
    #[error("rule name has surrounding whitespace or control characters")]
    InvalidRuleName,
    #[error("interface name must be 1..={MAX_INTERFACE_NAME_BYTES} safe ASCII bytes")]
    InvalidInterfaceName,
    #[error("invalid port range {start}..={end}")]
    InvalidPortRange { start: u16, end: u16 },
    #[error("a port selector is only valid with TCP or UDP")]
    PortWithIncompatibleProtocol,
    #[error("protocol and peer network use different IP families")]
    ProtocolNetworkFamilyMismatch,
    #[error("an any-protocol rule must have at least one selector")]
    UnrestrictedRule,
    #[error("application selectors are valid only for outbound rules")]
    ApplicationSelectorOnInboundRule,
    #[error("drop and reject actions are valid only for outbound rules")]
    DenyActionOnInboundRule,
    #[error(transparent)]
    InvalidApplicationSelector(#[from] crate::ApplicationValidationError),
    #[error("rule id must not be nil")]
    NilRuleId,
    #[error("rule update time precedes its creation time")]
    InvalidRuleTimestamps,
    #[error("a learned TCP or UDP endpoint requires a port")]
    LearnedTransportNeedsPort,
    #[error("a learned endpoint must retain its outbound interface")]
    LearnedEndpointNeedsInterface,
    #[error("learning cannot persist an any-protocol endpoint")]
    UnsupportedLearnedProtocol,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_nftables_metacharacters_in_interface_name() {
        let result = InterfaceName::new("eth0\"; drop table inet filter");
        assert_eq!(result, Err(ValidationError::InvalidInterfaceName));
    }

    #[test]
    fn rejects_terminal_and_bidi_spoofing_in_rule_names() {
        assert_eq!(
            RuleName::new("trusted\u{1b}[31m"),
            Err(ValidationError::InvalidRuleName)
        );
        assert_eq!(
            RuleName::new("allow ssh\u{202e}drop"),
            Err(ValidationError::InvalidRuleName)
        );
        assert_eq!(
            RuleName::new("allow\u{2028}ssh"),
            Err(ValidationError::InvalidRuleName)
        );
    }

    #[test]
    fn rejects_invalid_ranges_during_json_deserialization() {
        let result = serde_json::from_str::<PortRange>(r#"{"start":443,"end":80}"#);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_port_on_icmp_rule() -> Result<(), Box<dyn std::error::Error>> {
        let spec = RuleSpec::new(
            RuleName::new("bad icmp")?,
            Direction::Inbound,
            TransportProtocol::Icmp,
            None,
            Some(PortRange::single(7)?),
            None,
            RuleOrigin::Manual,
            true,
        );
        assert_eq!(spec, Err(ValidationError::PortWithIncompatibleProtocol));
        Ok(())
    }

    #[test]
    fn rejects_unrestricted_any_rule_from_json() {
        let json = r#"{
            "name":"allow everything",
            "direction":"outbound",
            "protocol":"any",
            "peer_network":null,
            "port":null,
            "interface":null,
            "origin":"manual",
            "enabled":true
        }"#;
        assert!(serde_json::from_str::<RuleSpec>(json).is_err());
    }

    #[test]
    fn legacy_rule_without_action_migrates_to_accept() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "name":"legacy https",
            "direction":"outbound",
            "protocol":"tcp",
            "peer_network":"203.0.113.7/32",
            "port":{"start":443,"end":443},
            "interface":null,
            "origin":"manual",
            "enabled":true
        }"#;
        let specification = serde_json::from_str::<RuleSpec>(json)?;
        assert_eq!(specification.action, RuleAction::Accept);
        assert!(
            serde_json::to_value(&specification)?
                .get("action")
                .is_none()
        );

        let mut deny = specification;
        deny.action = RuleAction::Drop;
        assert_eq!(
            serde_json::to_value(&deny)?["action"],
            serde_json::Value::String("drop".to_owned())
        );
        Ok(())
    }

    #[test]
    fn outbound_actions_are_typed_but_inbound_denies_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut outbound = RuleSpec::new(
            RuleName::new("deny https")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.7/32".parse()?),
            Some(PortRange::single(443)?),
            None,
            RuleOrigin::Manual,
            true,
        )?;
        for action in [RuleAction::Accept, RuleAction::Drop, RuleAction::Reject] {
            outbound.action = action;
            outbound.validate()?;
        }

        outbound.direction = Direction::Inbound;
        assert_eq!(
            outbound.validate(),
            Err(ValidationError::DenyActionOnInboundRule)
        );
        Ok(())
    }

    #[test]
    fn application_identity_can_be_the_only_any_protocol_constraint()
    -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"{
            "name":"one application",
            "direction":"outbound",
            "protocol":"any",
            "peer_network":null,
            "port":null,
            "interface":null,
            "application":{
                "executable":"/usr/bin/example",
                "executable_file":{
                    "device":8,
                    "inode":9,
                    "size":10,
                    "ctime_seconds":1700000000,
                    "ctime_nanoseconds":123456789
                },
                "command_line":null,
                "uid":1000,
                "cgroup":null
            },
            "origin":"manual",
            "enabled":true
        }"#;
        let specification = serde_json::from_str::<RuleSpec>(json)?;
        assert!(specification.application.is_some());
        specification.validate()?;
        Ok(())
    }

    #[test]
    fn learned_endpoints_must_retain_the_observed_interface()
    -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = LearnedEndpoint {
            address: "192.0.2.10".parse()?,
            protocol: TransportProtocol::Tcp,
            port: Some(PortRange::single(443)?),
            interface: None,
        };
        assert_eq!(
            endpoint.validate(),
            Err(ValidationError::LearnedEndpointNeedsInterface)
        );
        Ok(())
    }

    #[test]
    fn firewall_counters_round_trip_without_untyped_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let counters = FirewallCounters {
            accepted_in: CounterValue {
                packets: 2,
                bytes: 200,
            },
            accepted_out: CounterValue {
                packets: 3,
                bytes: 300,
            },
            dropped_in: CounterValue {
                packets: 5,
                bytes: 500,
            },
            dropped_out: CounterValue {
                packets: 7,
                bytes: 700,
            },
            learned_out: CounterValue {
                packets: 11,
                bytes: 1_100,
            },
        };
        let json = serde_json::to_vec(&counters)?;
        assert_eq!(serde_json::from_slice::<FirewallCounters>(&json)?, counters);
        Ok(())
    }
}
