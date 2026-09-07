//! Bounded local IPC protocol shared by the `OpenShield` daemon and TUI.

#![forbid(unsafe_code)]

use std::io::{self, Read, Write};

use ipnet::IpNet;
use openshield_core::{
    ApplicationInterception, ApplicationPath, CgroupPath, Direction, Event, Mode, Rule, RuleSpec,
};
use serde::de::DeserializeOwned;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use thiserror::Error;
use uuid::Uuid;

pub const MAX_FRAME_SIZE: usize = 64 * 1024;
/// Maximum number of rules considered for one page. The daemon additionally
/// shrinks serialized pages to the fixed frame-byte limit.
pub const MAX_RULES_PER_PAGE: u16 = 128;
pub const MAX_ERROR_MESSAGE_BYTES: usize = 512;
pub const OBSERVE_SOCKET_PATH: &str = "/run/openshield/observe.sock";
pub const CONTROL_SOCKET_PATH: &str = "/run/openshield/control.sock";
pub const OBSERVE_GROUP_NAME: &str = "openshield";

/// Firewall implementation which currently owns the `OpenShield` policy.
///
/// `Unknown` is deliberately the default so an older daemon response or a
/// test backend can never be presented as a verified production backend.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum FirewallBackendKind {
    #[default]
    Unknown,
    Nftables,
    Iptables,
}

/// Coarse execution level selected for the currently active policy.
///
/// This is runtime evidence, not a user preference. `Unknown` is deliberately
/// fail-safe for test backends and producers which cannot attest their active
/// packet path.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum CompatibilityLevel {
    #[default]
    Unknown,
    /// Every active policy decision is made by the kernel firewall backend.
    KernelNative,
    /// New application TCP flows use NFQUEUE attribution and established TCP
    /// uses the conntrack-generation fast path.
    ConntrackHybrid,
    /// Application traffic requires repeated NFQUEUE attribution.
    Nfqueue,
}

/// Policy property responsible for the selected compatibility level.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum CompatibilityReason {
    #[default]
    Unknown,
    BlockAll,
    EmergencyBlockAll,
    NetworkOnly,
    Learning,
    ApplicationTcp,
    ApplicationPerPacket,
}

/// Typed description of the effective runtime packet path.
///
/// An empty nested object decodes to the fail-safe `Unknown`/`Unknown` pair.
/// Partially populated, contradictory, and unknown fields are rejected so a
/// producer cannot accidentally advertise an impossible verified fast path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RuntimeCompatibility {
    pub level: CompatibilityLevel,
    pub reason: CompatibilityReason,
}

impl Serialize for RuntimeCompatibility {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if !self.is_consistent() {
            return Err(<S::Error as serde::ser::Error>::custom(
                "runtime compatibility level and reason are inconsistent",
            ));
        }
        let mut state = serializer.serialize_struct("RuntimeCompatibility", 2)?;
        state.serialize_field("level", &self.level)?;
        state.serialize_field("reason", &self.reason)?;
        state.end()
    }
}

impl RuntimeCompatibility {
    /// Derives the conservative active path from the committed policy and the
    /// attested backend. Policy compilers, daemon status, and clients use this
    /// same mapping so the label cannot acquire independent semantics.
    #[must_use]
    pub const fn for_policy(
        backend: FirewallBackendKind,
        mode: Mode,
        application_interception: ApplicationInterception,
    ) -> Self {
        if matches!(backend, FirewallBackendKind::Unknown) {
            return Self {
                level: CompatibilityLevel::Unknown,
                reason: CompatibilityReason::Unknown,
            };
        }

        match mode {
            Mode::BlockAll => Self {
                level: CompatibilityLevel::KernelNative,
                reason: CompatibilityReason::BlockAll,
            },
            Mode::Learning => Self {
                level: CompatibilityLevel::Nfqueue,
                reason: CompatibilityReason::Learning,
            },
            Mode::Enforcing => match application_interception {
                ApplicationInterception::None => Self {
                    level: CompatibilityLevel::KernelNative,
                    reason: CompatibilityReason::NetworkOnly,
                },
                ApplicationInterception::TcpInitial => Self {
                    level: CompatibilityLevel::ConntrackHybrid,
                    reason: CompatibilityReason::ApplicationTcp,
                },
                ApplicationInterception::PerPacket => Self {
                    level: CompatibilityLevel::Nfqueue,
                    reason: CompatibilityReason::ApplicationPerPacket,
                },
            },
        }
    }

    /// Returns whether the level and its policy reason form one of the
    /// protocol-defined evidence pairs.
    #[must_use]
    pub const fn is_consistent(self) -> bool {
        matches!(
            (self.level, self.reason),
            (CompatibilityLevel::Unknown, CompatibilityReason::Unknown)
                | (
                    CompatibilityLevel::KernelNative,
                    CompatibilityReason::BlockAll
                        | CompatibilityReason::EmergencyBlockAll
                        | CompatibilityReason::NetworkOnly
                )
                | (
                    CompatibilityLevel::ConntrackHybrid,
                    CompatibilityReason::ApplicationTcp
                )
                | (
                    CompatibilityLevel::Nfqueue,
                    CompatibilityReason::Learning | CompatibilityReason::ApplicationPerPacket
                )
        )
    }

    /// Validates this evidence against the surrounding policy mode and
    /// attested production backend from a `StatusV2` response.
    #[must_use]
    pub const fn is_consistent_with(self, mode: Mode, backend: FirewallBackendKind) -> bool {
        matches!(
            (backend, mode, self.level, self.reason),
            (
                FirewallBackendKind::Nftables | FirewallBackendKind::Iptables,
                Mode::BlockAll,
                CompatibilityLevel::KernelNative,
                CompatibilityReason::BlockAll | CompatibilityReason::EmergencyBlockAll,
            ) | (
                FirewallBackendKind::Nftables | FirewallBackendKind::Iptables,
                Mode::Learning,
                CompatibilityLevel::Nfqueue,
                CompatibilityReason::Learning,
            ) | (
                FirewallBackendKind::Nftables | FirewallBackendKind::Iptables,
                Mode::Enforcing,
                CompatibilityLevel::KernelNative,
                CompatibilityReason::NetworkOnly,
            ) | (
                FirewallBackendKind::Nftables | FirewallBackendKind::Iptables,
                Mode::Enforcing,
                CompatibilityLevel::ConntrackHybrid,
                CompatibilityReason::ApplicationTcp,
            ) | (
                FirewallBackendKind::Nftables | FirewallBackendKind::Iptables,
                Mode::Enforcing,
                CompatibilityLevel::Nfqueue,
                CompatibilityReason::ApplicationPerPacket,
            ) | (
                FirewallBackendKind::Unknown,
                _,
                CompatibilityLevel::Unknown,
                CompatibilityReason::Unknown,
            )
        )
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RuntimeCompatibilityWire {
    level: Option<CompatibilityLevel>,
    reason: Option<CompatibilityReason>,
}

impl<'de> Deserialize<'de> for RuntimeCompatibility {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RuntimeCompatibilityWire::deserialize(deserializer)?;
        let compatibility = match (wire.level, wire.reason) {
            (None, None) => Self::default(),
            (Some(level), Some(reason)) => Self { level, reason },
            (Some(_), None) | (None, Some(_)) => {
                return Err(de::Error::custom(
                    "runtime compatibility level and reason must both be present",
                ));
            }
        };
        if !compatibility.is_consistent() {
            return Err(de::Error::custom(
                "runtime compatibility level and reason are inconsistent",
            ));
        }
        Ok(compatibility)
    }
}

/// Monotonic error counters reported by the live NFQUEUE runtime.
///
/// Every field is saturating: a daemon never wraps a counter back to zero.
/// The nested default keeps status responses from older daemons readable by
/// newer clients and permits future producers to omit zero-valued fields.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NfqueueCounters {
    /// Netlink receive-overflow events (`ENOBUFS`). The kernel denied an
    /// unknown number of queued packets for each event.
    pub queue_overflow: u64,
    /// Packets denied because the bounded `/proc` attribution deadline
    /// expired.
    pub attribution_timeout: u64,
    /// Errors which terminate the queue runtime and trigger fail-closed
    /// quarantine.
    pub terminal_queue_error: u64,
    /// Packets for which userspace successfully returned an explicit drop
    /// verdict. Overflow losses are not included because their cardinality is
    /// unavailable to userspace.
    pub denied: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(
    clippy::large_enum_variant,
    reason = "keeping the stable unboxed control-request API avoids protocol-wide churn"
)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "type",
    content = "data"
)]
pub enum Request {
    Read(ReadRequest),
    Control(ControlRequest),
}

pub type ClientRequest = Request;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "type",
    content = "data"
)]
pub enum ReadRequest {
    /// Returns mode, revision, total rule count, active firewall backend, and
    /// process-lifetime NFQUEUE counters.
    Status,
    /// Returns the legacy status fields plus typed runtime compatibility
    /// evidence. The separate request keeps the original `Status` wire shape
    /// stable for older clients.
    StatusV2,
    /// Returns rules ordered by UUID strictly after `after`.
    ///
    /// `limit` is a bounded client hint. Servers may choose any positive page
    /// size up to [`MAX_RULES_PER_PAGE`] (the daemon deliberately ignores tiny
    /// hints to prevent request-amplification attacks). Every page contains a
    /// revision; clients restart pagination if that revision changes.
    RulesPage { after: Option<Uuid>, limit: u16 },
    /// Starts a live event stream after initial status/page synchronization.
    Subscribe { after_revision: Option<u64> },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "type",
    content = "data"
)]
pub enum ControlRequest {
    SetMode {
        expected_revision: u64,
        mode: Mode,
    },
    CreateRule {
        expected_revision: u64,
        rule: RuleSpec,
    },
    UpdateRule {
        expected_revision: u64,
        id: Uuid,
        rule: RuleSpec,
    },
    DeleteRule {
        expected_revision: u64,
        id: Uuid,
    },
    SetRuleEnabled {
        expected_revision: u64,
        id: Uuid,
        enabled: bool,
    },
    /// Applies one atomic policy transaction to the current members of an
    /// outbound group. The acknowledgement carries the final revision and
    /// no single affected rule; individual changes retain ordered events.
    ManageOutboundGroup {
        expected_revision: u64,
        group: OutboundGroupSelector,
        action: OutboundGroupAction,
    },
}

/// Stable group identity, using the same cgroup/executable/destination
/// priority as the outbound rule tree. Paths are validated during decoding.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "type",
    content = "data"
)]
pub enum OutboundGroupSelector {
    /// An exact cgroup root, optionally restricted to one executable child.
    Cgroup {
        cgroup: CgroupPath,
        executable: Option<ApplicationPath>,
    },
    /// Executable fallback group, excluding members of any cgroup group.
    Executable { executable: ApplicationPath },
    /// Destination fallback group, excluding visible application groups.
    Destination { peer_network: Option<IpNet> },
}

impl OutboundGroupSelector {
    /// Tests membership without exposing redacted application metadata.
    #[must_use]
    pub fn matches(&self, rule: &Rule) -> bool {
        if rule.spec.direction != Direction::Outbound {
            return false;
        }
        let application = rule
            .spec
            .application
            .as_ref()
            .filter(|application| !application.metadata_redacted);
        match self {
            Self::Cgroup { cgroup, executable } => application.is_some_and(|application| {
                application.cgroup.as_ref() == Some(cgroup)
                    && executable.as_ref().is_none_or(|executable| {
                        application.executable.as_ref() == Some(executable)
                    })
            }),
            Self::Executable { executable } => application.is_some_and(|application| {
                application.cgroup.is_none() && application.executable.as_ref() == Some(executable)
            }),
            Self::Destination { peer_network } => {
                application.is_none_or(|application| {
                    application.cgroup.is_none() && application.executable.is_none()
                }) && rule.spec.peer_network.map(|network| network.trunc())
                    == peer_network.map(|network| network.trunc())
            }
        }
    }
}

/// Group actions change only the named policy property. In particular,
/// changing the verdict does not enable disabled rules or templates.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum OutboundGroupAction {
    Delete,
    Accept,
    Reject,
    Drop,
    Enable,
    Disable,
}

impl ControlRequest {
    /// Revision of the snapshot on which this privileged mutation is based.
    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        match self {
            Self::SetMode {
                expected_revision, ..
            }
            | Self::CreateRule {
                expected_revision, ..
            }
            | Self::UpdateRule {
                expected_revision, ..
            }
            | Self::DeleteRule {
                expected_revision, ..
            }
            | Self::SetRuleEnabled {
                expected_revision, ..
            }
            | Self::ManageOutboundGroup {
                expected_revision, ..
            } => *expected_revision,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "type",
    content = "data"
)]
pub enum Response {
    Status {
        revision: u64,
        mode: Mode,
        rule_count: u32,
        #[serde(default)]
        backend: FirewallBackendKind,
        #[serde(default)]
        nfqueue: NfqueueCounters,
    },
    StatusV2 {
        revision: u64,
        mode: Mode,
        rule_count: u32,
        #[serde(default)]
        backend: FirewallBackendKind,
        #[serde(default)]
        nfqueue: NfqueueCounters,
        runtime_compatibility: RuntimeCompatibility,
    },
    RulesPage {
        revision: u64,
        rules: Vec<Rule>,
        next_after: Option<Uuid>,
    },
    Ack(Ack),
    Event(Event),
    Error(ProtocolError),
}

pub type ServerMessage = Response;

#[must_use]
pub fn clamp_page_limit(limit: u16) -> u16 {
    limit.clamp(1, MAX_RULES_PER_PAGE)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub revision: u64,
    pub affected_rule: Option<Rule>,
}

impl Ack {
    #[must_use]
    pub const fn new(revision: u64, affected_rule: Option<Rule>) -> Self {
        Self {
            revision,
            affected_rule,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    Unauthorized,
    NotFound,
    Conflict,
    BackendUnavailable,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProtocolError {
    pub code: ErrorCode,
    pub message: String,
}

impl ProtocolError {
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: sanitize_error_message(&message.into()),
        }
    }
}

impl<'de> Deserialize<'de> for ProtocolError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireProtocolError {
            code: ErrorCode,
            message: String,
        }

        let wire = WireProtocolError::deserialize(deserializer)?;
        let sanitized = sanitize_error_message(&wire.message);
        if sanitized != wire.message {
            return Err(de::Error::custom(
                "protocol error message is empty, oversized, or unsafe for a terminal",
            ));
        }
        Ok(Self {
            code: wire.code,
            message: wire.message,
        })
    }
}

fn sanitize_error_message(message: &str) -> String {
    let mut sanitized = String::new();
    for character in message.chars() {
        if character.is_control()
            || matches!(
                character,
                '\u{061c}'
                    | '\u{200b}'..='\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2060}'..='\u{206f}'
                    | '\u{feff}'
            )
        {
            continue;
        }
        if sanitized.len().saturating_add(character.len_utf8()) > MAX_ERROR_MESSAGE_BYTES {
            break;
        }
        sanitized.push(character);
    }
    if sanitized.is_empty() {
        String::from("unspecified error")
    } else {
        sanitized
    }
}

/// Writes one JSON message prefixed by an unsigned four-byte big-endian size.
///
/// This function never invokes a shell and never writes a partial oversized
/// frame: serialization and the size check happen before the header is sent.
///
/// # Errors
///
/// Returns [`FrameError`] when encoding exceeds the bound, serialization
/// fails, or the destination cannot accept the complete frame.
pub fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: Write,
    T: Serialize + ?Sized,
{
    let mut bounded = BoundedBuffer::new(MAX_FRAME_SIZE);
    if let Err(source) = serde_json::to_writer(&mut bounded, value) {
        if let Some(actual) = bounded.overflow_size {
            return Err(FrameError::FrameTooLarge {
                actual,
                maximum: MAX_FRAME_SIZE,
            });
        }
        return Err(FrameError::Encode {
            message: source.to_string(),
        });
    }
    let payload = bounded.bytes;
    if payload.is_empty() {
        return Err(FrameError::EmptyFrame);
    }
    if payload.len() > MAX_FRAME_SIZE {
        return Err(FrameError::FrameTooLarge {
            actual: payload.len(),
            maximum: MAX_FRAME_SIZE,
        });
    }
    let size = u32::try_from(payload.len()).map_err(|_| FrameError::FrameTooLarge {
        actual: payload.len(),
        maximum: MAX_FRAME_SIZE,
    })?;
    writer.write_all(&size.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

#[derive(Debug)]
struct BoundedBuffer {
    bytes: Vec<u8>,
    maximum: usize,
    overflow_size: Option<usize>,
}

impl BoundedBuffer {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
            overflow_size: None,
        }
    }
}

impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let attempted = self.bytes.len().saturating_add(bytes.len());
        if attempted > self.maximum {
            self.overflow_size = Some(attempted);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "serialized IPC frame exceeds its fixed limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Reads exactly one bounded JSON frame.
///
/// An oversized advertised size is rejected before allocating its payload.
///
/// # Errors
///
/// Returns [`FrameError`] for an empty or oversized header, truncated I/O, or
/// JSON that does not strictly decode to `T`.
pub fn read_frame<R, T>(reader: &mut R) -> Result<T, FrameError>
where
    R: Read,
    T: DeserializeOwned,
{
    let mut header = [0_u8; 4];
    reader.read_exact(&mut header)?;
    let size_u32 = u32::from_be_bytes(header);
    let size = usize::try_from(size_u32).map_err(|_| FrameError::FrameTooLarge {
        actual: usize::MAX,
        maximum: MAX_FRAME_SIZE,
    })?;
    if size == 0 {
        return Err(FrameError::EmptyFrame);
    }
    if size > MAX_FRAME_SIZE {
        return Err(FrameError::FrameTooLarge {
            actual: size,
            maximum: MAX_FRAME_SIZE,
        });
    }

    let mut payload = vec![0_u8; size];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload).map_err(|source| FrameError::Decode {
        message: source.to_string(),
    })
}

/// Writes one typed client request.
///
/// # Errors
///
/// Returns [`FrameError`] under the same conditions as [`write_frame`].
pub fn write_request<W: Write>(writer: &mut W, request: &Request) -> Result<(), FrameError> {
    write_frame(writer, request)
}

/// Reads one typed client request.
///
/// # Errors
///
/// Returns [`FrameError`] under the same conditions as [`read_frame`].
pub fn read_request<R: Read>(reader: &mut R) -> Result<Request, FrameError> {
    read_frame(reader)
}

/// Writes one typed server response.
///
/// # Errors
///
/// Returns [`FrameError`] under the same conditions as [`write_frame`].
pub fn write_response<W: Write>(writer: &mut W, response: &Response) -> Result<(), FrameError> {
    write_frame(writer, response)
}

/// Reads one typed server response.
///
/// # Errors
///
/// Returns [`FrameError`] under the same conditions as [`read_frame`].
pub fn read_response<R: Read>(reader: &mut R) -> Result<Response, FrameError> {
    read_frame(reader)
}

/// Writes one generic bounded message.
///
/// # Errors
///
/// Returns [`FrameError`] under the same conditions as [`write_frame`].
pub fn write_message<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: Write,
    T: Serialize + ?Sized,
{
    write_frame(writer, value)
}

/// Reads one generic bounded message.
///
/// # Errors
///
/// Returns [`FrameError`] under the same conditions as [`read_frame`].
pub fn read_message<R, T>(reader: &mut R) -> Result<T, FrameError>
where
    R: Read,
    T: DeserializeOwned,
{
    read_frame(reader)
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("IPC frame is empty")]
    EmptyFrame,
    #[error("IPC frame is {actual} bytes; maximum is {maximum}")]
    FrameTooLarge { actual: usize, maximum: usize },
    #[error("I/O while processing IPC frame: {0}")]
    Io(#[from] io::Error),
    #[error("failed to encode IPC JSON: {message}")]
    Encode { message: String },
    #[error("failed to decode IPC JSON: {message}")]
    Decode { message: String },
}

#[cfg(test)]
mod tests {
    use std::{error::Error, io::Cursor};

    use openshield_core::{
        ApplicationPath, ApplicationSelector, CgroupPath, CommandArgument, CommandLineMatch,
        CommandLineSelector, Direction, ExecutableFileId, MAX_APPLICATION_PATH_BYTES,
        MAX_CGROUP_PATH_BYTES, MAX_COMMAND_ARGUMENT_BYTES, MAX_COMMAND_LINE_BYTES,
        MAX_RULE_NAME_BYTES, PortRange, RuleName, RuleOrigin, RuleSpec, TransportProtocol,
    };

    use super::*;

    fn largest_rule() -> Result<Rule, Box<dyn Error>> {
        let name = "x".repeat(MAX_RULE_NAME_BYTES);
        let executable = format!("/{}", "\"".repeat(MAX_APPLICATION_PATH_BYTES - 1));
        let cgroup = format!("/{}", "\"".repeat(MAX_CGROUP_PATH_BYTES - 1));
        let argument_size = MAX_COMMAND_ARGUMENT_BYTES - 1;
        let argument_count = MAX_COMMAND_LINE_BYTES / (argument_size + 1);
        let arguments = (0..argument_count)
            .map(|_| CommandArgument::new("\"".repeat(argument_size)))
            .collect::<Result<Vec<_>, _>>()?;
        let mut specification = RuleSpec::new(
            RuleName::new(name)?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff/128".parse()?),
            Some(PortRange::new(1, u16::MAX)?),
            None,
            RuleOrigin::Manual,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new(executable)?),
            Some(ExecutableFileId {
                device: u64::MAX,
                inode: u64::MAX,
                size: u64::MAX,
                ctime_seconds: i64::MAX,
                ctime_nanoseconds: 999_999_999,
            }),
            Some(CommandLineSelector::new(
                CommandLineMatch::Exact,
                arguments,
            )?),
            Some(u32::MAX),
            Some(CgroupPath::new(cgroup)?),
        )?);
        Ok(Rule::new(specification)?)
    }

    #[test]
    fn request_round_trip_uses_big_endian_length() -> Result<(), Box<dyn Error>> {
        let request = Request::Read(ReadRequest::Subscribe {
            after_revision: Some(42),
        });
        let mut bytes = Vec::new();
        write_request(&mut bytes, &request)?;
        let advertised = u32::from_be_bytes(bytes[0..4].try_into()?);
        assert_eq!(usize::try_from(advertised)?, bytes.len() - 4);
        assert_eq!(read_request(&mut Cursor::new(bytes))?, request);
        Ok(())
    }

    #[test]
    fn control_request_round_trip_preserves_expected_revision() -> Result<(), Box<dyn Error>> {
        let request = Request::Control(ControlRequest::SetMode {
            expected_revision: 41,
            mode: Mode::Learning,
        });
        let mut bytes = Vec::new();
        write_request(&mut bytes, &request)?;
        assert_eq!(read_request(&mut Cursor::new(bytes))?, request);
        Ok(())
    }

    #[test]
    fn outbound_group_requests_round_trip_all_scopes_and_actions() -> Result<(), Box<dyn Error>> {
        let executable = ApplicationPath::new("/usr/bin/client")?;
        let cgroup = CgroupPath::new("/system.slice/client.service")?;
        for group in [
            OutboundGroupSelector::Cgroup {
                cgroup: cgroup.clone(),
                executable: None,
            },
            OutboundGroupSelector::Cgroup {
                cgroup,
                executable: Some(executable.clone()),
            },
            OutboundGroupSelector::Executable { executable },
            OutboundGroupSelector::Destination {
                peer_network: Some("203.0.113.27/24".parse()?),
            },
            OutboundGroupSelector::Destination { peer_network: None },
        ] {
            for action in [
                OutboundGroupAction::Delete,
                OutboundGroupAction::Accept,
                OutboundGroupAction::Reject,
                OutboundGroupAction::Drop,
                OutboundGroupAction::Enable,
                OutboundGroupAction::Disable,
            ] {
                let control = ControlRequest::ManageOutboundGroup {
                    expected_revision: 41,
                    group: group.clone(),
                    action,
                };
                assert_eq!(control.expected_revision(), 41);
                let request = Request::Control(control);
                let mut bytes = Vec::new();
                write_request(&mut bytes, &request)?;
                assert_eq!(read_request(&mut Cursor::new(bytes))?, request);
            }
        }
        Ok(())
    }

    #[test]
    fn outbound_group_selectors_reject_invalid_or_ambiguous_wire_values() {
        for payload in [
            r#"{"type":"executable","data":{"executable":"relative"}}"#,
            r#"{"type":"executable","data":{"executable":"/usr/../bin/client"}}"#,
            r#"{"type":"cgroup","data":{"cgroup":"/../service","executable":null}}"#,
            r#"{"type":"cgroup","data":{"cgroup":"/service","executable":"relative"}}"#,
            r#"{"type":"destination","data":{"peer_network":"invalid"}}"#,
            r#"{"type":"destination","data":{"peer_network":null,"executable":"/secret"}}"#,
            r#"{"type":"executable","data":{"executable":"/client","metadata_redacted":true}}"#,
            r#"{"type":"executable","data":{"executable":"/first","executable":"/second"}}"#,
        ] {
            assert!(serde_json::from_str::<OutboundGroupSelector>(payload).is_err());
        }
        assert!(serde_json::from_str::<OutboundGroupAction>(r#""allow""#).is_err());
    }

    #[test]
    fn outbound_group_membership_respects_priority_and_redaction() -> Result<(), Box<dyn Error>> {
        let mut rule = largest_rule()?;
        rule.spec.peer_network = Some("203.0.113.27/24".parse()?);
        let executable = ApplicationPath::new("/usr/bin/client")?;
        let cgroup = CgroupPath::new("/system.slice/client.service")?;
        let application = rule
            .spec
            .application
            .as_mut()
            .ok_or("missing application")?;
        application.executable = Some(executable.clone());
        application.cgroup = Some(cgroup.clone());
        let root = OutboundGroupSelector::Cgroup {
            cgroup: cgroup.clone(),
            executable: None,
        };
        let child = OutboundGroupSelector::Cgroup {
            cgroup,
            executable: Some(executable.clone()),
        };
        let fallback = OutboundGroupSelector::Executable { executable };
        let destination = OutboundGroupSelector::Destination {
            peer_network: Some("203.0.113.0/24".parse()?),
        };
        let any_destination = OutboundGroupSelector::Destination { peer_network: None };
        assert!(root.matches(&rule));
        assert!(child.matches(&rule));
        assert!(!fallback.matches(&rule));
        assert!(!destination.matches(&rule));

        let mut sibling = rule.clone();
        sibling
            .spec
            .application
            .as_mut()
            .ok_or("missing application")?
            .executable = Some(ApplicationPath::new("/usr/bin/other")?);
        assert!(root.matches(&sibling));
        assert!(!child.matches(&sibling));

        let mut fallback_rule = rule.clone();
        fallback_rule
            .spec
            .application
            .as_mut()
            .ok_or("missing application")?
            .cgroup = None;
        assert!(!root.matches(&fallback_rule));
        assert!(!child.matches(&fallback_rule));
        assert!(fallback.matches(&fallback_rule));
        assert!(!destination.matches(&fallback_rule));

        let redacted = rule.redacted_for_observer();
        assert!(!root.matches(&redacted));
        assert!(!child.matches(&redacted));
        assert!(!fallback.matches(&redacted));
        assert!(destination.matches(&redacted));
        assert!(
            !OutboundGroupSelector::Executable {
                executable: ApplicationPath::new("/redacted")?,
            }
            .matches(&redacted)
        );

        rule.spec.application = None;
        assert!(destination.matches(&rule));
        assert!(!any_destination.matches(&rule));
        rule.spec.peer_network = None;
        assert!(!destination.matches(&rule));
        assert!(any_destination.matches(&rule));
        rule.spec.direction = Direction::Inbound;
        for selector in [&root, &child, &fallback, &destination, &any_destination] {
            assert!(!selector.matches(&rule));
        }
        Ok(())
    }

    #[test]
    fn status_round_trip_preserves_backend_and_nfqueue_counters() -> Result<(), Box<dyn Error>> {
        let nfqueue = NfqueueCounters {
            queue_overflow: 1,
            attribution_timeout: 2,
            terminal_queue_error: 3,
            denied: 4,
        };
        let response = Response::Status {
            revision: 7,
            mode: Mode::Learning,
            rule_count: 3,
            backend: FirewallBackendKind::Nftables,
            nfqueue,
        };
        let mut bytes = Vec::new();
        write_response(&mut bytes, &response)?;
        assert_eq!(read_response(&mut Cursor::new(bytes))?, response);
        Ok(())
    }

    #[test]
    fn status_v2_round_trip_preserves_runtime_compatibility() -> Result<(), Box<dyn Error>> {
        let request = Request::Read(ReadRequest::StatusV2);
        let mut request_bytes = Vec::new();
        write_request(&mut request_bytes, &request)?;
        assert_eq!(read_request(&mut Cursor::new(request_bytes))?, request);

        let response = Response::StatusV2 {
            revision: 11,
            mode: Mode::Enforcing,
            rule_count: 4,
            backend: FirewallBackendKind::Nftables,
            nfqueue: NfqueueCounters::default(),
            runtime_compatibility: RuntimeCompatibility {
                level: CompatibilityLevel::ConntrackHybrid,
                reason: CompatibilityReason::ApplicationTcp,
            },
        };
        let mut response_bytes = Vec::new();
        write_response(&mut response_bytes, &response)?;
        assert_eq!(read_response(&mut Cursor::new(response_bytes))?, response);
        Ok(())
    }

    #[test]
    fn status_v2_compatibility_defaults_unknown_but_rejects_unknown_fields()
    -> Result<(), Box<dyn Error>> {
        let payload = br#"{"type":"status_v2","data":{"revision":7,"mode":"learning","rule_count":3,"runtime_compatibility":{}}}"#;
        let mut bytes = Vec::from(u32::try_from(payload.len())?.to_be_bytes());
        bytes.extend_from_slice(payload);
        assert_eq!(
            read_response(&mut Cursor::new(bytes))?,
            Response::StatusV2 {
                revision: 7,
                mode: Mode::Learning,
                rule_count: 3,
                backend: FirewallBackendKind::Unknown,
                nfqueue: NfqueueCounters::default(),
                runtime_compatibility: RuntimeCompatibility::default(),
            }
        );

        let payload = br#"{"type":"status_v2","data":{"revision":7,"mode":"learning","rule_count":3,"runtime_compatibility":{"unexpected":true}}}"#;
        let mut bytes = Vec::from(u32::try_from(payload.len())?.to_be_bytes());
        bytes.extend_from_slice(payload);
        assert!(matches!(
            read_response(&mut Cursor::new(bytes)),
            Err(FrameError::Decode { .. })
        ));
        Ok(())
    }

    #[test]
    fn runtime_compatibility_rejects_partial_and_contradictory_evidence() {
        let valid_pairs = [
            ("unknown", "unknown"),
            ("kernel_native", "block_all"),
            ("kernel_native", "emergency_block_all"),
            ("kernel_native", "network_only"),
            ("conntrack_hybrid", "application_tcp"),
            ("nfqueue", "learning"),
            ("nfqueue", "application_per_packet"),
        ];
        let levels = ["unknown", "kernel_native", "conntrack_hybrid", "nfqueue"];
        let reasons = [
            "unknown",
            "block_all",
            "emergency_block_all",
            "network_only",
            "learning",
            "application_tcp",
            "application_per_packet",
        ];

        assert!(serde_json::from_value::<RuntimeCompatibility>(serde_json::json!({})).is_ok());
        for level in levels {
            assert!(
                serde_json::from_value::<RuntimeCompatibility>(
                    serde_json::json!({ "level": level })
                )
                .is_err(),
                "partially populated level {level} must be rejected"
            );
            for reason in reasons {
                let decoded = serde_json::from_value::<RuntimeCompatibility>(serde_json::json!({
                    "level": level,
                    "reason": reason,
                }));
                let expected_valid = valid_pairs.contains(&(level, reason));
                assert_eq!(
                    decoded.is_ok(),
                    expected_valid,
                    "unexpected consistency result for {level}/{reason}"
                );
            }
        }
        for reason in reasons {
            assert!(
                serde_json::from_value::<RuntimeCompatibility>(
                    serde_json::json!({ "reason": reason })
                )
                .is_err(),
                "partially populated reason {reason} must be rejected"
            );
        }

        assert!(
            serde_json::to_value(RuntimeCompatibility {
                level: CompatibilityLevel::KernelNative,
                reason: CompatibilityReason::ApplicationPerPacket,
            })
            .is_err(),
            "an in-process producer must not serialize contradictory evidence"
        );
    }

    #[test]
    fn runtime_compatibility_validates_the_surrounding_status() {
        let network_only = RuntimeCompatibility {
            level: CompatibilityLevel::KernelNative,
            reason: CompatibilityReason::NetworkOnly,
        };
        assert!(network_only.is_consistent_with(Mode::Enforcing, FirewallBackendKind::Nftables));
        assert!(!network_only.is_consistent_with(Mode::Learning, FirewallBackendKind::Nftables));
        assert!(!network_only.is_consistent_with(Mode::Enforcing, FirewallBackendKind::Unknown));
        assert!(
            RuntimeCompatibility {
                level: CompatibilityLevel::KernelNative,
                reason: CompatibilityReason::EmergencyBlockAll,
            }
            .is_consistent_with(Mode::BlockAll, FirewallBackendKind::Iptables)
        );
        assert!(
            RuntimeCompatibility::default()
                .is_consistent_with(Mode::Learning, FirewallBackendKind::Unknown)
        );
        assert!(
            !RuntimeCompatibility::default()
                .is_consistent_with(Mode::Learning, FirewallBackendKind::Iptables)
        );
    }

    #[test]
    fn legacy_status_wire_shape_does_not_gain_v2_fields() -> Result<(), Box<dyn Error>> {
        let response = Response::Status {
            revision: 7,
            mode: Mode::Learning,
            rule_count: 3,
            backend: FirewallBackendKind::Nftables,
            nfqueue: NfqueueCounters::default(),
        };
        let encoded = serde_json::to_value(response)?;
        assert_eq!(encoded["type"], "status");
        assert!(encoded["data"].get("runtime_compatibility").is_none());
        Ok(())
    }

    #[test]
    fn status_without_backend_is_safely_reported_as_unknown() -> Result<(), Box<dyn Error>> {
        let payload =
            br#"{"type":"status","data":{"revision":7,"mode":"learning","rule_count":3}}"#;
        let mut bytes = Vec::from(u32::try_from(payload.len())?.to_be_bytes());
        bytes.extend_from_slice(payload);
        assert_eq!(
            read_response(&mut Cursor::new(bytes))?,
            Response::Status {
                revision: 7,
                mode: Mode::Learning,
                rule_count: 3,
                backend: FirewallBackendKind::Unknown,
                nfqueue: NfqueueCounters::default(),
            }
        );
        Ok(())
    }

    #[test]
    fn omitted_nested_nfqueue_fields_default_to_zero() -> Result<(), Box<dyn Error>> {
        let payload = br#"{"type":"status","data":{"revision":7,"mode":"learning","rule_count":3,"nfqueue":{"queue_overflow":9}}}"#;
        let mut bytes = Vec::from(u32::try_from(payload.len())?.to_be_bytes());
        bytes.extend_from_slice(payload);
        assert_eq!(
            read_response(&mut Cursor::new(bytes))?,
            Response::Status {
                revision: 7,
                mode: Mode::Learning,
                rule_count: 3,
                backend: FirewallBackendKind::Unknown,
                nfqueue: NfqueueCounters {
                    queue_overflow: 9,
                    ..NfqueueCounters::default()
                },
            }
        );
        Ok(())
    }

    #[test]
    fn oversized_advertised_frame_is_rejected_before_payload_read() -> Result<(), Box<dyn Error>> {
        let advertised = u32::try_from(MAX_FRAME_SIZE + 1)?;
        let bytes = advertised.to_be_bytes();
        let error = read_request(&mut Cursor::new(bytes));
        assert!(matches!(
            error,
            Err(FrameError::FrameTooLarge {
                actual,
                maximum: MAX_FRAME_SIZE
            }) if actual == MAX_FRAME_SIZE + 1
        ));
        Ok(())
    }

    #[test]
    fn zero_length_frame_is_rejected() {
        let error = read_request(&mut Cursor::new(0_u32.to_be_bytes()));
        assert!(matches!(error, Err(FrameError::EmptyFrame)));
    }

    #[test]
    fn malformed_json_is_rejected() -> Result<(), Box<dyn Error>> {
        let payload = b"not json";
        let mut bytes = Vec::from(u32::try_from(payload.len())?.to_be_bytes());
        bytes.extend_from_slice(payload);
        let error = read_request(&mut Cursor::new(bytes));
        assert!(matches!(error, Err(FrameError::Decode { .. })));
        Ok(())
    }

    #[test]
    fn oversized_outbound_message_writes_nothing() {
        let value = "x".repeat(MAX_FRAME_SIZE);
        let mut bytes = Vec::new();
        assert!(matches!(
            write_frame(&mut bytes, &value),
            Err(FrameError::FrameTooLarge { .. })
        ));
        assert!(bytes.is_empty());
    }

    #[test]
    fn page_limit_is_always_clamped_to_safe_bounds() {
        assert_eq!(clamp_page_limit(0), 1);
        assert_eq!(clamp_page_limit(1), 1);
        assert_eq!(clamp_page_limit(MAX_RULES_PER_PAGE), MAX_RULES_PER_PAGE);
        assert_eq!(
            clamp_page_limit(MAX_RULES_PER_PAGE.saturating_add(1)),
            MAX_RULES_PER_PAGE
        );
        assert_eq!(clamp_page_limit(u16::MAX), MAX_RULES_PER_PAGE);
    }

    #[test]
    fn one_largest_rule_fits_one_bounded_frame() -> Result<(), Box<dyn Error>> {
        let rule = largest_rule()?;
        let response = Response::RulesPage {
            revision: 7,
            rules: vec![rule],
            next_after: Some(Uuid::new_v4()),
        };
        let mut bytes = Vec::new();
        write_response(&mut bytes, &response)?;
        assert!(bytes.len() <= MAX_FRAME_SIZE + 4);
        Ok(())
    }

    #[test]
    fn maximum_control_argument_expansion_fits_request_and_response_frames()
    -> Result<(), Box<dyn Error>> {
        let mut rule = largest_rule()?;
        rule.spec
            .application
            .as_mut()
            .ok_or("application selector missing")?
            .command_line = Some(CommandLineSelector::new(
            CommandLineMatch::Exact,
            vec![CommandArgument::new(
                "\u{01}".repeat(MAX_COMMAND_LINE_BYTES - 1),
            )?],
        )?);
        rule.spec.validate()?;
        let request = Request::Control(ControlRequest::CreateRule {
            expected_revision: u64::MAX,
            rule: rule.spec.clone(),
        });
        let response = Response::RulesPage {
            revision: u64::MAX,
            rules: vec![rule],
            next_after: Some(Uuid::new_v4()),
        };
        let mut request_bytes = Vec::new();
        write_request(&mut request_bytes, &request)?;
        assert!(request_bytes.len() > MAX_COMMAND_LINE_BYTES * 6);
        assert!(request_bytes.len() <= MAX_FRAME_SIZE + 4);
        assert_eq!(read_request(&mut Cursor::new(request_bytes))?, request);
        let mut response_bytes = Vec::new();
        write_response(&mut response_bytes, &response)?;
        assert!(response_bytes.len() <= MAX_FRAME_SIZE + 4);
        assert_eq!(read_response(&mut Cursor::new(response_bytes))?, response);
        Ok(())
    }

    #[test]
    fn unknown_request_fields_are_rejected() -> Result<(), Box<dyn Error>> {
        let payload = br#"{"type":"read","data":{"type":"status","data":{"smuggled":true}}}"#;
        let mut bytes = Vec::from(u32::try_from(payload.len())?.to_be_bytes());
        bytes.extend_from_slice(payload);
        assert!(matches!(
            read_request(&mut Cursor::new(bytes)),
            Err(FrameError::Decode { .. })
        ));
        Ok(())
    }

    #[test]
    fn control_revision_must_be_present_numeric_and_unambiguous() -> Result<(), Box<dyn Error>> {
        for payload in [
            br#"{"type":"control","data":{"type":"set_mode","data":{"mode":"learning"}}}"#.as_slice(),
            br#"{"type":"control","data":{"type":"set_mode","data":{"expected_revision":"latest","mode":"learning"}}}"#.as_slice(),
            br#"{"type":"control","data":{"type":"set_mode","data":{"expected_revision":7,"mode":"learning","smuggled":true}}}"#.as_slice(),
        ] {
            let mut bytes = Vec::from(u32::try_from(payload.len())?.to_be_bytes());
            bytes.extend_from_slice(payload);
            assert!(matches!(
                read_request(&mut Cursor::new(bytes)),
                Err(FrameError::Decode { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn error_messages_are_bounded_and_terminal_safe() {
        let error = ProtocolError::new(
            ErrorCode::InvalidRequest,
            format!("bad\u{1b}[31m\n{}", "x".repeat(MAX_ERROR_MESSAGE_BYTES * 2)),
        );
        assert!(!error.message.chars().any(char::is_control));
        assert!(error.message.len() <= MAX_ERROR_MESSAGE_BYTES);

        let unsafe_json = br#"{"code":"internal","message":"bad\nterminal"}"#;
        assert!(serde_json::from_slice::<ProtocolError>(unsafe_json).is_err());
    }
}
