use ipnet::IpNet;
use openshield_core::{
    ApplicationPath, ApplicationSelector, CgroupPath, CommandArgument, CommandLineMatch,
    CommandLineSelector, Direction, Event, EventKind, ExecutableFileId, FirewallCounters,
    InterfaceName, MAX_APPLICATION_PATH_BYTES, MAX_CGROUP_PATH_BYTES, MAX_COMMAND_LINE_BYTES, Mode,
    PortRange, Rule, RuleAction, RuleName, RuleOrigin, RuleSpec, Snapshot, TransportProtocol,
};
use openshield_protocol::{ControlRequest, FirewallBackendKind, RuntimeCompatibility};
use std::borrow::Cow;
use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::i18n::I18n;

pub const MAX_VISIBLE_EVENTS: usize = 500;
const MAX_RULE_NAME_CHARS: usize = 128;
const MAX_NETWORK_CHARS: usize = 64;
const MAX_PORT_CHARS: usize = 11;
const MAX_INTERFACE_CHARS: usize = 15;
const MAX_UID_CHARS: usize = 10;
const MAX_ARGUMENTS_JSON_BYTES: usize = MAX_COMMAND_LINE_BYTES * 3;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum View {
    #[default]
    Status,
    Outbound,
    Inbound,
    Events,
    Help,
}

impl View {
    pub fn title(self, i18n: &I18n) -> &str {
        match self {
            Self::Status => i18n.tr("view.status"),
            Self::Outbound => i18n.tr("view.outbound"),
            Self::Inbound => i18n.tr("view.inbound"),
            Self::Events => i18n.tr("view.events"),
            Self::Help => i18n.tr("view.help"),
        }
    }

    pub const fn next(self) -> Self {
        match self {
            Self::Status => Self::Outbound,
            Self::Outbound => Self::Inbound,
            Self::Inbound => Self::Events,
            Self::Events => Self::Help,
            Self::Help => Self::Status,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Disconnected(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormField {
    Name,
    Action,
    Protocol,
    PeerNetwork,
    Port,
    Interface,
    Application,
    Executable,
    CommandMode,
    Arguments,
    Uid,
    Cgroup,
    Enabled,
}

impl FormField {
    const OUTBOUND: &'static [Self] = &[
        Self::Name,
        Self::Action,
        Self::Protocol,
        Self::PeerNetwork,
        Self::Port,
        Self::Interface,
        Self::Application,
        Self::Executable,
        Self::CommandMode,
        Self::Arguments,
        Self::Uid,
        Self::Cgroup,
        Self::Enabled,
    ];

    const INBOUND: &'static [Self] = &[
        Self::Name,
        Self::Protocol,
        Self::PeerNetwork,
        Self::Port,
        Self::Interface,
        Self::Enabled,
    ];
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CommandMode {
    #[default]
    Any,
    Exact,
    Prefix,
}

impl CommandMode {
    const fn cycle(self, reverse: bool) -> Self {
        match (self, reverse) {
            (Self::Any, false) | (Self::Prefix, true) => Self::Exact,
            (Self::Exact, false) | (Self::Any, true) => Self::Prefix,
            (Self::Prefix, false) | (Self::Exact, true) => Self::Any,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleForm {
    pub id: Option<Uuid>,
    pub active_field: FormField,
    pub name: String,
    direction: Direction,
    pub action: RuleAction,
    pub protocol: TransportProtocol,
    pub peer_network: String,
    pub port: String,
    pub interface: String,
    pub bind_application: bool,
    pub executable: String,
    pub command_mode: CommandMode,
    pub arguments: String,
    pub uid: String,
    pub cgroup: String,
    pub origin: RuleOrigin,
    pub enabled: bool,
    pub error: Option<String>,
    original_executable: Option<ApplicationPath>,
    original_executable_file: Option<ExecutableFileId>,
    direction_lock: Option<Direction>,
}

impl Default for RuleForm {
    fn default() -> Self {
        Self {
            id: None,
            active_field: FormField::Name,
            name: String::new(),
            direction: Direction::Outbound,
            action: RuleAction::Accept,
            protocol: TransportProtocol::Any,
            peer_network: String::new(),
            port: String::new(),
            interface: String::new(),
            bind_application: false,
            executable: String::new(),
            command_mode: CommandMode::Any,
            arguments: String::new(),
            uid: String::new(),
            cgroup: String::new(),
            origin: RuleOrigin::Manual,
            enabled: true,
            error: None,
            original_executable: None,
            original_executable_file: None,
            direction_lock: None,
        }
    }
}

impl RuleForm {
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    #[must_use]
    pub fn for_direction(direction: Direction) -> Self {
        Self {
            direction,
            direction_lock: Some(direction),
            ..Self::default()
        }
    }

    pub fn from_rule(rule: &Rule) -> Self {
        let application = rule.spec.application.as_ref();
        let command_line = application.and_then(|selector| selector.command_line.as_ref());
        let arguments = command_line.map_or_else(String::new, |selector| {
            let values: Vec<&str> = selector
                .arguments
                .iter()
                .map(CommandArgument::as_str)
                .collect();
            serde_json::to_string(&values).unwrap_or_default()
        });
        Self {
            id: Some(rule.id),
            active_field: FormField::Name,
            name: rule.spec.name.to_string(),
            direction: rule.spec.direction,
            action: rule.spec.action,
            protocol: rule.spec.protocol,
            peer_network: rule
                .spec
                .peer_network
                .as_ref()
                .map_or_else(String::new, ToString::to_string),
            port: rule.spec.port.map_or_else(String::new, |range| {
                if range.start() == range.end() {
                    range.start().to_string()
                } else {
                    format!("{}-{}", range.start(), range.end())
                }
            }),
            interface: rule
                .spec
                .interface
                .as_ref()
                .map_or_else(String::new, ToString::to_string),
            bind_application: application.is_some(),
            executable: application
                .and_then(|selector| selector.executable.as_ref())
                .map_or_else(String::new, ToString::to_string),
            command_mode: command_line.map_or(CommandMode::Any, |selector| match selector.kind {
                CommandLineMatch::Exact => CommandMode::Exact,
                CommandLineMatch::Prefix => CommandMode::Prefix,
            }),
            arguments,
            uid: application
                .and_then(|selector| selector.uid)
                .map_or_else(String::new, |uid| uid.to_string()),
            cgroup: application
                .and_then(|selector| selector.cgroup.as_ref())
                .map_or_else(String::new, ToString::to_string),
            origin: rule.spec.origin,
            enabled: rule.spec.enabled,
            error: None,
            original_executable: application.and_then(|selector| selector.executable.clone()),
            original_executable_file: application.and_then(|selector| selector.executable_file),
            direction_lock: Some(rule.spec.direction),
        }
    }

    pub fn move_next(&mut self) {
        self.move_field(false);
        self.error = None;
    }

    pub fn move_previous(&mut self) {
        self.move_field(true);
        self.error = None;
    }

    fn move_field(&mut self, reverse: bool) {
        let fields = if self.direction == Direction::Inbound {
            FormField::INBOUND
        } else {
            FormField::OUTBOUND
        };
        let position = fields
            .iter()
            .position(|field| *field == self.active_field)
            .unwrap_or(0);
        let next = if reverse {
            position.checked_sub(1).unwrap_or(fields.len() - 1)
        } else {
            (position + 1) % fields.len()
        };
        self.active_field = fields[next];
    }

    pub fn insert_char(&mut self, character: char) {
        let (value, limit) = match self.active_field {
            FormField::Name => (&mut self.name, MAX_RULE_NAME_CHARS),
            FormField::PeerNetwork => (&mut self.peer_network, MAX_NETWORK_CHARS),
            FormField::Port => (&mut self.port, MAX_PORT_CHARS),
            FormField::Interface => (&mut self.interface, MAX_INTERFACE_CHARS),
            FormField::Executable => (&mut self.executable, MAX_APPLICATION_PATH_BYTES),
            FormField::Arguments => (&mut self.arguments, MAX_ARGUMENTS_JSON_BYTES),
            FormField::Uid => {
                if character.is_ascii_digit() && self.uid.len() < MAX_UID_CHARS {
                    self.uid.push(character);
                    self.error = None;
                }
                return;
            }
            FormField::Cgroup => (&mut self.cgroup, MAX_CGROUP_PATH_BYTES),
            FormField::Protocol
            | FormField::Action
            | FormField::Application
            | FormField::CommandMode
            | FormField::Enabled => return,
        };

        if is_safe_form_character(character)
            && value.len().saturating_add(character.len_utf8()) <= limit
        {
            value.push(character);
            self.error = None;
        }
    }

    pub fn backspace(&mut self) {
        match self.active_field {
            FormField::Name => {
                self.name.pop();
            }
            FormField::PeerNetwork => {
                self.peer_network.pop();
            }
            FormField::Port => {
                self.port.pop();
            }
            FormField::Interface => {
                self.interface.pop();
            }
            FormField::Executable => {
                self.executable.pop();
            }
            FormField::Arguments => {
                self.arguments.pop();
            }
            FormField::Uid => {
                self.uid.pop();
            }
            FormField::Cgroup => {
                self.cgroup.pop();
            }
            FormField::Protocol
            | FormField::Action
            | FormField::Application
            | FormField::CommandMode
            | FormField::Enabled => return,
        }
        self.error = None;
    }

    pub fn cycle_choice(&mut self, reverse: bool) {
        match self.active_field {
            FormField::Action => {
                self.action = cycle_rule_action(self.action, reverse);
            }
            FormField::Protocol => {
                self.protocol = cycle_protocol(self.protocol, reverse);
            }
            FormField::Application => {
                self.bind_application = !self.bind_application;
                if !self.bind_application {
                    // Hidden selector fields must never survive this explicit
                    // switch and silently broaden a rule on save.
                    self.executable.clear();
                    self.command_mode = CommandMode::Any;
                    self.arguments.clear();
                    self.uid.clear();
                    self.cgroup.clear();
                    self.original_executable = None;
                    self.original_executable_file = None;
                }
            }
            FormField::CommandMode => {
                self.command_mode = self.command_mode.cycle(reverse);
            }
            FormField::Enabled => self.enabled = !self.enabled,
            FormField::Name
            | FormField::PeerNetwork
            | FormField::Port
            | FormField::Interface
            | FormField::Executable
            | FormField::Arguments
            | FormField::Uid
            | FormField::Cgroup => return,
        }
        self.error = None;
    }

    pub fn to_rule_spec(&self, i18n: &I18n) -> Result<RuleSpec, String> {
        if self
            .direction_lock
            .is_some_and(|direction| direction != self.direction)
        {
            return Err(i18n.format(
                "validation.invalid_rule",
                &[("error", i18n.tr("editor.field_direction"))],
            ));
        }
        let name = self.name.trim();
        if name.is_empty() {
            return Err(i18n.tr("validation.name_empty").to_owned());
        }

        let peer_network = if self.peer_network.trim().is_empty() {
            None
        } else {
            Some(parse_peer_network(self.peer_network.trim(), i18n)?)
        };

        let port = parse_port_range(self.port.trim(), i18n)?;
        if matches!(
            self.protocol,
            TransportProtocol::Icmp | TransportProtocol::IcmpV6
        ) && port.is_some()
        {
            return Err(i18n.tr("validation.icmp_port").to_owned());
        }

        let interface = if self.interface.trim().is_empty() {
            None
        } else {
            Some(InterfaceName::new(self.interface.trim()).map_err(|error| {
                i18n.format(
                    "validation.invalid_interface",
                    &[("error", error.to_string().as_str())],
                )
            })?)
        };

        let application = self.parse_application(i18n)?;

        let rule = RuleSpec {
            name: RuleName::new(name).map_err(|error| {
                i18n.format(
                    "validation.invalid_name",
                    &[("error", error.to_string().as_str())],
                )
            })?,
            direction: self.direction,
            action: self.action,
            protocol: self.protocol,
            peer_network,
            port,
            interface,
            application,
            origin: self.origin,
            enabled: self.enabled,
        };
        rule.validate().map_err(|error| {
            i18n.format(
                "validation.invalid_rule",
                &[("error", error.to_string().as_str())],
            )
        })?;
        Ok(rule)
    }

    fn parse_application(&self, i18n: &I18n) -> Result<Option<ApplicationSelector>, String> {
        if !self.bind_application {
            let has_hidden_selector = !self.executable.trim().is_empty()
                || self.command_mode != CommandMode::Any
                || !self.arguments.trim().is_empty()
                || !self.uid.trim().is_empty()
                || !self.cgroup.trim().is_empty()
                || self.original_executable.is_some()
                || self.original_executable_file.is_some();
            if has_hidden_selector {
                return Err(i18n.tr("validation.application_fields_disabled").to_owned());
            }
            return Ok(None);
        }
        if self.direction != Direction::Outbound {
            return Err(i18n.tr("validation.application_outbound").to_owned());
        }
        let executable = self.executable.trim();
        if executable.is_empty() {
            return Err(i18n.tr("validation.executable_required").to_owned());
        }
        let executable = ApplicationPath::new(executable).map_err(|error| {
            i18n.format(
                "validation.invalid_executable",
                &[("error", error.to_string().as_str())],
            )
        })?;
        let executable_file = (self.original_executable.as_ref() == Some(&executable))
            .then_some(self.original_executable_file)
            .flatten();
        let command_line = match self.command_mode {
            CommandMode::Any => {
                if !self.arguments.trim().is_empty() {
                    return Err(i18n.tr("validation.arguments_unused").to_owned());
                }
                None
            }
            CommandMode::Exact | CommandMode::Prefix => {
                let arguments = parse_command_arguments(self.arguments.trim(), i18n)?;
                let kind = if self.command_mode == CommandMode::Exact {
                    CommandLineMatch::Exact
                } else {
                    CommandLineMatch::Prefix
                };
                Some(CommandLineSelector::new(kind, arguments).map_err(|error| {
                    i18n.format(
                        "validation.invalid_arguments",
                        &[("error", error.to_string().as_str())],
                    )
                })?)
            }
        };
        let uid = if self.uid.trim().is_empty() {
            None
        } else {
            Some(
                self.uid
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| i18n.tr("validation.invalid_uid").to_owned())?,
            )
        };
        let cgroup = if self.cgroup.trim().is_empty() {
            None
        } else {
            Some(CgroupPath::new(self.cgroup.trim()).map_err(|error| {
                i18n.format(
                    "validation.invalid_cgroup",
                    &[("error", error.to_string().as_str())],
                )
            })?)
        };
        ApplicationSelector::new(Some(executable), executable_file, command_line, uid, cgroup)
            .map(Some)
            .map_err(|error| {
                i18n.format(
                    "validation.invalid_rule",
                    &[("error", error.to_string().as_str())],
                )
            })
    }
}

fn parse_command_arguments(value: &str, i18n: &I18n) -> Result<Vec<CommandArgument>, String> {
    let values = serde_json::from_str::<Vec<serde_json::Value>>(value)
        .map_err(|_| i18n.tr("validation.arguments_json").to_owned())?;
    values
        .into_iter()
        .map(|value| {
            let value = value
                .as_str()
                .ok_or_else(|| i18n.tr("validation.arguments_strings").to_owned())?;
            CommandArgument::new(value).map_err(|error| {
                i18n.format(
                    "validation.invalid_arguments",
                    &[("error", error.to_string().as_str())],
                )
            })
        })
        .collect()
}

fn is_safe_form_character(character: char) -> bool {
    !character.is_control()
        && !matches!(
            character,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
        )
}

fn parse_peer_network(value: &str, i18n: &I18n) -> Result<IpNet, String> {
    if let Ok(network) = value.parse::<IpNet>() {
        return Ok(network);
    }
    value.parse::<IpAddr>().map(IpNet::from).map_err(|error| {
        i18n.format(
            "validation.invalid_peer",
            &[("error", error.to_string().as_str())],
        )
    })
}

fn parse_port_range(value: &str, i18n: &I18n) -> Result<Option<PortRange>, String> {
    if value.is_empty() {
        return Ok(None);
    }

    let mut parts = value.split('-');
    let start = parts
        .next()
        .ok_or_else(|| i18n.tr("validation.port_missing").to_owned())?
        .parse::<u16>()
        .map_err(|_| i18n.tr("validation.port_number").to_owned())?;
    let end = match parts.next() {
        Some(value) => value
            .parse::<u16>()
            .map_err(|_| i18n.tr("validation.port_end_number").to_owned())?,
        None => start,
    };
    if parts.next().is_some() {
        return Err(i18n.tr("validation.port_format").to_owned());
    }

    PortRange::new(start, end).map(Some).map_err(|error| {
        i18n.format(
            "validation.invalid_port_range",
            &[("error", error.to_string().as_str())],
        )
    })
}

/// Stable, non-localized identity of an outbound rule group.
///
/// The variant order is the grouping priority. Command-line arguments and all
/// other application selectors intentionally remain member details and never
/// split an executable group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundGroupKey<'a> {
    Cgroup(Cow<'a, str>),
    Executable(Cow<'a, str>),
    Destination(Option<IpNet>),
}

impl<'a> OutboundGroupKey<'a> {
    #[must_use]
    pub fn from_rule(rule: &'a Rule) -> Option<Self> {
        if rule.spec.direction != Direction::Outbound {
            return None;
        }
        if let Some(application) = rule
            .spec
            .application
            .as_ref()
            .filter(|application| !application.metadata_redacted)
        {
            if let Some(cgroup) = &application.cgroup {
                return Some(Self::Cgroup(Cow::Borrowed(cgroup.as_str())));
            }
            if let Some(executable) = &application.executable {
                return Some(Self::Executable(Cow::Borrowed(executable.as_str())));
            }
        }
        Some(Self::Destination(
            rule.spec.peer_network.map(|network| network.trunc()),
        ))
    }

    const fn rank(&self) -> u8 {
        match self {
            Self::Cgroup(_) => 0,
            Self::Executable(_) => 1,
            Self::Destination(Some(_)) => 2,
            Self::Destination(None) => 3,
        }
    }

    fn to_owned_key(&self) -> OutboundGroupKey<'static> {
        match self {
            Self::Cgroup(value) => OutboundGroupKey::Cgroup(Cow::Owned(value.to_string())),
            Self::Executable(value) => OutboundGroupKey::Executable(Cow::Owned(value.to_string())),
            Self::Destination(network) => OutboundGroupKey::Destination(*network),
        }
    }

    fn same_identity(&self, other: &OutboundGroupKey<'_>) -> bool {
        match (self, other) {
            (Self::Cgroup(left), OutboundGroupKey::Cgroup(right))
            | (Self::Executable(left), OutboundGroupKey::Executable(right)) => left == right,
            (Self::Destination(left), OutboundGroupKey::Destination(right)) => left == right,
            _ => false,
        }
    }
}

impl Ord for OutboundGroupKey<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank()
            .cmp(&other.rank())
            .then_with(|| match (self, other) {
                (Self::Cgroup(left), Self::Cgroup(right))
                | (Self::Executable(left), Self::Executable(right)) => left.cmp(right),
                (Self::Destination(Some(left)), Self::Destination(Some(right))) => left.cmp(right),
                _ => Ordering::Equal,
            })
    }
}

impl PartialOrd for OutboundGroupKey<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
pub struct OutboundGroup<'a> {
    pub key: OutboundGroupKey<'a>,
    pub rules: Vec<&'a Rule>,
}

fn protocol_rank(protocol: TransportProtocol) -> u8 {
    match protocol {
        TransportProtocol::Any => 0,
        TransportProtocol::Tcp => 1,
        TransportProtocol::Udp => 2,
        TransportProtocol::Icmp => 3,
        TransportProtocol::IcmpV6 => 4,
    }
}

fn compare_rule_members(left: &Rule, right: &Rule) -> Ordering {
    left.spec
        .peer_network
        .cmp(&right.spec.peer_network)
        .then_with(|| protocol_rank(left.spec.protocol).cmp(&protocol_rank(right.spec.protocol)))
        .then_with(|| {
            left.spec
                .port
                .map(|port| (port.start(), port.end()))
                .cmp(&right.spec.port.map(|port| (port.start(), port.end())))
        })
        .then_with(|| {
            left.spec
                .interface
                .as_ref()
                .map(InterfaceName::as_str)
                .cmp(&right.spec.interface.as_ref().map(InterfaceName::as_str))
        })
        .then_with(|| left.spec.name.as_str().cmp(right.spec.name.as_str()))
        .then_with(|| left.id.cmp(&right.id))
}

fn compare_inbound_rules(left: &Rule, right: &Rule) -> Ordering {
    protocol_rank(left.spec.protocol)
        .cmp(&protocol_rank(right.spec.protocol))
        .then_with(|| {
            left.spec
                .port
                .map(|port| (port.start(), port.end()))
                .cmp(&right.spec.port.map(|port| (port.start(), port.end())))
        })
        .then_with(|| left.spec.peer_network.cmp(&right.spec.peer_network))
        .then_with(|| left.spec.name.as_str().cmp(right.spec.name.as_str()))
        .then_with(|| left.id.cmp(&right.id))
}

const fn cycle_protocol(protocol: TransportProtocol, reverse: bool) -> TransportProtocol {
    match (protocol, reverse) {
        (TransportProtocol::Any, false) | (TransportProtocol::Udp, true) => TransportProtocol::Tcp,
        (TransportProtocol::Tcp, false) | (TransportProtocol::Icmp, true) => TransportProtocol::Udp,
        (TransportProtocol::Udp, false) | (TransportProtocol::IcmpV6, true) => {
            TransportProtocol::Icmp
        }
        (TransportProtocol::Icmp, false) | (TransportProtocol::Any, true) => {
            TransportProtocol::IcmpV6
        }
        (TransportProtocol::IcmpV6, false) | (TransportProtocol::Tcp, true) => {
            TransportProtocol::Any
        }
    }
}

const fn cycle_rule_action(action: RuleAction, reverse: bool) -> RuleAction {
    match (action, reverse) {
        (RuleAction::Accept, false) | (RuleAction::Reject, true) => RuleAction::Drop,
        (RuleAction::Drop, false) | (RuleAction::Accept, true) => RuleAction::Reject,
        (RuleAction::Reject, false) | (RuleAction::Drop, true) => RuleAction::Accept,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Overlay {
    None,
    ModePicker { selected: Mode },
    ConfirmBlockAll,
    Editor(Box<RuleForm>),
    ConfirmDelete { id: Uuid, name: String },
    Message { title: String, body: String },
}

#[derive(Clone, Debug)]
pub struct App {
    pub i18n: I18n,
    pub view: View,
    pub connection: ConnectionState,
    pub telemetry: ConnectionState,
    pub snapshot: Option<Snapshot>,
    rule_ids: HashSet<Uuid>,
    pub backend: Option<FirewallBackendKind>,
    pub runtime_compatibility: RuntimeCompatibility,
    pub counters: Option<FirewallCounters>,
    pub events: VecDeque<Event>,
    selected_outbound_group: usize,
    selected_outbound_member: usize,
    selected_outbound_rule_id: Option<Uuid>,
    selected_outbound_group_key: Option<OutboundGroupKey<'static>>,
    selected_inbound_rule: usize,
    selected_inbound_rule_id: Option<Uuid>,
    outbound_details_scroll: Cell<u16>,
    inbound_details_scroll: Cell<u16>,
    pub overlay: Overlay,
    pub read_only: bool,
    pub should_quit: bool,
    pub notice: Option<String>,
    pub dropped_events: u64,
    pending_revision: Option<u64>,
    telemetry_connected_at: Option<Instant>,
    last_counters_at: Option<Instant>,
}

impl App {
    pub fn new(read_only: bool, i18n: I18n) -> Self {
        Self {
            i18n,
            view: View::Status,
            connection: ConnectionState::Connecting,
            telemetry: ConnectionState::Connecting,
            snapshot: None,
            rule_ids: HashSet::new(),
            backend: None,
            runtime_compatibility: RuntimeCompatibility::default(),
            counters: None,
            events: VecDeque::with_capacity(MAX_VISIBLE_EVENTS),
            selected_outbound_group: 0,
            selected_outbound_member: 0,
            selected_outbound_rule_id: None,
            selected_outbound_group_key: None,
            selected_inbound_rule: 0,
            selected_inbound_rule_id: None,
            outbound_details_scroll: Cell::new(0),
            inbound_details_scroll: Cell::new(0),
            overlay: Overlay::None,
            read_only,
            should_quit: false,
            notice: None,
            dropped_events: 0,
            pending_revision: None,
            telemetry_connected_at: None,
            last_counters_at: None,
        }
    }

    #[cfg(test)]
    pub fn set_snapshot(&mut self, snapshot: Snapshot) {
        self.set_observed_snapshot(
            snapshot,
            FirewallBackendKind::Unknown,
            RuntimeCompatibility::default(),
        );
    }

    pub fn set_observed_snapshot(
        &mut self,
        snapshot: Snapshot,
        backend: FirewallBackendKind,
        runtime_compatibility: RuntimeCompatibility,
    ) {
        if self
            .snapshot
            .as_ref()
            .is_some_and(|current| current.revision > snapshot.revision)
        {
            return;
        }
        self.rule_ids = snapshot.rules.iter().map(|rule| rule.id).collect();
        self.snapshot = Some(snapshot);
        self.backend = Some(backend);
        self.runtime_compatibility = runtime_compatibility;
        self.clamp_rule_selection();
    }

    #[cfg(test)]
    pub fn set_restarted_snapshot(&mut self, snapshot: Snapshot) {
        self.set_restarted_observed_snapshot(
            snapshot,
            FirewallBackendKind::Unknown,
            RuntimeCompatibility::default(),
        );
    }

    pub fn set_restarted_observed_snapshot(
        &mut self,
        snapshot: Snapshot,
        backend: FirewallBackendKind,
        runtime_compatibility: RuntimeCompatibility,
    ) {
        self.rule_ids = snapshot.rules.iter().map(|rule| rule.id).collect();
        self.snapshot = Some(snapshot);
        self.backend = Some(backend);
        self.runtime_compatibility = runtime_compatibility;
        self.counters = None;
        self.last_counters_at = None;
        self.events.clear();
        self.reset_rule_selections();
        self.clamp_rule_selection();
        self.overlay = Overlay::None;
        self.pending_revision = None;
        self.notice = Some(self.i18n.tr("notice.daemon_restarted").to_owned());
    }

    pub fn set_disconnected(&mut self, reason: String) {
        self.connection = ConnectionState::Disconnected(reason);
        self.snapshot = None;
        self.rule_ids.clear();
        self.backend = None;
        self.runtime_compatibility = RuntimeCompatibility::default();
        self.counters = None;
        self.last_counters_at = None;
        self.reset_rule_selections();
        self.pending_revision = None;
        if !matches!(self.overlay, Overlay::None | Overlay::Message { .. }) {
            self.overlay = Overlay::None;
            self.notice = Some(self.i18n.tr("notice.connection_lost").to_owned());
        }
    }

    #[cfg(test)]
    pub fn push_event(&mut self, event: Event) {
        if self.push_event_at(event, Instant::now()) {
            self.clamp_rule_selection();
        }
    }

    /// Applies one observer event without repeatedly rebuilding sorted rule
    /// views. The observer drain reconciles selection once after the burst.
    pub(crate) fn push_observer_event(&mut self, event: Event) -> bool {
        self.push_event_at(event, Instant::now())
    }

    pub(crate) fn reconcile_rule_selection(&mut self) {
        self.clamp_rule_selection();
    }

    pub fn set_telemetry_connected(&mut self) {
        self.set_telemetry_connected_at(Instant::now());
    }

    pub fn set_telemetry_disconnected(&mut self, reason: String) {
        self.telemetry = ConnectionState::Disconnected(reason);
        self.telemetry_connected_at = None;
    }

    #[must_use]
    pub fn counters_age(&self, now: Instant) -> Option<Duration> {
        self.last_counters_at
            .map(|received_at| now.saturating_duration_since(received_at))
    }

    #[must_use]
    pub fn telemetry_connection_age(&self, now: Instant) -> Option<Duration> {
        self.telemetry_connected_at
            .map(|connected_at| now.saturating_duration_since(connected_at))
    }

    fn set_telemetry_connected_at(&mut self, now: Instant) {
        if !matches!(self.telemetry, ConnectionState::Connected) {
            self.telemetry_connected_at = Some(now);
        }
        self.telemetry = ConnectionState::Connected;
    }

    fn push_event_at(&mut self, event: Event, received_at: Instant) -> bool {
        self.set_telemetry_connected_at(received_at);
        let mut policy_changed = false;
        let changes_policy = matches!(
            &event.kind,
            EventKind::ModeChanged { .. }
                | EventKind::RuleCreated { .. }
                | EventKind::RuleUpdated { .. }
                | EventKind::RuleDeleted { .. }
                | EventKind::RuleEnabledChanged { .. }
        );
        let record_event = if let EventKind::CountersUpdated { counters } = &event.kind {
            let values_changed = self.counters.as_ref() != Some(counters);
            self.counters = Some(counters.clone());
            self.last_counters_at = Some(received_at);
            values_changed
        } else {
            true
        };
        if let Some(snapshot) = &mut self.snapshot {
            if changes_policy && event.revision > snapshot.revision.saturating_add(1) {
                let first = snapshot.revision.saturating_add(1).to_string();
                let last = event.revision.saturating_sub(1).to_string();
                self.notice = Some(self.i18n.format(
                    "notice.revisions_skipped",
                    &[("first", first.as_str()), ("last", last.as_str())],
                ));
            }
            if changes_policy && event.revision > snapshot.revision {
                // Runtime compatibility is an attestation for one exact
                // policy. Only a structural event which advances that policy
                // invalidates it; delayed or duplicate events must not erase
                // a newer StatusV2 attestation.
                self.runtime_compatibility = RuntimeCompatibility::default();
                match &event.kind {
                    EventKind::ModeChanged { current, .. } => snapshot.mode = *current,
                    EventKind::RuleCreated { rule } => {
                        if self.rule_ids.insert(rule.id) {
                            snapshot.rules.push(rule.clone());
                        }
                    }
                    EventKind::RuleUpdated { rule } | EventKind::RuleEnabledChanged { rule } => {
                        if let Some(current) = snapshot
                            .rules
                            .iter_mut()
                            .find(|current| current.id == rule.id)
                        {
                            *current = rule.clone();
                        }
                    }
                    EventKind::RuleDeleted { rule } => {
                        self.rule_ids.remove(&rule.id);
                        snapshot.rules.retain(|current| current.id != rule.id);
                    }
                    EventKind::CountersUpdated { .. } => {}
                }
                snapshot.revision = event.revision;
                policy_changed = true;
            }
        }
        if record_event {
            if self.events.len() == MAX_VISIBLE_EVENTS {
                self.events.pop_front();
            }
            self.events.push_back(event);
        }
        policy_changed
    }

    pub fn select_next_rule(&mut self) {
        match self.view {
            View::Outbound => self.select_outbound_group(false),
            View::Inbound => self.select_inbound_rule(false),
            View::Status | View::Events | View::Help => {}
        }
    }

    pub fn select_previous_rule(&mut self) {
        match self.view {
            View::Outbound => self.select_outbound_group(true),
            View::Inbound => self.select_inbound_rule(true),
            View::Status | View::Events | View::Help => {}
        }
    }

    pub fn select_next_group_member(&mut self) {
        self.select_outbound_member(false);
    }

    pub fn select_previous_group_member(&mut self) {
        self.select_outbound_member(true);
    }

    pub fn scroll_rule_details(&self, reverse: bool) {
        let scroll = match self.view {
            View::Outbound => &self.outbound_details_scroll,
            View::Inbound => &self.inbound_details_scroll,
            View::Status | View::Events | View::Help => return,
        };
        let current = scroll.get();
        scroll.set(if reverse {
            current.saturating_sub(3)
        } else {
            current.saturating_add(3)
        });
    }

    #[must_use]
    pub fn clamp_rule_details_scroll(&self, maximum: usize) -> u16 {
        let scroll = match self.view {
            View::Outbound => &self.outbound_details_scroll,
            View::Inbound => &self.inbound_details_scroll,
            View::Status | View::Events | View::Help => return 0,
        };
        let maximum = u16::try_from(maximum).unwrap_or(u16::MAX);
        let clamped = scroll.get().min(maximum);
        scroll.set(clamped);
        clamped
    }

    pub fn open_mode_picker(&mut self) {
        if !self.require_write_access() {
            return;
        }
        let Some(snapshot) = self.snapshot.as_ref() else {
            self.notice = Some(self.i18n.tr("notice.wait_snapshot").to_owned());
            return;
        };
        let selected = snapshot.mode;
        self.pending_revision = Some(snapshot.revision);
        self.overlay = Overlay::ModePicker { selected };
    }

    pub fn request_mode(&mut self, mode: Mode) -> Option<ControlRequest> {
        if !self.require_write_access() {
            return None;
        }
        if !matches!(self.overlay, Overlay::ModePicker { .. }) {
            return None;
        }
        let Some(expected_revision) = self.pending_revision else {
            self.notice = Some(self.i18n.tr("notice.base_revision_missing").to_owned());
            self.overlay = Overlay::None;
            return None;
        };
        if mode == Mode::BlockAll {
            self.overlay = Overlay::ConfirmBlockAll;
            None
        } else {
            self.overlay = Overlay::None;
            self.pending_revision = None;
            Some(ControlRequest::SetMode {
                expected_revision,
                mode,
            })
        }
    }

    pub fn confirm_block_all(&mut self, confirmed: bool) -> Option<ControlRequest> {
        if !matches!(self.overlay, Overlay::ConfirmBlockAll) {
            return None;
        }
        self.overlay = Overlay::None;
        let expected_revision = self.pending_revision.take();
        if confirmed && expected_revision.is_none() {
            self.notice = Some(self.i18n.tr("notice.base_revision_missing").to_owned());
        }
        expected_revision
            .filter(|_| confirmed)
            .map(|expected_revision| ControlRequest::SetMode {
                expected_revision,
                mode: Mode::BlockAll,
            })
    }

    pub fn open_create_rule(&mut self) {
        if !self.require_write_access() {
            return;
        }
        let Some(direction) = self.active_rule_direction() else {
            self.notice = Some(self.i18n.tr("notice.no_rule_selected").to_owned());
            return;
        };
        let Some(snapshot) = self.snapshot.as_ref() else {
            self.notice = Some(self.i18n.tr("notice.wait_snapshot").to_owned());
            return;
        };
        self.pending_revision = Some(snapshot.revision);
        self.overlay = Overlay::Editor(Box::new(RuleForm::for_direction(direction)));
    }

    pub fn open_edit_rule(&mut self) {
        if !self.require_write_access() {
            return;
        }
        let Some(snapshot) = self.snapshot.as_ref() else {
            self.notice = Some(self.i18n.tr("notice.wait_snapshot").to_owned());
            return;
        };
        let Some(rule) = self.selected_rule().cloned() else {
            self.notice = Some(self.i18n.tr("notice.no_rule_selected").to_owned());
            return;
        };
        self.pending_revision = Some(snapshot.revision);
        self.overlay = Overlay::Editor(Box::new(RuleForm::from_rule(&rule)));
    }

    pub fn submit_editor(&mut self) -> Option<ControlRequest> {
        let Some(expected_revision) = self.pending_revision else {
            self.overlay = Overlay::None;
            self.notice = Some(self.i18n.tr("notice.base_revision_missing").to_owned());
            return None;
        };
        let Overlay::Editor(form) = &mut self.overlay else {
            return None;
        };
        match form.to_rule_spec(&self.i18n) {
            Ok(rule) => {
                let request = if let Some(id) = form.id {
                    ControlRequest::UpdateRule {
                        expected_revision,
                        id,
                        rule,
                    }
                } else {
                    ControlRequest::CreateRule {
                        expected_revision,
                        rule,
                    }
                };
                self.overlay = Overlay::None;
                self.pending_revision = None;
                Some(request)
            }
            Err(error) => {
                form.error = Some(error);
                None
            }
        }
    }

    pub fn open_delete_confirmation(&mut self) {
        if !self.require_write_access() {
            return;
        }
        let Some(snapshot) = self.snapshot.as_ref() else {
            self.notice = Some(self.i18n.tr("notice.wait_snapshot").to_owned());
            return;
        };
        let Some((id, name)) = self
            .selected_rule()
            .map(|rule| (rule.id, rule.spec.name.to_string()))
        else {
            self.notice = Some(self.i18n.tr("notice.no_rule_selected").to_owned());
            return;
        };
        self.pending_revision = Some(snapshot.revision);
        self.overlay = Overlay::ConfirmDelete { id, name };
    }

    pub fn confirm_delete(&mut self, confirmed: bool) -> Option<ControlRequest> {
        let Overlay::ConfirmDelete { id, .. } = &self.overlay else {
            return None;
        };
        let id = *id;
        self.overlay = Overlay::None;
        let expected_revision = self.pending_revision.take();
        if confirmed && expected_revision.is_none() {
            self.notice = Some(self.i18n.tr("notice.base_revision_missing").to_owned());
        }
        expected_revision
            .filter(|_| confirmed)
            .map(|expected_revision| ControlRequest::DeleteRule {
                expected_revision,
                id,
            })
    }

    pub fn toggle_selected_rule(&mut self) -> Option<ControlRequest> {
        if !self.require_write_access() {
            return None;
        }
        let snapshot = self.snapshot.as_ref()?;
        let rule = self.selected_rule()?;
        Some(ControlRequest::SetRuleEnabled {
            expected_revision: snapshot.revision,
            id: rule.id,
            enabled: !rule.spec.enabled,
        })
    }

    pub fn close_overlay(&mut self) {
        self.overlay = Overlay::None;
        self.pending_revision = None;
    }

    fn require_write_access(&mut self) -> bool {
        if self.read_only {
            self.notice = Some(self.i18n.tr("notice.read_only").to_owned());
            false
        } else {
            true
        }
    }

    #[must_use]
    pub fn outbound_groups(&self) -> Vec<OutboundGroup<'_>> {
        let mut groups = BTreeMap::<OutboundGroupKey<'_>, Vec<&Rule>>::new();
        if let Some(snapshot) = &self.snapshot {
            for rule in &snapshot.rules {
                if let Some(key) = OutboundGroupKey::from_rule(rule) {
                    groups.entry(key).or_default().push(rule);
                }
            }
        }
        groups
            .into_iter()
            .map(|(key, mut rules)| {
                rules.sort_unstable_by(|left, right| compare_rule_members(left, right));
                OutboundGroup { key, rules }
            })
            .collect()
    }

    #[must_use]
    pub fn inbound_rules(&self) -> Vec<&Rule> {
        let mut rules = self.snapshot.as_ref().map_or_else(Vec::new, |snapshot| {
            snapshot
                .rules
                .iter()
                .filter(|rule| rule.spec.direction == Direction::Inbound)
                .collect::<Vec<_>>()
        });
        rules.sort_unstable_by(|left, right| compare_inbound_rules(left, right));
        rules
    }

    #[must_use]
    pub const fn selected_outbound_group_index(&self) -> usize {
        self.selected_outbound_group
    }

    #[must_use]
    pub const fn selected_outbound_member_index(&self) -> usize {
        self.selected_outbound_member
    }

    #[must_use]
    pub const fn selected_inbound_rule_index(&self) -> usize {
        self.selected_inbound_rule
    }

    #[must_use]
    pub fn selected_rule(&self) -> Option<&Rule> {
        let selected_id = match self.view {
            View::Outbound => self.selected_outbound_rule_id,
            View::Inbound => self.selected_inbound_rule_id,
            View::Status | View::Events | View::Help => None,
        }?;
        self.snapshot
            .as_ref()?
            .rules
            .iter()
            .find(|rule| rule.id == selected_id)
    }

    const fn active_rule_direction(&self) -> Option<Direction> {
        match self.view {
            View::Outbound => Some(Direction::Outbound),
            View::Inbound => Some(Direction::Inbound),
            View::Status | View::Events | View::Help => None,
        }
    }

    fn select_outbound_group(&mut self, reverse: bool) {
        let target = {
            let groups = self.outbound_groups();
            if groups.is_empty() {
                None
            } else {
                let index = if reverse {
                    self.selected_outbound_group.saturating_sub(1)
                } else {
                    (self.selected_outbound_group + 1).min(groups.len() - 1)
                };
                groups[index]
                    .rules
                    .first()
                    .map(|rule| (index, groups[index].key.to_owned_key(), rule.id))
            }
        };
        if let Some((index, key, id)) = target {
            if self.selected_outbound_rule_id != Some(id) {
                self.outbound_details_scroll.set(0);
            }
            self.selected_outbound_group = index;
            self.selected_outbound_member = 0;
            self.selected_outbound_group_key = Some(key);
            self.selected_outbound_rule_id = Some(id);
        }
    }

    fn select_outbound_member(&mut self, reverse: bool) {
        let target = {
            let groups = self.outbound_groups();
            groups.get(self.selected_outbound_group).and_then(|group| {
                if group.rules.is_empty() {
                    None
                } else {
                    let index = if reverse {
                        self.selected_outbound_member.saturating_sub(1)
                    } else {
                        (self.selected_outbound_member + 1).min(group.rules.len() - 1)
                    };
                    Some((index, group.rules[index].id))
                }
            })
        };
        if let Some((index, id)) = target {
            if self.selected_outbound_rule_id != Some(id) {
                self.outbound_details_scroll.set(0);
            }
            self.selected_outbound_member = index;
            self.selected_outbound_rule_id = Some(id);
        }
    }

    fn select_inbound_rule(&mut self, reverse: bool) {
        let target = {
            let rules = self.inbound_rules();
            if rules.is_empty() {
                None
            } else {
                let index = if reverse {
                    self.selected_inbound_rule.saturating_sub(1)
                } else {
                    (self.selected_inbound_rule + 1).min(rules.len() - 1)
                };
                Some((index, rules[index].id))
            }
        };
        if let Some((index, id)) = target {
            if self.selected_inbound_rule_id != Some(id) {
                self.inbound_details_scroll.set(0);
            }
            self.selected_inbound_rule = index;
            self.selected_inbound_rule_id = Some(id);
        }
    }

    fn reset_rule_selections(&mut self) {
        self.selected_outbound_group = 0;
        self.selected_outbound_member = 0;
        self.selected_outbound_rule_id = None;
        self.selected_outbound_group_key = None;
        self.selected_inbound_rule = 0;
        self.selected_inbound_rule_id = None;
        self.outbound_details_scroll.set(0);
        self.inbound_details_scroll.set(0);
    }

    fn clamp_rule_selection(&mut self) {
        let selected_id = self.selected_outbound_rule_id;
        let selected_key = self.selected_outbound_group_key.clone();
        let group_hint = self.selected_outbound_group;
        let member_hint = self.selected_outbound_member;
        let outbound = {
            let groups = self.outbound_groups();
            if groups.is_empty() {
                None
            } else {
                let selected_position = selected_id.and_then(|id| {
                    groups.iter().enumerate().find_map(|(group_index, group)| {
                        group
                            .rules
                            .iter()
                            .position(|rule| rule.id == id)
                            .map(|member_index| (group_index, member_index))
                    })
                });
                let (group_index, member_index) = selected_position.unwrap_or_else(|| {
                    let group_index = selected_key
                        .as_ref()
                        .and_then(|key| {
                            groups
                                .iter()
                                .position(|group| key.same_identity(&group.key))
                        })
                        .unwrap_or_else(|| group_hint.min(groups.len() - 1));
                    let member_index = member_hint.min(groups[group_index].rules.len() - 1);
                    (group_index, member_index)
                });
                Some((
                    group_index,
                    member_index,
                    groups[group_index].key.to_owned_key(),
                    groups[group_index].rules[member_index].id,
                ))
            }
        };
        if let Some((group, member, key, id)) = outbound {
            if self.selected_outbound_rule_id != Some(id) {
                self.outbound_details_scroll.set(0);
            }
            self.selected_outbound_group = group;
            self.selected_outbound_member = member;
            self.selected_outbound_group_key = Some(key);
            self.selected_outbound_rule_id = Some(id);
        } else {
            self.selected_outbound_group = 0;
            self.selected_outbound_member = 0;
            self.selected_outbound_group_key = None;
            self.selected_outbound_rule_id = None;
        }

        let selected_id = self.selected_inbound_rule_id;
        let inbound_hint = self.selected_inbound_rule;
        let inbound = {
            let rules = self.inbound_rules();
            if rules.is_empty() {
                None
            } else {
                let index = selected_id
                    .and_then(|id| rules.iter().position(|rule| rule.id == id))
                    .unwrap_or_else(|| inbound_hint.min(rules.len() - 1));
                Some((index, rules[index].id))
            }
        };
        if let Some((index, id)) = inbound {
            if self.selected_inbound_rule_id != Some(id) {
                self.inbound_details_scroll.set(0);
            }
            self.selected_inbound_rule = index;
            self.selected_inbound_rule_id = Some(id);
        } else {
            self.selected_inbound_rule = 0;
            self.selected_inbound_rule_id = None;
        }
    }
}

pub fn peer_label(rule: &Rule, i18n: &I18n) -> String {
    rule.spec
        .peer_network
        .as_ref()
        .map_or_else(|| i18n.tr("common.any").to_owned(), ToString::to_string)
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use openshield_core::FirewallCounters;
    use openshield_protocol::{CompatibilityLevel, CompatibilityReason};

    use super::*;

    #[test]
    fn unprivileged_state_rejects_every_mutation_entry_point() {
        let mut app = App::new(true, I18n::test_english());

        app.open_mode_picker();
        app.open_create_rule();

        assert_eq!(app.overlay, Overlay::None);
        assert!(app.request_mode(Mode::Learning).is_none());
        assert!(app.toggle_selected_rule().is_none());
        assert!(
            app.notice
                .as_deref()
                .is_some_and(|notice| notice.contains("root"))
        );
    }

    #[test]
    fn block_all_requires_explicit_confirmation() {
        let mut app = App::new(false, I18n::test_english());
        app.set_snapshot(Snapshot {
            revision: 7,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: Vec::new(),
        });

        app.open_mode_picker();
        assert!(app.request_mode(Mode::BlockAll).is_none());
        assert_eq!(app.overlay, Overlay::ConfirmBlockAll);
        assert!(app.confirm_block_all(false).is_none());

        app.open_mode_picker();
        assert!(app.request_mode(Mode::BlockAll).is_none());
        assert_eq!(
            app.confirm_block_all(true),
            Some(ControlRequest::SetMode {
                expected_revision: 7,
                mode: Mode::BlockAll
            })
        );
    }

    #[test]
    fn form_accepts_inbound_allow_rule() {
        let form = RuleForm {
            name: "SSH из локальной сети".to_owned(),
            direction: Direction::Inbound,
            protocol: TransportProtocol::Tcp,
            peer_network: "192.168.1.0/24".to_owned(),
            port: "22".to_owned(),
            interface: "eth0".to_owned(),
            ..RuleForm::default()
        };

        let result = form.to_rule_spec(&I18n::test_english());
        assert!(result.is_ok(), "{result:?}");
        if let Ok(rule) = result {
            assert_eq!(rule.direction, Direction::Inbound);
            assert_eq!(rule.protocol, TransportProtocol::Tcp);
            assert!(rule.port.is_some());
        }
    }

    #[test]
    fn outbound_action_and_enabled_state_are_independent() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut form = RuleForm {
            name: "diagnostic deny".to_owned(),
            active_field: FormField::Action,
            protocol: TransportProtocol::Tcp,
            enabled: false,
            ..RuleForm::default()
        };

        form.cycle_choice(false);
        assert_eq!(form.action, RuleAction::Drop);
        assert!(!form.enabled);
        form.cycle_choice(false);
        assert_eq!(form.action, RuleAction::Reject);
        assert!(!form.enabled);
        form.cycle_choice(true);
        assert_eq!(form.action, RuleAction::Drop);

        let specification = form.to_rule_spec(&I18n::test_english()).map_err(io_error)?;
        assert_eq!(specification.action, RuleAction::Drop);
        assert!(!specification.enabled);
        Ok(())
    }

    #[test]
    fn inbound_editor_does_not_offer_non_accept_actions() {
        let mut form = RuleForm::for_direction(Direction::Inbound);
        form.move_next();
        assert_eq!(form.active_field, FormField::Protocol);

        form.name = "invalid inbound deny".to_owned();
        form.protocol = TransportProtocol::Tcp;
        form.action = RuleAction::Drop;
        assert!(form.to_rule_spec(&I18n::test_english()).is_err());
    }

    #[test]
    fn new_form_leaves_executable_version_for_daemon_pinning()
    -> Result<(), Box<dyn std::error::Error>> {
        let form = RuleForm {
            name: "curl application".to_owned(),
            protocol: TransportProtocol::Tcp,
            port: "443".to_owned(),
            bind_application: true,
            executable: "/usr/bin/curl".to_owned(),
            command_mode: CommandMode::Exact,
            arguments: r#"["curl","--header=A B"]"#.to_owned(),
            uid: "1000".to_owned(),
            cgroup: "/user.slice/example.scope".to_owned(),
            ..RuleForm::default()
        };

        let rule = form.to_rule_spec(&I18n::test_english()).map_err(io_error)?;
        let selector = rule.application.ok_or("application selector missing")?;
        assert_eq!(selector.executable_file, None);
        assert_eq!(selector.uid, Some(1_000));
        assert!(selector.command_line.is_some_and(|command| {
            command.kind == CommandLineMatch::Exact
                && command.arguments.len() == 2
                && command.arguments[1].as_str() == "--header=A B"
        }));
        Ok(())
    }

    #[test]
    fn edit_preserves_pin_only_for_the_unchanged_executable()
    -> Result<(), Box<dyn std::error::Error>> {
        let form = RuleForm {
            name: "curl application".to_owned(),
            protocol: TransportProtocol::Tcp,
            bind_application: true,
            executable: "/usr/bin/curl".to_owned(),
            ..RuleForm::default()
        };
        let mut specification = form.to_rule_spec(&I18n::test_english()).map_err(io_error)?;
        let pinned_version = ExecutableFileId {
            device: 8,
            inode: 99,
            size: 12_345,
            ctime_seconds: 1_700_000_000,
            ctime_nanoseconds: 123_456_789,
        };
        specification
            .application
            .as_mut()
            .ok_or("application selector missing")?
            .executable_file = Some(pinned_version);
        specification.validate()?;
        let rule = Rule::new(specification)?;

        let mut edit = RuleForm::from_rule(&rule);
        let unchanged = edit.to_rule_spec(&I18n::test_english()).map_err(io_error)?;
        assert_eq!(
            unchanged
                .application
                .and_then(|selector| selector.executable_file),
            Some(pinned_version)
        );

        edit.executable = "/usr/bin/wget".to_owned();
        let changed = edit.to_rule_spec(&I18n::test_english()).map_err(io_error)?;
        assert_eq!(
            changed
                .application
                .and_then(|selector| selector.executable_file),
            None
        );
        Ok(())
    }

    #[test]
    fn form_rejects_application_rules_for_inbound_traffic() {
        let form = RuleForm {
            name: "invalid inbound application".to_owned(),
            direction: Direction::Inbound,
            protocol: TransportProtocol::Tcp,
            bind_application: true,
            executable: "/usr/bin/server".to_owned(),
            ..RuleForm::default()
        };
        assert!(form.to_rule_spec(&I18n::test_english()).is_err());
    }

    #[test]
    fn disabled_application_matching_clears_and_rejects_hidden_selectors() {
        let mut form = RuleForm {
            name: "application rule".to_owned(),
            active_field: FormField::Application,
            protocol: TransportProtocol::Tcp,
            bind_application: true,
            executable: "/usr/bin/client".to_owned(),
            command_mode: CommandMode::Prefix,
            arguments: r#"["client","--safe"]"#.to_owned(),
            uid: "1000".to_owned(),
            cgroup: "/system.slice/client.service".to_owned(),
            ..RuleForm::default()
        };
        form.cycle_choice(false);
        assert!(!form.bind_application);
        assert!(form.executable.is_empty());
        assert_eq!(form.command_mode, CommandMode::Any);
        assert!(form.arguments.is_empty());
        assert!(form.uid.is_empty());
        assert!(form.cgroup.is_empty());
        assert!(form.to_rule_spec(&I18n::test_english()).is_ok());

        let orphaned = RuleForm {
            name: "unsafe broadening".to_owned(),
            protocol: TransportProtocol::Tcp,
            executable: "/usr/bin/client".to_owned(),
            ..RuleForm::default()
        };
        assert_eq!(
            orphaned.to_rule_spec(&I18n::test_english()),
            Err(I18n::test_english()
                .tr("validation.application_fields_disabled")
                .to_owned())
        );
    }

    #[test]
    fn form_rejects_ambiguous_or_non_string_argv() {
        let mut form = RuleForm {
            name: "invalid argv".to_owned(),
            bind_application: true,
            executable: "/usr/bin/example".to_owned(),
            command_mode: CommandMode::Prefix,
            arguments: r#"["example",7]"#.to_owned(),
            ..RuleForm::default()
        };
        assert!(form.to_rule_spec(&I18n::test_english()).is_err());

        form.arguments = "example --flag".to_owned();
        assert!(form.to_rule_spec(&I18n::test_english()).is_err());
    }

    #[test]
    fn form_rejects_reversed_port_range() {
        let form = RuleForm {
            name: "bad ports".to_owned(),
            protocol: TransportProtocol::Tcp,
            port: "9000-8000".to_owned(),
            ..RuleForm::default()
        };

        assert!(form.to_rule_spec(&I18n::test_english()).is_err());
    }

    #[test]
    fn form_accepts_single_peer_address_without_prefix() {
        let form = RuleForm {
            name: "single host".to_owned(),
            protocol: TransportProtocol::Tcp,
            peer_network: "203.0.113.8".to_owned(),
            port: "443".to_owned(),
            ..RuleForm::default()
        };

        let result = form.to_rule_spec(&I18n::test_english());
        assert!(result.is_ok(), "{result:?}");
        if let Ok(rule) = result {
            assert_eq!(
                rule.peer_network.map(|network| network.prefix_len()),
                Some(32)
            );
        }
    }

    #[test]
    fn editing_learned_rule_preserves_immutable_origin() -> Result<(), Box<dyn std::error::Error>> {
        let original_form = RuleForm {
            name: "learned endpoint".to_owned(),
            protocol: TransportProtocol::Tcp,
            peer_network: "203.0.113.9".to_owned(),
            port: "443".to_owned(),
            origin: RuleOrigin::Learned,
            ..RuleForm::default()
        };
        let rule = Rule::new(
            original_form
                .to_rule_spec(&I18n::test_english())
                .map_err(io_error)?,
        )?;
        let rule_id = rule.id;
        let mut app = App::new(false, I18n::test_english());
        app.view = View::Outbound;
        app.set_snapshot(Snapshot {
            revision: 1,
            flow_generation: 1,
            mode: Mode::Enforcing,
            rules: vec![rule],
        });

        app.open_edit_rule();
        assert!(matches!(
            &app.overlay,
            Overlay::Editor(form) if form.origin == RuleOrigin::Learned
        ));
        let request = app.submit_editor();
        assert!(matches!(
            request,
            Some(ControlRequest::UpdateRule {
                expected_revision: 1,
                id,
                rule,
            }) if id == rule_id && rule.origin == RuleOrigin::Learned
        ));
        Ok(())
    }

    #[test]
    fn editor_keeps_revision_from_when_the_intent_was_opened()
    -> Result<(), Box<dyn std::error::Error>> {
        let rule = Rule::new(
            RuleForm {
                name: "concurrent rule".to_owned(),
                protocol: TransportProtocol::Tcp,
                port: "443".to_owned(),
                ..RuleForm::default()
            }
            .to_rule_spec(&I18n::test_english())
            .map_err(io_error)?,
        )?;
        let rule_id = rule.id;
        let mut app = App::new(false, I18n::test_english());
        app.view = View::Outbound;
        app.set_snapshot(Snapshot {
            revision: 1,
            flow_generation: 1,
            mode: Mode::Enforcing,
            rules: vec![rule.clone()],
        });
        app.open_edit_rule();

        let mut concurrently_updated = rule;
        concurrently_updated.spec.enabled = false;
        app.push_event(Event {
            revision: 2,
            occurred_at: Utc::now(),
            kind: EventKind::RuleEnabledChanged {
                rule: concurrently_updated,
            },
        });

        assert!(matches!(
            app.submit_editor(),
            Some(ControlRequest::UpdateRule {
                expected_revision: 1,
                id,
                ..
            }) if id == rule_id
        ));
        Ok(())
    }

    #[test]
    fn form_rejects_ports_for_icmp() {
        let form = RuleForm {
            name: "icmp".to_owned(),
            protocol: TransportProtocol::Icmp,
            port: "7".to_owned(),
            ..RuleForm::default()
        };

        assert!(form.to_rule_spec(&I18n::test_english()).is_err());
    }

    #[test]
    fn event_buffer_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let mut app = App::new(true, I18n::test_english());
        let event_count = u64::try_from(MAX_VISIBLE_EVENTS + 3)?;
        for revision in 0..event_count {
            let mut counters = FirewallCounters::default();
            counters.accepted_in.packets = revision;
            app.push_event(Event {
                revision,
                occurred_at: Utc::now(),
                kind: EventKind::CountersUpdated { counters },
            });
        }
        assert_eq!(app.events.len(), MAX_VISIBLE_EVENTS);
        assert_eq!(app.events.front().map(|event| event.revision), Some(3));
        Ok(())
    }

    #[test]
    fn rule_selection_never_underflows() {
        let mut app = App::new(false, I18n::test_english());
        app.select_previous_rule();
        assert_eq!(app.selected_outbound_group, 0);
        assert_eq!(app.selected_inbound_rule, 0);
    }

    #[test]
    fn stale_snapshot_cannot_roll_state_back() {
        let mut app = App::new(true, I18n::test_english());
        app.set_snapshot(Snapshot {
            revision: 8,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: Vec::new(),
        });
        app.set_snapshot(Snapshot {
            revision: 7,
            flow_generation: 1,
            mode: Mode::BlockAll,
            rules: Vec::new(),
        });

        assert_eq!(app.snapshot.as_ref().map(|state| state.revision), Some(8));
        assert_eq!(
            app.snapshot.as_ref().map(|state| state.mode),
            Some(Mode::Learning)
        );
    }

    #[test]
    fn confirmed_daemon_restart_replaces_higher_revision_state() {
        let mut app = App::new(false, I18n::test_english());
        app.view = View::Outbound;
        app.set_snapshot(Snapshot {
            revision: 12,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: Vec::new(),
        });
        app.push_event(Event {
            revision: 12,
            occurred_at: Utc::now(),
            kind: EventKind::CountersUpdated {
                counters: FirewallCounters::default(),
            },
        });
        app.open_create_rule();

        app.set_restarted_snapshot(Snapshot {
            revision: 2,
            flow_generation: 1,
            mode: Mode::BlockAll,
            rules: Vec::new(),
        });

        assert_eq!(app.snapshot.as_ref().map(|state| state.revision), Some(2));
        assert_eq!(
            app.snapshot.as_ref().map(|state| state.mode),
            Some(Mode::BlockAll)
        );
        assert!(app.counters.is_none());
        assert!(app.events.is_empty());
        assert_eq!(app.overlay, Overlay::None);
        assert_eq!(
            app.notice.as_deref(),
            Some(app.i18n.tr("notice.daemon_restarted"))
        );
    }

    #[test]
    fn counter_event_does_not_advance_policy_revision() {
        let mut app = App::new(true, I18n::test_english());
        app.set_snapshot(Snapshot {
            revision: 4,
            flow_generation: 1,
            mode: Mode::BlockAll,
            rules: Vec::new(),
        });
        app.push_event(Event {
            revision: 5,
            occurred_at: Utc::now(),
            kind: EventKind::CountersUpdated {
                counters: FirewallCounters::default(),
            },
        });

        assert_eq!(app.snapshot.as_ref().map(|state| state.revision), Some(4));
        assert!(app.counters.is_some());
    }

    #[test]
    fn telemetry_disconnect_preserves_valid_snapshot_and_counters() {
        let mut app = App::new(true, I18n::test_english());
        let received_at = Instant::now();
        app.set_snapshot(Snapshot {
            revision: 4,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: Vec::new(),
        });
        app.push_event_at(
            Event {
                revision: 4,
                occurred_at: Utc::now(),
                kind: EventKind::CountersUpdated {
                    counters: FirewallCounters::default(),
                },
            },
            received_at,
        );

        app.set_telemetry_disconnected("subscription closed".to_owned());

        assert_eq!(app.snapshot.as_ref().map(|state| state.revision), Some(4));
        assert!(app.counters.is_some());
        assert_eq!(
            app.counters_age(received_at + Duration::from_secs(7)),
            Some(Duration::from_secs(7))
        );
        assert!(matches!(app.telemetry, ConnectionState::Disconnected(_)));
    }

    #[test]
    fn incoming_event_recovers_telemetry_health() {
        let mut app = App::new(true, I18n::test_english());
        let received_at = Instant::now();
        app.set_telemetry_disconnected("temporary failure".to_owned());

        app.push_event_at(
            Event {
                revision: 0,
                occurred_at: Utc::now(),
                kind: EventKind::CountersUpdated {
                    counters: FirewallCounters::default(),
                },
            },
            received_at,
        );

        assert_eq!(app.telemetry, ConnectionState::Connected);
        assert_eq!(
            app.telemetry_connection_age(received_at + Duration::from_secs(2)),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            app.counters_age(received_at + Duration::from_secs(2)),
            Some(Duration::from_secs(2))
        );
    }

    #[test]
    fn unchanged_counter_heartbeat_refreshes_telemetry_freshness() {
        let mut app = App::new(true, I18n::test_english());
        let first_received_at = Instant::now();
        let counters = FirewallCounters::default();
        let counter_event = |occurred_at| Event {
            revision: 0,
            occurred_at,
            kind: EventKind::CountersUpdated {
                counters: counters.clone(),
            },
        };
        app.push_event_at(counter_event(Utc::now()), first_received_at);

        let heartbeat_at = first_received_at + Duration::from_secs(2);
        app.push_event_at(counter_event(Utc::now()), heartbeat_at);

        assert_eq!(
            app.counters_age(first_received_at + Duration::from_secs(4)),
            Some(Duration::from_secs(2))
        );
        assert_eq!(app.counters, Some(counters));
        assert_eq!(app.events.len(), 1);
    }

    #[test]
    fn idle_counter_heartbeats_do_not_evict_policy_events() {
        let mut app = App::new(true, I18n::test_english());
        app.push_event(Event {
            revision: 1,
            occurred_at: Utc::now(),
            kind: EventKind::ModeChanged {
                previous: Mode::BlockAll,
                current: Mode::Learning,
            },
        });
        for _ in 0..(MAX_VISIBLE_EVENTS + 10) {
            app.push_event(Event {
                revision: 1,
                occurred_at: Utc::now(),
                kind: EventKind::CountersUpdated {
                    counters: FirewallCounters::default(),
                },
            });
        }

        assert_eq!(app.events.len(), 2);
        assert!(matches!(
            app.events.front().map(|event| &event.kind),
            Some(EventKind::ModeChanged { .. })
        ));
    }

    #[test]
    fn disconnect_clears_stale_policy_and_cancels_mutation() {
        let mut app = App::new(false, I18n::test_english());
        app.view = View::Outbound;
        app.set_snapshot(Snapshot {
            revision: 4,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: Vec::new(),
        });
        app.counters = Some(FirewallCounters::default());
        app.open_create_rule();

        app.set_disconnected("daemon restarted".to_owned());

        assert!(app.snapshot.is_none());
        assert!(app.backend.is_none());
        assert!(app.counters.is_none());
        assert!(app.counters_age(Instant::now()).is_none());
        assert_eq!(app.overlay, Overlay::None);
        assert!(matches!(app.connection, ConnectionState::Disconnected(_)));
    }

    #[test]
    fn structural_event_invalidates_runtime_attestation_but_counters_do_not() {
        let mut app = App::new(true, I18n::test_english());
        let attested = RuntimeCompatibility {
            level: CompatibilityLevel::KernelNative,
            reason: CompatibilityReason::NetworkOnly,
        };
        app.set_observed_snapshot(
            Snapshot {
                revision: 2,
                flow_generation: 1,
                mode: Mode::Enforcing,
                rules: Vec::new(),
            },
            FirewallBackendKind::Nftables,
            attested,
        );

        app.push_event(Event {
            revision: 2,
            occurred_at: Utc::now(),
            kind: EventKind::CountersUpdated {
                counters: FirewallCounters::default(),
            },
        });
        assert_eq!(app.runtime_compatibility, attested);

        app.push_event(Event {
            revision: 2,
            occurred_at: Utc::now(),
            kind: EventKind::ModeChanged {
                previous: Mode::Enforcing,
                current: Mode::Learning,
            },
        });
        assert_eq!(app.runtime_compatibility, attested);

        app.push_event(Event {
            revision: 1,
            occurred_at: Utc::now(),
            kind: EventKind::ModeChanged {
                previous: Mode::Enforcing,
                current: Mode::Learning,
            },
        });
        assert_eq!(app.runtime_compatibility, attested);

        app.push_event(Event {
            revision: 3,
            occurred_at: Utc::now(),
            kind: EventKind::ModeChanged {
                previous: Mode::Enforcing,
                current: Mode::Learning,
            },
        });
        assert_eq!(app.runtime_compatibility, RuntimeCompatibility::default());
    }

    #[test]
    fn outbound_groups_use_cgroup_then_executable_then_destination()
    -> Result<(), Box<dyn std::error::Error>> {
        let cgroup_a = test_rule(
            "cgroup one",
            Direction::Outbound,
            Some("203.0.113.10"),
            Some("/usr/bin/client"),
            Some("/system.slice/client.service"),
            Some(r#"["client","--one"]"#),
        )?;
        let cgroup_b = test_rule(
            "cgroup two",
            Direction::Outbound,
            Some("203.0.113.11"),
            Some("/usr/bin/client"),
            Some("/system.slice/client.service"),
            Some(r#"["client","--two"]"#),
        )?;
        let executable_a = test_rule(
            "path one",
            Direction::Outbound,
            Some("198.51.100.1"),
            Some("/usr/bin/fetch"),
            None,
            Some(r#"["fetch","--one"]"#),
        )?;
        let executable_b = test_rule(
            "path two",
            Direction::Outbound,
            Some("198.51.100.2"),
            Some("/usr/bin/fetch"),
            None,
            Some(r#"["fetch","--two"]"#),
        )?;
        let destination = test_rule(
            "network",
            Direction::Outbound,
            Some("192.0.2.9"),
            None,
            None,
            None,
        )?;
        let inbound = test_rule(
            "inbound",
            Direction::Inbound,
            Some("192.0.2.9"),
            None,
            None,
            None,
        )?;
        let mut app = App::new(false, I18n::test_english());
        app.set_snapshot(Snapshot {
            revision: 1,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: vec![
                destination,
                executable_b,
                cgroup_a,
                inbound,
                executable_a,
                cgroup_b,
            ],
        });

        let groups = app.outbound_groups();
        assert_eq!(groups.len(), 3);
        assert!(matches!(
            &groups[0].key,
            OutboundGroupKey::Cgroup(value) if value == "/system.slice/client.service"
        ));
        assert_eq!(groups[0].rules.len(), 2);
        assert!(matches!(
            &groups[1].key,
            OutboundGroupKey::Executable(value) if value == "/usr/bin/fetch"
        ));
        assert_eq!(groups[1].rules.len(), 2);
        assert!(matches!(
            &groups[2].key,
            OutboundGroupKey::Destination(Some(network)) if network.to_string() == "192.0.2.9/32"
        ));
        Ok(())
    }

    #[test]
    fn group_selection_prefers_the_disabled_application_template()
    -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = test_rule(
            "learned endpoint",
            Direction::Outbound,
            Some("203.0.113.10"),
            Some("/usr/bin/client"),
            Some("/system.slice/client.service"),
            Some(r#"["client","--one"]"#),
        )?;
        let mut template_form = RuleForm {
            name: "application-wide template".to_owned(),
            origin: RuleOrigin::Template,
            enabled: false,
            bind_application: true,
            executable: "/usr/bin/client".to_owned(),
            cgroup: "/system.slice/client.service".to_owned(),
            ..RuleForm::default()
        };
        template_form.action = RuleAction::Accept;
        let template = Rule::new(
            template_form
                .to_rule_spec(&I18n::test_english())
                .map_err(io_error)?,
        )?;
        let template_id = template.id;

        let mut app = App::new(false, I18n::test_english());
        app.view = View::Outbound;
        app.set_snapshot(Snapshot {
            revision: 2,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: vec![endpoint, template],
        });

        let groups = app.outbound_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].rules[0].id, template_id);
        assert_eq!(app.selected_rule().map(|rule| rule.id), Some(template_id));
        assert!(matches!(
            app.toggle_selected_rule(),
            Some(ControlRequest::SetRuleEnabled {
                id,
                enabled: true,
                ..
            }) if id == template_id
        ));
        Ok(())
    }

    #[test]
    fn equivalent_destination_networks_share_one_group() -> Result<(), Box<dyn std::error::Error>> {
        let first = test_rule(
            "first subnet spelling",
            Direction::Outbound,
            Some("192.0.2.1/24"),
            None,
            None,
            None,
        )?;
        let second = test_rule(
            "second subnet spelling",
            Direction::Outbound,
            Some("192.0.2.99/24"),
            None,
            None,
            None,
        )?;
        let mut app = App::new(false, I18n::test_english());
        app.set_snapshot(Snapshot {
            revision: 1,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: vec![first, second],
        });

        let groups = app.outbound_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].rules.len(), 2);
        assert_eq!(
            groups[0].key,
            OutboundGroupKey::Destination(Some("192.0.2.0/24".parse()?))
        );
        Ok(())
    }

    #[test]
    fn mutation_api_rejects_non_rule_views() -> Result<(), Box<dyn std::error::Error>> {
        let rule = test_rule(
            "outbound",
            Direction::Outbound,
            Some("192.0.2.1"),
            None,
            None,
            None,
        )?;
        let mut app = App::new(false, I18n::test_english());
        app.set_snapshot(Snapshot {
            revision: 1,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: vec![rule],
        });

        assert!(app.selected_rule().is_none());
        assert!(app.toggle_selected_rule().is_none());
        app.open_create_rule();
        assert_eq!(app.overlay, Overlay::None);
        app.open_edit_rule();
        assert_eq!(app.overlay, Overlay::None);
        Ok(())
    }

    #[test]
    fn redacted_application_group_falls_back_to_destination()
    -> Result<(), Box<dyn std::error::Error>> {
        let rule = test_rule(
            "private app",
            Direction::Outbound,
            Some("203.0.113.20"),
            Some("/usr/bin/private"),
            Some("/user.slice/private.scope"),
            None,
        )?
        .redacted_for_observer();
        assert!(matches!(
            OutboundGroupKey::from_rule(&rule),
            Some(OutboundGroupKey::Destination(Some(network)))
                if network.to_string() == "203.0.113.20/32"
        ));
        Ok(())
    }

    #[test]
    fn group_key_keeps_selector_kinds_distinct_and_supports_any_destination()
    -> Result<(), Box<dyn std::error::Error>> {
        let cgroup = test_rule(
            "cgroup",
            Direction::Outbound,
            Some("192.0.2.1"),
            Some("/same"),
            Some("/same"),
            None,
        )?;
        let executable = test_rule(
            "executable",
            Direction::Outbound,
            Some("192.0.2.2"),
            Some("/same"),
            None,
            None,
        )?;
        let any_destination = test_rule(
            "any destination",
            Direction::Outbound,
            None,
            None,
            None,
            None,
        )?;
        let mut app = App::new(false, I18n::test_english());
        app.set_snapshot(Snapshot {
            revision: 1,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: vec![cgroup, executable, any_destination],
        });

        let keys = app
            .outbound_groups()
            .into_iter()
            .map(|group| group.key)
            .collect::<Vec<_>>();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&OutboundGroupKey::Cgroup(Cow::Borrowed("/same"))));
        assert!(keys.contains(&OutboundGroupKey::Executable(Cow::Borrowed("/same"))));
        assert!(keys.contains(&OutboundGroupKey::Destination(None)));
        Ok(())
    }

    #[test]
    fn outbound_selection_tracks_uuid_across_insert_and_group_change()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = test_rule(
            "first",
            Direction::Outbound,
            Some("203.0.113.20"),
            Some("/usr/bin/client"),
            Some("/system.slice/client.service"),
            None,
        )?;
        let second = test_rule(
            "second",
            Direction::Outbound,
            Some("203.0.113.30"),
            Some("/usr/bin/client"),
            Some("/system.slice/client.service"),
            None,
        )?;
        let mut app = App::new(false, I18n::test_english());
        app.view = View::Outbound;
        app.set_snapshot(Snapshot {
            revision: 1,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: vec![first, second],
        });
        app.select_next_group_member();
        let selected_id = app.selected_rule().ok_or("missing selection")?.id;

        let inserted = test_rule(
            "inserted",
            Direction::Outbound,
            Some("203.0.113.10"),
            Some("/usr/bin/client"),
            Some("/system.slice/client.service"),
            None,
        )?;
        app.push_event(Event {
            revision: 2,
            occurred_at: Utc::now(),
            kind: EventKind::RuleCreated { rule: inserted },
        });
        assert_eq!(app.selected_rule().map(|rule| rule.id), Some(selected_id));
        assert!(matches!(
            app.toggle_selected_rule(),
            Some(ControlRequest::SetRuleEnabled { id, .. }) if id == selected_id
        ));

        let mut migrated = app.selected_rule().ok_or("missing selection")?.clone();
        migrated
            .spec
            .application
            .as_mut()
            .ok_or("missing selector")?
            .cgroup = Some(CgroupPath::new("/system.slice/new.service")?);
        migrated.spec.validate()?;
        app.push_event(Event {
            revision: 3,
            occurred_at: Utc::now(),
            kind: EventKind::RuleUpdated {
                rule: migrated.clone(),
            },
        });
        assert_eq!(app.selected_rule().map(|rule| rule.id), Some(selected_id));
        assert!(matches!(
            app.toggle_selected_rule(),
            Some(ControlRequest::SetRuleEnabled { id, .. }) if id == selected_id
        ));

        app.push_event(Event {
            revision: 4,
            occurred_at: Utc::now(),
            kind: EventKind::RuleDeleted { rule: migrated },
        });
        assert!(
            app.selected_rule()
                .is_some_and(|rule| rule.id != selected_id)
        );
        assert!(matches!(
            app.toggle_selected_rule(),
            Some(ControlRequest::SetRuleEnabled { id, .. }) if id != selected_id
        ));
        Ok(())
    }

    #[test]
    fn inbound_tab_edits_only_the_selected_inbound_uuid() -> Result<(), Box<dyn std::error::Error>>
    {
        let outbound = test_rule(
            "outbound",
            Direction::Outbound,
            Some("192.0.2.1"),
            None,
            None,
            None,
        )?;
        let inbound_22 = test_rule(
            "ssh",
            Direction::Inbound,
            Some("192.0.2.0/24"),
            None,
            None,
            None,
        )?;
        let mut inbound_443 = test_rule(
            "https",
            Direction::Inbound,
            Some("198.51.100.0/24"),
            None,
            None,
            None,
        )?;
        inbound_443.spec.port = Some(PortRange::new(443, 443)?);
        inbound_443.spec.validate()?;
        let mut app = App::new(false, I18n::test_english());
        app.view = View::Inbound;
        app.set_snapshot(Snapshot {
            revision: 9,
            flow_generation: 1,
            mode: Mode::Enforcing,
            rules: vec![outbound, inbound_443, inbound_22],
        });
        app.select_next_rule();
        let selected_id = app.selected_rule().ok_or("missing inbound")?.id;
        app.open_edit_rule();
        assert!(matches!(
            &app.overlay,
            Overlay::Editor(form)
                if form.id == Some(selected_id) && form.direction == Direction::Inbound
        ));
        app.close_overlay();
        assert!(matches!(
            app.toggle_selected_rule(),
            Some(ControlRequest::SetRuleEnabled { id, .. }) if id == selected_id
        ));
        Ok(())
    }

    #[test]
    fn inbound_editor_locks_direction_and_omits_application()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut app = App::new(false, I18n::test_english());
        app.view = View::Inbound;
        app.set_snapshot(Snapshot {
            revision: 3,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: Vec::new(),
        });
        app.open_create_rule();
        let Overlay::Editor(form) = &mut app.overlay else {
            return Err("inbound editor did not open".into());
        };
        assert_eq!(form.direction, Direction::Inbound);
        form.name = "HTTPS ingress".to_owned();
        form.protocol = TransportProtocol::Tcp;
        form.port = "443".to_owned();
        for _ in 0..20 {
            form.move_next();
            assert!(!matches!(
                form.active_field,
                FormField::Application
                    | FormField::Executable
                    | FormField::CommandMode
                    | FormField::Arguments
                    | FormField::Uid
                    | FormField::Cgroup
            ));
        }
        let request = app.submit_editor().ok_or("valid rule was not submitted")?;
        assert!(matches!(
            request,
            ControlRequest::CreateRule { rule, .. }
                if rule.direction == Direction::Inbound && rule.application.is_none()
        ));
        Ok(())
    }

    fn test_rule(
        name: &str,
        direction: Direction,
        peer: Option<&str>,
        executable: Option<&str>,
        cgroup: Option<&str>,
        arguments: Option<&str>,
    ) -> Result<Rule, Box<dyn std::error::Error>> {
        let form = RuleForm {
            name: name.to_owned(),
            direction,
            protocol: TransportProtocol::Tcp,
            peer_network: peer.unwrap_or_default().to_owned(),
            port: "443".to_owned(),
            bind_application: executable.is_some(),
            executable: executable.unwrap_or_default().to_owned(),
            command_mode: if arguments.is_some() {
                CommandMode::Exact
            } else {
                CommandMode::Any
            },
            arguments: arguments.unwrap_or_default().to_owned(),
            cgroup: cgroup.unwrap_or_default().to_owned(),
            ..RuleForm::default()
        };
        Ok(Rule::new(
            form.to_rule_spec(&I18n::test_english()).map_err(io_error)?,
        )?)
    }

    fn io_error(message: String) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, message)
    }
}
