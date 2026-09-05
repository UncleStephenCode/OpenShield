use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, poll};
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, getsockname,
    recvfrom, sendto, socket,
};
use openshield_core::{
    ApplicationIdentity, ApplicationPath, CgroupPath, CommandArgument, ExecutableFileId,
    InterfaceName, MAX_COMMAND_ARGUMENTS, MAX_COMMAND_LINE_BYTES, Rule, RuleAction, RuleSpec,
    Snapshot, TransportProtocol,
};

const MAX_PROC_ENTRIES: usize = 131_072;
const MAX_FDS_PER_TASK: usize = 4_096;
pub(crate) const MAX_ATTRIBUTION_BATCH_SIZE: usize = 32;
const MAX_SOCKET_TABLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_STATUS_BYTES: usize = 256 * 1024;
const MAX_STAT_BYTES: usize = 64 * 1024;
const MAX_CGROUP_BYTES: usize = 256 * 1024;
const PROC_SCAN_DEADLINE: Duration = Duration::from_millis(250);
const NETLINK_HEADER_BYTES: usize = 16;
const INET_DIAG_REQUEST_BYTES: usize = 56;
const INET_DIAG_MESSAGE_BYTES: usize = 72;
const SOCK_DIAG_REQUEST_BYTES: usize = NETLINK_HEADER_BYTES + INET_DIAG_REQUEST_BYTES;
const SOCK_DIAG_RECEIVE_BUFFER_BYTES: usize = 64 * 1024;
const MAX_SOCK_DIAG_RESPONSE_BYTES: usize = MAX_SOCKET_TABLE_BYTES;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_MULTI: u16 = 0x02;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLM_F_DUMP: u16 = 0x100 | 0x200;
const NLMSG_ERROR: u16 = 0x02;
const NLMSG_DONE: u16 = 0x03;
const NLMSG_OVERRUN: u16 = 0x04;
const INET_DIAG_NOCOOKIE: u32 = u32::MAX;

#[derive(Debug)]
struct ProcfsAttributionTimeout;

impl std::fmt::Display for ProcfsAttributionTimeout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded application attribution timed out")
    }
}

impl std::error::Error for ProcfsAttributionTimeout {}

/// Distinguishes the bounded attribution deadline from ordinary attribution
/// failures without relying on log text. Context added by callers remains in
/// the anyhow chain and does not erase this marker.
#[must_use]
pub(crate) fn is_attribution_timeout(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<ProcfsAttributionTimeout>().is_some())
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OutboundConnection {
    pub source_address: IpAddr,
    pub source_port: Option<u16>,
    pub destination_address: IpAddr,
    pub destination_port: Option<u16>,
    pub protocol: TransportProtocol,
    pub output_interface: InterfaceName,
    pub socket_uid: u32,
}

impl OutboundConnection {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.source_address.is_ipv4() == self.destination_address.is_ipv4(),
            "connection address families differ"
        );
        match self.protocol {
            TransportProtocol::Tcp | TransportProtocol::Udp => ensure!(
                self.source_port.is_some_and(|port| port != 0)
                    && self.destination_port.is_some_and(|port| port != 0),
                "transport connection has missing or reserved ports"
            ),
            TransportProtocol::Icmp => ensure!(
                self.source_address.is_ipv4()
                    && self.source_port.is_some()
                    && self.destination_port.is_none(),
                "invalid ICMP echo connection tuple"
            ),
            TransportProtocol::IcmpV6 => ensure!(
                self.source_address.is_ipv6()
                    && self.source_port.is_some()
                    && self.destination_port.is_none(),
                "invalid ICMPv6 echo connection tuple"
            ),
            TransportProtocol::Any => bail!("untyped outbound connection cannot be attributed"),
        }
        Ok(())
    }
}

/// Resolves a manually supplied executable path to the exact file identity
/// persisted in policy state. Canonicalization and a stable pair of opened-file
/// snapshots bind the rule to the executable version visible in the daemon's
/// mount namespace.
pub fn pin_rule_application(specification: &mut RuleSpec) -> Result<()> {
    let Some(selector) = specification.application.as_mut() else {
        return Ok(());
    };
    let executable = selector
        .executable
        .as_ref()
        .ok_or_else(|| anyhow!("application selector has no executable path"))?;
    let executable_path = Path::new(executable.as_str());
    let canonical_path = fs::canonicalize(executable_path).with_context(|| {
        format!(
            "cannot canonicalize executable {}",
            executable_path.display()
        )
    })?;
    let (first_handle, actual_file) = open_executable_version(&canonical_path)?;
    let verified_canonical_path = fs::canonicalize(executable_path).with_context(|| {
        format!(
            "cannot re-canonicalize executable {}",
            executable_path.display()
        )
    })?;
    ensure!(
        verified_canonical_path == canonical_path,
        "executable path changed while it was pinned"
    );
    let (verification_handle, verified_file) = open_executable_version(&verified_canonical_path)?;
    ensure!(
        verified_file == actual_file,
        "executable version changed while it was pinned"
    );
    let final_canonical_path = fs::canonicalize(executable_path).with_context(|| {
        format!(
            "cannot finally canonicalize executable {}",
            executable_path.display()
        )
    })?;
    ensure!(
        final_canonical_path == canonical_path,
        "executable path changed while it was pinned"
    );
    let canonical_text = canonical_path
        .to_str()
        .ok_or_else(|| anyhow!("canonical executable path is not UTF-8"))?;
    let canonical_application = ApplicationPath::new(canonical_text.to_owned())?;
    if let Some(expected_file) = selector.executable_file {
        ensure!(
            expected_file == actual_file,
            "supplied executable version does not match the opened path"
        );
    }
    selector.executable = Some(canonical_application);
    selector.executable_file = Some(actual_file);
    specification.validate()?;
    drop((first_handle, verification_handle));
    Ok(())
}

fn open_executable_version(path: &Path) -> Result<(File, ExecutableFileId)> {
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("cannot open executable {}", path.display()))?;
    let metadata = handle
        .metadata()
        .context("cannot inspect executable file")?;
    let identity = executable_file_id(&metadata)?;
    Ok((handle, identity))
}

fn executable_file_id(metadata: &Metadata) -> Result<ExecutableFileId> {
    ensure!(
        metadata.is_file(),
        "application executable is not a regular file"
    );
    let identity = ExecutableFileId {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        ctime_seconds: metadata.ctime(),
        ctime_nanoseconds: metadata.ctime_nsec(),
    };
    identity.validate()?;
    Ok(identity)
}

#[must_use]
#[cfg(test)]
pub fn matching_application_rule<'a>(
    snapshot: &'a Snapshot,
    connection: &OutboundConnection,
    identity: &ApplicationIdentity,
) -> Option<&'a Rule> {
    snapshot
        .rules
        .iter()
        .filter(|rule| application_rule_matches(rule, connection, identity))
        .min_by_key(|rule| (rule_action_priority(rule.spec.action), rule.id))
}

/// Immutable, indexed subset of policy used by the NFQUEUE decision path.
///
/// Every persisted application rule has a mandatory executable version pin.
/// Indexing on that pin prevents an unprivileged packet stream from forcing a
/// scan of all application rules. Rules for the same executable are still
/// evaluated in policy order so matching semantics remain unchanged.
#[derive(Clone, Debug)]
pub struct ApplicationDecisionPolicy {
    snapshot: Snapshot,
    rules_by_executable: HashMap<ExecutableFileId, Vec<usize>>,
    network_accept_rules: Vec<usize>,
}

impl ApplicationDecisionPolicy {
    #[must_use]
    pub fn new(snapshot: Snapshot) -> Self {
        let mut rules_by_executable = HashMap::<ExecutableFileId, Vec<usize>>::new();
        let mut network_accept_rules = Vec::new();
        for (index, rule) in snapshot.rules.iter().enumerate() {
            match rule.spec.application.as_ref() {
                Some(selector) => {
                    let Some(file) = selector.executable_file else {
                        // State validation rejects enabled unpinned
                        // application rules. If an internal caller violates
                        // that invariant, omitting it is fail-closed.
                        continue;
                    };
                    rules_by_executable.entry(file).or_default().push(index);
                }
                None if rule.spec.enabled
                    && rule.spec.direction == openshield_core::Direction::Outbound
                    && rule.spec.action == RuleAction::Accept =>
                {
                    network_accept_rules.push(index);
                }
                None => {}
            }
        }
        Self {
            snapshot,
            rules_by_executable,
            network_accept_rules,
        }
    }

    #[must_use]
    pub fn matching_rule(
        &self,
        connection: &OutboundConnection,
        identity: &ApplicationIdentity,
    ) -> Option<&Rule> {
        let application_match = self
            .rules_by_executable
            .get(&identity.executable_file)
            .into_iter()
            .flatten()
            .filter_map(|index| self.snapshot.rules.get(*index))
            .filter(|rule| application_rule_matches(rule, connection, identity))
            .min_by_key(|rule| (rule_action_priority(rule.spec.action), rule.id));
        application_match.or_else(|| self.matching_network_accept(connection))
    }

    /// Finds only an explicit application-bound deny. Learning uses this
    /// narrower lookup so an Accept rule can never be mistaken for either an
    /// enforcement decision or a fail-closed attribution error.
    #[must_use]
    pub(crate) fn matching_deny_rule(
        &self,
        connection: &OutboundConnection,
        identity: &ApplicationIdentity,
    ) -> Option<&Rule> {
        self.rules_by_executable
            .get(&identity.executable_file)
            .into_iter()
            .flatten()
            .filter_map(|index| self.snapshot.rules.get(*index))
            .filter(|rule| matches!(rule.spec.action, RuleAction::Drop | RuleAction::Reject))
            .filter(|rule| application_rule_matches(rule, connection, identity))
            .min_by_key(|rule| (rule_action_priority(rule.spec.action), rule.id))
    }

    /// Finds the deterministic network-only Accept fallback for a packet
    /// whose application envelope reached NFQUEUE but whose attributed
    /// identity did not match an application rule.
    #[must_use]
    pub(crate) fn matching_network_accept(&self, connection: &OutboundConnection) -> Option<&Rule> {
        self.network_accept_rules
            .iter()
            .filter_map(|index| self.snapshot.rules.get(*index))
            .filter(|rule| outbound_network_rule_matches(rule, connection))
            .min_by_key(|rule| rule.id)
    }

    /// Returns the optional process fields required by application rules whose
    /// kernel-provided network tuple and socket UID can still match.
    ///
    /// This is deliberately a deny-only prefilter: absence of a candidate lets
    /// the NFQUEUE path reject the packet without scanning procfs, while the
    /// presence of a candidate never authorizes it. Executable identity and all
    /// requested optional fields are still captured and race-checked before the
    /// immutable policy is evaluated.
    #[must_use]
    pub(crate) fn enforcement_capture_requirements(
        &self,
        connection: &OutboundConnection,
    ) -> Option<IdentityCaptureRequirements> {
        let mut requirements = IdentityCaptureRequirements::minimal();
        let mut candidate_found = false;
        for rule in &self.snapshot.rules {
            if !application_rule_network_and_uid_matches(rule, connection) {
                continue;
            }
            let Some(selector) = rule.spec.application.as_ref() else {
                // The predicate above already rejects this case. Keep the
                // decision fail-closed if an internal invariant is broken.
                continue;
            };
            candidate_found = true;
            requirements.command_line |= selector.command_line.is_some();
            requirements.cgroups |= selector.cgroup.is_some();
        }
        candidate_found.then_some(requirements)
    }

    /// Returns capture requirements only for application Drop/Reject
    /// envelopes. This is the sole synchronous attribution path in Learning.
    #[must_use]
    pub(crate) fn deny_capture_requirements(
        &self,
        connection: &OutboundConnection,
    ) -> Option<IdentityCaptureRequirements> {
        let mut requirements = IdentityCaptureRequirements::minimal();
        let mut candidate_found = false;
        for rule in &self.snapshot.rules {
            if !matches!(rule.spec.action, RuleAction::Drop | RuleAction::Reject)
                || !application_rule_network_and_uid_matches(rule, connection)
            {
                continue;
            }
            let Some(selector) = rule.spec.application.as_ref() else {
                continue;
            };
            candidate_found = true;
            requirements.command_line |= selector.command_line.is_some();
            requirements.cgroups |= selector.cgroup.is_some();
        }
        candidate_found.then_some(requirements)
    }

    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.snapshot.rules.len()
    }

    #[cfg(test)]
    fn candidate_count(&self, file: ExecutableFileId) -> usize {
        self.rules_by_executable.get(&file).map_or(0, Vec::len)
    }
}

/// Optional process fields needed after the mandatory executable/socket
/// identity has been established. The type is crate-private so external callers
/// cannot request selective capture; the public resolver retains full capture.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct IdentityCaptureRequirements {
    command_line: bool,
    cgroups: bool,
}

impl IdentityCaptureRequirements {
    pub(crate) const fn minimal() -> Self {
        Self {
            command_line: false,
            cgroups: false,
        }
    }

    pub(crate) const fn full() -> Self {
        Self {
            command_line: true,
            cgroups: true,
        }
    }
}

impl Deref for ApplicationDecisionPolicy {
    type Target = Snapshot;

    fn deref(&self) -> &Self::Target {
        &self.snapshot
    }
}

fn application_rule_matches(
    rule: &Rule,
    connection: &OutboundConnection,
    identity: &ApplicationIdentity,
) -> bool {
    application_rule_network_and_uid_matches(rule, connection)
        && rule
            .spec
            .application
            .as_ref()
            .is_some_and(|selector| selector.matches(identity))
}

const fn rule_action_priority(action: RuleAction) -> u8 {
    match action {
        RuleAction::Drop => 0,
        RuleAction::Reject => 1,
        RuleAction::Accept => 2,
    }
}

fn application_rule_network_and_uid_matches(rule: &Rule, connection: &OutboundConnection) -> bool {
    outbound_network_selectors_match(rule, connection)
        && rule.spec.application.as_ref().is_some_and(|selector| {
            selector
                .uid
                .is_none_or(|expected| expected == connection.socket_uid)
        })
}

fn outbound_network_rule_matches(rule: &Rule, connection: &OutboundConnection) -> bool {
    rule.spec.application.is_none()
        && rule.spec.action == RuleAction::Accept
        && outbound_network_selectors_match(rule, connection)
}

fn outbound_network_selectors_match(rule: &Rule, connection: &OutboundConnection) -> bool {
    rule.spec.enabled
        && rule.spec.direction == openshield_core::Direction::Outbound
        && (rule.spec.protocol == TransportProtocol::Any
            || rule.spec.protocol == connection.protocol)
        && rule
            .spec
            .peer_network
            .is_none_or(|network| network.contains(&connection.destination_address))
        && rule.spec.port.is_none_or(|range| {
            connection
                .destination_port
                .is_some_and(|port| port >= range.start() && port <= range.end())
        })
        && rule
            .spec
            .interface
            .as_ref()
            .is_none_or(|interface| interface == &connection.output_interface)
}

#[derive(Debug)]
pub struct ProcfsResolver {
    root: PathBuf,
    sock_diag: RefCell<Option<SockDiagSocket>>,
    /// Synthetic procfs roots cannot answer netlink queries. Keeping this
    /// switch test-only makes a production TCP/UDP downgrade unrepresentable.
    #[cfg(test)]
    use_procfs_socket_lookup: bool,
    /// The daemon creates all of its threads with the standard Rust thread
    /// runtime, which shares one descriptor table. Its own TGID can therefore
    /// be checked through `/proc/<tgid>/fd` before and after the external-owner
    /// scan instead of once for every observer and worker task. An unexpected
    /// matching socket in that table is denied rather than attributed to the
    /// firewall daemon. This optimization must be re-audited if daemon code
    /// ever unshares `CLONE_FILES`, uses `CLOSE_RANGE_UNSHARE`, receives a file
    /// descriptor from another process, or changes a thread's filesystem UID
    /// independently.
    daemon_process_id: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnerTask {
    process_id: u32,
    tid: u32,
    path: PathBuf,
    fd_path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SocketOwnerKey {
    inode: u64,
    uid: u32,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct OwnerSnapshot {
    unique: BTreeMap<SocketOwnerKey, Vec<OwnerTask>>,
    failures: BTreeMap<SocketOwnerKey, String>,
}

/// Per-request failure retained while a batched attribution is assembled.
///
/// `anyhow` context is intentionally flattened only after recording whether
/// the original chain contained the bounded-attribution timeout marker. The
/// marker is reconstructed when the result is returned so NFQUEUE accounting
/// can distinguish overload from ordinary deny decisions.
#[derive(Clone, Debug, Eq, PartialEq)]
struct BatchResolutionFailure {
    message: String,
    attribution_timeout: bool,
}

impl BatchResolutionFailure {
    fn message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            attribution_timeout: false,
        }
    }

    fn from_error(error: &anyhow::Error) -> Self {
        Self {
            message: format!("{error:#}"),
            attribution_timeout: is_attribution_timeout(error),
        }
    }

    fn into_error(self) -> anyhow::Error {
        if self.attribution_timeout {
            anyhow::Error::new(ProcfsAttributionTimeout).context(self.message)
        } else {
            anyhow!(self.message)
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct SocketFdSearch<'a> {
    target: &'a str,
    expected_uid: u32,
    deadline: Instant,
    maximum_fds: usize,
    preferred_fd_name: Option<&'a OsStr>,
}

impl Default for ProcfsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcfsResolver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("/proc"),
            sock_diag: RefCell::new(None),
            #[cfg(test)]
            use_procfs_socket_lookup: false,
            daemon_process_id: Some(std::process::id()),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            sock_diag: RefCell::new(None),
            use_procfs_socket_lookup: true,
            daemon_process_id: None,
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn at_with_daemon_process(root: impl Into<PathBuf>, daemon_process_id: u32) -> Self {
        Self {
            root: root.into(),
            sock_diag: RefCell::new(None),
            use_procfs_socket_lookup: true,
            daemon_process_id: Some(daemon_process_id),
        }
    }

    #[cfg(test)]
    pub fn resolve(&self, connection: &OutboundConnection) -> Result<ApplicationIdentity> {
        self.resolve_with_requirements(connection, IdentityCaptureRequirements::full())
    }

    #[cfg(test)]
    pub(crate) fn resolve_for_enforcement(
        &self,
        connection: &OutboundConnection,
        requirements: IdentityCaptureRequirements,
    ) -> Result<ApplicationIdentity> {
        if requirements == IdentityCaptureRequirements::full() {
            return self.resolve(connection);
        }
        self.resolve_with_requirements(connection, requirements)
    }

    /// Resolves a bounded group of independently queued packets while sharing
    /// only the exhaustive socket-owner discovery passes.
    ///
    /// `SOCK_DIAG` lookup remains per request. Identity capture is shared only
    /// for requests in this batch which resolve to the same inode, UID and
    /// capture requirements. Two complete procfs owner snapshots bracket those
    /// captures, and every request is accepted only when its unique owner is
    /// byte-for-byte stable across both snapshots. This amortizes directory
    /// traversal without creating a long-lived authorization cache: a later
    /// UDP batch starts attribution again from `SOCK_DIAG`.
    pub(crate) fn resolve_batch_for_enforcement(
        &self,
        requests: &[(&OutboundConnection, IdentityCaptureRequirements)],
    ) -> Vec<Result<ApplicationIdentity>> {
        self.resolve_batch_for_enforcement_until(requests, Instant::now() + PROC_SCAN_DEADLINE)
    }

    fn resolve_batch_for_enforcement_until(
        &self,
        requests: &[(&OutboundConnection, IdentityCaptureRequirements)],
        deadline: Instant,
    ) -> Vec<Result<ApplicationIdentity>> {
        if requests.is_empty() {
            return Vec::new();
        }
        if requests.len() == 1 {
            return vec![self.resolve_with_requirements_until(
                requests[0].0,
                requests[0].1,
                deadline,
            )];
        }
        if requests.len() > MAX_ATTRIBUTION_BATCH_SIZE {
            return requests
                .iter()
                .map(|_| {
                    Err(anyhow!(
                        "application attribution batch exceeds its fixed bound"
                    ))
                })
                .collect();
        }

        let (keys, mut errors, targets) = self.resolve_batch_socket_keys(requests, deadline);

        let before = if targets.is_empty() {
            OwnerSnapshot::default()
        } else {
            match self.resolve_unique_process_tasks_batch(
                &targets,
                deadline,
                MAX_FDS_PER_TASK,
                MAX_PROC_ENTRIES,
            ) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    let error =
                        error.context("cannot establish the first batched socket-owner snapshot");
                    let failure = BatchResolutionFailure::from_error(&error);
                    for (key, slot) in keys.iter().zip(&mut errors) {
                        if key.is_some() && slot.is_none() {
                            *slot = Some(failure.clone());
                        }
                    }
                    return batch_resolution_results(errors, vec![None; requests.len()]);
                }
            }
        };

        let mut identities = vec![None; requests.len()];
        let mut capture_results = BTreeMap::<
            (SocketOwnerKey, IdentityCaptureRequirements),
            std::result::Result<ApplicationIdentity, BatchResolutionFailure>,
        >::new();
        for (index, ((_, requirements), key)) in requests.iter().zip(&keys).enumerate() {
            let Some(key) = key else {
                continue;
            };
            if let Some(failure) = before.failures.get(key) {
                errors[index] = Some(BatchResolutionFailure::message(failure.clone()));
                continue;
            }
            let Some(owners) = before.unique.get(key) else {
                errors[index] = Some(BatchResolutionFailure::message(
                    "batched socket-owner snapshot omitted a target",
                ));
                continue;
            };
            let capture_key = (*key, *requirements);
            let captured = capture_results
                .entry(capture_key)
                .or_insert_with(|| {
                    Self::capture_owner_identity(
                        owners.clone(),
                        key.inode,
                        key.uid,
                        deadline,
                        *requirements,
                    )
                    .map_err(|error| BatchResolutionFailure::from_error(&error))
                })
                .clone();
            match captured {
                Ok(identity) => identities[index] = Some(identity),
                Err(failure) => errors[index] = Some(failure),
            }
        }

        reject_inconsistent_batch_identities(&keys, &mut errors, &mut identities);
        self.revalidate_batch_owners(&keys, &before, deadline, &mut errors, &mut identities);

        batch_resolution_results(errors, identities)
    }

    fn resolve_batch_socket_keys(
        &self,
        requests: &[(&OutboundConnection, IdentityCaptureRequirements)],
        deadline: Instant,
    ) -> (
        Vec<Option<SocketOwnerKey>>,
        Vec<Option<BatchResolutionFailure>>,
        BTreeSet<SocketOwnerKey>,
    ) {
        let mut keys = Vec::with_capacity(requests.len());
        let mut errors = Vec::with_capacity(requests.len());
        let mut targets = BTreeSet::new();
        for (connection, _) in requests {
            let resolved = (|| {
                connection.validate()?;
                self.resolve_socket_inode(connection, deadline)
                    .context("cannot resolve socket inode for batched attribution")
            })();
            match resolved {
                Ok(inode) => {
                    let key = SocketOwnerKey {
                        inode,
                        uid: connection.socket_uid,
                    };
                    targets.insert(key);
                    keys.push(Some(key));
                    errors.push(None);
                }
                Err(error) => {
                    keys.push(None);
                    errors.push(Some(BatchResolutionFailure::from_error(&error)));
                }
            }
        }
        (keys, errors, targets)
    }

    fn revalidate_batch_owners(
        &self,
        keys: &[Option<SocketOwnerKey>],
        before: &OwnerSnapshot,
        deadline: Instant,
        errors: &mut [Option<BatchResolutionFailure>],
        identities: &mut [Option<ApplicationIdentity>],
    ) {
        let successful_targets = keys
            .iter()
            .zip(identities.iter())
            .filter_map(|(key, identity)| identity.as_ref().and(*key))
            .collect::<BTreeSet<_>>();
        if successful_targets.is_empty() {
            return;
        }
        let after = match self.resolve_unique_process_tasks_batch(
            &successful_targets,
            deadline,
            MAX_FDS_PER_TASK,
            MAX_PROC_ENTRIES,
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let error =
                    error.context("cannot establish the final batched socket-owner snapshot");
                let failure = BatchResolutionFailure::from_error(&error);
                for (identity, slot) in identities.iter_mut().zip(errors) {
                    if identity.take().is_some() {
                        *slot = Some(failure.clone());
                    }
                }
                return;
            }
        };
        for (index, key) in keys.iter().enumerate() {
            let Some(key) = key else {
                continue;
            };
            if identities[index].is_none() {
                continue;
            }
            if let Some(failure) = after.failures.get(key) {
                identities[index] = None;
                errors[index] = Some(BatchResolutionFailure::message(format!(
                    "socket ownership became unsafe during batched attribution: {failure}"
                )));
            } else if before.unique.get(key) != after.unique.get(key) {
                identities[index] = None;
                errors[index] = Some(BatchResolutionFailure::message(
                    "socket ownership changed during batched attribution",
                ));
            }
        }
    }

    #[cfg(test)]
    fn resolve_with_requirements(
        &self,
        connection: &OutboundConnection,
        requirements: IdentityCaptureRequirements,
    ) -> Result<ApplicationIdentity> {
        self.resolve_with_requirements_until(
            connection,
            requirements,
            Instant::now() + PROC_SCAN_DEADLINE,
        )
    }

    fn resolve_with_requirements_until(
        &self,
        connection: &OutboundConnection,
        requirements: IdentityCaptureRequirements,
        deadline: Instant,
    ) -> Result<ApplicationIdentity> {
        connection.validate()?;
        let inode = self.resolve_socket_inode(connection, deadline)?;
        let owners = self.resolve_unique_process_tasks(
            inode,
            connection.socket_uid,
            deadline,
            MAX_FDS_PER_TASK,
        )?;
        Self::capture_owner_identity(owners, inode, connection.socket_uid, deadline, requirements)
    }

    fn capture_owner_identity(
        owners: Vec<OwnerTask>,
        inode: u64,
        uid: u32,
        deadline: Instant,
        requirements: IdentityCaptureRequirements,
    ) -> Result<ApplicationIdentity> {
        let mut identities = owners
            .into_iter()
            .map(|owner| {
                Self::capture_identity(
                    &owner.path,
                    owner.tid,
                    &owner.fd_path,
                    inode,
                    uid,
                    deadline,
                    requirements,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let identity = identities
            .pop()
            .ok_or_else(|| anyhow!("attributed process has no socket-owning task"))?;
        ensure!(
            identities
                .iter()
                .all(|other| equivalent_enforcement_identity(other, &identity)),
            "socket-owning tasks have ambiguous application identities"
        );
        Ok(identity)
    }

    fn resolve_socket_inode(
        &self,
        connection: &OutboundConnection,
        deadline: Instant,
    ) -> Result<u64> {
        #[cfg(test)]
        if self.use_procfs_socket_lookup {
            return self.resolve_socket_inode_from_procfs(connection, deadline);
        }
        if matches!(
            connection.protocol,
            TransportProtocol::Tcp | TransportProtocol::Udp
        ) {
            // There is intentionally no procfs fallback here. A SOCK_DIAG
            // error, incomplete dump, or ambiguous response denies this
            // packet instead of changing attribution semantics at runtime.
            return self
                .resolve_socket_inode_with_sock_diag(connection, deadline)
                .context("cannot resolve socket inode through NETLINK_SOCK_DIAG");
        }
        self.resolve_socket_inode_from_procfs(connection, deadline)
    }

    fn resolve_socket_inode_with_sock_diag(
        &self,
        connection: &OutboundConnection,
        deadline: Instant,
    ) -> Result<u64> {
        let mut diagnostic = self
            .sock_diag
            .try_borrow_mut()
            .map_err(|_| anyhow!("NETLINK_SOCK_DIAG resolver is already in use"))?;
        if diagnostic.is_none() {
            *diagnostic = Some(SockDiagSocket::open(deadline)?);
        }
        let result = diagnostic
            .as_mut()
            .ok_or_else(|| anyhow!("NETLINK_SOCK_DIAG resolver did not initialize"))?
            .query(connection, deadline);
        if result.is_err() {
            // A timed-out or malformed multipart response can leave unread
            // datagrams behind. Close the socket on every failed query so a
            // later packet can never consume stale data under a new sequence.
            diagnostic.take();
        }
        result
    }

    fn resolve_socket_inode_from_procfs(
        &self,
        connection: &OutboundConnection,
        deadline: Instant,
    ) -> Result<u64> {
        let table_name = match (connection.protocol, connection.source_address) {
            (TransportProtocol::Tcp, IpAddr::V4(_)) => "tcp",
            (TransportProtocol::Tcp, IpAddr::V6(_)) => "tcp6",
            (TransportProtocol::Udp, IpAddr::V4(_)) => "udp",
            (TransportProtocol::Udp, IpAddr::V6(_)) => "udp6",
            (TransportProtocol::Icmp, IpAddr::V4(_)) => "icmp",
            (TransportProtocol::IcmpV6, IpAddr::V6(_)) => "icmp6",
            _ => bail!("unsupported protocol/address-family combination"),
        };
        let table = read_bounded(
            &self.root.join("self").join("net").join(table_name),
            MAX_SOCKET_TABLE_BYTES,
            deadline,
        )
        .with_context(|| format!("cannot read /proc/self/net/{table_name}"))?;
        let text = std::str::from_utf8(&table).context("socket table is not UTF-8 ASCII")?;
        let mut candidate_inode = None;
        let mut ambiguous = false;
        for (index, line) in text.lines().skip(1).enumerate() {
            ensure_within_deadline(deadline)?;
            ensure!(
                index < MAX_PROC_ENTRIES,
                "socket table entry bound exceeded"
            );
            if let Some(candidate) = parse_socket_line(line)?
                && candidate.uid == connection.socket_uid
                && candidate.matches(connection)
            {
                match candidate_inode {
                    None => candidate_inode = Some(candidate.inode),
                    Some(inode) if inode == candidate.inode => {}
                    Some(_) => ambiguous = true,
                }
            }
        }
        ensure!(
            candidate_inode.is_some() && !ambiguous,
            "socket attribution is missing or ambiguous"
        );
        ensure_within_deadline(deadline)?;
        candidate_inode.ok_or_else(|| anyhow!("socket attribution disappeared"))
    }

    fn resolve_unique_process_tasks(
        &self,
        inode: u64,
        uid: u32,
        deadline: Instant,
        maximum_fds: usize,
    ) -> Result<Vec<OwnerTask>> {
        ensure!(maximum_fds > 0, "per-task fd bound is zero");
        let target = format!("socket:[{inode}]");
        let process_ids = enumerate_process_ids(&self.root, deadline)?;
        if let Some(daemon_process_id) = self.daemon_process_id {
            Self::reject_daemon_socket_owner(
                &self.root.join(daemon_process_id.to_string()),
                inode,
                uid,
                deadline,
                maximum_fds,
            )?;
        }
        let mut owners: BTreeMap<u32, Vec<OwnerTask>> = BTreeMap::new();
        let mut task_count = 0_usize;
        let mut preferred_fd_name: Option<OsString> = None;
        for process_id in process_ids {
            ensure_within_deadline(deadline)?;
            let process = self.root.join(process_id.to_string());
            if self.daemon_process_id == Some(process_id) {
                continue;
            }
            let task_root = process.join("task");
            let Some(task_ids) =
                enumerate_task_ids(&process, &task_root, process_id, deadline, &mut task_count)?
            else {
                continue;
            };
            for tid in task_ids {
                ensure_within_deadline(deadline)?;
                let task = task_root.join(tid.to_string());
                let search = SocketFdSearch {
                    target: &target,
                    expected_uid: uid,
                    deadline,
                    maximum_fds,
                    preferred_fd_name: preferred_fd_name.as_deref(),
                };
                if let Some(fd_path) = task_socket_fd(&task, process_id, tid, search)? {
                    if preferred_fd_name.is_none() {
                        preferred_fd_name = Some(
                            fd_path
                                .file_name()
                                .ok_or_else(|| anyhow!("socket descriptor path has no file name"))?
                                .to_os_string(),
                        );
                    }
                    owners.entry(process_id).or_default().push(OwnerTask {
                        process_id,
                        tid,
                        path: task,
                        fd_path,
                    });
                }
            }
            ensure!(
                owners.len() <= 1,
                "socket is shared by multiple processes; attribution is ambiguous"
            );
        }
        if let Some(daemon_process_id) = self.daemon_process_id {
            Self::reject_daemon_socket_owner(
                &self.root.join(daemon_process_id.to_string()),
                inode,
                uid,
                deadline,
                maximum_fds,
            )?;
        }
        ensure_within_deadline(deadline)?;
        owners
            .into_iter()
            .next()
            .map(|(_tgid, tasks)| tasks)
            .ok_or_else(|| anyhow!("no process owns the attributed socket inode"))
    }

    fn resolve_unique_process_tasks_batch(
        &self,
        targets: &BTreeSet<SocketOwnerKey>,
        deadline: Instant,
        maximum_fds: usize,
        maximum_owner_records: usize,
    ) -> Result<OwnerSnapshot> {
        ensure!(!targets.is_empty(), "socket-owner batch is empty");
        ensure!(
            targets.len() <= MAX_ATTRIBUTION_BATCH_SIZE,
            "socket-owner batch exceeds its fixed bound"
        );
        ensure!(maximum_fds > 0, "per-task fd bound is zero");
        ensure!(
            maximum_owner_records > 0,
            "batched socket-owner record bound is zero"
        );

        let targets_by_uid = socket_targets_by_uid(targets);
        let mut daemon_owned =
            self.daemon_owned_targets_for_batch(&targets_by_uid, deadline, maximum_fds)?;

        let mut owners = BTreeMap::<SocketOwnerKey, BTreeMap<u32, Vec<OwnerTask>>>::new();
        let mut ambiguous_targets = BTreeSet::new();
        let mut owner_records = 0_usize;
        let process_ids = enumerate_process_ids(&self.root, deadline)?;
        let mut task_count = 0_usize;
        for process_id in process_ids {
            ensure_within_deadline(deadline)?;
            if self.daemon_process_id == Some(process_id) {
                continue;
            }
            let process = self.root.join(process_id.to_string());
            let task_root = process.join("task");
            let Some(task_ids) =
                enumerate_task_ids(&process, &task_root, process_id, deadline, &mut task_count)?
            else {
                continue;
            };
            for tid in task_ids {
                ensure_within_deadline(deadline)?;
                let task = task_root.join(tid.to_string());
                let observed_uid = match read_process_fs_uid(&task, deadline) {
                    Ok(uid) => uid,
                    Err(error) => {
                        if path_disappeared(&task)? {
                            continue;
                        }
                        return Err(error).with_context(|| {
                            format!("cannot inspect filesystem UID for task {tid}")
                        });
                    }
                };
                let Some(inodes) = targets_by_uid.get(&observed_uid) else {
                    continue;
                };
                let matches = task_socket_fds_for_inodes(
                    &task,
                    process_id,
                    tid,
                    observed_uid,
                    inodes,
                    deadline,
                    maximum_fds,
                )?;
                for (inode, fd_path) in matches {
                    let key = SocketOwnerKey {
                        inode,
                        uid: observed_uid,
                    };
                    if ambiguous_targets.contains(&key) {
                        continue;
                    }
                    let process_owners = owners.entry(key).or_default();
                    if !process_owners.is_empty() && !process_owners.contains_key(&process_id) {
                        process_owners.clear();
                        ambiguous_targets.insert(key);
                        continue;
                    }
                    owner_records = owner_records
                        .checked_add(1)
                        .ok_or_else(|| anyhow!("batched socket-owner record count overflowed"))?;
                    ensure!(
                        owner_records <= maximum_owner_records,
                        "batched socket-owner record bound exceeded"
                    );
                    process_owners
                        .entry(process_id)
                        .or_default()
                        .push(OwnerTask {
                            process_id,
                            tid,
                            path: task.clone(),
                            fd_path,
                        });
                }
            }
        }

        daemon_owned.extend(self.daemon_owned_targets_for_batch(
            &targets_by_uid,
            deadline,
            maximum_fds,
        )?);
        ensure_within_deadline(deadline)?;

        Self::finish_owner_snapshot(targets, &daemon_owned, &ambiguous_targets, owners)
    }

    fn daemon_owned_targets_for_batch(
        &self,
        targets_by_uid: &BTreeMap<u32, BTreeSet<u64>>,
        deadline: Instant,
        maximum_fds: usize,
    ) -> Result<BTreeSet<SocketOwnerKey>> {
        let Some(daemon_process_id) = self.daemon_process_id else {
            return Ok(BTreeSet::new());
        };
        Self::daemon_owned_targets(
            &self.root.join(daemon_process_id.to_string()),
            targets_by_uid,
            deadline,
            maximum_fds,
        )
    }

    fn finish_owner_snapshot(
        targets: &BTreeSet<SocketOwnerKey>,
        daemon_owned: &BTreeSet<SocketOwnerKey>,
        ambiguous_targets: &BTreeSet<SocketOwnerKey>,
        mut owners: BTreeMap<SocketOwnerKey, BTreeMap<u32, Vec<OwnerTask>>>,
    ) -> Result<OwnerSnapshot> {
        let mut snapshot = OwnerSnapshot::default();
        for target in targets {
            if daemon_owned.contains(target) {
                snapshot.failures.insert(
                    *target,
                    "the firewall daemon unexpectedly owns the attributed application socket"
                        .to_owned(),
                );
                continue;
            }
            if ambiguous_targets.contains(target) {
                snapshot.failures.insert(
                    *target,
                    "socket is shared by multiple processes; attribution is ambiguous".to_owned(),
                );
                continue;
            }
            let Some(mut process_owners) = owners.remove(target) else {
                snapshot.failures.insert(
                    *target,
                    "no process owns the attributed socket inode".to_owned(),
                );
                continue;
            };
            if process_owners.len() != 1 {
                snapshot.failures.insert(
                    *target,
                    "socket is shared by multiple processes; attribution is ambiguous".to_owned(),
                );
                continue;
            }
            let owner_tasks = process_owners
                .pop_first()
                .map(|(_process_id, tasks)| tasks)
                .ok_or_else(|| anyhow!("unique socket-owner process disappeared"))?;
            snapshot.unique.insert(*target, owner_tasks);
        }
        Ok(snapshot)
    }

    fn daemon_owned_targets(
        process: &Path,
        targets_by_uid: &BTreeMap<u32, BTreeSet<u64>>,
        deadline: Instant,
        maximum_fds: usize,
    ) -> Result<BTreeSet<SocketOwnerKey>> {
        let uid_before = read_process_fs_uid(process, deadline)
            .context("cannot verify the firewall daemon filesystem UID")?;
        let Some(inodes) = targets_by_uid.get(&uid_before) else {
            return Ok(BTreeSet::new());
        };
        let descriptors = fs::read_dir(process.join("fd"))
            .context("cannot inspect the firewall daemon descriptor table")?;
        let matches = scan_fd_entries_for_inodes(
            descriptors,
            inodes,
            deadline,
            maximum_fds,
            "firewall daemon",
        )?;
        if !matches.is_empty() {
            let uid_after = read_process_fs_uid(process, deadline)
                .context("cannot re-verify the firewall daemon filesystem UID")?;
            ensure!(
                uid_before == uid_after,
                "firewall daemon filesystem UID changed during descriptor scan"
            );
        }
        Ok(matches
            .into_keys()
            .map(|inode| SocketOwnerKey {
                inode,
                uid: uid_before,
            })
            .collect())
    }

    fn reject_daemon_socket_owner(
        process: &Path,
        inode: u64,
        expected_uid: u32,
        deadline: Instant,
        maximum_fds: usize,
    ) -> Result<()> {
        let daemon_uid = read_process_fs_uid(process, deadline)
            .context("cannot verify the firewall daemon filesystem UID")?;
        if daemon_uid != expected_uid {
            // This is the same UID filter applied before every other task fd
            // scan. A cross-UID descriptor holder is deliberately not an
            // attributable owner (see the threat model).
            return Ok(());
        }
        let target = format!("socket:[{inode}]");
        ensure!(
            find_socket_fd_bounded(process, &target, deadline, maximum_fds)
                .context("cannot inspect the firewall daemon descriptor table")?
                .is_none(),
            "the firewall daemon unexpectedly owns the attributed application socket"
        );
        Ok(())
    }

    fn capture_identity(
        process: &Path,
        pid: u32,
        fd_path: &Path,
        inode: u64,
        expected_uid: u32,
        deadline: Instant,
        requirements: IdentityCaptureRequirements,
    ) -> Result<ApplicationIdentity> {
        let socket_target = format!("socket:[{inode}]");
        let fd_path = verified_socket_fd(process, fd_path, &socket_target, deadline)?;
        let start_before = read_start_time(process, deadline)?;
        let uid_before = read_process_fs_uid(process, deadline)?;
        ensure!(uid_before == expected_uid, "process/socket uid mismatch");

        ensure_within_deadline(deadline)?;
        let executable_link_before =
            fs::read_link(process.join("exe")).context("cannot read process executable link")?;
        ensure_within_deadline(deadline)?;
        let executable_text = executable_link_before
            .to_str()
            .ok_or_else(|| anyhow!("process executable path is not UTF-8"))?;
        let executable = ApplicationPath::new(executable_text.to_owned())?;
        let executable_handle =
            File::open(process.join("exe")).context("cannot pin process executable")?;
        ensure_within_deadline(deadline)?;
        let executable_metadata = executable_handle
            .metadata()
            .context("cannot inspect pinned process executable")?;
        ensure_within_deadline(deadline)?;
        let executable_file = executable_file_id(&executable_metadata)
            .context("cannot identify pinned process executable version")?;

        let command_line = if requirements.command_line {
            read_command_line(process, deadline)?
        } else {
            Vec::new()
        };
        let cgroups = if requirements.cgroups {
            read_cgroups(process, deadline)?
        } else {
            Vec::new()
        };

        ensure_within_deadline(deadline)?;
        let executable_link_after =
            fs::read_link(process.join("exe")).context("cannot re-read process executable link")?;
        ensure_within_deadline(deadline)?;
        let executable_after_metadata = File::open(process.join("exe"))
            .context("cannot re-pin process executable")?
            .metadata()
            .context("cannot re-inspect process executable")?;
        let executable_file_after = executable_file_id(&executable_after_metadata)
            .context("cannot re-identify pinned process executable version")?;
        ensure_within_deadline(deadline)?;
        let command_line_after = if requirements.command_line {
            read_command_line(process, deadline)?
        } else {
            Vec::new()
        };
        let cgroups_after = if requirements.cgroups {
            read_cgroups(process, deadline)?
        } else {
            Vec::new()
        };
        let start_after = read_start_time(process, deadline)?;
        let uid_after = read_process_fs_uid(process, deadline)?;
        ensure!(
            executable_link_before == executable_link_after
                && executable_file == executable_file_after
                && command_line == command_line_after
                && cgroups == cgroups_after
                && start_before == start_after
                && uid_before == uid_after,
            "process identity changed while it was captured"
        );
        ensure_within_deadline(deadline)?;
        let final_socket_link = fs::read_link(&fd_path)
            .ok()
            .and_then(|link| link.to_str().map(ToOwned::to_owned));
        ensure_within_deadline(deadline)?;
        ensure!(
            final_socket_link.as_deref() == Some(socket_target.as_str()),
            "process closed or replaced the attributed socket"
        );

        let identity = ApplicationIdentity {
            pid,
            process_start_time_ticks: start_before,
            executable,
            executable_file,
            command_line,
            uid: uid_before,
            cgroups,
        };
        identity.validate()?;
        Ok(identity)
    }
}

fn enumerate_process_ids(root: &Path, deadline: Instant) -> Result<Vec<u32>> {
    let mut process_ids = Vec::new();
    ensure_within_deadline(deadline)?;
    for entry in fs::read_dir(root).context("cannot enumerate procfs")? {
        ensure_within_deadline(deadline)?;
        let entry = entry.context("cannot read procfs directory entry")?;
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let Ok(process_id) = name.parse::<u32>() else {
            continue;
        };
        process_ids.push(process_id);
        ensure!(
            process_ids.len() <= MAX_PROC_ENTRIES,
            "procfs process bound exceeded"
        );
    }
    process_ids.sort_unstable();
    Ok(process_ids)
}

fn enumerate_task_ids(
    process: &Path,
    task_root: &Path,
    process_id: u32,
    deadline: Instant,
    task_count: &mut usize,
) -> Result<Option<Vec<u32>>> {
    let entries = match fs::read_dir(task_root) {
        Ok(entries) => entries,
        Err(error) if procfs_enumeration_may_indicate_disappearance(&error) => {
            if procfs_subject_disappeared_after(&error, process)? {
                return Ok(None);
            }
            return Err(error).with_context(|| {
                format!(
                    "cannot prove socket ownership: task list for live process {process_id} is unavailable"
                )
            });
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot enumerate task list for process {process_id}"));
        }
    };
    let mut task_ids = Vec::new();
    for entry in entries {
        ensure_within_deadline(deadline)?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot inspect task entry for process {process_id}")
                });
            }
        };
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let Ok(task_id) = name.parse::<u32>() else {
            continue;
        };
        *task_count = task_count
            .checked_add(1)
            .ok_or_else(|| anyhow!("procfs task count overflow"))?;
        ensure!(
            *task_count <= MAX_PROC_ENTRIES,
            "procfs task bound exceeded"
        );
        task_ids.push(task_id);
    }
    task_ids.sort_unstable();
    if task_ids.is_empty() {
        if path_disappeared(process)? {
            return Ok(None);
        }
        bail!("cannot prove socket ownership: live process {process_id} has no enumerable tasks");
    }
    Ok(Some(task_ids))
}

fn task_socket_fd(
    task: &Path,
    process_id: u32,
    task_id: u32,
    search: SocketFdSearch<'_>,
) -> Result<Option<PathBuf>> {
    let observed_fsuid = match read_process_fs_uid(task, search.deadline) {
        Ok(uid) => uid,
        Err(error) => {
            if path_disappeared(task)? {
                return Ok(None);
            }
            return Err(error)
                .with_context(|| format!("cannot inspect filesystem UID for task {task_id}"));
        }
    };
    if observed_fsuid != search.expected_uid {
        return Ok(None);
    }
    if let Some(fd_name) = search.preferred_fd_name {
        let preferred_path = task.join("fd").join(fd_name);
        let preferred_link = match fs::read_link(&preferred_path) {
            Ok(link) => link.to_str().map(ToOwned::to_owned),
            // The fd number is only an optimization hint learned earlier in
            // this exhaustive scan. Any miss or error falls back to the
            // original bounded directory walk, including its zombie and
            // disappearance handling; the hint is never authorization.
            Err(_) => None,
        };
        ensure_within_deadline(search.deadline)?;
        if preferred_link.as_deref() == Some(search.target) {
            verify_socket_owner_uid(
                task,
                task_id,
                observed_fsuid,
                search.expected_uid,
                search.deadline,
            )?;
            return Ok(Some(preferred_path));
        }
    }
    let descriptors = match fs::read_dir(task.join("fd")) {
        Ok(entries) => entries,
        Err(error) if procfs_enumeration_may_indicate_disappearance(&error) => {
            if procfs_subject_disappeared_after(&error, task)? {
                return Ok(None);
            }
            return Err(error).with_context(|| {
                format!(
                    "cannot prove socket ownership: descriptor table for live task {task_id} is unavailable"
                )
            });
        }
        Err(error) => {
            if error.kind() == ErrorKind::PermissionDenied
                && task_id == process_id
                && task_is_stably_zombie(task, search.deadline)?
            {
                // A terminated thread-group leader can remain as a zombie
                // while workers continue. Linux has already run exit_files()
                // for a zombie, so its inaccessible fd directory cannot hide
                // a socket owner. Continue scanning the live worker tasks.
                return Ok(None);
            }
            return Err(error)
                .with_context(|| format!("cannot enumerate descriptor table for task {task_id}"));
        }
    };
    ensure_within_deadline(search.deadline)?;
    for (count, entry) in descriptors.enumerate() {
        ensure!(
            count < search.maximum_fds,
            "cannot prove unique socket ownership: per-task fd bound exceeded"
        );
        ensure_within_deadline(search.deadline)?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot inspect descriptor entry for task {task_id}")
                });
            }
        };
        let link = match fs::read_link(entry.path()) {
            Ok(link) => link.to_str().map(ToOwned::to_owned),
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot inspect descriptor link for task {task_id}"));
            }
        };
        ensure_within_deadline(search.deadline)?;
        if link.as_deref() == Some(search.target) {
            verify_socket_owner_uid(
                task,
                task_id,
                observed_fsuid,
                search.expected_uid,
                search.deadline,
            )?;
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

fn task_socket_fds_for_inodes(
    task: &Path,
    process_id: u32,
    task_id: u32,
    observed_fsuid: u32,
    target_inodes: &BTreeSet<u64>,
    deadline: Instant,
    maximum_fds: usize,
) -> Result<BTreeMap<u64, PathBuf>> {
    let descriptors = match fs::read_dir(task.join("fd")) {
        Ok(entries) => entries,
        Err(error) if procfs_enumeration_may_indicate_disappearance(&error) => {
            if procfs_subject_disappeared_after(&error, task)? {
                return Ok(BTreeMap::new());
            }
            return Err(error).with_context(|| {
                format!(
                    "cannot prove batched socket ownership: descriptor table for live task {task_id} is unavailable"
                )
            });
        }
        Err(error) => {
            if error.kind() == ErrorKind::PermissionDenied
                && task_id == process_id
                && task_is_stably_zombie(task, deadline)?
            {
                return Ok(BTreeMap::new());
            }
            return Err(error)
                .with_context(|| format!("cannot enumerate descriptor table for task {task_id}"));
        }
    };
    let matches = scan_fd_entries_for_inodes(
        descriptors,
        target_inodes,
        deadline,
        maximum_fds,
        "application task",
    )?;
    if !matches.is_empty() {
        verify_socket_owner_uid(task, task_id, observed_fsuid, observed_fsuid, deadline)?;
    }
    Ok(matches)
}

fn scan_fd_entries_for_inodes(
    descriptors: fs::ReadDir,
    target_inodes: &BTreeSet<u64>,
    deadline: Instant,
    maximum_fds: usize,
    subject: &str,
) -> Result<BTreeMap<u64, PathBuf>> {
    let mut matches = BTreeMap::<u64, PathBuf>::new();
    for (count, entry) in descriptors.enumerate() {
        ensure!(
            count < maximum_fds,
            "cannot prove unique batched socket ownership: {subject} fd bound exceeded"
        );
        ensure_within_deadline(deadline)?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot inspect {subject} descriptor entry"));
            }
        };
        let link = match fs::read_link(entry.path()) {
            Ok(link) => link,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot inspect {subject} descriptor link"));
            }
        };
        ensure_within_deadline(deadline)?;
        let Some(inode) = socket_inode_from_link(&link) else {
            continue;
        };
        if !target_inodes.contains(&inode) {
            continue;
        }
        let path = entry.path();
        matches
            .entry(inode)
            .and_modify(|current| {
                if path < *current {
                    current.clone_from(&path);
                }
            })
            .or_insert(path);
    }
    Ok(matches)
}

fn socket_inode_from_link(link: &Path) -> Option<u64> {
    let text = link.to_str()?;
    let inode = text.strip_prefix("socket:[")?.strip_suffix(']')?;
    if inode.is_empty() || !inode.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    inode.parse().ok()
}

fn socket_targets_by_uid(targets: &BTreeSet<SocketOwnerKey>) -> BTreeMap<u32, BTreeSet<u64>> {
    let mut targets_by_uid = BTreeMap::<u32, BTreeSet<u64>>::new();
    for target in targets {
        targets_by_uid
            .entry(target.uid)
            .or_default()
            .insert(target.inode);
    }
    targets_by_uid
}

fn reject_inconsistent_batch_identities(
    keys: &[Option<SocketOwnerKey>],
    errors: &mut [Option<BatchResolutionFailure>],
    identities: &mut [Option<ApplicationIdentity>],
) {
    let mut first_identity_indexes = BTreeMap::<SocketOwnerKey, usize>::new();
    let mut inconsistent = BTreeSet::new();
    for (index, (key, identity)) in keys.iter().zip(identities.iter()).enumerate() {
        let (Some(key), Some(identity)) = (key, identity) else {
            continue;
        };
        if let Some(first_index) = first_identity_indexes.get(key) {
            let Some(first_identity) = identities[*first_index].as_ref() else {
                continue;
            };
            if !equivalent_mandatory_process_identity(first_identity, identity) {
                inconsistent.insert(*key);
            }
        } else {
            first_identity_indexes.insert(*key, index);
        }
    }
    for ((key, error), identity) in keys.iter().zip(errors).zip(identities) {
        if key.is_some_and(|key| inconsistent.contains(&key)) && identity.take().is_some() {
            *error = Some(BatchResolutionFailure::message(
                "mandatory process identity changed between captures for one socket",
            ));
        }
    }
}

fn equivalent_mandatory_process_identity(
    left: &ApplicationIdentity,
    right: &ApplicationIdentity,
) -> bool {
    left.pid == right.pid
        && left.process_start_time_ticks == right.process_start_time_ticks
        && left.executable == right.executable
        && left.executable_file == right.executable_file
        && left.uid == right.uid
}

fn batch_resolution_results(
    errors: Vec<Option<BatchResolutionFailure>>,
    identities: Vec<Option<ApplicationIdentity>>,
) -> Vec<Result<ApplicationIdentity>> {
    errors
        .into_iter()
        .zip(identities)
        .map(|(error, identity)| match (error, identity) {
            (Some(error), _) => Err(error.into_error()),
            (None, Some(identity)) => Ok(identity),
            (None, None) => Err(anyhow!("batched application identity is unavailable")),
        })
        .collect()
}

fn verify_socket_owner_uid(
    task: &Path,
    task_id: u32,
    observed_fsuid: u32,
    expected_uid: u32,
    deadline: Instant,
) -> Result<()> {
    let owner_uid = read_process_fs_uid(task, deadline)
        .with_context(|| format!("cannot verify socket owner task {task_id}"))?;
    ensure!(
        owner_uid == observed_fsuid && owner_uid == expected_uid,
        "socket owner filesystem UID differs from the kernel socket UID"
    );
    Ok(())
}

fn equivalent_enforcement_identity(
    left: &ApplicationIdentity,
    right: &ApplicationIdentity,
) -> bool {
    left.executable == right.executable
        && left.executable_file == right.executable_file
        && left.command_line == right.command_line
        && left.uid == right.uid
        && left.cgroups == right.cgroups
}

fn procfs_enumeration_may_indicate_disappearance(error: &io::Error) -> bool {
    matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
        || error.raw_os_error() == Some(libc::ESRCH)
}

fn procfs_subject_disappeared_after(error: &io::Error, subject: &Path) -> Result<bool> {
    if !procfs_enumeration_may_indicate_disappearance(error) {
        return Ok(false);
    }
    path_disappeared(subject)
}

fn path_disappeared(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error)
            if error.kind() == ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH) =>
        {
            Ok(true)
        }
        Err(error) => {
            Err(error).with_context(|| format!("cannot recheck procfs path {}", path.display()))
        }
    }
}

fn task_is_stably_zombie(task: &Path, deadline: Instant) -> Result<bool> {
    let before = read_task_state(task, deadline)?;
    ensure_within_deadline(deadline)?;
    let after = read_task_state(task, deadline)?;
    Ok(before == b'Z' && after == b'Z')
}

fn read_task_state(task: &Path, deadline: Instant) -> Result<u8> {
    let bytes = read_bounded(&task.join("stat"), MAX_STAT_BYTES, deadline)?;
    let text = std::str::from_utf8(&bytes).context("task stat is not UTF-8 ASCII")?;
    let close = text
        .rfind(')')
        .ok_or_else(|| anyhow!("task stat has no command terminator"))?;
    let state = text
        .get(close + 1..)
        .ok_or_else(|| anyhow!("task stat is truncated"))?
        .split_ascii_whitespace()
        .next()
        .ok_or_else(|| anyhow!("task stat has no state field"))?;
    ensure!(
        state.len() == 1 && state.is_ascii(),
        "task stat state is invalid"
    );
    state
        .as_bytes()
        .first()
        .copied()
        .ok_or_else(|| anyhow!("task stat state disappeared"))
}

#[derive(Debug, Default)]
struct SockDiagCandidates {
    inode: Option<u64>,
    ambiguous: bool,
    response_bytes: usize,
    message_count: usize,
}

impl SockDiagCandidates {
    fn account_datagram(&mut self, bytes: usize) -> Result<()> {
        self.response_bytes = self
            .response_bytes
            .checked_add(bytes)
            .ok_or_else(|| anyhow!("SOCK_DIAG response byte count overflowed"))?;
        ensure!(
            self.response_bytes <= MAX_SOCK_DIAG_RESPONSE_BYTES,
            "SOCK_DIAG response byte bound exceeded"
        );
        Ok(())
    }

    fn account_message(&mut self) -> Result<()> {
        self.message_count = self
            .message_count
            .checked_add(1)
            .ok_or_else(|| anyhow!("SOCK_DIAG response message count overflowed"))?;
        ensure!(
            self.message_count <= MAX_PROC_ENTRIES,
            "SOCK_DIAG response message bound exceeded"
        );
        Ok(())
    }

    fn observe(&mut self, candidate: SocketCandidate, connection: &OutboundConnection) {
        if candidate.uid != connection.socket_uid || !candidate.matches(connection) {
            return;
        }
        match self.inode {
            None => self.inode = Some(candidate.inode),
            Some(inode) if inode == candidate.inode => {}
            Some(_) => self.ambiguous = true,
        }
    }

    fn finish(self) -> Result<u64> {
        ensure!(
            self.inode.is_some() && !self.ambiguous,
            "socket attribution is missing or ambiguous"
        );
        self.inode
            .ok_or_else(|| anyhow!("socket attribution disappeared"))
    }
}

#[derive(Debug)]
struct SockDiagSocket {
    socket: OwnedFd,
    local_port_id: u32,
    sequence: u32,
    receive_buffer: Box<[u8]>,
}

impl SockDiagSocket {
    fn open(deadline: Instant) -> Result<Self> {
        ensure_within_deadline(deadline)?;
        let socket = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            SockProtocol::NetlinkSockDiag,
        )
        .context("cannot create NETLINK_SOCK_DIAG socket")?;
        bind(socket.as_raw_fd(), &NetlinkAddr::new(0, 0))
            .context("cannot bind NETLINK_SOCK_DIAG socket")?;
        let local_address: NetlinkAddr =
            getsockname(socket.as_raw_fd()).context("cannot inspect NETLINK_SOCK_DIAG socket")?;
        ensure!(
            local_address.pid() != 0 && local_address.groups() == 0,
            "NETLINK_SOCK_DIAG socket has an invalid local address"
        );
        ensure_within_deadline(deadline)?;
        Ok(Self {
            socket,
            local_port_id: local_address.pid(),
            sequence: 0,
            receive_buffer: vec![0_u8; SOCK_DIAG_RECEIVE_BUFFER_BYTES].into_boxed_slice(),
        })
    }

    fn next_sequence(&mut self) -> Result<u32> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow!("NETLINK_SOCK_DIAG sequence space was exhausted"))?;
        Ok(self.sequence)
    }

    fn query(&mut self, connection: &OutboundConnection, deadline: Instant) -> Result<u64> {
        connection.validate()?;
        ensure!(
            matches!(
                connection.protocol,
                TransportProtocol::Tcp | TransportProtocol::Udp
            ),
            "SOCK_DIAG attribution only supports TCP and UDP"
        );
        ensure_within_deadline(deadline)?;

        let sequence = self.next_sequence()?;
        let request = build_sock_diag_request(connection, sequence, self.local_port_id)?;
        ensure_within_deadline(deadline)?;
        let sent = sendto(
            self.socket.as_raw_fd(),
            &request,
            &NetlinkAddr::new(0, 0),
            MsgFlags::empty(),
        )
        .context("cannot send NETLINK_SOCK_DIAG request")?;
        ensure!(sent == request.len(), "SOCK_DIAG request was truncated");

        let mut candidates = SockDiagCandidates::default();
        loop {
            let timeout = attribution_poll_timeout(deadline)?;
            let mut descriptors = [PollFd::new(self.socket.as_fd(), PollFlags::POLLIN)];
            let ready = match poll(&mut descriptors, timeout) {
                Ok(ready) => ready,
                Err(Errno::EINTR) => continue,
                Err(error) => return Err(error).context("cannot poll NETLINK_SOCK_DIAG response"),
            };
            if ready == 0 {
                ensure_within_deadline(deadline)?;
                continue;
            }
            let events = descriptors[0].revents().unwrap_or_else(PollFlags::empty);
            ensure!(
                !events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL),
                "NETLINK_SOCK_DIAG socket failed while receiving a response"
            );
            if !events.contains(PollFlags::POLLIN) {
                continue;
            }

            let received =
                match recvfrom::<NetlinkAddr>(self.socket.as_raw_fd(), &mut self.receive_buffer) {
                    Ok(received) => received,
                    Err(Errno::EINTR | Errno::EAGAIN) => continue,
                    // ENOBUFS means that at least one response was lost.
                    // Continuing could turn an ambiguous socket set into one
                    // apparently unique inode, so every other error is terminal.
                    Err(error) => {
                        return Err(error).context("cannot receive NETLINK_SOCK_DIAG response");
                    }
                };
            let (received_bytes, sender) = received;
            // recvfrom(2) does not expose MSG_TRUNC. Treat a completely filled
            // fixed buffer as potentially truncated; this may conservatively
            // deny an exact-size datagram but cannot hide a missing candidate.
            ensure!(
                received_bytes < self.receive_buffer.len(),
                "NETLINK_SOCK_DIAG datagram reached its truncation boundary"
            );
            let sender =
                sender.ok_or_else(|| anyhow!("SOCK_DIAG response has no sender address"))?;
            ensure!(
                sender.pid() == 0 && sender.groups() == 0,
                "SOCK_DIAG response did not originate from the kernel"
            );
            ensure!(received_bytes != 0, "SOCK_DIAG returned an empty datagram");
            candidates.account_datagram(received_bytes)?;
            ensure_within_deadline(deadline)?;
            if process_sock_diag_datagram(
                &self.receive_buffer[..received_bytes],
                sequence,
                self.local_port_id,
                connection,
                &mut candidates,
            )? {
                ensure_within_deadline(deadline)?;
                return candidates.finish();
            }
            ensure!(
                !candidates.ambiguous,
                "socket attribution is missing or ambiguous"
            );
        }
    }
}

fn attribution_poll_timeout(deadline: Instant) -> Result<u16> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(ProcfsAttributionTimeout)?;
    if remaining.is_zero() {
        return Err(ProcfsAttributionTimeout.into());
    }
    let milliseconds = remaining.as_millis().clamp(1, u128::from(u16::MAX));
    u16::try_from(milliseconds).context("attribution poll timeout is out of range")
}

fn build_sock_diag_request(
    connection: &OutboundConnection,
    sequence: u32,
    local_port_id: u32,
) -> Result<[u8; SOCK_DIAG_REQUEST_BYTES]> {
    let source_port = connection
        .source_port
        .ok_or_else(|| anyhow!("SOCK_DIAG connection has no source port"))?;
    let destination_port = connection
        .destination_port
        .ok_or_else(|| anyhow!("SOCK_DIAG connection has no destination port"))?;
    let family = if connection.source_address.is_ipv4() {
        u8::try_from(libc::AF_INET).context("AF_INET does not fit in the SOCK_DIAG request")?
    } else {
        u8::try_from(libc::AF_INET6).context("AF_INET6 does not fit in the SOCK_DIAG request")?
    };
    ensure!(
        connection.source_address.is_ipv4() == connection.destination_address.is_ipv4(),
        "SOCK_DIAG connection address families differ"
    );
    let protocol = match connection.protocol {
        TransportProtocol::Tcp => u8::try_from(libc::IPPROTO_TCP)
            .context("TCP protocol does not fit in the SOCK_DIAG request")?,
        TransportProtocol::Udp => u8::try_from(libc::IPPROTO_UDP)
            .context("UDP protocol does not fit in the SOCK_DIAG request")?,
        _ => bail!("SOCK_DIAG request only supports TCP and UDP"),
    };

    let mut request = [0_u8; SOCK_DIAG_REQUEST_BYTES];
    request[0..4].copy_from_slice(
        &u32::try_from(SOCK_DIAG_REQUEST_BYTES)
            .context("SOCK_DIAG request length does not fit in u32")?
            .to_ne_bytes(),
    );
    request[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    request[12..16].copy_from_slice(&local_port_id.to_ne_bytes());
    request[16] = family;
    request[17] = protocol;
    request[20..24].copy_from_slice(&u32::MAX.to_ne_bytes());
    request[24..26].copy_from_slice(&source_port.to_be_bytes());
    // A connected UDP socket carries the packet's destination port, while an
    // unconnected sender has idiag_dport zero. Leaving the UDP request field
    // zero asks the kernel for every socket on this local port; strict tuple
    // verification below retains only the exact or wildcard candidates and is
    // what makes SO_REUSEPORT ambiguity visible instead of selecting one peer.
    let diagnostic_destination_port = match connection.protocol {
        TransportProtocol::Tcp => destination_port,
        TransportProtocol::Udp => 0,
        _ => bail!("SOCK_DIAG destination filter only supports TCP and UDP"),
    };
    request[26..28].copy_from_slice(&diagnostic_destination_port.to_be_bytes());
    encode_sock_diag_address(&mut request[28..44], connection.source_address)?;
    encode_sock_diag_address(&mut request[44..60], connection.destination_address)?;
    request[64..68].copy_from_slice(&INET_DIAG_NOCOOKIE.to_ne_bytes());
    request[68..72].copy_from_slice(&INET_DIAG_NOCOOKIE.to_ne_bytes());
    Ok(request)
}

fn encode_sock_diag_address(target: &mut [u8], address: IpAddr) -> Result<()> {
    ensure!(
        target.len() == 16,
        "SOCK_DIAG address field has an invalid size"
    );
    target.fill(0);
    match address {
        IpAddr::V4(address) => target[..4].copy_from_slice(&address.octets()),
        IpAddr::V6(address) => target.copy_from_slice(&address.octets()),
    }
    Ok(())
}

fn process_sock_diag_datagram(
    bytes: &[u8],
    expected_sequence: u32,
    expected_port_id: u32,
    connection: &OutboundConnection,
    candidates: &mut SockDiagCandidates,
) -> Result<bool> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let remaining = bytes
            .get(offset..)
            .ok_or_else(|| anyhow!("SOCK_DIAG netlink offset is invalid"))?;
        ensure!(
            remaining.len() >= NETLINK_HEADER_BYTES,
            "SOCK_DIAG netlink header is truncated"
        );
        let length = read_ne_u32(&remaining[0..4], "SOCK_DIAG netlink message length")?;
        let length = usize::try_from(length).context("SOCK_DIAG message length is out of range")?;
        ensure!(
            length >= NETLINK_HEADER_BYTES && length <= remaining.len(),
            "SOCK_DIAG netlink message length is invalid"
        );
        let aligned_length = align_netlink_message(length)?;
        let consumed = if aligned_length <= remaining.len() {
            aligned_length
        } else if length == remaining.len() {
            // Linux may omit only the terminal message's trailing alignment.
            length
        } else {
            bail!("SOCK_DIAG netlink message alignment is invalid");
        };
        let message_type = read_ne_u16(&remaining[4..6], "SOCK_DIAG message type")?;
        let flags = read_ne_u16(&remaining[6..8], "SOCK_DIAG message flags")?;
        let sequence = read_ne_u32(&remaining[8..12], "SOCK_DIAG message sequence")?;
        let port_id = read_ne_u32(&remaining[12..16], "SOCK_DIAG message port ID")?;
        ensure!(
            sequence == expected_sequence,
            "SOCK_DIAG response sequence does not match the request"
        );
        ensure!(
            port_id == expected_port_id,
            "SOCK_DIAG response port ID does not match the bound socket"
        );
        ensure!(
            flags & NLM_F_DUMP_INTR == 0,
            "SOCK_DIAG dump was interrupted and may be incomplete"
        );
        candidates.account_message()?;
        let payload = &remaining[NETLINK_HEADER_BYTES..length];
        match message_type {
            SOCK_DIAG_BY_FAMILY => {
                ensure!(
                    flags & NLM_F_MULTI != 0,
                    "SOCK_DIAG dump response is not multipart"
                );
                let candidate = parse_sock_diag_candidate(payload, connection)?;
                candidates.observe(candidate, connection);
            }
            NLMSG_DONE => {
                ensure!(
                    consumed == remaining.len(),
                    "SOCK_DIAG completion is not the final netlink message"
                );
                if !payload.is_empty() {
                    ensure!(
                        payload.len() >= 4,
                        "SOCK_DIAG completion status is truncated"
                    );
                    let status = read_ne_i32(&payload[..4], "SOCK_DIAG completion status")?;
                    ensure!(
                        status == 0,
                        "kernel terminated SOCK_DIAG dump with status {status}"
                    );
                }
                return Ok(true);
            }
            NLMSG_ERROR => {
                ensure!(payload.len() >= 4, "SOCK_DIAG netlink error is truncated");
                let error = read_ne_i32(&payload[..4], "SOCK_DIAG netlink error")?;
                ensure!(
                    error < 0,
                    "SOCK_DIAG returned an unexpected successful acknowledgement"
                );
                bail!(
                    "kernel rejected SOCK_DIAG request with errno {}",
                    error.unsigned_abs()
                );
            }
            NLMSG_OVERRUN => bail!("kernel reported a SOCK_DIAG response overrun"),
            _ => bail!("SOCK_DIAG returned an unexpected netlink message type"),
        }
        offset = offset
            .checked_add(consumed)
            .ok_or_else(|| anyhow!("SOCK_DIAG netlink offset overflowed"))?;
    }
    Ok(false)
}

fn parse_sock_diag_candidate(
    payload: &[u8],
    connection: &OutboundConnection,
) -> Result<SocketCandidate> {
    ensure!(
        payload.len() >= INET_DIAG_MESSAGE_BYTES,
        "inet_diag_msg payload is truncated"
    );
    let expected_family = if connection.source_address.is_ipv4() {
        u8::try_from(libc::AF_INET).context("AF_INET is out of range")?
    } else {
        u8::try_from(libc::AF_INET6).context("AF_INET6 is out of range")?
    };
    ensure!(
        payload[0] == expected_family,
        "SOCK_DIAG response address family does not match the request"
    );
    let local_address = parse_sock_diag_address(payload[0], &payload[8..24])?;
    let remote_address = parse_sock_diag_address(payload[0], &payload[24..40])?;
    Ok(SocketCandidate {
        local_address,
        local_port: read_be_u16(&payload[4..6], "SOCK_DIAG local port")?,
        remote_address,
        remote_port: read_be_u16(&payload[6..8], "SOCK_DIAG remote port")?,
        uid: read_ne_u32(&payload[64..68], "SOCK_DIAG socket UID")?,
        inode: u64::from(read_ne_u32(&payload[68..72], "SOCK_DIAG socket inode")?),
    })
}

fn parse_sock_diag_address(family: u8, bytes: &[u8]) -> Result<IpAddr> {
    let octets: [u8; 16] = bytes
        .try_into()
        .map_err(|_| anyhow!("SOCK_DIAG address field has an invalid size"))?;
    if i32::from(family) == libc::AF_INET {
        ensure!(
            octets[4..].iter().all(|byte| *byte == 0),
            "SOCK_DIAG IPv4 address has nonzero extension bytes"
        );
        Ok(IpAddr::V4(Ipv4Addr::new(
            octets[0], octets[1], octets[2], octets[3],
        )))
    } else if i32::from(family) == libc::AF_INET6 {
        Ok(IpAddr::V6(Ipv6Addr::from(octets)))
    } else {
        bail!("SOCK_DIAG response has an unsupported address family")
    }
}

fn align_netlink_message(length: usize) -> Result<usize> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(|| anyhow!("SOCK_DIAG netlink alignment overflowed"))
}

fn read_ne_u16(bytes: &[u8], field: &str) -> Result<u16> {
    let bytes: [u8; 2] = bytes
        .try_into()
        .map_err(|_| anyhow!("{field} is truncated"))?;
    Ok(u16::from_ne_bytes(bytes))
}

fn read_be_u16(bytes: &[u8], field: &str) -> Result<u16> {
    let bytes: [u8; 2] = bytes
        .try_into()
        .map_err(|_| anyhow!("{field} is truncated"))?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_ne_u32(bytes: &[u8], field: &str) -> Result<u32> {
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| anyhow!("{field} is truncated"))?;
    Ok(u32::from_ne_bytes(bytes))
}

fn read_ne_i32(bytes: &[u8], field: &str) -> Result<i32> {
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| anyhow!("{field} is truncated"))?;
    Ok(i32::from_ne_bytes(bytes))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketCandidate {
    local_address: IpAddr,
    local_port: u16,
    remote_address: IpAddr,
    remote_port: u16,
    uid: u32,
    inode: u64,
}

impl SocketCandidate {
    fn matches(self, connection: &OutboundConnection) -> bool {
        let Some(source_port) = connection.source_port else {
            return false;
        };
        let local_matches = self.local_port == source_port
            && (self.local_address == connection.source_address
                || self.local_address.is_unspecified());
        let remote_matches = (self.remote_address == connection.destination_address
            && self.remote_port == connection.destination_port.unwrap_or_default())
            || (self.remote_address.is_unspecified() && self.remote_port == 0);
        local_matches && remote_matches && self.inode != 0
    }
}

fn parse_socket_line(line: &str) -> Result<Option<SocketCandidate>> {
    let mut fields = line.split_ascii_whitespace();
    let Some(_slot) = fields.next() else {
        return Ok(None);
    };
    let Some(local_endpoint) = fields.next() else {
        return Ok(None);
    };
    let Some(remote_endpoint) = fields.next() else {
        return Ok(None);
    };
    for _ in 0..4 {
        if fields.next().is_none() {
            return Ok(None);
        }
    }
    let Some(uid) = fields.next() else {
        return Ok(None);
    };
    let Some(_timeout) = fields.next() else {
        return Ok(None);
    };
    let Some(inode) = fields.next() else {
        return Ok(None);
    };

    // TIME_WAIT and other ownerless procfs rows commonly carry inode zero.
    // They can never participate in attribution, so reject them before doing
    // the comparatively expensive address parsing while still scanning every
    // row to preserve ambiguity detection for real socket owners.
    let inode = inode.parse::<u64>().context("invalid socket inode")?;
    if inode == 0 {
        return Ok(None);
    }
    let uid = uid.parse::<u32>().context("invalid socket uid")?;
    let (local_address, local_port) = parse_proc_endpoint(local_endpoint)?;
    let (remote_address, remote_port) = parse_proc_endpoint(remote_endpoint)?;
    Ok(Some(SocketCandidate {
        local_address,
        local_port,
        remote_address,
        remote_port,
        uid,
        inode,
    }))
}

fn parse_proc_endpoint(value: &str) -> Result<(IpAddr, u16)> {
    let (address, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("socket endpoint has no port separator"))?;
    let port = u16::from_str_radix(port, 16).context("invalid socket port")?;
    let address = match address.len() {
        8 => {
            let raw = u32::from_str_radix(address, 16).context("invalid IPv4 socket address")?;
            IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes()))
        }
        32 => {
            let mut octets = [0_u8; 16];
            for (index, chunk) in address.as_bytes().as_chunks::<8>().0.iter().enumerate() {
                let text = std::str::from_utf8(chunk).context("invalid IPv6 socket address")?;
                let raw =
                    u32::from_str_radix(text, 16).context("invalid IPv6 socket address word")?;
                octets[index * 4..index * 4 + 4].copy_from_slice(&raw.to_le_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => bail!("socket address has an invalid width"),
    };
    Ok((address, port))
}

fn find_socket_fd_bounded(
    process: &Path,
    target: &str,
    deadline: Instant,
    maximum_fds: usize,
) -> Result<Option<PathBuf>> {
    ensure!(maximum_fds > 0, "per-task fd bound is zero");
    ensure_within_deadline(deadline)?;
    let entries = fs::read_dir(process.join("fd")).context("cannot enumerate process fds")?;
    ensure_within_deadline(deadline)?;
    for (count, entry) in entries.enumerate() {
        ensure_within_deadline(deadline)?;
        ensure!(count < maximum_fds, "per-task fd bound exceeded");
        let entry = entry.context("cannot inspect process fd")?;
        let link = match fs::read_link(entry.path()) {
            Ok(link) => link.to_str().map(ToOwned::to_owned),
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).context("cannot inspect process descriptor link");
            }
        };
        ensure_within_deadline(deadline)?;
        if link.as_deref() == Some(target) {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

fn verified_socket_fd(
    process: &Path,
    observed_fd_path: &Path,
    target: &str,
    deadline: Instant,
) -> Result<PathBuf> {
    ensure_within_deadline(deadline)?;
    match fs::read_link(observed_fd_path) {
        Ok(link) if link.to_str() == Some(target) => return Ok(observed_fd_path.to_path_buf()),
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).context("cannot revalidate attributed socket descriptor");
        }
    }
    find_socket_fd_bounded(process, target, deadline, MAX_FDS_PER_TASK)?
        .ok_or_else(|| anyhow!("attributed socket fd is no longer owned by the process"))
}

fn read_process_fs_uid(process: &Path, deadline: Instant) -> Result<u32> {
    let bytes = read_bounded(&process.join("status"), MAX_STATUS_BYTES, deadline)?;
    let text = std::str::from_utf8(&bytes).context("process status is not UTF-8 ASCII")?;
    let line = text
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| anyhow!("process status has no Uid field"))?;
    line.split_ascii_whitespace()
        .nth(4)
        .ok_or_else(|| anyhow!("process Uid field does not contain an fsuid"))?
        .parse::<u32>()
        .context("process fsuid is invalid")
}

fn read_start_time(process: &Path, deadline: Instant) -> Result<u64> {
    let bytes = read_bounded(&process.join("stat"), MAX_STAT_BYTES, deadline)?;
    let text = std::str::from_utf8(&bytes).context("process stat is not UTF-8 ASCII")?;
    let close = text
        .rfind(')')
        .ok_or_else(|| anyhow!("process stat has no command terminator"))?;
    text.get(close + 1..)
        .ok_or_else(|| anyhow!("process stat is truncated"))?
        .split_ascii_whitespace()
        .nth(19)
        .ok_or_else(|| anyhow!("process stat has no start-time field"))?
        .parse::<u64>()
        .context("process start-time field is invalid")
}

fn read_command_line(process: &Path, deadline: Instant) -> Result<Vec<CommandArgument>> {
    let bytes = read_bounded(&process.join("cmdline"), MAX_COMMAND_LINE_BYTES, deadline)?;
    ensure!(!bytes.is_empty(), "process command line is empty");
    let mut raw_arguments: Vec<&[u8]> = bytes.split(|byte| *byte == 0).collect();
    if raw_arguments
        .last()
        .is_some_and(|argument| argument.is_empty())
    {
        raw_arguments.pop();
    }
    ensure!(
        !raw_arguments.is_empty() && raw_arguments.len() <= MAX_COMMAND_ARGUMENTS,
        "process command-line argument bound exceeded"
    );
    raw_arguments
        .into_iter()
        .map(|argument| {
            let argument = std::str::from_utf8(argument)
                .context("process command-line argument is not UTF-8")?;
            CommandArgument::new(argument.to_owned()).map_err(Into::into)
        })
        .collect()
}

fn read_cgroups(process: &Path, deadline: Instant) -> Result<Vec<CgroupPath>> {
    let bytes = read_bounded(&process.join("cgroup"), MAX_CGROUP_BYTES, deadline)?;
    let text = std::str::from_utf8(&bytes).context("process cgroup data is not UTF-8 ASCII")?;
    let mut unified = None;
    let mut memberships = 0_usize;
    for line in text.lines() {
        ensure_within_deadline(deadline)?;
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields
            .next()
            .ok_or_else(|| anyhow!("process cgroup entry has no hierarchy"))?;
        let controllers = fields
            .next()
            .ok_or_else(|| anyhow!("process cgroup entry has no controller list"))?;
        let path = fields
            .next()
            .ok_or_else(|| anyhow!("process cgroup entry has no path"))?;
        let validated_path = CgroupPath::new(path.to_owned())?;
        memberships = memberships
            .checked_add(1)
            .ok_or_else(|| anyhow!("process cgroup membership count overflow"))?;
        if hierarchy == "0" && controllers.is_empty() {
            ensure!(
                unified.is_none(),
                "process has multiple unified cgroup v2 memberships"
            );
            unified = Some(validated_path);
        } else {
            let hierarchy = hierarchy
                .parse::<u32>()
                .context("process cgroup v1 hierarchy is invalid")?;
            ensure!(
                hierarchy != 0 && !controllers.is_empty(),
                "process cgroup membership mixes invalid hierarchy metadata"
            );
            ensure!(
                controllers.split(',').all(|controller| {
                    !controller.is_empty()
                        && controller.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'=')
                        })
                }),
                "process cgroup v1 controller list is invalid"
            );
        }
    }
    ensure_within_deadline(deadline)?;
    ensure!(memberships != 0, "process has no cgroup membership");
    // A cgroup selector is deliberately defined only against the unambiguous
    // unified-v2 path.  On a v1-only host retain no cgroup identity: selectors
    // which request one then fail to match, while executable/file/UID/argv
    // attribution remains available instead of denying every application.
    Ok(unified.into_iter().collect())
}

fn read_bounded(path: &Path, maximum: usize, deadline: Instant) -> Result<Vec<u8>> {
    ensure_within_deadline(deadline)?;
    let mut file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    ensure_within_deadline(deadline)?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        ensure_within_deadline(deadline)?;
        let count = file
            .read(&mut chunk)
            .with_context(|| format!("cannot read {}", path.display()))?;
        ensure_within_deadline(deadline)?;
        if count == 0 {
            break;
        }
        ensure!(
            bytes.len().saturating_add(count) <= maximum,
            "bounded procfs file is oversized"
        );
        bytes.extend_from_slice(&chunk[..count]);
    }
    Ok(bytes)
}

fn ensure_within_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() > deadline {
        return Err(ProcfsAttributionTimeout.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fmt::Write as _;
    use std::io::{IoSlice, IoSliceMut, Write as _};
    use std::net::{SocketAddrV4, TcpListener, TcpStream, UdpSocket};
    use std::os::fd::RawFd;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::process::Command;

    use nix::cmsg_space;
    use nix::sys::socket::{
        ControlMessage, ControlMessageOwned, SockaddrIn, UnixAddr, recvmsg, sendmsg, setsockopt,
        sockopt,
    };
    use nix::unistd::geteuid;
    use openshield_core::{
        ApplicationSelector, CommandLineMatch, CommandLineSelector, Direction, Mode, PortRange,
        RuleName, RuleOrigin, RuleSpec, State,
    };

    use super::*;

    #[test]
    fn attribution_timeout_remains_typed_through_context() -> Result<(), Box<dyn Error>> {
        let expired = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .ok_or("cannot construct an expired attribution deadline")?;
        let error = ensure_within_deadline(expired)
            .context("cannot enumerate procfs")
            .err()
            .ok_or("expired deadline unexpectedly succeeded")?;

        assert!(is_attribution_timeout(&error));
        assert_eq!(
            error.to_string(),
            "cannot enumerate procfs",
            "caller context should remain the public diagnostic"
        );
        Ok(())
    }

    #[test]
    fn esrch_is_skipped_only_after_the_procfs_subject_is_confirmed_absent()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let live_subject = directory.path().join("live");
        fs::create_dir(&live_subject)?;
        let vanished_subject = directory.path().join("vanished");
        let esrch = io::Error::from_raw_os_error(libc::ESRCH);

        assert!(procfs_enumeration_may_indicate_disappearance(&esrch));
        assert!(!procfs_subject_disappeared_after(&esrch, &live_subject)?);
        assert!(procfs_subject_disappeared_after(&esrch, &vanished_subject)?);
        Ok(())
    }

    #[test]
    fn permission_and_unrelated_io_errors_never_hide_a_procfs_subject() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        let absent_subject = directory.path().join("absent");
        for error in [
            io::Error::from(ErrorKind::PermissionDenied),
            io::Error::from(ErrorKind::Other),
        ] {
            assert!(!procfs_enumeration_may_indicate_disappearance(&error));
            assert!(!procfs_subject_disappeared_after(&error, &absent_subject)?);
        }
        Ok(())
    }

    fn create_task_fixture(
        root: &Path,
        process_id: u32,
        task_id: u32,
        uid: u32,
    ) -> Result<PathBuf, Box<dyn Error>> {
        let task = root
            .join(process_id.to_string())
            .join("task")
            .join(task_id.to_string());
        fs::create_dir_all(task.join("fd"))?;
        fs::write(
            task.join("status"),
            format!("Name:\ttest\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
        )?;
        Ok(task)
    }

    fn create_process_fixture(
        root: &Path,
        process_id: u32,
        uid: u32,
    ) -> Result<PathBuf, Box<dyn Error>> {
        let process = root.join(process_id.to_string());
        fs::create_dir_all(process.join("fd"))?;
        fs::write(
            process.join("status"),
            format!("Name:\ttest\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
        )?;
        Ok(process)
    }

    fn complete_identity_fixture(task: &Path, pid: u32) -> Result<(), Box<dyn Error>> {
        let executable = task
            .parent()
            .and_then(Path::parent)
            .ok_or("task fixture has no process directory")?
            .join("fixture-executable");
        fs::write(&executable, b"fixture executable")?;
        symlink(&executable, task.join("exe"))?;
        fs::write(task.join("cmdline"), b"fixture-executable\0--test\0")?;
        fs::write(task.join("cgroup"), b"0::/openshield-test\n")?;
        let mut fields = vec!["S".to_owned(); 20];
        fields[19] = "987654".to_owned();
        fs::write(
            task.join("stat"),
            format!("{pid} (fixture) {}\n", fields.join(" ")),
        )?;
        Ok(())
    }

    fn loopback_connection(
        protocol: TransportProtocol,
        source_address: IpAddr,
        source_port: u16,
        destination_address: IpAddr,
        destination_port: u16,
        uid: u32,
    ) -> Result<OutboundConnection> {
        Ok(OutboundConnection {
            source_address,
            source_port: Some(source_port),
            destination_address,
            destination_port: Some(destination_port),
            protocol,
            output_interface: InterfaceName::new("lo")?,
            socket_uid: uid,
        })
    }

    fn write_udp_socket_table(
        root: &Path,
        sockets: &[(u16, u16, u32, u64)],
    ) -> Result<(), Box<dyn Error>> {
        let net = root.join("self/net");
        fs::create_dir_all(&net)?;
        let mut table = String::from(
            "sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode\n",
        );
        for (index, (source_port, destination_port, uid, inode)) in sockets.iter().enumerate() {
            writeln!(
                table,
                "{index}: 0100007F:{source_port:04X} 0100007F:{destination_port:04X} \
                 01 00000000:00000000 00:00000000 00000000 {uid} 0 {inode}"
            )?;
        }
        fs::write(net.join("udp"), table)?;
        Ok(())
    }

    fn synthetic_sock_diag_payload(
        connection: &OutboundConnection,
        local_address: IpAddr,
        remote_address: IpAddr,
        remote_port: u16,
        uid: u32,
        inode: u32,
    ) -> Result<Vec<u8>> {
        let mut payload = vec![0_u8; INET_DIAG_MESSAGE_BYTES];
        payload[0] = if local_address.is_ipv4() {
            u8::try_from(libc::AF_INET)?
        } else {
            u8::try_from(libc::AF_INET6)?
        };
        let source_port = connection
            .source_port
            .ok_or_else(|| anyhow!("test connection has no source port"))?;
        payload[4..6].copy_from_slice(&source_port.to_be_bytes());
        payload[6..8].copy_from_slice(&remote_port.to_be_bytes());
        encode_sock_diag_address(&mut payload[8..24], local_address)?;
        encode_sock_diag_address(&mut payload[24..40], remote_address)?;
        payload[64..68].copy_from_slice(&uid.to_ne_bytes());
        payload[68..72].copy_from_slice(&inode.to_ne_bytes());
        Ok(payload)
    }

    fn synthetic_netlink_message(
        message_type: u16,
        flags: u16,
        sequence: u32,
        port_id: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let length = NETLINK_HEADER_BYTES
            .checked_add(payload.len())
            .ok_or_else(|| anyhow!("test netlink length overflowed"))?;
        let aligned = align_netlink_message(length)?;
        let mut message = vec![0_u8; aligned];
        message[0..4].copy_from_slice(&u32::try_from(length)?.to_ne_bytes());
        message[4..6].copy_from_slice(&message_type.to_ne_bytes());
        message[6..8].copy_from_slice(&flags.to_ne_bytes());
        message[8..12].copy_from_slice(&sequence.to_ne_bytes());
        message[12..16].copy_from_slice(&port_id.to_ne_bytes());
        message[16..length].copy_from_slice(payload);
        Ok(message)
    }

    fn synthetic_sock_diag_dump(
        connection: &OutboundConnection,
        candidates: &[(IpAddr, IpAddr, u16, u32, u32)],
        sequence: u32,
        port_id: u32,
    ) -> Result<Vec<u8>> {
        let mut dump = Vec::new();
        for (local, remote, remote_port, uid, inode) in candidates {
            let payload = synthetic_sock_diag_payload(
                connection,
                *local,
                *remote,
                *remote_port,
                *uid,
                *inode,
            )?;
            dump.extend_from_slice(&synthetic_netlink_message(
                SOCK_DIAG_BY_FAMILY,
                NLM_F_MULTI,
                sequence,
                port_id,
                &payload,
            )?);
        }
        dump.extend_from_slice(&synthetic_netlink_message(
            NLMSG_DONE,
            NLM_F_MULTI,
            sequence,
            port_id,
            &0_i32.to_ne_bytes(),
        )?);
        Ok(dump)
    }

    fn live_socket_inode(file_descriptor: i32) -> Result<u64> {
        Ok(fs::metadata(format!("/proc/self/fd/{file_descriptor}"))?.ino())
    }

    #[test]
    fn parses_proc_ipv4_and_ipv6_endpoints() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            parse_proc_endpoint("0100007F:01BB")?,
            ("127.0.0.1".parse()?, 443)
        );
        assert_eq!(
            parse_proc_endpoint("B80D0120000000000000000001000000:0035")?,
            ("2001:db8::1".parse()?, 53)
        );
        Ok(())
    }

    #[test]
    fn ownerless_socket_rows_skip_expensive_endpoint_parsing() -> Result<(), Box<dyn Error>> {
        let ownerless = "0: invalid-local invalid-remote 06 00000000:00000000 \
                         00:00000000 00000000 1000 0 0";
        assert_eq!(parse_socket_line(ownerless)?, None);

        let owned = "0: invalid-local invalid-remote 01 00000000:00000000 \
                     00:00000000 00000000 1000 0 77";
        assert!(parse_socket_line(owned).is_err());
        Ok(())
    }

    #[test]
    fn socket_inode_resolution_deduplicates_one_inode_and_rejects_another()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let net = directory.path().join("self/net");
        fs::create_dir_all(&net)?;
        let header = "sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode\n";
        let first = "0: 0100007F:3039 0100007F:D431 01 00000000:00000000 \
                     00:00000000 00000000 1000 0 77\n";
        let duplicate = "1: 0100007F:3039 0100007F:D431 01 00000000:00000000 \
                         00:00000000 00000000 1000 0 77\n";
        let conflicting = "2: 0100007F:3039 0100007F:D431 01 00000000:00000000 \
                           00:00000000 00000000 1000 0 78\n";
        let table = net.join("udp");
        fs::write(&table, format!("{header}{first}{duplicate}"))?;

        let resolver = ProcfsResolver::at(directory.path());
        let connection = OutboundConnection {
            source_address: "127.0.0.1".parse()?,
            source_port: Some(12_345),
            destination_address: "127.0.0.1".parse()?,
            destination_port: Some(54_321),
            protocol: TransportProtocol::Udp,
            output_interface: InterfaceName::new("lo")?,
            socket_uid: 1_000,
        };
        assert_eq!(
            resolver.resolve_socket_inode(&connection, Instant::now() + Duration::from_secs(1))?,
            77
        );

        fs::write(&table, format!("{header}{first}{duplicate}{conflicting}"))?;
        let Err(error) =
            resolver.resolve_socket_inode(&connection, Instant::now() + Duration::from_secs(1))
        else {
            return Err("two distinct matching inodes were resolved".into());
        };
        assert!(error.to_string().contains("missing or ambiguous"));
        Ok(())
    }

    #[test]
    fn sock_diag_request_encodes_tcp_tuple_and_udp_ambiguity_filter() -> Result<(), Box<dyn Error>>
    {
        let tcp = loopback_connection(
            TransportProtocol::Tcp,
            "192.0.2.10".parse()?,
            40_000,
            "198.51.100.20".parse()?,
            443,
            1_000,
        )?;
        let request = build_sock_diag_request(&tcp, 77, 88)?;
        assert_eq!(request.len(), SOCK_DIAG_REQUEST_BYTES);
        assert_eq!(read_ne_u32(&request[0..4], "length")?, 72);
        assert_eq!(read_ne_u16(&request[4..6], "type")?, SOCK_DIAG_BY_FAMILY);
        assert_eq!(
            read_ne_u16(&request[6..8], "flags")?,
            NLM_F_REQUEST | NLM_F_DUMP
        );
        assert_eq!(read_ne_u32(&request[8..12], "sequence")?, 77);
        assert_eq!(read_ne_u32(&request[12..16], "port ID")?, 88);
        assert_eq!(i32::from(request[16]), libc::AF_INET);
        assert_eq!(i32::from(request[17]), libc::IPPROTO_TCP);
        assert_eq!(read_ne_u32(&request[20..24], "states")?, u32::MAX);
        assert_eq!(read_be_u16(&request[24..26], "source port")?, 40_000);
        assert_eq!(read_be_u16(&request[26..28], "destination port")?, 443);
        assert_eq!(
            &request[28..44],
            &[192, 0, 2, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            &request[44..60],
            &[198, 51, 100, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(read_ne_u32(&request[64..68], "cookie")?, u32::MAX);
        assert_eq!(read_ne_u32(&request[68..72], "cookie")?, u32::MAX);

        let mut udp = tcp;
        udp.protocol = TransportProtocol::Udp;
        let request = build_sock_diag_request(&udp, 1, 2)?;
        assert_eq!(i32::from(request[17]), libc::IPPROTO_UDP);
        assert_eq!(
            read_be_u16(&request[26..28], "UDP destination filter")?,
            0,
            "UDP dump must include connected and unconnected reuseport sockets"
        );
        Ok(())
    }

    #[test]
    fn sock_diag_candidate_parser_checks_family_and_ipv4_extension() -> Result<(), Box<dyn Error>> {
        let connection = loopback_connection(
            TransportProtocol::Udp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            12_345,
            "198.51.100.7".parse()?,
            53,
            1_000,
        )?;
        let payload = synthetic_sock_diag_payload(
            &connection,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
            1_000,
            77,
        )?;
        let candidate = parse_sock_diag_candidate(&payload, &connection)?;
        assert!(candidate.local_address.is_unspecified());
        assert!(candidate.remote_address.is_unspecified());
        assert_eq!(candidate.local_port, 12_345);
        assert_eq!(candidate.uid, 1_000);
        assert_eq!(candidate.inode, 77);
        assert!(candidate.matches(&connection));

        let mut wrong_family = payload.clone();
        wrong_family[0] = u8::try_from(libc::AF_INET6)?;
        assert!(parse_sock_diag_candidate(&wrong_family, &connection).is_err());
        let mut extended_ipv4 = payload;
        extended_ipv4[12] = 1;
        assert!(parse_sock_diag_candidate(&extended_ipv4, &connection).is_err());
        assert!(parse_sock_diag_candidate(&[0_u8; 71], &connection).is_err());
        Ok(())
    }

    #[test]
    fn sock_diag_request_and_response_preserve_ipv6_tuple() -> Result<(), Box<dyn Error>> {
        let source_address: Ipv6Addr = "2001:db8::10".parse()?;
        let destination_address: Ipv6Addr = "2001:db8::20".parse()?;
        let source = IpAddr::V6(source_address);
        let destination = IpAddr::V6(destination_address);
        let connection = loopback_connection(
            TransportProtocol::Tcp,
            source,
            40_000,
            destination,
            443,
            1_000,
        )?;
        let request = build_sock_diag_request(&connection, 7, 8)?;
        assert_eq!(i32::from(request[16]), libc::AF_INET6);
        assert_eq!(&request[28..44], &source_address.octets());
        assert_eq!(&request[44..60], &destination_address.octets());

        let payload =
            synthetic_sock_diag_payload(&connection, source, destination, 443, 1_000, 77)?;
        let candidate = parse_sock_diag_candidate(&payload, &connection)?;
        assert_eq!(candidate.local_address, source);
        assert_eq!(candidate.remote_address, destination);
        assert!(candidate.matches(&connection));
        Ok(())
    }

    #[test]
    fn sock_diag_dump_deduplicates_inode_and_rejects_reuseport_ambiguity()
    -> Result<(), Box<dyn Error>> {
        let connection = loopback_connection(
            TransportProtocol::Udp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            12_345,
            "198.51.100.7".parse()?,
            53,
            1_000,
        )?;
        let wildcard = (
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
            1_000,
            77,
        );
        let duplicate = [wildcard, wildcard];
        let dump = synthetic_sock_diag_dump(&connection, &duplicate, 5, 9)?;
        let mut candidates = SockDiagCandidates::default();
        candidates.account_datagram(dump.len())?;
        assert!(process_sock_diag_datagram(
            &dump,
            5,
            9,
            &connection,
            &mut candidates
        )?);
        assert_eq!(candidates.finish()?, 77);

        let conflicting = [wildcard, (wildcard.0, wildcard.1, 0, 1_000, 78)];
        let dump = synthetic_sock_diag_dump(&connection, &conflicting, 5, 9)?;
        let mut candidates = SockDiagCandidates::default();
        candidates.account_datagram(dump.len())?;
        assert!(process_sock_diag_datagram(
            &dump,
            5,
            9,
            &connection,
            &mut candidates
        )?);
        let error = candidates
            .finish()
            .err()
            .ok_or("ambiguous SOCK_DIAG dump unexpectedly resolved")?;
        assert!(error.to_string().contains("missing or ambiguous"));
        Ok(())
    }

    #[test]
    fn sock_diag_dump_filters_full_tuple_uid_and_ownerless_rows() -> Result<(), Box<dyn Error>> {
        let connection = loopback_connection(
            TransportProtocol::Udp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            12_345,
            "198.51.100.7".parse()?,
            53,
            1_000,
        )?;
        let unrelated = [
            (
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "198.51.100.8".parse()?,
                53,
                1_000,
                70,
            ),
            (
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "198.51.100.7".parse()?,
                53,
                1_001,
                71,
            ),
            (
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
                1_000,
                0,
            ),
        ];
        let dump = synthetic_sock_diag_dump(&connection, &unrelated, 5, 9)?;
        let mut candidates = SockDiagCandidates::default();
        candidates.account_datagram(dump.len())?;
        assert!(process_sock_diag_datagram(
            &dump,
            5,
            9,
            &connection,
            &mut candidates
        )?);
        assert!(candidates.finish().is_err());
        Ok(())
    }

    #[test]
    fn sock_diag_netlink_envelope_fails_closed() -> Result<(), Box<dyn Error>> {
        let connection = loopback_connection(
            TransportProtocol::Tcp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            12_345,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            443,
            1_000,
        )?;
        let payload = synthetic_sock_diag_payload(
            &connection,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            443,
            1_000,
            77,
        )?;
        let valid = synthetic_netlink_message(SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, 5, 9, &payload)?;
        for (message, sequence, port_id) in [
            (valid[..15].to_vec(), 5, 9),
            (valid.clone(), 6, 9),
            (valid.clone(), 5, 10),
            (
                synthetic_netlink_message(SOCK_DIAG_BY_FAMILY, 0, 5, 9, &payload)?,
                5,
                9,
            ),
            (synthetic_netlink_message(99, NLM_F_MULTI, 5, 9, &[])?, 5, 9),
        ] {
            assert!(
                process_sock_diag_datagram(
                    &message,
                    sequence,
                    port_id,
                    &connection,
                    &mut SockDiagCandidates::default(),
                )
                .is_err()
            );
        }

        let interrupted = synthetic_netlink_message(
            NLMSG_DONE,
            NLM_F_MULTI | NLM_F_DUMP_INTR,
            5,
            9,
            &0_i32.to_ne_bytes(),
        )?;
        assert!(
            process_sock_diag_datagram(
                &interrupted,
                5,
                9,
                &connection,
                &mut SockDiagCandidates::default(),
            )
            .is_err()
        );
        let kernel_error =
            synthetic_netlink_message(NLMSG_ERROR, 0, 5, 9, &(-libc::EPERM).to_ne_bytes())?;
        assert!(
            process_sock_diag_datagram(
                &kernel_error,
                5,
                9,
                &connection,
                &mut SockDiagCandidates::default(),
            )
            .is_err()
        );
        let successful_ack = synthetic_netlink_message(NLMSG_ERROR, 0, 5, 9, &0_i32.to_ne_bytes())?;
        assert!(
            process_sock_diag_datagram(
                &successful_ack,
                5,
                9,
                &connection,
                &mut SockDiagCandidates::default(),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn sock_diag_parser_handles_dense_bounded_batch() -> Result<(), Box<dyn Error>> {
        let connection = loopback_connection(
            TransportProtocol::Udp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            12_345,
            "198.51.100.7".parse()?,
            53,
            1_000,
        )?;
        let wildcard = (
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
            1_000,
            77,
        );
        let rows = vec![wildcard; 512];
        let dump = synthetic_sock_diag_dump(&connection, &rows, 5, 9)?;
        assert!(dump.len() < SOCK_DIAG_RECEIVE_BUFFER_BYTES);
        let mut candidates = SockDiagCandidates::default();
        candidates.account_datagram(dump.len())?;
        assert!(process_sock_diag_datagram(
            &dump,
            5,
            9,
            &connection,
            &mut candidates
        )?);
        assert_eq!(candidates.message_count, 513);
        assert_eq!(candidates.finish()?, 77);
        Ok(())
    }

    #[test]
    fn sock_diag_response_bounds_fail_closed_before_overflow() {
        let mut bytes = SockDiagCandidates {
            response_bytes: MAX_SOCK_DIAG_RESPONSE_BYTES,
            ..SockDiagCandidates::default()
        };
        assert!(bytes.account_datagram(1).is_err());

        let mut messages = SockDiagCandidates {
            message_count: MAX_PROC_ENTRIES,
            ..SockDiagCandidates::default()
        };
        assert!(messages.account_message().is_err());
    }

    #[test]
    #[ignore = "requires AF_INET and NETLINK_SOCK_DIAG access"]
    fn live_sock_diag_resolves_connected_tcp() -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let destination = listener.local_addr()?;
        let client = TcpStream::connect(destination)?;
        let (_server, _) = listener.accept()?;
        let source = client.local_addr()?;
        let connection = loopback_connection(
            TransportProtocol::Tcp,
            source.ip(),
            source.port(),
            destination.ip(),
            destination.port(),
            geteuid().as_raw(),
        )?;
        let expected = live_socket_inode(client.as_raw_fd())?;
        let resolver = ProcfsResolver::new();
        let actual =
            resolver.resolve_socket_inode(&connection, Instant::now() + Duration::from_secs(2))?;
        assert_eq!(actual, expected);
        let (first_descriptor, first_sequence) = {
            let diagnostic = resolver.sock_diag.borrow();
            let diagnostic = diagnostic
                .as_ref()
                .ok_or("successful SOCK_DIAG query did not retain its socket")?;
            (diagnostic.socket.as_raw_fd(), diagnostic.sequence)
        };
        let repeated =
            resolver.resolve_socket_inode(&connection, Instant::now() + Duration::from_secs(2))?;
        assert_eq!(repeated, expected);
        let diagnostic = resolver.sock_diag.borrow();
        let diagnostic = diagnostic
            .as_ref()
            .ok_or("repeated SOCK_DIAG query did not retain its socket")?;
        assert_eq!(diagnostic.socket.as_raw_fd(), first_descriptor);
        assert_eq!(diagnostic.sequence, first_sequence + 1);
        Ok(())
    }

    #[test]
    #[ignore = "requires AF_INET and NETLINK_SOCK_DIAG access"]
    fn live_sock_diag_resolves_connected_udp() -> Result<(), Box<dyn Error>> {
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        client.connect(peer.local_addr()?)?;
        let source = client.local_addr()?;
        let destination = peer.local_addr()?;
        let connection = loopback_connection(
            TransportProtocol::Udp,
            source.ip(),
            source.port(),
            destination.ip(),
            destination.port(),
            geteuid().as_raw(),
        )?;
        let expected = live_socket_inode(client.as_raw_fd())?;
        let resolver = ProcfsResolver::new();
        let actual =
            resolver.resolve_socket_inode(&connection, Instant::now() + Duration::from_secs(2))?;
        assert_eq!(actual, expected);

        let second = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        second.connect(destination)?;
        let second_source = second.local_addr()?;
        let second_connection = loopback_connection(
            TransportProtocol::Udp,
            second_source.ip(),
            second_source.port(),
            destination.ip(),
            destination.port(),
            geteuid().as_raw(),
        )?;
        let second_expected = live_socket_inode(second.as_raw_fd())?;
        let second_actual = resolver
            .resolve_socket_inode(&second_connection, Instant::now() + Duration::from_secs(2))?;
        assert_eq!(second_actual, second_expected);
        assert_ne!(second_actual, actual);
        Ok(())
    }

    #[test]
    #[ignore = "requires AF_INET and NETLINK_SOCK_DIAG access"]
    fn live_sock_diag_resolves_unconnected_wildcard_udp() -> Result<(), Box<dyn Error>> {
        let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
        let client = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        let destination = peer.local_addr()?;
        client.send_to(b"probe", destination)?;
        let connection = loopback_connection(
            TransportProtocol::Udp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            client.local_addr()?.port(),
            destination.ip(),
            destination.port(),
            geteuid().as_raw(),
        )?;
        let expected = live_socket_inode(client.as_raw_fd())?;
        let actual = ProcfsResolver::new()
            .resolve_socket_inode(&connection, Instant::now() + Duration::from_secs(2))?;
        assert_eq!(actual, expected);
        Ok(())
    }

    #[test]
    #[ignore = "requires AF_INET and NETLINK_SOCK_DIAG access"]
    fn live_sock_diag_rejects_udp_reuseport_ambiguity() -> Result<(), Box<dyn Error>> {
        let first = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::Udp,
        )?;
        setsockopt(&first, sockopt::ReusePort, &true)?;
        bind(
            first.as_raw_fd(),
            &SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )?;
        let first_address: SockaddrIn = getsockname(first.as_raw_fd())?;
        let first_address = SocketAddrV4::from(first_address);
        let second = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::SOCK_CLOEXEC,
            SockProtocol::Udp,
        )?;
        setsockopt(&second, sockopt::ReusePort, &true)?;
        bind(second.as_raw_fd(), &SockaddrIn::from(first_address))?;

        let connection = loopback_connection(
            TransportProtocol::Udp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            first_address.port(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            53,
            geteuid().as_raw(),
        )?;
        let resolver = ProcfsResolver::new();
        let result =
            resolver.resolve_socket_inode(&connection, Instant::now() + Duration::from_secs(2));
        assert!(result.is_err());
        assert!(result.err().is_some_and(|error| {
            error
                .chain()
                .any(|cause| cause.to_string().contains("missing or ambiguous"))
        }));
        assert!(
            resolver.sock_diag.borrow().is_none(),
            "a failed query retained a potentially contaminated netlink socket"
        );
        Ok(())
    }

    #[test]
    #[ignore = "helper process for the SCM_RIGHTS live attribution test"]
    fn scm_rights_socket_owner_helper() -> Result<()> {
        let Some(control_path) = std::env::var_os("OPENSHIELD_TEST_SCM_RIGHTS_CONTROL") else {
            // This helper is selected explicitly by the parent test. A broad
            // `--ignored` run without its private control channel is a no-op.
            return Ok(());
        };
        let mut control = UnixStream::connect(control_path)?;
        control.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut marker = [0_u8; 1];
        let mut slices = [IoSliceMut::new(&mut marker)];
        let mut ancillary = cmsg_space!([RawFd; 1]);
        let message = recvmsg::<UnixAddr>(
            control.as_raw_fd(),
            &mut slices,
            Some(&mut ancillary),
            MsgFlags::empty(),
        )?;
        ensure!(message.bytes == 1, "SCM_RIGHTS marker was truncated");
        let mut received_fd = None;
        for control_message in message.cmsgs()? {
            match control_message {
                ControlMessageOwned::ScmRights(descriptors) => {
                    ensure!(
                        received_fd.is_none() && descriptors.len() == 1,
                        "SCM_RIGHTS helper received an ambiguous descriptor set"
                    );
                    received_fd = descriptors.first().copied();
                }
                _ => bail!("SCM_RIGHTS helper received an unexpected control message"),
            }
        }
        ensure!(
            received_fd.is_some_and(|descriptor| descriptor >= 0),
            "SCM_RIGHTS helper received no socket descriptor"
        );
        control.write_all(b"R")?;
        control.read_exact(&mut marker)?;
        // The received raw descriptor deliberately remains installed until
        // this short-lived helper process exits; that is the ownership state
        // the parent resolver must observe through procfs.
        Ok(())
    }

    #[test]
    #[ignore = "requires AF_INET, NETLINK_SOCK_DIAG, SCM_RIGHTS, and host procfs access"]
    fn live_sock_diag_rejects_scm_rights_shared_process_owner() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let control_path = directory.path().join("scm-rights.sock");
        let listener = UnixListener::bind(&control_path)?;
        let mut child = Command::new(std::env::current_exe()?)
            .arg("--ignored")
            .arg("--exact")
            .arg("application::tests::scm_rights_socket_owner_helper")
            .arg("--test-threads=1")
            .env("OPENSHIELD_TEST_SCM_RIGHTS_CONTROL", &control_path)
            .spawn()?;
        let (mut control, _) = listener.accept()?;
        control.set_read_timeout(Some(Duration::from_secs(10)))?;

        let application_socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        let rights = [application_socket.as_raw_fd()];
        let marker = *b"F";
        sendmsg::<UnixAddr>(
            control.as_raw_fd(),
            &[IoSlice::new(&marker)],
            &[ControlMessage::ScmRights(&rights)],
            MsgFlags::empty(),
            None,
        )?;
        let mut ready = [0_u8; 1];
        control.read_exact(&mut ready)?;
        ensure!(ready == *b"R", "SCM_RIGHTS helper did not become ready");

        let connection = loopback_connection(
            TransportProtocol::Udp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            application_socket.local_addr()?.port(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            53,
            geteuid().as_raw(),
        )?;
        let resolver = ProcfsResolver {
            root: PathBuf::from("/proc"),
            sock_diag: RefCell::new(None),
            use_procfs_socket_lookup: false,
            daemon_process_id: None,
        };
        let ownership_result = (|| -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(2);
            let inode = resolver.resolve_socket_inode(&connection, deadline)?;
            let error = resolver
                .resolve_unique_process_tasks(
                    inode,
                    connection.socket_uid,
                    deadline,
                    MAX_FDS_PER_TASK,
                )
                .err()
                .ok_or_else(|| anyhow!("SCM_RIGHTS shared owner was attributed uniquely"))?;
            ensure!(
                error.to_string().contains("multiple processes"),
                "SCM_RIGHTS shared owner failed for an unexpected reason: {error:#}"
            );
            Ok(())
        })();

        let stop_result = control.write_all(b"X");
        let child_status = child.wait()?;
        stop_result?;
        ensure!(child_status.success(), "SCM_RIGHTS helper process failed");
        ownership_result?;
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn application_rule_requires_every_network_and_process_selector() -> Result<(), Box<dyn Error>>
    {
        let interface = InterfaceName::new("eth0")?;
        let identity = ApplicationIdentity {
            pid: 10,
            process_start_time_ticks: 11,
            executable: ApplicationPath::new("/usr/bin/curl")?,
            executable_file: ExecutableFileId {
                device: 8,
                inode: 9,
                size: 10,
                ctime_seconds: 11,
                ctime_nanoseconds: 12,
            },
            command_line: vec![CommandArgument::new("curl")?],
            uid: 1_000,
            cgroups: vec![],
        };
        let mut spec = RuleSpec::new(
            RuleName::new("curl https")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.7/32".parse()?),
            Some(PortRange::single(443)?),
            Some(interface.clone()),
            RuleOrigin::Manual,
            true,
        )?;
        spec.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new("/usr/bin/curl")?),
            Some(identity.executable_file),
            None,
            Some(1_000),
            None,
        )?);
        spec.validate()?;
        let base_spec = spec.clone();
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        state.create_rule(spec)?;
        let connection = OutboundConnection {
            source_address: "192.0.2.1".parse()?,
            source_port: Some(50_000),
            destination_address: "203.0.113.7".parse()?,
            destination_port: Some(443),
            protocol: TransportProtocol::Tcp,
            output_interface: interface,
            socket_uid: 1_000,
        };
        assert!(matching_application_rule(&state.snapshot(), &connection, &identity).is_some());

        let indexed = ApplicationDecisionPolicy::new(state.snapshot());
        assert_eq!(indexed.candidate_count(identity.executable_file), 1);
        assert!(indexed.matching_rule(&connection, &identity).is_some());
        assert_eq!(
            indexed.enforcement_capture_requirements(&connection),
            Some(IdentityCaptureRequirements::minimal())
        );

        // Overlapping application rules use deny-overrides independently of
        // random UUID ordering: Drop, then Reject, then Accept.
        let mut reject = base_spec.clone();
        reject.action = RuleAction::Reject;
        state.create_rule(reject)?;
        let mut drop_rule = base_spec;
        drop_rule.action = RuleAction::Drop;
        state.create_rule(drop_rule)?;
        let deny_overrides = ApplicationDecisionPolicy::new(state.snapshot());
        assert_eq!(deny_overrides.candidate_count(identity.executable_file), 3);
        assert_eq!(
            deny_overrides
                .matching_rule(&connection, &identity)
                .map(|rule| rule.spec.action),
            Some(RuleAction::Drop)
        );

        let mut wrong_uid = connection.clone();
        wrong_uid.socket_uid += 1;
        assert!(
            indexed
                .enforcement_capture_requirements(&wrong_uid)
                .is_none()
        );

        let mut unrelated_binary = identity.clone();
        unrelated_binary.executable_file.inode += 1;
        assert_eq!(indexed.candidate_count(unrelated_binary.executable_file), 0);
        assert!(
            indexed
                .matching_rule(&connection, &unrelated_binary)
                .is_none()
        );

        let network_accept = RuleSpec::new(
            RuleName::new("network fallback")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.0/24".parse()?),
            Some(PortRange::single(443)?),
            None,
            RuleOrigin::Manual,
            true,
        )?;
        state.create_rule(network_accept)?;
        let with_network_fallback = ApplicationDecisionPolicy::new(state.snapshot());
        assert_eq!(
            with_network_fallback
                .matching_rule(&connection, &identity)
                .map(|rule| rule.spec.action),
            Some(RuleAction::Drop),
            "an application deny must override an overlapping network accept"
        );
        assert_eq!(
            with_network_fallback
                .matching_rule(&connection, &unrelated_binary)
                .map(|rule| rule.spec.action),
            Some(RuleAction::Accept),
            "an unrelated application must retain the matching network allow"
        );

        let mut wrong_destination = connection;
        wrong_destination.destination_address = "203.0.113.8".parse()?;
        assert!(
            matching_application_rule(&state.snapshot(), &wrong_destination, &identity).is_none()
        );
        assert!(
            indexed
                .enforcement_capture_requirements(&wrong_destination)
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn enforcement_prefilter_requests_only_optional_fields_used_by_candidates()
    -> Result<(), Box<dyn Error>> {
        let interface = InterfaceName::new("eth0")?;
        let executable_file = ExecutableFileId {
            device: 8,
            inode: 9,
            size: 10,
            ctime_seconds: 11,
            ctime_nanoseconds: 12,
        };
        let mut spec = RuleSpec::new(
            RuleName::new("exact curl identity")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.7/32".parse()?),
            Some(PortRange::single(443)?),
            Some(interface.clone()),
            RuleOrigin::Manual,
            true,
        )?;
        spec.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new("/usr/bin/curl")?),
            Some(executable_file),
            Some(CommandLineSelector::new(
                CommandLineMatch::Exact,
                vec![CommandArgument::new("curl")?],
            )?),
            Some(1_000),
            Some(CgroupPath::new("/system.slice/curl.service")?),
        )?);
        spec.validate()?;
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        state.create_rule(spec)?;
        let policy = ApplicationDecisionPolicy::new(state.snapshot());
        let connection = OutboundConnection {
            source_address: "192.0.2.1".parse()?,
            source_port: Some(50_000),
            destination_address: "203.0.113.7".parse()?,
            destination_port: Some(443),
            protocol: TransportProtocol::Tcp,
            output_interface: interface,
            socket_uid: 1_000,
        };

        assert_eq!(
            policy.enforcement_capture_requirements(&connection),
            Some(IdentityCaptureRequirements::full())
        );

        let mut wrong_port = connection.clone();
        wrong_port.destination_port = Some(444);
        assert!(
            policy
                .enforcement_capture_requirements(&wrong_port)
                .is_none()
        );
        let mut wrong_uid = connection;
        wrong_uid.socket_uid = 1_001;
        assert!(
            policy
                .enforcement_capture_requirements(&wrong_uid)
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn privileged_manual_rule_pins_the_opened_executable() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let executable = directory.path().join("application");
        fs::write(&executable, b"test executable")?;
        let executable_text = executable
            .to_str()
            .ok_or("temporary path is not UTF-8")?
            .to_owned();
        let mut specification = RuleSpec::new(
            RuleName::new("pinned application")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.1/32".parse()?),
            Some(PortRange::single(443)?),
            None,
            RuleOrigin::Manual,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new(executable_text)?),
            None,
            None,
            None,
            None,
        )?);

        pin_rule_application(&mut specification)?;

        let metadata = fs::metadata(fs::canonicalize(&executable)?)?;
        let selector = specification.application.ok_or("selector disappeared")?;
        assert_eq!(
            selector.executable_file,
            Some(ExecutableFileId {
                device: metadata.dev(),
                inode: metadata.ino(),
                size: metadata.size(),
                ctime_seconds: metadata.ctime(),
                ctime_nanoseconds: metadata.ctime_nsec(),
            })
        );
        Ok(())
    }

    #[test]
    fn privileged_manual_rule_rejects_stale_in_place_version() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let executable = directory.path().join("application");
        fs::write(&executable, b"old")?;
        let old_file = executable_file_id(&fs::metadata(&executable)?)?;
        fs::write(&executable, b"new executable contents")?;
        let new_file = executable_file_id(&fs::metadata(&executable)?)?;
        assert_eq!(old_file.device, new_file.device);
        assert_eq!(old_file.inode, new_file.inode);
        assert_ne!(old_file.size, new_file.size);

        let mut specification = RuleSpec::new(
            RuleName::new("stale application")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.1/32".parse()?),
            Some(PortRange::single(443)?),
            None,
            RuleOrigin::Manual,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new(
                executable.to_str().ok_or("temporary path is not UTF-8")?,
            )?),
            Some(old_file),
            None,
            None,
            None,
        )?);

        let Err(error) = pin_rule_application(&mut specification) else {
            return Err("stale pin was accepted".into());
        };
        assert!(error.to_string().contains("version does not match"));
        Ok(())
    }

    #[test]
    fn manual_pin_canonicalizes_a_stable_symlink() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let executable = directory.path().join("application");
        let link = directory.path().join("application-link");
        fs::write(&executable, b"test executable")?;
        symlink(&executable, &link)?;
        let mut specification = RuleSpec::new(
            RuleName::new("symlinked application")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.1/32".parse()?),
            Some(PortRange::single(443)?),
            None,
            RuleOrigin::Manual,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new(
                link.to_str().ok_or("temporary path is not UTF-8")?,
            )?),
            None,
            None,
            None,
            None,
        )?);

        pin_rule_application(&mut specification)?;

        let selector = specification.application.ok_or("selector disappeared")?;
        assert_eq!(
            selector.executable.as_ref().map(ApplicationPath::as_str),
            fs::canonicalize(&executable)?.to_str()
        );
        Ok(())
    }

    #[test]
    fn nofollow_open_rejects_an_uncanonicalized_symlink() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let executable = directory.path().join("application");
        let link = directory.path().join("application-link");
        fs::write(&executable, b"test executable")?;
        symlink(&executable, &link)?;

        assert!(open_executable_version(&link).is_err());
        Ok(())
    }

    #[test]
    fn privileged_manual_rule_rejects_an_unresolvable_unpinned_path() -> Result<(), Box<dyn Error>>
    {
        let mut specification = RuleSpec::new(
            RuleName::new("missing application")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.1/32".parse()?),
            Some(PortRange::single(443)?),
            None,
            RuleOrigin::Manual,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new("/definitely/missing/application")?),
            None,
            None,
            None,
            None,
        )?);
        assert!(pin_rule_application(&mut specification).is_err());
        Ok(())
    }

    #[test]
    fn privileged_manual_rule_rejects_an_unresolvable_supplied_version()
    -> Result<(), Box<dyn Error>> {
        let mut specification = RuleSpec::new(
            RuleName::new("missing supplied application")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.1/32".parse()?),
            Some(PortRange::single(443)?),
            None,
            RuleOrigin::Manual,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new("/definitely/missing/application")?),
            Some(ExecutableFileId {
                device: 8,
                inode: 99,
                size: 12_345,
                ctime_seconds: 1_700_000_000,
                ctime_nanoseconds: 123_456_789,
            }),
            None,
            None,
            None,
        )?);

        assert!(pin_rule_application(&mut specification).is_err());
        Ok(())
    }

    #[test]
    fn start_time_parser_handles_spaces_and_parentheses_in_comm() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let pid = directory.path().join("123");
        fs::create_dir(&pid)?;
        let mut fields = vec!["S".to_owned(); 20];
        fields[19] = "987654".to_owned();
        fs::write(
            pid.join("stat"),
            format!("123 (odd ) name) {}\n", fields.join(" ")),
        )?;
        assert_eq!(
            read_start_time(&pid, Instant::now() + Duration::from_secs(1))?,
            987_654
        );
        Ok(())
    }

    #[test]
    fn zombie_state_parser_handles_spaces_and_parentheses_in_comm() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        fs::write(directory.path().join("stat"), "200 (odd ) name) Z 1 2 3\n")?;
        let deadline = Instant::now() + Duration::from_secs(1);
        assert_eq!(read_task_state(directory.path(), deadline)?, b'Z');
        assert!(task_is_stably_zombie(directory.path(), deadline)?);
        Ok(())
    }

    #[test]
    fn process_identity_uses_the_socket_relevant_fsuid() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        fs::write(
            directory.path().join("status"),
            "Name:\ttest\nUid:\t1000\t1001\t1002\t1003\n",
        )?;
        assert_eq!(
            read_process_fs_uid(directory.path(), Instant::now() + Duration::from_secs(1))?,
            1_003
        );
        Ok(())
    }

    #[test]
    fn cgroup_identity_uses_only_the_qualified_v2_unified_hierarchy() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        fs::write(
            directory.path().join("cgroup"),
            "5:cpu,cpuacct:/trusted\n0::/system.slice/application.scope\n",
        )?;

        assert_eq!(
            read_cgroups(directory.path(), Instant::now() + Duration::from_secs(1))?,
            vec![CgroupPath::new("/system.slice/application.scope")?]
        );
        Ok(())
    }

    #[test]
    fn cgroup_v1_keeps_non_cgroup_application_attribution_available() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        fs::write(
            directory.path().join("cgroup"),
            "5:cpu,cpuacct:/trusted\n4:memory:/trusted\n",
        )?;

        assert_eq!(
            read_cgroups(directory.path(), Instant::now() + Duration::from_secs(1))?,
            Vec::<CgroupPath>::new()
        );
        Ok(())
    }

    #[test]
    fn malformed_cgroup_v1_metadata_still_fails_closed() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        fs::write(directory.path().join("cgroup"), "0:cpu:/trusted\n")?;

        assert!(read_cgroups(directory.path(), Instant::now() + Duration::from_secs(1)).is_err());
        Ok(())
    }

    #[test]
    fn incomplete_fd_scan_cannot_claim_unique_socket_ownership() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let known_owner = create_task_fixture(directory.path(), 100, 100, 1_000)?;
        let bounded_task = create_task_fixture(directory.path(), 200, 200, 1_000)?;
        symlink("socket:[77]", known_owner.join("fd/3"))?;
        symlink("socket:[1]", bounded_task.join("fd/3"))?;
        symlink("socket:[2]", bounded_task.join("fd/4"))?;

        let resolver = ProcfsResolver::at(directory.path());
        let result = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            1,
        );

        assert!(result.is_err());
        assert!(
            result
                .err()
                .is_some_and(|error| error.to_string().contains("cannot prove unique"))
        );
        Ok(())
    }

    #[test]
    fn batched_owner_records_have_one_global_memory_bound() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        for task_id in [100, 101] {
            let task = create_task_fixture(directory.path(), 100, task_id, 1_000)?;
            symlink("socket:[77]", task.join("fd/3"))?;
            symlink("socket:[78]", task.join("fd/4"))?;
        }
        let targets = BTreeSet::from([
            SocketOwnerKey {
                inode: 77,
                uid: 1_000,
            },
            SocketOwnerKey {
                inode: 78,
                uid: 1_000,
            },
        ]);

        let error = ProcfsResolver::at(directory.path())
            .resolve_unique_process_tasks_batch(
                &targets,
                Instant::now() + Duration::from_secs(1),
                4,
                3,
            )
            .err()
            .ok_or("tasks multiplied the bounded batch owner records")?;

        assert!(error.to_string().contains("owner record bound exceeded"));
        Ok(())
    }

    #[test]
    fn unrelated_uid_fd_bound_does_not_break_owner_search() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let known_owner = create_task_fixture(directory.path(), 100, 100, 1_000)?;
        let unrelated_task = create_task_fixture(directory.path(), 200, 200, 2_000)?;
        symlink("socket:[77]", known_owner.join("fd/3"))?;
        symlink("socket:[1]", unrelated_task.join("fd/3"))?;
        symlink("socket:[2]", unrelated_task.join("fd/4"))?;

        let resolver = ProcfsResolver::at(directory.path());
        let owners = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            1,
        )?;

        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].tid, 100);
        Ok(())
    }

    #[test]
    fn socket_transfer_to_another_fsuid_has_no_attributable_owner() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let recipient = create_task_fixture(directory.path(), 200, 200, 2_000)?;
        symlink("socket:[77]", recipient.join("fd/3"))?;

        let resolver = ProcfsResolver::at(directory.path());
        let result = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            4,
        );

        assert!(result.is_err());
        assert!(result.err().is_some_and(|error| {
            error
                .to_string()
                .contains("no process owns the attributed socket inode")
        }));
        Ok(())
    }

    #[test]
    fn unshared_worker_fd_table_cannot_hide_a_second_process_owner() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let allowed = create_task_fixture(directory.path(), 100, 100, 1_000)?;
        let _other_leader = create_task_fixture(directory.path(), 200, 200, 1_000)?;
        let hidden_worker = create_task_fixture(directory.path(), 200, 201, 1_000)?;
        symlink("socket:[77]", allowed.join("fd/3"))?;
        symlink("socket:[77]", hidden_worker.join("fd/9"))?;

        let resolver = ProcfsResolver::at(directory.path());
        let result = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            4,
        );

        assert!(result.is_err());
        assert!(
            result
                .err()
                .is_some_and(|error| error.to_string().contains("multiple processes"))
        );
        Ok(())
    }

    #[test]
    fn shared_fd_table_visible_to_sibling_tasks_is_one_process_owner() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        let leader = create_task_fixture(directory.path(), 200, 200, 1_000)?;
        let worker = create_task_fixture(directory.path(), 200, 201, 1_000)?;
        symlink("socket:[77]", leader.join("fd/3"))?;
        symlink("socket:[77]", worker.join("fd/3"))?;

        let resolver = ProcfsResolver::at(directory.path());
        let owners = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            4,
        )?;

        assert_eq!(
            owners.iter().map(|owner| owner.tid).collect::<Vec<_>>(),
            vec![200, 201]
        );
        Ok(())
    }

    #[test]
    fn validated_fd_number_hint_avoids_rewalking_a_shared_sibling_table()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let leader = create_task_fixture(directory.path(), 200, 200, 1_000)?;
        let worker = create_task_fixture(directory.path(), 200, 201, 1_000)?;
        symlink("socket:[77]", leader.join("fd/3"))?;
        symlink("socket:[77]", worker.join("fd/3"))?;
        // The second entry would exceed the deliberately tiny exhaustive-scan
        // bound. A direct readlink of the already observed fd number is enough
        // to prove that this sibling task exposes the same target socket.
        symlink("socket:[88]", worker.join("fd/4"))?;

        let resolver = ProcfsResolver::at(directory.path());
        let owners = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            1,
        )?;

        assert_eq!(
            owners.iter().map(|owner| owner.tid).collect::<Vec<_>>(),
            vec![200, 201]
        );
        assert!(owners.iter().all(|owner| {
            owner.fd_path.file_name().and_then(|name| name.to_str()) == Some("3")
        }));
        Ok(())
    }

    #[test]
    fn daemon_descriptor_table_is_checked_twice_instead_of_every_sibling_task()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let _daemon = create_process_fixture(directory.path(), 100, 1_000)?;
        for task_id in 100..132 {
            let task = create_task_fixture(directory.path(), 100, task_id, 1_000)?;
            // A scan of any sibling table with the deliberately tiny bound
            // below would fail. The daemon owns and shares one files table, so
            // only /proc/<TGID>/fd needs to be inspected.
            symlink("socket:[1]", task.join("fd/3"))?;
            symlink("socket:[2]", task.join("fd/4"))?;
        }
        let external_owner = create_task_fixture(directory.path(), 200, 200, 1_000)?;
        let external_fd = external_owner.join("fd/9");
        symlink("socket:[77]", &external_fd)?;

        let resolver = ProcfsResolver::at_with_daemon_process(directory.path(), 100);
        let owners = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            1,
        )?;

        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].tid, 200);
        assert_eq!(owners[0].fd_path, external_fd);
        Ok(())
    }

    #[test]
    fn daemon_owning_an_application_socket_is_denied_even_with_an_external_holder()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let daemon = create_process_fixture(directory.path(), 100, 1_000)?;
        symlink("socket:[77]", daemon.join("fd/3"))?;
        let external_owner = create_task_fixture(directory.path(), 200, 200, 1_000)?;
        symlink("socket:[77]", external_owner.join("fd/9"))?;

        let resolver = ProcfsResolver::at_with_daemon_process(directory.path(), 100);
        let result = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            4,
        );

        assert!(result.is_err());
        assert!(result.err().is_some_and(|error| {
            error
                .to_string()
                .contains("firewall daemon unexpectedly owns")
        }));
        Ok(())
    }

    #[test]
    fn every_attribution_rescan_detects_a_new_external_socket_holder() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        fs::create_dir_all(directory.path().join("self/net"))?;
        fs::write(
            directory.path().join("self/net/udp"),
            "sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode\n\
             0: 0100007F:3039 0100007F:D431 01 00000000:00000000 00:00000000 00000000 1000 0 77\n",
        )?;
        let original_owner = create_task_fixture(directory.path(), 100, 100, 1_000)?;
        complete_identity_fixture(&original_owner, 100)?;
        symlink("socket:[77]", original_owner.join("fd/3"))?;
        let resolver = ProcfsResolver::at(directory.path());
        let connection = OutboundConnection {
            source_address: "127.0.0.1".parse()?,
            source_port: Some(12_345),
            destination_address: "127.0.0.1".parse()?,
            destination_port: Some(54_321),
            protocol: TransportProtocol::Udp,
            output_interface: InterfaceName::new("lo")?,
            socket_uid: 1_000,
        };

        let initial = resolver.resolve(&connection)?;
        assert_eq!(initial.pid, 100);

        let transferred_holder = create_task_fixture(directory.path(), 200, 200, 1_000)?;
        symlink("socket:[77]", transferred_holder.join("fd/9"))?;
        let repeated = resolver.resolve(&connection);

        assert!(repeated.is_err());
        assert!(
            repeated
                .err()
                .is_some_and(|error| error.to_string().contains("multiple processes"))
        );
        Ok(())
    }

    #[test]
    fn bounded_batch_amortizes_owner_scans_for_the_maximum_target_count()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let mut sockets = Vec::with_capacity(MAX_ATTRIBUTION_BATCH_SIZE);
        let mut connections = Vec::with_capacity(MAX_ATTRIBUTION_BATCH_SIZE);
        for index in 0..MAX_ATTRIBUTION_BATCH_SIZE {
            let offset = u16::try_from(index)?;
            let source_port = 20_000_u16
                .checked_add(offset)
                .ok_or("source port overflow")?;
            let destination_port = 40_000_u16
                .checked_add(offset)
                .ok_or("destination port overflow")?;
            let process_id = 1_000_u32
                .checked_add(u32::try_from(index)?)
                .ok_or("process identifier overflow")?;
            let inode = 10_000_u64
                .checked_add(u64::try_from(index)?)
                .ok_or("socket inode overflow")?;
            let owner = create_task_fixture(directory.path(), process_id, process_id, 1_000)?;
            complete_identity_fixture(&owner, process_id)?;
            symlink(format!("socket:[{inode}]"), owner.join("fd/3"))?;
            sockets.push((source_port, destination_port, 1_000, inode));
            connections.push(loopback_connection(
                TransportProtocol::Udp,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                source_port,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                destination_port,
                1_000,
            )?);
        }
        write_udp_socket_table(directory.path(), &sockets)?;

        let resolver = ProcfsResolver::at(directory.path());
        let requests = connections
            .iter()
            .map(|connection| (connection, IdentityCaptureRequirements::minimal()))
            .collect::<Vec<_>>();
        let identities = resolver.resolve_batch_for_enforcement_until(
            &requests,
            Instant::now() + Duration::from_secs(10),
        );

        assert_eq!(identities.len(), MAX_ATTRIBUTION_BATCH_SIZE);
        for (index, identity) in identities.into_iter().enumerate() {
            assert_eq!(identity?.pid, 1_000 + u32::try_from(index)?);
        }

        let oversized = (0..=MAX_ATTRIBUTION_BATCH_SIZE)
            .map(|_| (&connections[0], IdentityCaptureRequirements::minimal()))
            .collect::<Vec<_>>();
        assert!(
            resolver
                .resolve_batch_for_enforcement_until(
                    &oversized,
                    Instant::now() + Duration::from_secs(1),
                )
                .into_iter()
                .all(|result| result.is_err())
        );
        Ok(())
    }

    #[test]
    fn repeated_batched_udp_attribution_rejects_a_new_ambiguous_holder()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let sockets = [(12_345, 54_321, 1_000, 77), (12_346, 54_322, 1_000, 78)];
        write_udp_socket_table(directory.path(), &sockets)?;
        let first_owner = create_task_fixture(directory.path(), 100, 100, 1_000)?;
        complete_identity_fixture(&first_owner, 100)?;
        symlink("socket:[77]", first_owner.join("fd/3"))?;
        let second_owner = create_task_fixture(directory.path(), 200, 200, 1_000)?;
        complete_identity_fixture(&second_owner, 200)?;
        symlink("socket:[78]", second_owner.join("fd/3"))?;
        let first = loopback_connection(
            TransportProtocol::Udp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            12_345,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            54_321,
            1_000,
        )?;
        let second = loopback_connection(
            TransportProtocol::Udp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            12_346,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            54_322,
            1_000,
        )?;
        let requests = [
            (&first, IdentityCaptureRequirements::full()),
            (&first, IdentityCaptureRequirements::full()),
            (&second, IdentityCaptureRequirements::full()),
        ];
        let resolver = ProcfsResolver::at(directory.path());
        let initial = resolver.resolve_batch_for_enforcement_until(
            &requests,
            Instant::now() + Duration::from_secs(2),
        );
        assert_eq!(
            initial[0]
                .as_ref()
                .map_err(|error| io::Error::other(format!("{error:#}")))?
                .pid,
            100
        );
        assert_eq!(
            initial[1]
                .as_ref()
                .map_err(|error| io::Error::other(format!("{error:#}")))?
                .pid,
            100
        );
        assert_eq!(
            initial[2]
                .as_ref()
                .map_err(|error| io::Error::other(format!("{error:#}")))?
                .pid,
            200
        );

        let additional_holder = create_task_fixture(directory.path(), 300, 300, 1_000)?;
        symlink("socket:[77]", additional_holder.join("fd/9"))?;
        let repeated = resolver.resolve_batch_for_enforcement_until(
            &requests,
            Instant::now() + Duration::from_secs(2),
        );
        for result in &repeated[..2] {
            let first_error = result
                .as_ref()
                .err()
                .ok_or("ambiguous UDP socket was authorized from a stale batch")?;
            assert!(first_error.to_string().contains("multiple processes"));
        }
        assert_eq!(
            repeated[2]
                .as_ref()
                .map_err(|error| io::Error::other(format!("{error:#}")))?
                .pid,
            200
        );
        Ok(())
    }

    #[test]
    fn batch_identity_memo_never_crosses_capture_requirements() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        write_udp_socket_table(directory.path(), &[(12_345, 54_321, 1_000, 77)])?;
        let owner = create_task_fixture(directory.path(), 100, 100, 1_000)?;
        complete_identity_fixture(&owner, 100)?;
        symlink("socket:[77]", owner.join("fd/3"))?;
        fs::remove_file(owner.join("cmdline"))?;
        fs::remove_file(owner.join("cgroup"))?;
        let connection = loopback_connection(
            TransportProtocol::Udp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            12_345,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            54_321,
            1_000,
        )?;
        let requests = [
            (&connection, IdentityCaptureRequirements::full()),
            (&connection, IdentityCaptureRequirements::minimal()),
        ];

        let results = ProcfsResolver::at(directory.path()).resolve_batch_for_enforcement_until(
            &requests,
            Instant::now() + Duration::from_secs(2),
        );

        assert!(results[0].is_err());
        let minimal = results[1]
            .as_ref()
            .map_err(|error| io::Error::other(format!("{error:#}")))?;
        assert!(minimal.command_line.is_empty());
        assert!(minimal.cgroups.is_empty());
        assert_eq!(minimal.pid, 100);
        Ok(())
    }

    #[test]
    fn batch_consensus_rejects_pid_reuse_but_allows_optional_capture_differences()
    -> Result<(), Box<dyn Error>> {
        let key = SocketOwnerKey {
            inode: 77,
            uid: 1_000,
        };
        let base = ApplicationIdentity {
            pid: 100,
            process_start_time_ticks: 1_000,
            executable: ApplicationPath::new("/usr/bin/example")?,
            executable_file: ExecutableFileId {
                device: 8,
                inode: 9,
                size: 10,
                ctime_seconds: 11,
                ctime_nanoseconds: 12,
            },
            command_line: vec![CommandArgument::new("example")?],
            uid: 1_000,
            cgroups: vec![CgroupPath::new("/example.scope")?],
        };
        let mut selective = base.clone();
        selective.command_line.clear();
        selective.cgroups.clear();
        let keys = [Some(key), Some(key)];
        let mut identities = [Some(base.clone()), Some(selective)];
        let mut errors = [None, None];
        reject_inconsistent_batch_identities(&keys, &mut errors, &mut identities);
        assert!(identities.iter().all(Option::is_some));

        let mut reused = base.clone();
        reused.process_start_time_ticks += 1;
        let mut identities = [Some(base), Some(reused)];
        let mut errors = [None, None];
        reject_inconsistent_batch_identities(&keys, &mut errors, &mut identities);
        assert!(identities.iter().all(Option::is_none));
        assert!(errors.iter().all(|error| {
            error.as_ref().is_some_and(|failure| {
                failure
                    .message
                    .contains("mandatory process identity changed")
            })
        }));
        Ok(())
    }

    #[test]
    fn batched_attribution_has_one_wall_time_bound_and_preserves_typed_timeout()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let resolver = ProcfsResolver::at(directory.path());
        let connection = loopback_connection(
            TransportProtocol::Udp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            12_345,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            54_321,
            1_000,
        )?;
        let requests = [
            (&connection, IdentityCaptureRequirements::full()),
            (&connection, IdentityCaptureRequirements::minimal()),
        ];
        let started = Instant::now();
        let expired = started
            .checked_sub(Duration::from_secs(1))
            .ok_or("cannot construct expired batch deadline")?;
        let results = resolver.resolve_batch_for_enforcement_until(&requests, expired);
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(100),
            "expired batch attribution did not respect its common wall-time bound: {elapsed:?}"
        );
        for result in results {
            let error = result.err().ok_or("expired attribution was authorized")?;
            assert!(is_attribution_timeout(&error));
            assert!(
                error
                    .to_string()
                    .contains("cannot resolve socket inode for batched attribution")
            );
        }
        Ok(())
    }

    #[test]
    fn enforcing_can_skip_unreferenced_optional_identity_files_but_full_resolve_cannot()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        fs::create_dir_all(directory.path().join("self/net"))?;
        fs::write(
            directory.path().join("self/net/udp"),
            "sl local_address rem_address st tx_queue tr retrnsmt uid timeout inode\n\
             0: 0100007F:3039 0100007F:D431 01 00000000:00000000 00:00000000 00000000 1000 0 77\n",
        )?;
        let owner = create_task_fixture(directory.path(), 100, 100, 1_000)?;
        complete_identity_fixture(&owner, 100)?;
        symlink("socket:[77]", owner.join("fd/3"))?;
        fs::remove_file(owner.join("cmdline"))?;
        fs::remove_file(owner.join("cgroup"))?;
        let resolver = ProcfsResolver::at(directory.path());
        let connection = OutboundConnection {
            source_address: "127.0.0.1".parse()?,
            source_port: Some(12_345),
            destination_address: "127.0.0.1".parse()?,
            destination_port: Some(54_321),
            protocol: TransportProtocol::Udp,
            output_interface: InterfaceName::new("lo")?,
            socket_uid: 1_000,
        };

        let selective = resolver
            .resolve_for_enforcement(&connection, IdentityCaptureRequirements::minimal())?;
        assert!(selective.command_line.is_empty());
        assert!(selective.cgroups.is_empty());
        assert_eq!(selective.uid, 1_000);
        assert!(resolver.resolve(&connection).is_err());
        Ok(())
    }

    #[test]
    fn every_attribution_rescan_follows_a_socket_moved_to_another_fd() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        let owner = create_task_fixture(directory.path(), 100, 100, 1_000)?;
        let old_fd = owner.join("fd/3");
        let new_fd = owner.join("fd/9");
        symlink("socket:[77]", &old_fd)?;
        let resolver = ProcfsResolver::at(directory.path());

        let initial = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            4,
        )?;
        assert_eq!(initial[0].fd_path, old_fd);

        fs::remove_file(owner.join("fd/3"))?;
        symlink("socket:[77]", &new_fd)?;
        let repeated = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            4,
        )?;

        assert_eq!(repeated.len(), 1);
        assert_eq!(repeated[0].fd_path, new_fd);
        Ok(())
    }

    #[test]
    fn identity_capture_revalidates_a_stale_fd_hint_before_falling_back()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let owner = create_task_fixture(directory.path(), 200, 200, 1_000)?;
        complete_identity_fixture(&owner, 200)?;
        let original_fd = owner.join("fd/3");
        symlink("socket:[77]", &original_fd)?;
        let resolver = ProcfsResolver::at(directory.path());
        let mut owners = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            4,
        )?;
        let attributed = owners.pop().ok_or("owner disappeared")?;
        assert_eq!(attributed.fd_path, original_fd);

        // The common path rechecks only the exact descriptor returned by the
        // exhaustive owner scan. If the process moved the socket concurrently,
        // the bounded fallback must find it again in the same task rather than
        // accepting the stale descriptor.
        fs::remove_file(&attributed.fd_path)?;
        symlink("socket:[88]", &attributed.fd_path)?;
        symlink("socket:[77]", owner.join("fd/9"))?;
        let identity = ProcfsResolver::capture_identity(
            &attributed.path,
            attributed.tid,
            &attributed.fd_path,
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            IdentityCaptureRequirements::full(),
        )?;

        assert_eq!(identity.pid, 200);
        assert_eq!(identity.uid, 1_000);
        Ok(())
    }

    #[test]
    fn identity_capture_does_not_follow_a_socket_transferred_to_another_task()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let original_owner = create_task_fixture(directory.path(), 200, 200, 1_000)?;
        complete_identity_fixture(&original_owner, 200)?;
        let original_fd = original_owner.join("fd/3");
        symlink("socket:[77]", &original_fd)?;
        let resolver = ProcfsResolver::at(directory.path());
        let mut owners = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            4,
        )?;
        let attributed = owners.pop().ok_or("owner disappeared")?;

        fs::remove_file(&attributed.fd_path)?;
        let recipient = create_task_fixture(directory.path(), 300, 300, 1_000)?;
        symlink("socket:[77]", recipient.join("fd/9"))?;
        let result = ProcfsResolver::capture_identity(
            &attributed.path,
            attributed.tid,
            &attributed.fd_path,
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            IdentityCaptureRequirements::full(),
        );

        assert!(result.is_err());
        assert!(
            result.err().is_some_and(|error| {
                error.to_string().contains("no longer owned by the process")
            })
        );
        Ok(())
    }

    #[test]
    fn live_process_without_enumerable_tasks_fails_closed() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        fs::create_dir_all(directory.path().join("200/task"))?;

        let resolver = ProcfsResolver::at(directory.path());
        let result = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            4,
        );

        assert!(result.is_err());
        assert!(
            result
                .err()
                .is_some_and(|error| error.to_string().contains("no enumerable tasks"))
        );
        Ok(())
    }

    #[test]
    fn fixture_root_is_not_implicitly_host_proc() -> Result<(), Box<dyn Error>> {
        let resolver = ProcfsResolver::at("/definitely/not/proc");
        let connection = OutboundConnection {
            source_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            source_port: Some(10),
            destination_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            destination_port: Some(20),
            protocol: TransportProtocol::Tcp,
            output_interface: InterfaceName::new("lo")?,
            socket_uid: 0,
        };
        assert!(resolver.resolve(&connection).is_err());
        Ok(())
    }
}
