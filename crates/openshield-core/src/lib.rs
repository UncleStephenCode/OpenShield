//! Security-sensitive domain types and policy generation for `OpenShield`.
//!
//! This crate deliberately contains no shell execution and no packet-capture
//! code. Inputs are validated into typed values before either firewall-policy
//! compiler can use them.

#![forbid(unsafe_code)]

mod application;
mod iptables;
mod model;
mod nftables;
mod state;
mod storage;

pub use application::{
    ApplicationIdentity, ApplicationPath, ApplicationSelector, ApplicationValidationError,
    CgroupPath, CommandArgument, CommandLineMatch, CommandLineSelector, ExecutableFileId,
    LearnedApplicationEndpoint, MAX_APPLICATION_PATH_BYTES, MAX_CGROUP_PATH_BYTES,
    MAX_COMMAND_ARGUMENT_BYTES, MAX_COMMAND_ARGUMENTS, MAX_COMMAND_LINE_BYTES,
};
pub use iptables::{
    IPTABLES_APPLICATION_PACKET_CHAIN, IPTABLES_APPLICATION_TCP_CHAIN, IPTABLES_FORWARD_CHAIN,
    IPTABLES_INPUT_CHAIN, IPTABLES_LEARNING_OBSERVE_CHAIN, IPTABLES_MARK_SANITIZE_CHAIN,
    IPTABLES_OUTPUT_CHAIN, IPTABLES_OWNERSHIP_COMMENT, IptablesCompiler, IptablesPolicy,
    owned_chains, owned_mangle_chains,
};
pub use model::{
    CounterValue, Direction, FirewallCounters, InterfaceName, LearnedEndpoint,
    MAX_INTERFACE_NAME_BYTES, MAX_RULE_NAME_BYTES, Mode, PortRange, Rule, RuleAction, RuleName,
    RuleOrigin, RuleSpec, TransportProtocol, ValidationError,
};
pub use nftables::{
    APPLICATION_LEARNING_QUEUE_NUMBER, APPLICATION_QUEUE_NUMBER, APPLICATION_REPLY_QUEUE_NUMBER,
    COUNTER_ACCEPTED_IN, COUNTER_ACCEPTED_OUT, COUNTER_DROPPED_IN, COUNTER_DROPPED_OUT,
    COUNTER_LEARNED_OUT, CompileError, LEARNED_ICMP_V4_SET, LEARNED_ICMP_V6_SET,
    LEARNED_TCP_V4_SET, LEARNED_TCP_V6_SET, LEARNED_UDP_V4_SET, LEARNED_UDP_V6_SET,
    NFT_OWNERSHIP_COUNTER, NftablesCompiler, NftablesPolicy, TABLE_NAME, application_flow_mark,
    application_handoff_mark, application_pending_mark, application_reject_mark,
    application_reply_retry_mark,
};
pub use state::{
    ApplicationInterception, ApplicationLearningAdmission, ApplicationLearningAdmissionIndex,
    CoreError, Event, EventKind, LearnOutcome, MAX_FLOW_GENERATION, MAX_RULES, MAX_STATE_BYTES,
    Snapshot, State,
};
pub use storage::{AtomicStateStore, StateStore, StorageError};
