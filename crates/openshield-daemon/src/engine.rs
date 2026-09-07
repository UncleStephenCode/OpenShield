use std::collections::BTreeMap;
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{
    Arc, Condvar, Mutex,
    mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
#[cfg(test)]
use openshield_core::LearnedEndpoint;
use openshield_core::{
    ApplicationLearningAdmission, ApplicationLearningAdmissionIndex, CoreError,
    EnforcementStrategy, Event, EventKind, FirewallCounters, LearnedApplicationEndpoint,
    LearningLimits, MAX_AUTOMATIC_LEARNED_RULES, MAX_FLOW_GENERATION, MAX_RULES, Mode, Rule,
    RuleAction, RuleOrigin, Snapshot, State, StateStore, TransportProtocol,
};
#[cfg(test)]
use openshield_protocol::FirewallBackendKind;
use openshield_protocol::{
    Ack, CompatibilityLevel, CompatibilityReason, ControlRequest, ErrorCode, LearningStatus,
    NfqueueCounters, OutboundGroupAction, OutboundGroupSelector, ProtocolError, Response,
    RuntimeCompatibility, clamp_page_limit,
};
use tracing::{error, warn};
use uuid::Uuid;

use crate::application::{ApplicationDecisionPolicy, pin_rule_application};
use crate::backend::FirewallBackend;
use crate::compatibility::select_runtime_compatibility;

pub const MAX_EVENT_SUBSCRIBERS: usize = 64;
// One learning poll can publish 256 structural events while the engine lock
// prevents subscribers from completing a snapshot refresh. Keep one complete
// batch plus counter/policy-event headroom without making observer memory
// unbounded.
pub const EVENT_QUEUE_CAPACITY: usize = 512;
const MAX_LEARNED_RULES_PER_POLL: usize = 256;

pub type SharedEngine = Arc<Mutex<Engine>>;

/// Process-lifetime NFQUEUE counters shared by the packet workers and the
/// status path. Targets with native 64-bit atomics use relaxed ordering
/// because these values carry no synchronization payload. The `ARMv5` fallback
/// serializes each full-width value with a mutex.
#[derive(Debug, Default)]
struct SaturatingCounter {
    #[cfg(target_has_atomic = "64")]
    value: AtomicU64,
    // Rust supports OpenShield's ARMv5 target, but that target has no native
    // 64-bit atomics. Keep the full u64 contract there instead of silently
    // narrowing or making the target fail to compile.
    #[cfg(not(target_has_atomic = "64"))]
    value: Mutex<u64>,
}

impl SaturatingCounter {
    #[cfg(target_has_atomic = "64")]
    fn increment(&self) {
        // Returning `Some` makes this update infallible. Saturation is
        // intentional: wrapping a long-running daemon's telemetry to zero
        // could make a release gate mistake an error for a clean interval.
        let _ = self
            .value
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(1))
            });
    }

    #[cfg(not(target_has_atomic = "64"))]
    fn increment(&self) {
        let mut value = match self.value.lock() {
            Ok(value) => value,
            Err(poisoned) => poisoned.into_inner(),
        };
        *value = value.saturating_add(1);
    }

    #[cfg(target_has_atomic = "64")]
    fn load(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    #[cfg(not(target_has_atomic = "64"))]
    fn load(&self) -> u64 {
        let value = match self.value.lock() {
            Ok(value) => value,
            Err(poisoned) => poisoned.into_inner(),
        };
        *value
    }

    #[cfg(test)]
    fn set_for_test(&self, value: u64) {
        #[cfg(target_has_atomic = "64")]
        self.value.store(value, Ordering::Relaxed);
        #[cfg(not(target_has_atomic = "64"))]
        {
            let mut current = match self.value.lock() {
                Ok(current) => current,
                Err(poisoned) => poisoned.into_inner(),
            };
            *current = value;
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct NfqueueRuntimeCounters {
    queue_overflow: SaturatingCounter,
    attribution_timeout: SaturatingCounter,
    terminal_queue_error: SaturatingCounter,
    denied: SaturatingCounter,
}

impl NfqueueRuntimeCounters {
    pub(crate) fn record_queue_overflow(&self) {
        self.queue_overflow.increment();
    }

    pub(crate) fn record_attribution_timeout(&self) {
        self.attribution_timeout.increment();
    }

    pub(crate) fn record_terminal_queue_error(&self) {
        self.terminal_queue_error.increment();
    }

    pub(crate) fn record_denied(&self) {
        self.denied.increment();
    }

    #[must_use]
    pub(crate) fn snapshot(&self) -> NfqueueCounters {
        NfqueueCounters {
            queue_overflow: self.queue_overflow.load(),
            attribution_timeout: self.attribution_timeout.load(),
            terminal_queue_error: self.terminal_queue_error.load(),
            denied: self.denied.load(),
        }
    }
}

#[derive(Debug)]
struct EventBusState {
    next_id: u64,
    subscribers: BTreeMap<u64, SyncSender<Event>>,
    latest_counters: Option<Event>,
}

#[derive(Clone, Debug)]
pub struct EventBus {
    inner: Arc<Mutex<EventBusState>>,
    maximum_subscribers: usize,
    queue_capacity: usize,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(MAX_EVENT_SUBSCRIBERS, EVENT_QUEUE_CAPACITY)
    }

    #[must_use]
    fn with_limits(maximum_subscribers: usize, queue_capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(EventBusState {
                next_id: 0,
                subscribers: BTreeMap::new(),
                latest_counters: None,
            })),
            maximum_subscribers,
            queue_capacity,
        }
    }

    pub fn subscribe(&self) -> Result<EventSubscription, SubscribeError> {
        let mut state = self.inner.lock().map_err(|_| SubscribeError::Unavailable)?;
        if state.subscribers.len() >= self.maximum_subscribers {
            return Err(SubscribeError::LimitReached);
        }
        let id = state.next_id;
        state.next_id = state
            .next_id
            .checked_add(1)
            .ok_or(SubscribeError::Unavailable)?;
        let (sender, receiver) = mpsc::sync_channel(self.queue_capacity);
        if let Some(event) = &state.latest_counters {
            sender
                .try_send(event.clone())
                .map_err(|_| SubscribeError::Unavailable)?;
        }
        state.subscribers.insert(id, sender);
        Ok(EventSubscription {
            id,
            receiver,
            bus: self.clone(),
        })
    }

    pub fn publish(&self, event: &Event) {
        let Ok(mut state) = self.inner.lock() else {
            error!("event bus mutex is poisoned; dropping firewall event");
            return;
        };
        if matches!(&event.kind, EventKind::CountersUpdated { .. }) {
            state.latest_counters = Some(event.clone());
        }
        state
            .subscribers
            .retain(|id, sender| match sender.try_send(event.clone()) {
                Ok(()) => true,
                Err(TrySendError::Full(_)) => {
                    warn!(subscriber_id = *id, "dropping slow firewall observer");
                    false
                }
                Err(TrySendError::Disconnected(_)) => false,
            });
    }

    fn remove(&self, id: u64) {
        if let Ok(mut state) = self.inner.lock() {
            state.subscribers.remove(&id);
        }
    }

    fn clear_counter_snapshot(&self) {
        if let Ok(mut state) = self.inner.lock() {
            state.latest_counters = None;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscribeError {
    LimitReached,
    Unavailable,
}

#[derive(Debug)]
pub struct EventSubscription {
    id: u64,
    receiver: Receiver<Event>,
    bus: EventBus,
}

impl EventSubscription {
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Event, RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }
}

impl Drop for EventSubscription {
    fn drop(&mut self) {
        self.bus.remove(self.id);
    }
}

pub struct Engine {
    state: State,
    learning_limits: LearningLimits,
    quota_skipped_observations: SaturatingCounter,
    last_quota_warning: Mutex<Option<Instant>>,
    application_policy: Arc<ApplicationDecisionPolicy>,
    application_learning_admission: Arc<ApplicationLearningAdmissionIndex>,
    pending_application_learning_admission: Option<Arc<ApplicationLearningAdmissionIndex>>,
    pending_application_learning_candidate: Option<Arc<State>>,
    pending_application_learning_events: Vec<Event>,
    backend: Box<dyn FirewallBackend>,
    persistence: Arc<PersistenceCoordinator>,
    events: EventBus,
    nfqueue_counters: Arc<NfqueueRuntimeCounters>,
    poisoned: bool,
    fatal: bool,
    restart_required: bool,
    startup_policy: StartupPolicy,
    learning_persistence: LearningPersistence,
    next_learning_transaction: u64,
    superseded_learning_transaction: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupPolicy {
    Pending,
    Active,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LearningPersistence {
    Active,
    InFlight(u64),
    Paused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LearningQueueAdmission {
    Enqueue,
    AlreadyKnown,
    Saturated,
    PersistencePaused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistedStateAfterFailure {
    Previous,
    CandidateOrUnknown,
}

#[derive(Debug, Default)]
struct PersistenceCoordinatorState {
    learning_reservation: Option<u64>,
}

/// Serializes the durable state file without making packet verdicts wait for
/// file I/O.
///
/// A learning transaction reserves its place while the engine mutex is held,
/// then performs the actual write after releasing that mutex. Exclusive
/// writers (control rollback and emergency quarantine) wait for the reserved
/// write and therefore always persist after it. This ordering prevents a slow
/// learning write from overwriting a newer emergency `BlockAll` state.
#[derive(Debug)]
struct PersistenceCoordinator {
    store: Arc<dyn StateStore>,
    state: Mutex<PersistenceCoordinatorState>,
    idle: Condvar,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LearningStoreOutcome {
    Saved,
    PreviousRetained,
    Unsafe,
}

impl PersistenceCoordinator {
    fn new(store: Box<dyn StateStore>) -> Self {
        Self {
            store: Arc::from(store),
            state: Mutex::new(PersistenceCoordinatorState::default()),
            idle: Condvar::new(),
        }
    }

    fn coordinator_error() -> openshield_core::StorageError {
        openshield_core::StorageError::InvalidJson(
            "state persistence coordinator is poisoned".to_owned(),
        )
    }

    fn wait_until_exclusive(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, PersistenceCoordinatorState>, openshield_core::StorageError>
    {
        let mut state = self.state.lock().map_err(|_| Self::coordinator_error())?;
        while state.learning_reservation.is_some() {
            state = self
                .idle
                .wait(state)
                .map_err(|_| Self::coordinator_error())?;
        }
        Ok(state)
    }

    fn load_exclusive(&self) -> Result<Option<State>, openshield_core::StorageError> {
        let _state = self.wait_until_exclusive()?;
        self.store.load()
    }

    fn save_exclusive(&self, state: &State) -> Result<(), openshield_core::StorageError> {
        let _coordinator = self.wait_until_exclusive()?;
        self.store.save(state)
    }

    fn reserve_learning(
        self: &Arc<Self>,
        token: u64,
    ) -> Result<LearningReservation, ProtocolError> {
        let mut state = self.state.lock().map_err(|_| {
            ProtocolError::new(
                ErrorCode::Internal,
                "state persistence coordinator is poisoned",
            )
        })?;
        if state.learning_reservation.is_some() {
            return Err(ProtocolError::new(
                ErrorCode::Conflict,
                "another automatic-learning transaction is already being persisted",
            ));
        }
        state.learning_reservation = Some(token);
        Ok(LearningReservation {
            token,
            persistence: Arc::clone(self),
        })
    }

    fn cancel_learning_reservation(&self, token: u64) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.learning_reservation == Some(token) {
            state.learning_reservation = None;
            self.idle.notify_all();
        }
    }

    fn persist_learning(
        &self,
        token: u64,
        previous: &State,
        candidate: &State,
    ) -> LearningStoreOutcome {
        {
            let Ok(coordinator) = self.state.lock() else {
                return LearningStoreOutcome::Unsafe;
            };
            if coordinator.learning_reservation != Some(token) {
                return LearningStoreOutcome::Unsafe;
            }
        }

        // The reservation, rather than this mutex guard, excludes other
        // writers. Do not hold a poisonable synchronization primitive across
        // StateStore code: if an unexpected store panic unwinds this call, the
        // transaction's RAII reservation can still wake an emergency writer.
        let outcome = match self.store.save(candidate) {
            Ok(()) => LearningStoreOutcome::Saved,
            Err(save_error) => {
                error!(
                    error = %save_error,
                    "learned-state persistence failed; checking the authoritative state file"
                );
                if persisted_state_after_failed_save(self.store.as_ref(), previous, candidate)
                    == PersistedStateAfterFailure::CandidateOrUnknown
                {
                    match self.store.save(previous) {
                        Ok(()) => LearningStoreOutcome::PreviousRetained,
                        Err(rollback_error) => {
                            error!(
                                error = %rollback_error,
                                "learned-state storage rollback failed"
                            );
                            LearningStoreOutcome::Unsafe
                        }
                    }
                } else {
                    LearningStoreOutcome::PreviousRetained
                }
            }
        };

        self.cancel_learning_reservation(token);
        outcome
    }
}

#[derive(Debug)]
struct LearningReservation {
    token: u64,
    persistence: Arc<PersistenceCoordinator>,
}

impl Drop for LearningReservation {
    fn drop(&mut self) {
        // Preparing a transaction must never leave emergency persistence
        // waiting forever if its owner exits before calling persist().
        self.persistence.cancel_learning_reservation(self.token);
    }
}

pub(crate) struct ApplicationLearningTransaction {
    reservation: LearningReservation,
    previous: State,
    candidate: Arc<State>,
    events: Vec<Event>,
}

pub(crate) struct PersistedApplicationLearning {
    transaction: ApplicationLearningTransaction,
    outcome: LearningStoreOutcome,
}

impl ApplicationLearningTransaction {
    pub(crate) fn persist(self) -> PersistedApplicationLearning {
        let outcome = self.reservation.persistence.persist_learning(
            self.reservation.token,
            &self.previous,
            self.candidate.as_ref(),
        );
        PersistedApplicationLearning {
            transaction: self,
            outcome,
        }
    }

    const fn token(&self) -> u64 {
        self.reservation.token
    }
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Engine")
            .field("state", &self.state)
            .field(
                "application_policy_rules",
                &self.application_policy.rule_count(),
            )
            .field(
                "application_learning_revision",
                &self.application_learning_admission.revision(),
            )
            .field("persistence", &self.persistence)
            .field("events", &self.events)
            .field("nfqueue_counters", &self.nfqueue_counters.snapshot())
            .field("poisoned", &self.poisoned)
            .field("fatal", &self.fatal)
            .field("restart_required", &self.restart_required)
            .field("startup_policy", &self.startup_policy)
            .field("learning_persistence", &self.learning_persistence)
            .finish_non_exhaustive()
    }
}

fn rotate_startup_flow_generation(state: &mut State) -> Result<()> {
    // Never reuse an epoch which may still exist in conntrack after an older
    // daemon instance. A random value could collide with N-2 or an earlier
    // live flow; a persisted monotonic epoch cannot. Exhaustion is deliberately
    // fail-closed rather than wrapping an old authorization into validity.
    let generation = state
        .flow_generation()
        .checked_add(1)
        .filter(|generation| *generation <= MAX_FLOW_GENERATION)
        .ok_or_else(|| anyhow!("startup flow-authorization epochs are exhausted"))?;
    state
        .rotate_flow_generation(generation)
        .context("cannot rotate the startup flow-authorization epoch")
}

fn build_application_decision_policy(state: &State) -> ApplicationDecisionPolicy {
    let rules = match state.mode() {
        Mode::Enforcing => state
            .rules()
            .filter(|rule| {
                rule.spec.enabled
                    && (rule.spec.application.is_some()
                        || (rule.spec.direction == openshield_core::Direction::Outbound
                            && rule.spec.action == RuleAction::Accept))
            })
            .cloned()
            .collect(),
        Mode::Learning => state
            .rules()
            .filter(|rule| {
                rule.spec.enabled
                    && rule.spec.direction == openshield_core::Direction::Outbound
                    && rule.spec.application.is_some()
                    && matches!(rule.spec.action, RuleAction::Drop | RuleAction::Reject)
            })
            .cloned()
            .collect(),
        Mode::BlockAll => Vec::new(),
    };
    ApplicationDecisionPolicy::new(Snapshot {
        revision: state.revision(),
        flow_generation: state.flow_generation(),
        mode: state.mode(),
        rules,
    })
    .with_enforcement_strategy(if state.mode() == Mode::Enforcing {
        state.enforcement_strategy()
    } else {
        EnforcementStrategy::Strict
    })
}

fn build_application_learning_admission(
    state: &State,
    limits: LearningLimits,
) -> ApplicationLearningAdmissionIndex {
    state.application_learning_admission_index_with_limits(limits)
}

fn validate_application_learning_transition(
    previous: &State,
    candidate: &State,
    events: &[Event],
) -> bool {
    if candidate.mode() != Mode::Learning
        || candidate.enforcement_strategy() != previous.enforcement_strategy()
        || candidate.flow_generation() != previous.flow_generation()
        || candidate.rules().len() != previous.rules().len().saturating_add(events.len())
        || previous
            .rules()
            .any(|rule| candidate.rule(rule.id) != Some(rule))
    {
        return false;
    }

    let mut expected_revision = previous.revision();
    for event in events {
        let Some(next_revision) = expected_revision.checked_add(1) else {
            return false;
        };
        let EventKind::RuleCreated { rule } = &event.kind else {
            return false;
        };
        let valid_learned_rule = rule.spec.origin == RuleOrigin::Learned
            && rule.spec.direction == openshield_core::Direction::Outbound
            && rule.spec.action == RuleAction::Accept
            && rule.spec.enabled
            && rule.spec.application.is_some();
        let valid_template = rule.spec.origin == RuleOrigin::Template
            && rule.spec.direction == openshield_core::Direction::Outbound
            && rule.spec.action == RuleAction::Accept
            && rule.spec.protocol == TransportProtocol::Any
            && rule.spec.peer_network.is_none()
            && rule.spec.port.is_none()
            && rule.spec.interface.is_none()
            && !rule.spec.enabled
            && rule.spec.application.as_ref().is_some_and(|selector| {
                selector.executable.is_some()
                    && selector.executable_file.is_none()
                    && selector.command_line.is_none()
                    && selector.uid.is_none()
                    && !selector.metadata_redacted
            });
        if event.revision != next_revision
            || !(valid_learned_rule || valid_template)
            || previous.rule(rule.id).is_some()
            || candidate.rule(rule.id) != Some(rule)
        {
            return false;
        }
        expected_revision = next_revision;
    }
    candidate.revision() == expected_revision
}

impl Engine {
    #[cfg(test)]
    pub fn load(
        backend: Box<dyn FirewallBackend>,
        store: Box<dyn StateStore>,
        events: EventBus,
    ) -> Result<Self> {
        Self::load_with_learning_limits(backend, store, events, LearningLimits::default())
    }

    pub fn load_with_learning_limits(
        mut backend: Box<dyn FirewallBackend>,
        store: Box<dyn StateStore>,
        events: EventBus,
        learning_limits: LearningLimits,
    ) -> Result<Self> {
        let persistence = Arc::new(PersistenceCoordinator::new(store));
        // Do not leave a policy from an earlier daemon instance active while
        // persisted state is loaded and re-epoched. This also makes direct
        // invocation safe when the systemd ExecStartPre helper was not used.
        backend
            .fail_closed()
            .context("cannot establish the startup BlockAll quarantine")?;

        let state = match persistence.load_exclusive() {
            Ok(Some(mut state)) => {
                rotate_startup_flow_generation(&mut state)?;
                state
                    .ensure_application_group_templates(MAX_RULES)
                    .context("cannot migrate application group templates")?;
                if let Err(save_error) = persistence.save_exclusive(&state) {
                    let fail_closed = backend.fail_closed();
                    return match fail_closed {
                        Ok(()) => Err(save_error).context(
                            "new startup flow epoch could not be persisted; fail-closed policy retained",
                        ),
                        Err(fail_error) => Err(anyhow!(
                            "startup flow epoch persistence failed ({save_error}); fail-closed policy also failed ({fail_error:#})"
                        )),
                    };
                }
                state
            }
            Ok(None) => {
                let mut state = State::new();
                state
                    .set_mode(Mode::Learning)
                    .context("cannot construct the initial Learning policy")?;
                rotate_startup_flow_generation(&mut state)?;
                persistence.save_exclusive(&state).context(
                    "cannot persist the initial Learning policy; BlockAll remains active",
                )?;
                state
            }
            Err(load_error) => {
                let fail_closed = backend.fail_closed();
                return match fail_closed {
                    Ok(()) => Err(load_error).context(
                        "persisted state is unsafe or invalid; fail-closed policy installed",
                    ),
                    Err(fail_error) => Err(anyhow!(
                        "persisted state failed validation ({load_error}); fail-closed policy also failed ({fail_error:#})"
                    )),
                };
            }
        };

        let application_policy = Arc::new(build_application_decision_policy(&state));
        let application_learning_admission = Arc::new(build_application_learning_admission(
            &state,
            learning_limits,
        ));
        Ok(Self {
            state,
            learning_limits,
            quota_skipped_observations: SaturatingCounter::default(),
            last_quota_warning: Mutex::new(None),
            application_policy,
            application_learning_admission,
            pending_application_learning_admission: None,
            pending_application_learning_candidate: None,
            pending_application_learning_events: Vec::new(),
            backend,
            persistence,
            events,
            nfqueue_counters: Arc::new(NfqueueRuntimeCounters::default()),
            poisoned: false,
            fatal: false,
            restart_required: false,
            startup_policy: StartupPolicy::Pending,
            learning_persistence: LearningPersistence::Active,
            next_learning_transaction: 0,
            superseded_learning_transaction: None,
        })
    }

    /// Installs the validated desired policy after the fail-closed NFQUEUE
    /// consumer is ready. State loading always leaves kernel `BlockAll` active,
    /// so startup cannot expose a queue-listener gap.
    pub fn activate_startup_policy(&mut self) -> Result<()> {
        if self.startup_policy == StartupPolicy::Active {
            return Ok(());
        }
        if let Err(apply_error) = self.backend.apply(&self.state.snapshot()) {
            let fail_closed = self.backend.fail_closed();
            return match fail_closed {
                Ok(()) => Err(apply_error)
                    .context("startup policy could not be applied; BlockAll was retained"),
                Err(fail_error) => Err(anyhow!(
                    "startup policy failed ({apply_error:#}); retaining BlockAll also failed ({fail_error:#})"
                )),
            };
        }
        self.startup_policy = StartupPolicy::Active;
        if self.state.mode() == Mode::Enforcing
            && self.state.enforcement_strategy() == EnforcementStrategy::Fast
        {
            warn!(
                "restoring Fast enforcement: process hint caching does not guarantee discovery of additional socket owners"
            );
        }
        Ok(())
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.state.revision()
    }

    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.state.mode()
    }

    #[must_use]
    pub(crate) fn nfqueue_counters(&self) -> Arc<NfqueueRuntimeCounters> {
        Arc::clone(&self.nfqueue_counters)
    }

    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        self.fatal
    }

    /// Returns true when the process must exit unsuccessfully so its service
    /// manager can start a fresh instance from the persisted fail-closed
    /// state.  A known emergency `BlockAll` policy and an unknown kernel state
    /// are deliberately tracked separately.
    #[must_use]
    pub const fn restart_required(&self) -> bool {
        self.restart_required || self.fatal
    }

    pub fn subscription_revision(&self) -> Result<u64, ProtocolError> {
        if self.fatal {
            return Err(fatal_protocol_error());
        }
        Ok(self.state.revision())
    }

    /// Returns the bounded policy subset needed by userspace application
    /// attribution.
    ///
    /// Network-only rules are enforced before NFQUEUE and Learning needs no
    /// rule scan at all. Avoid cloning the complete (up to 10,000-rule) state
    /// for every queued packet.
    pub fn application_decision_snapshot(
        &self,
    ) -> Result<Arc<ApplicationDecisionPolicy>, ProtocolError> {
        if self.fatal || self.poisoned {
            return Err(self.emergency_protocol_error());
        }
        Ok(Arc::clone(&self.application_policy))
    }

    /// Reads only the fields which can invalidate an in-flight packet
    /// authorization. This final check runs while holding the engine lock and
    /// must not clone the complete rule set a second time.
    pub fn application_decision_identity(&self) -> Result<(Mode, u32), ProtocolError> {
        if self.fatal || self.poisoned {
            return Err(self.emergency_protocol_error());
        }
        Ok((self.state.mode(), self.state.flow_generation()))
    }

    /// Decides whether an attributed Learning observation can usefully enter
    /// the bounded persistence queue.
    ///
    /// The current state is checked after procfs attribution because learning
    /// commits intentionally retain the flow generation. This makes an exact
    /// rule learned during attribution visible without admitting one more
    /// redundant observation. Policy changes and poisoned state fail closed.
    pub(crate) fn application_learning_queue_admission(
        &self,
        expected_mode: Mode,
        expected_flow_generation: u32,
        endpoint: &LearnedApplicationEndpoint,
    ) -> Result<LearningQueueAdmission, ProtocolError> {
        if self.fatal || self.poisoned {
            return Err(self.emergency_protocol_error());
        }
        if expected_mode != Mode::Learning
            || self.state.mode() != expected_mode
            || self.state.flow_generation() != expected_flow_generation
        {
            return Err(ProtocolError::new(
                ErrorCode::Conflict,
                "policy changed while the application learning endpoint was attributed",
            ));
        }
        if self.application_learning_admission.revision() != self.state.revision()
            || self.application_learning_admission.mode() != self.state.mode()
            || self.application_learning_admission.flow_generation() != self.state.flow_generation()
        {
            return Err(ProtocolError::new(
                ErrorCode::Internal,
                "application learning admission cache is not current",
            ));
        }
        if self.learning_persistence == LearningPersistence::Paused {
            return Ok(LearningQueueAdmission::PersistencePaused);
        }
        let admission = match self.learning_persistence {
            LearningPersistence::InFlight(_) => self
                .pending_application_learning_admission
                .as_deref()
                .ok_or_else(|| {
                    ProtocolError::new(
                        ErrorCode::Internal,
                        "application learning transaction has no pending admission index",
                    )
                })?,
            LearningPersistence::Active | LearningPersistence::Paused => {
                self.application_learning_admission.as_ref()
            }
        };
        match admission
            .classify(endpoint)
            .map_err(|error| ProtocolError::new(ErrorCode::InvalidRequest, error.to_string()))?
        {
            ApplicationLearningAdmission::AlreadyKnown => Ok(LearningQueueAdmission::AlreadyKnown),
            ApplicationLearningAdmission::Saturated => {
                self.record_learning_quota_skipped(1);
                Ok(LearningQueueAdmission::Saturated)
            }
            ApplicationLearningAdmission::Candidate => Ok(LearningQueueAdmission::Enqueue),
        }
    }

    #[must_use]
    pub fn status_response(&self) -> Response {
        if self.fatal {
            return Response::Error(fatal_protocol_error());
        }
        let rule_count = u32::try_from(self.state.rules().len()).unwrap_or(u32::MAX);
        Response::Status {
            revision: self.state.revision(),
            mode: self.state.mode(),
            rule_count,
            backend: self.backend.kind(),
            nfqueue: self.nfqueue_counters.snapshot(),
        }
    }

    /// Returns status with an explicit, typed description of the effective
    /// packet-processing path. The legacy response remains unchanged and is
    /// still served for `ReadRequest::Status`.
    #[must_use]
    pub fn status_v2_response(&self) -> Response {
        if self.fatal {
            return Response::Error(fatal_protocol_error());
        }
        let rule_count = u32::try_from(self.state.rules().len()).unwrap_or(u32::MAX);
        let backend = self.backend.kind();
        let runtime_compatibility = self.runtime_compatibility();
        Response::StatusV2 {
            revision: self.state.revision(),
            mode: self.state.mode(),
            rule_count,
            backend,
            nfqueue: self.nfqueue_counters.snapshot(),
            runtime_compatibility,
        }
    }

    /// Quota evidence is aggregate-only, including for privileged callers.
    /// It reports capacity and lost observations, never certifies that all
    /// applications or endpoints have been learned successfully.
    pub fn learning_status(&self) -> LearningStatus {
        let summary = self.application_learning_admission.summary();
        LearningStatus {
            per_uid_limit: u32::try_from(self.learning_limits.per_uid()).unwrap_or(u32::MAX),
            per_application_limit: u32::try_from(self.learning_limits.per_application())
                .unwrap_or(u32::MAX),
            automatic_rule_limit: u32::try_from(MAX_AUTOMATIC_LEARNED_RULES).unwrap_or(u32::MAX),
            total_rule_limit: u32::try_from(MAX_RULES).unwrap_or(u32::MAX),
            automatic_rules: u32::try_from(summary.automatic_rules).unwrap_or(u32::MAX),
            saturated_uids: u32::try_from(summary.saturated_uids).unwrap_or(u32::MAX),
            saturated_applications: u32::try_from(summary.saturated_applications)
                .unwrap_or(u32::MAX),
            quota_skipped_observations: self.quota_skipped_observations.load(),
        }
    }

    pub fn status_v3_response(&self) -> Response {
        if self.fatal {
            return Response::Error(fatal_protocol_error());
        }
        Response::StatusV3 {
            revision: self.state.revision(),
            mode: self.state.mode(),
            rule_count: u32::try_from(self.state.rules().len()).unwrap_or(u32::MAX),
            backend: self.backend.kind(),
            nfqueue: self.nfqueue_counters.snapshot(),
            runtime_compatibility: self.runtime_compatibility(),
            learning: self.learning_status(),
        }
    }

    pub fn status_v4_response(&self) -> Response {
        if self.fatal {
            return Response::Error(fatal_protocol_error());
        }
        Response::StatusV4 {
            revision: self.state.revision(),
            mode: self.state.mode(),
            rule_count: u32::try_from(self.state.rules().len()).unwrap_or(u32::MAX),
            backend: self.backend.kind(),
            nfqueue: self.nfqueue_counters.snapshot(),
            runtime_compatibility: self.runtime_compatibility(),
            learning: self.learning_status(),
            enforcement_strategy: self.state.enforcement_strategy(),
        }
    }

    fn record_learning_quota_skipped(&self, count: usize) {
        if count == 0 {
            return;
        }
        for _ in 0..count {
            self.quota_skipped_observations.increment();
        }
        // Best effort logging cannot stall the packet decision path. The
        // lifetime counter remains visible even when a log is suppressed.
        let Ok(mut last) = self.last_quota_warning.try_lock() else {
            return;
        };
        if last.is_some_and(|previous| previous.elapsed() < Duration::from_secs(30)) {
            return;
        }
        *last = Some(Instant::now());
        warn!(
            skipped_observations = self.quota_skipped_observations.load(),
            per_uid_limit = self.learning_limits.per_uid(),
            per_application_limit = self.learning_limits.per_application(),
            "application learning quota reached; traffic may pass in Learning without a saved rule; review learning capacity before Enforcing"
        );
    }

    #[must_use]
    pub(crate) fn runtime_compatibility(&self) -> RuntimeCompatibility {
        if self.poisoned && self.state.mode() == Mode::BlockAll {
            return RuntimeCompatibility {
                level: CompatibilityLevel::KernelNative,
                reason: CompatibilityReason::EmergencyBlockAll,
            };
        }
        select_runtime_compatibility(
            self.backend.kind(),
            self.state.mode(),
            self.state.application_interception(),
        )
    }

    #[must_use]
    pub fn rules_page_response(&self, after: Option<Uuid>, requested_limit: u16) -> Response {
        if self.fatal {
            return Response::Error(fatal_protocol_error());
        }
        let limit = usize::from(clamp_page_limit(requested_limit));
        let mut matching = self.state.rules_after(after);
        let rules: Vec<Rule> = matching.by_ref().take(limit).cloned().collect();
        let next_after = matching
            .next()
            .and_then(|_| rules.last().map(|rule| rule.id));
        Response::RulesPage {
            revision: self.state.revision(),
            rules,
            next_after,
        }
    }

    pub fn handle_control(&mut self, request: ControlRequest) -> Result<Ack, ProtocolError> {
        if self.poisoned {
            return Err(ProtocolError::new(
                ErrorCode::BackendUnavailable,
                "policy engine is locked after a failed rollback",
            ));
        }

        let expected_revision = request.expected_revision();
        let current_revision = self.state.revision();
        if expected_revision != current_revision {
            return Err(ProtocolError::new(
                ErrorCode::Conflict,
                format!(
                    "policy revision changed: expected {expected_revision}, current {current_revision}; reload before retrying"
                ),
            ));
        }

        if let LearningPersistence::InFlight(token) = self.learning_persistence {
            if matches!(
                &request,
                ControlRequest::SetMode {
                    mode: Mode::BlockAll,
                    ..
                }
            ) {
                let revision = self.commit_block_all_during_learning(token)?;
                return Ok(Ack::new(revision, None));
            }
            return Err(ProtocolError::new(
                ErrorCode::Conflict,
                "automatic learning is being persisted; retry the privileged change",
            ));
        }

        let entering_enforcing = self.state.mode() == Mode::Learning
            && matches!(
                &request,
                ControlRequest::SetMode {
                    mode: Mode::Enforcing,
                    ..
                } | ControlRequest::SetEnforcement { .. }
            );
        let selecting_fast = matches!(
            &request,
            ControlRequest::SetEnforcement {
                strategy: EnforcementStrategy::Fast,
                ..
            }
        );
        let mut candidate = self.state.clone();
        let (events, affected_rule) = apply_control_to_candidate(&mut candidate, request)?;

        candidate
            .validate()
            .map_err(|error| core_protocol_error(&error))?;
        let revision = candidate.revision();
        self.commit(candidate, &events)?;
        if selecting_fast {
            warn!(
                "Fast enforcement selected: process hints are revalidated, but additional socket owners outside the hint cache may not be detected"
            );
        }
        if entering_enforcing {
            let status = self.learning_status();
            if status.saturated_uids > 0
                || status.saturated_applications > 0
                || status.automatic_rules >= status.automatic_rule_limit
                || self.state.rules().len() >= MAX_RULES
                || status.quota_skipped_observations > 0
            {
                warn!(
                    skipped_observations = status.quota_skipped_observations,
                    saturated_uids = status.saturated_uids,
                    saturated_applications = status.saturated_applications,
                    "Enforcing selected with learning quota warnings; unlearned traffic remains blocked"
                );
            }
        }
        Ok(Ack::new(revision, affected_rule))
    }

    /// Applies an operator-requested `BlockAll` before waiting for a pending
    /// learning write. The combined state (including the already prepared
    /// learned rules) is then persisted after that write, so the emergency
    /// policy is both immediate in the kernel and last on disk.
    fn commit_block_all_during_learning(&mut self, token: u64) -> Result<u64, ProtocolError> {
        let pending = self
            .pending_application_learning_candidate
            .as_deref()
            .ok_or_else(|| {
                ProtocolError::new(
                    ErrorCode::Internal,
                    "application learning transaction has no pending candidate",
                )
            })?;
        let mut blocked = pending.clone();
        let event = blocked
            .set_mode(Mode::BlockAll)
            .map_err(|error| core_protocol_error(&error))?;
        blocked
            .validate()
            .map_err(|error| core_protocol_error(&error))?;
        let revision = blocked.revision();
        let pending_events = self.pending_application_learning_events.clone();

        if let Err(error) = self.backend.fail_closed() {
            error!(
                error = %format_args!("{error:#}"),
                "operator BlockAll could not be installed while learning persistence was active"
            );
            self.poisoned = true;
            self.fatal = true;
            self.restart_required = true;
            self.learning_persistence = LearningPersistence::Paused;
            return Err(fatal_protocol_error());
        }

        // Do not roll the kernel back to Learning if persistence fails. A
        // second save resolves an error reported after an atomic rename; if it
        // also fails, retain resident BlockAll and require storage repair.
        let persisted = self.persistence.save_exclusive(&blocked).or_else(|error| {
            warn!(%error, "retrying persistence of operator BlockAll after an ambiguous save");
            self.persistence.save_exclusive(&blocked)
        });

        self.replace_state(blocked);
        self.superseded_learning_transaction = Some(token);
        if let Err(error) = persisted {
            error!(
                %error,
                "operator BlockAll is active but could not be persisted; daemon remains quarantined"
            );
            self.poisoned = true;
            self.learning_persistence = LearningPersistence::Paused;
            self.restart_required = false;
            return Err(self.emergency_protocol_error());
        }

        self.learning_persistence = LearningPersistence::Active;
        self.events.clear_counter_snapshot();
        for pending_event in &pending_events {
            self.events.publish(pending_event);
        }
        self.events.publish(&event);
        Ok(revision)
    }

    #[cfg(test)]
    pub fn harvest_learning(
        &mut self,
        expected_revision: u64,
        endpoints: Vec<LearnedEndpoint>,
    ) -> Result<usize, ProtocolError> {
        if self.poisoned
            || self.learning_persistence != LearningPersistence::Active
            || self.state.mode() != Mode::Learning
            || self.state.revision() != expected_revision
            || self.state.rules().len() >= MAX_RULES
        {
            return Ok(0);
        }

        let mut candidate = self.state.clone();
        let valid_endpoints = endpoints.into_iter().take(MAX_RULES).filter(|endpoint| {
            if let Err(error) = endpoint.validate() {
                warn!(%error, "ignoring invalid endpoint from nft learning set");
                false
            } else {
                true
            }
        });
        let outcomes = candidate
            .learn_new_endpoints(valid_endpoints, MAX_LEARNED_RULES_PER_POLL)
            .map_err(|error| core_protocol_error(&error))?;
        let events: Vec<Event> = outcomes
            .into_iter()
            .filter_map(|outcome| outcome.event)
            .collect();
        if events.is_empty() {
            return Ok(0);
        }

        if let Err(error) = candidate.validate() {
            if matches!(error, CoreError::StateSizeLimitReached(_)) {
                self.learning_persistence = LearningPersistence::Paused;
                warn!(%error, "learning stopped at the persisted-state byte limit");
                return Ok(0);
            }
            return Err(core_protocol_error(&error));
        }

        if !self.commit_learning(candidate, &events)? {
            return Ok(0);
        }
        Ok(events.len())
    }

    pub(crate) fn prepare_application_learning(
        &mut self,
        expected_flow_generation: u32,
        endpoints: Vec<LearnedApplicationEndpoint>,
    ) -> Result<Option<ApplicationLearningTransaction>, ProtocolError> {
        if self.poisoned
            || self.learning_persistence != LearningPersistence::Active
            || self.state.mode() != Mode::Learning
            || self.state.flow_generation() != expected_flow_generation
        {
            return Ok(None);
        }

        let previous = self.state.clone();
        let mut candidate = self.state.clone();
        let valid_endpoints: Vec<_> = endpoints
            .into_iter()
            .take(MAX_RULES)
            .filter(|endpoint| {
                if let Err(error) = endpoint.validate() {
                    warn!(%error, "ignoring invalid application endpoint from packet quarantine");
                    false
                } else {
                    true
                }
            })
            .collect();
        let outcomes = candidate
            .learn_new_application_endpoints_with_limits(
                valid_endpoints.iter().cloned(),
                MAX_LEARNED_RULES_PER_POLL,
                self.learning_limits,
            )
            .map_err(|error| core_protocol_error(&error))?;
        // Classify against the resulting candidate: this catches capacity
        // exhausted inside this batch while excluding exact duplicates and
        // already saved rules. No dropped observation is treated as learned.
        let resulting_admission =
            build_application_learning_admission(&candidate, self.learning_limits);
        let skipped = valid_endpoints
            .iter()
            .filter(|endpoint| {
                matches!(
                    resulting_admission.classify(endpoint),
                    Ok(ApplicationLearningAdmission::Saturated)
                )
            })
            .count();
        self.record_learning_quota_skipped(skipped);
        let events: Vec<Event> = outcomes
            .into_iter()
            .filter_map(|outcome| outcome.event)
            .collect();
        if events.is_empty() {
            return Ok(None);
        }

        if let Err(error) = candidate.validate() {
            if matches!(error, CoreError::StateSizeLimitReached(_)) {
                self.learning_persistence = LearningPersistence::Paused;
                warn!(%error, "application learning stopped at the persisted-state byte limit");
                return Ok(None);
            }
            return Err(core_protocol_error(&error));
        }

        if !validate_application_learning_transition(&previous, &candidate, &events) {
            return Err(ProtocolError::new(
                ErrorCode::Internal,
                "automatic learning produced an invalid policy transition",
            ));
        }

        let token = self
            .next_learning_transaction
            .checked_add(1)
            .ok_or_else(|| {
                ProtocolError::new(
                    ErrorCode::Conflict,
                    "automatic-learning transaction counter is exhausted",
                )
            })?;
        let reservation = self.persistence.reserve_learning(token)?;
        self.next_learning_transaction = token;
        let candidate = Arc::new(candidate);
        self.pending_application_learning_admission = Some(Arc::new(
            build_application_learning_admission(candidate.as_ref(), self.learning_limits),
        ));
        self.pending_application_learning_candidate = Some(Arc::clone(&candidate));
        self.pending_application_learning_events.clone_from(&events);
        self.learning_persistence = LearningPersistence::InFlight(token);

        Ok(Some(ApplicationLearningTransaction {
            reservation,
            previous,
            candidate,
            events,
        }))
    }

    pub(crate) fn finalize_application_learning(
        &mut self,
        persisted: PersistedApplicationLearning,
    ) -> Result<usize, ProtocolError> {
        let PersistedApplicationLearning {
            transaction,
            outcome,
        } = persisted;

        let token = transaction.token();
        if self.superseded_learning_transaction == Some(token) {
            self.superseded_learning_transaction = None;
            return Ok(0);
        }
        if self.fatal || self.poisoned {
            return Err(self.emergency_protocol_error());
        }
        if self.learning_persistence != LearningPersistence::InFlight(token)
            || self.state != transaction.previous
        {
            error!(
                token,
                "automatic-learning transaction lost its base-state identity"
            );
            self.enter_emergency_fail_closed(
                self.state.revision().max(transaction.candidate.revision()),
            );
            return Err(self.emergency_protocol_error());
        }

        match outcome {
            LearningStoreOutcome::Saved => {
                let count = transaction.events.len();
                self.replace_state(Arc::unwrap_or_clone(transaction.candidate));
                self.learning_persistence = LearningPersistence::Active;
                self.events.clear_counter_snapshot();
                for event in &transaction.events {
                    self.events.publish(event);
                }
                Ok(count)
            }
            LearningStoreOutcome::PreviousRetained => {
                self.clear_pending_application_learning();
                self.learning_persistence = LearningPersistence::Paused;
                warn!(
                    "automatic learning paused after a recoverable persistence failure; previous state retained"
                );
                Ok(0)
            }
            LearningStoreOutcome::Unsafe => {
                self.enter_emergency_fail_closed(
                    self.state.revision().max(transaction.candidate.revision()),
                );
                Err(self.emergency_protocol_error())
            }
        }
    }

    #[cfg(test)]
    pub fn harvest_application_learning(
        &mut self,
        expected_flow_generation: u32,
        endpoints: Vec<LearnedApplicationEndpoint>,
    ) -> Result<usize, ProtocolError> {
        let Some(transaction) =
            self.prepare_application_learning(expected_flow_generation, endpoints)?
        else {
            return Ok(0);
        };
        let persisted = transaction.persist();
        self.finalize_application_learning(persisted)
    }

    pub fn publish_counters_if_current(
        &mut self,
        expected_revision: u64,
        counters: FirewallCounters,
    ) -> bool {
        if self.poisoned || self.state.revision() != expected_revision {
            return false;
        }
        // Every successful observation is also a liveness heartbeat.  Idle
        // counters are therefore republished once per poll without changing or
        // persisting the policy revision.
        let event = self.state.counters_event(counters, Utc::now());
        self.events.publish(&event);
        true
    }

    /// Reinstalls the complete current policy after an observation failure.
    ///
    /// The revision guard prevents an old monitoring result from overwriting a
    /// newer privileged transaction.  A successful repair is intentionally
    /// revision-neutral.  If the current policy cannot be installed, the
    /// engine installs and persists an emergency `BlockAll` state and requests
    /// a supervised restart.  If even `BlockAll` cannot be installed, normal
    /// status is suppressed by the fatal state.
    pub fn repair_policy(&mut self, expected_revision: u64) -> Result<bool, ProtocolError> {
        if self.poisoned {
            return Err(self.emergency_protocol_error());
        }
        if self.restart_required() {
            return Err(if self.fatal {
                fatal_protocol_error()
            } else {
                restart_protocol_error()
            });
        }
        if self.state.revision() != expected_revision {
            return Ok(false);
        }

        let previous = self.state.clone();
        match self.backend.apply(&previous.snapshot()) {
            Ok(()) => {
                self.events.clear_counter_snapshot();
                Ok(true)
            }
            Err(error) => {
                error!(
                    error = %format_args!("{error:#}"),
                    "firewall integrity repair failed; installing emergency BlockAll"
                );
                self.enter_emergency_fail_closed(previous.revision());
                Err(self.emergency_protocol_error())
            }
        }
    }

    pub fn quarantine_after_runtime_failure(&mut self) {
        if self.startup_policy == StartupPolicy::Pending {
            self.poisoned = true;
            self.learning_persistence = LearningPersistence::Paused;
            if let Err(error) = self.backend.fail_closed() {
                error!(error = %format_args!("{error:#}"), "cannot retain startup BlockAll quarantine");
                self.fatal = true;
            }
            return;
        }
        if !self.poisoned && !self.fatal {
            self.enter_emergency_fail_closed(self.state.revision());
        }
    }

    /// Installs kernel `BlockAll` without trusting or persisting an `Engine` value
    /// recovered from a poisoned outer mutex.
    ///
    /// A panic may have interrupted an in-memory mutation at an arbitrary
    /// point. The last durable state remains the only restart authority; the
    /// recovered object is used solely to reach its already-owned backend.
    pub(crate) fn quarantine_after_engine_poison(&mut self) {
        self.poisoned = true;
        self.fatal = true;
        self.restart_required = true;
        self.learning_persistence = LearningPersistence::Paused;
        self.events.clear_counter_snapshot();
        if let Err(error) = self.backend.fail_closed() {
            error!(
                error = %format_args!("{error:#}"),
                "cannot install BlockAll after policy-engine mutex poisoning"
            );
        }
    }

    /// Replaces the live kernel policy with `BlockAll` during a normal stop,
    /// while deliberately leaving the persisted user-selected mode intact for
    /// the next supervised start.
    pub fn install_shutdown_quarantine(&mut self) -> Result<()> {
        match self.backend.fail_closed() {
            Ok(()) => {
                self.events.clear_counter_snapshot();
                Ok(())
            }
            Err(error) => {
                self.poisoned = true;
                self.fatal = true;
                Err(error).context("cannot install the shutdown BlockAll quarantine")
            }
        }
    }

    fn commit(&mut self, candidate: State, events: &[Event]) -> Result<(), ProtocolError> {
        let previous = self.state.clone();
        if let Err(error) = self.backend.apply(&candidate.snapshot()) {
            // A timeout or lost process status does not prove that the atomic
            // netlink batch was never committed. Always reinstall the known
            // previous snapshot before claiming it remains active.
            error!(
                error = %format_args!("{error:#}"),
                "firewall transaction outcome is ambiguous; restoring previous policy"
            );
            match self.backend.apply(&previous.snapshot()) {
                Ok(()) => {
                    self.events.clear_counter_snapshot();
                    return Err(ProtocolError::new(
                        ErrorCode::BackendUnavailable,
                        "firewall transaction failed; previous policy was reinstalled",
                    ));
                }
                Err(rollback_error) => {
                    error!(
                        error = %format_args!("{rollback_error:#}"),
                        "firewall rollback after ambiguous apply failed"
                    );
                    self.enter_emergency_fail_closed(previous.revision().max(candidate.revision()));
                    return Err(self.emergency_protocol_error());
                }
            }
        }

        if let Err(save_error) = self.persistence.save_exclusive(&candidate) {
            error!(error = %save_error, "state persistence failed; rolling policy back");
            let backend_rollback = self.backend.apply(&previous.snapshot());
            let storage_rollback =
                match self.persisted_state_after_failed_save(&previous, &candidate) {
                    PersistedStateAfterFailure::Previous => Ok(()),
                    PersistedStateAfterFailure::CandidateOrUnknown => {
                        self.persistence.save_exclusive(&previous)
                    }
                };
            if backend_rollback.is_err() || storage_rollback.is_err() {
                if let Err(error) = &backend_rollback {
                    error!(error = %format_args!("{error:#}"), "firewall rollback failed");
                }
                if let Err(error) = &storage_rollback {
                    error!(%error, "state rollback failed");
                }
                self.enter_emergency_fail_closed(previous.revision().max(candidate.revision()));
                return Err(self.emergency_protocol_error());
            }
            return Err(ProtocolError::new(
                ErrorCode::Internal,
                "state persistence failed; previous policy restored",
            ));
        }

        self.replace_state(candidate);
        self.learning_persistence = LearningPersistence::Active;
        self.events.clear_counter_snapshot();
        for event in events {
            self.events.publish(event);
        }
        Ok(())
    }

    #[cfg(test)]
    fn commit_learning(
        &mut self,
        candidate: State,
        events: &[Event],
    ) -> Result<bool, ProtocolError> {
        let previous = self.state.clone();
        // Learning already permits all outbound traffic.  Newly learned
        // outbound allows do not change the active kernel decision until a
        // later Enforcing transaction, so rebuilding nftables here would only
        // discard dynamic sets and reset live counters.
        if let Err(save_error) = self.persistence.save_exclusive(&candidate) {
            error!(
                error = %save_error,
                "learned-state persistence failed; checking the authoritative state file"
            );
            if self.persisted_state_after_failed_save(&previous, &candidate)
                == PersistedStateAfterFailure::CandidateOrUnknown
                && let Err(rollback_error) = self.persistence.save_exclusive(&previous)
            {
                error!(
                    error = %rollback_error,
                    "learned-state storage rollback failed"
                );
                self.enter_emergency_fail_closed(previous.revision().max(candidate.revision()));
                return Err(self.emergency_protocol_error());
            }
            // The prior state is still authoritative and the active Learning
            // policy has not changed. Stop further automatic writes until a
            // privileged successful mutation or restart, rather than turning
            // a local traffic/storage-pressure event into destructive global
            // quarantine.
            self.learning_persistence = LearningPersistence::Paused;
            warn!(
                "automatic learning paused after a recoverable persistence failure; previous state retained"
            );
            return Ok(false);
        }

        self.replace_state(candidate);
        self.events.clear_counter_snapshot();
        for event in events {
            self.events.publish(event);
        }
        Ok(true)
    }

    fn persisted_state_after_failed_save(
        &self,
        previous: &State,
        candidate: &State,
    ) -> PersistedStateAfterFailure {
        match self.persistence.load_exclusive() {
            Ok(persisted) => {
                persisted_state_after_failed_save_result(persisted, previous, candidate)
            }
            Err(error) => {
                error!(%error, "cannot validate state file after a failed save");
                PersistedStateAfterFailure::CandidateOrUnknown
            }
        }
    }

    fn enter_emergency_fail_closed(&mut self, revision_floor: u64) {
        let retained_state = self
            .pending_application_learning_candidate
            .as_deref()
            .unwrap_or(&self.state)
            .clone();
        let revision_floor = revision_floor.max(retained_state.revision());
        self.poisoned = true;
        self.learning_persistence = LearningPersistence::Paused;
        self.restart_required = false;
        match self.backend.fail_closed() {
            Ok(()) => {
                let fail_closed = match State::from_snapshot(Snapshot {
                    revision: revision_floor.saturating_add(1),
                    flow_generation: retained_state.flow_generation(),
                    mode: Mode::BlockAll,
                    // BlockAll has no accept path regardless of stored rules.
                    // Retain the last validated policy so a transient runtime
                    // failure cannot become destructive policy data loss.
                    rules: retained_state.snapshot().rules,
                }) {
                    Ok(state) => state,
                    Err(error) => {
                        error!(%error, "cannot construct monotonic emergency state");
                        self.fatal = true;
                        self.restart_required = true;
                        return;
                    }
                };
                self.replace_state(fail_closed.clone());
                self.events.clear_counter_snapshot();
                match self.persistence.save_exclusive(&fail_closed) {
                    Ok(()) => self.restart_required = true,
                    Err(error) => {
                        // Exiting now could reload an ambiguous candidate or
                        // stale permissive state. Keep the known kernel
                        // BlockAll policy resident and reject all mutations
                        // until an operator repairs storage.
                        error!(
                            %error,
                            "could not persist emergency fail-closed state; daemon quarantined without automatic restart"
                        );
                    }
                }
            }
            Err(error) => {
                error!(error = %format_args!("{error:#}"), "emergency fail-closed update failed");
                // The in-memory state can no longer describe the kernel policy.
                // Refuse all normal status/control responses and make the server
                // terminate so the service manager can restart from persisted
                // state.  Do not overwrite that state with an uninstalled claim.
                self.fatal = true;
                self.restart_required = true;
            }
        }
    }

    fn emergency_protocol_error(&self) -> ProtocolError {
        if self.fatal {
            fatal_protocol_error()
        } else if self.restart_required {
            restart_protocol_error()
        } else {
            ProtocolError::new(
                ErrorCode::BackendUnavailable,
                "emergency BlockAll is active but could not be persisted; daemon is quarantined and requires storage repair",
            )
        }
    }

    fn replace_state(&mut self, state: State) {
        let application_policy = Arc::new(build_application_decision_policy(&state));
        let application_learning_admission = Arc::new(build_application_learning_admission(
            &state,
            self.learning_limits,
        ));
        self.state = state;
        self.application_policy = application_policy;
        self.application_learning_admission = application_learning_admission;
        self.clear_pending_application_learning();
    }

    fn clear_pending_application_learning(&mut self) {
        self.pending_application_learning_admission = None;
        self.pending_application_learning_candidate = None;
        self.pending_application_learning_events.clear();
    }
}

fn apply_control_to_candidate(
    candidate: &mut State,
    request: ControlRequest,
) -> Result<(Vec<Event>, Option<Rule>), ProtocolError> {
    match request {
        ControlRequest::SetEnforcement { strategy, .. } => {
            let event = candidate
                .enforce(strategy)
                .map_err(|error| core_protocol_error(&error))?;
            Ok((vec![event], None))
        }
        ControlRequest::SetMode { mode, .. } => {
            let event = candidate
                .set_mode(mode)
                .map_err(|error| core_protocol_error(&error))?;
            Ok((vec![event], None))
        }
        ControlRequest::CreateRule { mut rule, .. } => {
            if rule.origin != RuleOrigin::Manual {
                return Err(ProtocolError::new(
                    ErrorCode::InvalidRequest,
                    "only the daemon may create rules marked as learned or template",
                ));
            }
            pin_rule_application(&mut rule).map_err(|error| {
                ProtocolError::new(ErrorCode::InvalidRequest, error.to_string())
            })?;
            let (created, event) = candidate
                .create_rule(rule)
                .map_err(|error| core_protocol_error(&error))?;
            Ok((vec![event], Some(created)))
        }
        ControlRequest::UpdateRule { id, mut rule, .. } => {
            let Some(current) = candidate.rule(id) else {
                return Err(ProtocolError::new(
                    ErrorCode::NotFound,
                    format!("rule {id} does not exist"),
                ));
            };
            if current.spec.origin != rule.origin {
                return Err(ProtocolError::new(
                    ErrorCode::InvalidRequest,
                    "a rule's origin cannot be changed",
                ));
            }
            // Pin every edited application selector before it reaches State.
            // State deliberately removes the pin again only for the exact
            // disabled broad-template skeleton.  A disabled template that is
            // edited into a narrower/custom rule must remain pinned so it can
            // later be enabled without storing an unauthenticated selector.
            pin_rule_application(&mut rule).map_err(|error| {
                ProtocolError::new(ErrorCode::InvalidRequest, error.to_string())
            })?;
            let (updated, event) = candidate
                .update_rule(id, rule)
                .map_err(|error| core_protocol_error(&error))?;
            Ok((vec![event], Some(updated)))
        }
        ControlRequest::DeleteRule { id, .. } => {
            let (deleted, event) = candidate
                .delete_rule(id)
                .map_err(|error| core_protocol_error(&error))?;
            Ok((vec![event], Some(deleted)))
        }
        ControlRequest::SetRuleEnabled { id, enabled, .. } => {
            let current = candidate.rule(id).cloned().ok_or_else(|| {
                ProtocolError::new(ErrorCode::NotFound, format!("rule {id} does not exist"))
            })?;
            let (updated, event) = if enabled
                && (current.spec.origin == RuleOrigin::Template
                    || current
                        .spec
                        .application
                        .as_ref()
                        .is_some_and(|selector| selector.executable_file.is_none()))
            {
                let mut specification = current.spec;
                pin_rule_application(&mut specification).map_err(|error| {
                    ProtocolError::new(ErrorCode::InvalidRequest, error.to_string())
                })?;
                specification.enabled = true;
                candidate
                    .update_rule(id, specification)
                    .map_err(|error| core_protocol_error(&error))?
            } else {
                candidate
                    .set_rule_enabled(id, enabled)
                    .map_err(|error| core_protocol_error(&error))?
            };
            Ok((vec![event], Some(updated)))
        }
        ControlRequest::ManageOutboundGroup { group, action, .. } => {
            let events = apply_outbound_group_to_candidate(candidate, &group, action)?;
            Ok((events, None))
        }
    }
}

fn apply_outbound_group_to_candidate(
    candidate: &mut State,
    group: &OutboundGroupSelector,
    action: OutboundGroupAction,
) -> Result<Vec<Event>, ProtocolError> {
    // Resolve membership before editing the private candidate. State assigns
    // each event its normal consecutive revision, while the caller commits
    // the final policy to the firewall and storage exactly once.
    let members: Vec<Rule> = candidate
        .rules()
        .filter(|rule| group.matches(rule))
        .cloned()
        .collect();
    if members.is_empty() {
        return Err(ProtocolError::new(
            ErrorCode::NotFound,
            "outbound group has no matching rules; reload before retrying",
        ));
    }

    let mut events = Vec::with_capacity(members.len());
    for member in members {
        match action {
            OutboundGroupAction::Delete => {
                let (_, event) = candidate
                    .delete_rule(member.id)
                    .map_err(|error| core_protocol_error(&error))?;
                events.push(event);
            }
            OutboundGroupAction::Accept
            | OutboundGroupAction::Reject
            | OutboundGroupAction::Drop => {
                let mut specification = member.spec;
                specification.action = match action {
                    OutboundGroupAction::Reject => RuleAction::Reject,
                    OutboundGroupAction::Drop => RuleAction::Drop,
                    _ => RuleAction::Accept,
                };
                // Existing file pins are policy identity and must survive a
                // verdict change even when the executable has disappeared.
                // A disabled, broad Accept template may have no pin; changing
                // it into a deny rule requires pinning under State invariants.
                if specification.action != RuleAction::Accept
                    && specification
                        .application
                        .as_ref()
                        .is_some_and(|selector| selector.executable_file.is_none())
                {
                    pin_rule_application(&mut specification).map_err(|error| {
                        ProtocolError::new(ErrorCode::InvalidRequest, error.to_string())
                    })?;
                }
                let (_, event) = candidate
                    .update_rule(member.id, specification)
                    .map_err(|error| core_protocol_error(&error))?;
                events.push(event);
            }
            OutboundGroupAction::Enable | OutboundGroupAction::Disable => {
                let request = ControlRequest::SetRuleEnabled {
                    expected_revision: candidate.revision(),
                    id: member.id,
                    enabled: action == OutboundGroupAction::Enable,
                };
                let (changed, _) = apply_control_to_candidate(candidate, request)?;
                events.extend(changed);
            }
        }
    }
    Ok(events)
}

fn persisted_state_after_failed_save(
    store: &dyn StateStore,
    previous: &State,
    candidate: &State,
) -> PersistedStateAfterFailure {
    match store.load() {
        Ok(persisted) => persisted_state_after_failed_save_result(persisted, previous, candidate),
        Err(error) => {
            error!(%error, "cannot validate state file after a failed save");
            PersistedStateAfterFailure::CandidateOrUnknown
        }
    }
}

fn persisted_state_after_failed_save_result(
    persisted: Option<State>,
    previous: &State,
    candidate: &State,
) -> PersistedStateAfterFailure {
    match persisted {
        Some(persisted) if &persisted == previous => PersistedStateAfterFailure::Previous,
        Some(persisted) if &persisted == candidate => {
            warn!(
                "failed save replaced the state file before reporting an error; rollback is required"
            );
            PersistedStateAfterFailure::CandidateOrUnknown
        }
        _ => {
            error!("state file is absent or differs after a failed save");
            PersistedStateAfterFailure::CandidateOrUnknown
        }
    }
}

fn fatal_protocol_error() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::BackendUnavailable,
        "kernel policy state is unknown; daemon is terminating for service-manager recovery",
    )
}

fn restart_protocol_error() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::BackendUnavailable,
        "firewall integrity repair failed; emergency BlockAll is active and the daemon is restarting",
    )
}

fn core_protocol_error(error: &CoreError) -> ProtocolError {
    let code = match error {
        CoreError::Validation(_) => ErrorCode::InvalidRequest,
        CoreError::RuleNotFound(_) => ErrorCode::NotFound,
        CoreError::DuplicateRuleId(_)
        | CoreError::RulesLimitReached(_)
        | CoreError::StateSizeLimitReached(_)
        | CoreError::RevisionOverflow
        | CoreError::FlowGenerationExhausted => ErrorCode::Conflict,
        CoreError::InvalidFlowGeneration
        | CoreError::InvalidObserverRedaction
        | CoreError::StateSerialization(_)
        | CoreError::MismatchedRuleId { .. } => ErrorCode::Internal,
        CoreError::RedactedApplicationMetadata | CoreError::UnpinnedApplicationIdentity => {
            ErrorCode::InvalidRequest
        }
    };
    ProtocolError::new(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;

    use anyhow::{Result as AnyResult, bail};
    use openshield_core::{
        ApplicationPath, ApplicationSelector, CgroupPath, Direction, ExecutableFileId,
        InterfaceName, PortRange, RuleName, RuleSpec, Snapshot, StorageError, TransportProtocol,
    };
    use openshield_protocol::{CompatibilityLevel, CompatibilityReason, RuntimeCompatibility};

    use super::*;
    use crate::backend::FirewallObserver;

    #[derive(Clone, Debug, Default)]
    struct BackendProbe {
        kind: FirewallBackendKind,
        applied: Arc<Mutex<Vec<Snapshot>>>,
        fail_next: Arc<AtomicBool>,
        error_after_apply: Arc<AtomicBool>,
        failure_script: Arc<Mutex<VecDeque<bool>>>,
    }

    impl FirewallObserver for BackendProbe {
        fn policy_observation(&mut self) -> AnyResult<FirewallCounters> {
            Ok(FirewallCounters::default())
        }
    }

    impl FirewallBackend for BackendProbe {
        fn kind(&self) -> FirewallBackendKind {
            self.kind
        }

        fn apply(&mut self, snapshot: &Snapshot) -> AnyResult<()> {
            let scripted_failure = self
                .failure_script
                .lock()
                .map_err(|_| anyhow!("backend failure script poisoned"))?
                .pop_front()
                .unwrap_or(false);
            if scripted_failure {
                bail!("injected scripted apply failure");
            }
            if self.fail_next.swap(false, Ordering::SeqCst) {
                bail!("injected apply failure");
            }
            self.applied
                .lock()
                .map_err(|_| anyhow!("backend probe poisoned"))?
                .push(snapshot.clone());
            if self.error_after_apply.swap(false, Ordering::SeqCst) {
                bail!("injected error after policy installation");
            }
            Ok(())
        }

        fn fail_closed(&mut self) -> AnyResult<()> {
            self.apply(&State::new().snapshot())
        }
    }

    #[derive(Clone, Debug)]
    struct StoreProbe {
        state: Arc<Mutex<Option<State>>>,
        save_count: Arc<AtomicUsize>,
        fail_next: Arc<AtomicBool>,
        failure_script: Arc<Mutex<VecDeque<bool>>>,
    }

    impl StoreProbe {
        fn new(state: State) -> Self {
            Self {
                state: Arc::new(Mutex::new(Some(state))),
                save_count: Arc::new(AtomicUsize::new(0)),
                fail_next: Arc::new(AtomicBool::new(false)),
                failure_script: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        fn empty() -> Self {
            Self {
                state: Arc::new(Mutex::new(None)),
                save_count: Arc::new(AtomicUsize::new(0)),
                fail_next: Arc::new(AtomicBool::new(false)),
                failure_script: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        fn persisted_state(&self) -> AnyResult<Option<State>> {
            self.state
                .lock()
                .map(|state| state.clone())
                .map_err(|_| anyhow!("store probe poisoned"))
        }
    }

    impl StateStore for StoreProbe {
        fn load(&self) -> Result<Option<State>, StorageError> {
            self.state
                .lock()
                .map(|state| state.clone())
                .map_err(|_| StorageError::InvalidJson("store probe poisoned".to_owned()))
        }

        fn save(&self, state: &State) -> Result<(), StorageError> {
            self.save_count.fetch_add(1, Ordering::SeqCst);
            let scripted_failure = self
                .failure_script
                .lock()
                .map_err(|_| StorageError::InvalidJson("store failure script poisoned".to_owned()))?
                .pop_front()
                .unwrap_or(false);
            if scripted_failure || self.fail_next.swap(false, Ordering::SeqCst) {
                return Err(StorageError::InvalidJson(
                    "injected persistence failure".to_owned(),
                ));
            }
            *self
                .state
                .lock()
                .map_err(|_| StorageError::InvalidJson("store probe poisoned".to_owned()))? =
                Some(state.clone());
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    struct PanickingStore {
        inner: StoreProbe,
        panic_next_save: Arc<AtomicBool>,
    }

    impl PanickingStore {
        fn new(state: State) -> Self {
            Self {
                inner: StoreProbe::new(state),
                panic_next_save: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl StateStore for PanickingStore {
        fn load(&self) -> Result<Option<State>, StorageError> {
            self.inner.load()
        }

        fn save(&self, state: &State) -> Result<(), StorageError> {
            assert!(
                !self.panic_next_save.swap(false, Ordering::SeqCst),
                "injected state-store panic"
            );
            self.inner.save(state)
        }
    }

    #[derive(Debug)]
    struct BlockingStoreState {
        state: Option<State>,
        block_next_save: bool,
        entered_save: bool,
        release_save: bool,
    }

    #[derive(Clone, Debug)]
    struct BlockingStore {
        inner: Arc<(Mutex<BlockingStoreState>, Condvar)>,
    }

    impl BlockingStore {
        fn new(state: State) -> Self {
            Self {
                inner: Arc::new((
                    Mutex::new(BlockingStoreState {
                        state: Some(state),
                        block_next_save: false,
                        entered_save: false,
                        release_save: false,
                    }),
                    Condvar::new(),
                )),
            }
        }

        fn arm_next_save(&self) -> AnyResult<BlockingStoreRelease> {
            let (state, _) = &*self.inner;
            let mut state = state
                .lock()
                .map_err(|_| anyhow!("blocking store poisoned"))?;
            state.block_next_save = true;
            state.entered_save = false;
            state.release_save = false;
            Ok(BlockingStoreRelease {
                store: self.clone(),
            })
        }

        fn wait_until_save_is_blocked(&self) -> AnyResult<()> {
            let (state, changed) = &*self.inner;
            let mut state = state
                .lock()
                .map_err(|_| anyhow!("blocking store poisoned"))?;
            let deadline = Instant::now() + Duration::from_secs(5);
            while !state.entered_save {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    bail!("timed out waiting for blocked state save");
                }
                let (next, timeout) = changed
                    .wait_timeout(state, remaining)
                    .map_err(|_| anyhow!("blocking store poisoned"))?;
                state = next;
                if timeout.timed_out() && !state.entered_save {
                    bail!("timed out waiting for blocked state save");
                }
            }
            Ok(())
        }

        fn release(&self) {
            let (state, changed) = &*self.inner;
            if let Ok(mut state) = state.lock() {
                state.release_save = true;
                changed.notify_all();
            }
        }

        fn persisted_state(&self) -> AnyResult<Option<State>> {
            let (state, _) = &*self.inner;
            state
                .lock()
                .map(|state| state.state.clone())
                .map_err(|_| anyhow!("blocking store poisoned"))
        }
    }

    #[derive(Debug)]
    struct BlockingStoreRelease {
        store: BlockingStore,
    }

    impl Drop for BlockingStoreRelease {
        fn drop(&mut self) {
            self.store.release();
        }
    }

    impl StateStore for BlockingStore {
        fn load(&self) -> Result<Option<State>, StorageError> {
            let (state, _) = &*self.inner;
            state
                .lock()
                .map(|state| state.state.clone())
                .map_err(|_| StorageError::InvalidJson("blocking store poisoned".to_owned()))
        }

        fn save(&self, candidate: &State) -> Result<(), StorageError> {
            let (state, changed) = &*self.inner;
            let mut state = state
                .lock()
                .map_err(|_| StorageError::InvalidJson("blocking store poisoned".to_owned()))?;
            if state.block_next_save {
                state.block_next_save = false;
                state.entered_save = true;
                changed.notify_all();
                while !state.release_save {
                    state = changed.wait(state).map_err(|_| {
                        StorageError::InvalidJson("blocking store poisoned".to_owned())
                    })?;
                }
            }
            state.state = Some(candidate.clone());
            Ok(())
        }
    }

    fn manual_rule(name: &str) -> AnyResult<RuleSpec> {
        Ok(RuleSpec::new(
            RuleName::new(name)?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            None,
            Some(PortRange::single(443)?),
            None,
            RuleOrigin::Manual,
            true,
        )?)
    }

    fn learned_application_endpoint(
        address_offset: u32,
        uid: u32,
        application_number: u64,
    ) -> AnyResult<LearnedApplicationEndpoint> {
        Ok(LearnedApplicationEndpoint {
            endpoint: LearnedEndpoint {
                address: std::net::Ipv4Addr::from(0x0a00_0001_u32 + address_offset).into(),
                protocol: TransportProtocol::Tcp,
                port: Some(PortRange::single(443)?),
                interface: Some(InterfaceName::new("eth0")?),
            },
            application: ApplicationSelector::new(
                Some(ApplicationPath::new(format!(
                    "/usr/bin/openshield-engine-test-{application_number}"
                ))?),
                Some(ExecutableFileId {
                    device: 8,
                    inode: application_number + 1,
                    size: application_number + 1,
                    ctime_seconds: 1_700_000_000,
                    ctime_nanoseconds: 0,
                }),
                None,
                Some(uid),
                None,
            )?,
        })
    }

    fn engine_with_probes() -> AnyResult<(Engine, BackendProbe, StoreProbe, EventBus)> {
        engine_with_state(State::new())
    }

    fn engine_with_state(state: State) -> AnyResult<(Engine, BackendProbe, StoreProbe, EventBus)> {
        engine_with_state_and_limits(state, LearningLimits::default())
    }

    fn engine_with_state_and_limits(
        state: State,
        limits: LearningLimits,
    ) -> AnyResult<(Engine, BackendProbe, StoreProbe, EventBus)> {
        let backend = BackendProbe::default();
        let store = StoreProbe::new(state);
        let events = EventBus::new();
        let mut engine = Engine::load_with_learning_limits(
            Box::new(backend.clone()),
            Box::new(store.clone()),
            events.clone(),
            limits,
        )?;
        engine.activate_startup_policy()?;
        backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?
            .clear();
        store.save_count.store(0, Ordering::SeqCst);
        Ok((engine, backend, store, events))
    }

    fn outbound_group_state() -> AnyResult<(State, Vec<Rule>)> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        let mut rules = Vec::new();
        for (index, (executable, cgroup, network, inbound)) in [
            (
                Some("/group/alpha"),
                Some("/group/a"),
                Some("203.0.113.1/24"),
                false,
            ),
            (Some("/group/alpha"), Some("/group/a"), None, false),
            (Some("/group/beta"), Some("/group/a"), None, false),
            (Some("/group/alpha"), None, Some("203.0.113.1/24"), false),
            (Some("/group/alpha"), Some("/group/b"), None, false),
            (None, None, Some("203.0.113.1/24"), false),
            (None, None, Some("203.0.113.129/24"), false),
            (None, None, None, false),
            (None, None, Some("203.0.113.1/24"), true),
            (None, None, None, true),
        ]
        .into_iter()
        .enumerate()
        {
            let mut spec = manual_rule(&format!("group rule {index}"))?;
            spec.enabled = index % 2 == 0;
            spec.origin = if index == 5 {
                RuleOrigin::Learned
            } else {
                RuleOrigin::Manual
            };
            spec.peer_network = network.map(str::parse).transpose()?;
            if inbound {
                spec.direction = Direction::Inbound;
            }
            if let Some(executable) = executable {
                let mut application = learned_application_endpoint(1, 1_000, 1)?.application;
                application.executable = Some(ApplicationPath::new(executable)?);
                application.cgroup = cgroup.map(CgroupPath::new).transpose()?;
                spec.application = Some(application);
            }
            let (rule, _) = state.create_rule_at(
                Uuid::from_u128(u128::try_from(index)? + 1),
                spec,
                Utc::now(),
            )?;
            rules.push(rule);
        }
        Ok((state, rules))
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Explicit scope/action matrix and ordered-event assertions.
    fn outbound_group_actions_commit_all_selected_members_once() -> AnyResult<()> {
        let executable = ApplicationPath::new("/group/alpha")?;
        let cgroup = CgroupPath::new("/group/a")?;
        for (group, selected_indices) in [
            (
                OutboundGroupSelector::Cgroup {
                    cgroup: cgroup.clone(),
                    executable: None,
                },
                vec![0, 1, 2],
            ),
            (
                OutboundGroupSelector::Cgroup {
                    cgroup,
                    executable: Some(executable.clone()),
                },
                vec![0, 1],
            ),
            (OutboundGroupSelector::Executable { executable }, vec![3]),
            (
                OutboundGroupSelector::Destination {
                    peer_network: Some("203.0.113.90/24".parse()?),
                },
                vec![5, 6],
            ),
            (
                OutboundGroupSelector::Destination { peer_network: None },
                vec![7],
            ),
        ] {
            for action in [
                OutboundGroupAction::Delete,
                OutboundGroupAction::Accept,
                OutboundGroupAction::Reject,
                OutboundGroupAction::Drop,
                OutboundGroupAction::Enable,
                OutboundGroupAction::Disable,
            ] {
                let (state, original) = outbound_group_state()?;
                let (mut engine, backend, store, events) = engine_with_state(state)?;
                let previous_revision = engine.revision();
                let subscription = events
                    .subscribe()
                    .map_err(|_| anyhow!("subscribe failed"))?;
                let ack = engine
                    .handle_control(ControlRequest::ManageOutboundGroup {
                        expected_revision: previous_revision,
                        group: group.clone(),
                        action,
                    })
                    .map_err(|error| anyhow!(error.message))?;
                assert_eq!(ack.affected_rule, None);
                assert_eq!(
                    ack.revision,
                    previous_revision + u64::try_from(selected_indices.len())?
                );
                assert_eq!(engine.revision(), ack.revision);
                assert_eq!(store.save_count.load(Ordering::SeqCst), 1);
                assert_eq!(store.persisted_state()?, Some(engine.state.clone()));
                let applied = backend
                    .applied
                    .lock()
                    .map_err(|_| anyhow!("backend probe poisoned"))?;
                assert_eq!(applied.as_slice(), &[engine.state.snapshot()]);
                drop(applied);

                for (index, before) in original.iter().enumerate() {
                    if !selected_indices.contains(&index) {
                        assert_eq!(engine.state.rule(before.id), Some(before));
                        continue;
                    }
                    if action == OutboundGroupAction::Delete {
                        assert!(engine.state.rule(before.id).is_none());
                        continue;
                    }
                    let after = engine
                        .state
                        .rule(before.id)
                        .ok_or_else(|| anyhow!("member disappeared"))?;
                    let mut expected_spec = before.spec.clone();
                    match action {
                        OutboundGroupAction::Accept => expected_spec.action = RuleAction::Accept,
                        OutboundGroupAction::Reject => expected_spec.action = RuleAction::Reject,
                        OutboundGroupAction::Drop => expected_spec.action = RuleAction::Drop,
                        OutboundGroupAction::Enable => expected_spec.enabled = true,
                        OutboundGroupAction::Disable => expected_spec.enabled = false,
                        OutboundGroupAction::Delete => bail!("delete was already handled"),
                    }
                    assert_eq!(after.spec, expected_spec);
                    assert_eq!(after.created_at, before.created_at);
                    assert!(after.updated_at >= before.updated_at);
                }
                for (offset, index) in selected_indices.iter().enumerate() {
                    let event = subscription.recv_timeout(Duration::from_millis(50))?;
                    assert_eq!(
                        event.revision,
                        previous_revision + u64::try_from(offset)? + 1
                    );
                    match (action, event.kind) {
                        (OutboundGroupAction::Delete, EventKind::RuleDeleted { rule }) => {
                            assert_eq!(rule, original[*index]);
                        }
                        (
                            OutboundGroupAction::Enable | OutboundGroupAction::Disable,
                            EventKind::RuleEnabledChanged { rule },
                        )
                        | (
                            OutboundGroupAction::Accept
                            | OutboundGroupAction::Reject
                            | OutboundGroupAction::Drop,
                            EventKind::RuleUpdated { rule },
                        ) => {
                            assert_eq!(rule.id, original[*index].id);
                            assert_eq!(engine.state.rule(rule.id), Some(&rule));
                        }
                        _ => bail!("unexpected group event"),
                    }
                }
                assert!(matches!(
                    subscription.recv_timeout(Duration::from_millis(1)),
                    Err(RecvTimeoutError::Timeout)
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn outbound_group_rejects_stale_revisions_and_empty_matches_without_side_effects()
    -> AnyResult<()> {
        let (state, _) = outbound_group_state()?;
        let (mut engine, backend, store, events) = engine_with_state(state)?;
        let original = engine.state.clone();
        let subscription = events
            .subscribe()
            .map_err(|_| anyhow!("subscribe failed"))?;
        for (expected_revision, group, expected_code) in [
            (
                engine.revision() - 1,
                OutboundGroupSelector::Destination { peer_network: None },
                ErrorCode::Conflict,
            ),
            (
                engine.revision(),
                OutboundGroupSelector::Executable {
                    executable: ApplicationPath::new("/missing")?,
                },
                ErrorCode::NotFound,
            ),
        ] {
            let error = engine
                .handle_control(ControlRequest::ManageOutboundGroup {
                    expected_revision,
                    group,
                    action: OutboundGroupAction::Delete,
                })
                .err()
                .ok_or_else(|| anyhow!("group unexpectedly succeeded"))?;
            assert_eq!(error.code, expected_code);
            assert_eq!(engine.state, original);
            assert_eq!(store.persisted_state()?, Some(original.clone()));
            assert_eq!(store.save_count.load(Ordering::SeqCst), 0);
            assert!(
                backend
                    .applied
                    .lock()
                    .map_err(|_| anyhow!("backend probe poisoned"))?
                    .is_empty()
            );
        }
        assert!(matches!(
            subscription.recv_timeout(Duration::from_millis(1)),
            Err(RecvTimeoutError::Timeout)
        ));
        Ok(())
    }

    #[test]
    fn outbound_group_rolls_back_backend_and_persistence_failures_without_events() -> AnyResult<()>
    {
        for failure in 0..3 {
            let (state, _) = outbound_group_state()?;
            let (mut engine, backend, store, events) = engine_with_state(state)?;
            let original = engine.state.clone();
            let subscription = events
                .subscribe()
                .map_err(|_| anyhow!("subscribe failed"))?;
            match failure {
                0 => backend.fail_next.store(true, Ordering::SeqCst),
                1 => backend.error_after_apply.store(true, Ordering::SeqCst),
                _ => store.fail_next.store(true, Ordering::SeqCst),
            }
            let error = engine
                .handle_control(ControlRequest::ManageOutboundGroup {
                    expected_revision: engine.revision(),
                    group: OutboundGroupSelector::Cgroup {
                        cgroup: CgroupPath::new("/group/a")?,
                        executable: None,
                    },
                    action: OutboundGroupAction::Drop,
                })
                .err()
                .ok_or_else(|| anyhow!("group unexpectedly succeeded"))?;
            assert_eq!(
                error.code,
                if failure == 2 {
                    ErrorCode::Internal
                } else {
                    ErrorCode::BackendUnavailable
                }
            );
            assert_eq!(engine.state, original);
            assert_eq!(store.persisted_state()?, Some(original.clone()));
            let applied = backend
                .applied
                .lock()
                .map_err(|_| anyhow!("backend probe poisoned"))?;
            assert_eq!(applied.len(), if failure == 0 { 1 } else { 2 });
            assert_eq!(applied.last(), Some(&original.snapshot()));
            assert!(!engine.restart_required());
            assert!(matches!(
                subscription.recv_timeout(Duration::from_millis(1)),
                Err(RecvTimeoutError::Timeout)
            ));
        }
        Ok(())
    }

    #[test]
    fn outbound_group_revision_or_generation_exhaustion_discards_partial_candidate() -> AnyResult<()>
    {
        for exhausted_revision in [true, false] {
            let (state, _) = outbound_group_state()?;
            let mut snapshot = state.snapshot();
            if exhausted_revision {
                snapshot.revision = u64::MAX - 1;
            }
            let (mut engine, backend, store, events) =
                engine_with_state(State::from_snapshot(snapshot)?)?;
            if !exhausted_revision {
                // Startup intentionally rotates the generation. Put the live
                // policy at its final usable generation after that rotation.
                engine
                    .state
                    .rotate_flow_generation(MAX_FLOW_GENERATION - 1)?;
                *store
                    .state
                    .lock()
                    .map_err(|_| anyhow!("store probe poisoned"))? = Some(engine.state.clone());
            }
            let original = engine.state.clone();
            let subscription = events
                .subscribe()
                .map_err(|_| anyhow!("subscribe failed"))?;
            assert!(
                engine
                    .handle_control(ControlRequest::ManageOutboundGroup {
                        expected_revision: engine.revision(),
                        group: OutboundGroupSelector::Cgroup {
                            cgroup: CgroupPath::new("/group/a")?,
                            executable: None,
                        },
                        action: OutboundGroupAction::Delete,
                    })
                    .is_err()
            );
            assert_eq!(engine.state, original);
            assert_eq!(store.save_count.load(Ordering::SeqCst), 0);
            assert!(
                backend
                    .applied
                    .lock()
                    .map_err(|_| anyhow!("backend probe poisoned"))?
                    .is_empty()
            );
            assert!(matches!(
                subscription.recv_timeout(Duration::from_millis(1)),
                Err(RecvTimeoutError::Timeout)
            ));
        }
        Ok(())
    }

    fn outbound_group_template(
        executable: ApplicationPath,
        cgroup: CgroupPath,
    ) -> AnyResult<RuleSpec> {
        Ok(RuleSpec {
            name: RuleName::new("application-wide template")?,
            direction: Direction::Outbound,
            action: RuleAction::Accept,
            protocol: TransportProtocol::Any,
            peer_network: None,
            port: None,
            interface: None,
            application: Some(ApplicationSelector::new(
                Some(executable),
                None,
                None,
                None,
                Some(cgroup),
            )?),
            origin: RuleOrigin::Template,
            enabled: false,
        })
    }

    #[test]
    fn outbound_group_preserves_templates_and_pins_only_when_required() -> AnyResult<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("application");
        fs::write(&path, b"test executable")?;
        let executable =
            ApplicationPath::new(path.to_str().ok_or_else(|| anyhow!("non-UTF-8 path"))?)?;
        let cgroup = CgroupPath::new("/group/templates")?;
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        let (template, _) =
            state.create_rule(outbound_group_template(executable.clone(), cgroup.clone())?)?;
        let mut concrete = manual_rule("learned application")?;
        concrete.origin = RuleOrigin::Learned;
        concrete.application = Some(ApplicationSelector::new(
            Some(executable.clone()),
            None,
            None,
            Some(1_000),
            Some(cgroup.clone()),
        )?);
        pin_rule_application(&mut concrete)?;
        let (learned, _) = state.create_rule(concrete)?;
        let (mut engine, backend, store, _events) = engine_with_state(state)?;
        for (index, action) in [
            OutboundGroupAction::Reject,
            OutboundGroupAction::Drop,
            OutboundGroupAction::Accept,
            OutboundGroupAction::Enable,
            OutboundGroupAction::Disable,
        ]
        .into_iter()
        .enumerate()
        {
            let before = engine.state.clone();
            engine
                .handle_control(ControlRequest::ManageOutboundGroup {
                    expected_revision: engine.revision(),
                    group: OutboundGroupSelector::Cgroup {
                        cgroup: cgroup.clone(),
                        executable: Some(executable.clone()),
                    },
                    action,
                })
                .map_err(|error| anyhow!(error.message))?;
            assert_eq!(engine.state.rules().len(), 2);
            for original in [&template, &learned] {
                let previous = before
                    .rule(original.id)
                    .ok_or_else(|| anyhow!("member missing"))?;
                let current = engine
                    .state
                    .rule(original.id)
                    .ok_or_else(|| anyhow!("member missing"))?;
                assert_eq!(current.spec.origin, original.spec.origin);
                assert_eq!(current.spec.name, original.spec.name);
                assert_eq!(current.created_at, original.created_at);
                assert_eq!(current.spec.protocol, original.spec.protocol);
                let expected_enabled = match action {
                    OutboundGroupAction::Enable => true,
                    OutboundGroupAction::Disable => false,
                    _ => previous.spec.enabled,
                };
                assert_eq!(current.spec.enabled, expected_enabled);
                let selector = current
                    .spec
                    .application
                    .as_ref()
                    .ok_or_else(|| anyhow!("selector missing"))?;
                assert_eq!(selector.executable.as_ref(), Some(&executable));
                assert_eq!(selector.cgroup.as_ref(), Some(&cgroup));
                assert_eq!(
                    selector.uid,
                    original
                        .spec
                        .application
                        .as_ref()
                        .and_then(|selector| selector.uid)
                );
                if original.spec.origin == RuleOrigin::Template {
                    assert_eq!(
                        selector.executable_file.is_none(),
                        !current.spec.enabled && current.spec.action == RuleAction::Accept
                    );
                } else {
                    assert_eq!(current.spec.application, original.spec.application);
                }
            }
            assert_eq!(store.save_count.load(Ordering::SeqCst), index + 1);
            assert_eq!(
                backend
                    .applied
                    .lock()
                    .map_err(|_| anyhow!("backend probe poisoned"))?
                    .len(),
                index + 1
            );
            assert_eq!(store.persisted_state()?, Some(engine.state.clone()));
        }
        Ok(())
    }

    #[test]
    fn outbound_group_pin_failure_discards_every_prepared_member() -> AnyResult<()> {
        let directory = tempfile::tempdir()?;
        let existing = directory.path().join("existing");
        let missing = directory.path().join("missing");
        fs::write(&existing, b"test executable")?;
        let cgroup = CgroupPath::new("/group/templates")?;
        let mut state = State::new();
        for (index, path) in [existing, missing].into_iter().enumerate() {
            state.create_rule_at(
                Uuid::from_u128(u128::try_from(index)? + 1),
                outbound_group_template(
                    ApplicationPath::new(path.to_str().ok_or_else(|| anyhow!("non-UTF-8 path"))?)?,
                    cgroup.clone(),
                )?,
                Utc::now(),
            )?;
        }
        for action in [OutboundGroupAction::Enable, OutboundGroupAction::Drop] {
            let (mut engine, backend, store, events) = engine_with_state(state.clone())?;
            let original = engine.state.clone();
            let subscription = events
                .subscribe()
                .map_err(|_| anyhow!("subscribe failed"))?;
            let error = engine
                .handle_control(ControlRequest::ManageOutboundGroup {
                    expected_revision: engine.revision(),
                    group: OutboundGroupSelector::Cgroup {
                        cgroup: cgroup.clone(),
                        executable: None,
                    },
                    action,
                })
                .err()
                .ok_or_else(|| anyhow!("group unexpectedly succeeded"))?;
            assert_eq!(error.code, ErrorCode::InvalidRequest);
            assert_eq!(engine.state, original);
            assert_eq!(store.persisted_state()?, Some(original));
            assert_eq!(store.save_count.load(Ordering::SeqCst), 0);
            assert!(
                backend
                    .applied
                    .lock()
                    .map_err(|_| anyhow!("backend probe poisoned"))?
                    .is_empty()
            );
            assert!(matches!(
                subscription.recv_timeout(Duration::from_millis(1)),
                Err(RecvTimeoutError::Timeout)
            ));
        }
        Ok(())
    }

    #[test]
    fn enabling_an_unpinned_group_template_pins_it_before_kernel_apply() -> AnyResult<()> {
        let directory = tempfile::tempdir()?;
        let executable_path = directory.path().join("application");
        fs::write(&executable_path, b"test executable")?;
        let executable = ApplicationPath::new(
            executable_path
                .to_str()
                .ok_or_else(|| anyhow!("temporary executable path is not UTF-8"))?,
        )?;
        let application = ApplicationSelector::new(Some(executable), None, None, None, None)?;
        let specification = RuleSpec {
            name: RuleName::new("application-wide template")?,
            direction: Direction::Outbound,
            action: RuleAction::Accept,
            protocol: TransportProtocol::Any,
            peer_network: None,
            port: None,
            interface: None,
            application: Some(application),
            origin: RuleOrigin::Template,
            enabled: false,
        };
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        let (template, _) = state.create_rule(specification)?;
        let (mut engine, backend, store, _events) = engine_with_state(state)?;

        let ack = engine
            .handle_control(ControlRequest::SetRuleEnabled {
                expected_revision: engine.revision(),
                id: template.id,
                enabled: true,
            })
            .map_err(|error| anyhow!(error.message))?;
        let enabled = engine
            .state
            .rule(template.id)
            .ok_or_else(|| anyhow!("enabled template disappeared"))?;
        assert!(enabled.spec.enabled);
        assert!(
            enabled
                .spec
                .application
                .as_ref()
                .is_some_and(|selector| selector.executable_file.is_some())
        );
        let first_pin = enabled
            .spec
            .application
            .as_ref()
            .and_then(|selector| selector.executable_file)
            .ok_or_else(|| anyhow!("enabled template has no pin"))?;

        engine
            .handle_control(ControlRequest::SetRuleEnabled {
                expected_revision: engine.revision(),
                id: template.id,
                enabled: false,
            })
            .map_err(|error| anyhow!(error.message))?;
        let disabled = engine
            .state
            .rule(template.id)
            .ok_or_else(|| anyhow!("disabled template disappeared"))?;
        let disabled_application = disabled
            .spec
            .application
            .as_ref()
            .ok_or_else(|| anyhow!("disabled template lost its selector"))?;
        assert!(!disabled.spec.enabled);
        assert_eq!(disabled.spec.action, RuleAction::Accept);
        assert_eq!(disabled.spec.direction, Direction::Outbound);
        assert_eq!(disabled.spec.protocol, TransportProtocol::Any);
        assert!(disabled.spec.peer_network.is_none());
        assert!(disabled.spec.port.is_none());
        assert!(disabled.spec.interface.is_none());
        assert!(disabled_application.executable_file.is_none());
        assert!(disabled_application.command_line.is_none());
        assert!(disabled_application.uid.is_none());

        fs::write(&executable_path, b"replacement executable version")?;
        engine
            .handle_control(ControlRequest::SetRuleEnabled {
                expected_revision: engine.revision(),
                id: template.id,
                enabled: true,
            })
            .map_err(|error| anyhow!(error.message))?;
        let replacement_pin = engine
            .state
            .rule(template.id)
            .and_then(|rule| rule.spec.application.as_ref())
            .and_then(|selector| selector.executable_file)
            .ok_or_else(|| anyhow!("re-enabled template has no replacement pin"))?;
        assert_ne!(replacement_pin, first_pin);
        assert!(ack.revision < engine.revision());
        assert_eq!(store.persisted_state()?, Some(engine.state.clone()));
        let applied = backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?;
        assert_eq!(applied.last(), Some(&engine.state.snapshot()));
        Ok(())
    }

    #[test]
    fn editing_a_disabled_template_pins_and_preserves_the_custom_rule() -> AnyResult<()> {
        let directory = tempfile::tempdir()?;
        let executable_path = directory.path().join("application");
        fs::write(&executable_path, b"test executable")?;
        let executable = ApplicationPath::new(
            executable_path
                .to_str()
                .ok_or_else(|| anyhow!("temporary executable path is not UTF-8"))?,
        )?;
        let application = ApplicationSelector::new(Some(executable), None, None, None, None)?;
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        let (template, _) = state.create_rule(RuleSpec {
            name: RuleName::new("application-wide template")?,
            direction: Direction::Outbound,
            action: RuleAction::Accept,
            protocol: TransportProtocol::Any,
            peer_network: None,
            port: None,
            interface: None,
            application: Some(application),
            origin: RuleOrigin::Template,
            enabled: false,
        })?;
        let (mut engine, _backend, store, _events) = engine_with_state(state)?;
        let mut custom = template.spec;
        custom.protocol = TransportProtocol::Tcp;
        let expected_port = PortRange::single(443)?;
        custom.port = Some(expected_port);

        engine
            .handle_control(ControlRequest::UpdateRule {
                expected_revision: engine.revision(),
                id: template.id,
                rule: custom,
            })
            .map_err(|error| anyhow!(error.message))?;
        let edited = engine
            .state
            .rule(template.id)
            .ok_or_else(|| anyhow!("edited template disappeared"))?;
        assert!(!edited.spec.enabled);
        assert_eq!(edited.spec.protocol, TransportProtocol::Tcp);
        assert_eq!(edited.spec.port, Some(expected_port));
        assert!(
            edited
                .spec
                .application
                .as_ref()
                .is_some_and(|selector| selector.executable_file.is_some())
        );

        engine
            .handle_control(ControlRequest::SetRuleEnabled {
                expected_revision: engine.revision(),
                id: template.id,
                enabled: true,
            })
            .map_err(|error| anyhow!(error.message))?;
        assert!(engine.state.rule(template.id).is_some_and(|rule| {
            rule.spec.enabled
                && rule.spec.protocol == TransportProtocol::Tcp
                && rule.spec.port == Some(expected_port)
                && rule
                    .spec
                    .application
                    .as_ref()
                    .is_some_and(|selector| selector.executable_file.is_some())
        }));
        assert_eq!(store.persisted_state()?, Some(engine.state.clone()));
        Ok(())
    }

    fn spawn_application_learning(
        engine: &SharedEngine,
        generation: u32,
        endpoints: Vec<LearnedApplicationEndpoint>,
    ) -> thread::JoinHandle<Result<usize, ProtocolError>> {
        let engine = Arc::clone(engine);
        thread::spawn(move || {
            let transaction = engine
                .lock()
                .map_err(|_| {
                    ProtocolError::new(ErrorCode::Internal, "policy engine mutex poisoned")
                })?
                .prepare_application_learning(generation, endpoints)?
                .ok_or_else(|| {
                    ProtocolError::new(ErrorCode::Internal, "learning transaction was not prepared")
                })?;
            let persisted = transaction.persist();
            engine
                .lock()
                .map_err(|_| {
                    ProtocolError::new(ErrorCode::Internal, "policy engine mutex poisoned")
                })?
                .finalize_application_learning(persisted)
        })
    }

    fn application_learning_admission(
        engine: &Engine,
        generation: u32,
        endpoint: &LearnedApplicationEndpoint,
    ) -> AnyResult<LearningQueueAdmission> {
        engine
            .application_learning_queue_admission(Mode::Learning, generation, endpoint)
            .map_err(|error| anyhow!(error.message))
    }

    fn backend_was_not_rebuilt(backend: &BackendProbe) -> AnyResult<bool> {
        backend
            .applied
            .lock()
            .map(|applied| applied.is_empty())
            .map_err(|_| anyhow!("backend probe poisoned"))
    }

    #[test]
    fn status_reports_the_backend_owned_by_the_engine() -> AnyResult<()> {
        let backend = BackendProbe {
            kind: FirewallBackendKind::Nftables,
            ..BackendProbe::default()
        };
        let store = StoreProbe::new(State::new());
        let engine = Engine::load(Box::new(backend), Box::new(store), EventBus::new())?;

        assert!(matches!(
            engine.status_response(),
            Response::Status {
                backend: FirewallBackendKind::Nftables,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn status_v2_reports_the_effective_runtime_compatibility() -> AnyResult<()> {
        let backend = BackendProbe {
            kind: FirewallBackendKind::Nftables,
            ..BackendProbe::default()
        };
        let store = StoreProbe::new(State::new());
        let engine = Engine::load(Box::new(backend), Box::new(store), EventBus::new())?;

        assert!(matches!(
            engine.status_v2_response(),
            Response::StatusV2 {
                backend: FirewallBackendKind::Nftables,
                runtime_compatibility: RuntimeCompatibility {
                    level: CompatibilityLevel::KernelNative,
                    reason: CompatibilityReason::BlockAll,
                },
                ..
            }
        ));
        assert!(matches!(engine.status_response(), Response::Status { .. }));
        Ok(())
    }

    #[test]
    fn status_v2_never_attests_a_test_backend() -> AnyResult<()> {
        let store = StoreProbe::new(State::new());
        let engine = Engine::load(
            Box::new(BackendProbe::default()),
            Box::new(store),
            EventBus::new(),
        )?;

        assert!(matches!(
            engine.status_v2_response(),
            Response::StatusV2 {
                backend: FirewallBackendKind::Unknown,
                runtime_compatibility: RuntimeCompatibility {
                    level: CompatibilityLevel::Unknown,
                    reason: CompatibilityReason::Unknown,
                },
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn status_v2_distinguishes_emergency_quarantine_from_operator_block_all() -> AnyResult<()> {
        let backend = BackendProbe {
            kind: FirewallBackendKind::Nftables,
            ..BackendProbe::default()
        };
        let store = StoreProbe::new(State::new());
        let mut engine = Engine::load(Box::new(backend), Box::new(store), EventBus::new())?;
        engine.poisoned = true;

        assert!(matches!(
            engine.status_v2_response(),
            Response::StatusV2 {
                mode: Mode::BlockAll,
                runtime_compatibility: RuntimeCompatibility {
                    level: CompatibilityLevel::KernelNative,
                    reason: CompatibilityReason::EmergencyBlockAll,
                },
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn status_reports_a_typed_nfqueue_counter_snapshot() -> AnyResult<()> {
        let store = StoreProbe::new(State::new());
        let engine = Engine::load(
            Box::new(BackendProbe::default()),
            Box::new(store),
            EventBus::new(),
        )?;
        let counters = engine.nfqueue_counters();
        counters.record_queue_overflow();
        counters.record_attribution_timeout();
        counters.record_terminal_queue_error();
        counters.record_denied();

        assert!(matches!(
            engine.status_response(),
            Response::Status {
                nfqueue: NfqueueCounters {
                    queue_overflow: 1,
                    attribution_timeout: 1,
                    terminal_queue_error: 1,
                    denied: 1,
                },
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn nfqueue_counters_saturate_instead_of_wrapping() {
        let counters = NfqueueRuntimeCounters::default();
        counters.queue_overflow.set_for_test(u64::MAX);
        counters.attribution_timeout.set_for_test(u64::MAX);
        counters.terminal_queue_error.set_for_test(u64::MAX);
        counters.denied.set_for_test(u64::MAX);

        counters.record_queue_overflow();
        counters.record_attribution_timeout();
        counters.record_terminal_queue_error();
        counters.record_denied();

        assert_eq!(
            counters.snapshot(),
            NfqueueCounters {
                queue_overflow: u64::MAX,
                attribution_timeout: u64::MAX,
                terminal_queue_error: u64::MAX,
                denied: u64::MAX,
            }
        );
    }

    #[test]
    fn packet_decision_retains_only_network_accept_fallbacks_without_application_rules()
    -> AnyResult<()> {
        let mut state = State::new();
        state.create_rule(manual_rule("kernel-only")?)?;
        state.set_mode(Mode::Enforcing)?;
        let (mut engine, _backend, _store, _events) = engine_with_state(state)?;

        let snapshot = engine
            .application_decision_snapshot()
            .map_err(|error| anyhow!(error.message))?;
        let same_policy = engine
            .application_decision_snapshot()
            .map_err(|error| anyhow!(error.message))?;
        assert!(Arc::ptr_eq(&snapshot, &same_policy));
        assert_eq!(snapshot.mode, Mode::Enforcing);
        assert_eq!(snapshot.rules.len(), 1);
        assert!(snapshot.rules[0].spec.application.is_none());
        assert_eq!(snapshot.rules[0].spec.action, RuleAction::Accept);
        assert_eq!(
            engine
                .application_decision_identity()
                .map_err(|error| anyhow!(error.message))?,
            (snapshot.mode, snapshot.flow_generation)
        );

        let previous_revision = engine.revision();
        engine
            .handle_control(ControlRequest::SetMode {
                expected_revision: previous_revision,
                mode: Mode::Learning,
            })
            .map_err(|error| anyhow!(error.message))?;
        let learning_policy = engine
            .application_decision_snapshot()
            .map_err(|error| anyhow!(error.message))?;
        assert!(!Arc::ptr_eq(&snapshot, &learning_policy));
        assert_eq!(learning_policy.mode, Mode::Learning);
        assert!(learning_policy.rules.is_empty());
        Ok(())
    }

    #[test]
    fn quota_skips_are_visible_and_do_not_block_privileged_enforcing() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let (mut engine, _, store, _) =
            engine_with_state_and_limits(state, LearningLimits::new(2, 1)?)?;
        let generation = engine.state.flow_generation();
        let first = learned_application_endpoint(10, 1_000, 1)?;
        let second = learned_application_endpoint(11, 1_000, 1)?;
        assert_eq!(
            engine
                .harvest_application_learning(generation, vec![first.clone(), second.clone()])
                .map_err(|error| anyhow!(error.message))?,
            2,
        );
        let status = engine.learning_status();
        assert_eq!(status.per_uid_limit, 2);
        assert_eq!(status.per_application_limit, 1);
        assert_eq!(status.automatic_rules, 2); // learned endpoint and disabled template
        assert_eq!(status.saturated_uids, 0);
        assert_eq!(status.saturated_applications, 1);
        assert_eq!(status.quota_skipped_observations, 1);
        // Duplicate evidence is not a quota loss, and never enables a rule.
        assert_eq!(
            engine
                .harvest_application_learning(generation, vec![first])
                .map_err(|error| anyhow!(error.message))?,
            0,
        );
        assert_eq!(engine.learning_status().quota_skipped_observations, 1);
        assert_eq!(
            application_learning_admission(&engine, generation, &second)?,
            LearningQueueAdmission::Saturated
        );
        assert_eq!(engine.learning_status().quota_skipped_observations, 2);
        assert!(
            matches!(engine.status_v3_response(), Response::StatusV3 { learning, .. }
            if learning.quota_skipped_observations == 2)
        );
        engine
            .handle_control(ControlRequest::SetMode {
                expected_revision: engine.state.revision(),
                mode: Mode::Enforcing,
            })
            .map_err(|error| anyhow!(error.message))?;
        assert_eq!(engine.state.mode(), Mode::Enforcing);
        assert_eq!(engine.learning_status().quota_skipped_observations, 2);
        assert_eq!(engine.learning_status().per_application_limit, 1);
        assert_eq!(
            store.persisted_state()?.map(|state| state.mode()),
            Some(Mode::Enforcing)
        );
        assert_eq!(
            engine
                .state
                .rules()
                .filter(|rule| rule.spec.origin == RuleOrigin::Learned)
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn enforcement_strategy_is_persisted_and_rotates_packet_epoch() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let (mut engine, _, store, _) = engine_with_state(state)?;
        let before = engine
            .application_decision_snapshot()
            .map_err(|error| anyhow!(error.message))?;
        engine
            .handle_control(ControlRequest::SetEnforcement {
                expected_revision: engine.revision(),
                strategy: EnforcementStrategy::Fast,
            })
            .map_err(|error| anyhow!(error.message))?;
        let fast = engine
            .application_decision_snapshot()
            .map_err(|error| anyhow!(error.message))?;
        assert_eq!(fast.mode, Mode::Enforcing);
        assert_eq!(fast.enforcement_strategy(), EnforcementStrategy::Fast);
        assert_ne!(fast.flow_generation, before.flow_generation);
        assert!(matches!(
            engine.status_v4_response(),
            Response::StatusV4 {
                mode: Mode::Enforcing,
                enforcement_strategy: EnforcementStrategy::Fast,
                ..
            }
        ));
        assert!(matches!(
            engine.status_response(),
            Response::Status {
                mode: Mode::Enforcing,
                ..
            }
        ));
        assert_eq!(
            store
                .persisted_state()?
                .map(|state| state.enforcement_strategy()),
            Some(EnforcementStrategy::Fast)
        );
        engine
            .handle_control(ControlRequest::SetEnforcement {
                expected_revision: engine.revision(),
                strategy: EnforcementStrategy::Strict,
            })
            .map_err(|error| anyhow!(error.message))?;
        let strict = engine
            .application_decision_snapshot()
            .map_err(|error| anyhow!(error.message))?;
        assert_eq!(strict.enforcement_strategy(), EnforcementStrategy::Strict);
        assert_ne!(strict.flow_generation, fast.flow_generation);
        // An in-flight decision from Fast carries the old epoch and cannot be
        // accepted by the existing final-verdict generation check.
        assert_ne!(
            engine
                .application_decision_identity()
                .map_err(|error| anyhow!(error.message))?
                .1,
            fast.flow_generation
        );
        Ok(())
    }

    #[test]
    fn fast_strategy_does_not_change_learning_attribution_or_survive_legacy_enforce()
    -> AnyResult<()> {
        let mut state = State::new();
        state.enforce(EnforcementStrategy::Fast)?;
        state.set_mode(Mode::Learning)?;
        let (mut engine, _, _, _) = engine_with_state(state)?;
        assert_eq!(
            engine.state.enforcement_strategy(),
            EnforcementStrategy::Fast
        );
        assert_eq!(
            engine
                .application_decision_snapshot()
                .map_err(|error| anyhow!(error.message))?
                .enforcement_strategy(),
            EnforcementStrategy::Strict
        );
        engine
            .handle_control(ControlRequest::SetMode {
                expected_revision: engine.revision(),
                mode: Mode::Enforcing,
            })
            .map_err(|error| anyhow!(error.message))?;
        assert_eq!(
            engine.state.enforcement_strategy(),
            EnforcementStrategy::Strict
        );
        Ok(())
    }

    #[test]
    fn failed_fast_strategy_change_preserves_strict_state_and_stale_cas_is_rejected()
    -> AnyResult<()> {
        let (mut engine, backend, store, events) = engine_with_probes()?;
        let before = engine.state.clone();
        let subscription = events
            .subscribe()
            .map_err(|_| anyhow!("subscribe failed"))?;
        let request = ControlRequest::SetEnforcement {
            expected_revision: engine.revision(),
            strategy: EnforcementStrategy::Fast,
        };
        backend.fail_next.store(true, Ordering::SeqCst);
        assert!(engine.handle_control(request).is_err());
        assert_eq!(engine.state, before);
        assert_eq!(
            store
                .persisted_state()?
                .map(|state| state.enforcement_strategy()),
            Some(EnforcementStrategy::Strict)
        );
        assert!(matches!(
            subscription.recv_timeout(Duration::from_millis(10)),
            Err(RecvTimeoutError::Timeout)
        ));
        let stale = engine.handle_control(ControlRequest::SetEnforcement {
            expected_revision: engine.revision() + 1,
            strategy: EnforcementStrategy::Fast,
        });
        assert!(matches!(
            stale,
            Err(ProtocolError {
                code: ErrorCode::Conflict,
                ..
            })
        ));
        assert_eq!(engine.state, before);
        Ok(())
    }

    #[test]
    fn pending_learning_reservation_uses_custom_limits() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let (mut engine, _, _, _) =
            engine_with_state_and_limits(state, LearningLimits::new(2, 1)?)?;
        let generation = engine.state.flow_generation();
        let first = learned_application_endpoint(10, 1_000, 1)?;
        let second = learned_application_endpoint(11, 1_000, 1)?;
        let transaction = engine
            .prepare_application_learning(generation, vec![first])
            .map_err(|error| anyhow!(error.message))?
            .ok_or_else(|| anyhow!("expected a persistence transaction"))?;
        assert_eq!(
            application_learning_admission(&engine, generation, &second)?,
            LearningQueueAdmission::Saturated
        );
        assert_eq!(engine.learning_status().quota_skipped_observations, 1);
        let persisted = transaction.persist();
        assert_eq!(
            engine
                .finalize_application_learning(persisted)
                .map_err(|error| anyhow!(error.message))?,
            2
        );
        assert_eq!(engine.learning_status().saturated_applications, 1);
        Ok(())
    }

    #[test]
    fn learning_admission_cache_skips_known_and_saturated_observations() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let endpoints = (0..256)
            .map(|offset| learned_application_endpoint(offset, 1_000, 1))
            .collect::<AnyResult<Vec<_>>>()?;
        let known = endpoints[0].clone();
        assert_eq!(
            state
                .learn_new_application_endpoints(endpoints, MAX_RULES)?
                .len(),
            257
        );
        let saturated = learned_application_endpoint(300, 1_000, 1)?;
        let candidate = learned_application_endpoint(301, 1_001, 2)?;
        let (mut engine, _backend, _store, _events) =
            engine_with_state_and_limits(state, LearningLimits::new(512, 256)?)?;
        let generation = engine.state.flow_generation();

        assert_eq!(
            engine
                .application_learning_queue_admission(Mode::Learning, generation, &known)
                .map_err(|error| anyhow!(error.message))?,
            LearningQueueAdmission::AlreadyKnown
        );
        assert_eq!(
            engine
                .application_learning_queue_admission(Mode::Learning, generation, &saturated)
                .map_err(|error| anyhow!(error.message))?,
            LearningQueueAdmission::Saturated
        );
        assert_eq!(
            engine
                .application_learning_queue_admission(Mode::Learning, generation, &candidate)
                .map_err(|error| anyhow!(error.message))?,
            LearningQueueAdmission::Enqueue
        );
        assert!(
            engine
                .application_learning_queue_admission(
                    Mode::Learning,
                    generation.saturating_add(1),
                    &candidate,
                )
                .is_err()
        );

        assert_eq!(
            engine
                .harvest_application_learning(generation, vec![candidate.clone()])
                .map_err(|error| anyhow!(error.message))?,
            2
        );
        assert_eq!(
            engine
                .application_learning_queue_admission(Mode::Learning, generation, &candidate)
                .map_err(|error| anyhow!(error.message))?,
            LearningQueueAdmission::AlreadyKnown
        );

        let later = learned_application_endpoint(302, 1_002, 3)?;
        engine.learning_persistence = LearningPersistence::Paused;
        assert_eq!(
            engine
                .application_learning_queue_admission(Mode::Learning, generation, &later)
                .map_err(|error| anyhow!(error.message))?,
            LearningQueueAdmission::PersistencePaused
        );
        engine.poisoned = true;
        assert!(
            engine
                .application_learning_queue_admission(Mode::Learning, generation, &later)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn slow_learning_save_does_not_block_packet_decisions_or_duplicate_rules() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let backend = BackendProbe::default();
        let store = BlockingStore::new(state);
        let events = EventBus::new();
        let subscription = events
            .subscribe()
            .map_err(|_| anyhow!("subscribe failed"))?;
        let mut engine = Engine::load(Box::new(backend.clone()), Box::new(store.clone()), events)?;
        engine.activate_startup_policy()?;
        backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?
            .clear();

        let generation = engine.state.flow_generation();
        let endpoint = learned_application_endpoint(700, 2_000, 70)?;
        let second_endpoint = learned_application_endpoint(701, 2_001, 71)?;
        let later = learned_application_endpoint(702, 2_002, 72)?;
        let release = store.arm_next_save()?;
        let shared = Arc::new(Mutex::new(engine));
        let worker = spawn_application_learning(
            &shared,
            generation,
            vec![endpoint.clone(), second_endpoint.clone()],
        );

        store.wait_until_save_is_blocked()?;
        let mut packet_guard = shared
            .try_lock()
            .map_err(|error| anyhow!("packet path blocked by state save: {error}"))?;
        let snapshot = packet_guard
            .application_decision_snapshot()
            .map_err(|error| anyhow!(error.message))?;
        assert_eq!(snapshot.mode, Mode::Learning);
        assert_eq!(
            packet_guard
                .application_decision_identity()
                .map_err(|error| anyhow!(error.message))?,
            (Mode::Learning, generation)
        );
        assert_eq!(
            application_learning_admission(&packet_guard, generation, &endpoint)?,
            LearningQueueAdmission::AlreadyKnown,
            "the in-flight endpoint must not refill the bounded learning queue"
        );
        assert_eq!(
            application_learning_admission(&packet_guard, generation, &second_endpoint)?,
            LearningQueueAdmission::AlreadyKnown,
            "every endpoint in a multi-rule candidate must use the pending admission index"
        );
        assert_eq!(
            application_learning_admission(&packet_guard, generation, &later)?,
            LearningQueueAdmission::Enqueue
        );
        let expected_revision = packet_guard.revision();
        assert!(matches!(
            packet_guard.handle_control(ControlRequest::SetMode {
                expected_revision,
                mode: Mode::Enforcing,
            }),
            Err(ProtocolError {
                code: ErrorCode::Conflict,
                ..
            })
        ));
        assert!(
            backend_was_not_rebuilt(&backend)?,
            "a conflicting control transaction must not reach the kernel backend"
        );
        assert!(matches!(
            subscription.recv_timeout(Duration::from_millis(1)),
            Err(RecvTimeoutError::Timeout)
        ));
        drop(packet_guard);

        drop(release);
        let learned = worker
            .join()
            .map_err(|_| anyhow!("learning worker panicked"))?
            .map_err(|error| anyhow!(error.message))?;
        assert_eq!(learned, 4);
        for _ in 0..4 {
            let event = subscription.recv_timeout(Duration::from_millis(50))?;
            assert!(matches!(event.kind, EventKind::RuleCreated { .. }));
        }

        let mut engine = shared
            .lock()
            .map_err(|_| anyhow!("policy engine mutex poisoned"))?;
        let persisted = store
            .persisted_state()?
            .ok_or_else(|| anyhow!("learning candidate was not persisted"))?;
        assert_eq!(persisted, engine.state);
        assert_eq!(persisted.rules().len(), 4);
        assert_eq!(
            engine
                .harvest_application_learning(generation, vec![endpoint, second_endpoint])
                .map_err(|error| anyhow!(error.message))?,
            0
        );
        assert_eq!(engine.state.rules().len(), 4);
        Ok(())
    }

    #[test]
    fn operator_block_all_preempts_slow_learning_and_is_persisted_last() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let backend = BackendProbe::default();
        let store = BlockingStore::new(state);
        let events = EventBus::new();
        let subscription = events
            .subscribe()
            .map_err(|_| anyhow!("subscribe failed"))?;
        let mut engine = Engine::load(Box::new(backend.clone()), Box::new(store.clone()), events)?;
        engine.activate_startup_policy()?;
        backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?
            .clear();
        let generation = engine.state.flow_generation();
        let base_revision = engine.revision();
        let endpoint = learned_application_endpoint(800, 3_000, 80)?;
        let release = store.arm_next_save()?;
        let shared = Arc::new(Mutex::new(engine));
        let learning = spawn_application_learning(&shared, generation, vec![endpoint]);
        store.wait_until_save_is_blocked()?;

        let control_engine = Arc::clone(&shared);
        let control = thread::spawn(move || {
            control_engine
                .lock()
                .map_err(|_| {
                    ProtocolError::new(ErrorCode::Internal, "policy engine mutex poisoned")
                })?
                .handle_control(ControlRequest::SetMode {
                    expected_revision: base_revision,
                    mode: Mode::BlockAll,
                })
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let applied = backend
                .applied
                .lock()
                .map_err(|_| anyhow!("backend probe poisoned"))?;
            if let Some(snapshot) = applied.last() {
                assert_eq!(snapshot.mode, Mode::BlockAll);
                break;
            }
            drop(applied);
            if Instant::now() >= deadline {
                bail!("operator BlockAll did not reach the kernel before storage was released");
            }
            thread::yield_now();
        }

        drop(release);
        let ack = control
            .join()
            .map_err(|_| anyhow!("control worker panicked"))?
            .map_err(|error| anyhow!(error.message))?;
        assert_eq!(
            learning
                .join()
                .map_err(|_| anyhow!("learning worker panicked"))?
                .map_err(|error| anyhow!(error.message))?,
            0,
            "the superseded learning finalize must not restore Learning mode"
        );

        let engine = shared
            .lock()
            .map_err(|_| anyhow!("policy engine mutex poisoned"))?;
        let persisted = store
            .persisted_state()?
            .ok_or_else(|| anyhow!("BlockAll state was not persisted"))?;
        assert_eq!(engine.mode(), Mode::BlockAll);
        assert_eq!(persisted, engine.state);
        assert_eq!(persisted.revision(), ack.revision);
        assert_eq!(persisted.rules().len(), 2);
        let template_event = subscription.recv_timeout(Duration::from_millis(50))?;
        let learned_event = subscription.recv_timeout(Duration::from_millis(50))?;
        let mode_event = subscription.recv_timeout(Duration::from_millis(50))?;
        assert!(matches!(template_event.kind, EventKind::RuleCreated { .. }));
        assert!(matches!(learned_event.kind, EventKind::RuleCreated { .. }));
        assert!(template_event.revision < learned_event.revision);
        assert!(matches!(mode_event.kind, EventKind::ModeChanged { .. }));
        assert!(learned_event.revision < mode_event.revision);
        Ok(())
    }

    #[test]
    fn recoverable_application_learning_failure_clears_pending_state_and_pauses() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let (mut engine, backend, store, _events) = engine_with_state(state)?;
        let generation = engine.state.flow_generation();
        let endpoint = learned_application_endpoint(900, 4_000, 90)?;
        store.fail_next.store(true, Ordering::SeqCst);

        assert_eq!(
            engine
                .harvest_application_learning(generation, vec![endpoint.clone()])
                .map_err(|error| anyhow!(error.message))?,
            0
        );
        assert_eq!(engine.learning_persistence, LearningPersistence::Paused);
        assert!(engine.pending_application_learning_admission.is_none());
        assert!(engine.pending_application_learning_candidate.is_none());
        assert!(engine.pending_application_learning_events.is_empty());
        assert_eq!(
            engine
                .application_learning_queue_admission(Mode::Learning, generation, &endpoint)
                .map_err(|error| anyhow!(error.message))?,
            LearningQueueAdmission::PersistencePaused
        );
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref(),
            Some(&engine.state)
        );
        assert!(backend_was_not_rebuilt(&backend)?);
        Ok(())
    }

    #[test]
    fn dropped_learning_transaction_releases_persistence_for_emergency_block_all() -> AnyResult<()>
    {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let (mut engine, _backend, store, _events) = engine_with_state(state)?;
        let generation = engine.state.flow_generation();
        let endpoint = learned_application_endpoint(950, 4_500, 95)?;
        let transaction = engine
            .prepare_application_learning(generation, vec![endpoint])
            .map_err(|error| anyhow!(error.message))?
            .ok_or_else(|| anyhow!("learning transaction was not prepared"))?;

        assert!(
            engine
                .persistence
                .state
                .lock()
                .map_err(|_| anyhow!("persistence coordinator poisoned"))?
                .learning_reservation
                .is_some()
        );
        drop(transaction);
        assert!(
            engine
                .persistence
                .state
                .lock()
                .map_err(|_| anyhow!("persistence coordinator poisoned"))?
                .learning_reservation
                .is_none()
        );

        engine.quarantine_after_runtime_failure();
        assert_eq!(engine.mode(), Mode::BlockAll);
        assert!(engine.restart_required());
        let persisted = store
            .state
            .lock()
            .map_err(|_| anyhow!("store probe poisoned"))?
            .clone()
            .ok_or_else(|| anyhow!("emergency state was not persisted"))?;
        assert_eq!(persisted, engine.state);
        assert_eq!(persisted.rules().len(), 2);
        Ok(())
    }

    #[test]
    fn panicking_learning_store_does_not_poison_or_block_emergency_persistence() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let backend = BackendProbe::default();
        let store = PanickingStore::new(state);
        let persisted = store.inner.clone();
        let events = EventBus::new();
        let mut engine = Engine::load(Box::new(backend), Box::new(store.clone()), events)?;
        engine.activate_startup_policy()?;
        let generation = engine.state.flow_generation();
        let endpoint = learned_application_endpoint(951, 4_501, 96)?;
        let transaction = engine
            .prepare_application_learning(generation, vec![endpoint])
            .map_err(|error| anyhow!(error.message))?
            .ok_or_else(|| anyhow!("learning transaction was not prepared"))?;
        store.panic_next_save.store(true, Ordering::SeqCst);

        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _persisted = transaction.persist();
        }));
        assert!(panic.is_err());
        assert!(
            engine
                .persistence
                .state
                .lock()
                .map_err(|_| anyhow!("persistence coordinator poisoned"))?
                .learning_reservation
                .is_none(),
            "transaction unwind must release its persistence reservation"
        );

        engine.quarantine_after_runtime_failure();
        assert_eq!(engine.mode(), Mode::BlockAll);
        assert!(engine.restart_required());
        let persisted = persisted
            .state
            .lock()
            .map_err(|_| anyhow!("store probe poisoned"))?
            .clone()
            .ok_or_else(|| anyhow!("emergency state was not persisted"))?;
        assert_eq!(persisted, engine.state);
        assert_eq!(persisted.rules().len(), 2);
        Ok(())
    }

    #[test]
    fn first_start_stays_blocked_until_learning_policy_is_explicitly_activated() -> AnyResult<()> {
        let previous_generation = State::new().flow_generation();
        let backend = BackendProbe::default();
        let store = StoreProbe::empty();
        let mut engine = Engine::load(
            Box::new(backend.clone()),
            Box::new(store.clone()),
            EventBus::new(),
        )?;
        let generation = engine.state.flow_generation();
        assert_ne!(generation, previous_generation);
        assert_eq!(engine.mode(), Mode::Learning);
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(|state| (state.mode(), state.flow_generation())),
            Some((Mode::Learning, generation))
        );
        {
            let applied = backend
                .applied
                .lock()
                .map_err(|_| anyhow!("backend probe poisoned"))?;
            assert_eq!(applied.len(), 1);
            assert_eq!(applied[0].mode, Mode::BlockAll);
        }

        engine.activate_startup_policy()?;
        let applied = backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?;
        assert_eq!(applied.len(), 2);
        assert_eq!(applied[0].mode, Mode::BlockAll);
        assert_eq!(applied[1].mode, Mode::Learning);
        assert_eq!(applied[1].flow_generation, generation);
        Ok(())
    }

    #[test]
    fn existing_saved_mode_is_preserved_across_startup() -> AnyResult<()> {
        for expected_mode in [Mode::BlockAll, Mode::Learning, Mode::Enforcing] {
            let mut state = State::new();
            if expected_mode != Mode::BlockAll {
                state.set_mode(expected_mode)?;
            }
            let backend = BackendProbe::default();
            let store = StoreProbe::new(state);
            let mut engine =
                Engine::load(Box::new(backend.clone()), Box::new(store), EventBus::new())?;

            assert_eq!(engine.mode(), expected_mode);
            engine.activate_startup_policy()?;
            let applied = backend
                .applied
                .lock()
                .map_err(|_| anyhow!("backend probe poisoned"))?;
            assert_eq!(applied.len(), 2);
            assert_eq!(applied[0].mode, Mode::BlockAll);
            assert_eq!(applied[1].mode, expected_mode);
        }
        Ok(())
    }

    #[test]
    fn exhausted_startup_epoch_stays_fail_closed_instead_of_reusing_a_mark() -> AnyResult<()> {
        let mut state = State::new();
        state.rotate_flow_generation(MAX_FLOW_GENERATION)?;
        let backend = BackendProbe::default();
        let store = StoreProbe::new(state);

        assert!(
            Engine::load(Box::new(backend.clone()), Box::new(store), EventBus::new(),).is_err()
        );
        let applied = backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?;
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].mode, Mode::BlockAll);
        Ok(())
    }

    #[test]
    fn failed_first_learning_activation_retains_block_all_and_learning_intent() -> AnyResult<()> {
        let backend = BackendProbe::default();
        let store = StoreProbe::empty();
        let mut engine = Engine::load(
            Box::new(backend.clone()),
            Box::new(store.clone()),
            EventBus::new(),
        )?;
        backend
            .failure_script
            .lock()
            .map_err(|_| anyhow!("backend failure script poisoned"))?
            .extend([true, false]);

        assert!(engine.activate_startup_policy().is_err());
        assert_eq!(engine.mode(), Mode::Learning);
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(State::mode),
            Some(Mode::Learning)
        );
        let applied = backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?;
        assert_eq!(
            applied.last().map(|snapshot| snapshot.mode),
            Some(Mode::BlockAll)
        );
        Ok(())
    }

    #[test]
    fn shutdown_quarantine_does_not_overwrite_the_saved_mode() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        let (mut engine, backend, store, _events) = engine_with_state(state)?;
        let saved_revision = engine.revision();

        engine.install_shutdown_quarantine()?;

        assert_eq!(engine.mode(), Mode::Enforcing);
        assert_eq!(engine.revision(), saved_revision);
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(|state| (state.mode(), state.revision())),
            Some((Mode::Enforcing, saved_revision))
        );
        let applied = backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?;
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].mode, Mode::BlockAll);
        Ok(())
    }

    #[test]
    fn backend_failure_keeps_state_and_emits_no_event() -> AnyResult<()> {
        let (mut engine, backend, store, events) = engine_with_probes()?;
        let subscription = events
            .subscribe()
            .map_err(|_| anyhow!("subscribe failed"))?;
        backend.fail_next.store(true, Ordering::SeqCst);

        let result = engine.handle_control(ControlRequest::SetMode {
            expected_revision: 0,
            mode: Mode::Enforcing,
        });
        assert!(matches!(
            result,
            Err(ProtocolError {
                code: ErrorCode::BackendUnavailable,
                ..
            })
        ));
        assert_eq!(engine.mode(), Mode::BlockAll);
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(State::mode),
            Some(Mode::BlockAll)
        );
        assert!(matches!(
            subscription.recv_timeout(Duration::from_millis(10)),
            Err(RecvTimeoutError::Timeout)
        ));
        Ok(())
    }

    #[test]
    fn ambiguous_apply_is_rolled_back_even_if_candidate_reached_kernel() -> AnyResult<()> {
        let (mut engine, backend, store, _events) = engine_with_probes()?;
        backend.error_after_apply.store(true, Ordering::SeqCst);

        assert!(
            engine
                .handle_control(ControlRequest::SetMode {
                    expected_revision: 0,
                    mode: Mode::Enforcing,
                })
                .is_err()
        );
        assert_eq!(engine.mode(), Mode::BlockAll);
        assert!(!engine.restart_required());
        let applied = backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?;
        assert_eq!(applied.len(), 2);
        assert_eq!(applied[0].mode, Mode::Enforcing);
        assert_eq!(applied[1].mode, Mode::BlockAll);
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(State::mode),
            Some(Mode::BlockAll)
        );
        Ok(())
    }

    #[test]
    fn ambiguous_apply_and_failed_rollback_enter_persisted_emergency() -> AnyResult<()> {
        let (mut engine, backend, store, _events) = engine_with_probes()?;
        backend.error_after_apply.store(true, Ordering::SeqCst);
        backend
            .failure_script
            .lock()
            .map_err(|_| anyhow!("backend failure script poisoned"))?
            .extend([false, true, false]);

        assert!(
            engine
                .handle_control(ControlRequest::SetMode {
                    expected_revision: 0,
                    mode: Mode::Enforcing,
                })
                .is_err()
        );
        assert_eq!(engine.mode(), Mode::BlockAll);
        assert!(engine.restart_required());
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(State::mode),
            Some(Mode::BlockAll)
        );
        Ok(())
    }

    #[test]
    fn persistence_failure_rolls_firewall_back() -> AnyResult<()> {
        let (mut engine, backend, store, _events) = engine_with_probes()?;
        store.fail_next.store(true, Ordering::SeqCst);
        let result = engine.handle_control(ControlRequest::SetMode {
            expected_revision: 0,
            mode: Mode::Enforcing,
        });
        assert!(matches!(
            result,
            Err(ProtocolError {
                code: ErrorCode::Internal,
                ..
            })
        ));
        assert_eq!(engine.mode(), Mode::BlockAll);
        let applied = backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?;
        assert_eq!(applied.len(), 2);
        assert_eq!(applied[0].mode, Mode::Enforcing);
        assert_eq!(applied[1].mode, Mode::BlockAll);
        Ok(())
    }

    #[test]
    fn successful_rule_change_is_persisted_before_event() -> AnyResult<()> {
        let (mut engine, _backend, store, events) = engine_with_probes()?;
        let subscription = events
            .subscribe()
            .map_err(|_| anyhow!("subscribe failed"))?;
        let ack = engine
            .handle_control(ControlRequest::CreateRule {
                expected_revision: 0,
                rule: manual_rule("https")?,
            })
            .map_err(|error| anyhow!("control failed: {}", error.message))?;
        assert_eq!(ack.revision, 1);
        assert!(ack.affected_rule.is_some());
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(State::revision),
            Some(1)
        );
        assert_eq!(
            subscription
                .recv_timeout(Duration::from_millis(50))?
                .revision,
            1
        );
        Ok(())
    }

    #[test]
    fn two_mutations_from_one_revision_apply_exactly_once() -> AnyResult<()> {
        let (mut engine, backend, store, events) = engine_with_probes()?;
        let subscription = events
            .subscribe()
            .map_err(|_| anyhow!("subscribe failed"))?;

        let first = engine
            .handle_control(ControlRequest::SetMode {
                expected_revision: 0,
                mode: Mode::Learning,
            })
            .map_err(|error| anyhow!(error.message))?;
        assert_eq!(first.revision, 1);
        assert_eq!(
            subscription
                .recv_timeout(Duration::from_millis(50))?
                .revision,
            1
        );

        let second = engine.handle_control(ControlRequest::SetMode {
            expected_revision: 0,
            mode: Mode::Enforcing,
        });
        assert!(matches!(
            second,
            Err(ProtocolError {
                code: ErrorCode::Conflict,
                ..
            })
        ));
        assert_eq!(engine.revision(), 1);
        assert_eq!(engine.mode(), Mode::Learning);
        assert_eq!(
            backend
                .applied
                .lock()
                .map_err(|_| anyhow!("backend probe poisoned"))?
                .len(),
            1
        );
        let persisted = store
            .state
            .lock()
            .map_err(|_| anyhow!("store probe poisoned"))?;
        assert_eq!(persisted.as_ref().map(State::revision), Some(1));
        assert_eq!(persisted.as_ref().map(State::mode), Some(Mode::Learning));
        assert!(matches!(
            subscription.recv_timeout(Duration::from_millis(10)),
            Err(RecvTimeoutError::Timeout)
        ));
        Ok(())
    }

    #[test]
    fn pagination_is_sorted_and_has_stable_cursor() -> AnyResult<()> {
        let (mut engine, _backend, _store, _events) = engine_with_probes()?;
        for name in ["one", "two", "three"] {
            let expected_revision = engine.revision();
            engine
                .handle_control(ControlRequest::CreateRule {
                    expected_revision,
                    rule: manual_rule(name)?,
                })
                .map_err(|error| anyhow!("control failed: {}", error.message))?;
        }
        let Response::RulesPage {
            revision,
            rules,
            next_after,
        } = engine.rules_page_response(None, 2)
        else {
            bail!("unexpected response");
        };
        assert_eq!(revision, 3);
        assert_eq!(rules.len(), 2);
        let cursor = next_after.ok_or_else(|| anyhow!("missing page cursor"))?;
        assert_eq!(cursor, rules[1].id);
        let Response::RulesPage {
            rules: final_page,
            next_after: final_cursor,
            ..
        } = engine.rules_page_response(Some(cursor), 2)
        else {
            bail!("unexpected response");
        };
        assert_eq!(final_page.len(), 1);
        assert!(final_cursor.is_none());
        Ok(())
    }

    #[test]
    fn full_subscriber_queue_disconnects_slow_reader() -> AnyResult<()> {
        let bus = EventBus::with_limits(1, 1);
        let subscription = bus.subscribe().map_err(|_| anyhow!("subscribe failed"))?;
        let mut state = State::new();
        bus.publish(&state.set_mode(Mode::Learning)?);
        bus.publish(&state.set_mode(Mode::Enforcing)?);
        assert_eq!(
            subscription
                .recv_timeout(Duration::from_millis(50))?
                .revision,
            1
        );
        assert!(matches!(
            subscription.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Disconnected)
        ));
        Ok(())
    }

    #[test]
    fn new_subscriber_receives_latest_counter_snapshot() -> AnyResult<()> {
        let bus = EventBus::new();
        let state = State::new();
        let mut counters = FirewallCounters::default();
        counters.accepted_out.packets = 7;
        let event = state.counters_event(counters, Utc::now());
        bus.publish(&event);

        let subscription = bus.subscribe().map_err(|_| anyhow!("subscribe failed"))?;
        assert_eq!(subscription.recv_timeout(Duration::from_millis(50))?, event);
        Ok(())
    }

    #[test]
    fn unchanged_counters_are_republished_as_liveness_heartbeats() -> AnyResult<()> {
        let (mut engine, _backend, _store, events) = engine_with_probes()?;
        let subscription = events
            .subscribe()
            .map_err(|_| anyhow!("subscribe failed"))?;
        let revision = engine.revision();
        let counters = FirewallCounters::default();

        assert!(engine.publish_counters_if_current(revision, counters.clone()));
        assert!(engine.publish_counters_if_current(revision, counters));
        let first = subscription.recv_timeout(Duration::from_millis(50))?;
        let second = subscription.recv_timeout(Duration::from_millis(50))?;
        assert_eq!(first.revision, revision);
        assert_eq!(second.revision, revision);
        assert!(matches!(first.kind, EventKind::CountersUpdated { .. }));
        assert!(matches!(second.kind, EventKind::CountersUpdated { .. }));
        Ok(())
    }

    #[test]
    fn failed_emergency_policy_marks_engine_fatal_without_false_status() -> AnyResult<()> {
        let (mut engine, backend, store, _events) = engine_with_probes()?;
        store.fail_next.store(true, Ordering::SeqCst);
        backend
            .failure_script
            .lock()
            .map_err(|_| anyhow!("backend failure script poisoned"))?
            .extend([false, true, true]);

        let result = engine.handle_control(ControlRequest::SetMode {
            expected_revision: 0,
            mode: Mode::Enforcing,
        });
        assert!(matches!(
            result,
            Err(ProtocolError {
                code: ErrorCode::BackendUnavailable,
                ..
            })
        ));
        assert!(engine.is_fatal());
        assert!(matches!(
            engine.status_response(),
            Response::Error(ProtocolError {
                code: ErrorCode::BackendUnavailable,
                ..
            })
        ));
        assert!(engine.subscription_revision().is_err());
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(State::mode),
            Some(Mode::BlockAll)
        );
        Ok(())
    }

    #[test]
    fn emergency_fail_closed_state_keeps_revision_monotonic() -> AnyResult<()> {
        let mut prior = State::new();
        prior.set_mode(Mode::Learning)?;
        prior.create_rule(manual_rule("preserved through emergency")?)?;
        let prior_revision = prior.revision();
        let (mut engine, backend, store, _events) = engine_with_state(prior)?;
        store.fail_next.store(true, Ordering::SeqCst);
        backend
            .failure_script
            .lock()
            .map_err(|_| anyhow!("backend failure script poisoned"))?
            .extend([false, true, false]);

        let result = engine.handle_control(ControlRequest::SetMode {
            expected_revision: prior_revision,
            mode: Mode::Enforcing,
        });
        assert!(matches!(
            result,
            Err(ProtocolError {
                code: ErrorCode::BackendUnavailable,
                ..
            })
        ));
        assert!(!engine.is_fatal());
        assert!(engine.restart_required());
        assert_eq!(engine.mode(), Mode::BlockAll);
        assert!(engine.revision() > prior_revision);
        let persisted = store
            .state
            .lock()
            .map_err(|_| anyhow!("store probe poisoned"))?
            .clone()
            .ok_or_else(|| anyhow!("emergency state was not persisted"))?;
        assert_eq!(persisted.mode(), Mode::BlockAll);
        assert_eq!(persisted.revision(), engine.revision());
        assert_eq!(persisted.rules().len(), 1);
        assert!(matches!(
            engine.status_response(),
            Response::Status {
                revision,
                mode: Mode::BlockAll,
                rule_count: 1,
                backend: FirewallBackendKind::Unknown,
                nfqueue,
            } if revision == engine.revision() && nfqueue == NfqueueCounters::default()
        ));
        Ok(())
    }

    #[test]
    fn unpersisted_emergency_block_all_stays_quarantined_without_restart() -> AnyResult<()> {
        let mut prior = State::new();
        prior.set_mode(Mode::Learning)?;
        let prior_revision = prior.revision();
        let (mut engine, backend, store, _events) = engine_with_state(prior)?;
        store
            .failure_script
            .lock()
            .map_err(|_| anyhow!("store failure script poisoned"))?
            .extend([true, true, true]);
        backend
            .failure_script
            .lock()
            .map_err(|_| anyhow!("backend failure script poisoned"))?
            .extend([false, true, false]);

        assert!(
            engine
                .handle_control(ControlRequest::SetMode {
                    expected_revision: prior_revision,
                    mode: Mode::Enforcing,
                })
                .is_err()
        );
        assert!(!engine.is_fatal());
        assert!(!engine.restart_required());
        assert_eq!(engine.mode(), Mode::BlockAll);
        assert!(engine.revision() > prior_revision);
        assert!(matches!(
            engine.status_response(),
            Response::Status {
                mode: Mode::BlockAll,
                ..
            }
        ));
        let emergency_revision = engine.revision();
        assert!(
            engine
                .handle_control(ControlRequest::SetMode {
                    expected_revision: emergency_revision,
                    mode: Mode::Learning,
                })
                .is_err()
        );
        let persisted = store
            .state
            .lock()
            .map_err(|_| anyhow!("store probe poisoned"))?
            .clone()
            .ok_or_else(|| anyhow!("original persisted state disappeared"))?;
        assert_eq!(persisted.mode(), Mode::Learning);
        Ok(())
    }

    #[test]
    fn observation_repair_reapplies_current_policy_without_revision_change() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        let expected_revision = state.revision();
        let (mut engine, backend, _store, _events) = engine_with_state(state)?;

        assert!(
            engine
                .repair_policy(expected_revision)
                .map_err(|error| anyhow!(error.message))?
        );
        assert_eq!(engine.revision(), expected_revision);
        assert!(!engine.restart_required());
        let applied = backend
            .applied
            .lock()
            .map_err(|_| anyhow!("backend probe poisoned"))?;
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].revision, expected_revision);
        assert_eq!(applied[0].mode, Mode::Enforcing);
        Ok(())
    }

    #[test]
    fn failed_observation_repair_installs_persisted_block_all_and_requests_restart() -> AnyResult<()>
    {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        let expected_revision = state.revision();
        let (mut engine, backend, store, _events) = engine_with_state(state)?;
        backend
            .failure_script
            .lock()
            .map_err(|_| anyhow!("backend failure script poisoned"))?
            .extend([true, false]);

        let result = engine.repair_policy(expected_revision);
        assert!(matches!(
            result,
            Err(ProtocolError {
                code: ErrorCode::BackendUnavailable,
                ..
            })
        ));
        assert!(engine.restart_required());
        assert!(!engine.is_fatal());
        assert_eq!(engine.mode(), Mode::BlockAll);
        assert!(engine.revision() > expected_revision);
        let persisted = store
            .state
            .lock()
            .map_err(|_| anyhow!("store probe poisoned"))?
            .clone()
            .ok_or_else(|| anyhow!("emergency state was not persisted"))?;
        assert_eq!(persisted.mode(), Mode::BlockAll);
        assert_eq!(persisted.revision(), engine.revision());
        Ok(())
    }

    #[test]
    fn learning_persists_without_rebuilding_the_active_table() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let expected_revision = state.revision();
        let (mut engine, backend, store, events) = engine_with_state(state)?;
        let subscription = events
            .subscribe()
            .map_err(|_| anyhow!("subscribe failed"))?;
        let endpoint = LearnedEndpoint {
            address: "192.0.2.44".parse()?,
            protocol: TransportProtocol::Tcp,
            port: Some(PortRange::single(443)?),
            interface: Some(InterfaceName::new("eth0")?),
        };

        assert_eq!(
            engine
                .harvest_learning(expected_revision, vec![endpoint])
                .map_err(|error| anyhow!(error.message))?,
            1
        );
        assert!(
            backend
                .applied
                .lock()
                .map_err(|_| anyhow!("backend probe poisoned"))?
                .is_empty()
        );
        let persisted = store
            .state
            .lock()
            .map_err(|_| anyhow!("store probe poisoned"))?
            .clone()
            .ok_or_else(|| anyhow!("learned state was not persisted"))?;
        assert_eq!(persisted.rules().len(), 1);
        assert_eq!(persisted.revision(), engine.revision());
        assert_eq!(
            subscription
                .recv_timeout(Duration::from_millis(50))?
                .revision,
            engine.revision()
        );
        Ok(())
    }

    #[test]
    fn learning_poll_bounds_new_rules_and_progresses_past_duplicates() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let (mut engine, backend, store, events) = engine_with_state(state)?;
        let subscription = events
            .subscribe()
            .map_err(|_| anyhow!("subscribe failed"))?;
        let interface = InterfaceName::new("eth0")?;
        let port = PortRange::single(443)?;
        let endpoints: Vec<LearnedEndpoint> = (1_u32..=300)
            .map(|offset| LearnedEndpoint {
                address: std::net::Ipv4Addr::from(0xc633_6400_u32 + offset).into(),
                protocol: TransportProtocol::Tcp,
                port: Some(port),
                interface: Some(interface.clone()),
            })
            .collect();

        let first_revision = engine.revision();
        assert_eq!(
            engine
                .harvest_learning(first_revision, endpoints.clone())
                .map_err(|error| anyhow!(error.message))?,
            MAX_LEARNED_RULES_PER_POLL
        );
        assert_eq!(engine.revision(), first_revision + 256);
        for expected_revision in
            (first_revision + 1)..=(first_revision + MAX_LEARNED_RULES_PER_POLL as u64)
        {
            let event = subscription.recv_timeout(Duration::from_millis(50))?;
            assert_eq!(event.revision, expected_revision);
            assert!(matches!(event.kind, EventKind::RuleCreated { .. }));
        }
        assert_eq!(
            engine
                .harvest_learning(engine.revision(), endpoints)
                .map_err(|error| anyhow!(error.message))?,
            44
        );
        for expected_revision in (first_revision + 257)..=(first_revision + 300) {
            let event = subscription.recv_timeout(Duration::from_millis(50))?;
            assert_eq!(event.revision, expected_revision);
            assert!(matches!(event.kind, EventKind::RuleCreated { .. }));
        }
        assert!(matches!(
            subscription.recv_timeout(Duration::from_millis(1)),
            Err(RecvTimeoutError::Timeout)
        ));
        assert_eq!(
            store
                .state
                .lock()
                .map_err(|_| anyhow!("store probe poisoned"))?
                .as_ref()
                .map(|state| state.rules().len()),
            Some(300)
        );
        assert!(
            backend
                .applied
                .lock()
                .map_err(|_| anyhow!("backend probe poisoned"))?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn recoverable_learning_storage_failure_pauses_without_quarantine() -> AnyResult<()> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let expected_revision = state.revision();
        let (mut engine, backend, store, _events) = engine_with_state(state)?;
        store.fail_next.store(true, Ordering::SeqCst);
        let endpoint = LearnedEndpoint {
            address: "2001:db8::44".parse()?,
            protocol: TransportProtocol::Udp,
            port: Some(PortRange::single(53)?),
            interface: Some(InterfaceName::new("eth1")?),
        };

        assert_eq!(
            engine
                .harvest_learning(expected_revision, vec![endpoint.clone()])
                .map_err(|error| anyhow!(error.message))?,
            0
        );
        assert_eq!(
            engine
                .harvest_learning(expected_revision, vec![endpoint])
                .map_err(|error| anyhow!(error.message))?,
            0
        );
        assert_eq!(engine.revision(), expected_revision);
        assert!(
            backend
                .applied
                .lock()
                .map_err(|_| anyhow!("backend probe poisoned"))?
                .is_empty()
        );
        assert!(!engine.restart_required());
        Ok(())
    }

    #[test]
    fn persistent_learning_storage_pressure_keeps_previous_state_without_rewrite() -> AnyResult<()>
    {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let expected_revision = state.revision();
        let (mut engine, _backend, store, _events) = engine_with_state(state)?;
        store
            .failure_script
            .lock()
            .map_err(|_| anyhow!("store failure script poisoned"))?
            .extend([true, true]);
        let endpoint = LearnedEndpoint {
            address: "192.0.2.45".parse()?,
            protocol: TransportProtocol::Icmp,
            port: None,
            interface: Some(InterfaceName::new("tun0")?),
        };

        assert_eq!(
            engine
                .harvest_learning(expected_revision, vec![endpoint])
                .map_err(|error| anyhow!(error.message))?,
            0
        );
        assert!(!engine.restart_required());
        assert_eq!(engine.mode(), Mode::Learning);
        assert_eq!(engine.revision(), expected_revision);
        let persisted = store
            .state
            .lock()
            .map_err(|_| anyhow!("store probe poisoned"))?
            .clone()
            .ok_or_else(|| anyhow!("previous state disappeared"))?;
        assert_eq!(persisted.mode(), Mode::Learning);
        assert_eq!(persisted.revision(), expected_revision);
        assert_eq!(persisted.rules().len(), 0);
        assert_eq!(
            store
                .failure_script
                .lock()
                .map_err(|_| anyhow!("store failure script poisoned"))?
                .len(),
            1,
            "the known-good file must not be rewritten after a pre-commit failure"
        );
        Ok(())
    }
}
