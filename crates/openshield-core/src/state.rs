use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{self, Write};
use std::ops::Bound::{Excluded, Unbounded};

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    ApplicationPath, ApplicationSelector, CgroupPath, Direction, EnforcementStrategy,
    FirewallCounters, LearnedApplicationEndpoint, LearnedEndpoint, LearningLimits,
    LearningQuotaSummary, Rule, RuleAction, RuleName, RuleOrigin, RuleSpec, ValidationError,
    model::REDACTED_APPLICATION_RULE_NAME,
};

pub const MAX_RULES: usize = 10_000;
/// Maximum number of automatically learned rules retained in one policy.
///
/// The remaining 2,500 slots are reserved for privileged manual rules, so an
/// untrusted workload cannot consume the complete rule capacity during a
/// Learning window.
pub const MAX_AUTOMATIC_LEARNED_RULES: usize = 7_500;
/// Maximum exact JSON size of persisted policy state.
pub const MAX_STATE_BYTES: usize = 8 * 1024 * 1024;
const APPLICATION_GROUP_TEMPLATE_NAME: &str = "application-wide template";
/// Maximum policy generation representable inside the reserved nftables mark domains.
///
/// Application conntrack marks use two domain bits plus this 30-bit generation.
/// The separate packet-mark handshake reserves only its upper two bits and
/// preserves the remaining 30. Generation exhaustion is fail-closed.
pub const MAX_FLOW_GENERATION: u32 = 0x3fff_ffff;

/// Kernel/userspace path required by the active policy for outbound
/// application-aware decisions.
///
/// This classification is shared by the policy compilers and runtime status,
/// so an advertised compatibility level cannot drift from the installed
/// packet interception policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationInterception {
    /// No application attribution is required by the active policy.
    None,
    /// Only initial TCP packets require attribution; conntrack authorizes the
    /// established flow after the daemon's decision.
    TcpInitial,
    /// At least one eligible protocol requires per-packet attribution.
    PerPacket,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub revision: u64,
    #[serde(default = "initial_flow_generation")]
    pub flow_generation: u32,
    pub mode: crate::Mode,
    pub rules: Vec<Rule>,
}

impl Snapshot {
    /// Returns the application-attribution path required by this snapshot.
    #[must_use]
    pub fn application_interception(&self) -> ApplicationInterception {
        classify_application_interception(self.mode, &self.rules)
    }

    /// Checks rule bounds, identities, and all embedded rule invariants.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the snapshot is too large or malformed.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.rules.len() > MAX_RULES {
            return Err(CoreError::RulesLimitReached(MAX_RULES));
        }
        if !(1..=MAX_FLOW_GENERATION).contains(&self.flow_generation) {
            return Err(CoreError::InvalidFlowGeneration);
        }
        let mut ids = BTreeSet::new();
        for rule in &self.rules {
            rule.validate()?;
            reject_redacted_rule(rule)?;
            reject_unpinned_application_spec(&rule.spec)?;
            if !ids.insert(rule.id) {
                return Err(CoreError::DuplicateRuleId(rule.id));
            }
        }
        Ok(())
    }

    /// Validates a snapshot received through privileged or group-authorized
    /// observation IPC.
    ///
    /// Unlike [`Self::validate`], this accepts the one canonical application
    /// redaction emitted for non-root observers. Redacted metadata remains
    /// forbidden in [`State`] and can therefore never be persisted or
    /// enforced. A snapshot may not mix privileged and redacted application
    /// views.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when bounds, rule identities, application pins,
    /// or observer redaction invariants are violated.
    pub fn validate_for_observer(&self) -> Result<(), CoreError> {
        if self.rules.len() > MAX_RULES {
            return Err(CoreError::RulesLimitReached(MAX_RULES));
        }
        if !(1..=MAX_FLOW_GENERATION).contains(&self.flow_generation) {
            return Err(CoreError::InvalidFlowGeneration);
        }
        let mut ids = BTreeSet::new();
        let mut redaction_state = None;
        for rule in &self.rules {
            rule.validate()?;
            if let Some(selector) = &rule.spec.application {
                let redacted = selector.metadata_redacted;
                if redacted && rule.spec.name.as_str() != REDACTED_APPLICATION_RULE_NAME {
                    return Err(CoreError::InvalidObserverRedaction);
                }
                if !redacted {
                    reject_unpinned_application_spec(&rule.spec)?;
                }
                if redaction_state.is_some_and(|previous| previous != redacted) {
                    return Err(CoreError::InvalidObserverRedaction);
                }
                redaction_state = Some(redacted);
            }
            if !ids.insert(rule.id) {
                return Err(CoreError::DuplicateRuleId(rule.id));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn redacted_for_observer(&self) -> Self {
        Self {
            revision: self.revision,
            flow_generation: self.flow_generation,
            mode: self.mode,
            rules: self.rules.iter().map(Rule::redacted_for_observer).collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub revision: u64,
    pub occurred_at: DateTime<Utc>,
    pub kind: EventKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "snake_case",
    tag = "type",
    content = "data"
)]
pub enum EventKind {
    ModeChanged {
        previous: crate::Mode,
        current: crate::Mode,
    },
    RuleCreated {
        rule: Rule,
    },
    RuleUpdated {
        rule: Rule,
    },
    RuleDeleted {
        rule: Rule,
    },
    RuleEnabledChanged {
        rule: Rule,
    },
    CountersUpdated {
        counters: FirewallCounters,
    },
}

impl Event {
    #[must_use]
    pub fn redacted_for_observer(&self) -> Self {
        let kind = match &self.kind {
            EventKind::RuleCreated { rule } => EventKind::RuleCreated {
                rule: rule.redacted_for_observer(),
            },
            EventKind::RuleUpdated { rule } => EventKind::RuleUpdated {
                rule: rule.redacted_for_observer(),
            },
            EventKind::RuleDeleted { rule } => EventKind::RuleDeleted {
                rule: rule.redacted_for_observer(),
            },
            EventKind::RuleEnabledChanged { rule } => EventKind::RuleEnabledChanged {
                rule: rule.redacted_for_observer(),
            },
            other => other.clone(),
        };
        Self {
            revision: self.revision,
            occurred_at: self.occurred_at,
            kind,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    revision: u64,
    #[serde(default = "initial_flow_generation")]
    flow_generation: u32,
    mode: crate::Mode,
    #[serde(default, skip_serializing_if = "EnforcementStrategy::is_strict")]
    enforcement_strategy: EnforcementStrategy,
    rules: BTreeMap<Uuid, Rule>,
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

impl State {
    #[must_use]
    pub fn new() -> Self {
        Self {
            revision: 0,
            flow_generation: initial_flow_generation(),
            mode: crate::Mode::BlockAll,
            enforcement_strategy: EnforcementStrategy::Strict,
            rules: BTreeMap::new(),
        }
    }

    /// Reconstructs mutable state from a validated immutable snapshot.
    ///
    /// Legacy snapshots carry no userspace strategy, so reconstruction always
    /// uses Strict. Persistence uses State serialization to retain Fast.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the snapshot violates any state invariant.
    pub fn from_snapshot(snapshot: Snapshot) -> Result<Self, CoreError> {
        snapshot.validate()?;
        let rules = snapshot
            .rules
            .into_iter()
            .map(|rule| (rule.id, rule))
            .collect();
        let state = Self {
            revision: snapshot.revision,
            flow_generation: snapshot.flow_generation,
            mode: snapshot.mode,
            enforcement_strategy: EnforcementStrategy::Strict,
            rules,
        };
        state.validate()?;
        Ok(state)
    }

    /// Revalidates a deserialized state before it crosses a trust boundary.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the state is too large or malformed.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.rules.len() > MAX_RULES {
            return Err(CoreError::RulesLimitReached(MAX_RULES));
        }
        if !(1..=MAX_FLOW_GENERATION).contains(&self.flow_generation) {
            return Err(CoreError::InvalidFlowGeneration);
        }
        for (id, rule) in &self.rules {
            if id != &rule.id {
                return Err(CoreError::MismatchedRuleId {
                    map_id: *id,
                    rule_id: rule.id,
                });
            }
            rule.validate()?;
            reject_redacted_rule(rule)?;
            reject_unpinned_application_spec(&rule.spec)?;
        }
        bounded_serialized_state_size(self)?;
        Ok(())
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn flow_generation(&self) -> u32 {
        self.flow_generation
    }

    /// Replaces the runtime flow-authorization epoch without changing the
    /// user-visible policy revision.
    ///
    /// The daemon calls this once at startup, before installing persisted
    /// policy, so conntrack marks left by an earlier daemon instance cannot
    /// authorize a new instance's traffic.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidFlowGeneration`] for zero, an out-of-domain
    /// value, or accidental reuse of the current epoch.
    pub fn rotate_flow_generation(&mut self, generation: u32) -> Result<(), CoreError> {
        if !(1..=MAX_FLOW_GENERATION).contains(&generation) || generation == self.flow_generation {
            return Err(CoreError::InvalidFlowGeneration);
        }
        self.flow_generation = generation;
        Ok(())
    }

    #[must_use]
    pub const fn mode(&self) -> crate::Mode {
        self.mode
    }

    #[must_use]
    pub const fn enforcement_strategy(&self) -> EnforcementStrategy {
        self.enforcement_strategy
    }

    /// Returns the application-attribution path required by the current
    /// mutable policy without constructing a snapshot.
    #[must_use]
    pub fn application_interception(&self) -> ApplicationInterception {
        classify_application_interception(self.mode, self.rules.values())
    }

    #[must_use]
    pub fn rules(&self) -> impl ExactSizeIterator<Item = &Rule> {
        self.rules.values()
    }

    /// Iterates over rules ordered by UUID, starting strictly after `cursor`.
    ///
    /// This is a logarithmic `BTreeMap` seek followed by sequential iteration;
    /// callers serving a late pagination cursor do not rescan earlier rules.
    pub fn rules_after(&self, cursor: Option<Uuid>) -> impl Iterator<Item = &Rule> {
        let lower_bound = cursor.map_or(Unbounded, Excluded);
        self.rules
            .range((lower_bound, Unbounded))
            .map(|(_id, rule)| rule)
    }

    #[must_use]
    pub fn rule(&self, id: Uuid) -> Option<&Rule> {
        self.rules.get(&id)
    }

    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            revision: self.revision,
            flow_generation: self.flow_generation,
            mode: self.mode,
            rules: self.rules.values().cloned().collect(),
        }
    }

    /// Builds the immutable quota and exact-deduplication index used before
    /// admitting an application observation to the daemon's bounded learning
    /// queue.
    #[must_use]
    pub fn application_learning_admission_index(&self) -> ApplicationLearningAdmissionIndex {
        self.application_learning_admission_index_with_limits(LearningLimits::default())
    }

    /// Builds an admission index using the administrator's validated budgets.
    #[must_use]
    pub fn application_learning_admission_index_with_limits(
        &self,
        limits: LearningLimits,
    ) -> ApplicationLearningAdmissionIndex {
        ApplicationLearningAdmissionIndex::from_state(self, limits)
    }

    /// Changes the operating mode and emits a revisioned event.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::RevisionOverflow`] if no revision remains.
    pub fn set_mode(&mut self, mode: crate::Mode) -> Result<Event, CoreError> {
        self.set_mode_at(mode, Utc::now())
    }

    /// Atomically selects Enforcing and its userspace strategy.
    ///
    /// Every call advances revision and flow generation, including a strategy
    /// change while already enforcing. Rules and legacy event shapes are unchanged.
    ///
    /// # Errors
    ///
    /// Returns an overflow error without changing state when either revision
    /// or flow generation is exhausted.
    pub fn enforce(&mut self, strategy: EnforcementStrategy) -> Result<Event, CoreError> {
        self.set_mode_with_strategy_at(crate::Mode::Enforcing, strategy, Utc::now())
    }

    /// Changes the mode at an explicit event time.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::RevisionOverflow`] if no revision remains.
    pub fn set_mode_at(
        &mut self,
        mode: crate::Mode,
        now: DateTime<Utc>,
    ) -> Result<Event, CoreError> {
        // Legacy Enforcing always opts into Strict. Other modes remember the
        // previous strategy, but do not apply it to their permissive/blocked path.
        let strategy = if mode == crate::Mode::Enforcing {
            EnforcementStrategy::Strict
        } else {
            self.enforcement_strategy
        };
        self.set_mode_with_strategy_at(mode, strategy, now)
    }

    fn set_mode_with_strategy_at(
        &mut self,
        mode: crate::Mode,
        strategy: EnforcementStrategy,
        now: DateTime<Utc>,
    ) -> Result<Event, CoreError> {
        let revision = self.next_revision()?;
        let flow_generation = match self.next_flow_generation() {
            Ok(generation) => generation,
            Err(CoreError::FlowGenerationExhausted) if mode == crate::Mode::BlockAll => {
                self.flow_generation
            }
            Err(error) => return Err(error),
        };
        let previous = self.mode;
        self.mode = mode;
        self.enforcement_strategy = strategy;
        self.flow_generation = flow_generation;
        self.revision = revision;
        Ok(Event {
            revision,
            occurred_at: now,
            kind: EventKind::ModeChanged {
                previous,
                current: mode,
            },
        })
    }

    /// Validates and inserts a new rule.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] for invalid input, capacity, or revision failure.
    pub fn create_rule(&mut self, spec: RuleSpec) -> Result<(Rule, Event), CoreError> {
        self.create_rule_at(Uuid::new_v4(), spec, Utc::now())
    }

    /// Inserts a rule with an explicit identifier and event time.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] for invalid or duplicate input, capacity, or
    /// revision failure.
    pub fn create_rule_at(
        &mut self,
        id: Uuid,
        spec: RuleSpec,
        now: DateTime<Utc>,
    ) -> Result<(Rule, Event), CoreError> {
        reject_redacted_spec(&spec)?;
        reject_unpinned_application_spec(&spec)?;
        if self.rules.len() >= MAX_RULES {
            return Err(CoreError::RulesLimitReached(MAX_RULES));
        }
        if self.rules.contains_key(&id) {
            return Err(CoreError::DuplicateRuleId(id));
        }
        let rule = Rule::with_id_and_time(id, spec, now)?;
        let revision = self.next_revision()?;
        let flow_generation = (rule.spec.enabled && rule.spec.action != RuleAction::Accept)
            .then(|| self.next_flow_generation())
            .transpose()?;
        self.rules.insert(id, rule.clone());
        // Adding an enabled deny rule must invalidate application flow marks
        // which were authorized by an older policy. Accept rules and inert
        // rules can retain the generation, which also avoids interrupting a
        // Learning-mode handshake while its observation is persisted.
        if let Some(flow_generation) = flow_generation {
            self.flow_generation = flow_generation;
        }
        self.revision = revision;
        let event = Event {
            revision,
            occurred_at: now,
            kind: EventKind::RuleCreated { rule: rule.clone() },
        };
        Ok((rule, event))
    }

    /// Replaces all editable fields of an existing rule.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the rule is absent, invalid, or cannot be
    /// revisioned.
    pub fn update_rule(&mut self, id: Uuid, spec: RuleSpec) -> Result<(Rule, Event), CoreError> {
        self.update_rule_at(id, spec, Utc::now())
    }

    /// Replaces a rule at an explicit update time.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the rule is absent, invalid, or cannot be
    /// revisioned.
    pub fn update_rule_at(
        &mut self,
        id: Uuid,
        mut spec: RuleSpec,
        now: DateTime<Utc>,
    ) -> Result<(Rule, Event), CoreError> {
        clear_disabled_template_pin_if_skeleton(&mut spec);
        spec.validate()?;
        reject_redacted_spec(&spec)?;
        reject_unpinned_application_spec(&spec)?;
        let revision = self.next_revision()?;
        let Some(current) = self.rules.get(&id) else {
            return Err(CoreError::RuleNotFound(id));
        };
        let flow_generation = self.next_flow_generation()?;
        let mut rule = current.clone();
        rule.spec = spec;
        // Wall-clock corrections must not make a privileged mutation
        // unavailable. Revisions provide ordering; keep the persisted rule
        // timestamp monotonic when UTC moves backwards.
        rule.updated_at = now.max(rule.updated_at);
        rule.validate()?;
        self.rules.insert(id, rule.clone());
        self.flow_generation = flow_generation;
        self.revision = revision;
        let event = Event {
            revision,
            occurred_at: now,
            kind: EventKind::RuleUpdated { rule: rule.clone() },
        };
        Ok((rule, event))
    }

    /// Deletes a rule by identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the rule is absent or cannot be revisioned.
    pub fn delete_rule(&mut self, id: Uuid) -> Result<(Rule, Event), CoreError> {
        self.delete_rule_at(id, Utc::now())
    }

    /// Deletes a rule at an explicit event time.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the rule is absent or cannot be revisioned.
    pub fn delete_rule_at(
        &mut self,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(Rule, Event), CoreError> {
        let revision = self.next_revision()?;
        let Some(rule) = self.rules.get(&id).cloned() else {
            return Err(CoreError::RuleNotFound(id));
        };
        let flow_generation = self.next_flow_generation()?;
        self.rules.remove(&id);
        self.flow_generation = flow_generation;
        self.revision = revision;
        let event = Event {
            revision,
            occurred_at: now,
            kind: EventKind::RuleDeleted { rule: rule.clone() },
        };
        Ok((rule, event))
    }

    /// Enables or disables an existing rule.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the rule is absent, invalid after the update,
    /// or cannot be revisioned.
    pub fn set_rule_enabled(
        &mut self,
        id: Uuid,
        enabled: bool,
    ) -> Result<(Rule, Event), CoreError> {
        self.set_rule_enabled_at(id, enabled, Utc::now())
    }

    /// Enables or disables a rule at an explicit update time.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] if the rule is absent, invalid after the update,
    /// or cannot be revisioned.
    pub fn set_rule_enabled_at(
        &mut self,
        id: Uuid,
        enabled: bool,
        now: DateTime<Utc>,
    ) -> Result<(Rule, Event), CoreError> {
        let revision = self.next_revision()?;
        let Some(current) = self.rules.get(&id) else {
            return Err(CoreError::RuleNotFound(id));
        };
        let flow_generation = if current.spec.enabled && !enabled
            || !current.spec.enabled && enabled && current.spec.action != RuleAction::Accept
        {
            Some(self.next_flow_generation()?)
        } else {
            None
        };
        let mut rule = current.clone();
        rule.spec.enabled = enabled;
        clear_disabled_template_pin_if_skeleton(&mut rule.spec);
        rule.updated_at = now.max(rule.updated_at);
        rule.validate()?;
        reject_unpinned_application_spec(&rule.spec)?;
        self.rules.insert(id, rule.clone());
        if let Some(flow_generation) = flow_generation {
            self.flow_generation = flow_generation;
        }
        self.revision = revision;
        let event = Event {
            revision,
            occurred_at: now,
            kind: EventKind::RuleEnabledChanged { rule: rule.clone() },
        };
        Ok((rule, event))
    }

    /// Deduplicates and persists an endpoint captured in learning mode.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when the endpoint is invalid or the generated
    /// rule cannot be inserted.
    pub fn learn_endpoint(&mut self, endpoint: LearnedEndpoint) -> Result<LearnOutcome, CoreError> {
        endpoint.validate()?;
        let key = LearnedRuleKey::from_endpoint(&endpoint);
        if let Some(rule) = self.rules.values().find(|rule| {
            rule.spec.origin == RuleOrigin::Learned
                && rule.spec.direction == Direction::Outbound
                && LearnedRuleKey::from_rule(rule) == key
        }) {
            return Ok(LearnOutcome {
                rule: rule.clone(),
                event: None,
            });
        }
        if self
            .rules
            .values()
            .filter(|rule| is_automatic_rule(rule))
            .count()
            >= MAX_AUTOMATIC_LEARNED_RULES
        {
            return Err(CoreError::RulesLimitReached(MAX_AUTOMATIC_LEARNED_RULES));
        }
        self.insert_learned_endpoint(endpoint, None)
    }

    /// Creates at most `maximum_new` rules from a bounded endpoint batch using
    /// one O(N) deduplication index.
    ///
    /// The batch form is used by the daemon's learning poll so a full set of
    /// already-known endpoints cannot cause an O(rules × endpoints) scan while
    /// the policy engine is locked. Processing stops safely at
    /// [`MAX_AUTOMATIC_LEARNED_RULES`] so privileged manual rules retain a
    /// fixed capacity reserve.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when an endpoint is invalid or a generated rule
    /// cannot be inserted.
    pub fn learn_new_endpoints(
        &mut self,
        endpoints: impl IntoIterator<Item = LearnedEndpoint>,
        maximum_new: usize,
    ) -> Result<Vec<LearnOutcome>, CoreError> {
        let endpoints: Vec<LearnedEndpoint> = endpoints.into_iter().take(MAX_RULES).collect();
        for endpoint in &endpoints {
            endpoint.validate()?;
        }

        let mut known: HashSet<LearnedRuleKey> = self
            .rules
            .values()
            .filter(|rule| {
                rule.spec.origin == RuleOrigin::Learned
                    && rule.spec.direction == Direction::Outbound
            })
            .map(LearnedRuleKey::from_rule)
            .collect();
        let learned_count = self
            .rules
            .values()
            .filter(|rule| is_automatic_rule(rule))
            .count();
        let maximum_new = maximum_new
            .min(MAX_RULES - self.rules.len())
            .min(MAX_AUTOMATIC_LEARNED_RULES.saturating_sub(learned_count));
        let mut outcomes = Vec::with_capacity(maximum_new.min(endpoints.len()));

        for endpoint in endpoints {
            let key = LearnedRuleKey::from_endpoint(&endpoint);
            if known.contains(&key) {
                continue;
            }
            if outcomes.len() >= maximum_new {
                break;
            }

            let outcome = self.insert_learned_endpoint(endpoint, None)?;
            known.insert(key);
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }

    /// Creates bounded, deduplicated rules that retain the identity of the
    /// application responsible for each queued outbound connection.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when an endpoint or application selector is
    /// invalid, state capacity is exhausted, or a generated rule cannot be
    /// revisioned.
    pub fn learn_new_application_endpoints(
        &mut self,
        endpoints: impl IntoIterator<Item = LearnedApplicationEndpoint>,
        maximum_new: usize,
    ) -> Result<Vec<LearnOutcome>, CoreError> {
        self.learn_new_application_endpoints_with_limits(
            endpoints,
            maximum_new,
            LearningLimits::default(),
        )
    }

    /// Learns application endpoints within administrator-selected count budgets.
    ///
    /// Global rule and serialized-state limits remain unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] for invalid endpoints, exhausted state capacity,
    /// or an unrepresentable policy revision.
    pub fn learn_new_application_endpoints_with_limits(
        &mut self,
        endpoints: impl IntoIterator<Item = LearnedApplicationEndpoint>,
        maximum_new: usize,
        limits: LearningLimits,
    ) -> Result<Vec<LearnOutcome>, CoreError> {
        let endpoints: Vec<LearnedApplicationEndpoint> =
            endpoints.into_iter().take(MAX_RULES).collect();
        for endpoint in &endpoints {
            endpoint.validate().map_err(ValidationError::from)?;
        }

        let mut known: HashSet<LearnedRuleKey> = self
            .rules
            .values()
            .filter(|rule| {
                rule.spec.origin == RuleOrigin::Learned
                    && rule.spec.direction == Direction::Outbound
            })
            .map(LearnedRuleKey::from_rule)
            .collect();
        let mut known_templates: HashSet<ApplicationTemplateKey> = self
            .rules
            .values()
            .filter_map(ApplicationTemplateKey::from_template)
            .collect();
        let learned_count = self
            .rules
            .values()
            .filter(|rule| is_automatic_rule(rule))
            .count();
        let mut learned_per_uid = HashMap::<u32, usize>::new();
        let mut learned_per_application = HashMap::<(u32, crate::ExecutableFileId), usize>::new();
        for rule in self.rules.values().filter(|rule| {
            rule.spec.origin == RuleOrigin::Learned && rule.spec.direction == Direction::Outbound
        }) {
            let Some(application) = &rule.spec.application else {
                continue;
            };
            let (Some(uid), Some(file)) = (application.uid, application.executable_file) else {
                continue;
            };
            *learned_per_uid.entry(uid).or_default() += 1;
            *learned_per_application.entry((uid, file)).or_default() += 1;
        }
        let maximum_new = maximum_new
            .min(MAX_RULES - self.rules.len())
            .min(MAX_AUTOMATIC_LEARNED_RULES.saturating_sub(learned_count));
        let mut outcomes = Vec::with_capacity(maximum_new.min(endpoints.len()));

        for learned in endpoints {
            let key = LearnedRuleKey::from_application_endpoint(&learned);
            if known.contains(&key) {
                continue;
            }
            let template_key = ApplicationTemplateKey::from_selector(&learned.application)?;
            let needs_template = !known_templates.contains(&template_key);
            let required_slots = usize::from(needs_template) + 1;
            if outcomes.len().saturating_add(required_slots) > maximum_new {
                break;
            }
            let uid = learned
                .application
                .uid
                .ok_or(crate::ApplicationValidationError::IncompleteLearnedApplicationIdentity)
                .map_err(ValidationError::from)?;
            let file = learned
                .application
                .executable_file
                .ok_or(crate::ApplicationValidationError::IncompleteLearnedApplicationIdentity)
                .map_err(ValidationError::from)?;
            if learned_per_uid.get(&uid).copied().unwrap_or_default() >= limits.per_uid()
                || learned_per_application
                    .get(&(uid, file))
                    .copied()
                    .unwrap_or_default()
                    >= limits.per_application()
            {
                continue;
            }
            if needs_template {
                let outcome = self.insert_application_group_template(&template_key)?;
                known_templates.insert(template_key);
                outcomes.push(outcome);
            }
            let outcome =
                self.insert_learned_endpoint(learned.endpoint, Some(learned.application))?;
            known.insert(key);
            *learned_per_uid.entry(uid).or_default() += 1;
            *learned_per_application.entry((uid, file)).or_default() += 1;
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }

    /// Adds missing disabled application-wide templates for learned rules
    /// loaded from an older state schema.
    ///
    /// Templates consume the same bounded automatic-rule reserve as endpoint
    /// observations. Existing endpoint rules are never removed when there is
    /// insufficient room for every historical group.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError`] when a generated template cannot be validated or
    /// revisioned.
    pub fn ensure_application_group_templates(
        &mut self,
        maximum_new: usize,
    ) -> Result<Vec<LearnOutcome>, CoreError> {
        self.ensure_application_group_templates_with_size_limit(maximum_new, MAX_STATE_BYTES)
    }

    fn ensure_application_group_templates_with_size_limit(
        &mut self,
        maximum_new: usize,
        maximum_state_bytes: usize,
    ) -> Result<Vec<LearnOutcome>, CoreError> {
        let mut known: HashSet<ApplicationTemplateKey> = self
            .rules
            .values()
            .filter_map(ApplicationTemplateKey::from_template)
            .collect();
        let groups: Vec<ApplicationTemplateKey> = self
            .rules
            .values()
            .filter(|rule| {
                rule.spec.origin == RuleOrigin::Learned
                    && rule.spec.direction == Direction::Outbound
            })
            .filter_map(|rule| rule.spec.application.as_ref())
            .filter_map(|selector| ApplicationTemplateKey::from_selector(selector).ok())
            .filter(|key| known.insert(key.clone()))
            .collect();
        let automatic_count = self
            .rules
            .values()
            .filter(|rule| is_automatic_rule(rule))
            .count();
        let maximum_new = maximum_new
            .min(MAX_RULES.saturating_sub(self.rules.len()))
            .min(MAX_AUTOMATIC_LEARNED_RULES.saturating_sub(automatic_count));
        let mut outcomes = Vec::with_capacity(maximum_new.min(groups.len()));
        let mut serialized_size = bounded_serialized_state_size(self)?;
        for group in groups.into_iter().take(maximum_new) {
            let previous_revision = self.revision;
            let previous_flow_generation = self.flow_generation;
            let had_rules = !self.rules.is_empty();
            let outcome = self.insert_application_group_template(&group)?;
            let size_delta = match serialized_rule_map_entry_delta(
                &outcome.rule,
                previous_revision,
                self.revision,
                had_rules,
            ) {
                Ok(size_delta) => size_delta,
                Err(error) => {
                    self.rules.remove(&outcome.rule.id);
                    self.revision = previous_revision;
                    self.flow_generation = previous_flow_generation;
                    return Err(error);
                }
            };
            let candidate_size = serialized_size.saturating_add(size_delta);
            if candidate_size > maximum_state_bytes {
                // A legacy state close to the byte ceiling must remain
                // bootable. Template migration is additive convenience, so
                // roll back only the template which would cross the bound and
                // leave the already valid policy unchanged.
                self.rules.remove(&outcome.rule.id);
                self.revision = previous_revision;
                self.flow_generation = previous_flow_generation;
                break;
            }
            serialized_size = candidate_size;
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }

    fn insert_application_group_template(
        &mut self,
        key: &ApplicationTemplateKey,
    ) -> Result<LearnOutcome, CoreError> {
        let application = ApplicationSelector::new(
            Some(key.executable.clone()),
            None,
            None,
            None,
            key.cgroup.clone(),
        )
        .map_err(ValidationError::from)?;
        let spec = RuleSpec {
            name: RuleName::new(APPLICATION_GROUP_TEMPLATE_NAME)?,
            direction: Direction::Outbound,
            action: RuleAction::Accept,
            protocol: crate::TransportProtocol::Any,
            peer_network: None,
            port: None,
            interface: None,
            application: Some(application),
            origin: RuleOrigin::Template,
            enabled: false,
        };
        let (rule, event) = self.create_rule(spec)?;
        Ok(LearnOutcome {
            rule,
            event: Some(event),
        })
    }

    fn insert_learned_endpoint(
        &mut self,
        endpoint: LearnedEndpoint,
        application: Option<ApplicationSelector>,
    ) -> Result<LearnOutcome, CoreError> {
        let peer_network = Some(IpNet::from(endpoint.address));
        let suffix = endpoint.port.map_or_else(String::new, |port| {
            if port.start() == port.end() {
                format!(":{}", port.start())
            } else {
                format!(":{}-{}", port.start(), port.end())
            }
        });
        let name = RuleName::new(format!(
            "learned {} {}{suffix}",
            endpoint.protocol, endpoint.address
        ))?;
        let mut spec = RuleSpec::new(
            name,
            Direction::Outbound,
            endpoint.protocol,
            peer_network,
            endpoint.port,
            endpoint.interface,
            RuleOrigin::Learned,
            true,
        )?;
        spec.action = RuleAction::Accept;
        spec.application = application;
        spec.validate()?;
        let (rule, event) = self.create_rule(spec)?;
        Ok(LearnOutcome {
            rule,
            event: Some(event),
        })
    }

    #[must_use]
    pub fn counters_event(&self, counters: FirewallCounters, occurred_at: DateTime<Utc>) -> Event {
        Event {
            revision: self.revision,
            occurred_at,
            kind: EventKind::CountersUpdated { counters },
        }
    }

    fn next_revision(&self) -> Result<u64, CoreError> {
        self.revision
            .checked_add(1)
            .ok_or(CoreError::RevisionOverflow)
    }

    fn next_flow_generation(&self) -> Result<u32, CoreError> {
        if self.flow_generation >= MAX_FLOW_GENERATION {
            return Err(CoreError::FlowGenerationExhausted);
        }
        Ok(self.flow_generation + 1)
    }
}

fn classify_application_interception<'a>(
    mode: crate::Mode,
    rules: impl IntoIterator<Item = &'a Rule>,
) -> ApplicationInterception {
    match mode {
        crate::Mode::BlockAll => ApplicationInterception::None,
        crate::Mode::Learning => ApplicationInterception::PerPacket,
        crate::Mode::Enforcing => {
            let mut interception = ApplicationInterception::None;
            for rule in rules {
                if !rule.spec.enabled
                    || rule.spec.direction != Direction::Outbound
                    || rule.spec.application.is_none()
                {
                    continue;
                }

                match rule.spec.protocol {
                    crate::TransportProtocol::Tcp => {
                        interception = ApplicationInterception::TcpInitial;
                    }
                    crate::TransportProtocol::Any
                    | crate::TransportProtocol::Udp
                    | crate::TransportProtocol::Icmp
                    | crate::TransportProtocol::IcmpV6 => {
                        return ApplicationInterception::PerPacket;
                    }
                }
            }
            interception
        }
    }
}

fn is_automatic_rule(rule: &Rule) -> bool {
    matches!(rule.spec.origin, RuleOrigin::Learned | RuleOrigin::Template)
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct LearnedRuleKey {
    protocol: crate::TransportProtocol,
    peer_network: Option<IpNet>,
    port: Option<crate::PortRange>,
    interface: Option<crate::InterfaceName>,
    application: Option<ApplicationSelector>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ApplicationTemplateKey {
    executable: ApplicationPath,
    cgroup: Option<CgroupPath>,
}

impl ApplicationTemplateKey {
    fn from_selector(selector: &ApplicationSelector) -> Result<Self, ValidationError> {
        let executable = selector
            .executable
            .clone()
            .ok_or(crate::ApplicationValidationError::ApplicationSelectorNeedsExecutable)?;
        Ok(Self {
            executable,
            cgroup: selector.cgroup.clone(),
        })
    }

    fn from_template(rule: &Rule) -> Option<Self> {
        let selector = rule.spec.application.as_ref()?;
        if rule.spec.origin != RuleOrigin::Template
            || rule.spec.direction != Direction::Outbound
            || selector.metadata_redacted
        {
            return None;
        }
        Self::from_selector(selector).ok()
    }
}

impl LearnedRuleKey {
    fn from_endpoint(endpoint: &LearnedEndpoint) -> Self {
        Self {
            protocol: endpoint.protocol,
            peer_network: Some(IpNet::from(endpoint.address)),
            port: endpoint.port,
            interface: endpoint.interface.clone(),
            application: None,
        }
    }

    fn from_application_endpoint(endpoint: &LearnedApplicationEndpoint) -> Self {
        Self {
            protocol: endpoint.endpoint.protocol,
            peer_network: Some(IpNet::from(endpoint.endpoint.address)),
            port: endpoint.endpoint.port,
            interface: endpoint.endpoint.interface.clone(),
            application: Some(endpoint.application.clone()),
        }
    }

    fn from_rule(rule: &Rule) -> Self {
        Self {
            protocol: rule.spec.protocol,
            peer_network: rule.spec.peer_network,
            port: rule.spec.port,
            interface: rule.spec.interface.clone(),
            application: rule.spec.application.clone(),
        }
    }
}

/// Result of checking one attributed application endpoint against the current
/// automatic-learning count budgets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationLearningAdmission {
    /// The exact learned endpoint already exists and needs no queue entry.
    AlreadyKnown,
    /// At least one applicable count budget is exhausted.
    Saturated,
    /// The endpoint can still become a persisted automatic rule.
    Candidate,
}

/// Immutable exact-deduplication and count-quota view of one policy revision.
///
/// The daemon rebuilds this bounded index whenever its authoritative
/// [`State`] changes. It lets the packet path avoid filling the learning queue
/// with observations which the serialized learning worker would necessarily
/// discard.
#[derive(Clone, Debug)]
pub struct ApplicationLearningAdmissionIndex {
    limits: LearningLimits,
    revision: u64,
    flow_generation: u32,
    mode: crate::Mode,
    total_rule_count: usize,
    learned_rule_count: usize,
    known: HashSet<LearnedRuleKey>,
    known_templates: HashSet<ApplicationTemplateKey>,
    learned_per_uid: HashMap<u32, usize>,
    learned_per_application: HashMap<(u32, crate::ExecutableFileId), usize>,
}

impl ApplicationLearningAdmissionIndex {
    fn from_state(state: &State, limits: LearningLimits) -> Self {
        let mut known = HashSet::new();
        let mut known_templates = HashSet::new();
        let mut learned_rule_count = 0_usize;
        let mut learned_per_uid = HashMap::<u32, usize>::new();
        let mut learned_per_application = HashMap::<(u32, crate::ExecutableFileId), usize>::new();

        for rule in state.rules.values() {
            if !is_automatic_rule(rule) {
                continue;
            }
            learned_rule_count += 1;
            if let Some(template) = ApplicationTemplateKey::from_template(rule) {
                known_templates.insert(template);
            }
            if rule.spec.origin != RuleOrigin::Learned || rule.spec.direction != Direction::Outbound
            {
                continue;
            }
            known.insert(LearnedRuleKey::from_rule(rule));
            let Some(application) = &rule.spec.application else {
                continue;
            };
            let (Some(uid), Some(file)) = (application.uid, application.executable_file) else {
                continue;
            };
            *learned_per_uid.entry(uid).or_default() += 1;
            *learned_per_application.entry((uid, file)).or_default() += 1;
        }

        Self {
            limits,
            revision: state.revision,
            flow_generation: state.flow_generation,
            mode: state.mode,
            total_rule_count: state.rules.len(),
            learned_rule_count,
            known,
            known_templates,
            learned_per_uid,
            learned_per_application,
        }
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn flow_generation(&self) -> u32 {
        self.flow_generation
    }

    #[must_use]
    pub const fn mode(&self) -> crate::Mode {
        self.mode
    }

    #[must_use]
    pub fn summary(&self) -> LearningQuotaSummary {
        LearningQuotaSummary {
            automatic_rules: self.learned_rule_count,
            saturated_uids: self
                .learned_per_uid
                .values()
                .filter(|count| **count >= self.limits.per_uid())
                .count(),
            saturated_applications: self
                .learned_per_application
                .values()
                .filter(|count| **count >= self.limits.per_application())
                .count(),
        }
    }

    /// Checks whether an already validated observation can consume another
    /// automatic-learning slot.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ApplicationValidationError`] when the endpoint is not
    /// an exact application identity suitable for automatic persistence.
    pub fn classify(
        &self,
        endpoint: &LearnedApplicationEndpoint,
    ) -> Result<ApplicationLearningAdmission, crate::ApplicationValidationError> {
        endpoint.validate()?;
        let key = LearnedRuleKey::from_application_endpoint(endpoint);
        if self.known.contains(&key) {
            return Ok(ApplicationLearningAdmission::AlreadyKnown);
        }
        let template_key =
            ApplicationTemplateKey {
                executable: endpoint.application.executable.clone().ok_or(
                    crate::ApplicationValidationError::IncompleteLearnedApplicationIdentity,
                )?,
                cgroup: endpoint.application.cgroup.clone(),
            };
        let required_slots = 1 + usize::from(!self.known_templates.contains(&template_key));
        if self.total_rule_count.saturating_add(required_slots) > MAX_RULES
            || self.learned_rule_count.saturating_add(required_slots) > MAX_AUTOMATIC_LEARNED_RULES
        {
            return Ok(ApplicationLearningAdmission::Saturated);
        }
        let Some(uid) = endpoint.application.uid else {
            return Err(crate::ApplicationValidationError::IncompleteLearnedApplicationIdentity);
        };
        let Some(file) = endpoint.application.executable_file else {
            return Err(crate::ApplicationValidationError::IncompleteLearnedApplicationIdentity);
        };
        if self.learned_per_uid.get(&uid).copied().unwrap_or_default() >= self.limits.per_uid()
            || self
                .learned_per_application
                .get(&(uid, file))
                .copied()
                .unwrap_or_default()
                >= self.limits.per_application()
        {
            return Ok(ApplicationLearningAdmission::Saturated);
        }
        Ok(ApplicationLearningAdmission::Candidate)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LearnOutcome {
    pub rule: Rule,
    pub event: Option<Event>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CoreError {
    #[error(transparent)]
    Validation(#[from] ValidationError),
    #[error("rule {0} does not exist")]
    RuleNotFound(Uuid),
    #[error("rule id {0} appears more than once")]
    DuplicateRuleId(Uuid),
    #[error("state rule key {map_id} differs from embedded id {rule_id}")]
    MismatchedRuleId { map_id: Uuid, rule_id: Uuid },
    #[error("at most {0} rules are allowed")]
    RulesLimitReached(usize),
    #[error("state revision counter is exhausted")]
    RevisionOverflow,
    #[error("state flow-authorization generation is outside the supported mark domain")]
    InvalidFlowGeneration,
    #[error("state flow-authorization generation is exhausted")]
    FlowGenerationExhausted,
    #[error("redacted application metadata cannot enter persisted policy state")]
    RedactedApplicationMetadata,
    #[error("observer snapshot contains a noncanonical or mixed application redaction")]
    InvalidObserverRedaction,
    #[error("application rules require a pinned executable version identity")]
    UnpinnedApplicationIdentity,
    #[error("serialized state exceeds the {0}-byte persistence limit")]
    StateSizeLimitReached(usize),
    #[error("state serialization failed during size validation: {0}")]
    StateSerialization(String),
}

const fn initial_flow_generation() -> u32 {
    1
}

fn bounded_serialized_state_size(state: &State) -> Result<usize, CoreError> {
    #[derive(Default)]
    struct SizeCounter {
        bytes: usize,
        exceeded: bool,
    }

    impl Write for SizeCounter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let Some(total) = self.bytes.checked_add(bytes.len()) else {
                self.exceeded = true;
                return Err(io::Error::other("serialized state size overflow"));
            };
            if total > MAX_STATE_BYTES {
                self.exceeded = true;
                return Err(io::Error::other("serialized state exceeds fixed limit"));
            }
            self.bytes = total;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut counter = SizeCounter::default();
    match serde_json::to_writer(&mut counter, state) {
        Ok(()) => Ok(counter.bytes),
        Err(_) if counter.exceeded => Err(CoreError::StateSizeLimitReached(MAX_STATE_BYTES)),
        Err(error) => Err(CoreError::StateSerialization(error.to_string())),
    }
}

fn serialized_rule_map_entry_delta(
    rule: &Rule,
    previous_revision: u64,
    current_revision: u64,
    had_rules: bool,
) -> Result<usize, CoreError> {
    let rule_size = serde_json::to_vec(rule)
        .map_err(|error| CoreError::StateSerialization(error.to_string()))?
        .len();
    let key_and_separator_size = rule.id.to_string().len().saturating_add(3);
    let comma_size = usize::from(had_rules);
    let previous_revision_size = previous_revision.to_string().len();
    let current_revision_size = current_revision.to_string().len();
    rule_size
        .checked_add(key_and_separator_size)
        .and_then(|size| size.checked_add(comma_size))
        .and_then(|size| size.checked_add(current_revision_size))
        .and_then(|size| size.checked_sub(previous_revision_size))
        .ok_or_else(|| CoreError::StateSerialization("state size arithmetic overflowed".to_owned()))
}

fn reject_redacted_rule(rule: &Rule) -> Result<(), CoreError> {
    reject_redacted_spec(&rule.spec)
}

fn reject_redacted_spec(spec: &RuleSpec) -> Result<(), CoreError> {
    if spec
        .application
        .as_ref()
        .is_some_and(|selector| selector.metadata_redacted)
    {
        return Err(CoreError::RedactedApplicationMetadata);
    }
    Ok(())
}

fn reject_unpinned_application_spec(spec: &RuleSpec) -> Result<(), CoreError> {
    if spec
        .application
        .as_ref()
        .is_some_and(|selector| selector.executable_file.is_none())
        && !is_unpinned_application_template(spec)
    {
        return Err(CoreError::UnpinnedApplicationIdentity);
    }
    Ok(())
}

fn is_unpinned_application_template(spec: &RuleSpec) -> bool {
    let Some(selector) = spec.application.as_ref() else {
        return false;
    };
    spec.origin == RuleOrigin::Template
        && !spec.enabled
        && spec.action == RuleAction::Accept
        && spec.direction == Direction::Outbound
        && spec.protocol == crate::TransportProtocol::Any
        && spec.peer_network.is_none()
        && spec.port.is_none()
        && spec.interface.is_none()
        && selector.executable.is_some()
        && selector.executable_file.is_none()
        && selector.command_line.is_none()
        && selector.uid.is_none()
        && !selector.metadata_redacted
}

fn clear_disabled_template_pin_if_skeleton(spec: &mut RuleSpec) {
    if spec.origin != RuleOrigin::Template
        || spec.enabled
        || spec.action != RuleAction::Accept
        || spec.direction != Direction::Outbound
        || spec.protocol != crate::TransportProtocol::Any
        || spec.peer_network.is_some()
        || spec.port.is_some()
        || spec.interface.is_some()
    {
        return;
    }
    if let Some(selector) = spec.application.as_mut()
        && selector.executable.is_some()
        && selector.command_line.is_none()
        && selector.uid.is_none()
        && !selector.metadata_redacted
    {
        selector.executable_file = None;
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use chrono::TimeZone;

    use super::*;
    use crate::{
        ApplicationPath, ExecutableFileId, LearnedApplicationEndpoint, Mode, PortRange,
        TransportProtocol,
    };

    fn fixed_time() -> Result<DateTime<Utc>, Box<dyn Error>> {
        Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0)
            .single()
            .ok_or_else(|| "invalid test time".into())
    }

    fn test_spec(name: &str) -> Result<RuleSpec, Box<dyn Error>> {
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

    fn test_application_spec(
        name: &str,
        direction: Direction,
        protocol: TransportProtocol,
        enabled: bool,
    ) -> Result<RuleSpec, Box<dyn Error>> {
        let port = matches!(protocol, TransportProtocol::Tcp | TransportProtocol::Udp)
            .then(|| PortRange::single(443))
            .transpose()?;
        let peer_network = Some(if protocol == TransportProtocol::IcmpV6 {
            "2001:db8::7/128".parse()?
        } else {
            "203.0.113.7/32".parse()?
        });
        let mut specification = RuleSpec::new(
            RuleName::new(name)?,
            direction,
            protocol,
            peer_network,
            port,
            None,
            RuleOrigin::Manual,
            enabled,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new(
                "/usr/bin/openshield-interception-test",
            )?),
            Some(ExecutableFileId {
                device: 8,
                inode: 42,
                size: 4_096,
                ctime_seconds: 1_700_000_000,
                ctime_nanoseconds: 0,
            }),
            None,
            Some(1_000),
            None,
        )?);
        Ok(specification)
    }

    fn learned_application_endpoint(
        address_offset: u32,
        uid: u32,
        application_number: u64,
    ) -> Result<LearnedApplicationEndpoint, Box<dyn Error>> {
        Ok(LearnedApplicationEndpoint {
            endpoint: LearnedEndpoint {
                address: std::net::Ipv4Addr::from(0x0a00_0001_u32 + address_offset).into(),
                protocol: TransportProtocol::Tcp,
                port: Some(PortRange::single(443)?),
                interface: Some(crate::InterfaceName::new("eth0")?),
            },
            application: ApplicationSelector::new(
                Some(ApplicationPath::new(format!(
                    "/usr/bin/openshield-test-{application_number}"
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

    #[test]
    fn persisted_application_rules_require_a_pinned_file_identity() -> Result<(), Box<dyn Error>> {
        let mut specification = test_spec("unpinned application")?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new("/usr/bin/example")?),
            None,
            None,
            None,
            None,
        )?);
        let error = State::new().create_rule(specification);
        assert!(matches!(error, Err(CoreError::UnpinnedApplicationIdentity)));
        Ok(())
    }

    #[test]
    fn state_mutations_are_revisioned_and_snapshot_is_sorted() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        let later = Uuid::parse_str("ffffffff-ffff-4fff-8fff-ffffffffffff")?;
        let earlier = Uuid::parse_str("00000000-0000-4000-8000-000000000001")?;
        state.create_rule_at(later, test_spec("later")?, fixed_time()?)?;
        state.create_rule_at(earlier, test_spec("earlier")?, fixed_time()?)?;

        let snapshot = state.snapshot();
        assert_eq!(snapshot.revision, 2);
        assert_eq!(snapshot.rules[0].id, earlier);
        assert_eq!(snapshot.rules[1].id, later);
        let after_earlier: Vec<_> = state
            .rules_after(Some(earlier))
            .map(|rule| rule.id)
            .collect();
        assert_eq!(after_earlier, vec![later]);
        assert!(state.rules_after(Some(later)).next().is_none());
        Ok(())
    }

    #[test]
    fn failed_update_does_not_change_state() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        let before = state.clone();
        let missing = Uuid::new_v4();
        assert_eq!(
            state.update_rule_at(missing, test_spec("missing")?, fixed_time()?),
            Err(CoreError::RuleNotFound(missing))
        );
        assert_eq!(state, before);
        Ok(())
    }

    #[test]
    fn fresh_state_is_fail_closed() {
        let state = State::new();
        assert_eq!(state.mode(), Mode::BlockAll);
        assert_eq!(state.flow_generation(), 1);
        assert!(state.rules().next().is_none());
        assert_eq!(
            state.application_interception(),
            ApplicationInterception::None
        );
    }

    #[test]
    fn application_interception_is_mode_aware() -> Result<(), Box<dyn Error>> {
        let application_udp = Rule::new(test_application_spec(
            "application udp",
            Direction::Outbound,
            TransportProtocol::Udp,
            true,
        )?)?;
        let block_all = Snapshot {
            revision: 0,
            flow_generation: 1,
            mode: Mode::BlockAll,
            rules: vec![application_udp],
        };
        assert_eq!(
            block_all.application_interception(),
            ApplicationInterception::None
        );

        let learning = Snapshot {
            revision: 0,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: Vec::new(),
        };
        assert_eq!(
            learning.application_interception(),
            ApplicationInterception::PerPacket
        );
        Ok(())
    }

    #[test]
    fn enforcing_interception_ignores_rules_without_an_active_outbound_application_selector()
    -> Result<(), Box<dyn Error>> {
        let network = Rule::new(test_spec("network")?)?;
        let disabled_application = Rule::new(test_application_spec(
            "disabled application",
            Direction::Outbound,
            TransportProtocol::Udp,
            false,
        )?)?;
        let snapshot = Snapshot {
            revision: 0,
            flow_generation: 1,
            mode: Mode::Enforcing,
            rules: vec![network, disabled_application],
        };
        assert_eq!(
            snapshot.application_interception(),
            ApplicationInterception::None
        );
        Ok(())
    }

    #[test]
    fn enforcing_tcp_application_rules_use_initial_packet_attribution() -> Result<(), Box<dyn Error>>
    {
        let mut state = State::new();
        state.create_rule(test_application_spec(
            "tcp application",
            Direction::Outbound,
            TransportProtocol::Tcp,
            true,
        )?)?;
        state.set_mode(Mode::Enforcing)?;
        assert_eq!(
            state.application_interception(),
            ApplicationInterception::TcpInitial
        );
        assert_eq!(
            state.snapshot().application_interception(),
            ApplicationInterception::TcpInitial
        );
        Ok(())
    }

    #[test]
    fn enforcing_per_packet_application_protocol_dominates_tcp_in_any_order()
    -> Result<(), Box<dyn Error>> {
        let tcp = Rule::new(test_application_spec(
            "tcp application",
            Direction::Outbound,
            TransportProtocol::Tcp,
            true,
        )?)?;
        for protocol in [
            TransportProtocol::Any,
            TransportProtocol::Udp,
            TransportProtocol::Icmp,
            TransportProtocol::IcmpV6,
        ] {
            let per_packet = Rule::new(test_application_spec(
                "per-packet application",
                Direction::Outbound,
                protocol,
                true,
            )?)?;
            for rules in [
                vec![tcp.clone(), per_packet.clone()],
                vec![per_packet.clone(), tcp.clone()],
            ] {
                let snapshot = Snapshot {
                    revision: 0,
                    flow_generation: 1,
                    mode: Mode::Enforcing,
                    rules,
                };
                assert_eq!(
                    snapshot.application_interception(),
                    ApplicationInterception::PerPacket
                );
            }
        }
        Ok(())
    }

    #[test]
    fn startup_epoch_rotation_rejects_reuse_without_changing_revision() -> Result<(), CoreError> {
        let mut state = State::new();
        state.rotate_flow_generation(42)?;
        assert_eq!(state.flow_generation(), 42);
        assert_eq!(state.revision(), 0);
        assert_eq!(
            state.rotate_flow_generation(42),
            Err(CoreError::InvalidFlowGeneration)
        );
        assert_eq!(
            state.rotate_flow_generation(0),
            Err(CoreError::InvalidFlowGeneration)
        );
        Ok(())
    }

    #[test]
    fn restrictive_mutations_advance_a_non_reused_flow_generation() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        let (created, _) = state.create_rule(test_spec("generation")?)?;
        assert_eq!(state.flow_generation(), 1);

        state.set_rule_enabled(created.id, false)?;
        assert_eq!(state.flow_generation(), 2);
        state.set_rule_enabled(created.id, true)?;
        assert_eq!(state.flow_generation(), 2);
        state.update_rule(created.id, test_spec("updated generation")?)?;
        assert_eq!(state.flow_generation(), 3);
        state.delete_rule(created.id)?;
        assert_eq!(state.flow_generation(), 4);
        Ok(())
    }

    #[test]
    fn activating_or_creating_a_deny_invalidates_old_application_flows()
    -> Result<(), Box<dyn Error>> {
        let mut disabled_drop = test_spec("disabled drop")?;
        disabled_drop.enabled = false;
        disabled_drop.action = RuleAction::Drop;
        let mut state = State::new();
        let (rule, _) = state.create_rule(disabled_drop)?;
        assert_eq!(state.flow_generation(), 1);
        state.set_rule_enabled(rule.id, true)?;
        assert_eq!(state.flow_generation(), 2);

        let mut enabled_reject = test_spec("enabled reject")?;
        enabled_reject.action = RuleAction::Reject;
        state.create_rule(enabled_reject)?;
        assert_eq!(state.flow_generation(), 3);
        Ok(())
    }

    #[test]
    fn exhausted_generation_can_enter_but_never_leave_block_all() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.mode = Mode::Enforcing;
        state.flow_generation = MAX_FLOW_GENERATION;
        let before = state.clone();
        assert_eq!(
            state.set_mode(Mode::Learning),
            Err(CoreError::FlowGenerationExhausted)
        );
        assert_eq!(state, before);

        state.set_mode(Mode::BlockAll)?;
        assert_eq!(state.mode(), Mode::BlockAll);
        assert_eq!(state.flow_generation(), MAX_FLOW_GENERATION);
        assert_eq!(
            state.set_mode(Mode::Enforcing),
            Err(CoreError::FlowGenerationExhausted)
        );
        Ok(())
    }

    #[test]
    fn mode_change_emits_event() -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        let event = state.set_mode_at(Mode::Enforcing, fixed_time()?)?;
        assert_eq!(state.mode(), Mode::Enforcing);
        assert!(matches!(
            event.kind,
            EventKind::ModeChanged {
                previous: Mode::BlockAll,
                current: Mode::Enforcing
            }
        ));
        Ok(())
    }

    #[test]
    fn legacy_state_defaults_to_strict_without_changing_serialized_shape()
    -> Result<(), Box<dyn Error>> {
        let legacy = serde_json::json!({
            "revision": 9,
            "flow_generation": 3,
            "mode": "enforcing",
            "rules": {}
        });
        let state: State = serde_json::from_value(legacy.clone())?;
        state.validate()?;
        assert_eq!(EnforcementStrategy::default(), EnforcementStrategy::Strict);
        assert!(state.enforcement_strategy().is_strict());
        assert_eq!(serde_json::to_value(&state)?, legacy);
        assert!(State::new().enforcement_strategy().is_strict());
        Ok(())
    }

    #[test]
    fn fast_strategy_persists_but_legacy_snapshot_reconstruction_is_strict()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.enforce(EnforcementStrategy::Fast)?;
        state.validate()?;
        let encoded = serde_json::to_value(&state)?;
        assert_eq!(encoded["enforcement_strategy"], "fast");
        let decoded: State = serde_json::from_value(encoded)?;
        assert_eq!(decoded, state);
        assert!(!state.enforcement_strategy().is_strict());
        let snapshot = state.snapshot();
        let serialized_snapshot = serde_json::to_value(&snapshot)?;
        assert!(serialized_snapshot.get("enforcement_strategy").is_none());
        let reconstructed = State::from_snapshot(snapshot.clone())?;
        assert_eq!(reconstructed.snapshot(), snapshot);
        assert!(reconstructed.enforcement_strategy().is_strict());
        Ok(())
    }

    #[test]
    fn state_rejects_unknown_or_malformed_enforcement_strategy() -> Result<(), Box<dyn Error>> {
        for strategy in [
            serde_json::json!("auto"),
            serde_json::json!("Fast"),
            serde_json::json!(null),
            serde_json::json!(1),
            serde_json::json!({"fast": true}),
        ] {
            let mut encoded = serde_json::to_value(State::new())?;
            encoded["enforcement_strategy"] = strategy;
            assert!(serde_json::from_value::<State>(encoded).is_err());
        }
        assert!(
            serde_json::from_str::<State>(
                r#"{"revision":0,"mode":"block_all","rules":{},"enforcement_strategy":"strict","enforcement_strategy":"fast"}"#
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn selecting_strategy_rotates_generation_atomically_without_changing_rules()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.create_rule(test_spec("unchanged rule")?)?;
        let original_rules = state.snapshot().rules;
        for strategy in [EnforcementStrategy::Fast, EnforcementStrategy::Strict] {
            let revision = state.revision();
            let generation = state.flow_generation();
            let previous = state.mode();
            let event = state.enforce(strategy)?;
            assert_eq!(state.revision(), revision + 1);
            assert_eq!(state.flow_generation(), generation + 1);
            assert_eq!(state.mode(), Mode::Enforcing);
            assert_eq!(state.enforcement_strategy(), strategy);
            assert_eq!(state.snapshot().rules, original_rules);
            assert_eq!(event.revision, state.revision());
            assert_eq!(
                event.kind,
                EventKind::ModeChanged {
                    previous,
                    current: Mode::Enforcing
                }
            );
            let event_value = serde_json::to_value(&event)?;
            assert!(!event_value.to_string().contains("enforcement_strategy"));
        }
        Ok(())
    }

    #[test]
    fn enforcement_revision_and_generation_exhaustion_leave_state_unchanged()
    -> Result<(), Box<dyn Error>> {
        for initial_strategy in [EnforcementStrategy::Fast, EnforcementStrategy::Strict] {
            let mut state = State::new();
            state.enforce(initial_strategy)?;
            state.revision = u64::MAX;
            let before = state.clone();
            for requested in [EnforcementStrategy::Strict, EnforcementStrategy::Fast] {
                assert_eq!(state.enforce(requested), Err(CoreError::RevisionOverflow));
                assert_eq!(state, before);
            }

            state.revision = 10;
            state.flow_generation = MAX_FLOW_GENERATION;
            let before = state.clone();
            for requested in [EnforcementStrategy::Strict, EnforcementStrategy::Fast] {
                assert_eq!(
                    state.enforce(requested),
                    Err(CoreError::FlowGenerationExhausted)
                );
                assert_eq!(state, before);
            }
        }
        Ok(())
    }

    #[test]
    fn legacy_enforcing_resets_strategy_but_other_modes_remember_it() -> Result<(), Box<dyn Error>>
    {
        let mut state = State::new();
        state.enforce(EnforcementStrategy::Fast)?;
        for mode in [Mode::Learning, Mode::BlockAll] {
            state.set_mode(mode)?;
            assert_eq!(state.enforcement_strategy(), EnforcementStrategy::Fast);
            assert_eq!(state.mode(), mode);
        }
        state.set_mode(Mode::Enforcing)?;
        assert!(state.enforcement_strategy().is_strict());
        assert!(
            serde_json::to_value(&state)?
                .get("enforcement_strategy")
                .is_none()
        );
        state.enforce(EnforcementStrategy::Fast)?;
        state.set_mode_at(Mode::Enforcing, fixed_time()?)?;
        assert!(state.enforcement_strategy().is_strict());
        Ok(())
    }

    #[test]
    fn both_enforcement_strategies_produce_the_same_kernel_snapshot() -> Result<(), Box<dyn Error>>
    {
        let mut strict = State::new();
        strict.create_rule(test_spec("same network policy")?)?;
        let mut fast = strict.clone();
        strict.enforce(EnforcementStrategy::Strict)?;
        fast.enforce(EnforcementStrategy::Fast)?;
        assert_eq!(strict.snapshot(), fast.snapshot());
        assert_ne!(strict, fast);
        assert_eq!(
            strict.application_interception(),
            fast.application_interception()
        );
        Ok(())
    }

    #[test]
    fn learning_deduplicates_endpoints() -> Result<(), Box<dyn Error>> {
        let endpoint = LearnedEndpoint {
            address: "203.0.113.8".parse()?,
            protocol: TransportProtocol::Tcp,
            port: Some(PortRange::single(443)?),
            interface: Some(crate::InterfaceName::new("eth0")?),
        };
        let mut state = State::new();
        let first = state.learn_endpoint(endpoint.clone())?;
        let second = state.learn_endpoint(endpoint)?;
        assert!(first.event.is_some());
        assert!(second.event.is_none());
        assert_eq!(first.rule.id, second.rule.id);
        Ok(())
    }

    #[test]
    fn maximum_learning_batch_is_linear_and_duplicate_safe() -> Result<(), Box<dyn Error>> {
        let interface = crate::InterfaceName::new("eth0")?;
        let port = PortRange::single(443)?;
        let mut endpoints = Vec::with_capacity(MAX_RULES);
        for index in 0..MAX_RULES {
            let offset = u32::try_from(index)?;
            endpoints.push(LearnedEndpoint {
                address: std::net::Ipv4Addr::from(0x0a00_0001_u32 + offset).into(),
                protocol: TransportProtocol::Tcp,
                port: Some(port),
                interface: Some(interface.clone()),
            });
        }

        let mut state = State::new();
        let learned = state.learn_new_endpoints(endpoints.clone(), MAX_RULES)?;
        assert_eq!(learned.len(), MAX_AUTOMATIC_LEARNED_RULES);
        assert!(learned.iter().all(|outcome| outcome.event.is_some()));
        assert_eq!(state.rules().len(), MAX_AUTOMATIC_LEARNED_RULES);
        let full_revision = state.revision();

        let duplicates = state.learn_new_endpoints(endpoints, MAX_RULES)?;
        assert!(duplicates.is_empty());
        assert_eq!(state.revision(), full_revision);
        let admission = state.application_learning_admission_index();
        let application = learned_application_endpoint(9_000, 1_000, 1)?;
        assert_eq!(
            admission.classify(&application)?,
            ApplicationLearningAdmission::Saturated
        );
        Ok(())
    }

    #[test]
    fn application_learning_enforces_per_application_and_uid_quotas() -> Result<(), Box<dyn Error>>
    {
        let limits = LearningLimits::new(8, 4)?;
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let first_application = (0..6)
            .map(|offset| learned_application_endpoint(offset, 1_000, 1))
            .collect::<Result<Vec<_>, _>>()?;
        let known_endpoint = first_application[0].clone();
        assert_eq!(
            state
                .learn_new_application_endpoints_with_limits(first_application, MAX_RULES, limits)?
                .len(),
            limits.per_application() + 1
        );

        let second_application = (6..12)
            .map(|offset| learned_application_endpoint(offset, 1_000, 2))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            state
                .learn_new_application_endpoints_with_limits(second_application, MAX_RULES, limits)?
                .len(),
            limits.per_application() + 1
        );
        assert_eq!(state.rules().len(), limits.per_uid() + 2);

        let saturated_uid = learned_application_endpoint(700, 1_000, 3)?;
        let other_uid = learned_application_endpoint(701, 1_001, 3)?;
        let mixed = state.learn_new_application_endpoints_with_limits(
            [saturated_uid.clone(), other_uid],
            MAX_RULES,
            limits,
        )?;
        assert_eq!(mixed.len(), 2);
        assert_eq!(
            mixed[0]
                .rule
                .spec
                .application
                .as_ref()
                .and_then(|app| app.uid),
            None
        );
        assert_eq!(
            mixed[1]
                .rule
                .spec
                .application
                .as_ref()
                .and_then(|app| app.uid),
            Some(1_001)
        );

        let admission = state.application_learning_admission_index_with_limits(limits);
        assert_eq!(
            admission.summary(),
            LearningQuotaSummary {
                automatic_rules: 12,
                saturated_uids: 1,
                saturated_applications: 2,
            }
        );
        assert_eq!(admission.revision(), state.revision());
        assert_eq!(admission.flow_generation(), state.flow_generation());
        assert_eq!(admission.mode(), state.mode());
        assert_eq!(
            admission.classify(&known_endpoint)?,
            ApplicationLearningAdmission::AlreadyKnown
        );
        assert_eq!(
            admission.classify(&saturated_uid)?,
            ApplicationLearningAdmission::Saturated
        );
        assert_eq!(
            admission.classify(&learned_application_endpoint(702, 1_002, 3)?)?,
            ApplicationLearningAdmission::Candidate
        );
        Ok(())
    }

    #[test]
    fn upgraded_defaults_admit_after_the_historical_512_rule_uid_limit()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        let historical_limits = LearningLimits::new(512, 256)?;
        let endpoints = (0..512)
            .map(|offset| learned_application_endpoint(offset, 1_000, u64::from(offset / 128)))
            .collect::<Result<Vec<_>, _>>()?;
        state.learn_new_application_endpoints_with_limits(
            endpoints,
            MAX_RULES,
            historical_limits,
        )?;
        let next = learned_application_endpoint(512, 1_000, 0)?;
        assert_eq!(
            state
                .application_learning_admission_index_with_limits(historical_limits)
                .classify(&next)?,
            ApplicationLearningAdmission::Saturated
        );
        assert_eq!(
            state
                .application_learning_admission_index()
                .classify(&next)?,
            ApplicationLearningAdmission::Candidate
        );
        let existing_ids: HashSet<_> = state.rules().map(|rule| rule.id).collect();
        let learned = state.learn_new_application_endpoints([next.clone()], MAX_RULES)?;
        assert_eq!(learned.len(), 1);
        assert!(learned[0].rule.spec.enabled);
        assert_eq!(learned[0].rule.spec.action, RuleAction::Accept);
        assert!(existing_ids.iter().all(|id| state.rule(*id).is_some()));
        let reloaded: State = serde_json::from_slice(&serde_json::to_vec(&state)?)?;
        reloaded.validate()?;
        assert_eq!(
            reloaded
                .application_learning_admission_index()
                .classify(&next)?,
            ApplicationLearningAdmission::AlreadyKnown
        );
        Ok(())
    }

    #[test]
    fn disabled_and_old_executable_versions_still_consume_learning_quota()
    -> Result<(), Box<dyn Error>> {
        let limits = LearningLimits::new(2, 1)?;
        let mut state = State::new();
        let old = learned_application_endpoint(30, 1_000, 1)?;
        let mut current = learned_application_endpoint(31, 1_000, 2)?;
        current.application.executable = old.application.executable.clone();
        state.learn_new_application_endpoints_with_limits(
            [old.clone(), current.clone()],
            MAX_RULES,
            limits,
        )?;
        let learned_ids: Vec<_> = state
            .rules()
            .filter(|rule| rule.spec.origin == RuleOrigin::Learned)
            .map(|rule| rule.id)
            .collect();
        for id in learned_ids {
            state.set_rule_enabled(id, false)?;
        }
        let index = state.application_learning_admission_index_with_limits(limits);
        assert_eq!(
            index.summary(),
            LearningQuotaSummary {
                automatic_rules: 3,
                saturated_uids: 1,
                saturated_applications: 2,
            }
        );
        assert_eq!(
            index.classify(&old)?,
            ApplicationLearningAdmission::AlreadyKnown
        );
        let new_endpoint = learned_application_endpoint(32, 1_000, 3)?;
        assert_eq!(
            index.classify(&new_endpoint)?,
            ApplicationLearningAdmission::Saturated
        );
        assert!(
            state
                .learn_new_application_endpoints_with_limits([new_endpoint], MAX_RULES, limits)?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn application_learning_creates_one_safe_disabled_template_per_path_and_cgroup()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        let first = learned_application_endpoint(10, 1_000, 7)?;
        let second = learned_application_endpoint(11, 1_000, 7)?;
        let outcomes = state.learn_new_application_endpoints([first, second], MAX_RULES)?;
        assert_eq!(outcomes.len(), 3);

        let templates: Vec<_> = state
            .rules()
            .filter(|rule| rule.spec.origin == RuleOrigin::Template)
            .collect();
        assert_eq!(templates.len(), 1);
        let template = templates[0];
        let template_id = template.id;
        assert!(!template.spec.enabled);
        assert_eq!(template.spec.action, RuleAction::Accept);
        assert_eq!(template.spec.direction, Direction::Outbound);
        assert_eq!(template.spec.protocol, TransportProtocol::Any);
        assert!(template.spec.peer_network.is_none());
        assert!(template.spec.port.is_none());
        assert!(template.spec.interface.is_none());
        let selector = template
            .spec
            .application
            .as_ref()
            .ok_or("template has no application selector")?;
        assert!(selector.executable.is_some());
        assert!(selector.executable_file.is_none());
        assert!(selector.command_line.is_none());
        assert!(selector.uid.is_none());
        drop(templates);
        assert_eq!(
            state.set_rule_enabled(template_id, true),
            Err(CoreError::UnpinnedApplicationIdentity)
        );
        assert!(
            !state
                .rule(template_id)
                .ok_or("template disappeared")?
                .spec
                .enabled
        );
        assert!(
            state
                .rules()
                .filter(|rule| rule.spec.origin == RuleOrigin::Learned)
                .all(|rule| rule.spec.enabled && rule.spec.action == RuleAction::Accept)
        );
        Ok(())
    }

    #[test]
    fn unpinned_application_identity_is_limited_to_the_exact_template_skeleton()
    -> Result<(), Box<dyn Error>> {
        let mut learned_state = State::new();
        let endpoint = learned_application_endpoint(12, 1_000, 12)?;
        learned_state.learn_new_application_endpoints([endpoint], MAX_RULES)?;
        let skeleton = learned_state
            .rules()
            .find(|rule| rule.spec.origin == RuleOrigin::Template)
            .ok_or("missing generated template")?
            .spec
            .clone();
        State::new().create_rule(skeleton.clone())?;

        let mut invalid = Vec::new();
        let mut changed = skeleton.clone();
        changed.origin = RuleOrigin::Manual;
        invalid.push(changed);
        let mut changed = skeleton.clone();
        changed.enabled = true;
        invalid.push(changed);
        let mut changed = skeleton.clone();
        changed.action = RuleAction::Drop;
        invalid.push(changed);
        let mut changed = skeleton.clone();
        changed.protocol = TransportProtocol::Tcp;
        invalid.push(changed);
        let mut changed = skeleton.clone();
        changed.peer_network = Some("203.0.113.0/24".parse()?);
        invalid.push(changed);
        let mut changed = skeleton.clone();
        changed.protocol = TransportProtocol::Tcp;
        changed.port = Some(PortRange::single(443)?);
        invalid.push(changed);
        let mut changed = skeleton.clone();
        changed.interface = Some(crate::InterfaceName::new("eth0")?);
        invalid.push(changed);
        let mut changed = skeleton;
        changed
            .application
            .as_mut()
            .ok_or("template selector disappeared")?
            .uid = Some(1_000);
        invalid.push(changed);

        for specification in invalid {
            assert_eq!(
                State::new().create_rule(specification),
                Err(CoreError::UnpinnedApplicationIdentity)
            );
        }
        Ok(())
    }

    #[test]
    fn disabling_an_edited_template_preserves_its_custom_specification()
    -> Result<(), Box<dyn Error>> {
        let mut learned_state = State::new();
        learned_state.learn_new_application_endpoints(
            [learned_application_endpoint(51, 1_000, 51)?],
            MAX_RULES,
        )?;
        let mut custom = learned_state
            .rules()
            .find(|rule| rule.spec.origin == RuleOrigin::Template)
            .ok_or("missing generated template")?
            .spec
            .clone();
        custom.enabled = true;
        custom.action = RuleAction::Drop;
        custom.protocol = TransportProtocol::Tcp;
        custom.peer_network = Some("203.0.113.0/24".parse()?);
        custom.port = Some(PortRange::single(443)?);
        custom
            .application
            .as_mut()
            .ok_or("template selector missing")?
            .executable_file = Some(ExecutableFileId {
            device: 8,
            inode: 51,
            size: 4_096,
            ctime_seconds: 1_700_000_000,
            ctime_nanoseconds: 0,
        });

        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        let (created, _) = state.create_rule(custom.clone())?;
        state.set_rule_enabled(created.id, false)?;
        let disabled = &state.rule(created.id).ok_or("template disappeared")?.spec;
        assert!(!disabled.enabled);
        assert_eq!(disabled.action, custom.action);
        assert_eq!(disabled.protocol, custom.protocol);
        assert_eq!(disabled.peer_network, custom.peer_network);
        assert_eq!(disabled.port, custom.port);
        assert_eq!(disabled.application, custom.application);
        Ok(())
    }

    #[test]
    fn historical_learned_groups_receive_missing_templates_without_duplicates()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        let learned = learned_application_endpoint(20, 1_000, 8)?;
        let outcome = state.insert_learned_endpoint(learned.endpoint, Some(learned.application))?;
        assert_eq!(outcome.rule.spec.action, RuleAction::Accept);
        assert_eq!(
            state.ensure_application_group_templates(MAX_RULES)?.len(),
            1
        );
        assert!(
            state
                .ensure_application_group_templates(MAX_RULES)?
                .is_empty()
        );
        assert_eq!(
            state
                .rules()
                .filter(|rule| rule.spec.origin == RuleOrigin::Template)
                .count(),
            1
        );
        Ok(())
    }

    #[test]
    fn template_migration_stops_before_the_state_byte_limit_without_mutation()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        let learned = learned_application_endpoint(21, 1_000, 9)?;
        state.insert_learned_endpoint(learned.endpoint, Some(learned.application))?;
        let before = state.clone();
        let existing_size = serde_json::to_vec(&state)?.len();

        assert!(
            state
                .ensure_application_group_templates_with_size_limit(MAX_RULES, existing_size)?
                .is_empty()
        );
        assert_eq!(state, before);
        assert_eq!(
            state.ensure_application_group_templates(MAX_RULES)?.len(),
            1
        );
        state.validate()?;
        Ok(())
    }

    #[test]
    fn admission_reserves_both_endpoint_and_missing_template_slots() -> Result<(), Box<dyn Error>> {
        let endpoint = learned_application_endpoint(22, 1_000, 10)?;
        let mut admission = State::new().application_learning_admission_index();
        admission.total_rule_count = MAX_RULES - 1;
        assert_eq!(
            admission.classify(&endpoint)?,
            ApplicationLearningAdmission::Saturated
        );

        admission.known_templates.insert(ApplicationTemplateKey {
            executable: endpoint
                .application
                .executable
                .clone()
                .ok_or("learned selector has no path")?,
            cgroup: endpoint.application.cgroup.clone(),
        });
        assert_eq!(
            admission.classify(&endpoint)?,
            ApplicationLearningAdmission::Candidate
        );
        Ok(())
    }

    #[test]
    fn learning_batch_limits_new_rules_without_losing_later_endpoints() -> Result<(), Box<dyn Error>>
    {
        let interface = crate::InterfaceName::new("eth0")?;
        let port = PortRange::single(53)?;
        let endpoints: Vec<LearnedEndpoint> = (1_u32..=300)
            .map(|offset| LearnedEndpoint {
                address: std::net::Ipv4Addr::from(0xc000_0200_u32 + offset).into(),
                protocol: TransportProtocol::Udp,
                port: Some(port),
                interface: Some(interface.clone()),
            })
            .collect();

        let mut state = State::new();
        assert_eq!(
            state.learn_new_endpoints(endpoints.clone(), 256)?.len(),
            256
        );
        assert_eq!(state.learn_new_endpoints(endpoints, 256)?.len(), 44);
        assert_eq!(state.rules().len(), 300);
        Ok(())
    }

    #[test]
    fn learning_rejects_generic_l3_endpoints() -> Result<(), Box<dyn Error>> {
        let endpoint = LearnedEndpoint {
            address: "2001:db8::7".parse()?,
            protocol: TransportProtocol::Any,
            port: None,
            interface: Some(crate::InterfaceName::new("tun0")?),
        };
        let mut state = State::new();
        assert!(matches!(
            state.learn_endpoint(endpoint),
            Err(CoreError::Validation(
                ValidationError::UnsupportedLearnedProtocol
            ))
        ));
        assert!(state.rules().next().is_none());
        Ok(())
    }

    #[test]
    fn counter_events_do_not_mutate_persisted_state() {
        let state = State::new();
        let before = state.clone();
        let counters = FirewallCounters::default();
        let event = state.counters_event(counters.clone(), Utc::now());
        assert_eq!(event.revision, state.revision());
        assert_eq!(event.kind, EventKind::CountersUpdated { counters });
        assert_eq!(state, before);
    }

    #[test]
    fn clock_rollback_keeps_rule_mutations_available_and_timestamps_monotonic()
    -> Result<(), Box<dyn Error>> {
        let mut state = State::new();
        let id = Uuid::new_v4();
        state.create_rule_at(id, test_spec("clock")?, fixed_time()?)?;
        let earlier = Utc
            .with_ymd_and_hms(2026, 8, 20, 11, 59, 59)
            .single()
            .ok_or("invalid earlier test time")?;
        let (disabled, _) = state.set_rule_enabled_at(id, false, earlier)?;
        assert!(!disabled.spec.enabled);
        assert_eq!(disabled.updated_at, fixed_time()?);

        let mut updated_spec = test_spec("updated during rollback")?;
        updated_spec.enabled = false;
        let (updated, _) = state.update_rule_at(id, updated_spec, earlier)?;
        assert_eq!(updated.spec.name.as_str(), "updated during rollback");
        assert_eq!(updated.updated_at, fixed_time()?);
        Ok(())
    }
}
