use std::collections::{HashMap, HashSet};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use nix::errno::Errno;
use nix::net::if_::if_indextoname;
use nix::poll::{PollFd, PollFlags, poll};
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, getsockname,
    recv, sendto, socket,
};
use openshield_core::{
    APPLICATION_LEARNING_QUEUE_NUMBER, APPLICATION_QUEUE_NUMBER, InterfaceName,
    LearnedApplicationEndpoint, LearnedEndpoint, Mode, RuleAction, TransportProtocol,
    application_handoff_mark, application_pending_mark, application_reject_mark,
};
use tracing::{error, info, warn};

use crate::application::{
    ApplicationDecisionPolicy, IdentityCaptureRequirements, MAX_ATTRIBUTION_BATCH_SIZE,
    OutboundConnection, ProcfsResolver, is_attribution_timeout,
};
use crate::backend::QueueVerdictStrategy;
use crate::engine::{LearningQueueAdmission, NfqueueRuntimeCounters, SharedEngine};

#[path = "nfqueue_enforcing.rs"]
mod enforcing;
#[path = "nfqueue_reply.rs"]
mod reply;
#[path = "nfqueue_scheduler.rs"]
mod scheduler;

const NFNL_SUBSYS_QUEUE: u16 = 3;
const NFQNL_MSG_PACKET: u16 = 0;
const NFQNL_MSG_VERDICT: u16 = 1;
const NFQNL_MSG_CONFIG: u16 = 2;
const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_CFG_CMD_UNBIND: u8 = 2;
const NFQNL_COPY_PACKET: u8 = 2;
const NFQA_PACKET_HDR: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_MARK: u16 = 3;
const NFQA_IFINDEX_OUTDEV: u16 = 6;
const NFQA_PAYLOAD: u16 = 10;
const NFQA_CAP_LEN: u16 = 13;
const NFQA_SKB_INFO: u16 = 14;
const NFQA_UID: u16 = 16;
const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
const NFQA_CFG_MASK: u16 = 4;
const NFQA_CFG_FLAGS: u16 = 5;
const NFQA_CFG_F_FAIL_OPEN: u32 = 1;
const NFQA_CFG_F_GSO: u32 = 1 << 2;
const NFQA_CFG_F_UID_GID: u32 = 1 << 3;
const NFQA_SKB_GSO: u32 = 1 << 1;
const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;
const NF_REPEAT: u32 = 4;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLMSG_ERROR: u16 = 2;
const NETLINK_HEADER_BYTES: usize = 16;
const NFGENMSG_BYTES: usize = 4;
const ATTRIBUTE_HEADER_BYTES: usize = 4;
const PACKET_HEADER_BYTES: usize = 7;
const COPY_RANGE: u32 = 512;
const QUEUE_MAX_LENGTH: u32 = 256;
const RECEIVE_BUFFER_BYTES: usize = 128 * 1024;
const RECEIVE_POLL_MILLIS: u16 = 100;
const CONFIGURATION_TIMEOUT: Duration = Duration::from_secs(1);
const CONFIGURATION_POLL_MILLIS: u16 = 100;
const LEARNING_QUEUE_CAPACITY: usize = 512;
const LEARNING_BATCH_SIZE: usize = 256;
const LEARNING_TCP_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const LEARNING_DATAGRAM_COALESCE_INTERVAL: Duration = Duration::from_millis(100);
const LEARNING_TCP_RECENT_CAPACITY: usize = 512;
const LEARNING_FIRST_PACKET_WAIT: Duration = Duration::from_millis(250);
const LEARNING_PENDING_CAPACITY: usize = 128;
const LEARNING_PENDING_POLL_MILLIS: u16 = 5;
const LEARNING_SEEN_FLOW_TTL: Duration = Duration::from_secs(60);
const NFNETLINK_FAMILY_UNSPEC: u8 = 0;
const MAX_PACKET_BATCH_SIZE: usize = MAX_ATTRIBUTION_BATCH_SIZE;

#[derive(Debug)]
pub struct QueueRuntime {
    packet_threads: Vec<JoinHandle<()>>,
    attribution_thread: JoinHandle<()>,
    learning_thread: JoinHandle<()>,
    counters: Arc<NfqueueRuntimeCounters>,
}

impl QueueRuntime {
    pub fn join(self) -> Result<()> {
        let Self {
            packet_threads,
            attribution_thread,
            learning_thread,
            counters,
        } = self;
        let mut packet_panicked = false;
        for packet_thread in packet_threads {
            packet_panicked |= packet_thread.join().is_err();
        }
        let attribution = attribution_thread.join();
        let learning = learning_thread.join();
        if packet_panicked || attribution.is_err() || learning.is_err() {
            counters.record_terminal_queue_error();
            bail!("application quarantine worker terminated unexpectedly");
        }
        Ok(())
    }
}

#[allow(clippy::too_many_lines)]
pub fn spawn(
    engine: &SharedEngine,
    shutdown: &Arc<AtomicBool>,
    verdict_strategy: QueueVerdictStrategy,
) -> Result<QueueRuntime> {
    let counters = engine
        .lock()
        .map_err(|_| anyhow!("policy engine mutex is poisoned during NFQUEUE startup"))?
        .nfqueue_counters();
    // Separate fixed queues make overflow semantics a property of the policy
    // mode without a racy userspace reconfiguration window. Enforcing only
    // references the fail-closed queue; Learning only references the queue
    // whose kernel overflow verdict is Accept.
    let enforcing_queue = QueueSocket::open(APPLICATION_QUEUE_NUMBER, false)
        .context("cannot bind the fail-closed application packet queue")?;
    let learning_queue = QueueSocket::open(APPLICATION_LEARNING_QUEUE_NUMBER, true)
        .context("cannot bind the fail-open Learning observation queue")?;
    let reply_queue = QueueSocket::open(openshield_core::APPLICATION_REPLY_QUEUE_NUMBER, false)
        .context("cannot bind the fail-closed application reply retry queue")?;
    let reply_registry = reply::shared_registry(enforcing_queue.port_id()?)?;
    // Validate the real service's procfs view while the bootstrap BlockAll
    // policy is still installed, before workers or desired policy activation.
    // A successful socket bind alone does not prove reply scheduling can work
    // (notably with systemd ProcSubset=pid hiding nested network proc entries).
    reply::verify_startup_progress(&reply_registry).context(
        "cannot initialize application reply scheduling; network procfs must be readable",
    )?;
    let (learning_sender, learning_receiver) = mpsc::sync_channel(LEARNING_QUEUE_CAPACITY);
    let (attribution_sender, attribution_receiver) = mpsc::sync_channel(LEARNING_QUEUE_CAPACITY);
    let (completion_sender, completion_receiver) = mpsc::sync_channel(LEARNING_PENDING_CAPACITY);
    let learning_engine = Arc::clone(engine);
    let learning_shutdown = Arc::clone(shutdown);
    let learning_counters = Arc::clone(&counters);
    let learning_thread = thread::Builder::new()
        .name("openshield-app-learning".to_owned())
        .spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                learning_loop(
                    &learning_receiver,
                    &learning_engine,
                    &learning_shutdown,
                    &learning_counters,
                );
            }));
            if let Err(payload) = outcome {
                error!("application-learning worker panicked; entering fail-closed quarantine");
                // Stop the packet worker first so dropping its NFQUEUE socket
                // is an independent fail-closed boundary even if quarantine
                // persistence encounters another unexpected failure.
                learning_shutdown.store(true, Ordering::Release);
                quarantine_engine(&learning_engine);
                std::panic::resume_unwind(payload);
            }
        })
        .context("cannot spawn bounded application-learning worker")?;

    let attribution_engine = Arc::clone(engine);
    let attribution_shutdown = Arc::clone(shutdown);
    let attribution_counters = Arc::clone(&counters);
    let attribution_learning_sender = learning_sender.clone();
    let attribution_thread = match thread::Builder::new()
        .name("openshield-learning-attribution".to_owned())
        .spawn(move || {
            learning_attribution_loop(
                &attribution_receiver,
                &completion_sender,
                &attribution_learning_sender,
                &attribution_engine,
                &attribution_shutdown,
                &attribution_counters,
            );
        }) {
        Ok(thread) => thread,
        Err(error) => {
            shutdown.store(true, Ordering::Release);
            drop(attribution_sender);
            drop(learning_sender);
            let _ignored = learning_thread.join();
            return Err(error).context("cannot spawn asynchronous Learning attribution worker");
        }
    };

    let mut packet_threads = Vec::with_capacity(3);
    let mut completion_receiver = Some(completion_receiver);
    for (name, queue, queue_verdict_strategy, role) in [
        (
            "openshield-nfqueue-enforcing",
            enforcing_queue,
            verdict_strategy,
            QueueRole::Enforcing,
        ),
        (
            "openshield-nfqueue-learning",
            learning_queue,
            QueueVerdictStrategy::Accept,
            QueueRole::Learning,
        ),
        (
            "openshield-nfqueue-reply",
            reply_queue,
            QueueVerdictStrategy::Accept,
            QueueRole::Reply,
        ),
    ] {
        let packet_engine = Arc::clone(engine);
        let packet_shutdown = Arc::clone(shutdown);
        let packet_counters = Arc::clone(&counters);
        let packet_learning_sender = learning_sender.clone();
        let packet_attribution_sender = attribution_sender.clone();
        let packet_reply_registry = Arc::clone(&reply_registry);
        let packet_completions = if role == QueueRole::Learning {
            completion_receiver.take()
        } else {
            None
        };
        let packet_thread = thread::Builder::new().name(name.to_owned()).spawn(move || {
            packet_loop(
                queue,
                &packet_engine,
                &packet_shutdown,
                &packet_learning_sender,
                &packet_attribution_sender,
                packet_completions.as_ref(),
                queue_verdict_strategy,
                role,
                &packet_counters,
                &packet_reply_registry,
            );
        });
        match packet_thread {
            Ok(thread) => packet_threads.push(thread),
            Err(error) => {
                shutdown.store(true, Ordering::Release);
                for thread in packet_threads {
                    let _ignored = thread.join();
                }
                drop(attribution_sender);
                drop(learning_sender);
                let _ignored = attribution_thread.join();
                let _ignored = learning_thread.join();
                return Err(error).context("cannot spawn application packet worker");
            }
        }
    }
    drop(attribution_sender);
    drop(learning_sender);

    Ok(QueueRuntime {
        packet_threads,
        attribution_thread,
        learning_thread,
        counters,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueueRole {
    Enforcing,
    Learning,
    Reply,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn packet_loop(
    mut queue: QueueSocket,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    learning: &SyncSender<LearningObservation>,
    attribution: &SyncSender<LearningAttributionWork>,
    completions: Option<&Receiver<LearningVerdictTicket>>,
    verdict_strategy: QueueVerdictStrategy,
    role: QueueRole,
    counters: &NfqueueRuntimeCounters,
    reply_registry: &reply::SharedRegistry,
) {
    if role == QueueRole::Reply {
        reply::run(queue, engine, shutdown, counters, reply_registry);
        return;
    }
    if role == QueueRole::Enforcing {
        enforcing::run(
            queue,
            engine,
            shutdown,
            learning,
            attribution,
            verdict_strategy,
            counters,
            reply_registry,
        );
        return;
    }
    let mut receive_buffer = vec![0_u8; RECEIVE_BUFFER_BYTES];
    let mut errors = ErrorThrottle::default();
    let mut observations = LearningAttributionDebounce::default();
    let mut pending = PendingLearningVerdicts::default();

    while !shutdown.load(Ordering::Acquire) {
        if let Some(completions) = completions
            && let Err(error) = release_learning_verdicts(
                &mut queue,
                &mut pending,
                completions,
                engine,
                shutdown,
                counters,
                Instant::now(),
            )
        {
            handle_packet_queue_failure(
                role,
                engine,
                shutdown,
                counters,
                &mut errors,
                &format!("cannot return pending Learning verdict: {error:#}"),
            );
            return;
        }
        let received = queue.receive(&mut receive_buffer, pending.poll_millis());
        match received {
            Ok(QueueReceive::Idle | QueueReceive::Interrupted) => {}
            Ok(QueueReceive::Overflow) => {
                counters.record_queue_overflow();
                errors.report(queue.overflow_message());
            }
            Ok(QueueReceive::Datagram(size)) => {
                let mut batch = Vec::with_capacity(MAX_PACKET_BATCH_SIZE);
                let collected = append_packet_datagram(&receive_buffer[..size], &mut batch);
                if let Err(error) = collected {
                    handle_packet_queue_failure(
                        role,
                        engine,
                        shutdown,
                        counters,
                        &mut errors,
                        &format!("invalid netfilter netlink message: {error:#}"),
                    );
                    return;
                }
                let result = match role {
                    QueueRole::Learning => return_learning_batch_verdicts(
                        &mut queue,
                        batch,
                        engine,
                        shutdown,
                        attribution,
                        counters,
                        &mut errors,
                        &mut observations,
                        &mut pending,
                    ),
                    QueueRole::Enforcing | QueueRole::Reply => {
                        Err(anyhow!("non-Learning queue reached the Learning reader"))
                    }
                };
                if let Err(error) = result {
                    handle_packet_queue_failure(
                        role,
                        engine,
                        shutdown,
                        counters,
                        &mut errors,
                        &format!("cannot return packet verdict: {error:#}"),
                    );
                    return;
                }
            }
            Err(error) => {
                handle_packet_queue_failure(
                    role,
                    engine,
                    shutdown,
                    counters,
                    &mut errors,
                    &format!("application packet queue failed: {error:#}"),
                );
                return;
            }
        }
    }
}

fn handle_packet_queue_failure(
    role: QueueRole,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    counters: &NfqueueRuntimeCounters,
    errors: &mut ErrorThrottle,
    message: &str,
) {
    counters.record_terminal_queue_error();
    errors.report(message);
    if role == QueueRole::Learning {
        // Queue 1338 is observational and both nftables and iptables install
        // it with kernel bypass/fail-open semantics. Dropping only this socket
        // disables further attribution while leaving Learning traffic on the
        // declared allow path. Enforcing queue 1337 remains fail-closed.
        warn!(
            "Learning observation queue stopped; outbound traffic remains allowed by kernel bypass"
        );
    } else {
        quarantine_engine(engine);
        shutdown.store(true, Ordering::Release);
    }
}

#[allow(clippy::too_many_arguments)]
fn return_learning_batch_verdicts(
    queue: &mut impl LearningVerdictSink,
    batch: Vec<QueuedPacketWork>,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    attribution: &SyncSender<LearningAttributionWork>,
    counters: &NfqueueRuntimeCounters,
    errors: &mut ErrorThrottle,
    observations: &mut LearningAttributionDebounce,
    pending: &mut PendingLearningVerdicts,
) -> Result<()> {
    for work in batch {
        ensure!(
            !pending.packets.contains_key(&work.packet_id),
            "Learning queue reused an outstanding packet id"
        );
        // Serialize admission/verdicts with policy changes. Identity capture
        // itself must never hold this mutex or block this queue reader.
        let Ok(guard) = engine.lock() else {
            quarantine_engine(engine);
            shutdown.store(true, Ordering::Release);
            bail!("policy engine mutex is poisoned during Learning verdict");
        };
        let (mode, flow_generation) = match guard.application_decision_identity() {
            Ok(identity) => identity,
            Err(error) => {
                drop(guard);
                quarantine_engine(engine);
                shutdown.store(true, Ordering::Release);
                bail!(error.message);
            }
        };
        if mode != Mode::Learning || shutdown.load(Ordering::Acquire) {
            queue.verdict(work.packet_id, NF_DROP)?;
            counters.record_denied();
            continue;
        }
        let now = Instant::now();
        if let Ok(packet) = &work.packet
            && packet.initial_observation
            && !pending.seen(flow_generation, &packet.connection, now)
            && let Some(ticket) = pending.reserve(work.packet_id, flow_generation, now)?
        {
            let connection = packet.connection.clone();
            if submit_learning_attribution(
                LearningAttributionWork {
                    flow_generation,
                    packet: packet.clone(),
                    ticket: Some(ticket),
                },
                attribution,
                counters,
                errors,
            ) {
                pending.mark_seen(flow_generation, connection.clone(), now);
                observations.should_enqueue(flow_generation, &connection, now);
                // Capture completion or the fixed deadline will return this
                // verdict, after a fresh mode AND generation check.
                continue;
            }
            pending.cancel(ticket);
            // Backlog exhaustion is not authorization. Only the currently
            // locked Learning policy permits this immediate fallback.
            queue.verdict(work.packet_id, NF_ACCEPT)?;
            continue;
        }
        queue.verdict(work.packet_id, NF_ACCEPT)?;
        drop(guard);
        // Coalesce observations before the bounded background channel, not
        // just after it: otherwise repeated packets occupy every slot while
        // a desktop-sized /proc scan is still running. The verdict above is
        // already final; this scheduling hint is never consulted by q1337.
        if let Ok(packet) = &work.packet
            && !observations.should_enqueue(flow_generation, &packet.connection, Instant::now())
        {
            continue;
        }
        let connection = work
            .packet
            .as_ref()
            .ok()
            .map(|packet| packet.connection.clone());
        if enqueue_learning_attribution(work.packet, flow_generation, attribution, counters, errors)
            && let Some(connection) = connection
        {
            pending.mark_seen(flow_generation, connection, now);
        }
    }
    Ok(())
}

fn enqueue_learning_attribution(
    packet: std::result::Result<QueuedPacket, String>,
    flow_generation: u32,
    attribution: &SyncSender<LearningAttributionWork>,
    counters: &NfqueueRuntimeCounters,
    errors: &mut ErrorThrottle,
) -> bool {
    let packet = match packet {
        Ok(packet) => packet,
        Err(error) => {
            errors.report(&format!(
                "Learning admitted packet but could not parse its observation: {error}"
            ));
            return false;
        }
    };
    let observation = LearningAttributionWork {
        flow_generation,
        packet,
        ticket: None,
    };
    submit_learning_attribution(observation, attribution, counters, errors)
}

fn submit_learning_attribution(
    observation: LearningAttributionWork,
    attribution: &SyncSender<LearningAttributionWork>,
    counters: &NfqueueRuntimeCounters,
    errors: &mut ErrorThrottle,
) -> bool {
    match attribution.try_send(observation) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            counters.record_queue_overflow();
            errors.report("Learning admitted packet but the bounded attribution backlog was full");
            false
        }
        Err(TrySendError::Disconnected(_)) => {
            errors.report(
                "Learning admitted packet but the asynchronous attribution worker was unavailable",
            );
            false
        }
    }
}

/// Only the q1338 reader owns the actual verdict socket. Completion messages
/// carry no verdict or identity and cannot authorize a packet themselves.
trait LearningVerdictSink {
    fn verdict(&mut self, packet_id: u32, verdict: u32) -> Result<()>;
}

impl LearningVerdictSink for QueueSocket {
    fn verdict(&mut self, packet_id: u32, verdict: u32) -> Result<()> {
        Self::verdict(self, packet_id, verdict)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LearningVerdictTicket {
    packet_id: u32,
    serial: u64,
    flow_generation: u32,
}

#[derive(Debug)]
struct PendingLearningVerdict {
    ticket: LearningVerdictTicket,
    deadline: Instant,
    completed: bool,
}

/// Bounded scheduling state only: no identities or authorization decisions.
/// Flow hints suppress repeated holds, never checks in the Enforcing queue.
#[derive(Debug, Default)]
struct PendingLearningVerdicts {
    last_serial: u64,
    packets: HashMap<u32, PendingLearningVerdict>,
    seen_generation: Option<u32>,
    seen_flows: HashMap<OutboundConnection, Instant>,
}

impl PendingLearningVerdicts {
    fn poll_millis(&self) -> u16 {
        if self.packets.is_empty() {
            RECEIVE_POLL_MILLIS
        } else {
            LEARNING_PENDING_POLL_MILLIS
        }
    }

    fn reserve(
        &mut self,
        packet_id: u32,
        flow_generation: u32,
        now: Instant,
    ) -> Result<Option<LearningVerdictTicket>> {
        ensure!(
            !self.packets.contains_key(&packet_id),
            "Learning queue reused an outstanding packet id"
        );
        if self.packets.len() >= LEARNING_PENDING_CAPACITY {
            return Ok(None);
        }
        let Some(serial) = self.last_serial.checked_add(1) else {
            // Exhaustion loses a scheduling optimization, never reuses a
            // ticket that a late completion could still carry.
            return Ok(None);
        };
        self.last_serial = serial;
        let ticket = LearningVerdictTicket {
            packet_id,
            serial,
            flow_generation,
        };
        self.packets.insert(
            packet_id,
            PendingLearningVerdict {
                ticket,
                deadline: now + LEARNING_FIRST_PACKET_WAIT,
                completed: false,
            },
        );
        Ok(Some(ticket))
    }

    fn cancel(&mut self, ticket: LearningVerdictTicket) {
        if self
            .packets
            .get(&ticket.packet_id)
            .is_some_and(|pending| pending.ticket == ticket)
        {
            self.packets.remove(&ticket.packet_id);
        }
    }

    fn complete(&mut self, ticket: LearningVerdictTicket) {
        if let Some(pending) = self.packets.get_mut(&ticket.packet_id)
            && pending.ticket == ticket
        {
            pending.completed = true;
        }
    }

    fn refresh_seen(&mut self, generation: u32, now: Instant) {
        if self.seen_generation != Some(generation) {
            self.seen_flows.clear();
            self.seen_generation = Some(generation);
        }
        self.seen_flows
            .retain(|_, seen| now.saturating_duration_since(*seen) < LEARNING_SEEN_FLOW_TTL);
    }

    fn seen(&mut self, generation: u32, connection: &OutboundConnection, now: Instant) -> bool {
        self.refresh_seen(generation, now);
        self.seen_flows.contains_key(connection)
    }

    fn mark_seen(&mut self, generation: u32, connection: OutboundConnection, now: Instant) {
        self.refresh_seen(generation, now);
        if self.seen_flows.contains_key(&connection) {
            return;
        }
        if self.seen_flows.len() >= LEARNING_TCP_RECENT_CAPACITY
            && let Some(oldest) = self
                .seen_flows
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(connection, _)| connection.clone())
        {
            self.seen_flows.remove(&oldest);
        }
        self.seen_flows.insert(connection, now);
    }
}

#[allow(clippy::too_many_arguments)]
fn release_learning_verdicts(
    queue: &mut impl LearningVerdictSink,
    pending: &mut PendingLearningVerdicts,
    completions: &Receiver<LearningVerdictTicket>,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    counters: &NfqueueRuntimeCounters,
    now: Instant,
) -> Result<()> {
    for _ in 0..LEARNING_PENDING_CAPACITY {
        match completions.try_recv() {
            Ok(ticket) => pending.complete(ticket),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
        }
    }
    if pending.packets.is_empty() {
        return Ok(());
    }
    let Ok(guard) = engine.lock() else {
        quarantine_engine(engine);
        shutdown.store(true, Ordering::Release);
        bail!("policy engine mutex is poisoned during deferred Learning verdict");
    };
    let (mode, generation) = match guard.application_decision_identity() {
        Ok(identity) => identity,
        Err(error) => {
            drop(guard);
            quarantine_engine(engine);
            shutdown.store(true, Ordering::Release);
            bail!(error.message);
        }
    };
    let ready = pending
        .packets
        .values()
        .filter(|packet| {
            packet.completed
                || now >= packet.deadline
                || mode != Mode::Learning
                || packet.ticket.flow_generation != generation
                || shutdown.load(Ordering::Acquire)
        })
        .map(|packet| packet.ticket)
        .collect::<Vec<_>>();
    for ticket in ready {
        let accept = mode == Mode::Learning
            && ticket.flow_generation == generation
            && !shutdown.load(Ordering::Acquire);
        queue.verdict(ticket.packet_id, if accept { NF_ACCEPT } else { NF_DROP })?;
        if !accept {
            counters.record_denied();
        }
        pending.cancel(ticket);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn return_enforcing_verdict(
    queue: &mut QueueSocket,
    packet: QueuedPacketWork,
    decision: Result<PacketAuthorization>,
    ticket: Option<reply::OutgoingTicket>,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    attribution: &SyncSender<LearningAttributionWork>,
    verdict_strategy: QueueVerdictStrategy,
    counters: &NfqueueRuntimeCounters,
    errors: &mut ErrorThrottle,
    reply_registry: &reply::SharedRegistry,
) -> Result<()> {
    let timing = crate::application_timing::TimingScope::new(
        crate::application_timing::TimingStage::QueueVerdict,
        1,
    );
    let deferred_learning = decision
        .as_ref()
        .ok()
        .filter(|authorization| authorization.defer_learning_attribution)
        .map(|authorization| authorization.flow_generation);
    let deferred_packet = deferred_learning.and_then(|_| packet.packet.ok());
    let attribution_timed_out = match &decision {
        Ok(authorization) => authorization
            .observation_error
            .as_ref()
            .is_some_and(is_attribution_timeout),
        Err(error) => is_attribution_timeout(error),
    };
    if attribution_timed_out {
        counters.record_attribution_timeout();
    }
    let (accepted, decision_error) = return_packet_verdict(
        queue,
        packet.packet_id,
        decision,
        engine,
        shutdown,
        verdict_strategy,
    )?;
    reply::complete_outgoing(reply_registry, ticket, accepted && decision_error.is_none())?;
    // Advance only after the actual verdict send, including denied,
    // malformed and TCP packets that have no per-flow reply ticket.
    reply::record_outgoing_verdict(reply_registry, packet.packet_id)?;
    if !accepted {
        counters.record_denied();
    }
    if let Some(error) = decision_error {
        let context = if accepted {
            "Learning admitted packet but skipped its observation"
        } else {
            "application packet denied"
        };
        errors.report(&format!("{context}: {error:#}"));
    }
    if accepted && let (Some(flow_generation), Some(packet)) = (deferred_learning, deferred_packet)
    {
        enqueue_learning_attribution(Ok(packet), flow_generation, attribution, counters, errors);
    }
    timing.finish(usize::from(!accepted));
    Ok(())
}

fn return_packet_verdict(
    queue: &mut QueueSocket,
    packet_id: u32,
    decision: Result<PacketAuthorization>,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    verdict_strategy: QueueVerdictStrategy,
) -> Result<(bool, Option<anyhow::Error>)> {
    let authorization = match decision {
        Ok(authorization) => authorization,
        Err(error) => {
            queue.verdict(packet_id, NF_DROP)?;
            return Ok((false, Some(error)));
        }
    };
    let Ok(guard) = engine.lock() else {
        let error = anyhow!("policy engine mutex is poisoned during decision recheck");
        quarantine_engine(engine);
        shutdown.store(true, Ordering::Release);
        queue.verdict(packet_id, NF_DROP)?;
        return Ok((false, Some(error)));
    };
    let (current_mode, current_flow_generation) = match guard.application_decision_identity() {
        Ok(current) => current,
        Err(error) => {
            drop(guard);
            quarantine_engine(engine);
            shutdown.store(true, Ordering::Release);
            queue.verdict(packet_id, NF_DROP)?;
            return Ok((false, Some(anyhow!(error.message))));
        }
    };
    if !authorization_remains_valid(
        &authorization,
        current_mode,
        current_flow_generation,
        shutdown.load(Ordering::Acquire),
    ) {
        drop(guard);
        queue.verdict(packet_id, NF_DROP)?;
        return Ok((
            false,
            Some(anyhow!(
                "policy changed or shutdown started while application identity was resolved"
            )),
        ));
    }

    // Netfilter processes the verdict and reinjects the packet synchronously
    // inside sendto(2). Retaining the engine guard until it returns prevents
    // an atomic policy reload between this final recheck and the kernel
    // authorization path. nftables continues in its later base chain after
    // NF_ACCEPT and deliberately keeps the pending mark unchanged. iptables
    // queues from the last mangle/OUTPUT rule and attaches a kernel verdict
    // mark to NF_ACCEPT; its first filter rule then consumes that mark.
    let (verdict_code, verdict_mark) = authorization_verdict(
        authorization.action,
        verdict_strategy,
        authorization.packet_mark,
    );
    let accepted = authorization.action == RuleAction::Accept;
    let observation_error = authorization.observation_error;
    let verdict = match verdict_mark {
        Some(mark) => queue.verdict_with_mark(packet_id, verdict_code, mark),
        None => queue.verdict(packet_id, verdict_code),
    };
    drop(guard);
    verdict?;
    Ok((accepted, observation_error))
}

fn authorization_remains_valid(
    authorization: &PacketAuthorization,
    current_mode: Mode,
    current_flow_generation: u32,
    stopping: bool,
) -> bool {
    !stopping
        && current_mode == authorization.mode
        && current_flow_generation == authorization.flow_generation
}

fn authorization_verdict(
    action: RuleAction,
    strategy: QueueVerdictStrategy,
    packet_mark: u32,
) -> (u32, Option<u32>) {
    match (action, strategy) {
        (RuleAction::Accept, QueueVerdictStrategy::Accept) => (NF_ACCEPT, None),
        (RuleAction::Accept, QueueVerdictStrategy::RepeatWithHandoffMark) => {
            (NF_REPEAT, Some(application_handoff_mark(packet_mark)))
        }
        (RuleAction::Drop, _) => (NF_DROP, None),
        (RuleAction::Reject, QueueVerdictStrategy::Accept) => {
            (NF_ACCEPT, Some(application_reject_mark(packet_mark)))
        }
        (RuleAction::Reject, QueueVerdictStrategy::RepeatWithHandoffMark) => {
            (NF_REPEAT, Some(application_reject_mark(packet_mark)))
        }
    }
}

fn append_packet_datagram(bytes: &[u8], batch: &mut Vec<QueuedPacketWork>) -> Result<()> {
    for message in NetlinkMessages::new(bytes) {
        let message = message?;
        if message.message_type != queue_message_type(NFQNL_MSG_PACKET) {
            continue;
        }
        ensure!(
            batch.len() < MAX_PACKET_BATCH_SIZE,
            "queued packet batch exceeds its fixed bound"
        );
        let packet_id = packet_id(message.payload)
            .ok_or_else(|| anyhow!("queued packet has no bounded packet identifier"))?;
        batch.push(QueuedPacketWork {
            packet_id,
            packet: parse_queued_packet(message.payload).map_err(|error| format!("{error:#}")),
        });
    }
    Ok(())
}

#[cfg(test)]
fn decide_packet_batch(
    batch: &[QueuedPacketWork],
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    resolver: &ProcfsResolver,
    learning: &SyncSender<LearningObservation>,
) -> Vec<Result<PacketAuthorization>> {
    decide_packet_batch_until(
        batch,
        engine,
        shutdown,
        resolver,
        learning,
        Instant::now() + Duration::from_secs(2),
    )
}

fn decide_packet_batch_until(
    batch: &[QueuedPacketWork],
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    resolver: &ProcfsResolver,
    learning: &SyncSender<LearningObservation>,
    deadline: Instant,
) -> Vec<Result<PacketAuthorization>> {
    let mut decisions = (0..batch.len()).map(|_| None).collect::<Vec<_>>();
    let snapshot = (|| {
        engine
            .lock()
            .map_err(|_| anyhow!("policy engine mutex is poisoned"))?
            .application_decision_snapshot()
            .map_err(|error| anyhow!(error.message))
    })();
    let snapshot = match snapshot {
        Ok(snapshot) => snapshot,
        Err(error) => {
            quarantine_engine(engine);
            shutdown.store(true, Ordering::Release);
            let message = format!("{error:#}");
            return batch
                .iter()
                .map(|packet| match &packet.packet {
                    Ok(_) => Err(anyhow!(message.clone())),
                    Err(error) => Err(anyhow!(error.clone())),
                })
                .collect();
        }
    };

    let mut request_indexes = Vec::new();
    let mut requests = Vec::new();
    for (index, work) in batch.iter().enumerate() {
        let packet = match &work.packet {
            Ok(packet) => packet,
            Err(error) => {
                decisions[index] = Some(Err(anyhow!(error.clone())));
                continue;
            }
        };
        match packet_attribution_plan(&snapshot, packet) {
            Ok(PacketAttributionPlan::Resolve(requirements)) => {
                request_indexes.push(index);
                requests.push((&packet.connection, requirements));
            }
            Ok(PacketAttributionPlan::AcceptNetworkFallback) => {
                decisions[index] = Some(Ok(PacketAuthorization {
                    mode: snapshot.mode,
                    flow_generation: snapshot.flow_generation,
                    packet_mark: packet.packet_mark,
                    action: RuleAction::Accept,
                    observation_error: None,
                    defer_learning_attribution: false,
                }));
            }
            Ok(PacketAttributionPlan::AcceptAndObserveLearning) => {
                decisions[index] = Some(Ok(PacketAuthorization {
                    mode: snapshot.mode,
                    flow_generation: snapshot.flow_generation,
                    packet_mark: packet.packet_mark,
                    action: RuleAction::Accept,
                    observation_error: None,
                    defer_learning_attribution: true,
                }));
            }
            Err(error) => {
                decisions[index] = Some(Err(error));
            }
        }
    }

    let identities = resolver.resolve_batch_for_enforcement_until(&requests, deadline);
    for (index, identity) in request_indexes.into_iter().zip(identities) {
        let packet = batch[index]
            .packet
            .as_ref()
            .map_err(|error| anyhow!(error.clone()));
        decisions[index] = Some(match (packet, identity) {
            (Ok(packet), Ok(identity)) => authorize_attributed_packet(
                &snapshot, packet, &identity, engine, shutdown, learning,
            ),
            (Err(error), _) => Err(error),
            (_, Err(error)) => Err(error.context("cannot establish race-checked process identity")),
        });
    }

    decisions
        .into_iter()
        .map(|decision| {
            decision.unwrap_or_else(|| Err(anyhow!("batched packet decision is unavailable")))
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketAttributionPlan {
    Resolve(IdentityCaptureRequirements),
    AcceptNetworkFallback,
    AcceptAndObserveLearning,
}

fn packet_attribution_plan(
    snapshot: &ApplicationDecisionPolicy,
    packet: &QueuedPacket,
) -> Result<PacketAttributionPlan> {
    if packet.packet_mark != application_pending_mark(packet.packet_mark) {
        bail!("queued packet does not carry the kernel pending-mark domain");
    }
    match snapshot.mode {
        Mode::BlockAll => bail!("BlockAll denies queued traffic"),
        Mode::Learning => Ok(snapshot
            .deny_capture_requirements(&packet.connection)
            .map_or(PacketAttributionPlan::AcceptAndObserveLearning, |requirements| {
                PacketAttributionPlan::Resolve(requirements)
            })),
        Mode::Enforcing => snapshot
            .enforcement_capture_requirements(&packet.connection)
            .map(PacketAttributionPlan::Resolve)
            .or_else(|| {
                snapshot
                    .matching_network_accept(&packet.connection)
                    .map(|_| PacketAttributionPlan::AcceptNetworkFallback)
            })
            .ok_or_else(|| {
                anyhow!(
                    "no enabled application rule or network fallback matches the queued endpoint and socket UID"
                )
            }),
    }
}

#[allow(clippy::too_many_lines)]
fn authorize_attributed_packet(
    snapshot: &ApplicationDecisionPolicy,
    packet: &QueuedPacket,
    identity: &openshield_core::ApplicationIdentity,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    learning: &SyncSender<LearningObservation>,
) -> Result<PacketAuthorization> {
    let action = match snapshot.mode {
        Mode::BlockAll => bail!("BlockAll denies queued traffic"),
        Mode::Enforcing => snapshot
            .matching_rule(&packet.connection, identity)
            .map(|rule| rule.spec.action)
            .ok_or_else(|| {
                anyhow!(
                    "no enabled application rule matched: {}",
                    crate::application_diagnostics::rule_mismatch_summary(
                        snapshot,
                        &packet.connection,
                        identity,
                    )
                )
            })?,
        Mode::Learning => {
            if let Some(rule) = snapshot.matching_deny_rule(&packet.connection, identity) {
                return Ok(PacketAuthorization {
                    mode: snapshot.mode,
                    flow_generation: snapshot.flow_generation,
                    packet_mark: packet.packet_mark,
                    action: rule.spec.action,
                    observation_error: None,
                    defer_learning_attribution: false,
                });
            }

            // A different, successfully identified process may share the
            // explicit deny's network envelope. It remains allowed and is
            // learned from this already resolved identity. Parse, ambiguity,
            // and attribution failures never reach this branch and remain
            // fail-closed for the explicit deny envelope.
            let learned = (|| -> Result<LearnedApplicationEndpoint> {
                let selector = identity
                    .learned_selector()
                    .context("cannot create a stable learned application selector")?;
                let endpoint = LearnedEndpoint {
                    address: packet.connection.destination_address,
                    protocol: packet.connection.protocol,
                    port: packet
                        .connection
                        .destination_port
                        .map(openshield_core::PortRange::single)
                        .transpose()?,
                    interface: Some(packet.connection.output_interface.clone()),
                };
                let learned = LearnedApplicationEndpoint {
                    endpoint,
                    application: selector,
                };
                learned.validate()?;
                Ok(learned)
            })();
            let observation_error = match learned {
                Err(error) => Some(error),
                Ok(learned) => {
                    let Ok(guard) = engine.lock() else {
                        quarantine_engine(engine);
                        shutdown.store(true, Ordering::Release);
                        bail!("policy engine mutex is poisoned during learning admission");
                    };
                    let admission = guard.application_learning_queue_admission(
                        snapshot.mode,
                        snapshot.flow_generation,
                        &learned,
                    );
                    drop(guard);
                    let admission = match admission {
                        Ok(admission) => admission,
                        Err(error) if error.code == openshield_protocol::ErrorCode::Conflict => {
                            return Ok(PacketAuthorization::learning(
                                snapshot,
                                packet.packet_mark,
                                Some(anyhow!(error.message)),
                            ));
                        }
                        Err(error) => {
                            quarantine_engine(engine);
                            shutdown.store(true, Ordering::Release);
                            bail!(error.message);
                        }
                    };
                    (|| -> Result<()> {
                        match admission {
                            LearningQueueAdmission::Enqueue => {
                                let observation = LearningObservation {
                                    flow_generation: snapshot.flow_generation,
                                    endpoint: learned,
                                };
                                match learning.try_send(observation) {
                                    Ok(()) => {}
                                    Err(TrySendError::Full(_)) => {
                                        bail!("bounded application-learning queue is full");
                                    }
                                    Err(TrySendError::Disconnected(_)) => {
                                        bail!("application-learning worker is unavailable");
                                    }
                                }
                            }
                            LearningQueueAdmission::PersistencePaused => {
                                bail!("application learning persistence is paused");
                            }
                            LearningQueueAdmission::AlreadyKnown
                            | LearningQueueAdmission::Saturated => {}
                        }
                        Ok(())
                    })()
                    .err()
                }
            };
            return Ok(PacketAuthorization::learning(
                snapshot,
                packet.packet_mark,
                observation_error,
            ));
        }
    };
    Ok(PacketAuthorization {
        mode: snapshot.mode,
        flow_generation: snapshot.flow_generation,
        packet_mark: packet.packet_mark,
        action,
        observation_error: None,
        defer_learning_attribution: false,
    })
}

fn learning_attribution_loop(
    receiver: &Receiver<LearningAttributionWork>,
    completions: &SyncSender<LearningVerdictTicket>,
    learning: &SyncSender<LearningObservation>,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    counters: &NfqueueRuntimeCounters,
) {
    let resolver = ProcfsResolver::new();
    let mut errors = ErrorThrottle::default();
    let mut recent_attempts = LearningAttributionDebounce::default();
    while !shutdown.load(Ordering::Acquire) {
        let first = match receiver.recv_timeout(Duration::from_millis(RECEIVE_POLL_MILLIS.into())) {
            Ok(work) => work,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
        let (flow_generation, mut batch) = collect_learning_attribution_batch(first, receiver);
        let Ok(guard) = engine.lock() else {
            quarantine_engine(engine);
            shutdown.store(true, Ordering::Release);
            return;
        };
        let snapshot = match guard.application_decision_snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                drop(guard);
                errors.report(&format!(
                    "Learning attribution detected an unsafe engine state: {}",
                    error.message
                ));
                quarantine_engine(engine);
                shutdown.store(true, Ordering::Release);
                return;
            }
        };
        drop(guard);
        if snapshot.mode != Mode::Learning || snapshot.flow_generation != flow_generation {
            for work in &batch {
                complete_learning_capture(work.ticket, completions);
            }
            continue;
        }
        let now = Instant::now();
        batch.retain(|work| {
            let should_attempt =
                recent_attempts.should_attempt(flow_generation, &work.packet.connection, now);
            work.ticket.is_some() || should_attempt
        });
        if batch.is_empty() {
            continue;
        }
        let requests = batch
            .iter()
            .map(|work| (&work.packet.connection, IdentityCaptureRequirements::full()))
            .collect::<Vec<_>>();
        let identities = resolver.resolve_batch_for_learning(&requests);
        let completed_at = Instant::now();
        for (work, identity) in batch.into_iter().zip(identities) {
            recent_attempts.completed(&work.packet.connection, completed_at);
            match identity {
                Ok(identity) => {
                    match authorize_attributed_packet(
                        &snapshot,
                        &work.packet,
                        &identity,
                        engine,
                        shutdown,
                        learning,
                    ) {
                        Ok(authorization) => {
                            if let Some(error) = authorization.observation_error {
                                if is_attribution_timeout(&error) {
                                    counters.record_attribution_timeout();
                                }
                                errors.report(&format!(
                                    "Learning admitted packet but skipped its observation: {error:#}"
                                ));
                            }
                        }
                        Err(error) => errors.report(&format!(
                            "Learning observation failed after attribution: {error:#}"
                        )),
                    }
                }
                Err(error) => {
                    if is_attribution_timeout(&error) {
                        counters.record_attribution_timeout();
                    }
                    errors.report(&format!(
                        "Learning admitted packet but attribution failed: {error:#}"
                    ));
                }
            }
            // Identity was captured and offered to the asynchronous learning
            // writer before allowing the initial request to reach its peer.
            // Capture failure also releases it: q1338 observes permissive
            // Learning, while q1337 retains strict synchronous authorization.
            complete_learning_capture(work.ticket, completions);
        }
    }
}

fn complete_learning_capture(
    ticket: Option<LearningVerdictTicket>,
    completions: &SyncSender<LearningVerdictTicket>,
) {
    if let Some(ticket) = ticket {
        // Never let a stalled reader block attribution or hold an engine lock.
        // A full/disconnected completion channel is covered by the deadline.
        let _ignored = completions.try_send(ticket);
    }
}

fn collect_learning_attribution_batch(
    first: LearningAttributionWork,
    receiver: &Receiver<LearningAttributionWork>,
) -> (u32, Vec<LearningAttributionWork>) {
    let flow_generation = first.flow_generation;
    let mut connections = HashSet::from([first.packet.connection.clone()]);
    let mut batch = vec![first];
    let mut drained = 1_usize;
    while drained < MAX_ATTRIBUTION_BATCH_SIZE {
        match receiver.try_recv() {
            Ok(work) => {
                drained += 1;
                if work.flow_generation == flow_generation
                    && connections.insert(work.packet.connection.clone())
                {
                    batch.push(work);
                } else if work.flow_generation == flow_generation
                    && work.ticket.is_some()
                    && let Some(previous) = batch.iter_mut().find(|previous| {
                        previous.packet.connection == work.packet.connection
                            && previous.ticket.is_none()
                    })
                {
                    // Keep the first-packet completion when a prior sampled
                    // observation of the same flow was queued asynchronously.
                    *previous = work;
                }
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
        }
    }
    (flow_generation, batch)
}

/// Short-lived scheduling state for already accepted Learning observations.
///
/// This stores no application identity or authorization result and is never
/// consulted by queue 1337. Success and failure both become eligible for a new
/// TCP observation after a fixed interval; suppressed samples do not extend it.
#[derive(Debug, Default)]
struct LearningAttributionDebounce {
    flow_generation: Option<u32>,
    attempts: HashMap<OutboundConnection, Instant>,
}

impl LearningAttributionDebounce {
    fn should_attempt(
        &mut self,
        flow_generation: u32,
        connection: &OutboundConnection,
        now: Instant,
    ) -> bool {
        if connection.protocol != TransportProtocol::Tcp {
            return true;
        }
        self.should_enqueue(flow_generation, connection, now)
    }

    fn should_enqueue(
        &mut self,
        flow_generation: u32,
        connection: &OutboundConnection,
        now: Instant,
    ) -> bool {
        if self.flow_generation != Some(flow_generation) {
            self.attempts.clear();
            self.flow_generation = Some(flow_generation);
        }
        self.attempts.retain(|connection, previous| {
            let interval = if connection.protocol == TransportProtocol::Tcp {
                LEARNING_TCP_RETRY_INTERVAL
            } else {
                LEARNING_DATAGRAM_COALESCE_INTERVAL
            };
            now.saturating_duration_since(*previous) < interval
        });
        if self.attempts.contains_key(connection) {
            return false;
        }
        if self.attempts.len() >= LEARNING_TCP_RECENT_CAPACITY
            && let Some(oldest) = self
                .attempts
                .iter()
                .min_by_key(|(_, previous)| **previous)
                .map(|(connection, _)| connection.clone())
        {
            // Admit new flows even at capacity; bounded eviction only loses
            // a duplicate-suppression hint, never an authorization check.
            self.attempts.remove(&oldest);
        }
        self.attempts.insert(connection.clone(), now);
        true
    }

    fn completed(&mut self, connection: &OutboundConnection, now: Instant) {
        if let Some(previous) = self.attempts.get_mut(connection) {
            // A slow successful scan must not immediately expire its own
            // retry interval and start the same exhaustive scan once again.
            *previous = now;
        }
    }
}

fn learning_loop(
    receiver: &Receiver<LearningObservation>,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    counters: &NfqueueRuntimeCounters,
) {
    while !shutdown.load(Ordering::Acquire) {
        let first = match receiver.recv_timeout(Duration::from_millis(RECEIVE_POLL_MILLIS.into())) {
            Ok(observation) => observation,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
        let (generation, endpoints) = collect_learning_batch(first, receiver);
        let result = (|| {
            let transaction = engine
                .lock()
                .map_err(|_| {
                    anyhow!("policy engine mutex is poisoned during application learning")
                })?
                .prepare_application_learning(generation, endpoints)
                .map_err(|error| anyhow!(error.message))?;
            let Some(transaction) = transaction else {
                return Ok(0);
            };

            // Atomic file replacement and both fsync operations deliberately
            // run without the engine mutex. Packet snapshot/admission/final
            // verdict rechecks therefore remain live while storage is slow.
            let persisted = transaction.persist();
            engine
                .lock()
                .map_err(|_| anyhow!("policy engine mutex is poisoned after application learning"))?
                .finalize_application_learning(persisted)
                .map_err(|error| anyhow!(error.message))
        })();
        match result {
            Ok(0) => {}
            Ok(count) => info!(count, "persisted application-bound outbound rules"),
            Err(error) => {
                counters.record_terminal_queue_error();
                error!(error = %format_args!("{error:#}"), "application learning failed");
                quarantine_engine(engine);
                shutdown.store(true, Ordering::Release);
                return;
            }
        }
    }
}

fn collect_learning_batch(
    first: LearningObservation,
    receiver: &Receiver<LearningObservation>,
) -> (u32, Vec<LearnedApplicationEndpoint>) {
    let generation = first.flow_generation;
    let mut known = HashSet::with_capacity(LEARNING_BATCH_SIZE);
    known.insert(first.endpoint.clone());
    let mut endpoints = vec![first.endpoint];
    let mut drained = 1_usize;
    while drained < LEARNING_BATCH_SIZE {
        match receiver.try_recv() {
            Ok(observation) => {
                drained += 1;
                if observation.flow_generation == generation
                    && known.insert(observation.endpoint.clone())
                {
                    endpoints.push(observation.endpoint);
                }
            }
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
        }
    }
    (generation, endpoints)
}

fn quarantine_engine(engine: &SharedEngine) {
    match engine.lock() {
        Ok(mut engine) => engine.quarantine_after_runtime_failure(),
        Err(poisoned) => {
            error!(
                "policy engine mutex is poisoned; installing BlockAll from the recovered backend"
            );
            let mut recovered = poisoned.into_inner();
            recovered.quarantine_after_engine_poison();
            drop(recovered);
            // The recovered Engine is now fatal and contains no trusted live
            // policy claim. Let shutdown paths acquire it only to repeat
            // BlockAll and terminate; normal protocol calls still see fatal.
            engine.clear_poison();
        }
    }
}

#[derive(Clone, Debug)]
struct LearningObservation {
    flow_generation: u32,
    endpoint: LearnedApplicationEndpoint,
}

#[derive(Clone, Debug)]
struct LearningAttributionWork {
    flow_generation: u32,
    packet: QueuedPacket,
    ticket: Option<LearningVerdictTicket>,
}

#[derive(Debug)]
struct PacketAuthorization {
    mode: Mode,
    flow_generation: u32,
    packet_mark: u32,
    action: RuleAction,
    /// Best-effort Learning failure retained for telemetry without changing
    /// the explicitly permissive packet verdict.
    observation_error: Option<anyhow::Error>,
    /// A Learning q1337 false-positive envelope (for example a different
    /// trusted `NFQA_UID`) is admitted immediately and attributed by the same
    /// bounded worker as q1338 after the verdict has reached the kernel.
    defer_learning_attribution: bool,
}

impl PacketAuthorization {
    fn learning(
        snapshot: &ApplicationDecisionPolicy,
        packet_mark: u32,
        observation_error: Option<anyhow::Error>,
    ) -> Self {
        Self {
            mode: snapshot.mode,
            flow_generation: snapshot.flow_generation,
            packet_mark,
            action: RuleAction::Accept,
            observation_error,
            defer_learning_attribution: false,
        }
    }
}

#[derive(Clone, Debug)]
struct QueuedPacket {
    connection: OutboundConnection,
    packet_mark: u32,
    /// Initial TCP SYN (not SYN-ACK), or an attributable datagram. This is a
    /// Learning scheduling hint only, never an Enforcing authorization field.
    initial_observation: bool,
}

#[derive(Debug)]
struct QueuedPacketWork {
    packet_id: u32,
    packet: std::result::Result<QueuedPacket, String>,
}

fn parse_queued_packet(payload: &[u8]) -> Result<QueuedPacket> {
    ensure!(
        payload.len() >= NFGENMSG_BYTES,
        "queued packet netlink payload is truncated"
    );
    let attributes = Attributes::new(&payload[NFGENMSG_BYTES..]);
    let mut uid = None;
    let mut output_index = None;
    let mut mark = None;
    for attribute in attributes {
        let attribute = attribute?;
        match attribute.kind {
            NFQA_UID => uid = Some(network_u32(attribute.payload)?),
            NFQA_IFINDEX_OUTDEV => output_index = Some(network_u32(attribute.payload)?),
            NFQA_MARK => mark = Some(network_u32(attribute.payload)?),
            _ => {}
        }
    }
    let capture = parse_packet_capture(&payload[NFGENMSG_BYTES..])?;
    // Decode only bounded protocol/control metadata before requiring the
    // packet-bound UID. This improves diagnostics, never attribution fallback.
    let parsed = capture.parse(IpPacketDirection::Outbound)?;
    let socket_uid = uid.ok_or_else(|| {
        anyhow!(
            "queued packet has no kernel socket uid (protocol={:?}, tcp_flags={:?}, icmp_type={:?})",
            parsed.protocol, parsed.tcp_flags, parsed.icmp_type,
        )
    })?;
    let output_index =
        output_index.ok_or_else(|| anyhow!("queued packet has no output interface"))?;
    // Linux omits NFQA_MARK when the packet mark is zero. Learning's
    // observation queue deliberately does not use a private pending mark, so
    // an absent attribute is its canonical representation rather than a
    // malformed packet. Enforcing remains fail-closed: its attribution plan
    // below requires the non-zero pending-mark domain before any application
    // decision can be made.
    let packet_mark = mark.unwrap_or_default();
    let output_interface = interface_for_index(output_index)?;
    let connection = OutboundConnection {
        source_address: parsed.source_address,
        source_port: parsed.source_port,
        destination_address: parsed.destination_address,
        destination_port: parsed.destination_port,
        protocol: parsed.protocol,
        output_interface,
        socket_uid,
    };
    connection.validate()?;
    Ok(QueuedPacket {
        connection,
        packet_mark,
        initial_observation: parsed.initial_observation,
    })
}

fn packet_id(payload: &[u8]) -> Option<u32> {
    if payload.len() < NFGENMSG_BYTES {
        return None;
    }
    for attribute in Attributes::new(&payload[NFGENMSG_BYTES..]).flatten() {
        if attribute.kind == NFQA_PACKET_HDR && attribute.payload.len() >= PACKET_HEADER_BYTES {
            return attribute
                .payload
                .get(..4)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_be_bytes);
        }
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedIpPacket {
    source_address: std::net::IpAddr,
    source_port: Option<u16>,
    destination_address: std::net::IpAddr,
    destination_port: Option<u16>,
    protocol: TransportProtocol,
    initial_observation: bool,
    transport_offset: usize,
    tcp_flags: Option<u8>,
    icmp_type: Option<u8>,
}

/// A bounded prefix of the kernel-owned skb, never replacement packet data.
/// `CAP_LEN` may describe BIG TCP packets larger than the netlink attribute
/// limit: no allocation or indexing is based on that unbounded original size.
#[derive(Clone, Copy, Debug)]
struct PacketCapture<'a> {
    payload: &'a [u8],
    original_length: u32,
    skb_info: u32,
}

impl PacketCapture<'_> {
    fn parse(self, direction: IpPacketDirection) -> Result<ParsedIpPacket> {
        let version = self
            .payload
            .first()
            .map(|byte| byte >> 4)
            .ok_or_else(|| anyhow!("queued IP packet is empty"))?;
        // Deferred checksum flags are deliberately not an admission signal.
        // We only inspect headers; the unmodified skb completes its normal
        // kernel checksum/segmentation path after the ordinary policy verdict.
        let parsed = match version {
            4 => parse_ipv4_packet(self, direction),
            6 => parse_ipv6_packet(self, direction),
            _ => bail!("queued payload is not IPv4 or IPv6"),
        }?;
        if parsed.protocol == TransportProtocol::Udp {
            let offset = parsed.transport_offset;
            let length = u32::from(u16::from_be_bytes([
                self.payload[offset + 4],
                self.payload[offset + 5],
            ]));
            ensure!(
                u32::try_from(offset)? + length <= self.original_length,
                "UDP length exceeds the kernel packet length"
            );
        }
        Ok(parsed)
    }

    const fn is_gso(self) -> bool {
        self.skb_info & NFQA_SKB_GSO != 0
    }
}

fn parse_packet_capture(attributes: &[u8]) -> Result<PacketCapture<'_>> {
    let mut payload = None;
    let mut original_length = None;
    let mut skb_info = None;
    for attribute in Attributes::new(attributes) {
        let attribute = attribute?;
        match attribute.kind {
            NFQA_PAYLOAD => {
                ensure!(payload.is_none(), "duplicate queued packet payload");
                payload = Some(attribute.payload);
            }
            NFQA_CAP_LEN => {
                ensure!(
                    original_length.is_none(),
                    "duplicate queued packet capture length"
                );
                original_length = Some(network_u32(attribute.payload)?);
            }
            NFQA_SKB_INFO => {
                ensure!(
                    skb_info.is_none(),
                    "duplicate queued packet skb information"
                );
                skb_info = Some(network_u32(attribute.payload)?);
            }
            _ => {}
        }
    }
    let payload = payload.ok_or_else(|| anyhow!("queued packet has no payload"))?;
    let copied_length = u32::try_from(payload.len())?;
    ensure!(
        copied_length > 0 && copied_length <= COPY_RANGE,
        "queued packet capture exceeds the configured prefix bound or is empty"
    );
    let original_length = original_length.unwrap_or(copied_length);
    ensure!(
        original_length >= copied_length,
        "queued packet capture length is smaller than its payload"
    );
    Ok(PacketCapture {
        payload,
        original_length,
        skb_info: skb_info.unwrap_or_default(),
    })
}

#[cfg(test)]
fn parse_ip_packet(packet: &[u8]) -> Result<ParsedIpPacket> {
    PacketCapture {
        payload: packet,
        original_length: u32::try_from(packet.len())?,
        skb_info: 0,
    }
    .parse(IpPacketDirection::Outbound)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum IpPacketDirection {
    Outbound,
    Reply,
}

fn parse_ipv4_packet(
    capture: PacketCapture<'_>,
    direction: IpPacketDirection,
) -> Result<ParsedIpPacket> {
    let packet = capture.payload;
    ensure!(packet.len() >= 20, "IPv4 header is truncated");
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    ensure!(
        header_length >= 20 && packet.len() >= header_length,
        "invalid IPv4 IHL"
    );
    let total_length = u32::from(u16::from_be_bytes([packet[2], packet[3]]));
    ensure!(
        total_length == capture.original_length
            || (total_length == 0
                && capture.is_gso()
                && capture.original_length > u32::from(u16::MAX)),
        "IPv4 total length does not match the kernel capture length"
    );
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    ensure!(
        fragment.trailing_zeros() >= 13,
        "non-initial IPv4 fragment is not attributable"
    );
    let source_address = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination_address =
        std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    finish_transport(
        source_address.into(),
        destination_address.into(),
        packet[9],
        packet,
        header_length,
        direction,
    )
}

fn parse_ipv6_packet(
    capture: PacketCapture<'_>,
    direction: IpPacketDirection,
) -> Result<ParsedIpPacket> {
    let packet = capture.payload;
    ensure!(packet.len() >= 40, "IPv6 header is truncated");
    let payload_length = u32::from(u16::from_be_bytes([packet[4], packet[5]]));
    ensure!(
        payload_length + 40 == capture.original_length
            || (payload_length == 0
                && capture.is_gso()
                && capture.original_length > u32::from(u16::MAX) + 40),
        "IPv6 payload length does not match the kernel capture length (non-GSO jumbograms are unsupported)"
    );
    let source: [u8; 16] = packet[8..24]
        .try_into()
        .map_err(|_| anyhow!("IPv6 source is truncated"))?;
    let destination: [u8; 16] = packet[24..40]
        .try_into()
        .map_err(|_| anyhow!("IPv6 destination is truncated"))?;
    let mut next_header = packet[6];
    let mut offset = 40_usize;
    for _ in 0..8 {
        match next_header {
            0 | 43 | 60 => {
                ensure!(
                    packet.len() >= offset + 2,
                    "IPv6 extension header is truncated"
                );
                next_header = packet[offset];
                let length = (usize::from(packet[offset + 1]) + 1) * 8;
                offset = offset
                    .checked_add(length)
                    .ok_or_else(|| anyhow!("IPv6 extension offset overflow"))?;
                ensure!(packet.len() >= offset, "IPv6 extension data is truncated");
            }
            44 => {
                ensure!(
                    packet.len() >= offset + 8,
                    "IPv6 fragment header is truncated"
                );
                let fragment = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                ensure!(
                    fragment & 0xfff8 == 0,
                    "non-initial IPv6 fragment is not attributable"
                );
                next_header = packet[offset];
                offset += 8;
            }
            51 => {
                ensure!(packet.len() >= offset + 2, "IPv6 AH header is truncated");
                next_header = packet[offset];
                let length = (usize::from(packet[offset + 1]) + 2) * 4;
                offset = offset
                    .checked_add(length)
                    .ok_or_else(|| anyhow!("IPv6 AH offset overflow"))?;
                ensure!(packet.len() >= offset, "IPv6 AH data is truncated");
            }
            _ => {
                return finish_transport(
                    std::net::Ipv6Addr::from(source).into(),
                    std::net::Ipv6Addr::from(destination).into(),
                    next_header,
                    packet,
                    offset,
                    direction,
                );
            }
        }
    }
    bail!("IPv6 extension-header bound exceeded")
}

fn parse_transport_ports(protocol_number: u8, packet: &[u8], offset: usize) -> Result<(u16, u16)> {
    if protocol_number == 6 {
        ensure!(packet.len() >= offset + 20, "TCP header is truncated");
        let header_length = usize::from(packet[offset + 12] >> 4) * 4;
        ensure!(
            header_length >= 20 && packet.len() >= offset + header_length,
            "TCP data offset is invalid or its options are truncated"
        );
    } else {
        ensure!(packet.len() >= offset + 8, "UDP header is truncated");
        let length = u16::from_be_bytes([packet[offset + 4], packet[offset + 5]]);
        ensure!(
            length >= 8,
            "UDP length is smaller than its header (UDP jumbograms are unsupported)"
        );
    }
    let source = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    let destination = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
    ensure!(source != 0 && destination != 0, "transport port is zero");
    Ok((source, destination))
}

fn finish_transport(
    source_address: std::net::IpAddr,
    destination_address: std::net::IpAddr,
    protocol_number: u8,
    packet: &[u8],
    offset: usize,
    direction: IpPacketDirection,
) -> Result<ParsedIpPacket> {
    let (protocol, source_port, destination_port) = match protocol_number {
        6 | 17 => {
            let (source, destination) = parse_transport_ports(protocol_number, packet, offset)?;
            (
                if protocol_number == 6 {
                    TransportProtocol::Tcp
                } else {
                    TransportProtocol::Udp
                },
                Some(source),
                Some(destination),
            )
        }
        1 if source_address.is_ipv4() => {
            ensure!(packet.len() >= offset + 8, "ICMP header is truncated");
            ensure!(
                packet[offset]
                    == if direction == IpPacketDirection::Outbound {
                        8
                    } else {
                        0
                    }
                    && packet[offset + 1] == 0,
                "ICMP echo type/code does not match the queue direction"
            );
            let identifier = u16::from_be_bytes([packet[offset + 4], packet[offset + 5]]);
            (TransportProtocol::Icmp, Some(identifier), None)
        }
        58 if source_address.is_ipv6() => {
            ensure!(packet.len() >= offset + 8, "ICMPv6 header is truncated");
            ensure!(
                packet[offset]
                    == if direction == IpPacketDirection::Outbound {
                        128
                    } else {
                        129
                    }
                    && packet[offset + 1] == 0,
                "ICMPv6 echo type/code does not match the queue direction"
            );
            let identifier = u16::from_be_bytes([packet[offset + 4], packet[offset + 5]]);
            (TransportProtocol::IcmpV6, Some(identifier), None)
        }
        _ => bail!("queued packet uses an unsupported transport protocol"),
    };
    Ok(ParsedIpPacket {
        source_address,
        source_port,
        destination_address,
        destination_port,
        protocol,
        initial_observation: protocol != TransportProtocol::Tcp
            || packet
                .get(offset + 13)
                .is_some_and(|flags| flags & 0x17 == 0x02),
        transport_offset: offset,
        tcp_flags: (protocol == TransportProtocol::Tcp)
            .then(|| packet.get(offset + 13).copied())
            .flatten(),
        icmp_type: matches!(
            protocol,
            TransportProtocol::Icmp | TransportProtocol::IcmpV6
        )
        .then(|| packet.get(offset).copied())
        .flatten(),
    })
}

fn interface_for_index(index: u32) -> Result<InterfaceName> {
    ensure!(index != 0, "output interface index is zero");
    let name = if_indextoname(index).context("output interface index does not exist")?;
    let name = name
        .into_string()
        .map_err(|_| anyhow!("interface name is not UTF-8"))?;
    InterfaceName::new(name).context("output interface name is invalid")
}

#[derive(Debug)]
struct QueueSocket {
    socket: OwnedFd,
    queue_number: u16,
    fail_open: bool,
    sequence: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueueReceive {
    Idle,
    // A signal interrupted the syscall. No packet was consumed, so this
    // must not advance the reply read-through watermark.
    Interrupted,
    Datagram(usize),
    Overflow,
}

impl QueueSocket {
    fn open(queue_number: u16, fail_open: bool) -> Result<Self> {
        let socket = socket(
            AddressFamily::Netlink,
            SockType::Raw,
            // Verdict delivery happens while the policy-engine guard is held
            // so a restrictive policy reload cannot race packet reinjection.
            // A blocking netlink send would therefore let kernel-buffer
            // pressure freeze all control operations.  Fail closed on EAGAIN
            // instead: the caller quarantines the engine and closing the
            // queue causes outstanding packets to be denied.
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            SockProtocol::NetlinkNetFilter,
        )
        .context("cannot create NETLINK_NETFILTER socket")?;
        bind(socket.as_raw_fd(), &NetlinkAddr::new(0, 0))
            .context("cannot bind NETLINK_NETFILTER socket")?;
        let mut queue = Self {
            socket,
            queue_number,
            fail_open,
            sequence: 0,
        };
        queue.configure_command(NFQNL_CFG_CMD_BIND)?;
        queue
            .configure_parameters(fail_open)
            .context("kernel must support NFQUEUE GSO and socket UID metadata before activation")?;
        Ok(queue)
    }

    fn port_id(&self) -> Result<u32> {
        let address = getsockname::<NetlinkAddr>(self.socket.as_raw_fd())
            .context("cannot read the NFQUEUE netlink port id")?;
        let port_id = address.pid();
        ensure!(port_id != 0, "NFQUEUE netlink port id is zero");
        Ok(port_id)
    }

    fn overflow_message(&self) -> &'static str {
        if self.fail_open {
            "Learning observation queue overflowed; kernel fail-open admitted affected packets"
        } else {
            "application decision queue overflowed; affected Enforcing packets were denied"
        }
    }

    fn configure_command(&mut self, command: u8) -> Result<()> {
        let payload = [command, 0, 0, 0];
        self.configuration(&[(NFQA_CFG_CMD, payload.as_slice())])
    }

    fn configure_parameters(&mut self, fail_open: bool) -> Result<()> {
        let mut parameters = Vec::with_capacity(5);
        parameters.extend_from_slice(&COPY_RANGE.to_be_bytes());
        parameters.push(NFQNL_COPY_PACKET);
        let queue_length = QUEUE_MAX_LENGTH.to_be_bytes();
        let (flags, mask) = queue_configuration_flags(fail_open);
        let flags = flags.to_be_bytes();
        let mask = mask.to_be_bytes();
        self.configuration(&[
            (NFQA_CFG_PARAMS, parameters.as_slice()),
            (NFQA_CFG_QUEUE_MAXLEN, queue_length.as_slice()),
            (NFQA_CFG_FLAGS, flags.as_slice()),
            (NFQA_CFG_MASK, mask.as_slice()),
        ])
    }

    fn configuration(&mut self, attributes: &[(u16, &[u8])]) -> Result<()> {
        let sequence = self.next_sequence();
        let message = build_message(
            queue_message_type(NFQNL_MSG_CONFIG),
            NLM_F_REQUEST | NLM_F_ACK,
            sequence,
            NFNETLINK_FAMILY_UNSPEC,
            self.queue_number,
            attributes,
        )?;
        let sent = sendto(
            self.socket.as_raw_fd(),
            &message,
            &NetlinkAddr::new(0, 0),
            MsgFlags::empty(),
        )
        .context("cannot send NFQUEUE configuration")?;
        ensure!(sent == message.len(), "NFQUEUE configuration was truncated");
        self.wait_for_ack(sequence)
    }

    fn wait_for_ack(&mut self, expected_sequence: u32) -> Result<()> {
        let deadline = Instant::now() + CONFIGURATION_TIMEOUT;
        let mut buffer = vec![0_u8; RECEIVE_BUFFER_BYTES].into_boxed_slice();
        loop {
            ensure!(
                Instant::now() <= deadline,
                "NFQUEUE configuration acknowledgement timed out"
            );
            let mut descriptor = [PollFd::new(self.socket.as_fd(), PollFlags::POLLIN)];
            let ready = match poll(&mut descriptor, CONFIGURATION_POLL_MILLIS) {
                Ok(ready) => ready,
                Err(Errno::EINTR) => continue,
                Err(error) => {
                    return Err(error).context("cannot poll NFQUEUE configuration acknowledgement");
                }
            };
            if ready == 0 {
                continue;
            }
            let events = descriptor[0].revents().unwrap_or_else(PollFlags::empty);
            ensure!(
                !events.intersects(PollFlags::POLLHUP | PollFlags::POLLNVAL),
                "NFQUEUE socket closed while awaiting configuration acknowledgement"
            );
            let size = match recv(self.socket.as_raw_fd(), &mut buffer, MsgFlags::MSG_TRUNC) {
                Ok(size) => size,
                Err(Errno::EINTR | Errno::EAGAIN | Errno::ENOBUFS) => continue,
                Err(error) => {
                    return Err(error)
                        .context("cannot receive NFQUEUE configuration acknowledgement");
                }
            };
            ensure!(
                size <= buffer.len(),
                "NFQUEUE configuration datagram exceeded its fixed buffer"
            );
            let mut acknowledged = false;
            for message in NetlinkMessages::new(&buffer[..size]) {
                let message = message?;
                if message.message_type == NLMSG_ERROR && message.sequence == expected_sequence {
                    ensure!(
                        message.payload.len() >= 4,
                        "netlink acknowledgement is truncated"
                    );
                    let error = i32::from_ne_bytes(
                        message.payload[..4]
                            .try_into()
                            .map_err(|_| anyhow!("netlink acknowledgement is malformed"))?,
                    );
                    ensure!(
                        error == 0,
                        "kernel rejected NFQUEUE configuration: errno {}",
                        -error
                    );
                    acknowledged = true;
                } else if message.message_type == queue_message_type(NFQNL_MSG_PACKET) {
                    // Once BIND succeeds, packets may race ahead of its ACK.
                    // Deny them until all queue configuration is complete,
                    // rather than treating their interleaving as startup DoS.
                    if let Some(packet_id) = packet_id(message.payload) {
                        self.verdict(packet_id, NF_DROP)?;
                    }
                }
            }
            if acknowledged {
                return Ok(());
            }
        }
    }

    fn receive(&mut self, buffer: &mut [u8], timeout_millis: u16) -> Result<QueueReceive> {
        let mut descriptor = [PollFd::new(self.socket.as_fd(), PollFlags::POLLIN)];
        let ready = match poll(&mut descriptor, timeout_millis) {
            Ok(ready) => ready,
            Err(Errno::EINTR) => return Ok(QueueReceive::Interrupted),
            Err(Errno::EAGAIN) => return Ok(QueueReceive::Idle),
            Err(error) => return Err(error).context("cannot poll NFQUEUE socket"),
        };
        if ready == 0 {
            return Ok(QueueReceive::Idle);
        }
        let events = descriptor[0].revents().unwrap_or_else(PollFlags::empty);
        ensure!(
            !events.intersects(PollFlags::POLLHUP | PollFlags::POLLNVAL),
            "NFQUEUE socket reported a terminal poll event"
        );
        let size = match recv(self.socket.as_raw_fd(), buffer, MsgFlags::MSG_TRUNC) {
            Ok(size) => size,
            Err(Errno::EINTR) => return Ok(QueueReceive::Interrupted),
            Err(Errno::ENOBUFS) => return Ok(QueueReceive::Overflow),
            Err(error) => return Err(error).context("cannot receive queued packet"),
        };
        Ok(QueueReceive::Datagram(validate_received_datagram_size(
            size,
            buffer.len(),
        )?))
    }

    fn receive_ready(&mut self, buffer: &mut [u8]) -> Result<QueueReceive> {
        classify_ready_receive(
            recv(
                self.socket.as_raw_fd(),
                buffer,
                MsgFlags::MSG_TRUNC | MsgFlags::MSG_DONTWAIT,
            ),
            buffer.len(),
        )
    }

    fn verdict(&mut self, packet_id: u32, verdict: u32) -> Result<()> {
        self.send_verdict(packet_id, verdict, None)
    }

    fn verdict_with_mark(&mut self, packet_id: u32, verdict: u32, mark: u32) -> Result<()> {
        self.send_verdict(packet_id, verdict, Some(mark))
    }

    fn send_verdict(&mut self, packet_id: u32, verdict: u32, mark: Option<u32>) -> Result<()> {
        let sequence = self.next_sequence();
        let message = build_verdict_message(sequence, self.queue_number, packet_id, verdict, mark)?;
        let sent = sendto(
            self.socket.as_raw_fd(),
            &message,
            &NetlinkAddr::new(0, 0),
            MsgFlags::empty(),
        )
        .context("cannot send NFQUEUE verdict")?;
        ensure!(sent == message.len(), "NFQUEUE verdict was truncated");
        Ok(())
    }

    fn next_sequence(&mut self) -> u32 {
        advance_netlink_sequence(&mut self.sequence)
    }
}

const fn queue_configuration_flags(fail_open: bool) -> (u32, u32) {
    // Keep the original socket-associated skb: pre-queue GSO normalization
    // costs CPU and can omit UID metadata on segmented packets. GSO changes
    // representation only, never authorization or overflow policy. Require
    // the kernel to acknowledge it before activating any application rules.
    let flags =
        NFQA_CFG_F_UID_GID | NFQA_CFG_F_GSO | if fail_open { NFQA_CFG_F_FAIL_OPEN } else { 0 };
    (
        flags,
        NFQA_CFG_F_UID_GID | NFQA_CFG_F_GSO | NFQA_CFG_F_FAIL_OPEN,
    )
}

fn classify_ready_receive(
    received: std::result::Result<usize, Errno>,
    capacity: usize,
) -> Result<QueueReceive> {
    match received {
        Ok(size) => Ok(QueueReceive::Datagram(validate_received_datagram_size(
            size, capacity,
        )?)),
        Err(Errno::EAGAIN) => Ok(QueueReceive::Idle),
        Err(Errno::EINTR) => Ok(QueueReceive::Interrupted),
        Err(Errno::ENOBUFS) => Ok(QueueReceive::Overflow),
        Err(error) => Err(error).context("cannot drain a ready queued packet"),
    }
}

fn validate_received_datagram_size(size: usize, capacity: usize) -> Result<usize> {
    ensure!(size != 0, "NFQUEUE returned an empty netlink datagram");
    ensure!(
        size <= capacity,
        "queued netlink datagram exceeded its fixed buffer"
    );
    Ok(size)
}

fn advance_netlink_sequence(sequence: &mut u32) -> u32 {
    *sequence = sequence.wrapping_add(1);
    if *sequence == 0 {
        // Zero conventionally denotes an unsolicited netlink message.
        *sequence = 1;
    }
    *sequence
}

fn build_verdict_message(
    sequence: u32,
    queue_number: u16,
    packet_id: u32,
    verdict: u32,
    mark: Option<u32>,
) -> Result<Vec<u8>> {
    let mut verdict_header = Vec::with_capacity(8);
    verdict_header.extend_from_slice(&verdict.to_be_bytes());
    verdict_header.extend_from_slice(&packet_id.to_be_bytes());
    if let Some(mark) = mark {
        let mark = mark.to_be_bytes();
        build_message(
            queue_message_type(NFQNL_MSG_VERDICT),
            NLM_F_REQUEST,
            sequence,
            NFNETLINK_FAMILY_UNSPEC,
            queue_number,
            &[
                (NFQA_VERDICT_HDR, verdict_header.as_slice()),
                (NFQA_MARK, mark.as_slice()),
            ],
        )
    } else {
        build_message(
            queue_message_type(NFQNL_MSG_VERDICT),
            NLM_F_REQUEST,
            sequence,
            NFNETLINK_FAMILY_UNSPEC,
            queue_number,
            &[(NFQA_VERDICT_HDR, verdict_header.as_slice())],
        )
    }
}

impl Drop for QueueSocket {
    fn drop(&mut self) {
        let _ignored = self.configure_command(NFQNL_CFG_CMD_UNBIND);
    }
}

fn queue_message_type(operation: u16) -> u16 {
    (NFNL_SUBSYS_QUEUE << 8) | operation
}

fn build_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    family: u8,
    resource_id: u16,
    attributes: &[(u16, &[u8])],
) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    payload.push(family);
    payload.push(0);
    payload.extend_from_slice(&resource_id.to_be_bytes());
    for (kind, value) in attributes {
        append_attribute(&mut payload, *kind, value)?;
    }
    let length = NETLINK_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or_else(|| anyhow!("netlink message size overflow"))?;
    let length = u32::try_from(length).context("netlink message is oversized")?;
    let capacity = usize::try_from(length).context("netlink message length does not fit usize")?;
    let mut message = Vec::with_capacity(capacity);
    message.extend_from_slice(&length.to_ne_bytes());
    message.extend_from_slice(&message_type.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&0_u32.to_ne_bytes());
    message.extend_from_slice(&payload);
    Ok(message)
}

fn append_attribute(message: &mut Vec<u8>, kind: u16, payload: &[u8]) -> Result<()> {
    let length = ATTRIBUTE_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or_else(|| anyhow!("netlink attribute size overflow"))?;
    let encoded_length = u16::try_from(length).context("netlink attribute is oversized")?;
    message.extend_from_slice(&encoded_length.to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(payload);
    let aligned = align4(length)?;
    message.resize(
        message
            .len()
            .checked_add(aligned - length)
            .ok_or_else(|| anyhow!("netlink padding overflow"))?,
        0,
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct NetlinkMessage<'a> {
    message_type: u16,
    sequence: u32,
    payload: &'a [u8],
}

#[derive(Clone, Debug)]
struct NetlinkMessages<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> NetlinkMessages<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl<'a> Iterator for NetlinkMessages<'a> {
    type Item = Result<NetlinkMessage<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.bytes.len() {
            return None;
        }
        let Some(remaining) = self.bytes.get(self.offset..) else {
            return Some(Err(anyhow!("netlink offset is outside the datagram")));
        };
        if remaining.len() < NETLINK_HEADER_BYTES {
            self.offset = self.bytes.len();
            return Some(Err(anyhow!("netlink header is truncated")));
        }
        let Ok(length_bytes) = remaining[..4].try_into() else {
            self.offset = self.bytes.len();
            return Some(Err(anyhow!("netlink length is malformed")));
        };
        let length = u32::from_ne_bytes(length_bytes);
        let length = match usize::try_from(length) {
            Ok(length) if length >= NETLINK_HEADER_BYTES && length <= remaining.len() => length,
            _ => {
                self.offset = self.bytes.len();
                return Some(Err(anyhow!("netlink message length is invalid")));
            }
        };
        let aligned = match align4(length) {
            Ok(aligned) if aligned <= remaining.len() => aligned,
            // Netlink alignment is required between multipart messages, but
            // the kernel may omit the final message's trailing padding from a
            // datagram. Accept only an exact terminal boundary; one or more
            // stray/truncated padding bytes still fail closed below.
            Ok(_) if length == remaining.len() => length,
            _ => {
                self.offset = self.bytes.len();
                return Some(Err(anyhow!("netlink message alignment is invalid")));
            }
        };
        let message_type = u16::from_ne_bytes([remaining[4], remaining[5]]);
        let sequence =
            u32::from_ne_bytes([remaining[8], remaining[9], remaining[10], remaining[11]]);
        let payload = &remaining[NETLINK_HEADER_BYTES..length];
        self.offset += aligned;
        Some(Ok(NetlinkMessage {
            message_type,
            sequence,
            payload,
        }))
    }
}

#[derive(Clone, Copy, Debug)]
struct Attribute<'a> {
    kind: u16,
    payload: &'a [u8],
}

#[derive(Clone, Debug)]
struct Attributes<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Attributes<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl<'a> Iterator for Attributes<'a> {
    type Item = Result<Attribute<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.bytes.len() {
            return None;
        }
        let Some(remaining) = self.bytes.get(self.offset..) else {
            return Some(Err(anyhow!("attribute offset is invalid")));
        };
        if remaining.len() < ATTRIBUTE_HEADER_BYTES {
            self.offset = self.bytes.len();
            return Some(Err(anyhow!("netlink attribute header is truncated")));
        }
        let length = usize::from(u16::from_ne_bytes([remaining[0], remaining[1]]));
        let kind = u16::from_ne_bytes([remaining[2], remaining[3]]) & 0x3fff;
        if length < ATTRIBUTE_HEADER_BYTES || length > remaining.len() {
            self.offset = self.bytes.len();
            return Some(Err(anyhow!("netlink attribute length is invalid")));
        }
        let aligned = match align4(length) {
            Ok(aligned) if aligned <= remaining.len() => aligned,
            // As with the containing netlink message, a final attribute may
            // end exactly at the datagram boundary without its alignment pad.
            Ok(_) if length == remaining.len() => length,
            _ => {
                self.offset = self.bytes.len();
                return Some(Err(anyhow!("netlink attribute alignment is invalid")));
            }
        };
        let payload = &remaining[ATTRIBUTE_HEADER_BYTES..length];
        self.offset += aligned;
        Some(Ok(Attribute { kind, payload }))
    }
}

fn align4(value: usize) -> Result<usize> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(|| anyhow!("netlink alignment overflow"))
}

fn network_u32(bytes: &[u8]) -> Result<u32> {
    ensure!(
        bytes.len() == 4,
        "network u32 attribute has an invalid size"
    );
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
        anyhow!("network u32 attribute is malformed")
    })?))
}

#[derive(Debug, Default)]
struct ErrorThrottle {
    last_log: Option<Instant>,
    suppressed: u64,
}

impl ErrorThrottle {
    fn report(&mut self, message: &str) {
        let now = Instant::now();
        if self
            .last_log
            .is_none_or(|last| now.duration_since(last) >= Duration::from_secs(10))
        {
            if message.starts_with("Learning ") {
                warn!(
                    suppressed = self.suppressed,
                    message, "application learning observation skipped"
                );
            } else {
                warn!(
                    suppressed = self.suppressed,
                    message, "application packet denied"
                );
            }
            self.last_log = Some(now);
            self.suppressed = 0;
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::os::unix::fs::MetadataExt;
    use std::sync::{Arc, Mutex};

    use openshield_core::{
        ApplicationPath, ApplicationSelector, AtomicStateStore, Direction, ExecutableFileId,
        PortRange, RuleName, RuleOrigin, RuleSpec, State, StateStore,
    };

    use super::*;
    use crate::backend::MemoryBackend;
    use crate::engine::{Engine, EventBus};

    fn learning_observation(generation: u32, address_offset: u32) -> Result<LearningObservation> {
        Ok(LearningObservation {
            flow_generation: generation,
            endpoint: LearnedApplicationEndpoint {
                endpoint: LearnedEndpoint {
                    address: std::net::Ipv4Addr::from(0x0a00_0001_u32 + address_offset).into(),
                    protocol: TransportProtocol::Tcp,
                    port: Some(PortRange::single(443)?),
                    interface: Some(InterfaceName::new("eth0")?),
                },
                application: ApplicationSelector::new(
                    Some(ApplicationPath::new("/usr/bin/openshield-nfqueue-test")?),
                    Some(ExecutableFileId {
                        device: 8,
                        inode: 42,
                        size: 1_024,
                        ctime_seconds: 1_700_000_000,
                        ctime_nanoseconds: 0,
                    }),
                    None,
                    Some(1_000),
                    None,
                )?,
            },
        })
    }

    fn learning_attribution_work(
        generation: u32,
        address_offset: u32,
    ) -> Result<LearningAttributionWork> {
        Ok(LearningAttributionWork {
            flow_generation: generation,
            ticket: None,
            packet: QueuedPacket {
                connection: OutboundConnection {
                    source_address: "192.0.2.1".parse()?,
                    source_port: Some(40_000_u16.saturating_add(u16::try_from(address_offset)?)),
                    destination_address: std::net::Ipv4Addr::from(
                        0xcb00_7101_u32.saturating_add(address_offset),
                    )
                    .into(),
                    destination_port: Some(443),
                    protocol: TransportProtocol::Tcp,
                    output_interface: InterfaceName::new("eth0")?,
                    socket_uid: 1_000,
                },
                packet_mark: 0,
                initial_observation: true,
            },
        })
    }

    #[derive(Default)]
    struct RecordedLearningVerdicts(Vec<(u32, u32)>);

    impl LearningVerdictSink for RecordedLearningVerdicts {
        fn verdict(&mut self, packet_id: u32, verdict: u32) -> Result<()> {
            self.0.push((packet_id, verdict));
            Ok(())
        }
    }

    struct LearningQueueFixture {
        _directory: tempfile::TempDir,
        engine: SharedEngine,
        shutdown: AtomicBool,
        counters: NfqueueRuntimeCounters,
        queue: RecordedLearningVerdicts,
        observations: LearningAttributionDebounce,
        pending: PendingLearningVerdicts,
        attribution: SyncSender<LearningAttributionWork>,
        work: Receiver<LearningAttributionWork>,
        completion_sender: SyncSender<LearningVerdictTicket>,
        completions: Receiver<LearningVerdictTicket>,
    }

    impl LearningQueueFixture {
        fn new(capacity: usize) -> Result<Self> {
            let directory = tempfile::tempdir()?;
            let owner = std::fs::metadata(directory.path())?.uid();
            let store = AtomicStateStore::for_owner(directory.path().join("state.json"), owner);
            let mut engine = Engine::load(
                Box::new(MemoryBackend::default()),
                Box::new(store),
                EventBus::new(),
            )?;
            engine.activate_startup_policy()?;
            let (attribution, work) = mpsc::sync_channel(capacity);
            let (completion_sender, completions) = mpsc::sync_channel(LEARNING_PENDING_CAPACITY);
            Ok(Self {
                _directory: directory,
                engine: Arc::new(Mutex::new(engine)),
                shutdown: AtomicBool::new(false),
                counters: NfqueueRuntimeCounters::default(),
                queue: RecordedLearningVerdicts::default(),
                observations: LearningAttributionDebounce::default(),
                pending: PendingLearningVerdicts::default(),
                attribution,
                work,
                completion_sender,
                completions,
            })
        }

        fn submit(&mut self, id: u32, packet: QueuedPacket) -> Result<()> {
            return_learning_batch_verdicts(
                &mut self.queue,
                vec![QueuedPacketWork {
                    packet_id: id,
                    packet: Ok(packet),
                }],
                &self.engine,
                &self.shutdown,
                &self.attribution,
                &self.counters,
                &mut ErrorThrottle::default(),
                &mut self.observations,
                &mut self.pending,
            )
        }

        fn release(&mut self, now: Instant) -> Result<()> {
            release_learning_verdicts(
                &mut self.queue,
                &mut self.pending,
                &self.completions,
                &self.engine,
                &self.shutdown,
                &self.counters,
                now,
            )
        }

        fn set_mode(&self, mode: Mode) -> Result<()> {
            let mut engine = self
                .engine
                .lock()
                .map_err(|_| anyhow!("poisoned test engine"))?;
            let revision = engine
                .subscription_revision()
                .map_err(|error| anyhow!(error.message))?;
            engine
                .handle_control(openshield_protocol::ControlRequest::SetMode {
                    expected_revision: revision,
                    mode,
                })
                .map_err(|error| anyhow!(error.message))?;
            Ok(())
        }
    }

    #[test]
    fn learning_initial_syn_waits_for_capture_completion_without_waiting_for_persistence()
    -> Result<()> {
        let mut fixture = LearningQueueFixture::new(LEARNING_QUEUE_CAPACITY)?;
        fixture.submit(42, learning_attribution_work(1, 0)?.packet)?;
        assert!(fixture.queue.0.is_empty());
        assert_eq!(fixture.pending.poll_millis(), LEARNING_PENDING_POLL_MILLIS);
        let captured = fixture.work.try_recv()?;
        let ticket = captured
            .ticket
            .ok_or_else(|| anyhow!("first observation has no ticket"))?;
        fixture.release(Instant::now())?;
        assert!(fixture.queue.0.is_empty());
        // This signal follows identity capture; no persistence worker or disk
        // commit is needed for the Learning verdict to complete.
        complete_learning_capture(Some(ticket), &fixture.completion_sender);
        fixture.release(Instant::now())?;
        assert_eq!(fixture.queue.0, [(42, NF_ACCEPT)]);
        assert!(fixture.pending.packets.is_empty());
        assert_eq!(fixture.pending.poll_millis(), RECEIVE_POLL_MILLIS);
        assert!(fixture.engine.try_lock().is_ok());
        Ok(())
    }

    #[test]
    fn learning_sampled_established_tcp_never_waits_for_capture() -> Result<()> {
        let mut fixture = LearningQueueFixture::new(LEARNING_QUEUE_CAPACITY)?;
        let mut packet = learning_attribution_work(1, 0)?.packet;
        packet.initial_observation = false;
        fixture.submit(1, packet)?;
        assert_eq!(fixture.queue.0, [(1, NF_ACCEPT)]);
        assert!(fixture.pending.packets.is_empty());
        assert!(fixture.work.try_recv()?.ticket.is_none());
        Ok(())
    }

    #[test]
    fn learning_pending_capture_does_not_block_other_flows_or_out_of_order_completion() -> Result<()>
    {
        let mut fixture = LearningQueueFixture::new(LEARNING_QUEUE_CAPACITY)?;
        fixture.submit(1, learning_attribution_work(1, 0)?.packet)?;
        let first = fixture.work.try_recv()?;
        fixture.submit(2, learning_attribution_work(1, 1)?.packet)?;
        let second = fixture.work.try_recv()?;
        let before_deadline = fixture.pending.packets[&1]
            .deadline
            .checked_sub(Duration::from_nanos(1))
            .ok_or_else(|| anyhow!("test deadline underflow"))?;

        let mut established = learning_attribution_work(1, 2)?.packet;
        established.initial_observation = false;
        fixture.submit(3, established)?;
        assert_eq!(fixture.queue.0, [(3, NF_ACCEPT)]);
        assert_eq!(fixture.pending.packets.len(), 2);

        // A slow first capture cannot delay a later capture's verdict.
        complete_learning_capture(second.ticket, &fixture.completion_sender);
        fixture.release(before_deadline)?;
        assert_eq!(fixture.queue.0, [(3, NF_ACCEPT), (2, NF_ACCEPT)]);
        assert!(fixture.pending.packets.contains_key(&1));
        assert_eq!(fixture.pending.packets.len(), 1);

        complete_learning_capture(first.ticket, &fixture.completion_sender);
        fixture.release(before_deadline)?;
        assert_eq!(
            fixture.queue.0,
            [(3, NF_ACCEPT), (2, NF_ACCEPT), (1, NF_ACCEPT)]
        );
        assert!(fixture.pending.packets.is_empty());
        Ok(())
    }

    #[test]
    fn learning_pending_deadlines_expire_together_without_serial_capture_waits() -> Result<()> {
        let mut fixture = LearningQueueFixture::new(LEARNING_QUEUE_CAPACITY)?;
        for id in 0..32 {
            fixture.submit(id, learning_attribution_work(1, id)?.packet)?;
        }
        assert!(fixture.queue.0.is_empty());
        assert_eq!(fixture.pending.packets.len(), 32);
        let first_deadline = fixture.pending.packets[&0].deadline;
        let last_deadline = fixture.pending.packets[&31].deadline;
        fixture.release(
            first_deadline
                .checked_sub(Duration::from_nanos(1))
                .ok_or_else(|| anyhow!("test deadline underflow"))?,
        )?;
        assert!(fixture.queue.0.is_empty());

        // No worker completion is sent. All concurrently pending flows expire
        // by the latest individual deadline, not 32 successive hold intervals.
        fixture.release(last_deadline)?;
        fixture.queue.0.sort_unstable();
        assert_eq!(
            fixture.queue.0,
            (0..32).map(|id| (id, NF_ACCEPT)).collect::<Vec<_>>()
        );
        assert!(fixture.pending.packets.is_empty());
        assert_eq!(fixture.pending.poll_millis(), RECEIVE_POLL_MILLIS);
        Ok(())
    }

    #[test]
    fn learning_only_first_datagram_waits_and_repeated_observations_stay_async() -> Result<()> {
        let mut fixture = LearningQueueFixture::new(LEARNING_QUEUE_CAPACITY)?;
        let mut packet = learning_attribution_work(1, 0)?.packet;
        packet.connection.protocol = TransportProtocol::Udp;
        fixture.submit(1, packet.clone())?;
        assert!(fixture.queue.0.is_empty());
        let first = fixture.work.try_recv()?;
        assert!(first.ticket.is_some());
        fixture.submit(2, packet.clone())?;
        assert_eq!(fixture.queue.0, [(2, NF_ACCEPT)]);
        // Once ordinary debounce expires, another observation is enqueued but
        // the longer seen-flow hint still prevents another hold.
        fixture.observations.attempts.clear();
        fixture.submit(3, packet)?;
        assert_eq!(fixture.queue.0, [(2, NF_ACCEPT), (3, NF_ACCEPT)]);
        assert!(fixture.work.try_recv()?.ticket.is_none());
        assert_eq!(fixture.pending.packets.len(), 1);
        Ok(())
    }

    #[test]
    fn learning_first_packet_deadline_accepts_only_current_learning() -> Result<()> {
        let mut fixture = LearningQueueFixture::new(LEARNING_QUEUE_CAPACITY)?;
        fixture.submit(1, learning_attribution_work(1, 0)?.packet)?;
        let deadline = fixture.pending.packets[&1].deadline;
        fixture.release(
            deadline
                .checked_sub(Duration::from_nanos(1))
                .ok_or_else(|| anyhow!("test deadline underflow"))?,
        )?;
        assert!(fixture.queue.0.is_empty());
        fixture.release(deadline)?;
        assert_eq!(fixture.queue.0, [(1, NF_ACCEPT)]);
        Ok(())
    }

    #[test]
    fn pending_learning_packets_drop_immediately_on_enforcing_or_block_all() -> Result<()> {
        for mode in [Mode::Enforcing, Mode::BlockAll] {
            let mut fixture = LearningQueueFixture::new(LEARNING_QUEUE_CAPACITY)?;
            fixture.submit(1, learning_attribution_work(1, 0)?.packet)?;
            let work = fixture.work.try_recv()?;
            fixture.set_mode(mode)?;
            complete_learning_capture(work.ticket, &fixture.completion_sender);
            fixture.release(Instant::now())?;
            assert_eq!(fixture.queue.0, [(1, NF_DROP)]);
            fixture.submit(2, learning_attribution_work(1, 1)?.packet)?;
            assert_eq!(fixture.queue.0, [(1, NF_DROP), (2, NF_DROP)]);
            assert_eq!(fixture.counters.snapshot().denied, 2);
        }
        Ok(())
    }

    #[test]
    fn pending_learning_completion_cannot_cross_a_generation_even_when_learning_again() -> Result<()>
    {
        let mut fixture = LearningQueueFixture::new(LEARNING_QUEUE_CAPACITY)?;
        fixture.submit(1, learning_attribution_work(1, 0)?.packet)?;
        let work = fixture.work.try_recv()?;
        fixture.set_mode(Mode::Enforcing)?;
        fixture.set_mode(Mode::Learning)?;
        complete_learning_capture(work.ticket, &fixture.completion_sender);
        fixture.release(Instant::now())?;
        assert_eq!(fixture.queue.0, [(1, NF_DROP)]);
        Ok(())
    }

    #[test]
    fn pending_learning_packets_drop_on_shutdown() -> Result<()> {
        let mut fixture = LearningQueueFixture::new(LEARNING_QUEUE_CAPACITY)?;
        fixture.submit(1, learning_attribution_work(1, 0)?.packet)?;
        fixture.shutdown.store(true, Ordering::Release);
        fixture.release(Instant::now())?;
        assert_eq!(fixture.queue.0, [(1, NF_DROP)]);
        Ok(())
    }

    #[test]
    fn pending_learning_capacity_is_bounded_and_overflow_keeps_learning_live() -> Result<()> {
        let mut fixture = LearningQueueFixture::new(LEARNING_QUEUE_CAPACITY)?;
        for id in 0..=u32::try_from(LEARNING_PENDING_CAPACITY)? {
            fixture.submit(id, learning_attribution_work(1, id)?.packet)?;
        }
        assert_eq!(fixture.pending.packets.len(), LEARNING_PENDING_CAPACITY);
        assert_eq!(
            fixture.queue.0,
            [(u32::try_from(LEARNING_PENDING_CAPACITY)?, NF_ACCEPT)]
        );
        let work = fixture.work.try_iter().collect::<Vec<_>>();
        assert_eq!(work.len(), LEARNING_PENDING_CAPACITY + 1);
        assert!(work[LEARNING_PENDING_CAPACITY].ticket.is_none());
        Ok(())
    }

    #[test]
    fn learning_backlog_failure_releases_packet_and_does_not_poison_seen_hint() -> Result<()> {
        let mut fixture = LearningQueueFixture::new(0)?;
        let packet = learning_attribution_work(1, 0)?.packet;
        fixture.submit(1, packet.clone())?;
        assert_eq!(fixture.queue.0, [(1, NF_ACCEPT)]);
        assert!(fixture.pending.packets.is_empty());
        assert!(fixture.pending.seen_flows.is_empty());
        assert_eq!(fixture.counters.snapshot().queue_overflow, 1);
        let (disconnected, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        fixture.attribution = disconnected;
        fixture.submit(2, packet)?;
        assert_eq!(fixture.queue.0, [(1, NF_ACCEPT), (2, NF_ACCEPT)]);
        assert!(fixture.pending.packets.is_empty());
        assert!(fixture.pending.seen_flows.is_empty());
        Ok(())
    }

    #[test]
    fn pending_ticket_serial_rejects_late_completion_and_never_wraps() -> Result<()> {
        let now = Instant::now();
        let mut pending = PendingLearningVerdicts::default();
        let old = pending
            .reserve(42, 7, now)?
            .ok_or_else(|| anyhow!("missing ticket"))?;
        assert!(pending.reserve(42, 7, now).is_err());
        pending.cancel(old);
        let current = pending
            .reserve(42, 7, now)?
            .ok_or_else(|| anyhow!("missing ticket"))?;
        assert_ne!(old.serial, current.serial);
        pending.complete(old);
        pending.cancel(old);
        assert!(!pending.packets[&42].completed);
        let mut wrong_generation = current;
        wrong_generation.flow_generation += 1;
        pending.complete(wrong_generation);
        assert!(!pending.packets[&42].completed);
        pending.complete(current);
        assert!(pending.packets[&42].completed);
        pending.cancel(current);
        pending.last_serial = u64::MAX;
        assert!(pending.reserve(42, 7, now)?.is_none());
        assert_eq!(pending.last_serial, u64::MAX);
        Ok(())
    }

    #[test]
    fn learning_seen_flow_hint_is_bounded_expires_and_resets_on_generation() -> Result<()> {
        let now = Instant::now();
        let mut pending = PendingLearningVerdicts::default();
        let connection = learning_attribution_work(1, 0)?.packet.connection;
        pending.mark_seen(7, connection.clone(), now);
        assert!(pending.seen(7, &connection, now));
        assert!(!pending.seen(7, &connection, now + LEARNING_SEEN_FLOW_TTL));
        pending.mark_seen(7, connection.clone(), now);
        assert!(!pending.seen(8, &connection, now));
        for index in 0..=u32::try_from(LEARNING_TCP_RECENT_CAPACITY)? {
            pending.mark_seen(
                8,
                learning_attribution_work(1, index)?.packet.connection,
                now,
            );
        }
        assert_eq!(pending.seen_flows.len(), LEARNING_TCP_RECENT_CAPACITY);
        Ok(())
    }

    #[test]
    fn learning_batch_dedup_preserves_first_packet_capture_ticket() -> Result<()> {
        let first = learning_attribution_work(7, 0)?;
        let mut held = first.clone();
        let ticket = LearningVerdictTicket {
            packet_id: 42,
            serial: 1,
            flow_generation: 7,
        };
        held.ticket = Some(ticket);
        let (sender, receiver) = mpsc::sync_channel(2);
        sender.try_send(held)?;
        let (_generation, batch) = collect_learning_attribution_batch(first, &receiver);
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].ticket, Some(ticket));
        Ok(())
    }

    #[test]
    fn learning_capture_completion_channel_never_blocks_when_full_or_disconnected() -> Result<()> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let ticket = LearningVerdictTicket {
            packet_id: 42,
            serial: 1,
            flow_generation: 7,
        };
        complete_learning_capture(Some(ticket), &sender);
        complete_learning_capture(Some(ticket), &sender);
        assert_eq!(receiver.try_recv()?, ticket);
        drop(receiver);
        complete_learning_capture(Some(ticket), &sender);
        Ok(())
    }

    #[test]
    fn resolves_interface_name_directly_from_the_kernel_index() -> Result<(), Box<dyn Error>> {
        let loopback_index = nix::net::if_::if_nametoindex("lo")?;
        assert_eq!(interface_for_index(loopback_index)?.as_str(), "lo");
        assert!(interface_for_index(0).is_err());
        Ok(())
    }

    #[test]
    fn learning_batch_coalesces_duplicates_and_discards_stale_generations()
    -> Result<(), Box<dyn Error>> {
        let (sender, receiver) = mpsc::sync_channel(LEARNING_QUEUE_CAPACITY);
        let first = learning_observation(7, 1)?;
        sender.try_send(first.clone())?;
        sender.try_send(learning_observation(7, 2)?)?;
        sender.try_send(learning_observation(8, 3)?)?;

        let (generation, endpoints) = collect_learning_batch(first, &receiver);
        assert_eq!(generation, 7);
        assert_eq!(endpoints.len(), 2);
        assert_eq!(
            endpoints[0].endpoint.address,
            "10.0.0.2".parse::<std::net::IpAddr>()?
        );
        assert_eq!(
            endpoints[1].endpoint.address,
            "10.0.0.3".parse::<std::net::IpAddr>()?
        );
        Ok(())
    }

    #[test]
    fn duplicate_storm_does_not_make_one_batch_drain_without_bound() -> Result<(), Box<dyn Error>> {
        let (sender, receiver) = mpsc::sync_channel(LEARNING_QUEUE_CAPACITY);
        let first = learning_observation(7, 1)?;
        for _ in 0..LEARNING_BATCH_SIZE {
            sender.try_send(first.clone())?;
        }

        let (_generation, endpoints) = collect_learning_batch(first, &receiver);
        assert_eq!(endpoints.len(), 1);
        assert!(receiver.try_recv().is_ok());
        Ok(())
    }

    #[test]
    fn asynchronous_attribution_backlog_is_split_into_resolver_sized_batches()
    -> Result<(), Box<dyn Error>> {
        let (sender, receiver) = mpsc::sync_channel(LEARNING_QUEUE_CAPACITY);
        let total = MAX_ATTRIBUTION_BATCH_SIZE + 5;
        let first = learning_attribution_work(7, 0)?;
        for offset in 1..total {
            sender.try_send(learning_attribution_work(7, u32::try_from(offset)?)?)?;
        }

        let (generation, first_batch) = collect_learning_attribution_batch(first, &receiver);
        assert_eq!(generation, 7);
        assert_eq!(first_batch.len(), MAX_ATTRIBUTION_BATCH_SIZE);
        let next = receiver.try_recv()?;
        let (generation, second_batch) = collect_learning_attribution_batch(next, &receiver);
        assert_eq!(generation, 7);
        assert_eq!(first_batch.len() + second_batch.len(), total);
        assert!(receiver.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn asynchronous_attribution_coalesces_connections_and_discards_stale_generations()
    -> Result<(), Box<dyn Error>> {
        let (sender, receiver) = mpsc::sync_channel(LEARNING_QUEUE_CAPACITY);
        let first = learning_attribution_work(7, 1)?;
        let mut duplicate = first.clone();
        duplicate.packet.packet_mark = 5;
        sender.try_send(duplicate)?;
        sender.try_send(learning_attribution_work(8, 2)?)?;
        sender.try_send(learning_attribution_work(7, 3)?)?;

        let (generation, batch) = collect_learning_attribution_batch(first, &receiver);

        assert_eq!(generation, 7);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].packet.connection.source_port, Some(40_001));
        assert_eq!(batch[1].packet.connection.source_port, Some(40_003));
        Ok(())
    }

    #[test]
    fn duplicate_attribution_storm_keeps_the_batch_drain_bounded() -> Result<(), Box<dyn Error>> {
        let (sender, receiver) = mpsc::sync_channel(LEARNING_QUEUE_CAPACITY);
        let first = learning_attribution_work(7, 1)?;
        for _ in 0..MAX_ATTRIBUTION_BATCH_SIZE {
            sender.try_send(first.clone())?;
        }

        let (_, batch) = collect_learning_attribution_batch(first, &receiver);

        assert_eq!(batch.len(), 1);
        assert!(receiver.try_recv().is_ok());
        Ok(())
    }

    #[test]
    fn learning_tcp_debounce_retries_without_sliding_the_deadline() -> Result<(), Box<dyn Error>> {
        let connection = learning_attribution_work(7, 1)?.packet.connection;
        let mut debounce = LearningAttributionDebounce::default();
        let now = Instant::now();

        assert!(debounce.should_attempt(7, &connection, now));
        assert!(!debounce.should_attempt(7, &connection, now + Duration::from_millis(999)));
        assert!(debounce.should_attempt(7, &connection, now + LEARNING_TCP_RETRY_INTERVAL));
        assert!(!debounce.should_attempt(7, &connection, now + Duration::from_millis(1_001)));
        // A new policy generation retries immediately, regardless of whether
        // the previous attempt succeeded, failed, or was still in flight.
        assert!(debounce.should_attempt(8, &connection, now + Duration::from_millis(1_001)));
        Ok(())
    }

    #[test]
    fn learning_observation_coalescing_prevents_repeated_datagrams_filling_the_backlog()
    -> Result<(), Box<dyn Error>> {
        let mut connection = learning_attribution_work(7, 1)?.packet.connection;
        connection.protocol = TransportProtocol::Udp;
        let mut observations = LearningAttributionDebounce::default();
        let now = Instant::now();
        assert!(observations.should_enqueue(7, &connection, now));
        for _ in 0..LEARNING_QUEUE_CAPACITY {
            assert!(!observations.should_enqueue(7, &connection, now));
        }
        let mut other_application = connection.clone();
        other_application.socket_uid += 1;
        assert!(observations.should_enqueue(7, &other_application, now));
        assert!(observations.should_enqueue(
            7,
            &connection,
            now + LEARNING_DATAGRAM_COALESCE_INTERVAL,
        ));
        assert!(observations.should_enqueue(8, &connection, now));
        Ok(())
    }

    #[test]
    fn learning_tcp_retry_interval_starts_after_a_slow_background_scan()
    -> Result<(), Box<dyn Error>> {
        let connection = learning_attribution_work(7, 1)?.packet.connection;
        let mut observations = LearningAttributionDebounce::default();
        let started = Instant::now();
        assert!(observations.should_attempt(7, &connection, started));
        let completed = started + Duration::from_secs(4);
        observations.completed(&connection, completed);
        assert!(!observations.should_attempt(7, &connection, completed));
        assert!(observations.should_attempt(
            7,
            &connection,
            completed + LEARNING_TCP_RETRY_INTERVAL,
        ));
        Ok(())
    }

    #[test]
    fn learning_tcp_debounce_has_a_fixed_capacity_without_refusing_new_flows()
    -> Result<(), Box<dyn Error>> {
        let mut debounce = LearningAttributionDebounce::default();
        let now = Instant::now();
        for offset in 0..=LEARNING_TCP_RECENT_CAPACITY {
            let connection = learning_attribution_work(7, u32::try_from(offset)?)?
                .packet
                .connection;
            assert!(debounce.should_attempt(7, &connection, now));
            assert!(debounce.attempts.len() <= LEARNING_TCP_RECENT_CAPACITY);
        }
        let next = learning_attribution_work(7, u32::try_from(LEARNING_TCP_RECENT_CAPACITY + 1)?)?
            .packet
            .connection;
        assert!(debounce.should_attempt(7, &next, now + LEARNING_TCP_RETRY_INTERVAL));
        assert_eq!(debounce.attempts.len(), 1);
        Ok(())
    }

    #[test]
    fn learning_tcp_debounce_separates_socket_uids_interfaces_and_transport_protocols()
    -> Result<(), Box<dyn Error>> {
        let connection = learning_attribution_work(7, 1)?.packet.connection;
        let mut debounce = LearningAttributionDebounce::default();
        let now = Instant::now();
        assert!(debounce.should_attempt(7, &connection, now));

        let mut different_uid = connection.clone();
        different_uid.socket_uid += 1;
        assert!(debounce.should_attempt(7, &different_uid, now));
        let mut different_interface = connection.clone();
        different_interface.output_interface = InterfaceName::new("eth1")?;
        assert!(debounce.should_attempt(7, &different_interface, now));

        let mut udp = connection;
        udp.protocol = TransportProtocol::Udp;
        assert!(debounce.should_attempt(7, &udp, now));
        assert!(debounce.should_attempt(7, &udp, now));
        Ok(())
    }

    #[test]
    fn learning_deny_queue_drops_parse_errors_but_defers_no_candidate_observation()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let owner = std::fs::metadata(directory.path())?.uid();
        let store = AtomicStateStore::for_owner(directory.path().join("state.json"), owner);
        let interface = InterfaceName::new("eth0")?;
        let mut deny = RuleSpec::new(
            RuleName::new("uid-scoped application deny")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.7/32".parse()?),
            Some(PortRange::single(443)?),
            Some(interface.clone()),
            RuleOrigin::Manual,
            true,
        )?;
        deny.action = RuleAction::Drop;
        deny.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new("/usr/bin/curl")?),
            Some(ExecutableFileId {
                device: 8,
                inode: 9,
                size: 10,
                ctime_seconds: 11,
                ctime_nanoseconds: 12,
            }),
            None,
            Some(1_000),
            None,
        )?);
        let mut state = State::new();
        state.set_mode(Mode::Learning)?;
        state.create_rule(deny)?;
        store.save(&state)?;
        let engine = Engine::load(
            Box::new(MemoryBackend::default()),
            Box::new(store),
            EventBus::new(),
        )?;
        let (mode, _generation) = engine
            .application_decision_identity()
            .map_err(|error| anyhow!(error.message))?;
        assert_eq!(mode, Mode::Learning);
        let engine = Arc::new(Mutex::new(engine));
        let resolver = ProcfsResolver::at(directory.path().join("empty-proc"));
        let (learning_sender, receiver) = mpsc::sync_channel(LEARNING_QUEUE_CAPACITY);
        let uid_mismatch = QueuedPacket {
            connection: OutboundConnection {
                source_address: "192.0.2.1".parse()?,
                source_port: Some(50_000),
                destination_address: "203.0.113.7".parse()?,
                destination_port: Some(443),
                protocol: TransportProtocol::Tcp,
                output_interface: interface,
                socket_uid: 1_001,
            },
            packet_mark: application_pending_mark(7),
            initial_observation: true,
        };
        let mut matching_uid = uid_mismatch.clone();
        matching_uid.connection.socket_uid = 1_000;
        let batch = vec![
            QueuedPacketWork {
                packet_id: 1,
                packet: Err("unsupported packet shape".to_owned()),
            },
            QueuedPacketWork {
                packet_id: 2,
                packet: Ok(uid_mismatch),
            },
            QueuedPacketWork {
                packet_id: 3,
                packet: Ok(matching_uid),
            },
        ];
        let shutdown = AtomicBool::new(false);
        let decisions =
            decide_packet_batch(&batch, &engine, &shutdown, &resolver, &learning_sender);
        assert_eq!(decisions.len(), 3);
        assert!(decisions[0].is_err());
        let fallback = decisions[1]
            .as_ref()
            .map_err(|error| format!("{error:#}"))?;
        assert_eq!(fallback.action, RuleAction::Accept);
        assert!(fallback.defer_learning_attribution);
        assert!(decisions[2].is_err());
        assert!(receiver.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn queued_uid_mismatch_uses_matching_network_accept_without_procfs_attribution()
    -> Result<(), Box<dyn Error>> {
        let interface = InterfaceName::new("eth0")?;
        let mut application_rule = RuleSpec::new(
            RuleName::new("application deny")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.7/32".parse()?),
            Some(PortRange::single(443)?),
            Some(interface.clone()),
            RuleOrigin::Manual,
            true,
        )?;
        application_rule.action = RuleAction::Drop;
        application_rule.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new("/usr/bin/curl")?),
            Some(ExecutableFileId {
                device: 8,
                inode: 9,
                size: 10,
                ctime_seconds: 11,
                ctime_nanoseconds: 12,
            }),
            None,
            Some(1_000),
            None,
        )?);
        let network_accept = RuleSpec::new(
            RuleName::new("network accept")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.0/24".parse()?),
            Some(PortRange::single(443)?),
            Some(interface.clone()),
            RuleOrigin::Manual,
            true,
        )?;
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        state.create_rule(application_rule)?;
        state.create_rule(network_accept)?;

        let directory = tempfile::tempdir()?;
        let owner = std::fs::metadata(directory.path())?.uid();
        let store = AtomicStateStore::for_owner(directory.path().join("state.json"), owner);
        store.save(&state)?;
        let engine = Arc::new(Mutex::new(Engine::load(
            Box::new(MemoryBackend::default()),
            Box::new(store),
            EventBus::new(),
        )?));
        let packet = QueuedPacket {
            connection: OutboundConnection {
                source_address: "192.0.2.1".parse()?,
                source_port: Some(50_000),
                destination_address: "203.0.113.7".parse()?,
                destination_port: Some(443),
                protocol: TransportProtocol::Tcp,
                output_interface: interface,
                socket_uid: 1_001,
            },
            packet_mark: application_pending_mark(0),
            initial_observation: true,
        };
        let batch = [QueuedPacketWork {
            packet_id: 1,
            packet: Ok(packet),
        }];
        let (learning_sender, _learning_receiver) = mpsc::sync_channel(1);
        let shutdown = AtomicBool::new(false);
        let decisions = decide_packet_batch(
            &batch,
            &engine,
            &shutdown,
            &ProcfsResolver::at(directory.path().join("empty-proc")),
            &learning_sender,
        );
        let authorization = decisions.into_iter().next().ok_or("missing decision")??;
        assert_eq!(authorization.mode, Mode::Enforcing);
        assert_eq!(authorization.action, RuleAction::Accept);
        assert!(authorization.observation_error.is_none());
        Ok(())
    }

    #[test]
    fn message_and_attribute_parsers_reject_truncation() {
        assert!(
            NetlinkMessages::new(&[1, 2, 3])
                .next()
                .is_some_and(|item| item.is_err())
        );
        assert!(
            Attributes::new(&[1, 2, 3])
                .next()
                .is_some_and(|item| item.is_err())
        );
    }

    #[test]
    fn interrupted_ready_receive_does_not_prove_an_empty_queue() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            classify_ready_receive(Err(Errno::EINTR), RECEIVE_BUFFER_BYTES)?,
            QueueReceive::Interrupted
        );
        assert_eq!(
            classify_ready_receive(Err(Errno::EAGAIN), RECEIVE_BUFFER_BYTES)?,
            QueueReceive::Idle
        );
        assert_eq!(
            classify_ready_receive(Err(Errno::ENOBUFS), RECEIVE_BUFFER_BYTES)?,
            QueueReceive::Overflow
        );
        assert_eq!(
            classify_ready_receive(Ok(12), RECEIVE_BUFFER_BYTES)?,
            QueueReceive::Datagram(12)
        );
        assert!(classify_ready_receive(Err(Errno::EBADF), RECEIVE_BUFFER_BYTES).is_err());
        assert!(classify_ready_receive(Ok(0), RECEIVE_BUFFER_BYTES).is_err());
        assert!(
            classify_ready_receive(Ok(RECEIVE_BUFFER_BYTES + 1), RECEIVE_BUFFER_BYTES).is_err()
        );
        Ok(())
    }

    #[test]
    fn received_datagram_size_rejects_empty_and_truncated_input() {
        assert!(
            validate_received_datagram_size(0, RECEIVE_BUFFER_BYTES)
                .is_err_and(|error| error.to_string().contains("empty netlink datagram"))
        );
        assert!(
            validate_received_datagram_size(RECEIVE_BUFFER_BYTES + 1, RECEIVE_BUFFER_BYTES)
                .is_err_and(|error| error.to_string().contains("exceeded its fixed buffer"))
        );
        assert_eq!(
            validate_received_datagram_size(1, RECEIVE_BUFFER_BYTES).ok(),
            Some(1)
        );
    }

    #[test]
    fn packet_batch_preserves_every_bounded_packet_identifier() -> Result<(), Box<dyn Error>> {
        let mut datagram = Vec::new();
        for packet_id in [7_u32, 11_u32] {
            let mut packet_header = [0_u8; PACKET_HEADER_BYTES];
            packet_header[..4].copy_from_slice(&packet_id.to_be_bytes());
            datagram.extend_from_slice(&build_message(
                queue_message_type(NFQNL_MSG_PACKET),
                0,
                0,
                NFNETLINK_FAMILY_UNSPEC,
                APPLICATION_QUEUE_NUMBER,
                &[(NFQA_PACKET_HDR, packet_header.as_slice())],
            )?);
        }

        let mut batch = Vec::new();
        append_packet_datagram(&datagram, &mut batch)?;
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].packet_id, 7);
        assert_eq!(batch[1].packet_id, 11);
        assert!(batch.iter().all(|packet| packet.packet.is_err()));
        Ok(())
    }

    #[test]
    fn packet_batch_refuses_more_than_its_fixed_attribution_bound() -> Result<(), Box<dyn Error>> {
        let mut datagram = Vec::new();
        for packet_id in 0..=u32::try_from(MAX_PACKET_BATCH_SIZE)? {
            let mut packet_header = [0_u8; PACKET_HEADER_BYTES];
            packet_header[..4].copy_from_slice(&packet_id.to_be_bytes());
            datagram.extend_from_slice(&build_message(
                queue_message_type(NFQNL_MSG_PACKET),
                0,
                0,
                NFNETLINK_FAMILY_UNSPEC,
                APPLICATION_QUEUE_NUMBER,
                &[(NFQA_PACKET_HDR, packet_header.as_slice())],
            )?);
        }

        let mut batch = Vec::new();
        let error = append_packet_datagram(&datagram, &mut batch)
            .err()
            .ok_or("oversized queued packet batch was accepted")?;
        assert!(error.to_string().contains("exceeds its fixed bound"));
        assert_eq!(batch.len(), MAX_PACKET_BATCH_SIZE);
        Ok(())
    }

    #[test]
    fn parsers_accept_only_exact_unpadded_terminal_items() -> Result<(), Box<dyn Error>> {
        let mut message = vec![0_u8; NETLINK_HEADER_BYTES + 1];
        let message_length = u32::try_from(message.len())?;
        message[..4].copy_from_slice(&message_length.to_ne_bytes());
        message[4..6].copy_from_slice(&7_u16.to_ne_bytes());
        let parsed = NetlinkMessages::new(&message)
            .next()
            .ok_or("missing unpadded message")??;
        assert_eq!(parsed.payload, &[0]);

        message.push(0);
        assert!(
            NetlinkMessages::new(&message)
                .next()
                .is_some_and(|item| item.is_err())
        );

        let mut attribute = vec![0_u8; ATTRIBUTE_HEADER_BYTES + 1];
        let attribute_length = u16::try_from(attribute.len())?;
        attribute[..2].copy_from_slice(&attribute_length.to_ne_bytes());
        attribute[2..4].copy_from_slice(&9_u16.to_ne_bytes());
        let parsed = Attributes::new(&attribute)
            .next()
            .ok_or("missing unpadded attribute")??;
        assert_eq!(parsed.kind, 9);
        assert_eq!(parsed.payload, &[0]);

        attribute.push(0);
        assert!(
            Attributes::new(&attribute)
                .next()
                .is_some_and(|item| item.is_err())
        );
        Ok(())
    }

    #[test]
    fn configuration_message_is_bounded_and_uses_network_order_attributes()
    -> Result<(), Box<dyn Error>> {
        let queue_length = QUEUE_MAX_LENGTH.to_be_bytes();
        let message = build_message(
            queue_message_type(NFQNL_MSG_CONFIG),
            NLM_F_REQUEST,
            7,
            0,
            APPLICATION_QUEUE_NUMBER,
            &[(NFQA_CFG_QUEUE_MAXLEN, queue_length.as_slice())],
        )?;
        let parsed = NetlinkMessages::new(&message)
            .next()
            .ok_or("missing message")??;
        assert_eq!(parsed.message_type, queue_message_type(NFQNL_MSG_CONFIG));
        assert_eq!(parsed.sequence, 7);
        let attribute = Attributes::new(&parsed.payload[NFGENMSG_BYTES..])
            .next()
            .ok_or("missing attribute")??;
        assert_eq!(attribute.kind, NFQA_CFG_QUEUE_MAXLEN);
        assert_eq!(network_u32(attribute.payload)?, QUEUE_MAX_LENGTH);
        Ok(())
    }

    #[test]
    fn netlink_sequence_wraps_without_entering_the_unsolicited_zero_domain() {
        let mut sequence = u32::MAX;
        assert_eq!(advance_netlink_sequence(&mut sequence), 1);
        assert_eq!(advance_netlink_sequence(&mut sequence), 2);
    }

    #[test]
    fn parses_ipv4_tcp_tuple() -> Result<(), Box<dyn Error>> {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[203, 0, 113, 7]);
        packet[20..22].copy_from_slice(&50_000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[32] = 0x50;
        let parsed = parse_ip_packet(&packet)?;
        assert_eq!(
            parsed.source_address,
            "192.0.2.1".parse::<std::net::IpAddr>()?
        );
        assert_eq!(
            parsed.destination_address,
            "203.0.113.7".parse::<std::net::IpAddr>()?
        );
        assert_eq!(parsed.source_port, Some(50_000));
        assert_eq!(parsed.destination_port, Some(443));
        assert_eq!(parsed.protocol, TransportProtocol::Tcp);
        assert!(!parsed.initial_observation);
        for (flags, initial) in [
            (0x02, true),
            (0xc2, true),
            (0x12, false),
            (0x10, false),
            (0x03, false),
            (0x06, false),
        ] {
            packet[33] = flags;
            assert_eq!(parse_ip_packet(&packet)?.initial_observation, initial);
        }
        assert!(parse_ip_packet(&packet[..24]).is_err());
        packet[9] = 17;
        packet[24..26].copy_from_slice(&20_u16.to_be_bytes());
        assert!(parse_ip_packet(&packet)?.initial_observation);
        Ok(())
    }

    #[test]
    fn learning_packet_without_nfqa_mark_parses_as_unmarked() -> Result<(), Box<dyn Error>> {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[203, 0, 113, 7]);
        packet[20..22].copy_from_slice(&50_000_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
        packet[32] = 0x50;
        let uid = 1_000_u32.to_be_bytes();
        let output_index = nix::net::if_::if_nametoindex("lo")?.to_be_bytes();
        let message = build_message(
            queue_message_type(NFQNL_MSG_PACKET),
            0,
            1,
            NFNETLINK_FAMILY_UNSPEC,
            APPLICATION_LEARNING_QUEUE_NUMBER,
            &[
                (NFQA_PAYLOAD, packet.as_slice()),
                (NFQA_UID, uid.as_slice()),
                (NFQA_IFINDEX_OUTDEV, output_index.as_slice()),
            ],
        )?;
        let payload = NetlinkMessages::new(&message)
            .next()
            .ok_or("missing packet message")??
            .payload;
        let queued = parse_queued_packet(payload)?;
        assert_eq!(queued.packet_mark, 0);
        assert_eq!(queued.connection.socket_uid, 1_000);
        assert_eq!(queued.connection.output_interface.as_str(), "lo");
        Ok(())
    }

    #[test]
    fn parses_only_attributable_icmp_echo_identifiers() -> Result<(), Box<dyn Error>> {
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
        packet[16..20].copy_from_slice(&[203, 0, 113, 7]);
        packet[20] = 8;
        packet[24..26].copy_from_slice(&4_242_u16.to_be_bytes());
        let parsed = parse_ip_packet(&packet)?;
        assert_eq!(parsed.protocol, TransportProtocol::Icmp);
        assert_eq!(parsed.source_port, Some(4_242));
        assert_eq!(parsed.destination_port, None);

        packet[20] = 3;
        assert!(parse_ip_packet(&packet).is_err());
        Ok(())
    }

    #[test]
    fn drops_non_initial_fragments_and_deep_ipv6_extensions() {
        let mut ipv4 = vec![0_u8; 20];
        ipv4[0] = 0x45;
        ipv4[2..4].copy_from_slice(&20_u16.to_be_bytes());
        ipv4[6..8].copy_from_slice(&1_u16.to_be_bytes());
        assert!(parse_ip_packet(&ipv4).is_err());

        let mut ipv6 = vec![0_u8; 40 + 9 * 8];
        ipv6[0] = 0x60;
        ipv6[4..6].copy_from_slice(&72_u16.to_be_bytes());
        ipv6[6] = 0;
        for index in 0..9 {
            let offset = 40 + index * 8;
            ipv6[offset] = 0;
            ipv6[offset + 1] = 0;
        }
        assert!(parse_ip_packet(&ipv6).is_err());
    }

    #[test]
    fn nft_accept_and_drop_verdicts_do_not_carry_a_mark() -> Result<(), Box<dyn Error>> {
        for verdict in [NF_DROP, NF_ACCEPT] {
            let message = build_verdict_message(1, APPLICATION_QUEUE_NUMBER, 7, verdict, None)?;
            let netlink = NetlinkMessages::new(&message)
                .next()
                .ok_or("missing verdict message")??;
            let attributes =
                Attributes::new(&netlink.payload[NFGENMSG_BYTES..]).collect::<Result<Vec<_>>>()?;
            let header = attributes
                .iter()
                .find(|attribute| attribute.kind == NFQA_VERDICT_HDR)
                .ok_or("missing verdict header")?;
            assert_eq!(network_u32(&header.payload[..4])?, verdict);
            assert_eq!(network_u32(&header.payload[4..])?, 7);
            let mark = attributes
                .iter()
                .find(|attribute| attribute.kind == NFQA_MARK)
                .map(|attribute| network_u32(attribute.payload))
                .transpose()?;
            assert_eq!(mark, None);
        }
        Ok(())
    }

    #[test]
    fn iptables_accept_verdict_carries_the_handoff_mark() -> Result<(), Box<dyn Error>> {
        let mark = application_handoff_mark(0x0012_3456);
        let message = build_verdict_message(1, APPLICATION_QUEUE_NUMBER, 7, NF_ACCEPT, Some(mark))?;
        let netlink = NetlinkMessages::new(&message)
            .next()
            .ok_or("missing verdict message")??;
        let attributes =
            Attributes::new(&netlink.payload[NFGENMSG_BYTES..]).collect::<Result<Vec<_>>>()?;
        let header = attributes
            .iter()
            .find(|attribute| attribute.kind == NFQA_VERDICT_HDR)
            .ok_or("missing verdict header")?;
        assert_eq!(network_u32(&header.payload[..4])?, NF_ACCEPT);
        assert_eq!(network_u32(&header.payload[4..])?, 7);
        let returned_mark = attributes
            .iter()
            .find(|attribute| attribute.kind == NFQA_MARK)
            .ok_or("missing verdict mark")?;
        assert_eq!(network_u32(returned_mark.payload)?, mark);
        Ok(())
    }

    #[test]
    fn application_actions_map_to_backend_safe_nfqueue_verdicts() {
        let original_mark = 0x0012_3456;
        assert_eq!(
            authorization_verdict(
                RuleAction::Accept,
                QueueVerdictStrategy::Accept,
                original_mark
            ),
            (NF_ACCEPT, None)
        );
        assert_eq!(
            authorization_verdict(
                RuleAction::Accept,
                QueueVerdictStrategy::RepeatWithHandoffMark,
                original_mark
            ),
            (NF_REPEAT, Some(application_handoff_mark(original_mark)))
        );
        for strategy in [
            QueueVerdictStrategy::Accept,
            QueueVerdictStrategy::RepeatWithHandoffMark,
        ] {
            assert_eq!(
                authorization_verdict(RuleAction::Drop, strategy, original_mark),
                (NF_DROP, None)
            );
        }
        assert_eq!(
            authorization_verdict(
                RuleAction::Reject,
                QueueVerdictStrategy::Accept,
                original_mark
            ),
            (NF_ACCEPT, Some(application_reject_mark(original_mark)))
        );
        assert_eq!(
            authorization_verdict(
                RuleAction::Reject,
                QueueVerdictStrategy::RepeatWithHandoffMark,
                original_mark
            ),
            (NF_REPEAT, Some(application_reject_mark(original_mark)))
        );
    }

    #[test]
    fn queued_decisions_require_an_exact_mode_generation_and_shutdown_recheck() {
        let learning = PacketAuthorization {
            mode: Mode::Learning,
            flow_generation: 7,
            packet_mark: application_pending_mark(0),
            action: RuleAction::Accept,
            observation_error: None,
            defer_learning_attribution: false,
        };
        assert!(authorization_remains_valid(
            &learning,
            Mode::Learning,
            7,
            false
        ));
        assert!(!authorization_remains_valid(
            &learning,
            Mode::Learning,
            8,
            false
        ));
        assert!(!authorization_remains_valid(
            &learning,
            Mode::Enforcing,
            8,
            false
        ));
        assert!(!authorization_remains_valid(
            &learning,
            Mode::BlockAll,
            8,
            false
        ));
        assert!(!authorization_remains_valid(
            &learning,
            Mode::Learning,
            7,
            true
        ));

        let enforcing = PacketAuthorization {
            mode: Mode::Enforcing,
            flow_generation: 8,
            packet_mark: application_pending_mark(0),
            action: RuleAction::Accept,
            observation_error: None,
            defer_learning_attribution: false,
        };
        assert!(authorization_remains_valid(
            &enforcing,
            Mode::Enforcing,
            8,
            false
        ));
        assert!(!authorization_remains_valid(
            &enforcing,
            Mode::Enforcing,
            9,
            false
        ));
        assert!(!authorization_remains_valid(
            &enforcing,
            Mode::Enforcing,
            8,
            true
        ));
    }

    #[test]
    fn only_learning_queue_enables_kernel_overflow_acceptance() {
        assert_eq!(
            queue_configuration_flags(false),
            (
                NFQA_CFG_F_UID_GID | NFQA_CFG_F_GSO,
                NFQA_CFG_F_UID_GID | NFQA_CFG_F_GSO | NFQA_CFG_F_FAIL_OPEN
            )
        );
        assert_eq!(
            queue_configuration_flags(true),
            (
                NFQA_CFG_F_UID_GID | NFQA_CFG_F_GSO | NFQA_CFG_F_FAIL_OPEN,
                NFQA_CFG_F_UID_GID | NFQA_CFG_F_GSO | NFQA_CFG_F_FAIL_OPEN
            )
        );
        assert_ne!(APPLICATION_QUEUE_NUMBER, APPLICATION_LEARNING_QUEUE_NUMBER);
    }

    fn tcp_capture_prefix(ipv6: bool, original_length: u32) -> Vec<u8> {
        let mut packet = vec![0_u8; 512];
        let offset = if ipv6 { 40 } else { 20 };
        if ipv6 {
            packet[0] = 0x60;
            let payload_length = u16::try_from(original_length - 40).unwrap_or_default();
            packet[4..6].copy_from_slice(&payload_length.to_be_bytes());
            packet[6] = 6;
            packet[23] = 1;
            packet[39] = 2;
        } else {
            packet[0] = 0x45;
            let total_length = u16::try_from(original_length).unwrap_or_default();
            packet[2..4].copy_from_slice(&total_length.to_be_bytes());
            packet[9] = 6;
            packet[12..16].copy_from_slice(&[192, 0, 2, 1]);
            packet[16..20].copy_from_slice(&[198, 51, 100, 1]);
        }
        packet[offset..offset + 2].copy_from_slice(&50_000_u16.to_be_bytes());
        packet[offset + 2..offset + 4].copy_from_slice(&443_u16.to_be_bytes());
        packet[offset + 12] = 0x50;
        packet[offset + 13] = 0x18;
        packet
    }

    fn capture_attributes(packet: &[u8], original_length: u32, skb_info: u32) -> Result<Vec<u8>> {
        let mut attributes = Vec::new();
        append_attribute(&mut attributes, NFQA_PAYLOAD, packet)?;
        append_attribute(
            &mut attributes,
            NFQA_CAP_LEN,
            &original_length.to_be_bytes(),
        )?;
        append_attribute(&mut attributes, NFQA_SKB_INFO, &skb_info.to_be_bytes())?;
        Ok(attributes)
    }

    #[test]
    fn gso_capture_parses_bounded_large_packet_prefixes_without_checksum_guessing() -> Result<()> {
        for ipv6 in [false, true] {
            for skb_info in [0, NFQA_SKB_GSO, NFQA_SKB_GSO | 1, NFQA_SKB_GSO | 4] {
                let packet = tcp_capture_prefix(ipv6, 60_000);
                let attributes = capture_attributes(&packet, 60_000, skb_info)?;
                let capture = parse_packet_capture(&attributes)?;
                let parsed = capture.parse(IpPacketDirection::Outbound)?;
                assert_eq!(capture.payload.len(), 512);
                assert_eq!(capture.original_length, 60_000);
                assert_eq!(parsed.protocol, TransportProtocol::Tcp);
                assert_eq!(parsed.source_port, Some(50_000));
                assert_eq!(parsed.destination_port, Some(443));
                assert_eq!(parsed.tcp_flags, Some(0x18));
            }
        }
        Ok(())
    }

    #[test]
    fn big_tcp_zero_length_requires_kernel_gso_and_original_size_metadata() -> Result<()> {
        for ipv6 in [false, true] {
            for original_length in [70_000, 262_144, u32::MAX] {
                let packet = tcp_capture_prefix(ipv6, original_length);
                let attributes = capture_attributes(&packet, original_length, NFQA_SKB_GSO)?;
                assert!(
                    parse_packet_capture(&attributes)?
                        .parse(IpPacketDirection::Outbound)
                        .is_ok()
                );
                let attributes = capture_attributes(&packet, original_length, 0)?;
                assert!(
                    parse_packet_capture(&attributes)?
                        .parse(IpPacketDirection::Outbound)
                        .is_err()
                );
                let attributes = capture_attributes(&packet, 512, NFQA_SKB_GSO)?;
                assert!(
                    parse_packet_capture(&attributes)?
                        .parse(IpPacketDirection::Outbound)
                        .is_err()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn big_tcp_ipv6_hop_by_hop_header_keeps_bounded_transport_parsing() -> Result<()> {
        let original_length = 262_144_u32;
        let mut packet = tcp_capture_prefix(true, original_length);
        packet.copy_within(40..60, 48);
        packet[6] = 0;
        packet[40..48].copy_from_slice(&[6, 0, 0xc2, 4, 0, 0, 0, 0]);
        packet[44..48].copy_from_slice(&(original_length - 40).to_be_bytes());
        let attributes = capture_attributes(&packet, original_length, NFQA_SKB_GSO | 1)?;
        let parsed = parse_packet_capture(&attributes)?.parse(IpPacketDirection::Outbound)?;
        assert_eq!(parsed.transport_offset, 48);
        assert_eq!(parsed.source_port, Some(50_000));
        assert_eq!(parsed.destination_port, Some(443));
        assert_eq!(parsed.tcp_flags, Some(0x18));
        let attributes = capture_attributes(&packet[..60], original_length, NFQA_SKB_GSO)?;
        assert!(
            parse_packet_capture(&attributes)?
                .parse(IpPacketDirection::Outbound)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn udp_segmentation_keeps_kernel_length_separate_from_datagram_length() -> Result<()> {
        for ipv6 in [false, true] {
            let mut packet = tcp_capture_prefix(ipv6, 60_000);
            let offset = if ipv6 { 40 } else { 20 };
            packet[if ipv6 { 6 } else { 9 }] = 17;
            packet[offset + 4..offset + 6].copy_from_slice(&1208_u16.to_be_bytes());
            let attributes = capture_attributes(&packet, 60_000, NFQA_SKB_GSO | 1)?;
            let parsed = parse_packet_capture(&attributes)?.parse(IpPacketDirection::Outbound)?;
            assert_eq!(parsed.protocol, TransportProtocol::Udp);
            assert_eq!(parsed.source_port, Some(50_000));
            assert_eq!(parsed.destination_port, Some(443));
        }
        Ok(())
    }

    #[test]
    fn capture_metadata_rejects_duplicates_invalid_lengths_and_oversized_prefixes() -> Result<()> {
        let packet = tcp_capture_prefix(false, 60_000);
        for kind in [NFQA_PAYLOAD, NFQA_CAP_LEN, NFQA_SKB_INFO] {
            let mut attributes = capture_attributes(&packet, 60_000, NFQA_SKB_GSO)?;
            append_attribute(&mut attributes, kind, &[0; 4])?;
            assert!(parse_packet_capture(&attributes).is_err());
        }
        for original_length in [0, 511] {
            assert!(
                parse_packet_capture(&capture_attributes(&packet, original_length, 0)?).is_err()
            );
        }
        for kind in [NFQA_CAP_LEN, NFQA_SKB_INFO] {
            let mut attributes = Vec::new();
            append_attribute(&mut attributes, NFQA_PAYLOAD, &packet)?;
            append_attribute(&mut attributes, kind, &[0; 3])?;
            assert!(parse_packet_capture(&attributes).is_err());
        }
        assert!(
            parse_packet_capture(&capture_attributes(&[0; 513], 60_000, NFQA_SKB_GSO)?).is_err()
        );
        assert!(parse_packet_capture(&capture_attributes(&[], 60_000, NFQA_SKB_GSO)?).is_err());
        Ok(())
    }

    #[test]
    fn gso_captures_still_require_complete_tcp_and_udp_headers() -> Result<()> {
        let packet = tcp_capture_prefix(false, 60_000);
        for prefix_length in [24, 33, 39] {
            let attributes = capture_attributes(&packet[..prefix_length], 60_000, NFQA_SKB_GSO)?;
            assert!(
                parse_packet_capture(&attributes)?
                    .parse(IpPacketDirection::Outbound)
                    .is_err()
            );
        }
        for data_offset in [0x40, 0xf0] {
            let mut packet = packet[..40].to_vec();
            packet[32] = data_offset;
            let attributes = capture_attributes(&packet, 60_000, NFQA_SKB_GSO)?;
            assert!(
                parse_packet_capture(&attributes)?
                    .parse(IpPacketDirection::Outbound)
                    .is_err()
            );
        }
        let mut udp = packet;
        udp[9] = 17;
        for length in [0_u16, 7, 60_000] {
            udp[24..26].copy_from_slice(&length.to_be_bytes());
            let attributes = capture_attributes(&udp, 60_000, NFQA_SKB_GSO)?;
            assert!(
                parse_packet_capture(&attributes)?
                    .parse(IpPacketDirection::Outbound)
                    .is_err()
            );
        }
        udp[24..26].copy_from_slice(&1208_u16.to_be_bytes());
        let attributes = capture_attributes(&udp, 60_000, NFQA_SKB_GSO)?;
        assert_eq!(
            parse_packet_capture(&attributes)?
                .parse(IpPacketDirection::Outbound)?
                .protocol,
            TransportProtocol::Udp
        );
        let attributes = capture_attributes(&udp[..27], 60_000, NFQA_SKB_GSO)?;
        assert!(
            parse_packet_capture(&attributes)?
                .parse(IpPacketDirection::Outbound)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn gso_capture_does_not_supply_a_missing_socket_uid() -> Result<()> {
        let packet = tcp_capture_prefix(false, 60_000);
        let mut payload = vec![0_u8; NFGENMSG_BYTES];
        payload.extend_from_slice(&capture_attributes(&packet, 60_000, NFQA_SKB_GSO)?);
        let error = parse_queued_packet(&payload)
            .err()
            .ok_or_else(|| anyhow!("GSO bypassed socket UID"))?;
        assert!(error.to_string().contains("no kernel socket uid"));
        Ok(())
    }

    #[test]
    fn pending_mark_domain_preserves_unreserved_fwmark_bits() {
        for original in [0, 1, 0x0012_3456, 0x3fff_ffff, 0xffff_ffff] {
            let pending = application_pending_mark(original);
            assert_eq!(pending & 0x3fff_ffff, original & 0x3fff_ffff);
            assert_eq!(application_pending_mark(pending), pending);
        }
    }
}
