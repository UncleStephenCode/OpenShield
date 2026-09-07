//! Bounded Enforcing reader and one attribution worker. Scheduling is never
//! authorization: every dispatched identity is freshly resolved, and only the
//! reader sends verdicts under the existing final policy-generation guard.

use std::sync::mpsc::RecvTimeoutError;

use super::scheduler::{FairQueue, PendingPacket};
use super::{
    ApplicationDecisionPolicy, AtomicBool, Context, Duration, ErrorThrottle, Instant,
    LearningAttributionWork, LearningObservation, MAX_PACKET_BATCH_SIZE, NfqueueRuntimeCounters,
    Ordering, PacketAttributionPlan, PacketAuthorization, ProcfsResolver, QueueReceive, QueueRole,
    QueueSocket, QueueVerdictStrategy, QueuedPacketWork, RECEIVE_BUFFER_BYTES, RECEIVE_POLL_MILLIS,
    Receiver, Result, RuleAction, SharedEngine, SyncSender, TryRecvError, TrySendError, anyhow,
    append_packet_datagram, bail, decide_packet_batch_until, ensure, handle_packet_queue_failure,
    mpsc, packet_attribution_plan, reply, return_enforcing_verdict, thread,
};
use crate::application_timing::{TimingScope, TimingStage, record_elapsed};

const PENDING_CAPACITY: usize = 128;
const COMPLETION_POLL_MILLIS: u16 = 5;
const DECISION_BUDGET: Duration = crate::application::PROC_SCAN_DEADLINE;

struct Job {
    batch: Vec<QueuedPacketWork>,
    tickets: Vec<Option<reply::OutgoingTicket>>,
    deadline: Instant,
}

struct ImmediatePacket {
    work: QueuedPacketWork,
    ticket: Option<reply::OutgoingTicket>,
    decision: Result<PacketAuthorization>,
    timed_out: bool,
}

impl Job {
    fn admit(
        &mut self,
        snapshot: &ApplicationDecisionPolicy,
        work: QueuedPacketWork,
        ticket: Option<reply::OutgoingTicket>,
        deadline: Instant,
        now: Instant,
    ) -> Option<ImmediatePacket> {
        let timed_out = now >= deadline;
        let immediate = if timed_out {
            Some(Err(anyhow!("bounded application queue wait timed out")))
        } else {
            immediate_decision(snapshot, &work)
        };
        if let Some(decision) = immediate {
            return Some(ImmediatePacket {
                work,
                ticket,
                decision,
                timed_out,
            });
        }
        // Only packets that need attribution may constrain its shared budget.
        // Preserve every admitted packet's original receive-time deadline.
        self.deadline = self.deadline.min(deadline);
        self.batch.push(work);
        self.tickets.push(ticket);
        None
    }
}

struct Completion {
    job: Job,
    decisions: Vec<Result<PacketAuthorization>>,
}

struct Runtime<'a> {
    engine: &'a SharedEngine,
    shutdown: &'a AtomicBool,
    learning: &'a SyncSender<LearningObservation>,
    attribution: &'a SyncSender<LearningAttributionWork>,
    strategy: QueueVerdictStrategy,
    counters: &'a NfqueueRuntimeCounters,
    registry: &'a reply::SharedRegistry,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run(
    mut queue: QueueSocket,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    learning: &SyncSender<LearningObservation>,
    attribution: &SyncSender<LearningAttributionWork>,
    strategy: QueueVerdictStrategy,
    counters: &NfqueueRuntimeCounters,
    registry: &reply::SharedRegistry,
) {
    let runtime = Runtime {
        engine,
        shutdown,
        learning,
        attribution,
        strategy,
        counters,
        registry,
    };
    let mut errors = ErrorThrottle::default();
    let result = thread::scope(|scope| -> Result<()> {
        // Exactly one batch can be in flight. The completion slot never holds
        // identities behind another attribution job or a verdict backlog.
        let (jobs, work) = mpsc::sync_channel::<Job>(1);
        let (done, completions) = mpsc::sync_channel::<Completion>(1);
        let worker_runtime = &runtime;
        let worker = thread::Builder::new()
            .name("openshield-enforcing-attribution".to_owned())
            .spawn_scoped(scope, move || worker_runtime.worker(&work, &done))
            .context("cannot spawn bounded Enforcing attribution worker")?;
        let result = runtime.serve(&mut queue, &jobs, &completions, &mut errors);
        // Disconnect both directions before joining, also on reader failure.
        // A current scan has the same bounded deadline as its queued packets.
        drop(jobs);
        drop(completions);
        let joined = worker
            .join()
            .map_err(|_| anyhow!("Enforcing attribution worker panicked"))?;
        result?;
        joined
    });
    if let Err(error) = result {
        handle_packet_queue_failure(
            QueueRole::Enforcing,
            engine,
            shutdown,
            counters,
            &mut errors,
            &format!("bounded application scheduler failed: {error:#}"),
        );
    }
    // Closing the fail-closed socket drops any packets with no verdict. No
    // pending identity or authorization survives this worker's lifetime.
}

impl Runtime<'_> {
    fn worker(&self, work: &Receiver<Job>, done: &SyncSender<Completion>) -> Result<()> {
        let resolver = ProcfsResolver::new();
        while !self.shutdown.load(Ordering::Acquire) {
            let job = match work.recv_timeout(Duration::from_millis(RECEIVE_POLL_MILLIS.into())) {
                Ok(job) => job,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
            };
            let timing = TimingScope::new(TimingStage::QueueDecision, job.batch.len());
            let decisions = decide_packet_batch_until(
                &job.batch,
                self.engine,
                self.shutdown,
                &resolver,
                self.learning,
                job.deadline,
            );
            timing.finish(
                decisions
                    .iter()
                    .filter(|decision| decision.is_err())
                    .count(),
            );
            match done.try_send(Completion { job, decisions }) {
                Ok(()) => {}
                Err(TrySendError::Disconnected(_)) => return Ok(()),
                Err(TrySendError::Full(_)) => bail!("Enforcing completion bound violated"),
            }
        }
        Ok(())
    }

    fn serve(
        &self,
        queue: &mut QueueSocket,
        jobs: &SyncSender<Job>,
        completions: &Receiver<Completion>,
        errors: &mut ErrorThrottle,
    ) -> Result<()> {
        let mut pending = FairQueue::default();
        let mut in_flight = 0;
        let mut buffer = vec![0_u8; RECEIVE_BUFFER_BYTES];
        while !self.shutdown.load(Ordering::Acquire) {
            // Check completions before any new receive or dispatch. At most a
            // single bounded netlink datagram is handled between these checks.
            if in_flight > 0 {
                match completions.try_recv() {
                    Ok(completion) => {
                        self.finish(queue, completion, in_flight, errors)?;
                        in_flight = 0;
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => {
                        bail!("Enforcing attribution worker disconnected")
                    }
                }
            }
            if in_flight == 0 && pending.len() > 0 {
                in_flight = self.dispatch(queue, &mut pending, jobs, errors)?;
                continue;
            }
            if !can_receive(
                pending.len(),
                in_flight,
                reply::outgoing_packet_capacity(self.registry)?,
            ) {
                ensure!(in_flight > 0, "bounded scheduler cannot make progress");
                match completions.recv_timeout(Duration::from_millis(COMPLETION_POLL_MILLIS.into()))
                {
                    Ok(completion) => {
                        self.finish(queue, completion, in_flight, errors)?;
                        in_flight = 0;
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        bail!("Enforcing attribution worker disconnected")
                    }
                }
                continue;
            }
            let timeout = if in_flight == 0 {
                RECEIVE_POLL_MILLIS
            } else {
                COMPLETION_POLL_MILLIS
            };
            self.receive(queue, &mut pending, &mut buffer, timeout, errors)?;
            // Amortize already-ready input when idle. Never delay a completed
            // identity with a continuously-ready socket or an unbounded drain.
            if in_flight == 0 {
                for _ in 1..MAX_PACKET_BATCH_SIZE {
                    if pending.len() >= MAX_PACKET_BATCH_SIZE
                        || !can_receive(
                            pending.len(),
                            0,
                            reply::outgoing_packet_capacity(self.registry)?,
                        )
                        || !self.receive(queue, &mut pending, &mut buffer, 0, errors)?
                    {
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn receive(
        &self,
        queue: &mut QueueSocket,
        pending: &mut FairQueue,
        buffer: &mut [u8],
        timeout: u16,
        errors: &mut ErrorThrottle,
    ) -> Result<bool> {
        let received = if timeout == 0 {
            queue.receive_ready(buffer)
        } else {
            queue.receive(buffer, timeout)
        }?;
        match received {
            QueueReceive::Idle | QueueReceive::Interrupted => Ok(false),
            QueueReceive::Overflow => {
                self.counters.record_queue_overflow();
                errors.report(queue.overflow_message());
                Ok(false)
            }
            QueueReceive::Datagram(size) => {
                let received = Instant::now();
                let mut batch = Vec::with_capacity(MAX_PACKET_BATCH_SIZE);
                append_packet_datagram(&buffer[..size], &mut batch)?;
                // Classification/admission precedes ALL scheduling, including
                // malformed and early-denied packets without reply tickets.
                reply::register_outgoing_packets(self.registry, &batch)?;
                for work in batch {
                    pending.push(PendingPacket { work, received })?;
                }
                Ok(true)
            }
        }
    }

    fn dispatch(
        &self,
        queue: &mut QueueSocket,
        pending: &mut FairQueue,
        jobs: &SyncSender<Job>,
        errors: &mut ErrorThrottle,
    ) -> Result<usize> {
        let selected = pending.take_batch();
        let mut batch = Vec::with_capacity(selected.len());
        let mut deadlines = Vec::with_capacity(selected.len());
        for pending in selected {
            let elapsed = pending.received.elapsed();
            let timed_out = elapsed >= DECISION_BUDGET;
            record_elapsed(TimingStage::QueueWait, elapsed, 1, usize::from(timed_out));
            batch.push(pending.work);
            deadlines.push(pending.received + DECISION_BUDGET);
        }
        // Only one wave (<=32 packets) is dispatched at a time. All previous
        // wave verdicts have been sent before beginning these flow tickets.
        let tickets = reply::register_outgoing_batch(self.registry, &batch, self.engine)?;
        let snapshot = self
            .engine
            .lock()
            .map_err(|_| anyhow!("policy engine mutex is poisoned"))?
            .application_decision_snapshot()
            .map_err(|error| anyhow!(error.message))?;
        let mut job = Job {
            batch: Vec::new(),
            tickets: Vec::new(),
            deadline: Instant::now() + DECISION_BUDGET,
        };
        for ((packet, ticket), deadline) in batch.into_iter().zip(tickets).zip(deadlines) {
            if let Some(immediate) = job.admit(&snapshot, packet, ticket, deadline, Instant::now())
            {
                if immediate.timed_out {
                    self.counters.record_attribution_timeout();
                }
                self.verdict(
                    queue,
                    immediate.work,
                    immediate.decision,
                    immediate.ticket,
                    errors,
                )?;
            }
        }
        let count = job.batch.len();
        if count > 0 {
            jobs.try_send(job)
                .map_err(|_| anyhow!("Enforcing attribution dispatch failed"))?;
        }
        Ok(count)
    }

    fn finish(
        &self,
        queue: &mut QueueSocket,
        completion: Completion,
        expected: usize,
        errors: &mut ErrorThrottle,
    ) -> Result<()> {
        let Completion { job, decisions } = completion;
        ensure!(
            job.batch.len() == expected
                && decisions.len() == expected
                && job.tickets.len() == expected,
            "Enforcing completion does not match its in-flight batch"
        );
        for ((packet, decision), ticket) in job.batch.into_iter().zip(decisions).zip(job.tickets) {
            let decision = if Instant::now() >= job.deadline {
                self.counters.record_attribution_timeout();
                Err(anyhow!(
                    "bounded application decision deadline expired before verdict"
                ))
            } else {
                decision
            };
            self.verdict(queue, packet, decision, ticket, errors)?;
        }
        Ok(())
    }

    fn verdict(
        &self,
        queue: &mut QueueSocket,
        packet: QueuedPacketWork,
        decision: Result<PacketAuthorization>,
        ticket: Option<reply::OutgoingTicket>,
        errors: &mut ErrorThrottle,
    ) -> Result<()> {
        return_enforcing_verdict(
            queue,
            packet,
            decision,
            ticket,
            self.engine,
            self.shutdown,
            self.attribution,
            self.strategy,
            self.counters,
            errors,
            self.registry,
        )
    }
}

fn can_receive(pending: usize, in_flight: usize, progress_free: usize) -> bool {
    pending
        .saturating_add(in_flight)
        .saturating_add(MAX_PACKET_BATCH_SIZE)
        <= PENDING_CAPACITY
        && progress_free >= MAX_PACKET_BATCH_SIZE
}

fn immediate_decision(
    snapshot: &ApplicationDecisionPolicy,
    work: &QueuedPacketWork,
) -> Option<Result<PacketAuthorization>> {
    let packet = match &work.packet {
        Ok(packet) => packet,
        Err(error) => return Some(Err(anyhow!(error.clone()))),
    };
    let defer_learning = match packet_attribution_plan(snapshot, packet) {
        Ok(PacketAttributionPlan::Resolve(_)) => return None,
        Ok(PacketAttributionPlan::AcceptNetworkFallback) => false,
        Ok(PacketAttributionPlan::AcceptAndObserveLearning) => true,
        Err(error) => return Some(Err(error)),
    };
    Some(Ok(PacketAuthorization {
        mode: snapshot.mode,
        flow_generation: snapshot.flow_generation,
        packet_mark: packet.packet_mark,
        action: RuleAction::Accept,
        observation_error: None,
        defer_learning_attribution: defer_learning,
    }))
}

#[cfg(test)]
mod tests {
    use openshield_core::{
        ApplicationPath, ApplicationSelector, Direction, ExecutableFileId, InterfaceName, Mode,
        PortRange, RuleName, RuleOrigin, RuleSpec, State, TransportProtocol,
        application_pending_mark,
    };

    use super::*;
    use crate::application::OutboundConnection;
    use crate::nfqueue::QueuedPacket;

    fn policy() -> Result<ApplicationDecisionPolicy> {
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        for (port, application) in [(443, true), (80, false)] {
            let mut rule = RuleSpec::new(
                RuleName::new(format!("allow {port}"))?,
                Direction::Outbound,
                TransportProtocol::Tcp,
                None,
                Some(PortRange::single(port)?),
                None,
                RuleOrigin::Manual,
                true,
            )?;
            if application {
                rule.application = Some(ApplicationSelector::new(
                    Some(ApplicationPath::new("/usr/bin/test-client")?),
                    Some(ExecutableFileId {
                        device: 1,
                        inode: 2,
                        size: 3,
                        ctime_seconds: 4,
                        ctime_nanoseconds: 5,
                    }),
                    None,
                    Some(1000),
                    None,
                )?);
            }
            state.create_rule(rule)?;
        }
        Ok(ApplicationDecisionPolicy::new(state.snapshot()))
    }

    fn packet(id: u32, port: u16) -> Result<QueuedPacketWork> {
        Ok(QueuedPacketWork {
            packet_id: id,
            packet: Ok(QueuedPacket {
                connection: OutboundConnection {
                    source_address: "192.0.2.1".parse()?,
                    source_port: Some(50000),
                    destination_address: "203.0.113.1".parse()?,
                    destination_port: Some(port),
                    protocol: TransportProtocol::Tcp,
                    output_interface: InterfaceName::new("eth0")?,
                    socket_uid: 1000,
                },
                packet_mark: application_pending_mark(0),
                initial_observation: true,
            }),
        })
    }

    fn job(now: Instant) -> Job {
        Job {
            batch: Vec::new(),
            tickets: Vec::new(),
            deadline: now + DECISION_BUDGET,
        }
    }

    #[test]
    fn intake_reserves_a_full_datagram_including_in_flight_work() {
        assert!(can_receive(64, 32, 32));
        assert!(!can_receive(65, 32, 32));
        assert!(!can_receive(64, 32, 31));
        assert!(!can_receive(usize::MAX, 32, 1024));
        assert!(can_receive(0, 0, 32));
    }

    #[test]
    fn old_immediate_packets_do_not_shorten_fresh_attribution_deadline() -> Result<()> {
        let policy = policy()?;
        let now = Instant::now();
        let old_deadline = now + Duration::from_millis(1);
        let fresh_deadline = now + DECISION_BUDGET;
        let malformed = QueuedPacketWork {
            packet_id: 1,
            packet: Err("malformed packet".to_owned()),
        };
        for (old, accepted) in [
            (malformed, false),
            (packet(2, 22)?, false),
            (packet(3, 80)?, true),
        ] {
            let mut job = job(now);
            let immediate = job
                .admit(&policy, old, None, old_deadline, now)
                .ok_or_else(|| anyhow!("old packet unexpectedly requires attribution"))?;
            assert_eq!(immediate.decision.is_ok(), accepted);
            assert!(!immediate.timed_out);
            assert!(
                job.admit(&policy, packet(4, 443)?, None, fresh_deadline, now)
                    .is_none()
            );
            assert_eq!(job.batch.len(), 1);
            assert_eq!(job.batch[0].packet_id, 4);
            assert_eq!(job.tickets.len(), 1);
            assert_eq!(job.deadline, fresh_deadline);
            // Finishing after the old packet's deadline still leaves the
            // attributed packet within its own unchanged two-second ceiling.
            assert!(old_deadline + Duration::from_millis(1) < job.deadline);
        }
        Ok(())
    }

    #[test]
    fn attribution_batch_keeps_earliest_admitted_packet_deadline() -> Result<()> {
        let policy = policy()?;
        let now = Instant::now();
        let mut job = job(now);
        let earlier = now + Duration::from_millis(100);
        assert!(
            job.admit(&policy, packet(1, 443)?, None, now + DECISION_BUDGET, now)
                .is_none()
        );
        assert!(
            job.admit(&policy, packet(2, 443)?, None, earlier, now)
                .is_none()
        );
        assert_eq!(job.deadline, earlier);
        assert_eq!(job.batch.len(), 2);
        assert_eq!(job.tickets.len(), 2);
        Ok(())
    }

    #[test]
    fn dispatch_rechecks_expiry_before_attribution_or_immediate_accept() -> Result<()> {
        let policy = policy()?;
        let now = Instant::now();
        for port in [443, 80] {
            let mut job = job(now);
            let expired = job
                .admit(&policy, packet(1, port)?, None, now, now)
                .ok_or_else(|| anyhow!("expired packet unexpectedly requires attribution"))?;
            assert!(expired.timed_out);
            assert!(expired.decision.is_err());
            assert!(job.batch.is_empty());
            assert!(job.tickets.is_empty());
            assert_eq!(job.deadline, now + DECISION_BUDGET);
        }
        Ok(())
    }
}
