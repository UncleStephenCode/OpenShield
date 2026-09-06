//! Bounded readiness coordination for replies which raced an outgoing mark reset.
//!
//! No entry is an application identity or an authorization cache. A completed
//! wave permits only `NF_REPEAT`: the current kernel policy must authorize the
//! packet again. Missing, stale, failed or exhausted state never permits Accept.
//! The two reserved packet-mark bits bound each packet to three retries without
//! changing the other 30 bits. Each admission waits at most two seconds: up to
//! six seconds of userspace waiting over all hops, plus scheduling/queue delay.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, ensure};
use openshield_core::{
    APPLICATION_REPLY_QUEUE_NUMBER, Mode, TransportProtocol, application_reply_retry_mark,
};

use super::{
    Attributes, ErrorThrottle, IpPacketDirection, NF_DROP, NF_REPEAT, NFGENMSG_BYTES, NFQA_MARK,
    NFQA_PAYLOAD, NFQNL_MSG_PACKET, NetlinkMessages, QueueReceive, QueueRole, QueueSocket,
    QueuedPacketWork, RECEIVE_BUFFER_BYTES, RECEIVE_POLL_MILLIS, handle_packet_queue_failure,
    network_u32, packet_id, parse_ip_packet_direction, queue_message_type,
};
use crate::engine::{NfqueueRuntimeCounters, SharedEngine};

const CAPACITY: usize = 128;
const LIFETIME: Duration = Duration::from_secs(2);
const PENDING_POLL_MILLIS: u16 = 5;
const RETRY_BACKOFF: Duration = Duration::from_millis(5);

pub(super) type SharedRegistry = Arc<Mutex<Registry>>;

pub(super) fn shared_registry() -> SharedRegistry {
    Arc::new(Mutex::new(Registry::default()))
}

/// Deliberately excludes UID/PID: incoming packets do not prove either. This
/// tuple is only a scheduling key; even a collision cannot authorize a packet.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FlowKey {
    local: IpAddr,
    local_port: u16,
    remote: IpAddr,
    remote_port: Option<u16>,
    protocol: TransportProtocol,
}

#[derive(Debug)]
pub(super) struct OutgoingTicket {
    key: FlowKey,
    generation: u32,
    wave: u64,
    serial: u64,
}

#[derive(Debug)]
struct Wave {
    serial: u64,
    active: BTreeSet<u64>,
    failed: bool,
    updated: Instant,
}

#[derive(Debug, Default)]
pub(super) struct Registry {
    generation: Option<u32>,
    next_serial: u64,
    flows: HashMap<FlowKey, Wave>,
    last_queue_drain: Option<Instant>,
}

impl Registry {
    fn prune(&mut self, now: Instant) {
        self.flows.retain(|_, wave| {
            !wave.active.is_empty() || now.saturating_duration_since(wave.updated) < LIFETIME
        });
    }

    fn begin(&mut self, key: FlowKey, generation: u32, now: Instant) -> Result<OutgoingTicket> {
        if self.generation != Some(generation) {
            self.flows.clear();
            self.generation = Some(generation);
            self.last_queue_drain = None;
        }
        self.prune(now);
        ensure!(
            self.flows
                .values()
                .map(|wave| wave.active.len())
                .sum::<usize>()
                < CAPACITY,
            "reply readiness active ticket bound exceeded"
        );
        if !self.flows.contains_key(&key) && self.flows.len() >= CAPACITY {
            let oldest = self
                .flows
                .iter()
                .filter(|(_, wave)| wave.active.is_empty())
                .min_by_key(|(_, wave)| wave.updated)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.flows.remove(&oldest);
            }
        }
        ensure!(
            self.flows.contains_key(&key) || self.flows.len() < CAPACITY,
            "reply readiness flow bound exceeded"
        );
        self.next_serial = self
            .next_serial
            .checked_add(1)
            .ok_or_else(|| anyhow!("reply readiness ticket space exhausted"))?;
        let serial = self.next_serial;
        let wave = self.flows.entry(key.clone()).or_insert_with(|| Wave {
            serial,
            active: BTreeSet::new(),
            failed: false,
            updated: now,
        });
        if wave.active.is_empty() {
            wave.serial = serial;
            wave.failed = false;
        }
        wave.active.insert(serial);
        wave.updated = now;
        Ok(OutgoingTicket {
            key,
            generation,
            wave: wave.serial,
            serial,
        })
    }

    fn complete(&mut self, ticket: &OutgoingTicket, succeeded: bool, now: Instant) -> bool {
        if self.generation != Some(ticket.generation) {
            return false;
        }
        let Some(wave) = self.flows.get_mut(&ticket.key) else {
            return false;
        };
        if wave.serial != ticket.wave || !wave.active.remove(&ticket.serial) {
            return false;
        }
        wave.failed |= !succeeded;
        wave.updated = now;
        true
    }

    fn record_queue_drain(&mut self, checked_at: Instant) -> Result<()> {
        ensure!(
            self.flows.values().all(|wave| wave.active.is_empty()),
            "reply readiness drain observed before all outgoing verdicts"
        );
        self.last_queue_drain = Some(
            self.last_queue_drain
                .map_or(checked_at, |previous| previous.max(checked_at)),
        );
        Ok(())
    }

    fn readiness(&mut self, pending: &mut PendingReply, now: Instant) -> Disposition {
        self.prune(now);
        if self.generation != Some(pending.generation) {
            return Disposition::Wait;
        }
        let Some(wave) = self.flows.get(&pending.packet.key) else {
            // Once a reply has bound to a wave, eviction must not make it
            // attach to a different future wave for the same reused tuple.
            return if pending.wave.is_some() {
                Disposition::Drop
            } else {
                Disposition::Wait
            };
        };
        if pending.wave.is_some_and(|serial| serial != wave.serial) {
            return Disposition::Drop;
        }
        pending.wave = Some(wave.serial);
        if wave.failed {
            Disposition::Drop
        } else if wave.active.is_empty() {
            Disposition::Repeat
        } else {
            Disposition::Wait
        }
    }
}

pub(super) fn register_outgoing_batch(
    registry: &SharedRegistry,
    batch: &[QueuedPacketWork],
    engine: &SharedEngine,
) -> Result<Vec<Option<OutgoingTicket>>> {
    let guard = engine
        .lock()
        .map_err(|_| anyhow!("policy engine mutex poisoned before reply registration"))?;
    let (mode, generation) = guard
        .application_decision_identity()
        .map_err(|error| anyhow!(error.message))?;
    let mut registry = registry
        .lock()
        .map_err(|_| anyhow!("reply readiness registry is poisoned"))?;
    batch
        .iter()
        .map(|work| {
            let Some(packet) = work
                .packet
                .as_ref()
                .ok()
                .filter(|_| mode == Mode::Enforcing)
            else {
                return Ok(None);
            };
            let connection = &packet.connection;
            if !matches!(
                connection.protocol,
                TransportProtocol::Udp | TransportProtocol::Icmp | TransportProtocol::IcmpV6
            ) {
                return Ok(None);
            }
            let key = FlowKey {
                local: connection.source_address,
                local_port: connection
                    .source_port
                    .ok_or_else(|| anyhow!("outgoing reply key has no local port/identifier"))?,
                remote: connection.destination_address,
                remote_port: connection.destination_port,
                protocol: connection.protocol,
            };
            registry.begin(key, generation, Instant::now()).map(Some)
        })
        .collect()
}

pub(super) fn complete_outgoing(
    registry: &SharedRegistry,
    ticket: Option<OutgoingTicket>,
    succeeded: bool,
) -> Result<()> {
    if let Some(ticket) = ticket {
        // Completion happens only after the outgoing verdict send. A stale
        // ticket may be ignored, but can never settle another generation/wave.
        registry
            .lock()
            .map_err(|_| anyhow!("reply readiness registry is poisoned"))?
            .complete(&ticket, succeeded, Instant::now());
    }
    Ok(())
}

pub(super) fn record_queue_drained(registry: &SharedRegistry, checked_at: Instant) -> Result<()> {
    registry
        .lock()
        .map_err(|_| anyhow!("reply readiness registry is poisoned"))?
        .record_queue_drain(checked_at)
}

#[derive(Debug)]
struct ReplyPacket {
    key: FlowKey,
    packet_mark: u32,
}

fn parse_reply(payload: &[u8]) -> Result<ReplyPacket> {
    ensure!(
        payload.len() >= NFGENMSG_BYTES,
        "reply netlink payload is truncated"
    );
    ensure!(
        u16::from_be_bytes([payload[2], payload[3]]) == APPLICATION_REPLY_QUEUE_NUMBER,
        "reply message came from an unexpected queue"
    );
    let mut ip = None;
    let mut mark = None;
    for attribute in Attributes::new(&payload[NFGENMSG_BYTES..]) {
        let attribute = attribute?;
        match attribute.kind {
            NFQA_PAYLOAD => {
                ensure!(ip.is_none(), "reply has duplicate payload");
                ip = Some(attribute.payload);
            }
            NFQA_MARK => {
                ensure!(mark.is_none(), "reply has duplicate mark");
                mark = Some(network_u32(attribute.payload)?);
            }
            _ => {}
        }
    }
    let packet_mark = mark.unwrap_or_default();
    ensure!(
        packet_mark != application_reply_retry_mark(packet_mark),
        "terminal reply retry budget reached its queue again"
    );
    let ip = ip.ok_or_else(|| anyhow!("reply has no IP payload"))?;
    let parsed = parse_ip_packet_direction(ip, IpPacketDirection::Reply)?;
    ensure!(
        matches!(
            parsed.protocol,
            TransportProtocol::Udp | TransportProtocol::Icmp | TransportProtocol::IcmpV6
        ),
        "reply retry only supports UDP and ICMP echo replies"
    );
    ensure!(
        ip.len() >= parsed.transport_offset + 8,
        "reply transport header is truncated"
    );
    let (local_port, remote_port) = if parsed.protocol == TransportProtocol::Udp {
        (
            parsed
                .destination_port
                .ok_or_else(|| anyhow!("UDP reply has no destination port"))?,
            parsed.source_port,
        )
    } else {
        (
            parsed
                .source_port
                .ok_or_else(|| anyhow!("echo reply has no identifier"))?,
            None,
        )
    };
    Ok(ReplyPacket {
        key: FlowKey {
            local: parsed.destination_address,
            local_port,
            remote: parsed.source_address,
            remote_port,
            protocol: parsed.protocol,
        },
        packet_mark,
    })
}

#[derive(Debug)]
struct PendingReply {
    packet: ReplyPacket,
    generation: u32,
    wave: Option<u64>,
    started: Instant,
    not_before: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Disposition {
    Wait,
    Drop,
    Repeat,
}

impl PendingReply {
    fn disposition(
        &mut self,
        registry: &mut Registry,
        mode: Mode,
        generation: u32,
        stopping: bool,
        now: Instant,
    ) -> Disposition {
        if stopping
            || mode != Mode::Enforcing
            || generation != self.generation
            || now.saturating_duration_since(self.started) >= LIFETIME
        {
            return Disposition::Drop;
        }
        if now < self.not_before {
            return Disposition::Wait;
        }
        // A matching previous wave may already be settled while a new
        // original packet is still unread behind another flow's active batch.
        // Do not bind to that old wave: the outgoing reader must first observe
        // its socket empty AFTER this reply's admission, with all verdicts
        // returned. This remains scheduling evidence, never authorization.
        if registry
            .last_queue_drain
            .is_none_or(|drained| drained < self.started)
        {
            return Disposition::Wait;
        }
        registry.readiness(self, now)
    }
}

#[derive(Debug, Default)]
struct PendingReplies {
    packets: HashMap<u32, PendingReply>,
}

impl PendingReplies {
    fn insert(
        &mut self,
        id: u32,
        packet: ReplyPacket,
        generation: u32,
        now: Instant,
    ) -> Result<bool> {
        ensure!(
            !self.packets.contains_key(&id),
            "reply queue reused an outstanding packet id"
        );
        if self.packets.len() >= CAPACITY {
            return Ok(false);
        }
        // A ready receive socket does not sleep in poll. Explicitly back off
        // repeated admissions so one stale settled wave cannot immediately
        // consume all three attempts before the outgoing reader runs again.
        let not_before = if packet.packet_mark >> 30 == 0 {
            now
        } else {
            now.checked_add(RETRY_BACKOFF)
                .ok_or_else(|| anyhow!("reply retry backoff deadline overflowed"))?
        };
        self.packets.insert(
            id,
            PendingReply {
                packet,
                generation,
                wave: None,
                started: now,
                not_before,
            },
        );
        Ok(true)
    }

    fn poll_millis(&self) -> u16 {
        if self.packets.is_empty() {
            RECEIVE_POLL_MILLIS
        } else {
            PENDING_POLL_MILLIS
        }
    }
}

trait ReplyVerdictSink {
    fn drop_reply(&mut self, id: u32) -> Result<()>;
    fn repeat_reply(&mut self, id: u32, mark: u32) -> Result<()>;
}

impl ReplyVerdictSink for QueueSocket {
    fn drop_reply(&mut self, id: u32) -> Result<()> {
        self.verdict(id, NF_DROP)
    }
    fn repeat_reply(&mut self, id: u32, mark: u32) -> Result<()> {
        self.verdict_with_mark(id, NF_REPEAT, application_reply_retry_mark(mark))
    }
}

fn release_pending(
    queue: &mut impl ReplyVerdictSink,
    pending: &mut PendingReplies,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    counters: &NfqueueRuntimeCounters,
    registry: &SharedRegistry,
    now: Instant,
) -> Result<()> {
    let ids: Vec<_> = pending.packets.keys().copied().collect();
    for id in ids {
        // Match the engine -> registry lock order of outgoing registration.
        // Neither lock is ever held across a wait or attribution operation.
        let guard = engine
            .lock()
            .map_err(|_| anyhow!("policy engine mutex poisoned before reply retry"))?;
        let (mode, generation) = guard
            .application_decision_identity()
            .map_err(|error| anyhow!(error.message))?;
        let packet = pending
            .packets
            .get_mut(&id)
            .ok_or_else(|| anyhow!("pending reply disappeared"))?;
        let mut readiness = registry
            .lock()
            .map_err(|_| anyhow!("reply readiness registry is poisoned"))?;
        let disposition = packet.disposition(
            &mut readiness,
            mode,
            generation,
            shutdown.load(Ordering::Acquire),
            now.max(Instant::now()),
        );
        drop(readiness);
        match disposition {
            Disposition::Wait => continue,
            Disposition::Drop => {
                queue.drop_reply(id)?;
                counters.record_denied();
            }
            Disposition::Repeat => queue.repeat_reply(id, packet.packet.packet_mark)?,
        }
        // Keep the engine guard until after reinjection. Kernel generation and
        // explicit rules, not this readiness decision, authorize any delivery.
        drop(guard);
        pending.packets.remove(&id);
    }
    Ok(())
}

pub(super) fn run(
    mut queue: QueueSocket,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    counters: &NfqueueRuntimeCounters,
    registry: &SharedRegistry,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_inner(&mut queue, engine, shutdown, counters, registry)
    }));
    let failure = match result {
        Ok(Ok(())) => return,
        Ok(Err(error)) => format!("application reply retry worker failed: {error:#}"),
        Err(_) => "application reply retry worker panicked".to_owned(),
    };
    handle_packet_queue_failure(
        QueueRole::Reply,
        engine,
        shutdown,
        counters,
        &mut ErrorThrottle::default(),
        &failure,
    );
}

fn run_inner(
    queue: &mut QueueSocket,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
    counters: &NfqueueRuntimeCounters,
    registry: &SharedRegistry,
) -> Result<()> {
    let mut pending = PendingReplies::default();
    let mut buffer = vec![0_u8; RECEIVE_BUFFER_BYTES];
    let mut errors = ErrorThrottle::default();
    while !shutdown.load(Ordering::Acquire) {
        release_pending(
            queue,
            &mut pending,
            engine,
            shutdown,
            counters,
            registry,
            Instant::now(),
        )?;
        match queue.receive(&mut buffer, pending.poll_millis())? {
            QueueReceive::Idle | QueueReceive::Interrupted => {}
            QueueReceive::Overflow => {
                counters.record_queue_overflow();
                errors.report(
                    "application reply retry queue overflowed; kernel denied affected packets",
                );
            }
            QueueReceive::Datagram(size) => {
                for message in NetlinkMessages::new(&buffer[..size]) {
                    let message = message?;
                    if message.message_type != queue_message_type(NFQNL_MSG_PACKET) {
                        continue;
                    }
                    let id = packet_id(message.payload)
                        .ok_or_else(|| anyhow!("reply has no packet identifier"))?;
                    ensure!(
                        !pending.packets.contains_key(&id),
                        "reply queue reused an outstanding packet id"
                    );
                    let packet = match parse_reply(message.payload) {
                        Ok(packet) => packet,
                        Err(error) => {
                            queue.drop_reply(id)?;
                            counters.record_denied();
                            errors.report(&format!(
                                "application reply retry denied malformed packet: {error:#}"
                            ));
                            continue;
                        }
                    };
                    let guard = engine
                        .lock()
                        .map_err(|_| anyhow!("policy engine mutex poisoned on reply admission"))?;
                    let (mode, generation) = guard
                        .application_decision_identity()
                        .map_err(|error| anyhow!(error.message))?;
                    if mode != Mode::Enforcing
                        || shutdown.load(Ordering::Acquire)
                        || !pending.insert(id, packet, generation, Instant::now())?
                    {
                        queue.drop_reply(id)?;
                        counters.record_denied();
                    }
                }
            }
        }
    }
    for id in pending.packets.into_keys() {
        queue.drop_reply(id)?;
        counters.record_denied();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{append_attribute, parse_queued_packet};
    use super::*;
    use crate::backend::MemoryBackend;
    use crate::engine::{Engine, EventBus};
    use openshield_core::AtomicStateStore;
    use openshield_protocol::ControlRequest;
    use std::os::unix::fs::MetadataExt;

    fn set_mode(engine: &SharedEngine, mode: Mode) -> Result<u32> {
        let mut engine = engine.lock().map_err(|_| anyhow!("test engine poisoned"))?;
        let revision = engine
            .subscription_revision()
            .map_err(|error| anyhow!(error.message))?;
        engine
            .handle_control(ControlRequest::SetMode {
                expected_revision: revision,
                mode,
            })
            .map_err(|error| anyhow!(error.message))?;
        engine
            .application_decision_identity()
            .map(|(_, generation)| generation)
            .map_err(|error| anyhow!(error.message))
    }

    struct RecordedVerdicts {
        engine: SharedEngine,
        calls: Vec<(u32, u32, Option<u32>)>,
    }

    impl ReplyVerdictSink for RecordedVerdicts {
        fn drop_reply(&mut self, id: u32) -> Result<()> {
            assert!(self.engine.try_lock().is_err());
            self.calls.push((id, NF_DROP, None));
            Ok(())
        }
        fn repeat_reply(&mut self, id: u32, mark: u32) -> Result<()> {
            assert!(self.engine.try_lock().is_err());
            self.calls
                .push((id, NF_REPEAT, Some(application_reply_retry_mark(mark))));
            Ok(())
        }
    }

    #[test]
    fn release_uses_only_repeat_or_drop_under_fresh_engine_guard() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let owner = directory.path().metadata()?.uid();
        let store = AtomicStateStore::for_owner(directory.path().join("state.json"), owner);
        let mut engine = Engine::load(
            Box::new(MemoryBackend::default()),
            Box::new(store),
            EventBus::new(),
        )?;
        engine.activate_startup_policy()?;
        let engine = Arc::new(Mutex::new(engine));
        let generation = set_mode(&engine, Mode::Enforcing)?;
        let registry = shared_registry();
        let now = Instant::now();
        let mut pending = PendingReplies::default();
        let ticket = registry
            .lock()
            .map_err(|_| anyhow!("test registry poisoned"))?
            .begin(key(5000), generation, now)?;
        assert!(pending.insert(
            1,
            ReplyPacket {
                key: key(5000),
                packet_mark: 7
            },
            generation,
            now
        )?);
        let mut queue = RecordedVerdicts {
            engine: Arc::clone(&engine),
            calls: Vec::new(),
        };
        let shutdown = AtomicBool::new(false);
        let counters = NfqueueRuntimeCounters::default();
        release_pending(
            &mut queue,
            &mut pending,
            &engine,
            &shutdown,
            &counters,
            &registry,
            now,
        )?;
        assert!(queue.calls.is_empty());
        complete_outgoing(&registry, Some(ticket), true)?;
        record_queue_drained(&registry, Instant::now())?;
        release_pending(
            &mut queue,
            &mut pending,
            &engine,
            &shutdown,
            &counters,
            &registry,
            now,
        )?;
        assert_eq!(
            queue.calls,
            [(1, NF_REPEAT, Some(application_reply_retry_mark(7)))]
        );
        assert!(pending.packets.is_empty());
        assert!(pending.insert(
            2,
            ReplyPacket {
                key: key(5000),
                packet_mark: 7
            },
            generation,
            now
        )?);
        set_mode(&engine, Mode::Enforcing)?; // Same mode, different generation.
        release_pending(
            &mut queue,
            &mut pending,
            &engine,
            &shutdown,
            &counters,
            &registry,
            now,
        )?;
        assert_eq!(queue.calls[1], (2, NF_DROP, None));
        assert!(pending.packets.is_empty());
        Ok(())
    }

    fn key(port: u16) -> FlowKey {
        FlowKey {
            local: [192, 0, 2, 1].into(),
            local_port: port,
            remote: [198, 51, 100, 1].into(),
            remote_port: Some(53),
            protocol: TransportProtocol::Udp,
        }
    }

    fn pending(key: FlowKey, now: Instant) -> PendingReply {
        PendingReply {
            packet: ReplyPacket {
                key,
                packet_mark: 7,
            },
            generation: 1,
            wave: None,
            started: now,
            not_before: now,
        }
    }

    #[test]
    fn matching_wave_waits_for_every_actual_verdict() -> Result<()> {
        let now = Instant::now();
        let mut registry = Registry::default();
        let first = registry.begin(key(5000), 1, now)?;
        let second = registry.begin(key(5000), 1, now)?;
        let mut reply = pending(key(5000), now);
        assert_eq!(registry.readiness(&mut reply, now), Disposition::Wait);
        assert!(registry.complete(&first, true, now));
        assert_eq!(registry.readiness(&mut reply, now), Disposition::Wait);
        assert!(registry.complete(&second, true, now));
        assert_eq!(registry.readiness(&mut reply, now), Disposition::Repeat);
        Ok(())
    }

    #[test]
    fn another_flow_completion_never_wakes_pending_reply() -> Result<()> {
        let now = Instant::now();
        let mut registry = Registry::default();
        let matching = registry.begin(key(5000), 1, now)?;
        let other = registry.begin(key(5001), 1, now)?;
        let mut reply = pending(key(5000), now);
        assert!(registry.complete(&other, true, now));
        assert_eq!(registry.readiness(&mut reply, now), Disposition::Wait);
        assert!(registry.complete(&matching, true, now));
        assert_eq!(registry.readiness(&mut reply, now), Disposition::Repeat);
        Ok(())
    }

    #[test]
    fn mixed_outcomes_drop_regardless_of_completion_order() -> Result<()> {
        for failed_first in [false, true] {
            let now = Instant::now();
            let mut registry = Registry::default();
            let first = registry.begin(key(5000), 1, now)?;
            let second = registry.begin(key(5000), 1, now)?;
            registry.complete(&first, !failed_first, now);
            registry.complete(&second, failed_first, now);
            assert_eq!(
                registry.readiness(&mut pending(key(5000), now), now),
                Disposition::Drop
            );
        }
        Ok(())
    }

    #[test]
    fn reader_lag_uses_settled_readiness_but_not_expired_history() -> Result<()> {
        let now = Instant::now();
        let mut registry = Registry::default();
        let ticket = registry.begin(key(5000), 1, now)?;
        registry.complete(&ticket, true, now);
        assert_eq!(
            registry.readiness(&mut pending(key(5000), now), now + Duration::from_millis(1)),
            Disposition::Repeat
        );
        assert_eq!(
            registry.readiness(&mut pending(key(5000), now + LIFETIME), now + LIFETIME),
            Disposition::Wait
        );
        assert!(registry.flows.is_empty());
        Ok(())
    }

    #[test]
    fn reply_can_wait_for_original_registration_but_deadline_drops() -> Result<()> {
        let now = Instant::now();
        let mut registry = Registry::default();
        let mut reply = pending(key(5000), now);
        assert_eq!(
            reply.disposition(&mut registry, Mode::Enforcing, 1, false, now),
            Disposition::Wait
        );
        let ticket = registry.begin(key(5000), 1, now)?;
        assert_eq!(
            reply.disposition(&mut registry, Mode::Enforcing, 1, false, now),
            Disposition::Wait
        );
        registry.complete(&ticket, true, now);
        assert_eq!(
            reply.disposition(&mut registry, Mode::Enforcing, 1, false, now + LIFETIME),
            Disposition::Drop
        );
        Ok(())
    }

    #[test]
    fn policy_change_and_shutdown_override_ready_reply() -> Result<()> {
        let now = Instant::now();
        let mut registry = Registry::default();
        let ticket = registry.begin(key(5000), 1, now)?;
        registry.complete(&ticket, true, now);
        for (mode, generation, stopping) in [
            (Mode::Learning, 1, false),
            (Mode::BlockAll, 1, false),
            (Mode::Enforcing, 2, false),
            (Mode::Enforcing, 1, true),
        ] {
            assert_eq!(
                pending(key(5000), now).disposition(&mut registry, mode, generation, stopping, now),
                Disposition::Drop
            );
        }
        Ok(())
    }

    #[test]
    fn stale_generation_and_duplicate_tickets_cannot_settle_new_wave() -> Result<()> {
        let now = Instant::now();
        let mut registry = Registry::default();
        let old = registry.begin(key(5000), 1, now)?;
        let current = registry.begin(key(5000), 2, now)?;
        assert!(!registry.complete(&old, true, now));
        assert_eq!(registry.flows[&key(5000)].active.len(), 1);
        assert!(registry.complete(&current, true, now));
        let replacement = registry.begin(key(5000), 2, now)?;
        assert!(!registry.complete(&current, true, now));
        assert_eq!(registry.flows[&key(5000)].active.len(), 1);
        assert!(registry.complete(&replacement, false, now));
        Ok(())
    }

    #[test]
    fn reply_bound_to_old_wave_cannot_follow_reused_tuple() -> Result<()> {
        let now = Instant::now();
        let mut registry = Registry::default();
        let old = registry.begin(key(5000), 1, now)?;
        let mut reply = pending(key(5000), now);
        assert_eq!(registry.readiness(&mut reply, now), Disposition::Wait);
        registry.complete(&old, true, now);
        let current = registry.begin(key(5000), 1, now)?;
        registry.complete(&current, true, now);
        assert_eq!(registry.readiness(&mut reply, now), Disposition::Drop);
        Ok(())
    }

    #[test]
    fn active_ticket_budget_is_global_and_never_evicts_pending_wave() -> Result<()> {
        let now = Instant::now();
        let mut registry = Registry::default();
        for _ in 0..CAPACITY {
            registry.begin(key(5000), 1, now)?;
        }
        assert!(registry.begin(key(5001), 1, now).is_err());
        assert_eq!(registry.flows.len(), 1);
        assert_eq!(registry.flows[&key(5000)].active.len(), CAPACITY);
        registry.prune(now + LIFETIME);
        assert_eq!(registry.flows[&key(5000)].active.len(), CAPACITY);
        Ok(())
    }

    #[test]
    fn completed_flow_history_is_bounded_and_ticket_serials_do_not_wrap() -> Result<()> {
        let now = Instant::now();
        let mut registry = Registry::default();
        for index in 0..CAPACITY * 2 {
            let ticket = registry.begin(key(u16::try_from(5000 + index)?), 1, now)?;
            registry.complete(&ticket, true, now);
            assert!(registry.flows.len() <= CAPACITY);
        }
        registry.next_serial = u64::MAX;
        assert!(registry.begin(key(4000), 1, now).is_err());
        assert_eq!(registry.next_serial, u64::MAX);
        Ok(())
    }

    #[test]
    fn pending_capacity_and_packet_id_reuse_are_fail_closed() -> Result<()> {
        let now = Instant::now();
        let mut pending = PendingReplies::default();
        assert_eq!(pending.poll_millis(), RECEIVE_POLL_MILLIS);
        for id in 0..u32::try_from(CAPACITY)? {
            assert!(pending.insert(
                id,
                ReplyPacket {
                    key: key(5000),
                    packet_mark: 0
                },
                1,
                now
            )?);
        }
        assert_eq!(pending.poll_millis(), PENDING_POLL_MILLIS);
        assert!(!pending.insert(
            1000,
            ReplyPacket {
                key: key(5000),
                packet_mark: 0
            },
            1,
            now
        )?);
        assert!(
            pending
                .insert(
                    0,
                    ReplyPacket {
                        key: key(5000),
                        packet_mark: 0
                    },
                    1,
                    now
                )
                .is_err()
        );
        assert_eq!(pending.packets.len(), CAPACITY);
        Ok(())
    }

    fn envelope(ip: &[u8], mark: Option<u32>) -> Result<Vec<u8>> {
        let mut payload = vec![0, 0];
        payload.extend_from_slice(&APPLICATION_REPLY_QUEUE_NUMBER.to_be_bytes());
        append_attribute(&mut payload, NFQA_PAYLOAD, ip)?;
        if let Some(mark) = mark {
            append_attribute(&mut payload, NFQA_MARK, &mark.to_be_bytes())?;
        }
        Ok(payload)
    }

    fn ipv4(protocol: u8, transport: &[u8]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&[198, 51, 100, 1]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 1]);
        packet.extend_from_slice(transport);
        packet
    }

    #[test]
    fn incoming_udp_normalizes_tuple_without_uid_or_output_interface() -> Result<()> {
        let parsed = parse_reply(&envelope(
            &ipv4(17, &[0, 53, 0x13, 0x88, 0, 8, 0, 0]),
            None,
        )?)?;
        assert_eq!(parsed.key, key(5000));
        assert_eq!(parsed.packet_mark, 0);
        Ok(())
    }

    #[test]
    fn echo_reply_parser_preserves_identifier_and_rejects_wrong_direction() -> Result<()> {
        let parsed = parse_reply(&envelope(&ipv4(1, &[0, 0, 0, 0, 0x13, 0x88, 0, 1]), None)?)?;
        assert_eq!(parsed.key.local_port, 5000);
        assert_eq!(parsed.key.remote_port, None);
        assert_eq!(parsed.key.protocol, TransportProtocol::Icmp);
        for transport in [
            [8, 0, 0, 0, 0, 7, 0, 1],
            [3, 3, 0, 0, 0, 7, 0, 1],
            [0, 1, 0, 0, 0, 7, 0, 1],
        ] {
            assert!(parse_reply(&envelope(&ipv4(1, &transport), None)?).is_err());
        }
        Ok(())
    }

    #[test]
    fn ipv6_echo_reply_and_udp_are_parsed_but_requests_are_not() -> Result<()> {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x60;
        packet[6] = 58;
        packet[23] = 2;
        packet[39] = 1;
        packet.extend_from_slice(&[129, 0, 0, 0, 0, 5, 0, 1]);
        let parsed = parse_reply(&envelope(&packet, Some(7))?)?;
        assert_eq!(parsed.key.protocol, TransportProtocol::IcmpV6);
        assert_eq!(parsed.key.local_port, 5);
        packet[40] = 128;
        assert!(parse_reply(&envelope(&packet, None)?).is_err());
        packet[6] = 17;
        packet[40..48].copy_from_slice(&[0, 53, 0, 5, 0, 8, 0, 0]);
        assert_eq!(
            parse_reply(&envelope(&packet, None)?)?.key.protocol,
            TransportProtocol::Udp
        );
        Ok(())
    }

    #[test]
    fn reply_parser_rejects_tcp_truncation_fragment_and_retry_loop() -> Result<()> {
        assert!(parse_reply(&envelope(&ipv4(6, &[0, 53, 0, 5, 0, 0, 0, 0]), None)?).is_err());
        assert!(parse_reply(&envelope(&ipv4(17, &[0, 53, 0, 5]), None)?).is_err());
        let mut packet = ipv4(17, &[0, 53, 0, 5, 0, 8, 0, 0]);
        assert!(parse_reply(&envelope(&packet, Some(0xc000_0007))?).is_err());
        packet[7] = 1;
        assert!(parse_reply(&envelope(&packet, None)?).is_err());
        let mut payload = envelope(&packet, None)?;
        payload[3] ^= 1;
        assert!(parse_reply(&payload).is_err());
        Ok(())
    }

    #[test]
    fn three_retry_hops_preserve_foreign_bits_and_terminal_budget_denies() -> Result<()> {
        let now = Instant::now();
        let ip = ipv4(17, &[0, 53, 0x13, 0x88, 0, 8, 0, 0]);
        for low_mark in [0, 7, 0x1357_2468, 0x3fff_ffff] {
            let mut registry = Registry::default();
            let ticket = registry.begin(key(5000), 1, now)?;
            registry.complete(&ticket, true, now);
            registry.record_queue_drain(now)?;
            let mut mark = low_mark;
            for attempt in 0..3 {
                assert_eq!(mark >> 30, attempt);
                let packet = parse_reply(&envelope(&ip, Some(mark))?)?;
                let mut replies = PendingReplies::default();
                assert!(replies.insert(attempt, packet, 1, now)?);
                let reply = replies
                    .packets
                    .get_mut(&attempt)
                    .ok_or_else(|| anyhow!("test reply missing"))?;
                assert_eq!(
                    reply.not_before,
                    if attempt == 0 {
                        now
                    } else {
                        now + RETRY_BACKOFF
                    }
                );
                assert_eq!(
                    reply.disposition(&mut registry, Mode::Enforcing, 1, false, now),
                    if attempt == 0 {
                        Disposition::Repeat
                    } else {
                        Disposition::Wait
                    }
                );
                assert_eq!(
                    reply.disposition(
                        &mut registry,
                        Mode::Enforcing,
                        1,
                        false,
                        now + RETRY_BACKOFF
                    ),
                    Disposition::Repeat
                );
                mark = application_reply_retry_mark(mark);
                assert_eq!(mark & 0x3fff_ffff, low_mark);
            }
            assert_eq!(mark >> 30, 3);
            assert_eq!(application_reply_retry_mark(mark), mark);
            assert!(parse_reply(&envelope(&ip, Some(mark))?).is_err());
        }
        assert_eq!(LIFETIME * 3, Duration::from_secs(6));
        Ok(())
    }

    #[test]
    fn each_retry_hop_rechecks_generation_shutdown_and_its_own_deadline() -> Result<()> {
        let now = Instant::now();
        let mut registry = Registry::default();
        let ticket = registry.begin(key(5000), 1, now)?;
        registry.complete(&ticket, true, now);
        registry.record_queue_drain(now)?;
        for domain in [0, 0x4000_0000, 0x8000_0000] {
            let mut replies = PendingReplies::default();
            assert!(replies.insert(
                1,
                ReplyPacket {
                    key: key(5000),
                    packet_mark: domain | 7
                },
                1,
                now
            )?);
            let reply = replies
                .packets
                .get_mut(&1)
                .ok_or_else(|| anyhow!("test reply missing"))?;
            for (mode, generation, stopping) in [
                (Mode::Learning, 1, false),
                (Mode::BlockAll, 1, false),
                (Mode::Enforcing, 2, false),
                (Mode::Enforcing, 1, true),
            ] {
                assert_eq!(
                    reply.disposition(&mut registry, mode, generation, stopping, now),
                    Disposition::Drop
                );
            }
            assert_eq!(
                reply.disposition(&mut registry, Mode::Enforcing, 1, false, now + LIFETIME),
                Disposition::Drop
            );
        }
        Ok(())
    }

    #[test]
    fn old_settled_wave_cannot_repeat_before_fresh_empty_queue_barrier() -> Result<()> {
        let now = Instant::now();
        let admitted = now + Duration::from_millis(1);
        let mut registry = Registry::default();
        let old = registry.begin(key(5000), 1, now)?;
        registry.complete(&old, true, now);
        registry.record_queue_drain(now)?;
        let mut reply = pending(key(5000), admitted);
        assert_eq!(
            reply.disposition(&mut registry, Mode::Enforcing, 1, false, admitted),
            Disposition::Wait
        );
        assert!(reply.wave.is_none());
        // Another flow can occupy the reader while this original still waits
        // in its socket. No inner-drain / active-batch barrier is accepted.
        let other = registry.begin(key(5001), 1, admitted)?;
        assert!(registry.record_queue_drain(admitted).is_err());
        let current = registry.begin(key(5000), 1, admitted)?;
        registry.complete(&other, true, admitted);
        assert!(registry.record_queue_drain(admitted).is_err());
        registry.complete(&current, true, admitted);
        assert_eq!(
            reply.disposition(&mut registry, Mode::Enforcing, 1, false, admitted),
            Disposition::Wait
        );
        assert!(reply.wave.is_none());
        registry.record_queue_drain(admitted)?;
        assert_eq!(
            reply.disposition(&mut registry, Mode::Enforcing, 1, false, admitted),
            Disposition::Repeat
        );
        assert_eq!(reply.wave, Some(current.wave));
        Ok(())
    }

    #[test]
    fn drain_barrier_never_advances_on_active_verdict_or_across_generation() -> Result<()> {
        let now = Instant::now();
        let mut registry = Registry::default();
        registry.record_queue_drain(now)?;
        let ticket = registry.begin(key(5000), 1, now)?;
        assert_eq!(registry.last_queue_drain, None);
        assert!(registry.record_queue_drain(now).is_err());
        assert_eq!(registry.last_queue_drain, None);
        registry.complete(&ticket, false, now);
        registry.record_queue_drain(now)?;
        assert_eq!(
            pending(key(5000), now).disposition(&mut registry, Mode::Enforcing, 1, false, now),
            Disposition::Drop
        );
        registry.begin(key(5000), 2, now)?;
        assert_eq!(registry.last_queue_drain, None);
        Ok(())
    }

    #[test]
    fn missing_uid_diagnostic_is_protocol_only_and_still_denies() -> Result<()> {
        let mut transport = vec![0_u8; 20];
        transport[..4].copy_from_slice(&[0x13, 0x88, 0, 53]);
        transport[13] = 16;
        let message = parse_queued_packet(&envelope(&ipv4(6, &transport), None)?)
            .err()
            .ok_or_else(|| anyhow!("missing UID was accepted"))?
            .to_string();
        assert!(message.contains("no kernel socket uid"));
        assert!(message.contains("protocol=Tcp"));
        assert!(message.contains("tcp_flags=Some(16)"));
        assert!(!message.contains("192.0.2"));
        assert!(!message.contains("198.51.100"));
        Ok(())
    }
}
