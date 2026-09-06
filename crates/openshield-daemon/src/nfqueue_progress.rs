//! Bounded, captured read-through barriers for the one ordered OUTPUT queue.
//!
//! A barrier is scheduling evidence, never an authorization. The kernel assigns
//! packet IDs under the queue lock before ordered netlink delivery. Admission
//! records that order before dispatch, while verdicts may complete out of order.
//! Every received packet is classified before advancing the admission watermark.
//! Replies wait for matching-flow and unclassified verdicts through that fixed
//! boundary. Known unrelated flows need not finish, but their slots remain until
//! the completed prefix advances, preserving bounded accounting. Later traffic
//! cannot extend an already captured barrier. Missing metadata, a queue
//! replacement, ambiguous serial arithmetic, or a failed verdict cannot advance
//! progress. Every released reply still requires current-policy `NF_REPEAT`.

use std::collections::{BTreeMap, VecDeque};
use std::fs::OpenOptions;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use openshield_core::APPLICATION_QUEUE_NUMBER;

use super::{FlowKey, OutgoingFlow};

const PROC_QUEUE_PATH: &str = "/proc/self/net/netfilter/nfnetlink_queue";
const MAX_PROC_BYTES: usize = 16 * 1024;
const SERIAL_HALF_RANGE: u32 = 1 << 31;
const READ_BUDGET: Duration = Duration::from_millis(100);
const MAX_READ_CALLS: usize = 128;
const MAX_TRACKED_OUTGOING: usize = 1024;

/// The private epoch token also distinguishes successive runtime instances if
/// Linux eventually reuses the same netlink port ID. A runtime never rebinds its
/// queue: a queue failure tears down its workers and all outstanding barriers.
#[derive(Clone, Debug)]
pub(super) struct QueueIdentity {
    port_id: u32,
    epoch: Arc<()>,
}

#[derive(Clone, Debug)]
pub(super) struct ReadThroughBarrier {
    identity: QueueIdentity,
    sequence: u32,
}

#[derive(Debug)]
pub(super) struct QueueProgress {
    identity: QueueIdentity,
    completed: u32,
    last_admitted: u32,
    order: VecDeque<u32>,
    verdicts: BTreeMap<u32, PacketProgress>,
}

#[derive(Debug)]
struct PacketProgress {
    flow: OutgoingFlow,
    completed: bool,
}

impl QueueProgress {
    pub(super) fn new(port_id: u32) -> Result<Self> {
        ensure!(
            port_id != 0,
            "OUTPUT queue has no userspace netlink port ID"
        );
        Ok(Self {
            identity: QueueIdentity {
                port_id,
                epoch: Arc::new(()),
            },
            completed: 0,
            last_admitted: 0,
            order: VecDeque::new(),
            verdicts: BTreeMap::new(),
        })
    }

    pub(super) fn identity(&self) -> QueueIdentity {
        self.identity.clone()
    }

    pub(super) fn remaining_capacity(&self) -> usize {
        MAX_TRACKED_OUTGOING - self.order.len()
    }

    /// Register every packet in kernel receive order before any verdict or
    /// worker dispatch, including packets which need no application attribution.
    /// Validate the whole batch first so an error cannot partially admit it.
    pub(super) fn admit_classified(&mut self, packets: &[(u32, OutgoingFlow)]) -> Result<()> {
        ensure!(
            packets.len() <= self.remaining_capacity(),
            "OUTPUT verdict progress admission bound exceeded"
        );
        let mut previous = self.last_admitted;
        for &(packet_id, _) in packets {
            let advance = packet_id.wrapping_sub(previous);
            let outstanding_span = packet_id.wrapping_sub(self.completed);
            ensure!(
                advance != 0
                    && advance < SERIAL_HALF_RANGE
                    && outstanding_span != 0
                    && outstanding_span < SERIAL_HALF_RANGE
                    && !self.verdicts.contains_key(&packet_id),
                "OUTPUT received packet IDs are duplicated, reordered, or ambiguous"
            );
            previous = packet_id;
        }
        for (packet_id, flow) in packets {
            let packet_id = *packet_id;
            self.order.push_back(packet_id);
            self.verdicts.insert(
                packet_id,
                PacketProgress {
                    flow: flow.clone(),
                    completed: false,
                },
            );
        }
        self.last_admitted = previous;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn admit(&mut self, packet_ids: &[u32]) -> Result<()> {
        self.admit_classified(
            &packet_ids
                .iter()
                .map(|&id| (id, OutgoingFlow::Unknown))
                .collect::<Vec<_>>(),
        )
    }

    /// Called only after the actual verdict was successfully sent. Completed
    /// later slots remain bounded until the global prefix crosses the hole;
    /// inspecting flow-specific readiness never retires those slots early.
    pub(super) fn complete(&mut self, packet_id: u32) -> Result<()> {
        let packet = self
            .verdicts
            .get_mut(&packet_id)
            .context("OUTPUT verdict refers to an unadmitted or retired packet ID")?;
        ensure!(
            !packet.completed,
            "OUTPUT packet verdict completion is duplicated"
        );
        packet.completed = true;
        while let Some(&first) = self.order.front() {
            if !self
                .verdicts
                .get(&first)
                .is_some_and(|packet| packet.completed)
            {
                break;
            }
            self.order.pop_front();
            self.verdicts.remove(&first);
            self.completed = first;
        }
        Ok(())
    }

    pub(super) fn reached(&self, barrier: &ReadThroughBarrier) -> bool {
        self.identity.port_id == barrier.identity.port_id
            && Arc::ptr_eq(&self.identity.epoch, &barrier.identity.epoch)
            && self.completed.wrapping_sub(barrier.sequence) < SERIAL_HALF_RANGE
    }

    pub(super) fn reached_for_flow(&self, barrier: &ReadThroughBarrier, key: &FlowKey) -> bool {
        if self.reached(barrier) {
            return true;
        }
        if self.identity.port_id != barrier.identity.port_id
            || !Arc::ptr_eq(&self.identity.epoch, &barrier.identity.epoch)
            || self.last_admitted.wrapping_sub(barrier.sequence) >= SERIAL_HALF_RANGE
        {
            return false;
        }
        // Receipt through the captured ID proves that no older original is
        // still unread. Admission/classification is atomic under the registry
        // lock; it carries no process identity or policy authorization.
        self.order
            .iter()
            .take_while(|&&id| barrier.sequence.wrapping_sub(id) < SERIAL_HALF_RANGE)
            .all(|id| {
                self.verdicts.get(id).is_some_and(|packet| {
                    packet.completed
                        || match &packet.flow {
                            OutgoingFlow::Reply(flow) => flow != key,
                            OutgoingFlow::Unrelated => true,
                            OutgoingFlow::Unknown => false,
                        }
                })
            })
    }

    #[cfg(test)]
    pub(super) fn barrier_for_test(&self, sequence: u32) -> ReadThroughBarrier {
        ReadThroughBarrier {
            identity: self.identity(),
            sequence,
        }
    }
}

impl QueueIdentity {
    pub(super) fn capture(&self) -> Result<ReadThroughBarrier> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(PROC_QUEUE_PATH)
            .with_context(|| {
                format!("cannot inspect OUTPUT queue read-through boundary at {PROC_QUEUE_PATH}")
            })?;
        self.capture_from(file)
    }

    fn capture_from(&self, reader: impl Read) -> Result<ReadThroughBarrier> {
        let (bytes, length) = read_bounded_metadata(reader)?;
        let text = std::str::from_utf8(&bytes[..length])
            .context("NFQUEUE progress metadata is not UTF-8")?;
        let mut sequence = None;
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let mut fields = line.split_ascii_whitespace();
            let queue_number = fields
                .next()
                .context("NFQUEUE progress record has no queue number")?
                .parse::<u16>()
                .context("NFQUEUE progress queue number is invalid")?;
            if queue_number != APPLICATION_QUEUE_NUMBER {
                continue;
            }
            ensure!(
                sequence.is_none(),
                "OUTPUT queue progress record is duplicated"
            );
            let mut values = [0_u32; 8];
            for value in &mut values {
                *value = fields
                    .next()
                    .context("OUTPUT queue progress record is truncated")?
                    .parse()
                    .context("OUTPUT queue progress field is invalid")?;
            }
            ensure!(
                fields.next().is_none(),
                "OUTPUT queue progress record has extra fields"
            );
            ensure!(
                values[0] == self.port_id,
                "OUTPUT queue netlink owner changed"
            );
            ensure!(
                values[2] == 2 && values[3] == 512 && values[7] == 1,
                "OUTPUT queue progress configuration changed"
            );
            // values[1] is queue depth; values[4]/[5] are kernel/user drops.
            // None of them is a packet ID. Dropped IDs may leave a conservative
            // gap until a subsequent verdict or the reply's fixed timeout.
            sequence = Some(values[6]);
        }
        Ok(ReadThroughBarrier {
            identity: self.clone(),
            sequence: sequence.context("OUTPUT queue progress record is missing")?,
        })
    }
}

fn read_bounded_metadata(mut reader: impl Read) -> Result<([u8; MAX_PROC_BYTES], usize)> {
    let mut bytes = [0_u8; MAX_PROC_BYTES];
    let mut length = 0;
    let started = Instant::now();
    let mut calls = 0;
    while length < bytes.len() {
        ensure!(
            started.elapsed() < READ_BUDGET && calls < MAX_READ_CALLS,
            "NFQUEUE progress read exceeded its fixed budget"
        );
        calls += 1;
        match reader.read(&mut bytes[length..]) {
            Ok(0) => break,
            Ok(size) => length += size,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(error).context("cannot read OUTPUT queue read-through boundary");
            }
        }
    }
    if length == bytes.len() {
        let mut extra = [0_u8; 1];
        loop {
            ensure!(
                started.elapsed() < READ_BUDGET && calls < MAX_READ_CALLS,
                "NFQUEUE progress read exceeded its fixed budget"
            );
            calls += 1;
            match reader.read(&mut extra) {
                Ok(size) => {
                    ensure!(
                        size == 0,
                        "NFQUEUE progress metadata exceeds its fixed bound"
                    );
                    break;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error).context("cannot finish NFQUEUE metadata read"),
            }
        }
    }
    ensure!(
        started.elapsed() < READ_BUDGET,
        "NFQUEUE progress read expired"
    );
    Ok((bytes, length))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    pub(super) fn barrier(progress: &QueueProgress, sequence: u32) -> ReadThroughBarrier {
        ReadThroughBarrier {
            identity: progress.identity(),
            sequence,
        }
    }

    fn capture(progress: &QueueProgress, text: &str) -> Result<ReadThroughBarrier> {
        progress
            .identity()
            .capture_from(Cursor::new(text.as_bytes()))
    }

    fn flow(port: u16) -> Result<FlowKey> {
        Ok(FlowKey {
            local: "192.0.2.1".parse()?,
            local_port: port,
            remote: "198.51.100.1".parse()?,
            remote_port: Some(53),
            protocol: openshield_core::TransportProtocol::Udp,
        })
    }

    #[test]
    fn flow_barrier_waits_for_matching_and_unknown_verdicts_in_every_completion_order() -> Result<()>
    {
        let key = flow(5000)?;
        for order in [
            [1, 2, 3],
            [1, 3, 2],
            [2, 1, 3],
            [2, 3, 1],
            [3, 1, 2],
            [3, 2, 1],
        ] {
            let mut progress = QueueProgress::new(77)?;
            let target = barrier(&progress, 4);
            progress.admit_classified(&[
                (1, OutgoingFlow::Reply(flow(5001)?)),
                (2, OutgoingFlow::Reply(key.clone())),
                (3, OutgoingFlow::Unknown),
                (4, OutgoingFlow::Unrelated),
                // Even later matching or unknown packets cannot extend target.
                (5, OutgoingFlow::Reply(key.clone())),
                (6, OutgoingFlow::Unknown),
            ])?;
            let mut done = [false; 3];
            assert!(!progress.reached_for_flow(&target, &key));
            for id in order {
                progress.complete(id)?;
                done[usize::try_from(id - 1)?] = true;
                assert_eq!(progress.reached_for_flow(&target, &key), done[1] && done[2]);
            }
            // The separate global prefix/backpressure proof still waits for 4.
            assert!(!progress.reached(&target));
            assert_eq!(progress.remaining_capacity(), MAX_TRACKED_OUTGOING - 3);
        }
        Ok(())
    }

    #[test]
    fn flow_barrier_cannot_reuse_old_flow_before_new_original_is_classified() -> Result<()> {
        let key = flow(5000)?;
        let mut progress = QueueProgress::new(77)?;
        progress.admit_classified(&[(1, OutgoingFlow::Reply(key.clone()))])?;
        progress.complete(1)?;
        let target = barrier(&progress, 3);
        assert!(!progress.reached_for_flow(&target, &key));
        progress.admit_classified(&[(2, OutgoingFlow::Unrelated)])?;
        assert!(!progress.reached_for_flow(&target, &key));
        progress.admit_classified(&[(3, OutgoingFlow::Reply(key.clone()))])?;
        assert!(!progress.reached_for_flow(&target, &key));
        progress.complete(3)?;
        assert!(progress.reached_for_flow(&target, &key));
        assert!(!progress.reached(&target));
        Ok(())
    }

    #[test]
    fn flow_barrier_wrap_and_gaps_never_hide_matching_or_unknown_packets() -> Result<()> {
        let key = flow(5000)?;
        let mut progress = QueueProgress::new(77)?;
        progress.completed = u32::MAX - 3;
        progress.last_admitted = progress.completed;
        let target = barrier(&progress, 0);
        progress.admit_classified(&[
            (u32::MAX - 2, OutgoingFlow::Unrelated),
            (u32::MAX - 1, OutgoingFlow::Reply(key.clone())),
        ])?;
        progress.complete(u32::MAX - 1)?;
        assert!(!progress.reached_for_flow(&target, &key));
        // IDs MAX and 0 never arrived. Ordered receipt past them covers the
        // gap, but an unknown packet before another captured ID must finish.
        progress.admit_classified(&[(1, OutgoingFlow::Unknown)])?;
        assert!(progress.reached_for_flow(&target, &key));
        let later = barrier(&progress, 2);
        progress.admit_classified(&[(3, OutgoingFlow::Unrelated)])?;
        assert!(!progress.reached_for_flow(&later, &key));
        progress.complete(1)?;
        assert!(progress.reached_for_flow(&later, &key));
        assert!(!progress.reached(&target));
        assert!(progress.complete(0).is_err());
        assert!(!progress.reached_for_flow(
            &barrier(
                &progress,
                progress.completed.wrapping_add(SERIAL_HALF_RANGE)
            ),
            &key
        ));
        Ok(())
    }

    #[test]
    fn flow_classification_never_releases_another_runtime_epoch() -> Result<()> {
        let key = flow(5000)?;
        let original = QueueProgress::new(77)?;
        let target = barrier(&original, 1);
        for port in [77, 78] {
            let mut replacement = QueueProgress::new(port)?;
            replacement.admit_classified(&[(1, OutgoingFlow::Unrelated)])?;
            assert!(!replacement.reached_for_flow(&target, &key));
            replacement.complete(1)?;
            assert!(!replacement.reached_for_flow(&target, &key));
        }
        Ok(())
    }

    #[test]
    fn captured_target_does_not_wait_for_later_unrelated_traffic() -> Result<()> {
        let mut progress = QueueProgress::new(77)?;
        let target = barrier(&progress, 5);
        progress.admit(&[1, 2, 3, 4, 5])?;
        for id in 1..5 {
            progress.complete(id)?;
            assert!(!progress.reached(&target));
        }
        progress.complete(5)?;
        assert!(progress.reached(&target));
        for id in 6..100 {
            let _later_target = barrier(&progress, id + 7);
            progress.admit(&[id])?;
            progress.complete(id)?;
            assert!(progress.reached(&target));
        }
        Ok(())
    }

    #[test]
    fn zero_and_packet_id_wrap_are_ordered_without_saturating_arithmetic() -> Result<()> {
        let mut progress = QueueProgress::new(77)?;
        assert!(progress.reached(&barrier(&progress, 0)));
        assert!(!progress.reached(&barrier(&progress, 1)));
        progress.completed = u32::MAX - 1;
        progress.last_admitted = progress.completed;
        progress.admit(&[u32::MAX, 0, 1])?;
        let target = barrier(&progress, 0);
        assert!(!progress.reached(&target));
        progress.complete(u32::MAX)?;
        assert!(!progress.reached(&target));
        progress.complete(0)?;
        assert!(progress.reached(&target));
        progress.complete(1)?;
        assert!(progress.reached(&target));
        Ok(())
    }

    #[test]
    fn duplicate_backward_and_half_range_completions_never_advance() -> Result<()> {
        let mut progress = QueueProgress::new(77)?;
        progress.admit(&[7])?;
        progress.complete(7)?;
        for id in [7, 6, 7 + SERIAL_HALF_RANGE] {
            assert!(progress.complete(id).is_err());
            assert!(progress.admit(&[id]).is_err());
            assert_eq!(progress.completed, 7);
        }
        assert!(!progress.reached(&barrier(&progress, 7 + SERIAL_HALF_RANGE)));
        Ok(())
    }

    #[test]
    fn out_of_order_verdicts_advance_only_the_completed_admission_prefix() -> Result<()> {
        for order in [
            [1, 2, 3],
            [1, 3, 2],
            [2, 1, 3],
            [2, 3, 1],
            [3, 1, 2],
            [3, 2, 1],
        ] {
            let mut progress = QueueProgress::new(77)?;
            progress.admit(&[1, 2, 3])?;
            let first_two = barrier(&progress, 2);
            let all = barrier(&progress, 3);
            let mut done = [false; 3];
            for id in order {
                progress.complete(id)?;
                done[usize::try_from(id - 1)?] = true;
                assert_eq!(progress.reached(&first_two), done[0] && done[1]);
                assert_eq!(progress.reached(&all), done.iter().all(|done| *done));
            }
            assert_eq!(progress.remaining_capacity(), MAX_TRACKED_OUTGOING);
        }
        Ok(())
    }

    #[test]
    fn kernel_id_gaps_do_not_skip_admitted_packets_or_invent_verdicts() -> Result<()> {
        let mut progress = QueueProgress::new(77)?;
        let target = barrier(&progress, 9);
        progress.admit(&[5, 8, 11])?;
        progress.complete(11)?;
        assert_eq!(progress.completed, 0);
        assert!(!progress.reached(&target));
        assert!(progress.complete(9).is_err());
        progress.complete(5)?;
        assert_eq!(progress.completed, 5);
        assert!(!progress.reached(&target));
        progress.complete(8)?;
        assert_eq!(progress.completed, 11);
        assert!(progress.reached(&target));
        Ok(())
    }

    #[test]
    fn wrapped_out_of_order_verdicts_preserve_the_prefix() -> Result<()> {
        let mut progress = QueueProgress::new(77)?;
        progress.completed = u32::MAX - 2;
        progress.last_admitted = progress.completed;
        progress.admit(&[u32::MAX - 1, 0, 2])?;
        let target = barrier(&progress, 0);
        progress.complete(0)?;
        progress.complete(2)?;
        assert!(!progress.reached(&target));
        assert_eq!(progress.completed, u32::MAX - 2);
        progress.complete(u32::MAX - 1)?;
        assert_eq!(progress.completed, 2);
        assert!(progress.reached(&target));
        assert!(progress.admit(&[u32::MAX]).is_err());
        assert!(progress.complete(0).is_err());
        Ok(())
    }

    #[test]
    fn unadmitted_or_duplicate_completions_cannot_cover_an_earlier_hole() -> Result<()> {
        let mut progress = QueueProgress::new(77)?;
        assert!(progress.complete(1).is_err());
        progress.admit(&[1, 2])?;
        progress.complete(2)?;
        for id in [2, 3, u32::MAX] {
            assert!(progress.complete(id).is_err());
            assert_eq!(progress.completed, 0);
        }
        assert_eq!(progress.remaining_capacity(), MAX_TRACKED_OUTGOING - 2);
        progress.complete(1)?;
        assert_eq!(progress.completed, 2);
        assert!(progress.complete(1).is_err());
        Ok(())
    }

    #[test]
    fn failed_admission_is_atomic_and_cannot_reorder_or_replay_ids() -> Result<()> {
        let mut progress = QueueProgress::new(77)?;
        progress.admit(&[2])?;
        for ids in [&[3, 3][..], &[4, 3], &[3, 2], &[3, SERIAL_HALF_RANGE]] {
            assert!(progress.admit(ids).is_err());
            assert_eq!(progress.last_admitted, 2);
            assert_eq!(progress.order.iter().copied().collect::<Vec<_>>(), [2]);
            assert_eq!(progress.verdicts.len(), 1);
        }
        progress.admit(&[])?;
        progress.complete(2)?;
        assert!(progress.admit(&[2]).is_err());
        progress.admit(&[3, 4])?;
        assert_eq!(progress.last_admitted, 4);
        Ok(())
    }

    #[test]
    fn total_outstanding_serial_window_cannot_reach_half_range() -> Result<()> {
        let mut progress = QueueProgress::new(77)?;
        progress.admit(&[1, SERIAL_HALF_RANGE - 1])?;
        assert!(progress.admit(&[SERIAL_HALF_RANGE]).is_err());
        assert_eq!(progress.last_admitted, SERIAL_HALF_RANGE - 1);
        progress.complete(1)?;
        progress.admit(&[SERIAL_HALF_RANGE])?;
        progress.complete(SERIAL_HALF_RANGE)?;
        assert_eq!(progress.completed, 1);
        progress.complete(SERIAL_HALF_RANGE - 1)?;
        assert_eq!(progress.completed, SERIAL_HALF_RANGE);
        Ok(())
    }

    #[test]
    fn completed_later_slots_remain_bounded_until_the_oldest_verdict_arrives() -> Result<()> {
        let mut progress = QueueProgress::new(77)?;
        let last = u32::try_from(MAX_TRACKED_OUTGOING)?;
        progress.admit(&(1..=last).collect::<Vec<_>>())?;
        for id in 2..=last {
            progress.complete(id)?;
        }
        assert_eq!(progress.remaining_capacity(), 0);
        assert_eq!(progress.completed, 0);
        assert!(progress.admit(&[last + 1]).is_err());
        assert_eq!(progress.order.len(), MAX_TRACKED_OUTGOING);
        assert_eq!(progress.verdicts.len(), MAX_TRACKED_OUTGOING);
        progress.complete(1)?;
        assert_eq!(progress.remaining_capacity(), MAX_TRACKED_OUTGOING);
        assert_eq!(progress.completed, last);
        progress.admit(&[last + 1])?;
        progress.complete(last + 1)?;
        Ok(())
    }

    #[test]
    fn metadata_barrier_captured_before_receipt_still_waits_for_every_admitted_id() -> Result<()> {
        let mut progress = QueueProgress::new(77)?;
        let target = capture(&progress, "1337 77 3 2 512 0 0 3 1\n")?;
        progress.admit(&[2, 4])?;
        progress.complete(4)?;
        assert!(!progress.reached(&target));
        progress.complete(2)?;
        assert!(progress.reached(&target));
        Ok(())
    }

    #[test]
    fn queue_identity_and_runtime_epoch_are_not_reusable() -> Result<()> {
        assert!(QueueProgress::new(0).is_err());
        let original = QueueProgress::new(77)?;
        let target = barrier(&original, 0);
        assert!(original.reached(&target));
        assert!(!QueueProgress::new(78)?.reached(&target));
        assert!(!QueueProgress::new(77)?.reached(&target));
        Ok(())
    }

    #[test]
    fn metadata_uses_packet_sequence_not_depth_or_drop_counters() -> Result<()> {
        let mut progress = QueueProgress::new(77)?;
        let target = capture(
            &progress,
            "1338 88 0 2 512 0 0 999 1\n1337 77 7 2 512 123 456 9 1\n",
        )?;
        progress.admit(&[8, 9])?;
        progress.complete(8)?;
        assert!(!progress.reached(&target));
        progress.complete(9)?;
        assert!(progress.reached(&target));
        Ok(())
    }

    #[test]
    fn missing_replaced_duplicate_and_malformed_records_fail_closed() -> Result<()> {
        let progress = QueueProgress::new(77)?;
        for text in [
            "",
            "1339 77 0 2 512 0 0 1 1\n",
            "1337 78 0 2 512 0 0 1 1\n",
            "1337 77 0 1 512 0 0 1 1\n",
            "1337 77 0 2 4096 0 0 1 1\n",
            "1337 77 0 2 512 0 0 1\n",
            "1337 77 0 2 512 0 0 1 1 extra\n",
            "1337 77 0 2 512 0 0 4294967296 1\n",
            "1337 77 0 2 512 0 0 1 1\n1337 77 0 2 512 0 0 2 1\n",
        ] {
            assert!(capture(&progress, text).is_err(), "accepted {text:?}");
        }
        Ok(())
    }

    #[test]
    fn read_errors_non_utf8_and_oversized_metadata_fail_closed() -> Result<()> {
        struct FailedRead;
        impl Read for FailedRead {
            fn read(&mut self, _bytes: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "fixture denial",
                ))
            }
        }
        let identity = QueueProgress::new(77)?.identity();
        assert!(identity.capture_from(FailedRead).is_err());
        assert!(identity.capture_from(Cursor::new([0xff])).is_err());
        assert!(
            identity
                .capture_from(Cursor::new(vec![b' '; MAX_PROC_BYTES + 1]))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn repeatedly_interrupted_metadata_cannot_spin_without_bound() -> Result<()> {
        struct InterruptedRead(usize);
        impl Read for InterruptedRead {
            fn read(&mut self, _bytes: &mut [u8]) -> io::Result<usize> {
                self.0 += 1;
                Err(io::Error::from(ErrorKind::Interrupted))
            }
        }
        let mut reader = InterruptedRead(0);
        assert!(
            QueueProgress::new(77)?
                .identity()
                .capture_from(&mut reader)
                .is_err()
        );
        assert_eq!(reader.0, MAX_READ_CALLS);
        Ok(())
    }
}
