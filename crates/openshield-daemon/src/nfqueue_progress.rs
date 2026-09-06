//! Bounded, captured read-through barriers for the one ordered OUTPUT queue.
//!
//! A barrier is scheduling evidence, never an authorization. The kernel assigns
//! packet IDs under the queue lock before ordered netlink delivery. Completing
//! an ID after its actual verdict therefore covers earlier delivered IDs. Later
//! traffic cannot extend an already captured barrier. Missing metadata, a queue
//! replacement, ambiguous serial arithmetic, or a failed verdict cannot advance
//! progress. Every released reply still requires current-policy `NF_REPEAT`.

use std::fs::OpenOptions;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use openshield_core::APPLICATION_QUEUE_NUMBER;

const PROC_QUEUE_PATH: &str = "/proc/self/net/netfilter/nfnetlink_queue";
const MAX_PROC_BYTES: usize = 16 * 1024;
const SERIAL_HALF_RANGE: u32 = 1 << 31;
const READ_BUDGET: Duration = Duration::from_millis(100);
const MAX_READ_CALLS: usize = 128;

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
        })
    }

    pub(super) fn identity(&self) -> QueueIdentity {
        self.identity.clone()
    }

    pub(super) fn complete(&mut self, packet_id: u32) -> Result<()> {
        let advance = packet_id.wrapping_sub(self.completed);
        ensure!(
            advance != 0 && advance < SERIAL_HALF_RANGE,
            "OUTPUT verdict packet IDs are duplicated, reordered, or ambiguous"
        );
        self.completed = packet_id;
        Ok(())
    }

    pub(super) fn reached(&self, barrier: &ReadThroughBarrier) -> bool {
        self.identity.port_id == barrier.identity.port_id
            && Arc::ptr_eq(&self.identity.epoch, &barrier.identity.epoch)
            && self.completed.wrapping_sub(barrier.sequence) < SERIAL_HALF_RANGE
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
            .context("cannot inspect OUTPUT queue read-through boundary")?;
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

    #[test]
    fn captured_target_does_not_wait_for_later_unrelated_traffic() -> Result<()> {
        let mut progress = QueueProgress::new(77)?;
        let target = barrier(&progress, 5);
        for id in 1..5 {
            progress.complete(id)?;
            assert!(!progress.reached(&target));
        }
        progress.complete(5)?;
        assert!(progress.reached(&target));
        for id in 6..100 {
            let _later_target = barrier(&progress, id + 7);
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
        progress.complete(7)?;
        for id in [7, 6, 7 + SERIAL_HALF_RANGE] {
            assert!(progress.complete(id).is_err());
            assert_eq!(progress.completed, 7);
        }
        assert!(!progress.reached(&barrier(&progress, 7 + SERIAL_HALF_RANGE)));
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
