//! Bounded, best-effort wall-time diagnostics, never authorization inputs.
//!
//! No packet addresses, process identities, or selector values are retained.
//! The fixed-size accumulator never waits for a competing recorder. Dropped
//! samples are counted so a diagnostic report cannot imply exact accounting.
//! Nested stage times overlap with the batch total; these are not CPU times.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const REPORT_INTERVAL: Duration = Duration::from_secs(10);
const STAGE_COUNT: usize = 8;

static WINDOW: Mutex<TimingWindow> = Mutex::new(TimingWindow::new());
static DROPPED_SAMPLES: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug)]
pub(crate) enum TimingStage {
    Batch,
    SocketLookup,
    OwnerBefore,
    Metadata,
    OwnerAfter,
    QueueWait,
    QueueDecision,
    QueueVerdict,
}

impl TimingStage {
    const ALL: [Self; STAGE_COUNT] = [
        Self::Batch,
        Self::SocketLookup,
        Self::OwnerBefore,
        Self::Metadata,
        Self::OwnerAfter,
        Self::QueueWait,
        Self::QueueDecision,
        Self::QueueVerdict,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::Batch => "batch",
            Self::SocketLookup => "socket_lookup",
            Self::OwnerBefore => "owner_before",
            Self::Metadata => "metadata",
            Self::OwnerAfter => "owner_after",
            Self::QueueWait => "queue_wait",
            Self::QueueDecision => "queue_decision",
            Self::QueueVerdict => "queue_verdict",
        }
    }
}

/// Record a stage on every exit, including an error or early return. Until
/// `finish` supplies the actual failure count, every unit is counted failed.
#[derive(Debug)]
pub(crate) struct TimingScope {
    stage: TimingStage,
    started: Instant,
    units: usize,
    failures: usize,
}

impl TimingScope {
    #[must_use]
    pub(crate) fn new(stage: TimingStage, units: usize) -> Self {
        Self {
            stage,
            started: Instant::now(),
            units,
            failures: units,
        }
    }

    pub(crate) fn finish(mut self, failures: usize) {
        self.failures = failures.min(self.units);
    }
}

impl Drop for TimingScope {
    fn drop(&mut self) {
        record_elapsed(
            self.stage,
            self.started.elapsed(),
            self.units,
            self.failures,
        );
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct StageTotals {
    samples: u64,
    units: u64,
    failures: u64,
    wall_us: u64,
    max_wall_us: u64,
}

impl StageTotals {
    const EMPTY: Self = Self {
        samples: 0,
        units: 0,
        failures: 0,
        wall_us: 0,
        max_wall_us: 0,
    };

    fn record(&mut self, elapsed: Duration, units: usize, failures: usize) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.samples = self.samples.saturating_add(1);
        self.units = self
            .units
            .saturating_add(u64::try_from(units).unwrap_or(u64::MAX));
        self.failures = self
            .failures
            .saturating_add(u64::try_from(failures.min(units)).unwrap_or(u64::MAX));
        self.wall_us = self.wall_us.saturating_add(micros);
        self.max_wall_us = self.max_wall_us.max(micros);
    }
}

#[derive(Debug)]
struct TimingWindow {
    started: Option<Instant>,
    stages: [StageTotals; STAGE_COUNT],
    enumerated_processes: u64,
    enumerated_tasks: u64,
}

impl TimingWindow {
    const fn new() -> Self {
        Self {
            started: None,
            stages: [StageTotals::EMPTY; STAGE_COUNT],
            enumerated_processes: 0,
            enumerated_tasks: 0,
        }
    }

    fn take_report(&mut self, now: Instant) -> Option<TimingReport> {
        let started = self.started.get_or_insert(now);
        let elapsed = now.saturating_duration_since(*started);
        if elapsed < REPORT_INTERVAL {
            return None;
        }
        let previous = std::mem::replace(self, Self::new());
        self.started = Some(now);
        Some(TimingReport {
            window_wall_ms: u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            stages: previous.stages,
            enumerated_processes: previous.enumerated_processes,
            enumerated_tasks: previous.enumerated_tasks,
        })
    }
}

#[derive(Debug)]
struct TimingReport {
    window_wall_ms: u64,
    stages: [StageTotals; STAGE_COUNT],
    enumerated_processes: u64,
    enumerated_tasks: u64,
}

impl TimingReport {
    fn emit(self, dropped_samples: usize) {
        // Formatting and logging are outside the mutex and occur at most once
        // per interval. Only fixed stage names and numeric aggregates appear.
        let stages = TimingStage::ALL.map(|stage| {
            let totals = self.stages[stage as usize];
            serde_json::json!([
                stage.name(),
                {
                    "samples": totals.samples,
                    "units": totals.units,
                    "failures": totals.failures,
                    "wall_us": totals.wall_us,
                    "max_wall_us": totals.max_wall_us,
                }
            ])
        });
        let stages = serde_json::Value::Array(Vec::from(stages));
        tracing::info!(
            window_wall_ms = self.window_wall_ms,
            enumerated_processes = self.enumerated_processes,
            enumerated_tasks = self.enumerated_tasks,
            dropped_samples,
            stages = %stages,
            "application attribution stage timings (wall time, not CPU)"
        );
    }
}

fn update_window(update: impl FnOnce(&mut TimingWindow)) {
    let Ok(mut window) = WINDOW.try_lock() else {
        let _ = DROPPED_SAMPLES.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            Some(count.saturating_add(1))
        });
        return;
    };
    update(&mut window);
    let report = window.take_report(Instant::now());
    let dropped = report
        .as_ref()
        .map(|_| DROPPED_SAMPLES.swap(0, Ordering::Relaxed));
    drop(window);
    if let Some(report) = report {
        report.emit(dropped.unwrap_or(0));
    }
}

pub(crate) fn record_elapsed(stage: TimingStage, elapsed: Duration, units: usize, failures: usize) {
    update_window(|window| window.stages[stage as usize].record(elapsed, units, failures));
}

/// Counts work for completed task enumerations, not unique system processes
/// across time. Both owner snapshots contribute; no PID or TID is retained.
pub(crate) fn record_enumeration(processes: usize, tasks: usize) {
    update_window(|window| {
        window.enumerated_processes = window
            .enumerated_processes
            .saturating_add(u64::try_from(processes).unwrap_or(u64::MAX));
        window.enumerated_tasks = window
            .enumerated_tasks
            .saturating_add(u64::try_from(tasks).unwrap_or(u64::MAX));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_saturate_and_failures_never_exceed_units() {
        let mut totals = StageTotals {
            samples: u64::MAX,
            units: u64::MAX,
            failures: u64::MAX,
            wall_us: u64::MAX,
            max_wall_us: 0,
        };
        totals.record(Duration::MAX, 1, usize::MAX);
        assert_eq!(totals.samples, u64::MAX);
        assert_eq!(totals.units, u64::MAX);
        assert_eq!(totals.failures, u64::MAX);
        assert_eq!(totals.wall_us, u64::MAX);
        assert_eq!(totals.max_wall_us, u64::MAX);

        let mut totals = StageTotals::default();
        totals.record(Duration::from_micros(7), 3, 8);
        assert_eq!(totals.samples, 1);
        assert_eq!(totals.units, 3);
        assert_eq!(totals.failures, 3);
        assert_eq!(totals.wall_us, 7);
        assert_eq!(totals.max_wall_us, 7);
    }

    #[test]
    fn reports_are_rate_limited_and_reset_only_completed_window() {
        let mut window = TimingWindow::new();
        let now = Instant::now();
        window.stages[TimingStage::Batch as usize].record(Duration::from_millis(5), 4, 1);
        assert!(window.take_report(now).is_none());
        assert!(window.take_report(now + REPORT_INTERVAL / 2).is_none());
        let report = window.take_report(now + REPORT_INTERVAL);
        assert_eq!(
            report.as_ref().map(|report| report.window_wall_ms),
            Some(10_000)
        );
        assert_eq!(report.map(|report| report.stages[0].units), Some(4));
        assert!(window.take_report(now + REPORT_INTERVAL).is_none());
        assert_eq!(window.stages[0].units, 0);
        window.stages[0].record(Duration::from_millis(1), 1, 0);
        assert!(window.take_report(now + REPORT_INTERVAL * 2).is_some());
    }

    #[test]
    fn stage_names_and_storage_are_fixed_and_public_metadata_free() {
        let stages = TimingStage::ALL;
        assert_eq!(stages.len(), STAGE_COUNT);
        for (index, stage) in stages.into_iter().enumerate() {
            assert_eq!(stage as usize, index);
            assert!(
                stage
                    .name()
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
        }
        assert!(size_of::<TimingWindow>() < 1024);
    }

    #[test]
    fn unfinished_scope_conservatively_counts_every_unit_failed() {
        let scope = TimingScope::new(TimingStage::Batch, 7);
        assert_eq!(scope.units, 7);
        assert_eq!(scope.failures, 7);
        // Dropping the guard is deliberately allowed: early returns must not
        // silently disappear from stage accounting.
        drop(scope);
    }
}
