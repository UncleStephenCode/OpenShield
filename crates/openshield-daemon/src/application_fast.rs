//! Explicitly opt-in, reduced-scope socket-owner discovery.
//!
//! No identities, socket inodes or verdicts survive a batch. A successful
//! exhaustive Strict lookup seeds only a recent (UID, TGID, anchor TID,
//! start-time) search hint. Fast still reads the current socket and process
//! metadata. A dead or replaced hint is omitted from the reduced search rather
//! than invalidating unrelated live hints. Unlike Strict, a hit cannot exclude
//! a second owner in an omitted or uncached process (for example after
//! `SCM_RIGHTS`); this is the documented tradeoff.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, ensure};
use openshield_core::{ApplicationIdentity, EnforcementStrategy};

use crate::application_timing::{TimingScope, TimingStage};

use super::{
    IdentityCaptureRequirements, MAX_ATTRIBUTION_BATCH_SIZE, MAX_FDS_PER_TASK, MAX_PROC_ENTRIES,
    OutboundConnection, OwnerFdHints, OwnerScanLimits, OwnerScanRequest, OwnerSnapshot,
    OwnerTaskGroup, ProcfsResolver, SocketOwnerKey, ensure_within_deadline, enumerate_task_ids,
    owner_fd_hints, read_process_fs_uid, read_start_time, reject_inconsistent_batch_identities,
    scan_owner_task_groups, socket_targets_by_uid,
};

const MAX_OWNER_HINTS: usize = 256;
const OWNER_HINT_TTL: Duration = Duration::from_mins(3);

#[derive(Clone, Copy, Debug)]
struct OwnerHint {
    process_id: u32,
    anchor_tid: u32,
    anchor_start: u64,
    last_verified_at: Instant,
}

#[derive(Debug, Default)]
pub(super) struct OwnerCache {
    generation: Option<u32>,
    learning_warm: bool,
    entries: BTreeMap<(u32, u32), OwnerHint>,
}

pub(super) type SharedOwnerCache = Arc<Mutex<OwnerCache>>;

pub(super) fn production_owner_cache() -> SharedOwnerCache {
    static CACHE: OnceLock<SharedOwnerCache> = OnceLock::new();
    Arc::clone(CACHE.get_or_init(|| Arc::new(Mutex::new(OwnerCache::default()))))
}

#[cfg(test)]
pub(super) fn private_owner_cache() -> SharedOwnerCache {
    Arc::new(Mutex::new(OwnerCache::default()))
}

impl OwnerCache {
    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.generation = None;
        self.learning_warm = false;
    }

    pub(super) fn prepare(&mut self, generation: u32, now: Instant) {
        let direct_learning_transition = self.learning_warm
            && self
                .generation
                .is_some_and(|previous| previous.wrapping_add(1) == generation);
        if self.generation != Some(generation) && !direct_learning_transition {
            self.entries.clear();
        }
        self.generation = Some(generation);
        self.learning_warm = false;
        self.entries.retain(|_, hint| {
            now.saturating_duration_since(hint.last_verified_at) < OWNER_HINT_TTL
        });
    }

    pub(super) fn prepare_learning(&mut self, generation: u32, now: Instant) {
        if self.generation != Some(generation) {
            self.entries.clear();
        }
        self.generation = Some(generation);
        self.learning_warm = true;
        self.entries.retain(|_, hint| {
            now.saturating_duration_since(hint.last_verified_at) < OWNER_HINT_TTL
        });
    }

    fn insert(&mut self, uid: u32, hint: OwnerHint) {
        let key = (uid, hint.process_id);
        if !self.entries.contains_key(&key)
            && self.entries.len() >= MAX_OWNER_HINTS
            && let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, hint)| hint.last_verified_at)
                .map(|(key, _)| *key)
        {
            self.entries.remove(&oldest);
        }
        self.entries.insert(key, hint);
    }

    fn touch(&mut self, verified_processes: &BTreeSet<(u32, u32)>, now: Instant) {
        for key in verified_processes {
            if let Some(hint) = self.entries.get_mut(key) {
                // This only retains a process search hint. The current socket,
                // descriptor, UID, start time, executable and requested
                // metadata were checked on both sides of this Fast capture;
                // no identity or allow verdict is retained here.
                hint.last_verified_at = now;
            }
        }
    }

    fn clear_after_detected_ambiguity(&mut self, results: &[Result<ApplicationIdentity>]) {
        let detected_ambiguity = results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .any(|error| {
                let message = format!("{error:#}");
                message.contains("socket is shared by multiple processes")
                    || message.contains("socket-owning tasks have ambiguous application identities")
                    || message.contains("mandatory process identity changed between captures")
            });
        if detected_ambiguity {
            // A reduced lookup may have seen just one of the now-known
            // holders. Do not let an older positive hint hide the ambiguity
            // on the next Fast request.
            self.entries.clear();
        }
    }

    pub(super) fn seed(
        &mut self,
        before: &OwnerSnapshot,
        keys: &[Option<SocketOwnerKey>],
        results: &[Result<ApplicationIdentity>],
        now: Instant,
    ) {
        if keys.len() != results.len() {
            return;
        }
        // Never seed a process when another target owned by that same process
        // failed the exhaustive batch. Other failures cannot invalidate an
        // independently successful, twice-checked owner.
        let unsafe_processes = keys
            .iter()
            .zip(results)
            .filter(|(_, result)| result.is_err())
            .filter_map(|(key, _)| *key)
            .flat_map(|key| {
                before
                    .observed_processes
                    .get(&key)
                    .into_iter()
                    .flatten()
                    .copied()
            })
            .collect::<BTreeSet<_>>();
        for (key, result) in keys.iter().zip(results) {
            let (Some(key), Ok(identity)) = (key, result) else {
                continue;
            };
            if let Some(owner) = before.unique.get(key).into_iter().flatten().find(|owner| {
                owner.tid == identity.pid && !unsafe_processes.contains(&owner.process_id)
            }) {
                self.insert(
                    key.uid,
                    OwnerHint {
                        process_id: owner.process_id,
                        anchor_tid: owner.tid,
                        anchor_start: identity.process_start_time_ticks,
                        last_verified_at: now,
                    },
                );
            }
        }
    }
}

impl ProcfsResolver {
    pub(crate) fn resolve_batch_with_strategy_until(
        &self,
        requests: &[(&OutboundConnection, IdentityCaptureRequirements)],
        deadline: Instant,
        strategy: EnforcementStrategy,
        generation: u32,
    ) -> Vec<Result<ApplicationIdentity>> {
        if strategy == EnforcementStrategy::Strict {
            return self.resolve_batch_for_enforcement_until(requests, deadline);
        }
        if requests.len() > MAX_ATTRIBUTION_BATCH_SIZE {
            return self.resolve_batch_for_enforcement_until(requests, deadline);
        }
        if requests.is_empty() {
            if let Ok(mut cache) = self.fast_owners.try_lock() {
                cache.prepare(generation, Instant::now());
            }
            return Vec::new();
        }
        let hints = self
            .fast_owners
            .try_lock()
            .ok()
            .map(|mut cache| {
                cache.prepare(generation, Instant::now());
                cache
                    .entries
                    .iter()
                    .map(|(key, hint)| (*key, *hint))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if hints.is_empty() {
            return self.resolve_batch_strict_until(requests, deadline, true);
        }
        if let Ok(identities) = self.resolve_fast_candidates(requests, deadline, &hints)
            && identities.iter().all(Option::is_some)
        {
            return identities
                .into_iter()
                .map(|identity| {
                    identity.ok_or_else(|| anyhow!("fast owner discovery omitted a result"))
                })
                .collect();
        }
        // Do not mix partial Fast success with Strict fallback: exhaustive
        // discovery for a failed request could find a shared owner for the
        // same socket that another request tentatively accepted as a hit.
        // Retain unrelated live hints across ordinary misses and process churn;
        // otherwise one short-lived UDP sender forces every desktop flow back
        // into a full UID-wide scan. A Strict fallback which actually detects
        // shared ownership still invalidates the reduced search scope.
        let results = self.resolve_batch_strict_until(requests, deadline, true);
        if let Ok(mut cache) = self.fast_owners.try_lock() {
            cache.clear_after_detected_ambiguity(&results);
        }
        results
    }

    fn fast_hint_groups(
        &self,
        hints: &[((u32, u32), OwnerHint)],
        targets: &BTreeSet<SocketOwnerKey>,
        deadline: Instant,
    ) -> Result<Vec<OwnerTaskGroup>> {
        let uids: BTreeSet<_> = targets.iter().map(|key| key.uid).collect();
        let mut processes = BTreeSet::new();
        let mut groups = Vec::new();
        let mut task_count = 0;
        for ((uid, _), hint) in hints {
            if !uids.contains(uid) {
                continue;
            }
            ensure_within_deadline(deadline)?;
            // `prepare` removes expired entries. Recheck the copied timestamp
            // without turning a concurrent boundary crossing into permission.
            if Instant::now().saturating_duration_since(hint.last_verified_at) >= OWNER_HINT_TTL {
                continue;
            }
            let process = self.root.join(hint.process_id.to_string());
            let task_root = process.join("task");
            let anchor = task_root.join(hint.anchor_tid.to_string());
            let start = match read_start_time(&anchor, deadline) {
                Ok(start) => start,
                Err(error) if super::is_attribution_timeout(&error) => return Err(error),
                Err(_) => continue,
            };
            if start != hint.anchor_start {
                continue;
            }
            let observed_uid = match read_process_fs_uid(&anchor, deadline) {
                Ok(observed_uid) => observed_uid,
                Err(error) if super::is_attribution_timeout(&error) => return Err(error),
                Err(_) => continue,
            };
            if observed_uid != *uid {
                continue;
            }
            if processes.insert(hint.process_id) {
                let task_ids = match enumerate_task_ids(
                    &process,
                    &task_root,
                    hint.process_id,
                    deadline,
                    &mut task_count,
                ) {
                    Ok(Some(task_ids)) => task_ids,
                    Err(error) if super::is_attribution_timeout(&error) => return Err(error),
                    Ok(None) | Err(_) => continue,
                };
                groups.push(OwnerTaskGroup {
                    process_id: hint.process_id,
                    task_ids,
                });
            }
        }
        ensure_within_deadline(deadline)?;
        Ok(groups)
    }

    fn fast_owner_snapshot(
        &self,
        groups: &[OwnerTaskGroup],
        targets: &BTreeSet<SocketOwnerKey>,
        deadline: Instant,
        previous_hints: Option<&OwnerFdHints<'_>>,
    ) -> Result<OwnerSnapshot> {
        let targets_by_uid = socket_targets_by_uid(targets);
        let mut daemon_owned =
            self.daemon_owned_targets_for_batch(&targets_by_uid, deadline, MAX_FDS_PER_TASK)?;
        let request = OwnerScanRequest {
            root: &self.root,
            targets_by_uid: &targets_by_uid,
            deadline,
            limits: OwnerScanLimits {
                maximum_fds: MAX_FDS_PER_TASK,
                maximum_owner_records: MAX_PROC_ENTRIES,
                maximum_tasks: MAX_PROC_ENTRIES,
                parallel_task_threshold: usize::MAX,
            },
            previous_hints,
        };
        let accumulated = scan_owner_task_groups(request, groups, 1)?;
        daemon_owned.extend(self.daemon_owned_targets_for_batch(
            &targets_by_uid,
            deadline,
            MAX_FDS_PER_TASK,
        )?);
        Self::finish_owner_snapshot(
            targets,
            &daemon_owned,
            &accumulated.ambiguous_targets,
            accumulated.owners,
            accumulated.observed_processes,
        )
    }

    fn resolve_fast_candidates(
        &self,
        requests: &[(&OutboundConnection, IdentityCaptureRequirements)],
        deadline: Instant,
        hints: &[((u32, u32), OwnerHint)],
    ) -> Result<Vec<Option<ApplicationIdentity>>> {
        let timing = TimingScope::new(TimingStage::Batch, requests.len());
        // These are current netlink results, not cached tuple/inode mappings.
        let (keys, mut errors, targets) = self.resolve_batch_socket_keys(requests, deadline);
        if targets.is_empty() {
            return Ok(vec![None; requests.len()]);
        }
        let groups = self.fast_hint_groups(hints, &targets, deadline)?;
        let before = self.fast_owner_snapshot(&groups, &targets, deadline, None)?;
        let captures = Self::capture_batch_identities(requests, &keys, &before, deadline);
        let fd_hints = owner_fd_hints(&before, &targets, deadline)?;
        let after_groups = self.fast_hint_groups(hints, &targets, deadline)?;
        ensure!(
            groups == after_groups,
            "cached process task set changed during attribution"
        );
        let after = self.fast_owner_snapshot(&after_groups, &targets, deadline, Some(&fd_hints))?;
        // Recheck anchor start times/UIDs after FD scans as well.
        ensure!(
            after_groups == self.fast_hint_groups(hints, &targets, deadline)?,
            "cached owner changed after final descriptor scan"
        );
        let mut identities = vec![None; requests.len()];
        for (index, ((_, requirements), key)) in requests.iter().zip(&keys).enumerate() {
            let Some(key) = key else { continue };
            if errors[index].is_some()
                || before.failures.contains_key(key)
                || after.failures.contains_key(key)
                || before.unique.get(key) != after.unique.get(key)
            {
                continue;
            }
            if let Some(Ok(identity)) = captures.get(&(*key, *requirements)) {
                identities[index] = Some(identity.clone());
            }
        }
        reject_inconsistent_batch_identities(&keys, &mut errors, &mut identities);
        ensure_within_deadline(deadline)?;
        let verified_processes = keys
            .iter()
            .zip(&identities)
            .filter(|(_, identity)| identity.is_some())
            .filter_map(|(key, _)| *key)
            .flat_map(|key| {
                before
                    .unique
                    .get(&key)
                    .into_iter()
                    .flatten()
                    .map(move |owner| (key.uid, owner.process_id))
            })
            .collect::<BTreeSet<_>>();
        if let Ok(mut cache) = self.fast_owners.try_lock() {
            cache.touch(&verified_processes, Instant::now());
        }
        timing.finish(
            identities
                .iter()
                .filter(|identity| identity.is_none())
                .count(),
        );
        Ok(identities)
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    use openshield_core::TransportProtocol;

    use super::super::tests::{
        complete_identity_fixture, create_task_fixture, loopback_connection, write_udp_socket_table,
    };
    use super::super::{ApplicationDecisionPolicy, PROC_SCAN_DEADLINE};
    #[allow(clippy::wildcard_imports)]
    use super::*;

    struct Fixture {
        root: tempfile::TempDir,
        owner: PathBuf,
        connection: OutboundConnection,
        resolver: ProcfsResolver,
    }

    impl Fixture {
        fn new(protocol: TransportProtocol) -> Result<Self, Box<dyn Error>> {
            let root = tempfile::tempdir()?;
            let owner = create_task_fixture(root.path(), 100, 100, 1_000)?;
            complete_identity_fixture(&owner, 100)?;
            symlink("socket:[77]", owner.join("fd/3"))?;
            let connection = loopback_connection(
                protocol,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                12_345,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                54_321,
                1_000,
            )?;
            let resolver = ProcfsResolver::at(root.path());
            let fixture = Self {
                root,
                owner,
                connection,
                resolver,
            };
            fixture.table(77)?;
            Ok(fixture)
        }

        fn table(&self, inode: u64) -> Result<(), Box<dyn Error>> {
            write_udp_socket_table(self.root.path(), &[(12_345, 54_321, 1_000, inode)])?;
            if self.connection.protocol == TransportProtocol::Tcp {
                fs::copy(
                    self.root.path().join("self/net/udp"),
                    self.root.path().join("self/net/tcp"),
                )?;
            }
            Ok(())
        }

        fn resolve(
            &self,
            strategy: EnforcementStrategy,
            generation: u32,
        ) -> Result<ApplicationIdentity> {
            self.resolver
                .resolve_batch_with_strategy_until(
                    &[(&self.connection, IdentityCaptureRequirements::full())],
                    Instant::now() + PROC_SCAN_DEADLINE,
                    strategy,
                    generation,
                )
                .pop()
                .ok_or_else(|| anyhow!("no test result"))?
        }

        fn hints(&self) -> Vec<((u32, u32), OwnerHint)> {
            self.resolver
                .fast_owners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entries
                .iter()
                .map(|(key, hint)| (*key, *hint))
                .collect()
        }
    }

    #[test]
    fn hints_have_global_capacity_inactivity_ttl_and_generation_invalidation()
    -> Result<(), Box<dyn Error>> {
        let now = Instant::now();
        let mut cache = OwnerCache::default();
        cache.prepare(1, now);
        for process_id in 1..=257 {
            cache.insert(
                1_000,
                OwnerHint {
                    process_id,
                    anchor_tid: process_id,
                    anchor_start: 5,
                    last_verified_at: now,
                },
            );
        }
        assert_eq!(cache.entries.len(), MAX_OWNER_HINTS);
        cache.prepare(
            1,
            (now + OWNER_HINT_TTL)
                .checked_sub(Duration::from_millis(1))
                .ok_or("cannot represent a live hint instant")?,
        );
        assert_eq!(cache.entries.len(), MAX_OWNER_HINTS);
        cache.prepare(1, now + OWNER_HINT_TTL);
        assert!(cache.entries.is_empty());
        cache.insert(
            1_000,
            OwnerHint {
                process_id: 1,
                anchor_tid: 1,
                anchor_start: 5,
                last_verified_at: now,
            },
        );
        cache.prepare(2, now);
        assert!(cache.entries.is_empty());
        Ok(())
    }

    #[test]
    fn new_tcp_and_udp_inodes_hit_recent_process_hints_without_reusing_identity()
    -> Result<(), Box<dyn Error>> {
        for protocol in [TransportProtocol::Tcp, TransportProtocol::Udp] {
            let fixture = Fixture::new(protocol)?;
            fixture.resolve(EnforcementStrategy::Fast, 1)?;
            let seeded_at = Instant::now()
                .checked_sub(Duration::from_secs(60))
                .ok_or("cannot represent an old Fast hint")?;
            fixture
                .resolver
                .fast_owners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entries
                .values_mut()
                .for_each(|hint| hint.last_verified_at = seeded_at);
            fixture.table(88)?;
            fs::remove_file(fixture.owner.join("fd/3"))?;
            symlink("socket:[88]", fixture.owner.join("fd/9"))?;
            let requests = [(&fixture.connection, IdentityCaptureRequirements::full())];
            let hits = fixture.resolver.resolve_fast_candidates(
                &requests,
                Instant::now() + PROC_SCAN_DEADLINE,
                &fixture.hints(),
            )?;
            assert_eq!(hits[0].as_ref().map(|identity| identity.pid), Some(100));
            fixture.resolve(EnforcementStrategy::Fast, 1)?;
            assert!(fixture.hints()[0].1.last_verified_at > seeded_at);
        }
        Ok(())
    }

    #[test]
    fn fast_refreshes_executable_arguments_and_cgroup() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new(TransportProtocol::Udp)?;
        let before = fixture.resolve(EnforcementStrategy::Fast, 1)?;
        fs::write(fixture.owner.join("cmdline"), b"different\0--changed\0")?;
        fs::write(fixture.owner.join("cgroup"), b"0::/moved\n")?;
        let replacement = fixture.root.path().join("different-executable");
        fs::write(&replacement, b"different program")?;
        fs::remove_file(fixture.owner.join("exe"))?;
        symlink(&replacement, fixture.owner.join("exe"))?;
        let after = fixture.resolve(EnforcementStrategy::Fast, 1)?;
        assert_ne!(before.executable, after.executable);
        assert_ne!(before.executable_file, after.executable_file);
        assert_ne!(before.command_line, after.command_line);
        assert_ne!(before.cgroups, after.cgroups);
        Ok(())
    }

    #[test]
    fn pid_reuse_invalidates_hint_before_strict_fallback() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new(TransportProtocol::Udp)?;
        let old = fixture.resolve(EnforcementStrategy::Fast, 1)?;
        let stat = fs::read_to_string(fixture.owner.join("stat"))?.replace("987654", "987655");
        fs::write(fixture.owner.join("stat"), stat)?;
        let candidates = fixture.resolver.resolve_fast_candidates(
            &[(&fixture.connection, IdentityCaptureRequirements::full())],
            Instant::now() + PROC_SCAN_DEADLINE,
            &fixture.hints(),
        )?;
        assert!(candidates.iter().all(Option::is_none));
        let fresh = fixture.resolve(EnforcementStrategy::Fast, 1)?;
        assert_ne!(fresh.process_start_time_ticks, old.process_start_time_ticks);
        assert_eq!(
            fixture.hints()[0].1.anchor_start,
            fresh.process_start_time_ticks
        );
        Ok(())
    }

    #[test]
    fn one_disappeared_hint_does_not_poison_an_unrelated_live_fast_owner()
    -> Result<(), Box<dyn Error>> {
        for protocol in [TransportProtocol::Tcp, TransportProtocol::Udp] {
            let fixture = Fixture::new(protocol)?;
            fixture.resolve(EnforcementStrategy::Fast, 1)?;
            fixture
                .resolver
                .fast_owners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(
                    1_000,
                    OwnerHint {
                        process_id: 200,
                        anchor_tid: 200,
                        anchor_start: 123,
                        last_verified_at: Instant::now(),
                    },
                );

            let candidates = fixture.resolver.resolve_fast_candidates(
                &[(&fixture.connection, IdentityCaptureRequirements::full())],
                Instant::now() + PROC_SCAN_DEADLINE,
                &fixture.hints(),
            )?;

            assert_eq!(
                candidates[0].as_ref().map(|identity| identity.pid),
                Some(100)
            );
            assert_eq!(fixture.hints().len(), 2);
        }
        Ok(())
    }

    #[test]
    fn ordinary_fast_miss_retains_unrelated_live_hints() -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new(TransportProtocol::Udp)?;
        fixture.resolve(EnforcementStrategy::Fast, 1)?;
        let missing = OutboundConnection {
            source_port: Some(12_346),
            ..fixture.connection.clone()
        };
        write_udp_socket_table(
            fixture.root.path(),
            &[(12_345, 54_321, 1_000, 77), (12_346, 54_321, 1_000, 88)],
        )?;

        assert!(
            fixture.resolver.resolve_batch_with_strategy_until(
                &[(&missing, IdentityCaptureRequirements::full())],
                Instant::now() + PROC_SCAN_DEADLINE,
                EnforcementStrategy::Fast,
                1,
            )[0]
            .is_err()
        );
        assert_eq!(fixture.hints().len(), 1);
        assert!(fixture.resolve(EnforcementStrategy::Fast, 1).is_ok());
        Ok(())
    }

    #[test]
    fn fd_reuse_missing_socket_and_expired_deadline_never_use_old_allow()
    -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new(TransportProtocol::Udp)?;
        fixture.resolve(EnforcementStrategy::Fast, 1)?;
        fs::remove_file(fixture.owner.join("fd/3"))?;
        symlink("socket:[99]", fixture.owner.join("fd/3"))?;
        assert!(fixture.resolve(EnforcementStrategy::Fast, 1).is_err());
        fixture.table(0)?;
        assert!(fixture.resolve(EnforcementStrategy::Fast, 1).is_err());
        let expired = fixture.resolver.resolve_batch_with_strategy_until(
            &[(&fixture.connection, IdentityCaptureRequirements::full())],
            Instant::now(),
            EnforcementStrategy::Fast,
            1,
        );
        assert!(expired.into_iter().all(|identity| identity.is_err()));
        Ok(())
    }

    #[test]
    fn strict_clears_hints_and_learning_warms_the_next_fast_generation()
    -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new(TransportProtocol::Udp)?;
        fixture.resolve(EnforcementStrategy::Fast, 1)?;
        assert_eq!(fixture.hints().len(), 1);
        fixture.resolve(EnforcementStrategy::Strict, 1)?;
        assert!(fixture.hints().is_empty());
        fixture
            .resolver
            .resolve_batch_for_learning(
                &[(&fixture.connection, IdentityCaptureRequirements::full())],
                1,
            )
            .into_iter()
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(fixture.hints().len(), 1);
        let enforcing_resolver = ProcfsResolver::at_with_fast_owners(
            fixture.root.path(),
            Arc::clone(&fixture.resolver.fast_owners),
        );
        enforcing_resolver
            .resolve_batch_with_strategy_until(
                &[(&fixture.connection, IdentityCaptureRequirements::full())],
                Instant::now() + PROC_SCAN_DEADLINE,
                EnforcementStrategy::Fast,
                2,
            )
            .into_iter()
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(fixture.hints().len(), 1);
        Ok(())
    }

    #[test]
    fn known_shared_owner_is_rejected_but_uncached_sharing_is_the_explicit_fast_tradeoff()
    -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new(TransportProtocol::Udp)?;
        fixture.resolve(EnforcementStrategy::Fast, 1)?;
        let other = create_task_fixture(fixture.root.path(), 200, 200, 1_000)?;
        complete_identity_fixture(&other, 200)?;
        symlink("socket:[77]", other.join("fd/3"))?;
        // This is intentionally NOT the Strict guarantee: the uncached holder
        // cannot be discovered by a hinted-only scan. Keep the tradeoff tested.
        assert!(fixture.resolve(EnforcementStrategy::Fast, 1).is_ok());
        fixture
            .resolver
            .fast_owners
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                1_000,
                OwnerHint {
                    process_id: 200,
                    anchor_tid: 200,
                    anchor_start: 987_654,
                    last_verified_at: Instant::now(),
                },
            );
        assert!(fixture.resolve(EnforcementStrategy::Fast, 1).is_err());
        assert!(fixture.resolve(EnforcementStrategy::Strict, 1).is_err());
        assert!(fixture.hints().is_empty());
        // A generation switch also forces exhaustive discovery rather than
        // continuing to trust the earlier Fast search scope.
        assert!(fixture.resolve(EnforcementStrategy::Fast, 2).is_err());
        Ok(())
    }

    #[test]
    fn partial_fast_capture_cannot_survive_strict_detection_of_a_shared_socket()
    -> Result<(), Box<dyn Error>> {
        let fixture = Fixture::new(TransportProtocol::Udp)?;
        fixture.resolve(EnforcementStrategy::Fast, 1)?;
        let other = create_task_fixture(fixture.root.path(), 200, 200, 1_000)?;
        complete_identity_fixture(&other, 200)?;
        symlink("socket:[77]", other.join("fd/3"))?;
        fs::remove_file(fixture.owner.join("cmdline"))?;
        let requests = [
            (&fixture.connection, IdentityCaptureRequirements::minimal()),
            (&fixture.connection, IdentityCaptureRequirements::full()),
        ];
        let tentative = fixture.resolver.resolve_fast_candidates(
            &requests,
            Instant::now() + PROC_SCAN_DEADLINE,
            &fixture.hints(),
        )?;
        assert!(tentative[0].is_some());
        assert!(tentative[1].is_none());
        let resolved = fixture.resolver.resolve_batch_with_strategy_until(
            &requests,
            Instant::now() + PROC_SCAN_DEADLINE,
            EnforcementStrategy::Fast,
            1,
        );
        assert!(resolved.iter().all(Result::is_err));
        assert!(fixture.hints().is_empty());
        let follow_up = fixture.resolver.resolve_batch_with_strategy_until(
            &[(&fixture.connection, IdentityCaptureRequirements::minimal())],
            Instant::now() + PROC_SCAN_DEADLINE,
            EnforcementStrategy::Fast,
            1,
        );
        assert_eq!(follow_up.len(), 1);
        assert!(follow_up.iter().all(Result::is_err));
        assert!(fixture.hints().is_empty());
        Ok(())
    }

    #[test]
    fn mixed_strict_batch_cannot_seed_a_hint_through_another_socket_of_the_same_tgid()
    -> Result<(), Box<dyn Error>> {
        for protocol in [TransportProtocol::Tcp, TransportProtocol::Udp] {
            let fixture = Fixture::new(protocol)?;
            symlink("socket:[88]", fixture.owner.join("fd/9"))?;
            let other = create_task_fixture(fixture.root.path(), 200, 200, 1_000)?;
            complete_identity_fixture(&other, 200)?;
            symlink("socket:[88]", other.join("fd/3"))?;
            write_udp_socket_table(
                fixture.root.path(),
                &[(12_345, 54_321, 1_000, 77), (12_346, 54_321, 1_000, 88)],
            )?;
            if protocol == TransportProtocol::Tcp {
                fs::copy(
                    fixture.root.path().join("self/net/udp"),
                    fixture.root.path().join("self/net/tcp"),
                )?;
            }
            let shared_connection = OutboundConnection {
                source_port: Some(12_346),
                ..fixture.connection.clone()
            };
            let requests = [
                (&fixture.connection, IdentityCaptureRequirements::full()),
                (&shared_connection, IdentityCaptureRequirements::full()),
            ];
            let resolved = fixture.resolver.resolve_batch_with_strategy_until(
                &requests,
                Instant::now() + PROC_SCAN_DEADLINE,
                EnforcementStrategy::Fast,
                1,
            );
            assert_eq!(resolved.len(), 2);
            assert!(resolved[0].is_ok());
            assert!(resolved[1].is_err());
            assert!(fixture.hints().is_empty());
            // Caching PID 100 through its unique socket would hide PID 200
            // from the next reduced-scope search for their shared socket.
            let follow_up = fixture.resolver.resolve_batch_with_strategy_until(
                &[(&shared_connection, IdentityCaptureRequirements::full())],
                Instant::now() + PROC_SCAN_DEADLINE,
                EnforcementStrategy::Fast,
                1,
            );
            assert_eq!(follow_up.len(), 1);
            assert!(follow_up.iter().all(Result::is_err));
            assert!(fixture.hints().is_empty());
        }
        Ok(())
    }

    #[test]
    fn expiration_and_generation_switch_force_exhaustive_shared_owner_detection()
    -> Result<(), Box<dyn Error>> {
        for expire in [false, true] {
            let fixture = Fixture::new(TransportProtocol::Udp)?;
            fixture.resolve(EnforcementStrategy::Fast, 1)?;
            let other = create_task_fixture(fixture.root.path(), 200, 200, 1_000)?;
            complete_identity_fixture(&other, 200)?;
            symlink("socket:[77]", other.join("fd/3"))?;
            assert!(fixture.resolve(EnforcementStrategy::Fast, 1).is_ok());
            if expire {
                for hint in fixture
                    .resolver
                    .fast_owners
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .entries
                    .values_mut()
                {
                    hint.last_verified_at = Instant::now()
                        .checked_sub(OWNER_HINT_TTL)
                        .ok_or("cannot represent an expired hint")?;
                }
            }
            assert!(
                fixture
                    .resolve(EnforcementStrategy::Fast, if expire { 1 } else { 2 })
                    .is_err()
            );
            assert!(fixture.hints().is_empty());
        }
        Ok(())
    }

    #[test]
    fn policy_strategy_is_explicit_and_defaults_to_strict() {
        let policy = ApplicationDecisionPolicy::new(openshield_core::State::new().snapshot());
        assert_eq!(policy.enforcement_strategy(), EnforcementStrategy::Strict);
        assert_eq!(
            policy
                .with_enforcement_strategy(EnforcementStrategy::Fast)
                .enforcement_strategy(),
            EnforcementStrategy::Fast
        );
    }
}
