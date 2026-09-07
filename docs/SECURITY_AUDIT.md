[English](SECURITY_AUDIT.md) | [Русский](SECURITY_AUDIT.ru.md)

# Security audit status

Review snapshot: 2026-09-05, OpenShield 0.2.1 source tree, Rust stable 1.98.0.
Exact evidence collected for earlier versions below remains labelled with the
version that was measured and is not silently relabelled as v0.2.1 evidence.

This document records the controls found in the current tree, the evidence that
has actually been collected, and the remaining security boundaries. It is not a
formal certification and does not claim that the software is free of defects.
The normative boundary is defined by the
[threat model](THREAT_MODEL.md) and [architecture](ARCHITECTURE.md).

## Implemented controls

### Local authorization and bounded IPC

- Policy mutation is available only through `/run/openshield/control.sock`.
  The socket is owned by UID 0 with mode `0600`; its group does not participate
  in authorization. The daemon additionally requires Linux `SO_PEERCRED` UID 0.
  Filesystem permissions are therefore not the sole authorization check.
- Read-only observation uses `/run/openshield/observe.sock`, owned by
  `root:openshield` with mode `0660`. The daemon accepts root, a peer whose
  primary GID is `openshield`, or a peer whose bounded, stable procfs credential
  check confirms supplementary membership. Credentials must remain consistent
  with `SO_PEERCRED`. Monitoring is not available to an arbitrary local user.
- A non-root observer receives a redacted snapshot: application selectors and
  identifying application-rule names are replaced before serialization.
  Network rules, endpoints, events, mode, and aggregate counters remain visible
  to authorized group members.
- IPC messages are strictly typed and reject unknown fields. Frames, clients,
  worker queues, subscriptions, event queues, pagination, reads, writes, and
  per-UID work rates are bounded. Slow or malformed observers are disconnected
  without blocking the policy engine.
- Every privileged mutation includes an expected revision. A stale request is
  rejected before state, backend, or event side effects. A lost reply is treated
  by the TUI as an unconfirmed outcome followed by a snapshot refresh, not as a
  safe invitation to repeat the mutation.
- The TUI reports policy mode, the daemon-selected typed backend, and the
  dynamically recomputed `StatusV2` active policy path separately from
  telemetry health. This is a policy classification, not kernel-capability
  attestation or fallback negotiation. Missing legacy data is displayed as `Unknown`. A live
  read-only quarantine is shown as the distinct red `EmergencyBlockAll`, not as
  a healthy operator-selected `BlockAll`. Its outbound
  cgroup/executable/destination grouping is presentation only: individual rules
  retain all selectors, selection follows stable UUIDs, and edit, delete, or
  enable actions cannot implicitly target a whole group. Inbound rules have a
  separate view and cannot carry application selectors.

### Policy construction and firewall backends

- Workspace code forbids unsafe Rust. Policy data cannot select a shell command,
  plugin, downloaded policy, eBPF object, or executable to run. An application
  path is a bounded identity selector only.
- Backend selection is deterministic. A trusted nftables executable is preferred
  only after a read-only preflight checks previous xtables state, table ownership,
  every bounded JSON query required by runtime observation, and a representative
  policy through the kernel's check-only transaction. The daemon selects the
  iptables/ip6tables compatibility backend if that preflight fails, and fails
  startup if neither complete backend is safe to use.
- Backend programs are selected from fixed absolute allowlists and must be
  root-owned, safely permissioned, regular executable files. Commands run with a
  cleared environment, fixed working directory, bounded input/output, and
  deadlines.
- The nftables compiler emits validated syntax and checks it before an atomic
  transaction. It owns only `table inet openshield` and verifies its ownership
  sentinel before replacement.
- The v0.1.32 nftables runtime observer invokes one fixed `nft` process for its
  table, chain, and counter queries and requires exactly three ordered bounded
  JSON documents. This preserves the one-second cadence, owned-table and base-
  chain/default-drop/counter invariants, and fail-closed repair while avoiding
  two additional process launches. It does not use a shell or broaden the
  executable or argument trust boundary.
- The compatibility compiler emits complete IPv4 and IPv6 restore programs. It
  uses `--noflush`, owns only `OPENSHIELD_*` chains, verifies ownership and full
  installed rule bodies, and keeps its dispatch jumps first in the relevant
  built-in chains. It refuses ambiguous coexistence with old OpenShield
  artifacts in nftables or another xtables implementation.
- Alternate xtables worlds are inspected with one bounded `*-save -c` snapshot
  and no `-t` selector, so legacy userspace enumerates only already loaded
  tables and cannot request module autoload during inspection. The combined
  output has strict table framing; only `filter` and `mangle` are examined for
  owned artifacts. An unavailable legacy protocol is accepted as empty only
  for its exact bounded diagnostic and empty stdout. Unexpected diagnostics,
  permission failures, timeouts, malformed or oversized output, and every
  other error remain fail-closed.
- xtables has no transaction that spans IPv4 and IPv6. OpenShield therefore
  validates both programs and puts both families into `BlockAll` before applying
  either requested policy. Failure can cause temporary denial but must not
  create a cross-family authorization window; verification failure triggers an
  emergency `BlockAll` attempt.
- New local inbound service traffic is default-deny and requires an explicit
  enabled inbound allow. Exact normal-mode DHCP bootstrap and essential IPv6
  control traffic are built-in; `BlockAll` contains no exception. Outbound behavior follows the selected mode. `BlockAll` also
  drops forwarded traffic; `Learning` and `Enforcing` return forwarded traffic
  to the pre-existing firewall policy instead of granting it or managing
  forwarding rules.
- Independent packet-consumer threads own fail-closed NFQUEUE 1337 (Enforcing
  and Learning application-deny candidates) and observational Learning NFQUEUE
  1338. Queue 1338 delegates to a bounded asynchronous attribution worker.
  The first eligible TCP SYN or datagram of a recently unseen flow may await
  completion for at most 250 ms; at most 128 packets are pending, with a 5 ms
  reader poll and no synchronous procfs work on that reader. Repeats are accepted
  immediately. Expiry or full backlog retains the ordinary Learning allow
  policy, but pending verdicts require the same current mode/generation under
  the engine lock and no shutdown. Serial/generation tickets reject stale
  completions. A separate bounded worker persists successful Learning
  observations. Both outgoing queues are bounded by queue length, packet
  copy length, procfs work, and attribution time.
  Queue 1337 deliberately has no queue bypass:
  parse, ownership, identity, ambiguity, or queue-pressure failures deny the
  affected traffic. `Learning` allows unmatched traffic but retains enabled
  explicit network and application denies. Its observational queue uses
  backend-native bypass; ordinary parse, attribution, quota, or persistence
  pressure may lose an observation without turning ordinary Learning into a
  successful-attribution allow policy. A terminal
  queue-integrity or policy-engine failure
  still requests emergency `BlockAll` rather than continuing in an unknown
  state.
- A third reader owns fail-closed INPUT queue 1339 for eligible delayed
  UDP/ICMP echo replies. It returns only Drop or `NF_REPEAT`, never Accept.
  Its bounded readiness state waits for actual outgoing verdicts through the
  kernel sequence captured on admission, without requiring queue 1337 to become
  empty. Missing metadata or a different queue owner/runtime cannot release a
  reply. This scheduling state cannot authorize a flow. Current kernel rules and
  conntrack generation still decide delivery on every retry. At most 128 replies
  wait, for up to 2 seconds per attempt and three attempts per packet. The
  attempt bits preserve all unreserved packet-mark bits. Timeouts, policy
  changes, and exhaustion remain fail-closed; sustained load may still lose replies.
- In the iptables fallback, the reserved-mark sanitizer is the first mangle
  OUTPUT dispatcher and the separate Learning observer is the last. The daemon
  requires each exactly once. Pre-existing host marking, QoS, and policy-routing
  rules therefore run before queue 1338 can return `NF_ACCEPT`, bypass an absent
  listener, or accept on overflow.
- The reported active-path classification is derived conservatively from
  committed enabled rules. `KernelNative` is limited to `BlockAll` or application-free
  `Enforcing`; TCP-only application `Enforcing` is `ConntrackHybrid`; `Learning`
  and every enabled UDP/ICMP/ICMPv6/`Any` application path are `Nfqueue`.
  Network-only matches remain kernel-native at the lower levels. An unavailable
  NFQUEUE consumer does not select a weaker network-only policy: bootstrap
  `BlockAll` remains installed and startup fails.
- The only automatic startup backend fallback is from nftables to the complete
  iptables/ip6tables bundle when nftables cannot be validated. L3/L2/L1 are not
  successive fallback implementations for an unchanged policy.
- The engine rechecks mode and generation under its lock through verdict
  delivery and reinjection. nftables uses `NF_ACCEPT` followed by its later
  authorization base chain for fail-closed queue 1337; iptables uses `NF_REPEAT`
  with an authenticated `NFQA_MARK` handoff consumed by the first repeated
  OpenShield OUTPUT rule. Learning queue 1338 instead returns `NF_ACCEPT` from
  its late observation position.
  Verdict delivery is nonblocking, and a terminal send error requests emergency
  `BlockAll` instead of indefinitely retaining the policy lock.

### Application identity and learning

- An outbound persisted application selector requires a canonical absolute
  executable path plus its complete file-version tuple: device, inode, size,
  and ctime seconds and nanoseconds. Optional filesystem UID, tokenized exact or
  prefix argv, cgroup path, and all network fields are combined with logical AND.
  The selected path is never executed.
- For a manual create/update, the daemon resolves the path in its own mount
  namespace, performs repeated canonicalization and read-only regular-file opens
  with `O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`, and requires the canonical path and all
  five version fields to remain stable. It fills an omitted pin and rejects a
  stale supplied pin. Older two-field persisted application identities are
  rejected rather than silently repinned; network-only state is unaffected.
- Attribution maps the queued packet tuple and kernel UID to one socket inode
  and one stable process identity. Every attribution attempt that reaches owner
  resolution receives a fresh bounded enumeration of external PID/TID entries;
  no userspace cross-packet identity or authorization-result cache was introduced.
  It scans bounded fd tables only for tasks whose filesystem UID equals the
  kernel socket UID, groups matching holders by TGID, and rechecks process start
  time, executable path and full file version, argv, cgroup, UID, and socket
  ownership. The daemon's shared fd table is checked immediately before the
  external scan and again after that scan completes instead of once per self
  task; a target socket or failed check is denied and the daemon is never accepted
  as the application owner. Within one scan, a descriptor number found for one task is
  tried first for later matching-UID tasks. Only an exact target link plus a
  repeated UID check is accepted; every mismatch or read error falls back to a
  complete bounded scan, and the hint is not retained across packets. The owner
  scan's exact fd path is
  revalidated before identity capture, falls back to a bounded rescan of that same
  task if stale, and is rechecked after capture. The absence of a matching-UID
  holder, multiple matching TGIDs, an incomplete scan, an unstable identity, or
  exhausted bounds fails attribution. This denies in Enforcing; in Learning it
  suppresses persistence while the outbound packet remains allowed.
- Since v0.1.32 attribution batches contain at most 32 already-ready items
  without waiting to fill a batch. Each packet still performs its own
  `SOCK_DIAG` lookup. The optimization shares two complete bounded procfs
  owner snapshots, one before and one after identity capture, including a
  single-item batch. The absolute operation deadline is 2 seconds for queue
  1337 and 5 seconds for asynchronous Learning; individual `SOCK_DIAG` queries
  remain capped at 250 ms within that deadline. Each snapshot has a global cap of 131,072 owner records
  across all targets. Within a batch, metadata is read once per exact TGID/TID,
  task path, socket UID, and capture requirements. Every socket FD is checked
  before and after that read; all owning tasks must agree. Per-socket results
  remain keyed by inode, UID, and requirements and are discarded with the batch.
  Duplicate requests must reach consensus on PID, process
  start time, executable path and complete file version, and filesystem UID.
  The typed attribution-timeout marker is preserved into NFQUEUE accounting.
  A changed snapshot, inconsistent identity, timeout, ambiguity, or exceeded
  bound denies the affected packet in Enforcing and only suppresses observation
  persistence in Learning. No identity or authorization result survives
  into the next batch, so otherwise-unmatched UDP/ICMP remains repeatedly
  attributed.
- Full fd scans use pinned, rewound directories and safe `RawDir`/`readlinkat_raw`
  with reusable bounded buffers, avoiding full-path allocation for negative fd
  entries. Truncated links cannot satisfy the socket-inode parser. Scan-local
  descriptor hints skip a full walk only after every target inode for that UID
  is revalidated; fallback preserves a verified preferred descriptor for sockets
  with duplicate fds. Both complete owner snapshots, thread/UID checks,
  executable pins, race revalidation, and all work bounds remain mandatory.
  This adds no PID authorization cache, eBPF tier, kernel module, `CAP_BPF`, or
  MOK/boot configuration requirement. Selector-mismatch diagnostics report
  bounded field categories/counts rather than argv, executable paths, or cgroups.
- Owner snapshots may use two fd-scanning workers only at 64 or more external
  tasks, multiple TGIDs, and two available CPUs. The caller and one scoped helper
  scan whole TGIDs distributed by task count. Complete PID/TID enumeration
  keeps one global task bound; a shared positive-owner accumulator keeps one
  record cap and cross-worker ambiguity checks. Both workers share the existing
  deadline, every helper is joined, and sorted owner sets retain exact before/
  after equality. Small or single-TGID scans remain serial. Worker failures deny
  attribution; parallelism does not reduce proof requirements or worst-case work.
  Learning's 250 ms first-observation deadline and 5 ms poll are not hard
  real-time guarantees under scheduler or policy-lock contention.
- On cgroup v2, exactly one unified `0::/path` entry supplies the cgroup
  identity. On a v1-only host, bounded controller memberships are validated but
  no cgroup identity is returned. Executable path, full file version, filesystem
  UID, and argv attribution still work; an explicit cgroup-path selector fails
  closed.
- Authorized established TCP traffic is tied to the current nonzero policy
  generation. Policy-invalidating changes, including enabling or creating a
  deny, increment that generation by one. UDP and ICMP
  are attributed per otherwise-unmatched outbound packet; successful attribution
  refreshes the current generation for its reply, while unsolicited inbound
  traffic still needs an explicit allow.
- Native rejection replies are admitted through local default-deny only for
  the exact RELATED/REPLY TCP RST, IPv4 ICMP destination-unreachable /
  port-unreachable, or IPv6 ICMPv6 destination-unreachable / port-unreachable
  shape, and only with the current nonzero 30-bit rejection generation attested
  in OpenShield's low-31 connmark domain with the accept-domain bit clear.
  Policy-generation changes invalidate stale attestations; all other RELATED
  traffic follows the ordinary policy.
- Before a broader network accept, application envelopes drop matching
  UNTRACKED current tuples that cannot enter attribution. Destination- or
  port-constrained envelopes additionally drop a matching conntrack-original
  destination/port while retaining the final output-interface constraint. This
  closes a local-DNAT bypass conservatively and may deny a translated flow
  rather than attribute a rule written for the pre-translation endpoint.
- Rule activation and verdict are independent. An outbound rule may be disabled
  or enabled and, when enabled in either normal mode, may `accept`, silently
  `drop`, or natively `reject`; overlapping rules use deterministic deny-before-allow
  precedence. Inbound rules remain accept-only and inbound service traffic
  remains default-deny outside the exact built-in normal-mode control set.
- `Learning` allows unmatched locally originated outbound traffic while enabled
  explicit denies remain active. Successfully attributed observations create enabled `accept` rules with exact
  application/protocol/endpoint/interface selectors. For every new
  cgroup/executable-path grouping identity it also creates one disabled
  `accept` template containing only that cgroup and path. The template is inert
  and deliberately unpinned while disabled. A privileged enable reopens and
  validates the executable, adds its complete file-version pin atomically with
  the policy update, and thereby grants that application broad outbound access;
  an absent or changed path rejects the enable instead of weakening identity.
  Disabling an unchanged Template restores its canonical unpinned skeleton and
  every later enable repins the then-current executable. An edited non-skeleton
  Template and disabled Manual or Learned rules retain their complete
  specification and pin. A bounded learning queue, batch-size limit, and
  deduplication cap bound the work. Automatic insertion stops when
  exact learned rules plus templates reach 7,500 globally, or exact learned
  rules reach configured quotas: by default 4,096 per filesystem UID or 1,024
  per pair of filesystem UID and complete executable file version. Disabled
  learned rules and older executable versions remain charged to their UID. These are
  admission budgets, not validation invariants for legacy or root-edited state;
  distinct subordinate UIDs count separately. The total limit remains 10,000
  rules, normally reserving 2,500 count slots for privileged manual rules; the
  independent 8 MiB semantic-state limit also applies. Unsupported protocols do not become broad
  `Any` rules. A revision-checked immutable index classifies each successfully
  attributed observation before queue admission. Exact-known, saturated, and
  persistence-paused observations keep the current Learning allow without
  entering the queue; only a potential new candidate consumes a slot, and the
  worker coalesces exact duplicates in each bounded drain. A policy/cache mismatch,
  full queue, disconnected learning worker, or attribution failure suppresses
  persistence but does not block an ordinary Learning packet. A transition out
  of Learning denies an in-flight stale decision; a Learning-to-Learning
  generation change retains its already-permissive Accept verdict but may
  discard the stale observation. At a learning quota,
  no permit is persisted for Enforcing. Preparation, persistence reservation,
  and the pending admission index run under the engine mutex; atomic save and
  `fsync` do not. Exact pending endpoints are deduplicated, and state/events are
  published only after durable commit. Concurrent privileged controls return
  `Conflict`, except root `BlockAll`, which installs the kernel deny immediately
  and is serialized last. Recoverable failure retains the previous state and
  pauses persistence; unsafe outcomes enter fail-closed quarantine.

### State, startup, shutdown, and packaging

- State storage is bounded and root-owned, rejects links and unsafe metadata,
  and uses a same-directory temporary file, `fsync`, and atomic rename.
  A coordinator prevents an older learning write from overwriting newer control
  state. Ambiguous persistence or rollback outcomes escalate to kernel
  `BlockAll` or a read-only recovery state.
- A direct daemon start acquires a root-owned singleton lock, discovers a
  trusted backend, and installs bootstrap `BlockAll` before inspecting state or
  constructing the fallible runtime. If no state exists, the first requested
  state persisted by the daemon is `Learning`. The bootstrap policy is
  temporary and does not overwrite that requested mode.
- Startup increments the persisted nonzero 30-bit policy generation by exactly
  one before the requested policy is activated. Values are not reused before
  exhaustion; exhaustion retains `BlockAll` and fails startup rather than
  wrapping. While bootstrap `BlockAll` remains active, the first v0.2.1 start
  over v0.2.0 state adds missing canonical disabled templates for existing
  Learned application groups. The additive migration respects automatic-rule,
  total-rule, and 8 MiB limits and never removes endpoint rules when no room
  remains; it is persisted before policy activation. Readiness is announced
  only after the policy, both fixed NFQUEUE consumers, and verified IPC sockets
  are active.
- Graceful daemon shutdown and packaged post-stop hooks reinstall kernel
  `BlockAll` without replacing the saved requested mode.
- Service definitions are provided for systemd, OpenRC, SysVinit, runit, s6, and
  dinit. They install pre-start and post-stop quarantine around the supervised
  daemon. This ordering does not cover initramfs or packet paths that bypass the
  chosen init system.
- `packaging/stage-install.sh` stages into an existing package root and refuses
  `/`, `..`, lexical symlink components, foreign-owned objects,
  group/world-writable directories, and multiply linked regular files. Before
  every write it validates canonical ancestry as caller- or system-owned and
  safely permissioned, with the conventional system-owned sticky `/tmp`
  exception. Its probes stop at the first rejected object. It never enables or
  starts a service on the host.
- The systemd service retains `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_PTRACE`,
  and `CAP_DAC_READ_SEARCH`. It keeps `root` as the primary group and adds
  `openshield` as a supplementary group. The socket owner may assign that group
  to the observer socket without `CAP_CHOWN`, while `CAP_NET_RAW` is required for safe legacy xtables
  inspection and fallback operation; several process-memory syscalls remain
  denied. Non-recursive tmpfiles rules create and relabel the root-owned
  runtime/state directories and standard `0600` `/run/xtables.lock`; the unit
  requires tmpfiles setup and makes only those exact paths, rather than all of
  `/run` or `/var/lib`, writable. This preserves serialization with other
  xtables processes without recursively changing saved state. The unit reduces
  attack surface but is not a sandbox against a compromised daemon.
  `ProcSubset=all` with `ReadOnlyPaths=/proc` is required for the nested
  `/proc/self/net/netfilter/nfnetlink_queue` progress record. `ProcSubset=pid`
  hides that entry even when `/proc/self/net/tcp` is readable. This change
  expands read visibility of general procfs metadata; it does not restore procfs
  writes or change network authorization. Queue ownership/configuration and
  progress readability are checked before worker startup and desired-policy
  activation. A failed check leaves bootstrap `BlockAll` in place.
  Previously recorded systemd exposure scores below are historical, not a new
  score for this revised procfs configuration.

## Verification evidence

The evidence layers below are intentionally separate. Passing one layer does not
establish the properties of another.

Evidence below remains tied to the explicitly named revision and execution
environment. The v0.1.32 source, component, local Tumbleweed x86-64 E2E, and
local performance evidence retained below does not predeclare a tag build
successful; release artifacts must still pass the configured Quality Gate,
package matrix, 74 firewall jobs, and performance gate in GitHub Actions. The recorded full
v0.1.31 performance run remains valid historical evidence, but failed its
relative-performance gate, so neither that run nor this document certifies a
v0.1.31 tag. Broader binary, packaging, cross-target, and Tumbleweed results
identified as v0.1.28 do not certify newly built 0.1.32 artifacts.

- Local v0.1.32 verification on Rust 1.98.0 passed
  `cargo fmt --all -- --check` and locked
  workspace all-target clippy with warnings denied. The complete Rust suite in
  a container passed 350 tests; the normal invocation ignored six live tests,
  and a separate live-test invocation passed all six. The Python performance
  harness suite passed 211 tests in an isolated Python 3.13 container; one
  identity-probe build test was intentionally skipped because that minimal
  image contains no C compiler. Coverage includes automatic-learning budgets, version pinning,
  fsuid-prefilter, immutable policy indexes, compatibility classification, and
  the performance-report confidence model. Daemon unit tests used mock backends
  and temporary Unix sockets and did not touch the host firewall. These are
  component results and remain distinct from the full performance-gate result
  below.
- The v0.2.1 release-version preparation resolved all four workspace crates and
  their exact internal dependency pins as `0.2.1`. In the pinned Rust 1.98.0
  container, the locked all-target suite passed 377 tests while the normal run
  ignored six environment-dependent tests; the separate ignored-test invocation
  passed all six. Formatting, all-target Clippy with warnings denied, and the
  x86-64 static-PIE musl release build passed, and both executables reported
  `0.2.1`. The performance-harness unit suite passed 219 tests with 11
  intentional environment-dependent skips. The release matrix validated 43
  binary builds, 43 packages, 86 declared platforms, 37 package-install jobs,
  and 74 firewall jobs. The locally container-built Tumbleweed x86-64 RPM,
  SHA-256 `fa638b0503447a7c85815a5a51d6add653330b92e2d5e05e854eb1dc1602d373`,
  passed metadata and installation validation followed by the complete nftables
  and iptables-fallback E2E in disposable containers. Those runs did not inspect
  or modify the host firewall. This is local source/build/runtime evidence; the
  v0.2.1 GitHub release workflow has not yet run.
- The final local v0.1.32 x86-64 Tumbleweed CI-smoke performance gate completed
  with `PASS` for both nftables and the iptables fallback. It used daemon SHA-256
  `d3b824e680baebb30e30f65e2fa010cd0643d3272a2f370bc0001ee727487c29` and
  configuration SHA-256
  `b52b3a390a25a6cc611fb91a2ecb1b9df2cebd1bbef86cf6615ba7144fd7ed43`.
  The independently recomputed result covered 36 comparison groups, 108
  order-balanced adjacent AB/BA pairs, and 276 metric-evidence records, with no
  blocking steady or burst regression. The worst steady mean reduction was
  0.407% for throughput and 0.527% for PPS against their 10% limits; minimum
  target attainment was 91.26%. Peak daemon CPU was 26.78% of one core, peak
  RSS was 7.66 MiB, and peak request p99 was 2.717 ms. The retained advisory
  evidence remains material: CPU/latency crossed the observation threshold in
  29 of 36 steady groups, with maxima of +150.44% cgroup CPU, +242.62% request
  p99, and +597.99% TCP-connect p99 relative to very small baselines. All four controlled NFQUEUE-overload
  proofs passed fail-closed and recovery checks; ordinary windows reported no
  NIC drops/errors, TCP retransmits, UDP loss, NFQUEUE drops/errors, attribution
  timeout, terminal queue error, or fail-open behavior. This local result
  validates the tested source snapshot and binary, not a future GitHub release
  artifact.
- For v0.1.28, `cargo-audit` checked the 152-dependency lock graph against 1,235
  advisories from the RustSec database revision dated 2026-09-01 and reported no
  applicable advisory. The offline cargo-deny advisories, bans, licenses, and
  sources checks passed; only the two explicitly allowed duplicate-version
  warnings for `hashbrown` and `syn` remained.
- Both v0.1.28 static-PIE musl binaries completed a no-network, read-only,
  capability-free `--version` smoke test in all 60 rows of
  `tests/compat/distros.tsv`. This establishes startup compatibility of those
  artifacts with the selected container userspaces, not firewall operation or
  certification of 60 distributions.
- For v0.1.28, `cargo check --workspace --all-targets --locked` completed for all 23 Linux
  targets whose standard libraries were available from stable Rust 1.98.0. The
  two recorded RISC-V 32 targets are Tier 3 and were skipped because stable
  rustup does not provide their standard libraries; a separately reviewed
  nightly `build-std` workflow would be required.
- Separate v0.1.28 Tumbleweed GNU binaries were linked and ELF-validated for x86_64,
  i586, AArch64, ppc64le, and s390x. The four non-host daemon/TUI pairs ran
  capability-free `--version` smokes under digest-pinned Cross QEMU images;
  i586 also ran in the pinned official Tumbleweed `linux/386` image. These are
  execution smokes, not hardware or firewall certification.
- For v0.1.28, static staging checks covered all six init layouts. Isolated container
  parser/supervisor fixtures passed for OpenRC, SysVinit, runit, s6, and dinit,
  including lifecycle quarantine and group creation. systemd is staged and
  analyzed separately rather than booted as PID 1 in that container matrix. The
  staged unit with target stubs passed `systemd-analyze verify`; offline
  `systemd-analyze security --offline=yes --threshold=100` passed with exposure
  2.7 (`OK`). Verification and the same 2.7 assessment were repeated with
  systemd installed inside the pinned Tumbleweed container.
  Alpine/BusyBox also executed the staging helper, and unsafe staging-tree
  fixtures, including symlink and writable-parent cases, were rejected. The
  full tmpfiles create/relabel declaration was applied twice in the pinned
  Tumbleweed container; exact root ownership/modes and idempotence passed. These
  are packaging/unit-fixture results, not a systemd boot or packet-filtering run.
- The TUI suite covers all 31 locale resources with the same complete message
  key set and verifies exact key, placeholder, and newline parity. No non-English value is
  exactly equal to its English counterpart. A second regression checks every
  unordered locale pair and, after excluding placeholders and common protocol
  or product identifiers, permits at most 24 nontrivial short exact matches and
  four substantive exact matches per pair. Twelve proposed resources with 29
  to 119 Russian copies were removed rather than presented as complete
  translations. A later forensic comparison also removed `os`, `inh`, `bua`,
  `xal`, `ady`, and `kjh` after finding large cross-language copied blocks. The
  TUI all-target clippy run with warnings denied and package formatting check
  also passed. These mechanical checks detect structural and bulk-copy errors;
  they are not linguistic certification or a substitute for native technical
  review.
- `tests/e2e/server-learning-enforcing.sh` defines separate disposable nftables
  and iptables workflows for observation authorization, Learning, application
  attribution, Enforcing, coexistence, inbound allow, shutdown quarantine, and
  restart. The current scenario separately requires a TCP-only L2
  `ConntrackHybrid` status and proves its established-flow fast path with a
  real persistent socket while the daemon is paused, before adding UDP and
  requiring the mixed policy to report L1 `Nfqueue`. The locally built v0.1.32
  daemon passed both backends in isolated openSUSE Tumbleweed x86-64
  containers. The
  successful scenarios printed:

  ```text
  PASS server Learning -> TCP L2 -> UDP/TCP L1 -> inbound allow -> restart (nftables)
  PASS server Learning -> TCP L2 -> UDP/TCP L1 -> inbound allow -> restart (iptables)
  ```

  The nftables run installed both frontends and selected nftables; the iptables
  run omitted `nft` and selected the fallback. These were local, isolated
  Docker network/container-namespace tests. They did not exercise or modify the
  host firewall and are not production certification.
- `tests/perf` and the release `performance` job define a bounded, isolated
  host-firewall load gate after all functional E2E jobs. The exact release
  daemon is compared with a no-daemon baseline for nftables and, when available,
  the iptables/ip6tables fallback, covering `Learning` and `Enforcing`,
  network-only rules, application TCP, and application UDP. Each exact group
  receives three predetermined independent pairs with unique pair and baseline
  sample identities. A baseline sample is single-use, both pair sides use
  separate pristine DUT generations, and order is balanced AB/BA. The protected
  block may use only its assigned immediately adjacent baseline. Both sides use
  identical offered parameters and a policy-independent deterministic trace
  seed, with conntrack flushed for every load point. The conservative comparison
  gap is the maximum separation across the authenticated workload interval and
  the synchronized DUT and peer metric intervals; its configured ceiling is 15
  seconds for CI and 90 seconds for the production-like profile. Each phase has a new
  client process; established TCP fast-path behavior is therefore demonstrated
  by multiple keep-alive operations inside that phase, not by carrying sockets
  between phases. The real `/var/lib/openshield` directory is stored in the
  container's writable overlay, exercises atomic rename and `fsync`, retains
  learned state for the backend topology, and is discarded at cleanup. Formal
  validity checks invalidate generator or peer/server
  saturation and propagate an invalid baseline to its pair. Every executed
  invalid result row fails the complete report. Separate capacity
  and safety checks cover target attainment, latency, loss/retransmits,
  daemon CPU/RSS, NIC and NFQUEUE errors, expected NFQUEUE path shape,
  wrong-executable probes, and verified `BlockAll` quarantine. Invalid points
  cannot become capacity maxima. Configuration, synchronized metric documents,
  and pairing evidence use `openshield.perf.config.v2`,
  `openshield.perf.metrics.v3`, and
  `openshield.perf.baseline-pairing.v2`, respectively. Daemon-observed queue failures use deltas of
  the typed, process-lifetime `status.data.nfqueue` counters as authoritative
  gate evidence; throttled log messages are retained only as diagnostic lower
  bounds. All per-window relative deltas and threshold crossings are retained.
  The CI observation thresholds remain 10%. Under the current v0.2.1
  field-evaluation policy, the authenticated criterion
  `cpu_latency_relative_regressions_are_advisory: true` assigns CPU and latency
  means to `observe`; throughput and PPS means retain the blocking `fail`
  action. The production-like profile sets the criterion to `false` and keeps
  all relative means blocking. A one-sided 95% Student-t lower confidence bound
  records stronger confirmation without changing that action. A single
  burst has no confidence claim, but throughput/PPS threshold crossings block
  directly and CPU/latency follows the profile action; absolute CPU/RSS and p99
  latency, burst validity, configured
  capacity bounds, and safety remain mandatory. Loss, retransmits, NIC or
  NFQUEUE drops/errors, and fail-open behavior are immediate failures rather
  than statistically aggregated relative decisions. The CI smoke has three short steady repetitions
  and is path/safety evidence, not a maximum-capacity result; the production
  profile also requires three longer repetitions. Softirq deltas are host-wide, include unrelated host
  work, and are meaningful only relative to the paired baseline on a quiet
  runner. A separate, non-capacity overload gate uses `SIGSTOP`/`SIGCONT` around
  the NFQUEUE consumer while real application TCP and UDP fill the bounded
  queue. It requires the configured minimum combined kernel/userspace NFQUEUE
  drops, an explicit pressure-client ready/start barrier, same-transport
  network-only liveness round trips around every wrong-executable probe, and no
  successful wrong-executable round trip during or after the stall. Generator,
  peer, or canary saturation and socket/NIC errors invalidate this evidence.
  Recovery must either be error-free in `Enforcing` or enter an independently
  verified kernel `BlockAll` quarantine. A reported quarantine also requires
  bracketed real TCP and UDP negative probes while out-of-band loopback round
  trips inside the canary container prove both peer servers healthy. This
  item describes the implemented gates; benchmark numbers are evidence only
  when the corresponding JSON report is retained.

  The final local v0.1.31 full x86-64 Tumbleweed run produced a structurally
  valid report but an overall `FAIL` performance result. Ordinary measurement
  windows had zero safety failures and zero authoritative NFQUEUE error-counter
  deltas. All four deliberate overload proofs (TCP and UDP on nftables and
  iptables) passed their fail-closed and recovery checks. Application-aware L2
  and L1 groups contained mean regressions above the unchanged 10% threshold,
  with one-sided 95% lower confidence bounds providing stronger confirmation.
  Two L3 groups also failed the repeated CPU gate in this run: nftables
  `ingress_http_mixed` and iptables `egress_tcp_mixed`, both with network-only
  `Enforcing` policy. Therefore the source-level safety evidence is useful,
  but the performance result does not certify publication of the v0.1.31 tag.
- The v0.1.18 procfs optimization was measured in the same SHA-256-pinned
  Tumbleweed container image with `--network none`, private PID/network
  namespaces, no privileged mode, and only the daemon's four packaged
  capabilities. At 20
  loopback UDP packets/s, the NFQUEUE worker fell from 6.3% CPU in v0.1.17 to
  1.1%. At 500 packets/s it fell from 36.2% to 11.3%. On the former saturation
  step, the v0.1.17 nftables worker used 100% of one core and the generator
  managed to send 39,096 loopback datagrams in 20 seconds. With v0.1.18 the
  generator sent, and the firewall counters reported as accepted, all 60,001
  scheduled datagrams; the NFQUEUE worker used 48.7% on nftables and 47.7% on
  the forced iptables fallback, with zero NFQUEUE drops. A five-second
  `strace -c` sample at the 500-packets/s step reduced from about 890 to 176
  syscalls per processed packet and from about 410 to 39 `readlink` calls per
  packet. These are controlled regression measurements on one host kernel, not
  a universal throughput claim.

Commands and exact interpretation are documented in
[the compatibility guide](../tests/compat/README.md).

## Residual findings and deliberate limits

- The dynamically selected L3/L2/L1 value classifies the active policy path; it
  is not a distribution-kernel capability level. `KernelNative` is the
  nftables/iptables policy path, not an eBPF application
  data plane or a claim about distribution kernel features. OpenShield 0.1.32 does
  not add `CAP_BPF`, a kernel module, a boot-parameter change, or MOK enrollment.
  Exact application identity still uses the audited NFQUEUE/procfs path. A
  future kernel application fast path requires independent rule-equivalence,
  lifecycle, packaging, Secure Boot, LSM, and native-kernel evidence.

### Deployment and availability

- Enabling a packaged service does not prove whole-boot enforcement. initramfs,
  early network consumers, custom service ordering, or network paths outside the
  declared init dependency can transmit before OpenShield is active.
- The staging helper trusts its caller not to modify the verified package tree
  concurrently. A malicious owner racing its own tree remains outside that
  helper's boundary; package builds should use a fresh private root with no
  concurrent writers.
- A fresh requested mode is `Learning`, but inbound traffic is still
  default-deny. On a remote server, first activation can cut off administration.
  Use a local console or tested out-of-band path, create and verify the inbound
  management allow first, and keep a recovery procedure ready before enabling
  the service.
- Learning is an operator-controlled trust window. Any successfully attributed
  local process can create exact application-and-endpoint rules plus disabled
  templates and consume its per-application or per-UID quota. Multiple
  UIDs/applications can still consume the 7,500 automatic-rule capacity or the
  independent 8 MiB state budget and
  pause further learning. Reaching the byte limit or a recoverable save failure
  discards the current batch and pauses automatic learning until a successful
  privileged mutation or daemon restart, while the active Learning traffic
  policy remains. The 2,500-slot manual count reserve does not reserve bytes.
  Learned rules require review before Enforcing.
  Since v0.2.5, root can configure the per-UID and per-UID/file-version quotas
  in optional `/etc/openshield/learning-limits.json`, within
  `1 <= per_application <= per_uid <= 7500`. The fixed path and its parents
  are checked for safe root ownership, permissions, and absence of symlinks
  after bootstrap `BlockAll`; invalid content or metadata fails startup.
  Packages do not overwrite this local configuration. `StatusV3` and TUI
  warnings make quota exhaustion visible without granting traffic or vetoing
  root's Enforcing request. Existing rules survive upgrades; observations
  previously missed at a quota must be repeated in Learning. Larger quotas do
  not remove the resource-exhaustion or incomplete-attribution risks.
- An authorized root operator can still fill the 10,000-rule total with manual
  mutations. Root is inside the administrative trust boundary, but this remains
  an operational availability limit.
- In `Enforcing`, procfs attribution and the active bounded NFQUEUE consumer can be
  forced into fail-closed denial by process, thread, fd, or queue pressure.
  This is a material availability/DoS risk, not a fail-open path. In
  `Learning`, the same pressure can lose observations and therefore leave the
  later `Enforcing` rule set incomplete, but unmatched traffic continues under
  the declared default allow. In particular, the
  one bounded directory walk inspects at most 4,096 fd entries for a task whose
  filesystem UID matches the socket UID and denies attribution if proof would
  require a later entry; global enumeration admits at most 131,072 proc/task
  entries.
  Unrelated-UID fd tables are skipped, but global process/task pressure and
  matching-UID fd pressure can still deny application attribution. The v0.1.18
  self-TGID and scan-local fd-hint optimizations reduce the common-case scan cost.
  Every completed owner snapshot still includes two shared self-table checks.
  The v0.1.32 micro-batch shares its before/after snapshots across at most 32
  already-ready packets, retains per-packet `SOCK_DIAG`, and applies one 2-second
  deadline to a queue-1337 batch (5 seconds for asynchronous Learning) plus a
  131,072-owner-record cap to each snapshot. Per-query `SOCK_DIAG` remains capped
  at 250 ms. Fixed-buffer, directory-relative reads reduce common-case overhead,
  not the worst-case scan size.
  Intra-batch metadata grouping is keyed by TGID/TID, task path, socket UID, and
  capture requirements. Per-socket FD checks, mandatory-identity consensus,
  and unchanged ownership remain required; nothing is
  cached across batches. These optimizations do not alter worst-case complexity. A
  sustained packet stream or hostile procfs cardinality can still saturate the
  active consumer and deny legitimate application-bound traffic in `Enforcing`.
  The
  immutable packet-policy cache removes the previous per-packet full-state clone
  and indexes enabled rules by complete executable file version. A lookup scans
  only the policy-ordered bucket for the observed version. Matching within that
  bucket remains linear, and a legacy or root-edited state can concentrate many
  rules under one pin regardless of the configurable per-UID/file-version
  automatic-insertion budget (1,024 by default), which is not a bound on a pin
  shared across UIDs.
  The Learning admission index prevents already-known, saturated, or paused
  observations from filling the persistence queue, but classification follows
  procfs attribution attempt. New eligible candidates can still fill the
  persistence queue and lose observations without changing Learning's allow
  verdict. Learning-only scheduling suppression can avoid duplicate work before
  attribution; candidates that reach attribution retain its procfs cost.
  Nonblocking verdict delivery prevents an indefinite policy-lock stall, but
  sustained netlink send pressure can request emergency `BlockAll`; this is an
  intentional fail-closed availability tradeoff.
- Forced termination, kernel failure, or power loss can bypass graceful
  post-stop code. Pre-start hooks and the early in-process bootstrap reduce, but
  cannot eliminate, that deployment boundary.

### Identity and privilege

- The bounded first-observation wait is not a historical process/socket event
  collector. A fire-and-forget UDP process may exit after `sendto()` before
  attribution, even while its packet is queued. Learning then allows ordinary
  traffic without a rule; stale PIDs or guessed identities are not substitutes.
  Request/response and one-way UDP coverage are reported separately by the
  [short-lived regression](../tests/compat/README.md#short-lived-application-regression).
- Procfs attribution is a repeated post-event consistency check, not an atomic
  kernel sender/exec record. An exec or descriptor transfer concurrent with
  packet processing can expose only the later observable identity. UDP
  `SO_REUSEPORT` and related ownership patterns have the same non-atomic
  boundary.
- Executable identity is path plus device, inode, size, and ctime seconds and
  nanoseconds. Ordinary in-place rewrites change size or ctime and stop matching,
  but the tuple is not a content digest or mount-namespace identity. Metadata
  reuse, privileged/raw-filesystem manipulation, namespace aliases,
  interpreters, injected libraries, plugins, and JIT code remain outside full
  code attestation.
- argv and cgroup are mutable metadata. On cgroup v1, application attribution
  remains available, but exact cgroup-path selectors cannot match.
- Stable shared, inherited, or `SCM_RIGHTS`-passed descriptors are denied when
  they create ambiguity among matching-UID TGIDs, but procfs fallback is not
  proof of which process performed the actual send. A cross-UID recipient is
  skipped before fd inspection; without an original matching-UID holder the
  decision fails closed, but with that holder still present the recipient is
  invisible and the original holder can be attributed. After an established TCP flow is authorized,
  identity is not recaptured for every packet; a later exec or fd transfer can
  retain the connection until reconnection or policy-generation change.
- `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` materially expand the impact of a
  daemon compromise. The syscall deny list does not prevent ordinary I/O to a
  successfully opened `/proc/pid/mem` or every traversal through procfs magic
  links.
- Application selectors can constrain `accept`, `drop`, or `reject` rules.
  Network-only denies take precedence; application candidates are attributed
  before an overlapping network-only accept fallback, and application actions
  are ordered `drop`, `reject`, then `accept`.

### Coexistence and protocol scope

- OpenShield reserves the upper two packet-mark bits and preserves the lower 30.
  It reserves the low 31 conntrack bits for application authorization and
  preserves bit 31. Other firewalls, VPNs, QoS, or CONNMARK users of the
  reserved bits can conflict. A privileged earlier mark writer or an
  asynchronous queue placed between OpenShield hooks can invalidate the
  reinjection assumptions.
- Other firewall rules may still drop traffic that OpenShield returns or
  accepts. Conversely, a privileged ruleset editor can bypass or damage
  OpenShield. Run no competing manager without reviewing hook order, marks, and
  chain ownership.
- nftables health checks validate owned table/base-chain metadata and counters,
  not the complete rule body. The iptables backend compares full owned rule
  bodies, but its first-position dispatch can be displaced by another
  privileged editor. Neither check is protection from UID 0 or `CAP_NET_ADMIN`.
  The v0.1.32 nftables observer obtains its table, chain, and counter documents
  from one fixed `nft` process, but preserves the same one-second cadence,
  ordered bounded parsing, validation set, and fail-closed repair behavior.
- The fixed backend executable is checked before it is later run by path. A
  privileged package update can replace it in that interval. This TOCTOU remains
  inside the trusted UID-0/package-manager boundary.
- iptables cannot update IPv4 and IPv6 atomically together. The deliberate
  cross-family `BlockAll` quarantine can temporarily deny valid traffic during a
  policy update.
- Authorized members of `openshield` can see sensitive network endpoints,
  events, rules, mode, and counters even though application identity fields are
  redacted for non-root. Group membership must be treated as a monitoring
  privilege. Authorization occurs when the Unix connection is accepted; an
  authorized process can relay that already-connected socket fd to another
  process, so group access is not a non-delegable confidentiality boundary.
- ICMP type/code selectors are not implemented, and application attribution
  supports only ICMP/ICMPv6 echo. Required ICMPv6 permits should be narrowed by
  network and interface.
- OpenShield filters host IPv4/IPv6 traffic. It is not an L2/ARP firewall and
  does not constrain a process that already has `CAP_NET_RAW` from direct
  `AF_PACKET` injection.

### Compatibility and localization

- State and IPC compatibility is forward-only from v0.2.0 to v0.2.1. The new
  reader treats an absent `action` as `accept`, but v0.2.0 cannot parse v0.2.1
  `drop`/`reject` actions or the `template` origin. Mixed daemon/TUI versions and
  an in-place downgrade after v0.2.1 has written state are unsupported. Upgrade
  and rollback require a protected console, active kernel `BlockAll`, a reviewed
  state backup, and a distribution-tested procedure.
- Static `--version` smoke tests share the host kernel and do not exercise libc
  integration, init boot, firewall tools, NFQUEUE, package upgrades, or real
  traffic. Archived and rolling images are probes, not supported-lifecycle
  guarantees.
- Cross-compilation checks do not establish runtime behavior on every x86, ARM,
  AArch64, or RISC-V machine. No claim of support for all architectures or every
  ABI is made.
- The 31 locale resources have mechanical schema coverage, but translations,
  especially for languages with limited technical-review resources, still need
  review by native technical speakers. No native technical review is recorded
  for the 11 additions. Six proposed cross-language fallback resources (`os`,
  `inh`, `bua`, `xal`, `ady`, and `kjh`) remain unsupported pending replacement
  and native review. The set is broad but not exhaustive.

If state persistence and emergency recovery both become ambiguous, OpenShield
keeps or attempts kernel `BlockAll` and enters a read-only recovery posture.
Only a local root operator with an independent console should repair or
deliberately replace the state before restart.
