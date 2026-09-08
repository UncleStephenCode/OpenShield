[English](THREAT_MODEL.md) | [Русский](THREAT_MODEL.ru.md)

# Threat model

## Security objectives

1. A non-root local user cannot change firewall mode or rules.
2. A malformed, slow, or flooding observer cannot stop enforcement or consume
   unbounded memory, threads, or event queues.
3. Policy input cannot select commands, plugins, or executable code. An
   application path is identity data only and is never executed.
4. Failed parsing, persistence, identity attribution, or firewall-backend updates
   preserve or strengthen the last known restrictive policy. The explicit
   exception is observational queue 1338 in `Learning`: it accepts ordinary
   unmatched traffic independently of attribution success, so a failed observation
   creates no rule. Its first-observation wait is bounded to 250 ms and pending
   verdicts require the same current Learning mode and generation.
   Enabled explicit denies still apply through the kernel or fail-closed queue 1337.
5. New inbound service traffic is denied unless an enabled inbound rule matches;
   only the exact built-in normal-mode DHCP/IPv6 control set is exempt.
6. In enforcing mode, new outbound traffic is denied unless all fields of an
   enabled outbound rule match, including its application selector when present.
7. In `Enforcing`, missing, ambiguous, stale, unsupported, or over-limit
   application identity information results in DROP, not a network-wide
   fallback allow.
8. A non-root observer cannot obtain executable paths, complete file-version
   identities, command arguments, UID or cgroup selectors, or identifying names of
   application-bound rules through the observation protocol.
9. `BlockAll` denies forwarded traffic. `Learning` and `Enforcing` delegate it
   to the existing firewall without accepting it or providing forwarding-rule
   CRUD.
10. Active-policy path reporting cannot turn an unverified or more expensive
    application path into a claimed kernel fast path. Missing legacy status data
    is `Unknown`, and an unavailable mandatory NFQUEUE runtime keeps `BlockAll`
    active and stops startup. A live read-only emergency quarantine is reported
    as `EmergencyBlockAll`, not as a healthy operator-selected `BlockAll`.

## Explicit Fast-strategy exception

Strict is the default. Root can explicitly select Fast in the Enforcing submenu
after acknowledging a weaker socket-owner discovery guarantee. Fast keeps one
process-wide cache of at most 256 positive UID/TGID/TID/start-time hints for
three minutes of inactivity. A successful exhaustive Strict attribution creates
a hint; a successful Fast capture renews only its freshly revalidated owner.
Each queued attribution request retains fresh socket resolution (`SOCK_DIAG`
for TCP/UDP, procfs for ICMP/ICMPv6), fd/UID/start-time/executable checks,
required argv/cgroup capture, and current rule/action/generation checks. Both
owner passes are limited to hinted TGIDs. Dead, replaced, expired, or unusable candidates are omitted;
ordinary misses retain unrelated live hints across the Strict fallback. A
fallback which actually detects ambiguous ownership clears the reduced scope.
There is no verdict cache, new queue bypass, or relaxation of kernel rules.

Fast has one additional, explicit policy exception: an automatic learned
`Accept` ignores its captured argv/cgroup when a later process has the same
canonical executable path, full executable-file identity, UID, and endpoint.
An attacker running that exact executable as that UID can therefore share its
learned endpoints across process instances. Strict avoids this exception.
Manual rules and all `Drop`/`Reject` rules never use it.

A previously uncached process sharing the same socket through inheritance,
`fork`, or `SCM_RIGHTS` can remain invisible to Fast, even for the same UID.
The three-minute inactivity TTL limits hint retention, not a guaranteed detection window;
a successful Strict lookup of another socket can seed the same process again.
Thus Fast does not offer Strict's global matching-UID
ambiguity detection. In the goals above, rejection of ambiguous identity means
ambiguity actually detected by the selected strategy, not proof that Fast has
discovered every holder. Strict remains the choice for exhaustive owner search.
Learning and BlockAll are unchanged and do not use this exception.

`StatusV4` reports the remembered strategy without process identifiers.
Strategy changes require root and a revision-checked transaction that advances
the flow generation. Missing persisted strategy defaults to Strict; selecting
legacy Enforcing resets it to Strict. Before downgrading to an older daemon,
root must persist Strict so that the new Fast-only state field is omitted.
Fast neither establishes actual-sender identity nor promises measured
CPU/latency gains.

## Attacker model

The design assumes an attacker may:

- run arbitrary processes as any unprivileged local UID;
- choose command arguments and move a process within cgroups available to that
  user;
- inherit, duplicate, or pass socket descriptors and deliberately create
  ambiguous ownership;
- create many connections or processes to exhaust bounded attribution and
  learning capacity;
- create files and sockets in world-writable directories and modify files the
  attacker owns;
- connect repeatedly to the observation socket and send malformed frames;
- control remote endpoints and packet contents;
- supply every editable rule field through the TUI or protocol.

The observation feed is not available to an arbitrary local UID: the attacker
must also compromise root or membership in the `openshield` group to read it.

A compromised kernel, compromised UID 0, or a malicious replacement for a
selected root-owned backend executable is outside this boundary. Such an attacker already
has authority equivalent to the firewall daemon. Compromise of the daemon itself
is addressed as a high-impact residual risk because its retained capabilities
are broader than firewall administration alone.

## Controls inherited from the OpenSnitch audit

- Sockets are under a verified root-owned directory, never predictable paths in
  `/tmp`. Control is owned by UID 0, has mode `0600`, and checks `SO_PEERCRED`
  UID 0; its group does not participate in authorization.
  Observation is `root:openshield` `0660` and checks `SO_PEERCRED` plus a
  bounded stable primary/supplementary-group identity before serving data.
- There is no unauthenticated TCP/gRPC management endpoint and no TLS fail-open
  mode.
- The protocol has bounded frames, connection limits, absolute request
  deadlines, and bounded subscriber queues. Observation uses 32 fixed workers,
  a 64-job queue, at most 24 observation subscriptions (two per UID), and at most four
  connections per UID. One per-UID bucket has a 256-token burst, refills at 64
  tokens/s, and is charged both on connection acceptance and before each
  `Status`, `RulesPage`, or `Subscribe`; exhaustion closes the session. The
  connection state machine permits `Subscribe` only first,
  bounds pre-pagination `Status` requests to two, and then accepts only strictly
  advancing rule cursors. The server ignores smaller client limits, fetches up
  to 128 rules per cursor, and byte-shrinks only to fit the 64 KiB frame bound,
  returning a resumable cursor. A subscriber is disconnected if its bounded
  512-event queue fills.
- The daemon never accepts arbitrary task paths, logger paths, eBPF module paths,
  shell commands, or downloadable plugins. A validated application path is a
  bounded selector and is never invoked.
- Rule identifiers are UUIDs; display names are never filesystem paths.
- Persistence rejects symbolic links and uses fixed root-owned locations.
- Normal daemon code does not read process environments or process memory.
  Before serializing a response for a non-root observer, the daemon replaces the
  complete application selector and its potentially identifying rule name with
  fixed redacted values.
- Network-only decisions remain in backend chains. Enforcing application
  decisions and Learning application-deny candidates use fixed fail-closed
  NFQUEUE 1337; ordinary Learning observations use the
  separate fixed NFQUEUE 1338. Both have a maximum kernel queue length of 256
  packets and a 512-byte copy range. Queue bypass and accept-on-overflow are
  present only on queue 1338, whose outbound `Learning` default already permits
  unmatched traffic; `Enforcing` and `BlockAll` never reference that queue.
- `StatusV2` reports policy mode, firewall backend, and the dynamically
  recomputed active-policy path classification as separate typed fields. It is
  not kernel-capability attestation or fallback negotiation. The value is derived from committed
  enabled rules: `KernelNative` only for `BlockAll` or application-free
  `Enforcing`, `ConntrackHybrid` only for TCP-only application `Enforcing`, and
  `Nfqueue` for `Learning` or any enabled per-packet application protocol.
  Absent legacy data defaults to `Unknown`. This status is descriptive and
  cannot broaden a rule. Network-only traffic stays in the kernel at every
  known level. Failure to initialize mandatory NFQUEUE leaves the bootstrap
  `BlockAll` policy installed and terminates the daemon instead of falling back
  to a weaker policy. Learning's explicit queue bypass becomes reachable only
  after successful startup activation.
  The only automatic startup backend fallback is nftables to the complete
  iptables/ip6tables bundle when nftables cannot be validated.
- Two independent outgoing packet consumers own the fixed kernel queues: queue 1337 has
  neither bypass nor `NFQA_CFG_F_FAIL_OPEN`, while observational queue 1338 has
  both. A separate fail-closed reader of INPUT queue 1339 can briefly hold
  eligible UDP/ICMP echo replies and repeat current kernel policy, never accept
  them itself. Its captured outgoing sequence, flow readiness and three-attempt packet mark
  are scheduling state, not an authorization cache. Bounded waits and fresh
  mode/generation checks apply; see [the architecture](ARCHITECTURE.md).
  Queue 1338 normally returns `NF_ACCEPT` immediately; the first eligible
  TCP SYN or datagram of a recently unseen flow may wait for an asynchronous
  attribution attempt, bounded by 250 ms and 128 pending packets. Its reader
  remains responsive with a 5 ms pending-work poll. Expiry, full backlog, or full
  pending capacity does not make successful attribution a Learning allow
  requirement. A pending verdict is accepted only under the engine lock while
  the same Learning mode/generation remains active and shutdown has not started;
  otherwise it is dropped. Serial/generation tickets reject stale completions.
  Another bounded worker persists successful observations. Queue
  1337 permits only a successful matching decision and conservatively drops an
  unresolved deny candidate, except for a kernel-UID mismatch deferred to
  best-effort observation. The Strict path handles parsed TCP, UDP, ICMP echo, and
  ICMPv6 echo traffic in batches of no more than 32 ready items and never
  waits to fill a batch. Every packet independently maps its kernel UID and
  network tuple to a socket inode through `SOCK_DIAG`. One bounded external
  PID/TID owner snapshot before identity capture and another after capture are
  shared across the batch, including single-item batches. One absolute deadline
  covers the complete operation: 2 seconds for queue 1337 and 5 seconds for
  asynchronous Learning attribution; every `SOCK_DIAG` query is additionally
  capped at 250 ms within that deadline. Each snapshot has one global cap of 131,072 owner records
  across all targets. These bounds are not multiplied by packet count. Identity
  capture is memoized only inside the batch for the
  same inode, socket UID, and capture requirements. Requests sharing a socket
  must agree on PID, process start time, executable path and complete file
  version, and filesystem UID. The typed timeout marker is preserved for
  NFQUEUE accounting. In Strict there is no cross-batch process-identity or
  authorization-result cache; a later UDP/ICMP batch starts with new per-packet
  `SOCK_DIAG` lookups and fresh owner snapshots. The resolver scans a task's fd table only when
  its filesystem UID equals the kernel socket UID; matching holders are grouped
  by TGID. When the UIDs match, the
  daemon's shared `/proc/<self>/fd` table is checked immediately before the
  external scan and again after that scan completes: two bounded checks per
  completed owner scan replace per-self-thread fd scans. In Enforcing, a target
  socket or failed check produces DROP in Enforcing, and self task fd tables
  are excluded from attribution. Within one external scan, a descriptor number
  found for one task is tried first on later matching-UID tasks. Only an exact
  target link with a repeated UID check is accepted; all target inodes for that
  UID must be confirmed to skip the complete fd walk. A missing target, mismatch,
  or read error falls back to the bounded scan; verified preferred descriptors
  make duplicate-fd selection stable. The hint is not retained across batches.
  Full walks pin and rewind the fd directory and use safe `RawDir`/`readlinkat_raw`
  with fixed reusable buffers. A truncated link cannot be a valid socket link;
  read errors, disappearance checks, UID checks, and all work bounds retain their
  fail-closed meaning. A changed before/after owner snapshot, the absence of a matching-UID holder, different matching TGIDs,
  an incomplete or unavailable live process/task scan, or candidate
  descriptor-bound exhaustion fails attribution. Sibling holder TIDs in one TGID
  count as one process only if their captured executable path/file version, argv,
  filesystem-UID, and cgroup identities agree. The exact fd path found by the owner scan is not trusted as
  authorization: it is revalidated before identity capture, a vanished or moved
  hint triggers one bounded rescan of the same task, and the selected fd is
  rechecked after capture. A vanished
  entry is skipped only after procfs confirms disappearance. `PermissionDenied`
  on a TGID-leader fd table is skipped only after two bounded `stat` reads
  confirm stable zombie state `Z`; every other error, non-zombie state, or
  unconfirmed state fails attribution. Any remaining failure, ambiguity, configured
  bound, or the shared procfs deadline produces DROP in Enforcing and
  for a Learning application-deny candidate; on queue 1338 it suppresses
  persistence without changing Learning's ordinary allow policy, subject to
  pending-verdict mode/generation checks. The
  policy generation is rechecked under the engine lock, which remains
  held through the backend-specific verdict and packet reinjection. nftables
  returns `NF_ACCEPT` and completes authorization in a later base chain;
  fail-closed queue 1337 on iptables returns `NF_REPEAT` with an authenticated
  `NFQA_MARK` handoff that
  the first repeated OpenShield OUTPUT rule consumes. The verdict socket is
  nonblocking: terminal send failure requests emergency `BlockAll` instead of
  indefinitely holding the policy lock.
- The upper two packet-mark bits form an internal pending/handoff domain and are
  stripped from untrusted outbound marks; the lower 30 packet bits survive the
  complete NFQUEUE path. Successful established-TCP authorization writes a
  persisted, nonzero, non-reused domain/generation into the low 31 conntrack
  bits while preserving bit 31, binding both TCP directions and invalidating
  older connections after restrictive policy changes. UDP/ICMP uses no
  outbound cache: the low 31 bits are cleared before every original packet,
  the packet is re-attributed, and successful authorization refreshes those
  bits for the matching inbound reply.
- An enabled persisted application selector requires a canonical absolute
  executable path and the full file-version tuple `(device, inode, size, ctime
  seconds, ctime nanoseconds)`. An automatically learned disabled template is
  the only unpinned persisted exception: it contains a path and optional cgroup
  but no network, argv, UID, or file-version selector. Enabling it is root-only
  and the daemon must resolve and pin the current executable before applying it.
  For manual create/update, the daemon must resolve the path in
  its own mount namespace and compares repeated canonical-path and opened-file
  snapshots; it fills an omitted pin and rejects a stale supplied pin. Exact
  filesystem UID, exact unified-cgroup-v2 path, and tokenized exact or prefix
  command-line constraints are optional; every supplied network and application
  field is combined with AND. On v2 the cgroup identity comes from exactly one
  `0::/path` entry. On a v1-only host, bounded memberships are validated but the
  identity is empty: executable path, full file version, UID, and argv attribution
  remains available, while an explicit cgroup-path selector cannot match. Older
  persisted two-field application pins are rejected rather than silently
  repinned; network-only state remains compatible.
- In Enforcing, stateful reverse traffic is tied to the current generation of a
  live application accept rule; an old conntrack entry alone is not an
  authorization. Learning permits conntrack replies to locally initiated
  traffic admitted by its outbound default or rules. Unsolicited inbound service
  traffic still requires an explicit inbound allow in both modes; the exact
  DHCPv4/DHCPv6 bootstrap and essential IPv6 control forms are separate built-ins.
- Native rejection replies receive one narrow exception from local
  default-deny. Only an exact RELATED/REPLY TCP RST, IPv4 ICMP
  destination-unreachable/port-unreachable, or IPv6 ICMPv6
  destination-unreachable/port-unreachable is admitted, and only when its
  OpenShield-owned low-31 connmark bits attest the current nonzero 30-bit
  rejection generation with the accept-domain bit clear. A generation change
  invalidates stale attestation; other RELATED traffic receives no exception.
- Before a broader network accept, application envelopes also drop a matching
  UNTRACKED current tuple that cannot enter attribution. Destination- or
  port-constrained envelopes add a conntrack-original destination/port DROP,
  while retaining the final output-interface constraint, to close a local-DNAT
  bypass. This guard may conservatively deny a translated flow rather than
  attribute a rule written for the pre-translation endpoint.
- Learned endpoint authorizations use action `accept` and retain the observed application identity, protocol,
  endpoint, and outbound interface, so a VPN or link-local endpoint does not
  silently become allowed for another program or on every interface.
- Application learning uses a separate bounded 512-item queue and persists no
  more than 256 automatic rules per batch. Automatic insertion stops when
  learned endpoint rules plus templates reach 7,500 globally, or endpoint
  rules reach the configured quotas: by default 4,096 per filesystem UID or
  1,024 per pair of filesystem UID and complete executable file version.
  Disabled learned rules count, and older file versions still count toward the
  UID quota. These are admission
  budgets rather than validation invariants for legacy or root-edited state.
  Distinct subordinate UIDs count separately, so one operator-controlled UID
  range can distribute activity until the global budget. The 10,000 total-rule
  limit normally leaves 2,500 count slots for privileged manual rules; the exact
  8 MiB encoded-state quota is independent. After successful procfs attribution,
  a revision-checked immutable admission index classifies an exact-known,
  count-saturated, persistence-paused, or potential-new observation. Only the
  potential new candidate enters the 512-item queue; the other three retain the
  current `Learning` allow without consuming queue capacity. A benign
  admission-cache mismatch suppresses persistence without changing that allow;
  a transition out of Learning denies the stale queued decision. A concurrent
  Learning-to-Learning generation change retains the already-permissive Accept
  verdict but may suppress the stale observation, while a poisoned or terminal
  runtime enters emergency `BlockAll`. The worker coalesces
  exact duplicates in each bounded 256-observation drain. A count-saturated
  endpoint therefore has no persisted permit in Enforcing. Reaching
  the byte quota or a recoverable save failure discards that batch and pauses
  all automatic learning in the daemon process until a successful privileged
  mutation or restart, while retaining the previous state and active traffic
  policy. Persistence is two-phase: preparation, reservation, and the pending
  admission index run under the engine lock, while atomic save and `fsync` run
  after releasing it. Exact pending matches are deduplicated; state and events
  are published only after durable commit. Other privileged controls return
  `Conflict`. Root `BlockAll` instead installs the kernel deny immediately and
  is serialized last. Unsafe storage or base-state outcomes enter fail-closed
  quarantine rather than publishing an uncommitted candidate.
- Learning quotas can be set only through the fixed optional root-owned
  `/etc/openshield/learning-limits.json`, with
  `1 <= per_application <= per_uid <= 7500`. Missing configuration uses
  defaults 1,024/4,096 respectively. The file and parent directories must be
  root-owned, safely permissioned, and nonsymlinks. Parsing and metadata
  validation occur at startup after bootstrap `BlockAll`; invalid or unsafe
  configuration fails startup. Global count and state-byte limits are unchanged.
  `StatusV3` exposes bounded scalar quota diagnostics, without selector lists;
  the TUI warns about incomplete learning, including on a root request for
  Enforcing. This is an advisory warning, not a new permission or a veto on
  authorized mode changes. Missed endpoints must be observed again in Learning;
  no warning is proof of complete attribution or persistence.
- Rule activation and action are separate. A disabled rule is inert. In either
  normal mode, enabled outbound rules may accept, silently drop, or actively
  reject. `Learning` admits unmatched traffic and creates learned `Accept`
  rules, but does not override enabled explicit denies.
  Inbound rules are accept-only. Deny actions are evaluated before accepts so a broad accept
  cannot override a matching deny. Enabling an automatically generated broad
  application template therefore cannot override a matching drop/reject rule.
  Disabling an unchanged Template restores its canonical unpinned skeleton and
  every later enable securely repins the current file. An edited non-skeleton
  Template and disabled Manual or Learned rules retain their complete
  specification and file pin.
- Every daemon start first installs kernel `BlockAll`. Missing state is persisted
  as `Learning`; an existing saved mode is preserved. The engine increments the
  persisted nonzero 30-bit flow generation by exactly one, persists the new
  value, and only then applies the requested policy. Generations are never
  reused before exhaustion, so TCP authorization marks from every earlier daemon
  process remain invalid. Exhaustion retains `BlockAll` and fails startup rather
  than wrapping the counter. While bootstrap `BlockAll` remains active, the
  first v0.2.1 start over v0.2.0 state adds missing disabled template skeletons
  for existing Learned application groups. This additive migration respects the
  automatic-rule, total-rule, and 8 MiB limits and never removes endpoint rules
  when no room remains; migrated state is persisted before policy activation.
- State and IPC compatibility is forward-only from v0.2.0 to v0.2.1. v0.2.1
  accepts a missing rule `action` as `accept`; v0.2.0 cannot parse v0.2.1
  `drop`/`reject` actions or the `template` origin. Mixed daemon/TUI versions and
  an in-place downgrade after v0.2.1 has written state are outside the supported
  boundary and require a protected-console rollback procedure.
- Graceful daemon shutdown and every packaged post-stop hook install kernel
  `BlockAll` without overwriting the persisted requested mode. Forced
  termination, early boot, and initramfs paths remain deployment boundaries.
- The packaged unit installs `BlockAll` before its main process and reports
  systemd readiness only after the selected policy, both fixed NFQUEUE
  consumers, and IPC endpoints are active. It requires tmpfiles setup to pre-create the
  root-owned runtime/state directories and standard `0600` `/run/xtables.lock`,
  and grants write access to those exact paths rather than all of `/run` or
  `/var/lib`. Non-recursive relabeling preserves their policy-defined SELinux
  contexts without altering stored state. Once enabled, its
  `RequiredBy=network-pre.target` installation dependency and
  `Before=network-pre.target` ordering make standard consumers depend on that
  successful readiness; the scope limitation is recorded below.
- A verified root-owned `0600` singleton lock is acquired before any state or
  backend mutation, including `--install-fail-closed`; stale socket cleanup is
  bound to the device/inode created by that daemon instance.
- Every root control mutation is conditional on its source snapshot revision.
  Concurrent or stale edits fail with `Conflict` before side effects, and the
  TUI resynchronizes without automatically replaying the rejected intent.
- A lost acknowledgement is not reported as a failed mutation: the TUI treats
  transport errors as ambiguous, warns against retrying, and reloads state.
- UTC rollback cannot invalidate a rule update: revisions define ordering and
  persisted `updated_at` values are kept monotonic.
- The packaged unit limits the daemon to `CAP_NET_ADMIN`, `CAP_NET_RAW`,
  `CAP_SYS_PTRACE`, and `CAP_DAC_READ_SEARCH`. It keeps primary group `root` and
  adds supplementary group `openshield`; the socket owner can select that
  group without retaining `CAP_CHOWN`. `CAP_NET_RAW` is required for legacy
  xtables inspection and fallback operation; the syscall filter denies `ptrace`,
  `process_vm_readv`, `process_vm_writev`, `kcmp`, `pidfd_getfd`, and
  `open_by_handle_at`.

## Residual risks

- The dynamically recomputed active-policy path is a worst-case classification,
  not a kernel feature attestation, runtime fallback negotiation for an
  unchanged policy, or proof that every packet follows one path.
  Since version 0.1.31, `KernelNative` means nftables/iptables policy evaluation; it
  does not mean eBPF application attribution. This release ships no eBPF
  application data plane and makes no `CAP_BPF`, boot-parameter, MOK, or kernel
  module change. The procfs/NFQUEUE attribution risks below therefore remain.
  The only automatic startup backend fallback is nftables to the complete
  iptables/ip6tables bundle when nftables cannot be validated.

- Learning is intentionally permissive for outbound traffic. An untrusted local
  process can reach arbitrary remote endpoints during a Learning window even if
  attribution fails, the learning queue is saturated, or no rule can be stored.
  Queue bypass is therefore expected in this mode. Operators must limit Learning
  to a controlled interval, review generated rules/templates, and switch to
  Enforcing before relying on outbound containment.
- A generated disabled template contains only executable path and optional
  cgroup. Once root enables it, the daemon pins the current executable version,
  but the rule deliberately omits endpoint, port, interface, argv, and UID. It
  grants substantially broader access than an exact learned endpoint and must
  be reviewed like any other privileged wildcard rule.

- The packaged `RequiredBy=network-pre.target` relationship is created by
  `systemctl enable`; merely installing the unit does not activate it. A network
  manager, unit, initramfs, or early packet path that bypasses
  `network-pre.target` also bypasses this dependency and may send traffic
  without OpenShield. Strict whole-boot enforcement requires tested
  distribution-specific integration or an initramfs policy.
- The `root:openshield` `0660` observation feed exposes mode, network rules,
  endpoints, events, and aggregate counters to every member of that group.
  Application selectors and identifying application-rule names are redacted for
  a non-root member, but the remaining data can still be sensitive. Group
  membership must therefore be managed as a monitoring privilege and audited.
  Authorization happens when a Unix connection is accepted; an authorized
  member can relay the already-connected socket fd to another process, so this
  group check is not a non-delegable confidentiality boundary.
- At 64 or more external tasks across multiple TGIDs and two available CPUs, an
  owner snapshot may scan fd tables with two workers. The complete PID/TID list
  is enumerated first under the global task cap; whole TGIDs are distributed
  greedily by task count. One positive-owner accumulator retains the global
  record cap and cross-worker ambiguity checks. One absolute deadline covers
  both workers, and every helper is joined before use of the sorted result.
  Spawn/join errors and incomplete scans fail closed. This may increase
  instantaneous CPU use; one large TGID and small process sets remain serial.
- Learning is not a historical process/socket event collector. The first-packet
  250 ms capture opportunity is a userspace deadline, not a hard real-time bound
  under scheduler or policy-lock contention. It helps short-lived request/response clients, but a
  one-way UDP sender can return from `sendto()` and exit before attribution.
  Queuing the datagram does not pin its process identity. Such a missing rule
  must not be filled from a stale PID or guessed identity; review the learned
  rule set before Enforcing. Bounded duplicate suppression can also lose
  observations under churn, without authorizing an Enforcing packet.
- Procfs attribution is a bounded, repeated post-hoc consistency check, not an
  atomic kernel record of the process generation that initiated an operation.
  In particular, a process can enqueue a packet and then exec an allowed image
  while retaining the socket; the resolver may observe only the post-exec image
  and authorize an operation initiated before exec. Repeated reads detect
  changes during the scan but cannot reconstruct sender/exec history. UDP
  `SO_REUSEPORT` groups and wildcard/specific binds under the same UID can also
  change the actual sender while tuple and UID observations remain compatible.
  The implementation does not provide an atomic sender record or cryptographic
  process attestation.
- An executable is identified by canonical path plus device, inode, size, and
  ctime at nanosecond field precision. An ordinary in-place rewrite changes size
  or ctime and therefore stops matching, but this tuple is neither a content
  digest nor a mount-namespace identity. Filesystems with coarse or reused
  metadata, privileged/raw-filesystem manipulation, and namespace/path aliases
  remain outside a cryptographic identity guarantee. Script execution may
  identify the interpreter rather than the script the operator had in mind.
  Protect application files with root ownership and non-writable parent
  directories, and explicitly repin reviewed rules after software updates.
- These fields identify observed process metadata, not all code executing inside
  that process. For example, `LD_PRELOAD=/tmp/evil.so /allowed/path` preserves
  the executable path and full file version, argv, filesystem UID, and cgroup while a
  constructor can perform network I/O. Interpreters, plugins, and JIT-generated
  code have the same boundary; hashing only the main executable would not fix
  it. Strong code identity requires a trusted launcher/cgroup with
  user-controlled loaders disabled, or an LSM/IMA/eBPF execution domain.
- Command-line and cgroup values are mutable process metadata collected after a
  packet enters the queue. Repeated reads detect observed changes, but they do
  not make those values immutable. The UID selector is the numeric filesystem
  UID, not a real/effective/saved-UID tuple.
- Unified cgroup v2 is required only for an exact cgroup-path selector. A v1-only
  host can still attribute executable path, full file version, filesystem UID, and
  argv after validating bounded v1 memberships, but reports no cgroup identity;
  an explicit cgroup-path rule therefore fails closed.
- At initial Strict attribution, stable shared, inherited, or `SCM_RIGHTS`-passed
  descriptors can make procfs ownership differ from the process that actually
  sent the packet. Multiple matching-UID TGIDs are denied. A task whose
  filesystem UID differs from the kernel socket UID is excluded before its fd
  table is scanned: if no matching-UID holder remains, attribution fails closed,
  but if the original matching-UID holder retains the descriptor, a cross-UID
  recipient is invisible to this fallback and the original holder can be
  attributed. Kernel-LSM sender attribution is not implemented; procfs ownership
  is not proof of the actual sender.
- Fast can additionally miss a new matching-UID shared-socket holder outside
  its cached TGIDs, without a guaranteed discovery deadline. Fresh checks of the known
  holder do not close this gap; the explicit Fast confirmation accepts it.
  This is a security tradeoff, not an equivalent replacement for Strict.
- Process identity is resolved for the first queued packet of an established TCP
  connection rather than every subsequent TCP packet. A later exec,
  filesystem-UID/cgroup change, or descriptor transfer can continue that
  connection until reconnection or a policy-generation change. UDP/ICMP is
  re-attributed for every outbound packet, but neither path is kernel
  exec-lifecycle enforcement.
- The active mode-specific bounded NFQUEUE consumer performs procfs work that is worst-case
  proportional to process/task enumeration plus the descriptor tables of tasks
  whose filesystem UID matches the socket UID. One directory walk inspects at
  most 16,384 fd entries per matching-UID task and fails if proof requires a later
  entry. Since v0.1.32, a batch performs two owner snapshots, each admitting at most
  131,072 owner records globally across all of its targets. A single 2-second
  deadline bounds both scans and every intervening lookup and capture for queue
  1337; asynchronous Learning uses 5 seconds, not a 5-second packet hold.
  Process/thread floods, a matching-UID fd flood, queue pressure, or the
  attribution deadline can therefore deny legitimate traffic in Enforcing. This is an
  availability/denial-of-service risk, not a fail-open path. An incomplete live
  process/task enumeration remains globally fail-closed; an oversized fd table
  affects attribution for traffic with its matching socket UID, while unrelated
  UID fd tables are skipped. An inaccessible non-zombie candidate, a state that
  cannot be confirmed as a stable zombie, or an error other than the narrowly
  handled `PermissionDenied` case has the same fail-closed availability effect.
  The v0.1.18 optimization replaces per-self-thread fd scans with two bounded
  checks of the daemon's shared table and normally avoids rescanning the selected
  external task's fd table during identity capture. The scan-local fd-number hint
  can also avoid redundant sibling-table enumeration, but every miss falls back
  to the complete bounded scan. These changes do not skip the fresh external
  PID/TID scan, introduce an authorization-result cache, or change the worst-case
  complexity. Sustained packet rates or hostile procfs cardinality can therefore
  still saturate the active consumer. In Enforcing this denies legitimate
  traffic; in Learning it loses observations while the declared outbound allow
  remains in force.
  The micro-batch introduced in v0.1.32 amortizes those two snapshots across at most 32
  already-ready packets, but it deliberately retains per-packet `SOCK_DIAG`,
  permits identity reuse only inside the current batch, and requires stable
  before/after ownership plus mandatory-identity consensus. It reduces common-
  case work; it is not an authorization cache and cannot remove the worst-case
  fail-closed availability limit.
  The immutable application-policy cache removes a full-state clone from each
  packet and indexes enabled rules by complete executable file version. A lookup
  scans only the policy-ordered bucket for the observed version, rather than all
  application rules. Matching within that bucket remains linear; a root-edited or
  legacy state can concentrate many rules under one pin regardless of the
  configurable per-UID/file-version automatic-insertion budget. That budget
  defaults to 1,024 and is not an absolute bound on a pin shared across UIDs.
  The Learning admission index prevents already-known, saturated, and paused
  observations from filling the persistence queue, but it runs only after the
  mandatory process attribution. A stream of new eligible candidates can still
  fill the observation or persistence queue and consume procfs work. In
  Learning this suppresses an observation while the packet remains allowed;
  the same resource pressure in Enforcing remains a fail-closed availability
  limit.
  The nonblocking verdict socket prevents a send stall from retaining the policy
  lock indefinitely, but sustained netlink send pressure can request emergency
  `BlockAll`; this is an intentional fail-closed availability tradeoff.
- `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` are retained so the hardened service
  can inspect another UID's protected procfs metadata. Denying `ptrace` and
  `process_vm_*` does not provide memory isolation: a compromised daemon can use
  `CAP_SYS_PTRACE` to open `/proc/<pid>/mem` and then use ordinary read/write
  syscalls. `CAP_DAC_READ_SEARCH` can also bypass read/search permissions for
  files visible inside the service mount namespace, including system secrets;
  following `/proc/<pid>/root` and related procfs magic links may additionally
  reach a target process's mount view despite the service's mount hardening. The
  daemon therefore retains broader readable-procfs and filesystem access.
- Reply scheduling requires the nested network procfs queue-progress entry.
  The unit therefore uses `ProcSubset=all` plus `ReadOnlyPaths=/proc`, retaining
  `ProtectProc=invisible` and the other capability, syscall and kernel-tunable
  restrictions. This exposes additional general procfs metadata compared with
  `subset=pid`; it does not broaden packet authorization. Startup validates the
  actual entry before activation. A missing/hidden/malformed entry cannot become
  a successful readiness signal or a guessed reply grant.
- Outbound application rules support `accept`, `drop`, and `reject`. Enabled
  network-only deny rules run first; an overlapping application candidate is
  then attributed before a broader network-only accept may be used as a
  fallback. Within the application class, `drop` precedes `reject`, which
  precedes `accept`. This deterministic order prevents a broad network allow
  from bypassing an application deny, but operators must still review
  overlapping rules because a network deny intentionally overrides an
  application allow.
- OpenShield reserves the upper two packet-mark bits and preserves the lower
  30. It reserves the low 31 conntrack-mark bits for application authorization
  and preserves bit 31. Other packet-mark users must avoid those upper two bits;
  another firewall, VPN, QoS, or CONNMARK writer must avoid the low 31 conntrack
  bits. Conflicting use may break either policy. More seriously, a privileged earlier
  chain that copies an attacker-controlled `SO_MARK` into the conntrack mark
  before OpenShield's sanitizer can create the current domain/generation value
  and bypass the TCP application queue for an established flow. OpenShield
  requires exclusive ownership of its low 31 conntrack bits and compatible hook ordering. An
  external asynchronous queue between its priority-0 policy chain and
  priority-1 late chain also breaks the engine-lock/reinjection timing
  assumption.
- A root user can intentionally install rules that cut off remote administration.
  The TUI requires confirmation for `BlockAll`, but root remains authoritative.
- Rules owned by other products may still drop traffic that OpenShield returns
  or accepts. The nftables backend never flushes tables it does not own; the
  compatibility backend uses `--noflush` and owns only `OPENSHIELD_*` chains,
  but inserts dispatch jumps first in built-in IPv4/IPv6 chains.
- Fixed backend paths are checked as root-owned, safely permissioned regular
  executables before later path-based spawns. A privileged package update or
  root process can replace one between validation and execution. This path
  TOCTOU is inside the already trusted UID-0/package-management boundary.
- Learning creates application-and-endpoint rules, not trust in remote content.
  A learned server or local executable can later become malicious, so learned
  entries should be reviewed. Any attributable local process can deliberately
  contact many endpoints and consume its configured application or UID quota
  (by default 1,024 and 4,096 respectively). Distributed activity can still consume the
  7,500-rule learned capacity or 8 MiB state quota during a Learning window.
  The 2,500-slot manual reserve is count-only. These limits preserve bounds but
  can cause learning to pause and do not remove rule-poisoning risk.
  Increasing these budgets expands the admission window and does not reduce
  process-attribution CPU cost or latency.
- Root can still consume the complete 10,000-rule count through privileged
  manual mutations. This is inside the administrative trust boundary but can
  cause an operator-created availability limit.
- Competing privileged firewall managers can delete or reorder OpenShield
  objects. The daemon attempts to repair detected divergence, but arbitrary
  concurrent privileged editors are unsupported.
- A privileged `flush chain` leaves the base chain's default-drop policy in
  place, so it cannot create a fail-open path, but lightweight health checks do
  not reconstruct missing allow rules until a later policy apply or restart.
- Health monitoring checks table, base-chain, policy, and named-counter metadata,
  not complete rule bodies. A privileged targeted edit or additional allow rule
  can therefore evade detection. Such a `CAP_NET_ADMIN` peer is outside the
  unprivileged threat boundary and must not run concurrently.
  On nftables, the three checks are requested from one fixed `nft` process and
  parsed as ordered, bounded JSON documents. This reduces process-launch cost
  but retains the same one-second cadence, validation coverage, and fail-closed
  repair behavior; it does not strengthen the trust boundary against root.
- Normal modes include exact hop-limit/source-constrained IPv6 Router
  Advertisement, Neighbor Solicitation/Advertisement, MLD query, and required
  RELATED-error forms so basic IPv6 control traffic is not accidentally lost.
  Other ICMPv6 needs still require an explicit network/interface-scoped inbound
  allow, and the rule model has no ICMP type/code selector. `BlockAll` contains
  no control-plane exception. Application attribution supports only echo
  requests for ICMP/ICMPv6.
- The `inet` table covers host IPv4/IPv6, not layer-2 ARP or direct frame
  injection by a privileged `AF_PACKET`/`CAP_NET_RAW` peer. OpenShield 0.1 is
  not an L2 firewall.
- If both a state transaction and emergency-state persistence fail, the daemon
  keeps kernel `BlockAll` active and enters read-only quarantine instead of
  restarting from an ambiguous file. Recovery then requires a local root
  operator to repair storage and deliberately replace or move aside the state
  file before restarting.
