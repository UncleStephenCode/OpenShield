[English](ARCHITECTURE.md) | [Русский](ARCHITECTURE.ru.md)

# OpenShield architecture

This document describes the OpenShield v0.2.2 policy model.

OpenShield is a Linux host firewall composed of two Rust binaries:

- `openshield-daemon` is the only component allowed to change the firewall. It
  owns either a dedicated `inet openshield` nftables table or the reserved
  `OPENSHIELD_*` iptables/ip6tables chains, and persists validated rules.
- `openshield-tui` displays status and events only to root or members of the
  `openshield` system group. Mutating controls are enabled only when the daemon
  authenticates the peer as UID 0.

The daemon never accepts TCP control connections. It exposes two local Unix
sockets below the root-owned `/run/openshield` directory:

| Socket | Mode | Operations |
| --- | ---: | --- |
| `control.sock` | UID 0, `0600` | change mode; create, update, enable, disable, or delete rules |
| `observe.sock` | `root:openshield`, `0660` | read a sanitized snapshot and subscribe to bounded events |

Filesystem permissions are defense in depth. Every connection is authenticated
with Linux `SO_PEERCRED`. Control is rejected unless the peer UID is 0.
Observation requires UID 0, a primary `openshield` GID, or a stable
supplementary-group match. For the latter, the daemon reads bounded procfs
credentials twice and verifies the process start time and effective credentials
against `SO_PEERCRED`; ambiguity denies access. Protocol messages use a
length-prefixed JSON frame with a
small fixed maximum size. Slow observers have bounded queues and are dropped,
so they cannot delay packet filtering or policy changes. The observation path
uses 32 fixed workers, a 64-job admission queue, at most 24 live observation
subscriptions, and per-UID limits of four connections and two subscriptions. A
single per-UID token bucket (burst 256, refill 64 tokens/second) is charged both
when a connection is accepted and before each `Status`, `RulesPage`, or
`Subscribe` request; exhaustion returns `Conflict` and closes the session. A
session state machine permits `Subscribe` only as the first
request; snapshot sessions permit at most two `Status` requests and, after rule
pagination begins, only a strictly advancing cursor. For each cursor the server
fetches up to its fixed 128-rule maximum, ignoring a smaller client-supplied
limit, and then binary-searches a shorter page only when needed to keep the
encoded frame within 64 KiB. The response carries a resumable cursor, and the
TUI reuses one connection for the complete snapshot. Each event subscriber has
a 512-event queue, large enough for a complete 256-rule learning batch plus
policy/counter headroom while remaining bounded.
Rule pages and events are redacted server-side for every authorized observer
whose peer UID is not 0: application path, file-version identity, command line,
UID, cgroup, and the potentially identifying rule name are replaced before
serialization. Group membership grants no control-plane authority.
Authorization applies when the Unix connection is accepted; Unix fd passing can
delegate an already-connected observation stream, so group access is not a
non-delegable confidentiality boundary.

Before loading state or invoking a firewall backend, every privileged daemon action takes
a nonblocking exclusive `flock` on the verified root-owned regular `0600`
`/run/openshield/daemon.lock`. The main process retains it for its complete
lifetime; `--install-fail-closed` uses the same lock for its transaction. The
lock pathname is opened with `O_NOFOLLOW|O_CLOEXEC`, its inode is never unlinked
by the daemon, and a second instance exits before it can change live policy or
replace IPC sockets. Socket cleanup records the filesystem device/inode created
by each listener and unlinks only that exact object.

Every control mutation carries `expected_revision`, captured when the operator
starts the edit. The engine compares it with current state before cloning,
validation, persistence, or backend work. A mismatch returns `Conflict` with no
side effects. The TUI then requests a fresh snapshot and requires a new operator
action; it never silently retries a stale full-rule update. A transport timeout
or EOF after sending a command is treated as an unconfirmed outcome because the
daemon may have committed before its acknowledgement was lost. The TUI warns
against retrying and resynchronizes instead of claiming the change failed.

`ManageOutboundGroup` (wire name `manage_outbound_group`) applies only to
outbound rules. Its selector identifies an exact cgroup path, optionally
restricted to an exact executable path within that cgroup; a fallback executable
group without a cgroup; or a fallback destination CIDR (`None` means any
destination). Arguments do not split executable groups. The TUI freezes the
selector and `expected_revision` when the group menu opens. The daemon stages
all changes in one candidate policy and commits the backend and persistence
once, while changed rules retain consecutive event revisions. Root-only control
still applies, and Accept/Reject/Drop preserve each rule's enabled state.
Older daemons reject the unknown command; update the daemon and TUI together.

## TUI policy projection

The TUI separates Status, Outbound rules, Inbound rules, Events, and Help into
five tabs selected by `1` through `5` or cycled with `Tab`. Status obtains the
active typed backend identity from the daemon and displays `nftables` or the
`iptables`/`ip6tables` fallback independently of observation-stream health. A
`StatusV2` snapshot also displays the policy mode and dynamically recomputed
active policy-path classification. A legacy response is shown as `Unknown`; the
client never infers acceleration from absent data.
An active read-only fail-closed quarantine is reported as L3 with the distinct
`EmergencyBlockAll` reason. Both the level and reason are rendered as an
emergency, so this state cannot look like an operator-selected healthy
`BlockAll`.

The outbound view is a projection over the authoritative rule snapshot, not a
second policy model. It selects exactly one grouping key per rule in priority
order: unified-cgroup-v2 path, exact validated executable path without argv, then
destination network. A rule with no destination network uses an explicit
"any destination" key. All lower-priority selectors remain individual rule
fields. The left pane selects a group; the right pane retains each member and
shows its complete network and application constraints. Navigation follows
stable rule UUIDs so insertion, sorting, or migration between groups cannot
redirect an edit, delete, or enable operation to a different rule. Grouping
never changes matching or creates an implicit bulk mutation.

Inbound rules have a separate view and editor entry point. They expose source
network, local port or range, interface, and protocol, but never an application
selector or a deny action. Rule activation and verdict are independent:
`enabled=false` makes a rule inert, while an enabled outbound rule can
`Accept`, `Drop`, or `Reject`. Inbound rules are accept-only, and the daemon
rejects an inbound `Drop` or `Reject` even if a client bypasses the TUI.
`Up`/`Down` change the current group or inbound rule and
`Left`/`Right` change the selected member of an outbound group.
`PageUp`/`PageDown` scroll the complete, bounded rule detail projection. The
current tab supplies the direction for `n`; `e`, `d`, and `Space` act on one
selected UUID. On Outbound, `g` opens the actions for the selected group row
(including an executable child), and every group action requires confirmation.
The daemon still independently enforces root-only control;
authorized non-root `openshield` observers can navigate only the redacted,
read-only projection.

## Application attribution

An application selector is valid only on an outbound rule. The executable path
is mandatory. Every enabled persisted selector must also contain its
file-version identity: device, inode, size, and ctime seconds and nanoseconds.
The only unpinned persisted exception is the disabled automatic group template
described below. Optional exact constraints are filesystem UID and cgroup path;
command arguments use token-preserving exact or prefix matching. All configured
network and application fields are ANDed. Activation is independent of action:
in either normal mode, an enabled matching application rule can accept, silently
drop, or natively reject traffic, while any disabled rule is inert. `Learning`
allows unmatched outbound traffic and creates learned `Accept` rules, but does
not override enabled explicit denies. In the application index, overlapping
matches use the fixed order `Drop`, `Reject`, then `Accept`, independently of
UUID ordering. The
daemon never executes the path and does not support environment,
regular-expression, parent-process, persistent-PID, MD5, or SHA-1 selectors.

On a cgroup v2 host, the cgroup identity is the path from exactly one unified
procfs entry `0::/path`; missing or multiple unified entries deny attribution.
On a v1-only host, the resolver validates the bounded controller memberships but
returns an empty cgroup identity. Executable path, full file-version identity,
filesystem-UID, and argv attribution therefore remains available, while a rule
that explicitly requires a cgroup path fails closed. A cgroup-path selector
requires unified cgroup v2; application attribution as a whole does not.

This is process-metadata matching, not complete code identity. A dynamically
linked allowed executable can retain every selector field while loading
user-controlled code through `LD_PRELOAD`; interpreters, plugins, and JITs have
the same boundary. Stronger code identity requires an execution-domain control
outside this procfs selector design.

For a privileged manual mutation, or when root enables an unpinned automatic
template, the engine must resolve the path inside its own mount namespace. It
canonicalizes the path, opens the canonical target read-only with
`O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK`, requires a regular file, then repeats the
canonicalization and open while retaining both handles and performs a final path
check. The canonical path and all five file-version fields must remain stable.
The daemon fills an omitted pin and rejects a conflicting supplied pin; an
unresolvable path is rejected even when the client supplies an identity. For a
template enable, pinning, validation, persistence, and backend replacement are
one revision-checked privileged policy transaction: the rule cannot become an
enabled unpinned selector if any step fails.

A successfully attributed Learning observation creates an enabled `Accept`
endpoint rule. Its selector contains the observed executable path and complete
file version, filesystem UID, exact tokenized argv, and the single
unified-cgroup-v2 path when one is available; its network fields retain the
observed protocol, destination address and port, and outbound interface. On a
v1-only host the learned cgroup field is absent. For each exact
`(optional cgroup path, executable path)` group, automatic learning also creates one
disabled `Accept` template. The template selector contains only the executable
path and optional cgroup path: it has no destination network, port, interface,
argv, UID, or file-version pin and uses protocol `Any`. It is deliberately broad
but inert until root reviews and enables it, at which point the daemon atomically
pins the executable metadata as described above. Disabling an unchanged
template restores the canonical unpinned skeleton, so every subsequent enable
securely repins the executable then present at the path. A Template that root
has edited into a non-skeleton rule, and disabled Manual or Learned rules,
retain their complete specification and file pin.
The TUI omits a pin for a new or changed path so the daemon can derive it; an edit
that preserves the path carries the old complete pin for stale-version rejection.
Serialized application rules that contain only the older device/inode pair fail
closed and must be reviewed and recreated; network-only state is unaffected.

In `Enforcing`, traffic inside an enabled application rule's network envelope
enters fixed NFQUEUE 1337 without a queue-bypass flag. In `Learning`, enabled
application `Drop`/`Reject` candidate envelopes also enter queue 1337; failure
to resolve a candidate safely is `Drop`, except that an NFQA_UID mismatch is
accepted and deferred to best-effort observation. Other locally originated
outbound traffic is allowed by default and offered to separate observational
NFQUEUE 1338 with kernel `bypass` and `NFQA_CFG_F_FAIL_OPEN`: an absent or
saturated observer must not turn Learning into accidental packet loss. For
packets delivered to userspace, the kernel supplies a bounded packet prefix,
socket UID when available, and output-interface index. Missing packet-bound UID
remains an attribution failure; a later socket-table lookup is not a substitute
for proof of the queued packet's sender. All three queues request
`NFQA_CFG_F_GSO` so the kernel need not segment a large socket-associated skb
before enqueueing it. The reader validates `NFQA_CAP_LEN`, `NFQA_SKB_INFO`, IP
lengths, and complete transport headers within the 512-byte prefix; it neither
copies the full payload nor replaces the kernel packet. A deferred checksum is
not an attribution failure or an allow signal. GSO metadata never substitutes
for socket UID. Unsupported queue configuration fails before activation.
Three independent packet-consumer threads own the fixed queues. Queue 1337 has
a separate reader and exactly one attribution worker. The reader keeps at most
128 pending packets in total, including the single in-flight batch of at most
32 packets. It checks completed work before receiving another bounded datagram
and polls at 5 ms while attribution is in flight. Pending packets are selected
round-robin by kernel socket UID and then by flow, with a quantum of four packets
per flow; packets within a flow retain their receive order. These are scheduling
hints, never process identities or authorization. A busy flow can fill a whole
batch when there are no competitors, and the reader never waits for a batch to
fill. Per-flow reply tickets are registered only when the selected batch is
dispatched, not for the entire waiting backlog. At dispatch, malformed packets,
expired work, and decisions requiring no process attribution receive their
verdicts without waiting for that batch's attribution. Only the reader sends
verdicts, subject to the final mode, policy-generation, and shutdown recheck.
Capacity exhaustion stops further intake until completed work releases space;
the kernel queue retains its fail-closed overflow policy. No pending identity or
authorization is reused in a later batch. Queue 1338 submits a bounded copy to
its separate asynchronous attribution worker; another bounded worker persists
successful observations.
Queue 1339 defers only established UDP/ICMP echo replies inside enabled outbound
application-Accept envelopes in Enforcing, after the usual kernel allow paths.
An outgoing non-TCP packet still clears the shared authorization mark before
attribution. If an earlier reply arrives during that interval, a bounded
per-flow readiness registry can wait for already queued verdicts, then return
`NF_REPEAT` to re-evaluate the current INPUT policy. It never returns `NF_ACCEPT`.
On admission, the reply reader captures queue 1337's kernel packet sequence
from bounded `/proc/self/net/netfilter/nfnetlink_queue` metadata. It waits until
the OUTPUT reader has received and classified packets through that fixed
sequence. Within this boundary, matching UDP/ICMP flow packets and unclassified
packets must have their actual verdicts sent; known unrelated TCP or UDP/ICMP
flows may remain pending. Classification records only parsed scheduling tuples,
never process identity or authorization. Later traffic, including
new packets of the same flow, cannot extend this boundary or invalidate a
reply merely by starting a new attribution batch. A recorded failure in the
current flow still denies the retry. The netlink port and a private runtime epoch
bind the boundary to this queue instance; malformed or unavailable metadata
causes a reply to be dropped, not admitted. Before scheduling or issuing any
verdict, the OUTPUT reader atomically registers every received packet ID and its
classification in kernel receive order, including malformed packets and TCP
packets with no per-flow reply ticket. Verdicts may complete out of order. Only
a completely finished admission prefix retires slots from the global tracker;
flow-specific readiness never retires unrelated unfinished work. The tracker
has 1024 fixed-capacity slots;
completed later slots still consume capacity until earlier packets finish.
Duplicate or unadmitted completions, replayed IDs, and ambiguous half-range serial
arithmetic are rejected. Ordered receipt beyond a dropped-ID gap covers that
gap without inventing a verdict; an admitted matching or unclassified packet
within the boundary still has to finish, including across rollover. No received
ID or completed slot is evicted to make room.
This prevents a completed old flow entry from releasing a reply while an
already queued outgoing packet is still unread behind another attribution batch.
The two reserved packet-mark bits count at most three retries while preserving
the other 30 bits; they are not a conntrack mark or an authorization token.
At most 128 replies wait up to 2 seconds per attempt (at most 6 seconds across
three attempts), with a 5 ms poll interval and an explicit pause before retries.
Missing/failed/expired readiness, policy-generation changes,
and overload remain fail-closed. This narrows the mark-reset loss window; it is
not a per-request UDP authorization cache or a guarantee of lossless overload.
Attribution overload and repeated mark resets on the same flow can still
exhaust the bounded wait. Flow-specific reply waiting does not remove the
request's own attribution or OUTPUT intake backpressure.

Command arguments retain their exact UTF-8 bytes and token boundaries, including
newlines and formatting characters. Each argument can occupy up to 8191 bytes;
the complete NUL-delimited command line remains bounded to 8192 bytes and 64
arguments. NUL inside an argument, non-UTF-8 procfs data, and larger command lines
remain unsupported. Display and the TUI JSON editor escape controls and bidi
characters reversibly rather than changing the identity used for matching.

In Learning, the first eligible TCP SYN or datagram for a recently unseen flow can remain
pending for at most 250 ms, or until that attribution attempt completes. At most
128 packets can be pending. The reader keeps receiving packets and checks pending
completion/deadlines with a 5 ms poll interval; it never waits synchronously for
procfs. These are userspace deadlines, not hard real-time guarantees under CPU
starvation or policy-lock contention. Repeat observations are accepted immediately.
The recent-flow index has at most 512 entries, a 60-second lifetime, and a policy
generation key; it stores scheduling state, not process identities. Full attribution backlog
or pending capacity uses the ordinary Learning allow policy, not a longer wait.
Before any pending verdict, the reader holds the engine lock and requires the
same current Learning mode and policy generation and no shutdown; otherwise it
returns `DROP`. Completion tickets contain a serial and generation so a stale
worker completion cannot release a reused packet ID. Attribution completion is
not authorization or a guarantee that the persistence worker has committed a rule.
Queue 1338 loss, consumer outage, or attribution
backlog loses observation evidence, not ordinary connectivity. Attribution
batches contain at most 32 already-ready items and never wait to fill. Every
request retains its own `SOCK_DIAG`
tuple-to-inode lookup. The resolver then performs one complete bounded procfs
owner snapshot before identity capture and another after capture for all targets
in the batch, including single-item batches. The entire operation shares one
absolute deadline. For queue 1337, the two-second budget starts when the reader
receives the packet and includes userspace scheduling, attribution, and the
completion check before its verdict; it does not include earlier residence in
the kernel queue. A batch uses the earliest deadline of its non-expired members.
Asynchronous queue 1338 attribution has a separate five-second budget. These are
work limits, not hard real-time guarantees under CPU starvation or lock contention.
Each `SOCK_DIAG` query is additionally capped at 250 ms and
cannot extend that deadline. Each snapshot has one global limit of 131,072 owner
records across all targets. These work bounds are not intentional waits and
are not multiplied by packet count.

The bounded first-packet wait improves process visibility for TCP connect and UDP
request/response clients. It cannot guarantee attribution of fire-and-forget UDP:
`sendto()` can return and the process can exit before attribution reads procfs,
even with its datagram still queued. No historical exec/socket event stream or
PID authorization cache is introduced. Short-lived rules remain best-effort and
must be reviewed before switching to Enforcing. The
[short-lived application regression](../tests/compat/README.md#short-lived-application-regression)
separately checks request/response learning, denied unknown executables, and the
unavoidable one-way UDP observation limit.

Within a batch, metadata capture is grouped by exact TGID, TID, procfs task path,
socket UID, and capture requirements. Each socket descriptor is checked before
and after the shared metadata read; every owning TID must agree. A failed
descriptor does not invalidate an independently verified neighbour. Both complete
owner snapshots remain mandatory. Per-socket results are keyed by inode, socket
UID, and capture requirements and are discarded at the end of the batch. Duplicate requests
for one socket must reach consensus on mandatory identity: PID, process start
time, executable path, complete file version, and filesystem UID. The optional
argv and cgroup fields are still captured whenever the matching policy requires
them. The typed procfs timeout marker survives batched error propagation and is
recorded by the NFQUEUE runtime counters. A later batch starts again with
per-packet `SOCK_DIAG`; there is no cross-batch process-identity or authorization
cache, so otherwise-unmatched UDP and ICMP packets continue to require fresh
attribution.

`application_timing.rs` records fixed-size, best-effort wall-time aggregates for
`batch`, `socket_lookup`, `owner_before`, `metadata`, `owner_after`, `queue_wait`,
`queue_decision`, and `queue_verdict`. The accumulator uses `try_lock`: contention
skips the sample rather than waiting, and skipped samples are counted. While
activity continues, reports are emitted no more often than once every ten seconds,
outside the accumulator lock. Each stage contains sample, work-unit, and failure
counts plus total and maximum wall time in microseconds. Enumeration counters
measure completed process/task enumeration work, not unique system processes.
The log contains no addresses, PID/TID values, or rule selectors. Stage times may
overlap and are not CPU usage or additive latency components. Diagnostics never
participate in authorization, and the collector adds no eBPF attribution path.

For each owner snapshot, external PID/TID entries are enumerated once, every
task's filesystem UID is read, and `/proc/TGID/task/TID/fd` is scanned only when
that UID equals a target's kernel socket UID. Matching holders are grouped by
TGID. A changed before/after snapshot, lack of a matching-UID holder, different
matching TGIDs, inconsistent mandatory identity, incomplete or unavailable live
process/task enumeration, the shared deadline or owner-record bound, or a
candidate descriptor-bound exhaustion makes the affected attribution fail
closed in `Enforcing`. Sibling holder TIDs in one TGID are accepted as one process only when
their captured executable path/file version, argv, filesystem-UID, and cgroup
enforcement identities are equal. Unsupported traffic, malformed metadata, and
any other configured-bound failure cause `DROP` in `Enforcing` and for a
Learning application-deny candidate. On observational queue 1338, the same
failure suppresses persistence but does not change the ordinary Learning allow
policy, subject to the current mode/generation check for pending packets;
queue saturation, a disconnected asynchronous worker, or a recoverable
persistence failure has the same observation-only effect. Enabled explicit
denies and concurrent mode transitions remain authoritative. An integrity
failure, poisoned engine, terminal verdict/backend error,
or unsafe/ambiguous storage outcome can still trigger emergency quarantine with
kernel `BlockAll`.

The daemon's own TGID is handled separately because its standard Rust threads
share one descriptor table. When its filesystem UID equals the kernel socket UID,
the resolver performs a bounded check of `/proc/<self>/fd` immediately before
external-owner enumeration and another after that enumeration completes. These
are two shared-table checks on a completed owner scan instead of one scan per
daemon thread. Finding the target socket or failing either inspection fails the
attribution, and the daemon's per-thread fd paths are never accepted as
application owners. The failed attribution produces `DROP` in Enforcing and no
persisted observation in Learning, whose ordinary outbound verdict remains
`Accept` as described above.
This optimization is valid only while daemon threads retain the standard shared
file table and do not receive file descriptors from another process or change
filesystem UID independently; introducing `unshare(CLONE_FILES)`/
`CLOSE_RANGE_UNSHARE`, cross-process descriptor receipt, or per-thread
filesystem-UID changes requires re-auditing and, if the invariant no longer
holds, redesigning it.
The normal cross-UID exclusion applies when the UIDs differ. For an external
owner, descriptor numbers found for one task are tried first for later
matching-UID tasks in the same scan. The full walk is skipped only when every
target inode for that UID is confirmed by an exact link and repeated filesystem
UID check. Any missing target, mismatch, or read error falls back to the complete
bounded fd-table scan. That scan preserves a verified preferred fd when a socket
has duplicate descriptors, keeping before/after snapshots comparable. Hints are
not retained across batches. The final owner snapshot also borrows positive
descriptor names from the first snapshot of the same batch, keyed by TGID, TID,
socket UID, and inode. It enumerates all tasks again and freshly checks each
task's UID and every hinted link. A miss uses the full bounded fd walk, and
tasks without positive evidence are still checked exhaustively; no negative
owner result or identity is reused. Task-specific names keep duplicate-fd
selection stable without assuming that sibling tasks share their fd tables.

Fresh filesystem-UID checks read `status` into an 8 KiB stack buffer, allocating
bounded overflow storage only for larger files. The reader still consumes the
whole file and retains the 256 KiB limit, UTF-8 validation, and checks for read
errors and the original deadline; a valid UID prefix cannot hide an invalid or
oversized suffix.

The full fd walk pins an opened directory, rewinds it before each scan, and uses
safe `rustix` `RawDir`/`readlinkat_raw` with reusable bounded buffers. Negative fd
entries need no full-path allocation or repeated pathname lookup. Rewinding
prevents a reused directory offset from producing a false empty snapshot.
Truncated links cannot count as a canonical `socket:[inode]`; disappearance and
all other read errors retain their existing checked handling. UID, fd-count,
deadline, exact owner-set equality, and executable-version checks are unchanged.
This is a userspace I/O optimization, not a cache of authorized processes.

Owner enumeration first builds one bounded, sorted list of external PID/TID
groups. Only when there are at least 64 tasks in at least two TGIDs and the
runtime reports two available CPUs may the fd phase use two workers per owner
snapshot: the calling resolver and one scoped helper. Queues 1337 and 1338 have
independent attribution workers; when both are active, up to four scanning
threads may run in the daemon. Whole TGIDs are assigned in PID order to the
currently less-loaded worker by task count; this spreads sequential PID/UID
clusters without inferring a task's filesystem UID from its leader. A single
large process remains serial. Each worker retains its own verified scan-local
fd hints and can read the batch's task-specific first-snapshot hints during
the final snapshot. Negative fd scans need no shared lock;
positive records enter one mutex-protected owner/ambiguity accumulator, with one
global record cap, not a cap per worker. Both workers share the original
absolute deadline and join before a snapshot can be used. Spawn, join, poisoned
lock, incomplete enumeration, and deadline errors fail attribution. Resulting
owner tasks are sorted by TGID/TID before exact before/after comparison. The
second snapshot repeats enumeration from scratch; daemon-owned socket checks
still bracket each complete external scan. Parallelism reduces neither the
required proof nor worst-case work and may increase instantaneous CPU usage.
The exact fd path found by the ownership scan is
likewise only a performance hint:
runtime capture revalidates its symlink before reading identity metadata, falls
back to a bounded rescan of that same task's fd table when the hint vanished or
no longer names the target, and rechecks the selected symlink after identity
capture. A revalidation or fallback error fails attribution with the same
mode-specific consequence. A vanished procfs entry is skipped only after
disappearance is confirmed.
`PermissionDenied` on a TGID leader's fd table is skipped only after two bounded
`stat` reads confirm stable zombie state `Z`; every other error, non-zombie
state, or unconfirmed state fails attribution.
For runtime capture, `/proc/TID/exe` is opened and its complete file version is
compared with a second path/open snapshot together with the remaining process
metadata. Before issuing a successful backend-specific verdict, the reader
rechecks the current mode, generation, and shutdown flag under the engine lock;
the lock remains held through the actual verdict send. Its immutable
`Arc<ApplicationDecisionPolicy>` packet-policy cache contains all enabled
application rules in `Enforcing`, only enabled `Drop`/`Reject` application rules
in `Learning`, and is empty in `BlockAll`; it is rebuilt after a successful policy or learning
commit. The per-packet snapshot acquisition is therefore an O(1) `Arc` clone
instead of a clone of the complete state. The cache indexes rules by the complete
executable file version. A lookup scans only the policy-ordered candidate vector
for that exact version rather than all application rules. A root-edited or legacy
state can still place many rules under one pin, so candidate matching is linear
within that bucket. Learning uses a separate 512-item queue and persists at most
256 observations per batch. This is a rule-index cache, not a process-identity or
authorization-result cache. Apart from the established-TCP conntrack-generation
fast path described below, every enforcement packet still receives fresh
attribution. Learning-only duplicate suppression is bounded and invalidated by
policy generation; it may skip an observation but cannot authorize Enforcing
traffic. Its scheduling index has at most 512 entries and retries TCP observations after one second and datagrams after
100 ms rather than retaining failed or successful identities permanently.

Both backend compilers implement an early mark-sanitization step, the main
policy path, and a late authorization path. The following handshake describes
fail-closed queue 1337 in Enforcing and for application denies in Learning.
OpenShield reserves the upper two bits of
the 32-bit packet mark for its pending/handoff handshake and preserves the lower
30 bits through NFQUEUE, so existing lower-bit `fwmark` policy-routing and QoS
values are not discarded. On nftables, an `NF_ACCEPT` verdict leaves the pending
mark unchanged and processing continues into the later authorization base chain.
On iptables, `NF_ACCEPT` would terminate the filter hook, so the daemon returns
`NF_REPEAT` with an authenticated handoff mark; the first rule on the repeated
OpenShield OUTPUT path consumes that domain and transfers control to the
protocol-specific authorization chain. The daemon holds the policy-engine lock
from its final mode/generation recheck through verdict delivery and reinjection.
The netlink verdict socket is nonblocking: send-buffer exhaustion fails the
operation and triggers emergency quarantine instead of blocking every control
operation while the engine lock is held. Both backend paths clear the reserved
packet bits before the packet leaves the pipeline. The observational Learning
queue 1338 is instead placed late in the outbound path and always returns
`NF_ACCEPT`; on iptables its mangle/OUTPUT dispatcher is exactly once and last,
after pre-existing host marking, QoS, and policy-routing rules.

Successful application authorization writes an OpenShield domain plus the
current persisted, nonzero 30-bit policy generation into the low 31 conntrack
mark bits while preserving bit 31. TCP uses those low bits as a cache: the
original and reply directions of an established connection must carry that
exact current value. Mode changes and rule mutations that can revoke or alter
authorization advance the generation without reuse. In particular, creating or
enabling an outbound `Drop`/`Reject`, disabling an active rule, and updating or
deleting a rule invalidate established-TCP fast-path marks; inserting another
enabled `Accept` need not interrupt already authorized flows. An old conntrack
entry alone therefore does not keep a connection authorized after a
deny-affecting mutation. The fast path also requires `ct state established`, so
a pre-set mark on NEW traffic cannot skip the application queue.

Application-bound UDP, ICMP echo, and ICMPv6 echo do not use the mark as an
outbound cache. Before every original packet, the policy clears OpenShield's low
31 conntrack bits while preserving bit 31, then queues and attributes the packet
again. Successful authorization refreshes the current low-31-bit generation so
the matching reply can be accepted. This prevents another process from
inheriting an outbound authorization by reusing a UDP five-tuple while retaining
the unrelated high conntrack bit.

The persisted 30-bit generation advances monotonically by one and is never
reused before exhaustion. Exhaustion rejects mutations that need a new value;
transition to `BlockAll` remains available.

Packet-mark and conntrack-mark interoperability therefore differ. OpenShield
reserves the upper two packet-mark bits and preserves the lower 30. In the
conntrack mark it reserves the low 31 bits and preserves bit 31. Another
firewall, VPN, QoS, or CONNMARK scheme using those low conntrack bits can
overwrite or be overwritten by OpenShield and is not a supported combination;
coexistence is possible only for the preserved high bit after hook ordering has
been reviewed. Other components must also leave the upper two packet-mark bits
unused. A privileged earlier CONNMARK rule can still forge the current low-31-bit
value on an already-established TCP flow, so exclusive ownership of those bits
and compatible hook ordering are security requirements, not only compatibility
advice.

Both compilers use deny-before-allow ordering. Within the network-rule set and
within the application index, matches are ordered `Drop`, `Reject`, then
`Accept`; direct network denies run before the application fast path, and
application candidate envelopes are
queued before broader direct network accepts, so an overlapping allow cannot
override a matching deny or bypass a matching application constraint. `Reject`
is compiled as the native nftables `reject` or iptables/ip6tables `REJECT`
verdict, including after an application decision; it is not silently reduced to
`Drop`. A native rejection may itself traverse the local firewall. OpenShield
admits only an exact RELATED/REPLY TCP RST, IPv4 ICMP destination-unreachable /
port-unreachable, or IPv6 ICMPv6 destination-unreachable / port-unreachable
carrying the current nonzero 30-bit rejection generation in the OpenShield-owned
low-31 connmark domain, with the accept-domain bit clear. A policy-generation
change invalidates stale rejection attestations; no other RELATED shape receives
this exception.

Application candidate guards also run before every broader network `Accept`.
An UNTRACKED packet that matches the candidate's current tuple is dropped because
it cannot prove an original conntrack direction and enter attribution. If the
candidate constrains destination or port, a second guard drops a tracked packet
whose conntrack-original destination/port matches, even when local DNAT changed
the tuple seen by OUTPUT; the final output-interface constraint is retained.
This mismatch is conservatively fail-closed and may deny a translated flow
rather than attributing a rule written for the pre-translation endpoint.

## Dynamic active-policy path classification

The daemon derives a typed active-policy path classification from the validated
snapshot and returns it in `StatusV2`. The value is recomputed after every
committed mode or rule change and describes the worst-case, most expensive data
path which the current policy can exercise. It is not kernel-capability
attestation or runtime fallback negotiation for an otherwise identical policy:

- **L3 `KernelNative`** applies in `BlockAll` and in `Enforcing` when no enabled
  application-bound rule exists. The selected nftables or iptables compiler
  expresses the complete active filtering policy in kernel rules.
- **L2 `ConntrackHybrid`** applies in `Enforcing` when every enabled
  application-bound rule is TCP. A new TCP connection reaches NFQUEUE for
  process attribution; after successful authorization, packets in both
  directions must carry the exact current conntrack domain/generation and the
  established path remains in the kernel. The generated queue expression is
  TCP-scoped at this level: unrelated UDP and ICMP traffic is resolved by
  kernel network rules or the terminal kernel drop and never enters NFQUEUE.
- **L1 `Nfqueue`** applies throughout `Learning`, and in `Enforcing` when any
  enabled application-bound rule can match UDP, ICMP, ICMPv6, or `Any`.
  Enforcing and Learning application denies use mandatory fail-closed queue
  1337. Ordinary Learning observations use bounded asynchronous queue 1338
  with `bypass`; their failure loses evidence rather than connectivity. This
  level dominates L2 when both kinds of rule are present.
- **`Unknown`** is reserved for a legacy response or a runtime whose level has
  not been verified. It is never interpreted as one of the accelerated paths.

Disabled application rules do not affect the level. Network-only rules and
packets which match them remain kernel-native in Enforcing at L2 and L1.
Learning additionally observes eligible traffic even behind a network allow;
the reported value
is a conservative daemon-wide summary, not a statement that every packet takes
the same route. A successful mode or rule transaction recomputes the level from
the committed snapshot. Level selection does not relax selector conjunctions,
rewrite a rule, or substitute a network-only allow for an application rule.

Policy mode, firewall backend, and active-path classification are orthogonal
status dimensions. Startup first installs `BlockAll`. Its only automatic
backend fallback is from a fully validated nftables backend to the complete
iptables/ip6tables bundle when nftables is unusable. The same four status
values have the same meaning on both backends. Startup does not activate a
saved non-`BlockAll` policy until the NFQUEUE consumer and the other required
resources are ready. If NFQUEUE setup fails, the daemon retains `BlockAll` and
exits rather than starting with a network-only approximation. Learning's
explicit kernel `bypass` becomes reachable only after that startup transaction.
A later terminal queue failure requests emergency `BlockAll`; it never promotes
the level or adds bypass to Enforcing.

Normal `BlockAll` and emergency quarantine both execute a kernel-native deny
policy, but they are not operationally equivalent. `StatusV2` reports reason
`BlockAll` for the operator-selected mode and `EmergencyBlockAll` while the
engine is poisoned and read-only. The latter permits observation but rejects
all privileged mutations until recovery.

L3 is a description of the policy currently compiled into nftables or
iptables, not an eBPF implementation. OpenShield currently has no eBPF application
data plane, does not retain `CAP_BPF`, does not install a kernel module, and
does not modify boot parameters or MOK state. A future cgroup/BPF-LSM path must
have separate feature/load/attach/exercise probes, exact rule-equivalence tests,
and a fail-closed detach/downgrade transaction before it can introduce a higher
level or change these semantics.

## Modes

`BlockAll`

: Input, output, and forward hooks use a drop policy. No local or forwarded IP
  traffic is permitted. Local Unix-socket control remains available.

`Learning`

: Unmatched locally originated outbound traffic is allowed, while enabled
  explicit network and application `Drop`/`Reject` rules remain active. Network
  decisions stay on the direct kernel path; application-deny candidates use
  fail-closed queue 1337. Other eligible packets use observational queue 1338
  with `bypass` and asynchronous attribution; only the first eligible observation
  may await the bounded 250 ms capture opportunity described above.
  Successful attribution can persist an
  enabled, exact endpoint `Accept` rule and the disabled per-`(cgroup,path)`
  template. Failed or skipped attribution and recoverable learning persistence
  failures create no rule but do not deny the ordinary outbound packet. New
  inbound service traffic remains default-deny and can be admitted by an enabled
  inbound `Accept` rule. Exact built-in DHCP bootstrap and essential IPv6
  control-plane traffic are the only normal-mode exceptions; `BlockAll` has
  none. Conntrack replies to locally initiated Learning traffic are allowed.

`Enforcing`

: New inbound and outbound connections are default-deny. Enabled network-only
  rules are enforced directly by the selected backend. An application-bound
  outbound rule additionally requires fail-closed NFQUEUE identity attribution
  and applies its independent `Accept`, `Drop`, or `Reject` action. Denies are
  evaluated before allows. There is no blanket established-flow exception;
  only an application-authorized TCP flow with the exact current generation can
  use the established fast path. Other RELATED traffic requires an explicit
  rule; the sole generated-reply exception is the exact generation-attested
  native `Reject` response described above.

The built-in normal-mode input set is deliberately exact and precedes the
generic `INVALID`/default drop: DHCPv4 UDP 67-to-68 only to a broadcast
destination; DHCPv6 UDP 547-to-546 only from `fe80::/10`; hop-limit-checked
Router Advertisement, Neighbor Solicitation/Advertisement, and link-local MLD
query forms; and the enumerated non-spoofable RELATED ICMPv6 errors required by
IPv6 operation. It is absent in `BlockAll` and is not a general service allow.

In `BlockAll`, the forward path drops before delegation. In `Learning` and
`Enforcing`, OpenShield returns forwarded traffic to the pre-existing firewall
policy; it neither accepts forwarded traffic nor provides forwarding-rule CRUD.

Mode and rule changes are compiled into a complete backend policy. The preferred
nftables path checks it with `nft --check`, then replaces the dedicated table in
one atomic transaction. The compatibility path uses fixed, validated
`iptables`/`ip6tables` command, restore, and save bundles. It owns only
`OPENSHIELD_*` chains and uses restore with `--noflush`. Filter dispatch jumps
are first in the built-in INPUT, OUTPUT, and FORWARD chains. The mangle OUTPUT
mark sanitizer is first, while a distinct Learning-observation dispatcher is
required exactly once and last, after pre-existing host mangle rules. Thus a
plain Learning `NF_ACCEPT`, queue bypass, or accept-on-overflow cannot skip host
marking, QoS, or policy-routing work. Because
xtables cannot atomically update IPv4 and IPv6 together, both families enter
`BlockAll` before the two validated family transactions; a replacement can
temporarily deny traffic but must not create a cross-family authorization
window. Both compilers place enabled outbound `Drop` rules first, native
`Reject` rules second, and `Accept` rules last; inbound policy accepts enabled
`Accept` rules and the exact built-in normal-mode bootstrap/control set, then
denies other new traffic. An apply or verification
failure escalates back to emergency `BlockAll`.
Runtime counters reset on a successful replacement. State is stored in the
root-owned `0600` `/var/lib/openshield/state.json` using a same-directory
temporary file, `fsync`, and atomic rename; unsafe ownership, permissions, file
types, and symbolic links are rejected. Exact argv in learned selectors can
contain secrets, so this file and its backups are confidential; non-root
observation redacts application selectors. A semantic 8 MiB encoded-state quota is checked before backend
application, independently of the 10,000-rule total count limit. Automatic
insertion stops when exact learned rules plus templates reach 7,500, normally
leaving 2,500 count slots for privileged manual rules; this admission budget is
not a validation invariant for root-edited or legacy state. Root can still fill
the total limit through manual mutations. Rule ordering is
revision-based. If UTC moves backwards, rule
update timestamps are clamped to their prior value so clock correction cannot
make otherwise valid privileged mutations unavailable.

State and IPC compatibility is forward-only from v0.2.0 to v0.2.1. The v0.2.1
reader maps an absent rule `action` to `accept`, but v0.2.0 rejects the new
`drop`/`reject` actions and `template` origin. Mixed daemon/TUI versions and an
in-place downgrade after v0.2.1 has written state are unsupported. Upgrade and
rollback require a protected console, active kernel `BlockAll`, a reviewed state
backup, and a distribution-tested procedure.

The monitor reads bounded backend-specific chain and counter state once per
second rather than serializing every compiled rule. The iptables path compares
the complete OpenShield-owned rules with the last verified transaction;
the nftables path requests tables, chains, and counters in one fixed `nft`
process, parses exactly three ordered bounded JSON documents, and verifies the
owned table, base hooks, default-drop policies, and named counters. Combining
the three nftables reads removes two process launches but does not change the
one-second cadence, validation invariants, output bounds, or fail-closed repair.
Application learning is fed
by the separate bounded NFQUEUE worker described above. Deduplication builds one
O(N) index for the batch, and one batch persists at most 256 new automatic rules,
counting both endpoint rules and group templates. A new attributable endpoint is
stored as an enabled `Accept` rule. If its exact `(optional cgroup path, executable path)`
group has no template, the same transaction first creates the disabled,
network-unconstrained `Accept` template described above. Automatic
insertion also stops at 512 learned rules per filesystem UID and 256 per pair of
filesystem UID and full executable file-version identity. These are admission
budgets, not absolute state invariants. They use the numeric filesystem UID;
distinct subordinate UIDs count independently and can distribute learning until
the global budget is reached. The engine keeps a second immutable
`ApplicationLearningAdmissionIndex` and rebuilds it together with the packet
policy at startup and after every successful normal, learning, or emergency state
replacement. After mandatory race-checked procfs attribution, it rechecks poison
state, mode, generation, index revision, and persistence status under the engine
lock. The index recognizes exact learned outbound keys and the total, global
learned, per-filesystem-UID, and per-UID/file-version counts. Exact-known,
saturated, and persistence-paused observations do not enter the 512-item queue;
only a potential new candidate is enqueued. Queue full or disconnect discards
the observation but retains Learning's outbound `Accept` verdict. The worker
also coalesces exact duplicates in each bounded 256-observation drain. This keeps
known or necessarily discarded observations from consuming queue capacity, but
does not avoid attribution for a packet already delivered to userspace. A saturated endpoint has no new rule
persisted, so the same traffic is denied after a switch to Enforcing unless
another rule matches. Ten thousand total rules
and 8 MiB are independent absolute state limits. Reaching the byte quota or a
recoverable save failure discards the current batch and pauses all further
automatic learning in that daemon process until a successful privileged policy
mutation or a restart; Learning's default allow for unmatched outbound traffic
remains in force while enabled explicit denies still apply. An argv or unified-v2 cgroup change creates a distinct endpoint
candidate rather than widening an existing learned selector; a cgroup/path
change also selects a different template group. Operators must therefore conduct
Learning in a controlled window and review exact endpoint rules and broad,
disabled templates before Enforcing.

Application Learning uses a serialized two-phase persistence transaction.
Under the `Engine` mutex the worker validates the base state, builds the
candidate and events, reserves persistence, and installs the pending-candidate
admission index. Atomic save and file/directory `fsync` then run without that
mutex, keeping packet snapshots, admission, and verdict rechecks live during
storage latency. Exact endpoints in the pending candidate are deduplicated.
Finalization reacquires the mutex, verifies the transaction token and exact base
state, and publishes state and events only after durable commit. Other
privileged mutations return `Conflict` while persistence is reserved. Root
`BlockAll` is the exception: it installs the kernel deny immediately, then
persists the combined blocked state after the learning write and supersedes its
finalizer. Recoverable failures retain the prior state and pause persistence;
unsafe storage, rollback, or base-state outcomes enter fail-closed quarantine.

After a save error the daemon rereads authoritative state: an exact previous
snapshot is left untouched, while a candidate or unknown result is rolled back.
Only an ambiguous result together with failed rollback escalates to `BlockAll`. This keeps health
and learning work bounded. The nftables lightweight observation does not compare
complete rule bodies; a privileged targeted edit or additional allow can evade
it. The iptables comparison is stricter for owned chains, but no monitor makes
arbitrary concurrent privileged firewall editors a supported configuration.

## Performance verification model

The isolated harness in [`tests/perf`](../tests/perf/README.md) exercises the
same nftables and, where the kernel supports it, iptables/ip6tables paths as the
daemon. Network-only policy is measured in both `Learning` and `Enforcing`;
outbound application TCP and UDP use privileged exact rules in `Enforcing`,
while Learning exercises observational attribution and durable creation of its
enabled endpoint rules and disabled templates under the outbound allow-all
policy. The DUT creates the real
`/var/lib/openshield` directory in its writable container overlay rather than a
`tmpfs`, so the production atomic-rename and `fsync` state path is exercised.
State and learned rules survive phase-client exits and daemon control
transactions within one backend topology, but that disposable writable layer
is not reused by a later independent harness run.

Warm-up, every ramp step, every steady repetition, and burst each start an
independent client process and initial socket set. The server remains alive for
the whole load point. Application TCP fast-path evidence is collected inside
each phase: a keep-alive connection first crosses NFQUEUE for process
attribution and then carries multiple request/response operations under the
current conntrack generation. No established connection is carried across a
phase boundary. A bounded 50--3,600,000 ms weighted lifetime distribution is
selected deterministically for every persistent connection. Expiry closes and
reopens an ordinary TCP socket between completed exchanges, producing a real
new conntrack/NFQUEUE attribution path without interrupting in-flight work;
short-connection profiles validate but otherwise ignore the lifetime. Each
exact backend/policy/mode/profile/load group has three predetermined,
independent baseline/protected pairs. Every pair has unique pair and baseline
sample identities, uses its baseline exactly once, and runs its sides in
separate pristine DUT generations. The daemon is never started on the baseline
DUT. Pair order is fixed before measurement and balanced AB/BA, and a protected
block may use only its assigned immediately adjacent baseline. Both sides use
identical offered parameters and a policy-independent deterministic trace seed;
conntrack is flushed before each baseline and policy load point. The
conservative comparison gap is the maximum temporal separation across the
authenticated workload interval and the synchronized DUT and peer metric
intervals. It must not exceed 15 seconds in CI or 90 seconds in the
production-like profile.

The configuration, synchronized metrics, and baseline-pairing contracts are
versioned as `openshield.perf.config.v2`, `openshield.perf.metrics.v3`, and
`openshield.perf.baseline-pairing.v2`. The result model separates validity,
capacity, and safety. Generator CPU or
scheduler saturation and peer/server CPU, rejection, or protocol saturation
invalidate a window; an invalid baseline propagates to its pair. Valid windows
then have formal configured gates for target attainment, latency, loss,
retransmits, daemon CPU/RSS, interface errors, NFQUEUE drops, and expected queue
shape. Repeated wrong-executable probes during application bursts and direct
kernel inspection of a reported quarantine prevent a fail-open result from
passing. Every executed invalid result row fails the complete report rather
than being silently excluded; invalid points also cannot become capacity
evidence. A production maximum requires three successful steady repetitions.

Relative performance uses those independent adjacent pristine AB/BA pairs.
Every window delta and threshold crossing is preserved as evidence. The
v0.2.2 CI thresholds remain 10% for throughput, PPS, CPU, and latency. The
arithmetic mean of three independent paired steady deltas blocks release for
throughput and PPS when it exceeds the threshold. The release-smoke setting
`cpu_latency_relative_regressions_are_advisory: true` records CPU and latency
crossings as warnings; the production-like profile retains blocking checks for
all four dimensions. A one-sided 95% Student-t lower confidence bound records
stronger confirmation but cannot override a blocking mean threshold. A single burst has no
repeated-sample confidence claim, so its relative crossing is diagnostic only;
its validity, configured capacity bounds, and safety remain mandatory. Safety
signals such as loss, retransmits, NIC or NFQUEUE
drops/errors, and fail-open behavior fail immediately and are not subject to
the statistical relative decision. Host `/proc/softirqs` counters are not
namespaced or attributable to the daemon; they are interpreted only as a
paired-baseline delta on a quiet runner. The bounded release smoke follows
the functional firewall E2E jobs, but its three short steady repetitions
validate the path and safety gate rather than certifying a capacity maximum.

A separate configured overload gate deliberately stops the daemon with
`SIGSTOP`, drives real application TCP and UDP until the bounded NFQUEUE shows
at least the required combined kernel/userspace drop count, and repeatedly
tests a different executable while the consumer is stalled. The pressure
client first publishes readiness and waits at an explicit start barrier. A
separate network-only endpoint on the same canary veth and transport must
complete a real round trip immediately before and after every negative probe;
resource saturation or socket/NIC errors at the generator, peer, or canary make
the proof invalid. `SIGCONT` is attempted in a `finally` path, with
disposable-container teardown as the outer fallback. After resume, the daemon
must either retain `Enforcing` and pass an allowed-traffic recovery exchange or
expose a `BlockAll` quarantine independently verified in the selected kernel
backend. A reported quarantine additionally requires bracketed real TCP and UDP
negative probes while loopback round trips inside the canary container prove
both peer servers healthy immediately before and after each probe. The
different executable must remain blocked both during and after the stall. This
controlled test is a fail-closed stress proof and is kept out of capacity
calculations. Its TCP pressure payload forces short connections, so the
inherited validated keep-alive lifetime distribution cannot reduce NFQUEUE
saturation pressure.

## Trust boundaries

The daemon trusts the Linux kernel, UID 0, and the selected fixed system backend
executables. nftables is preferred only after a read-only preflight verifies
the previous xtables state, table ownership, the exact bounded JSON table,
chain, and counter queries needed by runtime observation, and a representative
Learning policy with the kernel's check-only transaction. The fallback requires
complete trusted IPv4 and IPv6 xtables bundles. Executable
paths come from compiled allowlists, are metadata-checked, and are invoked with a
cleared environment and typed arguments, never a shell. The daemon does not load
plugins, scripts, downloaded policy, eBPF objects, or configuration-selected
executables. User-provided values become firewall syntax only after parsing into
typed IP networks, ports, protocols, directions, and a strictly validated
interface name. Application values remain typed identity data and are never
interpreted as commands.

The packaged systemd process retains `CAP_NET_ADMIN`, `CAP_NET_RAW`,
`CAP_SYS_PTRACE`, and `CAP_DAC_READ_SEARCH`. It keeps primary group `root` and
explicitly adds `openshield` as a supplementary group. As the socket owner it
assigns that group to a new observation socket without `CAP_CHOWN`. Legacy
xtables needs `CAP_NET_RAW` to open the
raw IPv4/IPv6 sockets used for alternate-backend inspection and fallback;
the last two capabilities let procfs access checks permit identity inspection
across local UIDs. Its syscall filter explicitly denies `ptrace`, `process_vm_readv`,
`process_vm_writev`, `kcmp`, `pidfd_getfd`, and `open_by_handle_at`, and it does
not normally read process memory or environments. This deny list is not memory
isolation: `CAP_SYS_PTRACE` can authorize a compromised daemon to open
`/proc/<pid>/mem`, after which ordinary read/write syscalls remain available.
Together with `CAP_DAC_READ_SEARCH`, procfs magic links such as
`/proc/<pid>/root` can also expose another process's mount view despite service
mount restrictions. The retained capabilities therefore materially expand the
impact of a daemon compromise and are inside the trusted computing base.

The service exposes `ProcSubset=all` on an explicitly read-only `/proc` while
retaining `ProtectProc=invisible`. `subset=pid` hides the nested NFQUEUE progress
file even through `/proc/self/net`, so it is incompatible with reply scheduling.
Queue setup validates this entry against the bound OUTPUT netlink owner before
any worker or desired-policy activation. Failure retains bootstrap `BlockAll`
and prevents readiness. General procfs metadata is consequently more visible;
read-only mounts are not a substitute for the capability/LSM threat boundary.

The observation API reveals firewall mode, rules, aggregate one-second counters,
and learned network endpoints only to root and members of `openshield`. For an
authorized non-root observer, all application metadata and identifying rule
names are redacted by the daemon. UID 0 can read the full rule, including
bounded command-line selectors. Runtime attribution reads bounded procfs
identity metadata and a bounded queued-packet prefix, but never the process
environment; version 0.2.2 does not provide a per-packet capture feed.

## Failure policy

Network-only decisions stay in the selected kernel backend. In `Enforcing`,
initial application decisions use the fixed bounded NFQUEUE without queue
bypass. A missing, overloaded, or failed consumer therefore denies queued
Enforcing traffic instead of allowing it. In `Learning`, the queue is
observational and uses `bypass`; parsing/attribution failure, queue pressure, or
a recoverable persistence failure may lose evidence but does not block ordinary
outbound traffic. A terminal queue or policy-integrity error can still ask the
engine to install emergency `BlockAll` and stop the daemon. A crashed or
overloaded TUI has no effect on either path.

On every daemon start, the engine first installs kernel `BlockAll`, then loads
state and increments the persisted nonzero 30-bit flow generation by exactly
one. During the first v0.2.1 start over v0.2.0 state, it also adds missing
canonical disabled templates for existing Learned `(optional cgroup,path)`
groups. Migration is additive: it respects the automatic-rule, total-rule, and
8 MiB state limits and never removes an existing endpoint rule when no room
remains. The resulting state is persisted before the requested policy is
applied. The monotonic counter is
not reused before exhaustion, so conntrack authorization marks from every
earlier daemon process are invalid. Exhaustion retains `BlockAll` and fails
startup instead of wrapping. This startup quarantine also applies when the
daemon is invoked directly without the packaged `ExecStartPre` helper.

Missing state is initialized and persisted as `Learning`, while kernel
`BlockAll` remains active until that new policy can be activated. Invalid or
unsafe existing state causes the daemon to retain `BlockAll`, keep IPC sockets
closed, and exit with failure. Automatic restart attempts continue to fail
closed and cannot reach readiness until the operator repairs the state. If
runtime backend objects disappear or differ from verified invariants, the
monitor attempts to reinstall the current validated snapshot;
failure escalates to emergency `BlockAll`. The emergency state keeps the last
validated rules as policy data while its mode provides no accept path. If that
state is persisted, the daemon asks the service manager for a restart. If
persistence itself fails, it deliberately stays alive in a poisoned read-only
quarantine with kernel `BlockAll` active; automatically restarting could
otherwise load an ambiguous permissive file.

Graceful daemon shutdown installs kernel `BlockAll` without persisting a mode
change. The systemd, OpenRC, SysVinit, runit, s6, and dinit integrations provide
corresponding pre-start and post-stop quarantine hooks. Their ordering is a
service-manager boundary, not proof of coverage for initramfs or early traffic.

The packaged systemd unit also installs `BlockAll` in `ExecStartPre` and
`ExecStopPost`. Its main
process uses `Type=notify` and sends `READY=1` only after the persisted policy is
active, both fixed NFQUEUE consumers are bound, and the fixed IPC sockets have
been verified. It requires
`systemd-tmpfiles-setup.service`; the package's
tmpfiles rules create root-owned runtime/state directories and the standard
`0600` `/run/xtables.lock`, then relabel those exact paths without recursively
touching their contents. The unit grants write access only to those paths
instead of all of `/run` or `/var/lib`.
Its `[Install]` section contains
`RequiredBy=network-pre.target`; after `systemctl enable openshield-daemon`, that
success dependency combines with `Before=network-pre.target` so a standard
consumer cannot proceed through the target unless the daemon reaches readiness.

This boundary applies only after the unit is enabled and only to consumers that
honour `network-pre.target`. A network manager, unit, initramfs, or early packet
path that bypasses the target also bypasses the dependency. Strict whole-boot
enforcement therefore requires tested distribution-specific integration or an
initramfs policy.
