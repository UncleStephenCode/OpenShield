[English](README.md) | [Русский](README.ru.md)

# OpenShield

Current source release: **v0.2.1**.

OpenShield is a local, application-aware Linux host firewall written in Rust.
It consists of a privileged daemon and a terminal user interface (TUI). The
daemon prefers nftables and automatically falls back to a complete
`iptables`/`ip6tables` tool set when the fixed, trusted `nft` executable or the
running kernel cannot validate an nftables policy.

OpenShield is a focused Rust port of the OpenSnitch security model, not a
line-by-line replacement. It does not load the original Python/Go plugins,
execute configuration-selected programs, or accept the legacy rule format. The
audit and port started from the local `../opensnitch` revision
`a1353848ba1b660320e90cefea782c3fba272c00` (2026-07-27). The copied `LICENSE`
has the same SHA-256 digest as that revision.

The workspace uses Rust 1.98.0, edition 2024, and forbids `unsafe` Rust in
workspace code.

## Policy modes

| Mode | Local input | Local output | Forwarding |
| --- | --- | --- | --- |
| `BlockAll` | drop | drop | drop |
| `Learning` | default-drop for new connections; explicit inbound allows, narrow host-bootstrap/control exceptions, plus conntrack replies to locally initiated flows | allow unmatched traffic and apply enabled explicit `drop`/`reject` rules; supported attributed traffic creates enabled `accept` rules and disabled application templates | return to the pre-existing firewall policy |
| `Enforcing` | default-drop; explicit inbound allows, narrow host-bootstrap/control exceptions, replies bound to a currently authorized outbound flow, and narrowly authenticated native `Reject` replies | default-drop; enabled outbound rules apply `accept`, silent `drop`, or active `reject` | return to the pre-existing firewall policy |

A machine with no state file gets a persisted `Learning` policy. This does not
create a fail-open startup window: every daemon start first installs a temporary
kernel `BlockAll` quarantine. The saved policy is activated only after it has
been validated, all three fixed NFQUEUE consumers are ready, and all required local
prerequisites are available. Queue 1337 is fail-closed for `Enforcing` and for
explicit application-bound denies in `Learning`; queue 1338 is the bounded,
observational `Learning` queue. Fail-closed queue 1339 can briefly defer eligible
UDP/ICMP replies while an outgoing decision is pending, then repeat the current
INPUT policy; it never authorizes a packet itself. An existing saved mode is preserved.
While startup `BlockAll` remains active, the first v0.2.1 load of v0.2.0 state
adds missing disabled application-group templates within the automatic-rule,
total-rule, and 8 MiB limits; existing learned endpoint rules are never removed
to make room. The migrated state is persisted before policy activation.

Graceful shutdown installs kernel `BlockAll` again without overwriting the saved
mode. Service-manager pre-start and post-stop hooks provide the same quarantine
around daemon failures. A forced kill or kernel/backend failure cannot provide a
universal persistence guarantee; operational recovery must therefore use a
local console or independent out-of-band access.

Learning attempts to attribute supported outbound TCP, UDP, ICMP echo, and
ICMPv6 echo traffic, but it no longer uses successful observation as the
default allow condition. Unmatched outbound traffic is allowed while the live
policy remains `Learning`; missing, ambiguous, oversized, unsupported,
timed-out, or queue-saturated observation creates no rule instead of blocking
ordinary traffic. Queue 1338 performs attribution asynchronously and has kernel
bypass and fail-open queue flags. The first eligible TCP SYN or datagram of a
recently unseen flow can wait up to 250 ms for an attribution attempt; repeat
observations are accepted immediately. Expiry or backlog does not deny ordinary
traffic while the same `Learning` generation remains active. Enabled explicit
network `drop`/`reject` rules remain active in the kernel. Traffic inside an
enabled application-deny envelope instead enters fail-closed queue 1337; a
matching deny is applied and an unresolved candidate is conservatively dropped,
except that a kernel UID false-positive is admitted and deferred to best-effort
observation. `Enforcing` never uses the observational bypass and remains
fail-closed. Inbound traffic is never learned automatically. New inbound
connections still require an explicit allow rule except for the built-in normal-mode
bootstrap/control-plane set: DHCPv4 server-to-client replies only to a broadcast
destination, DHCPv6 server-to-client replies only from a link-local source, and
the narrowly enumerated IPv6 NDP, Router Advertisement, MLD-query, and required
RELATED error traffic. `BlockAll` contains none of these exceptions.
Automatic insertion stops when exact learned rules plus generated templates
reach 7,500, when exact learned rules reach 512 for one filesystem UID, or when
they reach 256 for one filesystem UID and full executable file-version identity.
These are admission budgets, not validation
invariants for a legacy or root-edited state. The 10,000-rule total normally
leaves 2,500 count slots for root-created rules, although root can still fill the
total manually. Budgets use the numeric filesystem UID, so distinct subordinate
UIDs count independently and can distribute activity until the global budget.
Traffic that reaches a learning quota remains allowed in Learning but is not
persisted and is therefore denied in Enforcing unless another enabled `accept`
rule matches. The separate 8 MiB state limit still
applies. Reaching that byte limit or a recoverable save failure discards the
current batch and pauses automatic persistence until a successful root mutation
or daemon restart; otherwise eligible, successfully attributed `Learning`
packets remain allowed but create no new rules while persistence is paused. An
immutable current-policy admission index also keeps exact-known and saturated
observations out of the 512-item persistence queue; only a new candidate consumes
a queue slot.

Application Learning uses a two-phase durable commit. Candidate preparation,
admission reservation, and a pending-candidate admission index run under the
engine lock; atomic save and file/directory `fsync` run after releasing it, so
packet verdicts do not wait for storage latency. The pending index deduplicates
exact observations already covered by the in-flight candidate. State and events
are published only after the durable commit. Other privileged changes receive
`Conflict` while it is in flight. Root `BlockAll` instead installs the kernel
deny immediately and is serialized last, preventing the older learning write
from restoring Learning. A recoverable save failure retains the previous state
and pauses automatic persistence; an unsafe outcome enters fail-closed
`BlockAll` quarantine.

## Dynamic active-policy path

Since OpenShield 0.1.31, the daemon reports a dynamically recomputed
active-policy path classification in its `StatusV2` response. This is not kernel-capability
attestation, compatibility negotiation, the policy mode, or the selected
firewall backend. It identifies the most expensive active path required by the
current policy. A lower-numbered value describes a more userspace-intensive
path, not weaker enforcement and not a runtime fallback for the same policy:

| Level | Reported name | Active policy path |
| ---: | --- | --- |
| L3 | `KernelNative` | `BlockAll`, or `Enforcing` without an enabled application-bound rule; filtering is compiled directly into the selected kernel firewall backend |
| L2 | `ConntrackHybrid` | `Enforcing` with enabled application-bound TCP rules only; the first packet is attributed through NFQUEUE and established TCP uses the current conntrack-generation fast path |
| L1 | `Nfqueue` | `Learning` uses bounded asynchronous observations, while `Enforcing` with an enabled application-bound UDP, ICMP, ICMPv6, or `Any` rule requires fresh userspace attribution for otherwise-unmatched packets |
| — | `Unknown` | a legacy status response or an unverified runtime; the UI must not present it as an accelerated path |

The level is deliberately a worst-case summary. Network-only packets continue
to be handled by nftables or iptables in the kernel even when the reported
level is L2 or L1. Rule and mode changes recompute the level from validated
state; they do not turn a strict application selector into a broader network
allow.

An operator-selected `BlockAll` reports reason `BlockAll`. If an ambiguous
backend or persistence outcome forces the live daemon into its read-only
fail-closed quarantine, the same L3 kernel path is reported with the distinct
reason `EmergencyBlockAll`; the TUI highlights it as an emergency rather than
as a healthy accelerated state. Privileged mutations remain disabled until the
documented recovery procedure is completed.

Backend selection is a separate startup decision. The only automatic startup
backend fallback is from nftables to the complete iptables/ip6tables bundle
when nftables cannot be validated. Neither choice changes the active-path
semantics. If the NFQUEUE
runtime cannot be made ready, startup retains `BlockAll` and exits; it never
continues with a network-only approximation. Queue bypass is compiled only for
the observational Learning queue; neither Enforcing nor the Learning
application-deny queue enables it.

This release does not enable an eBPF application data plane. It neither grants
`CAP_BPF`, changes the boot command line, enrolls a MOK, nor requires a custom
kernel module. Kernel eBPF/cgroup/LSM acceleration remains future work until its
rule equivalence, lifecycle downgrade, packaging, and distribution-kernel tests
can demonstrate the same fail-closed behavior.

## Application-bound outbound rules

An enabled application selector always includes a canonical executable path and
a persisted file-version identity: device, inode, size, and change time in
seconds and nanoseconds. The only unpinned form accepted in persisted state is
an automatically generated disabled group template. Optional selectors constrain the filesystem UID, the exact
unified-cgroup-v2 path, and an exact or prefix command line. The command line is
represented as a JSON array of strings, so token boundaries and empty arguments
are preserved. Every supplied application and network field is combined with
logical AND.

For a root-created rule, the daemon must resolve the path in its own mount
namespace. It repeatedly canonicalizes and opens a regular file, fills an omitted
version pin, and rejects a supplied stale pin or an unresolvable path. The TUI
therefore sends no pin for a new or changed path and carries the complete old pin
when the path is unchanged, so a concurrent executable replacement rejects the
edit instead of silently authorizing new code. A learned rule pins the observed
canonical path, complete file version, filesystem UID, exact tokenized argv,
and, when available, the single unified-cgroup-v2 path. On cgroup v1 the cgroup
field is absent while the other fields remain enforced.

For each newly observed application grouping identity, Learning also creates one
disabled `accept` template containing only the canonical executable path and,
when available, its unified-cgroup-v2 path. It has protocol `Any` and no network,
port, interface, argv, UID, or persisted file-version selector. Enabling that
template is a privileged operation: immediately before committing the change,
the daemon resolves and pins the current executable version using the same
race-resistant path checks as a manually created rule. The template is inert
until enabled and then deliberately grants that application unrestricted
outbound network access. Disabling an unchanged template restores its canonical
unpinned skeleton, and every later enable repins the then-current file. A
Template edited into a non-skeleton rule and other disabled rules retain their
complete specification and pin.

Exact argv can contain credentials, tokens, or other secrets. Learning persists
it in the root-owned `0600` `/var/lib/openshield/state.json`; non-root observation
redacts application selectors. Protect the state file and its backups. A change
to argv or the unified cgroup path intentionally stops the learned selector from
matching and requires a separate rule or a reviewed root edit. Treat Learning as
a controlled capture window and review learned rules before Enforcing.

The daemon attributes a queued packet from the kernel-reported UID and network
tuple, requires one unambiguous socket inode and process owner, and performs
bounded repeated checks of `/proc` metadata. It enumerates descriptor tables
only for tasks whose filesystem UID equals the kernel socket UID, groups matching
holders by process. In Enforcing, incomplete candidate scans, multiple process
owners, changing identity, or exhausted bounds deny the packet. The same
failures in an ordinary Learning observation skip rule creation rather than
deny the packet; the initial observation wait is bounded as described below.
Learning application-deny candidates are a deliberate
exception: they use fail-closed NFQUEUE 1337 and deny on unresolved attribution
inside the candidate envelope, apart from a kernel-UID mismatch that is accepted
and deferred to best-effort observation. The separate Learning NFQUEUE 1338
hands bounded attribution to an asynchronous worker; it has queue bypass and
an accept-on-overflow policy. At most 128 first observations may await completion
or a 250 ms deadline. This is a userspace deadline, not a hard real-time bound
under scheduler starvation or policy-lock contention. The reader polls pending work at 5 ms intervals rather
than blocking on `/proc`; later observations are accepted immediately. Releasing
a pending packet requires the same current `Learning` mode and generation under
the policy lock; a mode/generation change or shutdown drops it. TCP authorization
in Enforcing is tied to a persisted 30-bit policy
generation that increases by one and is not reused before exhaustion; UDP and
ICMP are re-attributed for every otherwise-unmatched outbound packet.

Since v0.1.32, fail-closed decisions and asynchronous Learning observations can
be attributed in bounded batches of at most 32 already-ready items; neither path
waits to fill a batch. Each item still gets an independent `SOCK_DIAG` socket
lookup. Only the complete procfs owner
enumerations are shared: one snapshot before identity capture and one after it.
The entire batch has one absolute deadline: 2 seconds for queue 1337 (including
userspace queue wait, not time already spent in the kernel queue) and
5 seconds for asynchronous Learning attribution. Each `SOCK_DIAG` lookup is
additionally capped at 250 ms, without extending the batch deadline. These are
work limits, not intentional delays. Even a single-item batch performs both
owner snapshots; each snapshot has a global cap of 131,072 owner records across
all targets. An identity may be
reused only inside that batch for the same socket
inode, socket UID, and capture requirements, and duplicate requests must agree
on PID, process start time, executable path and complete file version, and UID.
A typed timeout remains visible in NFQUEUE counters. In Enforcing, and inside a
Learning application-deny envelope, ambiguity, a changed owner snapshot, a missed
deadline, or an exceeded bound denies the affected packet. On observational
queue 1338 it prevents persistence, not Learning's ordinary allow decision.
Pinned fd-directory handles, reusable directory/link buffers, and verified
batch-local fd-number hints reduce filesystem lookup and allocation overhead;
they do not replace either complete owner snapshot. There is no cross-batch
identity or authorization cache, so otherwise-unmatched Enforcing UDP/ICMP
traffic is attributed again in every later batch.

Queue 1337 now has a separate bounded reader and exactly one attribution worker.
At most 128 packets are waiting or in flight in userspace, with one batch of at
most 32 being resolved. Round-robin scheduling between socket UIDs and flows uses
a four-packet quantum; these keys affect scheduling, never authorization. Safe
decisions that need no process identity are returned at dispatch without waiting
for that batch's procfs scan. A reply waits until OUTPUT has received and
classified packets through its fixed kernel sequence boundary, and actual
verdicts for the matching flow and all unclassified packets through that boundary
are complete. Known unrelated flows do not delay it. The global completed prefix
still controls bounded slot retirement. Release uses only `NF_REPEAT`, not an
allow verdict; current kernel policy decides delivery. Policy mode, generation
and shutdown are checked again before sending.
The journal's `application attribution stage timings` aggregates report bounded
stage wall times about every ten seconds during activity, without process names,
arguments or network addresses. This is diagnostic evidence, not a claim that
the remaining CPU and latency problem is resolved; no eBPF path is enabled.

With at least 64 external tasks across two or more processes and at least two
available CPUs, each owner snapshot uses at most two scan workers (the resolver
and one scoped helper). Small process sets and single-process workloads stay
serial. All PID/TID entries are enumerated under one global task bound before
dispatch; workers share the absolute deadline, owner-record cap, and ambiguity
tracking. Whole-process partitions preserve sibling checks and deterministic
owner ordering. An incomplete scan or worker failure remains fail-closed.

The first-observation wait improves the chance of learning short-lived TCP and
UDP request/response clients, but it is not an exec/socket event recorder. A
fire-and-forget UDP sender may return from `sendto()` and exit before procfs
attribution completes, even while its packet is queued. Such traffic remains
allowed in Learning but may create no rule. Verify learned rules before enabling
Enforcing; see the [isolated short-lived application regression](tests/compat/README.md#short-lived-application-regression).

These selectors identify observed process metadata, not all code executing in
the process. The version pin detects ordinary in-place rewrites through size or
change-time differences, but dynamic loaders, interpreters, scripts, plugins,
JIT code, mount-namespace aliases, descriptor transfer, and post-queue `exec`
remain explicit trust boundaries. This mechanism is not cryptographic software
attestation. Older serialized two-field device/inode application pins are rejected
rather than silently upgraded; network-only state remains compatible. Review and
recreate affected rules from a protected console.
See the [threat model](docs/THREAT_MODEL.md) before relying on application rules
as a security boundary.

Activation and action are independent fields. `enabled: false` makes a rule
inert. In either normal mode, an enabled outbound rule can `accept`, silently
`drop`, or actively `reject` matching traffic using the selected backend.
`Learning` supplies a default allow for unmatched traffic and creates successful
learned endpoint rules with `accept`, but it does not override enabled explicit
`drop` or `reject` rules. Inbound
rules remain accept-only. When v0.2.1 reads a rule without `action`, it uses
`accept` and omits that default from canonical JSON.
The backend uses a deterministic deny-before-allow order so a broad accept rule
cannot override a matching drop or reject rule.

The native response generated by `reject` is admitted through default-deny only
for an exact RELATED/REPLY TCP RST, ICMP port-unreachable, or ICMPv6
port-unreachable carrying the current generation-bound OpenShield connmark.
Policy-generation changes invalidate stale attestations; other RELATED traffic
gets no exception. Before a broader network accept, application envelopes also
drop matching UNTRACKED current tuples and, for destination/port constraints,
matching conntrack-original tuples after local DNAT while retaining the final
output-interface constraint. The conservative guard may deny a translated flow
rather than bypass application attribution.

State and IPC compatibility is forward-only from v0.2.0 to v0.2.1. The new
reader accepts an absent `action` as `accept`, but v0.2.0 cannot parse v0.2.1
`drop`/`reject` actions or the `template` origin. Mixed daemon/TUI versions and
an in-place downgrade after v0.2.1 has written state are unsupported. Perform
upgrade or rollback from a protected console with kernel `BlockAll` active, a
reviewed state backup, and a distribution-tested procedure.

## Local access control

The daemon exposes no TCP management endpoint. It creates two Unix sockets in
the root-owned `/run/openshield` directory:

| Path | Owner and mode | Authorization |
| --- | --- | --- |
| `/run/openshield/control.sock` | UID 0, `0600` | mode and rule mutations; Linux `SO_PEERCRED` must report UID 0 |
| `/run/openshield/observe.sock` | `root:openshield`, `0660` | read-only status, rules, events, and counters; peer must be root or a member of `openshield` |

Observation is not public. The daemon authenticates the peer with
`SO_PEERCRED`; for a supplementary-group match it reads the peer's bounded procfs
credentials twice and verifies a stable process start time. Filesystem mode
alone is not treated as authorization. Non-root observers receive redacted
application selectors and redacted names for application rules. Mutation
requests are rejected on the observation socket regardless of the client.
Authorization occurs when the Unix connection is accepted; a group member can
pass an already-connected socket fd to another process. Treat group membership
and processes running in those sessions as part of the monitoring trust boundary.

The package must create the system group before starting the daemon. To grant a
user read-only monitoring access, add that user to `openshield` with the
distribution's account-management tool, then start a new login session so the
supplementary group is present. Group membership does not grant rule or mode
changes.

The IPC protocol uses typed, length-bounded JSON frames, absolute I/O deadlines,
bounded worker and subscription queues, rate limits, server-side pagination,
and optimistic policy revisions. A stale mutation returns `Conflict`; the TUI
reloads state and never retries an unconfirmed change automatically.

## TUI rule workflow

The TUI has five top-level tabs: `1` Status, `2` Outbound, `3` Inbound,
`4` Events, and `5` Help. `Tab` advances to the next tab. The Status tab reports
the firewall implementation that the daemon actually selected (`nftables` or
the `iptables`/`ip6tables` fallback), the policy mode, and the dynamically
selected active policy path from `StatusV2`, separately from telemetry
connection health. `Unknown` is shown explicitly for a legacy or unverified
response; the label is not a claim about eBPF or distribution-kernel features.

The Outbound tab presents rules as a two-pane view. The left pane groups them by
the first available identity in this fixed priority order:

1. exact unified-cgroup-v2 path;
2. exact validated executable path, without command-line arguments;
3. destination IP network (including a distinct "any destination" group).

Only that one value is the group key. The right pane retains the individual
rules and shows their protocol, destination, port or range, interface, command
line, UID, executable file-version identity, origin, action, enabled state, UUID, and
timestamps. Grouping is a presentation operation only: it never combines
rules, changes their AND matching semantics, or turns a single-rule action into
a group-wide policy change. `Up`/`Down` select a group and `Left`/`Right`
select an individual rule in that group. `PageUp`/`PageDown` scroll the full
detail pane without truncating bounded selectors. `n` creates a rule for the current
direction, `e` edits the selected rule, `d` deletes it, and `Space` toggles only
that selected rule. A disabled application template is shown in the same group;
review it carefully before enabling its intentionally unrestricted outbound
`accept` action.

The Inbound tab is intentionally separate. It creates explicit inbound allow
rules scoped by source network, local port or range, interface, and protocol;
application selectors are not valid for inbound rules. Outside Block All, new
inbound traffic not matched by an enabled inbound allow or an exact built-in
host-bootstrap/control exception remains denied; Block All overrides every rule
and contains no such exception. Stateful replies follow the policy-mode rules above,
including only the narrowly authenticated native `Reject` replies in
`Enforcing`. `m` opens the mode selector from any
tab. Mode changes and every rule mutation require root. A non-root member of
the `openshield` group can use the same navigation for read-only monitoring,
but receives server-redacted application identity and cannot mutate policy.

## Building

Build as an unprivileged user with the pinned lock file:

```console
cargo build --release --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check
cargo audit --file Cargo.lock
cargo deny check
```

Application attribution requires Linux procfs plus kernel conntrack and NFQUEUE
support. A cgroup-path selector additionally requires a unified cgroup v2
identity. On v1-only systems, executable path, full file-version identity,
filesystem-UID, and argv matching remain available, while an explicit
cgroup-path selector fails closed.
Network-only rules remain usable when attribution is unavailable. A usable installation also needs one
of these backend sets:

- a fixed, root-owned `nft` executable and kernel nftables support; or
- complete, fixed, root-owned IPv4 and IPv6 `iptables`, `*-restore`, and
  `*-save` bundles.

Executables are selected only from compiled absolute-path allowlists, checked
for safe metadata, invoked with typed arguments and a cleared environment, and
never passed through a shell.

## Performance and capacity testing

[`tests/perf`](tests/perf/README.md) provides a reproducible,
container-isolated host-firewall benchmark for nftables and the iptables
fallback. It compares a paired no-daemon baseline with network-only,
application-bound TCP, and application-bound UDP policies in `Enforcing` and
`Learning`. Real processes and sockets cross veth interfaces, exercising
NFQUEUE, conntrack, and `/proc` attribution rather than simulated TCP packets.

Production-like profiles cover incoming HTTP/1.1 keep-alive and short
connections, mixed response sizes, outbound application traffic, large UDP
streams, and many-flow high-PPS UDP. Reports include observed PPS/Mbps, CPS,
concurrency, latency percentiles, loss/retransmits, daemon CPU/RSS, softirq,
conntrack, NIC/NFQUEUE evidence, fail-closed probes, paired overhead, and
sustainable points. Generator or peer saturation invalidates a result. The
bounded release smoke runs only after functional firewall E2E; it validates
paths and safety but is not a portable capacity claim. Configuration,
synchronized metric documents, and pairing evidence use
`openshield.perf.config.v2`, `openshield.perf.metrics.v3`, and
`openshield.perf.baseline-pairing.v2`, respectively. Each exact comparison
group uses three predetermined, independent, single-use baseline/protected
pairs from separate pristine DUT generations. Pair order is balanced AB/BA,
and the protected block may use only its uniquely identified adjacent
baseline. The conservative comparison gap is the maximum separation across
the authenticated workload interval and synchronized DUT and peer metric
intervals; it is capped at 15 seconds for CI and 90 seconds for the
production-like profile. Any executed invalid result row fails the report.

The CI profile retains 10% relative thresholds and records every individual
delta, crossing, three-pair arithmetic mean, and one-sided 95% Student-t lower
confidence bound. Under the current v0.2.1 CI policy, relative DUT-cgroup CPU
and request/connect-latency crossings are explicitly advisory;
relative throughput and PPS regressions remain blocking. Absolute CPU/RSS and
p99-latency limits, burst capacity, drops, NFQUEUE errors, and fail-closed
safety also remain mandatory gates. The production-like profile keeps CPU and
latency regressions blocking. A single burst has no confidence claim, but
directly blocks throughput/PPS crossings; CPU/latency follows the profile's
explicit action. The
retained full v0.1.31 run was structurally valid but failed its performance
gate. The retained full local v0.1.32 run passed its authenticated performance
gate; that evidence remains scoped to the exact v0.1.32 binary, configuration,
and report and is not silently promoted to v0.2.1.

## Installation and init systems

OpenShield includes service definitions for systemd, OpenRC, SysVinit, runit,
s6, and dinit. `packaging/stage-install.sh` stages a package tree for exactly one
of these init systems; by design it refuses to install directly into `/`.
Package maintainers should use it with a fresh `DESTDIR`, install the staged
files through their package manager, and run the platform-specific enablement
step described in [packaging/README.md](packaging/README.md).
The authoritative distribution/architecture release matrix and its gated
build-to-publication flow are documented in [.github/README-CI.md](.github/README-CI.md).

The release workflow produces separate architecture-specific builds and RPMs
for every Tumbleweed platform selected by the authoritative release matrix:

| Target architecture | Release suffix | RPM architecture | Release-CI evidence |
| --- | --- | --- | --- |
| `x86_64` | `tumbleweed-amd64` | `x86_64` | native package install and nftables/iptables E2E |
| `i586` / `i686` | `tumbleweed-386` | `i586` | x86-64 compatibility package install and nftables/iptables E2E |
| `aarch64` | `tumbleweed-arm64` | `aarch64` | native package install and nftables/iptables E2E |
| ARMv6 hard-float | `tumbleweed-armv6` | `armv6hl` | build and QEMU `--version` smoke only |
| ARMv7 hard-float | `tumbleweed-armv7` | `armv7hl` | build and QEMU `--version` smoke only |
| `ppc64le` | `tumbleweed-ppc64le` | `ppc64le` | build and QEMU `--version` smoke only |
| `riscv64` | `tumbleweed-riscv64` | `riscv64` | build and QEMU `--version` smoke only |
| `s390x` | `tumbleweed-s390x` | `s390x` | build and QEMU `--version` smoke only |

Install the matching Tumbleweed RPM with `zypper`. Its firewall dependency is
`(nftables or iptables)` and it recommends nftables, so a normal installation
selects nftables. An existing iptables-only host remains supported when nftables
is unavailable or recommendations are deliberately disabled; runtime discovery
still tries a fully usable nftables backend first.

For a manual systemd installation, install both binaries, the unit, and the
sysusers and tmpfiles declarations. Create the group, root-owned service
directories, and shared xtables lock before starting the service:

```console
sudo install -o root -g root -m 0755 target/release/openshield-daemon /usr/bin/openshield-daemon
sudo install -o root -g root -m 0755 target/release/openshield-tui /usr/bin/openshield-tui
sudo install -o root -g root -m 0644 packaging/daemon/openshield-daemon.service /usr/lib/systemd/system/openshield-daemon.service
sudo install -o root -g root -m 0644 packaging/daemon/openshield.sysusers /usr/lib/sysusers.d/openshield.conf
sudo install -o root -g root -m 0644 packaging/daemon/openshield.tmpfiles /usr/lib/tmpfiles.d/openshield.conf
sudo systemd-sysusers /usr/lib/sysusers.d/openshield.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/openshield.conf
sudo systemctl daemon-reload
```

When SELinux or AppArmor is enabled, keep it enforcing. The packaged unit does
not select or disable either LSM; see the
[systemd packaging guide](packaging/daemon/README.md#selinux-and-apparmor) for
exact-path label checks and denial diagnostics.

### Safe first activation on a remote server

> **Warning:** `Learning` still denies new inbound application traffic unless an
> explicit inbound allow rule matches. Narrow built-in bootstrap/control-plane
> exceptions do not admit SSH or VPN. Starting OpenShield over the only SSH or
> VPN path can immediately lock out the operator.

Use a local console or independently tested out-of-band management for the
first activation. Start the daemon, open the root TUI from that console, and
create a narrowly scoped inbound rule for the administration protocol, source
network, local port, and interface. Verify the rule from a second session before
depending on remote access. Keep Learning enabled only for a controlled window,
review and narrow every learned outbound rule, then switch to `Enforcing` and
verify required DNS, time synchronization, package mirrors, monitoring, backup,
and application traffic.

```console
sudo systemctl enable --now openshield-daemon.service
sudo openshield-tui
```

A monitoring user with a fresh `openshield` group session can then run:

```console
openshield-tui
```

Do not manually flush or edit OpenShield-owned backend objects. Do not run a
second privileged firewall manager unless its hook ordering, chain ownership,
upper-two packet-mark use, and low-31 conntrack-mark use have been reviewed for
compatibility. Recovery and
removal are administrative firewall changes and should be performed from a
console using a distribution-specific, tested rollback procedure.

## Backend behavior and coexistence

nftables is preferred. It uses the dedicated `inet openshield` table and
validates a complete replacement before an atomic nftables transaction.

The compatibility backend creates only `OPENSHIELD_*` chains. Filter dispatch
jumps remain first in the built-in IPv4 and IPv6 INPUT, OUTPUT, and FORWARD
chains. In mangle OUTPUT, the reserved-mark sanitizer is first and the
Learning observation dispatcher is exactly once and last, after pre-existing
host marking, QoS, and policy-routing rules. Consequently queue bypass,
accept-on-overflow, and an ordinary Learning verdict cannot skip those rules.
It uses `iptables-restore`/`ip6tables-restore` with `--noflush`; it does
not flush a system table or change a built-in chain policy. Because xtables has
no transaction spanning both address families, policy replacement first places
both families in `BlockAll`, then applies IPv4 and IPv6. A transition can cause
a temporary denial, but is designed not to create a cross-family allow window.

In `Learning` and `Enforcing`, the OpenShield forwarding chain returns to the
existing firewall rather than accepting forwarded traffic itself. Consequently
the system's pre-existing forwarding policy remains authoritative. In
`BlockAll`, OpenShield drops forwarded traffic before delegating it.

OpenShield reserves the upper two packet-mark bits and preserves the lower 30.
For application authorization it reserves the low 31 conntrack-mark bits and
preserves bit 31. A firewall, VPN, QoS, or CONNMARK writer using the reserved
bits can invalidate either policy. The daemon's
health checks are backend-specific but do not establish safe coexistence with
arbitrary privileged ruleset editors.

For nftables, the once-per-second health observation requests tables, chains,
and counters in one fixed `nft` process and parses three ordered bounded JSON
documents. This removes two process launches per observation without changing
the cadence, table/base-chain/default-drop/counter checks, or fail-closed repair
behavior. The iptables fallback retains its backend-specific full owned-chain
comparison.

## Compatibility evidence

Compatibility claims are intentionally scoped:

The packaged-systemd correction of September 6, daemon SHA-256
`0c9cc05f0cee9195632686482c01d45a1e20457e92f5bac8fa9a3011630639c7`,
passed 489 ordinary Rust tests, all seven separately invoked ignored checks,
formatting, Clippy, and 243 Python tests. Its RPM passed delayed-reply,
short-lived/long-argv, server, Privoxy, and large TCP/GSO tests on both backends,
plus package installation. The new [real systemd fixture](tests/compat/README.md#packaged-systemd-sandbox)
passed on both backends: the installed unit can read queue progress through
read-only procfs, and an incompatible `ProcSubset=pid` override prevents startup
while preserving `BlockAll`. No host firewall or service was changed.

The same candidate's continuous 10-PPS UDP contention test remains **FAIL on
latency**. All 650 UDP, 130 TCP and 65 ICMP replies per backend arrived, and all
3,400 unknown-application attempts were blocked, with no NFQUEUE errors or drops.
UDP p99 was 585–788 ms for nftables and 585–591 ms for iptables, against roughly
55 ms baseline; daemon CPU remained about 185–187%. Intra-batch metadata grouping
has not demonstrated an overall CPU reduction in this fixture. The 500 ms
additional-p99 limit was not relaxed. These functional results do not certify
performance: the full performance smoke was not rerun, and these changes have
not yet run in GitHub Actions.

The later September 6 candidate, daemon SHA-256
`0282b8ac3cf0ad4f33f7a5420de05c340b64d8b26d45a959700beb56719cb121`,
passed 481 ordinary workspace Rust tests, all seven separately invoked ignored
checks, formatting, all-target Clippy, and 243 Python tests. In the new continuous
contention fixture it delivered all 650 UDP replies per backend, including
warm-up, with nftables and iptables; TCP/ICMP also had no loss and all 3,400
unknown-application attempts per backend were blocked. However, the fixture's
overall result remains **FAIL on latency**: UDP p99 was 565–583 ms with nftables
and 570–728 ms with iptables, against an approximately 55 ms baseline. This
exceeds the 500 ms additional-latency limit; the limit was not relaxed. The full
performance smoke was not rerun. See the
[continuous contention fixture](tests/compat/README.md#continuous-attribution-contention).

The September 6 v0.2.1 correction, daemon SHA-256
`083165d4de3655b7db3ff5795da3e32dc3ed9566c588902ed90cbf580ace615a`, passed
462 workspace Rust tests, all seven separately invoked ignored tests, formatting,
all-target Clippy, and 230 Python tests without skips. Its exact RPM passed
delayed ICMP/UDP/TCP reply tests, short-lived application/long-argv learning,
server Learning-to-Enforcing, and real Privoxy regressions on both nftables and
iptables in isolated Tumbleweed x86-64 containers. The delayed fixture had no
loss or unexpected firewall/NFQUEUE drops; under 1,024-thread/8,192-fd procfs
pressure, UDP/ICMP p99 was approximately 341–363 ms with a 55 ms peer delay,
while established TCP remained near 56 ms. These are functional regression
observations, not maximum-capacity or complete performance-smoke results.
The full performance smoke was not rerun for this correction. See the
[reproducible fixtures](tests/compat/README.md#delayed-tcpudpicmp-replies).

The September 5 results below describe the earlier v0.2.1 artifact identified
by its hashes, not every subsequent untagged source change. In particular, its
ICMP fixture used immediate replies; later delayed-reply tests exposed a
conntrack mark-reset race not covered by that result.

- the earlier v0.2.1 source resolves all four workspace crates and their exact
  internal dependency pins as `0.2.1`. In the pinned Rust 1.98.0 container, the
  locked workspace all-target suite passed 428 tests while the normal run ignored
  seven tests; all seven were then executed successfully: five live `SOCK_DIAG`
  tests, the `SCM_RIGHTS` helper test, and the synthetic fd-scan microbenchmark. Formatting,
  all-target Clippy with warnings denied, and the static-PIE musl release build
  passed. The Python suite passed 230 tests with no skips. Both local release
  executables report `0.2.1`;
- that Tumbleweed x86-64 RPM has SHA-256
  `1036ad5fab15baf5c7c29348fdc17ce8f827d04fad2d89e9abdc74e0cad8fbd1`;
  its daemon has SHA-256
  `4acdb2109b14832a3cb7c9928fa374b8768ddd324d2bf6a9c95effb0f62b8796`.
  Installation passed with default nftables selection and in an iptables-only
  container. The complete server Learning-to-Enforcing E2E and the real Privoxy
  regression each passed with both backends;
- the [short-lived application fixture](tests/compat/README.md#short-lived-application-regression)
  learned all six exact TCP/DNS application rules with both backends under
  pressure from 1,024 threads and 8,192 descriptors. Enforcing admitted all ten
  ICMP probes, with zero loss and zero `dropped_in`/`dropped_out` counter deltas;
  unknown executables and changed arguments were denied. ICMP p95 was 152 ms on
  nftables and 179 ms on iptables. The pre-optimization binary observed in
  the same nftables fixture had learned zero of six rules, with ICMP p95 of 706 ms and
  10% loss. These are individual fixture observations, not a statistical
  maximum-capacity result. Fire-and-forget UDP rule creation remains best-effort:
  its sender may exit before procfs attribution;
- the pre-optimization and September 5 binaries both passed the complete local
  performance smoke on nftables and iptables with the unchanged configuration
  (SHA-256 `b52b3a390a25a6cc611fb91a2ecb1b9df2cebd1bbef86cf6615ba7144fd7ed43`).
  Each run recorded 576 phase results, 108 independent baseline/protected pairs,
  36 comparison groups, and four successful fail-closed overload/recovery proofs.
  The final run is `20260905T204011Z-5e5ff23f6bd5fee5e47b6286956ed5db`.
  Throughput/PPS, validity, and safety gates passed. Relative CPU/latency
  increases above 10% remain recorded observations under the existing advisory
  policy; this result does not mean every metric stayed within 10%, nor does
  this bounded smoke certify maximum sustainable capacity;
- the six init images passed their parser/supervisor checks. The systemd unit
  was validated, but systemd was not booted as PID 1. Static compatibility
  validation covers the inventory of 60 distributions and 25 Rust targets and
  a release matrix of 43 binary builds, 43 packages, 86 declared platforms,
  37 package-install jobs, and 74 firewall jobs. Inventory validation is not
  execution evidence for all those distributions or architectures. These local
  checks do not confirm the GitHub workflow result for the current source tree;
- local v0.1.32 verification on Rust 1.98.0 passed
  `cargo fmt --all -- --check` and locked
  workspace all-target clippy with warnings denied. The complete Rust suite in
  a container passed 350 tests, with six live tests ignored by the normal run;
  all six then passed in a separate live-test invocation. The Python
  performance-harness suite passed 211 tests and reported one expected sandbox
  socket skip. These are component results, not a performance-gate
  result;
- the locally built v0.1.32 x86-64 daemon passed the isolated openSUSE
  Tumbleweed scenario with both nftables and the iptables fallback, including Learning,
  TCP-only L2 and mixed UDP/TCP L1 application attribution, inbound default
  deny and explicit allow, fail-closed shutdown, and restart with the persisted
  policy. OpenShield rules were confined to the disposable container network
  namespaces; Docker manages its bridge/NAT rules on the host;
- both v0.1.28 static-PIE musl binaries completed a no-network, read-only,
  capability-free `--version` smoke test in all 60 container image rows in
  `tests/compat/distros.tsv`;
- for v0.1.28, all six service layouts passed static validation; dedicated container
  supervisor checks passed for OpenRC, SysVinit, runit, s6, and dinit, while
  systemd is checked separately rather than booted as PID 1 in that matrix;
- for v0.1.28, `cargo check --workspace --all-targets --locked` passed for all 23 stable Rust
  Linux targets covering x86, x86_64/amd64, ARMv5/6/7 (soft- and hard-float
  variants where Rust provides them), arm64/aarch64, and RISC-V 64 with the
  listed GNU or musl environments;
- the two RISC-V 32 targets are Rust Tier 3 and were skipped because stable
  rustup does not ship their standard libraries; they require an explicitly
  separate nightly `build-std` workflow;
- the release workflow builds 43 architecture/family binary targets and 43
  corresponding package targets. The runtime submatrix installs 19 package
  variants in 37 pinned distribution/platform rows: 16 `amd64`, 15 `arm64`,
  and 6 `386`;
- each of those 37 rows runs the nftables and iptables
  Learning-to-Enforcing scenarios, for 74 firewall jobs. Both results are
  publication requirements, not evidence that those jobs passed for the current
  source tree;
- `amd64` and `arm64` execute on native runners, while `386` uses the x86-64
  kernel's 32-bit compatibility path. The other 24 ARMv5/6/7, `ppc64le`,
  `riscv64`, and `s390x` package variants are build-only; their pinned
  Cross/QEMU checks stop at ELF validation and a target-image `--version`
  smoke. They account for 49 of the 86 declared distribution/platform
  mappings and have no package-install or firewall-runtime evidence.

The 60-image smoke matrix does not boot each image's init system and does not
exercise its kernel, firewall backend, NFQUEUE, package manager, or upgrade
path. Archive and rolling images are compatibility probes, not supported-life
guarantees. See [tests/compat/README.md](tests/compat/README.md) for exact rows,
commands, and interpretation.

The release workflow now requires the isolated
`tests/e2e/server-learning-enforcing.sh` scenario with nftables and iptables for
the 37 runtime-tested distribution/platform rows. The nftables scenario
installs both frontends and requires nftables to win; the iptables scenario
omits `nft` and requires the compatibility backend. Each run covers Learning,
TCP-only application `Enforcing` at L2 `ConntrackHybrid`, mixed UDP/TCP
application `Enforcing` at L1 `Nfqueue`, an explicit inbound allow, and
restart. The L2 check uses a real persistent TCP socket: its first exchange
after the mode-generation change is attributed through NFQUEUE, then the
daemon is paused while another exchange must complete through the established
conntrack fast path. These 74 configured publication gates must not be read as
results until the corresponding workflow has completed. They run in disposable
namespaces on a Unix-socket Docker engine. OpenShield applies rules only inside
those namespaces; Docker itself manages host bridge/NAT rules. These checks are
not production or native-hardware certification.

## TUI localization

The TUI embeds 31 separate JSON resources with one complete, identical key set:
the original 20 locales plus 11 additions. Each non-English resource is loaded
as a complete map without merging or falling back to English. Tests verify exact key,
placeholder, and newline parity for every compiled resource; no non-English
value is exactly equal to its English counterpart. An all-pairs regression also
rejects bulk reuse of substantive messages across languages. The complete
maintained list, inventory of missing and removed resources, and native-review
status are documented in
[`crates/openshield-tui/locales/README.md`](crates/openshield-tui/locales/README.md).
Select a locale explicitly with, for example:

```console
openshield-tui --locale ru
```

Without `--locale`, the TUI checks `LC_ALL`, `LC_MESSAGES`, `LANGUAGE`, and
`LANG`, then falls back to English only when no supported locale is selected.
Locale identifiers are bounded and never used as filesystem paths. Automated
structure and copy-detection tests do not constitute linguistic certification
or replace review by native technical translators. No native technical review
is recorded for the 11 additions. Six proposed resources (`os`, `inh`, `bua`,
`xal`, `ady`, and `kjh`) were removed after forensic comparison found large
cross-language copied blocks; they remain unsupported pending replacement and
native technical review.

## Important limits

- New inbound traffic is default-deny in both normal modes except for exact
  built-in DHCP bootstrap and IPv6 control-plane traffic; `BlockAll` has no
  exception. Services still require explicit, interface- and network-scoped
  inbound rules.
- The filter covers host IPv4/IPv6, not Ethernet/ARP or direct frame injection
  by an already privileged `AF_PACKET`/`CAP_NET_RAW` process.
- Learning is a bounded operator-controlled trust window, not a verdict that a
  local executable or remote endpoint is benign.
- The packaged systemd service retains `CAP_NET_ADMIN`, `CAP_NET_RAW`,
  `CAP_SYS_PTRACE`, and `CAP_DAC_READ_SEARCH`. Its primary group remains `root`,
  and `openshield` is explicitly added as a supplementary group. As the socket
  owner it can assign that supplementary group to the observation socket
  without `CAP_CHOWN`; `CAP_NET_RAW` is required to inspect
  and operate the legacy xtables fallback, and the last two capabilities
  permit cross-UID procfs attribution. The systemd syscall filter reduces attack
  surface but is not process-memory or filesystem isolation after compromise.
- The workspace, matrices, and audit reduce known risk; they do not prove the
  absence of vulnerabilities or certify every Linux distribution, kernel,
  architecture, boot path, or hardware implementation.

See the [architecture](docs/ARCHITECTURE.md),
[threat model](docs/THREAT_MODEL.md),
[security audit](docs/SECURITY_AUDIT.md),
[security policy](SECURITY.md), and
[packaging guide](packaging/README.md).
