[English](README.md) | [Русский](README.ru.md)

# OpenShield host-firewall performance tests

This directory contains a reproducible, safety-gated performance harness for
OpenShield's actual host-firewall data paths. It is not a generic bandwidth
benchmark. The primary outputs are the highest sustainable packet rate,
connection rate, and concurrency point, together with latency and resource
overhead relative to a paired run without OpenShield.

The harness never changes the host firewall. It requires a local Unix-socket
Docker engine and builds two independent disposable three-container topologies
for every backend: a pristine baseline topology and a protected topology:

- the DUT contains the exact supplied `openshield-daemon`, the local workload
  process, and either nftables or the iptables/ip6tables fallback;
- an unprivileged, capability-free pressure peer runs the opposite workload
  endpoint;
- a second capability-free peer and a separate internal network provide the
  controlled-overload canary path; on the same canary veth, each transport has
  an application-bound target for the wrong-executable probe and a distinct
  network-only liveness endpoint;
- the DUT and pressure peer use a dedicated internal Docker network, so all
  measured traffic crosses real veth interfaces and separate network
  namespaces rather than loopback;
- only the DUT receives `NET_ADMIN`, `NET_RAW`, `SYS_PTRACE`, and
  `DAC_READ_SEARCH`, and those capabilities exist only inside its namespace.

The two topologies use distinct immutable Docker container IDs. The OpenShield
daemon is never started in the baseline DUT; lifecycle guards reject an attempt
to start it there or to run a protected policy in that topology. The protected
DUT is the only DUT in which the daemon and its policies are activated. Both
topologies are provisioned from the same pinned image and must produce exactly
identical bounded environment evidence before their measurements may be paired.

Every TCP/UDP client, server, and executable-identity probe runs as the fixed
non-root numeric identity `65532:65532` in all three containers, without
supplementary groups or added capabilities. The daemon, control helper, and
metric collectors remain root because their firewall and `/proc` duties require
it. A root supervisor installs each phase JSON in a non-writable directory as
`root:root` mode `0644`, so a generator can read but cannot replace or rewrite
its input. Its assigned private writable location is a mode `0700` home/tmp
directory on the container's disposable `/tmp` tmpfs.

The DUT creates the daemon's real `/var/lib/openshield` state directory on the
container's writable overlay rather than substituting a `tmpfs` or mock state
store. `state.json`, its atomic rename and `fsync` path, flow generation, and
learned rules therefore survive the exit of every phase client and subsequent
daemon control transactions within that backend topology. The writable layer
is destroyed with the disposable DUT, so this is real persistence for one
isolated backend run, not state carried between independent harness
invocations.

The production two-phase Learning path remains active: preparation and pending
admission run under the engine mutex, while atomic save and file/directory
`fsync` run after releasing it. Storage latency is therefore part of the
workload without intentionally stalling packet verdicts on that mutex; exact
observations covered by the in-flight candidate are deduplicated. The harness
does not relax NFQUEUE-error, drop, validity, or latency gates during a write.
In OpenShield 0.2.1, the ordinary Learning path intentionally allows unmatched
outbound traffic: observational attribution or persistence pressure may lose
evidence but may not deny that packet. Enabled explicit denies are outside these
capacity scenarios and remain enforceable. The performance gate still reports and rejects such lost evidence;
the controlled fail-closed overload proof remains scoped to `Enforcing`.

TCP clients use ordinary nonblocking sockets and complete HTTP/1.1 or bounded
framed request/response exchanges. UDP clients use persistent ordinary UDP
sockets. The harness does not inject handcrafted TCP packets. Consequently the
kernel exercises TCP state, conntrack, NFQUEUE, socket ownership, and `/proc`
process attribution in the same shape as the production daemon.

UDP completion does not rely on an ordering guarantee that UDP does not
provide. Every flow carries an explicit sequence. The server tracks a bounded
reordering window and acknowledges that flow's drain frame only after it has
consumed the exact contiguous sequence prefix preceding the frame. A gap,
duplicate/crossing sequence, exceeded bound, missing acknowledgement, or
client/server count mismatch invalidates and fails the point.

## Paths under test

Every protected case has a predetermined temporally adjacent measurement from
the pristine baseline DUT. The cases are:

| Case | Expected OpenShield path |
| --- | --- |
| `baseline` | Independent pristine DUT with the same image and veth topology; the daemon is never started |
| `network_only` | In Enforcing, exact network allows remain in the kernel and queue delta is zero within the configured noise bound; Learning additionally observes eligible outbound flows |
| `application_tcp` | Enforcing attributes each new TCP connection through NFQUEUE and uses the current conntrack generation for established traffic; Learning observes SYN plus bounded established samples |
| `application_udp` | Enforcing reattributes every otherwise-unmatched outbound datagram after clearing the reusable conntrack generation; Learning observes datagrams with bounded userspace duplicate suppression |

Since OpenShield 0.1.31, `StatusV2` classifies the worst-case active policy path.
An `Enforcing` `network_only` case is L3 `KernelNative`; an `Enforcing`
`application_tcp` case is L2 `ConntrackHybrid`; every `Learning` case and an
`application_udp` case is L1 `Nfqueue`. Network-only Enforcing packets remain in
the kernel even when the policy-wide level is L1; Learning also exercises its
observational queue. `Unknown` invalidates a claim
about which OpenShield path was measured. The backend name is recorded
separately because the nftables-to-iptables startup fallback does not change
these levels.

These names do not describe an eBPF data plane. Version 0.2.1 exercises the
existing nftables/iptables, conntrack, NFQUEUE, and procfs paths and introduces
no `CAP_BPF`, kernel module, boot-parameter, or MOK requirement. The controlled
NFQUEUE overload case is therefore still the relevant fail-closed saturation
proof for application attribution.

`network_only` runs in both `Enforcing` and `Learning`. Application cases run
with a privileged manual executable rule in `Enforcing`; in `Learning`, offered
traffic without an explicit deny is admitted while successful observations create
real enabled `accept` endpoint rules plus disabled path/cgroup templates. The
`known_endpoint` learning variant keeps the client's
argv stable while changing only the owner-controlled JSON configuration file.
The optional `discovery_churn` variant deliberately changes that argv path at
every phase and load point to measure repeated first-seen learning.

Inbound profiles are network-only because OpenShield intentionally forbids
application selectors on inbound rules. The included HTTP profiles model an
NGINX-like service with short and persistent HTTP/1.1 connections and a
deterministic weighted response-size mixture. Outbound TCP and UDP profiles run
the generator on the DUT and therefore exercise OpenShield's unique
application-aware path. UDP includes long-lived large-datagram streams and a
many-flow 128--512-byte high-PPS profile.

Each exact backend/policy/mode/profile/load group executes at least three
independent baseline/protected comparison pairs. Every pair has a fresh
warm-up and one matching steady-state window; the first pair also executes the
configured ramp and the last pair executes the burst. `production-like.json` sets
`capacity_certification=true`; a capacity-qualified maximum requires three
passing steady windows and, when `require_burst_capacity=true`, the matching
passing burst at the same load level. The much shorter `ci-smoke.json` sets
`capacity_certification=false`: it verifies path selection, reporting, and
fail-closed safety, but can never publish a capacity-qualified point.
The release smoke retains every backend, mode, policy path, and workload
profile, but uses one half-load ramp and three independent one-second steady
pairs. Its
bounded rates target hundreds of operations in every steady window, reducing
the single-digit-sample instability of the earlier sub-second profile. All
three independent pairs must pass. Each independent CI block now receives a
1.0-second warm-up. The deterministic workload-time estimate for the complete
two-backend plan is 609.6 seconds under the explicit
`max_total_workload_seconds` bound of 620 seconds; Docker provisioning,
teardown, and runner scheduling are bounded separately by the outer timeouts.

Every phase launches a fresh client process with a fresh initial socket set;
TCP connections are deliberately not carried from warm-up into ramp, steady,
or burst. The server stays alive for the whole load point. A keep-alive client
performs multiple real request/response operations on each connection inside
the same phase, so that phase independently exercises one first-packet
NFQUEUE/process-attribution decision followed by established TCP traffic on the
conntrack-generation fast-path. The harness never infers fast-path behavior
from a connection created in an earlier phase.

The fresh client uses an authenticated, bounded
`spawned -> ready -> started -> summary -> finished/hold -> released` protocol.
`spawned` pins the inner container process by PID, `/proc` start time,
executable, and UID before client preparation; `ready` is emitted only after
configuration validation and client allocation. Slow daemon control-plane
snapshots are completed before this process is launched. Start commands are
sent to both metric collectors before either acknowledgement is awaited, and
the client emits its own monotonic `started` acknowledgement after both
authenticated metric boundaries. The controller has a 60-second pre-start
budget while inner gates wait 120 seconds, so their timeout ordering is explicit.

At the end of load, the client publishes the summary and a `finished` event
containing its SHA-256, then remains alive without producing traffic. The
controller stops and reaps both collectors independently while `/proc` CPU and
RSS for the client are still available, and only then sends the exact `release`
command. Every JSON row retains all lifecycle events, boundaries, and pinned
metric-collector identities. On any error, cleanup of start-gated clients and
metric collectors targets only the pinned inner identity through `pidfd`; PID
reuse or identity drift aborts the topology, and no broad `pkill` is used. This keeps
launcher/teardown work outside the measured window and makes orphaned
`docker exec` children a release-blocking failure.

Within a comparison pair, the baseline and OpenShield policy case use the same
offered configuration and deterministic trace seed; policy is intentionally
absent from seed derivation. Repetitions receive distinct deterministic seeds.
Before every block, conntrack is flushed; the protected topology also returns
to Learning, clears its rules, rebuilds the selected policy, and only then
selects the requested mode.

The complete execution order is derived from the validated configuration before
any measurement is observed. Each repetition receives a unique
`comparison_pair_id` and `baseline_sample_id`; its pristine baseline is used
exactly once and is immediately adjacent to its protected block. Order
alternates AB/BA within each exact group, with the starting order alternating
between groups, so both orders are represented and globally balanced. The
harness cannot select a more favorable reference after seeing results: pair
identity, repetition, comparison order, and execution sequence are fixed in
advance. Missing, duplicated, reused, single-order, unbalanced, non-adjacent,
or ambiguous evidence invalidates the release gate. The configured
`maximum_comparison_gap_seconds` bounds the actual elapsed gap between paired
steady measurement windows. The harness computes the conservative maximum of
the authenticated workload, DUT collector, and peer collector boundaries, not
the shorter idle time between outer blocks. The CI smoke keeps a strict
15-second bound. The production-like profile uses 90 seconds because its first
pair intentionally places a 10-second warm-up and five 10-second ramp steps,
plus bounded teardown and cooldown, between sequential steady windows. This
cost is explicit rather than hidden; exceeding either profile's bound makes the
evidence invalid instead of labeling drift as a measured regression.

## Running safely

Build the daemon first as an unprivileged user. Give the harness an absolute,
non-symlink path to an exact mode-`0755` binary and a new absolute report
directory:

```console
cargo build --release --locked --bin openshield-daemon
python3 tests/perf/run.py \
  --config tests/perf/config/production-like.json \
  --daemon "$PWD/target/release/openshield-daemon" \
  --output-dir /tmp/openshield-perf-result
```

The command pulls the SHA-256-pinned images declared by the profile and installs
runtime tools inside the temporary DUT before disconnecting its provisioning
network. Do not run the harness with a remote Docker context: it refuses every
context except `unix:///...`. The CI wrapper generates a fresh 128-bit token
and gives every current-run container and network its exact label. On normal
exit, `TERM`, `INT`, or hard timeout it selects by that label and re-inspects
each immutable Docker ID before deletion. It never prunes Docker or deletes by
a shared name prefix, so other jobs' resources are outside the cleanup scope.
No `sudo`, host `nft`, or host `iptables` invocation is used.

The release-only bounded gate is:

```console
OPENSHIELD_DAEMON="$PWD/target/release/openshield-daemon" \
  tests/perf/ci-smoke.sh /tmp/openshield-perf-ci
```

The wrapper has an 1800-second hard process-group timeout and validates the
report schema, file types, permissions, and size bounds. It runs on the single
openSUSE Tumbleweed `linux/amd64` release stand after all functional firewall
E2E jobs.

The host orchestrator re-executes as `python3 -I -B -S` before importing any
workspace-resolvable module. `environment.py` is opened without following
symlinks and compiled directly from source; the later harness manifest must
match the exact bytes that were loaded. Containers do not receive the repository
tree. They receive a generated read-only `runtime-bundle/` containing only the
seven allowlisted runtime sources and a canonical SHA-256 manifest. A separate,
manifest-pinned launcher keeps every process argument within the daemon's
attribution bounds (at most 64 arguments and 1024 bytes per argument). Every
Python entrypoint runs with `-I -B -S`, verifies that manifest, hashes every component,
and rejects symlinks, writable entries, missing files, extras, and bytecode
before executing the selected source. The bundle and its manifest are retained
with the report so CI can independently repeat the verification.

Each backend result records bounded environment evidence: the resolved Docker
image ID, exact `x86_64` machine, parsed openSUSE Tumbleweed `/etc/os-release`,
`uname`, the SHA-256 of the repository's
`repo-oss` `repomd.xml`, and the exact sorted unique RPM
`name|epoch|version|release|arch` inventory. The nftables and iptables runs must
use the same image ID, OS identity, machine/kernel, and repository metadata.
Their RPM manifests are retained separately and are not required to be identical:
the only permitted nftables-only names are the pinned dependency closure
`nftables`, `libnftables1`, `libjansson4`, and `libedit0`; the iptables-only
delta must be empty. A changed dependency closure therefore fails closed until
the pinned stand and allowlist are deliberately reviewed together. Missing or
malformed evidence, any other package delta, or a mismatch in the shared
identity fields invalidates the run. The container image reference and
image ID are content-addressed, but provisioning currently uses the signed live
Tumbleweed repository. Recording its metadata makes the selected package set
auditable; it does not make that set immutable or reproduce it in a later run.

The same evidence is captured independently for that backend's baseline and
protected DUT. Their complete environment documents must be identical as
structured data, their 64-hex-character Docker client IDs must be valid and
distinct, and the recorded baseline daemon-start flag must be false. Any
mismatch makes `baseline_pairing.valid` false and blocks the release.

## Configuration

Both checked-in files use `openshield.perf.config.v2`. In v2, steady repetitions
denote independent baseline/protected pairs rather than correlated windows in
one block. Unknown keys, duplicate
JSON keys, non-finite numbers, unsafe names, duplicate ports, unpinned images,
and values outside fixed resource bounds are rejected before Docker is used.
The estimated total workload duration must also fit
`max_total_workload_seconds`. This deterministic estimate covers configured
phase, cooldown, and overload durations. It deliberately does not claim to
cover Docker lifecycle, policy transitions, package setup, or runner jitter;
the outer process and workflow timeouts separately bound that wall-clock work.

The following values are intended to be replaced with measured production
p50/p95/p99 distributions later:

- `load_levels` and phase duration/scales;
- TCP `concurrency`, `cps`, approximate wire `pps`, bidirectional application
  `mbps`, keep-alive ratio, request size, weighted `response_mix`, and weighted
  persistent-connection lifetime `connection_lifetime_ms_mix`;
- UDP flow count, approximate IP `pps`, bidirectional application `mbps`,
  request/response sizes, sampled-reply cadence, socket buffer, and MTU model;
- all latency, loss, saturation, daemon CPU/RSS, NFQUEUE, and path-shape gates;
- the single deterministic `seed` used to derive a separate seed for every
  backend, scenario, load point, and phase.

The boolean criterion `cpu_latency_relative_regressions_are_advisory` changes
only the disposition of repeated relative DUT-cgroup CPU and
request/TCP-connect latency threshold crossings. It does not change their
numeric limits or any measurement. It is `true` in `ci-smoke.json`, where those
relative crossings remain visible evidence but do not alone fail the noisy
shared-runner release smoke, and `false` in `production-like.json`, where they
remain blocking. Relative throughput/PPS limits, absolute latency and daemon
CPU/RSS ceilings, validity, drops, NFQUEUE errors, and fail-closed checks are
blocking in both profiles.

TCP and UDP `pps` are pacing targets from a documented packet-cost estimate;
they are not reported as observed PPS. Actual RX/TX PPS and Mbps always come
from DUT and peer interface counters. Application operations/s and bytes/s are
reported separately. CPS is counted from successful real TCP connects, and
concurrency is a thread-safe peak and time-weighted live-flow gauge.

`connection_lifetime_ms_mix` uses the exact
`MILLISECONDS:WEIGHT,...` syntax. Lifetimes must be unique integers from 50 to
3,600,000 ms. A seed-isolated deterministic choice is made whenever a
persistent socket is connected; after its deadline the client closes it and
opens a new real TCP socket between completed exchanges. This preserves normal
TCP and conntrack semantics and never interrupts a request in flight. `short`
mode still creates one connection per exchange and therefore validates but
otherwise ignores this field.

The TCP target-rate model also charges this finite lifetime turnover to the
configured wire caps without assuming that every concurrent socket expires at
`N / E[L]`. Let `r` be the aggregate operation rate, `N` the concurrency, `k`
the keep-alive probability, `L` the configured discrete lifetime random
variable in seconds, and `lambda = r / N` the worker-local operation rate. For
mixed traffic (`0 < k < 1`), the probability that a persistent cycle reaches a
lifetime renewal before a competing short request is
`q(r) = k * E[exp(-lambda * (1 - k) * L)]`. The short-to-keep-alive cycle start
rate is `B(r) = r * (1 - k) * k`, so the expected lifetime-renewal rate is
`X(r) = q(r) / (1 - q(r)) * B(r)`. For pure keep-alive, this reduces to
`X(r) = r / (1 + r * E[L] / N)`; for pure short traffic, `X(r) = 0`.

This is explicitly a steady-state, worker-local Poisson-arrival estimate. It
models the competing short request that closes an idle persistent socket and
does not double-count normal connections already included in the per-operation
cost. Each actual lifetime renewal adds seven estimated packets: four for the
close and three for the replacement TCP handshake. If `P` is the ordinary
packet estimate per operation, the nonlinear PPS and CPS candidates solve
`P * r + 7 * X(r) <= configured_pps` and
`(1 - k^2) * r + X(r) <= configured_cps`; the final operation target is the
minimum of those candidates and the independent Mbps candidate. For the
checked-in pure keep-alive smoke profile, `E[L] = 0.275 s`, `N = 16`, and
`P = 4.8`; unchanged `pps = 1280` and `cps = 160` produce a corrected target of
`200.874426 operations/s` and `X = 45.114679 renewals/s`. This correction does
not lower the offered PPS/CPS or the numerical value of any release threshold.
It prevents FIN and replacement-handshake traffic from being omitted from the
target denominator; observed PPS, CPS, and throughput still come from real
sockets and kernel/interface counters.

## Measurements and validity

Every phase records:

- actual DUT and peer RX/TX packets and bytes, converted to PPS and Mbps over
  the authenticated workload wall interval. The collector interval and rate
  denominator are both retained and independently checked before any paired
  PPS comparison;
- application operation rate, actual TCP CPS, current/peak/mean flows, response
  latency p50/p95/p99, and separate TCP connect p50/p95/p99 latency;
- errors, sampled UDP reply loss, kernel TCP retransmits, conntrack count, and
  interface drops/errors;
- `openshield-daemon` CPU as a percentage of one core and mean/peak RSS;
- authoritative container-cgroup CPU as raw `cpu.stat` usage minus only the
  metric collector's own high-resolution process-CPU interval strictly bracketed
  inside the two cgroup boundaries. Boundary bookkeeping is conservatively left
  included. The raw, excluded, and adjusted values remain in
  evidence; unavailable, negative, impossible, or too close-to-zero to resolve
  the configured relative threshold accounting invalidates the evidence.
  Daemon children and firewall/kernel work remain included;
- host-wide NET_RX/NET_TX softirq deltas;
- mode-selected NFQUEUE depth, wrap-safe packet-sequence delta, and exact
  kernel/user drop deltas from `/proc/net/netfilter/nfnetlink_queue`: queue
  1337 for baseline and `Enforcing`, queue 1338 for observational `Learning`.
  The selected number is retained in every DUT metric document and is checked
  independently against the scenario mode;
- process-lifetime monotonic deltas from the typed
  `status.data.nfqueue` counters: `queue_overflow`, `attribution_timeout`,
  `terminal_queue_error`, and `denied`; these status deltas are authoritative
  for daemon-observed NFQUEUE conditions in the release gate (one overflow
  event can represent an unknown number of kernel-denied packets);
- rate-limited daemon queue/attribution log diagnostics, explicitly labelled
  as diagnostic lower bounds and never used as authoritative pass evidence;
- daemon mode and any transition to quarantine/`BlockAll`.

Validity and pass/fail are separate. Missing or excessive generator CPU,
excessive scheduler lag, saturated or unmeasurable server CPU, rejected
connections, and server protocol/internal errors invalidate the affected
window. A baseline that misses its offered target also becomes invalid and
invalidates every paired OpenShield window. A per-phase peer CPU sample over
its configured ceiling is another invalidation signal. These points are marked
as unreliable, excluded from maximum-sustainable calculations, and are never
reported as an OpenShield regression or capacity result.

The same rule applies to the controlled-overload generator, pressure peer, and
canary: missing or excessive process/resource measurements, socket-queue
errors, workload/protocol errors, or NIC drops/errors invalidate the overload
proof. The sole socket-counter exception is a DUT UDP `SndbufErrors` delta
confined to the timestamp-ordered interval in which the NFQUEUE consumer is
stopped and a direct kernel NFQUEUE-drop delta proves the intended pressure.
It is accepted only after the pressure process has exited, when it exactly
equals that workload's explicitly classified UDP send failures (timeout,
`EAGAIN`, or `ENOBUFS`) and does not exceed the final direct kernel-drop delta
for the controlled interval. The daemon is then resumed and one continuous
collector atomically reuses its next snapshot as both the end of the
pressure/resume-transition window and the start of the clean recovery window.
Thus every counter remains accounted for without starting recovery while the
consumer is stopped. The recovery window, peer, and canary must have zero UDP
buffer errors and TCP listen errors. Its authenticated start acknowledgement
must precede the daemon stop; the DUT recovery window additionally requires an
alive unchanged daemon, an empty NFQUEUE, zero late NFQUEUE drops, and zero TCP
retransmits. DUT UDP receive errors and any
ordinary-workload socket error remain invalidating. A blocked probe cannot be
credited to a dead or saturated peer.

A valid steady window passes capacity only when it attains the configured
fraction of offered application operations and remains within the configured
error, sampled UDP reply-loss, TCP retransmit, p99 latency, daemon CPU/RSS,
interface drop/error, and NFQUEUE drop/error bounds. Path safety independently
requires, in Enforcing, NFQUEUE sequence deltas of zero for network-only, approximately one
per new application TCP connection with a low keep-alive per-operation ratio,
and approximately one per application UDP datagram. Learning instead requires
outbound TCP queue hits to track new connections plus bounded established samples,
and UDP hits to track outgoing datagrams, including network-only cases. Its first
eligible observation may wait up to 250 ms for asynchronous capture; repeat
observations are admitted immediately. Do not interpret that bounded capture wait
as an Enforcing fast-path latency or a guarantee of complete one-way UDP learning.
The [short-lived application fixture](../compat/README.md#short-lived-application-regression)
covers that separate lifetime boundary. Every required steady
window must pass. Every burst must remain valid and fail-closed; when
`require_burst_capacity` is true, it must pass the capacity bounds as well.
Explicit wrong-executable fail-open behavior is tested separately by the
independent canary during controlled NFQUEUE overload, so the paired burst
workloads remain equivalent.

The numerical release `ci-smoke.json` thresholds remain unchanged: at most a
10% paired reduction in throughput or DUT PPS and at most a 10% paired increase
in request p50/p95/p99, TCP-connect p50/p95/p99, or DUT-cgroup CPU. Every
per-window delta and crossing is retained in JSON and Markdown evidence. For
throughput and DUT PPS, a group becomes blocking when the arithmetic mean of at
least three valid, independent, adjacent pristine AB/BA steady pairs exceeds
the configured limit. The one-sided 95% Student-t lower confidence bound
remains as stronger evidence; high variance cannot hide a blocking throughput
or PPS mean regression. In release smoke,
`cpu_latency_relative_regressions_are_advisory: true` keeps the same mean and
confidence calculations for relative DUT-cgroup CPU and request/TCP-connect
latency, but classifies crossings as advisory: they remain prominent evidence
and do not alone fail publication on the shared runner. Absolute p99 latency,
daemon CPU/RSS, target-attainment, and validity ceilings are unchanged and
blocking. `production-like.json` sets the option to `false`, uses 5% for every
relative limit, and blocks every relative mean regression above those limits.
Publication-grade non-inferiority still requires the dedicated runner described
below.

A single burst has insufficient repeated evidence for a statistical
non-inferiority claim. It nevertheless applies the configured threshold
directly: throughput and DUT PPS crossings block both checked-in profiles;
relative CPU/latency crossings follow the explicit advisory setting (observe in
CI smoke, fail in production-like). Burst validity, configured capacity
ceilings, and fail-closed safety also remain mandatory and blocking. Safety is
never deferred to statistical confirmation:
application loss/errors, TCP retransmits, NIC drops/errors, or NFQUEUE errors or
drops fail the affected ordinary window immediately. Any unexpected allow in
`Enforcing` is fail-open and fails immediately; Learning's declared outbound
allow is not classified as fail-open. The only intentional exception is
the separately reported controlled-overload proof: there NFQUEUE drops prove
that saturation actually occurred, an exactly accounted DUT UDP send-buffer
error may record local fail-closed backpressure before the pressure process is
reaped, and the atomically adjacent post-resume recovery window must be clean.
Every canary probe must still demonstrate fail-closed behavior without one
successful round trip.

If the daemon enters `BlockAll`, the event is retained in the result and the
harness independently inspects the active nftables or IPv4/IPv6 xtables chains.
A reported quarantine without a canonical kernel drop policy is a hard safety
failure. A verified quarantine is fail-closed but still fails the requested
capacity point.

## Controlled NFQUEUE overload gate

The separate `overload` configuration is a destructive stress test of the
disposable namespace, not a capacity point. For each backend it installs an
exact outbound application rule in `Enforcing`, flushes conntrack, and runs both
real short-connection TCP and real UDP workloads. This proof deliberately
remains on the fail-closed enforcing queue 1337; it never targets observational
Learning queue 1338. The pressure client first
validates its configuration and allocates bounded resources, emits an explicit ready event, and
waits at a start barrier. Only then does the harness stop the authenticated
daemon process with `SIGSTOP`, send the client its `start` command, and poll direct NFQUEUE
snapshots through an enlarged but fixed saturation window. This sequencing
cannot mistake client startup latency for queue resistance. A `finally` path
attempts authenticated `SIGCONT` before an error can leave this section;
disposable-container teardown is the outer fallback.

Saturation is valid only when the measured sum of kernel and userspace NFQUEUE
drops reaches `minimum_nfqueue_drops`; merely offering a large load is not
proof. The independent canary uses the same transport and veth for two distinct
endpoints. Its network-only liveness exchange must succeed immediately before
and immediately after every application-bound wrong-executable probe, while the
probe itself must time out in the strictly validated blocked form without one
successful round trip. Thus a probe cannot appear blocked because the canary
server, socket path, veth, or transport failed. After resume, the daemon must
either remain in `Enforcing` and complete the configured allowed recovery
operations without errors, or enter a `BlockAll` quarantine. A reported
quarantine is accepted only when canonical kernel snapshots and daemon status
bracket real TCP and UDP probes to endpoints proven reachable before overload;
both probes must time out while real loopback round trips inside the canary
container succeed immediately before and after each negative probe. This
out-of-band check proves peer health without traversing the DUT firewall. IPv6
is recorded explicitly as unavailable in the current IPv4-only topology rather
than being claimed as tested. Synchronized metrics,
proven saturation, paired liveness observations, blocked probes, clean
generator/peer/canary evidence, and one of those two fail-closed outcomes are
all mandatory. TCP connection/concurrency, UDP datagram/flow counts, readiness
and saturation deadlines, stall and workload durations, probe count/timeout,
recovery work, and the minimum drop evidence are bounded configuration fields.
Overload results are reported separately and never contribute to
maximum-sustainable PPS, CPS, or concurrency.

The overload TCP payload inherits the validated lifetime distribution but
forces `short` mode, so queue pressure remains an explicit new-connection test
and is not reduced by keep-alive lifetime choices.

## Reports and interpretation

Every run atomically creates owner-only files:

- `report.json` (`openshield.perf.report.v2`): complete structured configuration identity, the SHA-256
  manifest of every executable harness/workload source, backend gates,
  environment evidence, phase measurements, safety evidence, paired baselines,
  validated baseline-pairing evidence, and sustainable points;
- `report.csv`: one flat row per phase for analysis and plotting, including the
  baseline sample, AB/BA order, execution sequence, topology role, monotonic
  block boundaries, and measured steady-window comparison gap;
- `overload.csv`: one flat safety-evidence row per backend and TCP/UDP
  controlled-overload proof;
- `report.md`: short outcome, baseline-pairing status and counts, failed/invalid
  windows, and sustainable-point table;
- `raw/`: bounded per-phase input and evidence useful for diagnosis. Baseline
  and protected environment evidence is retained below the corresponding
  topology-role directory; each canonical result filename includes its
  unique `baseline_sample_id`, preventing independent samples from overwriting
  one another;
- `runtime-bundle/`: the exact source-only allowlist mounted into containers,
  plus its canonical manifest; no `.pyc` or unlisted import candidate is allowed.

Each JSON controlled-overload record uses `openshield.perf.overload.v2`; this
version adds the mandatory, gap-free split between the controlled
pressure/resume-transition and clean post-resume DUT metric windows. Metric
documents use `openshield.perf.metrics.v3`; this version makes raw, bracketed
collector, and adjusted cgroup CPU explicit. Its `nfqueue.queue_number` field
records the queue selected before the collector starts. Synchronized collectors acknowledge the exact
initial boundary before workload or overload activity can begin.

`report.json.baseline_pairing` uses
`openshield.perf.baseline-pairing.v2` and the strategy
`independent_order_balanced_ab_ba`. It records overall validity and failure reasons,
baseline environments, per-backend environment/DUT-identity pairs, baseline
sample and protected-comparison counts, AB and BA counts, and the maximum
observed paired steady-window gap. Every normal phase result, in JSON and CSV, carries
`baseline_sample_id`, `comparison_pair_id`, `comparison_repetition`,
`comparison_order`, `execution_sequence`, `topology_role`,
`block_started_monotonic_ns`, `block_finished_monotonic_ns`, and
`comparison_gap_seconds`. Baseline rows have no comparison order or gap;
protected rows must name exactly one adjacent, single-use baseline/pair identity
and a finite non-negative gap.

Relative throughput, DUT PPS, request and TCP-connect p50/p95/p99 latency, and
DUT-cgroup CPU deltas are paired by backend, policy, mode, learning variant,
profile, load level, and steady phase role. All individual deltas and crossings
remain in the report. The relative decision is made over at least three valid
independent steady AB/BA pairs by their arithmetic mean; the one-sided 95%
Student-t lower confidence bound described above records stronger confirmation.
Whether CPU/latency crossings are advisory is taken from the authenticated
configuration field `cpu_latency_relative_regressions_are_advisory`; throughput
and PPS crossings remain blocking. A burst records a single-sample comparison
and immediately blocks every crossing whose release action is `fail`.
The release wrapper then runs a separate source-manifested validator. Starting
from primary workload and DUT metric fields, it independently recomputes every
paired delta, arithmetic mean, strict threshold comparison, advisory/blocking
disposition, Student-t lower bound, observation/failure linkage, and final
per-row relative outcome. For every steady and burst row it also independently
recomputes target attainment and absolute p99 latency and checks raw daemon
CPU/RSS against their configured hard limits instead of trusting
`capacity_pass`. It also rebuilds
the normalized configuration from the checked-in JSON, independently derives
the workload-time estimate, and verifies its canonical compact sorted UTF-8
SHA-256. A self-consistent but altered report cannot substitute its own
configuration or relative decision.
A maximum is called capacity-qualified only
when `capacity_certification=true`, at least three steady-state repetitions at
that load point all remain valid, sustainable, and fail-closed, and every
configured mandatory burst gate for that point passes as well. With
`capacity_certification=false`, passing steady windows remain useful diagnostic
candidate points but `capacity_qualified` is always false.

In report v2, *paired* means the same backend/profile/load/phase and
deterministic trace plus a unique `comparison_pair_id`, single-use
`baseline_sample_id`, and exact repetition. Monotonic block boundaries prove
whether the baseline immediately precedes or follows its protected block;
authenticated workload and DUT/peer collector boundaries determine the actual
steady-window gap independently of warm-up, ramp, burst, teardown, and cooldown. The
separate baseline DUT remains pristine for its entire lifetime, rather than
temporarily disabling the daemon in a previously protected namespace. This
adjacent AB/BA design reduces runner drift and makes the choice auditable; it
does not turn a shared hosted runner into a controlled benchmark host. The
release gate remains conservative: fewer than three independent pairs, missing
either order, imbalance greater than one, or missing, duplicated, reordered,
non-adjacent, ambiguous, or environment-mismatched evidence makes the group
invalid rather than suppressing a marginal 10% observation. Advisory
CPU/latency observations remain preserved; they are never rewritten as values
below the threshold.

Container/veth results are appropriate for regression and architecture-path
validation. They are not a NIC line-rate claim. Offloads can make interface
packet counters differ from physical-wire packets. `/proc/softirqs` is global
to the host kernel rather than a container or network namespace, and therefore
includes Docker and unrelated host activity; its deltas are interpreted only
against the paired baseline on a quiet runner and never as daemon-attributed
CPU. Docker scheduling adds further noise, and a shared CI runner is not a
controlled benchmark host. The protected daemon also remains resident while
the separate pristine topology is measured; although its own DUT-cgroup CPU is
accounted independently, shared-host scheduling can still bias throughput and
latency. In addition, a signed live Tumbleweed repository is
mutable between runs even though each run records its exact metadata and RPM
inventory. Publication-grade numbers require a prebuilt performance image
pinned by digest, a dedicated runner with reserved CPUs and recorded
offload/IRQ/kernel settings, a non-saturating external peer, enough independent
repetitions, and retained JSON evidence. No full performance run or numerical
claim is considered successful without that evidence.
