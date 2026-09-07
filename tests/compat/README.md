[English](README.md) | [Русский](README.ru.md)

# Linux compatibility matrices

The compatibility suite separates four different kinds of evidence. A pass in
one layer must not be interpreted as a pass in another.

| Layer | What it establishes | What it does not establish |
| --- | --- | --- |
| image manifest | a named container image was available from its registry at the time of the check | binary compatibility or runtime support |
| static musl smoke | both binaries can start and print `--version` in the image's userspace | init boot, libc integration, firewall tools, kernel features, NFQUEUE, or policy correctness |
| cross-target `cargo check` | the workspace type-checks for an installed Rust target standard library | linking, execution, hardware behavior, kernel ABI, or packaging |
| init parser/supervisor fixture | staged files, selected parsers, lifecycle hooks, and group helper behave in isolated fixtures | a real boot or real firewall policy |

The real Learning-to-Enforcing firewall workflow is a separate end-to-end test.

## Release validation versus compatibility research

The release pipeline has its own authoritative matrix:
[`packaging/ci/release-matrix.json`](../../packaging/ci/release-matrix.json).
It defines 43 binary rows and 43 matching package rows. Its runtime submatrix
installs 19 package variants in exactly 37 distribution/userspace and
OCI-platform rows: 16 `amd64`, 15 `arm64`, and 6 `386`. Every runtime row is
expanded into both firewall backends, producing 74 firewall E2E jobs. The other
24 package variants account for 49 of the 86 declared distribution/platform
mappings; they are build-only and have no package-install or firewall evidence.
The release dependency graph is:

```text
Validation
    -> Quality Gate
    -> Binaries
    -> Packages
    -> Install Matrix
    -> Container Tests
    -> Firewall E2E
    -> Performance Smoke
    -> Release Evidence
    -> Publish
```

The complete policy, architecture evidence levels, and publication boundary are
documented in [the release CI guide](../../.github/README-CI.md). Compilation is
allowed only after Validation and the Quality Gate. Publication is allowed only
after the evidence stage has reconciled every required matrix row and release
asset.

The single openSUSE Tumbleweed `linux/amd64` performance smoke begins only after
the entire functional E2E matrix succeeds. It is a bounded release regression
gate and does not add architecture or distribution support evidence to this
compatibility matrix.

The 37 runtime rows cover Debian 12/13, Ubuntu 22.04/24.04/26.04, Fedora 43/44,
Rocky Linux 9/10, AlmaLinux 9/10, openSUSE Leap 16.0, Tumbleweed, Alpine
3.23/3.24, and Arch Linux on `amd64`, `arm64`, and, where published by the
image, `386`. A family/architecture binary and package may be built once, but
installation, container testing, and both backend results remain separate for
every selected distribution/platform row. ARMv5/6/7, `ppc64le`, `riscv64`,
and `s390x` remain build targets only.

This release matrix and the 60-row research matrix below serve different
purposes. Passing the broad compatibility smoke does not add a release row, and
removing an archived research image does not change the package-support
contract. Do not derive release claims from `distros.tsv`.

## Distribution image matrix

`distros.tsv` contains exactly 60 rows across Debian/Ubuntu, Alpine, Fedora,
Rocky, AlmaLinux, CentOS Stream, Oracle Linux, openSUSE, Amazon Linux, Arch,
Gentoo, Void, Devuan, and Artix. Rows intentionally include maintained,
rolling, legacy, and archived releases spanning approximately the preceding ten
years. The lifecycle column describes the image row; it is not a project support
commitment.

Validate matrix syntax and row count without Docker:

```console
scripts/test-distro-matrix.sh validate
```

Check registry manifests:

```console
scripts/test-distro-matrix.sh manifests
```

Run a smoke matrix using a directory that contains statically linked musl
`openshield-daemon` and `openshield-tui` binaries:

```console
scripts/test-distro-matrix.sh smoke /absolute/musl/release-directory
```

`smoke` requires a local Unix-socket Docker endpoint, disables networking in
each test container, mounts binaries read-only, makes the root filesystem
read-only, drops all capabilities, and enables `no-new-privileges`. It does not
remove images, which avoids racing with other local Docker users. `smoke-clean`
remains as a deprecated, non-destructive alias for `smoke`. The completed matrix
run against the final static-PIE artifacts reported `matrix rows: 60; failures:
0`; both binaries completed `--version` in every row.

This result primarily demonstrates portability of the chosen static musl
artifacts across those container userspaces. Containers share the host kernel,
and `--version` deliberately does not initialize procfs attribution or either
firewall backend. It is not certification of 60 complete distributions.

## Rust target matrix

`targets.tsv` contains 25 built-in Linux target names. Validate the file with:

```console
scripts/check-target-matrix.sh validate
```

In a Rust 1.98.0 environment with rustup, install missing stable target
components and type-check them with:

```console
scripts/check-target-matrix.sh check --install
```

The harness runs cross-target checks with one Cargo job to bound peak memory and
make the matrix deterministic on constrained builders.

The completed stable run checked 23/23 available stable targets without failures:

| Architecture family | Covered variants |
| --- | --- |
| x86 | i586 and i686; GNU and musl where listed |
| x86_64 / amd64 | GNU and musl |
| ARM | ARMv5, ARMv6, and ARMv7; soft-float and hard-float variants where the Rust target provides them; GNU and musl as listed |
| arm64 / aarch64 | GNU and musl |
| PowerPC 64 LE | `powerpc64le` GNU |
| IBM Z | `s390x` GNU |
| RISC-V 64 | `riscv64gc` GNU/musl and `riscv64a23` GNU |

`riscv32gc-unknown-linux-gnu` and
`riscv32gc-unknown-linux-musl` are recorded as Rust Tier 3. Stable rustup does
not provide their standard libraries, so the stable matrix skips them. Building
them requires a separately reviewed nightly `build-std` workflow; they are not
claimed as stable release targets.

The workflow defines 43 release binary rows and requires each one to be linked,
checked for the expected ELF identity and static runtime boundary, and
smoke-run in a pinned image for its target family and architecture. `amd64` and
`arm64` jobs use native x86-64 and AArch64 runners. `386` uses the x86 runner's
compatibility path. ARMv5, ARMv6, ARMv7, `ppc64le`, `riscv64`, and `s390x` use
digest-pinned Cross build images and a selected QEMU user-mode handler only for
their target-image `--version` binary smoke. The privileged handler registration
step is rejected on self-hosted runners.

A publishable run must install all 37 selected package rows and complete both
backend scenarios for each of them. QEMU user-mode rows do not enter the
package-install or firewall matrices. Their successful binary smoke is not
package-runtime evidence, distribution-kernel coverage, physical-hardware
certification, or a blanket runtime guarantee for ARM, PowerPC, IBM Z, or
RISC-V hardware.
Architecture aliases do not create additional targets: AMD64 means x86_64, and
ARM64 means AArch64. `aarch` alone is not a Rust Linux target name.

## Init-system matrix

Run source/layout checks without Docker:

```console
scripts/test-init-matrix.sh validate
```

Run the isolated parser and supervisor fixtures:

```console
scripts/test-init-matrix.sh manifests
scripts/test-init-matrix.sh containers-clean
```

The completed checks covered staging layouts for all six supported init systems,
OpenRC parsing, SysVinit PID/executable semantics, runit and s6 supervised
start/finish quarantine, s6 dependency compilation, dinit parsing, and both
BusyBox `addgroup` and shadow `groupadd` group creation. systemd is statically
staged and checked separately: the unit with target stubs passed
`systemd-analyze verify`, and offline
`systemd-analyze security --offline=yes --threshold=100` passed with exposure
2.7 (`OK`). Verification and the same 2.7 assessment were repeated with systemd
installed inside the pinned Tumbleweed container. The full tmpfiles
create/relabel declaration for the runtime directory, state directory, and
shared xtables lock also passed repeated application and exact metadata checks.
This matrix does not boot systemd in a container or as PID 1.

The lifecycle fixtures mount a stub daemon. Their successful result does not
mean a backend was selected or that real packets were filtered.

## Dynamic active-policy path evidence

Since OpenShield 0.1.31, `StatusV2` exposes a dynamically recomputed,
conservative active-policy path classification:
L3 `KernelNative` for `BlockAll` or application-free `Enforcing`, L2
`ConntrackHybrid` for TCP-only application `Enforcing`, L1 `Nfqueue` for
`Learning` or an enabled UDP/ICMP/ICMPv6/`Any` application rule, and `Unknown`
for a legacy or unverified response. This is the worst-case active path;
network-only matches remain in the kernel at L2 and L1.

This is not kernel-capability attestation or fallback negotiation for an
unchanged policy. The classification is independent of
nftables-versus-iptables selection. Both backend scenarios must preserve
identical rule semantics. Mandatory Enforcing NFQUEUE setup fails closed;
Learning uses its explicitly observational queue with a kernel bypass and
continues its documented outbound allow policy if observation is unavailable.
A container result demonstrates the level
calculation and packet paths on the runner kernel only. It does not certify the
stock kernel, boot configuration, LSM, or Secure Boot state of the named
distribution. OpenShield has no eBPF application data plane, so none of the
37 runtime rows or 49 build-only mappings is an eBPF support claim.
The only automatic startup backend fallback is from nftables to the complete
iptables/ip6tables bundle when nftables cannot be validated.

The bounded NFQUEUE micro-batch and single-process nftables observation introduced in v0.1.32
are userspace changes. They add no architecture-specific kernel object,
capability, LSM rule, Secure Boot key, or module requirement. This statement
describes compatibility. Retained v0.1.32 E2E and performance reports remain
scoped to the exact artifacts they tested; a current release claim requires its
own retained reports.

## State and IPC upgrade boundary

Compatibility is forward-only from v0.2.0 to v0.2.1. The v0.2.1 reader maps an
absent rule `action` to `accept`, but a v0.2.0 process cannot parse v0.2.1
`drop`/`reject` actions or the `template` origin. Mixed daemon/TUI versions and
an in-place downgrade after v0.2.1 writes state are unsupported. Use a protected
console, active kernel `BlockAll`, a reviewed state backup, and a
distribution-tested upgrade or rollback procedure. The compatibility and E2E
matrices described here do not validate package upgrade or downgrade.

## Real firewall end-to-end workflow

The workflow expands every one of the 37 runtime platform rows into two
complete Learning-to-Enforcing tests: one with nftables preferred while both
frontends are installed, and one with `nft` absent so the complete
iptables/ip6tables fallback must be selected. A publishable run therefore
requires 37 nftables and 37 iptables jobs across DEB, RPM, APK, and Arch
packages on native `amd64`/`arm64` runners and the x86-64 kernel's `386`
compatibility path. QEMU-user rows are excluded. The harness explicitly
provisions the requested backend before installing the release package; that
test setup does not by itself change or broaden a package format's dependency
metadata.

Every release image is pinned by SHA-256 digest and paired with an explicit OCI
platform. The evidence stage records the image/platform identity, package and
binary hashes, installation result, assigned backend results, and expected
release-asset inventory. Docker still uses the runner kernel, so these results
validate container userspace and isolated network-namespace behavior rather
than the distribution's own kernel or a complete init boot.

`../e2e/server-learning-enforcing.sh` creates a disposable Docker network with a
client and HTTP server. It is designed to verify, separately for each backend:

- selection of the requested nftables or iptables backend;
- initial persisted `Learning` mode after startup quarantine;
- observation access for `openshield` and denial for an outsider;
- denial of control to a non-root group member;
- a real TCP exchange remaining admitted in `Learning` when bounded process
  attribution is deliberately unavailable, without an incomplete learned rule;
- learning enabled `accept` application-bound TCP and UDP rules;
- creation of disabled minimal application-group templates and secure
  executable pinning when a privileged user enables one;
- continued access for the learned executable and denial of another executable
  in `Enforcing`;
- admission of different arguments only after the matching template is enabled;
- application-bound `drop` and native `reject`, plus their independent disabled state;
- coexistence with a downstream firewall DROP;
- inbound denial followed by an explicit inbound allow;
- graceful-shutdown kernel `BlockAll` without replacing persisted `Enforcing`;
- restart into the persisted mode.

Build daemon binaries compatible with the selected client userspace, then run
each backend explicitly. Debian Bookworm is the default:

```console
tests/e2e/server-learning-enforcing.sh nftables /absolute/bookworm/release-directory
tests/e2e/server-learning-enforcing.sh iptables /absolute/bookworm/release-directory
```

The pinned Tumbleweed snapshot can be selected without changing the script:

```console
CLIENT_FAMILY=tumbleweed CLIENT_IMAGE='opensuse/tumbleweed@sha256:8f6397b7b7ebc78e111d9a13fb2b157664ad5524e1f3b908deb45938b3095045' \
  tests/e2e/server-learning-enforcing.sh nftables /absolute/tumbleweed/release-directory
CLIENT_FAMILY=tumbleweed CLIENT_IMAGE='opensuse/tumbleweed@sha256:8f6397b7b7ebc78e111d9a13fb2b157664ad5524e1f3b908deb45938b3095045' \
  tests/e2e/server-learning-enforcing.sh iptables /absolute/tumbleweed/release-directory
```

The workflow installs packages in the disposable client container and therefore
needs registry/package-network access. Firewall capabilities are granted only
inside that container; the script does not apply rules on the host. Before
creating resources, it reads the active endpoint with `docker context inspect`
and refuses every endpoint whose URI is not `unix:///*`.

Each successful runtime release row reports both backend runs in its selected
userspace:

```text
PASS server Learning allow -> templates -> TCP L2 -> UDP/TCP L1 -> inbound allow -> restart (nftables)
PASS server Learning allow -> templates -> TCP L2 -> UDP/TCP L1 -> inbound allow -> restart (iptables)
```

In an nftables run both frontends are installed and nftables must be selected.
In an iptables run `nft` is absent and the compatibility backend must be
selected, so the pair tests preference and fallback rather than merely forcing
a name.

A successful pair covers the scripted behavior inside disposable network and
container namespaces on a local Unix-socket Docker engine. It does not test or
modify the host firewall and does not certify production kernels, deployments,
upgrades, or competing firewall configurations.

## Short-lived application regression

[`../e2e/short-lived-attribution.sh`](../e2e/short-lived-attribution.sh) extracts
the static daemon from an RPM without installing it on the host. It runs a pinned
x86-64 Tumbleweed DUT and an independent TCP/DNS/UDP peer in disposable Docker
namespaces. Both backends are explicit:

```console
tests/e2e/short-lived-attribution.sh nftables /absolute/openshield-package.rpm
tests/e2e/short-lived-attribution.sh iptables /absolute/openshield-package.rpm
```

Requirements are a local Unix-socket Docker engine whose kernel exposes unified
cgroup v2 to the DUT, registry/package network access, and host tools
`rpm2cpio`, `cpio`, `file`, `readelf`, and `sha256sum`. OpenShield and its
firewall capabilities remain inside the DUT network namespace. Docker itself
creates and removes the isolated bridge and may therefore manage transient host
bridge/NAT rules. The fixture creates many same-UID and other-UID processes,
threads, and descriptors, then checks:

- real short-lived TCP and DNS-then-TCP exchanges reaching the peer in Learning;
- persisted rules with exact UID, executable version, argv, cgroup, interface,
  and endpoint selectors, without duplicates, foreign bindings, or substituted
  network-only allows;
- continued access after Enforcing and denial of an unknown same-UID executable
  and unmatched argv for a known executable;
- baseline/Enforcing ICMP latency and loss, zero firewall-drop counter growth
  for allowed ping, plus a timed silent drop for an unknown ping binary;
- fire-and-forget UDP delivery separately from best-effort rule observation.

A final isolated argv stage learns and enforces TCP and UDP/DNS rules containing
a 2,083-byte argument with newline, tab, escape, and bidi characters. Replacing
those bytes with their visible escape spellings must not match. Peer-side counts
prove that denied requests did not leave the DUT, rather than merely timing out
because an inbound reply was blocked.

The first-observation wait is bounded to 250 ms and cannot keep a one-way UDP
sender alive after `sendto()` returns. Missing fire-and-forget attribution is
reported as a limitation, not silently counted as successful learning. Request/
response rules and fail-closed checks remain required. The script prints its
retained `/tmp/openshield-short-evidence.*` directory containing daemon logs,
rule/peer audits, packet-exchange, counter and ping JSON, status, and exact
package/daemon hashes; its containers and network are removed. A cleanup
failure fails the run and reports the exact labelled resource. This focused
regression does not replace the full functional or
[performance suite](../perf/README.md), and container results exercise the host
kernel rather than a booted Tumbleweed kernel.

## Delayed TCP/UDP/ICMP replies

[`../e2e/delayed-icmp.sh`](../e2e/delayed-icmp.sh), despite its historical name,
tests all three protocols using the same RPM and container prerequisites:

```console
tests/e2e/delayed-icmp.sh nftables /absolute/openshield-package.rpm
tests/e2e/delayed-icmp.sh iptables /absolute/openshield-package.rpm
```

The independent peer delays replies by 55 ms. Under bounded procfs pressure,
the fixture compares baseline and Enforcing at 1 and 5 requests/second: real
ICMP echo, multiple outstanding UDP requests on one connected socket, a
persistent TCP connection, and short TCP connections. Exact application rules
are installed in Learning to isolate reply handling from auto-learning; the
short-lived fixture tests automatic rule creation separately.

Passing requires all expected replies, positive accepted traffic counters,
zero unexpected firewall drops and NFQUEUE errors/drops, live peer timing
evidence, and denial of unknown executable/argv probes. A separate
functional latency bound permits at most 500 ms additional p95/p99 and 1000 ms
additional maximum latency relative to baseline under this procfs pressure;
these generous regression bounds do not replace the performance gate. A pre-switch
TCP reply must remain denied after generation invalidation; fresh authorized
TCP connections must work. This is not a promise that an already waiting TCP
session survives a policy-generation change without reauthorization/reconnect.
Evidence is retained in the printed `/tmp/openshield-delayed-evidence.*` directory.
The peer's ICMP sysctl and firewall rules are changed only inside disposable
containers; no host sysctl, module, or OpenShield policy is modified.

## Continuous attribution contention

[`../e2e/continuous-attribution.sh`](../e2e/continuous-attribution.sh) adds
continuous socket churn to the delayed-peer fixture. Run each backend separately:

```console
CONTINUOUS_UDP_PPS=10 sh tests/e2e/continuous-attribution.sh nftables /absolute/openshield-package.rpm
CONTINUOUS_UDP_PPS=10 sh tests/e2e/continuous-attribution.sh iptables /absolute/openshield-package.rpm
```

Baseline and Enforcing both have 1,024 sleeping worker threads and 8,192 open
descriptors distributed across the application's UID and another UID. A separate
unknown executable opens real TCP/UDP sockets at 20, 50, and 100 attempts/second,
for 20 seconds per level after warm-up. Known applications simultaneously send
ICMP at 1 request/second, persistent TCP at 2 requests/second, and pipelined UDP
at `CONTINUOUS_UDP_PPS` (default 2). The peer delays replies by 55 ms. Rules are
installed explicitly to isolate queue scheduling from automatic learning.

The report records send-time cohorts, latency, loss, daemon CPU/RSS, queue depth,
kernel/user drops, and whether queue 1339 was actually exercised. Invalid peer
timing or generator saturation invalidates the measurement. Unknown-application
delivery, missing expected replies, NFQUEUE drops, or more than 500 ms additional
p99 latency fail this functional regression. This is not a maximum-capacity or
5–10% performance-gate claim. Evidence remains under the printed
`/tmp/openshield-continuous-evidence.*` path. Do not run other heavy builds or
load tests concurrently when comparing candidates.

With nftables, the earlier daemon `083165d4…` passed the 2-PPS UDP case, but the 10-PPS case
exposed 372 missing replies out of 600 steady-state UDP requests despite zero
NFQUEUE kernel/user drops. Thus the earlier finite delayed-reply pass did not
establish correctness under continuous attribution contention.

## Packaged systemd sandbox

[`../e2e/systemd-sandbox.sh`](../e2e/systemd-sandbox.sh) installs the specified
RPM in pinned Tumbleweed x86_64 and boots real systemd as container PID 1, with
private cgroup v2 and an independent peer. Run once per backend:

```console
sh tests/e2e/systemd-sandbox.sh nftables /absolute/openshield-package.rpm
sh tests/e2e/systemd-sandbox.sh iptables /absolute/openshield-package.rpm
```

The test verifies the installed unit, capabilities, seccomp, mount namespace,
read-only `/proc`, and readable queue progress. A temporary container-only
`ProcSubset=pid` override must prevent readiness with an explicit startup error
and keep real TCP/UDP traffic blocked. After removing the override, the original
unit must start, allow TCP/UDP/ICMP in Learning and Enforcing using manually
created application-bound rules, and deny an unknown executable. Automatic rule
creation is covered by the separate short-lived/server/proxy fixtures, not this
sandbox check. Briefly pausing only the container daemon forces
a delayed UDP reply to overlap queued outgoing traffic, exercising the reply
barrier. Independent peer records check that blocked traffic was not delivered.

Evidence remains under the printed `/tmp/openshield-systemd-evidence.*` path.
`report.json` describes in-container checks; only `run.txt` with `stage=complete`
and `status=0` confirms the peer audit and wrapper cleanup also passed.
Unsupported private cgroup/systemd startup exits with status 77, not a pass.
The release workflow runs this after functional E2E only for Tumbleweed
`linux/amd64`, with both backends, and preserves diagnostics on success or failure.
The container needs `CAP_SYS_ADMIN` for systemd, but the daemon retains only its
packaged capability set. Host PID/network namespaces and host cgroup binds are
not used; no host service or firewall is changed. This test does not certify
host AppArmor/SELinux policy: SELinux container labels are disabled and only the
systemd client uses `apparmor=unconfined` so the container can mount its private
sandbox. The peer keeps its default AppArmor profile. These are per-container
settings, not host policy changes; see [Docker's AppArmor documentation](https://docs.docker.com/engine/security/apparmor/).
The daemon's systemd restrictions are checked separately.

## Large TCP writes and GSO

[`../e2e/gso-attribution.sh`](../e2e/gso-attribution.sh) extracts the daemon from
the specified RPM and tests it in an isolated Tumbleweed x86_64 container with
an independent TCP peer in a separate container. Run from the repository root,
once per backend:

```console
bash tests/e2e/gso-attribution.sh nftables /absolute/openshield-package.rpm
bash tests/e2e/gso-attribution.sh iptables /absolute/openshield-package.rpm
```

The fixed-seed workload uses real TCP sockets, `TCP_CORK`, and application
writes of 128 bytes, 64 KiB, 256 KiB, and 1 MiB; it does not generate synthetic
TCP packets. It checks Learning, a connection held across the transition to
Enforcing and policy-generation change, new Enforcing connections, denial of
an unknown executable and changed argv, and continued authorized access after
those negative probes. SHA-256 replies and independent peer record counts check
data integrity and prevent blocked replies from masking unauthorized delivery.
NFQUEUE kernel/user drops, overflow, attribution timeouts, and terminal queue
errors must not increase; both application queues must actually be exercised.

A passive device observer requires outgoing IPv4 TCP skbs larger than the
1500-byte MTU. For nftables, trace evidence separately records large-skb
traversal of Learning queue 1338 and Enforcing queue 1337, and new-connection
queue use. See `trace_scope` and `queue_trace_proven` in the JSON report:
an unobserved large Enforcing queue subcase is explicitly reported as untested,
not passed, because established TCP may use the kernel fast-path. For iptables,
the large-queue trace fields and `queue_trace_proven` are `null`; device-level
offload observation and Enforcing new-connection queue checks still apply.
These observations do not independently inspect the kernel's `NFQA_SKB_GSO`
attribute on delivered queue messages.

The script retains JSON results, peer records, daemon logs, available traces,
and exact RPM/daemon hashes under the printed `/tmp/openshield-gso-evidence.*`
path, then removes its containers and network. This is an IPv4 TCP functional
regression, not a throughput, retransmit, or latency benchmark. IPv6, BIG TCP,
and UDP segmentation offload have parser unit coverage but are not exercised
by this runtime fixture. As with the other container fixtures, the kernel under
test is the host kernel, not a booted Tumbleweed kernel.
