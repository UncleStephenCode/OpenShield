[English](README-CI.md) | [Русский](README-CI.ru.md)

# Release CI architecture

The release workflow treats validation, compilation, packaging, installation,
runtime verification, and publication as separate trust boundaries. A later
stage may consume only artifacts and evidence produced by its declared
predecessors.

## Release dependency graph

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

The stages have the following responsibilities:

1. **Validation** binds the requested tag to the checked-out source revision,
   checks the workspace version, validates the release-matrix schema and unique
   row identifiers, and verifies that every referenced image is pinned by
   digest and contains the declared OCI platform.
2. **Quality Gate** runs the repository-wide formatting, lint, locked test, and
   static packaging checks before any release binary is accepted.
3. **Binaries** uses one matrix job to compile the daemon and TUI for every
   package-family/architecture pair. Each artifact carries its target identity,
   is checked as an ELF file, and is smoke-run in a pinned image of that family
   before it can be packaged.
4. **Packages** produces the DEB, RPM, APK, and Arch artifacts from those exact
   binaries. Identical family/architecture packages are built once and reused
   by all applicable distribution rows.
5. **Install Matrix** installs 19 runtime-tested package variants with the
   native package manager in 37 authoritative distribution/platform rows. The
   other 24 package variants are explicitly build-only and do not acquire
   installation evidence.
6. **Container Tests** exercises the pinned OpenRC, SysVinit, runit, s6, and
   dinit parser/supervisor fixtures after every package-install row succeeds.
7. **Firewall E2E** runs the complete Learning-to-Enforcing policy scenario
   twice for each of the 37 runtime-tested distribution/platform rows: once with
   nftables preferred and once in an iptables-only fallback environment (74
   jobs in total). The two openSUSE Tumbleweed `linux/amd64` jobs additionally
   run a real-socket Learning-to-Fast-Enforcing regression with TCP and UDP,
   process churn, a same-UID process holding 5,000 descriptors, and another
   process instance with changed argv but the same executable file. This catches
   cache-wide invalidation, desktop descriptor-limit regressions, and
   Strict/Fast learned-selector regressions before the performance gate.
8. **Performance Smoke** starts only after all 74 functional E2E jobs succeed.
   One openSUSE Tumbleweed `linux/amd64` stand runs a bounded nftables/iptables
   profile against the exact release `binary-tumbleweed-amd64` daemon in
   disposable Docker namespaces and validates the generated machine-readable
   and human-readable reports.
9. **Release Evidence** collects the source revision, matrix revision, image and
   platform identities, artifact hashes, the 37 package-install results, the 74
   backend-test results, and the expected inventory of all 43 binary archives
   and 43 packages. Evidence completeness is checked against the authoritative
   matrix rather than inferred from whichever jobs happened to finish. GitHub's
   ZIP transport normalizes raw files to `0644`; those ELF copies are verified
   as transport bytes, while exact `0755` executable modes and matching content
   are required inside each publishable `tar.xz` archive.
10. **Publish** is reachable only when the performance gate has passed and every
   required evidence record and release asset is present and consistent.
   Publication remains resumable, but an existing asset is never silently
   replaced with different bytes.

Validation and the Quality Gate therefore precede every release compilation;
package installation and firewall testing consume packages produced during the
same run, not binaries rebuilt inside test jobs. This runtime gate applies only
to package variants explicitly selected by the matrix.

Release tags use the canonical `vX.Y.Z` form and must point to the commit that
contains the same workspace version. Semver-like `X.Y.Z` tags without `v` are
included in the workflow trigger only so Validation can report the naming
error; all build, packaging, testing, and publication jobs remain unreachable.

Compilation runs on a native hosted runner or inside a digest-pinned Cross
toolchain container. It is intentionally not bootstrapped from each target
distribution's mutable package repository. The resulting static binary is then
executed in a pinned image of its package family. For the runtime-tested subset,
the exact package is also installed and tested in every declared distribution
image.

## Authoritative release matrix

[`packaging/ci/release-matrix.json`](../packaging/ci/release-matrix.json) is the
authoritative machine-readable list of release validation rows. It contains 43
binary/package family/architecture build targets, 86 declared
distribution/platform mappings, and a 37-row runtime submatrix covering 19
package variants:

| Distribution rows | Built package targets | Package-install and firewall E2E targets |
| --- | --- | --- |
| Debian 12 | `386`, `amd64`, ARMv7, `arm64`, `ppc64le` | `386`, `amd64`, `arm64` |
| Debian 13 | `386`, `amd64`, ARMv5, ARMv7, `arm64`, `ppc64le`, `riscv64`, `s390x` | `386`, `amd64`, `arm64` |
| Ubuntu 22.04, 24.04, and 26.04 | `amd64`, ARMv7, `arm64`, `ppc64le`, `riscv64`, `s390x` | `amd64`, `arm64` |
| Fedora 43 and 44 | `amd64`, `arm64`, `ppc64le`, `s390x` | `amd64`, `arm64` |
| Rocky Linux 9 / 10 | `amd64`, `arm64`, `ppc64le`, `s390x`; Rocky 10 also `riscv64` | `amd64`, `arm64` |
| AlmaLinux 9 / 10 | `amd64`, `arm64`, `ppc64le`, `s390x`; AlmaLinux 10 also `386` | `amd64`, `arm64`; AlmaLinux 10 also `386` |
| openSUSE Leap 16.0 | `amd64`, `arm64`, `ppc64le`, `s390x` | `amd64`, `arm64` |
| openSUSE Tumbleweed | `386`, `amd64`, ARMv6, ARMv7, `arm64`, `ppc64le`, `riscv64`, `s390x` | `386`, `amd64`, `arm64` |
| Alpine 3.23 and 3.24 | the same eight targets as Tumbleweed | `386`, `amd64`, `arm64` |
| Arch Linux | `amd64` | `amd64` |

The matrix is the release contract. All 43 binary archives and 43 packages are
built, but only the 37 selected distribution/platform rows acquire package
installation and firewall evidence. A package family is shared across
compatible image versions: for example, one runtime-tested DEB per architecture
is installed independently in every selected Debian and Ubuntu userspace that
publishes that architecture. The remaining 24 package variants account for 49
declared distribution/platform mappings; they are published as build-only
artifacts and carry no runtime-support claim.

This release matrix must not be confused with
[`tests/compat/distros.tsv`](../tests/compat/distros.tsv). The latter contains
60 maintained, rolling, legacy, and archived images used for broad portability
research. Its static-musl `--version` smoke tests do not install a package,
start an init system, initialize NFQUEUE, or exercise a firewall policy. A row
in that research matrix is not a release-support declaration.

## Architecture evidence

- `amd64` jobs execute natively on an x86-64 runner.
- `arm64` jobs execute natively on an AArch64 runner.
- `linux/386` packages execute through the x86-64 kernel's direct 32-bit
  compatibility path; this is not a test on a physical 32-bit processor.
- ARMv5, ARMv6, ARMv7, PowerPC64LE, RISC-V 64 and IBM Z builds use
  SHA-256-pinned Cross toolchain images and a pinned QEMU `binfmt_misc` handler
  only for target-image binary `--version` smoke tests. Their packages are not
  installed and their firewall is not exercised in release CI.

For QEMU binary-smoke rows, the workflow registers only the required
`binfmt_misc` handler by directly running the SHA-256-pinned `tonistiigi/binfmt`
image on the ephemeral runner. It does not depend on a third-party setup action.
The registration container is necessarily privileged and is explicitly refused
on self-hosted runners. Registration is followed immediately by checks of the
enabled handler, fix-binary flag and interpreter, then by a network-isolated,
capability-free probe in the pinned foreign-platform image. Any mismatch fails
the binary build job before its artifact is accepted.

QEMU success is retained only in the binary-build job log as emulated
binary-smoke evidence; it is not a runtime record in `RELEASE-EVIDENCE.json`. It
cannot certify package installation, firewall or NFQUEUE behavior, application
attribution, CPU-specific behavior, physical hardware, boot firmware, or a
distribution kernel. Those architectures require trusted native runners or
full-system hardware/VM test systems before runtime support can be claimed.

All Docker containers share the runner's Linux kernel. Even a native container
therefore validates the selected userspace, package manager, command-line
firewall tools, and isolated network namespace—not the kernel shipped by that
distribution or its complete boot sequence. Standard package-test containers
also do not boot systemd as PID 1.

## Firewall backend coverage

Each of the 37 runtime rows runs the complete Learning-to-Enforcing E2E
separately with nftables and with an iptables-only fallback installation: 37
jobs per backend, 74 in total. DEB and RPM use an explicit package-manager
alternative dependency. APK and Arch do not force-install one backend, because
those formats cannot express the same portable alternative; the installation
tests verify the package and dependency layout, while the separate firewall E2E
jobs prove that either backend can satisfy the runtime contract.

In an nftables scenario both frontends are installed and the daemon must still
select nftables. In an iptables scenario `nft` is absent, the complete IPv4 and
IPv6 xtables tool set must be available, and the daemon must select
`iptables/ip6tables`. This proves preference and fallback rather than merely
forcing a backend label.

OpenShield 0.1.31 additionally reports a dynamically recomputed, conservative
`StatusV2` active-policy path classification independently of that backend:
L3 `KernelNative` for `BlockAll` or
application-free `Enforcing`, L2 `ConntrackHybrid` for TCP-only application
`Enforcing`, and L1 `Nfqueue` for `Learning` or an enabled
UDP/ICMP/ICMPv6/`Any` application rule. Missing legacy data is `Unknown`, never
an inferred fast path. This classification describes the most expensive active
path; it is not kernel-capability attestation or a fallback sequence for an
unchanged policy. A network-only match remains in the kernel at L2 and L1. The
only automatic startup backend fallback is nftables to the complete
iptables/ip6tables bundle. Failure to make
mandatory NFQUEUE ready must leave the bootstrap `BlockAll` active and fail the
job. Version 0.1.31 does not contain an eBPF application data plane, add
`CAP_BPF`, or change boot/MOK state, and container results are not evidence for
such support in a distribution kernel.

## Bounded performance release gate

The performance job belongs only to the tag/`workflow_dispatch` release
workflow; the ordinary pull-request workflow does not run it. Its direct
dependency on the complete `e2e` matrix makes functional correctness a strict
precondition. The single openSUSE Tumbleweed `linux/amd64` job downloads
`binary-tumbleweed-amd64` from the same run, restores the daemon's executable
mode in a private runner directory, verifies its version, and passes that
absolute path to the performance harness. It does not rebuild the daemon or
expand into a distribution/architecture performance matrix.

`tests/perf/ci-smoke.sh` accepts only a local Unix-socket Docker context. For
each backend the harness creates separate pristine-baseline and protected DUT
generations with their own peers and internal networks; only the DUTs receive
the capabilities required for their private firewall namespaces. The daemon is
never started on the baseline DUT. Its captured environment must exactly equal
the protected environment while the immutable container IDs must differ. The
wrapper limits the enlarged paired harness to 1800 seconds, the workflow leaves
a 45-minute outer bound for cleanup and evidence upload, and report/log sizes
are bounded (`report.json` is capped at 20 MiB for the 576-row independent-pair
evidence set). Neither the
wrapper nor the harness runs `sudo`, `nft`, or `iptables` against the runner
host.

The canary network has two distinct same-transport endpoints on the same veth:
an application-bound target for wrong-executable probes and a network-only
liveness target. A liveness exchange must succeed immediately before and after
each blocked probe, so a broken canary path cannot masquerade as fail-closed.

The wrapper generates a fresh 128-bit run token and passes it to the harness;
every disposable container and network receives that exact Docker label. On a
normal exit, `TERM`, `INT`, or hard timeout, cleanup lists resources by the
label and then re-inspects every immutable ID before removal. It never prunes
Docker globally or selects resources by a shared name prefix. The Python runner
also turns cooperative termination signals into an exception so the current
backend's `finally` cleanup runs before the wrapper's bounded fallback cleanup.

The checked-in `tests/perf/config/ci-smoke.json` profile is a short regression
smoke, not a statistically portable benchmark. It retains every backend,
mode, policy path, and workload profile, with one half-load ramp and three
independent baseline/protected pairs containing one-second steady windows.
Each pair performs its own warm-up; the first pair performs the ramp and the
last performs the burst. Offered rates are sized to produce hundreds
of operations in each steady window instead of deriving percentiles from
single-digit samples. Every repeated window must pass. A pass requires all of
the following:

The warm-up in every independent CI block is 1.0 second. The validator derives
609.6 seconds of workload for the complete two-backend plan, below the explicit
620-second `max_total_workload_seconds` bound. The TCP target uses a
steady-state, worker-local Poisson competing-risk estimate for the lifetime
renewal rate `X(r)`, rather than assuming that all concurrent sockets expire at
`N / E[L]`. For pure keep-alive,
`X(r) = r / (1 + r * E[L] / N)`; mixed mode additionally accounts for short
requests that retire idle persistent sockets. Four close packets and a
three-packet replacement handshake are charged through
`P * r + 7 * X(r) <= configured_pps`, while CPS uses
`(1 - k^2) * r + X(r) <= configured_cps`. The checked-in keep-alive values keep
`pps = 1280` and `cps = 160` and yield `200.874426 operations/s`; neither those
intensities nor the numerical 10% release thresholds are lowered. The advisory
classification described below does not change those values.

The comparison order is fixed before measurement. Each exact group receives
three unique, single-use baseline/protected pairs whose order alternates AB/BA;
the starting order alternates between groups for global balance. A protected
block can use only its predetermined immediately adjacent baseline; observed
values never select a more favourable reference. `baseline_pairing` evidence
records the unique pair and baseline IDs, repetition, schedule, exact
environment equality, distinct DUT identities, order, monotonic block
boundaries, and comparison gap. The CI wrapper independently reconstructs and
validates the 576-row plan. The conservative maximum gap between authenticated
workload and DUT/peer collector steady-window boundaries is capped at 15 seconds;
exceeding that bound invalidates the evidence and blocks publication without
mislabeling environmental drift as a performance regression.

- the runner exits successfully before the hard timeout;
- `report.json` uses schema `openshield.perf.report.v2`, sets both `valid` and
  `passed` to `true`, contains valid
  `openshield.perf.baseline-pairing.v2` evidence, and reports nftables as
  `passed`;
- iptables is also `passed`; an `unsupported` result is neutral only for a
  profile that explicitly sets `allow_unsupported_iptables` to `true`, which
  the release smoke profile does not do;
- generator, pressure-peer, or canary resource saturation, socket-queue or NIC
  errors, an invalid sample, a failed blocking configured ceiling in a required
  steady/burst window, a missing backend, or a missing/malformed report fails
  the job;
- all per-window relative deltas and threshold crossings are retained. For
  throughput and DUT PPS, the release profile blocks when the one-sided 95%
  Student-t lower confidence bound over at least three valid, independent,
  adjacent pristine AB/BA pairs exceeds the unchanged 10% reduction limit. A
  mean-only crossing remains visible but does not turn shared-runner variance
  into a release failure. With
  `cpu_latency_relative_regressions_are_advisory: true`, the same calculation
  and one-sided 95% Student-t bound for relative DUT-cgroup CPU and
  request/TCP-connect latency are evidence only on the shared release runner;
  exceeding 10% does not by itself block publication. Absolute daemon CPU/RSS
  and p99-latency ceilings remain blocking. The longer production-like profile
  sets `cpu_latency_relative_regressions_are_advisory: false`, so every
  statistically confirmed relative regression over its 5% limits remains blocking;
- a separate source-manifested validator recomputes the canonical configuration
  SHA-256 and workload-time estimate from the checked-in JSON, then derives all
  steady paired deltas, means, strict threshold comparisons, advisory/blocking
  disposition, Student-t lower-bound decisions, and observation/failure linkage from primary
  measurements; report-provided aggregate decisions are not trusted;
- a single burst relative comparison remains an authenticated observation
  because it has no repeated-sample confidence claim, while burst validity,
  configured absolute capacity ceilings, and safety remain mandatory;
- the CI absolute daemon CPU ceiling is 95% of one core outside bursts
  (`maximum_daemon_cpu_percent_one_core`) and 150% during bursts
  (`maximum_burst_daemon_cpu_percent_one_core`). Both are blocking capacity
  limits, independently recomputed from primary measurements. The
  production-like profile sets both to 90%. Throughput/PPS, latency, RSS,
  validity, and safety limits are unchanged;
- application errors/loss, TCP retransmits, NIC drops/errors, NFQUEUE
  drops/errors, or fail-open behavior block immediately and are never deferred
  to the repeated-sample relative decision;
  the independent canary in the separate controlled-overload test proves the
  absence of fail-open behavior: application-bound Enforcing traffic remains
  fail-closed while its queue consumer is unavailable;
- the overload pressure client must publish readiness and wait at its explicit
  start barrier before the authenticated daemon process is stopped; the fixed
  saturation window must then show the configured NFQUEUE drop evidence, and a
  same-transport network-only liveness exchange must succeed immediately on
  both sides of every wrong-executable probe;
- a reported `BlockAll` quarantine additionally requires daemon status and
  canonical kernel snapshots bracketing real TCP and UDP negative probes, plus
  successful canary-container loopback round trips immediately before and
  after each negative probe;
- ordinary measurement windows require zero application loss/errors, TCP
  retransmits, NIC drops/errors, and NFQUEUE drops/errors;
  NFQUEUE drops are expected only in the explicitly controlled overload proof,
  where saturation must be observed, every application-bound wrong-executable
  probe must remain fail-closed, and the separate network-only canary must stay
  live;
- UDP drain acknowledgements count only after the server proves the exact
  contiguous per-flow sequence prefix within its fixed reordering bound; the
  gate never assumes UDP delivery order;
- daemon-observed NFQUEUE failures are gated on deltas of the typed,
  process-lifetime `status.data.nfqueue` counters; throttled daemon logs remain
  diagnostic lower bounds and are not authoritative pass evidence;
- `report.json` contains the exact unique set of backend/profile/policy/mode/
  load/phase windows derived from the checked-in profile; `report.csv` and
  `overload.csv` have their expected schemas and matching row counts; and all
  four report files are nonempty bounded regular files.

For each backend, `report.json` also records the content-addressed Docker image
ID, exact `x86_64` machine, parsed openSUSE Tumbleweed `/etc/os-release`, bounded
`uname`, `repo-oss/repomd.xml` SHA-256, and the exact sorted RPM NEVRA inventory.
Image, OS, machine/kernel, and repository metadata must match. RPM inventories
remain separate: the nftables topology must show its expected exclusive
`nftables` package, while any other dependency delta is retained as evidence
rather than requiring false full-manifest equality. Tumbleweed repository
metadata is signed, but the repository remains live: the evidence records the
selected package set without making it immutable across runs.

On success, the four report files are uploaded together as a 30-day GitHub Actions
artifact and the Markdown report is written to the job summary. On failure, a
seven-day diagnostic artifact contains the wrapper error plus whichever report
and run-log files are available and pass the wrapper's regular-file and size
checks. The performance job is a publication prerequisite, but its reports are
diagnostic workflow artifacts rather than published release assets.
Hosted-runner measurements are suitable for catching gross regressions against
conservative absolute ceilings only; they do not establish comparative
throughput, latency, hardware, distribution, or non-amd64 support claims.
Publication-grade performance numbers require a prebuilt performance image
pinned by digest, a dedicated runner, and retained environment and run
evidence. CI completion alone is not evidence of a successful full performance
run or a publishable numerical result.

## Pinned inputs and release evidence

Actions, downloaded build tools, Cross/QEMU environments, release-matrix
images, the E2E server, and all init fixtures are pinned to immutable revisions
or SHA-256 digests. A release-matrix image must
use `name@sha256:digest`; CI also checks that its manifest index contains the
row's explicit `linux/<architecture>` platform. The platform is always passed
to Docker so the daemon does not silently select the runner architecture.

Image pinning makes the base filesystem reproducible. Package repositories
consulted during installation can still change, so each of the 37 runtime rows
records the image digest, requested platform, execution mode, installed
OpenShield asset name and SHA-256, and both backend outcomes. Build-only
packages have no installation or backend record. The init gate records its
pinned images and script SHA-256. A successful manifest lookup alone is never
release evidence.

For openSUSE rows, CI refreshes only the required GPG-checked OSS repository
before provisioning. A libzypp status `4` during refresh is retried at most
three times with bounded backoff; every other status and every installation
transaction fails immediately. Installation disables implicit refresh, so a
partial repository update cannot be misreported as missing dependencies.

The evidence stage fails closed for missing, duplicate, unexpected, or
contradictory rows and assets. `SHA256SUMS` covers all published packages and
binary archives. Publication depends on both the successful performance gate
and that verified inventory; it cannot run directly after only the build or
package stages.
