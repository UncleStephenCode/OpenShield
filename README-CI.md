[English](README-CI.md) | [Русский](README-CI.ru.md)

# OpenShield CI and releases

The authoritative release-CI documentation is
[`.github/README-CI.md`](.github/README-CI.md). The workflow itself is
`.github/workflows/release.yml`, and its machine-readable support contract is
`packaging/ci/release-matrix.json`.

The release graph is fail-closed:

```text
Validation
    -> Quality Gate
    -> 43 family/architecture binary builds
    -> 43 family/architecture package builds
    -> 37 distribution/platform installations for 19 package variants
    -> pinned init-system container tests
    -> 74 firewall E2E jobs
    -> bounded nftables/iptables performance smoke
    -> sealed release candidate and evidence
    -> publication
```

Only after all 74 functional firewall jobs pass, one bounded performance smoke
uses the exact `binary-tumbleweed-amd64` daemon from the release run on one
openSUSE Tumbleweed `linux/amd64` stand. It exercises nftables and iptables in
disposable Docker namespaces, has a 1800-second harness limit and a 45-minute job
limit, and uploads validated JSON, CSV, and Markdown reports. The checked-in
release profile requires both backends to pass and rejects invalid or saturated
measurements. Its relative thresholds remain 10%, and every per-window delta
and crossing remains in the evidence. In release smoke,
`cpu_latency_relative_regressions_are_advisory: true` makes only the paired
DUT-cgroup CPU and request/TCP-connect latency regressions advisory on the
shared runner. Their means and one-sided 95% Student-t bounds are still
reported, but do not by themselves block publication. A paired throughput or
DUT-PPS reduction remains blocking when the one-sided 95% lower confidence
bound over at least three independent, adjacent steady AB/BA pairs exceeds
10%. A mean-only crossing is retained as an observation instead of turning
shared-runner variance into a release failure. Absolute daemon
CPU/RSS and p99-latency ceilings, target attainment, validity, and burst
capacity remain mandatory. A single burst has no repeated-sample confidence
claim, so its relative crossings are observations; its absolute capacity,
validity, and safety checks remain blocking.
Drops, retransmits, NFQUEUE errors, and fail-open behavior are immediate
failures rather than statistical decisions. The independent controlled-overload
canary proves the absence of fail-open behavior: application-bound Enforcing
traffic remains fail-closed while the queue consumer is unavailable. This
release-only smoke is not run by
the pull-request workflow and is not a portable benchmark or a support claim
for every architecture.

Every independent CI block has a 1.0-second warm-up. The complete two-backend
workload plan is estimated at 609.6 seconds and must remain below its explicit
620-second workload bound. The finite keep-alive target model uses a
worker-local Poisson competing-risk estimate instead of assuming simultaneous
socket expiry. It charges four close packets plus a three-packet replacement
handshake to the existing PPS and CPS caps; the checked-in pure keep-alive
profile keeps `pps = 1280` and `cps = 160` and yields
`200.874426 operations/s`. Configured intensities and the numerical 10% release
thresholds are not reduced. Only the release-smoke classification of relative
CPU and latency crossings is advisory; the production-like profile sets
`cpu_latency_relative_regressions_are_advisory: false` and keeps them blocking.

The overload pressure client uses an explicit ready/start barrier before the
daemon is stopped. On the same canary veth, a separate same-transport
network-only liveness endpoint must succeed immediately before and after every
application-bound wrong-executable probe. Generator, pressure-peer, or canary
resource saturation and socket/NIC errors invalidate the proof. UDP drain ACKs
are emitted only after a bounded exact contiguous per-flow sequence prefix is
proved; no UDP ordering guarantee is assumed.

If the daemon reports a `BlockAll` quarantine, canonical kernel snapshots and
daemon status bracket real TCP and UDP negative probes. A real loopback round
trip inside the canary container must also succeed immediately before and after
each negative probe, so a dead peer cannot be mistaken for quarantine.

Each backend records the pinned Docker image ID, exact `x86_64` machine,
openSUSE Tumbleweed `/etc/os-release`, `uname`, `repo-oss` metadata SHA-256,
and exact sorted RPM NEVRA inventory. Image, OS, machine/kernel, and repository
metadata must match across the two topology runs. RPM manifests are retained
separately: the nftables topology must have the expected exclusive `nftables`
package, while all other dependency differences remain explicit evidence and
are not silently treated as equality. This makes a run auditable, but a signed
live Tumbleweed repository is still mutable across runs. Publication-grade
numbers require a prebuilt digest-pinned performance image, a dedicated runner,
and retained evidence; CI success by itself is not a claim that a full
publishable performance run succeeded.

The runtime matrix contains 37 pinned distribution/platform rows: 16 `amd64`,
15 `arm64`, and 6 `386`. Every row executes both the nftables-preference and
iptables-only fallback scenarios. `amd64` and `arm64` use native GitHub-hosted
runners; `linux/386` uses the x86-64 kernel's direct 32-bit compatibility path.

All 43 binary and 43 package targets are still built. The other 24 package
variants for ARMv5/6/7, PowerPC64LE, RISC-V 64, and IBM Z are build-only:
they account for 49 of the 86 declared distribution/platform mappings. Their
Cross/QEMU lanes provide ELF and capability-free `--version` smoke evidence,
but no package-install or firewall-runtime evidence. Publication of one of
these artifacts is not a runtime-support or native-hardware claim.

Each runtime-tested package is linked to its installation and firewall evidence
by asset name and SHA-256; build-only packages carry build and asset-integrity
evidence instead. Before making any publication API request, the write-capable
job independently verifies the tag, source revision, matrix hash, complete
asset inventory, file sizes, digests, and `SHA256SUMS`.

GitHub's ZIP artifact transport normalizes regular files to mode `0644`.
Release Evidence therefore treats the downloaded raw ELF files as byte-level
transport copies and requires that mode explicitly. The publishable `tar.xz`
remains the authority for executable metadata: it must contain exactly the
daemon and TUI as regular `0755` members whose sizes and SHA-256 contents match
the transport copies. Package assembly restores `0755` explicitly.

To create a release, set `[workspace.package].version` in `Cargo.toml`, commit
the complete change, and create the matching `vX.Y.Z` tag on that commit. A
numeric `X.Y.Z` tag without the mandatory `v` prefix reaches Validation only,
where it fails with an explicit diagnostic; it can never reach compilation or
publication. Recovery of an already published release is allowed only through
the explicit `workflow_dispatch` repair option; existing assets with different
bytes are never overwritten.
