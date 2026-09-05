[English](SECURITY.md) | [Русский](SECURITY.ru.md)

# Security policy

Please report suspected vulnerabilities privately to the repository owner before
opening a public issue. Include the affected revision, threat prerequisites, a
minimal reproducer, and the observed impact. Do not include live credentials or
data from systems you do not own.

The supported branch is `main`. Security fixes should add a regression test and,
where relevant, a threat-model update.

Control is local and root-only. Read-only monitoring is limited to root and
members of the `openshield` system group; membership grants access to network
rules, endpoints, events, mode, and counters and must be treated as a security
privilege. nftables is preferred, with a validated iptables/ip6tables fallback.

OpenShield deliberately treats all protocol input as untrusted, including input
from a local root client. The project forbids unsafe Rust in workspace code and
rejects shell execution, configuration-selected executables, and unbounded IPC
frames. NFQUEUE bypass is generated only for observational Learning queue 1338;
it is forbidden for fail-closed queue 1337, `Enforcing`, and `BlockAll`. Executable
paths in outbound rules are bounded, typed identity selectors; the daemon never
executes them.

Since OpenShield 0.1.31, the daemon reports its policy mode, selected firewall
backend, and dynamically recomputed active-policy path classification as separate `StatusV2`
fields. This classification is not kernel-capability attestation or fallback
negotiation for an unchanged policy. `KernelNative` means nftables/iptables policy evaluation, not an eBPF
application data plane. This release does not add `CAP_BPF`, a kernel module,
boot-parameter changes, or MOK enrollment. If mandatory NFQUEUE setup fails,
the daemon retains bootstrap `BlockAll` and exits; it never substitutes a
weaker network-only policy. Once Learning is active, failure or saturation of
the observational path does not block ordinary unmatched outbound traffic and
does not create a rule. Enabled explicit network and application `Drop`/`Reject`
rules remain active; application-deny candidates use fail-closed queue 1337.
The only automatic startup backend fallback is from nftables to the complete
iptables/ip6tables bundle when nftables cannot be validated.
When the running daemon has entered read-only fail-closed quarantine,
`StatusV2` uses the distinct `EmergencyBlockAll` reason and the TUI presents it
as an emergency; it is not confused with an operator-selected `BlockAll`.

Since v0.1.32, OpenShield amortizes procfs owner enumeration across at most 32
already-ready NFQUEUE packets without weakening attribution. `SOCK_DIAG` stays
per packet; two bounded owner snapshots bracket capture; reuse is confined to
one batch; mandatory process identity must reach consensus; and one absolute
250 ms deadline covers the whole batch, while one global owner-record cap covers
all targets in each snapshot. Typed
timeouts remain auditable. Every ambiguity or exhausted bound denies in
`Enforcing` and inside a Learning application-deny envelope; on observational
queue 1338 it prevents persistence after the immediate `NF_ACCEPT`. nftables runtime observation now obtains tables,
chains, and counters from one fixed process while retaining the same checks,
one-second cadence, and fail-closed repair policy.

Outbound rule activation and verdict are separate fields. Disabled rules are
inert. In either normal mode, enabled rules may accept, silently drop, or
actively reject. `Learning` allows unmatched outbound traffic and creates
learned `Accept` rules, but it does not override enabled explicit denies.
Inbound rules remain accept-only. Normal modes include only exact DHCP
bootstrap and essential IPv6 control-plane exceptions before their inbound
default deny; `BlockAll` includes none. A native `Reject` response is admitted only
for the exact RELATED/REPLY TCP RST, ICMP port-unreachable, or ICMPv6
port-unreachable shape carrying the current generation-bound OpenShield
connmark; all other RELATED traffic remains subject to the ordinary policy.
Automatically created application-wide templates are disabled and unpinned at
rest; enabling one requires root, pins the current executable version inside
the daemon, and deliberately grants the selected path/cgroup unrestricted
outbound access. Disabling an unchanged template restores that canonical
unpinned skeleton, and every later enable pins the then-current executable.
An edited non-skeleton template and other disabled rules retain their complete
specification and pin.

The operational boundary, fail-closed assumptions, and the material risks of
the daemon's retained procfs-inspection capabilities are documented in the
[threat model](docs/THREAT_MODEL.md).
The current audit evidence and unresolved limitations are listed separately in
[the security audit](docs/SECURITY_AUDIT.md).
