[English](README.md) | [Русский](README.ru.md)

# systemd daemon packaging

This directory contains the systemd unit, sysusers declaration, and tmpfiles
declaration. The unit is valid for both the preferred nftables backend and the automatic
`iptables`/`ip6tables` fallback.

Install these files through the package manager:

| Source | Destination | Mode |
| --- | --- | ---: |
| `openshield-daemon.service` | `/usr/lib/systemd/system/openshield-daemon.service` | `0644` |
| `openshield.sysusers` | `/usr/lib/sysusers.d/openshield.conf` | `0644` |
| `openshield.tmpfiles` | `/usr/lib/tmpfiles.d/openshield.conf` | `0644` |
| release daemon | `/usr/bin/openshield-daemon` | `0755` |
| release TUI | `/usr/bin/openshield-tui` | `0755` |

Run `systemd-sysusers` and `systemd-tmpfiles --create` before starting the
service. The daemon deliberately refuses partial startup when the required
`openshield` group cannot be resolved.

## RPM firewall and runtime dependencies

Every RPM declares the rich dependency `(nftables or iptables)` and recommends
`nftables`. A normal solver therefore installs the preferred nftables frontend,
while an iptables-only installation remains valid when nftables is unavailable
or recommendations are disabled. At runtime OpenShield still selects nftables
first and uses `iptables`/`ip6tables` only as its fallback.

Every RPM also requires `/usr/bin/systemd-tmpfiles`. The path dependency lets
the distribution select its native provider, including `systemd-mini` where
available, and guarantees that the post-install script can create and relabel
the exact runtime paths before the first manual start.

Every release-matrix RPM payload is required to be statically linked and to
have no ELF `PT_INTERP` segment. The build-time ELF gate enforces this boundary
for all package targets; package-install tests repeat it for the runtime-tested
`amd64`, `arm64`, and `386` variants. The other architectures are build-only
and carry no package-install evidence. Static linkage does not remove the Linux
kernel-version and userspace compatibility constraints recorded by the release
evidence.

## Runtime objects

The service creates or verifies:

- `/run/openshield`, pre-created by tmpfiles as `root:root` and `0755`;
- `/var/lib/openshield`, pre-created by tmpfiles as `root:root` and `0700`;
- `/run/openshield/control.sock`, owned by UID 0 and mode `0600`, for UID-0
  mutation (its group is intentionally irrelevant at that mode);
- `/run/openshield/observe.sock`, `root:openshield` and `0660`, for read-only
  monitoring by root and members of `openshield`;
- `/run/openshield/daemon.lock`, a root-owned regular `0600` singleton lock;
- `/run/xtables.lock`, the standard root-owned `0600` xtables serialization
  lock created by tmpfiles;
- `/var/lib/openshield/state.json`, a root-owned `0600` atomically persisted
  state file.

Unix-socket permissions are only the first check. The daemon also authenticates
control and observation peers with Linux `SO_PEERCRED`, including a bounded,
stable supplementary-group check for observers. Do not relocate the sockets to
a shared temporary directory or weaken ownership checks.

`ProtectSystem=strict` leaves only the two OpenShield directories and the
pre-created `/run/xtables.lock` writable. The file-level exception is required
because both old and new xtables implementations default to that shared lock;
using a private lock would stop OpenShield from serializing with other xtables
processes. The daemon clears the environment of firewall subprocesses, so a
service-level `XTABLES_LOCKFILE` override is intentionally not part of this
contract. The tmpfiles rules adjust and relabel only the two exact directories
and the exact lock path, never their contents recursively. They do not truncate
an existing lock or grant group write access. Packages must apply the
declaration before the first manual service start; at boot the unit is ordered
after and requires
`systemd-tmpfiles-setup.service`.

## Startup and shutdown boundary

`ExecStartPre` invokes the fixed, root-only
`openshield-daemon --install-fail-closed` action. The long-running daemon repeats
the kernel `BlockAll` bootstrap before reading or activating policy. On a fresh
installation it persists `Learning`; an existing saved mode remains unchanged.
The saved policy is activated only after validation and all three fixed NFQUEUE
consumers are available: fail-closed queue 1337 for Enforcing and Learning
application denies, bounded asynchronous observational Learning queue 1338,
and fail-closed reply-retry queue 1339. The last queue can only drop or repeat
the INPUT policy; it never authorizes traffic itself.

The main process uses `Type=notify` and sends `READY=1` only after the policy,
all NFQUEUE consumers, and verified IPC sockets are active. `ExecStopPost` installs
kernel `BlockAll` after the main process releases its singleton lock. Graceful
shutdown inside the daemon also installs this quarantine without changing the
persisted mode.

The unit has `Before=network-pre.target` and, when enabled, its
`RequiredBy=network-pre.target` link makes standard consumers depend on
successful readiness. Merely installing the unit does not create that link.
A network manager, initramfs component, unit, or early packet path that bypasses
`network-pre.target` also bypasses this ordering. Strict whole-boot filtering
requires distribution-specific validation or an initramfs policy.

`Restart=on-failure` repeats the fail-closed pre-start action. Do not delete
`daemon.lock`: each operation opens it with `O_NOFOLLOW|O_CLOEXEC`, verifies its
metadata, and locks the same persistent inode before state or firewall changes.

## Privileges and hardening

The unit uses `ProcSubset=all` with `ReadOnlyPaths=/proc`, not `ProcSubset=pid`.
The latter hides the nested `/proc/self/net/netfilter/nfnetlink_queue` entry
needed by the bounded reply scheduler, even when direct `/proc/self/net/icmp`
lookups work. `ProtectProc=invisible`, kernel-tunable protection, the capability
set and syscall restrictions remain enabled. General procfs metadata becomes
readable; this is an explicit filesystem-visibility tradeoff, not a relaxation
of packet authorization. Do not restore `ProcSubset=pid` in a local override.
After binding its queues and before starting workers or activating the saved
policy, the daemon validates the real queue-progress entry and netlink owner.
Failure leaves the bootstrap `BlockAll` policy in place, without reporting
readiness. A stale service override or an LSM denial must be corrected before
startup; the daemon does not guess queue progress or permit unverified replies.

The service runs with UID 0 and primary group `root`, and explicitly adds the
supplementary group `openshield`. As the socket owner it may assign that group
to the observation socket without retaining `CAP_CHOWN`. Keeping `Group=root`
and managing the directories with non-recursive tmpfiles rules prevents systemd
from changing preserved runtime locks or persistent state before exec. The
service retains
`CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_SYS_PTRACE`, and `CAP_DAC_READ_SEARCH`. Legacy xtables requires
`CAP_NET_RAW` to open the raw IPv4/IPv6 sockets used for alternate-backend
inspection and fallback operation. The last two capabilities are needed to
associate a queued socket inode with protected `/proc/<pid>` metadata across
local UIDs. The syscall filter denies direct inspection calls including `ptrace`, `process_vm_*`,
`kcmp`, `pidfd_getfd`, and `open_by_handle_at`.

The dynamically recomputed L3 `KernelNative`, L2 `ConntrackHybrid`, and L1
`Nfqueue` names reported by `StatusV2` classify the active policy path. They
are not kernel-capability levels or fallback implementations for an unchanged
policy. The only automatic startup backend fallback is from nftables to the
complete iptables/ip6tables bundle. These classifications do not load
eBPF. The packaged daemon deliberately adds neither `CAP_BPF` nor a kernel module,
boot-parameter change, or MOK enrollment to the packaged service.

The userspace fast path introduced in v0.1.32 needs no additional capability: it batches at
most 32 already-ready NFQUEUE packets while retaining per-packet `SOCK_DIAG`,
bounded before/after procfs owner snapshots, mandatory identity consensus, and
one absolute deadline (2 seconds for queue 1337, 5 seconds for asynchronous
Learning; each `SOCK_DIAG` query is capped at 250 ms). Pinned, rewound fd-directory
walks with reusable buffers need no additional capability and preserve both owner
snapshots. Queue 1338 separately limits the first eligible observation wait to
250 ms, with 128 pending packets and a 5 ms reader poll; pending verdicts require
the same current Learning mode/generation and no shutdown. It does not introduce
an authorization cache or guarantee rules for one-way UDP senders that exit before
procfs capture. nftables table/chain/counter observation uses
one fixed process per second with the same integrity checks. No package, LSM,
Secure Boot, or kernel-module configuration change is required.

This is attack-surface reduction, not complete isolation. After daemon
compromise, retained capabilities can still permit access to process memory and
files through other system calls or procfs magic links. Review the
[threat model](../../docs/THREAT_MODEL.md) before deployment.

## SELinux and AppArmor

The package does not select an `SELinuxContext=` or `AppArmorProfile=` and never
disables either LSM. tmpfiles creates the runtime directory, state directory,
and shared xtables lock as `root:root`, then restores those three exact paths to
the contexts defined by the installed SELinux file-context database. The
non-recursive `z` rules do not relabel their contents.

This is compatibility with the distribution's standard policy, not a bundled
confinement policy for OpenShield. A locally supplied SELinux domain or AppArmor
profile must explicitly cover the daemon's documented files, procfs attribution,
socket families, capabilities, and fixed nftables/xtables executables. Diagnose
policy failures while enforcement remains enabled:

```console
systemctl show openshield-daemon.service -p Group -p SupplementaryGroups
ls -ldZ /run/openshield /var/lib/openshield /run/xtables.lock
sudo ausearch -m AVC,USER_AVC -ts boot
sudo journalctl -k -b --grep='apparmor="DENIED"'
```

On SELinux systems, `matchpathcon -V` can compare an existing path with policy;
`restorecon -v` on the three exact paths above safely reapplies policy-defined
contexts. Do not work around a denial with `setenforce 0`, `aa-complain`, a
blanket allow rule, or unreviewed `audit2allow` output.

## Operational warning

Fresh state is `Learning`, but inbound traffic is default-drop in every mode.
First activation can terminate the only SSH or VPN session. Use a local console
or independent out-of-band access, create a narrowly scoped inbound management
rule, verify a second session, review learned outbound rules, and only then move
to `Enforcing`. `Learning` permits unmatched locally originated outbound
traffic while enabled explicit `drop`/`reject` rules remain active;
successfully attributed endpoints become enabled `accept` rules. It also creates
one disabled template with a path and, when available, cgroup per application
group. Enabling that broad template is a root-only change and pins the executable
version at that moment. Disabling an unchanged template restores its canonical
unpinned skeleton, so each later enable repins the current file; edited
non-skeleton templates retain their full specification and pin while disabled.
In either normal mode, enabled outbound rules apply `accept`, `drop`, or
`reject`; `enabled: false` makes any rule inert. Learning's default allow does
not override an enabled explicit deny. Inbound rules remain accept-only.

Do not run another privileged firewall manager unless chain ordering, the upper
two packet-mark bits, and OpenShield's low 31 conntrack-mark bits have been
reviewed. Conntrack bit 31 is preserved. OpenShield health monitoring is not a
proof that arbitrary concurrent ruleset edits are safe.
