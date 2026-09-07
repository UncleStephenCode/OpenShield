[English](README.md) | [Русский](README.ru.md)

# Packaging and service integration

OpenShield provides package-staging assets for systemd, OpenRC, SysVinit,
runit, s6, and dinit. These files implement the same security lifecycle:

1. create or verify the `openshield` observation group;
2. install kernel `BlockAll` before starting the long-running daemon;
3. start the daemon as root from the fixed `/usr/bin/openshield-daemon` path;
4. install kernel `BlockAll` again after a supervised stop;
5. leave the persisted requested mode unchanged across the shutdown quarantine.

The normal initial persisted mode is `Learning`. It permits unmatched local
outbound traffic, keeps enabled explicit `drop`/`reject` rules active, and
creates enabled `accept` endpoint rules plus one disabled
template with a path and, when available, cgroup per observed application
group. The pre-start quarantine
is a temporary kernel policy, not a replacement for that saved mode. New
inbound service traffic remains default-deny; exact normal-mode DHCP/IPv6
control exceptions are absent from `BlockAll`.

## Staging a package tree

Build release binaries first. Then call the staging helper with an existing,
caller-owned, safely permissioned package root, one supported init-system name,
and the absolute directory containing both binaries:

```console
packaging/stage-install.sh /absolute/package-root systemd /absolute/release-dir
```

Replace `systemd` with `openrc`, `sysvinit`, `runit`, `s6`, or `dinit` as
needed. The helper validates its arguments and refuses `/`, `..` components,
symbolic links in lexical destination components, foreign-owned objects,
group/world-writable directories, and multiply linked regular files anywhere
in the staging tree. It also validates canonical ancestry before every write;
only caller- or system-owned safe parents are accepted, with the conventional
system-owned sticky `/tmp` exception. Filesystem probes stop at the first
rejected object. It never enables or starts a host service. It stages:

- both binaries in `/usr/bin`;
- the license in `/usr/share/openshield`;
- the group helper in `/usr/libexec/openshield`;
- the sysusers and tmpfiles declarations for systemd, or the selected
  non-systemd service files in their conventional directories.

The staging caller is trusted not to change the verified tree concurrently.
Use a fresh, private package root and do not share write access while staging;
the helper is not a defense against a malicious caller racing its own tree.

Install this tree through the target distribution's package manager. Package
maintainer scripts must create the group before the first start. systemd
packages should invoke sysusers and tmpfiles before the first manual start so
the standard root-owned `0600` `/run/xtables.lock` exists. Other packages may invoke the
fixed `/usr/libexec/openshield/ensure-group` helper as root; it is idempotent and
uses only fixed account-management commands.

Do not start the service automatically during an unattended remote package
upgrade unless an inbound management rule and an independently tested recovery
path already exist. Inbound traffic is default-drop even in `Learning`.

State and IPC compatibility is forward-only from v0.2.0 to v0.2.1. v0.2.1 reads
an absent rule `action` as `accept`, but v0.2.0 cannot read v0.2.1
`drop`/`reject` actions or `template` origins. Do not run mixed daemon/TUI
versions or perform an in-place downgrade after v0.2.1 has written state.
Upgrade or rollback from a protected console with kernel `BlockAll` active, a
reviewed state backup, and a distribution-tested procedure.

## Release-package matrix

The authoritative release workflow builds 43 architecture/family binaries and
43 matching packages. Its runtime submatrix covers 19 package variants in 37
pinned distribution/OCI-platform rows: 16 `amd64`, 15 `arm64`, and 6 `386`.
Installation evidence remains independent for every selected distribution
version and platform. Each installed-package row runs both the nftables and
iptables Learning-to-Enforcing scenarios, for 74 firewall jobs that must
succeed before publication. These are workflow gates, not a claim that a newly
edited matrix has already passed.

Native runners execute `amd64` and `arm64`; `386` uses the x86-64 kernel's
direct 32-bit compatibility path. The other 24 ARMv5/6/7, PowerPC64LE, RISC-V
64, and IBM Z package variants account for 49 of the 86 declared
distribution/platform mappings and are build-only. Their digest-pinned
Cross/QEMU lanes provide ELF validation and a target-image `--version` smoke,
but no package-install, firewall, or native-hardware evidence. See the [release
CI guide](../.github/README-CI.md) for the exact matrix and evidence boundary.

## Init-system notes

| Init system | Staged service | Ordering and supervision |
| --- | --- | --- |
| systemd | `/usr/lib/systemd/system/openshield-daemon.service` | `Type=notify`, before and required by enabled `network-pre.target`, restart on failure, pre-start and post-stop quarantine |
| OpenRC | `/etc/init.d/openshield` | requires local mounts, orders before `net`, supervised background PID, pre-start and post-stop quarantine |
| SysVinit | `/etc/init.d/openshield` | LSB metadata, `start-stop-daemon`, PID/executable validation, quarantine around lifecycle |
| runit | `/etc/sv/openshield/` | foreground `run`, readiness `check`, and `finish` quarantine |
| s6 | `/etc/s6/sv/openshield/` | `longrun`, filesystem dependency, foreground `run`, and `finish` quarantine |
| dinit | `/etc/dinit.d/openshield*` | scripted preflight dependency, supervised process, restart delay, stop quarantine |

Service enablement paths and commands vary among distributions. Packages should
use the distribution's native preset/enable policy rather than creating an
unverified generic symlink. None of these service files controls initramfs or a
network path that ignores the init system's declared ordering.

The daemon itself requires effective UID 0. Its systemd primary group stays
`root`; `openshield` is explicitly added as a supplementary group so the daemon
can assign it to its own observation socket without `CAP_CHOWN`. That group
authorizes read-only monitoring and is not the daemon's primary execution
identity.

## Verification

Static staging, file-mode, syntax, dependency, and symbolic-link rejection
checks:

```console
scripts/test-init-matrix.sh validate
```

Container parser/supervisor fixtures:

```console
scripts/test-init-matrix.sh manifests
scripts/test-init-matrix.sh containers-clean
```

The container harness checks OpenRC parsing, SysVinit `start-stop-daemon`
semantics, runit and s6 lifecycle/quarantine hooks, dinit service parsing, and
group-helper behavior. Alpine/BusyBox also executes the staging helper against
an isolated package tree. Unsafe ownership, mode, link, and symlink fixtures are
expected to be rejected. systemd is covered by static staging and separate
`systemd-analyze` checks; the complete tmpfiles create/relabel declaration also
passed idempotent application and exact metadata checks in pinned Tumbleweed.
The harness does not boot systemd in a container.
Stub daemons are used, so these checks do not exercise a real kernel firewall,
NFQUEUE, boot sequence, or service-manager recovery after a firewall error.

Run the real firewall end-to-end workflow only in its disposable, isolated
Docker network as described in [the compatibility guide](../tests/compat/README.md).

For systemd-specific capability and readiness details, see
[daemon/README.md](daemon/README.md).
