#!/bin/sh
# PID 1 bootstrap for the isolated packaged-unit regression only.
set -eu
backend=$1
package=$2
case "$backend" in nftables|iptables) ;; *) exit 2 ;; esac
[ "$$" -eq 1 ] || { echo 'BLOCKED: bootstrap must be PID 1' >&2; exit 77; }
[ "$(cat /proc/self/cgroup)" = '0::/' ] || {
    echo 'BLOCKED: a private unified cgroup namespace is required' >&2; exit 77;
}
[ "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs ] || exit 77
# Docker supplied this mount at the PRIVATE cgroup namespace root. There is no
# host /sys/fs/cgroup bind, host PID namespace, or host network namespace.
mount -o remount,rw /sys/fs/cgroup || {
    echo 'BLOCKED: the private cgroup subtree cannot be made writable' >&2; exit 77;
}
# Tumbleweed repository metadata is updated in place. A pinned container can
# therefore observe a repomd.xml whose referenced files disappear while the
# mirror is rotating. Use the shared fail-closed helper: it validates the
# official origins, upgrades them to HTTPS, forces fresh metadata on retries,
# and alternates the two official openSUSE endpoints.
[ -f /opt/zypper-refresh.sh ] && [ ! -L /opt/zypper-refresh.sh ] || exit 1
sh /opt/zypper-refresh.sh repo-oss
packages='systemd python3 iptables shadow util-linux procps iputils'
[ "$backend" != nftables ] || packages="$packages nftables"
# shellcheck disable=SC2086
zypper --non-interactive --no-refresh install --no-recommends --repo repo-oss $packages
if [ "$backend" = iptables ] && command -v nft >/dev/null; then
    echo 'iptables fixture unexpectedly contains nft' >&2; exit 1
fi
rpm -Uvh "$package"
useradd --system --no-create-home --shell /bin/false sandboxapp
python=$(readlink -f "$(command -v python3)")
install -d -m 0755 /usr/libexec
install -m 0755 "$python" /usr/libexec/openshield-sandbox-allowed
install -m 0755 "$python" /usr/libexec/openshield-sandbox-unknown
mkdir -m 0755 /run/openshield-sandbox
exec /usr/lib/systemd/systemd --system --unit=multi-user.target
