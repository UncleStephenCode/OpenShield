#!/bin/sh
# Exercise the INSTALLED unit under genuine systemd PID 1, not a bare daemon.
set -eu
[ "$#" -eq 2 ] || {
    printf 'usage: %s {nftables|iptables} ABSOLUTE_RPM\n' "$0" >&2; exit 2;
}
backend=$1
package=$2
case "$backend" in nftables|iptables) ;; *) exit 2 ;; esac
case "$package" in /*) ;; *) exit 2 ;; esac
[ -f "$package" ] && [ ! -L "$package" ] || exit 2
for tool in docker python3 sha256sum timeout; do command -v "$tool" >/dev/null || exit 2; done
case "${DOCKER_HOST:-}" in ''|unix:///*) ;; *) echo 'refusing remote Docker' >&2; exit 2 ;; esac
endpoint=$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')
case "$endpoint" in unix:///*) ;; *) echo 'refusing remote Docker context' >&2; exit 2 ;; esac
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
evidence=$(mktemp -d /tmp/openshield-systemd-evidence.XXXXXX)
token=${evidence##*/}
label="org.openshield.systemd-e2e.run=$token"
network=
client=
peer=
stage=initialization
image='opensuse/tumbleweed@sha256:8f6397b7b7ebc78e111d9a13fb2b157664ad5524e1f3b908deb45938b3095045'
# Keep the peer reference identical to the existing focused E2E fixtures.
peer_image='python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285'

cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ -n "$client" ]; then
        docker logs "$client" > "$evidence/container.log" 2>&1
        docker exec "$client" journalctl -u openshield-daemon.service --no-pager -o short-precise > "$evidence/daemon.log" 2>&1
        docker exec "$client" systemctl show openshield-daemon.service > "$evidence/unit-properties.txt" 2>&1
        docker exec "$client" systemctl cat openshield-daemon.service > "$evidence/unit.txt" 2>&1
        docker exec "$client" cat /proc/net/netfilter/nfnetlink_queue > "$evidence/queues-final.txt" 2>&1
        docker exec "$client" python3 /opt/ipc_client.py status > "$evidence/status-final.json" 2>&1
        docker exec "$client" cat /run/openshield/proc-visible.json > "$evidence/proc-visible.json" 2>&1
        for name in report.json proc-hidden.json unit-proof.json negative-startup.json; do
            docker exec "$client" cat "/run/openshield-sandbox/$name" > "$evidence/$name" 2>&1
        done
    fi
    if [ -n "$peer" ]; then docker logs "$peer" > "$evidence/peer.jsonl" 2>&1; fi
    for container in "$client" "$peer"; do
        [ -n "$container" ] || continue
        actual=$(docker inspect --format '{{index .Config.Labels "org.openshield.systemd-e2e.run"}}' "$container")
        if [ "$actual" = "$token" ]; then docker rm -f "$container" >/dev/null || result=1; else result=1; fi
    done
    if [ -n "$network" ]; then
        actual=$(docker network inspect --format '{{index .Labels "org.openshield.systemd-e2e.run"}}' "$network")
        if [ "$actual" = "$token" ]; then docker network rm "$network" >/dev/null || result=1; else result=1; fi
    fi
    printf 'backend=%s\nstage=%s\nstatus=%s\nrpm=%s\n' "$backend" "$stage" "$result" "$package" > "$evidence/run.txt"
    printf 'OpenShield systemd sandbox evidence: %s\n' "$evidence"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

sha256sum "$package" > "$evidence/package.sha256"
stage=provision
docker pull --platform linux/amd64 "$image" >/dev/null
docker pull --platform linux/amd64 "$peer_image" >/dev/null
network=$(docker network create --label "$label" "openshield-systemd-$token")
peer=$(docker create --platform linux/amd64 --name "openshield-systemd-peer-$token" --label "$label" \
    --network "$network" --cgroupns private --cap-drop ALL --read-only \
    --security-opt no-new-privileges --security-opt label=disable --memory 128m --pids-limit 64 \
    --mount "type=bind,src=$directory/systemd-sandbox.py,dst=/opt/systemd-sandbox.py,readonly" \
    "$peer_image" python3 -u /opt/systemd-sandbox.py peer)
client=$(docker create --platform linux/amd64 --name "openshield-systemd-client-$token" --label "$label" \
    --network "$network" --cgroupns private --cap-add SYS_ADMIN --cap-add SYS_PTRACE \
    --cap-add DAC_READ_SEARCH --cap-add NET_ADMIN --cap-add NET_RAW \
    --security-opt no-new-privileges --security-opt label=disable --security-opt apparmor=unconfined \
    --memory 768m --pids-limit 512 \
    --env container=docker --env LC_ALL=C --env PYTHONDONTWRITEBYTECODE=1 --stop-signal SIGRTMIN+3 \
    --tmpfs /run:rw,nosuid,nodev,size=64m --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    --mount "type=bind,src=$package,dst=/packages/openshield.rpm,readonly" \
    --mount "type=bind,src=$directory/systemd-sandbox-init.sh,dst=/opt/systemd-sandbox-init.sh,readonly" \
    --mount "type=bind,src=$directory/systemd-sandbox.py,dst=/opt/systemd-sandbox.py,readonly" \
    --mount "type=bind,src=$directory/ipc_client.py,dst=/opt/ipc_client.py,readonly" \
    "$image" /bin/sh /opt/systemd-sandbox-init.sh "$backend" /packages/openshield.rpm)
docker inspect "$client" > "$evidence/container-inspect.json"
docker start "$peer" "$client" >/dev/null
stage=systemd_boot
attempt=0
while ! docker exec "$client" test -S /run/systemd/private 2>/dev/null; do
    running=$(docker inspect --format '{{.State.Running}}' "$client")
    if [ "$running" != true ]; then
        status=$(docker inspect --format '{{.State.ExitCode}}' "$client")
        [ "$status" != 77 ] || { echo 'BLOCKED: private systemd bootstrap unsupported' >&2; exit 77; }
        exit 1
    fi
    attempt=$((attempt + 1))
    [ "$attempt" -lt 300 ] || { echo 'BLOCKED: systemd PID 1 did not become ready' >&2; exit 77; }
    sleep 1
done
docker exec "$client" timeout 30 /bin/sh -ec 'test "$(cat /proc/1/comm)" = systemd; systemctl is-system-running --wait || test "$(systemctl is-system-running)" = degraded'
peer_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$peer")
case "$peer_ip" in ''|*[!0-9.]*) exit 1 ;; esac
stage=fail_closed_startup_preflight
docker exec "$client" timeout --signal=KILL 45 python3 /opt/systemd-sandbox.py startup-negative "$peer_ip"
stage=packaged_unit_start
docker exec "$client" systemctl start openshield-daemon.service
docker exec "$client" systemctl is-active --quiet openshield-daemon.service
docker exec "$client" python3 /opt/systemd-sandbox.py unit-proof
stage=proc_subset_negative
docker exec "$client" systemd-run --quiet --wait --pipe --collect --unit=openshield-proc-hidden \
    --property=ProcSubset=pid --property=ProtectProc=invisible \
    /usr/bin/python3 /opt/systemd-sandbox.py probe hidden
stage=packaged_mount_namespace
docker exec "$client" /bin/sh -ec '
    pid=$(systemctl show --value --property=MainPID openshield-daemon.service)
    case "$pid" in ""|0|*[!0-9]*) exit 1 ;; esac
    nsenter --mount --target "$pid" -- /usr/bin/python3 /opt/systemd-sandbox.py probe visible
'
stage=real_sockets
docker exec "$client" timeout --signal=KILL 120 python3 /opt/systemd-sandbox.py exercise "$backend" "$peer_ip"
docker logs "$peer" > "$evidence/peer.jsonl"
docker exec "$client" /bin/sh -ec '
    cursor=$(cat /run/openshield-sandbox/positive-journal-cursor)
    exec journalctl -u openshield-daemon.service --after-cursor "$cursor" --no-pager -o cat
' > "$evidence/positive-daemon.log"
python3 - "$evidence" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path
directory = Path(sys.argv[1])
log = (directory / "positive-daemon.log").read_text()
if "OUTPUT queue read-through boundary" in log:
    raise RuntimeError("packaged daemon could not inspect queue progress")
events = [json.loads(line) for line in (directory / "peer.jsonl").read_text().splitlines()]
if any(event.get("token", "").startswith(("unknown", "startup-blocked")) for event in events):
    raise RuntimeError("unknown executable traffic reached the independent peer")
if not any(event.get("token") == "barrier-prime" for event in events):
    raise RuntimeError("the peer did not witness the controlled reply overlap")
expected = Counter({token: 1 for token in (
    "learning-tcp", "learning-udp", "enforcing-tcp", "enforcing-udp",
    "barrier-prime", "barrier-second", "post-denial-tcp", "post-denial-udp",
)})
if Counter(event.get("token") for event in events) != expected:
    raise RuntimeError("independent peer record audit differs from exact authorized exchanges")
PY
stage=complete
