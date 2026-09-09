#!/bin/sh
set -eu

[ "$#" -eq 2 ] || { printf 'usage: %s {nftables|iptables} ABSOLUTE_RPM\n' "$0" >&2; exit 2; }
backend=$1
rpm_path=$2
case "$backend" in nftables|iptables) ;; *) exit 2 ;; esac
case "$rpm_path" in /*) ;; *) exit 2 ;; esac
[ -f "$rpm_path" ] && [ ! -L "$rpm_path" ] || exit 2
for command in docker rpm2cpio cpio sha256sum python3; do
    command -v "$command" >/dev/null 2>&1 || { printf 'missing command: %s\n' "$command" >&2; exit 2; }
done
case "${DOCKER_HOST:-}" in ''|unix:///*) ;; *) printf '%s\n' 'refusing remote Docker' >&2; exit 2 ;; esac
endpoint=$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')
case "$endpoint" in unix:///*) ;; *) printf '%s\n' 'refusing remote Docker context' >&2; exit 2 ;; esac

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
evidence=$(mktemp -d /tmp/openshield-gso-evidence.XXXXXX)
token=${evidence##*/}
label="org.openshield.gso-e2e.run=$token"
network=
client=
peer=
stage=initialization
tumbleweed_image='opensuse/tumbleweed@sha256:8f6397b7b7ebc78e111d9a13fb2b157664ad5524e1f3b908deb45938b3095045'
peer_image='python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285'

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    set +e
    printf 'stage=%s\nresult=%s\nbackend=%s\nrpm=%s\n' "$stage" "$status" "$backend" "$rpm_path" > "$evidence/run.txt"
    if [ -n "$client" ]; then
        for name in openshield.log gso-report.json gso-trace.log; do
            docker cp "$client:/tmp/$name" "$evidence/$name" >/dev/null 2>&1
        done
        docker exec "$client" cat /proc/net/netfilter/nfnetlink_queue > "$evidence/nfqueue-final.txt" 2>&1
        docker exec "$client" python3 /opt/ipc_client.py status > "$evidence/status-final.json" 2>&1
    fi
    if [ -n "$peer" ]; then
        docker exec "$peer" cat /tmp/gso-peer.jsonl > "$evidence/gso-peer.jsonl" 2>&1
    fi
    for container in "$client" "$peer"; do
        [ -n "$container" ] || continue
        actual=$(docker inspect --format '{{index .Config.Labels "org.openshield.gso-e2e.run"}}' "$container")
        if [ "$actual" = "$token" ]; then
            docker rm -f "$container" >/dev/null || status=1
        else
            printf 'refusing cleanup of container with unexpected ownership: %s\n' "$container" >&2
            status=1
        fi
    done
    if [ -n "$network" ]; then
        actual=$(docker network inspect --format '{{index .Labels "org.openshield.gso-e2e.run"}}' "$network")
        if [ "$actual" = "$token" ]; then docker network rm "$network" >/dev/null || status=1; else status=1; fi
    fi
    printf 'OpenShield GSO evidence: %s\n' "$evidence"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

wait_path() {
    docker exec "$1" /bin/sh -c '
        attempt=0
        while [ "$attempt" -lt 600 ]; do
            [ ! -e "$1" ] || exit 0
            attempt=$((attempt + 1)); sleep 0.1
        done
        exit 1
    ' openshield-gso-wait "$2"
}

stage=extract
mkdir "$evidence/extracted"
rpm2cpio "$rpm_path" > "$evidence/package.cpio"
(cd "$evidence/extracted" && cpio -idm --quiet --no-absolute-filenames \
    ./usr/bin/openshield-daemon usr/bin/openshield-daemon \
    < "$evidence/package.cpio")
daemon="$evidence/extracted/usr/bin/openshield-daemon"
[ -x "$daemon" ] && [ ! -L "$daemon" ] || exit 1
sha256sum "$rpm_path" "$daemon" > "$evidence/sha256.txt"

stage=provision
printf '==> OpenShield GSO E2E (%s): %s\n' "$backend" "$stage"
docker pull --platform linux/amd64 "$tumbleweed_image" >/dev/null
docker pull --platform linux/amd64 "$peer_image" >/dev/null
network=$(docker network create --label "$label" --opt com.docker.network.driver.mtu=1500 "openshield-gso-$token")
peer=$(docker create --platform linux/amd64 --name "openshield-gso-peer-$token" --label "$label" \
    --network "$network" --cap-drop ALL --read-only --security-opt no-new-privileges --security-opt label=disable \
    --memory 256m --pids-limit 64 --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m \
    --mount "type=bind,src=$script_directory/gso-sockets.py,dst=/opt/gso-sockets.py,readonly" \
    "$peer_image" sleep infinity)
client=$(docker create --platform linux/amd64 --name "openshield-gso-client-$token" --label "$label" \
    --network "$network" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH \
    --security-opt no-new-privileges --security-opt label=disable --memory 512m --pids-limit 256 \
    --env PYTHONDONTWRITEBYTECODE=1 \
    --mount "type=bind,src=$evidence/extracted/usr/bin,dst=/opt/openshield,readonly" \
    --mount "type=bind,src=$script_directory/gso-sockets.py,dst=/opt/gso-sockets.py,readonly" \
    --mount "type=bind,src=$script_directory/ipc_client.py,dst=/opt/ipc_client.py,readonly" \
    "$tumbleweed_image" sleep infinity)
docker start "$peer" "$client" >/dev/null
peer_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$peer")
case "$peer_ip" in ''|*[!0-9.]*) exit 1 ;; esac
docker exec --detach "$peer" python3 /opt/gso-sockets.py serve "$peer_ip" 18199
wait_path "$peer" /tmp/gso-peer.ready
attempt=1
while ! docker exec "$client" zypper --non-interactive refresh repo-oss >/dev/null; do
    [ "$attempt" -lt 3 ] || exit 1
    sleep "$((attempt * 5))"; attempt=$((attempt + 1))
done
packages='iptables python3 shadow util-linux procps'
[ "$backend" != nftables ] || packages="$packages nftables"
# shellcheck disable=SC2086
docker exec "$client" zypper --non-interactive --no-refresh install --repo repo-oss $packages >/dev/null
if [ "$backend" = iptables ] && docker exec "$client" /bin/sh -c 'command -v nft >/dev/null'; then
    printf '%s\n' 'iptables fallback fixture unexpectedly contains nft' >&2; exit 1
fi
docker exec "$client" /bin/sh -c '
    groupadd --system openshield
    useradd --system --no-create-home --shell /bin/false gsoapp
    install -d -m 0755 /run/openshield
    install -d -m 0700 /var/lib/openshield
    python=$(readlink -f "$(command -v python3)")
    install -m 0755 "$python" /tmp/gso-allowed
    install -m 0755 "$python" /tmp/gso-unknown
'
stage=daemon
docker exec --detach "$client" /bin/sh -c 'exec /opt/openshield/openshield-daemon >/tmp/openshield.log 2>&1'
wait_path "$client" /run/openshield/control.sock
docker exec "$client" python3 /opt/ipc_client.py assert-runtime learning "$backend" nfqueue learning
stage=large_tcp
printf '==> OpenShield GSO E2E (%s): %s\n' "$backend" "$stage"
docker exec "$client" timeout --signal=KILL 180 python3 /opt/gso-sockets.py exercise "$backend" "$peer_ip" 18199
docker cp "$client:/tmp/gso-report.json" "$evidence/gso-report.json" >/dev/null
docker exec "$peer" cat /tmp/gso-peer.jsonl > "$evidence/gso-peer.jsonl"
stage=verify_peer
PYTHONDONTWRITEBYTECODE=1 python3 - "$evidence" <<'PY'
import json
import sys
from pathlib import Path

directory = Path(sys.argv[1])
report = json.loads((directory / "gso-report.json").read_text())
events = [json.loads(line) for line in (directory / "gso-peer.jsonl").read_text().splitlines()]
if len(events) != report["expected_peer_frames"]:
    raise RuntimeError(f"peer frame count mismatch: {len(events)} != {report['expected_peer_frames']}")
if any("error" in event for event in events):
    raise RuntimeError(f"peer reported TCP errors: {events}")
if sum(event["bytes"] for event in events) != sum(item["bytes"] for item in report["results"]):
    raise RuntimeError("peer and client byte counts differ")
print("GSO real TCP: exact peer byte/frame audit and negative probes passed")
PY
stage=complete
