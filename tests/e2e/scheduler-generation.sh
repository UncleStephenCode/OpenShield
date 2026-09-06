#!/bin/sh
# Private-container regression; never starts or modifies the host firewall.
set -eu

[ "$#" = 2 ] || { printf 'usage: %s {nftables|iptables} ABSOLUTE_RPM\n' "$0" >&2; exit 2; }
backend=$1
rpm_path=$2
case "$backend" in nftables|iptables) ;; *) exit 2 ;; esac
case "$rpm_path" in /*) ;; *) exit 2 ;; esac
[ -f "$rpm_path" ] && [ ! -L "$rpm_path" ] || exit 2
for command in docker rpm2cpio cpio sha256sum python3; do command -v "$command" >/dev/null || exit 2; done
case "${DOCKER_HOST:-}" in ''|unix:///*) ;; *) exit 2 ;; esac
case "$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')" in unix:///*) ;; *) exit 2 ;; esac
script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
temporary_directory=$(mktemp -d /tmp/openshield-scheduler-run.XXXXXX)
evidence_directory=$(mktemp -d /tmp/openshield-scheduler-evidence.XXXXXX)
token=${temporary_directory##*/}
label="org.openshield.scheduler-e2e.run=$token"
network_id=
client_id=
peer_id=
stage=initialization

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ -n "$client_id" ]; then
        docker exec "$client_id" touch /tmp/scheduler-noise.release >/dev/null 2>&1
        docker cp "$client_id:/tmp/scheduler-generation/." "$evidence_directory/" >/dev/null 2>&1
        docker exec "$client_id" cat /tmp/openshield.log >"$evidence_directory/daemon.log" 2>&1
        docker exec "$client_id" python3 /opt/e2e/ipc_client.py status >"$evidence_directory/status-final.json" 2>&1
        docker exec "$client_id" cat /proc/net/netfilter/nfnetlink_queue >"$evidence_directory/nfnetlink-queue.txt" 2>&1
    fi
    if [ -n "$peer_id" ]; then
        docker exec "$peer_id" cat /tmp/peer.jsonl >"$evidence_directory/peer.jsonl" 2>&1
        docker exec "$peer_id" cat /tmp/peer.error >"$evidence_directory/peer.error" 2>&1
    fi
    printf 'backend=%s\nrpm=%s\nstage=%s\nresult=%s\n' "$backend" "$rpm_path" "$stage" "$status" >"$evidence_directory/run.txt"
    sha256sum "$rpm_path" >>"$evidence_directory/run.txt"
    # IDs are captured only from create operations carrying this run's label.
    [ -z "$client_id" ] || docker rm -f "$client_id" >/dev/null 2>&1 || status=1
    [ -z "$peer_id" ] || docker rm -f "$peer_id" >/dev/null 2>&1 || status=1
    [ -z "$network_id" ] || docker network rm "$network_id" >/dev/null 2>&1 || status=1
    case "$temporary_directory" in /tmp/openshield-scheduler-run.*) rm -rf -- "$temporary_directory" ;; *) status=1 ;; esac
    printf 'OpenShield scheduler generation evidence: %s\n' "$evidence_directory"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

begin_stage() { stage=$1; printf '==> OpenShield scheduler generation (%s): %s\n' "$backend" "$stage"; }
wait_file() {
    docker exec "$1" /bin/sh -c 'n=0; while [ "$n" -lt 600 ]; do [ ! -f "$1" ] || exit 0; n=$((n+1)); sleep 0.1; done; exit 1' scheduler-wait "$2"
}

begin_stage 'extract candidate without host installation'
mkdir "$temporary_directory/extracted"
rpm2cpio "$rpm_path" >"$temporary_directory/package.cpio"
(cd "$temporary_directory/extracted"; cpio -idm --quiet ./usr/bin/openshield-daemon <"$temporary_directory/package.cpio")
daemon_binary="$temporary_directory/extracted/usr/bin/openshield-daemon"
[ -x "$daemon_binary" ] && [ ! -L "$daemon_binary" ] || exit 1
sha256sum "$daemon_binary" >"$evidence_directory/daemon.sha256"

begin_stage 'provision private Tumbleweed client and independent peer'
tumbleweed_image='opensuse/tumbleweed@sha256:8f6397b7b7ebc78e111d9a13fb2b157664ad5524e1f3b908deb45938b3095045'
peer_image='python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285'
network_id=$(docker network create --label "$label" "openshield-scheduler-$token")
peer_id=$(docker create --platform linux/amd64 --label "$label" --network "$network_id" --read-only --cap-drop ALL --security-opt no-new-privileges --security-opt label=disable --pids-limit 64 --memory 128m --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m --env PYTHONDONTWRITEBYTECODE=1 --mount "type=bind,src=$script_directory,dst=/opt/e2e,readonly" "$peer_image" sleep infinity)
client_id=$(docker create --platform linux/amd64 --label "$label" --network "$network_id" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH --security-opt no-new-privileges --security-opt label=disable --pids-limit 4096 --memory 2g --env PYTHONDONTWRITEBYTECODE=1 --mount "type=bind,src=$temporary_directory/extracted/usr/bin,dst=/opt/openshield,readonly" --mount "type=bind,src=$script_directory,dst=/opt/e2e,readonly" "$tumbleweed_image" sleep infinity)
docker start "$peer_id" "$client_id" >/dev/null
peer_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$peer_id")
case "$peer_ip" in ''|*[!0-9.]*) exit 1 ;; esac
attempt=1
while ! docker exec "$client_id" zypper --non-interactive refresh repo-oss >/dev/null; do [ "$attempt" -lt 3 ] || exit 1; sleep "$((attempt*5))"; attempt=$((attempt+1)); done
packages='iptables python3 shadow util-linux procps'
[ "$backend" = nftables ] && packages="$packages nftables"
# shellcheck disable=SC2086
docker exec "$client_id" zypper --non-interactive --no-refresh install --no-recommends --repo repo-oss $packages >/dev/null
docker exec "$client_id" /bin/sh -c '
    groupadd --system openshield
    useradd --system --no-create-home --shell /bin/false schedulerapp
    install -d -m 0755 -o root -g root /run/openshield /tmp/scheduler-generation
    install -d -m 0700 -o root -g root /var/lib/openshield
    install -d -m 0755 -o schedulerapp /tmp/scheduler-generation/known /tmp/scheduler-generation/unknown
    python=$(readlink -f "$(command -v python3)")
    install -m 0755 "$python" /tmp/scheduler-known
    install -m 0755 "$python" /tmp/scheduler-unknown
'
app_uid=$(docker exec "$client_id" id -u schedulerapp)
docker exec --detach "$peer_id" /bin/sh -c 'exec python3 /opt/e2e/scheduler-generation.py serve "$1" >/tmp/peer.jsonl 2>/tmp/peer.error' scheduler-peer "$peer_ip"
wait_file "$peer_id" /tmp/scheduler-peer.ready

begin_stage 'start daemon and exact application rules'
docker exec --detach "$client_id" /bin/sh -c '/opt/openshield/openshield-daemon >/tmp/openshield.log 2>&1 & printf "%s\n" "$!" >/tmp/openshield.pid; wait'
docker exec "$client_id" /bin/sh -c 'n=0; while [ "$n" -lt 300 ]; do [ ! -S /run/openshield/control.sock ] || exit 0; n=$((n+1)); sleep 0.1; done; exit 1'
docker exec "$client_id" python3 /opt/e2e/ipc_client.py assert-runtime learning "$backend" nfqueue learning >/dev/null
for protocol in udp tcp; do
    port=18142
    [ "$protocol" != tcp ] || port=18143
    docker exec "$client_id" python3 /opt/e2e/delayed-icmp.py create-rule "scheduler-$protocol" "$protocol" /tmp/scheduler-known "$app_uid" "$peer_ip" "$port" >"$evidence_directory/rule-$protocol.json"
done
docker exec "$client_id" python3 /opt/e2e/ipc_client.py set-mode enforcing >/dev/null
docker exec "$client_id" python3 /opt/e2e/ipc_client.py assert-runtime enforcing "$backend" nfqueue application_per_packet >/dev/null

begin_stage 'same-UID procfs pressure and mixed real TCP/UDP backlog'
docker exec --detach "$client_id" /bin/sh -c 'exec runuser -u schedulerapp -- python3 /opt/e2e/continuous-attribution.py noise /tmp/scheduler-noise.ready /tmp/scheduler-noise.release >/tmp/scheduler-generation/noise.log 2>&1'
wait_file "$client_id" /tmp/scheduler-noise.ready
docker exec "$client_id" /bin/sh -c 'exec python3 /opt/e2e/scheduler-generation.py control "$1" >/tmp/scheduler-generation/controller.jsonl 2>/tmp/scheduler-generation/controller.error' scheduler-controller "$peer_ip"

begin_stage 'audit independent peer and acknowledged post-revocation barriers'
docker cp "$client_id:/tmp/scheduler-generation/." "$evidence_directory/" >/dev/null
docker exec "$peer_id" cat /tmp/peer.jsonl >"$evidence_directory/peer.jsonl"
docker exec "$peer_id" cat /tmp/peer.error >"$evidence_directory/peer.error"
[ ! -s "$evidence_directory/peer.error" ] || exit 1
PYTHONDONTWRITEBYTECODE=1 python3 "$script_directory/scheduler-generation.py" analyze "$evidence_directory" >"$evidence_directory/analysis.log" 2>&1
