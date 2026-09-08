#!/bin/sh
set -eu

[ "$#" = 2 ] || { printf 'usage: %s {nftables|iptables} ABSOLUTE_RPM\n' "$0" >&2; exit 2; }
backend=$1
rpm_path=$2
udp_pps=${CONTINUOUS_UDP_PPS:-2}
case "$udp_pps" in 1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20) ;; *) exit 2 ;; esac
case "$backend" in nftables|iptables) ;; *) exit 2 ;; esac
case "$rpm_path" in /*) ;; *) exit 2 ;; esac
[ -f "$rpm_path" ] && [ ! -L "$rpm_path" ] || exit 2
for command in docker rpm2cpio cpio sha256sum python3; do command -v "$command" >/dev/null || exit 2; done
case "${DOCKER_HOST:-}" in ''|unix:///*) ;; *) exit 2 ;; esac
case "$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')" in unix:///*) ;; *) exit 2 ;; esac
script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
temporary_directory=$(mktemp -d /tmp/openshield-continuous-run.XXXXXX)
evidence_directory=$(mktemp -d /tmp/openshield-continuous-evidence.XXXXXX)
token=${temporary_directory##*/}
label="org.openshield.continuous-e2e.run=$token"
network_id=
client_id=
peer_id=
stage=initialization
result=0

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ -n "$client_id" ]; then
        docker exec "$client_id" touch /tmp/baseline-same.release /tmp/baseline-other.release /tmp/enforcing-same.release /tmp/enforcing-other.release >/dev/null 2>&1
        docker cp "$client_id:/tmp/evidence/." "$evidence_directory/" >/dev/null 2>&1
        docker exec "$client_id" cat /tmp/openshield.log >"$evidence_directory/daemon.log" 2>&1
        docker exec "$client_id" python3 /opt/e2e/ipc_client.py status >"$evidence_directory/status-final.json" 2>&1
        docker exec "$client_id" /bin/sh -c 'if command -v nft >/dev/null; then nft -a list ruleset; else iptables-save; ip6tables-save; fi' >"$evidence_directory/firewall-final.txt" 2>&1
    fi
    printf 'backend=%s\nrpm=%s\nstage=%s\nresult=%s\nudp_pps=%s\n' "$backend" "$rpm_path" "$stage" "$status" "$udp_pps" >"$evidence_directory/run.txt"
    sha256sum "$rpm_path" >>"$evidence_directory/run.txt"
    [ -z "$client_id" ] || docker rm -f "$client_id" >/dev/null 2>&1 || status=1
    [ -z "$peer_id" ] || docker rm -f "$peer_id" >/dev/null 2>&1 || status=1
    [ -z "$network_id" ] || docker network rm "$network_id" >/dev/null 2>&1 || status=1
    case "$temporary_directory" in /tmp/openshield-continuous-run.*) rm -rf -- "$temporary_directory" ;; *) status=1 ;; esac
    printf 'OpenShield continuous attribution evidence: %s\n' "$evidence_directory"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

begin_stage() { stage=$1; printf '==> OpenShield continuous attribution (%s): %s\n' "$backend" "$stage"; }
wait_file() {
    docker exec "$1" /bin/sh -c 'n=0; while [ "$n" -lt 1000 ]; do [ ! -f "$1" ] || exit 0; n=$((n+1)); sleep 0.1; done; exit 1' continuous-wait "$2"
}

begin_stage 'extract candidate without host installation'
mkdir "$temporary_directory/extracted"
rpm2cpio "$rpm_path" >"$temporary_directory/package.cpio"
(cd "$temporary_directory/extracted"; cpio -idm --quiet --no-absolute-filenames \
    ./usr/bin/openshield-daemon usr/bin/openshield-daemon \
    <"$temporary_directory/package.cpio")
daemon_binary="$temporary_directory/extracted/usr/bin/openshield-daemon"
[ -x "$daemon_binary" ] && [ ! -L "$daemon_binary" ] || exit 1
sha256sum "$daemon_binary" >"$evidence_directory/daemon.sha256"

begin_stage 'provision isolated Tumbleweed client and delayed peer'
tumbleweed_image='opensuse/tumbleweed@sha256:8f6397b7b7ebc78e111d9a13fb2b157664ad5524e1f3b908deb45938b3095045'
peer_image='python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285'
network_id=$(docker network create --label "$label" "openshield-continuous-$token")
peer_id=$(docker create --platform linux/amd64 --label "$label" --network "$network_id" --read-only --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges --security-opt label=disable --sysctl net.ipv4.icmp_echo_ignore_all=1 --pids-limit 512 --memory 256m --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m --env PYTHONDONTWRITEBYTECODE=1 --mount "type=bind,src=$script_directory,dst=/opt/e2e,readonly" "$peer_image" sleep infinity)
client_id=$(docker create --platform linux/amd64 --label "$label" --network "$network_id" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH --security-opt no-new-privileges --security-opt label=disable --sysctl 'net.ipv4.ping_group_range=0 2147483647' --pids-limit 8192 --memory 2g --env PYTHONDONTWRITEBYTECODE=1 --env "CONTINUOUS_UDP_PPS=$udp_pps" --mount "type=bind,src=$temporary_directory/extracted/usr/bin,dst=/opt/openshield,readonly" --mount "type=bind,src=$script_directory,dst=/opt/e2e,readonly" "$tumbleweed_image" sleep infinity)
docker start "$peer_id" "$client_id" >/dev/null
peer_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$peer_id")
case "$peer_ip" in ''|*[!0-9.]*) exit 1 ;; esac
attempt=1
while ! docker exec "$client_id" zypper --non-interactive refresh repo-oss >/dev/null; do [ "$attempt" -lt 3 ] || exit 1; sleep "$((attempt*5))"; attempt=$((attempt+1)); done
packages='iptables python3 shadow util-linux procps iproute2 iputils'
[ "$backend" = nftables ] && packages="$packages nftables"
# shellcheck disable=SC2086
docker exec "$client_id" zypper --non-interactive --no-refresh install --no-recommends --repo repo-oss $packages >/dev/null
docker exec "$client_id" /bin/sh -c '
    groupadd --system openshield
    useradd --system --no-create-home --shell /bin/false shortapp
    useradd --system --no-create-home --shell /bin/false noiseuser
    install -d -m 0755 -o root -g root /run/openshield /tmp/evidence
    install -d -m 0700 -o root -g root /var/lib/openshield
    python=$(readlink -f "$(command -v python3)")
    install -m 0755 "$python" /tmp/continuous-known
    install -m 0755 "$python" /tmp/continuous-unknown
    install -m 0755 "$(readlink -f "$(command -v ping)")" /tmp/continuous-ping
'
short_uid=$(docker exec "$client_id" id -u shortapp)

run_round() {
    phase=$1
    daemon_pid=$2
    docker exec --detach "$peer_id" /bin/sh -c 'python3 /opt/e2e/delayed-icmp.py serve "$1" 18092 18093 55 /tmp/peer.jsonl /tmp/peer.ready >/tmp/peer.log 2>&1 & printf "%s\n" "$!" >/tmp/peer.pid; wait' continuous-peer "$peer_ip"
    wait_file "$peer_id" /tmp/peer.ready
    for identity in same other; do
        account=shortapp
        [ "$identity" = same ] || account=noiseuser
        docker exec --detach "$client_id" /bin/sh -c '
            if runuser -u "$1" -- python3 /opt/e2e/continuous-attribution.py noise "/tmp/$2-$3.ready" "/tmp/$2-$3.release" >"/tmp/evidence/$2-noise-$3.jsonl" 2>&1; then status=0; else status=$?; fi
            printf "%s\n" "$status" >"/tmp/$2-$3.status"
        ' continuous-noise "$account" "$phase" "$identity"
        wait_file "$client_id" "/tmp/$phase-$identity.ready"
    done
    for kind in known churn; do
        executable=/tmp/continuous-known
        [ "$kind" = known ] || executable=/tmp/continuous-unknown
        docker exec --detach "$client_id" /bin/sh -c '
            if runuser -u shortapp -- "$1" /opt/e2e/continuous-attribution.py "$2" "$3" 18092 18093 "/tmp/$4.start" >"/tmp/evidence/$4-$2.jsonl" 2>"/tmp/evidence/$4-$2.error"; then status=0; else status=$?; fi
            printf "%s\n" "$status" >"/tmp/$4-$2.status"
        ' continuous-workload "$executable" "$kind" "$peer_ip" "$phase"
    done
    docker exec --detach "$client_id" /bin/sh -c '
        if runuser -u shortapp -- python3 /opt/e2e/continuous-attribution.py ping "$1" "/tmp/$2.start" >"/tmp/evidence/$2-ping.jsonl" 2>"/tmp/evidence/$2-ping.error"; then status=0; else status=$?; fi
        printf "%s\n" "$status" >"/tmp/$2-ping.status"
    ' continuous-ping "$peer_ip" "$phase"
    docker exec --detach "$client_id" /bin/sh -c '
        if python3 /opt/e2e/continuous-attribution.py monitor "$1" "/tmp/$2.start" >"/tmp/evidence/$2-monitor.jsonl" 2>"/tmp/evidence/$2-monitor.error"; then status=0; else status=$?; fi
        printf "%s\n" "$status" >"/tmp/$2-monitor.status"
    ' continuous-monitor "$daemon_pid" "$phase"
    docker exec "$client_id" python3 -c 'import pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text(str(time.monotonic()+1))' "/tmp/$phase.start"
    for kind in known churn ping monitor; do
        wait_file "$client_id" "/tmp/$phase-$kind.status"
        [ "$(docker exec "$client_id" cat "/tmp/$phase-$kind.status")" = 0 ] || result=1
    done
    docker exec "$client_id" touch "/tmp/$phase-same.release" "/tmp/$phase-other.release"
    for identity in same other; do
        wait_file "$client_id" "/tmp/$phase-$identity.status"
        [ "$(docker exec "$client_id" cat "/tmp/$phase-$identity.status")" = 0 ] || result=1
    done
    docker exec "$peer_id" cat /tmp/peer.jsonl >"$evidence_directory/$phase-peer.jsonl"
    docker exec "$peer_id" cat /tmp/peer.log >"$evidence_directory/$phase-peer.log"
    docker exec "$peer_id" /bin/sh -c 'kill "$(cat /tmp/peer.pid)"; rm -f /tmp/peer.ready'
}

begin_stage 'baseline: persistent known flows and 20/50/100 new sockets per second'
run_round baseline 0

begin_stage 'start daemon, exact known rules, then Enforcing'
docker exec --detach "$client_id" /bin/sh -c '/opt/openshield/openshield-daemon >/tmp/openshield.log 2>&1 & printf "%s\n" "$!" >/tmp/openshield.pid; wait'
docker exec "$client_id" /bin/sh -c 'n=0; while [ "$n" -lt 300 ]; do [ ! -S /run/openshield/control.sock ] || exit 0; n=$((n+1)); sleep 0.1; done; exit 1'
docker exec "$client_id" python3 /opt/e2e/ipc_client.py assert-runtime learning "$backend" nfqueue learning >/dev/null
for protocol in udp tcp icmp; do
    executable=/tmp/continuous-known
    port=18092
    [ "$protocol" != tcp ] || port=18093
    if [ "$protocol" = icmp ]; then executable=/tmp/continuous-ping; port=0; fi
    docker exec "$client_id" python3 /opt/e2e/delayed-icmp.py create-rule "continuous-$protocol" "$protocol" "$executable" "$short_uid" "$peer_ip" "$port" >"$evidence_directory/rule-$protocol.json"
done
docker exec "$client_id" python3 /opt/e2e/ipc_client.py set-mode enforcing >/dev/null
docker exec "$client_id" python3 /opt/e2e/ipc_client.py assert-runtime enforcing "$backend" nfqueue application_per_packet >/dev/null
daemon_pid=$(docker exec "$client_id" cat /tmp/openshield.pid)
begin_stage 'Enforcing: identical continuous mixed contention'
run_round enforcing "$daemon_pid"
docker cp "$client_id:/tmp/evidence/." "$evidence_directory/" >/dev/null
docker exec "$client_id" python3 /opt/e2e/ipc_client.py status >"$evidence_directory/status-final.json"
begin_stage 'analyze latency, fairness, queue backlog and fail-closed evidence'
if ! PYTHONDONTWRITEBYTECODE=1 python3 "$script_directory/continuous-attribution.py" analyze "$evidence_directory" >"$evidence_directory/analysis.log" 2>&1; then result=1; fi
exit "$result"
