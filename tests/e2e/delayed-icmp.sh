#!/bin/sh
set -eu

usage() {
    printf 'usage: %s {nftables|iptables} ABSOLUTE_RPM\n' "$0" >&2
}

[ "$#" -eq 2 ] || { usage; exit 2; }
backend=$1
rpm_path=$2
case "$backend" in nftables|iptables) ;; *) usage; exit 2 ;; esac
case "$rpm_path" in /*) ;; *) usage; exit 2 ;; esac
[ -f "$rpm_path" ] && [ ! -L "$rpm_path" ] || {
    printf '%s\n' 'RPM must be a regular non-symlink file' >&2
    exit 2
}
for command in docker rpm2cpio cpio file readelf sha256sum python3; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 2
    }
done
case "${DOCKER_HOST:-}" in
    ''|unix:///*) ;;
    *) printf '%s\n' 'refusing non-local DOCKER_HOST' >&2; exit 1 ;;
esac
docker_host=$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')
case "$docker_host" in
    unix:///*) ;;
    *) printf '%s\n' 'refusing non-local Docker endpoint' >&2; exit 1 ;;
esac

tumbleweed_image='opensuse/tumbleweed@sha256:8f6397b7b7ebc78e111d9a13fb2b157664ad5524e1f3b908deb45938b3095045'
peer_image='python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285'
script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository_directory=$(CDPATH='' cd -- "$script_directory/../.." && pwd -P)
expected_version=${EXPECTED_VERSION:-}
if [ -z "$expected_version" ]; then
    expected_version=$(sed -n 's/^version = "\([0-9][0-9A-Za-z.+~-]*\)"$/\1/p' \
        "$repository_directory/Cargo.toml")
fi
case "$expected_version" in
    ''|*[!0-9A-Za-z.+~-]*) printf '%s\n' 'unsafe expected version' >&2; exit 2 ;;
esac
PYTHONDONTWRITEBYTECODE=1 python3 "$script_directory/delayed-icmp.py" \
    self-test-comparison >/dev/null

temporary_directory=$(mktemp -d /tmp/openshield-delayed-e2e.XXXXXX)
if ! evidence_directory=$(mktemp -d /tmp/openshield-delayed-evidence.XXXXXX); then
    rmdir -- "$temporary_directory" || \
        printf 'could not remove temporary directory: %s\n' "$temporary_directory" >&2
    exit 1
fi
run_token=${temporary_directory##*/}
resource_label="org.openshield.delayed-e2e.run=$run_token"
network_name="openshield-delayed-$run_token"
client_name="openshield-delayed-client-$run_token"
peer_name="openshield-delayed-peer-$run_token"
network_id=
client_id=
peer_id=
stage=initialization
result=0
udp_port=18092
tcp_port=18093
reply_delay_ms=55

begin_stage() {
    stage=$1
    printf '==> OpenShield delayed transport E2E (%s): %s\n' "$backend" "$stage"
}

wait_for_file() {
    container=$1
    path=$2
    description=$3
    if docker exec "$container" /bin/sh -c '
        attempt=0
        while [ "$attempt" -lt 600 ]; do
            [ ! -f "$1" ] || exit 0
            attempt=$((attempt + 1)); sleep 0.1
        done
        exit 1
    ' openshield-delayed-wait "$path"; then
        return 0
    fi
    printf '%s did not become ready\n' "$description" >&2
    return 1
}

collect_evidence() {
    collection_failed=false
    {
        printf 'stage=%s\nbackend=%s\nrpm=%s\n' "$stage" "$backend" "$rpm_path"
        printf 'rpm_sha256=%s\n' "$(sha256sum "$rpm_path" | awk '{print $1}')"
        if [ -n "${daemon_binary:-}" ] && [ -f "$daemon_binary" ]; then
            printf 'daemon_sha256=%s\n' "$(sha256sum "$daemon_binary" | awk '{print $1}')"
        fi
        printf 'expected_version=%s\nresult=%s\n' "$expected_version" "$result"
        printf 'reply_delay_ms=%s\n' "$reply_delay_ms"
        printf '%s\n' 'noise_per_round=2_uids_x_16_processes_x_32_threads_x_256_fds'
    } > "$evidence_directory/run.txt" || collection_failed=true
    if [ -n "$client_id" ]; then
        docker cp "$client_id:/tmp/evidence/." "$evidence_directory/" \
            >/dev/null 2>&1 || collection_failed=true
        docker exec "$client_id" cat /tmp/openshield.log \
            > "$evidence_directory/daemon.log" 2>&1 || collection_failed=true
        docker exec "$client_id" python3 /opt/ipc_client.py status \
            > "$evidence_directory/status-final.json" 2>&1 || collection_failed=true
        docker exec "$client_id" python3 /opt/ipc_client.py rules \
            > "$evidence_directory/rules.json" 2>&1 || collection_failed=true
        docker exec "$client_id" /bin/sh -c '
            cat /proc/net/netfilter/nfnetlink_queue
        ' > "$evidence_directory/nfnetlink-queue.txt" 2>&1 || collection_failed=true
        if [ "$backend" = nftables ]; then
            docker exec "$client_id" nft -a list ruleset \
                > "$evidence_directory/firewall-final.txt" 2>&1 || \
                collection_failed=true
        else
            docker exec "$client_id" iptables-save \
                > "$evidence_directory/iptables-final.txt" 2>&1 || \
                collection_failed=true
            docker exec "$client_id" ip6tables-save \
                > "$evidence_directory/ip6tables-final.txt" 2>&1 || \
                collection_failed=true
        fi
    fi
    if [ -n "$peer_id" ]; then
        docker exec "$peer_id" cat /tmp/delayed-events.jsonl \
            > "$evidence_directory/peer-events.jsonl" 2>&1 || collection_failed=true
        docker exec "$peer_id" cat /tmp/peer-audit.json \
            > "$evidence_directory/peer-audit.json" 2>&1 || collection_failed=true
        docker exec "$peer_id" /bin/sh -c '
            printf "net.ipv4.icmp_echo_ignore_all = "
            cat /proc/sys/net/ipv4/icmp_echo_ignore_all
        ' > "$evidence_directory/peer-sysctl.txt" 2>&1 || collection_failed=true
    fi
    [ "$collection_failed" = false ]
}

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ "$status" -ne 0 ]; then
        result=$status
    fi
    cleanup_failed=false
    if [ -n "$peer_id" ]; then
        docker exec "$peer_id" touch /tmp/delayed-held.release \
            >/dev/null 2>&1 || cleanup_failed=true
    fi
    if [ -n "$client_id" ]; then
        docker exec "$client_id" /bin/sh -c '
            for name in baseline-5pps baseline-1pps enforcing-5pps enforcing-1pps; do
                touch "/tmp/noise-$name-same.release" \
                    "/tmp/noise-$name-other.release"
            done
            attempt=0
            while [ "$attempt" -lt 100 ]; do
                pending=false
                for name in baseline-5pps baseline-1pps enforcing-5pps enforcing-1pps; do
                    for identity in same other; do
                        ready="/tmp/noise-$name-$identity.ready"
                        status="/tmp/noise-$name-$identity.status"
                        if [ -f "$ready" ] && [ ! -f "$status" ]; then
                            pending=true
                        fi
                    done
                done
                [ "$pending" = true ] || exit 0
                attempt=$((attempt + 1)); sleep 0.05
            done
            exit 1
        ' >/dev/null 2>&1 || cleanup_failed=true
        docker exec "$client_id" /bin/sh -c '
            if [ -f /tmp/tcp-held.ready ] && [ ! -f /tmp/tcp-held.status ]; then
                attempt=0
                while [ "$attempt" -lt 120 ]; do
                    [ ! -f /tmp/tcp-held.status ] || exit 0
                    attempt=$((attempt + 1)); sleep 0.1
                done
                exit 1
            fi
        ' >/dev/null 2>&1 || cleanup_failed=true
    fi
    collect_evidence || cleanup_failed=true
    if [ -n "$client_id" ] && ! docker rm -f "$client_id" >/dev/null 2>&1; then
        cleanup_failed=true
    fi
    if [ -n "$peer_id" ] && ! docker rm -f "$peer_id" >/dev/null 2>&1; then
        cleanup_failed=true
    fi
    remaining_containers=$(docker ps -aq --filter "label=$resource_label" 2>/dev/null || true)
    for container in $remaining_containers; do
        docker rm -f "$container" >/dev/null 2>&1 || cleanup_failed=true
    done
    if [ -n "$network_id" ] && ! docker network rm "$network_id" >/dev/null 2>&1; then
        cleanup_failed=true
    fi
    remaining_networks=$(docker network ls -q --filter "label=$resource_label" 2>/dev/null || true)
    for network in $remaining_networks; do
        docker network rm "$network" >/dev/null 2>&1 || cleanup_failed=true
    done
    case "$temporary_directory" in
        /tmp/openshield-delayed-e2e.*)
            rm -rf -- "$temporary_directory" || cleanup_failed=true
            ;;
        *)
            printf 'refusing unsafe cleanup: %s\n' "$temporary_directory" >&2
            cleanup_failed=true
            ;;
    esac
    if [ "$cleanup_failed" = true ] && [ "$status" -eq 0 ]; then
        status=1
    fi
    {
        printf 'cleanup_failed=%s\n' "$cleanup_failed"
        printf 'final_status=%s\n' "$status"
    } > "$evidence_directory/cleanup.txt" || status=1
    printf 'OpenShield delayed transport E2E evidence: %s\n' "$evidence_directory"
    if [ "$status" -ne 0 ]; then
        printf 'OpenShield delayed transport E2E failed during stage "%s"\n' "$stage" >&2
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

start_noise() {
    noise_name=$1
    case "$noise_name" in
        baseline-5pps|baseline-1pps|enforcing-5pps|enforcing-1pps) ;;
        *) return 2 ;;
    esac
    docker exec --detach "$client_id" /bin/sh -c '
        name=$1
        if runuser -u shortapp -- python3 /opt/proxy-workload.py procfs-noise \
            16 32 256 "/tmp/noise-$name-same.ready" "/tmp/noise-$name-same.release" \
            >"/tmp/evidence/noise-$name-same.json" 2>&1; then status=0; else status=$?; fi
        printf "%s\n" "$status" >"/tmp/noise-$name-same.status.tmp" &&
            mv -f "/tmp/noise-$name-same.status.tmp" "/tmp/noise-$name-same.status"
    ' openshield-delayed-noise "$noise_name"
    docker exec --detach "$client_id" /bin/sh -c '
        name=$1
        if runuser -u noiseuser -- python3 /opt/proxy-workload.py procfs-noise \
            16 32 256 "/tmp/noise-$name-other.ready" "/tmp/noise-$name-other.release" \
            >"/tmp/evidence/noise-$name-other.json" 2>&1; then status=0; else status=$?; fi
        printf "%s\n" "$status" >"/tmp/noise-$name-other.status.tmp" &&
            mv -f "/tmp/noise-$name-other.status.tmp" "/tmp/noise-$name-other.status"
    ' openshield-delayed-noise "$noise_name"
    wait_for_file "$client_id" "/tmp/noise-$noise_name-same.ready" \
        "$noise_name same-UID procfs pressure"
    wait_for_file "$client_id" "/tmp/noise-$noise_name-other.ready" \
        "$noise_name other-UID procfs pressure"
}

stop_noise() {
    noise_name=$1
    docker exec "$client_id" touch "/tmp/noise-$noise_name-same.release" \
        "/tmp/noise-$noise_name-other.release"
    wait_for_file "$client_id" "/tmp/noise-$noise_name-same.status" \
        "$noise_name same-UID pressure exit"
    wait_for_file "$client_id" "/tmp/noise-$noise_name-other.status" \
        "$noise_name other-UID pressure exit"
    [ "$(docker exec "$client_id" cat "/tmp/noise-$noise_name-same.status")" = 0 ]
    [ "$(docker exec "$client_id" cat "/tmp/noise-$noise_name-other.status")" = 0 ]
}

run_round() {
    phase=$1
    count=$2
    interval=$3
    for transport in icmp udp tcp-keepalive tcp-short; do
        docker exec "$client_id" rm -f "/tmp/$phase-$transport.status"
    done
    docker exec --detach "$client_id" /bin/sh -c '
        if runuser -u shortapp -- python3 /opt/delayed-icmp.py ping-measure \
            /tmp/delayed-ping-allowed "$1" "$2" "$3" \
            >"/tmp/evidence/$4-icmp.json" 2>"/tmp/evidence/$4-icmp.error"; then
            status=0
        else status=$?; fi
        printf "%s\n" "$status" >"/tmp/$4-icmp.status.tmp" &&
            mv -f "/tmp/$4-icmp.status.tmp" "/tmp/$4-icmp.status"
    ' openshield-delayed-round "$peer_ip" "$count" "$interval" "$phase"
    docker exec --detach "$client_id" /bin/sh -c '
        if runuser -u shortapp -- /tmp/delayed-udp-allowed \
            /opt/delayed-icmp.py udp-measure "$1" "$2" "$3" "$4" 2 \
            >"/tmp/evidence/$5-udp.json" 2>"/tmp/evidence/$5-udp.error"; then
            status=0
        else status=$?; fi
        printf "%s\n" "$status" >"/tmp/$5-udp.status.tmp" &&
            mv -f "/tmp/$5-udp.status.tmp" "/tmp/$5-udp.status"
    ' openshield-delayed-round "$peer_ip" "$udp_port" "$count" "$interval" "$phase"
    docker exec --detach "$client_id" /bin/sh -c '
        if runuser -u shortapp -- /tmp/delayed-tcp-keepalive \
            /opt/delayed-icmp.py tcp-keepalive "$1" "$2" "$3" "$4" "$5" \
            >"/tmp/evidence/$6-tcp-keepalive.json" \
            2>"/tmp/evidence/$6-tcp-keepalive.error"; then status=0
        else status=$?; fi
        printf "%s\n" "$status" >"/tmp/$6-tcp-keepalive.status.tmp" &&
            mv -f "/tmp/$6-tcp-keepalive.status.tmp" "/tmp/$6-tcp-keepalive.status"
    ' openshield-delayed-round "$peer_ip" "$tcp_port" "$count" "$interval" \
        "$reply_delay_ms" "$phase"
    docker exec --detach "$client_id" /bin/sh -c '
        if runuser -u shortapp -- /tmp/delayed-tcp-short \
            /opt/delayed-icmp.py tcp-short "$1" "$2" 12 4 "$3" \
            >"/tmp/evidence/$4-tcp-short.json" \
            2>"/tmp/evidence/$4-tcp-short.error"; then status=0
        else status=$?; fi
        printf "%s\n" "$status" >"/tmp/$4-tcp-short.status.tmp" &&
            mv -f "/tmp/$4-tcp-short.status.tmp" "/tmp/$4-tcp-short.status"
    ' openshield-delayed-round "$peer_ip" "$tcp_port" "$reply_delay_ms" "$phase"
    round_status=0
    for transport in icmp udp tcp-keepalive tcp-short; do
        wait_for_file "$client_id" "/tmp/$phase-$transport.status" \
            "$phase $transport workload"
        [ "$(docker exec "$client_id" cat "/tmp/$phase-$transport.status")" = 0 ] || \
            round_status=1
    done
    return "$round_status"
}

capture_counters() {
    destination=$1
    docker exec "$client_id" /bin/sh -c '
        exec python3 /opt/short-lived-sockets.py capture-counters >"$1"
    ' openshield-delayed-counters "$destination"
}

capture_nfqueue() {
    destination=$1
    docker exec "$client_id" /bin/sh -c '
        exec python3 /opt/delayed-icmp.py nfqueue-snapshot >"$1"
    ' openshield-delayed-nfqueue "$destination"
}

assert_nfqueue_health() {
    output=$1
    before=$2
    after=$3
    shift 3
    docker exec "$client_id" /bin/sh -c '
        output=$1
        shift
        exec python3 /opt/delayed-icmp.py assert-nfqueue-health "$@" \
            >"/tmp/evidence/$output"
    ' openshield-delayed-nfqueue "$output" "$before" "$after" "$@"
}

create_rule() {
    output=$1
    shift
    docker exec "$client_id" /bin/sh -c '
        output=$1
        shift
        exec python3 /opt/delayed-icmp.py create-rule "$@" \
            >"/tmp/evidence/$output"
    ' openshield-delayed-rule "$output" "$@"
}

begin_stage 'extract RPM daemon without host installation'
install -d -m 0755 "$temporary_directory/extracted"
rpm2cpio "$rpm_path" > "$temporary_directory/package.cpio"
(
    cd "$temporary_directory/extracted"
    cpio -idm --quiet ./usr/bin/openshield-daemon < "$temporary_directory/package.cpio"
)
daemon_binary="$temporary_directory/extracted/usr/bin/openshield-daemon"
[ -x "$daemon_binary" ] && [ ! -L "$daemon_binary" ] || exit 1
case "$(LC_ALL=C file -b "$daemon_binary")" in
    *'statically linked'*|*'static-pie linked'*) ;;
    *) printf '%s\n' 'RPM daemon is not statically linked' >&2; exit 1 ;;
esac
if LC_ALL=C readelf -l "$daemon_binary" | grep -Eq '(^|[[:space:]])INTERP([[:space:]]|$)'; then
    printf '%s\n' 'RPM daemon unexpectedly has an ELF interpreter' >&2
    exit 1
fi

begin_stage 'create isolated client and delayed peer namespaces'
docker image inspect "$tumbleweed_image" >/dev/null 2>&1 || \
    docker pull --platform linux/amd64 "$tumbleweed_image" >/dev/null
docker image inspect "$peer_image" >/dev/null 2>&1 || \
    docker pull --platform linux/amd64 "$peer_image" >/dev/null
network_id=$(docker network create --label "$resource_label" "$network_name")
peer_id=$(docker create --platform linux/amd64 --name "$peer_name" --label "$resource_label" \
    --network "$network_id" --read-only --cap-drop ALL --cap-add NET_RAW \
    --security-opt no-new-privileges --security-opt label=disable \
    --sysctl net.ipv4.icmp_echo_ignore_all=1 \
    --pids-limit 512 --memory 256m \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m \
    --mount "type=bind,src=$script_directory/delayed-icmp.py,dst=/opt/delayed-icmp.py,readonly" \
    "$peer_image" sleep infinity)
client_id=$(docker create --platform linux/amd64 --name "$client_name" --label "$resource_label" \
    --network "$network_id" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE \
    --cap-add DAC_READ_SEARCH --security-opt no-new-privileges --security-opt label=disable \
    --sysctl 'net.ipv4.ping_group_range=0 2147483647' \
    --pids-limit 8192 --memory 2g --env PYTHONDONTWRITEBYTECODE=1 \
    --mount "type=bind,src=$temporary_directory/extracted/usr/bin,dst=/opt/openshield,readonly" \
    --mount "type=bind,src=$script_directory/delayed-icmp.py,dst=/opt/delayed-icmp.py,readonly" \
    --mount "type=bind,src=$script_directory/ipc_client.py,dst=/opt/ipc_client.py,readonly" \
    --mount "type=bind,src=$script_directory/proxy-workload.py,dst=/opt/proxy-workload.py,readonly" \
    --mount "type=bind,src=$script_directory/short-lived-sockets.py,dst=/opt/short-lived-sockets.py,readonly" \
    "$tumbleweed_image" sleep infinity)
docker start "$peer_id" "$client_id" >/dev/null
peer_ip=$(docker inspect \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$peer_id")
client_ip=$(docker inspect \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$client_id")
case "$peer_ip" in
    ''|*[!0-9.]*) printf '%s\n' 'unsafe peer address' >&2; exit 1 ;;
esac
case "$client_ip" in
    ''|*[!0-9.]*) printf '%s\n' 'unsafe client address' >&2; exit 1 ;;
esac
docker exec --detach "$peer_id" python3 /opt/delayed-icmp.py serve \
    "$peer_ip" "$udp_port" "$tcp_port" "$reply_delay_ms" \
    /tmp/delayed-events.jsonl /tmp/delayed-peer.ready
wait_for_file "$peer_id" /tmp/delayed-peer.ready 'delayed transport peer'
[ "$(docker exec "$peer_id" cat /proc/sys/net/ipv4/icmp_echo_ignore_all)" = 1 ]

begin_stage 'install client-only runtime dependencies'
attempt=1
while ! docker exec "$client_id" zypper --non-interactive refresh repo-oss >/dev/null; do
    [ "$attempt" -lt 3 ] || exit 1
    sleep "$((attempt * 5))"
    attempt=$((attempt + 1))
done
packages='iptables python3 shadow util-linux procps iproute2 iputils'
[ "$backend" = nftables ] && packages="$packages nftables"
# shellcheck disable=SC2086
docker exec "$client_id" zypper --non-interactive --no-refresh install --no-recommends \
    --repo repo-oss $packages >/dev/null
[ "$(docker exec "$client_id" stat -fc %T /sys/fs/cgroup)" = cgroup2fs ] || {
    printf '%s\n' 'delayed transport fixture requires cgroup v2' >&2
    exit 1
}
reported_version=$(docker exec "$client_id" timeout --signal=KILL 5 \
    /opt/openshield/openshield-daemon --version)
[ "$reported_version" = "openshield-daemon $expected_version" ] || exit 1
if [ "$backend" = iptables ] && \
    docker exec "$client_id" /bin/sh -c 'command -v nft >/dev/null'; then
    printf '%s\n' 'iptables fixture unexpectedly contains nft' >&2
    exit 1
fi
docker exec "$client_id" /bin/sh -c '
    getent group openshield >/dev/null || groupadd --system openshield
    id shortapp >/dev/null 2>&1 || useradd --system --no-create-home --shell /bin/false shortapp
    id noiseuser >/dev/null 2>&1 || useradd --system --no-create-home --shell /bin/false noiseuser
    install -d -m 0755 -o root -g root /run/openshield /tmp/evidence
    install -d -m 0700 -o root -g root /var/lib/openshield
    python=$(readlink -f "$(command -v python3)")
    for target in delayed-udp-allowed delayed-udp-unknown delayed-tcp-keepalive \
        delayed-tcp-short delayed-tcp-unknown; do
        install -m 0755 "$python" "/tmp/$target"
    done
    ping=$(readlink -f "$(command -v ping)")
    install -m 0755 "$ping" /tmp/delayed-ping-allowed
    install -m 0755 "$ping" /tmp/delayed-ping-unknown
'
short_uid=$(docker exec "$client_id" id -u shortapp)

begin_stage 'paired delayed baseline under bounded procfs pressure'
start_noise baseline-5pps
run_round baseline-5pps 30 0.2
stop_noise baseline-5pps
start_noise baseline-1pps
run_round baseline-1pps 10 1.0
stop_noise baseline-1pps

begin_stage 'start daemon in Learning and persist exact application rules'
docker exec --detach "$client_id" /bin/sh -c '
    /opt/openshield/openshield-daemon >/tmp/openshield.log 2>&1 &
    child=$!
    printf "%s\n" "$child" >/tmp/openshield.pid
    if wait "$child"; then status=0; else status=$?; fi
    printf "%s\n" "$status" >/tmp/openshield.exit-status.tmp &&
        mv -f /tmp/openshield.exit-status.tmp /tmp/openshield.exit-status
'
if ! docker exec "$client_id" /bin/sh -c '
    attempt=0
    while [ "$attempt" -lt 600 ]; do
        [ ! -f /tmp/openshield.exit-status ] || exit 2
        [ ! -S /run/openshield/control.sock ] || exit 0
        attempt=$((attempt + 1)); sleep 0.1
    done
    exit 1
'; then
    docker exec "$client_id" cat /tmp/openshield.log >&2 || true
    exit 1
fi
docker exec "$client_id" python3 /opt/ipc_client.py assert-runtime \
    learning "$backend" nfqueue learning >/dev/null
create_rule rule-icmp.json \
    delayed-icmp icmp /tmp/delayed-ping-allowed "$short_uid" "$peer_ip" 0
create_rule rule-udp.json \
    delayed-udp udp /tmp/delayed-udp-allowed "$short_uid" "$peer_ip" "$udp_port"
create_rule rule-tcp-keepalive-5.json \
    delayed-tcp-keepalive-5 tcp /tmp/delayed-tcp-keepalive "$short_uid" \
    "$peer_ip" "$tcp_port" /tmp/delayed-tcp-keepalive /opt/delayed-icmp.py \
    tcp-keepalive "$peer_ip" "$tcp_port" 30 0.2 "$reply_delay_ms"
create_rule rule-tcp-keepalive-1.json \
    delayed-tcp-keepalive-1 tcp /tmp/delayed-tcp-keepalive "$short_uid" \
    "$peer_ip" "$tcp_port" /tmp/delayed-tcp-keepalive /opt/delayed-icmp.py \
    tcp-keepalive "$peer_ip" "$tcp_port" 10 1.0 "$reply_delay_ms"
create_rule rule-tcp-short.json \
    delayed-tcp-short tcp /tmp/delayed-tcp-short "$short_uid" "$peer_ip" \
    "$tcp_port" /tmp/delayed-tcp-short /opt/delayed-icmp.py tcp-short \
    "$peer_ip" "$tcp_port" 12 4 "$reply_delay_ms"
docker exec "$client_id" /bin/sh -c '
    exec python3 /opt/delayed-icmp.py assert-rule-count 5 \
        >/tmp/evidence/rule-inventory.json
'

begin_stage 'enter Enforcing before fresh transport checks'
docker exec "$client_id" python3 /opt/ipc_client.py set-mode enforcing >/dev/null
docker exec "$client_id" python3 /opt/ipc_client.py assert-runtime \
    enforcing "$backend" nfqueue application_per_packet >/dev/null

begin_stage 'cross-protocol Enforcing at 5 PPS under procfs pressure'
start_noise enforcing-5pps
capture_counters /tmp/evidence/counters-before-5pps.json
capture_nfqueue /tmp/evidence/nfqueue-before-5pps.json
if ! run_round enforcing-5pps 30 0.2; then result=1; fi
capture_counters /tmp/evidence/counters-after-5pps.json
capture_nfqueue /tmp/evidence/nfqueue-after-5pps.json
if ! assert_nfqueue_health nfqueue-5pps-health.json \
    /tmp/evidence/nfqueue-before-5pps.json \
    /tmp/evidence/nfqueue-after-5pps.json; then
    result=1
fi
if ! docker exec "$client_id" /bin/sh -c '
    exec python3 /opt/delayed-icmp.py assert-counter-delta \
        /tmp/evidence/counters-before-5pps.json \
        /tmp/evidence/counters-after-5pps.json \
        >/tmp/evidence/counters-5pps-delta.json \
        2>/tmp/evidence/counters-5pps-delta.error
'; then
    result=1
fi
stop_noise enforcing-5pps

begin_stage 'negative application identity and argv checks'
if ! docker exec "$client_id" /bin/sh -c '
    exec runuser -u shortapp -- python3 /opt/short-lived-sockets.py ping-blocked \
        /tmp/delayed-ping-unknown "$1" >/tmp/evidence/denied-icmp.json 2>&1
' openshield-delayed-denied "$peer_ip"; then result=1; fi
if ! docker exec "$client_id" /bin/sh -c '
    exec runuser -u shortapp -- /tmp/delayed-udp-unknown /opt/delayed-icmp.py \
        udp-blocked "$1" "$2" >/tmp/evidence/denied-udp.json 2>&1
' openshield-delayed-denied "$peer_ip" "$udp_port"; then result=1; fi
if ! docker exec "$client_id" /bin/sh -c '
    exec runuser -u shortapp -- /tmp/delayed-tcp-unknown /opt/delayed-icmp.py \
        tcp-blocked "$1" "$2" >/tmp/evidence/denied-tcp-unknown.json 2>&1
' openshield-delayed-denied "$peer_ip" "$tcp_port"; then result=1; fi
if ! docker exec "$client_id" /bin/sh -c '
    exec runuser -u shortapp -- /tmp/delayed-tcp-keepalive /opt/delayed-icmp.py \
        tcp-blocked "$1" "$2" >/tmp/evidence/denied-tcp-argv.json 2>&1
' openshield-delayed-denied "$peer_ip" "$tcp_port"; then result=1; fi

begin_stage 'cross-protocol Enforcing at 1 PPS under procfs pressure'
start_noise enforcing-1pps
capture_counters /tmp/evidence/counters-before-1pps.json
capture_nfqueue /tmp/evidence/nfqueue-before-1pps.json
if ! run_round enforcing-1pps 10 1.0; then result=1; fi
capture_counters /tmp/evidence/counters-after-1pps.json
capture_nfqueue /tmp/evidence/nfqueue-after-1pps.json
if ! assert_nfqueue_health nfqueue-1pps-health.json \
    /tmp/evidence/nfqueue-before-1pps.json \
    /tmp/evidence/nfqueue-after-1pps.json; then
    result=1
fi
if ! docker exec "$client_id" /bin/sh -c '
    exec python3 /opt/delayed-icmp.py assert-counter-delta \
        /tmp/evidence/counters-before-1pps.json \
        /tmp/evidence/counters-after-1pps.json \
        >/tmp/evidence/counters-1pps-delta.json \
        2>/tmp/evidence/counters-1pps-delta.error
'; then
    result=1
fi
stop_noise enforcing-1pps

for rate in 5pps 1pps; do
    for transport in icmp udp tcp-keepalive tcp-short; do
        if ! docker exec "$client_id" /bin/sh -c '
            exec python3 /opt/delayed-icmp.py compare "$1" "$2" >"$3"
        ' openshield-delayed-compare \
            "/tmp/evidence/baseline-$rate-$transport.json" \
            "/tmp/evidence/enforcing-$rate-$transport.json" \
            "/tmp/evidence/comparison-$rate-$transport.json"; then
            result=1
        fi
    done
done

begin_stage 'verify fail-closed invalidation of a pre-switch TCP flow'
docker exec "$client_id" python3 /opt/ipc_client.py set-mode learning >/dev/null
docker exec "$client_id" python3 /opt/ipc_client.py assert-runtime \
    learning "$backend" nfqueue learning >/dev/null
docker exec --detach "$client_id" /bin/sh -c '
    if runuser -u shortapp -- /tmp/delayed-tcp-keepalive /opt/delayed-icmp.py \
        tcp-held "$1" "$2" 1000 /tmp/tcp-held.ready 9001 \
        >/tmp/evidence/tcp-held.json 2>/tmp/evidence/tcp-held.error; then status=0
    else status=$?; fi
    printf "%s\n" "$status" >/tmp/tcp-held.status.tmp &&
        mv -f /tmp/tcp-held.status.tmp /tmp/tcp-held.status
' openshield-delayed-held "$peer_ip" "$tcp_port"
wait_for_file "$client_id" /tmp/tcp-held.ready 'pre-switch TCP client'
if ! docker exec "$peer_id" /bin/sh -c '
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        grep -Eq "\"phase\": \"received\".*\"sequence\": 9001" \
            /tmp/delayed-events.jsonl && exit 0
        attempt=$((attempt + 1)); sleep 0.05
    done
    exit 1
'; then
    printf '%s\n' 'peer did not receive the held TCP request before mode switch' >&2
    exit 1
fi
docker exec "$client_id" python3 /opt/ipc_client.py set-mode enforcing >/dev/null
docker exec "$client_id" python3 /opt/ipc_client.py assert-runtime \
    enforcing "$backend" nfqueue application_per_packet >/dev/null
docker exec "$peer_id" touch /tmp/delayed-held.release
wait_for_file "$peer_id" /tmp/delayed-held.sent 'post-switch TCP peer response'
wait_for_file "$client_id" /tmp/tcp-held.status 'pre-switch TCP invalidation'
[ "$(docker exec "$client_id" cat /tmp/tcp-held.status)" = 0 ] || result=1
capture_counters /tmp/evidence/counters-after-held.json
if ! docker exec "$client_id" /bin/sh -c '
    exec python3 /opt/delayed-icmp.py assert-held-counters \
        /tmp/evidence/counters-after-held.json \
        >/tmp/evidence/counters-held-absolute.json
'; then result=1; fi

begin_stage 'final NFQUEUE and peer-liveness checks'
if ! docker exec "$client_id" /bin/sh -c '
    exec python3 /opt/proxy-workload.py assert-nfqueue-clean --require-denied \
        >/tmp/evidence/nfqueue-clean.json 2>/tmp/evidence/nfqueue-clean.error
'; then result=1; fi

begin_stage 'audit peer completeness and safety state'
if ! docker exec "$peer_id" /bin/sh -c '
    exec python3 /opt/delayed-icmp.py audit-peer \
        /tmp/delayed-events.jsonl "$1" 80 80 129 "$2" >/tmp/peer-audit.json
' openshield-delayed-audit "$client_ip" "$reply_delay_ms"; then result=1; fi
if docker exec "$client_id" grep -Eqi \
    'fail.open|quarantine|emergency BlockAll' /tmp/openshield.log; then
    printf '%s\n' 'daemon reported fail-open or quarantine' >&2
    result=1
fi

begin_stage 'complete'
if [ "$result" -eq 0 ]; then
    printf 'PASS delayed ICMP/UDP/TCP application Enforcing (%s)\n' "$backend"
else
    printf 'FAIL delayed ICMP/UDP/TCP application Enforcing (%s)\n' "$backend" >&2
fi
exit "$result"
