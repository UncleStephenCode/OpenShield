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

for command in docker rpm2cpio cpio file readelf sha256sum; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 2
    }
done
case "${DOCKER_HOST:-}" in ''|unix:///*) ;; *) printf '%s\n' 'refusing non-local DOCKER_HOST' >&2; exit 1 ;; esac
docker_host=$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')
case "$docker_host" in unix:///*) ;; *) printf '%s\n' 'refusing non-local Docker endpoint' >&2; exit 1 ;; esac

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

temporary_directory=$(mktemp -d /tmp/openshield-short-e2e.XXXXXX)
evidence_directory=$(mktemp -d /tmp/openshield-short-evidence.XXXXXX)
run_token=${temporary_directory##*/}
resource_label="org.openshield.short-e2e.run=$run_token"
network_name="openshield-short-$run_token"
client_name="openshield-short-client-$run_token"
peer_name="openshield-short-peer-$run_token"
network_id=
client_id=
peer_id=
stage=initialization
learning_rules_ok=false
result=0

begin_stage() {
    stage=$1
    printf '==> OpenShield short-lived E2E (%s): %s\n' "$backend" "$stage"
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
    ' openshield-short-wait "$path"; then
        return 0
    fi
    printf '%s did not become ready\n' "$description" >&2
    return 1
}

copy_evidence() {
    container=$1
    source=$2
    destination=$3
    [ -n "$container" ] || return 0
    docker cp "$container:$source" "$evidence_directory/$destination" >/dev/null 2>&1 || true
}

collect_evidence() {
    {
        printf 'stage=%s\nbackend=%s\nrpm=%s\n' "$stage" "$backend" "$rpm_path"
        printf 'rpm_sha256=%s\n' "$(sha256sum "$rpm_path" | awk '{print $1}')"
        if [ -n "${daemon_binary:-}" ] && [ -f "$daemon_binary" ]; then
            printf 'daemon_sha256=%s\n' \
                "$(sha256sum "$daemon_binary" | awk '{print $1}')"
        fi
        printf 'expected_version=%s\nlearning_rules_ok=%s\n' \
            "$expected_version" "$learning_rules_ok"
        printf '%s\n' 'noise=2_uids_x_16_processes_x_32_threads_x_256_fds'
    } > "$evidence_directory/run.txt"
    copy_evidence "$client_id" /tmp/openshield.log daemon.log
    copy_evidence "$client_id" /tmp/learning-rule-audit.json learning-rule-audit.json
    copy_evidence "$client_id" /tmp/learning-rule-audit.error learning-rule-audit.error
    copy_evidence "$client_id" /tmp/held-rule-audit.json held-rule-audit.json
    copy_evidence "$client_id" /tmp/peer-audit.json peer-audit.json
    copy_evidence "$client_id" /tmp/icmp-rule-audit.json icmp-rule-audit.json
    copy_evidence "$client_id" /tmp/peer-events.jsonl peer-events.jsonl
    copy_evidence "$client_id" /tmp/tcp-a-learning.json tcp-a-learning.json
    copy_evidence "$client_id" /tmp/tcp-b-learning.json tcp-b-learning.json
    copy_evidence "$client_id" /tmp/dns-a-learning.json dns-a-learning.json
    copy_evidence "$client_id" /tmp/dns-b-learning.json dns-b-learning.json
    copy_evidence "$client_id" /tmp/fire-learning.json fire-learning.json
    copy_evidence "$client_id" /tmp/tcp-a-enforcing.json tcp-a-enforcing.json
    copy_evidence "$client_id" /tmp/tcp-b-enforcing.json tcp-b-enforcing.json
    copy_evidence "$client_id" /tmp/dns-a-enforcing.json dns-a-enforcing.json
    copy_evidence "$client_id" /tmp/dns-b-enforcing.json dns-b-enforcing.json
    copy_evidence "$client_id" /tmp/unknown-tcp.json unknown-tcp.json
    copy_evidence "$client_id" /tmp/unknown-dns.json unknown-dns.json
    copy_evidence "$client_id" /tmp/unknown-argv-tcp.json unknown-argv-tcp.json
    copy_evidence "$client_id" /tmp/unknown-argv-dns.json unknown-argv-dns.json
    copy_evidence "$client_id" /tmp/ping-baseline.json ping-baseline.json
    copy_evidence "$client_id" /tmp/ping-enforcing.json ping-enforcing.json
    copy_evidence "$client_id" /tmp/ping-comparison.json ping-comparison.json
    copy_evidence "$client_id" /tmp/counters-before-ping.json counters-before-ping.json
    copy_evidence "$client_id" /tmp/counters-after-ping.json counters-after-ping.json
    copy_evidence "$client_id" /tmp/counters-ping-delta.json counters-ping-delta.json
    copy_evidence "$client_id" /tmp/ping-unknown.log ping-unknown.log
    copy_evidence "$client_id" /tmp/argv-attribution.jsonl argv-attribution.jsonl
    copy_evidence "$client_id" /tmp/argv-attribution.error argv-attribution.error
    copy_evidence "$client_id" /tmp/argv-peer-audit.json argv-peer-audit.json
    copy_evidence "$client_id" /tmp/noise-same.log noise-same.log
    copy_evidence "$client_id" /tmp/noise-other.log noise-other.log
    if [ -n "$peer_id" ]; then
        docker exec "$peer_id" cat /tmp/short-events.jsonl \
            > "$evidence_directory/peer-events.jsonl" 2>&1 || true
    fi
    if [ -n "$client_id" ]; then
        docker exec "$client_id" python3 /opt/ipc_client.py status \
            > "$evidence_directory/status.json" 2>&1 || true
        docker exec "$client_id" python3 /opt/ipc_client.py rules \
            > "$evidence_directory/rules.json" 2>&1 || true
    fi
}

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    set +e
    cleanup_failed=false
    collect_evidence || cleanup_failed=true
    if [ -n "$client_id" ] && ! docker rm -f "$client_id" >/dev/null 2>&1; then
        printf 'cannot remove client container %s\n' "$client_id" >&2
        cleanup_failed=true
    fi
    if [ -n "$peer_id" ] && ! docker rm -f "$peer_id" >/dev/null 2>&1; then
        printf 'cannot remove peer container %s\n' "$peer_id" >&2
        cleanup_failed=true
    fi
    if remaining_containers=$(docker ps -aq --filter "label=$resource_label"); then
        for container in $remaining_containers; do
            if ! docker rm -f "$container" >/dev/null 2>&1; then
                printf 'cannot remove labelled container %s\n' "$container" >&2
                cleanup_failed=true
            fi
        done
    else
        printf '%s\n' 'cannot enumerate labelled test containers during cleanup' >&2
        cleanup_failed=true
    fi
    if [ -n "$network_id" ] && ! docker network rm "$network_id" >/dev/null 2>&1; then
        printf 'cannot remove test network %s\n' "$network_id" >&2
        cleanup_failed=true
    fi
    if remaining_networks=$(docker network ls -q --filter "label=$resource_label"); then
        for network in $remaining_networks; do
            if ! docker network rm "$network" >/dev/null 2>&1; then
                printf 'cannot remove labelled test network %s\n' "$network" >&2
                cleanup_failed=true
            fi
        done
    else
        printf '%s\n' 'cannot enumerate labelled test networks during cleanup' >&2
        cleanup_failed=true
    fi
    case "$temporary_directory" in
        /tmp/openshield-short-e2e.*)
            if ! rm -rf -- "$temporary_directory"; then
                printf 'cannot remove temporary directory %s\n' \
                    "$temporary_directory" >&2
                cleanup_failed=true
            fi
            ;;
        *)
            printf 'refusing unsafe cleanup: %s\n' "$temporary_directory" >&2
            cleanup_failed=true
            ;;
    esac
    printf 'OpenShield short-lived E2E evidence: %s\n' "$evidence_directory"
    if [ "$cleanup_failed" = true ] && [ "$status" -eq 0 ]; then
        status=1
    fi
    if [ "$status" -ne 0 ]; then
        printf 'OpenShield short-lived E2E failed during stage "%s"\n' "$stage" >&2
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

begin_stage 'extract RPM daemon without host installation'
install -d -m 0755 "$temporary_directory/extracted"
rpm2cpio "$rpm_path" > "$temporary_directory/package.cpio"
(
    cd "$temporary_directory/extracted"
    cpio -idm --quiet --no-absolute-filenames \
        ./usr/bin/openshield-daemon usr/bin/openshield-daemon \
        < "$temporary_directory/package.cpio"
)
daemon_binary="$temporary_directory/extracted/usr/bin/openshield-daemon"
[ -x "$daemon_binary" ] && [ ! -L "$daemon_binary" ] || {
    printf '%s\n' 'RPM daemon is missing or non-executable' >&2
    exit 1
}
case "$(LC_ALL=C file -b "$daemon_binary")" in
    *'statically linked'*|*'static-pie linked'*) ;;
    *) printf '%s\n' 'RPM daemon is not statically linked' >&2; exit 1 ;;
esac
if LC_ALL=C readelf -l "$daemon_binary" | grep -Eq '(^|[[:space:]])INTERP([[:space:]]|$)'; then
    printf '%s\n' 'RPM daemon unexpectedly has an ELF interpreter' >&2
    exit 1
fi
begin_stage 'create isolated client and peer namespaces'
docker pull --platform linux/amd64 "$tumbleweed_image" >/dev/null
docker pull --platform linux/amd64 "$peer_image" >/dev/null
network_id=$(docker network create --label "$resource_label" "$network_name")
peer_id=$(docker create --platform linux/amd64 --name "$peer_name" --label "$resource_label" \
    --network "$network_id" --read-only --cap-drop ALL --cap-add NET_BIND_SERVICE \
    --security-opt no-new-privileges --security-opt label=disable \
    --pids-limit 256 --memory 256m \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m \
    --mount "type=bind,src=$script_directory/short-lived-sockets.py,dst=/opt/short-lived-sockets.py,readonly" \
    "$peer_image" sleep infinity)
client_id=$(docker create --platform linux/amd64 --name "$client_name" --label "$resource_label" \
    --network "$network_id" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE \
    --cap-add DAC_READ_SEARCH --security-opt no-new-privileges --security-opt label=disable \
    --sysctl 'net.ipv4.ping_group_range=0 2147483647' \
    --pids-limit 8192 --memory 2g --env PYTHONDONTWRITEBYTECODE=1 \
    --mount "type=bind,src=$temporary_directory/extracted/usr/bin,dst=/opt/openshield,readonly" \
    --mount "type=bind,src=$script_directory/ipc_client.py,dst=/opt/ipc_client.py,readonly" \
    --mount "type=bind,src=$script_directory/proxy-workload.py,dst=/opt/proxy-workload.py,readonly" \
    --mount "type=bind,src=$script_directory/argv-attribution.py,dst=/opt/argv-attribution.py,readonly" \
    --mount "type=bind,src=$script_directory/short-lived-sockets.py,dst=/opt/short-lived-sockets.py,readonly" \
    "$tumbleweed_image" sleep infinity)
docker start "$peer_id" "$client_id" >/dev/null
peer_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$peer_id")
case "$peer_ip" in ''|*[!0-9.]*) printf '%s\n' 'unsafe peer address' >&2; exit 1 ;; esac
client_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$client_id")
case "$client_ip" in ''|*[!0-9.]*) printf '%s\n' 'unsafe client address' >&2; exit 1 ;; esac
docker exec --detach "$peer_id" python3 /opt/short-lived-sockets.py serve \
    "$peer_ip" 18091 18092 /tmp/short-events.jsonl /tmp/short-server.ready
wait_for_file "$peer_id" /tmp/short-server.ready 'TCP/DNS/UDP peer'

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
docker exec "$client_id" zypper --non-interactive --no-refresh install \
    --repo repo-oss $packages >/dev/null
[ "$(docker exec "$client_id" stat -fc %T /sys/fs/cgroup)" = cgroup2fs ] || {
    printf '%s\n' 'short-lived attribution fixture requires cgroup v2' >&2
    exit 1
}
reported_version=$(docker exec "$client_id" timeout --signal=KILL 5 \
    /opt/openshield/openshield-daemon --version)
[ "$reported_version" = "openshield-daemon $expected_version" ] || {
    printf '%s\n' 'RPM daemon version mismatch' >&2
    exit 1
}
if [ "$backend" = iptables ] && docker exec "$client_id" /bin/sh -c 'command -v nft >/dev/null'; then
    printf '%s\n' 'iptables fixture unexpectedly contains nft' >&2
    exit 1
fi
docker exec "$client_id" /bin/sh -c '
    getent group openshield >/dev/null || groupadd --system openshield
    id shortapp >/dev/null 2>&1 || useradd --system --no-create-home --shell /bin/false shortapp
    id noiseuser >/dev/null 2>&1 || useradd --system --no-create-home --shell /bin/false noiseuser
    install -d -m 0755 -o root -g root /run/openshield
    install -d -m 0700 -o root -g root /var/lib/openshield
    python=$(readlink -f "$(command -v python3)")
    for target in short-held short-tcp-a short-tcp-b short-dns-a short-dns-b \
        short-udp-fire short-unknown short-argv; do
        install -m 0755 "$python" "/tmp/$target"
    done
    ping=$(readlink -f "$(command -v ping)")
    install -m 0755 "$ping" /tmp/short-ping-allowed
    install -m 0755 "$ping" /tmp/short-ping-unknown
'
docker exec "$client_id" /bin/sh -c '
    printf "nameserver %s\noptions timeout:1 attempts:1\n" "$1" > /etc/resolv.conf
' openshield-short-resolver "$peer_ip"
short_uid=$(docker exec "$client_id" id -u shortapp)

begin_stage 'measure ICMP baseline without OpenShield'
docker exec "$client_id" /bin/sh -c '
    exec runuser -u shortapp -- python3 /opt/short-lived-sockets.py ping-measure \
        /tmp/short-ping-allowed "$1" 10 >/tmp/ping-baseline.json
' openshield-short-ping-baseline "$peer_ip"

begin_stage 'start daemon in Learning'
docker exec --detach "$client_id" /bin/sh -c '
    /opt/openshield/openshield-daemon >/tmp/openshield.log 2>&1 &
    child=$!
    printf "%s\n" "$child" >/tmp/openshield.pid
    if wait "$child"; then status=0; else status=$?; fi
    printf "%s\n" "$status" >/tmp/openshield.exit-status
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

begin_stage 'start bounded procfs pressure'
docker exec --detach "$client_id" /bin/sh -c '
    if runuser -u shortapp -- python3 /opt/proxy-workload.py procfs-noise \
        16 32 256 /tmp/noise-same.ready /tmp/noise-same.release \
        >/tmp/noise-same.log 2>&1; then status=0; else status=$?; fi
    printf "%s\n" "$status" >/tmp/noise-same.status
'
docker exec --detach "$client_id" /bin/sh -c '
    if runuser -u noiseuser -- python3 /opt/proxy-workload.py procfs-noise \
        16 32 256 /tmp/noise-other.ready /tmp/noise-other.release \
        >/tmp/noise-other.log 2>&1; then status=0; else status=$?; fi
    printf "%s\n" "$status" >/tmp/noise-other.status
'
wait_for_file "$client_id" /tmp/noise-same.ready 'same-UID procfs pressure'
wait_for_file "$client_id" /tmp/noise-other.ready 'other-UID procfs pressure'

begin_stage 'verify held-flow Learning control'
docker exec --detach "$client_id" /bin/sh -c '
    if runuser -u shortapp -- /tmp/short-held /opt/short-lived-sockets.py held-tcp \
        "$1" 18091 /tmp/held.ready /tmp/held.release >/tmp/held.log 2>&1; then
        status=0
    else
        status=$?
    fi
    printf "%s\n" "$status" >/tmp/held.status
' openshield-short-held "$peer_ip"
wait_for_file "$client_id" /tmp/held.ready 'held Learning control'
attempt=0
while [ "$attempt" -lt 100 ]; do
    if docker exec "$client_id" /bin/sh -c '
        exec python3 /opt/short-lived-sockets.py audit-held-rule \
            "$1" 18091 "$2" >/tmp/held-rule-audit.json 2>&1
    ' openshield-short-held-audit "$peer_ip" "$short_uid"; then
        break
    fi
    attempt=$((attempt + 1)); sleep 0.1
done
[ "$attempt" -lt 100 ] || {
    printf '%s\n' 'held control was not learned' >&2
    docker exec "$client_id" cat /tmp/held-rule-audit.json >&2 || true
    exit 1
}
docker exec "$client_id" touch /tmp/held.release
wait_for_file "$client_id" /tmp/held.status 'held Learning control exit'
[ "$(docker exec "$client_id" cat /tmp/held.status)" = 0 ] || exit 1

begin_stage 'exercise unique short-lived TCP and DNS-to-TCP children'
run_children() {
    output=$1
    shift
    docker exec "$client_id" runuser -u shortapp -- \
        python3 /opt/short-lived-sockets.py spawn 8 4 "$@" > "$output"
}
run_children "$temporary_directory/tcp-a-learning.json" \
    /tmp/short-tcp-a /opt/short-lived-sockets.py tcp-once "$peer_ip" 18091 tcp-a
run_children "$temporary_directory/tcp-b-learning.json" \
    /tmp/short-tcp-b /opt/short-lived-sockets.py tcp-once "$peer_ip" 18091 tcp-b
run_children "$temporary_directory/dns-a-learning.json" \
    /tmp/short-dns-a /opt/short-lived-sockets.py dns-tcp-once \
    dns-a.e2e.openshield.test 18091 dns-a
run_children "$temporary_directory/dns-b-learning.json" \
    /tmp/short-dns-b /opt/short-lived-sockets.py dns-tcp-once \
    dns-b.e2e.openshield.test 18091 dns-b
docker exec "$client_id" runuser -u shortapp -- \
    python3 /opt/short-lived-sockets.py spawn 16 8 \
    /tmp/short-udp-fire /opt/short-lived-sockets.py fire-and-forget \
    "$peer_ip" 18092 fire > "$temporary_directory/fire-learning.json"
for artifact in tcp-a-learning tcp-b-learning dns-a-learning dns-b-learning fire-learning; do
    docker cp "$temporary_directory/$artifact.json" "$client_id:/tmp/$artifact.json" >/dev/null
done
attempt=0
while [ "$attempt" -lt 50 ]; do
    docker exec "$peer_id" cat /tmp/short-events.jsonl \
        > "$temporary_directory/peer-events.jsonl"
    docker cp "$temporary_directory/peer-events.jsonl" \
        "$client_id:/tmp/peer-events.jsonl" >/dev/null
    if docker exec "$client_id" /bin/sh -c '
        exec python3 /opt/short-lived-sockets.py audit-peer \
            /tmp/peer-events.jsonl "$1" >/tmp/peer-audit.json 2>&1
    ' openshield-short-peer-audit "$client_ip"; then
        break
    fi
    attempt=$((attempt + 1)); sleep 0.1
done
[ "$attempt" -lt 50 ] || {
    docker exec "$client_id" cat /tmp/peer-audit.json >&2 || true
    printf '%s\n' 'peer did not observe every Learning exchange' >&2
    exit 1
}

begin_stage 'wait for bounded asynchronous Learning persistence'
attempt=0
while [ "$attempt" -lt 100 ]; do
    if docker exec "$client_id" /bin/sh -c '
        exec python3 /opt/short-lived-sockets.py audit-rules \
            "$1" 18091 18092 "$2" \
            >/tmp/learning-rule-audit.json 2>/tmp/learning-rule-audit.error
    ' openshield-short-rule-audit "$peer_ip" "$short_uid"; then
        learning_rules_ok=true
        break
    fi
    attempt=$((attempt + 1)); sleep 0.1
done
if [ "$learning_rules_ok" != true ]; then
    docker exec "$client_id" /bin/sh -c '
        exec python3 /opt/short-lived-sockets.py audit-rules \
            "$1" 18091 18092 "$2" \
            >/tmp/learning-rule-audit.json 2>/tmp/learning-rule-audit.error
    ' openshield-short-rule-audit "$peer_ip" "$short_uid" || true
    printf '%s\n' 'short-lived Learning did not persist every required exact rule' >&2
    result=1
fi

begin_stage 'enter application-aware Enforcing and measure ICMP'
docker exec "$client_id" /bin/sh -c '
    exec python3 /opt/short-lived-sockets.py create-icmp-rule \
        /tmp/short-ping-allowed "$1" "$2" >/tmp/icmp-rule-audit.json
' openshield-short-icmp-rule "$short_uid" "$peer_ip"
docker exec "$client_id" python3 /opt/ipc_client.py set-mode enforcing >/dev/null
docker exec "$client_id" python3 /opt/ipc_client.py assert-runtime \
    enforcing "$backend" nfqueue application_per_packet >/dev/null

if [ "$learning_rules_ok" = true ]; then
    set +e
    run_children "$temporary_directory/tcp-a-enforcing.json" \
        /tmp/short-tcp-a /opt/short-lived-sockets.py tcp-once "$peer_ip" 18091 tcp-a
    tcp_a_status=$?
    run_children "$temporary_directory/tcp-b-enforcing.json" \
        /tmp/short-tcp-b /opt/short-lived-sockets.py tcp-once "$peer_ip" 18091 tcp-b
    tcp_b_status=$?
    run_children "$temporary_directory/dns-a-enforcing.json" \
        /tmp/short-dns-a /opt/short-lived-sockets.py dns-tcp-once \
        dns-a.e2e.openshield.test 18091 dns-a
    dns_a_status=$?
    run_children "$temporary_directory/dns-b-enforcing.json" \
        /tmp/short-dns-b /opt/short-lived-sockets.py dns-tcp-once \
        dns-b.e2e.openshield.test 18091 dns-b
    dns_b_status=$?
    set -e
    for pair in "$tcp_a_status:tcp-a" "$tcp_b_status:tcp-b" \
        "$dns_a_status:dns-a" "$dns_b_status:dns-b"; do
        case "$pair" in 0:*) ;; *) printf 'known Enforcing workload failed: %s\n' "$pair" >&2; result=1 ;; esac
    done
    for artifact in tcp-a-enforcing tcp-b-enforcing dns-a-enforcing dns-b-enforcing; do
        [ ! -f "$temporary_directory/$artifact.json" ] || \
            docker cp "$temporary_directory/$artifact.json" "$client_id:/tmp/$artifact.json" >/dev/null
    done
    if ! docker exec "$client_id" /bin/sh -c '
        exec runuser -u shortapp -- /tmp/short-unknown \
            /opt/short-lived-sockets.py tcp-blocked "$1" 18091 \
            >/tmp/unknown-tcp.json 2>&1
    ' openshield-short-unknown "$peer_ip"; then
        printf '%s\n' 'unknown same-UID executable did not fail closed' >&2
        result=1
    fi
    if ! docker exec "$client_id" /bin/sh -c '
        exec runuser -u shortapp -- /tmp/short-unknown \
            /opt/short-lived-sockets.py dns-blocked \
            dns-a.e2e.openshield.test 18091 >/tmp/unknown-dns.json 2>&1
    '; then
        printf '%s\n' 'unknown same-UID executable resolved DNS in Enforcing' >&2
        result=1
    fi
    if ! docker exec "$client_id" /bin/sh -c '
        exec runuser -u shortapp -- /tmp/short-tcp-a \
            /opt/short-lived-sockets.py tcp-blocked "$1" 18091 \
            >/tmp/unknown-argv-tcp.json 2>&1
    ' openshield-short-argv-denied "$peer_ip"; then
        printf '%s\n' 'known executable with unmatched argv crossed Enforcing' >&2
        result=1
    fi
    if ! docker exec "$client_id" /bin/sh -c '
        exec runuser -u shortapp -- /tmp/short-dns-a \
            /opt/short-lived-sockets.py dns-blocked \
            dns-a.e2e.openshield.test 18091 >/tmp/unknown-argv-dns.json 2>&1
    '; then
        printf '%s\n' 'known executable with unmatched DNS argv crossed Enforcing' >&2
        result=1
    fi
fi

docker exec "$client_id" /bin/sh -c '
    exec python3 /opt/short-lived-sockets.py capture-counters \
        >/tmp/counters-before-ping.json
'
set +e
docker exec "$client_id" /bin/sh -c '
    exec runuser -u shortapp -- python3 /opt/short-lived-sockets.py ping-measure \
        /tmp/short-ping-allowed "$1" 10 >/tmp/ping-enforcing.json
' openshield-short-ping-enforcing "$peer_ip"
ping_status=$?
set -e
docker exec "$client_id" /bin/sh -c '
    exec python3 /opt/short-lived-sockets.py capture-counters \
        >/tmp/counters-after-ping.json
'
if ! docker exec "$client_id" /bin/sh -c '
    exec python3 /opt/short-lived-sockets.py compare-counter-delta \
        /tmp/counters-before-ping.json /tmp/counters-after-ping.json \
        >/tmp/counters-ping-delta.json
'; then
    printf '%s\n' 'allowed ICMP incremented a firewall drop counter' >&2
    result=1
fi
if [ "$ping_status" -ne 0 ]; then
    printf '%s\n' 'application-bound ICMP lost packets or timed out' >&2
    result=1
else
    docker exec "$client_id" /bin/sh -c '
        exec python3 /opt/short-lived-sockets.py compare-ping \
            /tmp/ping-baseline.json /tmp/ping-enforcing.json \
            >/tmp/ping-comparison.json
    '
fi
if ! docker exec "$client_id" /bin/sh -c '
    exec runuser -u shortapp -- python3 /opt/short-lived-sockets.py ping-blocked \
        /tmp/short-ping-unknown "$1" >/tmp/ping-unknown.log 2>&1
' openshield-short-ping-denied "$peer_ip"; then
    printf '%s\n' 'unknown same-UID ping did not fail closed cleanly' >&2
    result=1
fi

if [ "$learning_rules_ok" = true ]; then
    if ! docker exec "$client_id" python3 /opt/proxy-workload.py \
        assert-nfqueue-clean --require-denied >/dev/null; then
        printf '%s\n' 'NFQUEUE reported a timeout, overflow, or terminal error' >&2
        result=1
    fi
else
    if ! docker exec "$client_id" python3 /opt/proxy-workload.py \
        assert-nfqueue-clean >/dev/null; then
        printf '%s\n' 'NFQUEUE reported a timeout, overflow, or terminal error' >&2
        result=1
    fi
fi
if docker exec "$client_id" grep -Eqi \
    'fail.open|quarantine|emergency BlockAll' /tmp/openshield.log; then
    printf '%s\n' 'daemon reported fail-open or quarantine' >&2
    result=1
fi

docker exec "$client_id" touch /tmp/noise-same.release /tmp/noise-other.release
wait_for_file "$client_id" /tmp/noise-same.status 'same-UID noise exit'
wait_for_file "$client_id" /tmp/noise-other.status 'other-UID noise exit'
if [ "$(docker exec "$client_id" cat /tmp/noise-same.status)" != 0 ]; then
    printf '%s\n' 'same-UID procfs pressure failed after readiness' >&2
    result=1
fi
if [ "$(docker exec "$client_id" cat /tmp/noise-other.status)" != 0 ]; then
    printf '%s\n' 'other-UID procfs pressure failed after readiness' >&2
    result=1
fi

begin_stage 'verify exact long and escaped argv Learning and Enforcing'
if ! docker exec "$client_id" /bin/sh -c '
    exec python3 /opt/argv-attribution.py exercise "$1" 18091 "$2" \
        >/tmp/argv-attribution.jsonl 2>/tmp/argv-attribution.error
' openshield-short-argv-regression "$peer_ip" "$short_uid"; then
    printf '%s\n' 'long/control argv was not learned exactly or did not enforce safely' >&2
    docker exec "$client_id" cat /tmp/argv-attribution.error >&2 || true
    result=1
fi
docker exec "$peer_id" cat /tmp/short-events.jsonl > "$temporary_directory/argv-peer-events.jsonl"
docker cp "$temporary_directory/argv-peer-events.jsonl" \
    "$client_id:/tmp/argv-peer-events.jsonl" >/dev/null
if ! docker exec "$client_id" /bin/sh -c '
    exec python3 /opt/argv-attribution.py audit-peer /tmp/argv-peer-events.jsonl "$1" \
        >/tmp/argv-peer-audit.json 2>&1
' openshield-short-argv-peer-audit "$client_ip"; then
    printf '%s\n' 'argv peer evidence contains a missing or unauthorized exchange' >&2
    result=1
fi
if ! docker exec "$client_id" python3 /opt/proxy-workload.py \
    assert-nfqueue-clean --require-denied >/dev/null; then
    printf '%s\n' 'argv regression encountered a NFQUEUE timeout, overflow, or terminal error' >&2
    result=1
fi

begin_stage 'complete'
if [ "$result" -eq 0 ]; then
    printf 'PASS short-lived TCP/UDP Learning and ICMP Enforcing (%s)\n' "$backend"
else
    printf 'FAIL short-lived TCP/UDP Learning or ICMP Enforcing (%s)\n' "$backend" >&2
fi
exit "$result"
