#!/bin/sh
set -eu

usage() {
    printf 'usage: %s {nftables|iptables} ABSOLUTE_ARTIFACT_DIRECTORY\n' "$0" >&2
}

[ "$#" -eq 2 ] || { usage; exit 2; }
backend=$1
artifact_directory=$2
case "$backend" in nftables|iptables) ;; *) usage; exit 2 ;; esac
case "$artifact_directory" in /*) ;; *) printf '%s\n' 'artifact directory must be absolute' >&2; exit 2 ;; esac
artifact_mode=${E2E_ARTIFACT_MODE:-binary}
native_client_source=${E2E_NATIVE_CLIENT:-}
case "$artifact_mode" in
    binary)
        [ -x "$artifact_directory/openshield-daemon" ] \
            || { printf '%s\n' 'missing daemon binary' >&2; exit 2; }
        daemon_path=/opt/openshield/openshield-daemon
        artifact_mount_destination=/opt/openshield
        ;;
    package)
        [ -d "$artifact_directory" ] \
            || { printf '%s\n' 'missing package directory' >&2; exit 2; }
        package_count=$(find "$artifact_directory" -mindepth 1 -maxdepth 1 -type f ! -name '.*' | wc -l)
        [ "$package_count" -eq 1 ] \
            || { printf '%s\n' 'expected exactly one package artifact' >&2; exit 2; }
        [ -z "$(find "$artifact_directory" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ] \
            || { printf '%s\n' 'unsafe package artifact directory' >&2; exit 2; }
        [ -z "$(find "$artifact_directory" -mindepth 1 -maxdepth 1 -name '.*' -print -quit)" ] \
            || { printf '%s\n' 'hidden package artifacts are not allowed' >&2; exit 2; }
        expected_version=${EXPECTED_VERSION:?EXPECTED_VERSION is required in package mode}
        case "$expected_version" in
            ''|*[!0-9A-Za-z.+~-]*) printf '%s\n' 'unsafe EXPECTED_VERSION' >&2; exit 2 ;;
        esac
        daemon_path=/usr/bin/openshield-daemon
        artifact_mount_destination=/packages
        ;;
    *)
        printf '%s\n' 'E2E_ARTIFACT_MODE must be binary or package' >&2
        exit 2
        ;;
esac
if [ -n "$native_client_source" ]; then
    for required_command in file readelf awk grep; do
        command -v "$required_command" >/dev/null 2>&1 || {
            printf 'required native-client verifier is unavailable: %s\n' \
                "$required_command" >&2
            exit 2
        }
    done
    case "$native_client_source" in
        /*) ;;
        *) printf '%s\n' 'E2E_NATIVE_CLIENT must be absolute' >&2; exit 2 ;;
    esac
    case "$native_client_source" in
        *[!A-Za-z0-9._/-]*)
            printf '%s\n' 'E2E_NATIVE_CLIENT contains unsafe path characters' >&2
            exit 2
            ;;
    esac
    if [ ! -f "$native_client_source" ] || [ ! -x "$native_client_source" ] \
        || [ -L "$native_client_source" ]; then
        printf '%s\n' 'E2E_NATIVE_CLIENT must be an executable regular non-symlink file' >&2
        exit 2
    fi
    native_client_identity=$(LC_ALL=C file -b "$native_client_source")
    case "$native_client_identity" in
        *"statically linked"*|*"static-pie linked"*) ;;
        *) printf '%s\n' 'E2E_NATIVE_CLIENT must be statically linked' >&2; exit 2 ;;
    esac
    if LC_ALL=C readelf -l "$native_client_source" \
        | grep -Eq '(^|[[:space:]])INTERP([[:space:]]|$)'; then
        printf '%s\n' 'E2E_NATIVE_CLIENT must not contain an ELF interpreter' >&2
        exit 2
    fi
    native_client_machine=$(LC_ALL=C readelf -h "$native_client_source" \
        | awk -F: '/^[[:space:]]*Machine:/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }')
    case "$(uname -m)" in
        x86_64) expected_native_client_machine='Advanced Micro Devices X86-64' ;;
        aarch64) expected_native_client_machine=AArch64 ;;
        *) printf '%s\n' 'unsupported E2E runner architecture for native helper' >&2; exit 2 ;;
    esac
    [ "$native_client_machine" = "$expected_native_client_machine" ] || {
        printf '%s\n' 'E2E_NATIVE_CLIENT does not match the Docker host architecture' >&2
        exit 2
    }
fi
client_family=${CLIENT_FAMILY:-debian}
client_platform=${CLIENT_PLATFORM:-linux/amd64}
client_image=${CLIENT_IMAGE:-rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922}
server_image=${SERVER_IMAGE:-python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285}
case "$client_family" in
    debian|deb|fedora|el9|el10|opensuse|tumbleweed|alpine|arch) ;;
    *) printf '%s\n' 'unsupported E2E client family' >&2; exit 2 ;;
esac
case "$client_platform" in
    linux/amd64|linux/arm64|linux/386|linux/arm/v5|linux/arm/v6|linux/arm/v7|linux/ppc64le|linux/s390x|linux/riscv64) ;;
    *) printf '%s\n' 'unsupported E2E client platform' >&2; exit 2 ;;
esac
for image in "$client_image" "$server_image"; do
    case "$image" in
        ''|-*|*[!A-Za-z0-9._/:@-]*) printf '%s\n' 'unsafe E2E image' >&2; exit 2 ;;
    esac
    case "$image" in
        *@sha256:????????????????????????????????????????????????????????????????) ;;
        *) printf '%s\n' 'E2E images must be pinned by SHA-256 digest' >&2; exit 2 ;;
    esac
    image_digest=${image##*@sha256:}
    case "$image_digest" in
        *[!0-9a-f]*) printf '%s\n' 'invalid E2E image digest' >&2; exit 2 ;;
    esac
done

command -v docker >/dev/null 2>&1 || {
    printf '%s\n' 'docker is not installed' >&2
    exit 1
}
docker_host=$(docker context inspect --format '{{(index .Endpoints "docker").Host}}' 2>/dev/null) || {
    printf '%s\n' 'cannot inspect the active Docker context' >&2
    exit 1
}
case "$docker_host" in
    unix:///*) ;;
    *)
        printf 'refusing non-local Docker endpoint: %s\n' "$docker_host" >&2
        exit 1
        ;;
esac

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
temporary_directory=$(mktemp -d /tmp/openshield-e2e.XXXXXX)
run_token=${temporary_directory##*/}
network_name="openshield-$run_token"
client_name="openshield-client-$run_token"
server_name="openshield-server-$run_token"
resource_label="org.openshield.e2e.run=$run_token"
network_id=
client_id=
server_id=
stage_name=initialization
daemon_pid_file=/tmp/openshield.pid
daemon_exit_file=/tmp/openshield.exit-status
daemon_wait_attempts=600

begin_stage() {
    stage_name=$1
    printf '==> OpenShield E2E (%s): %s\n' "$backend" "$stage_name"
}

refresh_zypper_repository() {
    container=$1
    repository=$2
    attempt=1
    maximum_attempts=3
    while :; do
        if docker exec "$container" zypper --non-interactive refresh "$repository"; then
            return 0
        else
            refresh_status=$?
        fi
        if [ "$refresh_status" -ne 4 ]; then
            printf 'zypper refresh for %s failed with non-retryable status %s\n' \
                "$repository" "$refresh_status" >&2
            return "$refresh_status"
        fi
        if [ "$attempt" -ge "$maximum_attempts" ]; then
            printf 'zypper refresh for %s failed after %s attempts (status %s)\n' \
                "$repository" "$attempt" "$refresh_status" >&2
            return "$refresh_status"
        fi
        retry_delay=$((attempt * 5))
        printf 'zypper refresh for %s failed (status %s); retrying in %s seconds\n' \
            "$repository" "$refresh_status" "$retry_delay" >&2
        sleep "$retry_delay"
        attempt=$((attempt + 1))
    done
}

wait_for_marker() {
    container=$1
    marker=$2
    description=$3
    if docker exec "$container" /bin/sh -c '
        marker=$1
        attempt=0
        while [ "$attempt" -lt 100 ]; do
            [ ! -f "$marker" ] || exit 0
            attempt=$((attempt + 1))
            sleep 0.1
        done
        exit 1
    ' openshield-marker-wait "$marker"; then
        return 0
    fi
    printf '%s did not become ready within 10 seconds\n' "$description" >&2
    return 1
}

start_observable_learning_hold() {
    learning_hold_tcp_port=$1
    learning_hold_udp_port=$2
    learning_hold_ready="/tmp/openshield-learning-hold-${learning_hold_tcp_port}-${learning_hold_udp_port}.ready"
    learning_hold_release="/tmp/openshield-learning-hold-${learning_hold_tcp_port}-${learning_hold_udp_port}.release"
    learning_hold_status="/tmp/openshield-learning-hold-${learning_hold_tcp_port}-${learning_hold_udp_port}.status"
    learning_hold_log="/tmp/openshield-learning-hold-${learning_hold_tcp_port}-${learning_hold_udp_port}.log"
    docker exec "$client" rm -f "$learning_hold_ready" "$learning_hold_release" \
        "$learning_hold_status" "${learning_hold_status}.tmp" "$learning_hold_log"
    docker exec --detach "$client" /bin/sh -c '
        address=$1
        tcp_port=$2
        udp_port=$3
        log_file=$4
        status_file=$5
        if python3 /opt/learning-sockets.py hold \
            "$address" "$tcp_port" "$udp_port" >"$log_file" 2>&1; then
            status=0
        else
            status=$?
        fi
        printf "%s\n" "$status" >"${status_file}.tmp"
        mv -f "${status_file}.tmp" "$status_file"
    ' openshield-learning-hold "$server_ip" "$learning_hold_tcp_port" \
        "$learning_hold_udp_port" "$learning_hold_log" "$learning_hold_status"
    wait_for_marker "$client" "$learning_hold_ready" \
        "observable Learning TCP/UDP flow on ports ${learning_hold_tcp_port}/${learning_hold_udp_port}"
}

finish_observable_learning_hold() {
    docker exec "$client" touch "$learning_hold_release"
    wait_for_marker "$client" "$learning_hold_status" \
        "observable Learning TCP/UDP flow exit"
    learning_hold_exit_status=$(docker exec "$client" cat "$learning_hold_status")
    [ "$learning_hold_exit_status" = 0 ] || {
        docker exec "$client" cat "$learning_hold_log" >&2 || true
        printf 'observable Learning TCP/UDP flow exited with status %s\n' \
            "$learning_hold_exit_status" >&2
        exit 1
    }
}

dump_daemon_log() {
    daemon_log=$1
    docker exec "$client" cat "$daemon_log" >&2 || true
}

start_daemon() {
    daemon_log=$1
    docker exec "$client" rm -f \
        "$daemon_pid_file" "$daemon_exit_file" "${daemon_exit_file}.tmp"
    docker exec --detach "$client" /bin/sh -c '
        log_file=$1
        pid_file=$2
        status_file=$3
        exact_caps=$4
        daemon=$5
        temporary_status="${status_file}.tmp"
        if [ "$exact_caps" = true ]; then
            setpriv \
                --regid root --groups openshield \
                --bounding-set=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search \
                --inh-caps=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search \
                --ambient-caps=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search \
                -- "$daemon" >"$log_file" 2>&1 &
        else
            "$daemon" >"$log_file" 2>&1 &
        fi
        child_pid=$!
        printf "%s\n" "$child_pid" >"$pid_file"
        if wait "$child_pid"; then
            child_status=0
        else
            child_status=$?
        fi
        printf "%s\n" "$child_status" >"$temporary_status"
        mv -f "$temporary_status" "$status_file"
        exit "$child_status"
    ' openshield-daemon-supervisor \
        "$daemon_log" "$daemon_pid_file" "$daemon_exit_file" \
        "$use_exact_unit_capabilities" "$daemon_path"
}

install_fail_closed_preflight() {
    docker exec "$client" /bin/sh -c '
        log_file=$1
        daemon=$2
        if ! setpriv \
            --regid root --groups openshield \
            --bounding-set=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search \
            --inh-caps=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search \
            --ambient-caps=-all,+net_admin,+net_raw,+sys_ptrace,+dac_read_search \
            -- "$daemon" --install-fail-closed \
            >"$log_file" 2>&1; then
            cat "$log_file" >&2
            exit 1
        fi
    ' openshield-fail-closed-preflight /tmp/openshield-preflight.log "$daemon_path"
}

assert_exact_unit_process_state() {
    docker exec "$client" /bin/sh -c '
        pid_file=$1
        pid=$(cat "$pid_file")
        case "$pid" in ""|*[!0-9]*) exit 1 ;; esac
        status=/proc/$pid/status
        observer_gid=$(getent group openshield | cut -d: -f3)
        expected_caps=0000000000083004
        [ -n "$observer_gid" ] && [ -r "$status" ]

        set -- $(sed -n "s/^Uid:[[:space:]]*//p" "$status")
        [ "$#" -eq 4 ] && [ "$1" = 0 ] && [ "$2" = 0 ] \
            && [ "$3" = 0 ] && [ "$4" = 0 ]
        set -- $(sed -n "s/^Gid:[[:space:]]*//p" "$status")
        [ "$#" -eq 4 ] && [ "$1" = 0 ] && [ "$2" = 0 ] \
            && [ "$3" = 0 ] && [ "$4" = 0 ]
        set -- $(sed -n "s/^Groups:[[:space:]]*//p" "$status")
        [ "$#" -eq 1 ] && [ "$1" = "$observer_gid" ]
        [ "$(sed -n "s/^NoNewPrivs:[[:space:]]*//p" "$status")" = 1 ]
        for field in CapInh CapPrm CapEff CapBnd CapAmb; do
            value=$(sed -n "s/^$field:[[:space:]]*//p" "$status")
            [ "$value" = "$expected_caps" ] || exit 1
        done
    ' openshield-unit-state "$daemon_pid_file" || {
        printf '%s\n' 'daemon process does not match the packaged systemd identity and capabilities' >&2
        return 1
    }
}

wait_for_daemon_ready() {
    daemon_log=$1
    daemon_description=$2
    if docker exec "$client" /bin/sh -c '
        socket_path=$1
        status_file=$2
        maximum_attempts=$3
        attempt=0
        while [ "$attempt" -lt "$maximum_attempts" ]; do
            [ ! -s "$status_file" ] || exit 3
            [ ! -S "$socket_path" ] || exit 0
            attempt=$((attempt + 1))
            sleep 0.1
        done
        exit 2
    ' openshield-daemon-ready-wait \
        /run/openshield/control.sock "$daemon_exit_file" "$daemon_wait_attempts"; then
        return 0
    else
        daemon_wait_status=$?
    fi
    dump_daemon_log "$daemon_log"
    if [ "$daemon_wait_status" -eq 3 ]; then
        daemon_status=$(docker exec "$client" cat "$daemon_exit_file" 2>/dev/null || true)
        printf '%s exited before readiness (status %s)\n' \
            "$daemon_description" "${daemon_status:-unknown}" >&2
    else
        printf '%s did not become ready within 60 seconds\n' "$daemon_description" >&2
    fi
    return 1
}

wait_for_daemon_exit() {
    daemon_log=$1
    daemon_description=$2
    if ! docker exec "$client" /bin/sh -c '
        status_file=$1
        maximum_attempts=$2
        attempt=0
        while [ "$attempt" -lt "$maximum_attempts" ]; do
            [ ! -s "$status_file" ] || exit 0
            attempt=$((attempt + 1))
            sleep 0.1
        done
        exit 1
    ' openshield-daemon-exit-wait "$daemon_exit_file" "$daemon_wait_attempts"; then
        dump_daemon_log "$daemon_log"
        printf '%s did not exit within 60 seconds\n' "$daemon_description" >&2
        return 1
    fi
    daemon_status=$(docker exec "$client" cat "$daemon_exit_file" 2>/dev/null || true)
    case "$daemon_status" in
        0) return 0 ;;
        ''|*[!0-9]*)
            dump_daemon_log "$daemon_log"
            printf '%s produced an invalid exit status: %s\n' \
                "$daemon_description" "${daemon_status:-empty}" >&2
            ;;
        *)
            dump_daemon_log "$daemon_log"
            printf '%s exited unsuccessfully with status %s\n' \
                "$daemon_description" "$daemon_status" >&2
            ;;
    esac
    return 1
}

cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        printf 'OpenShield E2E failed during stage "%s" (%s)\n' "$stage_name" "$backend" >&2
        if [ -n "$client_id" ]; then
            docker exec "$client_id" sh -c \
                'printf "%s\n" "--- runtime ---"
                 uname -a 2>/dev/null || true
                 cat /tmp/openshield.exit-status /var/lib/openshield/state.json 2>/dev/null || true
                 printf "%s\n" "--- daemon logs ---"
                 cat /tmp/openshield.log /tmp/openshield-restart.log 2>/dev/null || true
                 for save in \
                     /usr/sbin/iptables-legacy-save /usr/sbin/ip6tables-legacy-save \
                     /usr/sbin/iptables-nft-save /usr/sbin/ip6tables-nft-save; do
                     [ ! -x "$save" ] || for table in mangle filter; do
                         printf "%s\n" "--- $save -t $table ---"
                         "$save" -c -t "$table" 2>&1 || true
                     done
                 done' >&2 \
                || true
        fi
    fi
    [ -z "$client_id" ] || docker rm -f "$client_id" >/dev/null 2>&1 || true
    [ -z "$server_id" ] || docker rm -f "$server_id" >/dev/null 2>&1 || true
    [ -z "$network_id" ] || docker network rm "$network_id" >/dev/null 2>&1 || true
    case "$temporary_directory" in
        /tmp/openshield-e2e.*) rm -rf -- "$temporary_directory" ;;
        *) printf 'refusing unsafe temporary cleanup: %s\n' "$temporary_directory" >&2 ;;
    esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

begin_stage 'create isolated containers'
docker pull --platform "$client_platform" "$client_image" >/dev/null
docker pull "$server_image" >/dev/null
network_id=$(docker network create --label "$resource_label" "$network_name")
server_id=$(docker create --name "$server_name" --label "$resource_label" --network "$network_id" \
    --read-only --cap-drop ALL --security-opt no-new-privileges \
    --security-opt label=disable \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
    --mount "type=bind,src=$script_directory/learning-sockets.py,dst=/opt/learning-sockets.py,readonly" \
    "$server_image" python3 -m http.server 18081 --bind 0.0.0.0)
docker start "$server_id" >/dev/null

if [ -n "$native_client_source" ]; then
    client_id=$(docker create --platform "$client_platform" \
        --name "$client_name" --label "$resource_label" --network "$network_id" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH \
        --security-opt no-new-privileges --security-opt label=disable \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --mount "type=bind,src=$artifact_directory,dst=$artifact_mount_destination,readonly" \
        --mount "type=bind,src=$script_directory/ipc_client.py,dst=/opt/ipc_client.py,readonly" \
        --mount "type=bind,src=$script_directory/learning-sockets.py,dst=/opt/learning-sockets.py,readonly" \
        --mount "type=bind,src=$script_directory/tcp-session.py,dst=/opt/tcp-session.py,readonly" \
        --mount "type=bind,src=$native_client_source,dst=/opt/openshield-e2e-client,readonly" \
        "$client_image" sleep infinity)
else
    client_id=$(docker create --platform "$client_platform" \
        --name "$client_name" --label "$resource_label" --network "$network_id" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH \
        --security-opt no-new-privileges --security-opt label=disable \
        --env PYTHONDONTWRITEBYTECODE=1 \
        --mount "type=bind,src=$artifact_directory,dst=$artifact_mount_destination,readonly" \
        --mount "type=bind,src=$script_directory/ipc_client.py,dst=/opt/ipc_client.py,readonly" \
        --mount "type=bind,src=$script_directory/learning-sockets.py,dst=/opt/learning-sockets.py,readonly" \
        --mount "type=bind,src=$script_directory/tcp-session.py,dst=/opt/tcp-session.py,readonly" \
        "$client_image" sleep infinity)
fi
docker start "$client_id" >/dev/null
client=$client_id
server=$server_id

begin_stage 'provision firewall client'
use_exact_unit_capabilities=true
case "$client_family" in
    debian|deb)
        if [ "$backend" = nftables ]; then
            # Install both frontends: selecting nftables must demonstrate
            # preference, not just the absence of the compatibility backend.
            packages='nftables iptables curl netcat-openbsd python3 passwd util-linux'
        else
            packages='iptables curl netcat-openbsd python3 passwd util-linux'
        fi
        docker exec "$client" apt-get update >/dev/null
        # shellcheck disable=SC2086
        docker exec "$client" apt-get install -y --no-install-recommends $packages >/dev/null
        if [ "$artifact_mode" = package ]; then
            docker exec "$client" /bin/sh -c \
                'apt-get install -y --no-install-recommends /packages/*.deb' >/dev/null
        fi
        ;;
    fedora|el9|el10)
        # EL9 base images already provide curl-minimal.  Asking DNF for the
        # full curl package would require replacing it and makes provisioning
        # fail before the OpenShield package is exercised.
        docker exec "$client" dnf -y install \
            nmap-ncat python3 shadow-utils util-linux >/dev/null
        if ! docker exec "$client" /bin/sh -c 'command -v curl >/dev/null'; then
            docker exec "$client" dnf -y install curl-minimal >/dev/null
        fi
        if [ "$backend" = nftables ]; then
            docker exec "$client" /bin/sh -c \
                'dnf -y install nftables iptables-nft || dnf -y install nftables iptables' \
                >/dev/null
        else
            docker exec "$client" /bin/sh -c \
                'dnf -y install iptables-nft || dnf -y install iptables' >/dev/null
        fi
        if [ "$artifact_mode" = package ]; then
            docker exec "$client" /bin/sh -c \
                'dnf -y --setopt=install_weak_deps=False install /packages/*.rpm' >/dev/null
        fi
        ;;
    opensuse|tumbleweed)
        case "$client_family" in
            opensuse) zypper_repository='openSUSE:repo-oss' ;;
            tumbleweed) zypper_repository=repo-oss ;;
        esac
        if [ "$backend" = nftables ]; then
            # Keep legacy xtables installed so nftables activation exercises
            # alternate-backend inspection with the exact systemd capability set.
            packages='nftables iptables curl netcat-openbsd python3 shadow util-linux'
        else
            packages='iptables curl netcat-openbsd python3 shadow util-linux'
        fi
        refresh_zypper_repository "$client" "$zypper_repository" >/dev/null
        # shellcheck disable=SC2086
        docker exec "$client" zypper --non-interactive --no-refresh install \
            --repo "$zypper_repository" $packages >/dev/null
        if [ "$artifact_mode" = package ]; then
            docker exec "$client" /bin/sh -c \
                'zypper --non-interactive --no-refresh install \
                    --no-recommends --allow-unsigned-rpm /packages/*.rpm' \
                >/dev/null
        fi
        ;;
    alpine)
        if [ "$backend" = nftables ]; then
            # Keep xtables installed to prove that a usable nft command wins.
            packages='nftables iptables curl netcat-openbsd python3 shadow util-linux libc-utils'
        else
            packages='iptables curl netcat-openbsd python3 shadow util-linux libc-utils'
        fi
        # shellcheck disable=SC2086
        docker exec "$client" apk add --no-cache $packages >/dev/null
        if [ "$artifact_mode" = package ]; then
            docker exec "$client" /bin/sh -c \
                'apk add --allow-untrusted /packages/*.apk' >/dev/null
        fi
        ;;
    arch)
        docker exec "$client" pacman -Syu --noconfirm --needed \
            curl openbsd-netcat python shadow util-linux >/dev/null
        if [ "$backend" = nftables ]; then
            docker exec "$client" pacman -S --noconfirm --needed \
                nftables iptables >/dev/null
        else
            # The base image currently contains the nft-based iptables package.
            # Replace it transactionally with the official legacy provider,
            # then remove the now-unused nft command before installing OpenShield.
            docker exec "$client" pacman -S --noconfirm --ask=4 \
                iptables-legacy >/dev/null
            if docker exec "$client" pacman -Q nftables >/dev/null 2>&1; then
                docker exec "$client" pacman -Rns --noconfirm nftables >/dev/null
            fi
        fi
        if [ "$artifact_mode" = package ]; then
            docker exec "$client" /bin/sh -c \
                'pacman -U --noconfirm /packages/*.pkg.tar.zst' >/dev/null
        fi
        ;;
esac
if [ "$artifact_mode" = binary ]; then
    docker exec "$client" groupadd --system openshield
else
    docker exec "$client" getent group openshield >/dev/null
    docker exec "$client" test -x "$daemon_path"
    [ "$(docker exec "$client" "$daemon_path" --version)" \
        = "openshield-daemon $expected_version" ] || {
        printf '%s\n' 'installed daemon version does not match the release' >&2
        exit 1
    }
fi
docker exec "$client" useradd --system --no-create-home --shell /bin/false observer
docker exec "$client" useradd --system --no-create-home --shell /bin/false outsider
docker exec "$client" usermod --append --groups openshield observer

if [ "$backend" = nftables ]; then
    docker exec "$client" sh -c \
        'command -v nft >/dev/null && command -v iptables-save >/dev/null' || {
        printf '%s\n' 'nftables preference scenario does not have both backends installed' >&2
        exit 1
    }
else
    if docker exec "$client" sh -c 'command -v nft >/dev/null'; then
        printf '%s\n' 'iptables fallback scenario unexpectedly has nftables installed' >&2
        exit 1
    fi
    docker exec "$client" sh -c 'command -v iptables-save >/dev/null' || {
        printf '%s\n' 'iptables fallback scenario has no xtables frontend' >&2
        exit 1
    }
fi

# Install a pre-existing mangle decision before OpenShield establishes its
# dispatchers. The iptables Learning observation queue must run after this rule;
# otherwise NF_ACCEPT/queue-bypass would skip host mark/QoS/policy-routing work.
if [ "$backend" = iptables ]; then
    docker exec "$client" /bin/sh -c '
        installed=0
        for command in /usr/sbin/iptables /usr/sbin/iptables-legacy /usr/sbin/iptables-nft; do
            [ -x "$command" ] || continue
            if "$command" --wait 5 -t mangle -A OUTPUT -p tcp --dport 18081 \
                -m comment --comment e2e-preexisting-mark \
                -j MARK --set-xmark 0x100/0x100 2>/dev/null; then
                "$command" --wait 5 -t filter -A OUTPUT -p tcp --dport 18081 \
                    -m mark --mark 0x100/0x100 \
                    -m comment --comment e2e-preexisting-drop -j DROP
                installed=$((installed + 1))
            fi
        done
        [ "$installed" -gt 0 ]
    '
fi

begin_stage 'install systemd-equivalent fail-closed preflight'
install_fail_closed_preflight

begin_stage 'start daemon and select backend'
start_daemon /tmp/openshield.log
wait_for_daemon_ready /tmp/openshield.log 'initial daemon'
assert_exact_unit_process_state
if [ "$backend" = nftables ]; then
    expected_backend=nftables
    expected_backend_protocol=nftables
else
    expected_backend=iptables/ip6tables
    expected_backend_protocol=iptables
fi
docker exec "$client" grep -Fq "firewall_backend=\"$expected_backend\"" \
    /tmp/openshield.log || {
        docker exec "$client" cat /tmp/openshield.log >&2 || true
        printf 'daemon did not select expected backend: %s\n' "$expected_backend" >&2
        exit 1
    }
observer_gid=$(docker exec "$client" getent group openshield | cut -d: -f3)
socket_gid=$(docker exec "$client" stat -c '%g' /run/openshield/observe.sock)
if [ -z "$observer_gid" ] || [ "$socket_gid" != "$observer_gid" ]; then
    printf '%s\n' 'observation socket does not have the openshield group' >&2
    exit 1
fi

begin_stage 'verify IPC access control'
status=$(docker exec "$client" python3 /opt/ipc_client.py status)
case "$status" in *'"mode": "learning"'*) ;; *) printf 'unexpected initial status: %s\n' "$status" >&2; exit 1 ;; esac
docker exec "$client" python3 /opt/ipc_client.py assert-runtime \
    learning "$expected_backend_protocol" nfqueue learning >/dev/null
# `docker exec --user` does not consistently initialize supplementary groups
# across Docker/OCI versions. `runuser` exercises the actual group membership
# installed inside the isolated client instead of weakening the assertion.
docker exec "$client" runuser -u observer -- python3 /opt/ipc_client.py status >/dev/null
if docker exec "$client" runuser -u outsider -- python3 /opt/ipc_client.py status >/dev/null 2>&1; then
    printf '%s\n' 'a user outside the openshield group read observation IPC' >&2
    exit 1
fi
if docker exec "$client" runuser -u observer -- python3 /opt/ipc_client.py set-mode enforcing \
    >/dev/null 2>&1; then
    printf '%s\n' 'an openshield group member reached privileged control IPC' >&2
    exit 1
fi

begin_stage 'verify automatic runtime compatibility selection'
docker exec "$client" python3 /opt/ipc_client.py set-mode enforcing >/dev/null
docker exec "$client" python3 /opt/ipc_client.py assert-runtime \
    enforcing "$expected_backend_protocol" kernel_native network_only >/dev/null
docker exec "$client" python3 /opt/ipc_client.py set-mode learning >/dev/null
docker exec "$client" python3 /opt/ipc_client.py assert-runtime \
    learning "$expected_backend_protocol" nfqueue learning >/dev/null

server_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$server")
client_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$client")
case "$server_ip:$client_ip" in
    *[!0-9.:]*) printf '%s\n' 'unsafe container address' >&2; exit 1 ;;
esac

if [ "$backend" = iptables ]; then
    begin_stage 'verify Learning preserves pre-existing mangle policy'
    if docker exec "$client" curl --fail --silent --show-error --max-time 2 \
        "http://$server_ip:18081/" >/dev/null 2>&1; then
        printf '%s\n' 'Learning NFQUEUE bypassed a pre-existing mangle decision' >&2
        exit 1
    fi
    docker exec "$client" /bin/sh -c '
        for command in /usr/sbin/iptables /usr/sbin/iptables-legacy /usr/sbin/iptables-nft; do
            [ -x "$command" ] || continue
            "$command" --wait 5 -t filter -D OUTPUT -p tcp --dport 18081 \
                -m mark --mark 0x100/0x100 \
                -m comment --comment e2e-preexisting-drop -j DROP 2>/dev/null || true
            "$command" --wait 5 -t mangle -D OUTPUT -p tcp --dport 18081 \
                -m comment --comment e2e-preexisting-mark \
                -j MARK --set-xmark 0x100/0x100 2>/dev/null || true
        done
    '
fi

begin_stage 'verify Learning admits traffic when attribution is unavailable'
learning_python_executable=$(docker exec "$client" /bin/sh -c '
    executable=$(command -v python3) || exit 1
    readlink -f "$executable"
')
case "$learning_python_executable" in
    /*) ;;
    *) printf '%s\n' 'cannot resolve the Learning test executable' >&2; exit 1 ;;
esac
case "$learning_python_executable" in
    *[!A-Za-z0-9._/-]*)
        printf '%s\n' 'unsafe Learning test executable path' >&2
        exit 1
        ;;
esac
# The child uses a real TCP socket but deliberately has more than the bounded
# 64 argv entries. Attribution must reject that observation, while Learning
# still admits the connection and must not persist an incomplete rule.
docker exec "$client" /bin/sh -c '
    server_address=$1
    server_port=$2
    set --
    argument=0
    while [ "$argument" -lt 70 ]; do
        set -- "$@" "bounded-attribution-$argument"
        argument=$((argument + 1))
    done
    exec python3 -c '\''
import socket
import sys
import time

with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5) as stream:
    stream.sendall(b"GET /learning-attribution-failure HTTP/1.0\r\nHost: e2e\r\n\r\n")
    response = stream.recv(64)
    if not response.startswith(b"HTTP/"):
        raise RuntimeError("Learning did not admit the real TCP exchange")
    # Keep the owning process and socket visible long enough for the async
    # worker to reject the deliberately oversized argv, rather than merely
    # observing a process that exited before attribution.
    time.sleep(1)
'\'' "$server_address" "$server_port" "$@"
' openshield-learning-attribution "$server_ip" 18081
# A packet verdict intentionally precedes the asynchronous durable learning
# commit. Leave a bounded interval in which an erroneous partial observation
# would become visible before asserting its absence.
docker exec "$client" sleep 1
docker exec "$client" python3 /opt/ipc_client.py assert-no-learned \
    "$learning_python_executable" "$server_ip" 18081 tcp

begin_stage 'verify Learning packet telemetry'
if [ "$backend" = iptables ]; then
    if docker exec "$client" /usr/sbin/iptables-legacy-save -t mangle 2>/dev/null \
        | grep -Fq -- '-A OPENSHIELD_OBSERVE'; then
        learning_counter_save=/usr/sbin/iptables-legacy-save
    else
        learning_counter_save=/usr/sbin/iptables-save
    fi
    docker exec "$client" "$learning_counter_save" -c -t mangle \
        | grep -Eq -- '^\[[1-9][0-9]*:[0-9]+\] -A OPENSHIELD_OBSERVE .*--comment "?openshield:learned_out"? .*--queue-num 1338' || {
        printf '%s\n' 'iptables Learning observation counter did not advance' >&2
        exit 1
    }
else
    docker exec "$client" nft list counter inet openshield learned_out \
        | grep -Eq -- 'packets [1-9][0-9]* bytes [0-9]+' || {
        printf '%s\n' 'nftables Learning observation counter did not advance' >&2
        exit 1
    }
fi

begin_stage 'verify application-bound TCP conntrack-hybrid path'
docker exec --detach "$server" python3 -c '
import socket
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("0.0.0.0", 18083))
listener.listen(1)
open("/tmp/openshield-l2-server-ready", "w", encoding="ascii").close()
connection, _ = listener.accept()
with connection:
    while True:
        data = connection.recv(4096)
        if not data:
            break
        connection.sendall(data)
'
wait_for_marker "$server" /tmp/openshield-l2-server-ready 'TCP echo server'
l2_tcp_executable=$learning_python_executable
case "$l2_tcp_executable" in
    /*) ;;
    *) printf '%s\n' 'cannot resolve the TCP session executable' >&2; exit 1 ;;
esac
case "$l2_tcp_executable" in
    *[!A-Za-z0-9._/-]*)
        printf '%s\n' 'unsafe TCP session executable path' >&2
        exit 1
        ;;
esac
docker exec --detach "$client" /bin/sh -c '
    server_address=$1
    server_port=$2
    status_file=/tmp/openshield-l2-client.status
    temporary_status="${status_file}.tmp"
    if python3 /opt/tcp-session.py "$server_address" "$server_port" \
        >/tmp/openshield-l2-client.log 2>&1; then
        client_status=0
    else
        client_status=$?
    fi
    printf "%s\n" "$client_status" >"$temporary_status"
    mv -f "$temporary_status" "$status_file"
' openshield-l2-session "$server_ip" 18083
wait_for_marker "$client" /tmp/openshield-l2-learning-ready \
    'application-bound TCP session in Learning'
attempt=0
while [ "$attempt" -lt 50 ]; do
    if docker exec "$client" python3 /opt/ipc_client.py assert-learned \
        "$l2_tcp_executable" "$server_ip" 18083 tcp; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
if [ "$attempt" -ge 50 ]; then
    docker exec "$client" cat /tmp/openshield-l2-client.log >&2 || true
    exit 1
fi
docker exec "$client" python3 /opt/ipc_client.py assert-template \
    "$l2_tcp_executable" disabled

docker exec "$client" python3 /opt/ipc_client.py set-mode enforcing >/dev/null
docker exec "$client" python3 /opt/ipc_client.py assert-runtime \
    enforcing "$expected_backend_protocol" conntrack_hybrid application_tcp >/dev/null
docker exec "$client" touch /tmp/openshield-l2-enforcing-first
wait_for_marker "$client" /tmp/openshield-l2-enforcing-first-ready \
    'first re-attributed TCP exchange in Enforcing'

# Once the current generation has been attached to the established TCP flow,
# the next exchange must remain entirely in the conntrack fast path. Pausing
# the daemon makes a hidden second NFQUEUE attribution impossible while the
# real socket remains connected.
daemon_pid=$(docker exec "$client" cat "$daemon_pid_file")
case "$daemon_pid" in ''|*[!0-9]*) printf '%s\n' 'invalid daemon pid' >&2; exit 1 ;; esac
docker exec "$client" /bin/sh -c 'kill -STOP "$1"' \
    openshield-daemon-pause "$daemon_pid"
l2_fast_path_passed=true
if ! docker exec "$client" touch /tmp/openshield-l2-enforcing-fast \
    || ! wait_for_marker "$client" /tmp/openshield-l2-enforcing-fast-ready \
        'established TCP conntrack fast-path exchange'; then
    l2_fast_path_passed=false
fi
docker exec "$client" /bin/sh -c 'kill -CONT "$1"' \
    openshield-daemon-resume "$daemon_pid"
if [ "$l2_fast_path_passed" != true ]; then
    docker exec "$client" cat /tmp/openshield-l2-client.log >&2 || true
    printf '%s\n' 'established TCP exchange required the paused NFQUEUE worker' >&2
    exit 1
fi
wait_for_marker "$client" /tmp/openshield-l2-client.status \
    'application-bound TCP session exit'
l2_client_status=$(docker exec "$client" cat /tmp/openshield-l2-client.status)
[ "$l2_client_status" = 0 ] || {
    docker exec "$client" cat /tmp/openshield-l2-client.log >&2 || true
    printf 'application-bound TCP session exited with status %s\n' \
        "$l2_client_status" >&2
    exit 1
}
docker exec "$client" python3 /opt/ipc_client.py assert-runtime \
    enforcing "$expected_backend_protocol" conntrack_hybrid application_tcp >/dev/null

docker exec "$client" python3 /opt/ipc_client.py set-mode learning >/dev/null
docker exec "$client" python3 /opt/ipc_client.py assert-runtime \
    learning "$expected_backend_protocol" nfqueue learning >/dev/null

begin_stage 'verify transparent Learning with concurrent real sockets'
docker exec --detach "$server" python3 /opt/learning-sockets.py serve 18084 18085
wait_for_marker "$server" /tmp/openshield-learning-sockets-18084-18085.ready \
    'transparent Learning TCP/UDP server'
start_observable_learning_hold 18084 18085
# Keep one TCP connection and one connected UDP flow alive while polling. This
# makes asynchronous /proc attribution deterministic instead of relying on a
# short-lived client process remaining visible after its packet was admitted.
for learned_port in 18084 18085; do
    case "$learned_port" in
        18084) learned_protocol=tcp ;;
        18085) learned_protocol=udp ;;
    esac
    attempt=0
    while [ "$attempt" -lt 50 ]; do
        if docker exec "$client" python3 /opt/ipc_client.py assert-learned \
            "$learning_python_executable" "$server_ip" "$learned_port" \
            "$learned_protocol" >/dev/null 2>&1; then
            break
        fi
        attempt=$((attempt + 1))
        sleep 0.1
    done
    [ "$attempt" -lt 50 ] || {
        printf 'transparent Learning did not persist the %s endpoint\n' \
            "$learned_protocol" >&2
        exit 1
    }
done
docker exec "$client" python3 /opt/learning-sockets.py client \
    "$server_ip" 18084 18085 >/dev/null
# The second workload adds sequential NEW TCP connections, concurrent
# persistent TCP sockets with repeated exchanges, and persistent plus parallel
# DNS-like UDP request/reply flows.
finish_observable_learning_hold

begin_stage 'verify Learning has no synchronous attribution head-of-line blocking'
docker exec --detach "$server" python3 /opt/learning-sockets.py serve 18086 18087
wait_for_marker "$server" /tmp/openshield-learning-sockets-18086-18087.ready \
    'Learning burst TCP/UDP server'
# A same-UID process with many shared descriptors and threads makes bounded
# procfs attribution deliberately expensive without touching the host. The
# Learning packet consumer must return ACCEPT before that asynchronous work;
# the previous synchronous design accumulates per-batch deadlines and violates
# this real-socket burst's bound.
docker exec --detach "$client" /bin/sh -c '
    status_file=/tmp/openshield-procfs-pressure.status
    python3 /opt/learning-sockets.py procfs-pressure \
        128 640 /tmp/openshield-procfs-pressure.ready \
        >/tmp/openshield-procfs-pressure.log 2>&1 &
    child=$!
    printf "%s\n" "$child" >/tmp/openshield-procfs-pressure.pid
    if wait "$child"; then status=0; else status=$?; fi
    printf "%s\n" "$status" >"${status_file}.tmp"
    mv -f "${status_file}.tmp" "$status_file"
'
wait_for_marker "$client" /tmp/openshield-procfs-pressure.ready \
    'bounded procfs-pressure fixture'
procfs_pressure_pid=$(docker exec "$client" cat /tmp/openshield-procfs-pressure.pid)
case "$procfs_pressure_pid" in
    ''|*[!0-9]*) printf '%s\n' 'invalid procfs-pressure pid' >&2; exit 1 ;;
esac
burst_passed=true
if ! docker exec "$client" python3 /opt/learning-sockets.py burst \
    "$server_ip" 18086 18087; then
    burst_passed=false
fi
docker exec "$client" /bin/sh -c 'kill -TERM "$1"' \
    openshield-procfs-pressure-stop "$procfs_pressure_pid"
wait_for_marker "$client" /tmp/openshield-procfs-pressure.status \
    'bounded procfs-pressure fixture exit'
[ "$burst_passed" = true ] || {
    docker exec "$client" cat /tmp/openshield-procfs-pressure.log >&2 || true
    printf '%s\n' 'Learning burst was delayed or dropped by asynchronous attribution' >&2
    exit 1
}
# Invalidate any deliberately saturated observation backlog before testing a
# particular durable-write failure. Stale-generation async work must be
# discarded instead of mutating the next Learning generation.
docker exec "$client" python3 /opt/ipc_client.py set-mode enforcing >/dev/null
docker exec "$client" python3 /opt/ipc_client.py set-mode learning >/dev/null
docker exec "$client" python3 /opt/ipc_client.py assert-runtime \
    learning "$expected_backend_protocol" nfqueue learning >/dev/null

begin_stage 'verify transparent Learning while persistence is paused'
docker exec --detach "$server" python3 /opt/learning-sockets.py serve 18088 18089
wait_for_marker "$server" /tmp/openshield-learning-sockets-18088-18089.ready \
    'persistence-pause TCP/UDP server'
state_directory_mode=$(docker exec "$client" stat -c '%a' /var/lib/openshield)
case "$state_directory_mode" in
    [0-7][0-7][0-7]) ;;
    *) printf '%s\n' 'unsafe state-directory mode from container' >&2; exit 1 ;;
esac
# The daemon runs with the packaged capability set and lacks DAC_OVERRIDE.
# Removing owner-write permission therefore makes one otherwise safe atomic
# learning save fail without touching the host filesystem or firewall.
docker exec "$client" chmod 0500 /var/lib/openshield
start_observable_learning_hold 18088 18089
attempt=0
while [ "$attempt" -lt 50 ]; do
    if docker exec "$client" grep -Fq \
        'automatic learning paused after a recoverable persistence failure' \
        /tmp/openshield.log; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
docker exec "$client" chmod "$state_directory_mode" /var/lib/openshield
[ "$attempt" -lt 50 ] || {
    printf '%s\n' 'failed learning save did not enter the documented persistence pause' >&2
    exit 1
}
docker exec "$client" sleep 1
docker exec "$client" python3 /opt/ipc_client.py assert-no-learned \
    "$learning_python_executable" "$server_ip" 18088 tcp
docker exec "$client" python3 /opt/ipc_client.py assert-no-learned \
    "$learning_python_executable" "$server_ip" 18089 udp
# The hold repeatedly completed framed TCP keep-alives and DNS-like UDP
# request/reply exchanges before and after persistence entered its paused state.
finish_observable_learning_hold
# A successful privileged transition explicitly resumes automatic learning for
# the following scenarios.
docker exec "$client" python3 /opt/ipc_client.py set-mode enforcing >/dev/null
docker exec "$client" python3 /opt/ipc_client.py set-mode learning >/dev/null
docker exec "$client" python3 /opt/ipc_client.py assert-runtime \
    learning "$expected_backend_protocol" nfqueue learning >/dev/null

begin_stage 'learn mixed outbound TCP and UDP applications'
docker exec --detach "$server" python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 18082))
open("/tmp/openshield-udp-ready", "w", encoding="ascii").close()
while True:
    data, address = s.recvfrom(4096)
    s.sendto(data, address)
'
wait_for_marker "$server" /tmp/openshield-udp-ready 'UDP echo server'
if [ -n "$native_client_source" ]; then
    tcp_executable=/opt/openshield-e2e-client
    udp_executable=/opt/openshield-e2e-client
else
    udp_command=$(docker exec "$client" /bin/sh -c 'command -v nc')
    tcp_executable=$learning_python_executable
    udp_executable=$(docker exec "$client" readlink -f "$udp_command")
fi
for executable in "$tcp_executable" "$udp_executable"; do
    case "$executable" in
        /*) ;;
        *) printf '%s\n' 'cannot resolve an E2E traffic client executable' >&2; exit 1 ;;
    esac
    case "$executable" in
        *[!A-Za-z0-9._/-]*)
            printf '%s\n' 'unsafe E2E traffic client executable path' >&2
            exit 1
            ;;
    esac
done
udp_payload=openshield-udp-e2e

run_tcp_client() {
    timeout_seconds=$1
    if [ -n "$native_client_source" ]; then
        docker exec "$client" "$tcp_executable" tcp \
            "$server_ip" 18081 "$((timeout_seconds * 1000))"
    else
        docker exec "$client" python3 /opt/learning-sockets.py http \
            "$server_ip" 18081 / "$((timeout_seconds * 1000))" 1000
    fi
}

run_udp_client() {
    if [ -n "$native_client_source" ]; then
        docker exec "$client" "$udp_executable" udp \
            "$server_ip" 18082 19000 2000 "$udp_payload"
    else
        docker exec "$client" /bin/sh -c '
            payload=$1
            executable=$2
            source_port=$3
            server_address=$4
            server_port=$5
            # Keep stdin open briefly after the datagram is written.  Nmap
            # Ncat otherwise exits on EOF before the daemon can attribute the
            # short-lived UDP socket and before the echo reply is received.
            { printf "%s" "$payload"; sleep 1; } \
                | "$executable" -u -w 2 -p "$source_port" "$server_address" "$server_port"
        ' openshield-udp-client \
            "$udp_payload" "$udp_executable" 19000 "$server_ip" 18082
    fi
}

run_tcp_client_variant() {
    timeout_seconds=$1
    if [ -n "$native_client_source" ]; then
        docker exec "$client" "$tcp_executable" tcp \
            "$server_ip" 18081 "$((timeout_seconds * 1000))"
    else
        docker exec "$client" python3 /opt/learning-sockets.py http \
            "$server_ip" 18081 '/?openshield-template=variant' \
            "$((timeout_seconds * 1000))" 1000
    fi
}

run_tcp_client 5
if ! udp_reply=$(run_udp_client); then
    printf '%s\n' 'UDP echo command failed during Learning' >&2
    exit 1
fi
[ "$udp_reply" = "$udp_payload" ] || {
    printf '%s\n' 'UDP echo failed during Learning' >&2
    exit 1
}

attempt=0
while [ "$attempt" -lt 50 ]; do
    if docker exec "$client" python3 /opt/ipc_client.py assert-learned \
        "$tcp_executable" "$server_ip" 18081 tcp; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
[ "$attempt" -lt 50 ] || exit 1
attempt=0
while [ "$attempt" -lt 50 ]; do
    if docker exec "$client" python3 /opt/ipc_client.py assert-learned \
        "$udp_executable" "$server_ip" 18082 udp; then
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
[ "$attempt" -lt 50 ] || exit 1
docker exec "$client" python3 /opt/ipc_client.py assert-template \
    "$tcp_executable" disabled
docker exec "$client" python3 /opt/ipc_client.py assert-template \
    "$udp_executable" disabled

begin_stage 'enforce learned outbound rules'
docker exec "$client" python3 /opt/ipc_client.py set-mode enforcing >/dev/null
docker exec "$client" python3 /opt/ipc_client.py assert-runtime \
    enforcing "$expected_backend_protocol" nfqueue application_per_packet >/dev/null
run_tcp_client 5
if ! udp_reply=$(run_udp_client); then
    printf '%s\n' 'learned UDP command failed during Enforcing' >&2
    exit 1
fi
[ "$udp_reply" = "$udp_payload" ] || {
    printf '%s\n' 'learned UDP application did not receive its Enforcing reply' >&2
    exit 1
}

begin_stage 'verify disabled and enabled application-group template'
if run_tcp_client_variant 2 >/dev/null 2>&1; then
    printf '%s\n' 'a disabled application template admitted unmatched arguments' >&2
    exit 1
fi
docker exec "$client" python3 /opt/ipc_client.py enable-template \
    "$tcp_executable" >/dev/null
docker exec "$client" python3 /opt/ipc_client.py assert-template \
    "$tcp_executable" enabled
run_tcp_client_variant 5 || {
    printf '%s\n' 'an enabled application template did not admit unmatched arguments' >&2
    exit 1
}
docker exec "$client" python3 /opt/ipc_client.py disable-template \
    "$tcp_executable" >/dev/null
docker exec "$client" python3 /opt/ipc_client.py assert-template \
    "$tcp_executable" disabled

begin_stage 'verify outbound Drop, Reject, and independent enabled state'
action_test_command=$(docker exec "$client" /bin/sh -c 'command -v curl')
action_test_executable=$(docker exec "$client" readlink -f "$action_test_command")
case "$action_test_executable" in
    /*) ;;
    *) printf '%s\n' 'cannot resolve the action test executable' >&2; exit 1 ;;
esac
assert_learning_action() {
    action_description=$1
    expected_status=$2
    docker exec "$client" python3 /opt/ipc_client.py set-mode learning >/dev/null
    docker exec "$client" python3 /opt/ipc_client.py assert-runtime \
        learning "$expected_backend_protocol" nfqueue learning >/dev/null
    set +e
    docker exec "$client" "$action_test_executable" \
        --fail --silent --show-error --max-time 2 \
        "http://$server_ip:18081/" >/dev/null 2>&1
    learning_action_status=$?
    set -e
    if [ "$learning_action_status" -ne "$expected_status" ]; then
        printf 'Learning %s returned status %s instead of %s\n' \
            "$action_description" "$learning_action_status" \
            "$expected_status" >&2
        exit 1
    fi
    docker exec "$client" python3 /opt/ipc_client.py set-mode enforcing >/dev/null
    docker exec "$client" python3 /opt/ipc_client.py assert-runtime \
        enforcing "$expected_backend_protocol" nfqueue application_per_packet >/dev/null
}
# This broad kernel-only allow deliberately overlaps every application rule
# below. Application Drop/Reject must still win after userspace attribution.
docker exec "$client" python3 /opt/ipc_client.py create-network-tcp-rule \
    openshield-e2e-network-accept "$server_ip" 18081 accept >/dev/null
docker exec "$client" python3 /opt/ipc_client.py create-app-tcp-rule \
    openshield-e2e-app-accept "$action_test_executable" "$server_ip" 18081 accept >/dev/null
docker exec "$client" "$action_test_executable" \
    --fail --silent --show-error --max-time 5 "http://$server_ip:18081/" >/dev/null
docker exec "$client" python3 /opt/ipc_client.py create-network-tcp-rule \
    openshield-e2e-network-drop "$server_ip" 18081 drop >/dev/null
# Explicit enabled Drop and Reject actions remain active in Learning. Ordinary
# unmatched outbound traffic is the transparent allow-and-observe path tested
# above; a network-only deny is enforced directly by the kernel backend.
assert_learning_action 'network Drop' 28
set +e
docker exec "$client" "$action_test_executable" \
    --fail --silent --show-error --max-time 2 "http://$server_ip:18081/" >/dev/null 2>&1
network_drop_status=$?
set -e
if [ "$network_drop_status" -ne 28 ]; then
    printf 'network Drop overlapping application Accept returned status %s instead of a silent timeout\n' \
        "$network_drop_status" >&2
    exit 1
fi
docker exec "$client" python3 /opt/ipc_client.py set-named-rule-enabled \
    openshield-e2e-network-drop disabled >/dev/null
docker exec "$client" python3 /opt/ipc_client.py create-network-tcp-rule \
    openshield-e2e-network-reject "$server_ip" 18081 reject >/dev/null
assert_learning_action 'network Reject' 7
set +e
docker exec "$client" "$action_test_executable" \
    --fail --silent --show-error --max-time 2 "http://$server_ip:18081/" >/dev/null 2>&1
network_reject_status=$?
set -e
if [ "$network_reject_status" -ne 7 ]; then
    printf 'network Reject overlapping application Accept returned status %s instead of prompt refusal\n' \
        "$network_reject_status" >&2
    exit 1
fi
docker exec "$client" python3 /opt/ipc_client.py set-named-rule-enabled \
    openshield-e2e-network-reject disabled >/dev/null
docker exec "$client" python3 /opt/ipc_client.py create-app-tcp-rule \
    openshield-e2e-app-drop "$action_test_executable" "$server_ip" 18081 drop >/dev/null
# Application denies use the fail-closed enforcing queue even in Learning;
# the observational queue remains immediate and cannot override the decision.
assert_learning_action 'application Drop' 28
set +e
docker exec "$client" "$action_test_executable" \
    --fail --silent --show-error --max-time 2 "http://$server_ip:18081/" >/dev/null 2>&1
drop_status=$?
set -e
if [ "$drop_status" -ne 28 ]; then
    printf 'application Drop returned status %s instead of a silent timeout\n' \
        "$drop_status" >&2
    exit 1
fi
docker exec "$client" python3 /opt/ipc_client.py set-named-rule-enabled \
    openshield-e2e-app-drop disabled >/dev/null
docker exec "$client" "$action_test_executable" \
    --fail --silent --show-error --max-time 5 "http://$server_ip:18081/" >/dev/null || {
    printf '%s\n' 'a disabled application Drop rule remained active' >&2
    exit 1
}
docker exec "$client" python3 /opt/ipc_client.py create-app-tcp-rule \
    openshield-e2e-app-reject "$action_test_executable" "$server_ip" 18081 reject >/dev/null
assert_learning_action 'application Reject' 7
set +e
docker exec "$client" "$action_test_executable" \
    --fail --silent --show-error --max-time 2 "http://$server_ip:18081/" >/dev/null 2>&1
reject_status=$?
set -e
if [ "$reject_status" -ne 7 ]; then
    printf 'application Reject returned status %s instead of prompt refusal\n' \
        "$reject_status" >&2
    exit 1
fi
docker exec "$client" python3 /opt/ipc_client.py set-named-rule-enabled \
    openshield-e2e-app-reject disabled >/dev/null
docker exec "$client" "$action_test_executable" \
    --fail --silent --show-error --max-time 5 "http://$server_ip:18081/" >/dev/null || {
    printf '%s\n' 'a disabled application Reject rule remained active' >&2
    exit 1
}
docker exec "$client" python3 /opt/ipc_client.py set-named-rule-enabled \
    openshield-e2e-network-accept disabled >/dev/null

# An OpenShield allow must not bypass a later DROP owned by another firewall.
begin_stage 'verify downstream firewall DROP precedence'
if [ "$backend" = iptables ]; then
    # Each policy mutation replaces the owned chains and resets their
    # counters. Exercise both application paths under the final policy before
    # asserting that NF_REPEAT reached the authorization chains.
    run_tcp_client 5 >/dev/null
    udp_reply=$(run_udp_client)
    [ "$udp_reply" = "$udp_payload" ] || {
        printf '%s\n' 'UDP echo failed before NF_REPEAT counter inspection' >&2
        exit 1
    }
    if docker exec "$client" /usr/sbin/iptables-legacy-save -t filter 2>/dev/null \
        | grep -Fq -- '-A OUTPUT -j OPENSHIELD_OUT'; then
        iptables_command=/usr/sbin/iptables-legacy
        iptables_save=/usr/sbin/iptables-legacy-save
    else
        iptables_command=/usr/sbin/iptables
        iptables_save=/usr/sbin/iptables-save
    fi
    docker exec "$client" "$iptables_save" -c -t mangle \
        | grep -m1 -E -- ' -A OUTPUT ' \
        | grep -Eq -- '^\[[0-9]+:[0-9]+\] -A OUTPUT -j OPENSHIELD_MARK$' || {
        printf '%s\n' 'OpenShield mangle sanitizer is not the first OUTPUT rule' >&2
        exit 1
    }
    docker exec "$client" "$iptables_save" -c -t mangle \
        | grep -E -- ' -A OUTPUT ' \
        | tail -n1 \
        | grep -Eq -- '^\[[0-9]+:[0-9]+\] -A OUTPUT -j OPENSHIELD_OBSERVE$' || {
        printf '%s\n' 'OpenShield Learning observer is not the last mangle OUTPUT rule' >&2
        exit 1
    }
    docker exec "$client" "$iptables_save" -c -t filter \
        | grep -Eq -- '^\[[1-9][0-9]*:[0-9]+\] -A OPENSHIELD_APP_TCP -j CONNMARK ' || {
        printf '%s\n' 'NF_REPEAT did not reach the post-queue TCP authorization chain' >&2
        exit 1
    }
    docker exec "$client" "$iptables_save" -c -t filter \
        | grep -Eq -- '^\[[1-9][0-9]*:[0-9]+\] -A OPENSHIELD_APP_PKT -j CONNMARK ' || {
        printf '%s\n' 'NF_REPEAT did not reach the post-queue UDP authorization chain' >&2
        exit 1
    }
    docker exec "$client" "$iptables_command" --wait 5 -A OUTPUT -p tcp -d "$server_ip" \
        --dport 18081 -m comment --comment openshield-e2e-downstream -j DROP
    docker exec "$client" "$iptables_command" --wait 5 -A OUTPUT -p udp -d "$server_ip" \
        --dport 18082 -m comment --comment openshield-e2e-downstream -j DROP
else
    docker exec "$client" nft add table inet openshield_e2e_downstream
    docker exec "$client" nft add chain inet openshield_e2e_downstream output \
        '{ type filter hook output priority 10; policy accept; }'
    docker exec "$client" nft add rule inet openshield_e2e_downstream output \
        ip daddr "$server_ip" tcp dport 18081 drop
    docker exec "$client" nft add rule inet openshield_e2e_downstream output \
        ip daddr "$server_ip" udp dport 18082 drop
fi
if run_tcp_client 2 >/dev/null 2>&1; then
    printf '%s\n' 'an OpenShield allow bypassed a downstream firewall DROP' >&2
    exit 1
fi
udp_reply=$(run_udp_client || true)
if [ "$udp_reply" = "$udp_payload" ]; then
    printf '%s\n' 'an OpenShield UDP allow bypassed a downstream firewall DROP' >&2
    exit 1
fi
if [ "$backend" = iptables ]; then
    docker exec "$client" "$iptables_command" --wait 5 -D OUTPUT -p tcp -d "$server_ip" \
        --dport 18081 -m comment --comment openshield-e2e-downstream -j DROP
    docker exec "$client" "$iptables_command" --wait 5 -D OUTPUT -p udp -d "$server_ip" \
        --dport 18082 -m comment --comment openshield-e2e-downstream -j DROP
else
    docker exec "$client" nft delete table inet openshield_e2e_downstream
fi
run_tcp_client 5
if ! udp_reply=$(run_udp_client); then
    printf '%s\n' 'UDP echo command failed after downstream DROP removal' >&2
    exit 1
fi
[ "$udp_reply" = "$udp_payload" ] || {
    printf '%s\n' 'UDP echo did not recover after downstream DROP removal' >&2
    exit 1
}

# Reuse the exact UDP conntrack tuple from another executable. The outbound
# reset must remove the previous nc generation mark before Python is denied;
# otherwise the echo reply would expose a stale-connmark authorization bypass.
begin_stage 'verify application and connmark isolation'
if docker exec "$client" python3 -c \
    "import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 19000))
s.settimeout(2)
s.sendto(b'$udp_payload', ('$server_ip', 18082))
assert s.recvfrom(4096)[0] == b'$udp_payload'" \
    >/dev/null 2>&1; then
    printf '%s\n' 'a different executable inherited the learned UDP connmark' >&2
    exit 1
fi

if docker exec "$client" python3 -c \
    "import urllib.request; urllib.request.urlopen('http://$server_ip:18081/', timeout=2).read()" \
    >/dev/null 2>&1; then
    printf '%s\n' 'a different executable bypassed the learned application rule' >&2
    exit 1
fi

begin_stage 'verify inbound default deny and explicit allow'
docker exec --detach "$client" python3 -c '
from http.server import HTTPServer, SimpleHTTPRequestHandler
server = HTTPServer(("0.0.0.0", 18080), SimpleHTTPRequestHandler)
open("/tmp/openshield-http-ready", "w", encoding="ascii").close()
server.serve_forever()
'
wait_for_marker "$client" /tmp/openshield-http-ready 'inbound HTTP server'
if docker exec "$server" python3 -c \
    "import urllib.request; urllib.request.urlopen('http://$client_ip:18080/', timeout=2).read()" \
    >/dev/null 2>&1; then
    printf '%s\n' 'inbound traffic passed without an allow rule' >&2
    exit 1
fi
docker exec "$client" python3 /opt/ipc_client.py allow-inbound-tcp 18080 >/dev/null
docker exec "$server" python3 -c \
    "import urllib.request; urllib.request.urlopen('http://$client_ip:18080/', timeout=5).read()" \
    >/dev/null || {
        printf '%s\n' 'explicit inbound allow rule did not admit TCP traffic' >&2
        exit 1
    }

begin_stage 'graceful shutdown and fail-closed policy'
daemon_pid=$(docker exec "$client" cat "$daemon_pid_file")
case "$daemon_pid" in ''|*[!0-9]*) printf '%s\n' 'invalid daemon pid' >&2; exit 1 ;; esac
docker exec "$client" /bin/sh -c 'kill -TERM "$1"' \
    openshield-daemon-stop "$daemon_pid"
wait_for_daemon_exit /tmp/openshield.log 'initial daemon'
if docker exec "$client" test -S /run/openshield/control.sock; then
    printf '%s\n' 'daemon left the control socket after process exit' >&2
    exit 1
fi
docker exec "$client" python3 -c \
    'import json; assert json.load(open("/var/lib/openshield/state.json", encoding="utf-8"))["mode"] == "enforcing"'
if run_tcp_client 2 >/dev/null 2>&1; then
    printf '%s\n' 'graceful shutdown did not leave kernel BlockAll active' >&2
    exit 1
fi

begin_stage 'restart with persisted policy'
start_daemon /tmp/openshield-restart.log
wait_for_daemon_ready /tmp/openshield-restart.log 'restarted daemon'
assert_exact_unit_process_state
status=$(docker exec "$client" python3 /opt/ipc_client.py status)
case "$status" in *'"mode": "enforcing"'*) ;; *) printf 'unexpected restart status: %s\n' "$status" >&2; exit 1 ;; esac
run_tcp_client 5 || {
    printf '%s\n' 'persisted outbound rule did not recover after daemon restart' >&2
    exit 1
}
daemon_pid=$(docker exec "$client" cat "$daemon_pid_file")
case "$daemon_pid" in ''|*[!0-9]*) printf '%s\n' 'invalid restarted daemon pid' >&2; exit 1 ;; esac
docker exec "$client" /bin/sh -c 'kill -TERM "$1"' \
    openshield-daemon-stop "$daemon_pid"
wait_for_daemon_exit /tmp/openshield-restart.log 'restarted daemon'
if docker exec "$client" test -S /run/openshield/control.sock; then
    printf '%s\n' 'restarted daemon left the control socket after process exit' >&2
    exit 1
fi

printf 'PASS server Learning allow -> templates -> TCP L2 -> UDP/TCP L1 -> inbound allow -> restart (%s)\n' "$backend"
