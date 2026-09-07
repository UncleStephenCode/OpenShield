#!/bin/sh
set -eu

usage() {
    printf 'usage: %s {nftables|iptables} {bookworm|tumbleweed} ABSOLUTE_RPM\n' "$0" >&2
}

[ "$#" -eq 3 ] || { usage; exit 2; }
backend=$1
distribution=$2
rpm_path=$3
diagnostic_loopback=${PROXY_E2E_ALLOW_LOOPBACK_RULE:-false}
network_accept=${PROXY_NETWORK_ACCEPT:-false}
browser_identity=${PROXY_BROWSER_IDENTITY:-false}
enforcing_identity=${PROXY_ENFORCING_IDENTITY:-false}
noise_processes=${PROXY_NOISE_PROCESSES:-16}
noise_threads=${PROXY_NOISE_THREADS:-32}
noise_file_descriptors=${PROXY_NOISE_FDS:-256}
case "$backend" in nftables|iptables) ;; *) usage; exit 2 ;; esac
case "$distribution" in bookworm|tumbleweed) ;; *) usage; exit 2 ;; esac
case "$diagnostic_loopback" in true|false) ;; *) printf '%s\n' 'invalid PROXY_E2E_ALLOW_LOOPBACK_RULE' >&2; exit 2 ;; esac
case "$network_accept" in true|false) ;; *) printf '%s\n' 'invalid PROXY_NETWORK_ACCEPT' >&2; exit 2 ;; esac
case "$browser_identity" in true|false) ;; *) printf '%s\n' 'invalid PROXY_BROWSER_IDENTITY' >&2; exit 2 ;; esac
case "$enforcing_identity" in true|false) ;; *) printf '%s\n' 'invalid PROXY_ENFORCING_IDENTITY' >&2; exit 2 ;; esac
if [ "$enforcing_identity" = true ]; then
    browser_identity=true
fi
case "$noise_processes:$noise_threads:$noise_file_descriptors" in
    *[!0-9:]*|0:*|*:0:*|*:*:0) printf '%s\n' 'invalid procfs noise dimensions' >&2; exit 2 ;;
esac
[ "$noise_processes" -le 64 ] && [ "$noise_threads" -le 64 ] \
    && [ "$noise_file_descriptors" -le 512 ] \
    && [ $((noise_processes * noise_threads)) -le 2048 ] \
    && [ $((noise_processes * noise_file_descriptors)) -le 32768 ] || {
        printf '%s\n' 'procfs noise exceeds its safety bound' >&2
        exit 2
    }
case "$rpm_path" in /*) ;; *) usage; exit 2 ;; esac
[ -f "$rpm_path" ] && [ ! -L "$rpm_path" ] || {
    printf '%s\n' 'RPM must be a regular non-symlink file' >&2
    exit 2
}

bookworm_image='debian:12@sha256:6ebd97fa83deb272194a2cf015b3d26a4d538e9ad3a7a79d544c8af5b0a01443'
tumbleweed_image='opensuse/tumbleweed@sha256:8f6397b7b7ebc78e111d9a13fb2b157664ad5524e1f3b908deb45938b3095045'
peer_image='python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285'
case "$distribution" in
    bookworm) client_image=$bookworm_image ;;
    tumbleweed) client_image=$tumbleweed_image ;;
esac

for command in docker rpm2cpio cpio file readelf sha256sum; do
    command -v "$command" >/dev/null 2>&1 || {
        printf 'required command is unavailable: %s\n' "$command" >&2
        exit 2
    }
done
case "${DOCKER_HOST:-}" in
    ''|unix:///*) ;;
    *) printf '%s\n' 'refusing a non-local DOCKER_HOST override' >&2; exit 1 ;;
esac
docker_host=$(docker context inspect --format '{{(index .Endpoints "docker").Host}}' 2>/dev/null) || {
    printf '%s\n' 'cannot inspect the active Docker context' >&2
    exit 1
}
case "$docker_host" in unix:///*) ;; *) printf '%s\n' 'refusing non-local Docker endpoint' >&2; exit 1 ;; esac

script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
repository_directory=$(CDPATH='' cd -- "$script_directory/../.." && pwd -P)
expected_version=${EXPECTED_VERSION:-}
if [ -z "$expected_version" ]; then
    expected_version=$(sed -n 's/^version = "\([0-9][0-9A-Za-z.+~-]*\)"$/\1/p' \
        "$repository_directory/Cargo.toml")
fi
case "$expected_version" in
    ''|*[!0-9A-Za-z.+~-]*) printf '%s\n' 'unsafe or missing expected release version' >&2; exit 2 ;;
esac
temporary_directory=$(mktemp -d /tmp/openshield-proxy-e2e.XXXXXX)
evidence_directory=$(mktemp -d /tmp/openshield-proxy-evidence.XXXXXX)
run_token=${temporary_directory##*/}
resource_label="org.openshield.proxy-e2e.run=$run_token"
network_name="openshield-proxy-$run_token"
client_name="openshield-proxy-client-$run_token"
peer_name="openshield-proxy-peer-$run_token"
network_id=
client_id=
peer_id=
stage=initialization
privoxy_pid=
privoxy_uid=
browser_learning_elapsed_ms=not-measured
browser_enforcing_elapsed_ms=not-measured
browser_peer_network_rule_name=

begin_stage() {
    stage=$1
    printf '==> Privoxy Learning E2E (%s/%s): %s\n' "$distribution" "$backend" "$stage"
}

wait_for_file() {
    container=$1
    path=$2
    description=$3
    if docker exec "$container" /bin/sh -c '
        path=$1
        attempt=0
        while [ "$attempt" -lt 600 ]; do
            [ ! -f "$path" ] || exit 0
            attempt=$((attempt + 1))
            sleep 0.1
        done
        exit 1
    ' openshield-proxy-wait "$path"; then
        return 0
    fi
    printf '%s did not complete within 60 seconds\n' "$description" >&2
    return 1
}

wait_for_identity_ready() {
    container=$1
    ready_path=$2
    status_path=$3
    log_path=$4
    description=$5
    if docker exec "$container" /bin/sh -c '
        ready=$1
        status=$2
        attempt=0
        while [ "$attempt" -lt 600 ]; do
            [ ! -f "$ready" ] || exit 0
            [ ! -f "$status" ] || exit 2
            attempt=$((attempt + 1))
            sleep 0.1
        done
        exit 1
    ' openshield-proxy-identity-wait "$ready_path" "$status_path"; then
        return 0
    fi
    docker exec "$container" cat "$log_path" >&2 || true
    printf '%s did not establish its Enforcing sockets\n' "$description" >&2
    return 1
}

wait_for_privoxy_rule() {
    description=$1
    if docker exec "$client_id" /bin/sh -c '
        executable=$1
        address=$2
        attempt=0
        while [ "$attempt" -lt 200 ]; do
            python3 /opt/ipc_client.py assert-learned "$executable" "$address" 18081 tcp \
                >/dev/null 2>&1 && exit 0
            attempt=$((attempt + 1)); sleep 0.05
        done
        exit 1
    ' openshield-privoxy-rule-wait "$privoxy_binary" "$peer_ip"; then
        return 0
    fi
    docker exec "$client_id" python3 /opt/ipc_client.py rules >&2 || true
    printf 'OpenShield did not learn Privoxy after %s\n' "$description" >&2
    return 1
}

copy_evidence_file() {
    container=$1
    source=$2
    destination=$3
    [ -n "$container" ] || return 0
    docker cp "$container:$source" "$evidence_directory/$destination" >/dev/null 2>&1 || true
}

collect_evidence() {
    {
        printf 'stage=%s\nbackend=%s\ndistribution=%s\nrpm=%s\n' \
            "$stage" "$backend" "$distribution" "$rpm_path"
        printf 'diagnostic_loopback=%s\n' "$diagnostic_loopback"
        printf 'network_accept=%s\n' "$network_accept"
        printf 'browser_identity=%s\n' "$browser_identity"
        printf 'enforcing_identity=%s\n' "$enforcing_identity"
        printf 'noise_processes_per_uid=%s\nnoise_threads_per_process=%s\n' \
            "$noise_processes" "$noise_threads"
        printf 'noise_file_descriptors_per_process=%s\n' "$noise_file_descriptors"
        printf 'browser_learning_elapsed_ms=%s\n' "$browser_learning_elapsed_ms"
        printf 'browser_enforcing_elapsed_ms=%s\n' "$browser_enforcing_elapsed_ms"
        printf 'expected_version=%s\n' "$expected_version"
        printf 'rpm_sha256=%s\n' "$(sha256sum "$rpm_path" | awk '{print $1}')"
        printf 'privoxy_pid=%s\nprivoxy_uid=%s\n' "$privoxy_pid" "$privoxy_uid"
    } > "$evidence_directory/run.txt"
    copy_evidence_file "$client_id" /tmp/openshield.log daemon.log
    copy_evidence_file "$client_id" /tmp/openshield.exit-status daemon.exit-status
    copy_evidence_file "$client_id" /tmp/privoxy.log privoxy.log
    copy_evidence_file "$client_id" /tmp/privoxy.stdout privoxy.stdout
    copy_evidence_file "$client_id" /tmp/proxy-hold.log hold.log
    copy_evidence_file "$client_id" /tmp/proxy-cold.log cold.log
    copy_evidence_file "$client_id" /tmp/proxy-threaded.log threaded.log
    copy_evidence_file "$client_id" /tmp/proxy-denied.log denied.log
    copy_evidence_file "$client_id" /tmp/proxy-recovered.log recovered.log
    copy_evidence_file "$client_id" /tmp/browser-identities.json browser-identities.json
    copy_evidence_file "$client_id" /tmp/browser-direct-1.log browser-direct-1.log
    copy_evidence_file "$client_id" /tmp/browser-direct-2.log browser-direct-2.log
    copy_evidence_file "$client_id" /tmp/browser-proxy.log browser-proxy.log
    copy_evidence_file "$client_id" /tmp/browser-direct-1-enforcing.log browser-direct-1-enforcing.log
    copy_evidence_file "$client_id" /tmp/browser-direct-2-enforcing.log browser-direct-2-enforcing.log
    copy_evidence_file "$client_id" /tmp/browser-proxy-enforcing.log browser-proxy-enforcing.log
    copy_evidence_file "$client_id" /tmp/browser-enforcing-audit.json browser-enforcing-audit.json
    copy_evidence_file "$client_id" /tmp/browser-unknown-loopback.log browser-unknown-loopback.log
    copy_evidence_file "$client_id" /tmp/browser-unknown-peer.log browser-unknown-peer.log
    copy_evidence_file "$client_id" /tmp/noise-same.log noise-same.log
    copy_evidence_file "$client_id" /tmp/noise-other.log noise-other.log
    copy_evidence_file "$client_id" /tmp/proxy-audit.log audit.log
    copy_evidence_file "$client_id" /tmp/proxy-thread-sample.txt thread-sample.txt
    copy_evidence_file "$client_id" /var/lib/openshield/state.json state.json
    if [ -n "$peer_id" ]; then
        docker exec "$peer_id" cat /tmp/proxy-peer.log \
            > "$evidence_directory/peer.log" 2>&1 || true
    fi
    if [ -n "$client_id" ]; then
        docker exec "$client_id" python3 /opt/ipc_client.py status \
            > "$evidence_directory/status.json" 2>&1 || true
        docker exec "$client_id" python3 /opt/ipc_client.py rules \
            > "$evidence_directory/rules.json" 2>&1 || true
        docker exec "$client_id" /bin/sh -c '
            if command -v nft >/dev/null 2>&1; then nft list ruleset; fi
            for save in iptables-save ip6tables-save iptables-legacy-save ip6tables-legacy-save; do
                command -v "$save" >/dev/null 2>&1 || continue
                "$save" -c 2>&1 || true
            done
        ' > "$evidence_directory/firewall.txt" 2>&1 || true
        if [ -n "$privoxy_pid" ]; then
            docker exec "$client_id" cat "/proc/$privoxy_pid/status" \
                > "$evidence_directory/privoxy-status.txt" 2>&1 || true
        fi
        case "$distribution" in
            bookworm)
                docker exec "$client_id" dpkg-query -W privoxy \
                    > "$evidence_directory/privoxy-package.txt" 2>&1 || true
                ;;
            tumbleweed)
                docker exec "$client_id" rpm -q privoxy \
                    > "$evidence_directory/privoxy-package.txt" 2>&1 || true
                ;;
        esac
    fi
}

cleanup() {
    status=$?
    collect_evidence
    [ -z "$client_id" ] || docker rm -f "$client_id" >/dev/null 2>&1 || true
    [ -z "$peer_id" ] || docker rm -f "$peer_id" >/dev/null 2>&1 || true
    [ -z "$network_id" ] || docker network rm "$network_id" >/dev/null 2>&1 || true
    case "$temporary_directory" in
        /tmp/openshield-proxy-e2e.*) rm -rf -- "$temporary_directory" ;;
        *) printf 'refusing unsafe temporary cleanup: %s\n' "$temporary_directory" >&2 ;;
    esac
    printf 'Privoxy Learning E2E evidence: %s\n' "$evidence_directory"
    if [ "$status" -ne 0 ]; then
        printf 'Privoxy Learning E2E failed during stage "%s"\n' "$stage" >&2
    fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

begin_stage 'extract release daemon without host installation'
install -d -m 0755 "$temporary_directory/extracted"
rpm2cpio "$rpm_path" > "$temporary_directory/package.cpio"
(
    cd "$temporary_directory/extracted"
    cpio -idm --quiet ./usr/bin/openshield-daemon < "$temporary_directory/package.cpio"
)
daemon_binary="$temporary_directory/extracted/usr/bin/openshield-daemon"
[ -f "$daemon_binary" ] && [ -x "$daemon_binary" ] && [ ! -L "$daemon_binary" ] || {
    printf '%s\n' 'RPM did not contain an executable daemon' >&2
    exit 1
}
case "$(LC_ALL=C file -b "$daemon_binary")" in
    *'statically linked'*|*'static-pie linked'*) ;;
    *) printf '%s\n' 'RPM daemon is not statically linked' >&2; exit 1 ;;
esac
if LC_ALL=C readelf -l "$daemon_binary" | grep -Eq '(^|[[:space:]])INTERP([[:space:]]|$)'; then
    printf '%s\n' 'RPM daemon unexpectedly contains an ELF interpreter' >&2
    exit 1
fi
[ "$("$daemon_binary" --version)" = "openshield-daemon $expected_version" ] || {
    printf 'RPM daemon version is not %s\n' "$expected_version" >&2
    exit 1
}

cat > "$temporary_directory/privoxy.conf" <<'EOF'
confdir /etc/privoxy
logdir /tmp
actionsfile match-all.action
actionsfile default.action
filterfile default.filter
logfile privoxy.log
listen-address 127.0.0.1:8118
toggle 1
enable-remote-toggle 0
enable-edit-actions 0
accept-intercepted-requests 0
connection-sharing 0
keep-alive-timeout 300
default-server-timeout 300
socket-timeout 300
debug 1
debug 1024
debug 4096
EOF

begin_stage 'create isolated network namespaces'
docker pull --platform linux/amd64 "$client_image" >/dev/null
docker pull --platform linux/amd64 "$peer_image" >/dev/null
network_id=$(docker network create --label "$resource_label" "$network_name")
peer_id=$(docker create --platform linux/amd64 --name "$peer_name" --label "$resource_label" \
    --network "$network_id" --read-only --cap-drop ALL --security-opt no-new-privileges \
    --security-opt label=disable --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m \
    --mount "type=bind,src=$script_directory/proxy-workload.py,dst=/opt/proxy-workload.py,readonly" \
    "$peer_image" python3 /opt/proxy-workload.py serve 18081 \
        /tmp/proxy-peer.log /tmp/proxy-peer.ready)
client_id=$(docker create --platform linux/amd64 --name "$client_name" --label "$resource_label" \
    --network "$network_id" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE \
    --cap-add DAC_READ_SEARCH --security-opt no-new-privileges --security-opt label=disable \
    --pids-limit 8192 --memory 2g \
    --env PYTHONDONTWRITEBYTECODE=1 \
    --mount "type=bind,src=$temporary_directory/extracted/usr/bin,dst=/opt/openshield,readonly" \
    --mount "type=bind,src=$temporary_directory/privoxy.conf,dst=/opt/privoxy.conf,readonly" \
    --mount "type=bind,src=$script_directory/ipc_client.py,dst=/opt/ipc_client.py,readonly" \
    --mount "type=bind,src=$script_directory/proxy-workload.py,dst=/opt/proxy-workload.py,readonly" \
    "$client_image" sleep infinity)
docker start "$peer_id" "$client_id" >/dev/null
wait_for_file "$peer_id" /tmp/proxy-peer.ready 'HTTP peer'
peer_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$peer_id")
case "$peer_ip" in ''|*[!0-9.]*) printf '%s\n' 'unsafe peer IPv4 address' >&2; exit 1 ;; esac

begin_stage 'install real distribution Privoxy and firewall tools'
case "$distribution" in
    bookworm)
        docker exec "$client_id" /bin/sh -c \
            'printf "#!/bin/sh\nexit 101\n" >/usr/sbin/policy-rc.d; chmod 0755 /usr/sbin/policy-rc.d'
        docker exec "$client_id" apt-get update >/dev/null
        packages='privoxy iptables python3 passwd util-linux procps iproute2'
        [ "$backend" = nftables ] && packages="$packages nftables"
        # shellcheck disable=SC2086
        docker exec "$client_id" env DEBIAN_FRONTEND=noninteractive \
            apt-get install -y --no-install-recommends $packages >/dev/null
        ;;
    tumbleweed)
        attempt=1
        while ! docker exec "$client_id" zypper --non-interactive refresh repo-oss >/dev/null; do
            [ "$attempt" -lt 3 ] || exit 1
            sleep "$((attempt * 5))"
            attempt=$((attempt + 1))
        done
        packages='privoxy iptables python3 shadow util-linux procps iproute2'
        [ "$backend" = nftables ] && packages="$packages nftables"
        # shellcheck disable=SC2086
        docker exec "$client_id" zypper --non-interactive --no-refresh install \
            --repo repo-oss $packages >/dev/null
        ;;
esac
if [ "$backend" = iptables ] && docker exec "$client_id" /bin/sh -c 'command -v nft >/dev/null'; then
    printf '%s\n' 'iptables fallback fixture unexpectedly contains nft' >&2
    exit 1
fi
docker exec "$client_id" /bin/sh -c '
    getent group openshield >/dev/null || groupadd --system openshield
    id privoxy >/dev/null
    id proxyclient >/dev/null 2>&1 || useradd --system --no-create-home --shell /bin/false proxyclient
    id noiseuser >/dev/null 2>&1 || useradd --system --no-create-home --shell /bin/false noiseuser
    install -d -m 0755 -o root -g root /run/openshield
    install -d -m 0700 -o root -g root /var/lib/openshield
'
privoxy_binary=$(docker exec "$client_id" /bin/sh -c 'readlink -f "$(command -v privoxy)"')
case "$privoxy_binary" in /*) ;; *) printf '%s\n' 'cannot resolve Privoxy executable' >&2; exit 1 ;; esac
privoxy_uid=$(docker exec "$client_id" id -u privoxy)
case "$privoxy_uid" in 0|'') printf '%s\n' 'Privoxy package user is not unprivileged' >&2; exit 1 ;; esac

begin_stage 'start unprivileged threaded Privoxy'
docker exec "$client_id" rm -f /tmp/privoxy.log /tmp/privoxy.stdout
docker exec --detach "$client_id" /bin/sh -c '
    executable=$1
    exec runuser -u privoxy -- "$executable" --no-daemon /opt/privoxy.conf \
        >/tmp/privoxy.stdout 2>&1
' openshield-privoxy "$privoxy_binary"
if ! docker exec "$client_id" /bin/sh -c '
    attempt=0
    while [ "$attempt" -lt 200 ]; do
        pid=$(pgrep -xo privoxy 2>/dev/null || true)
        [ -z "$pid" ] || { printf "%s\n" "$pid" >/tmp/privoxy.pid; exit 0; }
        attempt=$((attempt + 1)); sleep 0.05
    done
    exit 1
'; then
    docker exec "$client_id" cat /tmp/privoxy.stdout >&2 || true
    exit 1
fi
privoxy_pid=$(docker exec "$client_id" cat /tmp/privoxy.pid)
process_uid=$(docker exec "$client_id" sed -n 's/^Uid:[[:space:]]*\([0-9][0-9]*\).*/\1/p' \
    "/proc/$privoxy_pid/status")
[ "$process_uid" = "$privoxy_uid" ] || {
    printf 'Privoxy process UID mismatch: package=%s process=%s\n' "$privoxy_uid" "$process_uid" >&2
    exit 1
}

client_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$client_id")
case "$client_ip" in ''|*[!0-9.]*) printf '%s\n' 'unsafe client IPv4 address' >&2; exit 1 ;; esac
docker exec --detach "$client_id" runuser -u proxyclient -- \
    python3 -m http.server 19090 --bind 0.0.0.0
if ! docker exec "$peer_id" /bin/sh -c '
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        python3 /opt/proxy-workload.py direct "$1" 19090 >/dev/null 2>&1 && exit 0
        attempt=$((attempt + 1)); sleep 0.05
    done
    exit 1
' openshield-inbound-baseline "$client_ip"; then
    printf '%s\n' 'external inbound baseline was not reachable before OpenShield' >&2
    exit 1
fi

begin_stage 'establish proxy and upstream TCP before daemon startup'
docker exec "$client_id" rm -f /tmp/proxy-hold.ready /tmp/proxy-hold.continue \
    /tmp/proxy-hold.status /tmp/proxy-hold.log
docker exec --detach "$client_id" /bin/sh -c '
    if runuser -u proxyclient -- python3 /opt/proxy-workload.py hold \
        8118 "$1" 18081 /tmp/proxy-hold.ready /tmp/proxy-hold.continue \
        >/tmp/proxy-hold.log 2>&1; then status=0; else status=$?; fi
    printf "%s\n" "$status" >/tmp/proxy-hold.status
' openshield-proxy-hold "$peer_ip"
wait_for_file "$client_id" /tmp/proxy-hold.ready 'pre-daemon proxy connection'
docker exec "$peer_id" grep -Fq '"path":"/pre-daemon"' /tmp/proxy-peer.log || {
    printf '%s\n' 'peer did not observe the pre-daemon upstream request' >&2
    exit 1
}

begin_stage 'start OpenShield in Learning'
docker exec "$client_id" rm -f /tmp/openshield.log /tmp/openshield.exit-status
docker exec --detach "$client_id" /bin/sh -c '
    daemon=$1
    "$daemon" >/tmp/openshield.log 2>&1 &
    child=$!
    printf "%s\n" "$child" >/tmp/openshield.pid
    if wait "$child"; then status=0; else status=$?; fi
    printf "%s\n" "$status" >/tmp/openshield.exit-status
' openshield-daemon-supervisor /opt/openshield/openshield-daemon
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
status=$(docker exec "$client_id" python3 /opt/ipc_client.py status)
case "$status" in *'"mode": "learning"'*) ;; *) printf 'unexpected daemon status: %s\n' "$status" >&2; exit 1 ;; esac
case "$backend" in
    nftables) expected_backend='firewall_backend="nftables"' ;;
    iptables) expected_backend='firewall_backend="iptables/ip6tables"' ;;
esac
docker exec "$client_id" grep -Fq "$expected_backend" /tmp/openshield.log || {
    docker exec "$client_id" cat /tmp/openshield.log >&2 || true
    exit 1
}
if [ "$diagnostic_loopback" = true ]; then
    docker exec "$client_id" python3 /opt/proxy-workload.py allow-loopback 8118 \
        >/dev/null
fi
if [ "$network_accept" = true ]; then
    docker exec "$client_id" python3 /opt/ipc_client.py create-network-tcp-rule \
        openshield-proxy-network-accept "$peer_ip" 18081 accept >/dev/null
    docker exec "$client_id" python3 /opt/proxy-workload.py assert-network-accept \
        openshield-proxy-network-accept "$peer_ip" 18081 >/dev/null
fi
if [ "$browser_identity" = true ]; then
    if [ "$network_accept" = false ]; then
        browser_peer_network_rule_name=openshield-browser-peer-accept
        docker exec "$client_id" python3 /opt/ipc_client.py create-network-tcp-rule \
            "$browser_peer_network_rule_name" "$peer_ip" 18081 accept >/dev/null
        docker exec "$client_id" python3 /opt/proxy-workload.py assert-network-accept \
            "$browser_peer_network_rule_name" "$peer_ip" 18081 >/dev/null
    else
        browser_peer_network_rule_name=openshield-proxy-network-accept
    fi
    docker exec "$client_id" python3 /opt/ipc_client.py create-network-tcp-rule \
        openshield-browser-loopback-accept 127.0.0.1 8118 accept >/dev/null
    docker exec "$client_id" python3 /opt/proxy-workload.py assert-network-accept \
        openshield-browser-loopback-accept 127.0.0.1 8118 >/dev/null
fi
docker exec "$peer_id" python3 /opt/proxy-workload.py direct-blocked "$client_ip" 19090 \
    >/dev/null

if [ "$browser_identity" = true ]; then
    begin_stage 'exercise shared-UID browser-style application identities'
    docker exec "$client_id" /bin/sh -c '
        python=$(readlink -f "$(command -v python3)")
        install -m 0755 "$python" /tmp/openshield-browser-direct
        install -m 0755 "$python" /tmp/openshield-browser-proxy
        install -m 0755 "$python" /tmp/openshield-browser-unknown
        rm -f /tmp/browser-*.ready /tmp/browser-*.release /tmp/browser-*.status \
            /tmp/browser-*.log /tmp/browser-identities.json
        rm -f /tmp/noise-*.ready /tmp/noise-*.release /tmp/noise-*.status \
            /tmp/noise-*.log
    '
    browser_uid=$(docker exec "$client_id" id -u proxyclient)
    browser_direct=/tmp/openshield-browser-direct
    browser_proxy=/tmp/openshield-browser-proxy
    docker exec --detach "$client_id" /bin/sh -c '
        if runuser -u proxyclient -- python3 /opt/proxy-workload.py procfs-noise \
            "$1" "$2" "$3" /tmp/noise-same.ready /tmp/noise-same.release \
            >/tmp/noise-same.log 2>&1; then status=0; else status=$?; fi
        printf "%s\n" "$status" >/tmp/noise-same.status
    ' openshield-noise-same "$noise_processes" "$noise_threads" "$noise_file_descriptors"
    docker exec --detach "$client_id" /bin/sh -c '
        if runuser -u noiseuser -- python3 /opt/proxy-workload.py procfs-noise \
            "$1" "$2" "$3" /tmp/noise-other.ready /tmp/noise-other.release \
            >/tmp/noise-other.log 2>&1; then status=0; else status=$?; fi
        printf "%s\n" "$status" >/tmp/noise-other.status
    ' openshield-noise-other "$noise_processes" "$noise_threads" "$noise_file_descriptors"
    wait_for_file "$client_id" /tmp/noise-same.ready 'same-UID procfs noise'
    wait_for_file "$client_id" /tmp/noise-other.ready 'different-UID procfs noise'
    browser_learning_started_ns=$(date +%s%N)
    docker exec --detach "$client_id" /bin/sh -c '
        if runuser -u proxyclient -- "$1" /opt/proxy-workload.py identity-hold \
            "$2" 18081 "$2" 18081 direct-one 8 \
            /tmp/browser-direct-1.ready /tmp/browser-direct-1.release \
            >/tmp/browser-direct-1.log 2>&1; then status=0; else status=$?; fi
        printf "%s\n" "$status" >/tmp/browser-direct-1.status
    ' openshield-browser-direct-1 "$browser_direct" "$peer_ip"
    docker exec --detach "$client_id" /bin/sh -c '
        if runuser -u proxyclient -- "$1" /opt/proxy-workload.py identity-hold \
            "$2" 18081 "$2" 18081 direct-two 8 \
            /tmp/browser-direct-2.ready /tmp/browser-direct-2.release \
            >/tmp/browser-direct-2.log 2>&1; then status=0; else status=$?; fi
        printf "%s\n" "$status" >/tmp/browser-direct-2.status
    ' openshield-browser-direct-2 "$browser_direct" "$peer_ip"
    docker exec --detach "$client_id" /bin/sh -c '
        if runuser -u proxyclient -- "$1" /opt/proxy-workload.py identity-hold \
            127.0.0.1 8118 "$2" 18081 proxied 16 \
            /tmp/browser-proxy.ready /tmp/browser-proxy.release \
            >/tmp/browser-proxy.log 2>&1; then status=0; else status=$?; fi
        printf "%s\n" "$status" >/tmp/browser-proxy.status
    ' openshield-browser-proxy "$browser_proxy" "$peer_ip"
    wait_for_file "$client_id" /tmp/browser-direct-1.ready 'first direct browser process'
    wait_for_file "$client_id" /tmp/browser-direct-2.ready 'second direct browser process'
    wait_for_file "$client_id" /tmp/browser-proxy.ready 'proxied browser process'
    if ! docker exec "$client_id" /bin/sh -c '
        attempt=0
        while [ "$attempt" -lt 200 ]; do
            python3 /opt/proxy-workload.py assert-browser-identities \
                "$1" "$2" "$3" "$4" "$5" "$6" 18081 8118 \
                >/tmp/browser-identities.json 2>/tmp/browser-identities.error && exit 0
            attempt=$((attempt + 1)); sleep 0.05
        done
        cat /tmp/browser-identities.error >&2
        exit 1
    ' openshield-browser-identities "$browser_direct" "$browser_proxy" \
        "$browser_uid" "$privoxy_binary" "$privoxy_uid" "$peer_ip"; then
        docker exec "$client_id" python3 /opt/ipc_client.py rules >&2 || true
        exit 1
    fi
    browser_learning_finished_ns=$(date +%s%N)
    browser_learning_elapsed_ms=$(((browser_learning_finished_ns - browser_learning_started_ns) / 1000000))
    docker exec "$client_id" touch /tmp/browser-direct-1.release \
        /tmp/browser-direct-2.release /tmp/browser-proxy.release
    wait_for_file "$client_id" /tmp/browser-direct-1.status 'first browser process exit'
    wait_for_file "$client_id" /tmp/browser-direct-2.status 'second browser process exit'
    wait_for_file "$client_id" /tmp/browser-proxy.status 'proxied browser process exit'
    for identity_status in browser-direct-1 browser-direct-2 browser-proxy; do
        [ "$(docker exec "$client_id" cat "/tmp/$identity_status.status")" = 0 ] || {
            docker exec "$client_id" cat "/tmp/$identity_status.log" >&2 || true
            exit 1
        }
    done
    if [ "$enforcing_identity" = true ]; then
        begin_stage 'disable network bypasses and enter Enforcing'
        docker exec "$client_id" python3 /opt/ipc_client.py set-named-rule-enabled \
            "$browser_peer_network_rule_name" disabled >/dev/null
        docker exec "$client_id" python3 /opt/ipc_client.py set-named-rule-enabled \
            openshield-browser-loopback-accept disabled >/dev/null
        docker exec "$client_id" python3 /opt/proxy-workload.py assert-network-accept \
            "$browser_peer_network_rule_name" "$peer_ip" 18081 disabled >/dev/null
        docker exec "$client_id" python3 /opt/proxy-workload.py assert-network-accept \
            openshield-browser-loopback-accept 127.0.0.1 8118 disabled >/dev/null
        docker exec "$client_id" python3 /opt/ipc_client.py set-mode enforcing >/dev/null
        docker exec "$client_id" python3 /opt/ipc_client.py assert-runtime \
            enforcing "$backend" conntrack_hybrid application_tcp >/dev/null

        # Clear the Learning traffic so the audit below can prove that every
        # request crossed the application-only Enforcing policy.
        docker exec "$peer_id" /bin/sh -c ': > /tmp/proxy-peer.log'
        docker exec "$client_id" rm -f /tmp/browser-direct-1.ready \
            /tmp/browser-direct-2.ready /tmp/browser-proxy.ready \
            /tmp/browser-direct-1.release /tmp/browser-direct-2.release \
            /tmp/browser-proxy.release /tmp/browser-direct-1.status \
            /tmp/browser-direct-2.status /tmp/browser-proxy.status \
            /tmp/browser-direct-1-enforcing.log \
            /tmp/browser-direct-2-enforcing.log \
            /tmp/browser-proxy-enforcing.log /tmp/browser-enforcing-audit.json

        begin_stage 'exercise application-only Enforcing under procfs pressure'
        browser_enforcing_started_ns=$(date +%s%N)
        docker exec --detach "$client_id" /bin/sh -c '
            if runuser -u proxyclient -- "$1" /opt/proxy-workload.py identity-hold \
                "$2" 18081 "$2" 18081 direct-one 8 \
                /tmp/browser-direct-1.ready /tmp/browser-direct-1.release \
                >/tmp/browser-direct-1-enforcing.log 2>&1; then status=0; else status=$?; fi
            printf "%s\n" "$status" >/tmp/browser-direct-1.status
        ' openshield-browser-direct-1-enforcing "$browser_direct" "$peer_ip"
        docker exec --detach "$client_id" /bin/sh -c '
            if runuser -u proxyclient -- "$1" /opt/proxy-workload.py identity-hold \
                "$2" 18081 "$2" 18081 direct-two 8 \
                /tmp/browser-direct-2.ready /tmp/browser-direct-2.release \
                >/tmp/browser-direct-2-enforcing.log 2>&1; then status=0; else status=$?; fi
            printf "%s\n" "$status" >/tmp/browser-direct-2.status
        ' openshield-browser-direct-2-enforcing "$browser_direct" "$peer_ip"
        docker exec --detach "$client_id" /bin/sh -c '
            if runuser -u proxyclient -- "$1" /opt/proxy-workload.py identity-hold \
                127.0.0.1 8118 "$2" 18081 proxied 16 \
                /tmp/browser-proxy.ready /tmp/browser-proxy.release \
                >/tmp/browser-proxy-enforcing.log 2>&1; then status=0; else status=$?; fi
            printf "%s\n" "$status" >/tmp/browser-proxy.status
        ' openshield-browser-proxy-enforcing "$browser_proxy" "$peer_ip"
        wait_for_identity_ready "$client_id" /tmp/browser-direct-1.ready \
            /tmp/browser-direct-1.status /tmp/browser-direct-1-enforcing.log \
            'first direct browser process'
        wait_for_identity_ready "$client_id" /tmp/browser-direct-2.ready \
            /tmp/browser-direct-2.status /tmp/browser-direct-2-enforcing.log \
            'second direct browser process'
        wait_for_identity_ready "$client_id" /tmp/browser-proxy.ready \
            /tmp/browser-proxy.status /tmp/browser-proxy-enforcing.log \
            'proxied browser process'
        browser_enforcing_finished_ns=$(date +%s%N)
        browser_enforcing_elapsed_ms=$(((browser_enforcing_finished_ns - browser_enforcing_started_ns) / 1000000))

        docker exec "$client_id" touch /tmp/browser-direct-1.release \
            /tmp/browser-direct-2.release /tmp/browser-proxy.release
        wait_for_file "$client_id" /tmp/browser-direct-1.status \
            'first Enforcing browser process exit'
        wait_for_file "$client_id" /tmp/browser-direct-2.status \
            'second Enforcing browser process exit'
        wait_for_file "$client_id" /tmp/browser-proxy.status \
            'Enforcing proxied browser process exit'
        for identity_status in browser-direct-1 browser-direct-2 browser-proxy; do
            [ "$(docker exec "$client_id" cat "/tmp/$identity_status.status")" = 0 ] || {
                docker exec "$client_id" cat "/tmp/$identity_status-enforcing.log" >&2 || true
                exit 1
            }
        done

        sleep 0.2
        docker exec "$peer_id" cat /tmp/proxy-peer.log \
            > "$temporary_directory/browser-enforcing-peer.log"
        docker cp "$temporary_directory/browser-enforcing-peer.log" \
            "$client_id:/tmp/browser-enforcing-peer.log" >/dev/null
        if ! docker exec "$client_id" /bin/sh -c '
            attempt=0
            while [ "$attempt" -lt 100 ]; do
                python3 /opt/proxy-workload.py audit-identity-round \
                    /tmp/browser-enforcing-peer.log 8 16 \
                    >/tmp/browser-enforcing-audit.json 2>/tmp/browser-enforcing-audit.error \
                    && exit 0
                attempt=$((attempt + 1)); sleep 0.05
            done
            cat /tmp/browser-enforcing-audit.error >&2
            exit 1
        '; then
            exit 1
        fi

        begin_stage 'verify unknown applications remain fail-closed in Enforcing'
        browser_unknown=/tmp/openshield-browser-unknown
        docker exec "$client_id" /bin/sh -c '
            exec runuser -u proxyclient -- "$1" /opt/proxy-workload.py \
                direct-blocked 127.0.0.1 8118 >/tmp/browser-unknown-loopback.log 2>&1
        ' openshield-browser-unknown-loopback "$browser_unknown"
        docker exec "$client_id" /bin/sh -c '
            exec runuser -u proxyclient -- "$1" /opt/proxy-workload.py \
                direct-blocked "$2" 18081 >/tmp/browser-unknown-peer.log 2>&1
        ' openshield-browser-unknown-peer "$browser_unknown" "$peer_ip"
        docker exec "$client_id" python3 /opt/ipc_client.py assert-runtime \
            enforcing "$backend" conntrack_hybrid application_tcp >/dev/null
        if docker exec "$client_id" grep -Eqi \
            'fail.open|quarantine|emergency BlockAll' /tmp/openshield.log; then
            printf '%s\n' 'daemon reported fail-open/quarantine during Enforcing identity workload' >&2
            exit 1
        fi
        docker exec "$client_id" python3 /opt/proxy-workload.py \
            assert-nfqueue-clean --require-denied >/dev/null
    fi

    docker exec "$client_id" touch /tmp/noise-same.release /tmp/noise-other.release
    wait_for_file "$client_id" /tmp/noise-same.status 'same-UID noise exit'
    wait_for_file "$client_id" /tmp/noise-other.status 'different-UID noise exit'
    for noise_status in noise-same noise-other; do
        [ "$(docker exec "$client_id" cat "/tmp/$noise_status.status")" = 0 ] || {
            docker exec "$client_id" cat "/tmp/$noise_status.log" >&2 || true
            exit 1
        }
    done
    docker exec "$client_id" python3 /opt/proxy-workload.py assert-nfqueue-clean >/dev/null
    begin_stage 'complete browser identity regression'
    if [ "$enforcing_identity" = true ]; then
        printf 'PASS browser identity E2E (%s/%s): Learning %s ms; application-only Enforcing %s ms\n' \
            "$distribution" "$backend" "$browser_learning_elapsed_ms" \
            "$browser_enforcing_elapsed_ms"
    else
        printf 'PASS browser identity E2E (%s/%s): shared UID, distinct executables, direct and proxied (%s ms to all learned identities)\n' \
            "$distribution" "$backend" "$browser_learning_elapsed_ms"
    fi
    exit 0
fi

begin_stage 'exercise the connection established before Learning'
docker exec "$client_id" touch /tmp/proxy-hold.continue
wait_for_file "$client_id" /tmp/proxy-hold.status 'held proxy workload'
[ "$(docker exec "$client_id" cat /tmp/proxy-hold.status)" = 0 ] || {
    docker exec "$client_id" cat /tmp/proxy-hold.log >&2 || true
    docker exec "$client_id" /bin/sh -c '
        runuser -u proxyclient -- python3 /opt/proxy-workload.py cold \
            8118 "$1" 18081 failed-hold-diagnostic 1 1 0 \
            >/tmp/proxy-cold.log 2>&1 || true
    ' openshield-proxy-cold-diagnostic "$peer_ip" || true
    exit 1
}
wait_for_privoxy_rule 'traffic on the pre-daemon established upstream connection'

begin_stage 'exercise cold short proxy connections'
docker exec "$client_id" /bin/sh -c '
    exec runuser -u proxyclient -- python3 /opt/proxy-workload.py cold \
        8118 "$1" 18081 cold 24 8 0 >/tmp/proxy-cold.log 2>&1
' openshield-proxy-cold "$peer_ip" || {
        docker exec "$client_id" cat /tmp/proxy-cold.log >&2 || true
        exit 1
    }

begin_stage 'exercise Privoxy worker threads under Learning'
docker exec "$client_id" rm -f /tmp/proxy-threaded.status /tmp/proxy-threaded.log \
    /tmp/proxy-thread-sample.txt
docker exec --detach "$client_id" /bin/sh -c '
    if runuser -u proxyclient -- python3 /opt/proxy-workload.py cold \
        8118 "$1" 18081 threaded 32 32 250 >/tmp/proxy-threaded.log 2>&1; then
        status=0
    else
        status=$?
    fi
    printf "%s\n" "$status" >/tmp/proxy-threaded.status
' openshield-proxy-threaded "$peer_ip"
docker exec "$client_id" /bin/sh -c '
    pid=$1
    expected_uid=$2
    maximum=0
    attempt=0
    while [ "$attempt" -lt 500 ] && [ ! -f /tmp/proxy-threaded.status ]; do
        set -- /proc/$pid/task/[0-9]*
        count=$#
        [ "$count" -le "$maximum" ] || maximum=$count
        for task do
            [ -r "$task/status" ] || continue
            uid=$(sed -n "s/^Uid:[[:space:]]*\([0-9][0-9]*\).*/\1/p" \
                "$task/status" 2>/dev/null || true)
            [ -n "$uid" ] || continue
            [ "$uid" = "$expected_uid" ] || exit 3
        done
        attempt=$((attempt + 1)); sleep 0.02
    done
    printf "maximum_threads=%s\n" "$maximum" >/tmp/proxy-thread-sample.txt
    [ -f /tmp/proxy-threaded.status ] && [ "$maximum" -ge 2 ]
' openshield-proxy-thread-sampler "$privoxy_pid" "$privoxy_uid" || {
    printf '%s\n' 'Privoxy did not expose multiple same-UID worker threads' >&2
    exit 1
}
[ "$(docker exec "$client_id" cat /tmp/proxy-threaded.status)" = 0 ] || {
    docker exec "$client_id" cat /tmp/proxy-threaded.log >&2 || true
    exit 1
}

begin_stage 'verify real upstream topology and learned identity'
docker exec "$peer_id" cat /tmp/proxy-peer.log > "$temporary_directory/proxy-peer.log"
docker cp "$temporary_directory/proxy-peer.log" "$client_id:/tmp/proxy-peer.log" >/dev/null
docker exec "$client_id" /bin/sh -c '
    exec python3 /opt/proxy-workload.py audit /tmp/proxy-peer.log 24 32 \
        >/tmp/proxy-audit.log 2>&1
' openshield-proxy-audit || {
        docker exec "$client_id" cat /tmp/proxy-audit.log >&2 || true
        exit 1
    }
wait_for_privoxy_rule 'cold and threaded connections'

begin_stage 'verify explicit application Drop still wins in Learning'
docker exec "$client_id" python3 /opt/ipc_client.py create-app-tcp-rule \
    openshield-proxy-explicit-drop "$privoxy_binary" "$peer_ip" 18081 drop >/dev/null
if docker exec "$client_id" /bin/sh -c '
    exec runuser -u proxyclient -- python3 /opt/proxy-workload.py cold \
        8118 "$1" 18081 denied 1 1 0 >/tmp/proxy-denied.log 2>&1
' openshield-proxy-denied "$peer_ip"; then
    printf '%s\n' 'explicit Privoxy Drop failed open in Learning' >&2
    exit 1
fi
docker exec "$client_id" python3 /opt/ipc_client.py set-named-rule-enabled \
    openshield-proxy-explicit-drop disabled >/dev/null
docker exec "$client_id" /bin/sh -c '
    exec runuser -u proxyclient -- python3 /opt/proxy-workload.py cold \
        8118 "$1" 18081 recovered 1 1 0 >/tmp/proxy-recovered.log 2>&1
' openshield-proxy-recovered "$peer_ip"
docker exec "$client_id" kill -0 "$(docker exec "$client_id" cat /tmp/openshield.pid)"
case "$(docker exec "$client_id" python3 /opt/ipc_client.py status)" in
    *'"mode": "learning"'*) ;;
    *) printf '%s\n' 'daemon left Learning during proxy workload' >&2; exit 1 ;;
esac
if docker exec "$client_id" grep -Eqi 'fail.open|quarantine|emergency BlockAll' /tmp/openshield.log; then
    printf '%s\n' 'daemon reported fail-open/quarantine during proxy workload' >&2
    exit 1
fi
docker exec "$client_id" python3 /opt/proxy-workload.py assert-nfqueue-clean \
    --require-denied >/dev/null

begin_stage 'complete'
printf 'PASS Privoxy Learning E2E (%s/%s): preexisting, cold, short, and threaded flows\n' \
    "$distribution" "$backend"
