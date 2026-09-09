#!/bin/sh
# Targeted quota regression, intended for Docker inside a disposable Linux VM.
# Only labelled private DUT/peer resources are created or removed. Host network,
# /proc, state, /etc and firewall are never mounted into the DUT.
set -eu

[ "$#" = 2 ] || { printf 'usage: sh %s {nftables|iptables} ABSOLUTE_DAEMON_BINARY\n' "$0" >&2; exit 2; }
backend=$1
daemon_binary=$2
case "$backend" in nftables|iptables) ;; *) exit 2 ;; esac
case "$daemon_binary" in /*) ;; *) exit 2 ;; esac
[ -f "$daemon_binary" ] && [ -x "$daemon_binary" ] && [ ! -L "$daemon_binary" ] || exit 2
[ "${OPENSHIELD_E2E_ISOLATED_VM:-0}" = 1 ] || {
    printf '%s\n' 'Run in a disposable VM and set OPENSHIELD_E2E_ISOLATED_VM=1.' >&2
    exit 2
}
for command in docker sha256sum; do command -v "$command" >/dev/null || exit 2; done
case "${DOCKER_HOST:-}" in ''|unix:///*) ;; *) exit 2 ;; esac
case "$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')" in unix:///*) ;; *) exit 2 ;; esac
case "${OPENSHIELD_E2E_SKIP_PACKAGES:-0}" in 0|1) ;; *) exit 2 ;; esac
script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
evidence_directory=$(mktemp -d /tmp/openshield-learning-quota-evidence.XXXXXX)
token=${evidence_directory##*/}
label="org.openshield.learning-quota-e2e.run=$token"
network_id=
client_id=
peer_id=
profile=initialization
stage=initialization
client_image=${OPENSHIELD_E2E_CLIENT_IMAGE:-opensuse/tumbleweed@sha256:8f6397b7b7ebc78e111d9a13fb2b157664ad5524e1f3b908deb45938b3095045}
peer_image=${OPENSHIELD_E2E_PEER_IMAGE:-python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285}
for image in "$client_image" "$peer_image"; do
    case "$image" in ''|-*|*[!A-Za-z0-9._/:@-]*) printf '%s\n' 'unsafe test image reference' >&2; exit 2 ;; esac
done

collect() {
    if [ -n "$client_id" ]; then
        mkdir -p "$evidence_directory/$profile"
        docker cp "$client_id:/tmp/learning-quota/." "$evidence_directory/$profile/" >/dev/null 2>&1 || true
        docker exec "$client_id" cat /tmp/openshield.log >"$evidence_directory/$profile/daemon.log" 2>&1 || true
        docker exec "$client_id" cat /tmp/controller.log >"$evidence_directory/$profile/controller.log" 2>&1 || true
        docker exec "$client_id" cat /proc/net/netfilter/nfnetlink_queue >"$evidence_directory/$profile/nfqueue.txt" 2>&1 || true
        docker exec "$client_id" /bin/sh -c 'if command -v nft >/dev/null; then nft -a list ruleset; else iptables-save; ip6tables-save; fi' >"$evidence_directory/$profile/firewall.txt" 2>&1 || true
    fi
    if [ -n "$peer_id" ]; then
        docker exec "$peer_id" cat /tmp/peer.jsonl >"$evidence_directory/$profile/peer.jsonl" 2>&1 || true
        docker exec "$peer_id" cat /tmp/peer.error >"$evidence_directory/$profile/peer.error" 2>&1 || true
    fi
}

remove_resources() {
    # All IDs below originate exclusively from this invocation's labelled
    # Docker create operations. Never enumerate/delete unrelated resources.
    removal_status=0
    if [ -n "$client_id" ]; then
        if docker rm -f "$client_id" >/dev/null; then client_id=; else removal_status=1; fi
    fi
    if [ -n "$peer_id" ]; then
        if docker rm -f "$peer_id" >/dev/null; then peer_id=; else removal_status=1; fi
    fi
    if [ -n "$network_id" ]; then
        if docker network rm "$network_id" >/dev/null; then network_id=; else removal_status=1; fi
    fi
    return "$removal_status"
}

cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    set +e
    collect
    remove_resources || result=1
    printf 'backend=%s\nprofile=%s\nstage=%s\nresult=%s\nclient_image=%s\npeer_image=%s\n' \
        "$backend" "$profile" "$stage" "$result" "$client_image" "$peer_image" >"$evidence_directory/run.txt"
    sha256sum "$daemon_binary" >>"$evidence_directory/run.txt"
    printf 'OpenShield learning quota evidence: %s\n' "$evidence_directory"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

begin_stage() { stage=$1; printf '==> OpenShield learning quota (%s/%s): %s\n' "$backend" "$profile" "$stage"; }
wait_file() {
    docker exec "$1" /bin/sh -c 'n=0; while [ "$n" -lt 300 ]; do [ ! -e "$1" ] || exit 0; n=$((n+1)); sleep 0.1; done; exit 1' quota-wait "$2"
}

for profile in historical small; do
    mkdir "$evidence_directory/$profile"
    begin_stage 'create fresh private DUT and independent peer'
    network_id=$(docker network create --label "$label" "openshield-quota-$token-$profile")
    peer_id=$(docker create --platform linux/amd64 --label "$label" --network "$network_id" \
        --read-only --cap-drop ALL --security-opt no-new-privileges --security-opt label=disable \
        --pids-limit 64 --memory 128m --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m \
        --env PYTHONDONTWRITEBYTECODE=1 --env OPENSHIELD_LEARNING_QUOTA_E2E=1 \
        --mount "type=bind,src=$script_directory,dst=/opt/e2e,readonly" "$peer_image" sleep infinity)
    client_id=$(docker create --platform linux/amd64 --label "$label" --network "$network_id" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH \
        --security-opt no-new-privileges --security-opt label=disable --pids-limit 256 --memory 1g \
        --env PYTHONDONTWRITEBYTECODE=1 --env OPENSHIELD_LEARNING_QUOTA_E2E=1 \
        --mount "type=bind,src=$daemon_binary,dst=/opt/openshield-daemon,readonly" \
        --mount "type=bind,src=$script_directory,dst=/opt/e2e,readonly" "$client_image" sleep infinity)
    docker start "$peer_id" "$client_id" >/dev/null
    peer_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$peer_id")
    case "$peer_ip" in ''|*[!0-9.]*) exit 1 ;; esac
    if [ "${OPENSHIELD_E2E_SKIP_PACKAGES:-0}" = 0 ]; then
        begin_stage 'provision packages inside disposable Tumbleweed DUT'
        docker exec -i "$client_id" sh -s -- repo-oss <"$script_directory/zypper-refresh.sh"
        packages='iptables python3 shadow coreutils'
        [ "$backend" != nftables ] || packages="$packages nftables"
        # shellcheck disable=SC2086
        docker exec "$client_id" zypper --non-interactive --no-refresh install --no-recommends --repo repo-oss $packages >/dev/null
    fi
    docker exec "$client_id" /bin/sh -c '
        getent group openshield >/dev/null || groupadd --system openshield
        install -d -m 0755 -o root -g root /run/openshield
        install -d -m 0700 -o root -g root /var/lib/openshield
        [ ! -e /var/lib/openshield/state.json ]
    '
    begin_stage 'seed historical policy or administrator-selected small budgets'
    docker exec "$client_id" python3 /opt/e2e/learning-quota.py seed "$profile" "$peer_ip"
    docker exec --detach "$peer_id" /bin/sh -c 'exec python3 /opt/e2e/learning-quota.py serve >/tmp/peer.jsonl 2>/tmp/peer.error'
    wait_file "$peer_id" /tmp/quota-peer.ready
    docker exec --detach "$client_id" /bin/sh -c 'exec /opt/openshield-daemon >/tmp/openshield.log 2>&1'
    wait_file "$client_id" /run/openshield/control.sock
    begin_stage 'Learning to Enforcing TCP/UDP and denied executable checks'
    docker exec "$client_id" /bin/sh -c 'exec python3 /opt/e2e/learning-quota.py run "$1" "$2" "$3" >/tmp/controller.log 2>&1' \
        quota-controller "$profile" "$peer_ip" "$backend"
    begin_stage 'verify independent peer never received forbidden traffic'
    docker exec "$peer_id" python3 /opt/e2e/learning-quota.py audit /tmp/peer.jsonl "$profile" \
        >"$evidence_directory/$profile/peer-audit.json"
    collect
    remove_resources
done
begin_stage PASS
