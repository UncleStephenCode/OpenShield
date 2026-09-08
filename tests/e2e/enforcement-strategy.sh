#!/bin/sh
# Standalone real Strict/Fast regression. Run Docker inside a disposable VM.
set -eu
[ "$#" = 2 ] || { printf 'usage: sh %s {nftables|iptables} ABSOLUTE_DAEMON_BINARY\n' "$0" >&2; exit 2; }
backend=$1
daemon_binary=$2
case "$backend" in nftables|iptables) ;; *) exit 2 ;; esac
case "$daemon_binary" in /*) ;; *) exit 2 ;; esac
[ -f "$daemon_binary" ] && [ -x "$daemon_binary" ] && [ ! -L "$daemon_binary" ] || exit 2
[ "${OPENSHIELD_E2E_ISOLATED_VM:-0}" = 1 ] || {
    printf '%s\n' 'Run in a disposable VM and set OPENSHIELD_E2E_ISOLATED_VM=1.' >&2; exit 2
}
for command in docker sha256sum; do command -v "$command" >/dev/null || exit 2; done
case "${DOCKER_HOST:-}" in ''|unix:///*) ;; *) exit 2 ;; esac
case "$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')" in unix:///*) ;; *) exit 2 ;; esac
case "${OPENSHIELD_E2E_SKIP_PACKAGES:-0}" in 0|1) ;; *) exit 2 ;; esac
script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
evidence_directory=$(mktemp -d /tmp/openshield-enforcement-strategy-evidence.XXXXXX)
token=${evidence_directory##*/}
label="org.openshield.enforcement-strategy-e2e.run=$token"
network_id=
client_id=
peer_id=
stage=initialization
client_image=${OPENSHIELD_E2E_CLIENT_IMAGE:-opensuse/tumbleweed@sha256:8f6397b7b7ebc78e111d9a13fb2b157664ad5524e1f3b908deb45938b3095045}
peer_image=${OPENSHIELD_E2E_PEER_IMAGE:-python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285}
for image in "$client_image" "$peer_image"; do
    case "$image" in ''|-*|*[!A-Za-z0-9._/:@-]*) printf '%s\n' 'unsafe image reference' >&2; exit 2 ;; esac
done

cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ -n "$client_id" ]; then
        docker cp "$client_id:/tmp/enforcement-strategy/." "$evidence_directory/" >/dev/null 2>&1
        docker exec "$client_id" cat /tmp/openshield.log >"$evidence_directory/daemon.log" 2>&1
        docker exec "$client_id" cat /tmp/controller.log >"$evidence_directory/controller.log" 2>&1
        docker exec "$client_id" cat /proc/net/netfilter/nfnetlink_queue >"$evidence_directory/nfqueue.txt" 2>&1
        docker exec "$client_id" /bin/sh -c 'if command -v nft >/dev/null; then nft -a list ruleset; else iptables-save; ip6tables-save; fi' >"$evidence_directory/firewall.txt" 2>&1
    fi
    if [ -n "$peer_id" ]; then
        docker exec "$peer_id" cat /tmp/peer.jsonl >"$evidence_directory/peer.jsonl" 2>&1
        docker exec "$peer_id" cat /tmp/peer.error >"$evidence_directory/peer.error" 2>&1
    fi
    # Exact IDs originate solely from this invocation's labelled creations.
    [ -z "$client_id" ] || docker rm -f "$client_id" >/dev/null 2>&1 || result=1
    [ -z "$peer_id" ] || docker rm -f "$peer_id" >/dev/null 2>&1 || result=1
    [ -z "$network_id" ] || docker network rm "$network_id" >/dev/null 2>&1 || result=1
    printf 'backend=%s\nstage=%s\nresult=%s\nclient_image=%s\npeer_image=%s\n' \
        "$backend" "$stage" "$result" "$client_image" "$peer_image" >"$evidence_directory/run.txt"
    sha256sum "$daemon_binary" >>"$evidence_directory/run.txt"
    printf 'OpenShield enforcement strategy evidence: %s\n' "$evidence_directory"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
begin_stage() { stage=$1; printf '==> OpenShield enforcement strategy (%s): %s\n' "$backend" "$stage"; }
wait_file() {
    docker exec "$1" /bin/sh -c 'n=0; while [ "$n" -lt 300 ]; do [ ! -e "$1" ] || exit 0; n=$((n+1)); sleep 0.1; done; exit 1' strategy-wait "$2"
}

begin_stage 'create private DUT and independent peer'
if [ "${OPENSHIELD_E2E_SKIP_PACKAGES:-0}" = 1 ]; then
    network_id=$(docker network create --internal --label "$label" "openshield-strategy-$token")
else
    network_id=$(docker network create --label "$label" "openshield-strategy-$token")
fi
peer_id=$(docker create --platform linux/amd64 --label "$label" --network "$network_id" \
    --read-only --cap-drop ALL --security-opt no-new-privileges --security-opt label=disable \
    --pids-limit 64 --memory 128m --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m \
    --env PYTHONDONTWRITEBYTECODE=1 --env OPENSHIELD_STRATEGY_E2E=1 \
    --mount "type=bind,src=$script_directory,dst=/opt/e2e,readonly" "$peer_image" sleep infinity)
client_id=$(docker create --platform linux/amd64 --label "$label" --network "$network_id" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH \
    --security-opt no-new-privileges --security-opt label=disable --pids-limit 256 --memory 1g \
    --ulimit nofile=20000:20000 \
    --env PYTHONDONTWRITEBYTECODE=1 --env OPENSHIELD_STRATEGY_E2E=1 \
    --mount "type=bind,src=$daemon_binary,dst=/opt/openshield-daemon,readonly" \
    --mount "type=bind,src=$script_directory,dst=/opt/e2e,readonly" "$client_image" sleep infinity)
docker start "$peer_id" "$client_id" >/dev/null
peer_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$peer_id")
case "$peer_ip" in ''|*[!0-9.]*) exit 1 ;; esac
if [ "${OPENSHIELD_E2E_SKIP_PACKAGES:-0}" = 0 ]; then
    begin_stage 'provision disposable Tumbleweed DUT'
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
docker exec "$client_id" python3 /opt/e2e/enforcement-strategy.py seed
docker exec --detach "$peer_id" /bin/sh -c 'exec python3 /opt/e2e/enforcement-strategy.py serve >/tmp/peer.jsonl 2>/tmp/peer.error'
wait_file "$peer_id" /tmp/quota-peer.ready
docker exec --detach "$client_id" /bin/sh -c 'exec /opt/openshield-daemon >/tmp/openshield.log 2>&1'
wait_file "$client_id" /run/openshield/control.sock
begin_stage 'Learning, Strict, Fast, active rule revocation, Strict'
docker exec "$client_id" /bin/sh -c 'exec python3 /opt/e2e/enforcement-strategy.py run "$1" "$2" >/tmp/controller.log 2>&1' \
    strategy-controller "$peer_ip" "$backend"
begin_stage 'independent peer audit of all allowed and forbidden tokens'
docker exec "$peer_id" python3 /opt/e2e/enforcement-strategy.py audit /tmp/peer.jsonl \
    >"$evidence_directory/peer-audit.json"
begin_stage PASS
