#!/bin/sh
# Container-only firewall regression. Mounts a built candidate read-only;
# requires local Docker, a Linux amd64 daemon binary, and the pinned images.
# Optional pre-provisioned images: OPENSHIELD_E2E_CLIENT_IMAGE,
# OPENSHIELD_E2E_PEER_IMAGE, OPENSHIELD_E2E_SKIP_PACKAGES=1. The client needs
# python3, shadow, coreutils, iptables, and (only for nftables) nftables.
# A pre-provisioned iptables client must not expose nft: daemon discovery
# prefers nftables and the test verifies that the requested backend is active.
set -eu

[ "$#" = 2 ] || { printf 'usage: sh %s {nftables|iptables} ABSOLUTE_DAEMON_BINARY\n' "$0" >&2; exit 2; }
backend=$1
daemon_binary=$2
case "$backend" in nftables|iptables) ;; *) exit 2 ;; esac
case "$daemon_binary" in /*) ;; *) exit 2 ;; esac
[ -f "$daemon_binary" ] && [ -x "$daemon_binary" ] && [ ! -L "$daemon_binary" ] || exit 2
for command in docker sha256sum; do command -v "$command" >/dev/null || exit 2; done
case "${DOCKER_HOST:-}" in ''|unix:///*) ;; *) exit 2 ;; esac
case "$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')" in unix:///*) ;; *) exit 2 ;; esac
case "${OPENSHIELD_E2E_SKIP_PACKAGES:-0}" in 0|1) ;; *) exit 2 ;; esac
script_directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
evidence_directory=$(mktemp -d /tmp/openshield-outbound-group-evidence.XXXXXX)
token=${evidence_directory##*/}
label="org.openshield.outbound-group-e2e.run=$token"
network_id=
client_id=
target_id=
other_id=
stage=initialization
client_image=${OPENSHIELD_E2E_CLIENT_IMAGE:-opensuse/tumbleweed@sha256:8f6397b7b7ebc78e111d9a13fb2b157664ad5524e1f3b908deb45938b3095045}
peer_image=${OPENSHIELD_E2E_PEER_IMAGE:-python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285}

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    set +e
    if [ -n "$client_id" ]; then
        docker cp "$client_id:/tmp/outbound-group/." "$evidence_directory/" >/dev/null 2>&1
        docker exec "$client_id" cat /tmp/openshield.log >"$evidence_directory/daemon.log" 2>&1
        docker exec "$client_id" python3 /opt/e2e/ipc_client.py status >"$evidence_directory/status-final.json" 2>&1
        docker exec "$client_id" /bin/sh -c 'if command -v nft >/dev/null; then nft -a list ruleset; else iptables-save; ip6tables-save; fi' >"$evidence_directory/firewall-final.txt" 2>&1
    fi
    for role in target other; do
        peer_id=$target_id
        [ "$role" != other ] || peer_id=$other_id
        if [ -n "$peer_id" ]; then
            docker exec "$peer_id" cat /tmp/peer.jsonl >"$evidence_directory/$role-peer.jsonl" 2>&1
            docker exec "$peer_id" cat /tmp/peer.error >"$evidence_directory/$role-peer.error" 2>&1
        fi
    done
    printf 'backend=%s\nbinary=%s\nclient_image=%s\npeer_image=%s\nstage=%s\nresult=%s\n' "$backend" "$daemon_binary" "$client_image" "$peer_image" "$stage" "$status" >"$evidence_directory/run.txt"
    sha256sum "$daemon_binary" >>"$evidence_directory/run.txt"
    # These IDs come only from this run's labelled create operations.
    [ -z "$client_id" ] || docker rm -f "$client_id" >/dev/null 2>&1 || status=1
    [ -z "$target_id" ] || docker rm -f "$target_id" >/dev/null 2>&1 || status=1
    [ -z "$other_id" ] || docker rm -f "$other_id" >/dev/null 2>&1 || status=1
    [ -z "$network_id" ] || docker network rm "$network_id" >/dev/null 2>&1 || status=1
    printf 'OpenShield outbound group evidence: %s\n' "$evidence_directory"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

begin_stage() { stage=$1; printf '==> OpenShield outbound groups (%s): %s\n' "$backend" "$stage"; }
wait_file() {
    docker exec "$1" /bin/sh -c 'n=0; while [ "$n" -lt 300 ]; do [ ! -f "$1" ] || exit 0; n=$((n+1)); sleep 0.1; done; exit 1' group-wait "$2"
}

begin_stage 'create private client and two independent peers'
network_id=$(docker network create --label "$label" "openshield-group-$token")
for role in target other; do
    peer_id=$(docker create --platform linux/amd64 --label "$label" --network "$network_id" --read-only --cap-drop ALL --security-opt no-new-privileges --security-opt label=disable --pids-limit 64 --memory 128m --tmpfs /tmp:rw,nosuid,nodev,noexec,size=32m --env PYTHONDONTWRITEBYTECODE=1 --env OPENSHIELD_OUTBOUND_GROUP_E2E=1 --mount "type=bind,src=$script_directory,dst=/opt/e2e,readonly" "$peer_image" sleep infinity)
    if [ "$role" = target ]; then target_id=$peer_id; else other_id=$peer_id; fi
done
client_id=$(docker create --platform linux/amd64 --label "$label" --network "$network_id" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH --security-opt no-new-privileges --security-opt label=disable --pids-limit 512 --memory 1g --env PYTHONDONTWRITEBYTECODE=1 --env OPENSHIELD_OUTBOUND_GROUP_E2E=1 --mount "type=bind,src=$daemon_binary,dst=/opt/openshield-daemon,readonly" --mount "type=bind,src=$script_directory,dst=/opt/e2e,readonly" "$client_image" sleep infinity)
docker start "$target_id" "$other_id" "$client_id" >/dev/null
target_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$target_id")
other_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$other_id")
case "$target_ip" in ''|*[!0-9.]*) exit 1 ;; esac
case "$other_ip" in ''|*[!0-9.]*) exit 1 ;; esac
[ "$target_ip" != "$other_ip" ] || exit 1

if [ "${OPENSHIELD_E2E_SKIP_PACKAGES:-0}" = 0 ]; then
    begin_stage 'install test dependencies inside the client'
    attempt=1
    while ! docker exec "$client_id" zypper --non-interactive refresh repo-oss >/dev/null; do
        [ "$attempt" -lt 3 ] || exit 1
        sleep "$((attempt*5))"
        attempt=$((attempt+1))
    done
    packages='iptables python3 shadow coreutils'
    [ "$backend" != nftables ] || packages="$packages nftables"
    # shellcheck disable=SC2086
    docker exec "$client_id" zypper --non-interactive --no-refresh install --no-recommends --repo repo-oss $packages >/dev/null
fi
docker exec "$client_id" /bin/sh -c '
    getent group openshield >/dev/null || groupadd --system openshield
    install -d -m 0755 -o root -g root /run/openshield /tmp/outbound-group
    install -d -m 0700 -o root -g root /var/lib/openshield
    [ ! -e /var/lib/openshield/state.json ]
'
for role in target other; do
    peer_id=$target_id
    peer_ip=$target_ip
    if [ "$role" = other ]; then peer_id=$other_id; peer_ip=$other_ip; fi
    docker exec --detach "$peer_id" /bin/sh -c 'exec python3 /opt/e2e/outbound-group.py serve "$1" >/tmp/peer.jsonl 2>/tmp/peer.error' group-peer "$peer_ip"
    wait_file "$peer_id" /tmp/outbound-group-peer.ready
done

begin_stage 'start private daemon and execute group controls'
docker exec --detach "$client_id" /bin/sh -c 'exec /opt/openshield-daemon >/tmp/openshield.log 2>&1'
docker exec "$client_id" /bin/sh -c 'n=0; while [ "$n" -lt 300 ]; do [ ! -S /run/openshield/control.sock ] || exit 0; n=$((n+1)); sleep 0.1; done; exit 1'
docker exec "$client_id" /bin/sh -c 'exec python3 /opt/e2e/outbound-group.py run "$1" "$2" "$3" >/tmp/outbound-group/controller.jsonl 2>/tmp/outbound-group/controller.error' group-run "$target_ip" "$other_ip" "$backend"

begin_stage 'audit independent peer receipts'
for role in target other; do
    peer_id=$target_id
    [ "$role" != other ] || peer_id=$other_id
    # Docker's copy archive can miss files in the peer's /tmp tmpfs mount.
    docker exec "$peer_id" cat /tmp/peer.jsonl >"$evidence_directory/$role-peer.jsonl"
    docker exec "$peer_id" cat /tmp/peer.error >"$evidence_directory/$role-peer.error"
    docker cp "$evidence_directory/$role-peer.jsonl" "$client_id:/tmp/outbound-group/$role-peer.jsonl" >/dev/null
    docker cp "$evidence_directory/$role-peer.error" "$client_id:/tmp/outbound-group/$role-peer.error" >/dev/null
done
docker exec "$client_id" /bin/sh -c 'exec python3 /opt/e2e/outbound-group.py analyze /tmp/outbound-group >/tmp/outbound-group/analysis.jsonl 2>/tmp/outbound-group/analysis.error'
