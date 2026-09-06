#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

usage() {
    printf '%s\n' \
        'usage: scripts/test-init-matrix.sh validate' \
        '       scripts/test-init-matrix.sh images' \
        '       scripts/test-init-matrix.sh manifests' \
        '       scripts/test-init-matrix.sh containers' \
        '       scripts/test-init-matrix.sh containers-clean'
}

mode=${1:-}
case "$mode" in
    validate|images|manifests|containers|containers-clean)
        [ "$#" -eq 1 ] || { usage >&2; exit 2; }
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository_directory=$(CDPATH= cd -- "$script_directory/.." && pwd -P)
package_directory=$repository_directory/packaging
fixture_directory=$repository_directory/tests/compat

# Release-critical init fixtures are immutable and deliberately constrained to
# the amd64 userspace they were reviewed with.  They test parsers/supervisors,
# not distribution kernels or non-amd64 release packages.
init_platform=linux/amd64
alpine_image='alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce'
devuan_image='devuan/devuan:daedalus@sha256:878e7d497ed8bb3333e85186cc9b8b89ed19270e13f770ea784b1cfbef695a00'
void_image='voidlinux/voidlinux:latest@sha256:26ba972f0c06beadcec4796ec3037e0bec32af4d255edb68a528bd98304c74f4'
artix_openrc_image='artixlinux/artixlinux:base-openrc@sha256:09d7ca64ca40db4ffa8f8e97f7bdac8969f9f4a8f791e42d82a6b2377d40ce71'
artix_s6_image='artixlinux/artixlinux:base-s6@sha256:e563ae1357cf6cd7c6df858b795db8ddf23ffa6ab1888739b91a33da189cf82b'
artix_dinit_image='artixlinux/artixlinux:base-dinit@sha256:234cf62105d8a5a10caebb9b62dadc271d33eccc9fd41399453e20004a8e319a'

temporary_directory=$(mktemp -d /tmp/openshield-init-matrix.XXXXXX)
new_images=$temporary_directory/new-images
: > "$new_images"
clean_images=false
[ "$mode" = containers-clean ] && clean_images=true

cleanup() {
    if [ "$clean_images" = true ] && command -v docker >/dev/null 2>&1; then
        while IFS= read -r cleanup_image; do
            [ -n "$cleanup_image" ] || continue
            docker image rm "$cleanup_image" >/dev/null 2>&1 \
                || printf 'WARN image cleanup failed: %s\n' "$cleanup_image" >&2
        done < "$new_images"
    fi
    case "$temporary_directory" in
        /tmp/openshield-init-matrix.*)
            rm -rf -- "$temporary_directory"
            ;;
        *)
            printf 'refusing unsafe temporary cleanup: %s\n' "$temporary_directory" >&2
            ;;
    esac
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
    printf 'FAIL %s\n' "$*" >&2
    exit 1
}

print_init_images() {
    printf '%s\t%s\t%s\n' \
        alpine-openrc "$alpine_image" "$init_platform" \
        devuan-sysvinit "$devuan_image" "$init_platform" \
        void-runit "$void_image" "$init_platform" \
        artix-openrc "$artix_openrc_image" "$init_platform" \
        artix-s6 "$artix_s6_image" "$init_platform" \
        artix-dinit "$artix_dinit_image" "$init_platform"
}

expect_file() {
    [ -f "$1" ] || fail "missing staged file: $1"
}

expect_executable() {
    [ -f "$1" ] && [ -x "$1" ] || fail "staged file is not executable: $1"
}

validate_sources() {
    for shell_file in \
        "$package_directory/ensure-group.sh" \
        "$package_directory/stage-install.sh" \
        "$package_directory/openrc/openshield" \
        "$package_directory/sysvinit/openshield" \
        "$package_directory/runit/openshield/run" \
        "$package_directory/runit/openshield/finish" \
        "$package_directory/runit/openshield/check" \
        "$package_directory/s6/openshield/run" \
        "$package_directory/s6/openshield/finish" \
        "$package_directory/dinit/dinit-preflight" \
        "$fixture_directory/init-stub-daemon.sh" \
        "$fixture_directory/init-stub-group.sh"
    do
        /bin/sh -n "$shell_file"
    done

    systemd_unit=$package_directory/daemon/openshield-daemon.service
    expected_capabilities='CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_PTRACE CAP_DAC_READ_SEARCH'
    ambient_capabilities=$(sed -n 's/^AmbientCapabilities=//p' "$systemd_unit")
    bounding_capabilities=$(sed -n 's/^CapabilityBoundingSet=//p' "$systemd_unit")
    [ "$ambient_capabilities" = "$expected_capabilities" ] \
        || fail 'systemd AmbientCapabilities is not the exact required capability set'
    [ "$bounding_capabilities" = "$expected_capabilities" ] \
        || fail 'systemd CapabilityBoundingSet is not the exact required capability set'
    [ "$ambient_capabilities" = "$bounding_capabilities" ] \
        || fail 'systemd ambient and bounding capability sets differ'
    [ "$(sed -n 's/^User=//p' "$systemd_unit")" = root ] \
        || fail 'systemd daemon user is not root'
    [ "$(sed -n 's/^Group=//p' "$systemd_unit")" = root ] \
        || fail 'systemd daemon primary group is not root'
    [ "$(sed -n 's/^SupplementaryGroups=//p' "$systemd_unit")" = openshield ] \
        || fail 'systemd daemon does not have the exact observation supplementary group'
    if grep -Eq '^(RuntimeDirectory|StateDirectory)' "$systemd_unit"; then
        fail 'systemd special directories would recursively change preserved ownership'
    fi
    [ "$(sed -n 's/^RequiresMountsFor=//p' "$systemd_unit")" \
        = '/run/openshield /var/lib/openshield' ] \
        || fail 'systemd unit does not retain explicit runtime/state mount dependencies'

    tmpfiles=$package_directory/daemon/openshield.tmpfiles
    for declaration in \
        'd /run/openshield 0755 root root -' \
        'z /run/openshield 0755 root root -' \
        'd /var/lib/openshield 0700 root root -' \
        'z /var/lib/openshield 0700 root root -' \
        'f /run/xtables.lock 0600 root root -' \
        'z /run/xtables.lock 0600 root root -'
    do
        grep -Fqx "$declaration" "$tmpfiles" \
            || fail "missing tmpfiles declaration: $declaration"
    done
    [ "$(sed '/^[[:space:]]*#/d; /^[[:space:]]*$/d' "$tmpfiles" | wc -l)" -eq 6 ] \
        || fail 'tmpfiles declaration exposes unexpected filesystem paths'
    if command -v systemd-tmpfiles >/dev/null 2>&1 \
        && systemd-tmpfiles --help | grep -Fq -- '--dry-run'; then
        systemd-tmpfiles --create --dry-run "$tmpfiles" >/dev/null 2>&1 \
            || fail 'systemd-tmpfiles rejected the create/relabel declaration'
    fi

    [ "$(sed -n '1p' "$package_directory/s6/openshield/type")" = longrun ] \
        || fail 's6 service type is not longrun'
    grep -q '^type = process$' "$package_directory/dinit/openshield" \
        || fail 'dinit daemon is not a process service'
    grep -q '^type = scripted$' "$package_directory/dinit/openshield-preflight" \
        || fail 'dinit preflight is not a scripted service'
    grep -q '^stop-command = /usr/bin/openshield-daemon --install-fail-closed$' \
        "$package_directory/dinit/openshield-preflight" \
        || fail 'dinit stop path is not fail-closed'
    grep -q '^[[:space:]]*before net$' "$package_directory/openrc/openshield" \
        || fail 'OpenRC service is not ordered before net'

    binary_directory=$temporary_directory/bin
    install -d -m 0755 "$binary_directory"
    install -m 0755 /bin/true "$binary_directory/openshield-daemon"
    install -m 0755 /bin/true "$binary_directory/openshield-tui"

    for init_system in systemd openrc sysvinit runit s6 dinit; do
        destination=$temporary_directory/stage-$init_system
        install -d -m 0755 "$destination"
        "$package_directory/stage-install.sh" "$destination" "$init_system" "$binary_directory" \
            >/dev/null
        expect_executable "$destination/usr/bin/openshield-daemon"
        expect_executable "$destination/usr/bin/openshield-tui"
        expect_executable "$destination/usr/libexec/openshield/ensure-group"
        expect_file "$destination/usr/share/openshield/LICENSE"
        case "$init_system" in
            systemd)
                expect_file "$destination/usr/lib/systemd/system/openshield-daemon.service"
                expect_file "$destination/usr/lib/sysusers.d/openshield.conf"
                expect_file "$destination/usr/lib/tmpfiles.d/openshield.conf"
                ;;
            openrc|sysvinit)
                expect_executable "$destination/etc/init.d/openshield"
                ;;
            runit)
                expect_executable "$destination/etc/sv/openshield/run"
                expect_executable "$destination/etc/sv/openshield/finish"
                expect_executable "$destination/etc/sv/openshield/check"
                ;;
            s6)
                expect_executable "$destination/etc/s6/sv/openshield/run"
                expect_executable "$destination/etc/s6/sv/openshield/finish"
                expect_file "$destination/etc/s6/sv/openshield/type"
                expect_file "$destination/etc/s6/sv/openshield/timeout-kill"
                expect_file "$destination/etc/s6/sv/openshield/timeout-finish"
                expect_file "$destination/etc/s6/sv/openshield/dependencies.d/mount-filesystems"
                ;;
            dinit)
                expect_file "$destination/etc/dinit.d/openshield"
                expect_file "$destination/etc/dinit.d/openshield-preflight"
                expect_executable "$destination/usr/libexec/openshield/dinit-preflight"
                ;;
        esac
    done

    redirect_target=$temporary_directory/redirect-target
    redirect_destination=$temporary_directory/redirect-destination
    install -d -m 0755 "$redirect_target"
    ln -s "$redirect_target" "$redirect_destination"
    if "$package_directory/stage-install.sh" "$redirect_destination" openrc "$binary_directory" \
        >/dev/null 2>&1; then
        fail 'stage installer accepted a symbolic-link DESTDIR'
    fi

    tainted_destination=$temporary_directory/tainted-destination
    install -d -m 0755 "$tainted_destination"
    ln -s "$redirect_target" "$tainted_destination/redirect"
    if "$package_directory/stage-install.sh" "$tainted_destination" openrc "$binary_directory" \
        >/dev/null 2>&1; then
        fail 'stage installer accepted a symlink inside DESTDIR'
    fi

    writable_destination=$temporary_directory/writable-destination
    install -d -m 0755 "$writable_destination"
    install -d -m 0777 "$writable_destination/untrusted"
    if "$package_directory/stage-install.sh" "$writable_destination" openrc "$binary_directory" \
        >/dev/null 2>&1; then
        fail 'stage installer accepted a writable directory inside DESTDIR'
    fi

    linked_destination=$temporary_directory/linked-destination
    linked_target=$temporary_directory/linked-target
    install -d -m 0755 "$linked_destination"
    : > "$linked_target"
    ln "$linked_target" "$linked_destination/prepared-hardlink"
    if "$package_directory/stage-install.sh" "$linked_destination" openrc "$binary_directory" \
        >/dev/null 2>&1; then
        fail 'stage installer accepted a multiply-linked file inside DESTDIR'
    fi

    printf '%s\n' \
        'PASS static: shell syntax, staged layouts, modes, and unsafe-tree rejection'
}

require_local_docker() {
    command -v docker >/dev/null 2>&1 || fail 'docker is not installed'
    docker_host=$(docker context inspect --format '{{(index .Endpoints "docker").Host}}' 2>/dev/null) \
        || fail 'cannot inspect the active Docker context'
    case "$docker_host" in
        unix:///*) ;;
        *) fail "refusing non-local Docker endpoint: $docker_host" ;;
    esac
}

record_new_images() {
    for container_image in \
        "$alpine_image" \
        "$devuan_image" \
        "$void_image" \
        "$artix_openrc_image" \
        "$artix_s6_image" \
        "$artix_dinit_image"
    do
        docker image inspect "$container_image" >/dev/null 2>&1 \
            || printf '%s\n' "$container_image" >> "$new_images"
    done
}

check_manifests() {
    require_local_docker
    manifest_failures=0
    for container_image in \
        "$alpine_image" \
        "$devuan_image" \
        "$void_image" \
        "$artix_openrc_image" \
        "$artix_s6_image" \
        "$artix_dinit_image"
    do
        if docker buildx imagetools inspect "$container_image" >/dev/null 2>&1; then
            printf 'PASS manifest: %s\n' "$container_image"
        else
            printf 'FAIL manifest: %s\n' "$container_image" >&2
            manifest_failures=$((manifest_failures + 1))
        fi
    done
    [ "$manifest_failures" -eq 0 ] || fail "$manifest_failures init images unavailable"
}

run_container_checks() {
    require_local_docker
    record_new_images

    # These two overlays are intentionally writable: groupadd/addgroup must
    # update their own ephemeral /etc.  They have no network or host mounts
    # other than the read-only helper under test.
    docker run --rm --platform "$init_platform" --network none --cap-drop ALL \
        --security-opt no-new-privileges --security-opt label=disable \
        --mount "type=bind,src=$package_directory,dst=/pkg,readonly" \
        --mount "type=bind,src=$repository_directory/LICENSE,dst=/LICENSE,readonly" \
        "$alpine_image" /bin/sh -ec \
        'for script in /pkg/ensure-group.sh /pkg/stage-install.sh /pkg/openrc/openshield /pkg/sysvinit/openshield /pkg/runit/openshield/run /pkg/runit/openshield/finish /pkg/runit/openshield/check /pkg/s6/openshield/run /pkg/s6/openshield/finish /pkg/dinit/dinit-preflight; do /bin/sh -n "$script"; done; /bin/sh /pkg/ensure-group.sh; /bin/sh /pkg/ensure-group.sh; getent group openshield >/dev/null; install -d -m 0755 /tmp/bin /tmp/stage; install -m 0755 /bin/true /tmp/bin/openshield-daemon; install -m 0755 /bin/true /tmp/bin/openshield-tui; /bin/sh /pkg/stage-install.sh /tmp/stage openrc /tmp/bin >/dev/null; test -x /tmp/stage/etc/init.d/openshield'
    printf '%s\n' \
        'PASS runtime: Alpine/BusyBox parsed scripts, staged safely, and kept addgroup idempotent'

    docker run --rm --platform "$init_platform" --network none --cap-drop ALL \
        --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER \
        --security-opt no-new-privileges --security-opt label=disable \
        --mount "type=bind,src=$package_directory/ensure-group.sh,dst=/test/ensure-group,readonly" \
        "$devuan_image" /bin/sh -ec \
        '/bin/sh /test/ensure-group; /bin/sh /test/ensure-group; getent group openshield >/dev/null'
    printf '%s\n' 'PASS runtime: Devuan/shadow groupadd is idempotent in an isolated overlay'

    docker run --rm --platform "$init_platform" --network none --read-only --cap-drop ALL \
        --security-opt no-new-privileges --security-opt label=disable \
        --tmpfs /etc/init.d:rw,exec,nosuid,nodev,mode=0755 \
        --mount "type=bind,src=$temporary_directory/stage-openrc/etc/init.d/openshield,dst=/staged/openshield,readonly" \
        "$artix_openrc_image" /bin/sh -ec \
        'cp /staged/openshield /etc/init.d/openshield; chmod 0755 /etc/init.d/openshield; /etc/init.d/openshield describe >/dev/null'
    printf '%s\n' 'PASS parser: Artix OpenRC loaded the service without running the firewall'

    docker run --rm --platform "$init_platform" --network none --read-only --cap-drop ALL \
        --security-opt no-new-privileges --security-opt label=disable \
        --tmpfs /run:rw,nosuid,nodev,mode=0755 \
        --mount "type=bind,src=$temporary_directory/stage-sysvinit/etc/init.d/openshield,dst=/staged/openshield,readonly" \
        "$devuan_image" /bin/sh -ec '
            /bin/sh -n /staged/openshield
            start-stop-daemon --start --test --quiet --background --make-pidfile --pidfile /run/openshield-test.pid --exec /bin/true --startas /bin/true
            /bin/sleep 30 & service_pid=$!
            trap '\''kill "$service_pid" 2>/dev/null || true; wait "$service_pid" 2>/dev/null || true'\'' EXIT
            printf "%s\n" "$service_pid" > /run/openshield-test.pid
            # The background PID exists before exec completes. Wait for the
            # actual executable, not a delay or the assertion being tested.
            expected_executable=$(readlink -f /bin/sleep)
            count=0
            while [ "$(readlink "/proc/$service_pid/exe" 2>/dev/null || true)" != "$expected_executable" ]; do
                if ! kill -0 "$service_pid" 2>/dev/null || [ "$count" -ge 50 ]; then
                    printf "%s\n" "FAIL Devuan fixture did not exec /bin/sleep within 5 seconds" >&2
                    exit 1
                fi
                sleep 0.1
                count=$((count + 1))
            done
            if ! start-stop-daemon --stop --test --quiet --pidfile /run/openshield-test.pid --exec /bin/sleep >/dev/null; then
                printf "%s\n" "FAIL Devuan rejected the ready PID and matching executable" >&2
                exit 1
            fi
            if start-stop-daemon --stop --test --quiet --pidfile /run/openshield-test.pid --exec /bin/false >/dev/null 2>&1; then
                printf "%s\n" "FAIL Devuan accepted a mismatched PID executable" >&2
                exit 1
            fi
        ' || fail 'Devuan SysV start-stop-daemon container check failed'
    printf '%s\n' 'PASS runtime: Devuan accepted SysV options and rejected a mismatched PID executable'

    docker run --rm --platform "$init_platform" --network none --read-only --cap-drop ALL \
        --security-opt no-new-privileges --security-opt label=disable \
        --tmpfs /service:rw,exec,nosuid,nodev,mode=0755 \
        --tmpfs /run:rw,exec,nosuid,nodev,mode=0755 \
        --tmpfs /var/lib/openshield:rw,nosuid,nodev,mode=0700 \
        --mount "type=bind,src=$temporary_directory/stage-runit/etc/sv/openshield,dst=/pkgservice,readonly" \
        --mount "type=bind,src=$fixture_directory/init-stub-daemon.sh,dst=/usr/bin/openshield-daemon,readonly" \
        --mount "type=bind,src=$fixture_directory/init-stub-group.sh,dst=/usr/libexec/openshield/ensure-group,readonly" \
        "$void_image" /bin/sh -ec '
            cp -R /pkgservice/. /service/
            chmod 0755 /service/run /service/finish /service/check
            runsv /service & supervisor=$!
            count=0
            while [ ! -s /service/supervise/pid ] && [ "$count" -lt 50 ]; do sleep 0.1; count=$((count + 1)); done
            [ -s /service/supervise/pid ]
            grep -q "^run$" /run/openshield-init-stub.log
            sv -w 5 down /service
            preflights=$(grep -c "^preflight$" /run/openshield-init-stub.log)
            [ "$preflights" -ge 2 ]
            sv exit /service
            wait "$supervisor"
        '
    printf '%s\n' 'PASS runtime: Void runit executed preflight, daemon lifecycle, and finish quarantine'

    docker run --rm --platform "$init_platform" --network none --read-only --cap-drop ALL \
        --security-opt no-new-privileges --security-opt label=disable \
        --tmpfs /work:rw,exec,nosuid,nodev,mode=0755 \
        --mount "type=bind,src=$temporary_directory/stage-s6/etc/s6/sv/openshield,dst=/staged-openshield,readonly" \
        "$artix_s6_image" /bin/sh -ec \
        'mkdir -p /work/source/mount-filesystems; printf "oneshot\n" > /work/source/mount-filesystems/type; printf "#!/bin/sh\nexit 0\n" > /work/source/mount-filesystems/up; chmod 0755 /work/source/mount-filesystems/up; cp -R /staged-openshield /work/source/openshield; s6-rc-compile /work/compiled /work/source; s6-rc-db -c /work/compiled dependencies openshield | grep -qx mount-filesystems'
    printf '%s\n' 'PASS parser: Artix s6-rc compiled OpenShield as a longrun service'

    docker run --rm --platform "$init_platform" --network none --read-only --cap-drop ALL \
        --security-opt no-new-privileges --security-opt label=disable \
        --tmpfs /service:rw,exec,nosuid,nodev,mode=0755 \
        --tmpfs /run:rw,exec,nosuid,nodev,mode=0755 \
        --tmpfs /var/lib/openshield:rw,nosuid,nodev,mode=0700 \
        --mount "type=bind,src=$temporary_directory/stage-s6/etc/s6/sv/openshield,dst=/pkgservice,readonly" \
        --mount "type=bind,src=$fixture_directory/init-stub-daemon.sh,dst=/usr/bin/openshield-daemon,readonly" \
        --mount "type=bind,src=$fixture_directory/init-stub-group.sh,dst=/usr/libexec/openshield/ensure-group,readonly" \
        "$artix_s6_image" /bin/sh -ec '
            cp -R /pkgservice/. /service/
            chmod 0755 /service/run /service/finish
            s6-supervise /service & supervisor=$!
            s6-svwait -u -t 5000 /service
            count=0
            while ! grep -q "^run$" /run/openshield-init-stub.log 2>/dev/null && [ "$count" -lt 50 ]; do sleep 0.1; count=$((count + 1)); done
            grep -q "^run$" /run/openshield-init-stub.log
            s6-svc -d /service
            s6-svwait -d -t 5000 /service
            count=0
            preflights=$(grep -c "^preflight$" /run/openshield-init-stub.log)
            while [ "$preflights" -lt 2 ] && [ "$count" -lt 50 ]; do sleep 0.1; count=$((count + 1)); preflights=$(grep -c "^preflight$" /run/openshield-init-stub.log); done
            [ "$preflights" -ge 2 ]
            s6-svc -x /service
            wait "$supervisor"
        '
    printf '%s\n' 'PASS runtime: Artix s6 executed preflight, daemon lifecycle, and finish quarantine'

    docker run --rm --platform "$init_platform" --network none --read-only --cap-drop ALL \
        --security-opt no-new-privileges --security-opt label=disable \
        --mount "type=bind,src=$temporary_directory/stage-dinit/etc/dinit.d,dst=/staged-dinit,readonly" \
        --mount type=bind,src=/bin/true,dst=/usr/bin/openshield-daemon,readonly \
        --mount "type=bind,src=$temporary_directory/stage-dinit/usr/libexec/openshield/dinit-preflight,dst=/usr/libexec/openshield/dinit-preflight,readonly" \
        "$artix_dinit_image" /usr/sbin/dinit-check \
        --services-dir /staged-dinit openshield
    printf '%s\n' 'PASS parser: Artix dinit-check found no service-description problems'

    printf '%s\n' 'NOTE real firewall/backend startup is intentionally outside this init parser/supervisor test'
}

case "$mode" in
    validate)
        validate_sources
        ;;
    images)
        print_init_images
        ;;
    manifests)
        check_manifests
        ;;
    containers|containers-clean)
        validate_sources
        run_container_checks
        ;;
esac
