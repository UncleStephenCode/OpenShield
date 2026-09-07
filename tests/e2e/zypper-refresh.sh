#!/bin/sh
# Provisioning helper for disposable E2E containers, before Python is installed.
set -eu

fail() {
    printf 'OpenShield E2E zypper: %s\n' "$*" >&2
    exit 1
}

[ -f /.dockerenv ] || fail 'this helper requires a disposable Docker container'
[ "$#" -eq 1 ] || fail 'expected one repository alias'
repository=$1
case "$repository" in
    openSUSE:repo-oss|repo-oss) ;;
    *) fail 'unsupported repository alias' ;;
esac

repositories=/etc/zypp/repos.d
if [ "${OPENSHIELD_E2E_TEST_ZYPPER_REPOS_DIR+x}" = x ]; then
    # The override is only for stub tests inside a disposable container.
    repositories=$OPENSHIELD_E2E_TEST_ZYPPER_REPOS_DIR
    case "$repositories" in
        /tmp/openshield-zypper-test.*) ;;
        *) fail 'test repository directory must be under /tmp/openshield-zypper-test.*' ;;
    esac
    test_directory_name=${repositories#/tmp/}
    case "$test_directory_name" in
        */*) fail 'test repository directory must be a direct child of /tmp' ;;
    esac
fi
[ -d "$repositories" ] && [ ! -L "$repositories" ] || fail 'invalid repository directory'
repository_file=$repositories/$repository.repo
[ -f "$repository_file" ] && [ ! -L "$repository_file" ] || fail 'repository must be a regular non-symlink file'

temporary=
trap '[ -z "$temporary" ] || rm -f -- "$temporary"' EXIT
trap 'exit 1' HUP INT TERM

# Validate every URL before replacing the original file. Parameter expansion
# preserves literal $basearch/${releasever}, whitespace, and other settings.
render_repository() {
    requested_origin=$1
    baseurl_count=0
    gpgkey_count=0
    while IFS= read -r line || [ -n "$line" ]; do
        setting=${line%%=*}
        setting=${setting#"${setting%%[![:space:]]*}"}
        setting=${setting%"${setting##*[![:space:]]}"}
        case "$setting" in
            baseurl|gpgkey)
                prefix=${line%%=*}
                value=${line#*=}
                leading=${value%%[![:space:]]*}
                value=${value#"$leading"}
                trailing=${value##*[![:space:]]}
                value=${value%"$trailing"}
                case "$value" in
                    *[[:space:]]*) fail 'repository URL must contain exactly one URL' ;;
                    *\?*|*\#*|*\\*) fail 'repository URL options and fragments are unsupported' ;;
                    http://cdn.opensuse.org/*) origin=cdn.opensuse.org; suffix=${value#http://cdn.opensuse.org} ;;
                    https://cdn.opensuse.org/*) origin=cdn.opensuse.org; suffix=${value#https://cdn.opensuse.org} ;;
                    http://download.opensuse.org/*) origin=download.opensuse.org; suffix=${value#http://download.opensuse.org} ;;
                    https://download.opensuse.org/*) origin=download.opensuse.org; suffix=${value#https://download.opensuse.org} ;;
                    *) fail 'repository URL must use the official download.opensuse.org or cdn.opensuse.org origin' ;;
                esac
                if [ "$setting" = baseurl ]; then
                    baseurl_count=$((baseurl_count + 1))
                    base_origin=$origin
                else
                    gpgkey_count=$((gpgkey_count + 1))
                fi
                [ -z "$requested_origin" ] || origin=$requested_origin
                printf '%s=%shttps://%s%s%s\n' "$prefix" "$leading" "$origin" "$suffix" "$trailing"
                ;;
            *) printf '%s\n' "$line" ;;
        esac
    done < "$repository_file"
    [ "$baseurl_count" -eq 1 ] || fail 'expected exactly one baseurl setting'
    [ "$gpgkey_count" -le 1 ] || fail 'expected at most one gpgkey setting'
}

rewrite_repository() {
    [ -f "$repository_file" ] && [ ! -L "$repository_file" ] || fail 'repository file changed type'
    temporary=$(mktemp "$repositories/.openshield-zypper.XXXXXX")
    cp -p -- "$repository_file" "$temporary"
    render_repository "$1" > "$temporary"
    if command -v cmp >/dev/null 2>&1 && cmp -s -- "$repository_file" "$temporary"; then
        rm -f -- "$temporary"
    else
        mv -f -- "$temporary" "$repository_file"
    fi
    temporary=
}

rewrite_repository ''
attempt=1
while :; do
    if [ "$attempt" -eq 1 ]; then
        if zypper --non-interactive refresh "$repository"; then exit 0; else status=$?; fi
    else
        # Fetch a fresh signed metadata index after switching official origins.
        if zypper --non-interactive refresh --force "$repository"; then exit 0; else status=$?; fi
    fi
    if [ "$status" -ne 4 ] || [ "$attempt" -ge 3 ]; then
        printf 'zypper refresh for %s failed after %s attempt(s) (status %s)\n' \
            "$repository" "$attempt" "$status" >&2
        exit "$status"
    fi
    case "$base_origin" in
        cdn.opensuse.org) next_origin=download.opensuse.org ;;
        download.opensuse.org) next_origin=cdn.opensuse.org ;;
    esac
    delay=$((attempt * 5))
    printf 'zypper refresh for %s failed (status %s); retrying via %s in %s seconds\n' \
        "$repository" "$status" "$next_origin" "$delay" >&2
    sleep "$delay"
    rewrite_repository "$next_origin"
    base_origin=$next_origin
    attempt=$((attempt + 1))
done
