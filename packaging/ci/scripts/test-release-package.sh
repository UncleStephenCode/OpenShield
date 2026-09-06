#!/usr/bin/env bash
set -euo pipefail

: "${FAMILY:?FAMILY is required}"
: "${IMAGE:?IMAGE is required}"
: "${PLATFORM:?PLATFORM is required}"
: "${EXPECTED_PACKAGE_ARCH:?EXPECTED_PACKAGE_ARCH is required}"
: "${EXPECTED_VERSION:?EXPECTED_VERSION is required}"
: "${EXPECTED_ELF_MACHINE:?EXPECTED_ELF_MACHINE is required}"

fail() {
  printf 'test-release-package: %s\n' "$*" >&2
  exit 2
}

case "$FAMILY" in
  deb|fedora|el9|el10|opensuse|tumbleweed|alpine|arch) ;;
  *) fail "unsupported FAMILY=$FAMILY" ;;
esac

# Release tests must be reproducible and must not let a matrix value be parsed
# as a Docker option. Restrict image references to conventional repository
# components, an optional registry port/tag, and an immutable lowercase digest.
image_pattern='^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)*(:[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?@sha256:[0-9a-f]{64}$'
[[ "$IMAGE" =~ $image_pattern ]] || fail 'IMAGE must be a pinned repository@sha256:64hex reference'

case "$PLATFORM" in
  linux/amd64)
    EXPECTED_ELF_CLASS=ELF64
    EXPECTED_ELF_DATA='little endian'
    platform_elf_machine='Advanced Micro Devices X86-64'
    ;;
  linux/arm64)
    EXPECTED_ELF_CLASS=ELF64
    EXPECTED_ELF_DATA='little endian'
    platform_elf_machine=AArch64
    ;;
  linux/386)
    EXPECTED_ELF_CLASS=ELF32
    EXPECTED_ELF_DATA='little endian'
    platform_elf_machine='Intel 80386'
    ;;
  linux/arm/v5|linux/arm/v6|linux/arm/v7)
    EXPECTED_ELF_CLASS=ELF32
    EXPECTED_ELF_DATA='little endian'
    platform_elf_machine=ARM
    ;;
  linux/ppc64le)
    EXPECTED_ELF_CLASS=ELF64
    EXPECTED_ELF_DATA='little endian'
    platform_elf_machine=PowerPC64
    ;;
  linux/s390x)
    EXPECTED_ELF_CLASS=ELF64
    EXPECTED_ELF_DATA='big endian'
    platform_elf_machine='IBM S/390'
    ;;
  linux/riscv64)
    EXPECTED_ELF_CLASS=ELF64
    EXPECTED_ELF_DATA='little endian'
    platform_elf_machine='RISC-V'
    ;;
  *) fail "unsupported PLATFORM=$PLATFORM" ;;
esac
[[ "$EXPECTED_ELF_MACHINE" == "$platform_elf_machine" ]] || {
  fail "EXPECTED_ELF_MACHINE=$EXPECTED_ELF_MACHINE does not match PLATFORM=$PLATFORM"
}

package_arch_pattern='^[A-Za-z0-9][A-Za-z0-9._+-]*$'
[[ "$EXPECTED_PACKAGE_ARCH" =~ $package_arch_pattern ]] || fail 'unsafe EXPECTED_PACKAGE_ARCH'
version_pattern='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
[[ "$EXPECTED_VERSION" =~ $version_pattern ]] \
  || fail 'EXPECTED_VERSION must be a semantic version without a v prefix'

version_core=${EXPECTED_VERSION%%[-+]*}
version_prerelease=
version_build=
version_suffix=${EXPECTED_VERSION#"$version_core"}
if [[ "$version_suffix" == -* ]]; then
  version_prerelease=${version_suffix#-}
  version_prerelease=${version_prerelease%%+*}
fi
if [[ "$version_suffix" == *+* ]]; then
  version_build=${version_suffix#*+}
fi

command -v docker >/dev/null 2>&1 || fail 'docker is not installed'
if [[ -n ${DOCKER_HOST:-} && -z ${DOCKER_CONTEXT:-} ]]; then
  # DOCKER_HOST overrides the active context unless DOCKER_CONTEXT is set.
  docker_host=$DOCKER_HOST
else
  docker_host=$(docker context inspect --format '{{(index .Endpoints "docker").Host}}' 2>/dev/null) \
    || fail 'cannot inspect the active Docker context'
fi
docker_host_pattern='^unix:///[A-Za-z0-9._/-]+$'
[[ "$docker_host" =~ $docker_host_pattern ]] \
  || fail "refusing non-local Docker endpoint: $docker_host"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
DIST="$REPO_ROOT/dist"
[[ -d "$DIST" && ! -L "$DIST" ]] || fail 'dist must be a real directory'

shopt -s nullglob
case "$FAMILY" in
  deb) package_candidates=("$DIST"/*.deb) ;;
  fedora|el9|el10|opensuse|tumbleweed) package_candidates=("$DIST"/*.rpm) ;;
  alpine) package_candidates=("$DIST"/*.apk) ;;
  arch) package_candidates=("$DIST"/*.pkg.tar.zst) ;;
esac
shopt -u nullglob
(( ${#package_candidates[@]} == 1 )) || {
  fail "expected exactly one $FAMILY package, found ${#package_candidates[@]}"
}
package_path=${package_candidates[0]}
[[ -f "$package_path" && ! -L "$package_path" ]] \
  || fail 'package must be a regular non-symlink file'
PACKAGE_BASENAME=${package_path##*/}
package_name_pattern='^[A-Za-z0-9][A-Za-z0-9._+~-]*$'
[[ "$PACKAGE_BASENAME" =~ $package_name_pattern ]] || fail 'unsafe package filename'

EXPECTED_RPM_RELEASE=
case "$FAMILY" in
  deb)
    # nFPM's semver schema maps prereleases to Debian's sorting-safe '~'.
    EXPECTED_PACKAGE_VERSION=$version_core
    [[ -z "$version_prerelease" ]] \
      || EXPECTED_PACKAGE_VERSION+="~$version_prerelease"
    [[ -z "$version_build" ]] || EXPECTED_PACKAGE_VERSION+="+$version_build"
    EXPECTED_PACKAGE_VERSION+=-1
    ;;
  fedora)
    EXPECTED_PACKAGE_VERSION=$version_core
    EXPECTED_RPM_RELEASE=1.fc44
    ;;
  el9)
    EXPECTED_PACKAGE_VERSION=$version_core
    EXPECTED_RPM_RELEASE=1.el9
    ;;
  el10)
    EXPECTED_PACKAGE_VERSION=$version_core
    EXPECTED_RPM_RELEASE=1.el10
    ;;
  opensuse)
    EXPECTED_PACKAGE_VERSION=$version_core
    EXPECTED_RPM_RELEASE=1.opensuse16
    ;;
  tumbleweed)
    EXPECTED_PACKAGE_VERSION=$version_core
    EXPECTED_RPM_RELEASE=1.tumbleweed
    ;;
  alpine)
    EXPECTED_PACKAGE_VERSION=$version_core
    [[ -z "$version_prerelease" ]] \
      || EXPECTED_PACKAGE_VERSION+="_$version_prerelease"
    EXPECTED_PACKAGE_VERSION+=-r0
    [[ -z "$version_build" ]] || EXPECTED_PACKAGE_VERSION+="-p$version_build"
    ;;
  # This is the exact pkgver emitted by nFPM 2.47's semver schema; binary
  # identity below is still checked against the complete SemVer value.
  arch) EXPECTED_PACKAGE_VERSION="$version_core-1" ;;
esac

case "$FAMILY" in
  fedora|el9|el10|opensuse|tumbleweed)
    # RPM uses the same sorting-safe prerelease form as Debian, without the
    # package release suffix in the Version field.
    [[ -z "$version_prerelease" ]] \
      || EXPECTED_PACKAGE_VERSION+="~$version_prerelease"
    [[ -z "$version_build" ]] || EXPECTED_PACKAGE_VERSION+="+$version_build"
    ;;
esac

# readelf is the authoritative gate here. Leap 16's s390x file/libmagic can
# misclassify a valid big-endian static ELF as generic "data".
COMMON_BINARY_ASSERTIONS='
      command -v readelf >/dev/null
      command -v awk >/dev/null
      for binary_name in openshield-daemon openshield-tui; do
        binary=/usr/bin/$binary_name
        test -f "$binary" && test -x "$binary" && test ! -L "$binary"
        elf_header=$(LC_ALL=C readelf -h -- "$binary") || {
          printf "%s\n" "invalid ELF binary: $binary" >&2
          exit 1
        }
        elf_program_headers=$(LC_ALL=C readelf -l -- "$binary") || {
          printf "%s\n" "cannot inspect ELF program headers: $binary" >&2
          exit 1
        }
        elf_dynamic=$(LC_ALL=C readelf -d -- "$binary") || {
          printf "%s\n" "cannot inspect ELF dynamic section: $binary" >&2
          exit 1
        }
        if printf "%s\n" "$elf_program_headers" \
          | grep -Eq '\''(^|[[:space:]])INTERP([[:space:]]|$)'\''; then
          printf "%s\n" "binary contains a dynamic ELF interpreter: $binary" >&2
          exit 1
        fi
        if printf "%s\n" "$elf_dynamic" | grep -Fq "(NEEDED)"; then
          printf "%s\n" "binary contains a dynamic ELF dependency: $binary" >&2
          exit 1
        fi
        elf_class=$(printf "%s\n" "$elf_header" \
          | awk -F: '\''/^[[:space:]]*Class:/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }'\'')
        elf_data=$(printf "%s\n" "$elf_header" \
          | awk -F: '\''/^[[:space:]]*Data:/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }'\'')
        elf_machine=$(printf "%s\n" "$elf_header" \
          | awk -F: '\''/^[[:space:]]*Machine:/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }'\'')
        [ "$elf_class" = "$EXPECTED_ELF_CLASS" ] || {
          printf "%s\n" "unexpected ELF class for $binary: $elf_class" >&2
          exit 1
        }
        case "$elf_data" in
          *"$EXPECTED_ELF_DATA"*) ;;
          *)
            printf "%s\n" "unexpected ELF byte order for $binary: $elf_data" >&2
            exit 1
            ;;
        esac
        [ "$elf_machine" = "$EXPECTED_ELF_MACHINE" ] || {
          printf "%s\n" "unexpected ELF machine for $binary: $elf_machine" >&2
          exit 1
        }
      done
      [ "$(openshield-daemon --version)" = "openshield-daemon $EXPECTED_VERSION" ]
      [ "$(openshield-tui --version)" = "openshield-tui $EXPECTED_VERSION" ]'

SYSTEMD_BASIC_ASSERTIONS='
      test -f /usr/lib/systemd/system/openshield-daemon.service
      test -f /usr/lib/sysusers.d/openshield.conf
      getent group openshield >/dev/null'

DEB_METADATA_ASSERTIONS='set -eu
      export LC_ALL=C
      package=/packages/$PACKAGE_BASENAME
      [ -f "$package" ] && [ ! -L "$package" ]
      [ "$(dpkg-deb -f "$package" Package)" = openshield ]
      package_version=$(dpkg-deb -f "$package" Version)
      package_arch=$(dpkg-deb -f "$package" Architecture)
      [ "$package_version" = "$EXPECTED_PACKAGE_VERSION" ]
      [ "$package_arch" = "$EXPECTED_PACKAGE_ARCH" ]'

DEB_INSTALL_ASSERTIONS='
      [ "$(dpkg-query -W -f="\${Package}" openshield)" = openshield ]
      [ "$(dpkg-query -W -f="\${Version}" openshield)" = "$EXPECTED_PACKAGE_VERSION" ]
      [ "$(dpkg-query -W -f="\${Architecture}" openshield)" = "$EXPECTED_PACKAGE_ARCH" ]'

RPM_METADATA_ASSERTIONS='set -eu
      export LC_ALL=C
      package=/packages/$PACKAGE_BASENAME
      [ -f "$package" ] && [ ! -L "$package" ]
      [ "$(rpm -qp --qf "%{NAME}" "$package")" = openshield ]
      [ "$(rpm -qp --qf "%{RELEASE}" "$package")" = "$EXPECTED_RPM_RELEASE" ]
      package_version=$(rpm -qp --qf "%{VERSION}" "$package")
      package_arch=$(rpm -qp --qf "%{ARCH}" "$package")
      [ "$package_version" = "$EXPECTED_PACKAGE_VERSION" ]
      [ "$package_arch" = "$EXPECTED_PACKAGE_ARCH" ]
      rpm -qp --requires "$package" | grep -Fqx "(nftables or iptables)"
      rpm -qp --requires "$package" | grep -Fqx /usr/bin/systemd-tmpfiles
      rpm -qp --recommends "$package" | grep -Fqx nftables
      for required_path in \
        /usr/bin/openshield-daemon \
        /usr/bin/openshield-tui \
        /usr/lib/systemd/system/openshield-daemon.service \
        /usr/lib/sysusers.d/openshield.conf \
        /usr/lib/tmpfiles.d/openshield.conf; do
        rpm -qpl "$package" | grep -Fqx "$required_path"
      done'

RPM_INSTALL_ASSERTIONS='
      [ "$(rpm -q --qf "%{VERSION}" openshield)" = "$EXPECTED_PACKAGE_VERSION" ]
      [ "$(rpm -q --qf "%{RELEASE}" openshield)" = "$EXPECTED_RPM_RELEASE" ]
      [ "$(rpm -q --qf "%{ARCH}" openshield)" = "$EXPECTED_PACKAGE_ARCH" ]
      test -f /usr/lib/systemd/system/openshield-daemon.service
      test -f /usr/lib/sysusers.d/openshield.conf
      test -f /usr/lib/tmpfiles.d/openshield.conf
      command -v systemd-tmpfiles >/dev/null
      getent group openshield >/dev/null
      [ "$(stat -c "%u:%g:%a" /run/openshield)" = 0:0:755 ]
      [ "$(stat -c "%u:%g:%a" /var/lib/openshield)" = 0:0:700 ]
      [ "$(stat -c "%u:%g:%a" /run/xtables.lock)" = 0:0:600 ]
      test -d /run/openshield
      test -d /var/lib/openshield
      test -f /run/xtables.lock
      unit=/usr/lib/systemd/system/openshield-daemon.service
      [ "$(sed -n "s/^Group=//p" "$unit")" = root ]
      [ "$(sed -n "s/^SupplementaryGroups=//p" "$unit")" = openshield ]
      [ "$(sed -n "s/^ProcSubset=//p" "$unit")" = all ]
      [ "$(sed -n "s/^ReadOnlyPaths=//p" "$unit")" = /proc ]
      [ "$(sed -n "s/^ProtectProc=//p" "$unit")" = invisible ]
      ! grep -Eq "^(RuntimeDirectory|StateDirectory)" "$unit"
      ! grep -Eq "^(AmbientCapabilities|CapabilityBoundingSet)=.*CAP_CHOWN" "$unit"
      runtime_probe=/run/openshield/.tmpfiles-nonrecursive-test
      state_probe=/var/lib/openshield/.tmpfiles-nonrecursive-test
      install -m 0600 /dev/null "$runtime_probe"
      install -m 0600 /dev/null "$state_probe"
      chown 0:1234 /run/openshield /var/lib/openshield "$runtime_probe" "$state_probe"
      systemd-tmpfiles --create /usr/lib/tmpfiles.d/openshield.conf
      [ "$(stat -c "%u:%g:%a" /run/openshield)" = 0:0:755 ]
      [ "$(stat -c "%u:%g:%a" /var/lib/openshield)" = 0:0:700 ]
      [ "$(stat -c "%u:%g:%a" "$runtime_probe")" = 0:1234:600 ]
      [ "$(stat -c "%u:%g:%a" "$state_probe")" = 0:1234:600 ]
      rm -f -- "$runtime_probe" "$state_probe"'

APK_METADATA_ASSERTIONS='set -eu
      export LC_ALL=C
      package=/packages/$PACKAGE_BASENAME
      [ -f "$package" ] && [ ! -L "$package" ]
      package_metadata=$(tar -xOf "$package" .PKGINFO)
      metadata_value() {
        awk -v wanted="$1" '\''
          index($0, wanted " = ") == 1 {
            count += 1
            value = substr($0, length(wanted) + 4)
          }
          END {
            if (count != 1) exit 1
            print value
          }
        '\''
      }
      package_name=$(printf "%s\n" "$package_metadata" | metadata_value pkgname)
      package_version=$(printf "%s\n" "$package_metadata" | metadata_value pkgver)
      package_arch=$(printf "%s\n" "$package_metadata" | metadata_value arch)
      [ "$package_name" = openshield ]
      [ "$package_version" = "$EXPECTED_PACKAGE_VERSION" ]
      [ "$package_arch" = "$EXPECTED_PACKAGE_ARCH" ]'

APK_INSTALL_ASSERTIONS='
      apk info -e "openshield=$EXPECTED_PACKAGE_VERSION"
      test -f /etc/init.d/openshield
      getent group openshield >/dev/null'

ARCH_METADATA_ASSERTIONS='set -eu
      export LC_ALL=C
      package=/packages/$PACKAGE_BASENAME
      [ -f "$package" ] && [ ! -L "$package" ]
      package_metadata=$(bsdtar -xOf "$package" .PKGINFO)
      metadata_value() {
        awk -v wanted="$1" '\''
          index($0, wanted " = ") == 1 {
            count += 1
            value = substr($0, length(wanted) + 4)
          }
          END {
            if (count != 1) exit 1
            print value
          }
        '\''
      }
      package_name=$(printf "%s\n" "$package_metadata" | metadata_value pkgname)
      package_version=$(printf "%s\n" "$package_metadata" | metadata_value pkgver)
      package_arch=$(printf "%s\n" "$package_metadata" | metadata_value arch)
      [ "$package_name" = openshield ]
      [ "$package_version" = "$EXPECTED_PACKAGE_VERSION" ]
      [ "$package_arch" = "$EXPECTED_PACKAGE_ARCH" ]'

ARCH_INSTALL_ASSERTIONS='
      [ "$(pacman -Q openshield)" = "openshield $EXPECTED_PACKAGE_VERSION" ]
      test -f /usr/lib/systemd/system/openshield-daemon.service
      getent group openshield >/dev/null'

# openSUSE package tests run concurrently across architectures and can hit a
# transient CDN timeout while libzypp refreshes repository metadata. Refresh
# only the required OSS repository, retry only libzypp status 4, and never
# retry an install transaction or a permanent solver/script failure.
ZYPPER_REFRESH_RETRY='
      refresh_zypper_repository() {
        openshield_zypper_repository=$1
        openshield_zypper_attempt=1
        openshield_zypper_max_attempts=3
        while :; do
          if zypper --non-interactive refresh "$openshield_zypper_repository"; then
            return 0
          else
            openshield_zypper_status=$?
          fi
          if [ "$openshield_zypper_status" -ne 4 ]; then
            printf "%s\n" \
              "zypper refresh for $openshield_zypper_repository failed with non-retryable status $openshield_zypper_status" >&2
            return "$openshield_zypper_status"
          fi
          if [ "$openshield_zypper_attempt" -ge "$openshield_zypper_max_attempts" ]; then
            printf "%s\n" \
              "zypper refresh for $openshield_zypper_repository failed after $openshield_zypper_attempt attempts (status $openshield_zypper_status)" >&2
            return "$openshield_zypper_status"
          fi
          openshield_zypper_delay=$((openshield_zypper_attempt * 5))
          printf "%s\n" \
            "zypper refresh for $openshield_zypper_repository failed (status $openshield_zypper_status); retrying in $openshield_zypper_delay seconds" >&2
          sleep "$openshield_zypper_delay"
          openshield_zypper_attempt=$((openshield_zypper_attempt + 1))
        done
      }'

case "$FAMILY" in
  deb)
    CMD=$DEB_METADATA_ASSERTIONS'
      export DEBIAN_FRONTEND=noninteractive
      apt-get update
      apt-get install -y --no-install-recommends binutils "$package"
    '$DEB_INSTALL_ASSERTIONS$SYSTEMD_BASIC_ASSERTIONS$COMMON_BINARY_ASSERTIONS
    ;;
  fedora|el9|el10)
    CMD=$RPM_METADATA_ASSERTIONS'
      dnf -y install binutils "$package"
    '$RPM_INSTALL_ASSERTIONS$COMMON_BINARY_ASSERTIONS
    ;;
  opensuse)
    CMD=$RPM_METADATA_ASSERTIONS$ZYPPER_REFRESH_RETRY'
      refresh_zypper_repository "openSUSE:repo-oss"
      zypper --non-interactive --no-refresh install \
        --repo "openSUSE:repo-oss" --allow-unsigned-rpm binutils "$package"
    '$RPM_INSTALL_ASSERTIONS$COMMON_BINARY_ASSERTIONS
    ;;
  tumbleweed)
    CMD=$RPM_METADATA_ASSERTIONS$ZYPPER_REFRESH_RETRY'
      refresh_zypper_repository "repo-oss"
      zypper --non-interactive --no-refresh install \
        --repo "repo-oss" --allow-unsigned-rpm binutils gawk "$package"
      rpm -q nftables >/dev/null
    '$RPM_INSTALL_ASSERTIONS$COMMON_BINARY_ASSERTIONS
    FALLBACK_CMD=$RPM_METADATA_ASSERTIONS$ZYPPER_REFRESH_RETRY'
      refresh_zypper_repository "repo-oss"
      zypper --non-interactive --no-refresh install \
        --repo "repo-oss" --no-recommends binutils gawk iptables
      rpm -q iptables >/dev/null
      if rpm -q nftables >/dev/null 2>&1 || command -v nft >/dev/null 2>&1; then
        printf "%s\n" "nftables unexpectedly present before fallback installation" >&2
        exit 1
      fi
      zypper --non-interactive --no-refresh install \
        --repo "repo-oss" --no-recommends --allow-unsigned-rpm "$package"
      rpm -q iptables >/dev/null
      if rpm -q nftables >/dev/null 2>&1 || command -v nft >/dev/null 2>&1; then
        printf "%s\n" "nftables recommendation was unexpectedly installed" >&2
        exit 1
      fi
    '$RPM_INSTALL_ASSERTIONS$COMMON_BINARY_ASSERTIONS
    ;;
  alpine)
    CMD=$APK_METADATA_ASSERTIONS'
      apk add --no-cache binutils nftables
      apk add --no-cache --allow-untrusted "$package"
    '$APK_INSTALL_ASSERTIONS$COMMON_BINARY_ASSERTIONS
    FALLBACK_CMD=$APK_METADATA_ASSERTIONS'
      apk add --no-cache binutils iptables
      if command -v nft >/dev/null 2>&1; then
        printf "%s\n" "nftables unexpectedly present before fallback installation" >&2
        exit 1
      fi
      apk add --no-cache --allow-untrusted "$package"
      apk info -e iptables >/dev/null
      if apk info -e nftables >/dev/null 2>&1 || command -v nft >/dev/null 2>&1; then
        printf "%s\n" "nftables was unexpectedly installed with the fallback package" >&2
        exit 1
      fi
      for tool in iptables ip6tables iptables-restore ip6tables-restore iptables-save ip6tables-save; do
        command -v "$tool" >/dev/null
      done
    '$APK_INSTALL_ASSERTIONS$COMMON_BINARY_ASSERTIONS
    ;;
  arch)
    CMD=$ARCH_METADATA_ASSERTIONS'
      pacman -Syu --noconfirm --needed binutils nftables
      pacman -U --noconfirm "$package"
    '$ARCH_INSTALL_ASSERTIONS$COMMON_BINARY_ASSERTIONS
    FALLBACK_CMD=$ARCH_METADATA_ASSERTIONS'
      pacman -Syu --noconfirm --needed binutils
      pacman -S --noconfirm --ask=4 iptables-legacy
      if pacman -Q nftables >/dev/null 2>&1; then
        pacman -Rns --noconfirm nftables
      fi
      if command -v nft >/dev/null 2>&1; then
        printf "%s\n" "nftables unexpectedly present before fallback installation" >&2
        exit 1
      fi
      pacman -U --noconfirm "$package"
      pacman -Q iptables-legacy >/dev/null
      if pacman -Q nftables >/dev/null 2>&1 || command -v nft >/dev/null 2>&1; then
        printf "%s\n" "nftables was unexpectedly installed with the fallback package" >&2
        exit 1
      fi
      for tool in iptables ip6tables iptables-restore ip6tables-restore iptables-save ip6tables-save; do
        command -v "$tool" >/dev/null
      done
    '$ARCH_INSTALL_ASSERTIONS$COMMON_BINARY_ASSERTIONS
    ;;
esac

docker pull --platform "$PLATFORM" "$IMAGE"

run_package_test() {
  docker run --rm \
    --platform "$PLATFORM" \
    --pull never \
    --pids-limit 2048 \
    --security-opt label=disable \
    --env "PACKAGE_BASENAME=$PACKAGE_BASENAME" \
    --env "EXPECTED_PACKAGE_ARCH=$EXPECTED_PACKAGE_ARCH" \
    --env "EXPECTED_PACKAGE_VERSION=$EXPECTED_PACKAGE_VERSION" \
    --env "EXPECTED_VERSION=$EXPECTED_VERSION" \
    --env "EXPECTED_ELF_CLASS=$EXPECTED_ELF_CLASS" \
    --env "EXPECTED_ELF_DATA=$EXPECTED_ELF_DATA" \
    --env "EXPECTED_ELF_MACHINE=$EXPECTED_ELF_MACHINE" \
    --env "EXPECTED_RPM_RELEASE=$EXPECTED_RPM_RELEASE" \
    --mount "type=bind,src=$DIST,dst=/packages,readonly" \
    "$IMAGE" \
    /bin/sh -c "$1"
}

run_package_test "$CMD"
if [[ "$FAMILY" == tumbleweed || "$FAMILY" == alpine || "$FAMILY" == arch ]]; then
  run_package_test "$FALLBACK_CMD"
fi
