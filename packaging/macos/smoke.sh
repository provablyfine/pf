#!/usr/bin/env bash
# Install, smoke-test, upgrade and uninstall a provablyfine macOS package.
#
#   packaging/macos/smoke.sh dist/provablyfine-0.7.8-arm64.pkg
#
# This modifies /opt and /usr/local on the machine it runs on. Use a CI
# runner or a test machine.
set -euo pipefail

pkg="${1:?usage: smoke.sh PACKAGE.pkg}"
id=net.provablyfine.client
sudo_cmd=""
if [ "$(id -u)" -ne 0 ]; then
    sudo_cmd="sudo"
fi

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

echo "== installing $(basename "$pkg")"
$sudo_cmd installer -pkg "$pkg" -target / >/dev/null

echo "== smoke tests"
expected="$(pkgutil --pkg-info "$id" | awk '/^version:/ { print $2 }')"
actual="$(/opt/provablyfine/pf version)"
[ "$actual" = "$expected" ] || fail "pf version is '$actual', the package version is '$expected'"
for name in pf pfa pfat; do
    test -x "/usr/local/bin/$name" || fail "/usr/local/bin/$name is missing"
    "/usr/local/bin/$name" --help >/dev/null
done
/usr/local/bin/pf openssh --help >/dev/null

echo "== sshd can use /opt/provablyfine/pf as a command"
# sshd refuses a command when the file or any directory above it is not
# owned by root or can be written by group or others.
bad="$(find /opt/provablyfine \( ! -user root -o -perm -020 -o -perm -002 \) -print | head -5)"
[ -z "$bad" ] || fail "unsafe ownership or modes: $bad"
for dir in / /opt; do
    owner="$(stat -f %Su "$dir")"
    mode="$(stat -f %Sp "$dir")"
    [ "$owner" = root ] || fail "$dir is owned by $owner"
    case "$mode" in
    ?????w* | ????????w?) fail "$dir is writable by group or others ($mode)" ;;
    esac
done
sudo -u nobody /opt/provablyfine/pf version >/dev/null || fail "user nobody cannot run pf"

echo "== upgrade removes files from the previous version"
$sudo_cmd touch /opt/provablyfine/_internal/STALE_FROM_OLD_VERSION
$sudo_cmd installer -pkg "$pkg" -target / >/dev/null
test ! -e /opt/provablyfine/_internal/STALE_FROM_OLD_VERSION || fail "stale file survived the upgrade"
/opt/provablyfine/pf version >/dev/null

echo "== uninstall"
$sudo_cmd /opt/provablyfine/uninstall.sh >/dev/null
test ! -e /opt/provablyfine || fail "/opt/provablyfine is still there"
for name in pf pfa pfat; do
    test ! -e "/usr/local/bin/$name" || fail "/usr/local/bin/$name is still there"
done
if pkgutil --pkg-info "$id" >/dev/null 2>&1; then
    fail "the receipt for $id is still there"
fi

echo "== OK"
