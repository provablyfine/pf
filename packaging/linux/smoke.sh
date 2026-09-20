#!/usr/bin/env bash
# Install, smoke-test, and uninstall a provablyfine deb or rpm inside a
# distribution container. The package must be mounted read-only at /pkg and
# this script at /smoke.sh:
#   docker run --rm -v "$PWD/pkg:/pkg:ro" -v "$PWD/smoke.sh:/smoke.sh:ro" \
#     debian:12 /smoke.sh
set -euo pipefail

pkg=""
kind=""
if command -v apt-get >/dev/null && ls /pkg/*.deb >/dev/null 2>&1; then
    kind=deb
    pkg=$(ls /pkg/*.deb | head -1)
elif command -v dnf >/dev/null && ls /pkg/*.rpm >/dev/null 2>&1; then
    kind=rpm
    pkg=$(ls /pkg/*.rpm | head -1)
else
    echo "no package matching this image's package manager found in /pkg" >&2
    exit 1
fi

echo "== installing $(basename "$pkg") in a ${kind}-based image"
case "$kind" in
deb)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq "$pkg" >/dev/null
    ;;
rpm)
    dnf install -y "$pkg" >/dev/null
    ;;
esac

echo "== smoke tests"
/opt/provablyfine/pf version
test -x /usr/bin/pf
test -x /usr/bin/pfa
test -x /usr/bin/pfat
/usr/bin/pf --help >/dev/null
/usr/bin/pfa --help >/dev/null
/usr/bin/pfat --help >/dev/null
test -x /usr/bin/ssh

echo "== uninstall"
case "$kind" in
deb)
    apt-get remove -y -qq provablyfine >/dev/null
    ;;
rpm)
    dnf remove -y provablyfine >/dev/null
    ;;
esac
test ! -e /usr/bin/pf
test ! -e /usr/bin/pfa
test ! -e /usr/bin/pfat

echo "== OK"
