#!/bin/sh
# Remove the provablyfine package.
#
#   sudo /opt/provablyfine/uninstall.sh
#
# macOS has no package manager that removes files. This script deletes
# every file listed in the installer receipt, removes the payload directory,
# then forgets the receipt.
set -eu

ID=net.provablyfine.client

if [ "$(id -u)" -ne 0 ]; then
    echo "run as root: sudo $0" >&2
    exit 1
fi

if ! pkgutil --pkg-info "$ID" >/dev/null 2>&1; then
    echo "$ID is not installed" >&2
    exit 1
fi

# Longest paths first, so files go before the directories that hold them.
pkgutil --files "$ID" | awk '{ print length($0) " " $0 }' | sort -rn | cut -d' ' -f2- |
    while IFS= read -r path; do
        target="/$path"
        if [ -d "$target" ] && [ ! -L "$target" ]; then
            rmdir "$target" 2>/dev/null || true
        else
            rm -f "$target"
        fi
    done

# The payload directory belongs to this package. Remove anything the receipt
# does not know about, such as files created later by the user or by a tool.
rm -rf /opt/provablyfine

pkgutil --forget "$ID" >/dev/null
echo "removed $ID"
