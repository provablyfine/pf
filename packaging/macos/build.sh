#!/usr/bin/env bash
# Build the macOS installer package from the PyInstaller payload.
#
#   uv run --group build pyinstaller packaging/macos/pf.spec --noconfirm
#   packaging/macos/build.sh
#
# Output: dist/provablyfine-<version>-<arch>.pkg
#
# The package installs the payload in /opt/provablyfine and puts pf, pfa and
# pfat wrappers in /usr/local/bin. sshd only accepts a command that lives in
# directories owned by root, which is why the payload does not live in a
# Homebrew or home directory.
#
# Signing is optional and follows the environment:
#   MACOS_APP_IDENTITY        "Developer ID Application: ..." signs the binaries
#   MACOS_INSTALLER_IDENTITY  "Developer ID Installer: ..." signs the package
#   MACOS_NOTARY_APPLE_ID, MACOS_NOTARY_PASSWORD, MACOS_NOTARY_TEAM_ID
#                             notarize and staple the signed package
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
payload="$repo/dist/provablyfine"

app_identity="${MACOS_APP_IDENTITY:-}"
installer_identity="${MACOS_INSTALLER_IDENTITY:-}"
notary_apple_id="${MACOS_NOTARY_APPLE_ID:-}"
notary_password="${MACOS_NOTARY_PASSWORD:-}"
notary_team_id="${MACOS_NOTARY_TEAM_ID:-}"

if [ ! -x "$payload/pf" ]; then
    echo "missing $payload/pf: run pyinstaller packaging/macos/pf.spec first" >&2
    exit 1
fi

notary_settings=0
[ -n "$notary_apple_id" ] && notary_settings=$((notary_settings + 1))
[ -n "$notary_password" ] && notary_settings=$((notary_settings + 1))
[ -n "$notary_team_id" ] && notary_settings=$((notary_settings + 1))
if [ "$notary_settings" -ne 0 ] && [ "$notary_settings" -ne 3 ]; then
    echo "notarization needs MACOS_NOTARY_APPLE_ID, MACOS_NOTARY_PASSWORD and MACOS_NOTARY_TEAM_ID" >&2
    exit 1
fi
if [ "$notary_settings" -eq 3 ] && [ -z "$installer_identity" ]; then
    echo "notarization needs a signed package: set MACOS_INSTALLER_IDENTITY" >&2
    exit 1
fi

version="${PF_VERSION:-$(cd "$repo" && uv version --short)}"
arch="$(uname -m)"
out="$repo/dist/provablyfine-$version-$arch.pkg"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
root="$work/root"

mkdir -p "$root/opt" "$root/usr/local/bin"
cp -R "$payload" "$root/opt/provablyfine"
cp "$here/uninstall.sh" "$root/opt/provablyfine/uninstall.sh"
for name in pf pfa pfat; do
    cp "$repo/packaging/linux/$name.sh" "$root/usr/local/bin/$name"
done
chmod 755 "$root"/usr/local/bin/* "$root/opt/provablyfine/uninstall.sh"
chmod -R go-w "$root"

if [ -n "$app_identity" ]; then
    echo "== signing binaries as: $app_identity"
    find "$root/opt/provablyfine" -type f | while IFS= read -r f; do
        if file "$f" | grep -q Mach-O; then
            codesign --force --timestamp --options runtime \
                --entitlements "$here/entitlements.plist" \
                --sign "$app_identity" "$f"
        fi
    done
fi

echo "== building $(basename "$out")"
pkgbuild \
    --root "$root" \
    --identifier net.provablyfine.client \
    --version "$version" \
    --install-location / \
    --scripts "$here/scripts" \
    --ownership recommended \
    "$work/component.pkg"

mkdir -p "$repo/dist"
rm -f "$out"
if [ -n "$installer_identity" ]; then
    productbuild --sign "$installer_identity" --timestamp --package "$work/component.pkg" "$out"
else
    productbuild --package "$work/component.pkg" "$out"
fi

if [ "$notary_settings" -eq 3 ]; then
    echo "== notarizing"
    xcrun notarytool submit "$out" \
        --apple-id "$notary_apple_id" \
        --password "$notary_password" \
        --team-id "$notary_team_id" \
        --wait
    xcrun stapler staple "$out"
    xcrun stapler validate "$out"
fi

echo "$out"
