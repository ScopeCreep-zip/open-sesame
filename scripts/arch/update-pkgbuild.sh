#!/usr/bin/env bash
# update-pkgbuild.sh — substitute version and checksums into PKGBUILD template.
# Called by the aur-publish workflow job.
#
# Environment:
#   VERSION       — package version without v prefix (required)
#   SHA256SUMS    — path to SHA256SUMS.txt from the release (required)
#   PKGBUILD_DIR  — directory containing the PKGBUILD template (required)
set -euo pipefail

: "${VERSION:?VERSION must be set}"
: "${SHA256SUMS:?SHA256SUMS must be set}"
: "${PKGBUILD_DIR:?PKGBUILD_DIR must be set}"

get_sha() {
    local filename="$1"
    awk -v f="./$filename" '$2==f {print $1; exit}' "${SHA256SUMS}"
}

HEADLESS_X86=$(get_sha "open-sesame-v${VERSION}-x86_64.tar.gz")
HEADLESS_ARM=$(get_sha "open-sesame-v${VERSION}-aarch64.tar.gz")
DESKTOP_X86=$(get_sha "open-sesame-desktop-v${VERSION}-x86_64.tar.gz")
DESKTOP_ARM=$(get_sha "open-sesame-desktop-v${VERSION}-aarch64.tar.gz")
SOURCE=$(get_sha "open-sesame-${VERSION}-source.tar.gz")

for var in HEADLESS_X86 HEADLESS_ARM DESKTOP_X86 DESKTOP_ARM SOURCE; do
    if [ -z "${!var}" ]; then
        echo "ERROR: could not find checksum for ${var}" >&2
        exit 1
    fi
done

sed -i \
    -e "s/^pkgver=VERSION$/pkgver=${VERSION}/" \
    -e "s/HEADLESS_X86_64_SHA/${HEADLESS_X86}/" \
    -e "s/HEADLESS_AARCH64_SHA/${HEADLESS_ARM}/" \
    -e "s/DESKTOP_X86_64_SHA/${DESKTOP_X86}/" \
    -e "s/DESKTOP_AARCH64_SHA/${DESKTOP_ARM}/" \
    -e "s/SOURCE_SHA/${SOURCE}/" \
    "${PKGBUILD_DIR}/PKGBUILD"

echo "Updated ${PKGBUILD_DIR}/PKGBUILD to v${VERSION}"
echo "  headless x86_64:  ${HEADLESS_X86}"
echo "  headless aarch64: ${HEADLESS_ARM}"
echo "  desktop x86_64:   ${DESKTOP_X86}"
echo "  desktop aarch64:  ${DESKTOP_ARM}"
echo "  source:           ${SOURCE}"
