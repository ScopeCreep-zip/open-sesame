#!/usr/bin/env bash
# build-pkg.sh — build .pkg.tar.zst packages using Ubuntu's makepkg.
# Called by ci:build:arch mise task after build-tarball.sh.
#
# Environment:
#   ARCH    — x86_64 or aarch64 (required)
#   VERSION — package version without v prefix (required)
set -euo pipefail

: "${ARCH:?ARCH must be set}"
: "${VERSION:?VERSION must be set}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUTPUT_DIR="$(pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# Copy PKGBUILD and .install files
cp "${ROOT}/aur/open-sesame-bin/PKGBUILD" "${WORKDIR}/"
cp "${ROOT}/aur/open-sesame-bin/open-sesame-bin.install" "${WORKDIR}/"
cp "${ROOT}/aur/open-sesame-bin/open-sesame-desktop-bin.install" "${WORKDIR}/"

# Copy tarballs into workdir so makepkg finds them as local sources
cp "open-sesame-v${VERSION}-${ARCH}.tar.gz" "${WORKDIR}/"
cp "open-sesame-desktop-v${VERSION}-${ARCH}.tar.gz" "${WORKDIR}/"

cd "${WORKDIR}"

# Substitute version and checksums
HEADLESS_SHA=$(sha256sum "open-sesame-v${VERSION}-${ARCH}.tar.gz" | cut -d' ' -f1)
DESKTOP_SHA=$(sha256sum "open-sesame-desktop-v${VERSION}-${ARCH}.tar.gz" | cut -d' ' -f1)

# Substitute version, current arch checksums, and SKIP the other arch
sed -i -e "s/^pkgver=VERSION$/pkgver=${VERSION}/" PKGBUILD
if [[ "${ARCH}" == "x86_64" ]]; then
    sed -i \
        -e "s/HEADLESS_X86_64_SHA/${HEADLESS_SHA}/" \
        -e "s/DESKTOP_X86_64_SHA/${DESKTOP_SHA}/" \
        -e "s/HEADLESS_AARCH64_SHA/SKIP/" \
        -e "s/DESKTOP_AARCH64_SHA/SKIP/" \
        PKGBUILD
else
    sed -i \
        -e "s/HEADLESS_AARCH64_SHA/${HEADLESS_SHA}/" \
        -e "s/DESKTOP_AARCH64_SHA/${DESKTOP_SHA}/" \
        -e "s/HEADLESS_X86_64_SHA/SKIP/" \
        -e "s/DESKTOP_X86_64_SHA/SKIP/" \
        PKGBUILD
fi

# Build with Ubuntu's makepkg — override CARCH, PKGEXT, PACKAGER, PKGDEST
export CARCH="${ARCH}"
export PKGEXT='.pkg.tar.zst'
export PACKAGER="Kat Morgan <usrbinkat@braincraft.io>"
export PKGDEST="${OUTPUT_DIR}"
makepkg --nodeps --force

echo "Built packages:"
ls -la "${PKGDEST}"/*.pkg.tar.zst
