#!/usr/bin/env bash
# test-ci-build.sh -- reproduce the CI ci:build:arch makepkg step on ubuntu:24.04.
# Verifies that ci:setup:arch-repo installs all dependencies (including bsdtar)
# and that build-pkg.sh succeeds on the same OS the GitHub runner uses.
#
# When run outside Ubuntu (no /etc/lsb-release with Ubuntu): re-execs itself
# inside ubuntu:24.04 via docker with the repo and tarballs mounted.
#
# Expects tarballs at repo root (produced by mise run build:arch):
#   open-sesame-v<VERSION>-x86_64.tar.gz
#   open-sesame-desktop-v<VERSION>-x86_64.tar.gz
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! grep -q 'Ubuntu' /etc/lsb-release 2>/dev/null; then
    HEADLESS_TAR=""
    DESKTOP_TAR=""
    for f in "${ROOT}"/open-sesame-v*-x86_64.tar.gz; do
        [ -f "$f" ] && HEADLESS_TAR="$f" && break
    done
    for f in "${ROOT}"/open-sesame-desktop-v*-x86_64.tar.gz; do
        [ -f "$f" ] && DESKTOP_TAR="$f" && break
    done
    if [ -z "${HEADLESS_TAR}" ] || [ -z "${DESKTOP_TAR}" ]; then
        echo "ERROR: tarballs not found at ${ROOT}/" >&2
        echo "  Run 'mise run build:arch' first." >&2
        exit 1
    fi
    VERSION="$(basename "${HEADLESS_TAR}" | sed 's/^open-sesame-v\(.*\)-x86_64\.tar\.gz$/\1/')"

    echo "Not on Ubuntu -- re-executing inside ubuntu:24.04 container..."
    echo "  VERSION=${VERSION}"
    exec docker run --rm \
        -e "VERSION=${VERSION}" \
        -v "${ROOT}:/src:ro" \
        -v "${HEADLESS_TAR}:/tarballs/headless.tar.gz:ro" \
        -v "${DESKTOP_TAR}:/tarballs/desktop.tar.gz:ro" \
        ubuntu:24.04 /src/scripts/arch/test-ci-build.sh
fi

: "${VERSION:?VERSION must be set}"
echo "=== CI build parity test on $(cat /etc/lsb-release | grep DISTRIB_DESCRIPTION | cut -d= -f2) ==="
echo "=== Version: ${VERSION} ==="

# Reproduce ci:setup:arch-repo
echo "=== Installing CI dependencies ==="
apt-get update -qq
apt-get install -y -qq makepkg pacman-package-manager zstd binutils libarchive-tools

# Verify bsdtar is available (the exact failure mode from CI)
echo "=== Verifying bsdtar ==="
which bsdtar
bsdtar --version

# Reproduce build-pkg.sh
echo "=== Running build-pkg.sh ==="
useradd -m builder 2>/dev/null || true

WORKDIR="$(mktemp -d)"
cp /src/aur/open-sesame-bin/PKGBUILD "${WORKDIR}/"
cp /src/aur/open-sesame-bin/open-sesame-bin.install "${WORKDIR}/"
cp /src/aur/open-sesame-bin/open-sesame-desktop-bin.install "${WORKDIR}/"

cp /tarballs/headless.tar.gz "${WORKDIR}/open-sesame-v${VERSION}-x86_64.tar.gz"
cp /tarballs/desktop.tar.gz "${WORKDIR}/open-sesame-desktop-v${VERSION}-x86_64.tar.gz"

cd "${WORKDIR}"

HEADLESS_SHA="$(sha256sum "open-sesame-v${VERSION}-x86_64.tar.gz" | cut -d' ' -f1)"
DESKTOP_SHA="$(sha256sum "open-sesame-desktop-v${VERSION}-x86_64.tar.gz" | cut -d' ' -f1)"

sed -i \
    -e "s/^pkgver=VERSION$/pkgver=${VERSION}/" \
    -e "s/HEADLESS_X86_64_SHA/${HEADLESS_SHA}/" \
    -e "s/DESKTOP_X86_64_SHA/${DESKTOP_SHA}/" \
    -e "s/HEADLESS_AARCH64_SHA/SKIP/" \
    -e "s/DESKTOP_AARCH64_SHA/SKIP/" \
    PKGBUILD

chown -R builder: "${WORKDIR}"

su builder -c "CARCH=x86_64 PKGEXT='.pkg.tar.zst' makepkg --nodeps --force"

echo ""
echo "=== Built packages ==="
ls -la *.pkg.tar.zst

echo ""
echo "=== CI build parity test PASSED ==="
