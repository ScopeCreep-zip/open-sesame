#!/usr/bin/env bash
# test-install.sh — build .pkg.tar.zst from local tarballs and verify install
# in an Arch Linux container.
#
# When run outside Arch (no /etc/arch-release): detects version from tarballs,
# re-execs itself inside archlinux:base-devel via docker with the repo and
# tarballs mounted by exact path.
#
# Expects tarballs at repo root (produced by mise run build:arch):
#   open-sesame-v<VERSION>-x86_64.tar.gz
#   open-sesame-desktop-v<VERSION>-x86_64.tar.gz
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [ ! -f /etc/arch-release ]; then
    # Detect version from tarball on host — exactly one headless tarball expected
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

    echo "Not on Arch — re-executing inside archlinux:base-devel container..."
    echo "  VERSION=${VERSION}"
    echo "  headless: $(basename "${HEADLESS_TAR}")"
    echo "  desktop:  $(basename "${DESKTOP_TAR}")"
    exec docker run --rm \
        -e "VERSION=${VERSION}" \
        -v "${ROOT}:/src:ro" \
        -v "${HEADLESS_TAR}:/tarballs/headless.tar.gz:ro" \
        -v "${DESKTOP_TAR}:/tarballs/desktop.tar.gz:ro" \
        archlinux:base-devel /src/scripts/arch/test-install.sh
fi

# ── Inside container ─────────────────────────────────────────────────────────
: "${VERSION:?VERSION must be set}"
echo "=== Version: ${VERSION} ==="

# ── Install base deps ───────────────────────────────────────────────────────
pacman -Sy --noconfirm --needed base-devel zstd >/dev/null 2>&1

# ── Create build user (makepkg refuses to run as root) ───────────────────────
useradd -m builder 2>/dev/null || true

# ── Set up build directory ───────────────────────────────────────────────────
WORKDIR="$(mktemp -d)"
cp /src/aur/open-sesame-bin/PKGBUILD "${WORKDIR}/"
cp /src/aur/open-sesame-bin/open-sesame-bin.install "${WORKDIR}/"
cp /src/aur/open-sesame-bin/open-sesame-desktop-bin.install "${WORKDIR}/"

cp /tarballs/headless.tar.gz "${WORKDIR}/open-sesame-v${VERSION}-x86_64.tar.gz"
cp /tarballs/desktop.tar.gz "${WORKDIR}/open-sesame-desktop-v${VERSION}-x86_64.tar.gz"

cd "${WORKDIR}"

# ── Substitute version and checksums ─────────────────────────────────────────
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

# ── Build packages ───────────────────────────────────────────────────────────
echo "=== Building .pkg.tar.zst ==="
su builder -c "CARCH=x86_64 PKGEXT='.pkg.tar.zst' makepkg --nodeps --force" 2>&1

echo ""
echo "=== Built packages ==="
ls -la *.pkg.tar.zst

# ── Install packages ─────────────────────────────────────────────────────────
echo ""
echo "=== Installing with pacman -U ==="
pacman -U --noconfirm *.pkg.tar.zst 2>&1

# ── Verify installation ─────────────────────────────────────────────────────
echo ""
echo "=== Verification ==="

echo "--- sesame --version ---"
sesame --version

echo "--- Installed files (headless) ---"
pacman -Ql open-sesame-bin 2>&1

echo "--- Installed files (desktop) ---"
pacman -Ql open-sesame-desktop-bin 2>&1

echo "--- Dependencies (headless) ---"
pacman -Qi open-sesame-bin 2>&1 | grep -E '^(Name|Version|Depends On|Provides|Conflicts)'

echo "--- Dependencies (desktop) ---"
pacman -Qi open-sesame-desktop-bin 2>&1 | grep -E '^(Name|Version|Depends On|Provides|Conflicts)'

echo "--- Preset files ---"
cat /usr/lib/systemd/user-preset/90-open-sesame.preset 2>/dev/null || echo "MISSING: 90-open-sesame.preset"
cat /usr/lib/systemd/user-preset/90-open-sesame-desktop.preset 2>/dev/null || echo "MISSING: 90-open-sesame-desktop.preset"

echo "--- Binary interpreter check (no nix store paths) ---"
for bin in sesame daemon-profile daemon-secrets daemon-launcher daemon-snippets daemon-wm daemon-clipboard daemon-input; do
    interp="$(readelf -l "/usr/bin/${bin}" 2>/dev/null | grep 'interpreter:' | sed 's/.*interpreter: \(.*\)]/\1/' || echo "NOT FOUND")"
    if [[ "${interp}" == /nix/store/* ]]; then
        echo "FAIL: ${bin} has nix interpreter: ${interp}"
        exit 1
    fi
    echo "  ${bin}: ${interp}"
done

echo ""
echo "=== All checks passed ==="
