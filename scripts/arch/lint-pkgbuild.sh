#!/usr/bin/env bash
# lint-pkgbuild.sh — lint PKGBUILDs with namcap inside an Arch container.
# Called by mise run test:arch:namcap and CI test.yml lint-pkgbuild job.
#
# When run outside Arch (no /etc/arch-release): re-execs itself inside
# archlinux:base-devel via docker.
#
# namcap always exits 0 regardless of findings. This script parses output
# for E: (error) and W: (warning) lines, fails on errors, prints warnings.
#
# Known false positive: "Split PKGBUILD needs additional makedepends
# ['open-sesame']" on the -bin pkgbase. open-sesame-desktop-bin depends on
# open-sesame, which open-sesame-bin provides via provides=('open-sesame').
# Intra-split provides are resolved at install time by makepkg, not at
# build time from repos. Adding open-sesame to makedepends would fail on
# clean systems where the package doesn't exist in any repo yet.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if [ ! -f /etc/arch-release ]; then
    echo "Not on Arch — re-executing inside archlinux:base-devel container..."
    exec docker run --rm -v "${ROOT}:/src:ro" archlinux:base-devel /src/scripts/arch/lint-pkgbuild.sh
fi

pacman -Sy --noconfirm --needed namcap >/dev/null 2>&1

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# Known false positives filtered before error/warning counting.
# Each entry is a grep -v extended regex applied to namcap output.
#
# 1. Intra-split provides: open-sesame-desktop-bin depends on open-sesame,
#    which open-sesame-bin provides. Resolved at install time, not build time.
# 2. Arch reference in source_x86_64 URLs: source_x86_64=() arrays inherently
#    contain the literal architecture in download URLs. $CARCH substitution is
#    not applicable inside arch-specific source arrays.
KNOWN_FP=(
    "needs additional makedepends \['open-sesame'\]"
    "Reference to x86_64 should be changed to"
)

errors=0
warnings=0

for pkgdir in "${ROOT}/aur/open-sesame-bin" "${ROOT}/aur/open-sesame"; do
    name="$(basename "$pkgdir")"
    cp "$pkgdir/PKGBUILD" "$WORKDIR/PKGBUILD"

    sed -i 's/^pkgver=VERSION$/pkgver=0.0.1/' "$WORKDIR/PKGBUILD"
    sed -i 's/HEADLESS_X86_64_SHA/SKIP/g' "$WORKDIR/PKGBUILD"
    sed -i 's/HEADLESS_AARCH64_SHA/SKIP/g' "$WORKDIR/PKGBUILD"
    sed -i 's/DESKTOP_X86_64_SHA/SKIP/g' "$WORKDIR/PKGBUILD"
    sed -i 's/DESKTOP_AARCH64_SHA/SKIP/g' "$WORKDIR/PKGBUILD"
    sed -i 's/SOURCE_SHA/SKIP/g' "$WORKDIR/PKGBUILD"

    echo "=== namcap: ${name} ==="
    output="$(namcap "$WORKDIR/PKGBUILD" 2>&1)" || true

    if [ -n "${output}" ]; then
        echo "${output}"

        # Filter known false positives before counting errors
        filtered="${output}"
        for pattern in "${KNOWN_FP[@]}"; do
            filtered="$(echo "${filtered}" | grep -v "${pattern}" || true)"
        done

        pkg_errors="$(echo "${filtered}" | grep -c ' E: ' || true)"
        pkg_warnings="$(echo "${filtered}" | grep -c ' W: ' || true)"
        errors=$((errors + pkg_errors))
        warnings=$((warnings + pkg_warnings))
    else
        echo "  (clean)"
    fi
    echo ""
done

echo "Summary: ${errors} error(s), ${warnings} warning(s)"

if [ "${errors}" -gt 0 ]; then
    echo "FAILED: ${errors} namcap error(s) found" >&2
    exit 1
fi

echo "All PKGBUILDs passed namcap (${warnings} advisory warning(s))"
