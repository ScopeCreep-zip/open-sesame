#!/usr/bin/env bash
# generate-checksums.sh — generate SHA256SUMS.txt and interpolate into RELEASE_BODY.md.
# Called by the upload-assets job in release.yml.
#
# Environment:
#   TAG     — release tag (required)
#   VERSION — release version without v prefix (required)
set -euo pipefail

: "${TAG:?TAG must be set}"
: "${VERSION:?VERSION must be set}"

sha256sum ./*.deb ./*.rpm ./*.tar.gz ./*.pkg.tar.zst > SHA256SUMS.txt
cat SHA256SUMS.txt

get_sha() { grep "$1" SHA256SUMS.txt | cut -d' ' -f1; }

# DEB checksums
SHA_HEADLESS_X86_64=$(get_sha "open-sesame-linux-x86_64\.deb")
SHA_HEADLESS_AARCH64=$(get_sha "open-sesame-linux-aarch64\.deb")
SHA_DESKTOP_X86_64=$(get_sha "open-sesame-desktop-linux-x86_64\.deb")
SHA_DESKTOP_AARCH64=$(get_sha "open-sesame-desktop-linux-aarch64\.deb")

# RPM checksums
SHA_RPM_HEADLESS_X86_64=$(get_sha "open-sesame-linux-x86_64\.rpm")
SHA_RPM_HEADLESS_AARCH64=$(get_sha "open-sesame-linux-aarch64\.rpm")
SHA_RPM_DESKTOP_X86_64=$(get_sha "open-sesame-desktop-linux-x86_64\.rpm")
SHA_RPM_DESKTOP_AARCH64=$(get_sha "open-sesame-desktop-linux-aarch64\.rpm")

# Tarball checksums
SHA_TAR_HEADLESS_X86_64=$(get_sha "open-sesame-v${VERSION}-x86_64\.tar\.gz")
SHA_TAR_HEADLESS_AARCH64=$(get_sha "open-sesame-v${VERSION}-aarch64\.tar\.gz")
SHA_TAR_DESKTOP_X86_64=$(get_sha "open-sesame-desktop-v${VERSION}-x86_64\.tar\.gz")
SHA_TAR_DESKTOP_AARCH64=$(get_sha "open-sesame-desktop-v${VERSION}-aarch64\.tar\.gz")

# Source tarball checksum
SHA_SOURCE=$(get_sha "open-sesame-${VERSION}-source\.tar\.gz")

sed -e "s/\${TAG}/${TAG}/g" \
    -e "s/\${VERSION}/${VERSION}/g" \
    -e "s/\${SHA256_HEADLESS_X86_64}/${SHA_HEADLESS_X86_64}/g" \
    -e "s/\${SHA256_HEADLESS_AARCH64}/${SHA_HEADLESS_AARCH64}/g" \
    -e "s/\${SHA256_DESKTOP_X86_64}/${SHA_DESKTOP_X86_64}/g" \
    -e "s/\${SHA256_DESKTOP_AARCH64}/${SHA_DESKTOP_AARCH64}/g" \
    -e "s/\${SHA256_RPM_HEADLESS_X86_64}/${SHA_RPM_HEADLESS_X86_64}/g" \
    -e "s/\${SHA256_RPM_HEADLESS_AARCH64}/${SHA_RPM_HEADLESS_AARCH64}/g" \
    -e "s/\${SHA256_RPM_DESKTOP_X86_64}/${SHA_RPM_DESKTOP_X86_64}/g" \
    -e "s/\${SHA256_RPM_DESKTOP_AARCH64}/${SHA_RPM_DESKTOP_AARCH64}/g" \
    -e "s/\${SHA256_TAR_HEADLESS_X86_64}/${SHA_TAR_HEADLESS_X86_64}/g" \
    -e "s/\${SHA256_TAR_HEADLESS_AARCH64}/${SHA_TAR_HEADLESS_AARCH64}/g" \
    -e "s/\${SHA256_TAR_DESKTOP_X86_64}/${SHA_TAR_DESKTOP_X86_64}/g" \
    -e "s/\${SHA256_TAR_DESKTOP_AARCH64}/${SHA_TAR_DESKTOP_AARCH64}/g" \
    -e "s/\${SHA256_SOURCE}/${SHA_SOURCE}/g" \
    .github/templates/RELEASE_BODY.md > install_instructions.md
