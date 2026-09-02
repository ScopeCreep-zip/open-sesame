#!/usr/bin/env bash
# build-tarball.sh — assemble headless and desktop tarballs for Arch/AUR packaging.
# Called by ci:build:arch mise task after cargo build + man + completions.
#
# Environment:
#   TARGET  — cargo target triple (required)
#   ARCH    — release architecture label: x86_64 or aarch64 (required)
#   VERSION — package version without v prefix (required)
set -euo pipefail

: "${TARGET:?TARGET must be set}"
: "${ARCH:?ARCH must be set (x86_64 or aarch64)}"
: "${VERSION:?VERSION must be set}"

RELEASE_DIR="target/${TARGET}/release"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ── Patchelf: strip nix store interpreter and rpath ──────────────────────────
# Only needed when building inside nix devShell. CI uses rustup and produces
# FHS-standard binaries. Single invocation per binary for aarch64 safety
# (patchelf#244).
BINS=(sesame daemon-profile daemon-secrets daemon-launcher daemon-snippets daemon-wm daemon-clipboard daemon-input)
case "${ARCH}" in
    x86_64)  INTERP="/lib64/ld-linux-x86-64.so.2" ;;
    aarch64) INTERP="/lib/ld-linux-aarch64.so.1" ;;
    *)       echo "ERROR: unsupported architecture '${ARCH}' for patchelf" >&2; exit 1 ;;
esac
for bin in "${BINS[@]}"; do
    if [ -f "${RELEASE_DIR}/${bin}" ]; then
        current_interp="$(patchelf --print-interpreter "${RELEASE_DIR}/${bin}" 2>/dev/null || true)"
        if [[ "${current_interp}" == /nix/store/* ]]; then
            patchelf --set-interpreter "${INTERP}" --remove-rpath "${RELEASE_DIR}/${bin}"
            echo "patchelf: ${bin}"
        fi
    fi
done

# ── Headless tarball ─────────────────────────────────────────────────────────
HEADLESS_STAGING="$(mktemp -d)"
DESKTOP_STAGING="$(mktemp -d)"
trap 'rm -rf "$HEADLESS_STAGING" "$DESKTOP_STAGING"' EXIT

mkdir -p \
    "${HEADLESS_STAGING}/usr/bin" \
    "${HEADLESS_STAGING}/usr/lib/systemd/user" \
    "${HEADLESS_STAGING}/usr/lib/systemd/user-preset" \
    "${HEADLESS_STAGING}/usr/share/man/man1" \
    "${HEADLESS_STAGING}/usr/share/bash-completion/completions" \
    "${HEADLESS_STAGING}/usr/share/zsh/site-functions" \
    "${HEADLESS_STAGING}/usr/share/fish/vendor_completions.d" \
    "${HEADLESS_STAGING}/usr/share/doc/open-sesame" \
    "${HEADLESS_STAGING}/usr/share/licenses/open-sesame"

install -Dm755 "${RELEASE_DIR}/sesame"           "${HEADLESS_STAGING}/usr/bin/sesame"
install -Dm755 "${RELEASE_DIR}/daemon-profile"   "${HEADLESS_STAGING}/usr/bin/daemon-profile"
install -Dm755 "${RELEASE_DIR}/daemon-secrets"   "${HEADLESS_STAGING}/usr/bin/daemon-secrets"
install -Dm755 "${RELEASE_DIR}/daemon-launcher"  "${HEADLESS_STAGING}/usr/bin/daemon-launcher"
install -Dm755 "${RELEASE_DIR}/daemon-snippets"  "${HEADLESS_STAGING}/usr/bin/daemon-snippets"

install -Dm644 "${ROOT}/contrib/systemd/open-sesame-headless.target"    "${HEADLESS_STAGING}/usr/lib/systemd/user/open-sesame-headless.target"
install -Dm644 "${ROOT}/contrib/systemd/open-sesame-profile.service"    "${HEADLESS_STAGING}/usr/lib/systemd/user/open-sesame-profile.service"
install -Dm644 "${ROOT}/contrib/systemd/open-sesame-secrets.service"    "${HEADLESS_STAGING}/usr/lib/systemd/user/open-sesame-secrets.service"
install -Dm644 "${ROOT}/contrib/systemd/open-sesame-launcher.service"   "${HEADLESS_STAGING}/usr/lib/systemd/user/open-sesame-launcher.service"
install -Dm644 "${ROOT}/contrib/systemd/open-sesame-snippets.service"   "${HEADLESS_STAGING}/usr/lib/systemd/user/open-sesame-snippets.service"
install -Dm644 "${ROOT}/contrib/systemd/user-preset/90-open-sesame.preset" "${HEADLESS_STAGING}/usr/lib/systemd/user-preset/90-open-sesame.preset"

install -Dm644 "${ROOT}/target/man/sesame.1.gz"      "${HEADLESS_STAGING}/usr/share/man/man1/sesame.1.gz"
install -Dm644 "${ROOT}/target/completions/sesame.bash" "${HEADLESS_STAGING}/usr/share/bash-completion/completions/sesame"
install -Dm644 "${ROOT}/target/completions/_sesame"  "${HEADLESS_STAGING}/usr/share/zsh/site-functions/_sesame"
install -Dm644 "${ROOT}/target/completions/sesame.fish" "${HEADLESS_STAGING}/usr/share/fish/vendor_completions.d/sesame.fish"
install -Dm644 "${ROOT}/config.example.toml"         "${HEADLESS_STAGING}/usr/share/doc/open-sesame/config.example.toml"
install -Dm644 "${ROOT}/LICENSE"                     "${HEADLESS_STAGING}/usr/share/licenses/open-sesame/LICENSE"

: "${SOURCE_DATE_EPOCH:=$(date +%s)}"
export SOURCE_DATE_EPOCH

HEADLESS_TAR="open-sesame-v${VERSION}-${ARCH}.tar.gz"
tar --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime="@${SOURCE_DATE_EPOCH}" \
    -cf - -C "${HEADLESS_STAGING}" . | gzip -n > "${HEADLESS_TAR}"
echo "Created ${HEADLESS_TAR}"

# ── Desktop tarball ──────────────────────────────────────────────────────────
mkdir -p \
    "${DESKTOP_STAGING}/usr/bin" \
    "${DESKTOP_STAGING}/usr/lib/systemd/user" \
    "${DESKTOP_STAGING}/usr/lib/systemd/user-preset" \
    "${DESKTOP_STAGING}/usr/share/licenses/open-sesame-desktop"

install -Dm755 "${RELEASE_DIR}/daemon-wm"        "${DESKTOP_STAGING}/usr/bin/daemon-wm"
install -Dm755 "${RELEASE_DIR}/daemon-clipboard" "${DESKTOP_STAGING}/usr/bin/daemon-clipboard"
install -Dm755 "${RELEASE_DIR}/daemon-input"     "${DESKTOP_STAGING}/usr/bin/daemon-input"

install -Dm644 "${ROOT}/contrib/systemd/open-sesame-desktop.target"       "${DESKTOP_STAGING}/usr/lib/systemd/user/open-sesame-desktop.target"
install -Dm644 "${ROOT}/contrib/systemd/open-sesame-wm.service"           "${DESKTOP_STAGING}/usr/lib/systemd/user/open-sesame-wm.service"
install -Dm644 "${ROOT}/contrib/systemd/open-sesame-clipboard.service"    "${DESKTOP_STAGING}/usr/lib/systemd/user/open-sesame-clipboard.service"
install -Dm644 "${ROOT}/contrib/systemd/open-sesame-input.service"        "${DESKTOP_STAGING}/usr/lib/systemd/user/open-sesame-input.service"
install -Dm644 "${ROOT}/contrib/systemd/user-preset/90-open-sesame-desktop.preset" "${DESKTOP_STAGING}/usr/lib/systemd/user-preset/90-open-sesame-desktop.preset"
install -Dm644 "${ROOT}/LICENSE"                                          "${DESKTOP_STAGING}/usr/share/licenses/open-sesame-desktop/LICENSE"

DESKTOP_TAR="open-sesame-desktop-v${VERSION}-${ARCH}.tar.gz"
tar --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime="@${SOURCE_DATE_EPOCH}" \
    -cf - -C "${DESKTOP_STAGING}" . | gzip -n > "${DESKTOP_TAR}"
echo "Created ${DESKTOP_TAR}"
