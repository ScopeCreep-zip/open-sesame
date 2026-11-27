#!/usr/bin/env bash
# install-arch-local.sh -- install open-sesame from locally built .pkg.tar.zst.
# Packages mounted at /packages/ via compose volume (SESAME_PACKAGES).
# Runs as root inside the arch container via docker exec.
#
# The headless package is chosen by its metadata (pkgname open-sesame-bin)
# and this machine's architecture; anything other than exactly one match is
# an error.
set -euo pipefail

ARCH=$(uname -m)
shopt -s nullglob
matches=()
for pkg in /packages/*-"${ARCH}".pkg.tar.zst; do
    read -r name _ < <(pacman -Qp "$pkg")
    if [[ "$name" == open-sesame-bin ]]; then
        matches+=("$pkg")
    fi
done
if ((${#matches[@]} != 1)); then
    echo "ERROR: expected one open-sesame-bin ${ARCH} package in /packages, found ${#matches[@]}: ${matches[*]}" >&2
    ls -la /packages/*.pkg.tar.zst >&2 || true
    exit 1
fi
pacman -U --noconfirm "${matches[0]}"
