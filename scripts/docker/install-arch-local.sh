#!/usr/bin/env bash
# install-arch-local.sh -- install open-sesame from locally built .pkg.tar.zst.
# Packages mounted at /packages/ (repo root) via compose volume.
# Runs as root inside the arch container via docker exec.
set -euo pipefail

shopt -s nullglob
pkgs=(/packages/open-sesame-bin-*-x86_64.pkg.tar.zst)
if [ ${#pkgs[@]} -eq 0 ]; then
    echo "ERROR: no open-sesame .pkg.tar.zst found in /packages/" >&2
    ls -la /packages/*.pkg.tar.zst 2>&1 || echo "  (no .pkg.tar.zst files)" >&2
    exit 1
fi
pacman -U --noconfirm "${pkgs[@]}"
