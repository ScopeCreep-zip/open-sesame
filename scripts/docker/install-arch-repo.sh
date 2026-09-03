#!/usr/bin/env bash
# install-arch-repo.sh -- install open-sesame from GitHub Pages pacman repo.
# Runs as root inside the arch container via docker exec.
set -euo pipefail

curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key | pacman-key --add -
KEY_ID=$(curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key \
    | gpg --show-keys --with-colons 2>/dev/null \
    | awk -F: '/^pub/{print $5; exit}')
pacman-key --lsign-key "${KEY_ID}"

printf '\n[open-sesame]\nSigLevel = Required DatabaseRequired\nServer = https://scopecreep-zip.github.io/open-sesame/arch/$arch\n' >> /etc/pacman.conf

pacman -Syu --noconfirm open-sesame-bin
