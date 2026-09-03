#!/usr/bin/env bash
# install-ubuntu-repo.sh -- install open-sesame from GitHub Pages APT repo.
# Runs as root inside the ubuntu container via docker exec.
set -euo pipefail

curl -fsSL https://scopecreep-zip.github.io/open-sesame/gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/open-sesame.gpg

echo "deb [signed-by=/usr/share/keyrings/open-sesame.gpg] https://scopecreep-zip.github.io/open-sesame noble main" \
    > /etc/apt/sources.list.d/open-sesame.list

apt-get update
apt-get install -y open-sesame
