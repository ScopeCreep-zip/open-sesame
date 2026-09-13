#!/usr/bin/env bash
# install-ubuntu-local.sh -- install open-sesame from locally built .deb packages.
# Packages mounted at /packages/ from target/debian/ via compose volume.
# Runs as root inside the ubuntu container via docker exec.
set -euo pipefail

ARCH=$(dpkg --print-architecture)
apt-get update
apt-get install -y /packages/open-sesame_*_"${ARCH}".deb
