#!/usr/bin/env bash
# install-ubuntu-local.sh -- install open-sesame from locally built .deb packages.
# Packages mounted at /packages/ via compose volume (SESAME_PACKAGES).
# Runs as root inside the ubuntu container via docker exec.
#
# The headless package is chosen by its control fields (Package open-sesame,
# this machine's Architecture), so cargo-deb's file names and the release's
# renamed artifacts both install; anything other than exactly one match is
# an error.
set -euo pipefail

ARCH=$(dpkg --print-architecture)
matches=()
for deb in /packages/*.deb; do
    [[ -e "$deb" ]] || continue
    if [[ $(dpkg-deb --field "$deb" Package) == open-sesame &&
    $(dpkg-deb --field "$deb" Architecture) == "$ARCH" ]]; then
        matches+=("$deb")
    fi
done
if ((${#matches[@]} != 1)); then
    echo "ERROR: expected one open-sesame ${ARCH} package in /packages, found ${#matches[@]}: ${matches[*]}" >&2
    exit 1
fi

apt-get update
apt-get install -y "${matches[0]}"
