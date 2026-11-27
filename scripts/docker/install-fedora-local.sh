#!/usr/bin/env bash
# install-fedora-local.sh -- install open-sesame from locally built .rpm packages.
# Packages mounted at /packages/ via compose volume (SESAME_PACKAGES).
# Runs as root inside the fedora container via docker exec.
#
# The headless package is chosen by its header (Name open-sesame, this
# machine's architecture), so cargo-generate-rpm's file names and the
# release's renamed artifacts both install; anything other than exactly one
# match is an error.
set -euo pipefail

ARCH=$(uname -m)
shopt -s nullglob
matches=()
for rpm in /packages/*.rpm; do
    if [[ $(rpm -qp --queryformat '%{NAME} %{ARCH}' "$rpm") == "open-sesame $ARCH" ]]; then
        matches+=("$rpm")
    fi
done
if ((${#matches[@]} != 1)); then
    echo "ERROR: expected one open-sesame ${ARCH} RPM in /packages, found ${#matches[@]}: ${matches[*]}" >&2
    ls -la /packages/ >&2
    exit 1
fi
dnf install -y "${matches[0]}"
