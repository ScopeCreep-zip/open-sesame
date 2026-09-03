#!/usr/bin/env bash
# install-fedora-local.sh -- install open-sesame from locally built .rpm packages.
# Packages mounted at /packages/ from target/x86_64-.../generate-rpm/ via compose volume.
# Runs as root inside the fedora container via docker exec.
set -euo pipefail

# Shell glob expansion, not dnf pattern matching.
shopt -s nullglob
rpms=(/packages/open-sesame-[0-9]*.rpm)
if [ ${#rpms[@]} -eq 0 ]; then
    echo "ERROR: no open-sesame RPM found in /packages/" >&2
    ls -la /packages/ >&2
    exit 1
fi
dnf install -y "${rpms[@]}"
