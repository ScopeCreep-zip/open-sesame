#!/usr/bin/env bash
# rename-rpm.sh — rename cargo-generate-rpm output to release artifact names.
# Called by ci:release:rename-rpm and ci:release:rename-rpm:arm64 mise tasks.
#
# Environment:
#   TARGET — cargo target triple (required)
#   ARCH   — release architecture label: x86_64 or aarch64 (required)
set -euo pipefail

: "${TARGET:?TARGET must be set}"
: "${ARCH:?ARCH must be set (x86_64 or aarch64)}"

RPM_DIR="target/${TARGET}/generate-rpm"

mapfile -t HEADLESS < <(find "$RPM_DIR" -maxdepth 1 -name 'open-sesame-[0-9]*.rpm' ! -name 'open-sesame-desktop*')
mapfile -t DESKTOP < <(find "$RPM_DIR" -maxdepth 1 -name 'open-sesame-desktop-*.rpm')

HEADLESS_COUNT=${#HEADLESS[@]}
DESKTOP_COUNT=${#DESKTOP[@]}

if [[ "$HEADLESS_COUNT" -ne 1 ]]; then
  echo "ERROR: expected 1 headless RPM, found ${HEADLESS_COUNT}: ${HEADLESS[*]}" >&2
  exit 1
fi
if [[ "$DESKTOP_COUNT" -ne 1 ]]; then
  echo "ERROR: expected 1 desktop RPM, found ${DESKTOP_COUNT}: ${DESKTOP[*]}" >&2
  exit 1
fi

mv "${HEADLESS[0]}" "open-sesame-linux-${ARCH}.rpm"
mv "${DESKTOP[0]}" "open-sesame-desktop-linux-${ARCH}.rpm"

echo "Renamed: open-sesame-linux-${ARCH}.rpm, open-sesame-desktop-linux-${ARCH}.rpm"
