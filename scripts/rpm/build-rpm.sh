#!/usr/bin/env bash
# build-rpm.sh — build both open-sesame RPMs with version-locked desktop requires and optional signing.
# Called by ci:build:rpm and ci:build:rpm:arm64 mise tasks.
#
# Environment:
#   TARGET                 — cargo target triple (required)
#   GPG_SIGNING_KEY_FILE   — path to PGP private key for --signing-key (optional)
set -euo pipefail

: "${TARGET:?TARGET must be set (e.g. x86_64-unknown-linux-gnu)}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERSION=$("${ROOT}/scripts/common/cargo-version.sh")

# Build signing arguments if key file is provided
SIGN_ARGS=()
if [ -n "${GPG_SIGNING_KEY_FILE:-}" ]; then
  SIGN_ARGS=(--signing-key "$GPG_SIGNING_KEY_FILE")
fi

# Write version-locked requires override to a temp file (avoids shell escaping)
OVERRIDES="$(mktemp)"
trap 'rm -f "$OVERRIDES"' EXIT
cat > "$OVERRIDES" <<EOF
[requires]
open-sesame = ">= ${VERSION}"
EOF

echo "==> Building headless .rpm (open-sesame) v${VERSION}..."
cargo generate-rpm -p open-sesame \
  --payload-compress gzip \
  --target "${TARGET}" \
  "${SIGN_ARGS[@]}"

echo "==> Building desktop .rpm (open-sesame-desktop) v${VERSION} requires open-sesame >= ${VERSION}..."
cargo generate-rpm -p daemon-wm \
  --payload-compress gzip \
  --target "${TARGET}" \
  --metadata-overwrite "$OVERRIDES" \
  "${SIGN_ARGS[@]}"
