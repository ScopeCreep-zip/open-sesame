#!/usr/bin/env bash
# cargo-version.sh — print the workspace version from Cargo metadata.
# Usage: VERSION=$(./scripts/common/cargo-version.sh)
set -euo pipefail
cargo metadata --format-version=1 -q \
    | jq -r '.packages[] | select(.name == "open-sesame") | .version'
