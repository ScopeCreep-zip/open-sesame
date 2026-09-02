#!/usr/bin/env bash
# rpm-gpg-import.sh — prepare a GPG homedir for RPM package signing.
# Adapted from github.com/sirredbeard/github-pages-rpm-repo
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PUB_DIR="$ROOT/packaging/gpg"
GENERATE=0
[[ "${1:-}" == "--generate" ]] && GENERATE=1

PRIVATE_KEY="${GPG_PRIVATE_KEY:-}"
PRIVATE_FILE="${GPG_PRIVATE_KEY_FILE:-}"
HOME_IN="${GPG_HOME:-}"

if [[ -n "$HOME_IN" && -d "$HOME_IN" ]]; then
  HOME_GPG="$HOME_IN"
else
  HOME_GPG="$(mktemp -d "${TMPDIR:-/tmp}/open-sesame-rpm-gpg.XXXXXX")"
  chmod 700 "$HOME_GPG"
  if [[ -n "$PRIVATE_KEY" ]]; then
    printf '%s\n' "$PRIVATE_KEY" | gpg --homedir "$HOME_GPG" --batch --import
  elif [[ -f "$PRIVATE_FILE" ]]; then
    gpg --homedir "$HOME_GPG" --batch --import "$PRIVATE_FILE"
  elif [[ "$GENERATE" -eq 1 ]]; then
    batch="$(mktemp)"
    cat > "$batch" <<'BATCH'
%echo Generating Open Sesame RPM signing key
Key-Type: RSA
Key-Length: 4096
Name-Real: Open Sesame RPM signing
Name-Email: rpm-signing@scopecreep.zip
Expire-Date: 0
%no-protection
%commit
BATCH
    gpg --homedir "$HOME_GPG" --batch --generate-key "$batch"
    rm -f "$batch"
    KEYID=$(gpg --homedir "$HOME_GPG" --list-keys --with-colons | awk -F: '/^pub/ {print $5; exit}')
    mkdir -p "$PUB_DIR"
    echo "$KEYID" > "$PUB_DIR/keyid.txt"
    gpg --homedir "$HOME_GPG" --armor --export "$KEYID" > "$PUB_DIR/public.asc"
  else
    echo "error: set GPG_PRIVATE_KEY, GPG_PRIVATE_KEY_FILE, GPG_HOME, or pass --generate" >&2
    exit 1
  fi
fi

KEYID=$(gpg --homedir "$HOME_GPG" --list-keys --with-colons | awk -F: '/^pub/ {print $5; exit}')
want="${GPG_KEY_ID:-}"
if [[ -z "$want" && -f "$PUB_DIR/keyid.txt" ]]; then
  want=$(tr -d ' \n' < "$PUB_DIR/keyid.txt")
fi
if [[ -n "$want" ]] && gpg --homedir "$HOME_GPG" --list-secret-keys --with-colons | grep -q "$want"; then
  KEYID="$want"
fi
if [[ -z "$KEYID" ]]; then
  echo "error: no public key in $HOME_GPG" >&2
  exit 1
fi
echo "$KEYID" > "${HOME_GPG}/.keyid"
echo "rpm gpg ready key=$KEYID home=$HOME_GPG" >&2
echo "$HOME_GPG"
