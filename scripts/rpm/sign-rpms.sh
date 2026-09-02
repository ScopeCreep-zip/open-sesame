#!/usr/bin/env bash
# sign-rpms.sh — rpmsign --addsign every .rpm in a directory.
# Adapted from github.com/sirredbeard/github-pages-rpm-repo
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RPM_DIR="${1:?usage: $0 RPM_DIR}"

if [[ ! -d "$RPM_DIR" ]]; then
  echo "error: not a directory: $RPM_DIR" >&2
  exit 1
fi
mapfile -t RPMS < <(find "$RPM_DIR" -maxdepth 1 -type f -name '*.rpm' | sort)
if [[ "${#RPMS[@]}" -eq 0 ]]; then
  echo "error: no RPMs in $RPM_DIR" >&2
  exit 1
fi

if ! command -v rpmsign >/dev/null 2>&1; then
  echo "error: rpmsign required (install rpm-sign)" >&2
  exit 1
fi

GPG_HOME="$("${ROOT}/scripts/rpm/rpm-gpg-import.sh")"
GPG_KEY_ID="$(cat "${GPG_HOME}/.keyid")"
export GNUPGHOME="$GPG_HOME"

RPM_MACROS="$(mktemp "${TMPDIR:-/tmp}/rpmmacros.XXXXXX")"
trap 'rm -f "$RPM_MACROS"' EXIT
cat > "$RPM_MACROS" <<MACROS
%_signature gpg
%_gpg_path ${GPG_HOME}
%_gpg_name ${GPG_KEY_ID}
%__gpg /usr/bin/gpg
%_gpg_sign_cmd_extra_args --batch --pinentry-mode loopback
MACROS
export RPM_MACROS_FILE="$RPM_MACROS"
# rpmsign reads ~/.rpmmacros by default; override via --macros is not portable
# across rpmsign versions, so symlink to temp file instead
ln -sf "$RPM_MACROS" "${HOME}/.rpmmacros"

echo "delsign + addsign ${#RPMS[@]} RPM(s) with key $GPG_KEY_ID"
rpmsign --delsign "${RPMS[@]}"
rpmsign --addsign "${RPMS[@]}"

mkdir -p "${ROOT}/dist" "${ROOT}/packaging/gpg"
gpg --homedir "$GPG_HOME" --armor --export "$GPG_KEY_ID" \
  > "${ROOT}/dist/RPM-GPG-KEY"
cp -f "${ROOT}/dist/RPM-GPG-KEY" "${ROOT}/packaging/gpg/public.asc"
echo "$GPG_KEY_ID" > "${ROOT}/packaging/gpg/keyid.txt"

rpm --import "${ROOT}/dist/RPM-GPG-KEY"

fail=0
for rpm_file in "${RPMS[@]}"; do
  # Use rpm --checksig exit code as primary verification.
  # rpm returns non-zero when signature verification fails.
  # -v output varies across rpm versions; exit code is stable.
  if rpm --checksig -v "$rpm_file" 2>&1; then
    echo "OK $(basename "$rpm_file")"
  else
    echo "error: signature verification failed for $rpm_file" >&2
    fail=1
  fi
done
if [[ "$fail" -ne 0 ]]; then
  exit 1
fi

echo "OK: signed ${#RPMS[@]} RPM(s); public key ${ROOT}/dist/RPM-GPG-KEY"
