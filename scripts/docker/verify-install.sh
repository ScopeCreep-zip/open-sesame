#!/usr/bin/env bash
# verify-install.sh -- install open-sesame in a systemd container and verify
# that its installed units run.
#
# Usage:
#   scripts/docker/verify-install.sh <ubuntu|fedora|arch> local <DIR> [--keep]
#   scripts/docker/verify-install.sh <ubuntu|fedora|arch> repo [--keep]
#   scripts/docker/verify-install.sh ubuntu source [--keep]
#
#   local DIR  install the packages in DIR (mounted at /packages): .deb,
#              .rpm, or .pkg.tar.zst, chosen by their metadata
#   repo       install from the published repository
#   source     the image's own build of this tree (Dockerfile source stage)
#   --keep     leave the container running for inspection
#
# The compose service <distro>-<source> boots systemd as PID 1 with a
# lingering user. Once the user's service manager answers, the package is
# installed (as root) and scripts/docker/post-install.sh starts the headless
# target and sesame-init as that user, and fails unless every headless
# daemon runs, the vault is unlocked, and no doctor check fails. On failure
# the system and user journals are printed. The container and its volumes
# are removed on exit unless --keep is given.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

usage() {
    sed -n '2,/^[^#]/{/^#/p;}' "${BASH_SOURCE[0]}" >&2
    exit 2
}

(($# >= 2)) || usage
DISTRO=$1
SOURCE=$2
shift 2
case "$DISTRO" in
ubuntu | fedora | arch) ;;
*)
    echo "ERROR: unknown distribution '$DISTRO' (ubuntu, fedora, arch)" >&2
    exit 2
    ;;
esac
case "$SOURCE" in
local)
    (($# >= 1)) || usage
    [[ -d "$1" ]] || {
        echo "ERROR: package directory '$1' does not exist" >&2
        exit 2
    }
    SESAME_PACKAGES=$(cd -- "$1" && pwd)
    export SESAME_PACKAGES
    shift
    ;;
repo) ;;
source)
    [[ "$DISTRO" == ubuntu ]] || {
        echo "ERROR: the source install exists for ubuntu only" >&2
        exit 2
    }
    ;;
*)
    echo "ERROR: unknown install source '$SOURCE' (local, repo, source)" >&2
    exit 2
    ;;
esac
KEEP=0
case "${1:-}" in
"") ;;
--keep) KEEP=1 ;;
*) usage ;;
esac

SERVICE=$DISTRO-$SOURCE
CONTAINER=open-sesame-$SERVICE
# The image's user is named after the distribution.
USERNAME=$DISTRO

# Host tools run without a development shell's library path.
docker() { env -u LD_LIBRARY_PATH docker "$@"; }
compose() { docker compose --project-directory "$ROOT" -f "$ROOT/compose.yml" "$@"; }

finish() {
    local status=$?
    if ((status != 0)); then
        echo "=== ${CONTAINER}: system journal ===" >&2
        docker exec "$CONTAINER" journalctl --no-pager -n 200 >&2 || true
        echo "=== ${CONTAINER}: ${USERNAME}'s journal ===" >&2
        docker exec --user "$USERNAME" "$CONTAINER" journalctl --user --no-pager -n 400 >&2 || true
    fi
    if ((KEEP)); then
        echo "kept: ${CONTAINER} (docker compose down -v ${SERVICE})"
    else
        compose down -v "$SERVICE" >/dev/null 2>&1 || true
    fi
    exit "$status"
}
trap finish EXIT

compose down -v "$SERVICE" >/dev/null 2>&1 || true
compose up --build -d "$SERVICE"

# The user's service manager, up once systemd has booted and lingering has
# started it.
for _ in $(seq 60); do
    docker exec --user "$USERNAME" "$CONTAINER" systemctl --user show-environment >/dev/null 2>&1 && break
    sleep 1
done
docker exec --user "$USERNAME" "$CONTAINER" systemctl --user show-environment >/dev/null || {
    echo "ERROR: ${USERNAME}'s service manager did not start in ${CONTAINER}" >&2
    exit 1
}

case "$SOURCE" in
local) docker exec "$CONTAINER" install-local.sh ;;
repo) docker exec "$CONTAINER" install-repo.sh ;;
source) ;;
esac
docker exec --user "$USERNAME" "$CONTAINER" post-install.sh
echo "=== ${SERVICE}: verified ==="
