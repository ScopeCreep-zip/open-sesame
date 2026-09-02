#!/usr/bin/env bash
# generate-arch-repo.sh — create pacman repo database for GitHub Pages.
# Called by ci:release:arch-repo mise task.
#
# Usage: ./scripts/arch/generate-arch-repo.sh SITE_DIR PACKAGES_DIR [GPG_KEY_ID]
set -euo pipefail

SITE_DIR="${1:?usage: $0 SITE_DIR PACKAGES_DIR [GPG_KEY_ID]}"
PACKAGES_DIR="${2:?usage: $0 SITE_DIR PACKAGES_DIR [GPG_KEY_ID]}"
GPG_KEY_ID="${3:-}"

for arch in x86_64 aarch64; do
    ARCH_DIR="${SITE_DIR}/${arch}"
    mkdir -p "${ARCH_DIR}"

    pkg_count=0
    for pkg in "${PACKAGES_DIR}"/*-"${arch}.pkg.tar.zst"; do
        [ -f "$pkg" ] || continue
        cp "$pkg" "${ARCH_DIR}/"
        pkg_count=$((pkg_count + 1))

        # Sign each package (binary detached, not armored — pacman requirement)
        if [ -n "${GPG_KEY_ID}" ]; then
            gpg --batch --yes --detach-sign --no-armor \
                --default-key "${GPG_KEY_ID}" \
                "${ARCH_DIR}/$(basename "$pkg")"
        fi
    done

    if [ "${pkg_count}" -eq 0 ]; then
        echo "No ${arch} packages found in ${PACKAGES_DIR}, skipping"
        continue
    fi

    # Generate repo database
    pushd "${ARCH_DIR}" > /dev/null
    if [ -n "${GPG_KEY_ID}" ]; then
        repo-add --sign --key "${GPG_KEY_ID}" open-sesame.db.tar.gz ./*.pkg.tar.zst
    else
        repo-add open-sesame.db.tar.gz ./*.pkg.tar.zst
    fi

    # Verify signatures exist if signing was requested
    if [ -n "${GPG_KEY_ID}" ]; then
        for sig in open-sesame.db.sig open-sesame.files.sig; do
            if [ ! -f "${sig}" ] && [ ! -L "${sig}" ]; then
                echo "ERROR: expected ${sig} after repo-add --sign but not found" >&2
                exit 1
            fi
        done
    fi

    # Replace symlinks with copies (GitHub Pages deploys via tar artifact, no symlinks)
    for link in open-sesame.db open-sesame.db.sig open-sesame.files open-sesame.files.sig; do
        if [ -L "${link}" ]; then
            target="$(readlink "${link}")"
            rm "${link}"
            cp "${target}" "${link}"
        fi
    done

    popd > /dev/null
    echo "Arch repo for ${arch}: ${pkg_count} package(s)"
done

echo "Arch repo generated at ${SITE_DIR}"
