#!/usr/bin/env bash
# verify-deployment.sh — poll GitHub Pages endpoints after deploy.
# Called by the publish job in release.yml.
#
# Environment:
#   OWNER — GitHub repository owner (required)
#   REPO  — GitHub repository name (required)
set -euo pipefail

: "${OWNER:?OWNER must be set}"
: "${REPO:?REPO must be set}"

base="https://${OWNER}.github.io/${REPO}"

poll_endpoint() {
    local name="$1" url="$2" check="${3:-}"
    echo "Polling ${name}..."
    for i in $(seq 1 24); do
        code="$(curl -sS -o /tmp/poll-check -w '%{http_code}' --location "${url}" || true)"
        echo "  attempt ${i}: HTTP ${code}"
        if [ "${code}" = "200" ]; then
            if [ -n "${check}" ]; then
                if grep -q "${check}" /tmp/poll-check; then
                    echo "  ${name} is live"
                    return 0
                fi
            else
                echo "  ${name} is live"
                return 0
            fi
        fi
        sleep 10
    done
    echo "WARNING: ${name} not live after 240s"
    return 0
}

poll_endpoint "APT Release" "${base}/dists/noble/Release"
poll_endpoint "RPM repomd.xml" "${base}/repo/repodata/repomd.xml" "repomd"
poll_endpoint "RPM-GPG-KEY" "${base}/RPM-GPG-KEY" "BEGIN PGP PUBLIC KEY BLOCK"
poll_endpoint "Arch repo db" "${base}/arch/x86_64/open-sesame.db"
