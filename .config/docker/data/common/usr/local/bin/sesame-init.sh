#!/bin/bash
set -euo pipefail

# SSH_AUTH_SOCK is set by either:
#   - sesame-init.service Environment=SSH_AUTH_SOCK=%t/ssh-agent.sock (systemd path)
#   - Dockerfile ENV SSH_AUTH_SOCK=/run/user/1000/ssh-agent.sock (docker exec path)
: "${SSH_AUTH_SOCK:?SSH_AUTH_SOCK must be set by the systemd unit or Docker ENV}"
export SSH_AUTH_SOCK

echo "Waiting for daemon-profile..."
MAX_WAIT=30
for attempt in $(seq 1 "${MAX_WAIT}"); do
    if /usr/bin/sesame status 2>/dev/null; then
        echo "  daemon-profile reachable (attempt ${attempt}/${MAX_WAIT})"
        break
    fi
    if [[ "${attempt}" -eq "${MAX_WAIT}" ]]; then
        echo "ERROR: daemon-profile not reachable after ${MAX_WAIT}s" >&2
        exit 1
    fi
    echo "  Waiting (attempt ${attempt}/${MAX_WAIT})..."
    sleep 1
done

sleep 2

echo "Verifying SSH agent..."
ssh-add -l || { echo "ERROR: no keys in SSH agent" >&2; exit 1; }

echo "Running sesame init with SSH key..."
exec /usr/bin/sesame init --ssh-key ~/.ssh/id_ed25519.pub --no-keybinding
