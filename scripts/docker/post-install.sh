#!/usr/bin/env bash
# post-install.sh -- activate open-sesame services after package installation
# in a running systemd container. Called via docker exec after packages are
# installed by the profile-specific install step.
#
# Usage: docker exec --user <username> <container> /usr/local/bin/post-install.sh
#
# This script must run as the container's unprivileged user (not root) so
# systemctl --user operates on the correct user manager instance.
#
# Does NOT run sesame init directly. sesame-init.service handles initialization
# via systemd, including the daemon-profile Type=notify-reload transition from
# pre-install to full mode.
set -euo pipefail

echo "=== Activating open-sesame services ==="

# Reload unit file definitions (packages installed after user manager started)
systemctl --user daemon-reload

# Reset any rate-limited services (sesame-init may have hit StartLimitBurst
# if it ran before packages were installed in local/source profiles).
systemctl --user reset-failed 2>/dev/null || true

# Apply preset policy (enables services declared in 90-open-sesame*.preset)
systemctl --user preset-all 2>/dev/null || true

# Start the headless target (pulls in profile, secrets, launcher, snippets)
systemctl --user start open-sesame-headless.target

# Explicitly start sesame-init in case it was rate-limited before reset-failed
systemctl --user start sesame-init.service 2>/dev/null || true

# Wait for daemon-profile to complete its mode transition.
# With Type=notify-reload, daemon-profile sends RELOADING=1 when it detects
# installation.toml, then READY=1 after full mode initialization completes.
# SubState transitions: running -> reload-notify -> running.
echo "Waiting for daemon-profile mode transition..."
for i in $(seq 1 60); do
    sub=$(systemctl --user show open-sesame-profile.service --property=SubState --value 2>/dev/null || echo "unknown")

    # running means either: never transitioned (no installation.toml yet) or
    # transition completed (READY=1 received). Check for installation.toml
    # to distinguish.
    if [ "$sub" = "running" ] && [ -f "${HOME}/.config/pds/installation.toml" ]; then
        echo "  daemon-profile in full mode (attempt ${i}/60)"
        break
    fi

    # reload-notify means RELOADING=1 sent, transition in progress -- keep waiting.
    if [ "$sub" = "reload-notify" ]; then
        if [ "$((i % 5))" -eq 0 ]; then
            echo "  daemon-profile transitioning (SubState=reload-notify, attempt ${i}/60)..."
        fi
    fi

    if [ "${i}" -eq 60 ]; then
        echo "ERROR: daemon-profile did not complete mode transition after 60s" >&2
        systemctl --user status open-sesame-profile.service --no-pager 2>&1 || true
        exit 1
    fi

    sleep 1
done

# Wait for sesame-init.service to complete initialization.
# The service creates installation.toml, enrolls SSH key, unlocks vault.
# With the Type=notify-reload fix, daemon-profile's mode transition is
# synchronized -- sesame-init should succeed on its first attempt.
echo "Waiting for sesame-init.service..."
for i in $(seq 1 60); do
    state=$(systemctl --user show sesame-init.service --property=ActiveState --value 2>/dev/null || echo "unknown")
    sub=$(systemctl --user show sesame-init.service --property=SubState --value 2>/dev/null || echo "unknown")

    if [ "$state" = "active" ] && [ "$sub" = "exited" ]; then
        echo "  sesame-init.service completed (attempt ${i}/60)"
        break
    fi

    # ConditionPathExists=!installation.toml means the service won't restart
    # after installation.toml exists. If the service is inactive and the file
    # exists, init completed on a prior attempt.
    if [ "$state" = "inactive" ] && [ -f "${HOME}/.config/pds/installation.toml" ]; then
        echo "  sesame-init.service inactive, installation.toml exists (attempt ${i}/60)"
        break
    fi

    if [ "${i}" -eq 60 ]; then
        echo "ERROR: sesame-init.service did not complete after 60s" >&2
        systemctl --user status sesame-init.service --no-pager 2>&1 || true
        journalctl --user -u sesame-init.service --no-pager --since "2 min ago" 2>&1 || true
        exit 1
    fi

    sleep 1
done

# Final reachability check
echo "Verifying daemon-profile reachable..."
for i in $(seq 1 15); do
    if sesame status 2>/dev/null; then
        echo "  daemon-profile reachable (attempt ${i}/15)"
        break
    fi
    if [ "${i}" -eq 15 ]; then
        echo "ERROR: daemon-profile not reachable after 15s" >&2
        systemctl --user status open-sesame-profile.service --no-pager 2>&1 || true
        exit 1
    fi
    sleep 1
done

echo "=== Verification ==="
sesame status --doctor --output=json
