# scriptlet-helpers.sh — shared helpers for open-sesame deb and RPM scriptlets.
# Concatenated into each scriptlet at build time by mise tasks.
# Do not add a shebang — this file is sourced, not executed directly.

# Upstream systemd-update-helper default (UPDATE_HELPER_USER_TIMEOUT_SEC=15).
SESAME_BUS_TIMEOUT=15s

# List UIDs of all active user systemd instances.
# Matches the enumeration pattern in systemd-update-helper.in.
active_user_uids() {
    systemctl list-units 'user@*' --legend=no 2>/dev/null \
        | sed -n 's/.*user@\([0-9]\+\)\.service.*/\1/p'
}

# Reload unit file definitions for all active user managers.
# Uses per-uid daemon-reload (correct: refreshes unit file cache).
# NOT systemctl reload 'user@*.service' (incorrect: triggers manager re-exec).
reload_user_managers() {
    for uid in $(active_user_uids); do
        SYSTEMD_BUS_TIMEOUT="${SESAME_BUS_TIMEOUT}" systemctl --user -M "$uid@" \
            daemon-reload 2>/dev/null || :
    done
}
