# scriptlet-helpers.sh -- shared helpers for open-sesame deb and RPM scriptlets.
# Concatenated into each scriptlet at build time by mise tasks.
# Do not add a shebang -- this file is sourced, not executed directly.

# Upstream systemd-update-helper default (UPDATE_HELPER_USER_TIMEOUT_SEC=15).
SESAME_BUS_TIMEOUT=15s

# Guard: no-op if systemd is not running (docker build, chroot, container
# image layer). Every scriptlet calls this before touching user managers.
sesame_require_systemd() {
    [ -d /run/systemd/system ] || exit 0
}

# Enumerate UIDs of active user manager instances.
# Matches the pattern in systemd-update-helper.in.
sesame_active_user_uids() {
    systemctl list-units 'user@*' --legend=no 2>/dev/null \
        | sed -n 's/.*user@\([0-9]\+\)\.service.*/\1/p'
}

# Run a systemctl --user command against a specific user's manager.
# Uses -M "$uid@" which forces a PAM-authenticated stdio-bridge connection,
# avoiding "Transport endpoint is not connected" when running as root.
sesame_user_systemctl() {
    local uid="$1"; shift
    SYSTEMD_BUS_TIMEOUT="${SESAME_BUS_TIMEOUT}" \
        systemctl --user -M "$uid@" "$@" 2>/dev/null || :
}
