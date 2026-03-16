//! systemd integration helpers.

/// Notify systemd that the daemon is ready (Type=notify).
///
/// `unset_environment` is false to preserve NOTIFY_SOCKET for
/// subsequent watchdog keepalive pings.
pub fn notify_ready() {
    sd_notify::notify(false, &[sd_notify::NotifyState::Ready]).ok();
}

/// Send a watchdog keepalive to systemd.
pub fn notify_watchdog() {
    sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]).ok();
}

/// Update the daemon's status string visible in `systemctl status`.
pub fn notify_status(status: &str) {
    sd_notify::notify(false, &[sd_notify::NotifyState::Status(status)]).ok();
}
