//! systemd integration helpers.

/// Notify systemd that the daemon is ready (Type=notify).
///
/// `unset_environment` is false to preserve NOTIFY_SOCKET for
/// subsequent watchdog keepalive pings.
pub fn notify_ready() {
    match std::env::var("NOTIFY_SOCKET") {
        Ok(val) => {
            tracing::info!(notify_socket = %val, "sd_notify: NOTIFY_SOCKET present, sending READY=1")
        }
        Err(_) => tracing::warn!("sd_notify: NOTIFY_SOCKET not set — notify will be a no-op"),
    }
    match sd_notify::notify(false, &[sd_notify::NotifyState::Ready]) {
        Ok(()) => tracing::info!("sd_notify: READY=1 sent successfully"),
        Err(e) => tracing::error!(error = %e, "sd_notify: failed to send READY=1"),
    }
}

/// Notify systemd that the daemon is entering a reload cycle (Type=notify-reload).
///
/// Sends `RELOADING=1` + `MONOTONIC_USEC=<now>` in one datagram so systemd
/// transitions the service to reload-notify state. Must be followed by
/// `notify_ready()` after the reload/transition work completes.
pub fn notify_reloading() {
    let mono_usec = {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: CLOCK_MONOTONIC is always valid, ts is stack-allocated and valid.
        unsafe {
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        }
        (ts.tv_sec as u64) * 1_000_000 + (ts.tv_nsec as u64) / 1_000
    };

    tracing::info!(mono_usec, "sd_notify: sending RELOADING=1");

    match sd_notify::notify(
        false,
        &[sd_notify::NotifyState::Custom(&format!(
            "RELOADING=1\nMONOTONIC_USEC={mono_usec}"
        ))],
    ) {
        Ok(()) => tracing::info!("sd_notify: RELOADING=1 sent successfully"),
        Err(e) => tracing::error!(error = %e, "sd_notify: failed to send RELOADING=1"),
    }
}

/// Send a watchdog keepalive to systemd.
pub fn notify_watchdog() {
    if let Err(e) = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]) {
        tracing::warn!(error = %e, "sd_notify: watchdog ping failed");
    }
}

/// Update the daemon's status string visible in `systemctl status`.
pub fn notify_status(status: &str) {
    sd_notify::notify(false, &[sd_notify::NotifyState::Status(status)]).ok();
}
