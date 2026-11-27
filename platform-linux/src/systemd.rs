//! systemd integration helpers.
//!
//! `sd_notify::notify` leaves `NOTIFY_SOCKET` set, so watchdog keepalives
//! and status updates keep working after `READY=1`. Outside systemd (no
//! `NOTIFY_SOCKET`) every notification is a no-op.

use sd_notify::NotifyState;

/// Notify systemd that the daemon is ready (Type=notify).
pub fn notify_ready() {
    match sd_notify::notify(&[NotifyState::Ready]) {
        Ok(()) => tracing::info!("sd_notify: READY=1 sent successfully"),
        Err(e) => tracing::error!(error = %e, "sd_notify: failed to send READY=1"),
    }
}

/// Notify systemd that the daemon is entering a reload cycle (Type=notify-reload).
///
/// Sends `RELOADING=1` + `MONOTONIC_USEC=<now>` in one datagram so systemd
/// transitions the service to reload-notify state; systemd v253+ fails the
/// reload without the timestamp. Must be followed by `notify_ready()` after
/// the reload/transition work completes.
pub fn notify_reloading() {
    let now = match NotifyState::monotonic_usec_now() {
        Ok(now) => now,
        Err(e) => {
            tracing::error!(error = %e, "sd_notify: CLOCK_MONOTONIC unreadable, RELOADING=1 not sent");
            return;
        }
    };
    tracing::info!(?now, "sd_notify: sending RELOADING=1");
    match sd_notify::notify(&[NotifyState::Reloading, now]) {
        Ok(()) => tracing::info!("sd_notify: RELOADING=1 sent successfully"),
        Err(e) => tracing::error!(error = %e, "sd_notify: failed to send RELOADING=1"),
    }
}

/// Send a watchdog keepalive to systemd.
pub fn notify_watchdog() {
    if let Err(e) = sd_notify::notify(&[NotifyState::Watchdog]) {
        tracing::warn!(error = %e, "sd_notify: watchdog ping failed");
    }
}

/// Update the daemon's status string visible in `systemctl status`.
pub fn notify_status(status: &str) {
    if let Err(e) = sd_notify::notify(&[NotifyState::Status(status)]) {
        tracing::warn!(error = %e, "sd_notify: status update failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    const RELOADING_TEST: &str =
        "systemd::tests::reloading_sends_the_state_and_a_monotonic_timestamp";

    /// The reload datagram systemd receives: `RELOADING=1` then a
    /// `MONOTONIC_USEC` timestamp, one state per line.
    ///
    /// Setting `NOTIFY_SOCKET` in-process is `unsafe` (`std::env::set_var`),
    /// so the test re-runs itself as a child with the variable set; the
    /// child only sends.
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "NOTIFY_SOCKET is sd_notify(3)'s; set only marks the re-run child"
    )]
    fn reloading_sends_the_state_and_a_monotonic_timestamp() {
        if std::env::var_os("NOTIFY_SOCKET").is_some() {
            notify_reloading();
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("notify.sock");
        let server = UnixDatagram::bind(&path).expect("bind notify socket");
        let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", RELOADING_TEST, "--test-threads=1"])
            .env("NOTIFY_SOCKET", &path)
            .status()
            .expect("run child test");
        assert!(status.success(), "child test failed: {status}");
        server
            .set_nonblocking(true)
            .expect("nonblocking notify socket");
        let mut buf = [0u8; 256];
        let n = server.recv(&mut buf).expect("datagram");
        let msg = std::str::from_utf8(&buf[..n]).expect("utf-8");
        let mut lines = msg.lines();
        assert_eq!(lines.next(), Some("RELOADING=1"));
        let usec = lines
            .next()
            .and_then(|l| l.strip_prefix("MONOTONIC_USEC="))
            .and_then(|v| v.parse::<u64>().ok())
            .expect("MONOTONIC_USEC=<integer>");
        assert!(usec > 0);
        assert_eq!(lines.next(), None);
    }
}
