//! Wayland clipboard capture over the data-control protocols
//! (`ext-data-control-v1`, falling back to `wlr-data-control-v1`), through
//! wl-clipboard-rs's `Watcher`: each new selection of the regular clipboard
//! on the first seat that offers text is read and reported as a
//! [`Capture`].
//!
//! The watcher runs on a dedicated thread (its wait is a blocking
//! `poll(2)`); captures cross to the daemon's runtime over a channel.
//! Compositors without data-control (GNOME's Mutter) refuse the watcher;
//! cosmic-comp, sway, Hyprland, niri, and `KWin` offer it to unsandboxed
//! clients.

use std::io::{self, Read};
use std::os::fd::AsFd;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec};
use wl_clipboard_rs::paste::{Error, MimeType, Seat, select_mime_type};
use wl_clipboard_rs::utils::PASSWORD_MANAGER_HINT_MIME_TYPE;
use wl_clipboard_rs::watch::{ClipboardEvent, ClipboardType, Offer, Watcher};

/// The largest selection captured: a larger one is skipped, not truncated.
pub const MAX_CAPTURE_BYTES: usize = 1 << 20;

/// The content of the password manager hint
/// (`x-kde-passwordManagerHint`, KDE Klipper's convention, offered by
/// `KeePassXC`, wl-copy `--sensitive`, and others) that marks a secret.
const SECRET_HINT: &[u8] = b"secret";

/// How long the source client has to deliver a selection.
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(2);
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// One captured selection.
pub struct Capture {
    /// The MIME type the text was read as.
    pub content_type: String,
    /// The selection's text.
    pub text: String,
    /// Whether the source marked the selection a secret (the password
    /// manager hint `x-kde-passwordManagerHint` with content `secret`).
    pub password_manager_hint: bool,
}

impl std::fmt::Debug for Capture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Capture")
            .field("content_type", &self.content_type)
            .field("len", &self.text.len())
            .field("password_manager_hint", &self.password_manager_hint)
            .finish_non_exhaustive()
    }
}

/// Read `pipe` to its end, waiting at most `timeout` in all. `Ok(None)`
/// when it holds more than `limit` bytes.
///
/// # Errors
///
/// `ErrorKind::TimedOut` when the writer neither finishes nor closes in
/// time; the read's own error otherwise.
fn read_bounded(
    mut pipe: impl Read + AsFd,
    limit: usize,
    timeout: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let deadline = Instant::now() + timeout;
    let mut data = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let wait = Timespec {
            tv_sec: i64::try_from(remaining.as_secs()).unwrap_or(i64::MAX),
            tv_nsec: i64::from(remaining.subsec_nanos()),
        };
        let mut fds = [PollFd::new(&pipe, PollFlags::IN)];
        match rustix::event::poll(&mut fds, Some(&wait)) {
            Ok(0) => return Err(io::ErrorKind::TimedOut.into()),
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        }
        match pipe.read(&mut chunk) {
            Ok(0) => return Ok(Some(data)),
            Ok(n) if data.len() + n > limit => return Ok(None),
            Ok(n) => data.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Read `mime_type` of `offer` within the bounds.
fn receive(offer: &mut Offer<'_>, mime_type: &str, limit: usize) -> io::Result<Option<Vec<u8>>> {
    let pipe = offer.receive(mime_type).map_err(io::Error::other)?;
    read_bounded(pipe, limit, RECEIVE_TIMEOUT)
}

/// The capture of a selection offering `mime_types`, `None` when it
/// offers no text, its text is not UTF-8, or it exceeds
/// [`MAX_CAPTURE_BYTES`]. The text type is the one wl-paste reads
/// (`select_mime_type` with `MimeType::Text`: UTF-8 plain text first).
fn capture(mime_types: Vec<String>, offer: &mut Offer<'_>) -> io::Result<Option<Capture>> {
    let hinted = mime_types
        .iter()
        .any(|m| m == PASSWORD_MANAGER_HINT_MIME_TYPE);
    let Some(content_type) = select_mime_type(mime_types, MimeType::Text) else {
        return Ok(None);
    };
    let password_manager_hint = hinted
        && receive(offer, PASSWORD_MANAGER_HINT_MIME_TYPE, SECRET_HINT.len())?
            .is_some_and(|hint| hint == SECRET_HINT);
    let Some(bytes) = receive(offer, &content_type, MAX_CAPTURE_BYTES)? else {
        tracing::debug!(%content_type, "selection larger than the capture limit, skipped");
        return Ok(None);
    };
    let Ok(text) = String::from_utf8(bytes) else {
        tracing::debug!(%content_type, "selection text is not UTF-8, skipped");
        return Ok(None);
    };
    Ok(Some(Capture {
        content_type,
        text,
        password_manager_hint,
    }))
}

/// Report every selection change of `watcher` to `tx`, until `tx` closes
/// (`Ok`) or the Wayland connection fails (`Err`).
fn watch(watcher: &mut Watcher, tx: &tokio::sync::mpsc::Sender<Capture>) -> Result<(), Error> {
    while let Some(event) = watcher.next_event()? {
        let ClipboardEvent::Changed {
            mime_types,
            mut offer,
            ..
        } = event
        else {
            continue;
        };
        match capture(mime_types, &mut offer) {
            Ok(Some(capture)) => {
                if tx.blocking_send(capture).is_err() {
                    return Ok(());
                }
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "clipboard selection could not be read"),
        }
    }
    Ok(())
}

/// Start capturing the regular clipboard on a dedicated thread, sending
/// each selection to `tx`. A Wayland failure after the start reconnects
/// with exponential backoff (1 s to 30 s); the thread ends when `tx`
/// closes.
///
/// # Errors
///
/// `core_types::Error::Platform` when the compositor offers no
/// data-control protocol or no seat, or the thread cannot be started:
/// clipboard capture is unavailable in this session.
pub fn spawn_capture(tx: tokio::sync::mpsc::Sender<Capture>) -> core_types::Result<()> {
    let connect = || Watcher::new(ClipboardType::Regular, Seat::Unspecified);
    let mut watcher = connect()
        .map_err(|e| core_types::Error::Platform(format!("clipboard capture unavailable: {e}")))?;
    std::thread::Builder::new()
        .name("clipboard-capture".into())
        .spawn(move || {
            let mut backoff = INITIAL_BACKOFF;
            loop {
                match watch(&mut watcher, &tx) {
                    Ok(()) => return,
                    Err(e) => tracing::error!(error = %e, "clipboard capture failed, reconnecting"),
                }
                watcher = loop {
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    if tx.is_closed() {
                        return;
                    }
                    match connect() {
                        Ok(watcher) => break watcher,
                        Err(e) => tracing::warn!(error = %e, "clipboard capture reconnect failed"),
                    }
                };
                backoff = INITIAL_BACKOFF;
            }
        })
        .map(drop)
        .map_err(|e| core_types::Error::Platform(format!("clipboard capture thread: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn a_pipe_is_read_to_its_end() {
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(b"copied text").unwrap();
        drop(writer);
        assert_eq!(
            read_bounded(reader, 64, RECEIVE_TIMEOUT)
                .unwrap()
                .as_deref(),
            Some(&b"copied text"[..])
        );
    }

    #[test]
    fn a_selection_over_the_limit_is_skipped_not_truncated() {
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(&[b'x'; 65]).unwrap();
        drop(writer);
        assert_eq!(read_bounded(reader, 64, RECEIVE_TIMEOUT).unwrap(), None);
    }

    #[test]
    fn a_source_that_never_finishes_times_out() {
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(b"partial").unwrap();
        let err = read_bounded(reader, 64, Duration::from_millis(50)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        drop(writer);
    }
}
