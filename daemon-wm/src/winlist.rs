//! The compositor window list: a poll loop on its own OS thread with
//! on-demand refresh, or, without a compositor backend, focus tracking.
//!
//! Compositor backends do synchronous Wayland roundtrips with `poll(2)`,
//! which would stall the daemon's single-threaded tokio runtime, so the
//! poll loop runs on a dedicated thread.

use core_types::Window;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;
use tokio::sync::{Mutex, watch};

/// The daemon's view of the open windows, shared with the task that
/// refreshes it.
pub type Windows = Arc<Mutex<Vec<Window>>>;

/// How often the poll thread re-enumerates without a request.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Consecutive failed enumerations after which the compositor is dead.
const MAX_FAILURES: u32 = 10;

/// On-demand refresh of a polled window list.
#[derive(Debug)]
pub struct Refresh {
    wake: std::sync::mpsc::Sender<()>,
    published: watch::Receiver<u64>,
    /// Set when the poll thread found the compositor connection dead.
    compositor_lost: watch::Receiver<bool>,
}

impl Refresh {
    /// Resolve once the compositor connection is lost; never when the
    /// poll thread ends for another reason.
    pub async fn lost(&mut self) {
        if self.compositor_lost.wait_for(|lost| *lost).await.is_err() {
            std::future::pending::<()>().await;
        }
    }

    /// Ask the poll thread for a fresh enumeration and wait up to `wait`
    /// for it to be published; the cached list stands otherwise.
    pub async fn fresh(&self, wait: Duration) {
        let mut published = self.published.clone();
        published.borrow_and_update();
        if self.wake.send(()).is_err() {
            tracing::warn!("window list poll thread gone, using cached list");
            return;
        }
        if !matches!(
            tokio::time::timeout(wait, published.changed()).await,
            Ok(Ok(()))
        ) {
            tracing::debug!(?wait, "fresh window list not ready, using cached");
        }
    }
}

/// Track the compositor's windows in `windows` with `list`: a poll thread
/// enumerates every `POLL_INTERVAL` and on request, and a task publishes
/// each list. After `MAX_FAILURES` consecutive failures the compositor
/// connection is dead: the thread reports it through
/// [`Refresh::lost`], and the event loop stops the daemon.
///
/// # Errors
///
/// When the poll thread cannot be spawned.
pub fn poll_compositor(
    list: impl FnMut() -> core_types::Result<Vec<Window>> + Send + 'static,
    windows: &Windows,
) -> std::io::Result<Refresh> {
    let (list_tx, mut list_rx) = tokio::sync::mpsc::channel(1);
    let (wake_tx, wake_rx) = std::sync::mpsc::channel::<()>();
    let (lost_tx, compositor_lost) = watch::channel(false);
    std::thread::Builder::new()
        .name("wm-winlist-poll".into())
        .spawn(move || {
            match poll_windows(list, &list_tx, &wake_rx, POLL_INTERVAL, MAX_FAILURES) {
                PollEnd::CompositorDead => {
                    tracing::error!(failures = MAX_FAILURES, "compositor connection dead");
                    // No receiver: the event loop has already exited.
                    let _ = lost_tx.send(true);
                }
                end => tracing::info!(?end, "window list poll thread stopped"),
            }
        })?;
    let (published_tx, published) = watch::channel(0_u64);
    let windows = Arc::clone(windows);
    tokio::spawn(async move {
        while let Some(list) = list_rx.recv().await {
            *windows.lock().await = list;
            published_tx.send_modify(|count| *count += 1);
        }
    });
    Ok(Refresh {
        wake: wake_tx,
        published,
        compositor_lost,
    })
}

/// Track windows by compositor focus alone (no compositor backend): a
/// focused app id is a window, closed when its app closes.
#[cfg(target_os = "linux")]
pub fn track_focus(windows: &Windows) {
    use platform_linux::focus_monitor::FocusEvent;
    let (focus_tx, mut focus_rx) = tokio::sync::mpsc::channel::<FocusEvent>(16);
    if let Err(e) = platform_linux::focus_monitor::spawn(focus_tx) {
        tracing::warn!(error = %e, "focus monitor unavailable");
        return;
    }
    let windows = Arc::clone(windows);
    tokio::spawn(async move {
        while let Some(event) = focus_rx.recv().await {
            let mut windows = windows.lock().await;
            match event {
                FocusEvent::Focus(app_id) => focus(&mut windows, &app_id),
                FocusEvent::Closed(app_id) => windows.retain(|w| w.app_id.as_str() != app_id),
            }
        }
    });
}

/// Mark `app_id`'s windows focused and every other unfocused; a first
/// focus of `app_id` adds a window for it. Focus events carry only the app
/// id: the window is titled by it, with a `WindowId` minted for the
/// session, and every other field unobserved.
fn focus(windows: &mut Vec<Window>, app_id: &str) {
    let mut known = false;
    for window in windows.iter_mut() {
        window.is_focused = window.app_id.as_str() == app_id;
        known |= window.is_focused;
    }
    if !known {
        windows.push(Window::new(
            core_types::WindowId::new(),
            core_types::AppId::new(app_id),
            app_id.to_owned(),
            true,
        ));
    }
}

/// Why the poll loop returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollEnd {
    /// The receiver of window lists is gone.
    ConsumerGone,
    /// The event loop dropped its wake sender: it has exited.
    EventLoopGone,
    /// `max_failures` consecutive enumerations failed.
    CompositorDead,
}

/// Enumerate windows with `list` and send each list to `windows`, again on
/// every `wake` signal (queued signals are coalesced) and at least every
/// `interval`.
pub fn poll_windows(
    mut list: impl FnMut() -> core_types::Result<Vec<Window>>,
    windows: &tokio::sync::mpsc::Sender<Vec<Window>>,
    wake: &Receiver<()>,
    interval: Duration,
    max_failures: u32,
) -> PollEnd {
    let mut consecutive_failures: u32 = 0;
    loop {
        match list() {
            Ok(found) => {
                consecutive_failures = 0;
                if windows.blocking_send(found).is_err() {
                    return PollEnd::ConsumerGone;
                }
            }
            Err(e) => {
                consecutive_failures += 1;
                tracing::warn!(error = %e, consecutive_failures, "failed to refresh window list");
                if consecutive_failures >= max_failures {
                    return PollEnd::CompositorDead;
                }
            }
        }
        match wake.recv_timeout(interval) {
            Ok(()) => while wake.try_recv().is_ok() {},
            Err(RecvTimeoutError::Timeout) => {}
            // recv_timeout no longer waits: polling on would spin.
            Err(RecvTimeoutError::Disconnected) => return PollEnd::EventLoopGone,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `poll_windows` on a thread and return how it ended, or `None`
    /// when it is still running after `deadline`.
    fn run(
        list: impl FnMut() -> core_types::Result<Vec<Window>> + Send + 'static,
        wake: Receiver<()>,
        deadline: Duration,
    ) -> (Option<PollEnd>, tokio::sync::mpsc::Receiver<Vec<Window>>) {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let end = poll_windows(list, &tx, &wake, Duration::from_millis(5), 3);
            let _ = done_tx.send(end);
        });
        (done_rx.recv_timeout(deadline).ok(), rx)
    }

    #[test]
    fn dropped_wake_sender_ends_the_loop() {
        let (wake_tx, wake_rx) = std::sync::mpsc::channel();
        drop(wake_tx);
        let (end, mut windows) = run(|| Ok(Vec::new()), wake_rx, Duration::from_secs(2));
        assert_eq!(end, Some(PollEnd::EventLoopGone));
        assert!(windows.try_recv().is_ok(), "one enumeration before the end");
    }

    #[test]
    fn consecutive_failures_end_the_loop() {
        let (_wake_tx, wake_rx) = std::sync::mpsc::channel::<()>();
        let (end, _windows) = run(
            || Err(core_types::Error::Platform("compositor gone".into())),
            wake_rx,
            Duration::from_secs(2),
        );
        assert_eq!(end, Some(PollEnd::CompositorDead));
    }

    #[test]
    fn focus_marks_one_app_and_adds_it_once() {
        let mut windows = Vec::new();
        focus(&mut windows, "firefox");
        focus(&mut windows, "ghostty");
        focus(&mut windows, "firefox");
        let focused: Vec<(&str, bool)> = windows
            .iter()
            .map(|w| (w.app_id.as_str(), w.is_focused))
            .collect();
        assert_eq!(focused, [("firefox", true), ("ghostty", false)]);
    }

    #[tokio::test]
    async fn a_refresh_waits_for_the_next_published_list() {
        let windows: Windows = Arc::default();
        let refresh = poll_compositor(|| Ok(vec![]), &windows).unwrap();
        let before = *refresh.published.borrow();
        refresh.fresh(Duration::from_secs(5)).await;
        assert!(*refresh.published.borrow() > before, "a list was published");
    }

    #[tokio::test]
    async fn a_dead_compositor_is_reported_to_the_event_loop() {
        let windows: Windows = Arc::default();
        let mut refresh = poll_compositor(
            || Err(core_types::Error::Platform("compositor gone".into())),
            &windows,
        )
        .unwrap();
        tokio::time::timeout(Duration::from_mins(1), refresh.lost())
            .await
            .expect("the compositor loss is reported");
    }

    #[test]
    fn closed_consumer_ends_the_loop() {
        let (_wake_tx, wake_rx) = std::sync::mpsc::channel::<()>();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        drop(rx);
        let end = poll_windows(
            || Ok(Vec::new()),
            &tx,
            &wake_rx,
            Duration::from_millis(5),
            3,
        );
        assert_eq!(end, PollEnd::ConsumerGone);
    }
}
