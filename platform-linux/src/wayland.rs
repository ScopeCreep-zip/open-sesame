//! Wayland client plumbing shared by the compositor backends: the
//! dispatch loop of a dedicated event thread, and decoding of packed
//! toplevel state arrays.

use std::time::Duration;

use rustix::event::{PollFd, PollFlags, Timespec};
use wayland_client::backend::{ReadEventsGuard, WaylandError};
use wayland_client::{Connection, EventQueue};

/// Whether a toplevel `state` event's packed array (native-endian `u32`
/// values, as both the wlr and COSMIC toplevel protocols send it) holds
/// `value`. A trailing partial element is not a value.
fn has_state(packed: &[u8], value: u32) -> bool {
    packed
        .chunks_exact(4)
        .filter_map(|chunk| <[u8; 4]>::try_from(chunk).ok())
        .map(u32::from_ne_bytes)
        .any(|v| v == value)
}

/// The values a toplevel protocol's `state` enum assigns to the states
/// daemon-wm reports.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StateValues {
    pub activated: u32,
    pub minimized: u32,
    pub fullscreen: u32,
}

/// The state values of `zwlr_foreign_toplevel_handle_v1`, read by the wlr
/// backend and the focus monitor.
pub(crate) const WLR_STATE: StateValues = {
    use wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1::State;
    StateValues {
        activated: State::Activated as u32,
        minimized: State::Minimized as u32,
        fullscreen: State::Fullscreen as u32,
    }
};

/// A toplevel's state, from its last `state` event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ToplevelState {
    pub activated: bool,
    pub minimized: bool,
    pub fullscreen: bool,
}

impl ToplevelState {
    /// The state a `state` event's packed array reports under `values`.
    pub(crate) fn decode(packed: &[u8], values: StateValues) -> Self {
        Self {
            activated: has_state(packed, values.activated),
            minimized: has_state(packed, values.minimized),
            fullscreen: has_state(packed, values.fullscreen),
        }
    }

    /// The window `id` of `app_id`, titled `title`, in this state.
    pub(crate) fn window(
        self,
        id: core_types::WindowId,
        app_id: &str,
        title: String,
    ) -> core_types::Window {
        let mut window =
            core_types::Window::new(id, core_types::AppId::new(app_id), title, self.activated);
        window.is_minimized = Some(self.minimized);
        window.is_fullscreen = Some(self.fullscreen);
        window
    }
}

/// How long one wait for the Wayland socket lasts before the loop checks
/// for buffered events again.
const POLL_INTERVAL: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 50_000_000,
};
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Exponential backoff after a failed step of the dispatch loop.
struct Backoff(Duration);

impl Backoff {
    fn reset(&mut self) {
        self.0 = INITIAL_BACKOFF;
    }

    /// Log the failure of `step`, sleep, and double the next wait.
    fn fail(&mut self, conn: &Connection, name: &str, step: &str, error: &dyn std::fmt::Display) {
        let protocol_error = conn.protocol_error();
        tracing::error!(
            %error,
            ?protocol_error,
            backoff_ms = self.0.as_millis(),
            "{name} dispatch: {step} failed, backing off"
        );
        std::thread::sleep(self.0);
        self.0 = (self.0 * 2).min(MAX_BACKOFF);
    }
}

/// Wait up to `POLL_INTERVAL` for the socket of `guard` and read it.
/// `Ok(false)` when the wait timed out or was interrupted (the guard is
/// dropped, cancelling the prepared read), or the read found no complete
/// message. `ERR` readiness is left for `read()` to report, as
/// `wayland_client`'s own blocking read does.
fn wait_and_read(guard: ReadEventsGuard) -> Result<bool, WaylandError> {
    let fd = guard.connection_fd();
    let mut fds = [PollFd::new(&fd, PollFlags::IN | PollFlags::ERR)];
    match rustix::event::poll(&mut fds, Some(&POLL_INTERVAL)) {
        Ok(0) | Err(rustix::io::Errno::INTR) => Ok(false),
        Ok(_) => match guard.read() {
            Ok(_) => Ok(true),
            Err(WaylandError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(e) => Err(e),
        },
        Err(e) => Err(WaylandError::Io(e.into())),
    }
}

/// Dispatch the events of `queue` into `state` forever, in the order
/// `wayland_client::EventQueue` documents for an external poll loop:
/// flush requests, dispatch everything buffered (including the system
/// backend's inner queue), then wait for the socket (`poll(2)`,
/// `POLL_INTERVAL` at most) and read it. A failed step backs off
/// exponentially from 100 ms to 30 s; `name` identifies the loop in the
/// log. Runs on a dedicated thread.
pub(crate) fn dispatch_forever<D: 'static>(
    conn: &Connection,
    mut queue: EventQueue<D>,
    mut state: D,
    name: &str,
) -> ! {
    let mut backoff = Backoff(INITIAL_BACKOFF);
    loop {
        if let Err(e) = conn.flush() {
            backoff.fail(conn, name, "flush", &e);
            continue;
        }
        if let Err(e) = queue.dispatch_pending(&mut state) {
            backoff.fail(conn, name, "dispatch_pending", &e);
            continue;
        }
        // `None`: events were queued meanwhile; dispatch them first.
        let Some(guard) = conn.prepare_read() else {
            continue;
        };
        match wait_and_read(guard) {
            Ok(true) => backoff.reset(),
            Ok(false) => {}
            Err(e) => backoff.fail(conn, name, "Wayland read", &e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_states_are_native_endian_u32_values() {
        let packed: Vec<u8> = [1u32, 2, 4].iter().flat_map(|v| v.to_ne_bytes()).collect();
        assert!(has_state(&packed, 2));
        assert!(!has_state(&packed, 3));
        assert!(!has_state(&[], 2));
        // A trailing partial element is ignored, not misread.
        let mut partial = packed.clone();
        partial.extend([3, 0]);
        assert!(!has_state(&partial, 3));
    }

    #[test]
    fn decoded_state_becomes_the_reported_window() {
        let values = StateValues {
            activated: 2,
            minimized: 1,
            fullscreen: 3,
        };
        let packed: Vec<u8> = [1u32, 3].iter().flat_map(|v| v.to_ne_bytes()).collect();
        let state = ToplevelState::decode(&packed, values);
        assert_eq!(
            state,
            ToplevelState {
                activated: false,
                minimized: true,
                fullscreen: true,
            }
        );
        let window = state.window(core_types::WindowId::new(), "firefox", "Docs".into());
        assert!(!window.is_focused);
        assert_eq!(window.is_minimized, Some(true));
        assert_eq!(window.is_fullscreen, Some(true));
        assert_eq!(window.workspace_id, None);
    }
}
