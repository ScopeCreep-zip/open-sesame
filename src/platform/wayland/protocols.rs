//! Wayland protocol handling for COSMIC desktop
//!
//! Uses:
//! - ext_foreign_toplevel_list_v1: Window enumeration
//! - zcosmic_toplevel_info_v1: Get cosmic handles
//! - zcosmic_toplevel_manager_v1: Window activation

use crate::core::window::{AppId, Window, WindowId};
use crate::util::{Error, Result};
use cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::{
    zcosmic_toplevel_handle_v1::{self, ZcosmicToplevelHandleV1},
    zcosmic_toplevel_info_v1::{self, ZcosmicToplevelInfoV1},
};
use cosmic_client_toolkit::cosmic_protocols::toplevel_management::v1::client::zcosmic_toplevel_manager_v1::ZcosmicToplevelManagerV1;
use std::collections::HashMap;
use std::os::unix::io::AsFd;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use wayland_client::{
    Connection, Dispatch, EventQueue, Proxy, QueueHandle,
    globals::{GlobalList, GlobalListContents, registry_queue_init},
    protocol::{wl_registry, wl_seat::WlSeat},
};
use wayland_protocols::ext::foreign_toplevel_list::v1::client::{
    ext_foreign_toplevel_handle_v1::{self, ExtForeignToplevelHandleV1},
    ext_foreign_toplevel_list_v1::{self, ExtForeignToplevelListV1},
};

/// Get Wayland timeout from environment or use default
fn wayland_timeout() -> Duration {
    std::env::var("SESAME_WAYLAND_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_secs(2))
}

/// Timeout for Wayland roundtrip operations (default 2s, override with SESAME_WAYLAND_TIMEOUT_MS)
fn get_wayland_timeout() -> Duration {
    static TIMEOUT: OnceLock<Duration> = OnceLock::new();
    *TIMEOUT.get_or_init(wayland_timeout)
}

/// Perform a Wayland roundtrip with timeout protection
///
/// Prevents indefinite blocking if the compositor hangs or deadlocks.
fn roundtrip_with_timeout<D: 'static>(
    conn: &Connection,
    event_queue: &mut EventQueue<D>,
    state: &mut D,
) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    let start = Instant::now();
    let fd = conn.as_fd().as_raw_fd();
    let timeout = get_wayland_timeout();

    loop {
        // Flush pending requests to server
        conn.flush()
            .map_err(|e| Error::WaylandConnection(Box::new(e)))?;

        // Dispatch pending events without blocking
        event_queue
            .dispatch_pending(state)
            .map_err(|e| Error::WaylandConnection(Box::new(e)))?;

        // Check timeout expiration
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Err(Error::Other(format!(
                "Wayland roundtrip timed out after {:?}",
                elapsed
            )));
        }

        // Calculate remaining time for poll
        let remaining = timeout - elapsed;
        let timeout_ms = remaining.as_millis().min(100) as i32;

        // Poll for readability
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };

        let ret = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::WaylandConnection(Box::new(err)));
        }

        if ret > 0 && (pollfd.revents & libc::POLLIN) != 0 {
            // Read available data from socket
            if let Some(guard) = conn.prepare_read()
                && let Err(e) = guard.read()
            {
                return Err(Error::WaylandConnection(Box::new(e)));
            }

            // Dispatch received events
            event_queue
                .dispatch_pending(state)
                .map_err(|e| Error::WaylandConnection(Box::new(e)))?;

            // Final blocking roundtrip to ensure all server events are received
            event_queue
                .roundtrip(state)
                .map_err(|e| Error::WaylandConnection(Box::new(e)))?;
            return Ok(());
        }
    }
}

/// Pending toplevel data being collected from events
#[derive(Debug, Default)]
struct PendingToplevel {
    identifier: Option<String>,
    app_id: Option<String>,
    title: Option<String>,
    is_activated: bool,
}

// ============================================================================
// Window Enumeration
// ============================================================================

/// State for toplevel enumeration
struct EnumerationState {
    #[allow(dead_code)]
    list: ExtForeignToplevelListV1,
    info: ZcosmicToplevelInfoV1,
    pending: HashMap<u32, PendingToplevel>,
    cosmic_pending: HashMap<u32, u32>, // cosmic handle id -> foreign handle id
    toplevels: Vec<(ExtForeignToplevelHandleV1, PendingToplevel)>,
}

impl EnumerationState {
    fn bind(globals: &GlobalList, qh: &QueueHandle<Self>) -> Result<Self> {
        let list = globals
            .bind::<ExtForeignToplevelListV1, _, _>(qh, 1..=1, ())
            .map_err(|_| Error::MissingProtocol {
                protocol: "ext_foreign_toplevel_list_v1",
            })?;

        let info = globals
            .bind::<ZcosmicToplevelInfoV1, _, _>(qh, 2..=3, ())
            .map_err(|_| Error::MissingProtocol {
                protocol: "zcosmic_toplevel_info_v1",
            })?;

        Ok(Self {
            list,
            info,
            pending: HashMap::new(),
            cosmic_pending: HashMap::new(),
            toplevels: Vec::new(),
        })
    }
}

/// Enumerate all windows on the desktop
pub fn enumerate_windows() -> Result<Vec<Window>> {
    tracing::debug!("enumerate_windows: starting");
    let conn = Connection::connect_to_env().map_err(|e| Error::WaylandConnection(Box::new(e)))?;

    let (globals, mut event_queue) = registry_queue_init::<EnumerationState>(&conn)
        .map_err(|e| Error::WaylandConnection(Box::new(e)))?;
    let qh = event_queue.handle();

    let mut state = EnumerationState::bind(&globals, &qh)?;
    tracing::debug!("enumerate_windows: bound to protocols");

    // First roundtrip: receive toplevel events (with timeout protection)
    roundtrip_with_timeout(&conn, &mut event_queue, &mut state)?;
    tracing::debug!(
        "enumerate_windows: roundtrip 1 complete, {} toplevels found",
        state.toplevels.len()
    );

    // Request cosmic handles for state information
    for (handle, pending) in &state.toplevels {
        let foreign_id = handle.id().protocol_id();
        let cosmic_handle = state.info.get_cosmic_toplevel(handle, &qh, ());
        let cosmic_id = cosmic_handle.id().protocol_id();
        state.cosmic_pending.insert(cosmic_id, foreign_id);
        tracing::debug!(
            "enumerate_windows: requested cosmic handle for {} (foreign_id={}, cosmic_id={})",
            pending.app_id.as_deref().unwrap_or("?"),
            foreign_id,
            cosmic_id
        );
    }

    // Second roundtrip: receive cosmic state events (with timeout protection)
    roundtrip_with_timeout(&conn, &mut event_queue, &mut state)?;
    tracing::debug!("enumerate_windows: roundtrip 2 complete (cosmic state events)");

    // Protocol state validation: verify all cosmic handles were received
    if state.cosmic_pending.len() != state.toplevels.len() {
        tracing::warn!(
            "Protocol state desync detected: requested {} cosmic handles but pending map has {} entries. Some window state may be incomplete.",
            state.toplevels.len(),
            state.cosmic_pending.len()
        );
    }

    // Convert to Window structs with focused window positioned last
    let mut windows: Vec<Window> = state
        .toplevels
        .into_iter()
        .filter_map(|(_handle, pending)| {
            let app_id = pending.app_id?;
            if app_id.is_empty() {
                return None;
            }

            tracing::info!(
                "Window: {} - {} (is_activated: {})",
                app_id,
                pending.title.as_deref().unwrap_or("?"),
                pending.is_activated
            );

            Some(Window::with_focus(
                WindowId::new(pending.identifier.unwrap_or_default()),
                AppId::new(app_id),
                pending.title.unwrap_or_default(),
                pending.is_activated,
            ))
        })
        .collect();

    tracing::info!(
        "enumerate_windows: {} windows after filtering",
        windows.len()
    );

    // Reorder windows with focused window at end for Alt+Tab behavior
    // Index 0 becomes the previous window for quick Alt+Tab switching
    if let Some(focused_idx) = windows.iter().position(|w| w.is_focused) {
        tracing::info!(
            "enumerate_windows: focused window at index {}, moving to end",
            focused_idx
        );
        let focused = windows.remove(focused_idx);
        windows.push(focused);
    } else {
        tracing::warn!("enumerate_windows: NO focused window detected - MRU order unavailable");
    }

    // Log final order
    for (i, w) in windows.iter().enumerate() {
        tracing::info!(
            "  [{}] {} - {} (focused: {})",
            i,
            w.app_id,
            w.title,
            w.is_focused
        );
    }

    Ok(windows)
}

// Dispatch implementations for EnumerationState

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for EnumerationState {
    fn event(
        _state: &mut Self,
        _proxy: &wl_registry::WlRegistry,
        _event: wl_registry::Event,
        _data: &GlobalListContents,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ExtForeignToplevelListV1, ()> for EnumerationState {
    fn event(
        state: &mut Self,
        _proxy: &ExtForeignToplevelListV1,
        event: ext_foreign_toplevel_list_v1::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let ext_foreign_toplevel_list_v1::Event::Toplevel { toplevel } = event {
            let id = toplevel.id().protocol_id();
            state.pending.insert(id, PendingToplevel::default());
        }
    }

    wayland_client::event_created_child!(EnumerationState, ExtForeignToplevelListV1, [
        ext_foreign_toplevel_list_v1::EVT_TOPLEVEL_OPCODE => (ExtForeignToplevelHandleV1, ())
    ]);
}

impl Dispatch<ExtForeignToplevelHandleV1, ()> for EnumerationState {
    fn event(
        state: &mut Self,
        proxy: &ExtForeignToplevelHandleV1,
        event: ext_foreign_toplevel_handle_v1::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        let id = proxy.id().protocol_id();

        match event {
            ext_foreign_toplevel_handle_v1::Event::Identifier { identifier } => {
                if let Some(pending) = state.pending.get_mut(&id) {
                    pending.identifier = Some(identifier);
                }
            }
            ext_foreign_toplevel_handle_v1::Event::Title { title } => {
                if let Some(pending) = state.pending.get_mut(&id) {
                    pending.title = Some(title);
                }
            }
            ext_foreign_toplevel_handle_v1::Event::AppId { app_id } => {
                if let Some(pending) = state.pending.get_mut(&id) {
                    pending.app_id = Some(app_id);
                }
            }
            ext_foreign_toplevel_handle_v1::Event::Done => {
                if let Some(pending) = state.pending.remove(&id) {
                    state.toplevels.push((proxy.clone(), pending));
                }
            }
            ext_foreign_toplevel_handle_v1::Event::Closed => {
                state.pending.remove(&id);
            }
            _ => {}
        }
    }
}

impl Dispatch<ZcosmicToplevelInfoV1, ()> for EnumerationState {
    fn event(
        _state: &mut Self,
        _proxy: &ZcosmicToplevelInfoV1,
        _event: zcosmic_toplevel_info_v1::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }

    wayland_client::event_created_child!(EnumerationState, ZcosmicToplevelInfoV1, [
        zcosmic_toplevel_info_v1::EVT_TOPLEVEL_OPCODE => (ZcosmicToplevelHandleV1, ())
    ]);
}

impl Dispatch<ZcosmicToplevelHandleV1, ()> for EnumerationState {
    fn event(
        state: &mut Self,
        proxy: &ZcosmicToplevelHandleV1,
        event: zcosmic_toplevel_handle_v1::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        let cosmic_id = proxy.id().protocol_id();

        // Resolve cosmic handle to foreign handle for pending toplevel update
        if let Some(&foreign_id) = state.cosmic_pending.get(&cosmic_id) {
            match &event {
                zcosmic_toplevel_handle_v1::Event::State { state: state_bytes } => {
                    tracing::debug!(
                        "Cosmic state event for cosmic_id={}, foreign_id={}, bytes={:?}",
                        cosmic_id,
                        foreign_id,
                        state_bytes
                    );

                    // Verify proper 4-byte alignment (each state is a u32)
                    if state_bytes.len() % 4 != 0 {
                        tracing::warn!(
                            "Malformed state data: {} bytes is not 4-byte aligned, skipping",
                            state_bytes.len()
                        );
                        return;
                    }

                    // Extract state values from byte array
                    for chunk in state_bytes.chunks_exact(4) {
                        // SAFETY: chunks_exact(4) guarantees exactly 4 bytes per chunk,
                        // and alignment was validated above
                        let state_value =
                            u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                        tracing::debug!("  State value: {}", state_value);
                        // State::Activated = 2
                        if state_value == 2 {
                            tracing::debug!("  -> Window is ACTIVATED");
                            // Locate pending toplevel by foreign_id
                            if let Some((_, pending)) = state
                                .toplevels
                                .iter_mut()
                                .find(|(h, _)| h.id().protocol_id() == foreign_id)
                            {
                                pending.is_activated = true;
                            }
                        }
                    }
                }
                other => {
                    tracing::debug!("Cosmic event: {:?}", other);
                }
            }
        }
    }
}

// ============================================================================
// Window Activation
// ============================================================================

/// State for window activation
struct ActivationState {
    #[allow(dead_code)]
    list: ExtForeignToplevelListV1,
    info: ZcosmicToplevelInfoV1,
    manager: ZcosmicToplevelManagerV1,
    seat: WlSeat,
    pending: HashMap<u32, PendingToplevel>,
    toplevels: Vec<(ExtForeignToplevelHandleV1, String)>, // handle + identifier
    target_identifier: String,
    cosmic_handle: Option<ZcosmicToplevelHandleV1>,
    activated: bool,
}

impl ActivationState {
    fn bind(globals: &GlobalList, qh: &QueueHandle<Self>, target: String) -> Result<Self> {
        let list = globals
            .bind::<ExtForeignToplevelListV1, _, _>(qh, 1..=1, ())
            .map_err(|_| Error::MissingProtocol {
                protocol: "ext_foreign_toplevel_list_v1",
            })?;

        let info = globals
            .bind::<ZcosmicToplevelInfoV1, _, _>(qh, 2..=3, ())
            .map_err(|_| Error::MissingProtocol {
                protocol: "zcosmic_toplevel_info_v1",
            })?;

        let manager = globals
            .bind::<ZcosmicToplevelManagerV1, _, _>(qh, 1..=4, ())
            .map_err(|_| Error::MissingProtocol {
                protocol: "zcosmic_toplevel_manager_v1",
            })?;

        let seat =
            globals
                .bind::<WlSeat, _, _>(qh, 1..=9, ())
                .map_err(|_| Error::MissingProtocol {
                    protocol: "wl_seat",
                })?;

        Ok(Self {
            list,
            info,
            manager,
            seat,
            pending: HashMap::new(),
            toplevels: Vec::new(),
            target_identifier: target,
            cosmic_handle: None,
            activated: false,
        })
    }

    /// Request cosmic handle for the target window
    fn request_cosmic_handle(&mut self, qh: &QueueHandle<Self>) -> bool {
        let target = self
            .toplevels
            .iter()
            .find(|(_, id)| *id == self.target_identifier);

        if let Some((handle, _)) = target {
            tracing::debug!("Requesting cosmic handle for target");
            let cosmic_handle = self.info.get_cosmic_toplevel(handle, qh, ());
            self.cosmic_handle = Some(cosmic_handle);
            true
        } else {
            tracing::warn!("Target window not found: {}", self.target_identifier);
            false
        }
    }

    /// Activate the window
    fn activate(&mut self) {
        if self.activated {
            return;
        }

        if let Some(cosmic_handle) = &self.cosmic_handle {
            tracing::info!("Activating window");
            self.manager.activate(cosmic_handle, &self.seat);
            self.activated = true;
        }
    }
}

/// Activate a window by its identifier
pub fn activate_window(id: &WindowId) -> Result<()> {
    let identifier = id.as_str();
    let conn = Connection::connect_to_env().map_err(|e| Error::WaylandConnection(Box::new(e)))?;
    let (globals, mut event_queue) = registry_queue_init::<ActivationState>(&conn)
        .map_err(|e| Error::WaylandConnection(Box::new(e)))?;
    let qh = event_queue.handle();

    let mut state = ActivationState::bind(&globals, &qh, identifier.to_string())?;

    // First roundtrip: retrieve all toplevels (with timeout protection)
    roundtrip_with_timeout(&conn, &mut event_queue, &mut state)?;

    // Request cosmic handle for target window
    if !state.request_cosmic_handle(&qh) {
        return Err(Error::WindowNotFound {
            identifier: identifier.to_string(),
        });
    }

    // Second roundtrip: wait for cosmic handle (with timeout protection)
    roundtrip_with_timeout(&conn, &mut event_queue, &mut state)?;

    // Activate target window
    state.activate();

    // Third roundtrip: ensure activation is processed (with timeout protection)
    roundtrip_with_timeout(&conn, &mut event_queue, &mut state)?;

    if state.activated {
        tracing::info!("Window activated successfully");
        Ok(())
    } else {
        Err(Error::ActivationFailed(
            "Failed to activate window".to_string(),
        ))
    }
}

// Dispatch implementations for ActivationState

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for ActivationState {
    fn event(
        _state: &mut Self,
        _proxy: &wl_registry::WlRegistry,
        _event: wl_registry::Event,
        _data: &GlobalListContents,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ExtForeignToplevelListV1, ()> for ActivationState {
    fn event(
        state: &mut Self,
        _proxy: &ExtForeignToplevelListV1,
        event: ext_foreign_toplevel_list_v1::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let ext_foreign_toplevel_list_v1::Event::Toplevel { toplevel } = event {
            let id = toplevel.id().protocol_id();
            state.pending.insert(id, PendingToplevel::default());
        }
    }

    wayland_client::event_created_child!(ActivationState, ExtForeignToplevelListV1, [
        ext_foreign_toplevel_list_v1::EVT_TOPLEVEL_OPCODE => (ExtForeignToplevelHandleV1, ())
    ]);
}

impl Dispatch<ExtForeignToplevelHandleV1, ()> for ActivationState {
    fn event(
        state: &mut Self,
        proxy: &ExtForeignToplevelHandleV1,
        event: ext_foreign_toplevel_handle_v1::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        let id = proxy.id().protocol_id();

        match event {
            ext_foreign_toplevel_handle_v1::Event::Identifier { identifier } => {
                if let Some(pending) = state.pending.get_mut(&id) {
                    pending.identifier = Some(identifier);
                }
            }
            ext_foreign_toplevel_handle_v1::Event::AppId { app_id } => {
                if let Some(pending) = state.pending.get_mut(&id) {
                    pending.app_id = Some(app_id);
                }
            }
            ext_foreign_toplevel_handle_v1::Event::Done => {
                if let Some(pending) = state.pending.remove(&id)
                    && let Some(identifier) = pending.identifier
                {
                    state.toplevels.push((proxy.clone(), identifier));
                }
            }
            _ => {}
        }
    }
}

impl Dispatch<ZcosmicToplevelInfoV1, ()> for ActivationState {
    fn event(
        _state: &mut Self,
        _proxy: &ZcosmicToplevelInfoV1,
        _event: zcosmic_toplevel_info_v1::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ZcosmicToplevelHandleV1, ()> for ActivationState {
    fn event(
        _state: &mut Self,
        _proxy: &ZcosmicToplevelHandleV1,
        _event: zcosmic_toplevel_handle_v1::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<ZcosmicToplevelManagerV1, ()> for ActivationState {
    fn event(
        _state: &mut Self,
        _proxy: &ZcosmicToplevelManagerV1,
        _event: cosmic_client_toolkit::cosmic_protocols::toplevel_management::v1::client::zcosmic_toplevel_manager_v1::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<WlSeat, ()> for ActivationState {
    fn event(
        _state: &mut Self,
        _proxy: &WlSeat,
        _event: wayland_client::protocol::wl_seat::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_id_creation() {
        let id = WindowId::new("test-123");
        assert_eq!(id.as_str(), "test-123");
    }
}
