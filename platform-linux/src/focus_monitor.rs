//! Focus tracking via wlr-foreign-toplevel-management-v1.
//!
//! Monitors the focused (activated) toplevel and sends `FocusEvent`s through
//! a channel whenever focus changes or a window closes.
//!
//! Compatible with: sway, Hyprland, niri, Wayfire, COSMIC (which also
//! advertises the wlr protocol for backwards compatibility).
//!
//! Runs as a long-lived task — spawn with `tokio::spawn`.

use std::collections::HashMap;
use std::os::unix::io::AsFd;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use wayland_client::{
    Connection, Dispatch, EventQueue, Proxy, QueueHandle,
    globals::{GlobalList, GlobalListContents, registry_queue_init},
    protocol::wl_registry,
};
use wayland_protocols_wlr::foreign_toplevel::v1::client::{
    zwlr_foreign_toplevel_handle_v1::{self, ZwlrForeignToplevelHandleV1},
    zwlr_foreign_toplevel_manager_v1::{self, ZwlrForeignToplevelManagerV1},
};

/// Event from the focus monitor: either a focus change or a window close.
#[derive(Debug, Clone)]
pub enum FocusEvent {
    /// An app gained focus. Payload is the app_id.
    Focus(String),
    /// A window closed. Payload is the app_id (empty if unknown).
    Closed(String),
}

/// Monitors the focused (activated) toplevel via wlr-foreign-toplevel-management-v1.
///
/// Connects to the Wayland display, binds the wlr foreign toplevel manager,
/// tracks toplevel state events, and sends `FocusEvent`s through the channel
/// whenever focus changes or a window closes.
///
/// Runs as a long-lived task — spawn with `tokio::spawn`.
pub async fn focus_monitor(tx: tokio::sync::mpsc::Sender<FocusEvent>) {
    if let Err(e) = focus_monitor_inner(&tx).await {
        tracing::warn!(error = %e, "focus monitor exiting");
    }
}

// -- Hoisted types (were function-local in focus_monitor_inner) --

/// Per-toplevel tracking state.
#[derive(Debug, Default, Clone)]
struct ToplevelData {
    app_id: String,
    activated: bool,
}

/// Wayland dispatch state for focus tracking.
struct FocusState {
    toplevels: HashMap<wayland_client::backend::ObjectId, ToplevelData>,
    focused_app_id: String,
    tx: tokio::sync::mpsc::Sender<FocusEvent>,
}

/// UserData attached to each toplevel handle proxy (unit — state tracked in FocusState).
#[derive(Debug, Default, Clone)]
struct HandleData;

// -- Dispatch for wl_registry (required by registry_queue_init) --
impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for FocusState {
    fn event(
        _: &mut Self,
        _: &wl_registry::WlRegistry,
        _: wl_registry::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

// -- Dispatch for the manager: handles `toplevel` and `finished` events --
impl Dispatch<ZwlrForeignToplevelManagerV1, ()> for FocusState {
    fn event(
        _state: &mut Self,
        _proxy: &ZwlrForeignToplevelManagerV1,
        event: zwlr_foreign_toplevel_manager_v1::Event,
        _: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        match event {
            zwlr_foreign_toplevel_manager_v1::Event::Toplevel { toplevel: _ } => {
                // New toplevel created — handle events arrive on the handle dispatch.
            }
            zwlr_foreign_toplevel_manager_v1::Event::Finished => {
                tracing::info!("wlr foreign toplevel manager finished");
            }
            _ => {}
        }
    }

    wayland_client::event_created_child!(FocusState, ZwlrForeignToplevelManagerV1, [
        zwlr_foreign_toplevel_manager_v1::EVT_TOPLEVEL_OPCODE =>
            (ZwlrForeignToplevelHandleV1, HandleData)
    ]);
}

// -- Dispatch for individual toplevel handles --
impl Dispatch<ZwlrForeignToplevelHandleV1, HandleData> for FocusState {
    fn event(
        state: &mut Self,
        handle: &ZwlrForeignToplevelHandleV1,
        event: zwlr_foreign_toplevel_handle_v1::Event,
        _data: &HandleData,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        let id = handle.id();
        match event {
            zwlr_foreign_toplevel_handle_v1::Event::AppId { app_id } => {
                // Pending until `done`.
                let entry = state.toplevels.entry(id).or_default();
                entry.app_id = app_id;
            }
            zwlr_foreign_toplevel_handle_v1::Event::State { state: state_bytes } => {
                // State is a packed array of u32 in native endian.
                let activated = state_bytes
                    .chunks_exact(4)
                    .flat_map(TryInto::<[u8; 4]>::try_into)
                    .map(u32::from_ne_bytes)
                    .any(|v| v == zwlr_foreign_toplevel_handle_v1::State::Activated as u32);

                let entry = state.toplevels.entry(id).or_default();
                entry.activated = activated;
            }
            zwlr_foreign_toplevel_handle_v1::Event::Done => {
                // Atomic commit point — check if the activated app changed.
                if let Some(entry) = state.toplevels.get(&id)
                    && entry.activated
                    && !entry.app_id.is_empty()
                    && entry.app_id != state.focused_app_id
                {
                    state.focused_app_id.clone_from(&entry.app_id);
                    let _ = state.tx.try_send(FocusEvent::Focus(entry.app_id.clone()));
                }
            }
            zwlr_foreign_toplevel_handle_v1::Event::Closed => {
                let closed_app_id = state
                    .toplevels
                    .get(&id)
                    .map(|t| t.app_id.clone())
                    .unwrap_or_default();
                let was_focused = state.toplevels.get(&id).is_some_and(|t| t.activated);
                state.toplevels.remove(&id);
                handle.destroy();
                if was_focused {
                    state.focused_app_id.clear();
                }
                let _ = state.tx.try_send(FocusEvent::Closed(closed_app_id));
            }
            // title, output_enter, output_leave, parent — not relevant for focus tracking.
            _ => {}
        }
    }
}

async fn focus_monitor_inner(tx: &tokio::sync::mpsc::Sender<FocusEvent>) -> core_types::Result<()> {
    // -- Connect and bind --
    let conn = Connection::connect_to_env()
        .map_err(|e| core_types::Error::Platform(format!("Wayland connection failed: {e}")))?;

    let (globals, mut event_queue): (GlobalList, EventQueue<FocusState>) =
        registry_queue_init(&conn).map_err(|e| {
            core_types::Error::Platform(format!("Wayland registry init failed: {e}"))
        })?;

    let qh = event_queue.handle();

    // Bind the wlr foreign toplevel manager (version 3).
    let _manager: ZwlrForeignToplevelManagerV1 = globals.bind(&qh, 1..=3, ()).map_err(|e| {
        core_types::Error::Platform(format!(
            "wlr-foreign-toplevel-management-v1 not available: {e}"
        ))
    })?;

    let mut state = FocusState {
        toplevels: HashMap::new(),
        focused_app_id: String::new(),
        tx: tx.clone(),
    };

    // Initial roundtrip to receive existing toplevels.
    event_queue
        .roundtrip(&mut state)
        .map_err(|e| core_types::Error::Platform(format!("Wayland roundtrip failed: {e}")))?;

    // -- Async event loop via tokio AsyncFd --
    let async_fd = AsyncFd::with_interest(
        conn.as_fd()
            .try_clone_to_owned()
            .map_err(|e| core_types::Error::Platform(format!("failed to clone Wayland fd: {e}")))?,
        Interest::READABLE,
    )
    .map_err(|e| core_types::Error::Platform(format!("AsyncFd creation failed: {e}")))?;

    loop {
        // Wait for the Wayland socket to become readable.
        let mut ready = async_fd
            .readable()
            .await
            .map_err(|e| core_types::Error::Platform(format!("AsyncFd readable failed: {e}")))?;

        // Read events from the socket into the internal buffer.
        if let Some(guard) = conn.prepare_read() {
            match guard.read() {
                Ok(_) => {}
                Err(wayland_client::backend::WaylandError::Io(ref e))
                    if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    let proto_err = conn.protocol_error();
                    return Err(core_types::Error::Platform(format!(
                        "Wayland read failed: {e} (protocol_error: {proto_err:?})"
                    )));
                }
            }
        }

        // Dispatch all pending events to our handlers.
        event_queue.dispatch_pending(&mut state).map_err(|e| {
            let proto_err = conn.protocol_error();
            core_types::Error::Platform(format!(
                "Wayland dispatch failed: {e} (protocol_error: {proto_err:?})"
            ))
        })?;

        // Flush any outgoing requests (e.g. destroy).
        conn.flush().map_err(|e| {
            let proto_err = conn.protocol_error();
            core_types::Error::Platform(format!(
                "Wayland flush failed: {e} (protocol_error: {proto_err:?})"
            ))
        })?;

        // Clear readiness so we wait again.
        ready.clear_ready();
    }
}
