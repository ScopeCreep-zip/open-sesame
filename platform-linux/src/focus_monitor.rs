//! Focus tracking via wlr-foreign-toplevel-management-v1.
//!
//! Monitors the focused (activated) toplevel and sends `FocusEvent`s through
//! a channel whenever focus changes or a window closes.
//!
//! Compatible with: sway, Hyprland, niri, Wayfire, COSMIC (which also
//! advertises the wlr protocol for backwards compatibility).
//!
//! [`spawn`] connects and binds on the calling thread, then dispatches on a
//! dedicated `focus-monitor` thread through `wayland::dispatch_forever`.

use std::collections::HashMap;
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
    /// An app gained focus. Payload is the `app_id`.
    Focus(String),
    /// A window closed. Payload is the `app_id`; a toplevel that never
    /// reported one emits no close event.
    Closed(String),
}

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

impl FocusState {
    /// Send `event` without blocking the Wayland dispatch. A full channel
    /// drops the event and is logged; a closed one means the consumer is
    /// gone.
    fn emit(&self, event: FocusEvent) {
        use tokio::sync::mpsc::error::TrySendError;
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(event)) => {
                tracing::warn!(?event, "focus event dropped: consumer channel full");
            }
            Err(TrySendError::Closed(_)) => {
                tracing::debug!("focus event consumer gone");
            }
        }
    }
}

/// User data attached to each toplevel handle proxy (unit — state tracked in `FocusState`).
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
        (): &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        // A new toplevel's events arrive on the handle dispatch.
        if let zwlr_foreign_toplevel_manager_v1::Event::Finished = event {
            tracing::info!("wlr foreign toplevel manager finished");
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
            zwlr_foreign_toplevel_handle_v1::Event::State { state: packed } => {
                state.toplevels.entry(id).or_default().activated =
                    crate::wayland::ToplevelState::decode(&packed, crate::wayland::WLR_STATE)
                        .activated;
            }
            zwlr_foreign_toplevel_handle_v1::Event::Done => {
                // Atomic commit point — check if the activated app changed.
                if let Some(entry) = state.toplevels.get(&id)
                    && entry.activated
                    && !entry.app_id.is_empty()
                    && entry.app_id != state.focused_app_id
                {
                    state.focused_app_id.clone_from(&entry.app_id);
                    let event = FocusEvent::Focus(entry.app_id.clone());
                    state.emit(event);
                }
            }
            zwlr_foreign_toplevel_handle_v1::Event::Closed => {
                let closed = state.toplevels.remove(&id);
                handle.destroy();
                if let Some(toplevel) = closed {
                    if toplevel.activated {
                        state.focused_app_id.clear();
                    }
                    if toplevel.app_id.is_empty() {
                        tracing::debug!("toplevel without app_id closed");
                    } else {
                        state.emit(FocusEvent::Closed(toplevel.app_id));
                    }
                } else {
                    tracing::debug!("untracked toplevel closed");
                }
            }
            // title, output_enter, output_leave, parent — not relevant for focus tracking.
            _ => {}
        }
    }
}

/// Monitor the focused (activated) toplevel via
/// wlr-foreign-toplevel-management-v1, sending a [`FocusEvent`] through
/// `tx` whenever focus changes or a window closes.
///
/// Connects to the Wayland display, binds the manager and receives the
/// existing toplevels on the calling thread; event dispatch then runs on a
/// dedicated `focus-monitor` thread for the life of the process, backing
/// off on failed dispatch steps.
///
/// # Errors
///
/// `core_types::Error::Platform` when the display is unreachable, the
/// compositor lacks the protocol, the initial roundtrip fails, or the
/// thread cannot be spawned.
pub fn spawn(tx: tokio::sync::mpsc::Sender<FocusEvent>) -> core_types::Result<()> {
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
        tx,
    };

    // Initial roundtrip to receive existing toplevels.
    event_queue
        .roundtrip(&mut state)
        .map_err(|e| core_types::Error::Platform(format!("Wayland roundtrip failed: {e}")))?;

    std::thread::Builder::new()
        .name("focus-monitor".into())
        .spawn(move || crate::wayland::dispatch_forever(&conn, event_queue, state, "focus"))
        .map_err(|e| {
            core_types::Error::Platform(format!("failed to spawn focus monitor thread: {e}"))
        })?;
    Ok(())
}
