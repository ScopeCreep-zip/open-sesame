//! `CompositorBackend` implementation using wlr-foreign-toplevel-management-v1.
//!
//! Tracks all toplevels via the wlr protocol: list, activate, and close.
//! Compatible with sway, Hyprland, niri, Wayfire, and COSMIC
//! (backwards-compatible wlr advertisement).
//!
//! Architecture: a dedicated dispatch thread (`wayland::dispatch_forever`)
//! continuously reads Wayland events and updates a shared state snapshot on
//! each `Done` event (the protocol's atomic commit point). `list_windows()`
//! reads the snapshot. `activate_window()` and `close_window()` call proxy
//! methods directly (wayland-client 0.31 proxies are `Send + Sync`) and
//! flush the shared connection.

use crate::compositor::CompositorBackend;
use crate::wayland::{ToplevelState, WLR_STATE};
use core_types::{Window, WindowId};

pub(crate) struct WlrBackend {
    state: std::sync::Arc<std::sync::Mutex<WlrState>>,
    conn: wayland_client::Connection,
    seat: wayland_client::protocol::wl_seat::WlSeat,
    /// Kept alive so the protocol manager isn't dropped (which sends `stop` to compositor).
    _manager: wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::ZwlrForeignToplevelManagerV1,
}

/// Published snapshot of toplevel state, shared between dispatch thread and API callers.
struct WlrState {
    toplevels: std::collections::HashMap<WindowId, WlrToplevelSnapshot>,
}

/// Committed toplevel state — only published after a `Done` event.
struct WlrToplevelSnapshot {
    app_id: String,
    title: String,
    state: ToplevelState,
    /// Proxy handle for activate/close — Send+Sync in wayland-client 0.31.
    handle: wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1::ZwlrForeignToplevelHandleV1,
}

/// Pending per-toplevel state on the dispatch thread (before `Done` commits).
struct WlrPendingToplevel {
    window_id: WindowId,
    app_id: String,
    title: String,
    state: ToplevelState,
    handle: wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1::ZwlrForeignToplevelHandleV1,
}

/// Dispatch thread state — owns the working copy of toplevels.
struct WlrDispatchState {
    pending: std::collections::HashMap<wayland_client::backend::ObjectId, WlrPendingToplevel>,
    shared: std::sync::Arc<std::sync::Mutex<WlrState>>,
}

impl WlrDispatchState {
    /// The pending state of the toplevel `handle`, created by its first
    /// event.
    fn pending_entry(
        &mut self,
        handle: &wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1::ZwlrForeignToplevelHandleV1,
    ) -> &mut WlrPendingToplevel {
        use wayland_client::Proxy;
        self.pending
            .entry(handle.id())
            .or_insert_with(|| WlrPendingToplevel {
                window_id: WindowId::new(),
                app_id: String::new(),
                title: String::new(),
                state: ToplevelState::default(),
                handle: handle.clone(),
            })
    }
}

/// User-data attached to each toplevel handle proxy (unit — state tracked in `WlrDispatchState`).
#[derive(Debug, Default, Clone)]
struct WlrHandleData;

// -- Dispatch impls for WlrDispatchState --

impl
    wayland_client::Dispatch<
        wayland_client::protocol::wl_registry::WlRegistry,
        wayland_client::globals::GlobalListContents,
    > for WlrDispatchState
{
    fn event(
        _: &mut Self,
        _: &wayland_client::protocol::wl_registry::WlRegistry,
        _: wayland_client::protocol::wl_registry::Event,
        _: &wayland_client::globals::GlobalListContents,
        _: &wayland_client::Connection,
        _: &wayland_client::QueueHandle<Self>,
    ) {
    }
}

impl wayland_client::Dispatch<wayland_client::protocol::wl_seat::WlSeat, ()> for WlrDispatchState {
    fn event(
        _: &mut Self,
        _: &wayland_client::protocol::wl_seat::WlSeat,
        _: wayland_client::protocol::wl_seat::Event,
        (): &(),
        _: &wayland_client::Connection,
        _: &wayland_client::QueueHandle<Self>,
    ) {
    }
}

impl wayland_client::Dispatch<wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::ZwlrForeignToplevelManagerV1, ()> for WlrDispatchState {
    fn event(
        _state: &mut Self,
        _proxy: &wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::ZwlrForeignToplevelManagerV1,
        event: wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::Event,
        (): &(),
        _conn: &wayland_client::Connection,
        _qh: &wayland_client::QueueHandle<Self>,
    ) {
        if let wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::Event::Finished = event {
            tracing::info!("wlr foreign toplevel manager finished");
        }
    }

    wayland_client::event_created_child!(WlrDispatchState, wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::ZwlrForeignToplevelManagerV1, [
        wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::EVT_TOPLEVEL_OPCODE =>
            (wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1::ZwlrForeignToplevelHandleV1, WlrHandleData)
    ]);
}

impl wayland_client::Dispatch<wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1::ZwlrForeignToplevelHandleV1, WlrHandleData> for WlrDispatchState {
    fn event(
        state: &mut Self,
        handle: &wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1::ZwlrForeignToplevelHandleV1,
        event: wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1::Event,
        _data: &WlrHandleData,
        _conn: &wayland_client::Connection,
        _qh: &wayland_client::QueueHandle<Self>,
    ) {
        use wayland_client::Proxy;
        use wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1;
        let id = handle.id();
        match event {
            zwlr_foreign_toplevel_handle_v1::Event::AppId { app_id } => {
                state.pending_entry(handle).app_id = app_id;
            }
            zwlr_foreign_toplevel_handle_v1::Event::Title { title } => {
                state.pending_entry(handle).title = title;
            }
            zwlr_foreign_toplevel_handle_v1::Event::State { state: packed } => {
                state.pending_entry(handle).state = ToplevelState::decode(&packed, WLR_STATE);
            }
            zwlr_foreign_toplevel_handle_v1::Event::Done => {
                // Atomic commit point — publish to shared state.
                if let Some(tl) = state.pending.get(&id) {
                    match state.shared.lock() {
                        Ok(mut shared) => {
                            shared.toplevels.insert(tl.window_id, WlrToplevelSnapshot {
                                app_id: tl.app_id.clone(),
                                title: tl.title.clone(),
                                state: tl.state,
                                handle: tl.handle.clone(),
                            });
                        }
                        Err(e) => tracing::error!("wlr shared state mutex poisoned on Done: {e}"),
                    }
                }
            }
            zwlr_foreign_toplevel_handle_v1::Event::Closed => {
                if let Some(tl) = state.pending.remove(&id) {
                    match state.shared.lock() {
                        Ok(mut shared) => { shared.toplevels.remove(&tl.window_id); }
                        Err(e) => tracing::error!("wlr shared state mutex poisoned on Closed: {e}"),
                    }
                }
                handle.destroy();
            }
            _ => {}
        }
    }
}

impl WlrBackend {
    pub(crate) fn connect() -> core_types::Result<Self> {
        use wayland_client::{Connection, globals::registry_queue_init, protocol::wl_seat};
        use wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::ZwlrForeignToplevelManagerV1;

        // -- Connect and bind --
        let conn = Connection::connect_to_env()
            .map_err(|e| core_types::Error::Platform(format!("Wayland connection failed: {e}")))?;

        let (globals, mut event_queue) =
            registry_queue_init::<WlrDispatchState>(&conn).map_err(|e| {
                core_types::Error::Platform(format!("Wayland registry init failed: {e}"))
            })?;

        let qh = event_queue.handle();

        let manager: ZwlrForeignToplevelManagerV1 = globals.bind(&qh, 1..=3, ()).map_err(|e| {
            core_types::Error::Platform(format!(
                "wlr-foreign-toplevel-management-v1 not available: {e}"
            ))
        })?;

        let seat: wl_seat::WlSeat = globals
            .bind(&qh, 1..=9, ())
            .map_err(|e| core_types::Error::Platform(format!("wl_seat not available: {e}")))?;

        let shared_state = std::sync::Arc::new(std::sync::Mutex::new(WlrState {
            toplevels: std::collections::HashMap::new(),
        }));

        let mut dispatch_state = WlrDispatchState {
            pending: std::collections::HashMap::new(),
            shared: std::sync::Arc::clone(&shared_state),
        };

        // Initial roundtrip to receive existing toplevels.
        event_queue
            .roundtrip(&mut dispatch_state)
            .map_err(|e| core_types::Error::Platform(format!("Wayland roundtrip failed: {e}")))?;

        // Spawn dedicated dispatch thread for continuous event processing.
        let dispatch_conn = conn.clone();
        std::thread::Builder::new()
            .name("wlr-dispatch".into())
            .spawn(move || {
                crate::wayland::dispatch_forever(&dispatch_conn, event_queue, dispatch_state, "wlr")
            })
            .map_err(|e| {
                core_types::Error::Platform(format!("failed to spawn wlr dispatch thread: {e}"))
            })?;

        Ok(Self {
            state: shared_state,
            conn,
            seat,
            _manager: manager,
        })
    }
}

impl WlrBackend {
    /// Issue `request` on the handle of window `id`, then flush it to the
    /// compositor.
    fn on_toplevel(
        &self,
        id: &WindowId,
        request: impl FnOnce(&WlrToplevelSnapshot),
    ) -> core_types::Result<()> {
        {
            let state = self
                .state
                .lock()
                .map_err(|e| core_types::Error::Platform(format!("lock poisoned: {e}")))?;
            let toplevel = state
                .toplevels
                .get(id)
                .ok_or_else(|| core_types::Error::Platform(format!("window {id} not found")))?;
            request(toplevel);
        }
        self.conn
            .flush()
            .map_err(|e| core_types::Error::Platform(format!("flush failed: {e}")))
    }
}

impl CompositorBackend for WlrBackend {
    fn list_windows(&self) -> core_types::Result<Vec<Window>> {
        let state = self
            .state
            .lock()
            .map_err(|e| core_types::Error::Platform(format!("lock poisoned: {e}")))?;
        Ok(state
            .toplevels
            .iter()
            .map(|(wid, tl)| tl.state.window(*wid, &tl.app_id, tl.title.clone()))
            .collect())
    }

    fn activate_window(&self, id: &WindowId) -> core_types::Result<()> {
        self.on_toplevel(id, |toplevel| toplevel.handle.activate(&self.seat))
    }

    fn close_window(&self, id: &WindowId) -> core_types::Result<()> {
        self.on_toplevel(id, |toplevel| toplevel.handle.close())
    }

    fn name(&self) -> &'static str {
        "wlr"
    }
}
