//! CompositorBackend implementation using wlr-foreign-toplevel-management-v1.
//!
//! Tracks all toplevels via the wlr protocol. Supports list, activate, focus,
//! and close operations. Compatible with sway, Hyprland, niri, Wayfire, and
//! COSMIC (backwards-compatible wlr advertisement).
//!
//! Architecture: a dedicated dispatch thread continuously reads Wayland events
//! and updates a shared state snapshot on each `Done` event (the protocol's
//! atomic commit point). `list_windows()` reads the snapshot. `activate_window()`
//! and `close_window()` call proxy methods directly (wayland-client 0.31 proxies
//! are `Send + Sync`) and flush the shared connection.

use crate::compositor::{BoxFuture, CompositorBackend, Workspace};
use core_types::{CompositorWorkspaceId, Geometry, Window, WindowId};

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
    activated: bool,
    /// Proxy handle for activate/close — Send+Sync in wayland-client 0.31.
    handle: wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1::ZwlrForeignToplevelHandleV1,
}

/// Pending per-toplevel state on the dispatch thread (before `Done` commits).
struct WlrPendingToplevel {
    window_id: WindowId,
    app_id: String,
    title: String,
    activated: bool,
    handle: wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_handle_v1::ZwlrForeignToplevelHandleV1,
}

/// Dispatch thread state — owns the working copy of toplevels.
struct WlrDispatchState {
    pending: std::collections::HashMap<wayland_client::backend::ObjectId, WlrPendingToplevel>,
    shared: std::sync::Arc<std::sync::Mutex<WlrState>>,
}

/// User-data attached to each toplevel handle proxy (unit — state tracked in WlrDispatchState).
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
        _: &(),
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
        _: &(),
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
                state.pending.entry(id).or_insert_with(|| WlrPendingToplevel {
                    window_id: WindowId::new(), app_id: String::new(),
                    title: String::new(), activated: false,
                    handle: handle.clone(),
                }).app_id = app_id;
            }
            zwlr_foreign_toplevel_handle_v1::Event::Title { title } => {
                state.pending.entry(id).or_insert_with(|| WlrPendingToplevel {
                    window_id: WindowId::new(), app_id: String::new(),
                    title: String::new(), activated: false,
                    handle: handle.clone(),
                }).title = title;
            }
            zwlr_foreign_toplevel_handle_v1::Event::State { state: state_bytes } => {
                let activated = state_bytes.chunks_exact(4)
                    .flat_map(TryInto::<[u8; 4]>::try_into)
                    .map(u32::from_ne_bytes)
                    .any(|v| v == zwlr_foreign_toplevel_handle_v1::State::Activated as u32);
                state.pending.entry(id).or_insert_with(|| WlrPendingToplevel {
                    window_id: WindowId::new(), app_id: String::new(),
                    title: String::new(), activated: false,
                    handle: handle.clone(),
                }).activated = activated;
            }
            zwlr_foreign_toplevel_handle_v1::Event::Done => {
                // Atomic commit point — publish to shared state.
                if let Some(tl) = state.pending.get(&id) {
                    match state.shared.lock() {
                        Ok(mut shared) => {
                            shared.toplevels.insert(tl.window_id, WlrToplevelSnapshot {
                                app_id: tl.app_id.clone(),
                                title: tl.title.clone(),
                                activated: tl.activated,
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
                wlr_dispatch_loop(dispatch_conn, event_queue, dispatch_state);
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

/// Continuous Wayland event dispatch loop running on a dedicated thread.
///
/// Uses `prepare_read()` + `libc::poll()` to efficiently wait for Wayland events
/// without busy-spinning. Dispatches events to the `WlrDispatchState` which
/// publishes committed state to the shared `WlrState` on `Done` events.
fn wlr_dispatch_loop(
    conn: wayland_client::Connection,
    mut event_queue: wayland_client::EventQueue<WlrDispatchState>,
    mut state: WlrDispatchState,
) {
    use std::os::fd::AsFd;
    use std::os::unix::io::AsRawFd;

    let mut backoff = std::time::Duration::from_millis(100);
    let max_backoff = std::time::Duration::from_secs(30);

    loop {
        // Prepare to read — if events are already buffered, this returns None
        // and we should dispatch immediately.
        if let Some(guard) = conn.prepare_read() {
            // Wait for Wayland fd to be readable (50ms periodic wake-up).
            let mut pollfd = libc::pollfd {
                fd: conn.as_fd().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ret = unsafe { libc::poll(&mut pollfd, 1, 50) };

            if ret > 0 && (pollfd.revents & libc::POLLIN) != 0 {
                match guard.read() {
                    Ok(_) => {
                        backoff = std::time::Duration::from_millis(100);
                    }
                    Err(wayland_client::backend::WaylandError::Io(ref e))
                        if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        let proto_err = conn.protocol_error();
                        tracing::error!(error = %e, ?proto_err, backoff_ms = backoff.as_millis(), "wlr dispatch: Wayland read failed, backing off");
                        std::thread::sleep(backoff);
                        backoff = (backoff * 2).min(max_backoff);
                        continue;
                    }
                }
            } else {
                // Timeout or error — drop the read guard to cancel.
                drop(guard);
            }
        }

        // Dispatch all buffered events.
        if let Err(e) = event_queue.dispatch_pending(&mut state) {
            let proto_err = conn.protocol_error();
            tracing::error!(error = %e, ?proto_err, backoff_ms = backoff.as_millis(), "wlr dispatch: dispatch_pending failed, backing off");
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(max_backoff);
            continue;
        }

        // Flush outgoing requests (e.g. destroy from Closed handling).
        if let Err(e) = conn.flush() {
            let proto_err = conn.protocol_error();
            tracing::error!(error = %e, ?proto_err, backoff_ms = backoff.as_millis(), "wlr dispatch: flush failed, backing off");
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(max_backoff);
            continue;
        }
    }
}

impl CompositorBackend for WlrBackend {
    fn list_windows(&self) -> BoxFuture<'_, core_types::Result<Vec<Window>>> {
        Box::pin(async move {
            let state = self
                .state
                .lock()
                .map_err(|e| core_types::Error::Platform(format!("lock poisoned: {e}")))?;
            let windows = state
                .toplevels
                .iter()
                .map(|(wid, tl)| Window {
                    id: *wid,
                    app_id: core_types::AppId::new(&tl.app_id),
                    title: tl.title.clone(),
                    workspace_id: CompositorWorkspaceId::from_uuid(uuid::Uuid::nil()),
                    monitor_id: core_types::MonitorId::from_uuid(uuid::Uuid::nil()),
                    geometry: Geometry {
                        x: 0,
                        y: 0,
                        width: 0,
                        height: 0,
                    },
                    is_focused: tl.activated,
                    is_minimized: false,
                    is_fullscreen: false,
                    profile_id: core_types::ProfileId::from_uuid(uuid::Uuid::nil()),
                })
                .collect();
            Ok(windows)
        })
    }

    fn list_workspaces(&self) -> BoxFuture<'_, core_types::Result<Vec<Workspace>>> {
        Box::pin(async { Ok(vec![]) })
    }

    fn activate_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>> {
        let id = *id;
        Box::pin(async move {
            let state = self
                .state
                .lock()
                .map_err(|e| core_types::Error::Platform(format!("lock poisoned: {e}")))?;
            let tl = state
                .toplevels
                .get(&id)
                .ok_or_else(|| core_types::Error::Platform("window not found".into()))?;
            tl.handle.activate(&self.seat);
            drop(state);
            self.conn
                .flush()
                .map_err(|e| core_types::Error::Platform(format!("flush failed: {e}")))?;
            Ok(())
        })
    }

    fn set_window_geometry(
        &self,
        _id: &WindowId,
        _geom: &Geometry,
    ) -> BoxFuture<'_, core_types::Result<()>> {
        Box::pin(async {
            Err(core_types::Error::Platform(
                "set_window_geometry not supported by wlr protocol".into(),
            ))
        })
    }

    fn move_to_workspace(
        &self,
        _id: &WindowId,
        _ws: &CompositorWorkspaceId,
    ) -> BoxFuture<'_, core_types::Result<()>> {
        Box::pin(async {
            Err(core_types::Error::Platform(
                "move_to_workspace not supported by wlr protocol".into(),
            ))
        })
    }

    fn focus_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>> {
        self.activate_window(id)
    }

    fn close_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>> {
        let id = *id;
        Box::pin(async move {
            let state = self
                .state
                .lock()
                .map_err(|e| core_types::Error::Platform(format!("lock poisoned: {e}")))?;
            let tl = state
                .toplevels
                .get(&id)
                .ok_or_else(|| core_types::Error::Platform("window not found".into()))?;
            tl.handle.close();
            drop(state);
            self.conn
                .flush()
                .map_err(|e| core_types::Error::Platform(format!("flush failed: {e}")))?;
            Ok(())
        })
    }

    fn name(&self) -> &str {
        "wlr"
    }
}
