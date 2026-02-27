//! Compositor backend trait and detection for Linux Wayland compositors.
//!
//! The `CompositorBackend` trait abstracts window/workspace management over
//! multiple Wayland compositor protocol sets:
//! - `cosmic-toplevel-info-v1` + `cosmic-toplevel-management-v1` (COSMIC)
//! - `wlr-foreign-toplevel-management-v1` (Hyprland, sway, niri, Wayfire)
//! - Sway/i3 IPC socket fallback
//!
//! Phase 1: trait + type definitions only. Backend implementations in Phase 2+.

use core_types::{Geometry, Window, WindowId, WorkspaceId};
use std::future::Future;
use std::pin::Pin;

/// A Wayland workspace.
#[derive(Debug, Clone)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: String,
    pub is_active: bool,
}

/// Configuration for creating a layer-shell surface.
#[derive(Debug, Clone)]
pub struct LayerSurfaceConfig {
    pub namespace: String,
    pub layer: Layer,
    pub anchor: Anchor,
    pub exclusive_zone: i32,
    pub keyboard_mode: KeyboardMode,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

/// Wayland layer-shell layer.
#[derive(Debug, Clone, Copy)]
pub enum Layer {
    Background,
    Bottom,
    Top,
    Overlay,
}

/// Anchor edges for layer-shell surfaces.
#[derive(Debug, Clone, Copy)]
pub struct Anchor {
    pub top: bool,
    pub right: bool,
    pub bottom: bool,
    pub left: bool,
}

/// Keyboard focus mode for layer-shell surfaces.
#[derive(Debug, Clone, Copy)]
pub enum KeyboardMode {
    None,
    Exclusive,
    OnDemand,
}

/// Opaque handle to a layer-shell surface.
pub struct LayerSurface {
    _private: (),
}

// Type alias for boxed async results used by CompositorBackend methods.
type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Abstraction over Wayland compositor protocols for window management.
///
/// Implementations:
/// - `CosmicBackend` (cosmic-toplevel-info-v1 + cosmic-toplevel-management-v1)
/// - `WlrBackend` (wlr-foreign-toplevel-management-v1)
/// - `SwayIpcBackend` (sway/i3 IPC socket)
///
/// Uses `Pin<Box<dyn Future>>` return types for dyn-compatibility — required
/// because `detect_compositor()` returns `Box<dyn CompositorBackend>` for
/// runtime backend selection. Rust RPITIT (`-> impl Future`) is not
/// dyn-compatible.
///
/// Phase 1: trait definition only. Implementations in Phase 2+.
pub trait CompositorBackend: Send + Sync {
    fn list_windows(&self) -> BoxFuture<'_, core_types::Result<Vec<Window>>>;
    fn list_workspaces(&self) -> BoxFuture<'_, core_types::Result<Vec<Workspace>>>;
    fn activate_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>>;
    fn set_window_geometry(
        &self,
        id: &WindowId,
        geom: &Geometry,
    ) -> BoxFuture<'_, core_types::Result<()>>;
    fn move_to_workspace(
        &self,
        id: &WindowId,
        ws: &WorkspaceId,
    ) -> BoxFuture<'_, core_types::Result<()>>;
    fn focus_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>>;
    fn close_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>>;

    /// Human-readable backend name for diagnostics (e.g. "cosmic", "wlr", "sway-ipc").
    fn name(&self) -> &str;
}

/// Detect and instantiate the appropriate compositor backend.
///
/// Detection order:
/// 1. COSMIC-specific protocols (if `cosmic` feature enabled)
/// 2. wlr-foreign-toplevel-management-v1 (Hyprland, sway, niri)
/// 3. Sway IPC socket at `$SWAYSOCK`
/// 4. Error with available protocol listing
///
pub fn detect_compositor() -> core_types::Result<Box<dyn CompositorBackend>> {
    #[cfg(feature = "cosmic")]
    {
        match CosmicBackend::connect() {
            Ok(backend) => {
                tracing::info!("compositor backend: cosmic (ext_foreign_toplevel + zcosmic_toplevel)");
                return Ok(Box::new(backend));
            }
            Err(e) => {
                tracing::info!("cosmic backend unavailable, trying wlr: {e}");
            }
        }
    }

    match WlrBackend::connect() {
        Ok(backend) => {
            tracing::info!("compositor backend: wlr-foreign-toplevel-management-v1");
            Ok(Box::new(backend))
        }
        Err(e) => Err(core_types::Error::Platform(
            format!("no supported compositor backend: {e}"),
        )),
    }
}

/// CompositorBackend implementation using wlr-foreign-toplevel-management-v1.
///
/// Tracks all toplevels via the wlr protocol. Supports list, activate, focus,
/// and close operations. Compatible with sway, Hyprland, niri, Wayfire, and
/// COSMIC (backwards-compatible wlr advertisement).
///
/// Architecture: a dedicated dispatch thread continuously reads Wayland events
/// and updates a shared state snapshot on each `Done` event (the protocol's
/// atomic commit point). `list_windows()` reads the snapshot. `activate_window()`
/// and `close_window()` call proxy methods directly (wayland-client 0.31 proxies
/// are `Send + Sync`) and flush the shared connection.
pub struct WlrBackend {
    state: std::sync::Arc<std::sync::Mutex<WlrState>>,
    conn: wayland_client::Connection,
    seat: wayland_client::protocol::wl_seat::WlSeat,
    /// Kept alive so the protocol manager isn't dropped (which sends `stop` to compositor).
    _manager: wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::ZwlrForeignToplevelManagerV1,
}

/// Published snapshot of toplevel state, shared between dispatch thread and API callers.
struct WlrState {
    toplevels: std::collections::HashMap<
        WindowId,
        WlrToplevelSnapshot,
    >,
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

// -- Dispatch impls for WlrDispatchState (module-level to satisfy non_local_definitions) --

impl wayland_client::Dispatch<wayland_client::protocol::wl_registry::WlRegistry, wayland_client::globals::GlobalListContents> for WlrDispatchState {
    fn event(_: &mut Self, _: &wayland_client::protocol::wl_registry::WlRegistry, _: wayland_client::protocol::wl_registry::Event, _: &wayland_client::globals::GlobalListContents, _: &wayland_client::Connection, _: &wayland_client::QueueHandle<Self>) {}
}

impl wayland_client::Dispatch<wayland_client::protocol::wl_seat::WlSeat, ()> for WlrDispatchState {
    fn event(_: &mut Self, _: &wayland_client::protocol::wl_seat::WlSeat, _: wayland_client::protocol::wl_seat::Event, _: &(), _: &wayland_client::Connection, _: &wayland_client::QueueHandle<Self>) {}
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
                if let Some(tl) = state.pending.get(&id)
                    && let Ok(mut shared) = state.shared.lock()
                {
                    shared.toplevels.insert(tl.window_id, WlrToplevelSnapshot {
                        app_id: tl.app_id.clone(),
                        title: tl.title.clone(),
                        activated: tl.activated,
                        handle: tl.handle.clone(),
                    });
                }
            }
            zwlr_foreign_toplevel_handle_v1::Event::Closed => {
                if let Some(tl) = state.pending.remove(&id)
                    && let Ok(mut shared) = state.shared.lock()
                {
                    shared.toplevels.remove(&tl.window_id);
                }
                handle.destroy();
            }
            _ => {}
        }
    }
}

impl WlrBackend {
    fn connect() -> core_types::Result<Self> {
        use wayland_client::{Connection, globals::registry_queue_init, protocol::wl_seat};
        use wayland_protocols_wlr::foreign_toplevel::v1::client::zwlr_foreign_toplevel_manager_v1::ZwlrForeignToplevelManagerV1;

        // -- Connect and bind --
        let conn = Connection::connect_to_env().map_err(|e| {
            core_types::Error::Platform(format!("Wayland connection failed: {e}"))
        })?;

        let (globals, mut event_queue) = registry_queue_init::<WlrDispatchState>(&conn).map_err(|e| {
            core_types::Error::Platform(format!("Wayland registry init failed: {e}"))
        })?;

        let qh = event_queue.handle();

        let manager: ZwlrForeignToplevelManagerV1 = globals.bind(&qh, 1..=3, ()).map_err(|e| {
            core_types::Error::Platform(format!("wlr-foreign-toplevel-management-v1 not available: {e}"))
        })?;

        let seat: wl_seat::WlSeat = globals.bind(&qh, 1..=9, ()).map_err(|e| {
            core_types::Error::Platform(format!("wl_seat not available: {e}"))
        })?;

        let shared_state = std::sync::Arc::new(std::sync::Mutex::new(WlrState {
            toplevels: std::collections::HashMap::new(),
        }));

        let mut dispatch_state = WlrDispatchState {
            pending: std::collections::HashMap::new(),
            shared: std::sync::Arc::clone(&shared_state),
        };

        // Initial roundtrip to receive existing toplevels.
        event_queue.roundtrip(&mut dispatch_state).map_err(|e| {
            core_types::Error::Platform(format!("Wayland roundtrip failed: {e}"))
        })?;

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
            // Wait for Wayland fd to be readable (50ms timeout for graceful shutdown).
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
            let state = self.state.lock().map_err(|e| {
                core_types::Error::Platform(format!("lock poisoned: {e}"))
            })?;
            let windows = state.toplevels.iter().map(|(wid, tl)| {
                Window {
                    id: *wid,
                    app_id: core_types::AppId::new(&tl.app_id),
                    title: tl.title.clone(),
                    workspace_id: WorkspaceId::new(),
                    monitor_id: core_types::MonitorId::new(),
                    geometry: Geometry { x: 0, y: 0, width: 0, height: 0 },
                    is_focused: tl.activated,
                    is_minimized: false,
                    is_fullscreen: false,
                    profile_id: core_types::ProfileId::new(),
                }
            }).collect();
            Ok(windows)
        })
    }

    fn list_workspaces(&self) -> BoxFuture<'_, core_types::Result<Vec<Workspace>>> {
        Box::pin(async { Ok(vec![]) })
    }

    fn activate_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>> {
        let id = *id;
        Box::pin(async move {
            let state = self.state.lock().map_err(|e| {
                core_types::Error::Platform(format!("lock poisoned: {e}"))
            })?;
            let tl = state.toplevels.get(&id)
                .ok_or_else(|| core_types::Error::Platform("window not found".into()))?;
            tl.handle.activate(&self.seat);
            drop(state);
            self.conn.flush().map_err(|e| {
                core_types::Error::Platform(format!("flush failed: {e}"))
            })?;
            Ok(())
        })
    }

    fn set_window_geometry(&self, _id: &WindowId, _geom: &Geometry) -> BoxFuture<'_, core_types::Result<()>> {
        Box::pin(async {
            Err(core_types::Error::Platform("set_window_geometry not supported by wlr protocol".into()))
        })
    }

    fn move_to_workspace(&self, _id: &WindowId, _ws: &WorkspaceId) -> BoxFuture<'_, core_types::Result<()>> {
        Box::pin(async {
            Err(core_types::Error::Platform("move_to_workspace not supported by wlr protocol".into()))
        })
    }

    fn focus_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>> {
        self.activate_window(id)
    }

    fn close_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>> {
        let id = *id;
        Box::pin(async move {
            let state = self.state.lock().map_err(|e| {
                core_types::Error::Platform(format!("lock poisoned: {e}"))
            })?;
            let tl = state.toplevels.get(&id)
                .ok_or_else(|| core_types::Error::Platform("window not found".into()))?;
            tl.handle.close();
            drop(state);
            self.conn.flush().map_err(|e| {
                core_types::Error::Platform(format!("flush failed: {e}"))
            })?;
            Ok(())
        })
    }

    fn name(&self) -> &str {
        "wlr"
    }
}

// ============================================================================
// COSMIC Backend (ext_foreign_toplevel_list_v1 + zcosmic_toplevel_info/manager)
// ============================================================================

/// CompositorBackend implementation using COSMIC-native protocols.
///
/// Uses three Wayland protocols:
/// - `ext_foreign_toplevel_list_v1`: window enumeration (toplevel handles)
/// - `zcosmic_toplevel_info_v1`: get cosmic handles with activation state
/// - `zcosmic_toplevel_manager_v1`: window activation via `manager.activate(handle, seat)`
///
/// Architecture: a dedicated dispatch thread continuously reads Wayland events.
/// Window enumeration follows a 2-roundtrip pattern (enumerate → get cosmic state).
/// Activation follows a 3-roundtrip pattern (enumerate → get cosmic handle → activate).
///
/// Unlike WlrBackend which maintains a live snapshot, CosmicBackend re-enumerates
/// on each list_windows() call because the ext_foreign_toplevel_list_v1 protocol
/// sends `Finished` after the initial burst — there's no continuous event stream.
/// This matches v1's proven behavior.
#[cfg(feature = "cosmic")]
pub struct CosmicBackend {
    conn: wayland_client::Connection,
    #[allow(dead_code)]
    globals: wayland_client::globals::GlobalList,
    /// Serializes all protocol operations (enumerate, activate) on the shared
    /// connection. Concurrent bind/destroy cycles on the same wl_display corrupt
    /// compositor state and can crash cosmic-comp.
    op_lock: std::sync::Mutex<()>,
}

#[cfg(feature = "cosmic")]
impl CosmicBackend {
    fn connect() -> core_types::Result<Self> {
        use wayland_client::{Connection, globals::registry_queue_init};

        let conn = Connection::connect_to_env().map_err(|e| {
            core_types::Error::Platform(format!("Wayland connection failed: {e}"))
        })?;

        // Probe for required protocols by checking the global list — do NOT bind
        // protocol objects here. Binding ExtForeignToplevelListV1 causes the compositor
        // to start sending Toplevel events; if the probe event queue is then dropped,
        // those objects become zombies and the compositor closes the connection when
        // the client fails to consume their events.
        let (globals, _event_queue) = registry_queue_init::<CosmicProbeState>(&conn).map_err(|e| {
            core_types::Error::Platform(format!("Wayland registry init failed: {e}"))
        })?;

        // Verify all three COSMIC protocols are advertised (by interface name).
        let global_list = globals.contents().clone_list();
        let has = |iface: &str| global_list.iter().any(|g| g.interface == iface);

        if !has("ext_foreign_toplevel_list_v1") {
            return Err(core_types::Error::Platform(
                "ext_foreign_toplevel_list_v1 not available".into(),
            ));
        }
        if !has("zcosmic_toplevel_info_v1") {
            return Err(core_types::Error::Platform(
                "zcosmic_toplevel_info_v1 not available".into(),
            ));
        }
        if !has("zcosmic_toplevel_manager_v1") {
            return Err(core_types::Error::Platform(
                "zcosmic_toplevel_manager_v1 not available".into(),
            ));
        }

        Ok(Self { conn, globals, op_lock: std::sync::Mutex::new(()) })
    }

    /// Enumerate all windows using the 2-roundtrip COSMIC protocol flow.
    ///
    /// Roundtrip 1: receive ext_foreign_toplevel handles (identifier, app_id, title, Done).
    /// Then request zcosmic_toplevel_handle for each via info.get_cosmic_toplevel().
    /// Roundtrip 2: receive cosmic state events (activation detection: state_value == 2).
    fn enumerate(&self) -> core_types::Result<Vec<Window>> {
        let _guard = self.op_lock.lock().map_err(|e| {
            core_types::Error::Platform(format!("op_lock poisoned: {e}"))
        })?;

        use wayland_client::globals::registry_queue_init;
        use wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::ExtForeignToplevelListV1;
        use cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1;

        let (globals, mut event_queue) = registry_queue_init::<CosmicEnumState>(&self.conn).map_err(|e| {
            let proto_err = self.conn.protocol_error();
            core_types::Error::Platform(format!(
                "registry init failed: {e} (protocol_error: {proto_err:?})"
            ))
        })?;
        let qh = event_queue.handle();

        let list: ExtForeignToplevelListV1 = globals.bind(&qh, 1..=1, ()).map_err(|e| {
            core_types::Error::Platform(format!("ext_foreign_toplevel_list bind: {e}"))
        })?;
        let info: ZcosmicToplevelInfoV1 = globals.bind(&qh, 2..=3, ()).map_err(|e| {
            core_types::Error::Platform(format!("zcosmic_toplevel_info bind: {e}"))
        })?;

        let mut state = CosmicEnumState {
            pending: std::collections::HashMap::new(),
            cosmic_pending: std::collections::HashMap::new(),
            toplevels: Vec::new(),
        };

        // Roundtrip 1: receive all ext_foreign_toplevel handles.
        cosmic_roundtrip(&self.conn, &mut event_queue, &mut state)?;

        // Request cosmic handles for state (activation detection).
        // Collect cosmic handle proxies for cleanup.
        let mut cosmic_handles = Vec::new();
        for (handle, _pending) in &state.toplevels {
            let foreign_id = wayland_client::Proxy::id(handle).protocol_id();
            let cosmic_handle = info.get_cosmic_toplevel(handle, &qh, ());
            let cosmic_id = wayland_client::Proxy::id(&cosmic_handle).protocol_id();
            state.cosmic_pending.insert(cosmic_id, foreign_id);
            cosmic_handles.push(cosmic_handle);
        }

        // Roundtrip 2: receive cosmic state events.
        cosmic_roundtrip(&self.conn, &mut event_queue, &mut state)?;

        // Convert to v2 Window structs.
        let mut windows: Vec<Window> = state.toplevels.iter()
            .filter_map(|(_handle, pending)| {
                let app_id = pending.app_id.as_deref().filter(|s| !s.is_empty())?;
                let identifier = pending.identifier.as_deref().unwrap_or("");

                let window_id = WindowId::from_uuid(uuid::Uuid::new_v5(
                    &COSMIC_WINDOW_NAMESPACE,
                    identifier.as_bytes(),
                ));

                Some(Window {
                    id: window_id,
                    app_id: core_types::AppId::new(app_id),
                    title: pending.title.clone().unwrap_or_default(),
                    workspace_id: WorkspaceId::new(),
                    monitor_id: core_types::MonitorId::new(),
                    geometry: core_types::Geometry { x: 0, y: 0, width: 0, height: 0 },
                    is_focused: pending.is_activated,
                    is_minimized: false,
                    is_fullscreen: false,
                    profile_id: core_types::ProfileId::new(),
                })
            })
            .collect();

        // MRU reorder: focused window to end (index 0 = previous, for Alt+Tab).
        if let Some(idx) = windows.iter().position(|w| w.is_focused) {
            let focused = windows.remove(idx);
            windows.push(focused);
        }

        // Protocol cleanup: destroy all objects before dropping EventQueue.
        // Per ext-foreign-toplevel-list-v1.xml: stop → wait finished → destroy handles → destroy list.
        // Per cosmic-toplevel-info-unstable-v1.xml: destroy cosmic handles.
        for cosmic_handle in cosmic_handles {
            cosmic_handle.destroy();
        }
        for (handle, _) in state.toplevels.drain(..) {
            handle.destroy();
        }
        list.stop();
        // Roundtrip to receive the `finished` event before destroying the list.
        let _ = cosmic_roundtrip(&self.conn, &mut event_queue, &mut state);
        list.destroy();
        // Flush destruction requests to the compositor.
        let _ = self.conn.flush();

        Ok(windows)
    }

    /// Activate a window using the 3-roundtrip COSMIC protocol flow.
    ///
    /// Roundtrip 1: enumerate toplevels.
    /// Find target by WindowId, request cosmic handle.
    /// Roundtrip 2: receive cosmic handle.
    /// Call manager.activate(cosmic_handle, seat).
    /// Roundtrip 3: ensure activation is processed.
    fn activate(&self, target_id: &WindowId) -> core_types::Result<()> {
        let _guard = self.op_lock.lock().map_err(|e| {
            core_types::Error::Platform(format!("op_lock poisoned: {e}"))
        })?;

        use wayland_client::globals::registry_queue_init;
        use wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::ExtForeignToplevelListV1;
        use cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1;
        use cosmic_client_toolkit::cosmic_protocols::toplevel_management::v1::client::zcosmic_toplevel_manager_v1::ZcosmicToplevelManagerV1;

        let (globals, mut event_queue) = registry_queue_init::<CosmicEnumState>(&self.conn).map_err(|e| {
            let proto_err = self.conn.protocol_error();
            core_types::Error::Platform(format!(
                "registry init failed: {e} (protocol_error: {proto_err:?})"
            ))
        })?;
        let qh = event_queue.handle();

        let list: ExtForeignToplevelListV1 = globals.bind(&qh, 1..=1, ()).map_err(|e| {
            core_types::Error::Platform(format!("ext_foreign_toplevel_list bind: {e}"))
        })?;
        let info: ZcosmicToplevelInfoV1 = globals.bind(&qh, 2..=3, ()).map_err(|e| {
            core_types::Error::Platform(format!("zcosmic_toplevel_info bind: {e}"))
        })?;
        let manager: ZcosmicToplevelManagerV1 = globals.bind(&qh, 1..=4, ()).map_err(|e| {
            core_types::Error::Platform(format!("zcosmic_toplevel_manager bind: {e}"))
        })?;
        let seat: wayland_client::protocol::wl_seat::WlSeat = globals.bind(&qh, 1..=9, ()).map_err(|e| {
            core_types::Error::Platform(format!("wl_seat bind: {e}"))
        })?;

        let mut state = CosmicEnumState {
            pending: std::collections::HashMap::new(),
            cosmic_pending: std::collections::HashMap::new(),
            toplevels: Vec::new(),
        };

        // Roundtrip 1: enumerate toplevels.
        cosmic_roundtrip(&self.conn, &mut event_queue, &mut state)?;

        // Find target window by deterministic UUID mapping.
        let target_handle = state.toplevels.iter()
            .find(|(_handle, pending)| {
                let identifier = pending.identifier.as_deref().unwrap_or("");
                let wid = WindowId::from_uuid(uuid::Uuid::new_v5(
                    &COSMIC_WINDOW_NAMESPACE,
                    identifier.as_bytes(),
                ));
                wid == *target_id
            })
            .map(|(handle, _)| handle.clone());

        let target_handle = target_handle.ok_or_else(|| {
            core_types::Error::Platform(format!("window {target_id} not found"))
        })?;

        // Request cosmic handle for the target.
        let cosmic_handle = info.get_cosmic_toplevel(&target_handle, &qh, ());

        // Roundtrip 2: receive cosmic handle.
        cosmic_roundtrip(&self.conn, &mut event_queue, &mut state)?;

        // Activate.
        manager.activate(&cosmic_handle, &seat);

        // Roundtrip 3: ensure activation is processed.
        cosmic_roundtrip(&self.conn, &mut event_queue, &mut state)?;

        tracing::info!(window_id = %target_id, "cosmic: window activated");

        // Protocol cleanup: destroy all objects before dropping EventQueue.
        // Per cosmic-toplevel-info-unstable-v1.xml: destroy cosmic handles.
        // Per cosmic-toplevel-management-unstable-v1.xml: destroy manager.
        // Per ext-foreign-toplevel-list-v1.xml: stop → wait finished → destroy handles → destroy list.
        cosmic_handle.destroy();
        for (handle, _) in state.toplevels.drain(..) {
            handle.destroy();
        }
        manager.destroy();
        list.stop();
        let _ = cosmic_roundtrip(&self.conn, &mut event_queue, &mut state);
        list.destroy();
        let _ = self.conn.flush();

        Ok(())
    }
}

/// UUID v5 namespace for deterministic WindowId derivation from COSMIC protocol identifiers.
#[cfg(feature = "cosmic")]
const COSMIC_WINDOW_NAMESPACE: uuid::Uuid = uuid::Uuid::from_bytes([
    0x6f, 0x70, 0x65, 0x6e, 0x2d, 0x73, 0x65, 0x73,
    0x61, 0x6d, 0x65, 0x2d, 0x77, 0x69, 0x6e, 0x64,
]); // "open-sesame-wind" as bytes

/// Wayland roundtrip with timeout protection (2s default).
/// Prevents indefinite blocking if the compositor hangs.
#[cfg(feature = "cosmic")]
fn cosmic_roundtrip<D: 'static>(
    conn: &wayland_client::Connection,
    event_queue: &mut wayland_client::EventQueue<D>,
    state: &mut D,
) -> core_types::Result<()> {
    use std::os::unix::io::{AsFd, AsRawFd};

    // Helper: format error with protocol_error() context for diagnostics.
    let fmt_err = |phase: &str, e: &dyn std::fmt::Display| -> core_types::Error {
        let proto_err = conn.protocol_error();
        core_types::Error::Platform(format!(
            "Wayland {phase}: {e} (protocol_error: {proto_err:?})"
        ))
    };

    let timeout = std::time::Duration::from_secs(2);
    let start = std::time::Instant::now();
    let fd = conn.as_fd().as_raw_fd();

    loop {
        conn.flush().map_err(|e| fmt_err("flush", &e))?;

        event_queue.dispatch_pending(state).map_err(|e| fmt_err("dispatch_pending", &e))?;

        if start.elapsed() >= timeout {
            return Err(core_types::Error::Platform(
                format!("Wayland roundtrip timed out after {timeout:?}"),
            ));
        }

        let remaining = timeout.saturating_sub(start.elapsed());
        let timeout_ms = remaining.as_millis().min(100) as i32;

        let mut pollfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let ret = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted { continue; }
            return Err(fmt_err("poll", &err));
        }

        if ret > 0 && (pollfd.revents & libc::POLLIN) != 0 {
            if let Some(guard) = conn.prepare_read()
                && let Err(e) = guard.read()
            {
                return Err(fmt_err("read", &e));
            }
            event_queue.dispatch_pending(state).map_err(|e| fmt_err("dispatch_pending[2]", &e))?;

            // Final blocking roundtrip to ensure all server events are received.
            event_queue.roundtrip(state).map_err(|e| fmt_err("roundtrip", &e))?;
            return Ok(());
        }
    }
}

#[cfg(feature = "cosmic")]
impl CompositorBackend for CosmicBackend {
    fn list_windows(&self) -> BoxFuture<'_, core_types::Result<Vec<Window>>> {
        Box::pin(async move { self.enumerate() })
    }

    fn list_workspaces(&self) -> BoxFuture<'_, core_types::Result<Vec<Workspace>>> {
        Box::pin(async { Ok(vec![]) })
    }

    fn activate_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>> {
        let id = *id;
        Box::pin(async move { self.activate(&id) })
    }

    fn set_window_geometry(&self, _id: &WindowId, _geom: &Geometry) -> BoxFuture<'_, core_types::Result<()>> {
        Box::pin(async {
            Err(core_types::Error::Platform("set_window_geometry not supported by cosmic protocol".into()))
        })
    }

    fn move_to_workspace(&self, _id: &WindowId, _ws: &WorkspaceId) -> BoxFuture<'_, core_types::Result<()>> {
        Box::pin(async {
            Err(core_types::Error::Platform("move_to_workspace not yet implemented for cosmic".into()))
        })
    }

    fn focus_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>> {
        self.activate_window(id)
    }

    fn close_window(&self, _id: &WindowId) -> BoxFuture<'_, core_types::Result<()>> {
        // TODO: implement via zcosmic_toplevel_manager_v1.close()
        Box::pin(async move {
            Err(core_types::Error::Platform("close_window not yet implemented for cosmic".into()))
        })
    }

    fn name(&self) -> &str {
        "cosmic"
    }
}

// -- Dispatch state types for CosmicBackend --

/// Minimal probe state used during connect() to verify protocol availability.
#[cfg(feature = "cosmic")]
struct CosmicProbeState;

#[cfg(feature = "cosmic")]
impl wayland_client::Dispatch<wayland_client::protocol::wl_registry::WlRegistry, wayland_client::globals::GlobalListContents> for CosmicProbeState {
    fn event(_: &mut Self, _: &wayland_client::protocol::wl_registry::WlRegistry, _: wayland_client::protocol::wl_registry::Event, _: &wayland_client::globals::GlobalListContents, _: &wayland_client::Connection, _: &wayland_client::QueueHandle<Self>) {}
}

// -- Enumeration dispatch state --

/// Pending toplevel data collected from ext_foreign_toplevel events.
#[cfg(feature = "cosmic")]
#[derive(Debug, Default)]
struct CosmicPendingToplevel {
    identifier: Option<String>,
    app_id: Option<String>,
    title: Option<String>,
    is_activated: bool,
}

/// State for COSMIC window enumeration and activation.
#[cfg(feature = "cosmic")]
struct CosmicEnumState {
    pending: std::collections::HashMap<u32, CosmicPendingToplevel>,
    cosmic_pending: std::collections::HashMap<u32, u32>, // cosmic handle id -> foreign handle id
    toplevels: Vec<(wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_handle_v1::ExtForeignToplevelHandleV1, CosmicPendingToplevel)>,
}

// Dispatch impls for CosmicEnumState — mirrors v1's EnumerationState pattern.

#[cfg(feature = "cosmic")]
impl wayland_client::Dispatch<wayland_client::protocol::wl_registry::WlRegistry, wayland_client::globals::GlobalListContents> for CosmicEnumState {
    fn event(_: &mut Self, _: &wayland_client::protocol::wl_registry::WlRegistry, _: wayland_client::protocol::wl_registry::Event, _: &wayland_client::globals::GlobalListContents, _: &wayland_client::Connection, _: &wayland_client::QueueHandle<Self>) {}
}

#[cfg(feature = "cosmic")]
impl wayland_client::Dispatch<wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::ExtForeignToplevelListV1, ()> for CosmicEnumState {
    fn event(
        state: &mut Self,
        _proxy: &wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::ExtForeignToplevelListV1,
        event: wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::Event,
        _: &(),
        _conn: &wayland_client::Connection,
        _qh: &wayland_client::QueueHandle<Self>,
    ) {
        if let wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::Event::Toplevel { toplevel } = event {
            let id = wayland_client::Proxy::id(&toplevel).protocol_id();
            state.pending.insert(id, CosmicPendingToplevel::default());
        }
    }

    wayland_client::event_created_child!(CosmicEnumState, wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::ExtForeignToplevelListV1, [
        wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::EVT_TOPLEVEL_OPCODE =>
            (wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_handle_v1::ExtForeignToplevelHandleV1, ())
    ]);
}

#[cfg(feature = "cosmic")]
impl wayland_client::Dispatch<wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_handle_v1::ExtForeignToplevelHandleV1, ()> for CosmicEnumState {
    fn event(
        state: &mut Self,
        proxy: &wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_handle_v1::ExtForeignToplevelHandleV1,
        event: wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_handle_v1::Event,
        _: &(),
        _conn: &wayland_client::Connection,
        _qh: &wayland_client::QueueHandle<Self>,
    ) {
        use wayland_client::Proxy;
        use wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_handle_v1;
        let id = proxy.id().protocol_id();

        match event {
            ext_foreign_toplevel_handle_v1::Event::Identifier { identifier } => {
                if let Some(p) = state.pending.get_mut(&id) { p.identifier = Some(identifier); }
            }
            ext_foreign_toplevel_handle_v1::Event::AppId { app_id } => {
                if let Some(p) = state.pending.get_mut(&id) { p.app_id = Some(app_id); }
            }
            ext_foreign_toplevel_handle_v1::Event::Title { title } => {
                if let Some(p) = state.pending.get_mut(&id) { p.title = Some(title); }
            }
            ext_foreign_toplevel_handle_v1::Event::Done => {
                if let Some(p) = state.pending.remove(&id) {
                    state.toplevels.push((proxy.clone(), p));
                }
            }
            ext_foreign_toplevel_handle_v1::Event::Closed => {
                state.pending.remove(&id);
            }
            _ => {}
        }
    }
}

#[cfg(feature = "cosmic")]
impl wayland_client::Dispatch<cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1, ()> for CosmicEnumState {
    fn event(_: &mut Self, _: &cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1, _: cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::Event, _: &(), _: &wayland_client::Connection, _: &wayland_client::QueueHandle<Self>) {}

    wayland_client::event_created_child!(CosmicEnumState, cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1, [
        cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::EVT_TOPLEVEL_OPCODE =>
            (cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_handle_v1::ZcosmicToplevelHandleV1, ())
    ]);
}

#[cfg(feature = "cosmic")]
impl wayland_client::Dispatch<cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_handle_v1::ZcosmicToplevelHandleV1, ()> for CosmicEnumState {
    fn event(
        state: &mut Self,
        proxy: &cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_handle_v1::ZcosmicToplevelHandleV1,
        event: cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_handle_v1::Event,
        _: &(),
        _conn: &wayland_client::Connection,
        _qh: &wayland_client::QueueHandle<Self>,
    ) {
        use wayland_client::Proxy;
        let cosmic_id = proxy.id().protocol_id();

        if let Some(&foreign_id) = state.cosmic_pending.get(&cosmic_id)
            && let cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_handle_v1::Event::State { state: state_bytes } = &event
        {
            if state_bytes.len() % 4 != 0 { return; }
            for chunk in state_bytes.chunks_exact(4) {
                let val = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                if val == 2 { // State::Activated
                    if let Some((_h, p)) = state.toplevels.iter_mut().find(|(h, _)| h.id().protocol_id() == foreign_id) {
                        p.is_activated = true;
                    }
                }
            }
        }
    }
}

#[cfg(feature = "cosmic")]
impl wayland_client::Dispatch<cosmic_client_toolkit::cosmic_protocols::toplevel_management::v1::client::zcosmic_toplevel_manager_v1::ZcosmicToplevelManagerV1, ()> for CosmicEnumState {
    fn event(_: &mut Self, _: &cosmic_client_toolkit::cosmic_protocols::toplevel_management::v1::client::zcosmic_toplevel_manager_v1::ZcosmicToplevelManagerV1, _: cosmic_client_toolkit::cosmic_protocols::toplevel_management::v1::client::zcosmic_toplevel_manager_v1::Event, _: &(), _: &wayland_client::Connection, _: &wayland_client::QueueHandle<Self>) {}
}

#[cfg(feature = "cosmic")]
impl wayland_client::Dispatch<wayland_client::protocol::wl_seat::WlSeat, ()> for CosmicEnumState {
    fn event(_: &mut Self, _: &wayland_client::protocol::wl_seat::WlSeat, _: wayland_client::protocol::wl_seat::Event, _: &(), _: &wayland_client::Connection, _: &wayland_client::QueueHandle<Self>) {}
}

// ============================================================================
// Focus Monitor (wlr-foreign-toplevel-management-v1)
// ============================================================================

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
/// Compatible with: sway, Hyprland, niri, Wayfire, COSMIC (which also
/// advertises the wlr protocol for backwards compatibility).
///
/// Runs as a long-lived task — spawn with `tokio::spawn`.
pub async fn focus_monitor(tx: tokio::sync::mpsc::Sender<FocusEvent>) {
    if let Err(e) = focus_monitor_inner(&tx).await {
        tracing::warn!(error = %e, "focus monitor exiting");
    }
}

async fn focus_monitor_inner(
    tx: &tokio::sync::mpsc::Sender<FocusEvent>,
) -> core_types::Result<()> {
    use std::collections::HashMap;
    use std::os::unix::io::AsFd;
    use tokio::io::unix::AsyncFd;
    use tokio::io::Interest;
    use wayland_client::{
        Connection, Dispatch, EventQueue, Proxy, QueueHandle,
        globals::{GlobalList, GlobalListContents, registry_queue_init},
        protocol::wl_registry,
    };
    use wayland_protocols_wlr::foreign_toplevel::v1::client::{
        zwlr_foreign_toplevel_handle_v1::{self, ZwlrForeignToplevelHandleV1},
        zwlr_foreign_toplevel_manager_v1::{self, ZwlrForeignToplevelManagerV1},
    };

    // -- Per-toplevel tracking state --
    #[derive(Debug, Default, Clone)]
    struct ToplevelData {
        app_id: String,
        activated: bool,
    }

    // -- Wayland dispatch state --
    struct FocusState {
        toplevels: HashMap<wayland_client::backend::ObjectId, ToplevelData>,
        focused_app_id: String,
        tx: tokio::sync::mpsc::Sender<FocusEvent>,
    }

    // UserData attached to each toplevel handle proxy (unit — state tracked in FocusState).
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
                        && entry.activated && !entry.app_id.is_empty() && entry.app_id != state.focused_app_id {
                            state.focused_app_id.clone_from(&entry.app_id);
                            let _ = state.tx.try_send(FocusEvent::Focus(entry.app_id.clone()));
                    }
                }
                zwlr_foreign_toplevel_handle_v1::Event::Closed => {
                    let closed_app_id = state.toplevels.get(&id)
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

    // -- Connect and bind --
    let conn = Connection::connect_to_env().map_err(|e| {
        core_types::Error::Platform(format!("Wayland connection failed: {e}"))
    })?;

    let (globals, mut event_queue): (GlobalList, EventQueue<FocusState>) =
        registry_queue_init(&conn).map_err(|e| {
            core_types::Error::Platform(format!("Wayland registry init failed: {e}"))
        })?;

    let qh = event_queue.handle();

    // Bind the wlr foreign toplevel manager (version 3).
    let _manager: ZwlrForeignToplevelManagerV1 = globals
        .bind(&qh, 1..=3, ())
        .map_err(|e| {
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
    event_queue.roundtrip(&mut state).map_err(|e| {
        core_types::Error::Platform(format!("Wayland roundtrip failed: {e}"))
    })?;

    // -- Async event loop via tokio AsyncFd --
    let async_fd = AsyncFd::with_interest(conn.as_fd().try_clone_to_owned().map_err(|e| {
        core_types::Error::Platform(format!("failed to clone Wayland fd: {e}"))
    })?, Interest::READABLE).map_err(|e| {
        core_types::Error::Platform(format!("AsyncFd creation failed: {e}"))
    })?;

    loop {
        // Wait for the Wayland socket to become readable.
        let mut ready = async_fd.readable().await.map_err(|e| {
            core_types::Error::Platform(format!("AsyncFd readable failed: {e}"))
        })?;

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
            core_types::Error::Platform(format!("Wayland dispatch failed: {e} (protocol_error: {proto_err:?})"))
        })?;

        // Flush any outgoing requests (e.g. destroy).
        conn.flush().map_err(|e| {
            let proto_err = conn.protocol_error();
            core_types::Error::Platform(format!("Wayland flush failed: {e} (protocol_error: {proto_err:?})"))
        })?;

        // Clear readiness so we wait again.
        ready.clear_ready();
    }
}
