//! CompositorBackend implementation using COSMIC-native protocols.
//!
//! Architecture: bind-once, dispatch-forever, read-snapshot.
//!
//! A dedicated dispatch thread continuously processes Wayland events from:
//! - `ext_foreign_toplevel_list_v1`: window creation/destruction
//! - `zcosmic_toplevel_info_v1`: cosmic state (activation, geometry)
//!
//! `list_windows()` reads a shared snapshot — zero allocations, zero protocol
//! operations per call. This eliminates the memory leak caused by the previous
//! per-poll `registry_queue_init` + `globals.bind` architecture (see #25).
//!
//! `activate_window()` and `close_window()` use disposable connections to avoid
//! crashing cosmic-comp when protocol objects are destroyed in flight.

use crate::compositor::{BoxFuture, CompositorBackend, Workspace};
use core_types::{CompositorWorkspaceId, Geometry, Window, WindowId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// UUID v5 namespace for deterministic WindowId derivation from COSMIC protocol identifiers.
const COSMIC_WINDOW_NAMESPACE: uuid::Uuid = uuid::Uuid::from_bytes([
    0x6f, 0x70, 0x65, 0x6e, 0x2d, 0x73, 0x65, 0x73, 0x61, 0x6d, 0x65, 0x2d, 0x77, 0x69, 0x6e, 0x64,
]); // "open-sesame-wind" as bytes

// ============================================================================
// Public backend
// ============================================================================

pub(crate) struct CosmicBackend {
    /// Shared snapshot updated by the dispatch thread on every toplevel event.
    state: Arc<Mutex<CosmicState>>,
    /// Kept alive so the dispatch thread's connection clone remains valid.
    /// The dispatch thread holds its own clone; this prevents the underlying
    /// Wayland fd from being closed if the backend outlives the thread.
    _conn: wayland_client::Connection,
}

/// Published snapshot of all toplevel windows, shared between the dispatch
/// thread and API callers.
struct CosmicState {
    toplevels: HashMap<WindowId, CosmicToplevelSnapshot>,
}

/// Committed toplevel state — updated on `ext_foreign_toplevel_handle_v1::Done`
/// and `zcosmic_toplevel_handle_v1::State`.
struct CosmicToplevelSnapshot {
    app_id: String,
    title: String,
    activated: bool,
}

impl CosmicBackend {
    pub(crate) fn connect() -> core_types::Result<Self> {
        use wayland_client::{Connection, globals::registry_queue_init};
        use wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::ExtForeignToplevelListV1;
        use cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1;

        let conn = Connection::connect_to_env()
            .map_err(|e| core_types::Error::Platform(format!("Wayland connection failed: {e}")))?;

        let (globals, mut event_queue) = registry_queue_init::<CosmicDispatchState>(&conn)
            .map_err(|e| {
                core_types::Error::Platform(format!("Wayland registry init failed: {e}"))
            })?;

        let qh = event_queue.handle();

        // Bind protocol objects ONCE. These live for the connection lifetime.
        let _list: ExtForeignToplevelListV1 = globals.bind(&qh, 1..=1, ()).map_err(|e| {
            core_types::Error::Platform(format!("ext_foreign_toplevel_list bind: {e}"))
        })?;
        let _info: ZcosmicToplevelInfoV1 = globals
            .bind(&qh, 2..=3, ())
            .map_err(|e| core_types::Error::Platform(format!("zcosmic_toplevel_info bind: {e}")))?;

        let shared_state = Arc::new(Mutex::new(CosmicState {
            toplevels: HashMap::new(),
        }));

        let mut dispatch_state = CosmicDispatchState {
            pending: HashMap::new(),
            cosmic_pending: HashMap::new(),
            shared: Arc::clone(&shared_state),
            info: None,
            qh: None,
        };

        // Store the info proxy and queue handle in dispatch state so the
        // toplevel list handler can call info.get_cosmic_toplevel() when
        // new toplevels arrive.
        //
        // Safety: the QueueHandle is cloneable and the info proxy is Send+Sync
        // in wayland-client 0.31. Both are stored before the queue is moved
        // to the dispatch thread.
        dispatch_state.info = Some(_info);
        dispatch_state.qh = Some(qh.clone());

        // Initial roundtrip to receive existing toplevels.
        event_queue
            .roundtrip(&mut dispatch_state)
            .map_err(|e| core_types::Error::Platform(format!("Wayland roundtrip failed: {e}")))?;

        // Spawn dedicated dispatch thread for continuous event processing.
        let dispatch_conn = conn.clone();
        std::thread::Builder::new()
            .name("cosmic-dispatch".into())
            .spawn(move || {
                cosmic_dispatch_loop(dispatch_conn, event_queue, dispatch_state);
            })
            .map_err(|e| {
                core_types::Error::Platform(format!("failed to spawn cosmic dispatch thread: {e}"))
            })?;

        Ok(Self {
            state: shared_state,
            _conn: conn,
        })
    }

    /// Activate a window using a disposable connection.
    ///
    /// cosmic-comp panics when protocol objects are destroyed while activation
    /// is in flight, so we use a separate connection that is dropped (leaked)
    /// after the operation. This isolates the shared dispatch connection.
    fn activate(&self, target_id: &WindowId) -> core_types::Result<()> {
        use wayland_client::{Connection, globals::registry_queue_init};
        use wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::ExtForeignToplevelListV1;
        use cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1;
        use cosmic_client_toolkit::cosmic_protocols::toplevel_management::v1::client::zcosmic_toplevel_manager_v1::ZcosmicToplevelManagerV1;

        let activate_conn = Connection::connect_to_env().map_err(|e| {
            core_types::Error::Platform(format!("Wayland activation connection failed: {e}"))
        })?;

        let (globals, mut event_queue) = registry_queue_init::<CosmicEnumState>(&activate_conn)
            .map_err(|e| {
                let proto_err = activate_conn.protocol_error();
                core_types::Error::Platform(format!(
                    "registry init failed: {e} (protocol_error: {proto_err:?})"
                ))
            })?;
        let qh = event_queue.handle();

        let _list: ExtForeignToplevelListV1 = globals.bind(&qh, 1..=1, ()).map_err(|e| {
            core_types::Error::Platform(format!("ext_foreign_toplevel_list bind: {e}"))
        })?;
        let info: ZcosmicToplevelInfoV1 = globals
            .bind(&qh, 2..=3, ())
            .map_err(|e| core_types::Error::Platform(format!("zcosmic_toplevel_info bind: {e}")))?;
        let manager: ZcosmicToplevelManagerV1 = globals.bind(&qh, 1..=4, ()).map_err(|e| {
            core_types::Error::Platform(format!("zcosmic_toplevel_manager bind: {e}"))
        })?;
        let seat: wayland_client::protocol::wl_seat::WlSeat = globals
            .bind(&qh, 1..=9, ())
            .map_err(|e| core_types::Error::Platform(format!("wl_seat bind: {e}")))?;

        let mut state = CosmicEnumState {
            pending: HashMap::new(),
            cosmic_pending: HashMap::new(),
            toplevels: Vec::new(),
        };

        cosmic_roundtrip(&activate_conn, &mut event_queue, &mut state)?;

        let target_handle = state
            .toplevels
            .iter()
            .find(|(_handle, pending)| {
                let identifier = pending.identifier.as_deref().unwrap_or("");
                let wid = WindowId::from_uuid(uuid::Uuid::new_v5(
                    &COSMIC_WINDOW_NAMESPACE,
                    identifier.as_bytes(),
                ));
                wid == *target_id
            })
            .map(|(handle, _)| handle.clone());

        let target_handle = target_handle
            .ok_or_else(|| core_types::Error::Platform(format!("window {target_id} not found")))?;

        let cosmic_handle = info.get_cosmic_toplevel(&target_handle, &qh, ());

        cosmic_roundtrip(&activate_conn, &mut event_queue, &mut state)?;

        manager.activate(&cosmic_handle, &seat);

        cosmic_roundtrip(&activate_conn, &mut event_queue, &mut state)?;

        tracing::info!(window_id = %target_id, "cosmic: window activated");

        // DO NOT destroy protocol objects — cosmic-comp panics.
        // The disposable connection is dropped, isolating the shared connection.
        let _ = activate_conn.flush();

        Ok(())
    }

    /// Close a window using a disposable connection.
    fn close(&self, target_id: &WindowId) -> core_types::Result<()> {
        use wayland_client::{Connection, globals::registry_queue_init};
        use wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::ExtForeignToplevelListV1;
        use cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1;
        use cosmic_client_toolkit::cosmic_protocols::toplevel_management::v1::client::zcosmic_toplevel_manager_v1::ZcosmicToplevelManagerV1;

        let close_conn = Connection::connect_to_env().map_err(|e| {
            core_types::Error::Platform(format!("Wayland close connection failed: {e}"))
        })?;

        let (globals, mut event_queue) = registry_queue_init::<CosmicEnumState>(&close_conn)
            .map_err(|e| {
                let proto_err = close_conn.protocol_error();
                core_types::Error::Platform(format!(
                    "registry init failed: {e} (protocol_error: {proto_err:?})"
                ))
            })?;
        let qh = event_queue.handle();

        let _list: ExtForeignToplevelListV1 = globals.bind(&qh, 1..=1, ()).map_err(|e| {
            core_types::Error::Platform(format!("ext_foreign_toplevel_list bind: {e}"))
        })?;
        let info: ZcosmicToplevelInfoV1 = globals
            .bind(&qh, 2..=3, ())
            .map_err(|e| core_types::Error::Platform(format!("zcosmic_toplevel_info bind: {e}")))?;
        let manager: ZcosmicToplevelManagerV1 = globals.bind(&qh, 1..=4, ()).map_err(|e| {
            core_types::Error::Platform(format!("zcosmic_toplevel_manager bind: {e}"))
        })?;

        let mut state = CosmicEnumState {
            pending: HashMap::new(),
            cosmic_pending: HashMap::new(),
            toplevels: Vec::new(),
        };

        cosmic_roundtrip(&close_conn, &mut event_queue, &mut state)?;

        let target_handle = state
            .toplevels
            .iter()
            .find(|(_handle, pending)| {
                let identifier = pending.identifier.as_deref().unwrap_or("");
                let wid = WindowId::from_uuid(uuid::Uuid::new_v5(
                    &COSMIC_WINDOW_NAMESPACE,
                    identifier.as_bytes(),
                ));
                wid == *target_id
            })
            .map(|(handle, _)| handle.clone());

        let target_handle = target_handle
            .ok_or_else(|| core_types::Error::Platform(format!("window {target_id} not found")))?;

        let cosmic_handle = info.get_cosmic_toplevel(&target_handle, &qh, ());

        cosmic_roundtrip(&close_conn, &mut event_queue, &mut state)?;

        manager.close(&cosmic_handle);

        cosmic_roundtrip(&close_conn, &mut event_queue, &mut state)?;

        tracing::info!(window_id = %target_id, "cosmic: window closed");

        let _ = close_conn.flush();
        Ok(())
    }
}

impl CompositorBackend for CosmicBackend {
    fn list_windows(&self) -> BoxFuture<'_, core_types::Result<Vec<Window>>> {
        Box::pin(async move {
            let state = self
                .state
                .lock()
                .map_err(|e| core_types::Error::Platform(format!("lock poisoned: {e}")))?;
            let mut windows: Vec<Window> = state
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
            // MRU reorder: focused window to end.
            if let Some(idx) = windows.iter().position(|w| w.is_focused) {
                let focused = windows.remove(idx);
                windows.push(focused);
            }
            Ok(windows)
        })
    }

    fn list_workspaces(&self) -> BoxFuture<'_, core_types::Result<Vec<Workspace>>> {
        Box::pin(async { Ok(vec![]) })
    }

    fn activate_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>> {
        let id = *id;
        Box::pin(async move { self.activate(&id) })
    }

    fn set_window_geometry(
        &self,
        _id: &WindowId,
        _geom: &Geometry,
    ) -> BoxFuture<'_, core_types::Result<()>> {
        Box::pin(async {
            Err(core_types::Error::Platform(
                "set_window_geometry not supported by cosmic protocol".into(),
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
                "move_to_workspace not yet implemented for cosmic".into(),
            ))
        })
    }

    fn focus_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>> {
        self.activate_window(id)
    }

    fn close_window(&self, id: &WindowId) -> BoxFuture<'_, core_types::Result<()>> {
        let id = *id;
        Box::pin(async move { self.close(&id) })
    }

    fn name(&self) -> &str {
        "cosmic"
    }
}

// ============================================================================
// Persistent dispatch thread (bind-once, dispatch-forever)
// ============================================================================

/// Pending toplevel data accumulated from ext_foreign_toplevel events before
/// the `Done` atomic commit point.
#[derive(Debug, Default)]
struct CosmicPendingToplevel {
    identifier: Option<String>,
    app_id: Option<String>,
    title: Option<String>,
    is_activated: bool,
    /// The cosmic handle proxy, set after `get_cosmic_toplevel` response.
    has_cosmic_state: bool,
}

/// Dispatch thread state — owns the working copy of toplevels and the
/// persistent protocol object references.
struct CosmicDispatchState {
    /// Pending toplevels keyed by ext_foreign_toplevel_handle protocol ID.
    pending: HashMap<u32, CosmicPendingToplevel>,
    /// Maps cosmic_handle protocol ID → foreign_handle protocol ID.
    cosmic_pending: HashMap<u32, u32>,
    /// Shared snapshot for API callers.
    shared: Arc<Mutex<CosmicState>>,
    /// Persistent zcosmic_toplevel_info_v1 proxy — bound once, reused for
    /// every `get_cosmic_toplevel` call on new toplevels.
    info: Option<cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1>,
    /// Queue handle for creating child objects via `get_cosmic_toplevel`.
    qh: Option<wayland_client::QueueHandle<CosmicDispatchState>>,
}

impl CosmicDispatchState {
    /// Publish the current pending state to the shared snapshot.
    fn publish(&self) {
        let mut shared = match self.shared.lock() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("cosmic shared state mutex poisoned: {e}");
                return;
            }
        };

        shared.toplevels.clear();
        for pending in self.pending.values() {
            let Some(identifier) = pending.identifier.as_deref() else {
                continue;
            };
            let Some(app_id) = pending.app_id.as_deref().filter(|s| !s.is_empty()) else {
                continue;
            };

            let window_id = WindowId::from_uuid(uuid::Uuid::new_v5(
                &COSMIC_WINDOW_NAMESPACE,
                identifier.as_bytes(),
            ));

            shared.toplevels.insert(
                window_id,
                CosmicToplevelSnapshot {
                    app_id: app_id.to_string(),
                    title: pending.title.clone().unwrap_or_default(),
                    activated: pending.is_activated,
                },
            );
        }
    }
}

/// Continuous Wayland event dispatch loop.
///
/// Mirrors the WLR backend's `wlr_dispatch_loop` — uses `prepare_read()` +
/// `poll()` for efficient blocking. Events are dispatched to
/// `CosmicDispatchState` which publishes snapshots to the shared state.
fn cosmic_dispatch_loop(
    conn: wayland_client::Connection,
    mut event_queue: wayland_client::EventQueue<CosmicDispatchState>,
    mut state: CosmicDispatchState,
) {
    use std::os::fd::AsFd;
    use std::os::unix::io::AsRawFd;

    let mut backoff = std::time::Duration::from_millis(100);
    let max_backoff = std::time::Duration::from_secs(30);

    loop {
        if let Some(guard) = conn.prepare_read() {
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
                        tracing::error!(error = %e, ?proto_err, backoff_ms = backoff.as_millis(), "cosmic dispatch: Wayland read failed, backing off");
                        std::thread::sleep(backoff);
                        backoff = (backoff * 2).min(max_backoff);
                        continue;
                    }
                }
            } else {
                drop(guard);
            }
        }

        if let Err(e) = event_queue.dispatch_pending(&mut state) {
            let proto_err = conn.protocol_error();
            tracing::error!(error = %e, ?proto_err, backoff_ms = backoff.as_millis(), "cosmic dispatch: dispatch_pending failed, backing off");
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(max_backoff);
            continue;
        }

        if let Err(e) = conn.flush() {
            let proto_err = conn.protocol_error();
            tracing::error!(error = %e, ?proto_err, backoff_ms = backoff.as_millis(), "cosmic dispatch: flush failed, backing off");
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(max_backoff);
            continue;
        }
    }
}

// ============================================================================
// Wayland dispatch impls for CosmicDispatchState (persistent dispatch thread)
// ============================================================================

impl
    wayland_client::Dispatch<
        wayland_client::protocol::wl_registry::WlRegistry,
        wayland_client::globals::GlobalListContents,
    > for CosmicDispatchState
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

impl wayland_client::Dispatch<wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::ExtForeignToplevelListV1, ()> for CosmicDispatchState {
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

            // Request cosmic state for this toplevel using the persistent info proxy.
            if let (Some(info), Some(qh)) = (&state.info, &state.qh) {
                let cosmic_handle = info.get_cosmic_toplevel(&toplevel, qh, ());
                let cosmic_id = wayland_client::Proxy::id(&cosmic_handle).protocol_id();
                state.cosmic_pending.insert(cosmic_id, id);
            }
        }
    }

    wayland_client::event_created_child!(CosmicDispatchState, wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::ExtForeignToplevelListV1, [
        wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::EVT_TOPLEVEL_OPCODE =>
            (wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_handle_v1::ExtForeignToplevelHandleV1, ())
    ]);
}

impl wayland_client::Dispatch<wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_handle_v1::ExtForeignToplevelHandleV1, ()> for CosmicDispatchState {
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
                if let Some(p) = state.pending.get_mut(&id) {
                    p.identifier = Some(identifier);
                }
            }
            ext_foreign_toplevel_handle_v1::Event::AppId { app_id } => {
                if let Some(p) = state.pending.get_mut(&id) {
                    p.app_id = Some(app_id);
                }
            }
            ext_foreign_toplevel_handle_v1::Event::Title { title } => {
                if let Some(p) = state.pending.get_mut(&id) {
                    p.title = Some(title);
                }
            }
            ext_foreign_toplevel_handle_v1::Event::Done => {
                // Atomic commit point for ext_foreign_toplevel.
                // Publish the snapshot.
                state.publish();
            }
            ext_foreign_toplevel_handle_v1::Event::Closed => {
                // Remove from pending and cosmic_pending, publish.
                state.pending.remove(&id);
                state.cosmic_pending.retain(|_, &mut foreign_id| foreign_id != id);
                state.publish();
                proxy.destroy();
            }
            _ => {}
        }
    }
}

impl wayland_client::Dispatch<cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1, ()> for CosmicDispatchState {
    fn event(
        _: &mut Self,
        _: &cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1,
        _: cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::Event,
        _: &(),
        _: &wayland_client::Connection,
        _: &wayland_client::QueueHandle<Self>,
    ) {
        // The info proxy's events (toplevel, done) are handled via the
        // ext_foreign_toplevel and cosmic_handle dispatch impls.
    }

    wayland_client::event_created_child!(CosmicDispatchState, cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1, [
        cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::EVT_TOPLEVEL_OPCODE =>
            (cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_handle_v1::ZcosmicToplevelHandleV1, ())
    ]);
}

impl wayland_client::Dispatch<cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_handle_v1::ZcosmicToplevelHandleV1, ()> for CosmicDispatchState {
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
            if state_bytes.len() % 4 != 0 {
                return;
            }
            let activated = state_bytes
                .chunks_exact(4)
                .any(|chunk| {
                    let val = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    val == cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_handle_v1::State::Activated as u32
                });
            if let Some(pending) = state.pending.get_mut(&foreign_id) {
                pending.is_activated = activated;
                pending.has_cosmic_state = true;
                state.publish();
            }
        }
    }
}

// ============================================================================
// Disposable enumeration state (for activate/close operations only)
// ============================================================================

/// Lightweight enumeration state used by activate() and close() on their
/// disposable connections. These connections are short-lived and leaked
/// intentionally to avoid crashing cosmic-comp.
struct CosmicEnumState {
    pending: HashMap<u32, CosmicEnumPending>,
    cosmic_pending: HashMap<u32, u32>,
    toplevels: Vec<(wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_handle_v1::ExtForeignToplevelHandleV1, CosmicEnumPending)>,
}

#[derive(Debug, Default)]
struct CosmicEnumPending {
    identifier: Option<String>,
    app_id: Option<String>,
    title: Option<String>,
    is_activated: bool,
}

impl
    wayland_client::Dispatch<
        wayland_client::protocol::wl_registry::WlRegistry,
        wayland_client::globals::GlobalListContents,
    > for CosmicEnumState
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
            state.pending.insert(id, CosmicEnumPending::default());
        }
    }

    wayland_client::event_created_child!(CosmicEnumState, wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::ExtForeignToplevelListV1, [
        wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::EVT_TOPLEVEL_OPCODE =>
            (wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_handle_v1::ExtForeignToplevelHandleV1, ())
    ]);
}

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

impl wayland_client::Dispatch<cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1, ()> for CosmicEnumState {
    fn event(_: &mut Self, _: &cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1, _: cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::Event, _: &(), _: &wayland_client::Connection, _: &wayland_client::QueueHandle<Self>) {}

    wayland_client::event_created_child!(CosmicEnumState, cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1, [
        cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::EVT_TOPLEVEL_OPCODE =>
            (cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_handle_v1::ZcosmicToplevelHandleV1, ())
    ]);
}

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
                if val == cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_handle_v1::State::Activated as u32
                    && let Some((_h, p)) = state.toplevels.iter_mut().find(|(h, _)| h.id().protocol_id() == foreign_id)
                {
                    p.is_activated = true;
                }
            }
        }
    }
}

impl wayland_client::Dispatch<cosmic_client_toolkit::cosmic_protocols::toplevel_management::v1::client::zcosmic_toplevel_manager_v1::ZcosmicToplevelManagerV1, ()> for CosmicEnumState {
    fn event(_: &mut Self, _: &cosmic_client_toolkit::cosmic_protocols::toplevel_management::v1::client::zcosmic_toplevel_manager_v1::ZcosmicToplevelManagerV1, _: cosmic_client_toolkit::cosmic_protocols::toplevel_management::v1::client::zcosmic_toplevel_manager_v1::Event, _: &(), _: &wayland_client::Connection, _: &wayland_client::QueueHandle<Self>) {}
}

impl wayland_client::Dispatch<wayland_client::protocol::wl_seat::WlSeat, ()> for CosmicEnumState {
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

// ============================================================================
// Helpers
// ============================================================================

/// Wayland roundtrip — used by activate/close on disposable connections.
fn cosmic_roundtrip<D: 'static>(
    conn: &wayland_client::Connection,
    event_queue: &mut wayland_client::EventQueue<D>,
    state: &mut D,
) -> core_types::Result<()> {
    let fmt_err = |phase: &str, e: &dyn std::fmt::Display| -> core_types::Error {
        let proto_err = conn.protocol_error();
        core_types::Error::Platform(format!(
            "Wayland {phase}: {e} (protocol_error: {proto_err:?})"
        ))
    };

    conn.flush().map_err(|e| fmt_err("flush", &e))?;
    event_queue
        .dispatch_pending(state)
        .map_err(|e| fmt_err("dispatch_pending", &e))?;
    event_queue
        .roundtrip(state)
        .map_err(|e| fmt_err("roundtrip", &e))?;

    Ok(())
}
