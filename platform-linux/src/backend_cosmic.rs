//! CompositorBackend implementation using COSMIC-native protocols.
//!
//! Uses three Wayland protocols:
//! - `ext_foreign_toplevel_list_v1`: window enumeration (toplevel handles)
//! - `zcosmic_toplevel_info_v1`: get cosmic handles with activation state
//! - `zcosmic_toplevel_manager_v1`: window activation via `manager.activate(handle, seat)`
//!
//! Window enumeration follows a 2-roundtrip pattern (enumerate -> get cosmic state).
//! Activation follows a 3-roundtrip pattern (enumerate -> get cosmic handle -> activate).
//!
//! Re-enumerates on each list_windows() call -- the ext_foreign_toplevel_list_v1
//! protocol doesn't provide continuous updates after the initial burst.

use crate::compositor::{BoxFuture, CompositorBackend, Workspace};
use core_types::{CompositorWorkspaceId, Geometry, Window, WindowId};

pub(crate) struct CosmicBackend {
    conn: wayland_client::Connection,
    /// Serializes all protocol operations (enumerate, activate) on the shared
    /// connection. Concurrent bind/destroy cycles on the same wl_display corrupt
    /// compositor state and can crash cosmic-comp.
    op_lock: std::sync::Mutex<()>,
}

impl CosmicBackend {
    pub(crate) fn connect() -> core_types::Result<Self> {
        use wayland_client::{Connection, globals::registry_queue_init};

        let conn = Connection::connect_to_env()
            .map_err(|e| core_types::Error::Platform(format!("Wayland connection failed: {e}")))?;

        // Probe for required protocols by checking the global list — do NOT bind
        // protocol objects here. Binding ExtForeignToplevelListV1 causes the compositor
        // to start sending Toplevel events; if the probe event queue is then dropped,
        // those objects become zombies and the compositor closes the connection when
        // the client fails to consume their events.
        let (globals, _event_queue) =
            registry_queue_init::<CosmicProbeState>(&conn).map_err(|e| {
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

        drop(globals);
        Ok(Self {
            conn,
            op_lock: std::sync::Mutex::new(()),
        })
    }

    /// Enumerate all windows using the 2-roundtrip COSMIC protocol flow.
    ///
    /// Roundtrip 1: receive ext_foreign_toplevel handles (identifier, app_id, title, Done).
    /// Then request zcosmic_toplevel_handle for each via info.get_cosmic_toplevel().
    /// Roundtrip 2: receive cosmic state events (activation detection via State::Activated).
    fn enumerate(&self) -> core_types::Result<Vec<Window>> {
        let _guard = self
            .op_lock
            .lock()
            .map_err(|e| core_types::Error::Platform(format!("op_lock poisoned: {e}")))?;

        use wayland_client::globals::registry_queue_init;
        use wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::ExtForeignToplevelListV1;
        use cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1;

        let (globals, mut event_queue) = registry_queue_init::<CosmicEnumState>(&self.conn)
            .map_err(|e| {
                let proto_err = self.conn.protocol_error();
                core_types::Error::Platform(format!(
                    "registry init failed: {e} (protocol_error: {proto_err:?})"
                ))
            })?;
        let qh = event_queue.handle();

        let list: ExtForeignToplevelListV1 = globals.bind(&qh, 1..=1, ()).map_err(|e| {
            core_types::Error::Platform(format!("ext_foreign_toplevel_list bind: {e}"))
        })?;
        let info: ZcosmicToplevelInfoV1 = globals
            .bind(&qh, 2..=3, ())
            .map_err(|e| core_types::Error::Platform(format!("zcosmic_toplevel_info bind: {e}")))?;

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
        let mut windows: Vec<Window> = state
            .toplevels
            .iter()
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
                    workspace_id: CompositorWorkspaceId::from_uuid(uuid::Uuid::nil()),
                    monitor_id: core_types::MonitorId::from_uuid(uuid::Uuid::nil()),
                    geometry: core_types::Geometry {
                        x: 0,
                        y: 0,
                        width: 0,
                        height: 0,
                    },
                    is_focused: pending.is_activated,
                    is_minimized: false,
                    is_fullscreen: false,
                    profile_id: core_types::ProfileId::from_uuid(uuid::Uuid::nil()),
                })
            })
            .collect();

        // MRU reorder: focused window to end (index 0 = previous, for Alt+Tab).
        if let Some(idx) = windows.iter().position(|w| w.is_focused) {
            let focused = windows.remove(idx);
            windows.push(focused);
        }

        // Protocol cleanup: destroy all objects before dropping EventQueue.
        // Per ext-foreign-toplevel-list-v1.xml: stop -> wait finished -> destroy handles -> destroy list.
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
        let _guard = self
            .op_lock
            .lock()
            .map_err(|e| core_types::Error::Platform(format!("op_lock poisoned: {e}")))?;

        use wayland_client::{Connection, globals::registry_queue_init};
        use wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_list_v1::ExtForeignToplevelListV1;
        use cosmic_client_toolkit::cosmic_protocols::toplevel_info::v1::client::zcosmic_toplevel_info_v1::ZcosmicToplevelInfoV1;
        use cosmic_client_toolkit::cosmic_protocols::toplevel_management::v1::client::zcosmic_toplevel_manager_v1::ZcosmicToplevelManagerV1;

        // Use a SEPARATE Wayland connection for activation. cosmic-comp panics
        // when we destroy protocol objects while activation is in flight, so we
        // intentionally leak them. When the EventQueue drops with leaked objects,
        // it causes a broken pipe on its connection. Using a disposable connection
        // here isolates the shared `self.conn` (used by enumerate/polling) from
        // this breakage.
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

        // Binding the list triggers toplevel enumeration; we don't call methods on it
        // directly (cleanup was removed to avoid crashing cosmic-comp), but the bind
        // itself is required for the compositor to send toplevel events.
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
            pending: std::collections::HashMap::new(),
            cosmic_pending: std::collections::HashMap::new(),
            toplevels: Vec::new(),
        };

        // Roundtrip 1: enumerate toplevels.
        cosmic_roundtrip(&activate_conn, &mut event_queue, &mut state)?;

        // Find target window by deterministic UUID mapping.
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

        // Request cosmic handle for the target.
        let cosmic_handle = info.get_cosmic_toplevel(&target_handle, &qh, ());

        // Roundtrip 2: receive cosmic handle.
        cosmic_roundtrip(&activate_conn, &mut event_queue, &mut state)?;

        // Activate.
        manager.activate(&cosmic_handle, &seat);

        // Roundtrip 3: ensure activation is processed.
        cosmic_roundtrip(&activate_conn, &mut event_queue, &mut state)?;

        tracing::info!(window_id = %target_id, "cosmic: window activated");

        // DO NOT destroy protocol objects here. cosmic-comp panics
        // (toplevel_management.rs:267 unreachable!()) when we destroy the
        // cosmic_handle or manager while an activation is in flight. The
        // panic kills the entire COSMIC desktop session.
        //
        // The leaked objects cause a broken pipe when EventQueue drops, but
        // this only affects `activate_conn` (disposable). The shared `self.conn`
        // used by enumerate/polling remains healthy.
        let _ = activate_conn.flush();

        Ok(())
    }

    /// Close a window using the COSMIC protocol.
    ///
    /// Uses the same disposable-connection pattern as `activate()` to avoid
    /// crashing cosmic-comp when protocol objects are destroyed in flight.
    fn close(&self, target_id: &WindowId) -> core_types::Result<()> {
        let _guard = self
            .op_lock
            .lock()
            .map_err(|e| core_types::Error::Platform(format!("op_lock poisoned: {e}")))?;

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
            pending: std::collections::HashMap::new(),
            cosmic_pending: std::collections::HashMap::new(),
            toplevels: Vec::new(),
        };

        // Roundtrip 1: enumerate toplevels.
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

        // Roundtrip 2: receive cosmic handle.
        cosmic_roundtrip(&close_conn, &mut event_queue, &mut state)?;

        manager.close(&cosmic_handle);

        // Roundtrip 3: ensure close is processed.
        cosmic_roundtrip(&close_conn, &mut event_queue, &mut state)?;

        tracing::info!(window_id = %target_id, "cosmic: window closed");

        let _ = close_conn.flush();
        Ok(())
    }
}

/// UUID v5 namespace for deterministic WindowId derivation from COSMIC protocol identifiers.
const COSMIC_WINDOW_NAMESPACE: uuid::Uuid = uuid::Uuid::from_bytes([
    0x6f, 0x70, 0x65, 0x6e, 0x2d, 0x73, 0x65, 0x73, 0x61, 0x6d, 0x65, 0x2d, 0x77, 0x69, 0x6e, 0x64,
]); // "open-sesame-wind" as bytes

/// Wayland roundtrip using `event_queue.roundtrip()`.
///
/// Sends a `wl_display.sync` request, guaranteeing the compositor responds even
/// when there are zero protocol objects to enumerate. This is a blocking call —
/// callers that need timeout protection should run on a dedicated thread.
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

    // Flush any pending outbound requests so the compositor sees them.
    conn.flush().map_err(|e| fmt_err("flush", &e))?;

    // Dispatch any events already buffered in the client-side queue.
    event_queue
        .dispatch_pending(state)
        .map_err(|e| fmt_err("dispatch_pending", &e))?;

    // Standard roundtrip: sends wl_display.sync, flushes, then reads events
    // until the sync callback arrives. This guarantees completion even with
    // zero toplevels because the compositor always responds to sync.
    event_queue
        .roundtrip(state)
        .map_err(|e| fmt_err("roundtrip", &e))?;

    Ok(())
}

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

// -- Dispatch state types for CosmicBackend --

/// Minimal probe state used during connect() to verify protocol availability.
struct CosmicProbeState;

impl
    wayland_client::Dispatch<
        wayland_client::protocol::wl_registry::WlRegistry,
        wayland_client::globals::GlobalListContents,
    > for CosmicProbeState
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

// -- Enumeration dispatch state --

/// Pending toplevel data collected from ext_foreign_toplevel events.
#[derive(Debug, Default)]
struct CosmicPendingToplevel {
    identifier: Option<String>,
    app_id: Option<String>,
    title: Option<String>,
    is_activated: bool,
}

/// State for COSMIC window enumeration and activation.
struct CosmicEnumState {
    pending: std::collections::HashMap<u32, CosmicPendingToplevel>,
    cosmic_pending: std::collections::HashMap<u32, u32>, // cosmic handle id -> foreign handle id
    toplevels: Vec<(wayland_protocols::ext::foreign_toplevel_list::v1::client::ext_foreign_toplevel_handle_v1::ExtForeignToplevelHandleV1, CosmicPendingToplevel)>,
}

// Dispatch impls for CosmicEnumState — mirrors v1's EnumerationState pattern.

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
            state.pending.insert(id, CosmicPendingToplevel::default());
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
