//! `ext_background_effect_v1` client binding for COSMIC compositor blur.
//!
//! Derived from cosmic-panel's implementation in panel_space.rs and
//! ext_background_effect.rs. Binds the global manager, receives capability
//! events, and creates per-surface blur effect objects.

use smithay_client_toolkit::globals::GlobalData;
use wayland_client::globals::{BindError, GlobalList};
use wayland_client::protocol::wl_surface::WlSurface;
use wayland_client::{Connection, Dispatch, Proxy, QueueHandle, delegate_dispatch};
use wayland_protocols::ext::background_effect::v1::client::ext_background_effect_manager_v1::{
    Capability, Event, ExtBackgroundEffectManagerV1,
};
use wayland_protocols::ext::background_effect::v1::client::ext_background_effect_surface_v1::ExtBackgroundEffectSurfaceV1;

use super::app::OverlayApp;

/// Handler for the blur protocol manager global.
#[derive(Debug, Clone)]
pub struct BlurManager {
    pub manager: ExtBackgroundEffectManagerV1,
    pub capabilities: Capability,
}

impl BlurManager {
    /// Bind the blur manager global. Returns Err if compositor doesn't advertise it.
    pub(crate) fn new(
        globals: &GlobalList,
        qh: &QueueHandle<OverlayApp>,
    ) -> Result<Self, BindError> {
        let manager = globals.bind(qh, 1..=1, GlobalData)?;
        Ok(Self {
            manager,
            capabilities: Capability::empty(),
        })
    }

    /// Whether the compositor supports blur.
    pub fn supports_blur(&self) -> bool {
        self.capabilities.contains(Capability::Blur)
    }

    /// Create a blur effect object for a surface. User data is `()`.
    pub(crate) fn get_blur_surface(
        &self,
        surface: &WlSurface,
        qh: &QueueHandle<OverlayApp>,
    ) -> ExtBackgroundEffectSurfaceV1 {
        self.manager.get_background_effect(surface, qh, ())
    }
}

// Dispatch for the manager — receives Capabilities event.
impl Dispatch<ExtBackgroundEffectManagerV1, GlobalData, OverlayApp> for BlurManager {
    fn event(
        state: &mut OverlayApp,
        _proxy: &ExtBackgroundEffectManagerV1,
        event: <ExtBackgroundEffectManagerV1 as Proxy>::Event,
        _data: &GlobalData,
        _conn: &Connection,
        _qh: &QueueHandle<OverlayApp>,
    ) {
        if let Event::Capabilities {
            flags: wayland_client::WEnum::Value(cap),
        } = event
        {
            if let Some(ref mut blur) = state.blur_manager {
                blur.capabilities = cap;
            }
            if cap.contains(Capability::Blur) {
                tracing::info!("compositor supports ext_background_effect_v1 blur");
            }
        }
    }
}

// Dispatch for the per-surface object — no events defined.
impl Dispatch<ExtBackgroundEffectSurfaceV1, (), OverlayApp> for BlurManager {
    fn event(
        _state: &mut OverlayApp,
        _proxy: &ExtBackgroundEffectSurfaceV1,
        _event: <ExtBackgroundEffectSurfaceV1 as Proxy>::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<OverlayApp>,
    ) {
        // No events on this interface.
    }
}

delegate_dispatch!(OverlayApp: [ExtBackgroundEffectManagerV1: GlobalData] => BlurManager);
delegate_dispatch!(OverlayApp: [ExtBackgroundEffectSurfaceV1: ()] => BlurManager);
