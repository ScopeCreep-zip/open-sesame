//! `CompositorHandler`, `OutputHandler`, `ShmHandler`, `LayerShellHandler`,
//! and `BackgroundEffectHandler` impls, and the SCTK dispatch delegation.

use smithay_client_toolkit::{
    background_effect::{BackgroundEffectHandler, BackgroundEffectState},
    compositor::CompositorHandler,
    delegate_dispatch2, delegate_registry,
    output::{OutputHandler, OutputState},
    registry::{ProvidesRegistryState, RegistryState},
    registry_handlers,
    seat::SeatState,
    shell::wlr_layer::{LayerShellHandler, LayerSurface, LayerSurfaceConfigure},
    shm::{Shm, ShmHandler, slot::SlotPool},
};
use wayland_client::{
    Connection, QueueHandle,
    protocol::{wl_output, wl_surface},
};

use super::app::OverlayApp;

/// Bytes per ARGB8888 pixel.
const BYTES_PER_PIXEL: usize = 4;

impl OverlayApp {
    /// The buffer size of the configured surface at the output scale;
    /// `None` before the compositor has configured it.
    pub(crate) fn physical_size(&self) -> Option<(u32, u32)> {
        let (width, height) = self.configured_size;
        let scale = u32::from(self.output_scale);
        (width > 0 && height > 0)
            .then(|| (width.saturating_mul(scale), height.saturating_mul(scale)))
    }

    /// Size the shared-memory pool for one buffer of [`Self::physical_size`].
    fn resize_pool(&mut self) {
        let Some((width, height)) = self.physical_size() else {
            return;
        };
        let Some(len) = usize::try_from(width)
            .ok()
            .zip(usize::try_from(height).ok())
            .and_then(|(w, h)| w.checked_mul(h)?.checked_mul(BYTES_PER_PIXEL))
        else {
            tracing::warn!(width, height, "surface too large for a buffer");
            return;
        };
        if let Some(pool) = self.slot_pool.as_mut() {
            if let Err(e) = pool.resize(len) {
                tracing::warn!(error = %e, len, "failed to resize the buffer pool");
            }
        } else {
            match SlotPool::new(len, &self.shm) {
                Ok(pool) => self.slot_pool = Some(pool),
                Err(e) => tracing::warn!(error = %e, len, "failed to create the buffer pool"),
            }
        }
    }
}

impl CompositorHandler for OverlayApp {
    /// SCTK reports the largest scale of the surface's outputs (or the
    /// compositor's preferred buffer scale) whenever it changes.
    fn scale_factor_changed(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        surface: &wl_surface::WlSurface,
        new_factor: i32,
    ) {
        let Some(scale) = u8::try_from(new_factor).ok().filter(|&s| s > 0) else {
            tracing::warn!(new_factor, "ignoring an invalid output scale");
            return;
        };
        self.output_scale = scale;
        surface.set_buffer_scale(new_factor);
        self.resize_pool();
        self.needs_redraw = true;
    }

    fn transform_changed(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        _: wl_output::Transform,
    ) {
    }

    fn frame(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &wl_surface::WlSurface, _: u32) {
        if self.needs_redraw {
            self.render_frame();
        }
    }

    fn surface_enter(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        _: &wl_output::WlOutput,
    ) {
    }

    fn surface_leave(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &wl_surface::WlSurface,
        _: &wl_output::WlOutput,
    ) {
    }
}

impl OutputHandler for OverlayApp {
    fn output_state(&mut self) -> &mut OutputState {
        &mut self.output_state
    }
    fn new_output(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_output::WlOutput) {}
    fn update_output(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_output::WlOutput) {}
    fn output_destroyed(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_output::WlOutput) {}
}

impl ShmHandler for OverlayApp {
    fn shm_state(&mut self) -> &mut Shm {
        &mut self.shm
    }
}

impl LayerShellHandler for OverlayApp {
    fn closed(&mut self, _: &Connection, qh: &QueueHandle<Self>, _: &LayerSurface) {
        tracing::warn!("compositor closed layer surface, recreating");
        self.hide();
        self.layer_surface = None;
        self.blur_surface = None;
        self.slot_pool = None;
        self.configured_size = (0, 0);
        self.recreate_layer_surface(qh);
    }

    /// The overlay sets no size and is anchored to every edge, so the
    /// compositor assigns its size (`zwlr_layer_surface_v1.set_size`). A
    /// configure without one is a compositor fault: nothing is drawn rather
    /// than drawn at a guessed size.
    fn configure(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        _: &LayerSurface,
        configure: LayerSurfaceConfigure,
        _: u32,
    ) {
        let (width, height) = configure.new_size;
        if width == 0 || height == 0 {
            tracing::error!(
                width,
                height,
                "compositor configured the overlay without a size, though it is anchored to every edge; the overlay is not drawn"
            );
            self.configured_size = (0, 0);
            return;
        }
        self.configured_size = (width, height);
        self.resize_pool();
        self.needs_redraw = true;
        self.render_frame();
    }
}

impl BackgroundEffectHandler for OverlayApp {
    fn background_effect_state(&mut self) -> &mut BackgroundEffectState {
        &mut self.background_effect
    }

    /// The compositor advertised its effects; a visible card gets its blur
    /// region on the next frame.
    fn update_capabilities(&mut self) {
        let blur = self.blurs();
        tracing::info!(blur, "ext_background_effect_v1 capabilities received");
        self.needs_redraw = true;
    }
}

impl ProvidesRegistryState for OverlayApp {
    fn registry(&mut self) -> &mut RegistryState {
        &mut self.registry_state
    }
    registry_handlers![OutputState, SeatState];
}

delegate_registry!(OverlayApp);
// Every other object (compositor, output, shm, seat, keyboard, layer shell,
// background effect) dispatches through its SCTK user data.
delegate_dispatch2!(OverlayApp);
