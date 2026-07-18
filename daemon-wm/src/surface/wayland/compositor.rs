//! CompositorHandler, OutputHandler, ShmHandler, LayerShellHandler impls.

use smithay_client_toolkit::{
    compositor::CompositorHandler,
    delegate_compositor, delegate_layer, delegate_output, delegate_registry, delegate_shm,
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

impl CompositorHandler for OverlayApp {
    fn scale_factor_changed(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        surface: &wl_surface::WlSurface,
        new_factor: i32,
    ) {
        self.output_scale = new_factor as f32;
        self.scale_known = true;
        surface.set_buffer_scale(new_factor);

        let (lw, lh) = self.configured_size;
        if lw > 0 && lh > 0 {
            let phys_w = (lw as f32 * self.output_scale) as u32;
            let phys_h = (lh as f32 * self.output_scale) as u32;
            let buf_size = (phys_w * phys_h * 4) as usize;
            if self.slot_pool.is_none() {
                if let Ok(pool) = SlotPool::new(buf_size, &self.shm) {
                    self.slot_pool = Some(pool);
                }
            } else if let Some(ref mut pool) = self.slot_pool
                && let Err(e) = pool.resize(buf_size)
            {
                tracing::warn!("failed to resize slot pool on scale change: {e}");
            }
        }
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

    fn frame(&mut self, _: &Connection, qh: &QueueHandle<Self>, _: &wl_surface::WlSurface, _: u32) {
        if self.needs_redraw {
            self.render_frame(qh);
        }
    }

    fn surface_enter(
        &mut self,
        _: &Connection,
        _: &QueueHandle<Self>,
        surface: &wl_surface::WlSurface,
        output: &wl_output::WlOutput,
    ) {
        if let Some(info) = self.output_state.info(output) {
            let new_scale = info.scale_factor as f32;
            let scale_changed = (new_scale - self.output_scale).abs() > f32::EPSILON;
            if scale_changed || !self.scale_known {
                self.output_scale = new_scale;
                self.scale_known = true;
                surface.set_buffer_scale(info.scale_factor);

                let (lw, lh) = self.configured_size;
                if lw > 0 && lh > 0 {
                    let phys_w = (lw as f32 * new_scale) as u32;
                    let phys_h = (lh as f32 * new_scale) as u32;
                    let buf_size = (phys_w * phys_h * 4) as usize;
                    if self.slot_pool.is_none() {
                        if let Ok(pool) = SlotPool::new(buf_size, &self.shm) {
                            self.slot_pool = Some(pool);
                        }
                    } else if let Some(ref mut pool) = self.slot_pool
                        && let Err(e) = pool.resize(buf_size)
                    {
                        tracing::warn!("failed to resize slot pool on output enter: {e}");
                    }
                }
                if scale_changed {
                    self.needs_redraw = true;
                }
            }
        }
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
        self.hide_common();
        self.layer_surface = None;
        self.blur_surface = None;
        self.slot_pool = None;
        self.configured_size = (0, 0);
        self.recreate_layer_surface(qh);
    }

    fn configure(
        &mut self,
        _: &Connection,
        qh: &QueueHandle<Self>,
        _: &LayerSurface,
        configure: LayerSurfaceConfigure,
        _: u32,
    ) {
        let (width, height) = if configure.new_size.0 > 0 && configure.new_size.1 > 0 {
            (configure.new_size.0, configure.new_size.1)
        } else {
            (1920, 1080)
        };
        self.configured_size = (width, height);

        if self.scale_known || self.slot_pool.is_some() {
            let scale = self.output_scale;
            let phys_w = (width as f32 * scale) as u32;
            let phys_h = (height as f32 * scale) as u32;
            let buf_size = (phys_w * phys_h * 4) as usize;
            if self.slot_pool.is_none() {
                if let Ok(pool) = SlotPool::new(buf_size, &self.shm) {
                    self.slot_pool = Some(pool);
                }
            } else if let Some(ref mut pool) = self.slot_pool
                && let Err(e) = pool.resize(buf_size)
            {
                tracing::warn!("failed to resize slot pool: {e}");
            }
        }
        self.needs_redraw = true;
        self.render_frame(qh);
    }
}

impl ProvidesRegistryState for OverlayApp {
    fn registry(&mut self) -> &mut RegistryState {
        &mut self.registry_state
    }
    registry_handlers![OutputState, SeatState];
}

delegate_compositor!(OverlayApp);
delegate_output!(OverlayApp);
delegate_shm!(OverlayApp);
delegate_layer!(OverlayApp);
delegate_registry!(OverlayApp);
