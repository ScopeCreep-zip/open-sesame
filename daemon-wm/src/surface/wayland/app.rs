//! OverlayApp struct — all state for the SCTK overlay thread.

use crate::render::OverlayTheme;
use cosmic_text::{FontSystem, SwashCache};
use smithay_client_toolkit::{
    compositor::{CompositorState, Region},
    output::OutputState,
    registry::RegistryState,
    seat::SeatState,
    shell::{
        WaylandSurface,
        wlr_layer::{Anchor, KeyboardInteractivity, Layer, LayerShell, LayerSurface},
    },
    shm::{Shm, slot::SlotPool},
};
use wayland_client::QueueHandle;
use wayland_protocols::ext::background_effect::v1::client::ext_background_effect_surface_v1::ExtBackgroundEffectSurfaceV1;

use super::blur::BlurManager;
use super::{OverlayEvent, OverlayPhase, WindowInfo};

pub(crate) struct OverlayApp {
    // -- Wayland state --
    pub registry_state: RegistryState,
    pub compositor_state: CompositorState,
    pub output_state: OutputState,
    pub seat_state: SeatState,
    pub shm: Shm,
    pub layer_shell: LayerShell,

    // -- Surface --
    pub layer_surface: Option<LayerSurface>,
    pub slot_pool: Option<SlotPool>,
    pub configured_size: (u32, u32),

    // -- Blur protocol --
    pub blur_manager: Option<BlurManager>,
    pub blur_surface: Option<ExtBackgroundEffectSurfaceV1>,

    // -- Rendering --
    pub font_system: FontSystem,
    pub swash_cache: SwashCache,

    // -- Overlay state --
    pub phase: OverlayPhase,
    pub windows: Vec<WindowInfo>,
    pub hints: Vec<String>,
    pub input_buffer: String,
    pub selection: usize,
    pub theme: OverlayTheme,
    pub show_app_id: bool,
    pub show_title: bool,
    pub activated_at: Option<std::time::Instant>,
    pub received_key_event: bool,
    pub ipc_keyboard_active: bool,
    pub last_real_input_at: Option<std::time::Instant>,
    pub error_message: String,
    pub staged_launch: Option<String>,
    pub unlock_profile: String,
    pub unlock_password_len: usize,
    pub unlock_message: String,

    // -- Modifier tracking --
    pub alt_held: bool,
    pub modifier_released_sent: bool,

    // -- Communication --
    pub event_tx: tokio::sync::mpsc::Sender<OverlayEvent>,

    // -- Lifecycle --
    pub running: bool,
    pub needs_redraw: bool,
    pub pending_sync: bool,

    // -- HiDPI --
    pub output_scale: f32,
    pub scale_known: bool,

    // -- Input region --
    pub empty_input_region: Region,
}

impl OverlayApp {
    pub fn send_event(&self, event: OverlayEvent) {
        let _ = self.event_tx.blocking_send(event);
    }

    pub fn hide_common(&mut self) {
        self.phase = OverlayPhase::Hidden;
        self.pending_sync = false;
        self.input_buffer.clear();
        self.selection = 0;
        self.windows.clear();
        self.hints.clear();
        self.activated_at = None;
        self.received_key_event = false;
        self.ipc_keyboard_active = false;
        self.last_real_input_at = None;
        self.staged_launch = None;
        self.needs_redraw = true;
        self.set_keyboard_interactivity(KeyboardInteractivity::None);
        if let Some(ref surface) = self.layer_surface {
            surface
                .wl_surface()
                .set_input_region(Some(self.empty_input_region.wl_region()));
        }
        // Clear blur region when hiding.
        if let Some(ref blur_surface) = self.blur_surface {
            blur_surface.set_blur_region(None);
        }
    }

    pub fn recreate_layer_surface(&mut self, qh: &QueueHandle<Self>) {
        let surface = self.compositor_state.create_surface(qh);
        let layer_surface = self.layer_shell.create_layer_surface(
            qh,
            surface,
            Layer::Overlay,
            Some("sesame"),
            None,
        );
        layer_surface.set_anchor(Anchor::TOP | Anchor::BOTTOM | Anchor::LEFT | Anchor::RIGHT);
        layer_surface.set_exclusive_zone(-1);
        layer_surface.set_keyboard_interactivity(KeyboardInteractivity::None);
        layer_surface
            .wl_surface()
            .set_input_region(Some(self.empty_input_region.wl_region()));
        layer_surface.commit();

        // Destroy old blur surface, create new one for the new wl_surface.
        if let Some(old_blur) = self.blur_surface.take() {
            old_blur.destroy();
        }
        if let Some(ref blur_mgr) = self.blur_manager {
            self.blur_surface = Some(blur_mgr.get_blur_surface(layer_surface.wl_surface(), qh));
        }

        self.layer_surface = Some(layer_surface);
        tracing::info!("layer surface recreated");
    }

    pub fn set_keyboard_interactivity(&self, mode: KeyboardInteractivity) {
        if let Some(ref surface) = self.layer_surface {
            surface.set_keyboard_interactivity(mode);
            if mode == KeyboardInteractivity::Exclusive {
                surface.wl_surface().set_input_region(None);
            }
            surface.commit();
        }
    }
}
