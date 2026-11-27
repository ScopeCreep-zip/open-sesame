//! `OverlayApp`: all state of the SCTK overlay thread.

use crate::render::{Columns, OverlayTheme};
use cosmic_text::{FontSystem, SwashCache};
use smithay_client_toolkit::{
    background_effect::BackgroundEffectState,
    compositor::{CompositorState, Region},
    error::GlobalError,
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

use super::poll::Activation;
use super::{OverlayEvent, WindowInfo};

/// What the overlay shows.
#[derive(Debug, Default)]
pub(crate) enum View {
    /// Nothing: the surface is unmapped from the user's view.
    #[default]
    Hidden,
    /// The armed overlay: an invisible surface holding keyboard
    /// exclusivity until the picker shows or the modifier is released.
    Border,
    /// The window picker.
    Picker {
        windows: Vec<WindowInfo>,
        hints: Vec<String>,
        input: String,
        selection: usize,
        staged_launch: Option<String>,
    },
    /// A launch in progress.
    Launching,
    /// A failed launch and its reason.
    LaunchError(String),
    /// The vault password prompt.
    UnlockPrompt {
        profile: String,
        password_len: usize,
        error: Option<String>,
    },
    /// Unlock progress; the message names the profile.
    UnlockProgress(String),
}

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
    /// The size the compositor configured, in logical pixels.
    pub configured_size: (u32, u32),
    /// The buffer scale of the outputs the surface is on (SCTK reports
    /// the largest through `scale_factor_changed`).
    pub output_scale: u8,
    /// An empty region: no input over a hidden or armed surface.
    pub empty_input_region: Region,

    // -- Blur protocol --
    /// `ext_background_effect_manager_v1`; holds no proxy on compositors
    /// without it.
    pub background_effect: BackgroundEffectState,
    /// The layer surface's effect object; `None` without the manager.
    pub blur_surface: Option<ExtBackgroundEffectSurfaceV1>,

    // -- Rendering --
    pub font_system: FontSystem,
    pub swash_cache: SwashCache,
    pub theme: OverlayTheme,
    pub columns: Columns,

    // -- Overlay state --
    pub view: View,
    pub activation: Activation,
    /// Whether the compositor reports Alt held on the overlay's keyboard.
    pub alt_held: bool,

    // -- Communication --
    pub event_tx: tokio::sync::mpsc::Sender<OverlayEvent>,

    // -- Lifecycle --
    pub running: bool,
    pub needs_redraw: bool,
}

impl OverlayApp {
    /// Send `event` to the daemon's event loop; once that loop is gone the
    /// overlay thread stops.
    pub fn send_event(&mut self, event: OverlayEvent) {
        if self.event_tx.blocking_send(event).is_err() {
            tracing::warn!("event loop gone, overlay thread stopping");
            self.running = false;
        }
    }

    /// Show `view`: redraw it and take the keyboard exclusively.
    pub fn show(&mut self, view: View) {
        self.view = view;
        self.needs_redraw = true;
        self.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
    }

    /// Hide the overlay: clear every view and activation, release the
    /// keyboard and input region, and remove the blur.
    pub fn hide(&mut self) {
        self.view = View::Hidden;
        self.activation = Activation::default();
        self.needs_redraw = true;
        self.set_keyboard_interactivity(KeyboardInteractivity::None);
        if let Some(surface) = &self.layer_surface {
            surface
                .wl_surface()
                .set_input_region(Some(self.empty_input_region.wl_region()));
        }
        if let Some(blur_surface) = &self.blur_surface {
            blur_surface.set_blur_region(None);
        }
    }

    /// Create the full-screen overlay layer surface and its blur object,
    /// replacing any previous one.
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

        if let Some(old_blur) = self.blur_surface.take() {
            old_blur.destroy();
        }
        self.blur_surface = match self
            .background_effect
            .get_background_effect(layer_surface.wl_surface(), qh)
        {
            Ok(blur_surface) => Some(blur_surface),
            // The compositor offers no background effects: no blur.
            Err(GlobalError::MissingGlobal(global)) => {
                tracing::debug!(
                    global,
                    "background effects not offered, the card is not blurred"
                );
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "background effect global unusable, the card is not blurred");
                None
            }
        };
        self.layer_surface = Some(layer_surface);
    }

    pub fn set_keyboard_interactivity(&self, mode: KeyboardInteractivity) {
        if let Some(surface) = &self.layer_surface {
            surface.set_keyboard_interactivity(mode);
            if mode == KeyboardInteractivity::Exclusive {
                surface.wl_surface().set_input_region(None);
            }
            surface.commit();
        }
    }
}
