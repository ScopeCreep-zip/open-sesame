//! Frame rendering: draw the view, then attach, blur, and commit it.

use smithay_client_toolkit::{compositor::Region, shell::WaylandSurface};
use wayland_client::protocol::wl_shm;
use wayland_protocols::ext::background_effect::v1::client::ext_background_effect_manager_v1::Capability;

use super::app::{OverlayApp, View};
use crate::render::layout::Rect;
use crate::render::{self, Canvas, Picker, whole};

/// The text of the launch-in-progress toast.
const LAUNCHING: &str = "Launching\u{2026}";

impl OverlayApp {
    /// Draw the current view and present it: the buffer, and the blur
    /// region behind the card drawn, in one commit.
    pub fn render_frame(&mut self) {
        self.needs_redraw = false;
        let Some((width, height)) = self.physical_size() else {
            return;
        };
        let Some(mut canvas) = Canvas::new(
            width,
            height,
            self.output_scale,
            &mut self.font_system,
            &mut self.swash_cache,
            &self.theme,
        ) else {
            tracing::warn!(width, height, "surface size has no pixmap");
            return;
        };
        let card = match &self.view {
            View::Hidden | View::Border => None,
            View::Picker {
                windows,
                hints,
                input,
                selection,
                staged_launch,
            } => Some(canvas.picker(&Picker {
                windows,
                hints,
                input,
                selection: *selection,
                staged_launch: staged_launch.as_deref(),
                columns: self.columns,
            })),
            View::Launching => Some(canvas.message(LAUNCHING)),
            View::LaunchError(reason) => Some(canvas.message(&render::launch_error_text(reason))),
            View::UnlockPrompt {
                profile,
                password_len,
                error,
            } => Some(canvas.unlock_prompt(profile, *password_len, error.as_deref())),
            View::UnlockProgress(message) => Some(canvas.message(message)),
        };
        let mut pixels = canvas.into_pixels();
        render::convert_rgba_to_argb8888(&mut pixels);
        self.present(&pixels, width, height, card);
    }

    /// Attach `pixels` (ARGB8888, `width` x `height` buffer pixels), set
    /// the blur region behind `card`, and commit. The blur region is
    /// double-buffered state applied by this same commit
    /// (`ext_background_effect_surface_v1.set_blur_region`).
    fn present(&mut self, pixels: &[u8], width: u32, height: u32, card: Option<Rect>) {
        let (Ok(w), Ok(h), Some(Ok(stride))) = (
            i32::try_from(width),
            i32::try_from(height),
            width.checked_mul(4).map(i32::try_from),
        ) else {
            tracing::warn!(width, height, "surface too large for a buffer");
            return;
        };
        let Some(pool) = self.slot_pool.as_mut() else {
            return;
        };
        let buffer = match pool.create_buffer(w, h, stride, wl_shm::Format::Argb8888) {
            Ok((buffer, canvas)) if canvas.len() == pixels.len() => {
                canvas.copy_from_slice(pixels);
                buffer
            }
            Ok((_, canvas)) => {
                tracing::warn!(
                    buffer = canvas.len(),
                    frame = pixels.len(),
                    "buffer and frame sizes differ"
                );
                return;
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to create a shm buffer");
                return;
            }
        };
        let Some(surface) = &self.layer_surface else {
            return;
        };
        let wl_surface = surface.wl_surface();
        if let Err(e) = buffer.attach_to(wl_surface) {
            tracing::warn!(error = %e, "failed to attach the frame buffer");
            return;
        }
        wl_surface.set_buffer_scale(i32::from(self.output_scale));
        wl_surface.damage_buffer(0, 0, w, h);
        self.set_blur_region(card);
        wl_surface.commit();
    }

    /// Whether the compositor advertised the blur effect.
    pub(crate) fn blurs(&self) -> bool {
        self.background_effect
            .capabilities()
            .is_some_and(|caps| caps.contains(Capability::Blur))
    }

    /// Blur behind `card` (buffer pixels), or nothing; the region is in
    /// surface-local (logical) coordinates.
    fn set_blur_region(&self, card: Option<Rect>) {
        let Some(blur_surface) = &self.blur_surface else {
            return;
        };
        if !self.blurs() {
            return;
        }
        let Some(card) = card else {
            blur_surface.set_blur_region(None);
            return;
        };
        match Region::new(&self.compositor_state) {
            Ok(region) => {
                let logical = card.unscaled(f32::from(self.output_scale));
                region.add(
                    whole(logical.x),
                    whole(logical.y),
                    whole(logical.width),
                    whole(logical.height),
                );
                blur_surface.set_blur_region(Some(region.wl_region()));
            }
            Err(e) => tracing::warn!(error = %e, "failed to create the blur region"),
        }
    }
}
