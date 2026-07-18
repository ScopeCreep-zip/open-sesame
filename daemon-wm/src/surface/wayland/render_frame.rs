//! Frame rendering — pixmap creation, phase-based render dispatch, blur region,
//! and buffer attach/commit.

use smithay_client_toolkit::{compositor::Region, shell::WaylandSurface};
use wayland_client::QueueHandle;
use wayland_client::protocol::wl_shm;

use super::OverlayPhase;
use super::app::OverlayApp;
use crate::render::{self, HintRow};

impl OverlayApp {
    pub fn render_frame(&mut self, _qh: &QueueHandle<Self>) {
        self.needs_redraw = false;

        let (logical_w, logical_h) = self.configured_size;
        if logical_w == 0 || logical_h == 0 {
            return;
        }

        let scale = self.output_scale;
        let width = (logical_w as f32 * scale) as u32;
        let height = (logical_h as f32 * scale) as u32;
        let wf = width as f32;
        let hf = height as f32;

        // Compute blur region geometry BEFORE borrowing the pool.
        // Blur covers the card area only — set whenever the card is visible.
        // The card is the ONLY visual element; it must have consistent blur
        // from the moment it appears until dismissal.
        let blur_rect = if self.phase == OverlayPhase::Full
            || self.phase == OverlayPhase::Launching
            || self.phase == OverlayPhase::LaunchError
            || self.phase == OverlayPhase::UnlockPrompt
            || self.phase == OverlayPhase::UnlockProgress
        {
            // For Full, use the window-list card geometry.
            // For toasts/prompts, use a generous centered region.
            if self.phase == OverlayPhase::Full {
                let row_count = self.windows.len();
                Some(render::compute_card_rect(
                    row_count,
                    wf,
                    hf,
                    scale,
                    self.show_app_id,
                    self.show_title,
                ))
            } else {
                // Toast/prompt: blur a centered region roughly 500x200
                let cw = (wf * 0.5).min(500.0);
                let ch = 200.0;
                Some(((wf - cw) / 2.0, (hf - ch) / 2.0, cw, ch))
            }
        } else {
            None
        };

        let pool = match self.slot_pool.as_mut() {
            Some(p) => p,
            None => return,
        };

        let stride = width as i32 * 4;
        let (buffer, canvas) = match pool.create_buffer(
            width as i32,
            height as i32,
            stride,
            wl_shm::Format::Argb8888,
        ) {
            Ok((buf, canvas)) => (buf, canvas),
            Err(e) => {
                tracing::warn!("failed to create shm buffer: {e}");
                return;
            }
        };

        if let Some(mut pixmap) = tiny_skia::Pixmap::new(width, height) {
            match self.phase {
                OverlayPhase::Hidden => {
                    pixmap.fill(tiny_skia::Color::TRANSPARENT);
                }
                OverlayPhase::BorderOnly => {
                    render::draw_border_only(&mut pixmap, wf, hf, scale, &self.theme);
                }
                OverlayPhase::Full => {
                    let rows: Vec<HintRow<'_>> = self
                        .windows
                        .iter()
                        .zip(self.hints.iter())
                        .map(|(w, h)| HintRow {
                            hint: h.as_str(),
                            app_id: &w.app_id,
                            title: &w.title,
                        })
                        .collect();
                    render::draw_full_overlay(
                        &mut pixmap,
                        &mut self.font_system,
                        &mut self.swash_cache,
                        wf,
                        hf,
                        scale,
                        &rows,
                        &self.input_buffer,
                        self.selection,
                        &self.hints,
                        &self.theme,
                        self.show_app_id,
                        self.show_title,
                        self.staged_launch.as_deref(),
                    );
                }
                OverlayPhase::Launching => {
                    render::draw_status_toast(
                        &mut pixmap,
                        &mut self.font_system,
                        &mut self.swash_cache,
                        wf,
                        hf,
                        scale,
                        "Launching\u{2026}",
                        &self.theme,
                    );
                }
                OverlayPhase::LaunchError => {
                    render::draw_error_toast(
                        &mut pixmap,
                        &mut self.font_system,
                        &mut self.swash_cache,
                        wf,
                        hf,
                        scale,
                        &self.error_message,
                        &self.theme,
                    );
                }
                OverlayPhase::UnlockPrompt => {
                    let error = if self.error_message.is_empty() {
                        None
                    } else {
                        Some(self.error_message.as_str())
                    };
                    render::draw_unlock_prompt(
                        &mut pixmap,
                        &mut self.font_system,
                        &mut self.swash_cache,
                        wf,
                        hf,
                        scale,
                        &self.unlock_profile,
                        self.unlock_password_len,
                        error,
                        &self.theme,
                    );
                }
                OverlayPhase::UnlockProgress => {
                    render::draw_status_toast(
                        &mut pixmap,
                        &mut self.font_system,
                        &mut self.swash_cache,
                        wf,
                        hf,
                        scale,
                        &self.unlock_message,
                        &self.theme,
                    );
                }
            }

            let mut pixel_data = pixmap.take();
            render::convert_rgba_to_argb8888(&mut pixel_data);
            let len = canvas.len().min(pixel_data.len());
            canvas[..len].copy_from_slice(&pixel_data[..len]);
        } else {
            canvas.fill(0);
        }

        // Attach buffer and commit.
        if let Some(ref surface) = self.layer_surface {
            let wl_surface = surface.wl_surface();
            buffer
                .attach_to(wl_surface)
                .expect("failed to attach buffer");
            wl_surface.set_buffer_scale(scale.ceil() as i32);
            wl_surface.damage_buffer(0, 0, width as i32, height as i32);
            wl_surface.commit();
        }

        // Set blur region AFTER buffer commit (pool borrow is dropped).
        if let Some((cx, cy, cw, ch)) = blur_rect {
            self.set_blur_region(cx as i32, cy as i32, cw as i32, ch as i32);
        }
    }

    /// Set the blur region on the compositor to cover the card area.
    fn set_blur_region(&self, x: i32, y: i32, w: i32, h: i32) {
        let Some(ref blur_surface) = self.blur_surface else {
            return;
        };

        if let Ok(region) = Region::new(&self.compositor_state) {
            region.add(x, y, w, h);
            blur_surface.set_blur_region(Some(region.wl_region()));
        }
    }
}
