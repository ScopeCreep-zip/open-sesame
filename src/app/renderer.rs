//! Frame-callback-based Wayland renderer
//!
//! Handles all rendering lifecycle concerns:
//! - Frame callbacks for vsync
//! - Buffer management
//! - Damage tracking (future)

use crate::config::Config;
use crate::core::WindowHint;
use crate::ui::Overlay;
use smithay_client_toolkit::shm::{Shm, slot::SlotPool};
use std::sync::Arc;
use wayland_client::protocol::wl_shm;

/// Renderer state and configuration
pub struct Renderer {
    pool: Option<SlotPool>,
    width: u32,
    height: u32,
    scale: f32,
    needs_redraw: bool,
    frame_count: u32,
}

impl Renderer {
    /// Create a new renderer
    pub fn new() -> Self {
        Self {
            pool: None,
            width: 0,
            height: 0,
            scale: 1.0,
            needs_redraw: false,
            frame_count: 0,
        }
    }

    /// Update dimensions (call on configure)
    pub fn configure(&mut self, width: u32, height: u32) {
        if self.width != width || self.height != height {
            self.width = width;
            self.height = height;
            self.pool = None; // Reset pool for new size
            self.needs_redraw = true;
        }
    }

    /// Update scale factor
    pub fn set_scale(&mut self, scale: f32) {
        if (self.scale - scale).abs() > 0.001 {
            self.scale = scale;
            self.needs_redraw = true;
        }
    }

    /// Schedule a redraw
    pub fn schedule_redraw(&mut self) {
        self.needs_redraw = true;
    }

    /// Check if redraw is needed
    pub fn needs_redraw(&self) -> bool {
        self.needs_redraw
    }

    /// Render the current state
    ///
    /// Returns the buffer data if rendering succeeded, None otherwise.
    /// The caller is responsible for attaching and committing.
    pub fn render(
        &mut self,
        shm: &Shm,
        config: &Arc<Config>,
        hints: &[WindowHint],
        input: &str,
        selected_index: usize,
        show_full: bool,
    ) -> Option<RenderResult> {
        if self.width == 0 || self.height == 0 {
            return None;
        }

        // Initialize pool if needed
        if self.pool.is_none() {
            let size = (self.width * self.height * 4) as usize;
            match SlotPool::new(size, shm) {
                Ok(pool) => self.pool = Some(pool),
                Err(e) => {
                    tracing::error!("Failed to create buffer pool: {}", e);
                    return None;
                }
            }
        }

        let pool = self.pool.as_mut()?;

        // Create overlay and render
        let overlay = Overlay::new(self.width, self.height, self.scale, config);
        let pixmap = if show_full {
            overlay.render_full(hints, input, selected_index)?
        } else {
            overlay.render_initial()?
        };

        let stride = pixmap.width() as i32 * 4;

        let (buffer, canvas) = match pool.create_buffer(
            pixmap.width() as i32,
            pixmap.height() as i32,
            stride,
            wl_shm::Format::Argb8888,
        ) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Failed to create buffer: {}", e);
                return None;
            }
        };

        // Copy pixel data (RGBA -> ARGB)
        let src = pixmap.data();
        for (dst_pixel, src_chunk) in canvas.chunks_exact_mut(4).zip(src.chunks_exact(4)) {
            dst_pixel[0] = src_chunk[2]; // B
            dst_pixel[1] = src_chunk[1]; // G
            dst_pixel[2] = src_chunk[0]; // R
            dst_pixel[3] = src_chunk[3]; // A
        }

        self.needs_redraw = false;
        self.frame_count += 1;

        Some(RenderResult {
            buffer,
            width: pixmap.width() as i32,
            height: pixmap.height() as i32,
        })
    }
}

/// Result of a successful render
pub struct RenderResult {
    pub buffer: smithay_client_toolkit::shm::slot::Buffer,
    pub width: i32,
    pub height: i32,
}

impl Default for Renderer {
    fn default() -> Self {
        Self::new()
    }
}
