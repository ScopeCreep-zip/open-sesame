//! Render context for passing state between render passes

use crate::config::Config;
use tiny_skia::Pixmap;

/// Context passed to each render pass
pub struct RenderContext<'a> {
    /// The pixmap being rendered to
    pub pixmap: &'a mut Pixmap,
    /// Display scale factor
    pub scale: f32,
    /// Configuration reference
    pub config: &'a Config,
}

impl<'a> RenderContext<'a> {
    /// Create a new render context
    pub fn new(pixmap: &'a mut Pixmap, scale: f32, config: &'a Config) -> Self {
        Self {
            pixmap,
            scale,
            config,
        }
    }

    /// Get the width in pixels
    pub fn width(&self) -> u32 {
        self.pixmap.width()
    }

    /// Get the height in pixels
    pub fn height(&self) -> u32 {
        self.pixmap.height()
    }

    /// Get scaled dimension
    pub fn scaled(&self, value: f32) -> f32 {
        value * self.scale
    }
}
