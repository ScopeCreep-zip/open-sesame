//! Primitive rendering utilities

use tiny_skia::{
    Color as SkiaColor, FillRule, Paint, Path, PathBuilder, Pixmap, Stroke, Transform,
};

/// RGBA color representation
#[derive(Debug, Clone, Copy)]
pub struct Color {
    /// Red channel (0-255)
    pub r: u8,
    /// Green channel (0-255)
    pub g: u8,
    /// Blue channel (0-255)
    pub b: u8,
    /// Alpha channel (0-255, where 255 is fully opaque)
    pub a: u8,
}

impl Color {
    /// Create a new color from RGBA values
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Create a new color from RGB values (fully opaque)
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// Convert to tiny_skia Color
    pub fn to_skia(self) -> SkiaColor {
        SkiaColor::from_rgba8(self.r, self.g, self.b, self.a)
    }

    /// Create paint from this color
    pub fn to_paint(self) -> Paint<'static> {
        let mut paint = Paint::default();
        paint.set_color(self.to_skia());
        paint.anti_alias = true;
        paint
    }
}

/// Create a rounded rectangle path
pub fn rounded_rect(x: f32, y: f32, width: f32, height: f32, radius: f32) -> Option<Path> {
    let mut pb = PathBuilder::new();

    // Clamp radius to half the smaller dimension
    let r = radius.min(width / 2.0).min(height / 2.0);

    // Top-left corner
    pb.move_to(x + r, y);

    // Top edge and top-right corner
    pb.line_to(x + width - r, y);
    pb.quad_to(x + width, y, x + width, y + r);

    // Right edge and bottom-right corner
    pb.line_to(x + width, y + height - r);
    pb.quad_to(x + width, y + height, x + width - r, y + height);

    // Bottom edge and bottom-left corner
    pb.line_to(x + r, y + height);
    pb.quad_to(x, y + height, x, y + height - r);

    // Left edge and back to top-left corner
    pb.line_to(x, y + r);
    pb.quad_to(x, y, x + r, y);

    pb.close();
    pb.finish()
}

/// Fill a rounded rectangle
pub fn fill_rounded_rect(
    pixmap: &mut Pixmap,
    x: f32,
    y: f32,
    width: f32,
    height: f32,
    radius: f32,
    color: Color,
) {
    if let Some(path) = rounded_rect(x, y, width, height, radius) {
        let paint = color.to_paint();
        pixmap.fill_path(
            &path,
            &paint,
            FillRule::Winding,
            Transform::identity(),
            None,
        );
    }
}

/// Stroke a rounded rectangle
#[allow(clippy::too_many_arguments)]
pub fn stroke_rounded_rect(
    pixmap: &mut Pixmap,
    x: f32,
    y: f32,
    width: f32,
    height: f32,
    radius: f32,
    color: Color,
    stroke_width: f32,
) {
    if let Some(path) = rounded_rect(x, y, width, height, radius) {
        let paint = color.to_paint();
        let stroke = Stroke {
            width: stroke_width,
            ..Default::default()
        };
        pixmap.stroke_path(&path, &paint, &stroke, Transform::identity(), None);
    }
}

/// Fill the entire pixmap with a color
pub fn fill_background(pixmap: &mut Pixmap, color: Color) {
    pixmap.fill(color.to_skia());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_creation() {
        let c = Color::rgba(255, 128, 64, 200);
        assert_eq!(c.r, 255);
        assert_eq!(c.g, 128);
        assert_eq!(c.b, 64);
        assert_eq!(c.a, 200);
    }

    #[test]
    fn test_rounded_rect_creation() {
        let path = rounded_rect(10.0, 10.0, 100.0, 50.0, 8.0);
        assert!(path.is_some());
    }

    #[test]
    fn test_rounded_rect_clamped_radius() {
        // Validates clamping when radius exceeds half the minimum dimension
        let path = rounded_rect(0.0, 0.0, 100.0, 20.0, 50.0);
        assert!(path.is_some());
    }
}
