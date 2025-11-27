//! Text rendering utilities
//!
//! Uses fontconfig for font resolution, providing native integration with
//! the system's font configuration and COSMIC desktop preferences.

use crate::platform::fonts;
use fontdue::{Font, FontSettings};
use std::sync::OnceLock;
use tiny_skia::{Color, Pixmap, PremultipliedColorU8};

/// Font weight for text rendering
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FontWeight {
    /// Regular weight for body text
    #[default]
    Regular,
    /// Semibold/medium weight for emphasis
    Semibold,
}

/// Cached fonts for different weights
struct FontCache {
    regular: Font,
    semibold: Option<Font>,
}

/// Global font cache - initialized once via fontconfig
static FONTS: OnceLock<FontCache> = OnceLock::new();

/// Text renderer with cached font
pub struct TextRenderer;

impl TextRenderer {
    /// Get the font cache, loading fonts via fontconfig if necessary
    ///
    /// # Panics
    /// Panics if fontconfig cannot resolve any fonts. This is a fatal error
    /// that indicates the system is misconfigured (no fonts available).
    fn fonts() -> &'static FontCache {
        FONTS.get_or_init(|| {
            load_fonts_via_fontconfig().unwrap_or_else(|msg| {
                // Panics to allow proper unwinding and cleanup during font resolution failures.
                panic!(
                    "FATAL: {}\n\n\
                    Letter Launcher requires fontconfig to resolve system fonts.\n\
                    This should work automatically on any properly configured Linux system.\n\n\
                    Ensure fontconfig is installed and has fonts available:\n\
                    fc-match sans",
                    msg
                );
            })
        })
    }

    /// Get a font for the specified weight
    pub fn font(weight: FontWeight) -> &'static Font {
        let cache = Self::fonts();
        match weight {
            FontWeight::Semibold => cache.semibold.as_ref().unwrap_or(&cache.regular),
            FontWeight::Regular => &cache.regular,
        }
    }

    /// Render text to a pixmap at the given position
    pub fn render_text(pixmap: &mut Pixmap, text: &str, x: f32, y: f32, size: f32, color: Color) {
        Self::render_text_weighted(pixmap, text, x, y, size, color, FontWeight::Regular);
    }

    /// Render text with a specific font weight
    pub fn render_text_weighted(
        pixmap: &mut Pixmap,
        text: &str,
        x: f32,
        y: f32,
        size: f32,
        color: Color,
        weight: FontWeight,
    ) {
        let font = Self::font(weight);

        let mut cursor_x = x;
        let px_size = size;

        for c in text.chars() {
            let (metrics, bitmap) = font.rasterize(c, px_size);

            if !bitmap.is_empty() && metrics.width > 0 && metrics.height > 0 {
                let glyph_x = cursor_x as i32 + metrics.xmin;
                // Position glyph relative to baseline: top of glyph = baseline - (height + ymin)
                let glyph_y = y as i32 - metrics.height as i32 - metrics.ymin;

                Self::blend_glyph(
                    pixmap,
                    &bitmap,
                    metrics.width,
                    metrics.height,
                    glyph_x,
                    glyph_y,
                    color,
                    c,
                );
            }

            cursor_x += metrics.advance_width;
        }
    }

    /// Blend a glyph bitmap onto the pixmap
    ///
    /// Safely handles bitmap bounds validation to prevent panics on malformed glyph data.
    #[allow(clippy::too_many_arguments)] // All parameters are necessary for glyph rendering
    fn blend_glyph(
        pixmap: &mut Pixmap,
        bitmap: &[u8],
        width: usize,
        height: usize,
        x: i32,
        y: i32,
        color: Color,
        character: char,
    ) {
        // Validate bitmap dimensions match actual data length
        let expected_len = width.saturating_mul(height);
        if bitmap.len() < expected_len {
            tracing::warn!(
                "Malformed glyph bitmap for '{}' (U+{:04X}): expected {} bytes ({}x{}), got {}. Skipping glyph.",
                character,
                character as u32,
                expected_len,
                width,
                height,
                bitmap.len()
            );
            return;
        }

        let pixmap_width = pixmap.width() as i32;
        let pixmap_height = pixmap.height() as i32;
        let pixels = pixmap.pixels_mut();

        for row in 0..height {
            for col in 0..width {
                let px = x + col as i32;
                let py = y + row as i32;

                if px < 0 || py < 0 || px >= pixmap_width || py >= pixmap_height {
                    continue;
                }

                // SAFETY: We validated bitmap.len() >= width * height above
                let bitmap_idx = row * width + col;
                let alpha = bitmap[bitmap_idx];
                if alpha == 0 {
                    continue;
                }

                let idx = (py as usize) * (pixmap_width as usize) + (px as usize);
                // alpha is glyph coverage (0-255), color.alpha() is float (0.0-1.0)
                let src_alpha = (alpha as f32 * color.alpha()) as u8;

                if src_alpha == 0 {
                    continue;
                }

                let dst = pixels[idx];
                let blended = blend_pixel(dst, color, src_alpha);
                pixels[idx] = blended;
            }
        }
    }

    /// Measure the width of text
    pub fn measure_text(text: &str, size: f32) -> f32 {
        Self::measure_text_weighted(text, size, FontWeight::Regular)
    }

    /// Measure the width of text with a specific font weight
    pub fn measure_text_weighted(text: &str, size: f32, weight: FontWeight) -> f32 {
        let font = Self::font(weight);
        text.chars()
            .map(|c| font.metrics(c, size).advance_width)
            .sum()
    }

    /// Get the ascent (height above baseline) for a font size
    pub fn ascent(size: f32) -> f32 {
        let font = Self::font(FontWeight::Regular);
        let metrics = font.horizontal_line_metrics(size);
        metrics.map(|m| m.ascent).unwrap_or(size * 0.8)
    }

    /// Get the descent (depth below baseline) for a font size
    pub fn descent(size: f32) -> f32 {
        let font = Self::font(FontWeight::Regular);
        let metrics = font.horizontal_line_metrics(size);
        metrics.map(|m| m.descent.abs()).unwrap_or(size * 0.2)
    }

    /// Get the total line height for a font size
    pub fn line_height(size: f32) -> f32 {
        Self::ascent(size) + Self::descent(size)
    }

    /// Truncate text to fit within a maximum width
    pub fn truncate_to_width(text: &str, max_width: f32, size: f32) -> String {
        let font = Self::font(FontWeight::Regular);

        let ellipsis = "...";
        let ellipsis_width: f32 = ellipsis
            .chars()
            .map(|c| font.metrics(c, size).advance_width)
            .sum();

        if max_width <= ellipsis_width {
            return String::new();
        }

        let mut width = 0.0;
        let mut result = String::new();

        for c in text.chars() {
            let char_width = font.metrics(c, size).advance_width;
            if width + char_width + ellipsis_width > max_width {
                result.push_str(ellipsis);
                break;
            }
            width += char_width;
            result.push(c);
        }

        result
    }
}

/// Blend a source color onto a destination pixel using premultiplied alpha
///
/// Uses the standard Porter-Duff "over" operation for premultiplied alpha:
/// out = src + dst * (1 - src_alpha)
///
/// Operates directly in premultiplied space to preserve color accuracy at glyph edges.
fn blend_pixel(dst: PremultipliedColorU8, src_color: Color, src_alpha: u8) -> PremultipliedColorU8 {
    if src_alpha == 0 {
        return dst;
    }

    // Convert source to premultiplied alpha
    // src_color is straight alpha (0.0-1.0), src_alpha is coverage (0-255)
    let sa = src_alpha as u32;
    let sr = ((src_color.red() * 255.0) as u32 * sa / 255).min(255) as u8;
    let sg = ((src_color.green() * 255.0) as u32 * sa / 255).min(255) as u8;
    let sb = ((src_color.blue() * 255.0) as u32 * sa / 255).min(255) as u8;

    if src_alpha == 255 {
        // Fully opaque source pixel, no blending needed
        return PremultipliedColorU8::from_rgba(sr, sg, sb, 255).unwrap();
    }

    // Porter-Duff "over" in premultiplied space: out = src + dst * (1 - src_alpha)
    let inv_sa = 255 - sa;

    let out_r = (sr as u32 + dst.red() as u32 * inv_sa / 255).min(255) as u8;
    let out_g = (sg as u32 + dst.green() as u32 * inv_sa / 255).min(255) as u8;
    let out_b = (sb as u32 + dst.blue() as u32 * inv_sa / 255).min(255) as u8;
    let out_a = (sa + dst.alpha() as u32 * inv_sa / 255).min(255) as u8;

    PremultipliedColorU8::from_rgba(out_r, out_g, out_b, out_a).unwrap()
}

/// Load fonts using fontconfig for resolution
///
/// Uses the system's fontconfig to resolve "sans" to the appropriate font file.
/// This respects user font configuration and COSMIC desktop preferences.
fn load_fonts_via_fontconfig() -> Result<FontCache, String> {
    // Resolve sans font via fontconfig
    let resolved = fonts::resolve_sans()
        .ok_or_else(|| "fontconfig could not resolve 'sans' font".to_string())?;

    tracing::info!(
        "fontconfig resolved sans to: {} ({})",
        resolved.family,
        resolved.path.display()
    );

    // Load the regular font
    let regular_data = std::fs::read(&resolved.path).map_err(|e| {
        format!(
            "Failed to read font file {}: {}",
            resolved.path.display(),
            e
        )
    })?;

    let regular = Font::from_bytes(regular_data, FontSettings::default())
        .map_err(|e| format!("Failed to parse font {}: {:?}", resolved.path.display(), e))?;

    // Try to find a bold/semibold variant in order of preference
    const WEIGHT_PRIORITY: &[&str] = &["Bold", "SemiBold", "Semibold", "Medium"];

    let semibold = WEIGHT_PRIORITY
        .iter()
        .find_map(|&style| fonts::resolve_font_with_style(&resolved.family, style))
        .and_then(|resolved| {
            tracing::debug!(
                "Resolved semibold variant: {} ({})",
                resolved.family,
                resolved.path.display()
            );
            std::fs::read(&resolved.path)
                .ok()
                .and_then(|data| Font::from_bytes(data, FontSettings::default()).ok())
        });

    Ok(FontCache { regular, semibold })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_measurement() {
        let width = TextRenderer::measure_text("test", 14.0);
        assert!(width > 0.0, "Text should have positive width");
    }

    #[test]
    fn test_truncation() {
        let result = TextRenderer::truncate_to_width("Hello World", 1000.0, 14.0);
        assert!(result.len() <= "Hello World".len() + 3);
    }

    #[test]
    fn test_fontconfig_resolution() {
        let resolved = fonts::resolve_sans();
        assert!(resolved.is_some(), "fontconfig should resolve sans font");
    }
}
