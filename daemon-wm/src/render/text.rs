//! cosmic-text shaping, measurement, and glyph rasterization.

use super::Color;
use cosmic_text::{Attrs, Buffer, FontSystem, Metrics, Shaping, SwashCache};

/// Measure text dimensions without rendering.
pub fn measure_text(
    font_system: &mut FontSystem,
    text: &str,
    font_size: f32,
    attrs: Attrs<'_>,
    max_width: Option<f32>,
) -> (f32, f32) {
    let metrics = Metrics::new(font_size, font_size * 1.3);
    let mut buffer = Buffer::new(font_system, metrics);
    buffer.set_size(font_system, max_width, None);
    buffer.set_text(font_system, text, attrs, Shaping::Advanced);
    buffer.shape_until_scroll(font_system, false);

    let mut total_w: f32 = 0.0;
    let mut total_h: f32 = 0.0;
    for run in buffer.layout_runs() {
        total_w = total_w.max(run.line_w);
        total_h = run.line_y + metrics.line_height;
    }
    (total_w, total_h)
}

/// Render text onto a pixmap at the given position.
#[allow(clippy::too_many_arguments)]
pub fn draw_text(
    pixmap: &mut tiny_skia::Pixmap,
    font_system: &mut FontSystem,
    swash_cache: &mut SwashCache,
    x: f32,
    y: f32,
    text: &str,
    font_size: f32,
    attrs: Attrs<'_>,
    color: Color,
    max_width: Option<f32>,
) -> (f32, f32) {
    let metrics = Metrics::new(font_size, font_size * 1.3);
    let mut buffer = Buffer::new(font_system, metrics);
    buffer.set_size(font_system, max_width, None);
    buffer.set_text(font_system, text, attrs, Shaping::Advanced);
    buffer.shape_until_scroll(font_system, false);

    let text_color = color.to_cosmic_text();
    let pw = pixmap.width();
    let ph = pixmap.height();
    let data = pixmap.data_mut();

    let mut total_w: f32 = 0.0;
    let mut total_h: f32 = 0.0;

    buffer.draw(
        font_system,
        swash_cache,
        text_color,
        |gx, gy, _gw, _gh, gcolor| {
            let px = x as i32 + gx;
            let py = y as i32 + gy;
            if px < 0 || py < 0 {
                return;
            }
            let ux = px as u32;
            let uy = py as u32;
            if ux >= pw || uy >= ph {
                return;
            }
            let idx = ((uy * pw + ux) * 4) as usize;
            let src_a = gcolor.a() as f32 / 255.0;
            if src_a < f32::EPSILON {
                return;
            }
            let inv_a = 1.0 - src_a;
            let src_r = gcolor.r() as f32 * src_a;
            let src_g = gcolor.g() as f32 * src_a;
            let src_b = gcolor.b() as f32 * src_a;
            data[idx] = (src_r + data[idx] as f32 * inv_a).min(255.0) as u8;
            data[idx + 1] = (src_g + data[idx + 1] as f32 * inv_a).min(255.0) as u8;
            data[idx + 2] = (src_b + data[idx + 2] as f32 * inv_a).min(255.0) as u8;
            data[idx + 3] =
                ((src_a + data[idx + 3] as f32 / 255.0 * inv_a) * 255.0).min(255.0) as u8;
        },
    );

    for run in buffer.layout_runs() {
        total_w = total_w.max(run.line_w);
        total_h = run.line_y + metrics.line_height;
    }
    (total_w, total_h)
}

/// Truncate text with ellipsis to fit within `max_width`.
pub fn ellipsize_text(
    font_system: &mut FontSystem,
    text: &str,
    font_size: f32,
    attrs: Attrs<'_>,
    max_width: f32,
) -> String {
    let (full_w, _) = measure_text(font_system, text, font_size, attrs, None);
    if full_w <= max_width {
        return text.to_string();
    }

    let ellipsis = "\u{2026}";
    let (ew, _) = measure_text(font_system, ellipsis, font_size, attrs, None);
    let target = max_width - ew;
    if target <= 0.0 {
        return ellipsis.to_string();
    }

    let chars: Vec<char> = text.chars().collect();
    let (mut lo, mut hi) = (0_usize, chars.len());
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        let prefix: String = chars[..mid].iter().collect();
        let (pw, _) = measure_text(font_system, &prefix, font_size, attrs, None);
        if pw <= target {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }

    let prefix: String = chars[..lo].iter().collect();
    format!("{prefix}{ellipsis}")
}
