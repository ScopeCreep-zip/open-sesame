//! tiny-skia + cosmic-text rendering for the window switcher overlay.
//!
//! Renders the overlay UI into a pixel buffer using tiny-skia for 2D path
//! operations (rounded rectangles, fills, strokes) and cosmic-text for text
//! shaping, layout, and glyph rasterization. All dimensions are specified in
//! logical pixels; the caller handles HiDPI scaling via buffer size.

use cosmic_text::{Attrs, Buffer, Family, FontSystem, Metrics, Shaping, SwashCache, Weight};

// ---------------------------------------------------------------------------
// Layout constants — Material Design 4-point grid
// ---------------------------------------------------------------------------

const BASE_PADDING: f32 = 20.0;
const BASE_ROW_HEIGHT: f32 = 48.0;
const BASE_ROW_SPACING: f32 = 8.0;
const BASE_BADGE_WIDTH: f32 = 48.0;
const BASE_BADGE_HEIGHT: f32 = 32.0;
const BASE_BADGE_RADIUS: f32 = 8.0;
const BASE_APP_COLUMN_WIDTH: f32 = 180.0;
const BASE_TEXT_SIZE: f32 = 16.0;
const BASE_BORDER_WIDTH: f32 = 3.0;
const BASE_CORNER_RADIUS: f32 = 16.0;
const BASE_COLUMN_GAP: f32 = 16.0;

// ---------------------------------------------------------------------------
// Color
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct Color {
    pub r: f64,
    pub g: f64,
    pub b: f64,
    pub a: f64,
}

impl Color {
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self {
            r: r as f64 / 255.0,
            g: g as f64 / 255.0,
            b: b as f64 / 255.0,
            a: a as f64 / 255.0,
        }
    }

    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self::rgba(r, g, b, 255)
    }

    /// Parse a CSS hex color like "#89b4fa" or "#89b4facc" (with alpha).
    pub fn from_hex(hex: &str) -> Option<Self> {
        let hex = hex.strip_prefix('#').unwrap_or(hex);
        match hex.len() {
            6 => {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                Some(Self::rgba(r, g, b, 255))
            }
            8 => {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                let a = u8::from_str_radix(&hex[6..8], 16).ok()?;
                Some(Self::rgba(r, g, b, a))
            }
            _ => None,
        }
    }

    fn brightened(&self, amount: f64) -> Self {
        Self {
            r: (self.r + amount).min(1.0),
            g: (self.g + amount).min(1.0),
            b: (self.b + amount).min(1.0),
            a: self.a,
        }
    }

    fn to_tiny_skia(self) -> tiny_skia::Color {
        tiny_skia::Color::from_rgba(self.r as f32, self.g as f32, self.b as f32, self.a as f32)
            .unwrap_or(tiny_skia::Color::TRANSPARENT)
    }

    fn to_cosmic_text(self) -> cosmic_text::Color {
        cosmic_text::Color::rgba(
            (self.r * 255.0) as u8,
            (self.g * 255.0) as u8,
            (self.b * 255.0) as u8,
            (self.a * 255.0) as u8,
        )
    }
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OverlayTheme {
    pub background: Color,
    pub card_background: Color,
    pub card_border: Color,
    pub text_primary: Color,
    pub text_secondary: Color,
    pub badge_background: Color,
    pub badge_text: Color,
    pub badge_matched_background: Color,
    pub badge_matched_text: Color,
    pub selection_highlight: Color,
    pub border_color: Color,
    pub border_width: f64,
    pub corner_radius: f64,
}

impl Default for OverlayTheme {
    fn default() -> Self {
        Self {
            background: Color::rgba(0, 0, 0, 200),
            card_background: Color::rgba(30, 30, 30, 240),
            card_border: Color::rgba(80, 80, 80, 255),
            text_primary: Color::rgb(255, 255, 255),
            text_secondary: Color::rgba(255, 255, 255, 180),
            badge_background: Color::rgba(100, 100, 100, 255),
            badge_text: Color::rgb(255, 255, 255),
            badge_matched_background: Color::rgba(76, 175, 80, 255),
            badge_matched_text: Color::rgb(255, 255, 255),
            selection_highlight: Color::rgba(255, 255, 255, 25),
            border_color: Color::from_hex("#89b4fa").unwrap_or(Color::rgba(137, 180, 250, 255)),
            border_width: 3.0,
            corner_radius: BASE_CORNER_RADIUS as f64,
        }
    }
}

impl OverlayTheme {
    /// Build theme from WmConfig settings.
    ///
    /// Priority: COSMIC system theme -> user config overrides -> hardcoded defaults.
    pub fn from_config(cfg: &core_config::WmConfig) -> Self {
        let mut theme = Self::from_cosmic().unwrap_or_default();
        let defaults = core_config::WmConfig::default();

        if cfg.border_color != defaults.border_color
            && let Some(c) = Color::from_hex(&cfg.border_color)
        {
            theme.border_color = c;
            theme.card_border = c;
        }
        if (cfg.border_width - defaults.border_width).abs() > f32::EPSILON {
            theme.border_width = cfg.border_width as f64;
        }
        if cfg.background_color != defaults.background_color
            && let Some(c) = Color::from_hex(&cfg.background_color)
        {
            theme.background = c;
        }
        if cfg.card_color != defaults.card_color
            && let Some(c) = Color::from_hex(&cfg.card_color)
        {
            theme.card_background = c;
        }
        if cfg.text_color != defaults.text_color
            && let Some(c) = Color::from_hex(&cfg.text_color)
        {
            theme.text_primary = c;
            theme.badge_text = c;
            theme.badge_matched_text = c;
        }
        if cfg.hint_color != defaults.hint_color
            && let Some(c) = Color::from_hex(&cfg.hint_color)
        {
            theme.badge_background = c;
        }
        if cfg.hint_matched_color != defaults.hint_matched_color
            && let Some(c) = Color::from_hex(&cfg.hint_matched_color)
        {
            theme.badge_matched_background = c;
        }
        theme
    }

    /// Build theme from COSMIC desktop system theme.
    #[cfg(target_os = "linux")]
    fn from_cosmic() -> Option<Self> {
        let cosmic = platform_linux::cosmic_theme::CosmicTheme::load()?;

        let bg = cosmic.background.base.to_rgba();
        let primary_base = cosmic.primary.base.to_rgba();
        let primary_on = cosmic.primary.on.to_rgba();
        let badge_base = cosmic.secondary.component.base.to_rgba();
        let badge_on = cosmic.secondary.component.on.to_rgba();
        let accent_base = cosmic.accent.base.to_rgba();
        let accent_on = cosmic.accent.on.to_rgba();
        let corner_radius = cosmic.corner_radii.radius_m[0] as f64;

        Some(Self {
            background: Color::rgba(bg.0, bg.1, bg.2, 200),
            card_background: Color::rgba(primary_base.0, primary_base.1, primary_base.2, 245),
            card_border: Color::rgba(accent_base.0, accent_base.1, accent_base.2, 255),
            text_primary: Color::rgba(primary_on.0, primary_on.1, primary_on.2, primary_on.3),
            text_secondary: Color::rgba(
                primary_on.0,
                primary_on.1,
                primary_on.2,
                ((primary_on.3 as f64) * 0.7) as u8,
            ),
            badge_background: Color::rgba(badge_base.0, badge_base.1, badge_base.2, 255),
            badge_text: Color::rgba(badge_on.0, badge_on.1, badge_on.2, badge_on.3),
            badge_matched_background: Color::rgba(accent_base.0, accent_base.1, accent_base.2, 255),
            badge_matched_text: Color::rgba(accent_on.0, accent_on.1, accent_on.2, accent_on.3),
            selection_highlight: Color::rgba(255, 255, 255, 25),
            border_color: Color::rgba(accent_base.0, accent_base.1, accent_base.2, 255),
            border_width: 2.0,
            corner_radius,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn from_cosmic() -> Option<Self> {
        None
    }
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

struct Layout {
    padding: f32,
    row_height: f32,
    row_spacing: f32,
    badge_width: f32,
    badge_height: f32,
    badge_radius: f32,
    app_column_width: f32,
    text_size: f32,
    border_width: f32,
    corner_radius: f32,
    column_gap: f32,
}

impl Layout {
    fn new(scale: f32) -> Self {
        Self {
            padding: BASE_PADDING * scale,
            row_height: BASE_ROW_HEIGHT * scale,
            row_spacing: BASE_ROW_SPACING * scale,
            badge_width: BASE_BADGE_WIDTH * scale,
            badge_height: BASE_BADGE_HEIGHT * scale,
            badge_radius: BASE_BADGE_RADIUS * scale,
            app_column_width: BASE_APP_COLUMN_WIDTH * scale,
            text_size: BASE_TEXT_SIZE * scale,
            border_width: BASE_BORDER_WIDTH * scale,
            corner_radius: BASE_CORNER_RADIUS * scale,
            column_gap: BASE_COLUMN_GAP * scale,
        }
    }
}

// ---------------------------------------------------------------------------
// Window hint row data
// ---------------------------------------------------------------------------

/// A single window hint row for rendering.
pub struct HintRow<'a> {
    pub hint: &'a str,
    pub app_id: &'a str,
    pub title: &'a str,
}

// ---------------------------------------------------------------------------
// Card geometry
// ---------------------------------------------------------------------------

struct CardRect {
    x: f32,
    y: f32,
    width: f32,
    height: f32,
}

// ---------------------------------------------------------------------------
// tiny-skia rounded-rect path builder
// ---------------------------------------------------------------------------

fn rounded_rect_path(x: f32, y: f32, w: f32, h: f32, r: f32) -> Option<tiny_skia::Path> {
    let r = r.min(w / 2.0).min(h / 2.0);
    let mut pb = tiny_skia::PathBuilder::new();
    pb.move_to(x + r, y);
    pb.line_to(x + w - r, y);
    pb.quad_to(x + w, y, x + w, y + r);
    pb.line_to(x + w, y + h - r);
    pb.quad_to(x + w, y + h, x + w - r, y + h);
    pb.line_to(x + r, y + h);
    pb.quad_to(x, y + h, x, y + h - r);
    pb.line_to(x, y + r);
    pb.quad_to(x, y, x + r, y);
    pb.close();
    pb.finish()
}

fn fill_rounded_rect(
    pixmap: &mut tiny_skia::Pixmap,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    r: f32,
    color: Color,
) {
    let Some(path) = rounded_rect_path(x, y, w, h, r) else {
        return;
    };
    let mut paint = tiny_skia::Paint::default();
    paint.set_color(color.to_tiny_skia());
    paint.anti_alias = true;
    pixmap.fill_path(
        &path,
        &paint,
        tiny_skia::FillRule::Winding,
        tiny_skia::Transform::identity(),
        None,
    );
}

#[allow(clippy::too_many_arguments)]
fn stroke_rounded_rect(
    pixmap: &mut tiny_skia::Pixmap,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    r: f32,
    color: Color,
    stroke_width: f32,
) {
    let Some(path) = rounded_rect_path(x, y, w, h, r) else {
        return;
    };
    let mut paint = tiny_skia::Paint::default();
    paint.set_color(color.to_tiny_skia());
    paint.anti_alias = true;
    let stroke = tiny_skia::Stroke {
        width: stroke_width,
        line_cap: tiny_skia::LineCap::Round,
        line_join: tiny_skia::LineJoin::Round,
        ..Default::default()
    };
    pixmap.stroke_path(
        &path,
        &paint,
        &stroke,
        tiny_skia::Transform::identity(),
        None,
    );
}

// ---------------------------------------------------------------------------
// Text rendering helpers
// ---------------------------------------------------------------------------

/// Measure text dimensions without rendering.
fn measure_text(
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
fn draw_text(
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
fn ellipsize_text(
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

// ---------------------------------------------------------------------------
// Screen border helper
// ---------------------------------------------------------------------------

fn draw_screen_border(
    pixmap: &mut tiny_skia::Pixmap,
    width: f32,
    height: f32,
    color: Color,
    border_width: f32,
    corner_radius: f32,
) {
    let bw = border_width * 2.0;
    let half = bw / 2.0;
    stroke_rounded_rect(
        pixmap,
        half,
        half,
        width - bw,
        height - bw,
        corner_radius,
        color,
        bw,
    );
}

// ---------------------------------------------------------------------------
// Public draw entry points
// ---------------------------------------------------------------------------

/// Draw border-only phase: transparent center, colored stroke around screen edges.
pub fn draw_border_only(
    pixmap: &mut tiny_skia::Pixmap,
    width: f32,
    height: f32,
    scale: f32,
    theme: &OverlayTheme,
) {
    let layout = Layout::new(scale);
    pixmap.fill(tiny_skia::Color::TRANSPARENT);
    draw_screen_border(
        pixmap,
        width,
        height,
        theme.border_color,
        layout.border_width,
        layout.corner_radius,
    );
}

/// Draw the full overlay: border + centered card with hint rows.
#[allow(clippy::too_many_arguments)]
pub fn draw_full_overlay(
    pixmap: &mut tiny_skia::Pixmap,
    font_system: &mut FontSystem,
    swash_cache: &mut SwashCache,
    width: f32,
    height: f32,
    scale: f32,
    rows: &[HintRow<'_>],
    input: &str,
    selection: usize,
    hints: &[String],
    theme: &OverlayTheme,
    show_app_id: bool,
    show_title: bool,
    staged_launch: Option<&str>,
) {
    let layout = Layout::new(scale);

    pixmap.fill(tiny_skia::Color::TRANSPARENT);
    draw_screen_border(
        pixmap,
        width,
        height,
        theme.border_color,
        layout.border_width,
        layout.corner_radius,
    );

    // Filter visible rows by input matching.
    let visible: Vec<(usize, &HintRow<'_>)> = rows
        .iter()
        .enumerate()
        .filter(|(i, _)| {
            if input.is_empty() {
                return true;
            }
            if *i < hints.len() {
                let hint = &hints[*i];
                let norm = input.to_lowercase();
                hint.starts_with(&norm)
            } else {
                false
            }
        })
        .collect();

    if visible.is_empty() && !input.is_empty() {
        if let Some(command) = staged_launch {
            draw_launch_staged(
                pixmap,
                font_system,
                swash_cache,
                width,
                height,
                command,
                &layout,
                theme,
            );
        } else {
            draw_no_matches(
                pixmap,
                font_system,
                swash_cache,
                width,
                height,
                input,
                &layout,
                theme,
            );
        }
        return;
    }

    let selection = selection.min(visible.len().saturating_sub(1));
    let card = calculate_card(&visible, width, height, &layout, show_app_id, show_title);

    // Card background.
    fill_rounded_rect(
        pixmap,
        card.x,
        card.y,
        card.width,
        card.height,
        layout.corner_radius,
        theme.card_background,
    );
    stroke_rounded_rect(
        pixmap,
        card.x,
        card.y,
        card.width,
        card.height,
        layout.corner_radius,
        theme.card_border,
        layout.border_width,
    );

    // Hint rows.
    for (vi, &(orig_idx, row)) in visible.iter().enumerate() {
        let row_y = card.y + layout.padding + vi as f32 * (layout.row_height + layout.row_spacing);
        let is_selected = vi == selection;

        let match_state = if !input.is_empty() && orig_idx < hints.len() {
            let norm = input.to_lowercase();
            if hints[orig_idx] == norm {
                HintMatchState::Exact
            } else if hints[orig_idx].starts_with(&norm) {
                HintMatchState::Partial
            } else {
                HintMatchState::None
            }
        } else {
            HintMatchState::None
        };

        draw_hint_row(
            pixmap,
            font_system,
            swash_cache,
            &card,
            row_y,
            row,
            is_selected,
            match_state,
            &layout,
            theme,
            show_app_id,
            show_title,
        );
    }

    // Input indicator.
    if !input.is_empty() {
        draw_input_indicator(
            pixmap,
            font_system,
            swash_cache,
            &card,
            input,
            &layout,
            theme,
        );
    }
}

/// Draw a centered status message (e.g. "Launching...").
#[allow(clippy::too_many_arguments)]
pub fn draw_status_toast(
    pixmap: &mut tiny_skia::Pixmap,
    font_system: &mut FontSystem,
    swash_cache: &mut SwashCache,
    width: f32,
    height: f32,
    scale: f32,
    message: &str,
    theme: &OverlayTheme,
) {
    let layout = Layout::new(scale);
    pixmap.fill(tiny_skia::Color::TRANSPARENT);
    draw_screen_border(
        pixmap,
        width,
        height,
        theme.border_color,
        layout.border_width,
        layout.corner_radius,
    );

    let attrs = Attrs::new()
        .family(Family::SansSerif)
        .weight(Weight::NORMAL);
    let font_size = layout.text_size * 1.2;
    let (tw, th) = measure_text(font_system, message, font_size, attrs, None);

    let pad = layout.padding * 2.0;
    let cw = tw + pad * 2.0;
    let ch = th + pad * 2.0;
    let cx = (width - cw) / 2.0;
    let cy = (height - ch) / 2.0;

    fill_rounded_rect(
        pixmap,
        cx,
        cy,
        cw,
        ch,
        layout.corner_radius,
        theme.card_background,
    );
    stroke_rounded_rect(
        pixmap,
        cx,
        cy,
        cw,
        ch,
        layout.corner_radius,
        theme.card_border,
        layout.border_width,
    );

    draw_text(
        pixmap,
        font_system,
        swash_cache,
        cx + pad,
        cy + pad,
        message,
        font_size,
        attrs,
        theme.text_secondary,
        None,
    );
}

/// Draw a centered error message with red accent border.
#[allow(clippy::too_many_arguments)]
pub fn draw_error_toast(
    pixmap: &mut tiny_skia::Pixmap,
    font_system: &mut FontSystem,
    swash_cache: &mut SwashCache,
    width: f32,
    height: f32,
    scale: f32,
    message: &str,
    theme: &OverlayTheme,
) {
    let layout = Layout::new(scale);
    let error_border = Color::rgba(239, 68, 68, 255);

    pixmap.fill(tiny_skia::Color::TRANSPARENT);
    draw_screen_border(
        pixmap,
        width,
        height,
        error_border,
        layout.border_width,
        layout.corner_radius,
    );

    let display = format!("Launch failed\n\n{message}\n\nPress any key to dismiss");
    let attrs = Attrs::new().family(Family::SansSerif);
    let font_size = layout.text_size * 1.1;
    let max_width = (width * 0.6).min(500.0);
    let (tw, th) = measure_text(font_system, &display, font_size, attrs, Some(max_width));

    let pad = layout.padding * 2.0;
    let cw = tw + pad * 2.0;
    let ch = th + pad * 2.0;
    let cx = (width - cw) / 2.0;
    let cy = (height - ch) / 2.0;

    fill_rounded_rect(
        pixmap,
        cx,
        cy,
        cw,
        ch,
        layout.corner_radius,
        theme.card_background,
    );
    stroke_rounded_rect(
        pixmap,
        cx,
        cy,
        cw,
        ch,
        layout.corner_radius,
        error_border,
        layout.border_width * 1.5,
    );

    draw_text(
        pixmap,
        font_system,
        swash_cache,
        cx + pad,
        cy + pad,
        &display,
        font_size,
        attrs,
        theme.text_primary,
        Some(max_width),
    );
}

/// Draw a vault unlock password prompt with dot-masked field.
///
/// Defense in depth: this function receives only the CHARACTER COUNT
/// (`password_len`), never the actual password bytes.
#[allow(clippy::too_many_arguments)]
pub fn draw_unlock_prompt(
    pixmap: &mut tiny_skia::Pixmap,
    font_system: &mut FontSystem,
    swash_cache: &mut SwashCache,
    width: f32,
    height: f32,
    scale: f32,
    profile: &str,
    password_len: usize,
    error: Option<&str>,
    theme: &OverlayTheme,
) {
    let layout = Layout::new(scale);
    let unlock_border = Color::rgba(250, 204, 21, 255);

    pixmap.fill(tiny_skia::Color::TRANSPARENT);
    draw_screen_border(
        pixmap,
        width,
        height,
        unlock_border,
        layout.border_width,
        layout.corner_radius,
    );

    let mut display = format!("Unlock \u{201C}{profile}\u{201D}\n\n");
    if password_len > 0 {
        let dot_count = password_len.min(32);
        for i in 0..dot_count {
            display.push('\u{25CF}');
            if i < dot_count - 1 {
                display.push(' ');
            }
        }
    } else {
        display.push_str("Enter password");
    }
    if let Some(err) = error {
        display.push_str("\n\n");
        display.push_str(err);
    }

    let attrs = Attrs::new().family(Family::SansSerif);
    let font_size = layout.text_size * 1.2;
    let max_width = (width * 0.6).min(500.0);
    let (_tw, th) = measure_text(font_system, &display, font_size, attrs, Some(max_width));

    let pad = layout.padding * 2.0;
    let cw = max_width + pad * 2.0;
    let ch = th + pad * 2.0;
    let cx = (width - cw) / 2.0;
    let cy = (height - ch) / 2.0;

    fill_rounded_rect(
        pixmap,
        cx,
        cy,
        cw,
        ch,
        layout.corner_radius,
        theme.card_background,
    );
    stroke_rounded_rect(
        pixmap,
        cx,
        cy,
        cw,
        ch,
        layout.corner_radius,
        unlock_border,
        layout.border_width * 1.5,
    );

    draw_text(
        pixmap,
        font_system,
        swash_cache,
        cx + pad,
        cy + pad,
        &display,
        font_size,
        attrs,
        theme.text_primary,
        Some(max_width),
    );
}

// ---------------------------------------------------------------------------
// Internal draw helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HintMatchState {
    None,
    Partial,
    Exact,
}

fn calculate_card(
    visible: &[(usize, &HintRow<'_>)],
    screen_w: f32,
    screen_h: f32,
    layout: &Layout,
    show_app_id: bool,
    show_title: bool,
) -> CardRect {
    let min_title_width: f32 = 200.0;
    let mut content_width = layout.padding * 2.0 + layout.badge_width + layout.column_gap;
    if show_app_id {
        content_width += layout.app_column_width + layout.column_gap;
    }
    if show_title {
        content_width += min_title_width;
    }

    let max_width = (screen_w * 0.9).min(700.0);
    let card_width = content_width.max(400.0).min(max_width);

    let row_count = visible.len().max(1);
    let content_height =
        row_count as f32 * (layout.row_height + layout.row_spacing) - layout.row_spacing;
    let card_height = content_height + layout.padding * 2.0;

    CardRect {
        x: (screen_w - card_width) / 2.0,
        y: (screen_h - card_height) / 2.0,
        width: card_width,
        height: card_height,
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_hint_row(
    pixmap: &mut tiny_skia::Pixmap,
    font_system: &mut FontSystem,
    swash_cache: &mut SwashCache,
    card: &CardRect,
    row_y: f32,
    row: &HintRow<'_>,
    is_selected: bool,
    match_state: HintMatchState,
    layout: &Layout,
    theme: &OverlayTheme,
    show_app_id: bool,
    show_title: bool,
) {
    // Selection highlight.
    if is_selected {
        let hx = card.x + layout.padding / 2.0;
        let hw = card.width - layout.padding;
        fill_rounded_rect(
            pixmap,
            hx,
            row_y,
            hw,
            layout.row_height,
            layout.badge_radius,
            theme.selection_highlight,
        );
    }

    // Column positions.
    let badge_x = card.x + layout.padding;
    let mut next_x = badge_x + layout.badge_width + layout.column_gap;

    let badge_bg = match match_state {
        HintMatchState::Exact => theme.badge_matched_background,
        HintMatchState::Partial => theme.badge_background.brightened(0.12),
        HintMatchState::None => theme.badge_background,
    };
    let badge_text_color = match match_state {
        HintMatchState::Exact => theme.badge_matched_text,
        _ => theme.badge_text,
    };

    // Draw badge.
    let badge_y = row_y + (layout.row_height - layout.badge_height) / 2.0;
    fill_rounded_rect(
        pixmap,
        badge_x,
        badge_y,
        layout.badge_width,
        layout.badge_height,
        layout.badge_radius,
        badge_bg,
    );

    // Badge text (centered, uppercase, semibold).
    let hint_text = row.hint.to_uppercase();
    let badge_attrs = Attrs::new()
        .family(Family::SansSerif)
        .weight(Weight::SEMIBOLD);
    let (tw, _th) = measure_text(font_system, &hint_text, layout.text_size, badge_attrs, None);
    let tx = badge_x + (layout.badge_width - tw) / 2.0;
    let ty = badge_y + (layout.badge_height - layout.text_size) / 2.0;
    draw_text(
        pixmap,
        font_system,
        swash_cache,
        tx,
        ty,
        &hint_text,
        layout.text_size,
        badge_attrs,
        badge_text_color,
        None,
    );

    // App name column.
    if show_app_id {
        let app_name = extract_app_name(row.app_id);
        let attrs = Attrs::new()
            .family(Family::SansSerif)
            .weight(Weight::NORMAL);
        let truncated = ellipsize_text(
            font_system,
            &app_name,
            layout.text_size,
            attrs,
            layout.app_column_width,
        );
        let ty = row_y + (layout.row_height - layout.text_size) / 2.0;
        draw_text(
            pixmap,
            font_system,
            swash_cache,
            next_x,
            ty,
            &truncated,
            layout.text_size,
            attrs,
            theme.text_primary,
            None,
        );
        next_x += layout.app_column_width + layout.column_gap;
    }

    // Title column.
    if show_title {
        let title_max = card.x + card.width - next_x - layout.padding;
        if title_max > 50.0 {
            let attrs = Attrs::new()
                .family(Family::SansSerif)
                .weight(Weight::NORMAL);
            let truncated =
                ellipsize_text(font_system, row.title, layout.text_size, attrs, title_max);
            let ty = row_y + (layout.row_height - layout.text_size) / 2.0;
            draw_text(
                pixmap,
                font_system,
                swash_cache,
                next_x,
                ty,
                &truncated,
                layout.text_size,
                attrs,
                theme.text_secondary,
                None,
            );
        }
    }
}

fn draw_input_indicator(
    pixmap: &mut tiny_skia::Pixmap,
    font_system: &mut FontSystem,
    swash_cache: &mut SwashCache,
    card: &CardRect,
    input: &str,
    layout: &Layout,
    theme: &OverlayTheme,
) {
    let text = format!("\u{203a} {input}");
    let attrs = Attrs::new().family(Family::SansSerif);
    let (tw, _th) = measure_text(font_system, &text, layout.text_size, attrs, None);

    let pill_pad_h = layout.padding;
    let pill_pad_v = layout.padding / 2.0;
    let pill_w = tw + pill_pad_h * 2.0;
    // Use font size (not line height) for pill sizing to keep text visually centered.
    let pill_h = layout.text_size + pill_pad_v * 2.0;
    let pill_x = card.x + (card.width - pill_w) / 2.0;
    let pill_y = card.y + card.height + layout.padding;

    fill_rounded_rect(
        pixmap,
        pill_x,
        pill_y,
        pill_w,
        pill_h,
        pill_h / 2.0,
        theme.badge_background,
    );
    // Center text vertically within the pill using font size.
    let text_y = pill_y + (pill_h - layout.text_size) / 2.0;
    draw_text(
        pixmap,
        font_system,
        swash_cache,
        pill_x + pill_pad_h,
        text_y,
        &text,
        layout.text_size,
        attrs,
        theme.text_primary,
        None,
    );
}

#[allow(clippy::too_many_arguments)]
fn draw_no_matches(
    pixmap: &mut tiny_skia::Pixmap,
    font_system: &mut FontSystem,
    swash_cache: &mut SwashCache,
    width: f32,
    height: f32,
    input: &str,
    layout: &Layout,
    theme: &OverlayTheme,
) {
    let message = format!("No matches for '{input}'");
    let attrs = Attrs::new().family(Family::SansSerif);
    let font_size = layout.text_size * 1.2;
    let (tw, th) = measure_text(font_system, &message, font_size, attrs, None);

    let pad = layout.padding * 2.0;
    let cw = tw + pad * 2.0;
    let ch = th + pad * 2.0;
    let cx = (width - cw) / 2.0;
    let cy = (height - ch) / 2.0;

    fill_rounded_rect(
        pixmap,
        cx,
        cy,
        cw,
        ch,
        layout.corner_radius,
        theme.card_background,
    );
    stroke_rounded_rect(
        pixmap,
        cx,
        cy,
        cw,
        ch,
        layout.corner_radius,
        theme.card_border,
        layout.border_width,
    );
    draw_text(
        pixmap,
        font_system,
        swash_cache,
        cx + pad,
        cy + pad,
        &message,
        font_size,
        attrs,
        theme.text_primary,
        None,
    );
}

#[allow(clippy::too_many_arguments)]
fn draw_launch_staged(
    pixmap: &mut tiny_skia::Pixmap,
    font_system: &mut FontSystem,
    swash_cache: &mut SwashCache,
    width: f32,
    height: f32,
    command: &str,
    layout: &Layout,
    theme: &OverlayTheme,
) {
    let message = format!("Launch {command}");
    let attrs = Attrs::new().family(Family::SansSerif);
    let font_size = layout.text_size * 1.2;
    let (tw, th) = measure_text(font_system, &message, font_size, attrs, None);

    let pad = layout.padding * 2.0;
    let cw = tw + pad * 2.0;
    let ch = th + pad * 2.0;
    let cx = (width - cw) / 2.0;
    let cy = (height - ch) / 2.0;

    fill_rounded_rect(
        pixmap,
        cx,
        cy,
        cw,
        ch,
        layout.corner_radius,
        theme.card_background,
    );
    stroke_rounded_rect(
        pixmap,
        cx,
        cy,
        cw,
        ch,
        layout.corner_radius,
        theme.badge_matched_background,
        layout.border_width * 2.0,
    );
    draw_text(
        pixmap,
        font_system,
        swash_cache,
        cx + pad,
        cy + pad,
        &message,
        font_size,
        attrs,
        theme.text_primary,
        None,
    );
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Extract a friendly app name from an app_id (reverse-DNS -> last segment, capitalize).
pub fn extract_app_name(app_id: &str) -> String {
    let name = app_id.split('.').next_back().unwrap_or(app_id);
    let mut chars: Vec<char> = name.chars().collect();
    if let Some(first) = chars.first_mut() {
        *first = first.to_ascii_uppercase();
    }
    chars.into_iter().collect()
}

// ---------------------------------------------------------------------------
// Pixel format conversion
// ---------------------------------------------------------------------------

/// Convert tiny-skia RGBA pixel buffer to Wayland ARGB8888 in-place.
///
/// Both formats use premultiplied alpha. Only the R and B channels
/// are swapped (positions 0 and 2 in each 4-byte pixel).
pub fn convert_rgba_to_argb8888(buffer: &mut [u8]) {
    for pixel in buffer.chunks_exact_mut(4) {
        pixel.swap(0, 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_app_name_reverse_dns() {
        assert_eq!(extract_app_name("com.mitchellh.ghostty"), "Ghostty");
    }

    #[test]
    fn extract_app_name_simple() {
        assert_eq!(extract_app_name("firefox"), "Firefox");
    }

    #[test]
    fn color_from_hex() {
        let c = Color::from_hex("#89b4fa").unwrap();
        assert!((c.r - 137.0 / 255.0).abs() < 0.01);
        assert!((c.g - 180.0 / 255.0).abs() < 0.01);
        assert!((c.b - 250.0 / 255.0).abs() < 0.01);
    }

    #[test]
    fn default_theme_valid() {
        let theme = OverlayTheme::default();
        assert!(theme.border_width > 0.0);
        assert!(theme.corner_radius > 0.0);
    }

    #[test]
    fn rgba_to_argb_conversion() {
        let mut buf = [255u8, 0, 0, 128]; // R=255, G=0, B=0, A=128
        convert_rgba_to_argb8888(&mut buf);
        assert_eq!(buf, [0, 0, 255, 128]); // B=0, G=0, R=255, A=128
    }
}
