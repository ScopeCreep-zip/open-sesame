//! Overlay rendering — pure pixel math on transparent pixmaps.
//!
//! One visual state: a centered card on full transparency. The compositor
//! provides the frosted glass backdrop via `ext_background_effect_v1`.
//! No screen-edge borders. No intermediate visual phases. The card appears
//! fully formed or not at all.

pub mod layout;
pub mod primitives;
pub mod text;

use cosmic_text::{Attrs, Family, FontSystem, SwashCache, Weight};
use layout::{CardRect, Layout};
use primitives::{fill_rounded_rect, stroke_rounded_rect};
use text::{draw_text, ellipsize_text, measure_text};

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

    pub fn brightened(&self, amount: f64) -> Self {
        Self {
            r: (self.r + amount).min(1.0),
            g: (self.g + amount).min(1.0),
            b: (self.b + amount).min(1.0),
            a: self.a,
        }
    }

    pub fn to_tiny_skia(self) -> tiny_skia::Color {
        tiny_skia::Color::from_rgba(self.r as f32, self.g as f32, self.b as f32, self.a as f32)
            .unwrap_or(tiny_skia::Color::TRANSPARENT)
    }

    pub fn to_cosmic_text(self) -> cosmic_text::Color {
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

/// Platform-agnostic overlay theme. One material, one visual identity.
#[derive(Debug, Clone)]
pub struct OverlayTheme {
    /// Card material: semi-transparent surface over compositor blur.
    pub card_background: Color,
    /// Card border: subtle accent-colored edge.
    pub card_border: Color,
    /// Primary text on the card surface.
    pub text_primary: Color,
    /// Secondary text (reduced opacity of primary).
    pub text_secondary: Color,
    /// Badge pill background.
    pub badge_background: Color,
    /// Badge pill text.
    pub badge_text: Color,
    /// Badge when hint is matched (accent color).
    pub badge_matched_background: Color,
    /// Badge text when matched.
    pub badge_matched_text: Color,
    /// Selection highlight: subtle white wash over the row.
    pub selection_highlight: Color,
    /// Corner radius from system theme.
    pub corner_radius: f64,
}

impl Default for OverlayTheme {
    fn default() -> Self {
        Self {
            card_background: Color::rgba(30, 30, 30, 120),
            card_border: Color::rgba(80, 80, 80, 180),
            text_primary: Color::rgb(255, 255, 255),
            text_secondary: Color::rgba(255, 255, 255, 180),
            badge_background: Color::rgba(100, 100, 100, 255),
            badge_text: Color::rgb(255, 255, 255),
            badge_matched_background: Color::rgba(76, 175, 80, 255),
            badge_matched_text: Color::rgb(255, 255, 255),
            selection_highlight: Color::rgba(255, 255, 255, 25),
            corner_radius: layout::BASE_CORNER_RADIUS as f64,
        }
    }
}

impl OverlayTheme {
    /// Build theme from WmConfig settings.
    /// Priority: COSMIC system theme → user config overrides → defaults.
    pub fn from_config(cfg: &core_config::WmConfig) -> Self {
        let mut theme = Self::from_cosmic().unwrap_or_default();
        let defaults = core_config::WmConfig::default();

        if cfg.card_color != defaults.card_color
            && let Some(c) = Color::from_hex(&cfg.card_color)
        {
            theme.card_background = c;
        }
        if cfg.border_color != defaults.border_color
            && let Some(c) = Color::from_hex(&cfg.border_color)
        {
            theme.card_border = c;
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

    /// Build theme from COSMIC desktop system theme via `cosmic-theme` crate.
    #[cfg(target_os = "linux")]
    fn from_cosmic() -> Option<Self> {
        let t = platform_linux::cosmic_theme::CosmicTheme::load()?;

        let pb = t.primary_base;
        let po = t.primary_on;
        let sb = t.secondary_component_base;
        let so = t.secondary_component_on;
        let ab = t.accent_base;
        let ao = t.accent_on;
        let corner_radius = t.radius_m[0] as f64;

        // Card alpha: always semi-transparent so blur shows through.
        // When frosted, use the theme's blur alpha. Otherwise, 50% opacity
        // so the compositor blur is always visible behind the card.
        let card_alpha = if t.frosted_panel || t.frosted_windows {
            (t.blur_alpha * 255.0) as u8
        } else {
            128
        };

        Some(Self {
            card_background: Color::rgba(pb.r, pb.g, pb.b, card_alpha),
            card_border: Color::rgba(ab.r, ab.g, ab.b, 120),
            text_primary: Color::rgba(po.r, po.g, po.b, po.a),
            text_secondary: Color::rgba(po.r, po.g, po.b, ((po.a as f64) * 0.7) as u8),
            badge_background: Color::rgba(sb.r, sb.g, sb.b, 255),
            badge_text: Color::rgba(so.r, so.g, so.b, so.a),
            badge_matched_background: Color::rgba(ab.r, ab.g, ab.b, 255),
            badge_matched_text: Color::rgba(ao.r, ao.g, ao.b, ao.a),
            selection_highlight: Color::rgba(255, 255, 255, 25),
            corner_radius,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn from_cosmic() -> Option<Self> {
        None
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single window hint row for rendering.
pub struct HintRow<'a> {
    pub hint: &'a str,
    pub app_id: &'a str,
    pub title: &'a str,
}

// ---------------------------------------------------------------------------
// Card material — one function, used by every phase
// ---------------------------------------------------------------------------

/// Draw the card container. Same material everywhere, always.
fn draw_card(
    pixmap: &mut tiny_skia::Pixmap,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    corner_radius: f32,
    theme: &OverlayTheme,
) {
    fill_rounded_rect(pixmap, x, y, w, h, corner_radius, theme.card_background);
    stroke_rounded_rect(pixmap, x, y, w, h, corner_radius, theme.card_border, 1.0);
}

// ---------------------------------------------------------------------------
// Public draw entry points
// ---------------------------------------------------------------------------

/// Armed phase: render nothing. The overlay surface exists (for keyboard
/// exclusivity) but is visually invisible. No border, no card, pure transparency.
pub fn draw_border_only(
    pixmap: &mut tiny_skia::Pixmap,
    _width: f32,
    _height: f32,
    _scale: f32,
    _theme: &OverlayTheme,
) {
    pixmap.fill(tiny_skia::Color::TRANSPARENT);
}

/// Draw the full overlay: centered card with hint rows on transparent background.
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

    let visible: Vec<(usize, &HintRow<'_>)> = rows
        .iter()
        .enumerate()
        .filter(|(i, _)| {
            if input.is_empty() {
                return true;
            }
            if *i < hints.len() {
                hints[*i].starts_with(&input.to_lowercase())
            } else {
                false
            }
        })
        .collect();

    if visible.is_empty() && !input.is_empty() {
        if let Some(command) = staged_launch {
            let message = format!("Launch {command}");
            draw_message_card(
                pixmap,
                font_system,
                swash_cache,
                width,
                height,
                &message,
                &layout,
                theme,
            );
        } else {
            let message = format!("No matches for \u{2018}{input}\u{2019}");
            draw_message_card(
                pixmap,
                font_system,
                swash_cache,
                width,
                height,
                &message,
                &layout,
                theme,
            );
        }
        return;
    }

    let selection = selection.min(visible.len().saturating_sub(1));
    let card = layout::calculate_card(
        visible.len(),
        width,
        height,
        &layout,
        show_app_id,
        show_title,
    );

    draw_card(
        pixmap,
        card.x,
        card.y,
        card.width,
        card.height,
        layout.corner_radius,
        theme,
    );

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
    draw_message_card(
        pixmap,
        font_system,
        swash_cache,
        width,
        height,
        message,
        &layout,
        theme,
    );
}

/// Draw a centered error message.
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
    pixmap.fill(tiny_skia::Color::TRANSPARENT);
    let display = format!("Launch failed\n\n{message}\n\nPress any key to dismiss");
    draw_message_card(
        pixmap,
        font_system,
        swash_cache,
        width,
        height,
        &display,
        &layout,
        theme,
    );
}

/// Draw a vault unlock password prompt.
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
    pixmap.fill(tiny_skia::Color::TRANSPARENT);

    let mut display = format!("Unlock \u{201C}{profile}\u{201D}\n\n");
    if password_len > 0 {
        for i in 0..password_len.min(32) {
            display.push('\u{25CF}');
            if i < password_len.min(32) - 1 {
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
    draw_message_card(
        pixmap,
        font_system,
        swash_cache,
        width,
        height,
        &display,
        &layout,
        theme,
    );
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HintMatchState {
    None,
    Partial,
    Exact,
}

/// Shared message card: same material, centered text.
#[allow(clippy::too_many_arguments)]
fn draw_message_card(
    pixmap: &mut tiny_skia::Pixmap,
    font_system: &mut FontSystem,
    swash_cache: &mut SwashCache,
    width: f32,
    height: f32,
    message: &str,
    layout: &Layout,
    theme: &OverlayTheme,
) {
    let attrs = Attrs::new()
        .family(Family::SansSerif)
        .weight(Weight::NORMAL);
    let font_size = layout.text_size * 1.2;
    let max_width = (width * 0.6).min(500.0);
    let (tw, th) = measure_text(font_system, message, font_size, attrs, Some(max_width));

    let pad = layout.padding * 2.0;
    let cw = tw + pad * 2.0;
    let ch = th + pad * 2.0;
    let cx = (width - cw) / 2.0;
    let cy = (height - ch) / 2.0;

    draw_card(pixmap, cx, cy, cw, ch, layout.corner_radius, theme);
    draw_text(
        pixmap,
        font_system,
        swash_cache,
        cx + pad,
        cy + pad,
        message,
        font_size,
        attrs,
        theme.text_primary,
        Some(max_width),
    );
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

    let hint_text = row.hint.to_uppercase();
    let badge_attrs = Attrs::new()
        .family(Family::SansSerif)
        .weight(Weight::SEMIBOLD);
    let (tw, _) = measure_text(font_system, &hint_text, layout.text_size, badge_attrs, None);
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
    let (tw, _) = measure_text(font_system, &text, layout.text_size, attrs, None);

    let pill_pad_h = layout.padding;
    let pill_pad_v = layout.padding / 2.0;
    let pill_w = tw + pill_pad_h * 2.0;
    let pill_h = layout.text_size + pill_pad_v * 2.0;
    let pill_x = card.x + (card.width - pill_w) / 2.0;
    let pill_y = card.y + card.height + layout.padding;

    // Same material as the card — not an opaque badge.
    draw_card(pixmap, pill_x, pill_y, pill_w, pill_h, pill_h / 2.0, theme);
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

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/// Extract a friendly app name from an app_id (reverse-DNS → last segment, capitalize).
pub fn extract_app_name(app_id: &str) -> String {
    let name = app_id.split('.').next_back().unwrap_or(app_id);
    let mut chars: Vec<char> = name.chars().collect();
    if let Some(first) = chars.first_mut() {
        *first = first.to_ascii_uppercase();
    }
    chars.into_iter().collect()
}

/// Convert tiny-skia RGBA pixel buffer to Wayland ARGB8888 in-place.
pub fn convert_rgba_to_argb8888(buffer: &mut [u8]) {
    for pixel in buffer.chunks_exact_mut(4) {
        pixel.swap(0, 2);
    }
}

/// Return the card geometry for blur region calculation.
pub fn compute_card_rect(
    row_count: usize,
    screen_w: f32,
    screen_h: f32,
    scale: f32,
    show_app_id: bool,
    show_title: bool,
) -> (f32, f32, f32, f32) {
    let l = Layout::new(scale);
    let card = layout::calculate_card(row_count, screen_w, screen_h, &l, show_app_id, show_title);
    (card.x, card.y, card.width, card.height)
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
    }

    #[test]
    fn default_theme_valid() {
        let theme = OverlayTheme::default();
        assert!(theme.corner_radius > 0.0);
    }

    #[test]
    fn rgba_to_argb_conversion() {
        let mut buf = [255u8, 0, 0, 128];
        convert_rgba_to_argb8888(&mut buf);
        assert_eq!(buf, [0, 0, 255, 128]);
    }
}
