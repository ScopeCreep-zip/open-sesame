//! Overlay rendering — pure pixel math on transparent pixmaps.
//!
//! One visual state: a centered card on full transparency. The compositor
//! provides the frosted glass backdrop via `ext_background_effect_v1`.
//! No screen-edge borders. No intermediate visual phases. The card appears
//! fully formed or not at all. A fresh pixmap is transparent (tiny-skia
//! zero-fills it), so the Armed phase draws nothing at all.

pub mod layout;
pub mod primitives;
pub mod text;

use crate::surface::wayland::WindowInfo;
use cosmic_text::{Attrs, Family, FontSystem, SwashCache, Weight};
use layout::{Layout, Rect};
use primitives::{fill_rounded_rect, stroke_rounded_rect};
use text::{Fit, Text};

/// `value` (a count or pixel dimension) as `f32`, saturating at
/// `u16::MAX`: overlay geometry never approaches it, and below it the
/// conversion is exact.
pub(crate) fn real(value: impl TryInto<u16>) -> f32 {
    value.try_into().map_or(f32::from(u16::MAX), f32::from)
}

/// The nearest whole pixel to `value`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "rounded first; `as` saturates at the i32 range and maps NaN to 0"
)]
pub(crate) fn whole(value: f32) -> i32 {
    value.round() as i32
}

// ---------------------------------------------------------------------------
// Color
// ---------------------------------------------------------------------------

/// An 8-bit straight-alpha RGBA color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    #[must_use]
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    #[must_use]
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self::rgba(r, g, b, 255)
    }

    /// The color of `#RRGGBB` or `#RRGGBBAA` (the `#` optional); `None` for
    /// any other text, multibyte characters included.
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        let hex = hex.strip_prefix('#').unwrap_or(hex);
        let channel = |at: usize| {
            hex.get(at..at + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        };
        match hex.len() {
            6 => Some(Self::rgb(channel(0)?, channel(2)?, channel(4)?)),
            8 => Some(Self::rgba(
                channel(0)?,
                channel(2)?,
                channel(4)?,
                channel(6)?,
            )),
            _ => None,
        }
    }

    /// Each color channel raised by `amount`, saturating; alpha unchanged.
    #[must_use]
    pub const fn brightened(self, amount: u8) -> Self {
        Self::rgba(
            self.r.saturating_add(amount),
            self.g.saturating_add(amount),
            self.b.saturating_add(amount),
            self.a,
        )
    }

    /// This color with its alpha scaled to `percent` percent.
    #[must_use]
    pub fn faded(self, percent: u8) -> Self {
        let a = u16::from(self.a) * u16::from(percent.min(100)) / 100;
        Self {
            a: u8::try_from(a).unwrap_or(u8::MAX),
            ..self
        }
    }

    #[must_use]
    pub fn to_tiny_skia(self) -> tiny_skia::Color {
        tiny_skia::Color::from_rgba8(self.r, self.g, self.b, self.a)
    }

    #[must_use]
    pub const fn to_cosmic_text(self) -> cosmic_text::Color {
        cosmic_text::Color::rgba(self.r, self.g, self.b, self.a)
    }
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

/// How much a partially matched badge brightens (about 12%).
const PARTIAL_MATCH_BRIGHTEN: u8 = 31;

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
    /// Card corner radius in logical pixels, from the system theme.
    pub corner_radius: f32,
    /// Interface font family from the system theme; `None` is sans-serif.
    pub font_family: Option<String>,
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
            corner_radius: layout::CORNER_RADIUS,
            font_family: None,
        }
    }
}

impl OverlayTheme {
    /// The family the overlay shapes text in.
    #[must_use]
    pub fn family(&self) -> Family<'_> {
        self.font_family
            .as_deref()
            .map_or(Family::SansSerif, Family::Name)
    }

    /// The theme for `cfg`: the COSMIC system theme (or the defaults
    /// without one), overridden by each color `cfg` sets to other than its
    /// compiled default.
    #[must_use]
    pub fn from_config(cfg: &core_config::WmConfig) -> Self {
        let mut theme = Self::from_cosmic().unwrap_or_default();
        let defaults = core_config::WmConfig::default();
        let set = |value: &str, default: &str| {
            (value != default).then(|| Color::from_hex(value)).flatten()
        };
        if let Some(c) = set(&cfg.card_color, &defaults.card_color) {
            theme.card_background = c;
        }
        if let Some(c) = set(&cfg.border_color, &defaults.border_color) {
            theme.card_border = c;
        }
        if let Some(c) = set(&cfg.text_color, &defaults.text_color) {
            theme.text_primary = c;
            theme.badge_text = c;
            theme.badge_matched_text = c;
        }
        if let Some(c) = set(&cfg.hint_color, &defaults.hint_color) {
            theme.badge_background = c;
        }
        if let Some(c) = set(&cfg.hint_matched_color, &defaults.hint_matched_color) {
            theme.badge_matched_background = c;
        }
        theme
    }

    /// The COSMIC desktop system theme, when the desktop provides one: the
    /// COSMIC configuration of this process's layout.
    #[cfg(target_os = "linux")]
    fn from_cosmic() -> Option<Self> {
        let cosmic_dir = core_layout::Layout::from_process()
            .cosmic_config_dir()
            .ok()?;
        let t = platform_linux::cosmic_theme::CosmicTheme::load(&cosmic_dir)?;
        let color = |c: platform_linux::cosmic_theme::ThemeColor| Color::rgba(c.r, c.g, c.b, c.a);
        let opaque = |c: platform_linux::cosmic_theme::ThemeColor| Color::rgb(c.r, c.g, c.b);
        // The card is always translucent so the compositor blur shows
        // through: the theme's blurred alpha when frosted, half otherwise.
        let card_alpha = if t.frosted_panel || t.frosted_windows {
            t.blur_alpha
        } else {
            128
        };
        let primary = color(t.primary_on);
        Some(Self {
            card_background: Color {
                a: card_alpha,
                ..opaque(t.primary_base)
            },
            card_border: Color {
                a: 120,
                ..opaque(t.accent_base)
            },
            text_primary: primary,
            text_secondary: primary.faded(70),
            badge_background: opaque(t.secondary_component_base),
            badge_text: color(t.secondary_component_on),
            badge_matched_background: opaque(t.accent_base),
            badge_matched_text: color(t.accent_on),
            selection_highlight: Color::rgba(255, 255, 255, 25),
            corner_radius: t.radius_m[0],
            font_family: Some(t.font_family),
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn from_cosmic() -> Option<Self> {
        None
    }
}

/// The window-list columns shown beside each hint badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Columns {
    pub app_id: bool,
    pub title: bool,
}

impl Columns {
    /// The columns `config` enables.
    #[must_use]
    pub fn of(config: &core_config::WmConfig) -> Self {
        Self {
            app_id: config.show_app_id,
            title: config.show_title,
        }
    }
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

/// The window picker as drawn: every window with its hint, the typed
/// input, the selected row, and a launch staged by the input.
#[derive(Debug, Clone, Copy)]
pub struct Picker<'v> {
    pub windows: &'v [WindowInfo],
    pub hints: &'v [String],
    pub input: &'v str,
    pub selection: usize,
    pub staged_launch: Option<&'v str>,
    pub columns: Columns,
}

/// How a row's hint relates to the typed input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HintMatch {
    None,
    Partial,
    Exact,
}

/// One picker row as drawn.
struct Row<'r> {
    hint: &'r str,
    window: &'r WindowInfo,
    selected: bool,
    matched: HintMatch,
}

/// The rows of `picker` its input leaves visible (every row when the input
/// is empty), with how each hint matches it.
fn visible_rows<'v>(picker: &Picker<'v>, input: &str) -> Vec<(&'v str, &'v WindowInfo, HintMatch)> {
    picker
        .windows
        .iter()
        .zip(picker.hints)
        .filter(|(_, hint)| hint.starts_with(input))
        .map(|(window, hint)| {
            let matched = match () {
                () if input.is_empty() => HintMatch::None,
                () if *hint == input => HintMatch::Exact,
                () => HintMatch::Partial,
            };
            (hint.as_str(), window, matched)
        })
        .collect()
}

/// The message of a failed launch.
#[must_use]
pub fn launch_error_text(reason: &str) -> String {
    format!("Launch failed\n\n{reason}\n\nPress any key to dismiss")
}

/// The password prompt's text: the profile, one dot per character (at most
/// 32), and the error of the last attempt.
fn unlock_prompt_text(profile: &str, password_len: usize, error: Option<&str>) -> String {
    let field = if password_len == 0 {
        "Enter password".to_owned()
    } else {
        vec!["\u{25CF}"; password_len.min(32)].join(" ")
    };
    let mut text = format!("Unlock \u{201C}{profile}\u{201D}\n\n{field}");
    if let Some(error) = error {
        text.push_str("\n\n");
        text.push_str(error);
    }
    text
}

/// A friendly app name from an app id: the last reverse-DNS segment,
/// capitalized.
fn app_name(app_id: &str) -> String {
    let name = app_id.rsplit('.').next().unwrap_or(app_id);
    let mut chars = name.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

/// Convert a tiny-skia RGBA pixel buffer to Wayland ARGB8888 in place.
pub fn convert_rgba_to_argb8888(buffer: &mut [u8]) {
    for pixel in buffer.chunks_exact_mut(4) {
        pixel.swap(0, 2);
    }
}

// ---------------------------------------------------------------------------
// Canvas
// ---------------------------------------------------------------------------

/// A frame being drawn: the pixmap, the fonts it is drawn with, the theme,
/// and the layout at the output scale. Each view returns the card it drew,
/// in buffer pixels.
pub struct Canvas<'a> {
    pixmap: tiny_skia::Pixmap,
    fonts: &'a mut FontSystem,
    glyphs: &'a mut SwashCache,
    theme: &'a OverlayTheme,
    layout: Layout,
    width: f32,
    height: f32,
}

impl<'a> Canvas<'a> {
    /// A transparent `width` x `height` canvas at `scale`; `None` when the
    /// size is zero or too large for a pixmap.
    #[must_use]
    pub fn new(
        width: u32,
        height: u32,
        scale: u8,
        fonts: &'a mut FontSystem,
        glyphs: &'a mut SwashCache,
        theme: &'a OverlayTheme,
    ) -> Option<Self> {
        Some(Self {
            pixmap: tiny_skia::Pixmap::new(width, height)?,
            fonts,
            glyphs,
            theme,
            layout: Layout::new(f32::from(scale), theme.corner_radius),
            width: real(width),
            height: real(height),
        })
    }

    /// The pixels drawn, premultiplied RGBA.
    #[must_use]
    pub fn into_pixels(self) -> Vec<u8> {
        self.pixmap.take()
    }

    /// The text attributes in the theme's family at `weight`.
    fn attrs(&self, weight: Weight) -> Attrs<'a> {
        Attrs::new().family(self.theme.family()).weight(weight)
    }

    /// Draw the card material — the same everywhere — over `rect`.
    fn card(&mut self, rect: Rect, radius: f32) {
        fill_rounded_rect(&mut self.pixmap, rect, radius, self.theme.card_background);
        stroke_rounded_rect(
            &mut self.pixmap,
            rect,
            radius,
            self.theme.card_border,
            self.layout.border_width,
        );
    }

    /// Draw `text` at `origin` in `color`.
    fn text(&mut self, text: &Text<'_>, origin: (f32, f32), color: Color) {
        text.draw(&mut self.pixmap, self.fonts, self.glyphs, origin, color);
    }

    /// A centered card holding `message`.
    pub fn message(&mut self, message: &str) -> Rect {
        let text = Text {
            content: message,
            size: self.layout.text_size * 1.2,
            attrs: self.attrs(Weight::NORMAL),
            fit: Fit::Wrap((self.width * 0.6).min(500.0)),
        };
        let (text_w, text_h) = text.extent(self.fonts);
        let pad = self.layout.padding * 2.0;
        let rect = Rect::centered(
            text_w + pad * 2.0,
            text_h + pad * 2.0,
            self.width,
            self.height,
        );
        self.card(rect, self.layout.corner_radius);
        let primary = self.theme.text_primary;
        self.text(&text, (rect.x + pad, rect.y + pad), primary);
        rect
    }

    /// The vault password prompt.
    pub fn unlock_prompt(
        &mut self,
        profile: &str,
        password_len: usize,
        error: Option<&str>,
    ) -> Rect {
        self.message(&unlock_prompt_text(profile, password_len, error))
    }

    /// The window picker: the visible rows on a card with the input below
    /// it, or the staged launch (or that nothing matches) when the input
    /// leaves no row.
    pub fn picker(&mut self, picker: &Picker<'_>) -> Rect {
        let input = picker.input.to_lowercase();
        let rows = visible_rows(picker, &input);
        if rows.is_empty() && !input.is_empty() {
            return match picker.staged_launch {
                Some(command) => self.message(&format!("Launch {command}")),
                None => self.message(&format!("No matches for \u{2018}{}\u{2019}", picker.input)),
            };
        }
        let card = self
            .layout
            .card(rows.len(), self.width, self.height, picker.columns);
        self.card(card, self.layout.corner_radius);
        let selection = picker.selection.min(rows.len().saturating_sub(1));
        for (index, &(hint, window, matched)) in rows.iter().enumerate() {
            let row = Row {
                hint,
                window,
                selected: index == selection,
                matched,
            };
            self.row(
                &card,
                self.layout.row_y(card.y, index),
                &row,
                picker.columns,
            );
        }
        if !picker.input.is_empty() {
            self.input_pill(&card, picker.input);
        }
        card
    }

    /// One picker row at `y`: the selection wash, the hint badge, and the
    /// enabled columns.
    fn row(&mut self, card: &Rect, y: f32, row: &Row<'_>, columns: Columns) {
        let layout = self.layout;
        let theme = self.theme;
        if row.selected {
            let wash = Rect {
                x: card.x + layout.padding / 2.0,
                y,
                width: card.width - layout.padding,
                height: layout.row_height,
            };
            fill_rounded_rect(
                &mut self.pixmap,
                wash,
                layout.badge_radius,
                theme.selection_highlight,
            );
        }

        let badge = Rect {
            x: card.x + layout.padding,
            y: y + (layout.row_height - layout.badge_height) / 2.0,
            width: layout.badge_width,
            height: layout.badge_height,
        };
        let (badge_background, badge_text) = match row.matched {
            HintMatch::Exact => (theme.badge_matched_background, theme.badge_matched_text),
            HintMatch::Partial => (
                theme.badge_background.brightened(PARTIAL_MATCH_BRIGHTEN),
                theme.badge_text,
            ),
            HintMatch::None => (theme.badge_background, theme.badge_text),
        };
        fill_rounded_rect(
            &mut self.pixmap,
            badge,
            layout.badge_radius,
            badge_background,
        );
        let hint = row.hint.to_uppercase();
        let hint = Text {
            content: &hint,
            size: layout.text_size,
            attrs: self.attrs(Weight::SEMIBOLD),
            fit: Fit::Natural,
        };
        let (hint_w, _) = hint.extent(self.fonts);
        let hint_origin = (
            badge.x + (badge.width - hint_w) / 2.0,
            badge.y + (badge.height - layout.text_size) / 2.0,
        );
        self.text(&hint, hint_origin, badge_text);

        let text_y = y + (layout.row_height - layout.text_size) / 2.0;
        let mut x = badge.x + badge.width + layout.column_gap;
        if columns.app_id {
            let name = app_name(&row.window.app_id);
            let name = Text {
                content: &name,
                size: layout.text_size,
                attrs: self.attrs(Weight::NORMAL),
                fit: Fit::Ellipsize(layout.app_column_width),
            };
            self.text(&name, (x, text_y), theme.text_primary);
            x += layout.app_column_width + layout.column_gap;
        }
        let title_width = card.x + card.width - x - layout.padding;
        if columns.title && title_width > MIN_TITLE_DRAW_WIDTH {
            let title = Text {
                content: &row.window.title,
                size: layout.text_size,
                attrs: self.attrs(Weight::NORMAL),
                fit: Fit::Ellipsize(title_width),
            };
            self.text(&title, (x, text_y), theme.text_secondary);
        }
    }

    /// The typed input in a pill of card material below `card`.
    fn input_pill(&mut self, card: &Rect, input: &str) {
        let layout = self.layout;
        let content = format!("\u{203a} {input}");
        let text = Text {
            content: &content,
            size: layout.text_size,
            attrs: self.attrs(Weight::NORMAL),
            fit: Fit::Natural,
        };
        let (text_w, _) = text.extent(self.fonts);
        let (pad_h, pad_v) = (layout.padding, layout.padding / 2.0);
        let width = text_w + pad_h * 2.0;
        let height = layout.text_size + pad_v * 2.0;
        let pill = Rect {
            x: card.x + (card.width - width) / 2.0,
            y: card.y + card.height + layout.padding,
            width,
            height,
        };
        self.card(pill, height / 2.0);
        let primary = self.theme.text_primary;
        self.text(&text, (pill.x + pad_h, pill.y + pad_v), primary);
    }
}

/// Narrowest title column worth drawing.
const MIN_TITLE_DRAW_WIDTH: f32 = 50.0;

#[cfg(test)]
mod tests {
    use super::*;

    fn window(app_id: &str, title: &str) -> WindowInfo {
        WindowInfo {
            app_id: app_id.into(),
            title: title.into(),
        }
    }

    #[test]
    fn app_names_are_the_capitalized_last_segment() {
        assert_eq!(app_name("com.mitchellh.ghostty"), "Ghostty");
        assert_eq!(app_name("firefox"), "Firefox");
        assert_eq!(app_name(""), "");
    }

    #[test]
    fn color_from_hex() {
        assert_eq!(
            Color::from_hex("#89b4fa"),
            Some(Color::rgb(0x89, 0xb4, 0xfa))
        );
        assert_eq!(
            Color::from_hex("89b4fa80"),
            Some(Color::rgba(0x89, 0xb4, 0xfa, 0x80))
        );
        assert_eq!(Color::from_hex("#89b4f"), None);
        assert_eq!(Color::from_hex("#zzzzzz"), None);
    }

    #[test]
    fn hex_colors_with_multibyte_characters_are_rejected() {
        // "ééé" is six bytes: a byte-indexed parse splits a code point.
        assert!(Color::from_hex("#ééé").is_none());
        assert!(Color::from_hex("#aé12345").is_none());
    }

    #[test]
    fn colors_brighten_and_fade_without_overflow() {
        let c = Color::rgba(250, 10, 0, 200);
        assert_eq!(c.brightened(31), Color::rgba(255, 41, 31, 200));
        assert_eq!(c.faded(70).a, 140);
        assert_eq!(c.faded(200).a, 200, "fading never adds opacity");
    }

    #[test]
    fn default_theme_valid() {
        let theme = OverlayTheme::default();
        assert!(theme.corner_radius > 0.0);
    }

    #[test]
    fn text_uses_the_desktop_font_when_the_theme_names_one() {
        let mut theme = OverlayTheme::default();
        assert_eq!(theme.family(), Family::SansSerif);
        theme.font_family = Some("Inter".into());
        assert_eq!(theme.family(), Family::Name("Inter"));
    }

    #[test]
    fn rgba_to_argb_conversion() {
        let mut buf = [255u8, 0, 0, 128];
        convert_rgba_to_argb8888(&mut buf);
        assert_eq!(buf, [0, 0, 255, 128]);
    }

    #[test]
    fn input_filters_rows_and_grades_their_hints() {
        let windows = [window("a", "A"), window("b", "B"), window("c", "C")];
        let hints = ["f".to_owned(), "fd".to_owned(), "g".to_owned()];
        let picker = Picker {
            windows: &windows,
            hints: &hints,
            input: "F",
            selection: 0,
            staged_launch: None,
            columns: Columns {
                app_id: true,
                title: true,
            },
        };
        let rows = visible_rows(&picker, "f");
        let graded: Vec<(&str, HintMatch)> = rows.iter().map(|(h, _, m)| (*h, *m)).collect();
        assert_eq!(
            graded,
            [("f", HintMatch::Exact), ("fd", HintMatch::Partial)]
        );
        assert_eq!(visible_rows(&picker, "").len(), 3);
    }

    #[test]
    fn the_unlock_prompt_shows_dots_and_the_error() {
        assert_eq!(
            unlock_prompt_text("work", 3, Some("Wrong password")),
            "Unlock \u{201C}work\u{201D}\n\n\u{25CF} \u{25CF} \u{25CF}\n\nWrong password"
        );
        assert!(unlock_prompt_text("work", 0, None).ends_with("Enter password"));
        assert_eq!(
            unlock_prompt_text("w", 100, None)
                .matches('\u{25CF}')
                .count(),
            32
        );
    }

    #[test]
    fn whole_pixels_round_and_saturate() {
        assert_eq!(whole(1.5), 2);
        assert_eq!(whole(-0.4), 0);
        assert_eq!(whole(f32::MAX), i32::MAX);
        assert_eq!(whole(f32::NAN), 0);
        assert!((real(3_u32) - 3.0).abs() < f32::EPSILON);
        assert!((real(usize::MAX) - f32::from(u16::MAX)).abs() < f32::EPSILON);
    }
}
