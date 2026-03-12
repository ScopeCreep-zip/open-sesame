//! Cairo + Pango rendering for the window switcher overlay.
//!
//! Ports the v1 overlay layout (Material Design spacing, three-column hint rows)
//! to GTK4's Cairo drawing surface with Pango text layout. All dimensions are
//! specified in logical pixels; GTK4 handles HiDPI scaling automatically via
//! the drawing area's scale factor.

// ---------------------------------------------------------------------------
// Layout constants — Material Design 4-point grid
// ---------------------------------------------------------------------------

const BASE_PADDING: f64 = 20.0;
const BASE_ROW_HEIGHT: f64 = 48.0;
const BASE_ROW_SPACING: f64 = 8.0;
const BASE_BADGE_WIDTH: f64 = 48.0;
const BASE_BADGE_HEIGHT: f64 = 32.0;
const BASE_BADGE_RADIUS: f64 = 8.0;
const BASE_APP_COLUMN_WIDTH: f64 = 180.0;
const BASE_TEXT_SIZE: f64 = 16.0;
const BASE_BORDER_WIDTH: f64 = 3.0;
const BASE_CORNER_RADIUS: f64 = 16.0;
const BASE_COLUMN_GAP: f64 = 16.0;

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

    fn set_source(&self, cr: &gtk4::cairo::Context) {
        cr.set_source_rgba(self.r, self.g, self.b, self.a);
    }

    fn brightened(&self, amount: f64) -> Self {
        Self {
            r: (self.r + amount).min(1.0),
            g: (self.g + amount).min(1.0),
            b: (self.b + amount).min(1.0),
            a: self.a,
        }
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
            corner_radius: BASE_CORNER_RADIUS,
        }
    }
}

impl OverlayTheme {
    /// Build theme from WmConfig settings.
    ///
    /// Priority: COSMIC system theme -> user config overrides -> hardcoded defaults.
    /// Matches v1's `Theme::from_config` behavior (`src.v1/ui/theme.rs:110-118`).
    pub fn from_config(cfg: &core_config::WmConfig) -> Self {
        // Try COSMIC system theme first (native desktop integration).
        let mut theme = Self::from_cosmic().unwrap_or_default();

        // Apply user config overrides. Only override if the user set a non-default value.
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
    ///
    /// Returns `None` if COSMIC theme files are not present.
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
                primary_on.0, primary_on.1, primary_on.2,
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

    /// Non-Linux fallback: COSMIC theme not available.
    #[cfg(not(target_os = "linux"))]
    fn from_cosmic() -> Option<Self> {
        None
    }
}

// ---------------------------------------------------------------------------
// Layout (computed once per draw, based on allocated size)
// ---------------------------------------------------------------------------

struct Layout {
    padding: f64,
    row_height: f64,
    row_spacing: f64,
    badge_width: f64,
    badge_height: f64,
    badge_radius: f64,
    app_column_width: f64,
    text_size: f64,
    border_width: f64,
    corner_radius: f64,
    column_gap: f64,
}

impl Layout {
    fn new(scale: f64) -> Self {
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
// Window hint row data passed into draw functions
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
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

// ---------------------------------------------------------------------------
// Cairo rounded-rect helper
// ---------------------------------------------------------------------------

fn rounded_rect(cr: &gtk4::cairo::Context, x: f64, y: f64, w: f64, h: f64, r: f64) {
    let r = r.min(w / 2.0).min(h / 2.0);
    cr.new_sub_path();
    cr.arc(x + w - r, y + r, r, -std::f64::consts::FRAC_PI_2, 0.0);
    cr.arc(x + w - r, y + h - r, r, 0.0, std::f64::consts::FRAC_PI_2);
    cr.arc(x + r, y + h - r, r, std::f64::consts::FRAC_PI_2, std::f64::consts::PI);
    cr.arc(x + r, y + r, r, std::f64::consts::PI, 3.0 * std::f64::consts::FRAC_PI_2);
    cr.close_path();
}

// ---------------------------------------------------------------------------
// Public draw entry points
// ---------------------------------------------------------------------------

/// Draw border-only phase: transparent center, colored stroke around screen edges.
pub fn draw_border_only(
    cr: &gtk4::cairo::Context,
    width: f64,
    height: f64,
    theme: &OverlayTheme,
) {
    // Transparent background (GTK4 surface is already transparent if we set visual alpha).
    cr.set_operator(gtk4::cairo::Operator::Source);
    cr.set_source_rgba(0.0, 0.0, 0.0, 0.0);
    let _ = cr.paint();
    cr.set_operator(gtk4::cairo::Operator::Over);

    let bw = theme.border_width * 2.0;
    let half = bw / 2.0;
    rounded_rect(cr, half, half, width - bw, height - bw, theme.corner_radius);
    theme.border_color.set_source(cr);
    cr.set_line_width(bw);
    let _ = cr.stroke();
}

/// Draw the full overlay: border + centered card with hint rows.
#[allow(clippy::too_many_arguments)]
pub fn draw_full_overlay(
    cr: &gtk4::cairo::Context,
    width: f64,
    height: f64,
    rows: &[HintRow<'_>],
    input: &str,
    selection: usize,
    hints: &[String],
    theme: &OverlayTheme,
    show_app_id: bool,
    show_title: bool,
    staged_launch: Option<&str>,
) {
    let layout = Layout::new(1.0);

    // Clear to transparent, then draw border.
    cr.set_operator(gtk4::cairo::Operator::Source);
    cr.set_source_rgba(0.0, 0.0, 0.0, 0.0);
    let _ = cr.paint();
    cr.set_operator(gtk4::cairo::Operator::Over);

    // Screen border.
    let bw = theme.border_width * 2.0;
    let half = bw / 2.0;
    rounded_rect(cr, half, half, width - bw, height - bw, theme.corner_radius);
    theme.border_color.set_source(cr);
    cr.set_line_width(bw);
    let _ = cr.stroke();

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
                hint.starts_with(&norm) || hint == &norm
            } else {
                false
            }
        })
        .collect();

    if visible.is_empty() && !input.is_empty() {
        if let Some(command) = staged_launch {
            draw_launch_staged(cr, width, height, command, &layout, theme);
        } else {
            draw_no_matches(cr, width, height, input, &layout, theme);
        }
        return;
    }

    let selection = selection.min(visible.len().saturating_sub(1));

    // Card dimensions.
    let card = calculate_card(&visible, width, height, &layout, show_app_id, show_title);

    // Card background.
    rounded_rect(cr, card.x, card.y, card.width, card.height, layout.corner_radius);
    theme.card_background.set_source(cr);
    let _ = cr.fill();

    // Card border.
    rounded_rect(cr, card.x, card.y, card.width, card.height, layout.corner_radius);
    theme.card_border.set_source(cr);
    cr.set_line_width(layout.border_width);
    let _ = cr.stroke();

    // Hint rows.
    for (vi, &(orig_idx, row)) in visible.iter().enumerate() {
        let row_y = card.y + layout.padding + vi as f64 * (layout.row_height + layout.row_spacing);
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
            cr, &card, row_y, row, is_selected, match_state, &layout, theme, show_app_id,
            show_title,
        );
    }

    // Input indicator.
    if !input.is_empty() {
        draw_input_indicator(cr, &card, input, &layout, theme);
    }
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
    screen_w: f64,
    screen_h: f64,
    layout: &Layout,
    show_app_id: bool,
    show_title: bool,
) -> CardRect {
    let min_title_width = 200.0;
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
        row_count as f64 * (layout.row_height + layout.row_spacing) - layout.row_spacing;
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
    cr: &gtk4::cairo::Context,
    card: &CardRect,
    row_y: f64,
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
        rounded_rect(cr, hx, row_y, hw, layout.row_height, layout.badge_radius);
        theme.selection_highlight.set_source(cr);
        let _ = cr.fill();
    }

    // Column positions.
    let badge_x = card.x + layout.padding;
    let mut next_x = badge_x + layout.badge_width + layout.column_gap;

    // Badge background color based on match state.
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
    rounded_rect(
        cr,
        badge_x,
        badge_y,
        layout.badge_width,
        layout.badge_height,
        layout.badge_radius,
    );
    badge_bg.set_source(cr);
    let _ = cr.fill();

    // Badge text (centered, uppercase, semibold).
    let pango_layout = pangocairo::functions::create_layout(cr);
    let mut font = gtk4::pango::FontDescription::new();
    font.set_family("Sans");
    font.set_weight(gtk4::pango::Weight::Semibold);
    font.set_absolute_size(layout.text_size * gtk4::pango::SCALE as f64);
    pango_layout.set_font_description(Some(&font));

    let hint_text = row.hint.to_uppercase();
    pango_layout.set_text(&hint_text);
    let (tw, th) = pango_layout.pixel_size();
    let tx = badge_x + (layout.badge_width - tw as f64) / 2.0;
    let ty = badge_y + (layout.badge_height - th as f64) / 2.0;
    cr.move_to(tx, ty);
    badge_text_color.set_source(cr);
    pangocairo::functions::show_layout(cr, &pango_layout);

    // App name column.
    if show_app_id {
        let app_name = extract_app_name(row.app_id);
        font.set_weight(gtk4::pango::Weight::Normal);
        pango_layout.set_font_description(Some(&font));
        pango_layout.set_text(&app_name);
        pango_layout.set_width((layout.app_column_width * gtk4::pango::SCALE as f64) as i32);
        pango_layout.set_ellipsize(gtk4::pango::EllipsizeMode::End);

        let (_, th) = pango_layout.pixel_size();
        let ty = row_y + (layout.row_height - th as f64) / 2.0;
        cr.move_to(next_x, ty);
        theme.text_primary.set_source(cr);
        pangocairo::functions::show_layout(cr, &pango_layout);

        // Reset width constraint.
        pango_layout.set_width(-1);
        next_x += layout.app_column_width + layout.column_gap;
    }

    // Title column.
    if show_title {
        let title_max = card.x + card.width - next_x - layout.padding;
        if title_max > 50.0 {
            pango_layout.set_text(row.title);
            pango_layout.set_width((title_max * gtk4::pango::SCALE as f64) as i32);
            pango_layout.set_ellipsize(gtk4::pango::EllipsizeMode::End);

            let (_, th) = pango_layout.pixel_size();
            let ty = row_y + (layout.row_height - th as f64) / 2.0;
            cr.move_to(next_x, ty);
            theme.text_secondary.set_source(cr);
            pangocairo::functions::show_layout(cr, &pango_layout);

            pango_layout.set_width(-1);
        }
    }
}

fn draw_input_indicator(
    cr: &gtk4::cairo::Context,
    card: &CardRect,
    input: &str,
    layout: &Layout,
    theme: &OverlayTheme,
) {
    let pango_layout = pangocairo::functions::create_layout(cr);
    let mut font = gtk4::pango::FontDescription::new();
    font.set_family("Sans");
    font.set_absolute_size(layout.text_size * gtk4::pango::SCALE as f64);
    pango_layout.set_font_description(Some(&font));

    let text = format!("\u{203a} {input}");
    pango_layout.set_text(&text);
    let (tw, th) = pango_layout.pixel_size();

    let pill_pad_h = layout.padding;
    let pill_pad_v = layout.padding / 2.0;
    let pill_w = tw as f64 + pill_pad_h * 2.0;
    let pill_h = th as f64 + pill_pad_v * 2.0;
    let pill_x = card.x + (card.width - pill_w) / 2.0;
    let pill_y = card.y + card.height + layout.padding;

    // Fully rounded pill.
    rounded_rect(cr, pill_x, pill_y, pill_w, pill_h, pill_h / 2.0);
    theme.badge_background.set_source(cr);
    let _ = cr.fill();

    cr.move_to(pill_x + pill_pad_h, pill_y + pill_pad_v);
    theme.text_primary.set_source(cr);
    pangocairo::functions::show_layout(cr, &pango_layout);
}

fn draw_no_matches(
    cr: &gtk4::cairo::Context,
    width: f64,
    height: f64,
    input: &str,
    layout: &Layout,
    theme: &OverlayTheme,
) {
    let pango_layout = pangocairo::functions::create_layout(cr);
    let mut font = gtk4::pango::FontDescription::new();
    font.set_family("Sans");
    font.set_absolute_size(layout.text_size * 1.2 * gtk4::pango::SCALE as f64);
    pango_layout.set_font_description(Some(&font));

    let message = format!("No matches for '{input}'");
    pango_layout.set_text(&message);
    let (tw, th) = pango_layout.pixel_size();

    let pad = layout.padding * 2.0;
    let cw = tw as f64 + pad * 2.0;
    let ch = th as f64 + pad * 2.0;
    let cx = (width - cw) / 2.0;
    let cy = (height - ch) / 2.0;

    rounded_rect(cr, cx, cy, cw, ch, layout.corner_radius);
    theme.card_background.set_source(cr);
    let _ = cr.fill();

    rounded_rect(cr, cx, cy, cw, ch, layout.corner_radius);
    theme.card_border.set_source(cr);
    cr.set_line_width(layout.border_width);
    let _ = cr.stroke();

    cr.move_to(cx + pad, cy + pad);
    theme.text_primary.set_source(cr);
    pangocairo::functions::show_layout(cr, &pango_layout);
}

fn draw_launch_staged(
    cr: &gtk4::cairo::Context,
    width: f64,
    height: f64,
    command: &str,
    layout: &Layout,
    theme: &OverlayTheme,
) {
    let pango_layout = pangocairo::functions::create_layout(cr);
    let mut font = gtk4::pango::FontDescription::new();
    font.set_family("Sans");
    font.set_absolute_size(layout.text_size * 1.2 * gtk4::pango::SCALE as f64);
    pango_layout.set_font_description(Some(&font));

    let message = format!("Launch {command}");
    pango_layout.set_text(&message);
    let (tw, th) = pango_layout.pixel_size();

    let pad = layout.padding * 2.0;
    let cw = tw as f64 + pad * 2.0;
    let ch = th as f64 + pad * 2.0;
    let cx = (width - cw) / 2.0;
    let cy = (height - ch) / 2.0;

    rounded_rect(cr, cx, cy, cw, ch, layout.corner_radius);
    theme.card_background.set_source(cr);
    let _ = cr.fill();

    rounded_rect(cr, cx, cy, cw, ch, layout.corner_radius);
    theme.badge_matched_background.set_source(cr);
    cr.set_line_width(layout.border_width * 2.0);
    let _ = cr.stroke();

    cr.move_to(cx + pad, cy + pad);
    theme.text_primary.set_source(cr);
    pangocairo::functions::show_layout(cr, &pango_layout);
}

// ---------------------------------------------------------------------------
// Status / error toasts
// ---------------------------------------------------------------------------

/// Draw a centered status message (e.g. "Launching...").
pub fn draw_status_toast(
    cr: &gtk4::cairo::Context,
    width: f64,
    height: f64,
    message: &str,
    theme: &OverlayTheme,
) {
    let layout = Layout::new(1.0);

    cr.set_operator(gtk4::cairo::Operator::Source);
    cr.set_source_rgba(0.0, 0.0, 0.0, 0.0);
    let _ = cr.paint();
    cr.set_operator(gtk4::cairo::Operator::Over);

    // Screen border.
    let bw = theme.border_width * 2.0;
    let half = bw / 2.0;
    rounded_rect(cr, half, half, width - bw, height - bw, theme.corner_radius);
    theme.border_color.set_source(cr);
    cr.set_line_width(bw);
    let _ = cr.stroke();

    let pango_layout = pangocairo::functions::create_layout(cr);
    let mut font = gtk4::pango::FontDescription::new();
    font.set_family("Sans");
    font.set_weight(gtk4::pango::Weight::Normal);
    font.set_absolute_size(layout.text_size * 1.2 * gtk4::pango::SCALE as f64);
    pango_layout.set_font_description(Some(&font));
    pango_layout.set_text(message);
    let (tw, th) = pango_layout.pixel_size();

    let pad = layout.padding * 2.0;
    let cw = tw as f64 + pad * 2.0;
    let ch = th as f64 + pad * 2.0;
    let cx = (width - cw) / 2.0;
    let cy = (height - ch) / 2.0;

    rounded_rect(cr, cx, cy, cw, ch, layout.corner_radius);
    theme.card_background.set_source(cr);
    let _ = cr.fill();

    rounded_rect(cr, cx, cy, cw, ch, layout.corner_radius);
    theme.card_border.set_source(cr);
    cr.set_line_width(layout.border_width);
    let _ = cr.stroke();

    cr.move_to(cx + pad, cy + pad);
    theme.text_secondary.set_source(cr);
    pangocairo::functions::show_layout(cr, &pango_layout);
}

/// Draw a centered error message with red accent border.
pub fn draw_error_toast(
    cr: &gtk4::cairo::Context,
    width: f64,
    height: f64,
    message: &str,
    theme: &OverlayTheme,
) {
    let layout = Layout::new(1.0);
    let error_border = Color::rgba(239, 68, 68, 255); // red-500

    cr.set_operator(gtk4::cairo::Operator::Source);
    cr.set_source_rgba(0.0, 0.0, 0.0, 0.0);
    let _ = cr.paint();
    cr.set_operator(gtk4::cairo::Operator::Over);

    // Screen border — red to indicate error.
    let bw = theme.border_width * 2.0;
    let half = bw / 2.0;
    rounded_rect(cr, half, half, width - bw, height - bw, theme.corner_radius);
    error_border.set_source(cr);
    cr.set_line_width(bw);
    let _ = cr.stroke();

    // Build display text: header + detail.
    let display = format!("Launch failed\n\n{message}\n\nPress any key to dismiss");

    let pango_layout = pangocairo::functions::create_layout(cr);
    let mut font = gtk4::pango::FontDescription::new();
    font.set_family("Sans");
    font.set_absolute_size(layout.text_size * 1.1 * gtk4::pango::SCALE as f64);
    pango_layout.set_font_description(Some(&font));
    pango_layout.set_text(&display);
    pango_layout.set_alignment(gtk4::pango::Alignment::Center);
    let max_width = (width * 0.6).min(500.0);
    pango_layout.set_width((max_width * gtk4::pango::SCALE as f64) as i32);
    pango_layout.set_wrap(gtk4::pango::WrapMode::WordChar);
    let (tw, th) = pango_layout.pixel_size();

    let pad = layout.padding * 2.0;
    let cw = tw as f64 + pad * 2.0;
    let ch = th as f64 + pad * 2.0;
    let cx = (width - cw) / 2.0;
    let cy = (height - ch) / 2.0;

    rounded_rect(cr, cx, cy, cw, ch, layout.corner_radius);
    theme.card_background.set_source(cr);
    let _ = cr.fill();

    rounded_rect(cr, cx, cy, cw, ch, layout.corner_radius);
    error_border.set_source(cr);
    cr.set_line_width(layout.border_width * 1.5);
    let _ = cr.stroke();

    cr.move_to(cx + pad, cy + pad);
    theme.text_primary.set_source(cr);
    pangocairo::functions::show_layout(cr, &pango_layout);
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
}
