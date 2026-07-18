//! Card geometry computation and layout constants.

/// Material Design 4-point grid constants (logical pixels at 1x scale).
pub const BASE_PADDING: f32 = 20.0;
pub const BASE_ROW_HEIGHT: f32 = 48.0;
pub const BASE_ROW_SPACING: f32 = 8.0;
pub const BASE_BADGE_WIDTH: f32 = 48.0;
pub const BASE_BADGE_HEIGHT: f32 = 32.0;
pub const BASE_BADGE_RADIUS: f32 = 8.0;
pub const BASE_APP_COLUMN_WIDTH: f32 = 180.0;
pub const BASE_TEXT_SIZE: f32 = 16.0;
pub const BASE_BORDER_WIDTH: f32 = 3.0;
pub const BASE_CORNER_RADIUS: f32 = 16.0;
pub const BASE_COLUMN_GAP: f32 = 16.0;

/// Scaled layout values for a given HiDPI factor.
pub struct Layout {
    pub padding: f32,
    pub row_height: f32,
    pub row_spacing: f32,
    pub badge_width: f32,
    pub badge_height: f32,
    pub badge_radius: f32,
    pub app_column_width: f32,
    pub text_size: f32,
    pub border_width: f32,
    pub corner_radius: f32,
    pub column_gap: f32,
}

impl Layout {
    pub fn new(scale: f32) -> Self {
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

/// Computed card rectangle in pixel coordinates.
pub struct CardRect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

/// Calculate centered card geometry for N visible rows.
pub fn calculate_card(
    row_count: usize,
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

    let rows = row_count.max(1);
    let content_height =
        rows as f32 * (layout.row_height + layout.row_spacing) - layout.row_spacing;
    let card_height = content_height + layout.padding * 2.0;

    CardRect {
        x: (screen_w - card_width) / 2.0,
        y: (screen_h - card_height) / 2.0,
        width: card_width,
        height: card_height,
    }
}
