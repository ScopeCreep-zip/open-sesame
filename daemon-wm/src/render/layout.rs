//! Card geometry and the layout metrics it is built from.

use super::{Columns, real};

/// Material Design 4-point grid metrics (logical pixels at 1x scale).
const PADDING: f32 = 20.0;
const ROW_HEIGHT: f32 = 48.0;
const ROW_SPACING: f32 = 8.0;
const BADGE_WIDTH: f32 = 48.0;
const BADGE_HEIGHT: f32 = 32.0;
const BADGE_RADIUS: f32 = 8.0;
const APP_COLUMN_WIDTH: f32 = 180.0;
const TEXT_SIZE: f32 = 16.0;
const COLUMN_GAP: f32 = 16.0;
/// The card and input-pill outline.
const BORDER_WIDTH: f32 = 1.0;
/// The card corner radius without a desktop theme.
pub const CORNER_RADIUS: f32 = 16.0;

/// Narrowest title column the card reserves room for.
const MIN_TITLE_WIDTH: f32 = 200.0;
/// The card's width bounds, and its widest fraction of the screen.
const MIN_CARD_WIDTH: f32 = 400.0;
const MAX_CARD_WIDTH: f32 = 700.0;
const MAX_CARD_FRACTION: f32 = 0.9;

/// A rectangle in buffer pixels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

impl Rect {
    /// The `width` x `height` rectangle centered in a `screen_w` x
    /// `screen_h` area.
    #[must_use]
    pub fn centered(width: f32, height: f32, screen_w: f32, screen_h: f32) -> Self {
        Self {
            x: (screen_w - width) / 2.0,
            y: (screen_h - height) / 2.0,
            width,
            height,
        }
    }

    /// This rectangle with every edge divided by `scale`: buffer pixels
    /// to surface-local (logical) coordinates.
    #[must_use]
    pub fn unscaled(self, scale: f32) -> Self {
        Self {
            x: self.x / scale,
            y: self.y / scale,
            width: self.width / scale,
            height: self.height / scale,
        }
    }
}

/// Layout metrics scaled to the output's buffer scale.
#[derive(Debug, Clone, Copy)]
pub struct Layout {
    pub padding: f32,
    pub row_height: f32,
    pub row_spacing: f32,
    pub badge_width: f32,
    pub badge_height: f32,
    pub badge_radius: f32,
    pub app_column_width: f32,
    pub text_size: f32,
    pub corner_radius: f32,
    pub column_gap: f32,
    pub border_width: f32,
}

impl Layout {
    /// The metrics at `scale`, with the theme's logical `corner_radius`.
    #[must_use]
    pub fn new(scale: f32, corner_radius: f32) -> Self {
        Self {
            padding: PADDING * scale,
            row_height: ROW_HEIGHT * scale,
            row_spacing: ROW_SPACING * scale,
            badge_width: BADGE_WIDTH * scale,
            badge_height: BADGE_HEIGHT * scale,
            badge_radius: BADGE_RADIUS * scale,
            app_column_width: APP_COLUMN_WIDTH * scale,
            text_size: TEXT_SIZE * scale,
            corner_radius: corner_radius * scale,
            column_gap: COLUMN_GAP * scale,
            border_width: BORDER_WIDTH * scale,
        }
    }

    /// The top of row `index` in a card whose top is `card_y`.
    #[must_use]
    pub fn row_y(&self, card_y: f32, index: usize) -> f32 {
        card_y + self.padding + real(index) * (self.row_height + self.row_spacing)
    }

    /// The card centered on a `screen_w` x `screen_h` screen for `rows`
    /// rows (at least one row's height) of `columns`.
    #[must_use]
    pub fn card(&self, rows: usize, screen_w: f32, screen_h: f32, columns: Columns) -> Rect {
        let mut content_width = self.padding * 2.0 + self.badge_width + self.column_gap;
        if columns.app_id {
            content_width += self.app_column_width + self.column_gap;
        }
        if columns.title {
            content_width += MIN_TITLE_WIDTH;
        }
        let max_width = (screen_w * MAX_CARD_FRACTION).min(MAX_CARD_WIDTH);
        let width = content_width.max(MIN_CARD_WIDTH).min(max_width);
        let height = self.row_y(0.0, rows.max(1)) - self.row_spacing + self.padding;
        Rect::centered(width, height, screen_w, screen_h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOTH: Columns = Columns {
        app_id: true,
        title: true,
    };

    #[test]
    fn cards_are_centered_and_grow_by_a_row_each() {
        let layout = Layout::new(1.0, CORNER_RADIUS);
        let one = layout.card(1, 1920.0, 1080.0, BOTH);
        let two = layout.card(2, 1920.0, 1080.0, BOTH);
        assert!((one.x * 2.0 + one.width - 1920.0).abs() < f32::EPSILON);
        assert!((two.height - one.height - (ROW_HEIGHT + ROW_SPACING)).abs() < f32::EPSILON);
        assert_eq!(
            layout.card(0, 1920.0, 1080.0, BOTH),
            one,
            "an empty card keeps one row"
        );
    }

    #[test]
    fn metrics_scale_and_rects_unscale() {
        let layout = Layout::new(2.0, 10.0);
        assert!((layout.corner_radius - 20.0).abs() < f32::EPSILON);
        assert!(
            (layout.border_width - 2.0).abs() < f32::EPSILON,
            "outlines scale too"
        );
        let card = layout.card(3, 3840.0, 2160.0, BOTH);
        let logical = card.unscaled(2.0);
        assert!((logical.width * 2.0 - card.width).abs() < f32::EPSILON);
        assert!((logical.x * 2.0 - card.x).abs() < f32::EPSILON);
    }
}
