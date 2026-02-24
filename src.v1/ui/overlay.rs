//! Overlay window rendering
//!
//! Renders the window switcher overlay with proper layout and alignment.
//!
//! # Border Lifecycle
//!
//! The screen-edge border is the **first** visual element rendered and remains
//! visible throughout the entire application lifecycle until exit. It provides
//! immediate visual feedback that sesame is active.
//!
//! The popup card (window list) appears on top of the border after `overlay_delay`.

use crate::config::Config;
use crate::core::WindowHint;
use crate::render::{Color, FontWeight, TextRenderer, primitives};
use crate::ui::Theme;
use tiny_skia::Pixmap;

// Layout constants based on Material Design spacing scale
// Reference: https://material.io/design/layout/spacing-methods.html

/// Base padding for card edges (Material Design 4-point grid)
const BASE_PADDING: f32 = 20.0;

/// Row height for touch targets (Material Design minimum 48dp)
const BASE_ROW_HEIGHT: f32 = 48.0;

/// Spacing between rows (Material Design dense spacing)
const BASE_ROW_SPACING: f32 = 8.0;

/// Badge width for 2-character hints
const BASE_BADGE_WIDTH: f32 = 48.0;

/// Badge height for comfortable reading
const BASE_BADGE_HEIGHT: f32 = 32.0;

/// Border radius for modern aesthetic
const BASE_BORDER_RADIUS: f32 = 8.0;

/// App name column width (fits ~20 characters)
const BASE_APP_COLUMN_WIDTH: f32 = 180.0;

/// Text size for body text (readable at 1080p)
const BASE_TEXT_SIZE: f32 = 16.0;

/// Border width for visibility without dominance
const BASE_BORDER_WIDTH: f32 = 3.0;

/// Corner radius for card (Material Design rounded corners)
const BASE_CORNER_RADIUS: f32 = 16.0;

/// Gap between columns for visual separation
const BASE_COLUMN_GAP: f32 = 16.0;

/// Layout configuration calculated for the current display
struct Layout {
    /// Scaled card padding
    padding: f32,
    /// Scaled row height
    row_height: f32,
    /// Scaled row spacing
    row_spacing: f32,
    /// Scaled badge width
    badge_width: f32,
    /// Scaled badge height
    badge_height: f32,
    /// Scaled badge corner radius
    badge_radius: f32,
    /// Scaled app name column width
    app_column_width: f32,
    /// Scaled text size
    text_size: f32,
    /// Scaled badge text size
    badge_text_size: f32,
    /// Scaled border width
    border_width: f32,
    /// Scaled corner radius
    corner_radius: f32,
    /// Column gap between elements
    column_gap: f32,
}

impl Layout {
    /// Create layout scaled for the given display parameters
    fn new(scale: f32) -> Self {
        Self {
            padding: BASE_PADDING * scale,
            row_height: BASE_ROW_HEIGHT * scale,
            row_spacing: BASE_ROW_SPACING * scale,
            badge_width: BASE_BADGE_WIDTH * scale,
            badge_height: BASE_BADGE_HEIGHT * scale,
            badge_radius: BASE_BORDER_RADIUS * scale,
            app_column_width: BASE_APP_COLUMN_WIDTH * scale,
            text_size: BASE_TEXT_SIZE * scale,
            badge_text_size: BASE_TEXT_SIZE * scale,
            border_width: BASE_BORDER_WIDTH * scale,
            corner_radius: BASE_CORNER_RADIUS * scale,
            column_gap: BASE_COLUMN_GAP * scale,
        }
    }
}

/// Phase of overlay display
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayPhase {
    /// Initial delay - show border highlight only
    Initial,
    /// Full overlay with window list
    Full,
}

/// Overlay renderer
pub struct Overlay {
    /// Display width in pixels
    width: u32,
    /// Display height in pixels
    height: u32,
    /// Scale factor for HiDPI
    scale: f32,
    /// Theme for rendering
    theme: Theme,
    /// Calculated layout
    layout: Layout,
}

impl Overlay {
    /// Create a new overlay renderer
    pub fn new(width: u32, height: u32, scale: f32, config: &Config) -> Self {
        // Clamp scale to reasonable range to prevent crashes/OOM from invalid values
        let scale = scale.clamp(0.5, 4.0);

        Self {
            width,
            height,
            scale,
            theme: Theme::from_config(config),
            layout: Layout::new(scale),
        }
    }

    /// Validate and compute scaled dimensions
    ///
    /// Returns `None` if dimensions are invalid (zero or too large).
    fn scaled_dimensions(&self) -> Option<(u32, u32)> {
        // Use checked arithmetic to prevent overflow on extreme inputs
        let scaled_width = (self.width as f32 * self.scale).min(u32::MAX as f32) as u32;
        let scaled_height = (self.height as f32 * self.scale).min(u32::MAX as f32) as u32;

        // Validates dimensions are within acceptable bounds (non-zero, maximum 16384px)
        if scaled_width == 0 || scaled_height == 0 || scaled_width > 16384 || scaled_height > 16384
        {
            tracing::warn!(
                "Invalid overlay dimensions: {}x{} (from {}x{} @ {}x scale)",
                scaled_width,
                scaled_height,
                self.width,
                self.height,
                self.scale
            );
            return None;
        }

        Some((scaled_width, scaled_height))
    }

    /// Render the screen-edge border highlight
    ///
    /// This is the foundational visual element that remains visible throughout
    /// the entire overlay lifecycle. It's rendered first and stays until exit.
    fn render_screen_border(&self, pixmap: &mut Pixmap) {
        let border_width = self.layout.border_width * 2.0;
        let half_border = border_width / 2.0;
        let width = pixmap.width() as f32;
        let height = pixmap.height() as f32;

        primitives::stroke_rounded_rect(
            pixmap,
            half_border,
            half_border,
            width - border_width,
            height - border_width,
            self.layout.corner_radius,
            self.theme.card_border,
            border_width,
        );
    }

    /// Render the initial phase (border highlight only, transparent center)
    pub fn render_initial(&self) -> Option<Pixmap> {
        let (scaled_width, scaled_height) = self.scaled_dimensions()?;

        let mut pixmap = Pixmap::new(scaled_width, scaled_height)?;
        // Background remains transparent

        // Draw border highlight around the entire screen
        self.render_screen_border(&mut pixmap);

        Some(pixmap)
    }

    /// Render the full overlay with window list
    ///
    /// The screen-edge border is **always** rendered first, then the popup card
    /// is rendered on top. This ensures the border remains visible throughout.
    pub fn render_full(
        &self,
        hints: &[WindowHint],
        input: &str,
        selection: usize,
    ) -> Option<Pixmap> {
        let (scaled_width, scaled_height) = self.scaled_dimensions()?;

        let mut pixmap = Pixmap::new(scaled_width, scaled_height)?;
        // Background remains transparent

        // Renders the screen border first as the foundational visual element
        self.render_screen_border(&mut pixmap);

        // Filter visible hints based on input
        let visible_hints: Vec<_> = hints
            .iter()
            .filter(|h| input.is_empty() || h.hint.matches_input(input))
            .collect();

        if visible_hints.is_empty() {
            self.render_no_matches_card(&mut pixmap, input);
            return Some(pixmap);
        }

        // Clamp selection to valid range to prevent out-of-bounds access
        let selection = selection.min(visible_hints.len().saturating_sub(1));

        // Calculate card dimensions
        let card = self.calculate_card_dimensions(
            &visible_hints,
            scaled_width as f32,
            scaled_height as f32,
        );

        // Draw card background
        primitives::fill_rounded_rect(
            &mut pixmap,
            card.x,
            card.y,
            card.width,
            card.height,
            self.layout.corner_radius,
            self.theme.card_background,
        );

        // Draw card border
        primitives::stroke_rounded_rect(
            &mut pixmap,
            card.x,
            card.y,
            card.width,
            card.height,
            self.layout.corner_radius,
            self.theme.card_border,
            self.layout.border_width,
        );

        // Draw each hint row
        for (i, hint) in visible_hints.iter().enumerate() {
            let row_y = card.y
                + self.layout.padding
                + i as f32 * (self.layout.row_height + self.layout.row_spacing);
            let is_selected = i == selection;
            self.render_hint_row(&mut pixmap, &card, row_y, hint, input, is_selected);
        }

        // Draw input indicator if typing
        if !input.is_empty() {
            self.render_input_indicator(&mut pixmap, &card, input);
        }

        Some(pixmap)
    }

    /// Calculate card position and dimensions
    fn calculate_card_dimensions(
        &self,
        hints: &[&WindowHint],
        screen_width: f32,
        screen_height: f32,
    ) -> CardRect {
        // Calculate required width based on content
        let min_title_width = 200.0 * self.scale;
        let content_width = self.layout.padding * 2.0
            + self.layout.badge_width
            + self.layout.column_gap
            + self.layout.app_column_width
            + self.layout.column_gap
            + min_title_width;

        // Card width constrained to content size, maximum 90% screen width or 700px
        let max_width = (screen_width * 0.9).min(700.0 * self.scale);
        let card_width = content_width.max(400.0 * self.scale).min(max_width);

        // Card height calculated from number of hint rows
        let content_height = hints.len() as f32
            * (self.layout.row_height + self.layout.row_spacing)
            - self.layout.row_spacing; // Excludes trailing spacing
        let card_height = content_height + self.layout.padding * 2.0;

        // Center the card
        let card_x = (screen_width - card_width) / 2.0;
        let card_y = (screen_height - card_height) / 2.0;

        CardRect {
            x: card_x,
            y: card_y,
            width: card_width,
            height: card_height,
        }
    }

    /// Render a single hint row with proper column alignment
    fn render_hint_row(
        &self,
        pixmap: &mut Pixmap,
        card: &CardRect,
        row_y: f32,
        hint: &WindowHint,
        input: &str,
        is_selected: bool,
    ) {
        let layout = &self.layout;

        // Determine match state
        let is_exact_match = !input.is_empty() && hint.hint.equals_input(input);
        let is_partial_match =
            !input.is_empty() && hint.hint.matches_input(input) && !is_exact_match;

        // Column positions
        let badge_x = card.x + layout.padding;
        let app_x = badge_x + layout.badge_width + layout.column_gap;
        let title_x = app_x + layout.app_column_width + layout.column_gap;
        let title_max_width = card.x + card.width - title_x - layout.padding;

        // Draw selection highlight background
        if is_selected {
            let highlight_x = card.x + layout.padding / 2.0;
            let highlight_width = card.width - layout.padding;
            primitives::fill_rounded_rect(
                pixmap,
                highlight_x,
                row_y,
                highlight_width,
                layout.row_height,
                layout.badge_radius,
                Color::rgba(255, 255, 255, 25), // Semi-transparent white highlight
            );
        }

        // === BADGE COLUMN ===
        let badge_y = row_y + (layout.row_height - layout.badge_height) / 2.0;

        let badge_bg = if is_exact_match {
            self.theme.badge_matched_background
        } else if is_partial_match {
            Color::rgba(
                self.theme.badge_background.r.saturating_add(30),
                self.theme.badge_background.g.saturating_add(30),
                self.theme.badge_background.b.saturating_add(30),
                self.theme.badge_background.a,
            )
        } else {
            self.theme.badge_background
        };

        // Draw badge background
        primitives::fill_rounded_rect(
            pixmap,
            badge_x,
            badge_y,
            layout.badge_width,
            layout.badge_height,
            layout.badge_radius,
            badge_bg,
        );

        // Renders badge text centered with semibold weight and uppercase styling
        let hint_text = hint.hint.as_string().to_uppercase();
        let hint_text_width = TextRenderer::measure_text_weighted(
            &hint_text,
            layout.badge_text_size,
            FontWeight::Semibold,
        );
        let hint_text_height = TextRenderer::line_height(layout.badge_text_size);
        let hint_text_x = badge_x + (layout.badge_width - hint_text_width) / 2.0;
        let hint_text_y = badge_y + (layout.badge_height + hint_text_height) / 2.0
            - TextRenderer::descent(layout.badge_text_size);

        let badge_text_color = if is_exact_match {
            self.theme.badge_matched_text
        } else {
            self.theme.badge_text
        };

        TextRenderer::render_text_weighted(
            pixmap,
            &hint_text,
            hint_text_x,
            hint_text_y,
            layout.badge_text_size,
            badge_text_color.to_skia(),
            FontWeight::Semibold,
        );

        // === APP NAME COLUMN ===
        let text_height = TextRenderer::line_height(layout.text_size);
        let text_baseline_y = row_y + (layout.row_height + text_height) / 2.0
            - TextRenderer::descent(layout.text_size);

        let app_name = extract_app_name(&hint.app_id);
        let truncated_app =
            TextRenderer::truncate_to_width(&app_name, layout.app_column_width, layout.text_size);

        TextRenderer::render_text(
            pixmap,
            &truncated_app,
            app_x,
            text_baseline_y,
            layout.text_size,
            self.theme.text_primary.to_skia(),
        );

        // === TITLE COLUMN ===
        if title_max_width > 50.0 {
            let truncated_title =
                TextRenderer::truncate_to_width(&hint.title, title_max_width, layout.text_size);

            TextRenderer::render_text(
                pixmap,
                &truncated_title,
                title_x,
                text_baseline_y,
                layout.text_size,
                self.theme.text_secondary.to_skia(),
            );
        }
    }

    /// Render "no matches" card (border already rendered by caller)
    fn render_no_matches_card(&self, pixmap: &mut Pixmap, input: &str) {
        let width = pixmap.width() as f32;
        let height = pixmap.height() as f32;

        let message = format!("No matches for '{}'", input);
        let text_size = self.layout.text_size * 1.2;
        let text_width = TextRenderer::measure_text(&message, text_size);
        let text_height = TextRenderer::line_height(text_size);

        // Small card for the message
        let card_padding = self.layout.padding * 2.0;
        let card_width = text_width + card_padding * 2.0;
        let card_height = text_height + card_padding * 2.0;
        let card_x = (width - card_width) / 2.0;
        let card_y = (height - card_height) / 2.0;

        primitives::fill_rounded_rect(
            pixmap,
            card_x,
            card_y,
            card_width,
            card_height,
            self.layout.corner_radius,
            self.theme.card_background,
        );

        primitives::stroke_rounded_rect(
            pixmap,
            card_x,
            card_y,
            card_width,
            card_height,
            self.layout.corner_radius,
            self.theme.card_border,
            self.layout.border_width,
        );

        let text_x = card_x + card_padding;
        let text_y = card_y + card_padding + TextRenderer::ascent(text_size);

        TextRenderer::render_text(
            pixmap,
            &message,
            text_x,
            text_y,
            text_size,
            self.theme.text_primary.to_skia(),
        );
    }

    /// Render input indicator below the card
    fn render_input_indicator(&self, pixmap: &mut Pixmap, card: &CardRect, input: &str) {
        let text = format!("› {}", input);
        let text_size = self.layout.text_size;
        let text_width = TextRenderer::measure_text(&text, text_size);
        let text_height = TextRenderer::line_height(text_size);

        // Small pill below the card
        let pill_padding_h = self.layout.padding;
        let pill_padding_v = self.layout.padding / 2.0;
        let pill_width = text_width + pill_padding_h * 2.0;
        let pill_height = text_height + pill_padding_v * 2.0;
        let pill_x = card.x + (card.width - pill_width) / 2.0;
        let pill_y = card.y + card.height + self.layout.padding;

        primitives::fill_rounded_rect(
            pixmap,
            pill_x,
            pill_y,
            pill_width,
            pill_height,
            pill_height / 2.0, // Fully rounded ends
            self.theme.badge_background,
        );

        let text_x = pill_x + pill_padding_h;
        let text_y = pill_y + pill_padding_v + TextRenderer::ascent(text_size);

        TextRenderer::render_text(
            pixmap,
            &text,
            text_x,
            text_y,
            text_size,
            self.theme.text_primary.to_skia(),
        );
    }
}

/// Rectangle for card positioning
struct CardRect {
    x: f32,
    y: f32,
    width: f32,
    height: f32,
}

/// Extract a friendly app name from app_id
fn extract_app_name(app_id: &str) -> String {
    // Handle reverse-DNS style (com.mitchellh.ghostty -> ghostty)
    let name = app_id.split('.').next_back().unwrap_or(app_id);

    // Capitalize first letter
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
    fn test_overlay_creation() {
        let config = Config::default();
        let overlay = Overlay::new(1920, 1080, 1.0, &config);
        assert_eq!(overlay.width, 1920);
        assert_eq!(overlay.height, 1080);
    }

    #[test]
    fn test_overlay_phase_eq() {
        assert_eq!(OverlayPhase::Initial, OverlayPhase::Initial);
        assert_ne!(OverlayPhase::Initial, OverlayPhase::Full);
    }

    #[test]
    fn test_extract_app_name() {
        assert_eq!(extract_app_name("com.mitchellh.ghostty"), "Ghostty");
        assert_eq!(extract_app_name("firefox"), "Firefox");
        assert_eq!(extract_app_name("org.mozilla.firefox"), "Firefox");
        assert_eq!(extract_app_name("microsoft-edge"), "Microsoft-edge");
    }
}
