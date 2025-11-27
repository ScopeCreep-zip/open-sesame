//! Theme definitions for UI rendering
//!
//! Integrates with COSMIC desktop theme when available, falling back to
//! user config or sensible defaults.

use crate::config::Config;
use crate::platform::CosmicTheme;
use crate::render::Color;

/// Theme for overlay rendering
#[derive(Debug, Clone)]
pub struct Theme {
    /// Background overlay color (semi-transparent)
    pub background: Color,
    /// Card background color
    pub card_background: Color,
    /// Card border color
    pub card_border: Color,
    /// Primary text color
    pub text_primary: Color,
    /// Secondary text color (for titles)
    pub text_secondary: Color,
    /// Hint badge background
    pub badge_background: Color,
    /// Hint badge text color
    pub badge_text: Color,
    /// Matched hint badge background
    pub badge_matched_background: Color,
    /// Matched hint badge text color
    pub badge_matched_text: Color,
    /// Border width
    pub border_width: f32,
    /// Corner radius
    pub corner_radius: f32,
}

impl Theme {
    /// Create a theme from COSMIC desktop configuration
    ///
    /// This provides native integration with COSMIC's theming system,
    /// automatically matching dark/light mode and accent colors.
    ///
    /// COSMIC uses a layered color system with guaranteed contrast:
    /// - Container level (base/on): For surfaces - `on` contrasts with `base`
    /// - Component level (component.base/on): For buttons/inputs inside containers
    ///
    /// The overlay popup implements a "primary" container pattern:
    /// - primary.base for the card background
    /// - primary.on for text (designed for contrast on primary.base)
    /// - primary.component.* for badge elements (interactive-like)
    /// - accent.* for highlights and matched states
    pub fn from_cosmic() -> Option<Self> {
        let cosmic = CosmicTheme::load()?;

        // Container-level colors for the card surface
        // These are the main surface colors with guaranteed text contrast
        let bg = cosmic.background.base.to_rgba();
        let primary_base = cosmic.primary.base.to_rgba();
        let primary_on = cosmic.primary.on.to_rgba();

        // Secondary component colors for badge elements
        // Using secondary.component (not primary.component) for better contrast
        // against the primary.base card background
        let badge_base = cosmic.secondary.component.base.to_rgba();
        let badge_on = cosmic.secondary.component.on.to_rgba();

        // Accent colors for highlights and selection states
        let accent_base = cosmic.accent.base.to_rgba();
        let accent_on = cosmic.accent.on.to_rgba();

        // Use COSMIC's corner radii (radius_m is typical for popups)
        let corner_radius = cosmic.corner_radii.radius_m[0];

        tracing::info!(
            "Loaded COSMIC {} theme",
            if cosmic.is_dark { "dark" } else { "light" }
        );

        Some(Self {
            // Semi-transparent background using COSMIC's background color
            background: Color::rgba(bg.0, bg.1, bg.2, 200),
            // Card uses primary container base (surface color)
            card_background: Color::rgba(primary_base.0, primary_base.1, primary_base.2, 245),
            // Border uses accent color for visual pop
            card_border: Color::rgba(accent_base.0, accent_base.1, accent_base.2, 255),
            // Text uses primary.on (designed for contrast on primary.base)
            text_primary: Color::rgba(primary_on.0, primary_on.1, primary_on.2, primary_on.3),
            // Secondary text slightly dimmed but still readable
            text_secondary: Color::rgba(
                primary_on.0,
                primary_on.1,
                primary_on.2,
                (primary_on.3 as f32 * 0.7) as u8,
            ),
            // Badge uses secondary.component colors for contrast against primary.base
            badge_background: Color::rgba(badge_base.0, badge_base.1, badge_base.2, 255),
            badge_text: Color::rgba(badge_on.0, badge_on.1, badge_on.2, badge_on.3),
            // Matched badge uses accent for visual emphasis
            badge_matched_background: Color::rgba(accent_base.0, accent_base.1, accent_base.2, 255),
            badge_matched_text: Color::rgba(accent_on.0, accent_on.1, accent_on.2, accent_on.3),
            border_width: 2.0,
            corner_radius,
        })
    }

    /// Create a theme from user configuration
    ///
    /// This is used when COSMIC theme is not available or when user
    /// has explicit color overrides in their config.
    pub fn from_config(config: &Config) -> Self {
        // Try COSMIC theme first, then fall back to config
        if let Some(cosmic_theme) = Self::from_cosmic() {
            // Apply any user overrides from config
            return Self::apply_config_overrides(cosmic_theme, config);
        }

        // Fall back to config-based theme
        Self::from_config_only(config)
    }

    /// Apply user config overrides to a COSMIC-derived theme
    fn apply_config_overrides(mut theme: Theme, config: &Config) -> Theme {
        let settings = &config.settings;
        let defaults = Config::default().settings;

        // Only override if user explicitly set a non-default value
        if settings.background_color != defaults.background_color {
            theme.background = Color::rgba(
                settings.background_color.r,
                settings.background_color.g,
                settings.background_color.b,
                settings.background_color.a,
            );
        }

        if settings.card_color != defaults.card_color {
            theme.card_background = Color::rgba(
                settings.card_color.r,
                settings.card_color.g,
                settings.card_color.b,
                settings.card_color.a,
            );
        }

        if settings.border_color != defaults.border_color {
            theme.card_border = Color::rgba(
                settings.border_color.r,
                settings.border_color.g,
                settings.border_color.b,
                settings.border_color.a,
            );
        }

        if settings.text_color != defaults.text_color {
            theme.text_primary = Color::rgba(
                settings.text_color.r,
                settings.text_color.g,
                settings.text_color.b,
                settings.text_color.a,
            );
            theme.text_secondary = Color::rgba(
                settings.text_color.r,
                settings.text_color.g,
                settings.text_color.b,
                (settings.text_color.a as f32 * 0.7) as u8,
            );
        }

        if settings.hint_color != defaults.hint_color {
            theme.badge_background = Color::rgba(
                settings.hint_color.r,
                settings.hint_color.g,
                settings.hint_color.b,
                settings.hint_color.a,
            );
        }

        if settings.hint_matched_color != defaults.hint_matched_color {
            theme.badge_matched_background = Color::rgba(
                settings.hint_matched_color.r,
                settings.hint_matched_color.g,
                settings.hint_matched_color.b,
                settings.hint_matched_color.a,
            );
        }

        if settings.border_width != defaults.border_width {
            theme.border_width = settings.border_width;
        }

        theme
    }

    /// Create theme from config only (no COSMIC integration)
    fn from_config_only(config: &Config) -> Self {
        let settings = &config.settings;

        Self {
            background: Color::rgba(
                settings.background_color.r,
                settings.background_color.g,
                settings.background_color.b,
                settings.background_color.a,
            ),
            card_background: Color::rgba(
                settings.card_color.r,
                settings.card_color.g,
                settings.card_color.b,
                settings.card_color.a,
            ),
            card_border: Color::rgba(
                settings.border_color.r,
                settings.border_color.g,
                settings.border_color.b,
                settings.border_color.a,
            ),
            text_primary: Color::rgba(
                settings.text_color.r,
                settings.text_color.g,
                settings.text_color.b,
                settings.text_color.a,
            ),
            text_secondary: Color::rgba(
                settings.text_color.r,
                settings.text_color.g,
                settings.text_color.b,
                (settings.text_color.a as f32 * 0.7) as u8,
            ),
            badge_background: Color::rgba(
                settings.hint_color.r,
                settings.hint_color.g,
                settings.hint_color.b,
                settings.hint_color.a,
            ),
            badge_text: Color::rgb(255, 255, 255),
            badge_matched_background: Color::rgba(
                settings.hint_matched_color.r,
                settings.hint_matched_color.g,
                settings.hint_matched_color.b,
                settings.hint_matched_color.a,
            ),
            badge_matched_text: Color::rgb(255, 255, 255),
            border_width: settings.border_width,
            corner_radius: 8.0,
        }
    }
}

impl Default for Theme {
    fn default() -> Self {
        // Try COSMIC theme first
        if let Some(cosmic_theme) = Self::from_cosmic() {
            return cosmic_theme;
        }

        // Fall back to hardcoded defaults
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
            border_width: 2.0,
            corner_radius: 16.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_theme() {
        let theme = Theme::default();
        assert!(theme.border_width > 0.0);
        assert!(theme.corner_radius > 0.0);
    }

    #[test]
    fn test_cosmic_theme_loading() {
        // This will work on COSMIC desktop, gracefully fail elsewhere
        let theme = Theme::from_cosmic();
        if let Some(t) = theme {
            println!("Loaded COSMIC theme with corner_radius={}", t.corner_radius);
        } else {
            println!("COSMIC theme not available (expected on non-COSMIC systems)");
        }
    }
}
