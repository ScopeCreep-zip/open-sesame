//! COSMIC Desktop Theme Integration
//!
//! Reads theme colors, fonts, and mode directly from COSMIC's configuration.
//! Provides native integration with the COSMIC desktop environment.
//!
//! Configuration paths:
//! - Theme mode: ~/.config/cosmic/com.system76.CosmicTheme.Mode/v1/is_dark
//! - Dark theme: ~/.config/cosmic/com.system76.CosmicTheme.Dark/v1/
//! - Light theme: ~/.config/cosmic/com.system76.CosmicTheme.Light/v1/
//! - Fonts: ~/.config/cosmic/com.system76.CosmicTk/v1/

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

/// RGBA color from COSMIC theme (0.0-1.0 floats)
///
/// Matches COSMIC's color representation in RON configuration files.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct CosmicColor {
    /// Red channel (0.0 to 1.0)
    pub red: f32,
    /// Green channel (0.0 to 1.0)
    pub green: f32,
    /// Blue channel (0.0 to 1.0)
    pub blue: f32,
    /// Alpha channel (0.0 to 1.0, defaults to 1.0)
    #[serde(default = "default_alpha")]
    pub alpha: f32,
}

fn default_alpha() -> f32 {
    1.0
}

impl CosmicColor {
    /// Convert to u8 RGBA tuple (0-255 per channel)
    pub fn to_rgba(&self) -> (u8, u8, u8, u8) {
        (
            (self.red.clamp(0.0, 1.0) * 255.0) as u8,
            (self.green.clamp(0.0, 1.0) * 255.0) as u8,
            (self.blue.clamp(0.0, 1.0) * 255.0) as u8,
            (self.alpha.clamp(0.0, 1.0) * 255.0) as u8,
        )
    }
}

/// Component colors from COSMIC theme
///
/// Represents the various states a UI component can have (base, hover, pressed, etc.)
#[derive(Debug, Clone, Deserialize)]
pub struct ComponentColors {
    /// Default/resting state color
    pub base: CosmicColor,
    /// Color when hovered
    pub hover: CosmicColor,
    /// Color when pressed/active
    pub pressed: CosmicColor,
    /// Color when selected
    pub selected: CosmicColor,
    /// Text color when selected
    pub selected_text: CosmicColor,
    /// Color when focused
    pub focus: CosmicColor,
    /// Foreground/text color on this component
    pub on: CosmicColor,
}

/// Container structure from COSMIC theme (background, primary, secondary)
///
/// Containers are layered surfaces in COSMIC's design system.
#[derive(Debug, Clone, Deserialize)]
pub struct Container {
    /// Base background color for this container layer
    pub base: CosmicColor,
    /// Colors for interactive components within this container
    pub component: ComponentColors,
    /// Foreground/text color on this container
    pub on: CosmicColor,
}

/// Accent colors from COSMIC theme
///
/// The accent color is the primary brand/highlight color.
#[derive(Debug, Clone, Deserialize)]
pub struct AccentColors {
    /// Default accent color
    pub base: CosmicColor,
    /// Accent color when hovered
    pub hover: CosmicColor,
    /// Accent color when focused
    pub focus: CosmicColor,
    /// Foreground color on accent backgrounds
    pub on: CosmicColor,
}

/// Corner radii from COSMIC theme
///
/// COSMIC uses a consistent set of corner radii across the desktop.
/// Each radius is an array of 4 floats for [top-left, top-right, bottom-right, bottom-left].
#[derive(Debug, Clone, Deserialize)]
pub struct CornerRadii {
    /// No rounding (0px)
    pub radius_0: [f32; 4],
    /// Extra small radius (~4px)
    pub radius_xs: [f32; 4],
    /// Small radius (~8px)
    pub radius_s: [f32; 4],
    /// Medium radius (~16px) - typical for cards and popups
    pub radius_m: [f32; 4],
    /// Large radius (~24px)
    pub radius_l: [f32; 4],
    /// Extra large radius (~32px)
    pub radius_xl: [f32; 4],
}

impl Default for CornerRadii {
    fn default() -> Self {
        Self {
            radius_0: [0.0; 4],
            radius_xs: [4.0; 4],
            radius_s: [8.0; 4],
            radius_m: [16.0; 4],
            radius_l: [24.0; 4],
            radius_xl: [32.0; 4],
        }
    }
}

/// Spacing values from COSMIC theme
///
/// COSMIC uses a consistent spacing scale across the desktop.
#[derive(Debug, Clone, Deserialize)]
pub struct Spacing {
    /// No spacing (0px)
    pub space_none: u16,
    /// Triple extra small (~4px)
    pub space_xxxs: u16,
    /// Double extra small (~8px)
    pub space_xxs: u16,
    /// Extra small (~12px)
    pub space_xs: u16,
    /// Small (~16px)
    pub space_s: u16,
    /// Medium (~24px)
    pub space_m: u16,
    /// Large (~32px)
    pub space_l: u16,
    /// Extra large (~48px)
    pub space_xl: u16,
    /// Double extra large (~64px)
    pub space_xxl: u16,
    /// Triple extra large (~128px)
    pub space_xxxl: u16,
}

impl Default for Spacing {
    fn default() -> Self {
        Self {
            space_none: 0,
            space_xxxs: 4,
            space_xxs: 8,
            space_xs: 12,
            space_s: 16,
            space_m: 24,
            space_l: 32,
            space_xl: 48,
            space_xxl: 64,
            space_xxxl: 128,
        }
    }
}

/// Complete COSMIC theme for open-sesame
///
/// Aggregates all theme components needed for rendering the overlay.
#[derive(Debug, Clone)]
pub struct CosmicTheme {
    /// Whether dark mode is active
    pub is_dark: bool,
    /// Background container colors (desktop/root level)
    pub background: Container,
    /// Primary container colors (cards, popups, dialogs)
    pub primary: Container,
    /// Secondary container colors (nested containers)
    pub secondary: Container,
    /// Accent colors for highlights and selection
    pub accent: AccentColors,
    /// Corner radii for rounded elements
    pub corner_radii: CornerRadii,
    /// Spacing scale for layout
    pub spacing: Spacing,
}

impl CosmicTheme {
    /// Load COSMIC theme from system configuration
    ///
    /// Reads from ~/.config/cosmic/ and returns None if COSMIC theme
    /// files are not present (e.g., not running on COSMIC desktop).
    pub fn load() -> Option<Self> {
        let is_dark = read_is_dark().unwrap_or(true);
        let theme_dir = if is_dark {
            cosmic_theme_dark_dir()
        } else {
            cosmic_theme_light_dir()
        };

        tracing::debug!(
            "Loading COSMIC theme from: {:?} (dark={})",
            theme_dir,
            is_dark
        );

        let background = read_container(&theme_dir, "background")?;
        let primary = read_container(&theme_dir, "primary")?;
        let secondary = read_container(&theme_dir, "secondary")?;
        let accent = read_accent(&theme_dir)?;
        let corner_radii = read_corner_radii(&theme_dir).unwrap_or_default();
        let spacing = read_spacing(&theme_dir).unwrap_or_default();

        tracing::info!(
            "Loaded COSMIC {} theme",
            if is_dark { "dark" } else { "light" }
        );

        Some(Self {
            is_dark,
            background,
            primary,
            secondary,
            accent,
            corner_radii,
            spacing,
        })
    }
}

/// Get COSMIC config directory base
fn cosmic_config_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("cosmic"))
}

/// Get COSMIC theme mode directory
fn cosmic_theme_mode_dir() -> Option<PathBuf> {
    cosmic_config_dir().map(|d| d.join("com.system76.CosmicTheme.Mode/v1"))
}

/// Get COSMIC dark theme directory
fn cosmic_theme_dark_dir() -> PathBuf {
    cosmic_config_dir()
        .map(|d| d.join("com.system76.CosmicTheme.Dark/v1"))
        .unwrap_or_else(|| PathBuf::from("/nonexistent"))
}

/// Get COSMIC light theme directory
fn cosmic_theme_light_dir() -> PathBuf {
    cosmic_config_dir()
        .map(|d| d.join("com.system76.CosmicTheme.Light/v1"))
        .unwrap_or_else(|| PathBuf::from("/nonexistent"))
}

/// Read whether dark mode is enabled
fn read_is_dark() -> Option<bool> {
    let path = cosmic_theme_mode_dir()?.join("is_dark");
    let content = fs::read_to_string(&path).ok()?;
    ron::from_str(&content).ok()
}

/// Read a container (background, primary, secondary) from theme dir
fn read_container(theme_dir: &Path, name: &str) -> Option<Container> {
    let path = theme_dir.join(name);
    let content = fs::read_to_string(&path).ok()?;
    match ron::from_str(&content) {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!("Failed to parse COSMIC {} config: {}", name, e);
            None
        }
    }
}

/// Read accent colors from theme dir
fn read_accent(theme_dir: &Path) -> Option<AccentColors> {
    let path = theme_dir.join("accent");
    let content = fs::read_to_string(&path).ok()?;
    match ron::from_str(&content) {
        Ok(a) => Some(a),
        Err(e) => {
            tracing::warn!("Failed to parse COSMIC accent config: {}", e);
            None
        }
    }
}

/// Read corner radii from theme dir
fn read_corner_radii(theme_dir: &Path) -> Option<CornerRadii> {
    let path = theme_dir.join("corner_radii");
    let content = fs::read_to_string(&path).ok()?;
    ron::from_str(&content).ok()
}

/// Read spacing from theme dir
fn read_spacing(theme_dir: &Path) -> Option<Spacing> {
    let path = theme_dir.join("spacing");
    let content = fs::read_to_string(&path).ok()?;
    ron::from_str(&content).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cosmic_color_conversion() {
        let color = CosmicColor {
            red: 1.0,
            green: 0.5,
            blue: 0.0,
            alpha: 0.8,
        };
        let (r, g, b, a) = color.to_rgba();
        assert_eq!(r, 255);
        assert_eq!(g, 127);
        assert_eq!(b, 0);
        assert_eq!(a, 204);
    }

    #[test]
    fn test_load_cosmic_theme() {
        // This will fail if not running on COSMIC, which is fine
        let theme = CosmicTheme::load();
        if let Some(t) = theme {
            println!("Loaded COSMIC theme: dark={}", t.is_dark);
        }
    }
}
