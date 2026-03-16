//! COSMIC Desktop Theme Integration.
//!
//! Reads theme colors, fonts, corner radii, and mode from COSMIC's RON
//! configuration files at `~/.config/cosmic/`.
//!
//! Paths:
//! - Theme mode: `~/.config/cosmic/com.system76.CosmicTheme.Mode/v1/is_dark`
//! - Dark theme: `~/.config/cosmic/com.system76.CosmicTheme.Dark/v1/`
//! - Light theme: `~/.config/cosmic/com.system76.CosmicTheme.Light/v1/`

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

/// RGBA color from COSMIC theme (0.0-1.0 floats).
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct CosmicColor {
    pub red: f32,
    pub green: f32,
    pub blue: f32,
    #[serde(default = "default_alpha")]
    pub alpha: f32,
}

fn default_alpha() -> f32 {
    1.0
}

impl CosmicColor {
    /// Convert to u8 RGBA tuple (0-255 per channel).
    pub fn to_rgba(&self) -> (u8, u8, u8, u8) {
        (
            (self.red.clamp(0.0, 1.0) * 255.0) as u8,
            (self.green.clamp(0.0, 1.0) * 255.0) as u8,
            (self.blue.clamp(0.0, 1.0) * 255.0) as u8,
            (self.alpha.clamp(0.0, 1.0) * 255.0) as u8,
        )
    }
}

/// Component colors from COSMIC theme (base, hover, pressed, etc.).
#[derive(Debug, Clone, Deserialize)]
pub struct ComponentColors {
    pub base: CosmicColor,
    pub hover: CosmicColor,
    pub pressed: CosmicColor,
    pub selected: CosmicColor,
    pub selected_text: CosmicColor,
    pub focus: CosmicColor,
    pub on: CosmicColor,
}

/// Container structure from COSMIC theme.
#[derive(Debug, Clone, Deserialize)]
pub struct Container {
    pub base: CosmicColor,
    pub component: ComponentColors,
    pub on: CosmicColor,
}

/// Accent colors from COSMIC theme.
#[derive(Debug, Clone, Deserialize)]
pub struct AccentColors {
    pub base: CosmicColor,
    pub hover: CosmicColor,
    pub focus: CosmicColor,
    pub on: CosmicColor,
}

/// Corner radii from COSMIC theme.
#[derive(Debug, Clone, Deserialize)]
pub struct CornerRadii {
    pub radius_0: [f32; 4],
    pub radius_xs: [f32; 4],
    pub radius_s: [f32; 4],
    pub radius_m: [f32; 4],
    pub radius_l: [f32; 4],
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

/// Complete COSMIC theme data needed for overlay rendering.
#[derive(Debug, Clone)]
pub struct CosmicTheme {
    pub is_dark: bool,
    pub background: Container,
    pub primary: Container,
    pub secondary: Container,
    pub accent: AccentColors,
    pub corner_radii: CornerRadii,
}

impl CosmicTheme {
    /// Load COSMIC theme from system configuration.
    ///
    /// Returns `None` if COSMIC theme files are not present (not COSMIC desktop).
    pub fn load() -> Option<Self> {
        let is_dark = read_is_dark().unwrap_or(true);
        let theme_dir = if is_dark {
            cosmic_theme_dark_dir()
        } else {
            cosmic_theme_light_dir()
        };

        tracing::debug!(
            dir = ?theme_dir,
            dark = is_dark,
            "loading COSMIC theme"
        );

        let background = read_container(&theme_dir, "background")?;
        let primary = read_container(&theme_dir, "primary")?;
        let secondary = read_container(&theme_dir, "secondary")?;
        let accent = read_accent(&theme_dir)?;
        let corner_radii = read_corner_radii(&theme_dir).unwrap_or_default();

        tracing::info!(
            mode = if is_dark { "dark" } else { "light" },
            "loaded COSMIC theme"
        );

        Some(Self {
            is_dark,
            background,
            primary,
            secondary,
            accent,
            corner_radii,
        })
    }
}

fn cosmic_config_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("cosmic"))
}

fn cosmic_theme_mode_dir() -> Option<PathBuf> {
    cosmic_config_dir().map(|d| d.join("com.system76.CosmicTheme.Mode/v1"))
}

fn cosmic_theme_dark_dir() -> PathBuf {
    cosmic_config_dir()
        .map(|d| d.join("com.system76.CosmicTheme.Dark/v1"))
        .unwrap_or_else(|| PathBuf::from("/nonexistent"))
}

fn cosmic_theme_light_dir() -> PathBuf {
    cosmic_config_dir()
        .map(|d| d.join("com.system76.CosmicTheme.Light/v1"))
        .unwrap_or_else(|| PathBuf::from("/nonexistent"))
}

fn read_is_dark() -> Option<bool> {
    let path = cosmic_theme_mode_dir()?.join("is_dark");
    let content = fs::read_to_string(&path).ok()?;
    ron::from_str(&content).ok()
}

fn read_container(theme_dir: &Path, name: &str) -> Option<Container> {
    let path = theme_dir.join(name);
    let content = fs::read_to_string(&path).ok()?;
    match ron::from_str(&content) {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!(name, error = %e, "failed to parse COSMIC container config");
            None
        }
    }
}

fn read_accent(theme_dir: &Path) -> Option<AccentColors> {
    let path = theme_dir.join("accent");
    let content = fs::read_to_string(&path).ok()?;
    match ron::from_str(&content) {
        Ok(a) => Some(a),
        Err(e) => {
            tracing::warn!(error = %e, "failed to parse COSMIC accent config");
            None
        }
    }
}

fn read_corner_radii(theme_dir: &Path) -> Option<CornerRadii> {
    let path = theme_dir.join("corner_radii");
    let content = fs::read_to_string(&path).ok()?;
    ron::from_str(&content).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosmic_color_conversion() {
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
    fn cosmic_theme_load_graceful() {
        // Returns None on non-COSMIC systems.
        let _ = CosmicTheme::load();
    }
}
