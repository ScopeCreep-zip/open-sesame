//! COSMIC Desktop Theme Integration.
//!
//! Reads theme colors, fonts, corner radii, and mode from COSMIC's RON
//! configuration files at `~/.config/cosmic/`. Supports both v2 (hex string
//! colors, COSMIC 1.3.0+) and v1 (float RGBA) formats with automatic fallback.
//!
//! Resolution order per key:
//! 1. User config v2: `~/.config/cosmic/com.system76.CosmicTheme.{Dark,Light}/v2/`
//! 2. System default v2: `/usr/share/cosmic/com.system76.CosmicTheme.{Dark,Light}/v2/`
//! 3. User config v1: `~/.config/cosmic/com.system76.CosmicTheme.{Dark,Light}/v1/`
//! 4. System default v1: `/usr/share/cosmic/com.system76.CosmicTheme.{Dark,Light}/v1/`

use serde::Deserialize;
use std::fs;
use std::path::Path;

// ---------------------------------------------------------------------------
// Color types
// ---------------------------------------------------------------------------

/// RGBA color with u8 channels (0-255). The unified output type regardless
/// of whether the source was v2 hex strings or v1 floats.
#[derive(Debug, Clone, Copy)]
pub struct ThemeColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl ThemeColor {
    pub fn to_rgba(&self) -> (u8, u8, u8, u8) {
        (self.r, self.g, self.b, self.a)
    }

    fn from_hex(hex: &str) -> Option<Self> {
        let hex = hex.trim();
        let hex = hex.strip_prefix('"').unwrap_or(hex);
        let hex = hex.strip_suffix('"').unwrap_or(hex);
        let hex = hex.strip_prefix('#').unwrap_or(hex);
        match hex.len() {
            6 => {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                Some(Self { r, g, b, a: 255 })
            }
            8 => {
                let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                let a = u8::from_str_radix(&hex[6..8], 16).ok()?;
                Some(Self { r, g, b, a })
            }
            _ => None,
        }
    }

    fn from_floats(r: f32, g: f32, b: f32, a: f32) -> Self {
        Self {
            r: (r.clamp(0.0, 1.0) * 255.0) as u8,
            g: (g.clamp(0.0, 1.0) * 255.0) as u8,
            b: (b.clamp(0.0, 1.0) * 255.0) as u8,
            a: (a.clamp(0.0, 1.0) * 255.0) as u8,
        }
    }
}

// ---------------------------------------------------------------------------
// V2 format (hex strings) — COSMIC 1.3.0+
// ---------------------------------------------------------------------------

/// Hex color that deserializes from a RON string like `"#1B1B1BFF"`.
#[derive(Debug, Clone, Deserialize)]
#[serde(transparent)]
struct HexColor(String);

impl HexColor {
    fn to_theme_color(&self) -> ThemeColor {
        ThemeColor::from_hex(&self.0).unwrap_or(ThemeColor { r: 0, g: 0, b: 0, a: 255 })
    }
}

#[derive(Debug, Clone, Deserialize)]
struct V2ComponentColors {
    base: HexColor,
    #[allow(dead_code)]
    hover: HexColor,
    #[allow(dead_code)]
    pressed: HexColor,
    #[allow(dead_code)]
    selected: HexColor,
    #[allow(dead_code)]
    selected_text: HexColor,
    #[allow(dead_code)]
    focus: HexColor,
    #[allow(dead_code)]
    divider: HexColor,
    on: HexColor,
    #[allow(dead_code)]
    disabled: HexColor,
    #[allow(dead_code)]
    on_disabled: HexColor,
    #[allow(dead_code)]
    border: HexColor,
    #[allow(dead_code)]
    disabled_border: HexColor,
}

#[derive(Debug, Clone, Deserialize)]
struct V2Container {
    base: HexColor,
    component: V2ComponentColors,
    #[allow(dead_code)]
    divider: HexColor,
    on: HexColor,
    #[serde(default)]
    #[allow(dead_code)]
    small_widget: Option<HexColor>,
}

// ---------------------------------------------------------------------------
// V1 format (float RGBA) — legacy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct V1Color {
    red: f32,
    green: f32,
    blue: f32,
    #[serde(default = "default_alpha")]
    alpha: f32,
}

fn default_alpha() -> f32 {
    1.0
}

impl V1Color {
    fn to_theme_color(&self) -> ThemeColor {
        ThemeColor::from_floats(self.red, self.green, self.blue, self.alpha)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct V1ComponentColors {
    base: V1Color,
    #[allow(dead_code)]
    hover: V1Color,
    #[allow(dead_code)]
    pressed: V1Color,
    #[allow(dead_code)]
    selected: V1Color,
    #[allow(dead_code)]
    selected_text: V1Color,
    #[allow(dead_code)]
    focus: V1Color,
    on: V1Color,
}

#[derive(Debug, Clone, Deserialize)]
struct V1Container {
    base: V1Color,
    component: V1ComponentColors,
    on: V1Color,
}

// ---------------------------------------------------------------------------
// Unified container type (output of theme loading)
// ---------------------------------------------------------------------------

/// Container with resolved colors (regardless of source format).
#[derive(Debug, Clone)]
pub struct Container {
    pub base: ThemeColor,
    pub component_base: ThemeColor,
    pub component_on: ThemeColor,
    pub on: ThemeColor,
}

/// Component/accent colors.
#[derive(Debug, Clone)]
pub struct AccentColors {
    pub base: ThemeColor,
    pub on: ThemeColor,
}

// ---------------------------------------------------------------------------
// Corner radii (same format in v1 and v2)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Complete theme
// ---------------------------------------------------------------------------

/// Complete COSMIC theme data needed for overlay rendering.
#[derive(Debug, Clone)]
pub struct CosmicTheme {
    pub is_dark: bool,
    pub background: Container,
    pub primary: Container,
    pub secondary: Container,
    pub transparent_background: Option<Container>,
    pub transparent_primary: Option<Container>,
    pub transparent_secondary: Option<Container>,
    pub accent: AccentColors,
    pub corner_radii: CornerRadii,
    /// True if any frosted_* setting is enabled in the theme.
    pub frosted: bool,
}

impl CosmicTheme {
    /// Load COSMIC theme from system configuration.
    ///
    /// Tries v2 format first (COSMIC 1.3.0+), falls back to v1.
    /// Returns `None` if COSMIC theme files are not present.
    pub fn load() -> Option<Self> {
        let is_dark = read_is_dark().unwrap_or(true);
        let theme_id = if is_dark {
            "com.system76.CosmicTheme.Dark"
        } else {
            "com.system76.CosmicTheme.Light"
        };

        tracing::debug!(theme_id, dark = is_dark, "loading COSMIC theme");

        // Try v2 first
        if let Some(theme) = load_v2(theme_id, is_dark) {
            tracing::info!(
                mode = if is_dark { "dark" } else { "light" },
                version = 2,
                frosted = theme.frosted,
                "loaded COSMIC theme"
            );
            return Some(theme);
        }

        // Fall back to v1
        if let Some(theme) = load_v1(theme_id, is_dark) {
            tracing::info!(
                mode = if is_dark { "dark" } else { "light" },
                version = 1,
                "loaded COSMIC theme (v1 fallback)"
            );
            return Some(theme);
        }

        tracing::debug!("no COSMIC theme found");
        None
    }
}

// ---------------------------------------------------------------------------
// V2 loading
// ---------------------------------------------------------------------------

fn load_v2(theme_id: &str, is_dark: bool) -> Option<CosmicTheme> {
    let background = read_v2_container(theme_id, "background")?;
    let primary = read_v2_container(theme_id, "primary")?;
    let secondary = read_v2_container(theme_id, "secondary")?;
    let accent = read_v2_accent(theme_id)?;

    let transparent_background = read_v2_container(theme_id, "transparent_background");
    let transparent_primary = read_v2_container(theme_id, "transparent_primary");
    let transparent_secondary = read_v2_container(theme_id, "transparent_secondary");

    let corner_radii = read_corner_radii(theme_id).unwrap_or_default();
    let frosted = read_frosted_state(theme_id);

    Some(CosmicTheme {
        is_dark,
        background,
        primary,
        secondary,
        transparent_background,
        transparent_primary,
        transparent_secondary,
        accent,
        corner_radii,
        frosted,
    })
}

fn read_v2_container(theme_id: &str, key: &str) -> Option<Container> {
    let content = read_theme_key(theme_id, "v2", key)?;
    let parsed: V2Container = ron::from_str(&content).ok().or_else(|| {
        tracing::trace!(theme_id, key, "failed to parse v2 container");
        None
    })?;
    Some(Container {
        base: parsed.base.to_theme_color(),
        component_base: parsed.component.base.to_theme_color(),
        component_on: parsed.component.on.to_theme_color(),
        on: parsed.on.to_theme_color(),
    })
}

fn read_v2_accent(theme_id: &str) -> Option<AccentColors> {
    let content = read_theme_key(theme_id, "v2", "accent")?;
    let parsed: V2ComponentColors = ron::from_str(&content).ok().or_else(|| {
        tracing::trace!(theme_id, "failed to parse v2 accent");
        None
    })?;
    Some(AccentColors {
        base: parsed.base.to_theme_color(),
        on: parsed.on.to_theme_color(),
    })
}

fn read_frosted_state(theme_id: &str) -> bool {
    let check = |key: &str| -> bool {
        read_theme_key(theme_id, "v2", key)
            .map(|s| s.trim() == "true")
            .unwrap_or(false)
    };
    check("frosted_panel")
        || check("frosted_windows")
        || check("frosted_system_interface")
        || check("frosted_applets")
}

// ---------------------------------------------------------------------------
// V1 loading (fallback)
// ---------------------------------------------------------------------------

fn load_v1(theme_id: &str, is_dark: bool) -> Option<CosmicTheme> {
    let background = read_v1_container(theme_id, "background")?;
    let primary = read_v1_container(theme_id, "primary")?;
    let secondary = read_v1_container(theme_id, "secondary")?;
    let accent = read_v1_accent(theme_id)?;
    let corner_radii = read_corner_radii(theme_id).unwrap_or_default();

    Some(CosmicTheme {
        is_dark,
        background,
        primary,
        secondary,
        transparent_background: None,
        transparent_primary: None,
        transparent_secondary: None,
        accent,
        corner_radii,
        frosted: false,
    })
}

fn read_v1_container(theme_id: &str, key: &str) -> Option<Container> {
    let content = read_theme_key(theme_id, "v1", key)?;
    let parsed: V1Container = ron::from_str(&content).ok().or_else(|| {
        tracing::trace!(theme_id, key, "failed to parse v1 container");
        None
    })?;
    Some(Container {
        base: parsed.base.to_theme_color(),
        component_base: parsed.component.base.to_theme_color(),
        component_on: parsed.component.on.to_theme_color(),
        on: parsed.on.to_theme_color(),
    })
}

fn read_v1_accent(theme_id: &str) -> Option<AccentColors> {
    let content = read_theme_key(theme_id, "v1", "accent")?;
    let parsed: V1ComponentColors = ron::from_str(&content).ok().or_else(|| {
        tracing::trace!(theme_id, "failed to parse v1 accent");
        None
    })?;
    Some(AccentColors {
        base: parsed.base.to_theme_color(),
        on: parsed.on.to_theme_color(),
    })
}

// ---------------------------------------------------------------------------
// Key resolution: user config -> system defaults
// ---------------------------------------------------------------------------

/// Read a theme key, trying user config first then system defaults.
fn read_theme_key(theme_id: &str, version: &str, key: &str) -> Option<String> {
    // User config
    if let Some(config_dir) = dirs::config_dir() {
        let path = config_dir.join("cosmic").join(theme_id).join(version).join(key);
        if let Ok(content) = fs::read_to_string(&path) {
            return Some(content);
        }
    }

    // System defaults
    let system_path = Path::new("/usr/share/cosmic").join(theme_id).join(version).join(key);
    fs::read_to_string(system_path).ok()
}

fn read_corner_radii(theme_id: &str) -> Option<CornerRadii> {
    let content = read_theme_key(theme_id, "v2", "corner_radii")
        .or_else(|| read_theme_key(theme_id, "v1", "corner_radii"))?;
    ron::from_str(&content).ok()
}

// ---------------------------------------------------------------------------
// Theme mode
// ---------------------------------------------------------------------------

fn read_is_dark() -> Option<bool> {
    let content = read_theme_key("com.system76.CosmicTheme.Mode", "v1", "is_dark")?;
    ron::from_str(content.trim()).ok()
}

// ---------------------------------------------------------------------------
// Legacy compat: re-export old type name
// ---------------------------------------------------------------------------

/// Legacy type alias for backwards compatibility.
pub type CosmicColor = ThemeColor;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_color_parsing() {
        let c = ThemeColor::from_hex("#89b4facc").unwrap();
        assert_eq!(c.r, 0x89);
        assert_eq!(c.g, 0xb4);
        assert_eq!(c.b, 0xfa);
        assert_eq!(c.a, 0xcc);
    }

    #[test]
    fn hex_color_6_digit() {
        let c = ThemeColor::from_hex("#ffffff").unwrap();
        assert_eq!(c.r, 255);
        assert_eq!(c.g, 255);
        assert_eq!(c.b, 255);
        assert_eq!(c.a, 255);
    }

    #[test]
    fn float_color_conversion() {
        let c = ThemeColor::from_floats(1.0, 0.5, 0.0, 0.8);
        assert_eq!(c.r, 255);
        assert_eq!(c.g, 127);
        assert_eq!(c.b, 0);
        assert_eq!(c.a, 204);
    }

    #[test]
    fn cosmic_theme_load_graceful() {
        // Returns None on non-COSMIC systems.
        let _ = CosmicTheme::load();
    }
}
