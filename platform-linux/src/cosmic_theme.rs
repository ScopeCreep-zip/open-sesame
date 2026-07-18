//! COSMIC Desktop Theme Integration.
//!
//! Thin wrapper around the `cosmic-theme` crate — the same library every
//! COSMIC app uses for theme loading. Handles RON deserialization, schema
//! versioning, dark/light mode detection, and all field types internally.
//!
//! We re-export what the overlay renderer needs: colors as u8 RGBA tuples,
//! corner radii, frosted state, and alpha map values.

use cosmic_theme::palette::Srgba;
pub use cosmic_theme::{self, Theme as CosmicThemeRaw};

/// Load the active COSMIC theme (dark or light based on current mode).
/// Returns `None` if COSMIC theme is not available (non-COSMIC desktop).
pub fn load_theme() -> Option<CosmicThemeRaw> {
    match CosmicThemeRaw::get_active() {
        Ok(theme) => {
            tracing::info!(
                is_dark = theme.is_dark,
                frosted_panel = theme.frosted_panel,
                frosted_windows = theme.frosted_windows,
                "COSMIC theme loaded successfully"
            );
            Some(theme)
        }
        Err((errors, fallback)) => {
            for e in &errors {
                tracing::error!(
                    error = %e,
                    error_debug = ?e,
                    "COSMIC theme load error — using fallback. \
                     This typically means Landlock sandbox is blocking \
                     cosmic-config's fs::create_dir_all(). The theme load \
                     must happen BEFORE apply_sandbox() or the sandbox must \
                     grant write access to ~/.config/cosmic/ and ~/.local/state/cosmic/"
                );
            }
            tracing::warn!(
                is_dark = fallback.is_dark,
                "using COSMIC theme fallback (system colors NOT active)"
            );
            Some(fallback)
        }
    }
}

/// RGBA color with u8 channels (0-255).
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

    pub fn from_srgba(c: Srgba) -> Self {
        Self {
            r: (c.red.clamp(0.0, 1.0) * 255.0) as u8,
            g: (c.green.clamp(0.0, 1.0) * 255.0) as u8,
            b: (c.blue.clamp(0.0, 1.0) * 255.0) as u8,
            a: (c.alpha.clamp(0.0, 1.0) * 255.0) as u8,
        }
    }
}

/// Simplified theme data for the overlay renderer.
/// Extracted from `cosmic_theme::Theme` with colors converted to u8 RGBA.
#[derive(Debug, Clone)]
pub struct CosmicTheme {
    pub is_dark: bool,
    pub frosted_panel: bool,
    pub frosted_windows: bool,

    // Card container (primary)
    pub primary_base: ThemeColor,
    pub primary_on: ThemeColor,
    pub primary_component_base: ThemeColor,
    pub primary_component_on: ThemeColor,

    // Secondary container (badges)
    pub secondary_component_base: ThemeColor,
    pub secondary_component_on: ThemeColor,

    // Accent
    pub accent_base: ThemeColor,
    pub accent_on: ThemeColor,

    // Corner radii
    pub radius_m: [f32; 4],

    // Alpha for blur
    pub blur_alpha: f32,
}

impl CosmicTheme {
    /// Load from the system COSMIC theme. Returns None on non-COSMIC systems.
    pub fn load() -> Option<Self> {
        let raw = load_theme()?;
        let is_frosted = raw.frosted_panel || raw.frosted_windows || raw.frosted_system_interface;

        // Use transparent containers when frosted, opaque otherwise.
        let primary = raw.primary(is_frosted);
        let secondary = raw.secondary(is_frosted);

        Some(Self {
            is_dark: raw.is_dark,
            frosted_panel: raw.frosted_panel,
            frosted_windows: raw.frosted_windows,

            primary_base: ThemeColor::from_srgba(primary.base),
            primary_on: ThemeColor::from_srgba(primary.on),
            primary_component_base: ThemeColor::from_srgba(primary.component.base),
            primary_component_on: ThemeColor::from_srgba(primary.component.on),

            secondary_component_base: ThemeColor::from_srgba(secondary.component.base),
            secondary_component_on: ThemeColor::from_srgba(secondary.component.on),

            accent_base: ThemeColor::from_srgba(raw.accent.base),
            accent_on: ThemeColor::from_srgba(raw.accent.on),

            radius_m: raw.corner_radii.radius_m,

            blur_alpha: raw.alpha_map.blurred_alpha(raw.frosted),
        })
    }
}
