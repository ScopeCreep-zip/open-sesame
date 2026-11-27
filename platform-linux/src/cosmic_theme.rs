//! COSMIC Desktop Theme Integration.
//!
//! Thin wrapper around the `cosmic-theme` crate — the same library every
//! COSMIC app uses for theme loading. Handles RON deserialization, schema
//! versioning, dark/light mode detection, and all field types internally.
//!
//! We re-export what the overlay renderer needs: colors as u8 RGBA tuples,
//! corner radii, frosted state, alpha map values, and the interface font.
//!
//! The theme is read the way COSMIC's settings write it: the mode from
//! `com.system76.CosmicTheme.Mode`, then the dark or light theme config.
//! `Theme::get_active` is not used: it reads the mode from the
//! `com.system76.CosmicTheme` config, which COSMIC does not write, and
//! creates that directory (`cosmic_config::Config::new` runs
//! `create_dir_all`), which fails on a read-only home. Every config is
//! opened only when its directory exists, so nothing is created.

use std::path::{Path, PathBuf};

use cosmic_config::CosmicConfigEntry;
use cosmic_theme::palette::Srgba;
pub use cosmic_theme::{self, Theme as CosmicThemeRaw};
use cosmic_theme::{DARK_THEME_ID, LIGHT_THEME_ID, THEME_MODE_ID, ThemeMode};

/// The directory cosmic-config opens for config `name` at `version`:
/// `<cosmic config dir>/<name>/v<version>`.
fn config_dir(cosmic_dir: &Path, name: &str, version: u64) -> PathBuf {
    cosmic_dir.join(name).join(format!("v{version}"))
}

/// Whether config `name` at `version` exists under `cosmic_dir`.
fn configured(cosmic_dir: &Path, name: &str, version: u64) -> bool {
    let dir = config_dir(cosmic_dir, name, version);
    let present = dir.is_dir();
    if !present {
        tracing::debug!(path = %dir.display(), "no COSMIC config here");
    }
    present
}

/// `entry`, or its defaults with each real error logged.
fn entry_or_defaults<T>(name: &str, entry: Result<T, (Vec<cosmic_config::Error>, T)>) -> T {
    entry.unwrap_or_else(|(errors, defaults)| {
        for e in errors.iter().filter(|e| e.is_err()) {
            tracing::warn!(config = name, error = %e, "COSMIC config entry unreadable, its defaults used");
        }
        defaults
    })
}

/// The active COSMIC theme (dark or light by the current mode) from the
/// COSMIC configuration under `cosmic_dir` (`Layout::cosmic_config_dir`).
/// `None` on a desktop without one.
#[must_use]
pub fn load_theme(cosmic_dir: &Path) -> Option<CosmicThemeRaw> {
    if !configured(cosmic_dir, THEME_MODE_ID, ThemeMode::version()) {
        return None;
    }
    let mode = match ThemeMode::config() {
        Ok(config) => entry_or_defaults(THEME_MODE_ID, ThemeMode::get_entry(&config)),
        Err(e) => {
            tracing::warn!(error = %e, "COSMIC theme mode unreadable");
            return None;
        }
    };
    let id = if mode.is_dark {
        DARK_THEME_ID
    } else {
        LIGHT_THEME_ID
    };
    if !configured(cosmic_dir, id, CosmicThemeRaw::VERSION) {
        return None;
    }
    let config = if mode.is_dark {
        CosmicThemeRaw::dark_config()
    } else {
        CosmicThemeRaw::light_config()
    };
    match config {
        Ok(config) => {
            let theme = entry_or_defaults(id, CosmicThemeRaw::get_entry(&config));
            tracing::info!(
                is_dark = theme.is_dark,
                frosted_panel = theme.frosted_panel,
                frosted_windows = theme.frosted_windows,
                "COSMIC theme loaded"
            );
            Some(theme)
        }
        Err(e) => {
            tracing::warn!(config = id, error = %e, "COSMIC theme unreadable");
            None
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

/// A `0.0..=1.0` color channel (clamped) as the nearest `0..=255` value.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is clamped to 0.0..=255.0 and rounded before the cast"
)]
fn channel(value: f32) -> u8 {
    (value.clamp(0.0, 1.0) * 255.0).round() as u8
}

impl ThemeColor {
    #[must_use]
    pub fn to_rgba(&self) -> (u8, u8, u8, u8) {
        (self.r, self.g, self.b, self.a)
    }

    #[must_use]
    pub fn from_srgba(c: Srgba) -> Self {
        Self {
            r: channel(c.red),
            g: channel(c.green),
            b: channel(c.blue),
            a: channel(c.alpha),
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

    /// The opacity of a blurred (frosted) container, as an alpha channel.
    pub blur_alpha: u8,

    /// The desktop's interface font family (Settings → Desktop → Fonts).
    pub font_family: String,
}

impl CosmicTheme {
    /// The COSMIC theme configured under `cosmic_dir`
    /// (`Layout::cosmic_config_dir`); `None` on non-COSMIC desktops.
    #[must_use]
    pub fn load(cosmic_dir: &Path) -> Option<Self> {
        let raw = load_theme(cosmic_dir)?;
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

            blur_alpha: channel(raw.alpha_map.blurred_alpha(raw.frosted)),

            font_family: raw.font.family,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{THEME_MODE_ID, channel, config_dir, load_theme};

    #[test]
    fn configs_live_in_versioned_directories() {
        assert_eq!(
            config_dir(std::path::Path::new("/c/cosmic"), THEME_MODE_ID, 1),
            std::path::Path::new("/c/cosmic/com.system76.CosmicTheme.Mode/v1")
        );
    }

    #[test]
    fn without_a_cosmic_configuration_nothing_is_read_or_created() {
        let dir = tempfile::tempdir().unwrap();
        let cosmic = dir.path().join("cosmic");
        assert!(load_theme(&cosmic).is_none());
        assert!(!cosmic.exists(), "no COSMIC directory is created");
    }

    #[test]
    fn channels_round_to_the_nearest_value_and_clamp() {
        assert_eq!(channel(1.0), 255);
        assert_eq!(channel(0.999), 255);
        assert_eq!(channel(0.5), 128);
        assert_eq!(channel(0.0), 0);
        assert_eq!(channel(-0.5), 0);
        assert_eq!(channel(1.5), 255);
    }
}
