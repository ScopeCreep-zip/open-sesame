//! Font resolution using freedesktop fontconfig
//!
//! Resolves font family names to file paths using the system's fontconfig.
//! Integrates with COSMIC's font configuration and user preferences.

use fontconfig::Fontconfig;
use std::path::PathBuf;

/// Font resolution result
pub struct ResolvedFont {
    /// Path to the font file
    pub path: PathBuf,
    /// Actual family name (may differ from requested)
    pub family: String,
}

/// Resolve a font family name to a file path using fontconfig
///
/// Attempts resolution in the following order:
/// 1. Exact family name match
/// 2. "sans" generic family
/// 3. Any available font
pub fn resolve_font(family: &str) -> Option<ResolvedFont> {
    let fc = Fontconfig::new()?;

    // Attempt exact family match
    if let Some(font) = fc.find(family, None) {
        tracing::debug!(
            "fontconfig: resolved '{}' to '{}'",
            family,
            font.path.display()
        );
        return Some(ResolvedFont {
            path: font.path,
            family: font.name,
        });
    }

    // Fall back to generic "sans"
    if family != "sans"
        && let Some(font) = fc.find("sans", None)
    {
        tracing::info!(
            "fontconfig: '{}' not found, falling back to sans ({})",
            family,
            font.path.display()
        );
        return Some(ResolvedFont {
            path: font.path,
            family: font.name,
        });
    }

    tracing::error!("fontconfig: no fonts available");
    None
}

/// Resolve the system's default sans-serif font
pub fn resolve_sans() -> Option<ResolvedFont> {
    resolve_font("sans")
}

/// Resolve a font with a specific style (bold, italic, etc)
pub fn resolve_font_with_style(family: &str, style: &str) -> Option<ResolvedFont> {
    let fc = Fontconfig::new()?;

    // Construct fontconfig pattern: "family:style=bold"
    let pattern = format!("{}:style={}", family, style);
    if let Some(font) = fc.find(&pattern, None) {
        return Some(ResolvedFont {
            path: font.path,
            family: font.name,
        });
    }

    // Fall back to regular style
    resolve_font(family)
}

/// Check if fontconfig is available and has fonts
pub fn fontconfig_available() -> bool {
    Fontconfig::new()
        .and_then(|fc| fc.find("sans", None))
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fontconfig_available() {
        assert!(fontconfig_available(), "fontconfig should have sans font");
    }

    #[test]
    fn test_resolve_sans() {
        let font = resolve_sans().expect("Should resolve sans font");
        assert!(font.path.exists(), "Font path should exist");
        println!(
            "Resolved sans to: {} ({})",
            font.family,
            font.path.display()
        );
    }

    #[test]
    fn test_resolve_open_sans() {
        if let Some(font) = resolve_font("Open Sans") {
            println!(
                "Resolved Open Sans to: {} ({})",
                font.family,
                font.path.display()
            );
        } else {
            println!("Open Sans not installed, fallback would be used");
        }
    }
}
