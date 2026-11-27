//! `sesame setup-keybinding`, `remove-keybinding`, `keybinding-status`,
//! and the keybinding step of `sesame init`: the overlay shortcuts bound
//! through the session's binding backend.
//!
//! One backend binds a session's shortcuts, chosen by what the session
//! and system provide, never by the calling shell's environment: the
//! `GlobalShortcuts` portal when the session's portal implements it
//! (daemon-launcher holds the portal session and binds at its start),
//! otherwise COSMIC's shortcut config when COSMIC's shortcut defaults are
//! installed. Never both, so a key cannot fire twice. The launcher key is
//! `[global] launcher_key`; the bindings of every request come from
//! `OverlayRequest::trigger`.

use core_layout::Layout;
use core_types::{KeyCombo, OverlayRequest};

/// The backend that binds this session's overlay shortcuts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backend {
    /// The `GlobalShortcuts` portal, through daemon-launcher.
    Portal,
    /// COSMIC's shortcut configuration (`platform_linux::cosmic_keys`).
    Cosmic,
}

impl Backend {
    /// The backend of this session; `None` when the portal lacks
    /// `GlobalShortcuts` and COSMIC's shortcut defaults are not installed.
    pub(crate) async fn of_session(layout: &Layout) -> Option<Self> {
        Self::choose(
            platform_linux::global_shortcuts::session_has_portal().await,
            platform_linux::cosmic_keys::shortcuts_supported(layout),
        )
    }

    /// The backend for a session with and without the portal interface and
    /// COSMIC's shortcut configuration: the portal first.
    const fn choose(portal: bool, cosmic: bool) -> Option<Self> {
        match (portal, cosmic) {
            (true, _) => Some(Self::Portal),
            (false, true) => Some(Self::Cosmic),
            (false, false) => None,
        }
    }
}

/// The configured launcher key (`[global] launcher_key`).
fn configured_launcher(layout: &Layout) -> anyhow::Result<KeyCombo> {
    Ok(core_config::load_config(layout)?.global.launcher_key)
}

/// Print each request's shortcut and command.
fn print_bindings(launcher: &KeyCombo) {
    for request in OverlayRequest::ALL {
        println!(
            "    {:<18}-> sesame {} ({})",
            request.trigger(launcher).to_string(),
            request.command_args().join(" "),
            request.description()
        );
    }
}

/// The message for a session without a binding backend.
const NO_BACKEND: &str = "no keybinding backend in this session: the desktop portal does not \
     implement org.freedesktop.portal.GlobalShortcuts and COSMIC's shortcut configuration \
     is not installed; bind `sesame wm overlay` (and its --backward, --launcher flags) in \
     the desktop's own shortcut settings";

/// Bind the overlay shortcuts with `launcher` (default: the configured
/// launcher key) through this session's backend.
///
/// # Errors
///
/// No backend; a `launcher` other than the configured key on the portal
/// backend (daemon-launcher binds the configured key); a configuration
/// or COSMIC config file that cannot be read or written.
pub(crate) async fn cmd_setup(layout: &Layout, launcher: Option<KeyCombo>) -> anyhow::Result<()> {
    let configured = configured_launcher(layout)?;
    let launcher = launcher.unwrap_or_else(|| configured.clone());
    match Backend::of_session(layout).await {
        Some(Backend::Cosmic) => {
            platform_linux::cosmic_keys::setup_keybinding(layout, &launcher)?;
            Ok(())
        }
        Some(Backend::Portal) if launcher != configured => anyhow::bail!(
            "the GlobalShortcuts portal binding follows [global] launcher_key \
             ({configured}): set launcher_key = \"{launcher}\" there and restart \
             daemon-launcher (systemctl --user restart open-sesame-launcher)"
        ),
        Some(Backend::Portal) => {
            println!(
                "Keybindings are bound through the desktop's GlobalShortcuts portal by \
                 daemon-launcher, which requests:"
            );
            print_bindings(&launcher);
            println!(
                "  The desktop assigns the final keys and may ask to confirm them; \
                 change them in its shortcut settings."
            );
            Ok(())
        }
        None => anyhow::bail!(NO_BACKEND),
    }
}

/// Remove the overlay shortcuts this session's backend holds.
///
/// # Errors
///
/// No backend, or a COSMIC config file that cannot be read or written.
pub(crate) async fn cmd_remove(layout: &Layout) -> anyhow::Result<()> {
    match Backend::of_session(layout).await {
        Some(Backend::Cosmic) => Ok(platform_linux::cosmic_keys::remove_keybinding(layout)?),
        Some(Backend::Portal) => {
            println!(
                "Portal shortcuts belong to the desktop: remove them in its shortcut \
                 settings (application \"open-sesame\"); daemon-launcher requests them \
                 again at its next start."
            );
            Ok(())
        }
        None => anyhow::bail!(NO_BACKEND),
    }
}

/// Show the backend and the shortcuts it holds.
///
/// # Errors
///
/// No backend, or a configuration or COSMIC config file that cannot be
/// read.
pub(crate) async fn cmd_status(layout: &Layout) -> anyhow::Result<()> {
    match Backend::of_session(layout).await {
        Some(Backend::Cosmic) => {
            println!("Keybinding backend: COSMIC shortcut config");
            Ok(platform_linux::cosmic_keys::keybinding_status(layout)?)
        }
        Some(Backend::Portal) => {
            println!(
                "Keybinding backend: GlobalShortcuts portal (bound by daemon-launcher); requested:"
            );
            print_bindings(&configured_launcher(layout)?);
            Ok(())
        }
        None => anyhow::bail!(NO_BACKEND),
    }
}

/// The keybinding step of `sesame init`: the configured launcher key
/// through this session's backend; a session without one is reported and
/// skipped.
///
/// # Errors
///
/// A configuration or COSMIC config file that cannot be read or written.
pub(crate) async fn init_step(layout: &Layout) -> anyhow::Result<String> {
    let launcher = configured_launcher(layout)?;
    Ok(match Backend::of_session(layout).await {
        Some(Backend::Cosmic) => {
            platform_linux::cosmic_keys::setup_keybinding(layout, &launcher)?;
            format!("{launcher} launcher keybinding configured (COSMIC)")
        }
        Some(Backend::Portal) => {
            format!("{launcher} launcher keybinding requested through the GlobalShortcuts portal")
        }
        None => "no keybinding backend (bind `sesame wm overlay` in the desktop's settings)".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::Backend;

    #[test]
    fn the_portal_wins_and_cosmic_is_the_fallback() {
        assert_eq!(Backend::choose(true, true), Some(Backend::Portal));
        assert_eq!(Backend::choose(true, false), Some(Backend::Portal));
        assert_eq!(Backend::choose(false, true), Some(Backend::Cosmic));
        assert_eq!(Backend::choose(false, false), None);
    }
}
