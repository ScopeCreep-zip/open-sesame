//! The overlay shortcuts through the `GlobalShortcuts` portal
//! (`org.freedesktop.portal.GlobalShortcuts`), over ashpd: one session
//! binding every `OverlayRequest` under its id, description, and
//! preferred trigger (`OverlayRequest::trigger`, in the XDG shortcuts
//! format), whose `Activated` signals become overlay requests.
//!
//! The desktop decides the final trigger and may ask the user; its
//! portal backend must implement the interface (KDE, GNOME 48 and later,
//! Hyprland). Where it does not, the COSMIC shortcut config carries the
//! bindings (`cosmic_keys`): one backend binds a session's shortcuts,
//! never both.

use ashpd::desktop::CreateSessionOptions;
use ashpd::desktop::global_shortcuts::{BindShortcutsOptions, GlobalShortcuts, NewShortcut};
use core_types::{KeyCombo, OverlayRequest};
use futures_util::{Stream, StreamExt};

/// The portal error as a platform error naming what failed.
fn platform(what: &str, e: &ashpd::Error) -> core_types::Error {
    core_types::Error::Platform(format!("GlobalShortcuts portal {what}: {e}"))
}

/// The shortcuts to bind: every overlay request under its id and
/// description, preferring its trigger for `launcher`.
fn shortcuts(launcher: &KeyCombo) -> Vec<NewShortcut> {
    OverlayRequest::ALL
        .into_iter()
        .map(|request| {
            NewShortcut::new(request.id(), request.description())
                .preferred_trigger(request.trigger(launcher).xdg_trigger().as_str())
        })
        .collect()
}

/// Whether the portal on `connection` (a session bus) implements
/// `GlobalShortcuts`.
pub async fn available(connection: &zbus::Connection) -> bool {
    // ashpd defaults failed version reads to version 1, so constructing its
    // proxy does not establish that the service or interface exists.
    let proxy: zbus::Proxy<'_> = match zbus::proxy::Builder::new(connection)
        .destination("org.freedesktop.portal.Desktop")
        .path("/org/freedesktop/portal/desktop")
        .interface("org.freedesktop.portal.GlobalShortcuts")
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
    {
        Ok(proxy) => proxy,
        Err(error) => {
            tracing::debug!(%error, "GlobalShortcuts portal proxy invalid");
            return false;
        }
    };
    match proxy.get_property::<u32>("version").await {
        Ok(version) => version > 0,
        Err(error) => {
            tracing::debug!(%error, "GlobalShortcuts portal unavailable");
            false
        }
    }
}

/// Whether this session's portal implements `GlobalShortcuts`; `false`
/// without a session bus.
pub async fn session_has_portal() -> bool {
    match zbus::Connection::session().await {
        Ok(connection) => available(&connection).await,
        Err(e) => {
            tracing::debug!(error = %e, "no session bus: no GlobalShortcuts portal");
            false
        }
    }
}

/// A bound `GlobalShortcuts` session. The session lives as long as
/// `connection` does: dropping the connection ends it.
pub struct PortalShortcuts {
    portal: GlobalShortcuts,
}

impl std::fmt::Debug for PortalShortcuts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalShortcuts").finish_non_exhaustive()
    }
}

impl PortalShortcuts {
    /// Create a session on `connection` and bind every overlay request,
    /// with `launcher` (`[global] launcher_key`) as the launcher's
    /// preferred trigger. The triggers the desktop assigned are logged.
    ///
    /// # Errors
    ///
    /// `core_types::Error::Platform` when the portal lacks the interface,
    /// or the session or the binding fails (the user may decline it).
    pub async fn bind(
        connection: &zbus::Connection,
        launcher: &KeyCombo,
    ) -> core_types::Result<Self> {
        let portal = GlobalShortcuts::with_connection(connection.clone())
            .await
            .map_err(|e| platform("unavailable", &e))?;
        let session = portal
            .create_session(CreateSessionOptions::default())
            .await
            .map_err(|e| platform("session", &e))?;
        let bound = portal
            .bind_shortcuts(
                &session,
                &shortcuts(launcher),
                None,
                BindShortcutsOptions::default(),
            )
            .await
            .and_then(|request| request.response())
            .map_err(|e| platform("binding", &e))?;
        for shortcut in bound.shortcuts() {
            tracing::info!(
                id = shortcut.id(),
                trigger = shortcut.trigger_description(),
                "overlay shortcut bound through the GlobalShortcuts portal"
            );
        }
        // The session is held by the portal for the connection's life;
        // its handle is not needed once the shortcuts are bound.
        drop(session);
        Ok(Self { portal })
    }

    /// The overlay requests the bound shortcuts activate. An activation
    /// of an id this session did not bind is logged and skipped.
    ///
    /// # Errors
    ///
    /// `core_types::Error::Platform` when the signal subscription fails.
    pub async fn activations(
        &self,
    ) -> core_types::Result<impl Stream<Item = OverlayRequest> + use<>> {
        let activated = self
            .portal
            .receive_activated()
            .await
            .map_err(|e| platform("Activated subscription", &e))?;
        Ok(activated.filter_map(|activation| async move {
            let request = OverlayRequest::from_id(activation.shortcut_id());
            if request.is_none() {
                tracing::warn!(id = activation.shortcut_id(), "unknown shortcut activated");
            }
            request
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_request_is_bound_once() {
        let launcher: KeyCombo = "alt+space".parse().unwrap();
        let bound = shortcuts(&launcher);
        assert_eq!(bound.len(), OverlayRequest::ALL.len());
        let rendered = format!("{bound:?}");
        for request in OverlayRequest::ALL {
            assert!(rendered.contains(request.id()), "{rendered}");
            assert!(
                rendered.contains(&request.trigger(&launcher).xdg_trigger()),
                "{rendered}"
            );
        }
    }
}
