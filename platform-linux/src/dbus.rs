//! D-Bus integration via zbus.
//!
//! Provides typed proxies for:
//! - `org.freedesktop.secrets` (Secret Service API) — KEK-only storage
//! - `org.freedesktop.portal.GlobalShortcuts` — compositor-agnostic hotkeys
//! - Custom `org.pds.*` interfaces for daemon-to-daemon RPC over D-Bus
//!   (secondary to the postcard IPC bus; used for portal integration)
//!
//! zbus configuration: `default-features = false, features = ["tokio"]`
//! ensures no background threads — all I/O runs on the tokio runtime.
//!
//! This module provides ONLY low-level D-Bus proxies. Business logic
//! (KeyLocker trait, key hierarchy) lives in daemon-secrets.
//! See ADR: KeyLocker Implementation in daemon-secrets.

use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

/// Connection handle wrapping a `zbus::Connection` to the session bus.
pub struct SessionBus {
    conn: zbus::Connection,
}

impl SessionBus {
    /// Connect to the D-Bus session bus.
    ///
    /// # Errors
    ///
    /// Returns an error if the session bus is unavailable.
    pub async fn connect() -> core_types::Result<Self> {
        let conn = zbus::Connection::session().await.map_err(|e| {
            core_types::Error::Platform(format!("D-Bus session bus connection failed: {e}"))
        })?;
        Ok(Self { conn })
    }

    /// Return a reference to the underlying zbus connection.
    pub fn connection(&self) -> &zbus::Connection {
        &self.conn
    }
}

/// Low-level Secret Service proxy for `org.freedesktop.secrets`.
///
/// Provides raw store/retrieve/delete/has for a single item
/// identified by service+account attributes. Returns raw bytes
/// (NOT SecureBytes — that wrapping happens in daemon-secrets).
pub struct SecretServiceProxy {
    conn: zbus::Connection,
    session_path: OwnedObjectPath,
}

impl SecretServiceProxy {
    /// Create a new proxy and open a plain-text session.
    ///
    /// The "plain" algorithm means secrets are transmitted unencrypted over
    /// D-Bus, which is safe because D-Bus is local and we trust the session
    /// bus. The alternative is Diffie-Hellman negotiation which adds
    /// complexity for no security benefit on local transport.
    ///
    /// # Errors
    ///
    /// Returns an error if the Secret Service is unavailable or session
    /// negotiation fails.
    pub async fn new(bus: &SessionBus) -> core_types::Result<Self> {
        let conn = bus.conn.clone();

        // Open a plain session.
        let proxy = zbus::Proxy::new(
            &conn,
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets",
            "org.freedesktop.secrets.Service",
        )
        .await
        .map_err(|e| core_types::Error::Platform(format!("Secret Service proxy failed: {e}")))?;

        let (_, session_path): (OwnedValue, OwnedObjectPath) = proxy
            .call("OpenSession", &("plain", Value::new("")))
            .await
            .map_err(|e| {
                core_types::Error::Platform(format!("Secret Service OpenSession failed: {e}"))
            })?;

        tracing::debug!(session = %session_path, "Secret Service session opened");

        Ok(Self { conn, session_path })
    }

    /// Store a blob in the Secret Service under the given service+account attributes.
    ///
    /// Uses the default collection (`/org/freedesktop/secrets/aliases/default`).
    /// Replace semantics: if an item with the same attributes exists, it is replaced.
    ///
    /// # Errors
    ///
    /// Returns an error if the D-Bus call fails.
    pub async fn store(
        &self,
        service: &str,
        account: &str,
        label: &str,
        data: &[u8],
    ) -> core_types::Result<()> {
        let collection_proxy = zbus::Proxy::new(
            &self.conn,
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets/aliases/default",
            "org.freedesktop.secrets.Collection",
        )
        .await
        .map_err(|e| core_types::Error::Platform(format!("Collection proxy failed: {e}")))?;

        // Secret struct: (session_path, parameters: [], value, content_type)
        let secret = (
            &self.session_path,
            Vec::<u8>::new(),           // parameters (empty for plain)
            data.to_vec(),              // the secret value
            "application/octet-stream", // content type
        );

        // Attributes for search/replace.
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("application", service);
        attrs.insert("account", account);
        attrs.insert("type", "master-key-wrapped");

        // Properties dict for CreateItem.
        let mut properties = std::collections::HashMap::new();
        properties.insert("org.freedesktop.Secret.Item.Label", Value::new(label));
        properties.insert("org.freedesktop.Secret.Item.Attributes", Value::new(attrs));

        let (_item_path, _prompt_path): (OwnedObjectPath, OwnedObjectPath) = collection_proxy
            .call("CreateItem", &(properties, secret, true)) // true = replace
            .await
            .map_err(|e| {
                core_types::Error::Platform(format!("Secret Service CreateItem failed: {e}"))
            })?;

        tracing::debug!(service, account, "stored wrapped key in Secret Service");
        Ok(())
    }

    /// Retrieve the blob stored under the given service+account attributes.
    ///
    /// Returns the raw secret bytes.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if no matching item exists.
    pub async fn retrieve(&self, service: &str, account: &str) -> core_types::Result<Vec<u8>> {
        let item_path = self.search_item(service, account).await?;

        let item_proxy = zbus::Proxy::new(
            &self.conn,
            "org.freedesktop.secrets",
            item_path.as_str(),
            "org.freedesktop.secrets.Item",
        )
        .await
        .map_err(|e| core_types::Error::Platform(format!("Item proxy failed: {e}")))?;

        // GetSecret returns (session, parameters, value, content_type)
        let (_, _, value, _): (OwnedObjectPath, Vec<u8>, Vec<u8>, String) = item_proxy
            .call("GetSecret", &(&self.session_path,))
            .await
            .map_err(|e| {
                core_types::Error::Platform(format!("Secret Service GetSecret failed: {e}"))
            })?;

        Ok(value)
    }

    /// Delete the item matching the given service+account attributes.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if no matching item exists.
    pub async fn delete(&self, service: &str, account: &str) -> core_types::Result<()> {
        let item_path = self.search_item(service, account).await?;

        let item_proxy = zbus::Proxy::new(
            &self.conn,
            "org.freedesktop.secrets",
            item_path.as_str(),
            "org.freedesktop.secrets.Item",
        )
        .await
        .map_err(|e| core_types::Error::Platform(format!("Item proxy failed: {e}")))?;

        let _prompt_path: OwnedObjectPath = item_proxy.call("Delete", &()).await.map_err(|e| {
            core_types::Error::Platform(format!("Secret Service Delete failed: {e}"))
        })?;

        tracing::debug!(service, account, "deleted wrapped key from Secret Service");
        Ok(())
    }

    /// Check if an item with the given attributes exists.
    pub async fn has(&self, service: &str, account: &str) -> core_types::Result<bool> {
        match self.search_item(service, account).await {
            Ok(_) => Ok(true),
            Err(core_types::Error::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Search for a single item by service+account attributes.
    async fn search_item(
        &self,
        service: &str,
        account: &str,
    ) -> core_types::Result<OwnedObjectPath> {
        let proxy = zbus::Proxy::new(
            &self.conn,
            "org.freedesktop.secrets",
            "/org/freedesktop/secrets",
            "org.freedesktop.secrets.Service",
        )
        .await
        .map_err(|e| core_types::Error::Platform(format!("Service proxy failed: {e}")))?;

        let mut attrs = std::collections::HashMap::new();
        attrs.insert("application", service);
        attrs.insert("account", account);
        attrs.insert("type", "master-key-wrapped");

        let (unlocked, _locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) =
            proxy.call("SearchItems", &(attrs,)).await.map_err(|e| {
                core_types::Error::Platform(format!("Secret Service SearchItems failed: {e}"))
            })?;

        unlocked.into_iter().next().ok_or_else(|| {
            core_types::Error::NotFound(format!(
                "no Secret Service item for service={service}, account={account}"
            ))
        })
    }
}

/// Global Shortcuts portal proxy for `org.freedesktop.portal.GlobalShortcuts`.
///
/// Compositor-agnostic global hotkey registration. Supported on COSMIC,
/// KDE Plasma 6.4+, and niri via xdg-desktop-portal.
pub struct GlobalShortcutsProxy {
    conn: zbus::Connection,
    session_path: Option<OwnedObjectPath>,
}

impl GlobalShortcutsProxy {
    pub async fn new(bus: &SessionBus) -> core_types::Result<Self> {
        Ok(Self {
            conn: bus.conn.clone(),
            session_path: None,
        })
    }

    pub async fn create_session(&mut self, app_id: &str) -> core_types::Result<()> {
        let proxy = zbus::Proxy::new(
            &self.conn,
            "org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.GlobalShortcuts",
        )
        .await
        .map_err(|e| core_types::Error::Platform(format!("GlobalShortcuts proxy failed: {e}")))?;

        let session_token = format!("pds_{app_id}");
        let mut options = std::collections::HashMap::new();
        options.insert("session_handle_token", Value::new(session_token.clone()));
        options.insert("handle_token", Value::new(format!("pds_req_{app_id}")));

        let (_request_path,): (OwnedObjectPath,) = proxy
            .call("CreateSession", &(options,))
            .await
            .map_err(|e| {
            core_types::Error::Platform(format!("GlobalShortcuts CreateSession failed: {e}"))
        })?;

        // Construct the session object path from the token per xdg-desktop-portal spec:
        // /org/freedesktop/portal/desktop/session/{sender}/{token}
        // where sender is the D-Bus unique name with ':' and '.' replaced by '_'.
        let sender = self
            .conn
            .unique_name()
            .ok_or_else(|| core_types::Error::Platform("no D-Bus unique name".into()))?;
        let sender_clean = sender.as_str().trim_start_matches(':').replace('.', "_");
        let session_obj =
            format!("/org/freedesktop/portal/desktop/session/{sender_clean}/{session_token}");
        self.session_path = Some(
            OwnedObjectPath::try_from(session_obj)
                .map_err(|e| core_types::Error::Platform(format!("invalid session path: {e}")))?,
        );

        tracing::debug!(session = ?self.session_path, "GlobalShortcuts session created");
        Ok(())
    }

    pub async fn bind_shortcuts(&self, shortcuts: &[(String, String)]) -> core_types::Result<()> {
        let Some(session) = &self.session_path else {
            return Err(core_types::Error::Platform(
                "no GlobalShortcuts session — call create_session first".into(),
            ));
        };

        let proxy = zbus::Proxy::new(
            &self.conn,
            "org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.GlobalShortcuts",
        )
        .await
        .map_err(|e| core_types::Error::Platform(format!("GlobalShortcuts proxy failed: {e}")))?;

        let shortcut_defs: Vec<(String, std::collections::HashMap<&str, Value<'_>>)> = shortcuts
            .iter()
            .map(|(id, description)| {
                let mut props = std::collections::HashMap::new();
                props.insert("description", Value::new(description.as_str()));
                (id.clone(), props)
            })
            .collect();

        let options: std::collections::HashMap<&str, Value<'_>> = std::collections::HashMap::new();

        let _: (OwnedObjectPath,) = proxy
            .call("BindShortcuts", &(session, shortcut_defs, "", options))
            .await
            .map_err(|e| {
                core_types::Error::Platform(format!("GlobalShortcuts BindShortcuts failed: {e}"))
            })?;

        tracing::debug!(count = shortcuts.len(), "shortcuts bound via portal");
        Ok(())
    }

    pub async fn list_shortcuts(&self) -> core_types::Result<Vec<String>> {
        let Some(session) = &self.session_path else {
            return Err(core_types::Error::Platform(
                "no GlobalShortcuts session".into(),
            ));
        };

        let proxy = zbus::Proxy::new(
            &self.conn,
            "org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.GlobalShortcuts",
        )
        .await
        .map_err(|e| core_types::Error::Platform(format!("GlobalShortcuts proxy failed: {e}")))?;

        let options: std::collections::HashMap<&str, Value<'_>> = std::collections::HashMap::new();
        let _: (OwnedObjectPath,) = proxy
            .call("ListShortcuts", &(session, options))
            .await
            .map_err(|e| {
                core_types::Error::Platform(format!("GlobalShortcuts ListShortcuts failed: {e}"))
            })?;

        Ok(vec![])
    }

    pub fn session_path(&self) -> Option<&OwnedObjectPath> {
        self.session_path.as_ref()
    }
}

// ============================================================================
// NetworkManager SSID Monitor
// ============================================================================

/// Monitors the active WiFi SSID via NetworkManager D-Bus signals.
///
/// Subscribes to `org.freedesktop.NetworkManager` `StateChanged` signal
/// on the system bus. On each state change, re-reads the primary active
/// connection's SSID and sends it through the channel if it changed.
///
/// Runs as a long-lived task — spawn with `tokio::spawn`.
pub async fn ssid_monitor(tx: tokio::sync::mpsc::Sender<String>) {
    if let Err(e) = ssid_monitor_inner(&tx).await {
        tracing::warn!(error = %e, "SSID monitor exiting");
    }
}

async fn ssid_monitor_inner(tx: &tokio::sync::mpsc::Sender<String>) -> core_types::Result<()> {
    let conn = zbus::Connection::system()
        .await
        .map_err(|e| core_types::Error::Platform(format!("system bus connection failed: {e}")))?;

    // Read the current SSID once at startup.
    let mut last_ssid = String::new();
    if let Some(ssid) = read_current_ssid(&conn).await {
        last_ssid.clone_from(&ssid);
        let _ = tx.send(ssid).await;
    }

    // Subscribe to NetworkManager StateChanged signal for coarse notifications,
    // then re-read the SSID on each state change. This is simpler and more
    // reliable than tracking individual AccessPoint property changes.
    let proxy = zbus::Proxy::new(
        &conn,
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
        "org.freedesktop.NetworkManager",
    )
    .await
    .map_err(|e| core_types::Error::Platform(format!("NetworkManager proxy failed: {e}")))?;

    let mut state_changed = proxy.receive_signal("StateChanged").await.map_err(|e| {
        core_types::Error::Platform(format!("failed to subscribe to NM StateChanged: {e}"))
    })?;

    // SignalStream implements futures_core::Stream<Item = Message> (infallible).
    use futures_util::StreamExt;
    while let Some(_signal) = state_changed.next().await {
        if let Some(ssid) = read_current_ssid(&conn).await
            && ssid != last_ssid
        {
            tracing::info!(ssid = %ssid, "SSID changed");
            last_ssid.clone_from(&ssid);
            if tx.send(ssid).await.is_err() {
                break; // receiver dropped
            }
        }
    }

    Ok(())
}

/// Read the SSID of the primary active WiFi connection via NetworkManager.
///
/// Returns `None` if there is no active WiFi connection or if the SSID
/// cannot be determined (wired-only, no NM, etc.).
async fn read_current_ssid(conn: &zbus::Connection) -> Option<String> {
    // Get the primary active connection object path.
    let nm_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        "/org/freedesktop/NetworkManager",
        "org.freedesktop.DBus.Properties",
    )
    .await
    .ok()?;

    // PrimaryConnection is the active connection NM considers primary.
    // D-Bus Get returns a variant; downcast_ref unwraps Value::Value automatically.
    let primary_val: OwnedValue = nm_proxy
        .call(
            "Get",
            &("org.freedesktop.NetworkManager", "PrimaryConnection"),
        )
        .await
        .ok()?;
    // ObjectPath<'a>: TryFrom<&Value<'a>> via value_try_from_ref_clone
    let primary_path = primary_val
        .downcast_ref::<zbus::zvariant::ObjectPath>()
        .ok()?;
    let primary: OwnedObjectPath = primary_path.to_owned().into();

    if primary.as_str() == "/" {
        return None; // no active connection
    }

    // Get the connection type to check if it's WiFi.
    let ac_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        primary.as_str(),
        "org.freedesktop.DBus.Properties",
    )
    .await
    .ok()?;

    let type_val: OwnedValue = ac_proxy
        .call(
            "Get",
            &("org.freedesktop.NetworkManager.Connection.Active", "Type"),
        )
        .await
        .ok()?;
    // String: TryFrom<&Value> (from_value.rs line 127)
    let conn_type: String = type_val.downcast_ref::<String>().ok()?;

    // Only WiFi connections have SSIDs.
    if conn_type != "802-11-wireless" {
        return None;
    }

    // Get the Devices on this active connection.
    let devices_val: OwnedValue = ac_proxy
        .call(
            "Get",
            &(
                "org.freedesktop.NetworkManager.Connection.Active",
                "Devices",
            ),
        )
        .await
        .ok()?;

    // Devices is ao (array of object paths).
    // Array<'a>: TryFrom<&Value<'a>> via value_try_from_ref_clone.
    // Array derefs to [Value<'_>], iterate and extract each ObjectPath.
    let devices_arr = devices_val.downcast_ref::<zbus::zvariant::Array>().ok()?;
    let device_path = devices_arr
        .first()?
        .downcast_ref::<zbus::zvariant::ObjectPath>()
        .ok()?;
    let device_path: OwnedObjectPath = device_path.to_owned().into();

    // Get the ActiveAccessPoint from the wireless device.
    let dev_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        device_path.as_str(),
        "org.freedesktop.DBus.Properties",
    )
    .await
    .ok()?;

    let ap_val: OwnedValue = dev_proxy
        .call(
            "Get",
            &(
                "org.freedesktop.NetworkManager.Device.Wireless",
                "ActiveAccessPoint",
            ),
        )
        .await
        .ok()?;
    let ap_obj = ap_val.downcast_ref::<zbus::zvariant::ObjectPath>().ok()?;
    let ap_path: OwnedObjectPath = ap_obj.to_owned().into();

    if ap_path.as_str() == "/" {
        return None; // no active AP
    }

    // Get the SSID (byte array) from the access point.
    let ap_proxy = zbus::Proxy::new(
        conn,
        "org.freedesktop.NetworkManager",
        ap_path.as_str(),
        "org.freedesktop.DBus.Properties",
    )
    .await
    .ok()?;

    let ssid_val: OwnedValue = ap_proxy
        .call(
            "Get",
            &("org.freedesktop.NetworkManager.AccessPoint", "Ssid"),
        )
        .await
        .ok()?;

    // SSID is ay (array of bytes).
    // Array<'a>: TryFrom<&Value<'a>>, then iterate extracting u8 from each element.
    let ssid_arr = ssid_val.downcast_ref::<zbus::zvariant::Array>().ok()?;
    let ssid_bytes: Vec<u8> = ssid_arr
        .iter()
        .map(|v| v.downcast_ref::<u8>().ok())
        .collect::<Option<Vec<_>>>()?;

    String::from_utf8(ssid_bytes).ok()
}
