//! D-Bus integration via zbus: the `NetworkManager` SSID monitor that feeds
//! Wi-Fi context signals to daemon-profile.
//!
//! zbus configuration: `default-features = false, features = ["tokio",
//! "proxy"]` runs all I/O on the tokio runtime, with no runtime of zbus's
//! own.

use futures_util::StreamExt;
use zbus::OwnedObjectPath;
use zbus::proxy::{Builder, CacheProperties, Defaults};

const NM_SERVICE: &str = "org.freedesktop.NetworkManager";

/// `org.freedesktop.NetworkManager` on its root object.
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager",
    default_service = "org.freedesktop.NetworkManager",
    default_path = "/org/freedesktop/NetworkManager"
)]
trait NetworkManager {
    /// `NetworkManager`'s overall state changed (`NMState`).
    #[zbus(signal)]
    fn state_changed(&self, state: u32) -> zbus::Result<()>;

    /// The active connection `NetworkManager` considers primary; `/` when none.
    #[zbus(property)]
    fn primary_connection(&self) -> zbus::Result<OwnedObjectPath>;
}

/// `org.freedesktop.NetworkManager.Connection.Active`.
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.Connection.Active",
    default_service = "org.freedesktop.NetworkManager"
)]
trait ActiveConnection {
    /// The connection type, `802-11-wireless` for Wi-Fi.
    #[zbus(property, name = "Type")]
    fn connection_type(&self) -> zbus::Result<String>;

    /// The devices the connection is active on.
    #[zbus(property)]
    fn devices(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
}

/// `org.freedesktop.NetworkManager.Device.Wireless`.
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.Device.Wireless",
    default_service = "org.freedesktop.NetworkManager"
)]
trait WirelessDevice {
    /// The associated access point; `/` when none.
    #[zbus(property)]
    fn active_access_point(&self) -> zbus::Result<OwnedObjectPath>;
}

/// `org.freedesktop.NetworkManager.AccessPoint`.
#[zbus::proxy(
    interface = "org.freedesktop.NetworkManager.AccessPoint",
    default_service = "org.freedesktop.NetworkManager"
)]
trait AccessPoint {
    /// The SSID bytes.
    #[zbus(property)]
    fn ssid(&self) -> zbus::Result<Vec<u8>>;
}

/// A proxy of type `P` on `NetworkManager` object `path`.
///
/// Every read is a `Properties.Get` (`CacheProperties::No`): a cached
/// property is updated by a task racing the `StateChanged` that triggers
/// the read, and each object is read once per state change.
async fn nm_proxy<'p, P>(conn: &zbus::Connection, path: &'p str) -> zbus::Result<P>
where
    P: From<zbus::Proxy<'p>> + Defaults,
{
    Builder::<P>::new(conn)
        .destination(NM_SERVICE)
        .path(path)
        .cache_properties(CacheProperties::No)
        .build()
        .await
}

/// A platform error naming the `NetworkManager` item that failed.
fn nm_error(what: &str) -> impl FnOnce(zbus::Error) -> core_types::Error + '_ {
    move |e| core_types::Error::Platform(format!("NetworkManager {what}: {e}"))
}

/// Monitors the active Wi-Fi SSID via `NetworkManager` D-Bus signals.
///
/// Subscribes to `org.freedesktop.NetworkManager` `StateChanged` signal
/// on the system bus at `system_bus` (`core_layout::Layout::system_bus_socket`,
/// the socket the caller's sandbox grants). On each state change,
/// re-reads the primary active connection's SSID and sends it through the
/// channel if it changed.
///
/// Runs as a long-lived task — spawn with `tokio::spawn`.
pub async fn ssid_monitor(system_bus: std::path::PathBuf, tx: tokio::sync::mpsc::Sender<String>) {
    if let Err(e) = ssid_monitor_inner(&system_bus, &tx).await {
        tracing::warn!(error = %e, "SSID monitor exiting");
    }
}

/// A bus connection over the socket at `path`.
async fn connect_bus(path: &std::path::Path) -> core_types::Result<zbus::Connection> {
    let bus_error = |e: &dyn std::fmt::Display| {
        core_types::Error::Platform(format!("system bus {}: {e}", path.display()))
    };
    let stream = tokio::net::UnixStream::connect(path)
        .await
        .and_then(tokio::net::UnixStream::into_std)
        .map_err(|e| bus_error(&e))?;
    zbus::connection::Builder::unix_stream(stream)
        .build()
        .await
        .map_err(|e| bus_error(&e))
}

async fn ssid_monitor_inner(
    system_bus: &std::path::Path,
    tx: &tokio::sync::mpsc::Sender<String>,
) -> core_types::Result<()> {
    let conn = connect_bus(system_bus).await?;
    let nm = NetworkManagerProxy::builder(&conn)
        .cache_properties(CacheProperties::No)
        .build()
        .await
        .map_err(nm_error("proxy"))?;

    // Subscribe before the first read, so a change between the two is
    // not missed.
    let mut state_changed = nm
        .receive_state_changed()
        .await
        .map_err(nm_error("StateChanged subscription"))?;

    let mut last_ssid = String::new();
    match read_current_ssid(&conn, &nm).await {
        Ok(Some(ssid)) => {
            last_ssid.clone_from(&ssid);
            if tx.send(ssid).await.is_err() {
                return Ok(()); // receiver dropped
            }
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(error = %e, "initial SSID read failed"),
    }

    // StateChanged is a coarse notification; the SSID is re-read on each.
    while state_changed.next().await.is_some() {
        match read_current_ssid(&conn, &nm).await {
            Ok(Some(ssid)) if ssid != last_ssid => {
                tracing::info!(ssid = %ssid, "SSID changed");
                last_ssid.clone_from(&ssid);
                if tx.send(ssid).await.is_err() {
                    break; // receiver dropped
                }
            }
            Ok(_) => {}
            // One failed read does not end monitoring; the next state
            // change reads again.
            Err(e) => tracing::warn!(error = %e, "SSID read failed"),
        }
    }

    Ok(())
}

/// Read the SSID of the primary active Wi-Fi connection via `NetworkManager`.
///
/// `Ok(None)` when there is no active connection, it is not Wi-Fi, or no
/// access point is associated.
///
/// # Errors
///
/// A D-Bus failure, a property of an unexpected type, an active Wi-Fi
/// connection without a device, or an SSID that is not UTF-8 (activation
/// rules compare SSIDs as text).
async fn read_current_ssid(
    conn: &zbus::Connection,
    nm: &NetworkManagerProxy<'_>,
) -> core_types::Result<Option<String>> {
    let primary = nm
        .primary_connection()
        .await
        .map_err(nm_error("PrimaryConnection"))?;
    if primary.as_str() == "/" {
        return Ok(None); // no active connection
    }

    let active: ActiveConnectionProxy<'_> = nm_proxy(conn, primary.as_str())
        .await
        .map_err(nm_error("active connection proxy"))?;
    let connection_type = active
        .connection_type()
        .await
        .map_err(nm_error("Connection.Active.Type"))?;
    if connection_type != "802-11-wireless" {
        return Ok(None);
    }

    let devices = active
        .devices()
        .await
        .map_err(nm_error("Connection.Active.Devices"))?;
    let device_path = devices.first().ok_or_else(|| {
        core_types::Error::Platform(format!(
            "NetworkManager active WiFi connection {} has no device",
            primary.as_str()
        ))
    })?;

    let device: WirelessDeviceProxy<'_> = nm_proxy(conn, device_path.as_str())
        .await
        .map_err(nm_error("wireless device proxy"))?;
    let ap_path = device
        .active_access_point()
        .await
        .map_err(nm_error("ActiveAccessPoint"))?;
    if ap_path.as_str() == "/" {
        return Ok(None); // no active AP
    }

    let ap: AccessPointProxy<'_> = nm_proxy(conn, ap_path.as_str())
        .await
        .map_err(nm_error("access point proxy"))?;
    let ssid = ap.ssid().await.map_err(nm_error("AccessPoint.Ssid"))?;
    String::from_utf8(ssid).map(Some).map_err(|e| {
        core_types::Error::Platform(format!("SSID is not UTF-8 ({} bytes)", e.as_bytes().len()))
    })
}
