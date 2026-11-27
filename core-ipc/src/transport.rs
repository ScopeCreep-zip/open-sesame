//! Peer credentials of a Unix domain socket connection, bound into the
//! Noise prologue by both sides. The bus endpoint is
//! `core_layout::Layout::bus_socket`.

use tokio::net::UnixStream;

/// A connected process's credentials, from `SO_PEERCRED` or the current
/// process.
#[derive(Debug, Clone)]
pub(crate) struct PeerCredentials {
    pub(crate) pid: u32,
    pub(crate) uid: u32,
}

/// The current process's real credentials (PID + UID): the local side of
/// the Noise prologue. Both sides of the handshake must agree on each
/// other's PID/UID for the prologue to match.
pub(crate) fn local_credentials() -> PeerCredentials {
    PeerCredentials {
        pid: std::process::id(),
        uid: rustix::process::getuid().as_raw(),
    }
}

/// The peer's credentials (`SO_PEERCRED`) of a connected socket.
///
/// # Errors
///
/// When the credentials cannot be read or carry no PID; the caller rejects
/// the connection. There is no default.
pub(crate) fn extract_ucred(stream: &UnixStream) -> core_types::Result<PeerCredentials> {
    let cred = stream
        .peer_cred()
        .map_err(|e| core_types::Error::Ipc(format!("UCred extraction failed: {e}")))?;
    let pid = cred
        .pid()
        .and_then(|p| u32::try_from(p).ok())
        .ok_or_else(|| core_types::Error::Ipc("UCred: PID unavailable".into()))?;
    Ok(PeerCredentials {
        pid,
        uid: cred.uid(),
    })
}
