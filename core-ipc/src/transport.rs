//! Transport abstractions and socket path resolution.

use std::path::PathBuf;
use tokio::net::UnixStream;

/// Peer credentials obtained from the transport layer.
#[derive(Debug, Clone)]
pub struct PeerCredentials {
    /// Process ID of the peer.
    pub pid: u32,
    /// User ID of the peer (Unix). On Windows, this is 0 (use SID instead).
    pub uid: u32,
}

impl PeerCredentials {
    /// Credentials for an in-process subscriber (e.g. the bus host itself).
    ///
    /// Not extracted from a socket — uses the current process's own PID.
    /// UID is set to `u32::MAX` as a sentinel (never matches a real `UCred` check).
    #[must_use]
    pub fn in_process() -> Self {
        Self {
            pid: std::process::id(),
            uid: u32::MAX,
        }
    }
}

/// Get the current process's real credentials (PID + UID).
///
/// Used to construct the local side of the Noise prologue. Both sides of
/// the handshake must agree on each other's PID/UID for the prologue to match.
#[must_use]
pub fn local_credentials() -> PeerCredentials {
    PeerCredentials {
        pid: std::process::id(),
        uid: current_uid(),
    }
}

/// Extract `UCred` (pid/uid) from a connected Unix domain socket.
///
/// Uses `SO_PEERCRED` on Linux to retrieve the peer's process credentials.
/// Returns an error if credentials cannot be extracted -- the caller MUST
/// reject the connection. There are no fallback defaults.
///
/// # Errors
///
/// Returns an error if peer credentials cannot be extracted from the socket.
pub fn extract_ucred(stream: &UnixStream) -> core_types::Result<PeerCredentials> {
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

/// Get the current process's real UID.
///
/// Uses `rustix` for safe, zero-unsafe POSIX syscall access.
#[cfg(unix)]
fn current_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

#[cfg(not(unix))]
fn current_uid() -> u32 {
    0
}

/// Resolve the platform-appropriate IPC socket path.
///
/// # Errors
///
/// Returns an error if required platform directories cannot be determined
/// (e.g. `XDG_RUNTIME_DIR` unset on Linux, no home directory on macOS).
pub fn socket_path() -> core_types::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let runtime = std::env::var("XDG_RUNTIME_DIR").map_err(|_| {
            core_types::Error::Platform(
                "XDG_RUNTIME_DIR is not set; cannot determine IPC socket path".into(),
            )
        })?;
        Ok(PathBuf::from(runtime).join("pds/bus.sock"))
    }

    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir()
            .ok_or_else(|| core_types::Error::Platform("cannot determine home directory".into()))?;
        Ok(home.join("Library/Application Support/pds/bus.sock"))
    }

    #[cfg(target_os = "windows")]
    {
        Ok(PathBuf::from(r"\\.\pipe\pds\bus"))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(core_types::Error::Platform(
            "unsupported platform: cannot determine IPC socket path".into(),
        ))
    }
}
