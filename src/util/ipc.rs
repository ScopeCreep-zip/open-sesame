//! Unix domain socket IPC for inter-instance communication
//!
//! Replaces signal-based IPC with a proper message protocol.
//! Provides reliable, bidirectional communication between instances.

use crate::util::paths;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

/// IPC commands that can be sent between instances
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcCommand {
    /// Cycle selection forward (Alt+Tab)
    CycleForward,
    /// Cycle selection backward (Alt+Shift+Tab)
    CycleBackward,
    /// Ping to check if instance is alive
    Ping,
}

impl IpcCommand {
    fn to_byte(self) -> u8 {
        match self {
            IpcCommand::CycleForward => b'F',
            IpcCommand::CycleBackward => b'B',
            IpcCommand::Ping => b'P',
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'F' => Some(IpcCommand::CycleForward),
            b'B' => Some(IpcCommand::CycleBackward),
            b'P' => Some(IpcCommand::Ping),
            _ => None,
        }
    }
}

/// IPC responses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcResponse {
    /// Command acknowledged and executed
    Ok,
    /// Pong response to ping
    Pong,
    /// Error occurred
    Error,
}

impl IpcResponse {
    fn to_byte(self) -> u8 {
        match self {
            IpcResponse::Ok => b'K',
            IpcResponse::Pong => b'O',
            IpcResponse::Error => b'E',
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b'K' => Some(IpcResponse::Ok),
            b'O' => Some(IpcResponse::Pong),
            b'E' => Some(IpcResponse::Error),
            _ => None,
        }
    }
}

/// IPC server that listens for commands from other instances
///
/// # Thread Lifecycle
///
/// The listener thread is spawned in `start()` and runs until process exit.
/// There is no explicit shutdown mechanism because:
/// - Application is short-lived (typically <1 second runtime)
/// - Thread holds no critical resources
/// - OS cleans up threads and file descriptors on process exit
pub struct IpcServer {
    receiver: Receiver<IpcCommand>,
    _listener_thread: thread::JoinHandle<()>,
    socket_path: PathBuf,
}

impl IpcServer {
    /// Creates and starts the IPC server.
    pub fn start() -> std::io::Result<Self> {
        let socket_path = Self::socket_path();

        // Stale socket file removed if exists
        if socket_path.exists() {
            std::fs::remove_file(&socket_path).ok();
        }

        // Parent directory existence ensured
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = UnixListener::bind(&socket_path)?;
        listener.set_nonblocking(true)?;

        tracing::info!("IPC server listening on {:?}", socket_path);

        let (sender, receiver) = mpsc::channel();
        let path_clone = socket_path.clone();

        let listener_thread = thread::spawn(move || {
            Self::listener_loop(listener, sender, path_clone);
        });

        Ok(Self {
            receiver,
            _listener_thread: listener_thread,
            socket_path,
        })
    }

    /// Checks for pending IPC commands (non-blocking).
    pub fn try_recv(&self) -> Option<IpcCommand> {
        self.receiver.try_recv().ok()
    }

    /// Returns the socket path.
    fn socket_path() -> PathBuf {
        match paths::cache_dir() {
            Ok(dir) => dir.join("ipc.sock"),
            Err(_) => {
                let uid = unsafe { libc::getuid() };
                PathBuf::from(format!("/run/user/{}/open-sesame.sock", uid))
            }
        }
    }

    /// Listener thread main loop
    ///
    /// Note: This thread intentionally has no explicit shutdown mechanism.
    /// Rationale:
    /// 1. The application is short-lived (exits after window selection)
    /// 2. Thread is I/O bound with short timeouts (no blocking operations)
    /// 3. Thread holds no critical resources (socket cleanup is in Drop)
    /// 4. OS automatically cleans up threads when process exits
    ///
    /// For a long-running daemon, you would add:
    /// - AtomicBool shutdown flag
    /// - Check flag in loop
    /// - Signal shutdown from Drop impl
    ///
    /// But for this use case, it's unnecessary complexity.
    fn listener_loop(listener: UnixListener, sender: Sender<IpcCommand>, _path: PathBuf) {
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    // Read timeout configuration
                    stream
                        .set_read_timeout(Some(Duration::from_millis(100)))
                        .ok();

                    let mut buf = [0u8; 1];
                    if stream.read_exact(&mut buf).is_ok()
                        && let Some(cmd) = IpcCommand::from_byte(buf[0])
                    {
                        tracing::debug!("IPC received command: {:?}", cmd);

                        // Response generation and transmission
                        let response = if cmd == IpcCommand::Ping {
                            IpcResponse::Pong
                        } else {
                            // Command forwarded to main thread
                            if sender.send(cmd).is_ok() {
                                IpcResponse::Ok
                            } else {
                                IpcResponse::Error
                            }
                        };

                        stream.write_all(&[response.to_byte()]).ok();
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No pending connection, brief sleep
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    tracing::error!("IPC accept error: {}", e);
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        // Socket file cleanup
        std::fs::remove_file(&self.socket_path).ok();
    }
}

/// IPC client for sending commands to a running instance
pub struct IpcClient;

impl IpcClient {
    /// Sends a command to the running instance.
    pub fn send(cmd: IpcCommand) -> std::io::Result<IpcResponse> {
        let socket_path = IpcServer::socket_path();

        let mut stream = UnixStream::connect(&socket_path)?;
        stream.set_read_timeout(Some(Duration::from_millis(500)))?;
        stream.set_write_timeout(Some(Duration::from_millis(500)))?;

        // Command transmission
        stream.write_all(&[cmd.to_byte()])?;

        // Response reception
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf)?;

        IpcResponse::from_byte(buf[0]).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid IPC response")
        })
    }

    /// Returns whether another instance is running.
    pub fn is_instance_running() -> bool {
        Self::send(IpcCommand::Ping).is_ok()
    }

    /// Sends cycle forward command.
    pub fn signal_cycle_forward() -> bool {
        match Self::send(IpcCommand::CycleForward) {
            Ok(IpcResponse::Ok) => {
                tracing::info!("IPC: cycle forward acknowledged");
                true
            }
            Ok(resp) => {
                tracing::warn!("IPC: unexpected response {:?}", resp);
                false
            }
            Err(e) => {
                tracing::error!("IPC: failed to send cycle forward: {}", e);
                false
            }
        }
    }

    /// Sends cycle backward command.
    pub fn signal_cycle_backward() -> bool {
        match Self::send(IpcCommand::CycleBackward) {
            Ok(IpcResponse::Ok) => {
                tracing::info!("IPC: cycle backward acknowledged");
                true
            }
            Ok(resp) => {
                tracing::warn!("IPC: unexpected response {:?}", resp);
                false
            }
            Err(e) => {
                tracing::error!("IPC: failed to send cycle backward: {}", e);
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_byte_roundtrip() {
        for cmd in [
            IpcCommand::CycleForward,
            IpcCommand::CycleBackward,
            IpcCommand::Ping,
        ] {
            let byte = cmd.to_byte();
            let decoded = IpcCommand::from_byte(byte);
            assert_eq!(decoded, Some(cmd));
        }
    }

    #[test]
    fn test_response_byte_roundtrip() {
        for resp in [IpcResponse::Ok, IpcResponse::Pong, IpcResponse::Error] {
            let byte = resp.to_byte();
            let decoded = IpcResponse::from_byte(byte);
            assert_eq!(decoded, Some(resp));
        }
    }

    #[test]
    fn test_invalid_bytes() {
        assert_eq!(IpcCommand::from_byte(0), None);
        assert_eq!(IpcCommand::from_byte(255), None);
        assert_eq!(IpcResponse::from_byte(0), None);
        assert_eq!(IpcResponse::from_byte(255), None);
    }
}
