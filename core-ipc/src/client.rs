//! IPC bus client — connects to the bus server, publishes events,
//! and receives subscribed events over a Unix domain socket.
//!
//! Two connection modes:
//! - `connect_encrypted()`: low-level constructor for tests and CLI clients.
//! - `connect_daemon_with_keypair_retry()`: production constructor for daemons.
//!   Spawns an I/O task that transparently handles `KeyRotationPending` —
//!   the caller's `recv()` is never interrupted by routine key rotation.

use crate::message::MessageContext;
use core_types::{DaemonId, EventKind, SecurityLevel};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, mpsc, oneshot};
use uuid::Uuid;

use crate::framing::{decode_frame, encode_frame};
use crate::message::Message;
use crate::transport::{extract_ucred, local_credentials};

/// Retry parameters for initial IPC bus connection.
pub struct RetryConfig {
    /// Maximum connection attempts before giving up.
    pub max_attempts: u32,
    /// Base backoff duration between attempts (multiplied by attempt number).
    pub backoff: Duration,
}

/// Metadata for transparent key rotation inside the I/O task.
#[derive(Clone)]
struct RotationConfig {
    daemon_name: String,
    daemon_id: DaemonId,
    socket_path: PathBuf,
    server_pub: [u8; 32],
    capabilities: Vec<String>,
    version: String,
}

/// The IPC bus client used by each daemon to communicate on the bus.
pub struct BusClient {
    daemon_id: DaemonId,
    msg_ctx: MessageContext,
    /// Outbound frames to send to the server.
    outbound_tx: mpsc::Sender<Vec<u8>>,
    /// Inbound frames received from the server (broadcast/unsolicited).
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    /// Pending request-response waiters, keyed by `msg_id`.
    pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<Message<EventKind>>>>>,
    epoch: Instant,
    /// Handle to the multiplexed I/O task (encrypted transport).
    /// `None` for in-process test clients created via `new()`.
    io_handle: Option<tokio::task::JoinHandle<()>>,
}

impl BusClient {
    /// Create a new bus client with pre-wired channels (for in-process testing).
    #[must_use]
    pub fn new(
        daemon_id: DaemonId,
        outbound_tx: mpsc::Sender<Vec<u8>>,
        inbound_rx: mpsc::Receiver<Vec<u8>>,
    ) -> Self {
        Self {
            daemon_id,
            msg_ctx: MessageContext::new(daemon_id),
            outbound_tx,
            inbound_rx,
            pending: Arc::new(Mutex::new(HashMap::new())),
            epoch: Instant::now(),
            io_handle: None,
        }
    }

    /// Connect to the bus server with Noise IK encrypted transport.
    ///
    /// Low-level constructor used by tests and `connect_with_keypair_retry`.
    /// Does NOT handle key rotation — the I/O task is a plain byte pipe.
    /// Production daemons should use `connect_daemon_with_keypair_retry` instead.
    ///
    /// # Errors
    ///
    /// Returns an error if connection, key read, or handshake fails.
    pub async fn connect_encrypted(
        daemon_id: DaemonId,
        path: &Path,
        server_public_key: &[u8; 32],
        client_keypair: &snow::Keypair,
    ) -> core_types::Result<Self> {
        let stream = connect_with_retry(path, 3, Duration::from_millis(100)).await?;
        let server_creds = extract_ucred(&stream)?;
        let local_creds = local_credentials();

        let (reader, writer) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let mut writer = tokio::io::BufWriter::new(writer);

        let transport = crate::noise::client_handshake(
            &mut reader,
            &mut writer,
            server_public_key,
            client_keypair,
            &local_creds,
            &server_creds,
        )
        .await?;

        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(256);
        let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(1024);
        let pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<Message<EventKind>>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let pending_clone = Arc::clone(&pending);
        let io_handle = tokio::spawn(async move {
            let mut transport = transport;
            let mut reader = reader;
            let mut writer = writer;
            loop {
                tokio::select! {
                    result = transport.read_encrypted_frame(&mut reader) => {
                        if let Ok(payload) = result {
                            route_inbound(payload, &pending_clone, &inbound_tx).await;
                        } else {
                            tracing::info!("server disconnected (encrypted)");
                            break;
                        }
                    }
                    msg = outbound_rx.recv() => {
                        if let Some(mut payload) = msg {
                            let result = transport.write_encrypted_frame(&mut writer, &payload).await;
                            zeroize::Zeroize::zeroize(&mut payload);
                            if let Err(e) = result {
                                tracing::debug!(error = %e, "encrypted write failed, closing client");
                                break;
                            }
                        } else {
                            tracing::debug!("outbound channel closed, I/O task exiting");
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self {
            daemon_id,
            msg_ctx: MessageContext::new(daemon_id),
            outbound_tx,
            inbound_rx,
            pending,
            epoch: Instant::now(),
            io_handle: Some(io_handle),
        })
    }

    /// Connect to the bus as a named daemon with transparent key rotation.
    ///
    /// Same handshake as `connect_encrypted`, but the I/O task intercepts
    /// `KeyRotationPending` messages matching `config.daemon_name` and
    /// performs reconnection internally. The caller's `recv()` is never
    /// interrupted by routine rotation.
    ///
    /// On rotation failure (disk error, connection refused), the I/O task
    /// logs the error and continues on the existing connection. The old key
    /// remains valid in the registry during the grace period.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial connection or handshake fails.
    async fn connect_as_daemon(
        config: RotationConfig,
        client_keypair: &snow::Keypair,
    ) -> core_types::Result<Self> {
        let stream = connect_with_retry(&config.socket_path, 3, Duration::from_millis(100)).await?;
        let server_creds = extract_ucred(&stream)?;
        let local_creds = local_credentials();

        let (reader, writer) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let mut writer = tokio::io::BufWriter::new(writer);

        let transport = crate::noise::client_handshake(
            &mut reader,
            &mut writer,
            &config.server_pub,
            client_keypair,
            &local_creds,
            &server_creds,
        )
        .await?;

        let daemon_id = config.daemon_id;
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Vec<u8>>(256);
        let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(1024);
        let pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<Message<EventKind>>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let pending_clone = Arc::clone(&pending);
        let io_handle = tokio::spawn(async move {
            let mut transport = transport;
            let mut reader = reader;
            let mut writer = writer;
            loop {
                tokio::select! {
                    result = transport.read_encrypted_frame(&mut reader) => {
                        if let Ok(payload) = result {
                            if let RotationResult::NotRotation = try_handle_rotation(
                                &payload, &config, &mut transport, &mut reader, &mut writer,
                            ).await {
                                route_inbound(payload, &pending_clone, &inbound_tx).await;
                            }
                        } else {
                            tracing::error!("server disconnected (encrypted)");
                            break;
                        }
                    }
                    msg = outbound_rx.recv() => {
                        if let Some(mut payload) = msg {
                            let result = transport.write_encrypted_frame(&mut writer, &payload).await;
                            zeroize::Zeroize::zeroize(&mut payload);
                            if let Err(e) = result {
                                tracing::debug!(error = %e, "encrypted write failed, closing client");
                                break;
                            }
                        } else {
                            tracing::debug!("outbound channel closed, I/O task exiting");
                            break;
                        }
                    }
                }
            }
        });

        Ok(Self {
            daemon_id,
            msg_ctx: MessageContext::new(daemon_id),
            outbound_tx,
            inbound_rx,
            pending,
            epoch: Instant::now(),
            io_handle: Some(io_handle),
        })
    }

    /// Send a message to the bus server.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the connection is closed.
    pub async fn send(&self, msg: &Message<EventKind>) -> core_types::Result<()> {
        let payload = encode_frame(msg)?;
        self.outbound_tx
            .send(payload)
            .await
            .map_err(|_| core_types::Error::Ipc("outbound channel closed".into()))?;
        Ok(())
    }

    /// Publish an event to the bus.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the outbound channel is closed.
    pub async fn publish(
        &self,
        event: EventKind,
        security_level: SecurityLevel,
    ) -> core_types::Result<()> {
        let msg = Message::new(&self.msg_ctx, event, security_level, self.epoch);
        self.send(&msg).await
    }

    /// Send a request and wait for a correlated response.
    ///
    /// # Errors
    ///
    /// Returns an error on send failure or timeout.
    pub async fn request(
        &self,
        event: EventKind,
        security_level: SecurityLevel,
        timeout: Duration,
    ) -> core_types::Result<Message<EventKind>> {
        let msg = Message::new(&self.msg_ctx, event, security_level, self.epoch);
        let msg_id = msg.msg_id;

        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(msg_id, tx);

        self.send(&msg).await?;

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => {
                self.pending.lock().await.remove(&msg_id);
                Err(core_types::Error::Ipc("response channel dropped".into()))
            }
            Err(_) => {
                self.pending.lock().await.remove(&msg_id);
                Err(core_types::Error::Ipc(format!(
                    "request timed out after {}ms",
                    timeout.as_millis()
                )))
            }
        }
    }

    /// Receive the next broadcast/unsolicited inbound event.
    ///
    /// Returns `None` if the server disconnected.
    pub async fn recv(&mut self) -> Option<Message<EventKind>> {
        let mut payload = self.inbound_rx.recv().await?;
        let result = decode_frame(&payload);
        // Zeroize raw postcard bytes — may contain serialized secret values.
        zeroize::Zeroize::zeroize(&mut payload);
        match result {
            Ok(msg) => Some(msg),
            Err(e) => {
                tracing::warn!(error = %e, "failed to decode inbound frame");
                None
            }
        }
    }

    /// Return this client's daemon ID.
    #[must_use]
    pub fn daemon_id(&self) -> DaemonId {
        self.daemon_id
    }

    /// Return the client's monotonic epoch.
    #[must_use]
    pub fn epoch(&self) -> Instant {
        self.epoch
    }

    /// Set the installation identity on the message context.
    pub fn set_installation(&mut self, installation: core_types::InstallationId) {
        self.msg_ctx.installation = Some(installation);
    }

    /// Gracefully shut down the client, flushing all pending outbound frames.
    pub async fn shutdown(self) {
        drop(self.outbound_tx);
        if let Some(handle) = self.io_handle {
            let _ = handle.await;
        }
    }

    /// Connect to the IPC bus with keypair re-read on each attempt.
    ///
    /// Low-level retry constructor for CLI clients and tests.
    /// Does NOT handle key rotation. Production daemons should use
    /// `connect_daemon_with_keypair_retry`.
    ///
    /// # Errors
    ///
    /// Returns an error if all attempts fail (keypair read or connect).
    pub async fn connect_with_keypair_retry(
        daemon_name: &str,
        daemon_id: DaemonId,
        socket_path: &Path,
        server_pub: &[u8; 32],
        max_attempts: u32,
        backoff: Duration,
    ) -> core_types::Result<(Self, crate::noise::ZeroizingKeypair)> {
        let mut last_err = None;
        for attempt in 1..=max_attempts {
            let (private_key, public_key) =
                match crate::noise::read_daemon_keypair(daemon_name).await {
                    Ok(kp) => kp,
                    Err(e) => {
                        tracing::warn!(attempt, error = %e, "keypair read failed, retrying");
                        last_err = Some(e);
                        if attempt < max_attempts {
                            tokio::time::sleep(backoff * attempt).await;
                        }
                        continue;
                    }
                };
            let client_keypair = crate::noise::ZeroizingKeypair::new(snow::Keypair {
                private: private_key.to_vec(),
                public: public_key.to_vec(),
            });

            match Self::connect_encrypted(
                daemon_id,
                socket_path,
                server_pub,
                client_keypair.as_inner(),
            )
            .await
            {
                Ok(client) => {
                    return Ok((client, client_keypair));
                }
                Err(e) => {
                    tracing::warn!(attempt, error = %e, "IPC connect failed, retrying");
                    last_err = Some(e);
                    if attempt < max_attempts {
                        tokio::time::sleep(backoff * attempt).await;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            core_types::Error::Ipc(format!("connect failed after {max_attempts} attempts"))
        }))
    }

    /// Connect to the IPC bus as a named daemon with transparent key rotation.
    ///
    /// Same retry logic as `connect_with_keypair_retry`, but the returned
    /// client's I/O task automatically handles `KeyRotationPending` messages.
    /// The caller never sees rotation events and `recv()` is uninterrupted.
    ///
    /// The initial `DaemonStarted` announcement is NOT sent by this method —
    /// the caller publishes it after connecting.
    ///
    /// # Errors
    ///
    /// Returns an error if all connection attempts fail.
    pub async fn connect_daemon_with_keypair_retry(
        daemon_name: &str,
        daemon_id: DaemonId,
        socket_path: &Path,
        server_pub: &[u8; 32],
        capabilities: Vec<String>,
        version: &str,
        retry: RetryConfig,
    ) -> core_types::Result<Self> {
        let config = RotationConfig {
            daemon_name: daemon_name.to_owned(),
            daemon_id,
            socket_path: socket_path.to_owned(),
            server_pub: *server_pub,
            capabilities,
            version: version.to_owned(),
        };

        let mut last_err = None;
        for attempt in 1..=retry.max_attempts {
            let (private_key, public_key) =
                match crate::noise::read_daemon_keypair(daemon_name).await {
                    Ok(kp) => kp,
                    Err(e) => {
                        tracing::warn!(attempt, error = %e, "keypair read failed, retrying");
                        last_err = Some(e);
                        if attempt < retry.max_attempts {
                            tokio::time::sleep(retry.backoff * attempt).await;
                        }
                        continue;
                    }
                };
            let client_keypair = crate::noise::ZeroizingKeypair::new(snow::Keypair {
                private: private_key.to_vec(),
                public: public_key.to_vec(),
            });

            match Self::connect_as_daemon(config.clone(), client_keypair.as_inner()).await {
                Ok(client) => return Ok(client),
                Err(e) => {
                    tracing::warn!(attempt, error = %e, "IPC connect failed, retrying");
                    last_err = Some(e);
                    if attempt < retry.max_attempts {
                        tokio::time::sleep(retry.backoff * attempt).await;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            core_types::Error::Ipc(format!(
                "connect failed after {} attempts",
                retry.max_attempts
            ))
        }))
    }
}

/// Result of checking whether an inbound payload is a rotation message.
enum RotationResult {
    /// The message was a `KeyRotationPending` for this daemon and was handled.
    /// Transport/reader/writer have been swapped. Continue the I/O loop.
    Handled,
    /// The message was not a rotation event. Forward it normally.
    NotRotation,
}

/// Check if an inbound payload is a `KeyRotationPending` for this daemon.
/// If so, reconnect with the new keypair and swap the transport in place.
/// On failure, log the error and return `NotRotation` so the original
/// payload is forwarded to the caller — the old connection remains valid.
#[allow(clippy::similar_names)] // reader vs new_reader, writer vs new_writer
async fn try_handle_rotation(
    payload: &[u8],
    config: &RotationConfig,
    transport: &mut crate::noise::NoiseTransport,
    reader: &mut tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: &mut tokio::io::BufWriter<tokio::net::unix::OwnedWriteHalf>,
) -> RotationResult {
    // Attempt decode. If it fails, this isn't a valid message for us.
    let msg: Message<EventKind> = match decode_frame(payload) {
        Ok(m) => m,
        Err(_) => return RotationResult::NotRotation,
    };

    let (announced_name, announced_pubkey) = match &msg.payload {
        EventKind::KeyRotationPending {
            daemon_name,
            new_pubkey,
            ..
        } => (daemon_name.as_str(), new_pubkey),
        _ => return RotationResult::NotRotation,
    };

    if announced_name != config.daemon_name {
        return RotationResult::NotRotation;
    }

    tracing::info!(
        daemon = %config.daemon_name,
        "key rotation: reading new keypair and reconnecting"
    );

    // Perform the reconnection. All errors are recoverable — the old
    // connection remains valid because both keys are in the registry.
    match perform_rotation(config, announced_pubkey, transport, reader, writer).await {
        Ok(()) => RotationResult::Handled,
        Err(e) => {
            tracing::error!(
                daemon = %config.daemon_name,
                error = %e,
                "key rotation failed, continuing on current connection"
            );
            RotationResult::NotRotation
        }
    }
}

/// Execute the key rotation: read keypair, connect, handshake, announce,
/// swap transport/reader/writer in place.
async fn perform_rotation(
    config: &RotationConfig,
    announced_pubkey: &[u8; 32],
    transport: &mut crate::noise::NoiseTransport,
    reader: &mut tokio::io::BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: &mut tokio::io::BufWriter<tokio::net::unix::OwnedWriteHalf>,
) -> core_types::Result<()> {
    let (new_private, new_public) = crate::noise::read_daemon_keypair(&config.daemon_name).await?;

    if new_public != *announced_pubkey {
        return Err(core_types::Error::Ipc(
            "rotated pubkey mismatch: disk vs announced — possible tampering".into(),
        ));
    }

    let kp = crate::noise::ZeroizingKeypair::new(snow::Keypair {
        private: new_private.to_vec(),
        public: new_public.to_vec(),
    });

    let new_stream = connect_with_retry(&config.socket_path, 3, Duration::from_millis(100)).await?;
    let server_creds = extract_ucred(&new_stream)?;
    let local_creds = local_credentials();

    let (new_read_half, new_write_half) = new_stream.into_split();
    let mut new_reader = tokio::io::BufReader::new(new_read_half);
    let mut new_writer = tokio::io::BufWriter::new(new_write_half);

    let mut new_transport = crate::noise::client_handshake(
        &mut new_reader,
        &mut new_writer,
        &config.server_pub,
        kp.as_inner(),
        &local_creds,
        &server_creds,
    )
    .await?;
    // kp dropped here — ZeroizingKeypair::drop() zeroizes private key.

    // Write DaemonStarted directly on the new connection before swapping.
    // Uses the same DaemonId to preserve the rotation cascade invariant:
    // DaemonTracker only triggers revocation when old_id != new_id.
    let msg_ctx = MessageContext::new(config.daemon_id);
    let announce = Message::new(
        &msg_ctx,
        EventKind::DaemonStarted {
            daemon_id: config.daemon_id,
            version: config.version.clone(),
            capabilities: config.capabilities.clone(),
        },
        SecurityLevel::Internal,
        Instant::now(),
    );
    let mut announce_bytes = encode_frame(&announce)?;
    new_transport
        .write_encrypted_frame(&mut new_writer, &announce_bytes)
        .await?;
    zeroize::Zeroize::zeroize(&mut announce_bytes);

    // Swap transport, reader, writer in place. Old socket fds are dropped,
    // causing the server to see a clean disconnect on the old connection.
    *transport = new_transport;
    *reader = new_reader;
    *writer = new_writer;

    tracing::info!(
        daemon = %config.daemon_name,
        "key rotation: transport swapped to new connection"
    );

    Ok(())
}

/// Route an inbound payload to pending waiters or the broadcast channel.
async fn route_inbound(
    payload: Vec<u8>,
    pending: &Mutex<HashMap<Uuid, oneshot::Sender<Message<EventKind>>>>,
    inbound_tx: &mpsc::Sender<Vec<u8>>,
) {
    match decode_frame::<Message<EventKind>>(&payload) {
        Ok(msg) => {
            if let Some(corr_id) = msg.correlation_id {
                let waiter = pending.lock().await.remove(&corr_id);
                if let Some(tx) = waiter {
                    let _ = tx.send(msg);
                    return;
                }
            }
            if inbound_tx.try_send(payload).is_err() {
                tracing::warn!("inbound channel full, frame dropped");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to decode inbound frame");
        }
    }
}

/// Connect to a Unix socket with retries.
async fn connect_with_retry(
    path: &Path,
    max_attempts: u32,
    backoff: Duration,
) -> core_types::Result<UnixStream> {
    let mut last_err = None;
    for attempt in 1..=max_attempts {
        match UnixStream::connect(path).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                tracing::debug!(
                    attempt,
                    max_attempts,
                    path = %path.display(),
                    error = %e,
                    "connection attempt failed"
                );
                last_err = Some(e);
                if attempt < max_attempts {
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }
    Err(core_types::Error::Ipc(format!(
        "failed to connect to {} after {max_attempts} attempts: {}",
        path.display(),
        last_err.map_or_else(|| "unknown error".to_string(), |e| e.to_string())
    )))
}
