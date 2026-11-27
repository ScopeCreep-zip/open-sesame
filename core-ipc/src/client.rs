//! IPC bus client — connects to the bus server, publishes events,
//! and receives subscribed events over a Unix domain socket.
//!
//! Two connection modes:
//! - `connect_encrypted()`: an ephemeral client (the CLI) with a keypair the
//!   registry does not know.
//! - `connect_daemon_with_keypair_retry()`: a named daemon with its issued
//!   keypair. Its I/O task handles `KeyRotationPending` for the daemon, so
//!   the caller's `recv()` is never interrupted by routine key rotation.
//!
//! Each inbound frame is decoded once, in the I/O task: correlated
//! responses go to their waiting request, everything else to `recv()`.

use crate::message::MessageContext;
use crate::noise::{BusEndpoint, Connection};
use core_layout::Layout;
use core_types::{DaemonId, EventKind, SecurityLevel};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UnixStream;
use tokio::sync::{Mutex, mpsc, oneshot};
use uuid::Uuid;

use crate::framing::{decode_frame, encode_frame};
use crate::message::Message;
use crate::transport::extract_ucred;

/// Retry parameters for initial IPC bus connection.
pub struct RetryConfig {
    /// Maximum connection attempts before giving up.
    pub max_attempts: u32,
    /// Base backoff duration between attempts (multiplied by attempt number).
    pub backoff: Duration,
}

/// Request-response waiters, keyed by the request's `msg_id`.
type Pending = Arc<Mutex<HashMap<Uuid, oneshot::Sender<Message<EventKind>>>>>;

/// What a named daemon's I/O task needs to follow a key rotation.
struct RotationConfig {
    /// The keypair and bus endpoint locations; rotation re-reads the
    /// keypair from the same layout the daemon started with.
    layout: Layout,
    daemon_name: String,
    daemon_id: DaemonId,
    endpoint: BusEndpoint,
    capabilities: Vec<String>,
    version: String,
}

/// Connect to the socket at `path` and handshake with `endpoint` as
/// `keypair`.
async fn open(
    path: &Path,
    endpoint: &BusEndpoint,
    keypair: &snow::Keypair,
) -> core_types::Result<Connection> {
    let stream = connect_with_retry(path, 3, Duration::from_millis(100)).await?;
    let server_creds = extract_ucred(&stream)?;
    Connection::client(stream, endpoint, keypair, &server_creds).await
}

/// The IPC bus client used by each daemon to communicate on the bus.
pub struct BusClient {
    daemon_id: DaemonId,
    msg_ctx: MessageContext,
    /// Outbound frames to send to the server.
    outbound_tx: mpsc::Sender<Vec<u8>>,
    /// Inbound messages that answer no pending request.
    inbound_rx: mpsc::Receiver<Message<EventKind>>,
    pending: Pending,
    epoch: Instant,
    /// The I/O task owning the encrypted connection.
    io_handle: tokio::task::JoinHandle<()>,
}

impl BusClient {
    /// Connect as an ephemeral client: `client_keypair` is not in the
    /// clearance registry, and no key rotation is followed.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection or handshake fails.
    pub async fn connect_encrypted(
        daemon_id: DaemonId,
        path: &Path,
        endpoint: &BusEndpoint,
        client_keypair: &snow::Keypair,
    ) -> core_types::Result<Self> {
        let connection = open(path, endpoint, client_keypair).await?;
        Ok(Self::start(daemon_id, connection, None))
    }

    /// Connect as the named daemon `daemon_name` with the keypair issued to
    /// it, retrying `retry.max_attempts` times. The keypair is re-read on
    /// every attempt (daemon-profile may be issuing it). The I/O task
    /// follows `KeyRotationPending` for this daemon: it reads the rotated
    /// keypair, reconnects, re-announces `DaemonStarted`, and swaps the
    /// connection without the caller seeing it.
    ///
    /// The initial `DaemonStarted` announcement is the caller's.
    ///
    /// # Errors
    ///
    /// The last attempt's error when every attempt fails.
    pub async fn connect_daemon_with_keypair_retry(
        layout: &Layout,
        daemon_name: &str,
        daemon_id: DaemonId,
        endpoint: &BusEndpoint,
        capabilities: Vec<String>,
        version: &str,
        retry: RetryConfig,
    ) -> core_types::Result<Self> {
        let socket = layout.bus_socket()?;
        let mut last_err = None;
        for attempt in 1..=retry.max_attempts {
            let attempt_result = async {
                let keypair = read_keypair(layout, daemon_name).await?;
                open(&socket, endpoint, keypair.as_inner()).await
            }
            .await;
            match attempt_result {
                Ok(connection) => {
                    let rotation = RotationConfig {
                        layout: layout.clone(),
                        daemon_name: daemon_name.to_owned(),
                        daemon_id,
                        endpoint: *endpoint,
                        capabilities,
                        version: version.to_owned(),
                    };
                    return Ok(Self::start(daemon_id, connection, Some(rotation)));
                }
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

    /// Start the I/O task that owns `connection`.
    fn start(
        daemon_id: DaemonId,
        connection: Connection,
        rotation: Option<RotationConfig>,
    ) -> Self {
        let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(256);
        let (inbound_tx, inbound_rx) = mpsc::channel(1024);
        let pending = Pending::default();
        let io_handle = tokio::spawn(io_loop(
            connection,
            rotation,
            Arc::clone(&pending),
            inbound_tx,
            outbound_rx,
        ));
        Self {
            daemon_id,
            msg_ctx: MessageContext::new(daemon_id),
            outbound_tx,
            inbound_rx,
            pending,
            epoch: Instant::now(),
            io_handle,
        }
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

    /// Publish an event whose delivery the caller does not act on
    /// (lifecycle announcements, notifications). A failure is logged at
    /// `warn` with `what` naming the event; the payload is never logged,
    /// since events can carry sensitive data.
    pub async fn publish_or_log(
        &self,
        what: &'static str,
        event: EventKind,
        security_level: SecurityLevel,
    ) {
        if let Err(e) = self.publish(event, security_level).await {
            tracing::warn!(event = what, error = %e, "bus publish failed");
        }
    }

    /// Send a request and wait for a correlated response.
    ///
    /// # Errors
    ///
    /// `core_types::Error::Timeout` when no response arrives within
    /// `timeout`; `core_types::Error::Ipc` on send failure.
    pub async fn request(
        &self,
        event: EventKind,
        security_level: SecurityLevel,
        timeout: Duration,
    ) -> core_types::Result<Message<EventKind>> {
        let msg =
            Message::new(&self.msg_ctx, event, security_level, self.epoch).expecting_response();
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
                Err(core_types::Error::Timeout {
                    operation: "request".into(),
                    after: timeout,
                })
            }
        }
    }

    /// Receive the next inbound message that answers no pending request.
    ///
    /// Returns `None` only when the server disconnected.
    pub async fn recv(&mut self) -> Option<Message<EventKind>> {
        self.inbound_rx.recv().await
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
        if let Err(e) = self.io_handle.await {
            // The I/O task panicked or was cancelled; frames still queued
            // in it were not delivered.
            tracing::error!(error = %e, "IPC client I/O task did not finish cleanly");
        }
    }
}

/// The daemon's issued keypair, verified against its checksum.
async fn read_keypair(
    layout: &Layout,
    daemon_name: &str,
) -> core_types::Result<crate::noise::ZeroizingKeypair> {
    let (private, public) = crate::noise::read_daemon_keypair(layout, daemon_name).await?;
    Ok(crate::noise::ZeroizingKeypair::new(snow::Keypair {
        private: private.to_vec(),
        public: public.to_vec(),
    }))
}

/// Own `connection`: write outbound frames, and decode each inbound frame
/// once — a `KeyRotationPending` for this daemon is followed (`rotation`),
/// a correlated response goes to its waiter, anything else to `recv()`.
async fn io_loop(
    mut connection: Connection,
    rotation: Option<RotationConfig>,
    pending: Pending,
    inbound_tx: mpsc::Sender<Message<EventKind>>,
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
) {
    loop {
        tokio::select! {
            result = connection.transport.read_encrypted_frame(&mut connection.reader) => {
                let payload = match result {
                    Ok(payload) => zeroize::Zeroizing::new(payload),
                    Err(e) => {
                        tracing::info!(error = %e, "bus connection closed");
                        break;
                    }
                };
                let Some(msg) = decode_inbound(&payload) else {
                    continue;
                };
                if let Some(config) = &rotation
                    && let EventKind::KeyRotationPending { daemon_name, new_pubkey, .. } = &msg.payload
                    && *daemon_name == config.daemon_name
                {
                    follow_rotation(config, new_pubkey, &mut connection).await;
                    continue;
                }
                deliver(msg, &pending, &inbound_tx).await;
            }
            msg = outbound_rx.recv() => {
                let Some(payload) = msg else {
                    tracing::debug!("outbound channel closed, I/O task exiting");
                    break;
                };
                let payload = zeroize::Zeroizing::new(payload);
                if let Err(e) = connection.transport.write_encrypted_frame(&mut connection.writer, &payload).await {
                    tracing::debug!(error = %e, "encrypted write failed, closing client");
                    break;
                }
            }
        }
    }
}

/// Decode one inbound frame. A frame that does not decode is logged and
/// skipped: one malformed frame does not end the connection.
fn decode_inbound(payload: &[u8]) -> Option<Message<EventKind>> {
    match decode_frame(payload) {
        Ok(msg) => Some(msg),
        Err(e) => {
            tracing::warn!(error = %e, "inbound frame does not decode, skipped");
            None
        }
    }
}

/// Route a decoded message to its pending waiter, or to `recv()`.
async fn deliver(
    msg: Message<EventKind>,
    pending: &Mutex<HashMap<Uuid, oneshot::Sender<Message<EventKind>>>>,
    inbound_tx: &mpsc::Sender<Message<EventKind>>,
) {
    if let Some(corr_id) = msg.correlation_id {
        let waiter = pending.lock().await.remove(&corr_id);
        if let Some(tx) = waiter {
            // A closed receiver means the requester already timed out
            // and returned its error; the late response has no reader.
            if tx.send(msg).is_err() {
                tracing::debug!(%corr_id, "response arrived after its requester gave up");
            }
            return;
        }
    }
    if inbound_tx.try_send(msg).is_err() {
        tracing::warn!("inbound channel full, message dropped");
    }
}

/// Follow a `KeyRotationPending` for this daemon. A failure (disk error,
/// connection refused, announced key differing from the key on disk) is
/// logged and the current connection kept: both keys stay valid in the
/// registry for the grace period.
async fn follow_rotation(
    config: &RotationConfig,
    announced_pubkey: &[u8; 32],
    connection: &mut Connection,
) {
    tracing::info!(
        daemon = %config.daemon_name,
        "key rotation: reading new keypair and reconnecting"
    );
    match rotated_connection(config, announced_pubkey).await {
        Ok(rotated) => {
            // The old socket is dropped: the server sees a clean disconnect.
            *connection = rotated;
            tracing::info!(
                daemon = %config.daemon_name,
                "key rotation: transport swapped to new connection"
            );
        }
        Err(e) => tracing::error!(
            daemon = %config.daemon_name,
            error = %e,
            "key rotation failed, continuing on current connection"
        ),
    }
}

/// A connection under the rotated keypair, already re-announced with
/// `DaemonStarted` under the same `DaemonId` (daemon-profile treats a new
/// `DaemonId` as a crash-restart and revokes the keys).
async fn rotated_connection(
    config: &RotationConfig,
    announced_pubkey: &[u8; 32],
) -> core_types::Result<Connection> {
    let keypair = read_keypair(&config.layout, &config.daemon_name).await?;
    if keypair.public() != announced_pubkey {
        return Err(core_types::Error::Ipc(
            "rotated pubkey mismatch: disk vs announced — possible tampering".into(),
        ));
    }
    let mut connection = open(
        &config.layout.bus_socket()?,
        &config.endpoint,
        keypair.as_inner(),
    )
    .await?;
    let announce = Message::new(
        &MessageContext::new(config.daemon_id),
        EventKind::DaemonStarted {
            daemon_id: config.daemon_id,
            version: config.version.clone(),
            capabilities: config.capabilities.clone(),
        },
        SecurityLevel::Internal,
        Instant::now(),
    );
    let announce_bytes = zeroize::Zeroizing::new(encode_frame(&announce)?);
    connection
        .transport
        .write_encrypted_frame(&mut connection.writer, &announce_bytes)
        .await?;
    Ok(connection)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn message(correlation: Option<Uuid>) -> Message<EventKind> {
        let msg = Message::new(
            &MessageContext::new(DaemonId::new()),
            EventKind::StatusRequest,
            SecurityLevel::Internal,
            Instant::now(),
        );
        match correlation {
            Some(id) => msg.with_correlation(id),
            None => msg,
        }
    }

    #[test]
    fn undecodable_frames_are_skipped_and_valid_ones_decode() {
        assert!(decode_inbound(&[0xff; 8]).is_none());
        let valid = message(None);
        let decoded = decode_inbound(&encode_frame(&valid).unwrap()).unwrap();
        assert_eq!(decoded.msg_id, valid.msg_id);
    }

    #[tokio::test]
    async fn responses_reach_their_waiter_and_the_rest_reach_recv() {
        let pending = Pending::default();
        let (inbound_tx, mut inbound_rx) = mpsc::channel(4);
        let request_id = Uuid::new_v4();
        let (waiter_tx, waiter_rx) = oneshot::channel();
        pending.lock().await.insert(request_id, waiter_tx);

        let response = message(Some(request_id));
        let response_id = response.msg_id;
        deliver(response, &pending, &inbound_tx).await;
        assert_eq!(waiter_rx.await.unwrap().msg_id, response_id);
        assert!(pending.lock().await.is_empty());

        // A broadcast, and a response nobody waits for, reach recv().
        let broadcast = message(None);
        let orphan = message(Some(Uuid::new_v4()));
        let (broadcast_id, orphan_id) = (broadcast.msg_id, orphan.msg_id);
        deliver(broadcast, &pending, &inbound_tx).await;
        deliver(orphan, &pending, &inbound_tx).await;
        assert_eq!(inbound_rx.recv().await.unwrap().msg_id, broadcast_id);
        assert_eq!(inbound_rx.recv().await.unwrap().msg_id, orphan_id);
    }
}
