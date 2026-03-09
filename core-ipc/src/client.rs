//! IPC bus client — connects to the bus server, publishes events,
//! and receives subscribed events over a Unix domain socket.
//!
//! Production uses Noise IK encrypted transport exclusively via
//! `connect_encrypted()`. Plaintext `connect()` is `#[cfg(test)]` only.

use core_types::{DaemonId, EventKind, SecurityLevel};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, oneshot, Mutex};
use uuid::Uuid;

use crate::framing::{decode_frame, encode_frame};
use crate::message::Message;
use crate::transport::{extract_ucred, local_credentials};

/// The IPC bus client used by each daemon to communicate on the bus.
pub struct BusClient {
    daemon_id: DaemonId,
    /// Outbound frames to send to the server.
    outbound_tx: mpsc::Sender<Vec<u8>>,
    /// Inbound frames received from the server (broadcast/unsolicited).
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    /// Pending request-response waiters, keyed by `msg_id`.
    pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<Message<EventKind>>>>>,
    epoch: Instant,
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
            outbound_tx,
            inbound_rx,
            pending: Arc::new(Mutex::new(HashMap::new())),
            epoch: Instant::now(),
        }
    }

    /// Connect to the bus server with Noise IK encrypted transport.
    ///
    /// Reads the server's public key from `server_public_key`, generates an
    /// ephemeral client keypair, performs the Noise IK handshake, then
    /// spawns encrypted reader/writer tasks.
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

        // Extract peer creds via SO_PEERCRED before split.
        // Reject the connection if credentials cannot be verified.
        let server_creds = extract_ucred(&stream)?;
        let local_creds = local_credentials();

        let (reader, writer) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let mut writer = tokio::io::BufWriter::new(writer);

        // Perform Noise IK handshake.
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
        // Capacity 1024: was 256, caused backpressure drops when daemon-secrets
        // blocked on synchronous SQLCipher I/O. Increased alongside spawn_blocking
        // migration. Acceptable memory overhead for fewer than 10 daemon clients.
        let (inbound_tx, inbound_rx) = mpsc::channel::<Vec<u8>>(1024);
        let pending: Arc<Mutex<HashMap<Uuid, oneshot::Sender<Message<EventKind>>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Single multiplexed I/O task for encrypted transport.
        //
        // snow::TransportState requires &mut self for both encrypt and decrypt,
        // so we cannot split into separate reader/writer tasks. Using select!
        // to multiplex avoids the deadlock where a reader holding a Mutex
        // starves the writer.
        let pending_clone = Arc::clone(&pending);
        tokio::spawn(async move {
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
                    Some(mut payload) = outbound_rx.recv() => {
                        let result = transport.write_encrypted_frame(&mut writer, &payload).await;
                        // Zeroize plaintext postcard buffer after encryption.
                        zeroize::Zeroize::zeroize(&mut payload);
                        if let Err(e) = result {
                            tracing::debug!(error = %e, "encrypted write failed, closing client");
                            break;
                        }
                    }
                    else => break,
                }
            }
        });

        Ok(Self {
            daemon_id,
            outbound_tx,
            inbound_rx,
            pending,
            epoch: Instant::now(),
        })
    }

    /// Send a message to the bus server.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails or the connection is closed.
    pub async fn send(&self, msg: &Message<EventKind>) -> core_types::Result<()> {
        let payload = encode_frame(msg)?;
        self.outbound_tx.send(payload).await.map_err(|_| {
            core_types::Error::Ipc("outbound channel closed".into())
        })?;
        // Payload ownership transferred to channel. The I/O task zeroizes
        // the buffer after Noise encryption (see outbound_rx select! arm).
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
        let msg = Message::new(self.daemon_id, event, security_level, self.epoch);
        self.send(&msg).await
    }

    /// Send a request and wait for a correlated response.
    ///
    /// Creates a message, registers a oneshot waiter keyed by `msg_id`,
    /// sends the message, and awaits the response with a timeout.
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
        let msg = Message::new(self.daemon_id, event, security_level, self.epoch);
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

    /// Connect to the IPC bus with keypair re-read on each attempt.
    ///
    /// On crash-restart, daemon-profile may regenerate the daemon's keypair.
    /// Each retry re-reads the keypair from disk to pick up the new one.
    /// Returns the connected client and the keypair (caller must zeroize
    /// `keypair.private` after use — `snow::Keypair` has no `Drop` zeroize).
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
            // Re-read keypair on each attempt (daemon-profile may have regenerated it).
            let (private_key, public_key) = match crate::noise::read_daemon_keypair(daemon_name).await {
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
            // ZeroizingKeypair: Drop zeroizes private key even on panic.
            let client_keypair = crate::noise::ZeroizingKeypair::new(snow::Keypair {
                private: private_key.to_vec(),
                public: public_key.to_vec(),
            });

            match Self::connect_encrypted(daemon_id, socket_path, server_pub, client_keypair.as_inner()).await {
                Ok(client) => {
                    return Ok((client, client_keypair));
                }
                Err(e) => {
                    // client_keypair dropped here -- ZeroizingKeypair::drop() zeroizes private key.
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

    /// Handle a `KeyRotationPending` event: re-read keypair from disk, verify
    /// the announced pubkey matches, reconnect with the new key, and re-announce.
    ///
    /// Returns the new `BusClient` on success. The caller should replace their
    /// existing client with the returned one.
    ///
    /// **Rotation cascade invariant**: The re-announce uses the SAME `daemon_id`
    /// passed in (not a new one). `DaemonTracker` in daemon-profile only triggers
    /// revocation when `old_id != new_id`, so planned rotations (same `DaemonId`)
    /// do not cascade. Only crash-restarts (new `DaemonId`) trigger revocation.
    ///
    /// # Errors
    ///
    /// Returns an error if keypair read, pubkey verification, or reconnect fails.
    pub async fn handle_key_rotation(
        daemon_name: &str,
        daemon_id: DaemonId,
        socket_path: &Path,
        server_pub: &[u8; 32],
        announced_pubkey: &[u8; 32],
        capabilities: Vec<String>,
        version: &str,
    ) -> core_types::Result<Self> {
        let (new_private, new_public) = crate::noise::read_daemon_keypair(daemon_name).await?;

        if new_public != *announced_pubkey {
            return Err(core_types::Error::Ipc(
                "rotated pubkey mismatch: disk vs announced — possible tampering".into(),
            ));
        }

        // ZeroizingKeypair: Drop zeroizes private key even on panic.
        let kp = crate::noise::ZeroizingKeypair::new(snow::Keypair {
            private: new_private.to_vec(),
            public: new_public.to_vec(),
        });
        let new_client = Self::connect_encrypted(daemon_id, socket_path, server_pub, kp.as_inner()).await?;
        // kp dropped here -- ZeroizingKeypair::drop() zeroizes private key.

        // Re-announce on the new connection.
        if let Err(e) = new_client
            .publish(
                core_types::EventKind::DaemonStarted {
                    daemon_id,
                    version: version.into(),
                    capabilities,
                },
                core_types::SecurityLevel::Internal,
            )
            .await
        {
            tracing::warn!(error = %e, daemon = daemon_name, "re-announce after key rotation failed");
        }

        Ok(new_client)
    }
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
