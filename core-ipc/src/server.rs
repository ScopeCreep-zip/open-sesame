//! IPC bus server — manages subscriber registrations, event routing,
//! and security level filtering over Unix domain sockets.
//!
//! The bus server lives inside `daemon-profile`. It binds a `UnixListener`,
//! accepts client connections with `UCred` authentication, and routes
//! postcard-framed messages between connected daemons.
//!
//! Every socket connection performs a Noise IK handshake, under the suite
//! the server was bound with, before any application data flows.

use core_types::{DaemonId, EventKind, SecurityLevel, TrustVector};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{RwLock, mpsc};
use uuid::Uuid;

use crate::framing::{decode_frame, encode_frame};
use crate::message::Message;
use crate::noise::{BusEndpoint, Connection, NoiseSuite};
use crate::registry::ClearanceRegistry;
use crate::transport::{PeerCredentials, extract_ucred, local_credentials};

/// How long a request waits for its response before the bus forgets its
/// sender: longer than any client request timeout, so an answer is never
/// dropped while its requester still waits.
const PENDING_REQUEST_TTL: Duration = Duration::from_mins(2);

/// Per-connection state tracked by the bus server. Routing delivers a
/// frame to every other connection whose clearance is at least the
/// frame's security level.
struct ConnectionState {
    daemon_id: Option<DaemonId>,
    /// Registry-verified daemon name from Noise IK handshake.
    /// `None` for unregistered clients (CLI, Open clearance).
    verified_name: Option<String>,
    tx: mpsc::Sender<Vec<u8>>,
    security_clearance: SecurityLevel,
    /// Trust assessment computed at connection time from handshake evidence.
    trust_vector: Option<TrustVector>,
}

/// A request awaiting its response: the connection that sent it, `None`
/// once that connection has closed, and when it was sent.
struct PendingRequest {
    conn_id: Option<u64>,
    sent_at: Instant,
}

/// Where the response to a request goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requester {
    /// The connection that sent the request, still open.
    Connected(u64),
    /// The requester disconnected before its response (it gave up
    /// waiting): there is nothing to deliver.
    Disconnected,
    /// No request with this id awaits a response: it was never tracked, or
    /// is older than the pending-request TTL.
    Unknown,
}

/// Shared state for the bus server, accessible from per-connection tasks.
struct ServerState {
    /// The server's Noise IK static keypair. Held in memory only.
    keypair: snow::Keypair,
    /// The suite every connection handshakes with and the public half of
    /// `keypair`, as clients receive it.
    endpoint: BusEndpoint,
    connections: RwLock<HashMap<u64, ConnectionState>>,
    /// Requests awaiting a response (`Message::expects_response`), by
    /// `msg_id`, for routing the response back to its sender.
    pending_requests: RwLock<HashMap<Uuid, PendingRequest>>,
    next_conn_id: AtomicU64,
    epoch: Instant,
    /// Maps public keys to daemon identities and security clearance levels.
    /// `RwLock` allows key rotation and revocation at runtime.
    registry: RwLock<ClearanceRegistry>,
    /// Confirmed RPC routing: maps `correlation_id` -> channel for host-side waiters.
    /// When a correlated response matches a registered confirmation, the raw frame is
    /// sent to the confirmation channel instead of the normal host delivery path.
    confirmations: RwLock<HashMap<Uuid, mpsc::Sender<Vec<u8>>>>,
    /// Maps verified daemon name -> connection ID for O(1) unicast.
    /// Populated when `route_frame()` processes `DaemonStarted` with a `verified_sender_name`.
    /// Invalidated on connection disconnect.
    name_to_conn: RwLock<HashMap<String, u64>>,
}

/// RAII guard that deregisters a confirmation route on drop.
///
/// Returned by [`BusServer::register_confirmation()`]. When dropped (including
/// on panic/early return), removes the confirmation entry from the routing table.
/// This prevents stale entries from accumulating if the caller times out or errors.
pub struct ConfirmationGuard {
    correlation_id: Uuid,
    state: Arc<ServerState>,
}

impl Drop for ConfirmationGuard {
    fn drop(&mut self) {
        // Use try_write to avoid blocking in Drop. If the lock is held,
        // the entry will be cleaned up by the next write operation.
        if let Ok(mut confirmations) = self.state.confirmations.try_write() {
            confirmations.remove(&self.correlation_id);
        } else {
            // Spawn a task to clean up asynchronously if we can't get the lock.
            let id = self.correlation_id;
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                state.confirmations.write().await.remove(&id);
            });
        }
    }
}

/// The IPC bus server: a bound socket and the state its connections share.
pub struct BusServer {
    listener: UnixListener,
    /// The bound socket, removed when the server is dropped.
    socket_path: PathBuf,
    state: Arc<ServerState>,
}

impl BusServer {
    /// Bind a Unix domain socket listener at `path`, handshaking every
    /// connection with `keypair` under `suite`.
    ///
    /// Creates a missing parent directory owner-only and restricts the
    /// socket to its owner. A stale socket at `path` is removed first.
    /// Clients reach this server through [`Self::endpoint`], published with
    /// [`crate::noise::publish_bus_endpoint`].
    ///
    /// # Errors
    ///
    /// When the directory cannot be created, a stale socket cannot be
    /// removed, the public key is not 32 bytes, or binding fails.
    pub fn bind(
        path: &Path,
        keypair: snow::Keypair,
        registry: ClearanceRegistry,
        suite: NoiseSuite,
    ) -> core_types::Result<Self> {
        let public_key: [u8; 32] =
            keypair.public.as_slice().try_into().map_err(|_| {
                core_types::Error::Ipc("bus server public key is not 32 bytes".into())
            })?;
        if let Some(parent) = path.parent() {
            core_layout::file::create_private_dir(parent)?;
        }
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(core_types::Error::Ipc(format!(
                    "failed to remove stale socket {}: {e}",
                    path.display()
                )));
            }
        }

        let listener = UnixListener::bind(path).map_err(|e| {
            core_types::Error::Ipc(format!("failed to bind socket {}: {e}", path.display()))
        })?;

        // Defense-in-depth: UCred same-UID validation is the security
        // boundary; an owner-only socket also refuses other users at
        // connect().
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| {
                    core_types::Error::Ipc(format!(
                        "failed to set socket permissions on {}: {e}",
                        path.display()
                    ))
                },
            )?;
        }

        tracing::info!(
            path = %path.display(),
            protocol = suite.protocol_name(),
            "IPC bus server bound"
        );

        Ok(Self {
            listener,
            socket_path: path.to_owned(),
            state: Arc::new(ServerState {
                keypair,
                endpoint: BusEndpoint { suite, public_key },
                connections: RwLock::new(HashMap::new()),
                pending_requests: RwLock::new(HashMap::new()),
                next_conn_id: AtomicU64::new(1),
                epoch: Instant::now(),
                registry: RwLock::new(registry),
                confirmations: RwLock::new(HashMap::new()),
                name_to_conn: RwLock::new(HashMap::new()),
            }),
        })
    }

    /// The endpoint clients handshake with: the suite this server binds
    /// every connection with and its static public key.
    #[must_use]
    pub fn endpoint(&self) -> BusEndpoint {
        self.state.endpoint
    }

    /// Run the accept loop until the future is dropped (cancel it with
    /// `tokio::select!` against a shutdown signal). A failed accept is
    /// logged and retried after 50 ms.
    pub async fn run(&self) -> std::convert::Infallible {
        loop {
            match self.listener.accept().await {
                Ok((stream, _addr)) => {
                    let peer = match extract_ucred(&stream) {
                        Ok(creds) => creds,
                        Err(e) => {
                            tracing::error!(error = %e, "rejecting connection: UCred extraction failed");
                            continue;
                        }
                    };

                    // Enforce same-UID policy: only the owning user may connect.
                    let my_uid = local_credentials().uid;
                    if peer.uid != my_uid {
                        tracing::error!(
                            peer_uid = peer.uid,
                            my_uid,
                            "rejecting connection: UID mismatch"
                        );
                        continue;
                    }

                    let conn_id = self.state.next_conn_id.fetch_add(1, Ordering::Relaxed);
                    tracing::info!(conn_id, pid = peer.pid, uid = peer.uid, "client connected");
                    let state = Arc::clone(&self.state);
                    tokio::spawn(handle_connection(state, conn_id, stream, peer));
                }
                Err(e) => {
                    tracing::error!(error = %e, "accept failed");
                    // Transient errors: continue. Fatal errors would typically
                    // be caught by the OS (e.g. too many open files).
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    }

    /// Register an in-process subscriber (the bus host itself): frames
    /// routed to it arrive on `tx`, filtered by `security_clearance` like
    /// any socket connection.
    pub async fn register(
        &self,
        daemon_id: DaemonId,
        security_clearance: SecurityLevel,
        tx: mpsc::Sender<Vec<u8>>,
    ) {
        let conn_id = self.state.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let state = ConnectionState {
            daemon_id: Some(daemon_id),
            verified_name: None, // In-process subscribers have no Noise handshake.
            tx,
            security_clearance,
            trust_vector: None,
        };
        self.state.connections.write().await.insert(conn_id, state);
        tracing::info!(%daemon_id, conn_id, "subscriber registered (in-process)");
    }

    /// Remove a subscriber by daemon ID.
    pub async fn unregister(&self, daemon_id: &DaemonId) {
        let mut conns = self.state.connections.write().await;
        conns.retain(|_, state| state.daemon_id.as_ref() != Some(daemon_id));
        tracing::info!(%daemon_id, "subscriber unregistered");
    }

    /// Publish an already-encoded frame to all matching subscribers.
    pub async fn publish(&self, frame: &[u8], security_level: SecurityLevel) {
        let conns = self.state.connections.read().await;
        // Decode sender from the frame to skip echoing back to the publisher.
        // This mirrors route_frame()'s `cid == sender_conn_id` skip for socket clients.
        let sender_id: Option<DaemonId> = decode_frame::<Message<EventKind>>(frame)
            .ok()
            .map(|msg| msg.sender);
        for (id, state) in conns.iter() {
            // Skip the publisher's own connection to prevent feedback loops.
            if let Some(sid) = sender_id
                && state.daemon_id == Some(sid)
            {
                continue;
            }
            if state.security_clearance >= security_level
                && state.tx.try_send(frame.to_vec()).is_err()
            {
                tracing::warn!(conn_id = id, "subscriber channel full, frame dropped");
            }
        }
    }

    /// Return the server's monotonic epoch for timestamp generation.
    #[must_use]
    pub fn epoch(&self) -> Instant {
        self.state.epoch
    }

    /// Send a frame to a specific connection by ID (unicast).
    ///
    /// Returns `true` if the frame was enqueued, `false` if the connection
    /// was not found or its channel was full.
    pub async fn send_to(&self, conn_id: u64, frame: &[u8]) -> bool {
        let conns = self.state.connections.read().await;
        conns
            .get(&conn_id)
            .is_some_and(|conn| conn.tx.try_send(frame.to_vec()).is_ok())
    }

    /// Access the clearance registry for mutation (key rotation, revocation).
    pub async fn registry_mut(&self) -> tokio::sync::RwLockWriteGuard<'_, ClearanceRegistry> {
        self.state.registry.write().await
    }

    /// Look up and forget the requester of request `correlation_id`, so its
    /// response is unicast back to it instead of broadcast.
    pub async fn take_pending_request(&self, correlation_id: &uuid::Uuid) -> Requester {
        take_requester(&self.state, correlation_id).await
    }

    /// Register a confirmation route for confirmed RPC.
    ///
    /// When a response with matching `correlation_id` arrives at `route_frame()`,
    /// the raw frame is sent to `confirm_tx` instead of the normal host delivery path.
    /// Returns a [`ConfirmationGuard`] that deregisters the route on drop (RAII cleanup).
    pub async fn register_confirmation(
        &self,
        correlation_id: Uuid,
        confirm_tx: mpsc::Sender<Vec<u8>>,
    ) -> ConfirmationGuard {
        self.state
            .confirmations
            .write()
            .await
            .insert(correlation_id, confirm_tx);
        ConfirmationGuard {
            correlation_id,
            state: Arc::clone(&self.state),
        }
    }

    /// Send a frame to the connection of the daemon `daemon_name` (the
    /// registry name it announced with `DaemonStarted`).
    ///
    /// # Errors
    ///
    /// `core_types::Error::Ipc` naming the daemon when it has not announced
    /// itself on a connection, or that connection is gone or its outbound
    /// channel is full.
    pub async fn send_to_named(&self, daemon_name: &str, frame: &[u8]) -> core_types::Result<()> {
        let conn_id = self
            .state
            .name_to_conn
            .read()
            .await
            .get(daemon_name)
            .copied();
        match conn_id {
            Some(id) if self.send_to(id, frame).await => Ok(()),
            Some(_) => Err(core_types::Error::Ipc(format!(
                "{daemon_name}: connection gone or outbound channel full"
            ))),
            None => Err(core_types::Error::Ipc(format!(
                "{daemon_name}: not connected"
            ))),
        }
    }
}

impl Drop for BusServer {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.socket_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(
                path = %self.socket_path.display(),
                error = %e,
                "failed to remove the bus socket"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

/// Handle a client connection: handshake, register, serve, and clean up.
///
/// The connection is registered in `state.connections` only after the
/// handshake succeeds, so no frame is routed to it before a transport
/// exists to encrypt it.
async fn handle_connection(
    state: Arc<ServerState>,
    conn_id: u64,
    stream: UnixStream,
    peer: PeerCredentials,
) {
    let connected_at = Instant::now();
    let connection =
        match Connection::server(stream, &state.keypair, state.endpoint.suite, &peer).await {
            Ok(connection) => connection,
            Err(e) => {
                tracing::error!(
                    audit = "connection-lifecycle",
                    event_type = "handshake-failed",
                    conn_id,
                    peer_pid = peer.pid,
                    peer_uid = peer.uid,
                    error = %e,
                    "Noise handshake failed, dropping connection"
                );
                return;
            }
        };
    let (security_clearance, verified_name) =
        identify(&state, conn_id, &connection.remote_static_key(), &peer).await;

    // Per-connection outbound channel (server -> client).
    let (tx, outbound_rx) = mpsc::channel::<Vec<u8>>(256);
    let conn = ConnectionState {
        daemon_id: None,
        verified_name,
        tx,
        security_clearance,
        trust_vector: Some(TrustVector {
            authn_strength: core_types::TrustLevel::Low,
            authz_freshness: Duration::ZERO,
            delegation_depth: 0,
            device_posture: 0.0,
            network_exposure: core_types::NetworkTrust::Local,
            agent_type: core_types::AgentType::Human,
        }),
    };
    state.connections.write().await.insert(conn_id, conn);

    serve(&state, conn_id, connection, outbound_rx, connected_at).await;
    close(&state, conn_id, connected_at).await;
}

/// The clearance and registry name of the client with static key
/// `client_key`: its registration, or `SecretsOnly` and no name for an
/// ephemeral client (the CLI), admitted by `UCred` same-UID validation.
async fn identify(
    state: &ServerState,
    conn_id: u64,
    client_key: &[u8; 32],
    peer: &PeerCredentials,
) -> (SecurityLevel, Option<String>) {
    let registry = state.registry.read().await;
    if let Some(identity) = registry.lookup(client_key)
        && let Some(name) = registry.lookup_name(client_key).map(str::to_owned)
    {
        tracing::info!(
            audit = "connection-lifecycle",
            event_type = "handshake-success",
            conn_id,
            daemon = %name,
            clearance = ?identity.security_level,
            pubkey = %hex::encode(client_key),
            peer_pid = peer.pid,
            peer_uid = peer.uid,
            "daemon authenticated via registry"
        );
        (identity.security_level, Some(name))
    } else {
        tracing::info!(
            audit = "connection-lifecycle",
            event_type = "ephemeral-client-accepted",
            conn_id,
            clearance = ?SecurityLevel::SecretsOnly,
            pubkey = %hex::encode(client_key),
            peer_pid = peer.pid,
            peer_uid = peer.uid,
            "ephemeral client accepted via UCred same-UID validation"
        );
        (SecurityLevel::SecretsOnly, None)
    }
}

/// Route the connection's frames and write the frames routed to it until
/// either direction fails.
///
/// `snow::TransportState` needs `&mut self` to encrypt and to decrypt, so
/// one task owns it and multiplexes reads and writes with `tokio::select!`:
/// split across tasks behind a lock, the reader would hold the lock while
/// it awaits the socket and starve the writer.
async fn serve(
    state: &ServerState,
    conn_id: u64,
    mut connection: Connection,
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    connected_at: Instant,
) {
    loop {
        tokio::select! {
            result = connection.transport.read_encrypted_frame(&mut connection.reader) => {
                match result {
                    Ok(payload) => {
                        // The decrypted postcard buffer may hold secret values.
                        let payload = zeroize::Zeroizing::new(payload);
                        route_frame(state, conn_id, &payload).await;
                    }
                    Err(e) => {
                        let daemon = state.connections.read().await
                            .get(&conn_id)
                            .and_then(|c| c.daemon_id)
                            .map(|id| id.to_string());
                        tracing::info!(
                            audit = "connection-lifecycle",
                            event_type = "disconnect",
                            conn_id,
                            daemon = daemon.as_deref().unwrap_or("unknown"),
                            session_duration_ms = %connected_at.elapsed().as_millis(),
                            error = %e,
                            "client disconnected"
                        );
                        return;
                    }
                }
            }
            Some(payload) = outbound_rx.recv() => {
                // The plaintext postcard buffer may hold secret values.
                let payload = zeroize::Zeroizing::new(payload);
                if let Err(e) = connection.transport.write_encrypted_frame(&mut connection.writer, &payload).await {
                    tracing::debug!(conn_id, error = %e, "encrypted write failed, closing");
                    return;
                }
            }
            else => return,
        }
    }
}

/// Forget the connection: its state and its daemon name. Its unanswered
/// requests stay tracked as disconnected until the pending-request TTL, so
/// a response arriving after the requester gave up is told apart from a
/// response to no request.
async fn close(state: &ServerState, conn_id: u64, connected_at: Instant) {
    state.connections.write().await.remove(&conn_id);
    for pending in state.pending_requests.write().await.values_mut() {
        if pending.conn_id == Some(conn_id) {
            pending.conn_id = None;
        }
    }
    state
        .name_to_conn
        .write()
        .await
        .retain(|_, cid| *cid != conn_id);
    tracing::debug!(
        audit = "connection-lifecycle",
        event_type = "cleanup",
        conn_id,
        session_duration_ms = %connected_at.elapsed().as_millis(),
        "connection cleaned up"
    );
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

/// Send an `AccessDenied` error response back to the sender so the client
/// gets an actionable error instead of a silent timeout.
fn send_access_denied(
    conn: &ConnectionState,
    request_msg_id: Uuid,
    epoch: Instant,
    reason: String,
) {
    let ctx = crate::message::MessageContext::new(DaemonId::new());
    let reply = Message::new(
        &ctx,
        EventKind::AccessDenied { reason },
        SecurityLevel::Open,
        epoch,
    )
    .with_correlation(request_msg_id);
    match encode_frame(&reply) {
        Ok(frame) => {
            if conn.tx.try_send(frame).is_err() {
                tracing::warn!(%request_msg_id, "access-denied reply dropped: channel full or closed");
            }
        }
        Err(e) => {
            tracing::error!(error = %e, %request_msg_id, "failed to encode an access-denied reply");
        }
    }
}

/// Route a received frame: admit it, stamp the server-verified sender
/// identity, then deliver it as a response (it has a `correlation_id`) or
/// as a request or broadcast to every other connection cleared for it.
async fn route_frame(state: &ServerState, sender_conn_id: u64, payload: &[u8]) {
    let mut msg: Message<EventKind> = match decode_frame(payload) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(conn_id = sender_conn_id, error = %e, "malformed frame, dropping");
            return;
        }
    };
    let Some((verified_name, trust_vector)) = admit(state, sender_conn_id, &msg).await else {
        return;
    };
    if let (EventKind::DaemonStarted { .. }, Some(name)) = (&msg.payload, &verified_name) {
        bind_name(state, name, sender_conn_id).await;
    }

    // The server-verified identity replaces whatever the sender claimed;
    // receivers get it in the re-encoded frame.
    msg.verified_sender_name = verified_name;
    if msg.trust_snapshot.is_none() {
        msg.trust_snapshot = trust_vector;
    }
    let stamped = match encode_frame(&msg) {
        Ok(p) => zeroize::Zeroizing::new(p),
        Err(e) => {
            tracing::error!(conn_id = sender_conn_id, error = %e, "failed to re-encode stamped frame");
            return;
        }
    };

    if let Some(correlation_id) = msg.correlation_id {
        deliver_response(state, correlation_id, &stamped).await;
        return;
    }
    if msg.expects_response {
        track_request(state, msg.msg_id, sender_conn_id).await;
    }
    broadcast(state, sender_conn_id, msg.security_level, &stamped).await;
}

/// Admit `msg` from connection `sender_conn_id`, returning the sender's
/// verified name and trust vector; `None` (answered with `AccessDenied`)
/// when the frame is refused. One lock acquisition covers the checks and
/// the identity binding, so they cannot interleave with another frame.
///
/// - The first frame binds the connection to its self-declared
///   `DaemonId`; a later frame claiming another is an impersonation
///   attempt.
/// - A sender may only emit at or below its own clearance, so a
///   compromised low-clearance daemon cannot inject high-clearance frames.
async fn admit(
    state: &ServerState,
    sender_conn_id: u64,
    msg: &Message<EventKind>,
) -> Option<(Option<String>, Option<TrustVector>)> {
    let mut conns = state.connections.write().await;
    let Some(conn) = conns.get_mut(&sender_conn_id) else {
        return Some((None, None));
    };
    match conn.daemon_id {
        Some(known) if known != msg.sender => {
            tracing::warn!(
                audit = "security",
                event_type = "sender-identity-mismatch",
                conn_id = sender_conn_id,
                expected_sender = %known,
                claimed_sender = %msg.sender,
                verified_name = conn.verified_name.as_deref().unwrap_or("unregistered"),
                "sender DaemonId changed mid-session, dropping frame"
            );
            send_access_denied(
                conn,
                msg.msg_id,
                state.epoch,
                "sender identity changed mid-session".into(),
            );
            return None;
        }
        Some(_) => {}
        None => {
            conn.daemon_id = Some(msg.sender);
            if let Some(name) = &conn.verified_name {
                tracing::info!(
                    audit = "identity-binding",
                    conn_id = sender_conn_id,
                    daemon_name = %name,
                    daemon_id = %msg.sender,
                    "daemon identity bound: registry name <-> self-declared DaemonId"
                );
            }
        }
    }
    if conn.security_clearance < msg.security_level {
        tracing::warn!(
            conn_id = sender_conn_id,
            sender_clearance = ?conn.security_clearance,
            msg_level = ?msg.security_level,
            "sender clearance below message security level, rejecting"
        );
        send_access_denied(
            conn,
            msg.msg_id,
            state.epoch,
            format!(
                "sender clearance {:?} below message security level {:?}",
                conn.security_clearance, msg.security_level,
            ),
        );
        return None;
    }
    Some((conn.verified_name.clone(), conn.trust_vector.clone()))
}

/// Bind daemon `name` (its `DaemonStarted`) to connection `conn_id` for
/// unicast. A daemon reconnecting with a rotated key opens a new
/// connection while the old one may not have closed yet: the old one is
/// evicted, or frames would keep going to the dead connection.
async fn bind_name(state: &ServerState, name: &str, conn_id: u64) {
    let previous = state
        .name_to_conn
        .write()
        .await
        .insert(name.to_owned(), conn_id);
    if let Some(stale) = previous.filter(|&previous| previous != conn_id) {
        state.connections.write().await.remove(&stale);
        tracing::info!(
            audit = "connection-lifecycle",
            event_type = "key-rotation-reconnect",
            daemon_name = %name,
            old_conn_id = stale,
            new_conn_id = conn_id,
            "evicted stale connection, accepting reconnect"
        );
    }
    tracing::info!(daemon_name = %name, conn_id, "name_to_conn mapping registered");
}

/// Remember that connection `conn_id` waits for the response to request
/// `msg_id`, forgetting requests older than [`PENDING_REQUEST_TTL`]: their
/// requesters have given up.
async fn track_request(state: &ServerState, msg_id: Uuid, conn_id: u64) {
    let now = Instant::now();
    let mut pending = state.pending_requests.write().await;
    pending.retain(|_, request| now.duration_since(request.sent_at) < PENDING_REQUEST_TTL);
    pending.insert(
        msg_id,
        PendingRequest {
            conn_id: Some(conn_id),
            sent_at: now,
        },
    );
}

/// Forget request `correlation_id` and return its requester.
async fn take_requester(state: &ServerState, correlation_id: &Uuid) -> Requester {
    match state.pending_requests.write().await.remove(correlation_id) {
        Some(PendingRequest {
            conn_id: Some(conn_id),
            ..
        }) => Requester::Connected(conn_id),
        Some(PendingRequest { conn_id: None, .. }) => Requester::Disconnected,
        None => Requester::Unknown,
    }
}

/// Deliver the response to request `correlation_id`: to a confirmed-RPC
/// waiter of the host when one is registered, and to the connection that
/// sent the request.
async fn deliver_response(state: &ServerState, correlation_id: Uuid, frame: &[u8]) {
    let confirmation = state
        .confirmations
        .read()
        .await
        .get(&correlation_id)
        .cloned();
    if let Some(tx) = &confirmation
        && tx.try_send(frame.to_vec()).is_err()
    {
        tracing::warn!(%correlation_id, "confirmed RPC response dropped: confirmation channel full");
    }
    match take_requester(state, &correlation_id).await {
        Requester::Connected(target) => {
            let conns = state.connections.read().await;
            if let Some(conn) = conns.get(&target)
                && conn.tx.try_send(frame.to_vec()).is_err()
            {
                tracing::warn!(conn_id = target, %correlation_id, "response dropped: channel full");
            }
        }
        Requester::Disconnected => {
            tracing::debug!(%correlation_id, "requester disconnected before its response, dropping");
        }
        Requester::Unknown if confirmation.is_none() => {
            tracing::debug!(%correlation_id, "response to no waiting request, dropping");
        }
        Requester::Unknown => {}
    }
}

/// Deliver `frame` at `level` to every connection but its sender whose
/// clearance admits it.
async fn broadcast(state: &ServerState, sender_conn_id: u64, level: SecurityLevel, frame: &[u8]) {
    let conns = state.connections.read().await;
    for (&cid, conn) in conns.iter() {
        if cid == sender_conn_id || conn.security_clearance < level {
            continue;
        }
        if conn.tx.try_send(frame.to_vec()).is_err() {
            tracing::warn!(conn_id = cid, "subscriber channel full, frame dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Server state with one Internal connection, `conn_id` 1.
    async fn state_with_one_connection() -> ServerState {
        let state = ServerState {
            keypair: crate::noise::generate_keypair().unwrap().into_inner(),
            endpoint: BusEndpoint {
                suite: NoiseSuite::default(),
                public_key: [0; 32],
            },
            connections: RwLock::new(HashMap::new()),
            pending_requests: RwLock::new(HashMap::new()),
            next_conn_id: AtomicU64::new(2),
            epoch: Instant::now(),
            registry: RwLock::new(ClearanceRegistry::new()),
            confirmations: RwLock::new(HashMap::new()),
            name_to_conn: RwLock::new(HashMap::new()),
        };
        let (tx, _rx) = mpsc::channel(8);
        state.connections.write().await.insert(
            1,
            ConnectionState {
                daemon_id: None,
                verified_name: None,
                tx,
                security_clearance: SecurityLevel::Internal,
                trust_vector: None,
            },
        );
        state
    }

    fn frame(msg: &Message<EventKind>) -> Vec<u8> {
        encode_frame(msg).unwrap()
    }

    #[tokio::test]
    async fn only_requests_awaiting_a_response_are_tracked() {
        let state = state_with_one_connection().await;
        let ctx = crate::message::MessageContext::new(DaemonId::new());
        let broadcast = Message::new(
            &ctx,
            EventKind::WmActivateOverlay,
            SecurityLevel::Internal,
            state.epoch,
        );
        for _ in 0..100 {
            route_frame(&state, 1, &frame(&broadcast)).await;
        }
        assert!(
            state.pending_requests.read().await.is_empty(),
            "broadcasts never get responses and must not be tracked"
        );
        let request = Message::new(
            &ctx,
            EventKind::StatusRequest,
            SecurityLevel::Internal,
            state.epoch,
        )
        .expecting_response();
        route_frame(&state, 1, &frame(&request)).await;
        let pending = state.pending_requests.read().await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[&request.msg_id].conn_id, Some(1));
    }

    #[tokio::test]
    async fn a_requester_that_disconnected_is_told_apart_from_no_request() {
        let state = state_with_one_connection().await;
        let (answered, abandoned) = (Uuid::now_v7(), Uuid::now_v7());
        track_request(&state, answered, 1).await;
        assert_eq!(
            take_requester(&state, &answered).await,
            Requester::Connected(1)
        );
        assert_eq!(
            take_requester(&state, &answered).await,
            Requester::Unknown,
            "a response is delivered once"
        );

        track_request(&state, abandoned, 1).await;
        close(&state, 1, Instant::now()).await;
        assert_eq!(
            take_requester(&state, &abandoned).await,
            Requester::Disconnected
        );
        assert_eq!(
            take_requester(&state, &Uuid::now_v7()).await,
            Requester::Unknown
        );
    }

    #[tokio::test]
    async fn requests_past_their_ttl_are_forgotten() {
        let state = state_with_one_connection().await;
        let expired = Uuid::now_v7();
        state.pending_requests.write().await.insert(
            expired,
            PendingRequest {
                conn_id: Some(1),
                sent_at: Instant::now()
                    .checked_sub(PENDING_REQUEST_TTL)
                    .expect("the monotonic clock is past the TTL"),
            },
        );
        let current = Uuid::now_v7();
        track_request(&state, current, 1).await;
        let pending = state.pending_requests.read().await;
        assert!(
            !pending.contains_key(&expired),
            "a request past the TTL is forgotten"
        );
        assert!(pending.contains_key(&current));
    }
}
