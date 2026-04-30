//! `TestDaemon`: in-process daemon state for integration tests.
//!
//! Constructs a `DaemonState` with real UDP sockets, an in-process IPC bus,
//! and test-controlled configuration. This lets integration tests call
//! dispatch functions (`handle_udp_frame`, `run_maintenance`, etc.) directly
//! without running the full daemon process.

use daemon_network::audit::AuditLog;
use daemon_network::flood::cookie::CookieChallenger;
use daemon_network::flood::pow::PowChallenger;
use daemon_network::metrics::Metrics;
use daemon_network::noise::state as noise_state;
use daemon_network::ratelimit::bucket::TokenBucket;
use daemon_network::session::state::PeerState;
use daemon_network::session::table::PeerTable;
use daemon_network::state::{DaemonState, InstallationIdentity};
use daemon_network::tofu::store::TofuStore;
use daemon_network::transport::frame::{Frame, WireSessionId};

use core_ipc::{BusClient, BusServer, ClearanceRegistry, generate_keypair};
use core_types::{DaemonId, SecurityLevel, TofuTrustLevel};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

/// A test daemon with all subsystems assembled and controllable.
pub struct TestDaemon {
    /// The assembled daemon state — pass to dispatch/lifecycle functions.
    pub state: DaemonState,
    /// A UDP socket for sending frames TO the daemon (the "client" side).
    pub client_socket: Arc<tokio::net::UdpSocket>,
    /// The daemon's listen address.
    pub daemon_addr: SocketAddr,
    /// Temp directory (holds TOFU db, audit log). Drop cleans up.
    _dir: tempfile::TempDir,
    /// Background server task handle.
    _server_handle: tokio::task::JoinHandle<()>,
}

impl TestDaemon {
    /// Create a new test daemon with default configuration.
    ///
    /// - 4-session peer table
    /// - 1s cookie epoch (fast rotation for tests)
    /// - 100/s handshake rate limit (generous for tests)
    /// - `PoW` inactive
    /// - No signing seed
    /// - In-process IPC bus (server runs in background)
    pub async fn new() -> Self {
        Self::with_config(4, 100, 300, 120).await
    }

    /// Create a test daemon with custom configuration.
    ///
    /// - `max_sessions`: peer table capacity
    /// - `handshake_rate`: global handshake rate limit per second
    /// - `idle_timeout_secs`: seconds before idle session cleanup
    /// - `rekey_interval_secs`: seconds before rekey sweep
    pub async fn with_config(
        max_sessions: u32,
        handshake_rate: u32,
        idle_timeout_secs: u64,
        rekey_interval_secs: u64,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();

        // UDP sockets: daemon + client on ephemeral ports.
        let daemon_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let daemon_addr = daemon_socket.local_addr().unwrap();
        let client_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());

        // In-process IPC bus.
        let sock_path = dir.path().join("bus.sock");
        let server_kp = generate_keypair().unwrap();
        let server_pub: [u8; 32] = server_kp.public().try_into().unwrap();
        let mut registry = ClearanceRegistry::new();
        let client_kp = generate_keypair().unwrap();
        let mut client_pub = [0u8; 32];
        client_pub.copy_from_slice(client_kp.public());
        registry.register("daemon-network".into(), client_pub, SecurityLevel::Internal);
        let server = BusServer::bind(&sock_path, server_kp.into_inner(), registry).unwrap();

        let server_handle = tokio::spawn(async move {
            let _ = server.run().await;
        });

        // Brief yield to let the server bind.
        tokio::task::yield_now().await;

        let bus_client = BusClient::connect_encrypted(
            DaemonId::from_uuid(Uuid::from_u128(1)),
            &sock_path,
            &server_pub,
            &snow::Keypair {
                private: client_kp.as_inner().private.clone(),
                public: client_kp.as_inner().public.clone(),
            },
        )
        .await
        .unwrap();

        // Noise keypair for the daemon's network identity.
        let local_keypair = Arc::new(
            snow::Builder::new(noise_state::NOISE_XX.parse().unwrap())
                .generate_keypair()
                .unwrap(),
        );

        // TOFU store.
        let tofu_store = Arc::new(std::sync::Mutex::new(
            TofuStore::open(&dir.path().join("tofu.db"), "test-daemon").unwrap(),
        ));

        // Audit log.
        let audit = Arc::new(AuditLog::open(&dir.path().join("audit.jsonl")).unwrap());

        // Discovery.
        let (discovery_tx, discovery_rx) = tokio::sync::mpsc::channel(256);
        let discovery = Arc::new(daemon_discovery::manager::DiscoveryManager::new(
            1024,
            discovery_tx,
        ));

        // TCP channel (not used in most tests, but required by `DaemonState`).
        let (tcp_tx, _tcp_rx) = tokio::sync::mpsc::channel(16);

        let identity = InstallationIdentity {
            id: Uuid::from_u128(42).to_string(),
            network_pubkey: {
                let mut k = [0u8; 32];
                k.copy_from_slice(&local_keypair.public[..32]);
                k
            },
            signing_pubkey: None,
        };

        let state = DaemonState {
            udp_socket: daemon_socket,
            peer_table: Arc::new(PeerTable::new(max_sessions)),
            tofu_store,
            cookie: Arc::new(std::sync::Mutex::new(CookieChallenger::new(1))),
            pow: Arc::new(std::sync::Mutex::new(PowChallenger::new())),
            global_hs_limiter: Arc::new(TokenBucket::new(handshake_rate, handshake_rate * 2)),
            metrics: Arc::new(Metrics::new()),
            audit,
            local_keypair,
            bus_client: Arc::new(tokio::sync::Mutex::new(bus_client)),
            discovery,
            discovery_rx,
            listen_port: daemon_addr.port(),
            idle_timeout_secs,
            rekey_interval_secs,
            bep44_enabled: false,
            dns_srv_domains: Arc::new(std::sync::RwLock::new(Vec::new())),
            identity,
            signing_seed: None,
            tcp_tx,
            require_known_peers: false,
            gossip_hmac_key: None,
            replication_watermarks: std::sync::Mutex::new(std::collections::HashMap::new()),
            replication_rate_limiter: std::sync::Mutex::new(std::collections::HashMap::new()),
            replication_inbound_tx: {
                let (tx, _rx) = tokio::sync::mpsc::channel(16);
                tx
            },
        };

        Self {
            state,
            client_socket,
            daemon_addr,
            _dir: dir,
            _server_handle: server_handle,
        }
    }

    /// Send a wire frame from the test client to the daemon's UDP socket.
    pub async fn send_frame(&self, frame: &Frame) {
        let bytes = frame.serialise();
        self.client_socket
            .send_to(&bytes, self.daemon_addr)
            .await
            .unwrap();
    }

    /// Receive a wire frame sent by the daemon to the test client socket.
    ///
    /// Times out after 2 seconds.
    pub async fn recv_frame(&self) -> Option<Frame> {
        let mut buf = vec![0u8; 1500];
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            self.client_socket.recv_from(&mut buf),
        )
        .await;
        match result {
            Ok(Ok((len, _src))) => Frame::parse(&buf[..len]),
            _ => None,
        }
    }

    /// Create a Noise session between the daemon and a fresh peer,
    /// insert it into the peer table, and return the session ID and
    /// the peer's transport (for encrypting/decrypting test frames).
    pub async fn insert_session(
        &self,
        peer_addr: SocketAddr,
    ) -> (WireSessionId, daemon_network::noise::state::NoiseTransport) {
        let peer_kp = snow::Builder::new(noise_state::NOISE_XX.parse().unwrap())
            .generate_keypair()
            .unwrap();

        let (sa, sb) = tokio::io::duplex(65536);
        let (mut ar, mut aw) = tokio::io::split(sa);
        let (mut br, mut bw) = tokio::io::split(sb);

        let daemon_kp_clone = snow::Keypair {
            private: self.state.local_keypair.private.clone(),
            public: self.state.local_keypair.public.clone(),
        };

        let (init_result, resp_result) = tokio::join!(
            noise_state::xx_initiator(&mut ar, &mut aw, &peer_kp),
            noise_state::xx_responder(&mut br, &mut bw, &daemon_kp_clone),
        );

        let peer_transport = init_result.unwrap();
        let daemon_transport = resp_result.unwrap();
        let remote_static = daemon_transport.remote_static().unwrap();

        let sid = WireSessionId::random();
        let peer_state = PeerState::new(
            sid,
            remote_static,
            peer_addr,
            daemon_transport,
            TofuTrustLevel::Tofu,
        );
        assert!(
            self.state.peer_table.insert(peer_state),
            "peer table must accept session"
        );

        (sid, peer_transport)
    }

    /// Convenience: read a metric counter value.
    pub fn metric(&self, counter: &std::sync::atomic::AtomicU64) -> u64 {
        counter.load(std::sync::atomic::Ordering::Relaxed)
    }
}
