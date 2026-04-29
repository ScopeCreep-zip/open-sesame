//! Network federation CLI commands.
//!
//! Provides `sesame network identity`, `sesame network peers`,
//! `sesame network discover`, `sesame network status`, `sesame network dial`.

use crate::cli::NetworkCmd;

pub(crate) async fn cmd_network(sub: NetworkCmd) -> anyhow::Result<()> {
    match sub {
        NetworkCmd::Identity { json } => cmd_identity(json).await,
        NetworkCmd::Peers { unpin } => cmd_peers(unpin.as_deref()).await,
        NetworkCmd::Discover => cmd_discover().await,
        NetworkCmd::Keygen => cmd_keygen(),
        NetworkCmd::Reload => cmd_reload().await,
        NetworkCmd::Status => cmd_status().await,
        NetworkCmd::Dial { addr } => cmd_dial(&addr).await,
    }
}

/// Dial a remote peer by address.
///
/// Initiates a Noise XX handshake over TCP to the specified address.
/// On success, the peer is TOFU-pinned and a session is established.
async fn cmd_dial(addr: &str) -> anyhow::Result<()> {
    let _: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid address '{addr}': {e}"))?;

    println!("Dialing {addr}...");

    let client = crate::ipc::connect().await?;
    let response = client
        .request(
            core_types::EventKind::NetworkDialRequest {
                addr: addr.to_string(),
            },
            core_types::SecurityLevel::Internal,
            std::time::Duration::from_secs(30),
        )
        .await;

    match response {
        Ok(msg) => match msg.payload {
            core_types::EventKind::NetworkDialResponse {
                success,
                session_id,
                error,
            } => {
                if success {
                    println!("  Session:  {}", session_id.unwrap_or_default());
                    println!("  Status:   established");
                } else {
                    println!("  Status:   failed");
                    if let Some(e) = error {
                        println!("  Error:    {e}");
                    }
                }
            }
            _ => println!("  Unexpected response from daemon-network"),
        },
        Err(e) => {
            println!("  IPC request failed: {e}");
            println!("  Is daemon-network running?");
        }
    }

    Ok(())
}

/// Generate a random 32-byte gossip authentication key.
///
/// The key is printed as base64. Add it to every installation's
/// `bootstrap.json` as the `gossip_secret` field to enable
/// HMAC-BLAKE3 authenticated SWIM gossip.
fn cmd_keygen() -> anyhow::Result<()> {
    use base64::Engine;
    let key = core_crypto::network::random_bytes::<32>();
    let encoded = base64::engine::general_purpose::STANDARD.encode(key);
    println!("{encoded}");
    Ok(())
}

/// Reload bootstrap.json and DNS SRV configuration via IPC.
async fn cmd_reload() -> anyhow::Result<()> {
    let client = crate::ipc::connect().await?;
    let response = client
        .request(
            core_types::EventKind::NetworkDiscoveryReloadRequest,
            core_types::SecurityLevel::Internal,
            std::time::Duration::from_secs(5),
        )
        .await;

    match response {
        Ok(msg) => match msg.payload {
            core_types::EventKind::NetworkDiscoveryReloadResponse { added } => {
                println!("Discovery reloaded: {added} new peers added to dial queue");
            }
            _ => println!("Unexpected response from daemon-network"),
        },
        Err(e) => {
            println!("IPC request failed: {e}");
            println!("Is daemon-network running?");
        }
    }

    Ok(())
}

/// Show discovery subsystem state via IPC.
async fn cmd_discover() -> anyhow::Result<()> {
    let client = crate::ipc::connect().await?;
    let response = client
        .request(
            core_types::EventKind::NetworkDiscoverRequest,
            core_types::SecurityLevel::Internal,
            std::time::Duration::from_secs(5),
        )
        .await;

    match response {
        Ok(msg) => match msg.payload {
            core_types::EventKind::NetworkDiscoverResponse {
                mdns_peers,
                bep44_published,
                dns_srv_domains,
                dial_queue_depth,
                swim_members,
            } => {
                println!("Open Sesame -- Discovery State");
                println!("----------------------------------------------");
                println!("  mDNS peers:       {mdns_peers}");
                println!("  BEP-44 published: {bep44_published}");
                println!("  DNS SRV domains:  {}", if dns_srv_domains.is_empty() { "(none)".into() } else { dns_srv_domains.join(", ") });
                println!("  Dial queue:       {dial_queue_depth}");
                println!("  SWIM members:     {swim_members}");
            }
            _ => println!("Unexpected response from daemon-network"),
        },
        Err(e) => {
            println!("IPC request failed: {e}");
            println!("Is daemon-network running?");
        }
    }

    Ok(())
}

/// Display this installation's network identity.
///
/// Reads installation.toml for the network public key and displays it
/// as PGP word list fingerprint (default) or JSON (for bootstrap.json inclusion).
async fn cmd_identity(json: bool) -> anyhow::Result<()> {
    let install = core_config::load_installation()
        .map_err(|e| anyhow::anyhow!("failed to load installation.toml: {e}"))?;

    let pubkey_hex = install.network_pubkey_hex.as_deref().unwrap_or("(not set)");
    let signing_hex = install.signing_pubkey_hex.as_deref().unwrap_or("(not set)");
    let display_name = install.display_name.as_deref().unwrap_or("(unnamed)");
    let ceremony = install.ceremony_completed.unwrap_or(false);

    if json {
        let out = serde_json::json!({
            "display_name": display_name,
            "installation_id": install.id.to_string(),
            "public_key_hex": pubkey_hex,
            "signing_pubkey_hex": signing_hex,
            "addresses": [],
            "trust_level": "bootstrap",
            "dial_on_start": false,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!("Open Sesame -- Network Identity");
        println!("----------------------------------------------");
        println!("  Installation ID:  {}", install.id);
        println!("  Display Name:     {display_name}");
        println!("  Network Pubkey:   {pubkey_hex}");
        println!("  Signing Pubkey:   {signing_hex}");
        println!("  Ceremony:         {}", if ceremony { "complete" } else { "incomplete" });

        if pubkey_hex != "(not set)"
            && let Ok(bytes) = hex::decode(pubkey_hex)
            && bytes.len() == 32
        {
            println!();
            println!("  Fingerprint (PGP words):");
            let short = &bytes[..8.min(bytes.len())];
            let words: Vec<&str> = short
                .iter()
                .enumerate()
                .map(|(i, &b)| {
                    if i % 2 == 0 {
                        PGP_EVEN[b as usize]
                    } else {
                        PGP_ODD[b as usize]
                    }
                })
                .collect();
            println!("    {}", words.join(" "));
        }
    }

    Ok(())
}

/// List known peers from the TOFU store.
async fn cmd_peers(unpin_key: Option<&str>) -> anyhow::Result<()> {
    // Handle --unpin via IPC to daemon-network.
    if let Some(key_hex) = unpin_key {
        let client = crate::ipc::connect().await?;
        let response = client
            .request(
                core_types::EventKind::NetworkUnpinRequest {
                    public_key_hex: key_hex.to_string(),
                },
                core_types::SecurityLevel::Internal,
                std::time::Duration::from_secs(5),
            )
            .await;

        match response {
            Ok(msg) => match msg.payload {
                core_types::EventKind::NetworkUnpinResponse { success, error } => {
                    if success {
                        println!("Unpinned peer {key_hex}");
                    } else {
                        println!("Unpin failed: {}", error.unwrap_or_default());
                    }
                }
                _ => println!("Unexpected response from daemon-network"),
            },
            Err(e) => {
                println!("IPC request failed: {e}");
                println!("Is daemon-network running?");
            }
        }
        return Ok(());
    }

    let state_dir = dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("pds");
    let tofu_path = state_dir.join("network-tofu.db");

    if !tofu_path.exists() {
        println!("No TOFU store found at {}", tofu_path.display());
        println!("daemon-network has not established any sessions yet.");
        return Ok(());
    }

    let conn = rusqlite::Connection::open_with_flags(
        &tofu_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|e| anyhow::anyhow!("failed to open TOFU store: {e}"))?;

    let mut stmt = conn.prepare(
        "SELECT public_key_hex, trust_level, last_known_addr, display_name
         FROM tofu_peers ORDER BY last_seen_at DESC",
    )?;

    let peers: Vec<(String, String, Option<String>, Option<String>)> = stmt
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if peers.is_empty() {
        println!("No peers in TOFU store.");
        return Ok(());
    }

    println!("Open Sesame -- Known Peers ({} total)", peers.len());
    println!("----------------------------------------------");

    for (key_hex, trust, addr, name) in &peers {
        let name = name.as_deref().unwrap_or("(unknown)");
        let addr = addr.as_deref().unwrap_or("(no address)");
        let key_short = if key_hex.len() >= 16 { &key_hex[..16] } else { key_hex };
        println!("  {key_short}...  {trust:<12}  {addr:<24}  {name}");
    }

    let events: i64 = conn.query_row("SELECT COUNT(*) FROM tofu_events", [], |row| row.get(0))?;
    println!();
    println!("Fork-evidence log: {events} events");

    Ok(())
}

/// Display daemon-network status via IPC, with TOFU store fallback.
async fn cmd_status() -> anyhow::Result<()> {
    println!("Open Sesame -- Network Status");
    println!("----------------------------------------------");

    if let Ok(client) = crate::ipc::connect().await
        && let Ok(msg) = client
            .request(
                core_types::EventKind::NetworkStatusRequest,
                core_types::SecurityLevel::Internal,
                std::time::Duration::from_secs(5),
            )
            .await
        && let core_types::EventKind::NetworkStatusResponse {
            active_sessions,
            tofu_peers,
            tofu_events,
            dial_queue_depth,
            listen_port,
            enabled,
        } = msg.payload
    {
        println!("  Enabled:      {enabled}");
        println!("  Listen port:  {listen_port}");
        println!("  Sessions:     {active_sessions}");
        println!("  TOFU events:  {tofu_events}");
        println!("  TOFU peers:   {tofu_peers}");
        println!("  Dial queue:   {dial_queue_depth}");
        return Ok(());
    }

    let state_dir = dirs::state_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("pds");
    let tofu_path = state_dir.join("network-tofu.db");

    if tofu_path.exists() {
        println!("  TOFU store:  {}", tofu_path.display());
        if let Ok(conn) = rusqlite::Connection::open_with_flags(
            &tofu_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ) {
            let peer_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM tofu_peers", [], |row| row.get(0))
                .unwrap_or(0);
            let event_count: i64 = conn
                .query_row("SELECT COUNT(*) FROM tofu_events", [], |row| row.get(0))
                .unwrap_or(0);
            println!("  Known peers: {peer_count}");
            println!("  Log events:  {event_count}");
        }
    } else {
        println!("  daemon-network not running, no TOFU store found");
    }

    Ok(())
}

use core_types::network::{PGP_EVEN, PGP_ODD};
