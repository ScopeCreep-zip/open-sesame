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

// PGP word list tables duplicated from daemon-network fingerprint module.
// The CLI crate does not depend on daemon-network to avoid pulling snow,
// aws-lc-rs, and other heavy crypto dependencies into the CLI binary.
const PGP_EVEN: [&str; 256] = [
    "aardvark", "absurd", "accrue", "acme", "adrift", "adult", "afflict", "ahead",
    "aimless", "algol", "allow", "alone", "ammo", "ancient", "apple", "artist",
    "assume", "athens", "atlas", "aztec", "baboon", "backfield", "backward", "banjo",
    "beaming", "bedlamp", "beehive", "beeswax", "befriend", "belfast", "berserk", "billiard",
    "bison", "blackjack", "blockade", "blowtorch", "bluebird", "bombast", "bookshelf", "brackish",
    "breadline", "breakup", "brickyard", "briefcase", "burbank", "button", "buzzard", "cement",
    "chairlift", "chatter", "checkup", "chessman", "chisel", "choking", "chopper", "christmas",
    "clamshell", "classic", "cleanup", "clockwork", "cobra", "commence", "concert", "cowbell",
    "crackdown", "cranky", "crowfoot", "crucial", "crumpled", "crusade", "cubic", "dashboard",
    "deadbolt", "deckhand", "dogsled", "dragnet", "drainage", "dreadful", "drifter", "dropout",
    "drumbeat", "drunken", "dupont", "dwelling", "eating", "edict", "egghead", "eightball",
    "endorse", "endow", "enlist", "erase", "escape", "exceed", "eyeglass", "eyetooth",
    "facet", "fairway", "fallout", "flagpole", "flatfoot", "flytrap", "fracture", "framework",
    "freedom", "frighten", "gazelle", "geiger", "glitter", "glucose", "goggles", "goldfish",
    "gremlin", "guidance", "hamlet", "highchair", "hockey", "indoors", "indulge", "inverse",
    "involve", "island", "jawbone", "keyboard", "kickoff", "kiwi", "klaxon", "locale",
    "lockup", "merit", "minnow", "miser", "mohawk", "mural", "music", "necklace",
    "neptune", "newborn", "nightbird", "oakland", "obtuse", "offload", "optic", "orca",
    "payday", "peachy", "pheasant", "physique", "playhouse", "pluto", "preclude", "prefer",
    "preshrunk", "printer", "prowler", "pupil", "puppy", "python", "quadrant", "quiver",
    "quota", "ragtime", "ratchet", "rebirth", "reform", "regain", "reindeer", "rematch",
    "repay", "retouch", "revenge", "reward", "rhythm", "ribcage", "ringbolt", "robust",
    "rocker", "ruffled", "sailboat", "sawdust", "scallion", "scenic", "scorecard", "scotland",
    "seabird", "select", "sentence", "shadow", "shamrock", "showgirl", "skullcap", "skydive",
    "slingshot", "slowdown", "snapline", "snapshot", "snowcap", "snowslide", "solo", "southward",
    "soybean", "spaniel", "spearhead", "spellbound", "spheroid", "spigot", "spindle", "spyglass",
    "stagehand", "stagnate", "stairway", "standard", "stapler", "steamship", "sterling", "stockman",
    "stopwatch", "stormy", "sugar", "surmount", "suspense", "sweatband", "swelter", "tactics",
    "talon", "tapeworm", "tempest", "tiger", "tissue", "tonic", "topmost", "tracker",
    "transit", "trauma", "treadmill", "trojan", "trouble", "tumor", "tunnel", "tycoon",
    "uncut", "unearth", "unify", "unkind", "until", "upward", "urban", "vengeance",
    "verdict", "viking", "viper", "vocal", "vulture", "waffle", "wallet", "watchword",
];

const PGP_ODD: [&str; 256] = [
    "adroitness", "adviser", "aftermath", "aggregate", "alkali", "almighty", "amulet", "amusement",
    "antenna", "applicant", "apollo", "armistice", "article", "asteroid", "atlantic", "atmosphere",
    "autopsy", "babylon", "backwater", "barbecue", "barometer", "bathrobe", "beaverton", "bedrock",
    "befuddle", "bellwether", "benchmark", "bikini", "blemish", "bodyguard", "bookseller", "borderline",
    "bottomless", "bradbury", "bravado", "brazilian", "breakaway", "burlington", "businessman", "butterfat",
    "camelot", "candidate", "cannonball", "capricorn", "caravan", "caretaker", "celebrate", "cellulose",
    "certify", "chambermaid", "cherokee", "chicago", "clergyman", "coherence", "combustion", "commando",
    "company", "component", "condition", "consensus", "converge", "corporate", "corrosion", "councilman",
    "crossover", "crucifix", "cumbersome", "customer", "dakota", "decadence", "december", "decimal",
    "designing", "detector", "diploma", "disaster", "disbelief", "disruptive", "distortion", "document",
    "embezzle", "enchanting", "enrollment", "enterprise", "equation", "equipment", "escapade", "ethernet",
    "eureka", "evidence", "examinee", "exodus", "fascinate", "filament", "finicky", "forever",
    "fortitude", "frequency", "gadgetry", "galveston", "getaway", "glossary", "goliath", "graduate",
    "gravity", "guitarist", "hamburger", "hamilton", "handiwork", "hazardous", "headwaters", "hemisphere",
    "hesitate", "hideaway", "holiness", "hurricane", "hydraulic", "hypnotic", "impetus", "inception",
    "indecent", "infancy", "inferno", "informant", "insincere", "insurgent", "integrate", "intention",
    "inventive", "istanbul", "Jamaica", "Jupiter", "leprosy", "letterhead", "liberty", "maritime",
    "matchmaker", "maverick", "medusa", "megaton", "microscope", "microwave", "midsummer", "millionaire",
    "miracle", "misnomer", "molasses", "molecule", "montana", "monument", "mosquito", "narrative",
    "nebula", "newsletter", "norwegian", "october", "ohio", "onlooker", "opulent", "orlando",
    "outfielder", "pacific", "pandemic", "pandora", "paperweight", "paragon", "paragraph", "paramount",
    "passenger", "pedigree", "pegasus", "penetrate", "perceptive", "performance", "pharmacy", "pineapple",
    "playmate", "plywood", "pneumonia", "politician", "pompadour", "populace", "portfolio", "potato",
    "processor", "prodigy", "professor", "propellant", "prosper", "publisher", "pugnacious", "pyramid",
    "quantity", "racketeer", "rebellion", "recipe", "renegade", "resistor", "retirement", "retrieval",
    "retrospect", "revenue", "revival", "revolver", "sandalwood", "sardonic", "saturday", "savagery",
    "scavenger", "sensation", "september", "sequence", "shanghai", "simulated", "singular", "skirmish",
    "sociable", "souvenir", "specialist", "speculate", "stethoscope", "stupendous", "subscriber", "subterfuge",
    "suggestion", "supernova", "surrender", "suspicious", "sympathy", "tambourine", "telephone", "therapist",
    "tobacco", "tolerance", "tomorrow", "torpedo", "tradition", "travesty", "trombonist", "truncated",
    "typewriter", "ultimate", "undaunted", "underfoot", "unicorn", "uninstall", "universe", "unravel",
    "upcoming", "vacancy", "vagabond", "vertigo", "virginia", "visitor", "vocalist", "voyager",
];
