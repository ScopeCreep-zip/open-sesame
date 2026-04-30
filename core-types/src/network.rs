//! Network federation types shared across milestones 1–3.
//!
//! Type substrate for:
//! - **M1** — Network transport: TOFU trust levels, frame types, message routing
//! - **M2** — Namespace and discovery: extended identity, discovery events
//! - **M3** — Vault replication: HLC timestamps, vault log entries, operations,
//!   re-encryption, offline delegation posture, coordinator documents

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// M1: Network Transport Types
// ============================================================================

/// TOFU trust level for network peers.
///
/// Distinct from [`TrustLevel`](crate::security::TrustLevel) which assesses
/// agent authentication strength. This enum tracks the *provenance* of a
/// peer's public key in the TOFU store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TofuTrustLevel {
    /// Pinned from first successful Noise XX handshake.
    Tofu,
    /// Pre-populated from `bootstrap.json` seed list.
    Bootstrap,
    /// Coordinator-signed endorsement received (M3).
    Endorsed,
    /// Coordinator revocation received (M3). Permanent block.
    Revoked,
    /// Operator issued unpin. Next handshake re-pins.
    Unpinned,
}

/// Network message type prefix for routing decrypted `Data` frames.
///
/// The first two bytes of every decrypted `Data` frame body carry this
/// discriminant. `daemon-network` routes by type without inspecting the
/// payload, preserving end-to-end semantics between application daemons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u16)]
#[non_exhaustive]
pub enum NetworkMessageType {
    /// Session control messages (handshake ack, keepalive, close).
    Control = 0x0001,
    /// Vault replication protocol (M3).
    VaultReplication = 0x0100,
    /// Profile sync protocol (M2).
    ProfileSync = 0x0101,
    /// Discovery protocol (M2).
    Discovery = 0x0200,
    /// Coordinator protocol (M3).
    Coordinator = 0x0300,
}

/// Wire frame type byte for the network transport.
///
/// Every frame (handshake or transport) carries this as the second byte
/// of the 20-byte header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
#[non_exhaustive]
pub enum FrameType {
    /// Noise XX msg1: `-> e`
    HandshakeInit = 0x01,
    /// Noise XX msg2: `<- e, ee, s, es`
    HandshakeResponse = 0x02,
    /// Noise XX msg3: `-> s, se`
    HandshakeFinal = 0x03,
    /// Stateless cookie challenge (`DoS` resistance).
    CookieRequest = 0x04,
    /// Cookie reply from initiator.
    CookieResponse = 0x05,
    /// Application data (post-handshake, AEAD-sealed).
    Data = 0x10,
    /// Path probe (empty body, AEAD-sealed).
    KeepAlive = 0x11,
    /// Graceful session termination.
    Close = 0x12,
    /// Nonce exhaustion / key rotation trigger.
    RehandshakeRequest = 0x13,
}

// ============================================================================
// M1: Fingerprint Display
// ============================================================================

// ============================================================================
// M2: Signed `HandshakeAck`
// ============================================================================

/// Signed `HandshakeAck` payload exchanged after Noise XX handshake completion.
///
/// Cryptographically binds the `InstallationId` to the Noise static key via
/// an Ed25519 signature over `canonical_json(payload) || noise_static_pubkey`.
/// The receiver verifies: (a) `network_pubkey` matches the Noise static key
/// from the handshake, and (b) the Ed25519 signature verifies against
/// `signing_pubkey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeAck {
    /// `InstallationId.id` UUID.
    pub installation_id: String,
    /// Human-readable name for this installation.
    pub display_name: Option<String>,
    /// X25519 public key used as the Noise static key (hex, 64 chars).
    pub network_pubkey: String,
    /// Ed25519 public key for signing and vault log (hex, 64 chars).
    pub signing_pubkey: String,
    /// Negotiated Noise protocol string (e.g., `"Noise_XX_25519_ChaChaPoly_BLAKE2s"`).
    pub cipher_suite: String,
    /// Ed25519 signature over `canonical_json(self without signature) || noise_static_pubkey_bytes`.
    pub signature: String,
}

/// Encoding format for displaying public key fingerprints to users.
///
/// Hex display is partial-preimage-vulnerable (Dechand et al. USENIX Security
/// 2016). Sentence/word-list encodings dominate hex on undetected-attack rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum FingerprintEncoding {
    /// PGP word list encoding (two-word per byte, 512 words). Recommended default.
    #[default]
    PgpWordList,
    /// Hexadecimal with colon separators. Legacy, NOT recommended for user-facing UI.
    Hex,
    /// Numeric (SAS-style, 6-digit codes). For out-of-band voice confirmation.
    NumericSas,
}

// ============================================================================
// M3: Vault Log Operation Tag
// ============================================================================

/// Typed operation tag for vault-log hooks.
///
/// Used at the daemon-secrets CRUD→vault-log boundary so the hook receives
/// a typed discriminant rather than a bare string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VaultLogOp {
    /// Secret created or updated.
    Set,
    /// Secret deleted.
    Delete,
    /// ACL grant or revocation.
    AclUpdate,
}

// ============================================================================
// M3: Hybrid Logical Clock
// ============================================================================

/// Hybrid logical clock timestamp for causal ordering.
///
/// Total order: `(wall_secs, counter, node_id)` lexicographically.
/// The `Ord` derivation produces exactly this ordering because fields
/// are declared in sort-priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct HlcTimestamp {
    /// Coarse wall clock (Unix epoch seconds). `u64` avoids Y2106 overflow.
    pub wall_secs: u64,
    /// Per-wall-second logical counter for ordering within the same second.
    pub counter: u64,
    /// First 8 bytes of `InstallationId.id` UUID. Tiebreaker for identical
    /// `(wall_secs, counter)` pairs from different nodes.
    pub node_id: [u8; 8],
}

impl HlcTimestamp {
    /// The zero timestamp (epoch start, node zero).
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            wall_secs: 0,
            counter: 0,
            node_id: [0; 8],
        }
    }

    /// Advance the local clock for a local event.
    ///
    /// Guarantees the returned timestamp is strictly greater than the
    /// previous value of `local`.
    pub fn tick(local: &mut Self, wall_now: u64) -> Self {
        if wall_now > local.wall_secs {
            local.wall_secs = wall_now;
            local.counter = 0;
        } else {
            local.counter = local.counter.saturating_add(1);
            if local.counter == u64::MAX {
                local.wall_secs = local.wall_secs.saturating_add(1);
                local.counter = 0;
            }
        }
        *local
    }

    /// Update the local clock on receiving a remote timestamp.
    ///
    /// Guarantees the returned timestamp is strictly greater than both
    /// the previous `local` value and `recv_ts`.
    pub fn receive(local: &mut Self, recv_ts: &Self, wall_now: u64) -> Self {
        let max_wall = wall_now.max(local.wall_secs).max(recv_ts.wall_secs);
        if max_wall > local.wall_secs && max_wall > recv_ts.wall_secs {
            local.wall_secs = max_wall;
            local.counter = 0;
        } else if max_wall == local.wall_secs && max_wall == recv_ts.wall_secs {
            local.counter = local.counter.max(recv_ts.counter).saturating_add(1);
        } else if max_wall == local.wall_secs {
            local.counter = local.counter.saturating_add(1);
        } else {
            local.wall_secs = recv_ts.wall_secs;
            local.counter = recv_ts.counter.saturating_add(1);
        }
        *local
    }
}

// ============================================================================
// M3: Vault Operation Log
// ============================================================================

/// A vault operation log entry.
///
/// Every vault mutation (secret CRUD, ACL change, delegation revocation,
/// coordinator operation) produces one log entry. The log is the ground truth;
/// `vault.db` is the fold of the log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultLogEntry {
    /// UUID v7 (time-ordered) unique entry identifier.
    pub id: uuid::Uuid,
    /// HLC timestamp for causal ordering.
    pub timestamp: HlcTimestamp,
    /// The `InstallationId.id` UUID of the authoring installation.
    pub author_installation_uuid: uuid::Uuid,
    /// Profile this entry belongs to.
    pub profile_id: uuid::Uuid,
    /// The vault operation.
    pub operation: VaultOperation,
    /// BLAKE3 hash of the previous entry by this author for this profile.
    /// `None` for the first entry.
    pub prev_by_author: Option<[u8; 32]>,
    /// Ed25519 signature (64 bytes, stored as `Vec<u8>` for serde compatibility).
    pub signature: Vec<u8>,
}

/// Vault operations that can appear in the replication log.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum VaultOperation {
    /// Insert or update a secret. Values are re-encrypted per destination device.
    SecretUpsert {
        key: String,
        /// Map from destination `InstallationId.id` hex to re-encrypted value.
        encrypted_values: HashMap<String, ReEncryptedValue>,
        content_type: String,
    },
    /// Delete a secret (tombstone).
    SecretDelete { key: String },
    /// Update profile metadata.
    ProfileMetadataUpdate {
        display_name: Option<String>,
        description: Option<String>,
    },
    /// Modify access control lists.
    AclUpdate {
        grants: Vec<String>,
        revocations: Vec<String>,
    },
    /// Revoke a delegation credential.
    DelegationRevocation {
        credential_id: uuid::Uuid,
        reason: String,
    },
    /// Store a coordinator endorsement.
    CoordinatorEndorsement { endorsement_json: String },
    /// Store a coordinator revocation.
    CoordinatorRevocation { revocation_json: String },
    /// Log compaction snapshot marker.
    CompactionSnapshot {
        snapshot_watermark: HlcTimestamp,
        snapshot_hash: [u8; 32],
    },
}

/// A secret value re-encrypted for a specific destination device.
///
/// Construction: ephemeral X25519 ECDH with destination's vault replication
/// public key → ChaCha20-Poly1305 seal with entry ID as AAD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReEncryptedValue {
    /// Ephemeral X25519 public key (32 bytes).
    pub ephemeral_pubkey: [u8; 32],
    /// 12-byte random nonce.
    pub nonce: [u8; 12],
    /// Ciphertext (variable length).
    pub ciphertext: Vec<u8>,
    /// Poly1305 authentication tag (16 bytes).
    pub tag: [u8; 16],
}

// ============================================================================
// M3: Offline Delegation
// ============================================================================

/// Offline delegation fallback behaviour when the delegating device is unreachable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum OfflineFallbackPosture {
    /// Hard fail when offline. For production/privileged credentials.
    DenyWhenOffline,
    /// Allow for up to `ttl_secs` after last proof-of-presence.
    CachedProofOfPresence { ttl_secs: u32 },
    /// Full allow within credential lifetime. For automated pipelines.
    AllowWhenOffline,
    /// Require local factor (hardware key, PIN) as offline substitute.
    LocalFactorFallback { factor_type: String },
}

/// Cached proof that the delegating device was recently reachable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfPresence {
    pub credential_id: uuid::Uuid,
    pub issued_at: HlcTimestamp,
    pub valid_until: HlcTimestamp,
    pub delegator_installation_id: uuid::Uuid,
    /// Ed25519 signature by the delegator's signing key.
    pub delegator_signature: Vec<u8>,
}

// ============================================================================
// M3: Coordinator Documents
// ============================================================================

/// A signed coordinator endorsement document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEndorsement {
    pub endorsement_id: uuid::Uuid,
    pub issued_at: HlcTimestamp,
    pub valid_until: HlcTimestamp,
    pub coordinator_installation_id: uuid::Uuid,
    /// Coordinator's Ed25519 public key (32 bytes).
    pub coordinator_pubkey: [u8; 32],
    pub subject_installation_id: uuid::Uuid,
    /// Subject's X25519 transport public key (32 bytes).
    pub subject_transport_pubkey: [u8; 32],
    pub display_name: String,
    pub capability_scope: EndorsementCapabilities,
    /// Ed25519 signature by the coordinator's signing key.
    pub coordinator_signature: Vec<u8>,
}

/// Capabilities granted by a coordinator endorsement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndorsementCapabilities {
    pub vault_replication: bool,
    pub rpc_calls: bool,
    pub coordinator_proxy: bool,
}

/// A signed coordinator revocation document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRevocation {
    pub revocation_id: uuid::Uuid,
    pub revokes_endorsement_id: uuid::Uuid,
    pub issued_at: HlcTimestamp,
    pub coordinator_installation_id: uuid::Uuid,
    /// Coordinator's Ed25519 public key (32 bytes).
    pub coordinator_pubkey: [u8; 32],
    /// Subject's X25519 transport public key (32 bytes).
    pub subject_transport_pubkey: [u8; 32],
    pub reason: RevocationReason,
    /// Ed25519 signature by the coordinator's signing key.
    pub coordinator_signature: Vec<u8>,
}

/// Reason for coordinator revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    KeyCompromise,
    PersonnelChange,
    PolicyViolation,
    Administrative,
    Renewal,
}

// ============================================================================
// M3: Delegation Credentials
// ============================================================================

/// A delegation credential document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationCredential {
    pub credential_id: uuid::Uuid,
    pub issued_at: HlcTimestamp,
    pub expires_at: HlcTimestamp,
    pub delegator_installation_id: uuid::Uuid,
    /// Delegator's Ed25519 signing public key (32 bytes).
    pub delegator_signing_pubkey: [u8; 32],
    pub delegate_installation_id: uuid::Uuid,
    pub capability_scope: DelegationScope,
    pub offline_fallback_posture: OfflineFallbackPosture,
    /// Ed25519 signature by the delegator's signing key.
    pub delegator_signature: Vec<u8>,
}

/// Scope of a delegation credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationScope {
    pub profile_ids: Vec<uuid::Uuid>,
    pub secret_key_patterns: Vec<String>,
    pub permitted_operations: Vec<String>,
}

// ============================================================================
// M3: Vault Replication Protocol Messages
// ============================================================================

/// Vault replication protocol messages exchanged between `daemon-network` peers.
///
/// Serialised as JSON within sealed `Data` frames with
/// `NetworkMessageType::VaultReplication`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VaultReplicationMessage {
    PullRequest {
        request_id: uuid::Uuid,
        profile_id: uuid::Uuid,
        since_watermark: Option<HlcTimestamp>,
        max_entries: u32,
    },
    PullResponse {
        request_id: uuid::Uuid,
        profile_id: uuid::Uuid,
        entries: Vec<VaultLogEntry>,
        has_more: bool,
        responder_head: HlcTimestamp,
    },
    PushHint {
        profile_id: uuid::Uuid,
        new_entry_count: u32,
        head_watermark: HlcTimestamp,
    },
    ErrorResponse {
        request_id: uuid::Uuid,
        code: u32,
        message: String,
    },
}

// ============================================================================
// PGP Word List (shared between daemon-network and open-sesame CLI)
// ============================================================================

/// PGP even-position words (byte value → word at even index).
pub const PGP_EVEN: [&str; 256] = [
    "aardvark",
    "absurd",
    "accrue",
    "acme",
    "adrift",
    "adult",
    "afflict",
    "ahead",
    "aimless",
    "algol",
    "allow",
    "alone",
    "ammo",
    "ancient",
    "apple",
    "artist",
    "assume",
    "athens",
    "atlas",
    "aztec",
    "baboon",
    "backfield",
    "backward",
    "banjo",
    "beaming",
    "bedlamp",
    "beehive",
    "beeswax",
    "befriend",
    "belfast",
    "berserk",
    "billiard",
    "bison",
    "blackjack",
    "blockade",
    "blowtorch",
    "bluebird",
    "bombast",
    "bookshelf",
    "brackish",
    "breadline",
    "breakup",
    "brickyard",
    "briefcase",
    "burbank",
    "button",
    "buzzard",
    "cement",
    "chairlift",
    "chatter",
    "checkup",
    "chessman",
    "chisel",
    "choking",
    "chopper",
    "christmas",
    "clamshell",
    "classic",
    "cleanup",
    "clockwork",
    "cobra",
    "commence",
    "concert",
    "cowbell",
    "crackdown",
    "cranky",
    "crowfoot",
    "crucial",
    "crumpled",
    "crusade",
    "cubic",
    "dashboard",
    "deadbolt",
    "deckhand",
    "dogsled",
    "dragnet",
    "drainage",
    "dreadful",
    "drifter",
    "dropout",
    "drumbeat",
    "drunken",
    "dupont",
    "dwelling",
    "eating",
    "edict",
    "egghead",
    "eightball",
    "endorse",
    "endow",
    "enlist",
    "erase",
    "escape",
    "exceed",
    "eyeglass",
    "eyetooth",
    "facet",
    "fairway",
    "fallout",
    "flagpole",
    "flatfoot",
    "flytrap",
    "fracture",
    "framework",
    "freedom",
    "frighten",
    "gazelle",
    "geiger",
    "glitter",
    "glucose",
    "goggles",
    "goldfish",
    "gremlin",
    "guidance",
    "hamlet",
    "highchair",
    "hockey",
    "indoors",
    "indulge",
    "inverse",
    "involve",
    "island",
    "jawbone",
    "keyboard",
    "kickoff",
    "kiwi",
    "klaxon",
    "locale",
    "lockup",
    "merit",
    "minnow",
    "miser",
    "mohawk",
    "mural",
    "music",
    "necklace",
    "neptune",
    "newborn",
    "nightbird",
    "oakland",
    "obtuse",
    "offload",
    "optic",
    "orca",
    "payday",
    "peachy",
    "pheasant",
    "physique",
    "playhouse",
    "pluto",
    "preclude",
    "prefer",
    "preshrunk",
    "printer",
    "prowler",
    "pupil",
    "puppy",
    "python",
    "quadrant",
    "quiver",
    "quota",
    "ragtime",
    "ratchet",
    "rebirth",
    "reform",
    "regain",
    "reindeer",
    "rematch",
    "repay",
    "retouch",
    "revenge",
    "reward",
    "rhythm",
    "ribcage",
    "ringbolt",
    "robust",
    "rocker",
    "ruffled",
    "sailboat",
    "sawdust",
    "scallion",
    "scenic",
    "scorecard",
    "scotland",
    "seabird",
    "select",
    "sentence",
    "shadow",
    "shamrock",
    "showgirl",
    "skullcap",
    "skydive",
    "slingshot",
    "slowdown",
    "snapline",
    "snapshot",
    "snowcap",
    "snowslide",
    "solo",
    "southward",
    "soybean",
    "spaniel",
    "spearhead",
    "spellbound",
    "spheroid",
    "spigot",
    "spindle",
    "spyglass",
    "stagehand",
    "stagnate",
    "stairway",
    "standard",
    "stapler",
    "steamship",
    "sterling",
    "stockman",
    "stopwatch",
    "stormy",
    "sugar",
    "surmount",
    "suspense",
    "sweatband",
    "swelter",
    "tactics",
    "talon",
    "tapeworm",
    "tempest",
    "tiger",
    "tissue",
    "tonic",
    "topmost",
    "tracker",
    "transit",
    "trauma",
    "treadmill",
    "trojan",
    "trouble",
    "tumor",
    "tunnel",
    "tycoon",
    "uncut",
    "unearth",
    "unify",
    "unkind",
    "until",
    "upward",
    "urban",
    "vengeance",
    "verdict",
    "viking",
    "viper",
    "vocal",
    "vulture",
    "waffle",
    "wallet",
    "watchword",
];

/// PGP odd-position words (byte value → word at odd index).
pub const PGP_ODD: [&str; 256] = [
    "adroitness",
    "adviser",
    "aftermath",
    "aggregate",
    "alkali",
    "almighty",
    "amulet",
    "amusement",
    "antenna",
    "applicant",
    "apollo",
    "armistice",
    "article",
    "asteroid",
    "atlantic",
    "atmosphere",
    "autopsy",
    "babylon",
    "backwater",
    "barbecue",
    "barometer",
    "bathrobe",
    "beaverton",
    "bedrock",
    "befuddle",
    "bellwether",
    "benchmark",
    "bikini",
    "blemish",
    "bodyguard",
    "bookseller",
    "borderline",
    "bottomless",
    "bradbury",
    "bravado",
    "brazilian",
    "breakaway",
    "burlington",
    "businessman",
    "butterfat",
    "camelot",
    "candidate",
    "cannonball",
    "capricorn",
    "caravan",
    "caretaker",
    "celebrate",
    "cellulose",
    "certify",
    "chambermaid",
    "cherokee",
    "chicago",
    "clergyman",
    "coherence",
    "combustion",
    "commando",
    "company",
    "component",
    "condition",
    "consensus",
    "converge",
    "corporate",
    "corrosion",
    "councilman",
    "crossover",
    "crucifix",
    "cumbersome",
    "customer",
    "dakota",
    "decadence",
    "december",
    "decimal",
    "designing",
    "detector",
    "diploma",
    "disaster",
    "disbelief",
    "disruptive",
    "distortion",
    "document",
    "embezzle",
    "enchanting",
    "enrollment",
    "enterprise",
    "equation",
    "equipment",
    "escapade",
    "ethernet",
    "eureka",
    "evidence",
    "examinee",
    "exodus",
    "fascinate",
    "filament",
    "finicky",
    "forever",
    "fortitude",
    "frequency",
    "gadgetry",
    "galveston",
    "getaway",
    "glossary",
    "goliath",
    "graduate",
    "gravity",
    "guitarist",
    "hamburger",
    "hamilton",
    "handiwork",
    "hazardous",
    "headwaters",
    "hemisphere",
    "hesitate",
    "hideaway",
    "holiness",
    "hurricane",
    "hydraulic",
    "hypnotic",
    "impetus",
    "inception",
    "indecent",
    "infancy",
    "inferno",
    "informant",
    "insincere",
    "insurgent",
    "integrate",
    "intention",
    "inventive",
    "istanbul",
    "Jamaica",
    "Jupiter",
    "leprosy",
    "letterhead",
    "liberty",
    "maritime",
    "matchmaker",
    "maverick",
    "medusa",
    "megaton",
    "microscope",
    "microwave",
    "midsummer",
    "millionaire",
    "miracle",
    "misnomer",
    "molasses",
    "molecule",
    "montana",
    "monument",
    "mosquito",
    "narrative",
    "nebula",
    "newsletter",
    "norwegian",
    "october",
    "ohio",
    "onlooker",
    "opulent",
    "orlando",
    "outfielder",
    "pacific",
    "pandemic",
    "pandora",
    "paperweight",
    "paragon",
    "paragraph",
    "paramount",
    "passenger",
    "pedigree",
    "pegasus",
    "penetrate",
    "perceptive",
    "performance",
    "pharmacy",
    "pineapple",
    "playmate",
    "plywood",
    "pneumonia",
    "politician",
    "pompadour",
    "populace",
    "portfolio",
    "potato",
    "processor",
    "prodigy",
    "professor",
    "propellant",
    "prosper",
    "publisher",
    "pugnacious",
    "pyramid",
    "quantity",
    "racketeer",
    "rebellion",
    "recipe",
    "renegade",
    "resistor",
    "retirement",
    "retrieval",
    "retrospect",
    "revenue",
    "revival",
    "revolver",
    "sandalwood",
    "sardonic",
    "saturday",
    "savagery",
    "scavenger",
    "sensation",
    "september",
    "sequence",
    "shanghai",
    "simulated",
    "singular",
    "skirmish",
    "sociable",
    "souvenir",
    "specialist",
    "speculate",
    "stethoscope",
    "stupendous",
    "subscriber",
    "subterfuge",
    "suggestion",
    "supernova",
    "surrender",
    "suspicious",
    "sympathy",
    "tambourine",
    "telephone",
    "therapist",
    "tobacco",
    "tolerance",
    "tomorrow",
    "torpedo",
    "tradition",
    "travesty",
    "trombonist",
    "truncated",
    "typewriter",
    "ultimate",
    "undaunted",
    "underfoot",
    "unicorn",
    "uninstall",
    "universe",
    "unravel",
    "upcoming",
    "vacancy",
    "vagabond",
    "vertigo",
    "virginia",
    "visitor",
    "vocalist",
    "voyager",
];

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- FingerprintEncoding --

    #[test]
    fn fingerprint_encoding_default_is_pgp_word_list() {
        assert_eq!(
            FingerprintEncoding::default(),
            FingerprintEncoding::PgpWordList
        );
    }

    // -- `HandshakeAck` --

    #[test]
    fn handshake_ack_roundtrip_json() {
        let ack = HandshakeAck {
            installation_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            display_name: Some("test-peer".into()),
            network_pubkey: "aa".repeat(32),
            signing_pubkey: "bb".repeat(32),
            cipher_suite: "Noise_XX_25519_ChaChaPoly_BLAKE2s".into(),
            signature: "cc".repeat(64),
        };
        let json = serde_json::to_string(&ack).unwrap();
        let decoded: HandshakeAck = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.installation_id, ack.installation_id);
        assert_eq!(decoded.cipher_suite, ack.cipher_suite);
        assert_eq!(decoded.signature, ack.signature);
        assert_eq!(decoded.display_name, ack.display_name);
    }

    #[test]
    fn handshake_ack_cipher_suite_field_present() {
        let ack = HandshakeAck {
            installation_id: String::new(),
            display_name: None,
            network_pubkey: String::new(),
            signing_pubkey: String::new(),
            cipher_suite: "Noise_XX_XWing_ChaChaPoly_BLAKE2b".into(),
            signature: String::new(),
        };
        let json = serde_json::to_string(&ack).unwrap();
        assert!(json.contains("Noise_XX_XWing_ChaChaPoly_BLAKE2b"));
    }

    #[test]
    fn fingerprint_encoding_roundtrip_json() {
        for enc in [
            FingerprintEncoding::PgpWordList,
            FingerprintEncoding::Hex,
            FingerprintEncoding::NumericSas,
        ] {
            let json = serde_json::to_string(&enc).unwrap();
            let decoded: FingerprintEncoding = serde_json::from_str(&json).unwrap();
            assert_eq!(enc, decoded);
        }
    }

    // -- VaultLogOp --

    #[test]
    fn vault_log_op_roundtrip_json() {
        for op in [VaultLogOp::Set, VaultLogOp::Delete, VaultLogOp::AclUpdate] {
            let json = serde_json::to_string(&op).unwrap();
            let decoded: VaultLogOp = serde_json::from_str(&json).unwrap();
            assert_eq!(op, decoded);
        }
    }

    // -- TofuTrustLevel --

    #[test]
    fn tofu_trust_level_roundtrip_json() {
        for level in [
            TofuTrustLevel::Tofu,
            TofuTrustLevel::Bootstrap,
            TofuTrustLevel::Endorsed,
            TofuTrustLevel::Revoked,
            TofuTrustLevel::Unpinned,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let decoded: TofuTrustLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, decoded);
        }
    }

    // -- NetworkMessageType --

    #[test]
    fn network_message_type_repr_values() {
        assert_eq!(NetworkMessageType::Control as u16, 0x0001);
        assert_eq!(NetworkMessageType::VaultReplication as u16, 0x0100);
        assert_eq!(NetworkMessageType::ProfileSync as u16, 0x0101);
        assert_eq!(NetworkMessageType::Discovery as u16, 0x0200);
        assert_eq!(NetworkMessageType::Coordinator as u16, 0x0300);
    }

    #[test]
    fn network_message_type_roundtrip_json() {
        for ty in [
            NetworkMessageType::Control,
            NetworkMessageType::VaultReplication,
            NetworkMessageType::ProfileSync,
            NetworkMessageType::Discovery,
            NetworkMessageType::Coordinator,
        ] {
            let json = serde_json::to_string(&ty).unwrap();
            let decoded: NetworkMessageType = serde_json::from_str(&json).unwrap();
            assert_eq!(ty, decoded);
        }
    }

    // -- FrameType --

    #[test]
    fn frame_type_repr_values() {
        assert_eq!(FrameType::HandshakeInit as u8, 0x01);
        assert_eq!(FrameType::Data as u8, 0x10);
        assert_eq!(FrameType::Close as u8, 0x12);
        assert_eq!(FrameType::RehandshakeRequest as u8, 0x13);
    }

    #[test]
    fn frame_type_roundtrip_json() {
        for ft in [
            FrameType::HandshakeInit,
            FrameType::HandshakeResponse,
            FrameType::HandshakeFinal,
            FrameType::CookieRequest,
            FrameType::CookieResponse,
            FrameType::Data,
            FrameType::KeepAlive,
            FrameType::Close,
            FrameType::RehandshakeRequest,
        ] {
            let json = serde_json::to_string(&ft).unwrap();
            let decoded: FrameType = serde_json::from_str(&json).unwrap();
            assert_eq!(ft, decoded);
        }
    }

    // -- HlcTimestamp --

    #[test]
    fn hlc_zero() {
        let z = HlcTimestamp::zero();
        assert_eq!(z.wall_secs, 0);
        assert_eq!(z.counter, 0);
        assert_eq!(z.node_id, [0; 8]);
    }

    #[test]
    fn hlc_ordering() {
        let a = HlcTimestamp {
            wall_secs: 1,
            counter: 0,
            node_id: [0; 8],
        };
        let b = HlcTimestamp {
            wall_secs: 1,
            counter: 1,
            node_id: [0; 8],
        };
        let c = HlcTimestamp {
            wall_secs: 2,
            counter: 0,
            node_id: [0; 8],
        };
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn hlc_node_id_tiebreak() {
        let a = HlcTimestamp {
            wall_secs: 1,
            counter: 0,
            node_id: [0; 8],
        };
        let b = HlcTimestamp {
            wall_secs: 1,
            counter: 0,
            node_id: [1, 0, 0, 0, 0, 0, 0, 0],
        };
        assert!(a < b);
    }

    #[test]
    fn hlc_tick_monotonic_same_wall() {
        let mut clock = HlcTimestamp {
            wall_secs: 100,
            counter: 0,
            node_id: [0; 8],
        };
        let t1 = HlcTimestamp::tick(&mut clock, 100);
        let t2 = HlcTimestamp::tick(&mut clock, 100);
        let t3 = HlcTimestamp::tick(&mut clock, 100);
        assert!(t2 > t1);
        assert!(t3 > t2);
    }

    #[test]
    fn hlc_tick_wall_advance_resets_counter() {
        let mut clock = HlcTimestamp {
            wall_secs: 100,
            counter: 42,
            node_id: [0; 8],
        };
        let t = HlcTimestamp::tick(&mut clock, 200);
        assert_eq!(t.wall_secs, 200);
        assert_eq!(t.counter, 0);
    }

    #[test]
    fn hlc_receive_greater_than_both() {
        let mut local = HlcTimestamp {
            wall_secs: 10,
            counter: 5,
            node_id: [0; 8],
        };
        let remote = HlcTimestamp {
            wall_secs: 10,
            counter: 3,
            node_id: [1; 8],
        };
        let before = local;
        let result = HlcTimestamp::receive(&mut local, &remote, 10);
        assert!(result > before);
        assert!(result > remote);
    }

    #[test]
    fn hlc_receive_wall_advance() {
        let mut local = HlcTimestamp {
            wall_secs: 5,
            counter: 99,
            node_id: [0; 8],
        };
        let remote = HlcTimestamp {
            wall_secs: 3,
            counter: 50,
            node_id: [1; 8],
        };
        let result = HlcTimestamp::receive(&mut local, &remote, 100);
        assert_eq!(result.wall_secs, 100);
        assert_eq!(result.counter, 0);
    }

    #[test]
    fn hlc_roundtrip_json() {
        let ts = HlcTimestamp {
            wall_secs: 1_700_000_000,
            counter: 42,
            node_id: [0xAA; 8],
        };
        let json = serde_json::to_string(&ts).unwrap();
        let decoded: HlcTimestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(ts, decoded);
    }

    // -- VaultOperation --

    #[test]
    fn vault_operation_secret_delete_roundtrip_json() {
        let op = VaultOperation::SecretDelete {
            key: "api-key".into(),
        };
        let json = serde_json::to_string(&op).unwrap();
        let decoded: VaultOperation = serde_json::from_str(&json).unwrap();
        match decoded {
            VaultOperation::SecretDelete { key } => assert_eq!(key, "api-key"),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn vault_operation_compaction_snapshot_roundtrip_json() {
        let op = VaultOperation::CompactionSnapshot {
            snapshot_watermark: HlcTimestamp {
                wall_secs: 1000,
                counter: 0,
                node_id: [0; 8],
            },
            snapshot_hash: [0xBB; 32],
        };
        let json = serde_json::to_string(&op).unwrap();
        let decoded: VaultOperation = serde_json::from_str(&json).unwrap();
        match decoded {
            VaultOperation::CompactionSnapshot {
                snapshot_watermark,
                snapshot_hash,
            } => {
                assert_eq!(snapshot_watermark.wall_secs, 1000);
                assert_eq!(snapshot_hash, [0xBB; 32]);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // -- ReEncryptedValue --

    #[test]
    fn re_encrypted_value_roundtrip_json() {
        let val = ReEncryptedValue {
            ephemeral_pubkey: [0xAA; 32],
            nonce: [0xBB; 12],
            ciphertext: vec![0xCC; 64],
            tag: [0xDD; 16],
        };
        let json = serde_json::to_string(&val).unwrap();
        let decoded: ReEncryptedValue = serde_json::from_str(&json).unwrap();
        assert_eq!(val.ephemeral_pubkey, decoded.ephemeral_pubkey);
        assert_eq!(val.nonce, decoded.nonce);
        assert_eq!(val.ciphertext, decoded.ciphertext);
        assert_eq!(val.tag, decoded.tag);
    }

    // -- OfflineFallbackPosture --

    #[test]
    fn offline_posture_deny_roundtrip_json() {
        let p = OfflineFallbackPosture::DenyWhenOffline;
        let json = serde_json::to_string(&p).unwrap();
        let decoded: OfflineFallbackPosture = serde_json::from_str(&json).unwrap();
        match decoded {
            OfflineFallbackPosture::DenyWhenOffline => {}
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn offline_posture_cached_roundtrip_json() {
        let p = OfflineFallbackPosture::CachedProofOfPresence { ttl_secs: 3600 };
        let json = serde_json::to_string(&p).unwrap();
        let decoded: OfflineFallbackPosture = serde_json::from_str(&json).unwrap();
        match decoded {
            OfflineFallbackPosture::CachedProofOfPresence { ttl_secs } => {
                assert_eq!(ttl_secs, 3600);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    // -- RevocationReason --

    #[test]
    fn revocation_reason_roundtrip_json() {
        for reason in [
            RevocationReason::KeyCompromise,
            RevocationReason::PersonnelChange,
            RevocationReason::PolicyViolation,
            RevocationReason::Administrative,
            RevocationReason::Renewal,
        ] {
            let json = serde_json::to_string(&reason).unwrap();
            let decoded: RevocationReason = serde_json::from_str(&json).unwrap();
            assert_eq!(reason, decoded);
        }
    }

    // -- EndorsementCapabilities --

    #[test]
    fn endorsement_capabilities_roundtrip_json() {
        let caps = EndorsementCapabilities {
            vault_replication: true,
            rpc_calls: true,
            coordinator_proxy: false,
        };
        let json = serde_json::to_string(&caps).unwrap();
        let decoded: EndorsementCapabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(caps.vault_replication, decoded.vault_replication);
        assert_eq!(caps.rpc_calls, decoded.rpc_calls);
        assert_eq!(caps.coordinator_proxy, decoded.coordinator_proxy);
    }

    // -- VaultReplicationMessage --

    #[test]
    fn replication_push_hint_roundtrip_json() {
        let msg = VaultReplicationMessage::PushHint {
            profile_id: uuid::Uuid::from_u128(42),
            new_entry_count: 5,
            head_watermark: HlcTimestamp {
                wall_secs: 1000,
                counter: 3,
                node_id: [0xAA; 8],
            },
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: VaultReplicationMessage = serde_json::from_str(&json).unwrap();
        match decoded {
            VaultReplicationMessage::PushHint {
                new_entry_count, ..
            } => assert_eq!(new_entry_count, 5),
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
