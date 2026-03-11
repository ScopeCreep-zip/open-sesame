//! Shared types, error types, and event schema for the PDS IPC bus.
//!
//! This crate defines the canonical type system shared across all PDS crates.
//! It has zero platform dependencies and is `no_std`-compatible for hot-path types.
//! Minimal external deps: serde, uuid, thiserror.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::ops::Deref;
use std::time::{Duration, Instant, SystemTime};
use uuid::Uuid;
use zeroize::Zeroize;

// ============================================================================
// SensitiveBytes — zeroize-on-drop wrapper for secret byte fields
// ============================================================================

/// Sensitive byte buffer with automatic zeroize-on-drop.
///
/// Used for secret values and passwords in IPC `EventKind` variants.
/// Zeroes the backing memory when dropped to prevent heap forensics.
/// Debug output is redacted to prevent log exposure.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SensitiveBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED; {} bytes]", self.0.len())
    }
}

impl From<Vec<u8>> for SensitiveBytes {
    fn from(data: Vec<u8>) -> Self {
        Self(data)
    }
}

// ============================================================================
// Identity Types
// ============================================================================

macro_rules! define_id {
    ($name:ident, $prefix:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            #[must_use]
            pub fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            #[must_use]
            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}-{}", $prefix, self.0)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

define_id!(ProfileId, "prof");
define_id!(WindowId, "win");
define_id!(WorkspaceId, "ws");
define_id!(MonitorId, "mon");
define_id!(ClipboardEntryId, "clip");
define_id!(DaemonId, "dmon");
define_id!(ExtensionId, "ext");
define_id!(AgentId, "agent");

// ============================================================================
// AppId
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppId(String);

impl AppId {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Extract the last segment of a reverse-DNS app ID.
    /// `"com.mitchellh.ghostty"` -> `"ghostty"`
    /// `"firefox"` -> `"firefox"`
    #[must_use]
    pub fn last_segment(&self) -> &str {
        self.0.rsplit('.').next().unwrap_or(&self.0)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Case-insensitive match against another `AppId` or fragment.
    #[must_use]
    pub fn matches(&self, other: &str) -> bool {
        self.0.eq_ignore_ascii_case(other)
            || self.last_segment().eq_ignore_ascii_case(other)
            || other
                .rsplit('.')
                .next()
                .is_some_and(|seg| self.last_segment().eq_ignore_ascii_case(seg))
    }
}

impl fmt::Display for AppId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ============================================================================
// SecretRef
// ============================================================================

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SecretRef {
    /// Profile-scoped keyring: `{ secret = "work/github-token" }`
    Keyring { secret: String },
    /// 1Password CLI: `{ op = "op://Private/OpenAI/api-key" }`
    OnePassword { op: String },
    /// Environment variable (CI only): `{ env = "DB_PASSWORD" }`
    Env { env: String },
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keyring { secret } => write!(f, "SecretRef(keyring:{secret})"),
            Self::OnePassword { op } => write!(f, "SecretRef(op:{op})"),
            Self::Env { env } => write!(f, "SecretRef(env:{env})"),
        }
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// ============================================================================
// SensitivityClass
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum SensitivityClass {
    #[default]
    Public,
    Confidential,
    Secret,
    TopSecret,
}

// ============================================================================
// SecurityLevel
// ============================================================================

/// Classifies the sensitivity of message content for bus routing.
///
/// NOT an agent trust tier. Agent trust is evaluated via `TrustVector`.
/// This enum determines which bus subscribers are permitted to receive a
/// message based on their registered clearance level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum SecurityLevel {
    /// Events visible to all subscribers including extensions.
    Open,
    /// Events visible to authenticated daemons only.
    #[default]
    Internal,
    /// Events visible only to daemons holding the current profile's security context.
    ProfileScoped,
    /// Events visible only to the secrets daemon.
    SecretsOnly,
}

// ============================================================================
// Cryptographic Algorithm Configuration
// ============================================================================

/// Key derivation function algorithm for master password -> master key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum KdfAlgorithm {
    /// Argon2id with memory-hard parameters. Leading-edge default.
    #[default]
    Argon2id,
    /// PBKDF2-SHA256 with 600K iterations. NIST/FedRAMP-compatible.
    Pbkdf2Sha256,
}

/// HKDF algorithm for master key -> vault key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum HkdfAlgorithm {
    /// BLAKE3 keyed derivation. Leading-edge default.
    #[default]
    Blake3,
    /// HKDF-SHA256. NIST/FedRAMP-compatible.
    HkdfSha256,
}

/// Noise protocol cipher suite selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum NoiseCipher {
    /// ChaCha20-Poly1305. Leading-edge default.
    #[default]
    ChaChaPoly,
    /// AES-256-GCM. NIST/FedRAMP-compatible.
    AesGcm,
}

/// Noise protocol hash function selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum NoiseHash {
    /// BLAKE2s. Leading-edge default.
    #[default]
    Blake2s,
    /// SHA-256. NIST/FedRAMP-compatible.
    Sha256,
}

/// Hash algorithm for audit log chain integrity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum AuditHash {
    /// BLAKE3. Leading-edge default.
    #[default]
    Blake3,
    /// SHA-256. NIST/FedRAMP-compatible.
    Sha256,
}

/// Pre-defined cryptographic algorithm profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum CryptoProfile {
    /// Modern algorithms: Argon2id, BLAKE3, ChaCha20-Poly1305, BLAKE2s.
    #[default]
    LeadingEdge,
    /// NIST/FedRAMP-compatible: PBKDF2-SHA256, HKDF-SHA256, AES-GCM, SHA-256.
    GovernanceCompatible,
    /// Individual algorithm selection via `CryptoConfig` fields.
    Custom,
}

/// Complete cryptographic algorithm configuration.
///
/// Determines which algorithms are used for key derivation, HKDF, Noise
/// transport, and audit hashing. `CryptoProfile::LeadingEdge` is the default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoConfig {
    pub kdf: KdfAlgorithm,
    pub hkdf: HkdfAlgorithm,
    pub noise_cipher: NoiseCipher,
    pub noise_hash: NoiseHash,
    pub audit_hash: AuditHash,
    /// Minimum crypto profile accepted from federation peers.
    pub minimum_peer_profile: CryptoProfile,
}

// ============================================================================
// Installation Identity
// ============================================================================

/// Unique identity for this Open Sesame installation.
///
/// Installation-scoped: two installations of Open Sesame on different machines
/// produce different `InstallationId`s, and therefore different `ProfileId`s
/// for the same profile name. This prevents cross-installation ID collisions
/// in federation scenarios.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationId {
    /// Unique installation identifier (UUID v4, generated once at `sesame init`).
    pub id: Uuid,
    /// Optional organizational namespace for enterprise deployments.
    pub org_ns: Option<OrganizationNamespace>,
    /// Derived namespace for deterministic ID generation (e.g., profile IDs).
    /// Computed as `uuid5(org_ns.namespace || PROFILE_NS, "install:{id}")`.
    pub namespace: Uuid,
    /// Optional machine binding for hardware attestation.
    pub machine_binding: Option<MachineBinding>,
}

/// Organizational namespace for enterprise-managed installations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationNamespace {
    /// Organization domain (e.g., "braincraft.io").
    pub domain: String,
    /// Deterministic namespace derived from domain: `uuid5(NAMESPACE_URL, domain)`.
    pub namespace: Uuid,
}

/// Cryptographic binding to a specific machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineBinding {
    /// Hash of machine identity material (e.g., `/etc/machine-id` + installation ID).
    pub binding_hash: [u8; 32],
    /// Type of machine binding used.
    pub binding_type: MachineBindingType,
}

/// How the machine identity was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MachineBindingType {
    /// Derived from `/etc/machine-id` (Linux) or equivalent.
    MachineId,
    /// Bound to a TPM-sealed key.
    TpmBound,
}

// ============================================================================
// OCI Reference
// ============================================================================

/// OCI-style content-addressable reference for extensions and policies.
///
/// Format: `registry/principal/scope:revision[@provenance]`
///
/// Examples:
/// - `registry.example.com/org/extension:1.0.0`
/// - `registry.example.com/org/extension:1.0.0@sha256:abc123`
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OciReference {
    pub registry: String,
    pub principal: String,
    pub scope: String,
    pub revision: String,
    pub provenance: Option<String>,
}

impl OciReference {
    /// Parse an OCI reference string.
    ///
    /// Expected format: `registry/principal/scope:revision[@provenance]`
    ///
    /// # Errors
    ///
    /// Returns `Error::Validation` if the input is empty or malformed.
    pub fn parse(input: &str) -> Result<Self> {
        input.parse()
    }
}

impl std::str::FromStr for OciReference {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Err(Error::Validation("OCI reference must not be empty".into()));
        }

        // Split off provenance (@...)
        let (main, provenance) = match s.rsplit_once('@') {
            Some((m, p)) if !p.is_empty() => (m, Some(p.to_owned())),
            Some((_, _)) => return Err(Error::Validation("OCI reference has empty provenance after '@'".into())),
            None => (s, None),
        };

        // Split off revision (:...)
        let (path, revision) = match main.rsplit_once(':') {
            Some((p, r)) if !r.is_empty() => (p, r.to_owned()),
            Some((_, _)) => return Err(Error::Validation("OCI reference has empty revision after ':'".into())),
            None => return Err(Error::Validation("OCI reference missing ':revision'".into())),
        };

        // Split path into registry/principal/scope (at least 3 segments)
        let segments: Vec<&str> = path.splitn(3, '/').collect();
        if segments.len() < 3 {
            return Err(Error::Validation(format!(
                "OCI reference path must have at least 3 segments (registry/principal/scope), got {}",
                segments.len()
            )));
        }

        for (name, val) in [("registry", segments[0]), ("principal", segments[1]), ("scope", segments[2])] {
            if val.is_empty() {
                return Err(Error::Validation(format!("OCI reference {name} must not be empty")));
            }
        }

        Ok(Self {
            registry: segments[0].to_owned(),
            principal: segments[1].to_owned(),
            scope: segments[2].to_owned(),
            revision,
            provenance,
        })
    }
}

impl fmt::Display for OciReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}:{}", self.registry, self.principal, self.scope, self.revision)?;
        if let Some(ref prov) = self.provenance {
            write!(f, "@{prov}")?;
        }
        Ok(())
    }
}

// ============================================================================
// Capability Lattice
// ============================================================================

/// A set of capabilities forming a lattice with union/intersection operations.
///
/// Capabilities are the unit of authorization. An agent's `session_scope`
/// determines what operations it may perform. Delegation narrows scope via
/// intersection — a delegatee can never exceed its delegator's capabilities.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub capabilities: BTreeSet<Capability>,
}

impl CapabilitySet {
    /// The empty capability set — no permissions.
    #[must_use]
    pub fn empty() -> Self {
        Self { capabilities: BTreeSet::new() }
    }

    /// A capability set containing all non-parameterized capabilities.
    #[must_use]
    pub fn all() -> Self {
        Self {
            capabilities: [
                Capability::Admin,
                Capability::SecretRead { key_pattern: None },
                Capability::SecretWrite { key_pattern: None },
                Capability::SecretDelete { key_pattern: None },
                Capability::SecretList,
                Capability::ProfileActivate,
                Capability::ProfileDeactivate,
                Capability::ProfileList,
                Capability::ProfileSetDefault,
                Capability::StatusRead,
                Capability::AuditRead,
                Capability::ConfigReload,
                Capability::Unlock,
                Capability::Lock,
                Capability::ExtensionInstall,
                Capability::ExtensionManage,
            ].into_iter().collect(),
        }
    }

    /// Set union: all capabilities from both sets.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        Self {
            capabilities: self.capabilities.union(&other.capabilities).cloned().collect(),
        }
    }

    /// Set intersection: only capabilities present in both sets.
    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        Self {
            capabilities: self.capabilities.intersection(&other.capabilities).cloned().collect(),
        }
    }

    /// True if every capability in `self` is also in `other`.
    #[must_use]
    pub fn is_subset(&self, other: &Self) -> bool {
        self.capabilities.is_subset(&other.capabilities)
    }

    /// True if every capability in `other` is also in `self`.
    #[must_use]
    pub fn is_superset(&self, other: &Self) -> bool {
        self.capabilities.is_superset(&other.capabilities)
    }

    /// True if the set has no capabilities.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }
}

/// Individual capability for authorization decisions.
///
/// Capabilities are descriptive permissions, not roles. An agent may hold
/// any combination. `Ord` is derived for `BTreeSet` membership; the ordering
/// is arbitrary and not meaningful for authorization.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    /// Full administrative access.
    Admin,
    /// Read secrets, optionally restricted by key pattern.
    SecretRead { key_pattern: Option<String> },
    /// Write secrets, optionally restricted by key pattern.
    SecretWrite { key_pattern: Option<String> },
    /// Delete secrets, optionally restricted by key pattern.
    SecretDelete { key_pattern: Option<String> },
    /// List secret keys (not values).
    SecretList,
    /// Activate trust profiles.
    ProfileActivate,
    /// Deactivate trust profiles.
    ProfileDeactivate,
    /// List trust profiles.
    ProfileList,
    /// Change the default trust profile.
    ProfileSetDefault,
    /// Read system status.
    StatusRead,
    /// Read audit log.
    AuditRead,
    /// Trigger configuration reload.
    ConfigReload,
    /// Unlock the secrets vault.
    Unlock,
    /// Lock the secrets vault.
    Lock,
    /// Delegate capabilities to another agent with scope and time constraints.
    Delegate {
        max_depth: u8,
        scope: Box<CapabilitySet>,
    },
    /// Install extensions.
    ExtensionInstall,
    /// Manage (enable/disable/remove) extensions.
    ExtensionManage,
}

/// A delegation grant from one agent to another.
///
/// Delegation narrows scope: the delegatee's effective capabilities are
/// `delegator_scope.intersection(grant.scope)`. Grants are time-bounded
/// and require heartbeat renewal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationGrant {
    /// Agent that issued this delegation.
    pub delegator: AgentId,
    /// Maximum capabilities the delegatee may exercise.
    pub scope: CapabilitySet,
    /// Time-to-live from grant creation.
    pub initial_ttl: Duration,
    /// Required heartbeat interval to maintain the delegation.
    pub heartbeat_interval: Duration,
    /// Anti-replay nonce.
    pub nonce: [u8; 16],
    /// Optional OCI reference restricting where this delegation can be used.
    pub point_of_use_filter: Option<OciReference>,
    /// Ed25519 signature over the grant fields by the delegator (64 bytes).
    pub signature: Vec<u8>,
}

/// A link in a delegation chain, recording the grant and its depth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationLink {
    pub grant: DelegationGrant,
    /// Depth in the delegation chain (0 = direct from human operator).
    pub depth: u8,
}

// ============================================================================
// Attestation
// ============================================================================

/// How an agent's identity claim was verified.
///
/// Each variant captures the evidence used for a specific attestation method.
/// Multiple attestations may be composed to strengthen trust (e.g., `UCred` +
/// `MasterPassword` = higher `TrustLevel` than either alone).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Attestation {
    /// Unix domain socket credentials (pid, uid, gid).
    UCred {
        pid: u32,
        uid: u32,
        gid: u32,
    },
    /// Noise IK static key verified against the clearance registry.
    NoiseIK {
        public_key: [u8; 32],
        registry_generation: u64,
    },
    /// Master password verified against the KDF-derived key.
    MasterPassword {
        verified_at: u64,
    },
    /// Hardware security key (FIDO2/WebAuthn).
    SecurityKey {
        credential_id: Vec<u8>,
        verified_at: u64,
    },
    /// Process attestation via `/proc` inspection or equivalent.
    ProcessAttestation {
        pid: u32,
        exe_hash: [u8; 32],
        uid: u32,
    },
    /// Delegated authority from another agent.
    Delegation {
        delegator: AgentId,
        scope: CapabilitySet,
        chain_depth: u8,
    },
    /// Device-level attestation (TPM, Secure Boot, etc.).
    DeviceAttestation {
        binding: MachineBinding,
        verified_at: u64,
    },
    /// Remote attestation from a federated peer (v2: defined, not exercised).
    RemoteAttestation {
        remote_installation: InstallationId,
        remote_device_attestation: Box<Attestation>,
    },
    /// Heartbeat renewal extending a time-bounded attestation.
    HeartbeatRenewal {
        original_attestation_type: AttestationType,
        renewal_attestation: Box<Attestation>,
        renewed_at: u64,
    },
}

/// Lightweight summary of an attestation method (variant name only, no payloads).
///
/// Used in wire protocol and audit log where the full attestation evidence
/// is not needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationType {
    UCred,
    NoiseIK,
    MasterPassword,
    SecurityKey,
    ProcessAttestation,
    Delegation,
    DeviceAttestation,
    RemoteAttestation,
    HeartbeatRenewal,
}

/// Which attestation methods are available to a given agent type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationMethod {
    /// Password-based (human agents).
    MasterPassword,
    /// Hardware security key (human agents with FIDO2).
    SecurityKey,
    /// Process identity verification (service/extension agents).
    ProcessAttestation,
    /// Delegation chain from another agent (AI/service agents).
    Delegation,
    /// Machine-level binding (all agent types on bound installations).
    DeviceAttestation,
}

// ============================================================================
// Agent Identity
// ============================================================================

/// What kind of entity an agent is.
///
/// `AgentType` is descriptive metadata, NOT a trust tier. An AI agent with
/// proper attestations and delegation can have higher effective trust than
/// a human agent without a security key. Trust is evaluated via `TrustVector`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentType {
    /// Human operator (interactive, keyboard/mouse).
    Human,
    /// AI agent (LLM-based, API-driven).
    AI { model_family: String },
    /// System service (systemd unit, daemon).
    Service { unit: String },
    /// WASM extension (sandboxed, content-addressed).
    Extension { manifest_hash: [u8; 32] },
}

/// Process-level identity of an agent on the local machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalAgentId {
    /// Identified by Unix UID only.
    UnixUid(u32),
    /// Identified by UID + process name.
    ProcessIdentity { uid: u32, process_name: String },
    /// Identified by systemd unit name.
    SystemdUnit(String),
    /// Identified by WASM module content hash.
    WasmHash([u8; 32]),
}

/// Metadata describing an agent's type and available attestation methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMetadata {
    pub agent_type: AgentType,
    pub available_attestation_methods: Vec<AttestationMethod>,
}

/// Complete identity of an agent operating through the system.
///
/// Combines the agent's unique ID, type classification, local process identity,
/// installation binding, accumulated attestations, authorized capabilities,
/// and delegation chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub id: AgentId,
    pub agent_type: AgentType,
    pub local_id: LocalAgentId,
    pub installation: InstallationId,
    /// Attestations accumulated during this session.
    pub attestations: Vec<Attestation>,
    /// Effective capability scope for this session.
    pub session_scope: CapabilitySet,
    /// Chain of delegations leading to this agent's authority.
    pub delegation_chain: Vec<DelegationLink>,
}

// ============================================================================
// Trust Evaluation
// ============================================================================

/// Discrete trust levels for individual assessment dimensions.
///
/// Ordering: `None < Low < Medium < High < Hardware`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    None,
    Low,
    Medium,
    High,
    Hardware,
}

/// Network exposure classification.
///
/// Ordering for trust: `Local` (most trusted) > `Encrypted` > `Onion` > `PublicInternet`.
/// Ordering for exposure (the enum's `Ord`): `Local < Encrypted < Onion < PublicInternet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkTrust {
    /// Unix domain socket, same machine.
    Local,
    /// Encrypted tunnel (Noise, TLS, `WireGuard`).
    Encrypted,
    /// Onion-routed (Tor, Veilid).
    Onion,
    /// Unencrypted or minimally-authenticated public internet.
    PublicInternet,
}

/// Multi-dimensional trust assessment of an agent at a point in time.
///
/// Used by authorization decisions to determine whether an operation should
/// be permitted. Each dimension is independently assessed and may change
/// over the lifetime of a session (e.g., `authz_freshness` degrades).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustVector {
    /// Strength of authentication evidence.
    pub authn_strength: TrustLevel,
    /// Time since last authorization refresh.
    pub authz_freshness: Duration,
    /// Depth in the delegation chain (0 = direct human).
    pub delegation_depth: u8,
    /// Composite device security posture score (0.0 = unknown, 1.0 = fully attested).
    pub device_posture: f64,
    /// Network exposure of the connection.
    pub network_exposure: NetworkTrust,
    /// Type of the agent being assessed.
    pub agent_type: AgentType,
}

// ============================================================================
// ProfileRef
// ============================================================================

/// Fully-qualified profile reference combining name, ID, and installation.
///
/// Used in federation contexts where a profile must be unambiguously identified
/// across installations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileRef {
    pub name: TrustProfileName,
    pub id: ProfileId,
    pub installation: InstallationId,
}

// ============================================================================
// Timestamp
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timestamp {
    /// Monotonic counter for ordering within a single daemon lifecycle.
    /// Nanoseconds since daemon start.
    pub monotonic_ns: u64,
    /// Wall clock for cross-daemon and cross-restart ordering.
    /// Milliseconds since Unix epoch.
    pub wall_ms: u64,
}

impl Timestamp {
    #[must_use]
    pub fn now(epoch: Instant) -> Self {
        let mono = epoch.elapsed();
        let wall = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        Self {
            #[allow(clippy::cast_possible_truncation)] // Uptime > 584 years before truncation
            monotonic_ns: mono.as_nanos() as u64,
            #[allow(clippy::cast_possible_truncation)] // Wall clock > 584M years before truncation
            wall_ms: wall.as_millis() as u64,
        }
    }
}

// ============================================================================
// Security Protocol Types
// ============================================================================

/// Why an unlock request was rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnlockRejectedReason {
    /// System is already unlocked. Distinct from wrong password.
    AlreadyUnlocked,
}

/// Why a secret operation was denied (typed denial, replaces ambiguous empty responses).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretDenialReason {
    Locked,
    ProfileNotActive,
    AccessDenied,
    RateLimited,
    NotFound,
    VaultError(String),
}

// ============================================================================
// EventKind
// ============================================================================

/// Externally-tagged enum (serde default) for postcard wire compatibility.
/// Postcard does not support `#[serde(tag = "...", content = "...")]`.
/// JSON output uses `{"VariantName": {...}}` format which is still
/// fully deserializable and forward-compatible via `#[serde(other)]`.
#[derive(Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EventKind {
    // -- Window Manager Events --
    WindowFocused {
        window_id: WindowId,
        app_id: AppId,
        workspace_id: WorkspaceId,
    },
    WindowMoved {
        window_id: WindowId,
        from_workspace: WorkspaceId,
        to_workspace: WorkspaceId,
    },
    WorkspaceSwitched {
        from: WorkspaceId,
        to: WorkspaceId,
        monitor_id: MonitorId,
    },
    LayoutChanged {
        workspace_id: WorkspaceId,
        layout_name: String,
    },

    // -- Profile Events --
    ProfileActivationBegun {
        target: ProfileId,
        trigger: String,
    },
    ProfileActivated {
        target: ProfileId,
        duration_ms: u32,
    },
    ProfileDeactivationBegun {
        target: ProfileId,
    },
    ProfileDeactivated {
        target: ProfileId,
        duration_ms: u32,
    },
    ProfileActivationFailed {
        target: ProfileId,
        reason: String,
    },
    DefaultProfileChanged {
        previous: ProfileId,
        current: ProfileId,
    },
    ContextChanged {
        changed_signals: Vec<String>,
    },

    // -- Clipboard Events --
    ClipboardChanged {
        entry_id: ClipboardEntryId,
        sensitivity: SensitivityClass,
        content_type: String,
        profile_id: ProfileId,
    },
    ClipboardEntryExpired {
        entry_id: ClipboardEntryId,
    },
    ClipboardScopeSealed {
        profile_id: ProfileId,
    },

    // -- Input Events --
    HotkeyFired {
        sequence: String,
        layer: String,
        action: String,
    },
    LayerChanged {
        from: String,
        to: String,
        trigger_app: Option<AppId>,
    },
    MacroTriggered {
        macro_id: String,
        expansion_preview: String,
    },

    // -- Secrets Events (authorized daemons only) --
    SecretResolved {
        secret_ref: String,
        ttl_remaining_s: u32,
    },
    SecretExpired {
        secret_ref: String,
    },
    SsoSessionExpired {
        profile_id: ProfileId,
        provider: String,
    },

    // -- Launcher Events --
    AppLaunched {
        app_id: AppId,
        launch_action: String,
        profile_id: ProfileId,
    },
    QuerySubmitted {
        query: String,
        result_count: u32,
        latency_ms: u32,
    },

    // -- System Events --
    DaemonStarted {
        daemon_id: DaemonId,
        version: String,
        capabilities: Vec<String>,
    },
    DaemonStopped {
        daemon_id: DaemonId,
        reason: String,
    },
    /// Key rotation: daemon-profile announces a new pubkey for a daemon.
    /// Daemons must re-read their keypair and reconnect within the grace period.
    KeyRotationPending {
        /// The daemon whose key is being rotated.
        daemon_name: String,
        /// New X25519 public key (exactly 32 bytes).
        new_pubkey: [u8; 32],
        /// Grace period in seconds before old key is revoked.
        grace_period_s: u32,
    },
    /// Key rotation completed: the registry has been updated.
    KeyRotationComplete {
        daemon_name: String,
    },
    ConfigReloaded {
        daemon_id: DaemonId,
        changed_keys: Vec<String>,
    },
    PolicyApplied {
        source: String,
        locked_keys: Vec<String>,
    },

    /// Audit event: a secret operation was attempted or completed.
    /// Emitted by daemon-secrets after each secret RPC for persistent audit logging.
    /// SECURITY: NEVER includes the secret value. Only metadata.
    SecretOperationAudit {
        /// The type of operation: "get", "set", "delete", "list"
        action: String,
        /// Trust profile the operation targeted
        profile: TrustProfileName,
        /// Secret key name (None for list operations)
        #[serde(default)]
        key: Option<String>,
        /// `DaemonId` of the requester
        requester: DaemonId,
        /// Server-verified name of the requester (if known)
        #[serde(default)]
        requester_name: Option<String>,
        /// Outcome: "success", "denied-locked", "denied-profile-not-active",
        /// "denied-acl", "rate-limited", "not-found", "denied-invalid-key", "failed", "empty"
        outcome: String,
    },

    // -- RPC: Secrets (all scoped by trust profile name) --
    SecretGet {
        profile: TrustProfileName,
        key: String,
    },
    SecretGetResponse {
        key: String,
        /// Secret value bytes. Plaintext over Noise-encrypted IPC transport
        /// (default). With `ipc-field-encryption` feature on daemon-secrets,
        /// this is additionally AES-256-GCM encrypted per-field.
        value: SensitiveBytes,
        /// Typed denial reason. `None` = success, `Some` = denied.
        #[serde(default)]
        denial: Option<SecretDenialReason>,
    },
    SecretSet {
        profile: TrustProfileName,
        key: String,
        /// Secret value bytes. Plaintext over Noise-encrypted IPC transport
        /// (default). With `ipc-field-encryption` feature on daemon-secrets,
        /// this is additionally AES-256-GCM encrypted per-field.
        value: SensitiveBytes,
    },
    SecretSetResponse {
        success: bool,
        /// Typed denial reason. `None` = success, `Some` = denied.
        #[serde(default)]
        denial: Option<SecretDenialReason>,
    },
    SecretDelete {
        profile: TrustProfileName,
        key: String,
    },
    SecretDeleteResponse {
        success: bool,
        /// Typed denial reason. `None` = success, `Some` = denied.
        #[serde(default)]
        denial: Option<SecretDenialReason>,
    },
    SecretList {
        profile: TrustProfileName,
    },
    SecretListResponse {
        keys: Vec<String>,
        /// Typed denial reason. `None` = success, `Some` = denied.
        #[serde(default)]
        denial: Option<SecretDenialReason>,
    },

    // -- RPC: Profile Activation --
    ProfileActivate {
        target: ProfileId,
        profile_name: TrustProfileName,
    },
    ProfileActivateResponse {
        success: bool,
    },
    ProfileDeactivate {
        target: ProfileId,
        profile_name: TrustProfileName,
    },
    ProfileDeactivateResponse {
        success: bool,
    },
    ProfileList,
    ProfileListResponse {
        profiles: Vec<ProfileSummary>,
    },
    SetDefaultProfile {
        profile_name: TrustProfileName,
    },
    SetDefaultProfileResponse {
        success: bool,
    },

    // -- RPC: Status --
    StatusRequest,
    StatusResponse {
        active_profiles: Vec<TrustProfileName>,
        default_profile: TrustProfileName,
        daemon_uptimes_ms: Vec<(DaemonId, u64)>,
        locked: bool,
    },

    // -- RPC: Unlock/Lock --
    UnlockRequest {
        /// Master password bytes (transmitted over UCred-authenticated Unix socket only).
        password: SensitiveBytes,
    },
    UnlockResponse {
        success: bool,
    },
    /// Typed rejection for unlock when preconditions are not met.
    /// Distinct from `UnlockResponse` { success: false } to avoid ambiguity
    /// between "wrong password" and "already unlocked".
    UnlockRejected {
        reason: UnlockRejectedReason,
    },
    LockRequest,
    LockResponse {
        success: bool,
    },

    // -- RPC: State Reconciliation --
    /// daemon-profile queries daemon-secrets for authoritative state.
    SecretsStateRequest,
    /// daemon-secrets returns authoritative lock + active profiles.
    SecretsStateResponse {
        locked: bool,
        active_profiles: Vec<TrustProfileName>,
    },

    // -- RPC: Window Manager --
    WmListWindows,
    WmListWindowsResponse {
        windows: Vec<Window>,
    },
    WmActivateWindow {
        window_id: String,
    },
    WmActivateWindowResponse {
        success: bool,
    },
    /// Trigger the window switcher overlay (forward direction).
    WmActivateOverlay,
    /// Trigger the window switcher overlay (backward direction).
    WmActivateOverlayBackward,
    /// Trigger the overlay in launcher mode (skip border-only, start in `FullOverlay`).
    WmActivateOverlayLauncher,
    WmOverlayShown,
    WmOverlayDismissed,

    // -- RPC: Launcher --
    LaunchQuery {
        query: String,
        max_results: u32,
        /// Trust profile context for scoped frecency and launch environment.
        #[serde(default)]
        profile: Option<TrustProfileName>,
    },
    LaunchQueryResponse {
        results: Vec<LaunchResult>,
    },
    LaunchExecute {
        entry_id: String,
        /// Trust profile context — injected as `SESAME_PROFILE` env var in spawned process.
        #[serde(default)]
        profile: Option<TrustProfileName>,
        /// Launch profile tags to compose for environment injection.
        #[serde(default)]
        tags: Vec<String>,
    },
    LaunchExecuteResponse {
        pid: u32,
        error: Option<String>,
    },

    // -- RPC: Clipboard --
    ClipboardHistory {
        profile: TrustProfileName,
        #[serde(default = "default_clipboard_limit")]
        limit: u32,
    },
    ClipboardHistoryResponse {
        entries: Vec<ClipboardEntry>,
    },
    ClipboardClear {
        profile: TrustProfileName,
    },
    ClipboardClearResponse {
        success: bool,
    },
    ClipboardGet {
        entry_id: ClipboardEntryId,
    },
    ClipboardGetResponse {
        content: Option<String>,
        content_type: Option<String>,
    },

    // -- RPC: Input --
    InputLayersList,
    InputLayersListResponse {
        layers: Vec<InputLayerInfo>,
    },
    InputStatus,
    InputStatusResponse {
        active_layer: String,
        grabbed_devices: Vec<String>,
        remapping_active: bool,
    },

    // -- RPC: Snippets --
    SnippetList {
        profile: TrustProfileName,
    },
    SnippetListResponse {
        snippets: Vec<SnippetInfo>,
    },
    SnippetExpand {
        profile: TrustProfileName,
        trigger: String,
    },
    SnippetExpandResponse {
        expanded: Option<String>,
    },
    SnippetAdd {
        profile: TrustProfileName,
        trigger: String,
        template: String,
    },
    SnippetAddResponse {
        success: bool,
    },

    // -- Agent Lifecycle --
    AgentConnected {
        agent_id: AgentId,
        agent_type: AgentType,
        attestations: Vec<AttestationType>,
    },
    AgentDisconnected {
        agent_id: AgentId,
        reason: String,
    },

    // -- Namespace Lifecycle --
    InstallationCreated {
        id: InstallationId,
        org: Option<OrganizationNamespace>,
        machine_binding_present: bool,
    },
    ProfileIdMigrated {
        name: TrustProfileName,
        old_id: ProfileId,
        new_id: ProfileId,
    },

    // -- Authorization Broker (v2: defined, not exercised) --
    AuthorizationRequired {
        request_id: Uuid,
        operation: String,
        missing_attestations: Vec<AttestationType>,
        expires_at: Timestamp,
    },
    AuthorizationGrant {
        request_id: Uuid,
        delegator: AgentId,
        scope: CapabilitySet,
        ttl_seconds: u32,
        point_of_use_filter: Option<OciReference>,
    },
    AuthorizationDenied {
        request_id: Uuid,
        reason: String,
    },
    AuthorizationTimeout {
        request_id: Uuid,
    },
    DelegationRevoked {
        delegation_id: Uuid,
        revoker: AgentId,
        reason: String,
    },
    HeartbeatRenewed {
        delegation_id: Uuid,
        renewal_source: AgentId,
        next_deadline: Timestamp,
    },

    // -- Federation (v2: defined, not exercised) --
    FederationSessionEstablished {
        session_id: Uuid,
        remote_installation: InstallationId,
    },
    FederationSessionTerminated {
        session_id: Uuid,
        reason: String,
    },

    // -- Device Posture --
    PostureEvaluated {
        secure_boot: Option<bool>,
        disk_encrypted: Option<bool>,
        screen_locked: Option<bool>,
        composite_score: f64,
    },

    // -- Bus-level errors (generated by the IPC server, not daemons) --

    /// The bus rejected the message. Sent back to the sender as a correlated
    /// response so the client gets an actionable error instead of a silent timeout.
    AccessDenied {
        reason: String,
    },

    // Forward compatibility: unknown events deserialize to this variant.
    #[serde(other)]
    Unknown,
}

/// Implement `fmt::Debug` for `EventKind` with automatic redaction of sensitive variants.
///
/// **Sensitive variants** (containing passwords, secret values) are listed in the first section
/// with explicit `[REDACTED; N bytes]` substitution. **All other variants** are listed in the
/// second section and get standard `debug_struct` output generated by the macro.
///
/// Adding a new non-sensitive variant: add one line to the second section.
/// Adding a new sensitive variant: add to the first section with explicit redaction.
/// The compiler enforces exhaustiveness — forgetting a variant is a compile error.
macro_rules! impl_event_debug {
    (
        sensitive {
            $( $sens_variant:ident { $($sens_field:ident $( => $redact:tt)?),* } ),* $(,)?
        }
        transparent {
            $( $name:ident $({ $($field:ident),* })? ),* $(,)?
        }
    ) => {
        impl fmt::Debug for EventKind {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $(
                        Self::$sens_variant { $($sens_field),* } => {
                            let mut s = f.debug_struct(stringify!($sens_variant));
                            $(
                                impl_event_debug!(@field s, $sens_field $( => $redact)?);
                            )*
                            s.finish()
                        }
                    )*
                    $(
                        Self::$name $({ $($field),* })? => {
                            let mut s = f.debug_struct(stringify!($name));
                            $( $(s.field(stringify!($field), $field);)* )?
                            s.finish()
                        }
                    )*
                }
            }
        }
    };
    // Field helper: redacted
    (@field $s:expr, $field:ident => REDACTED) => {
        $s.field(stringify!($field), &format_args!("[REDACTED; {} bytes]", $field.len()));
    };
    // Field helper: transparent (print as-is)
    (@field $s:expr, $field:ident) => {
        $s.field(stringify!($field), $field);
    };
}

impl_event_debug! {
    sensitive {
        SecretGetResponse { key, value => REDACTED, denial },
        SecretSet { profile, key, value => REDACTED },
        UnlockRequest { password => REDACTED },
    }
    transparent {
        WindowFocused { window_id, app_id, workspace_id },
        WindowMoved { window_id, from_workspace, to_workspace },
        WorkspaceSwitched { from, to, monitor_id },
        LayoutChanged { workspace_id, layout_name },
        ProfileActivationBegun { target, trigger },
        ProfileActivated { target, duration_ms },
        ProfileDeactivationBegun { target },
        ProfileDeactivated { target, duration_ms },
        ProfileActivationFailed { target, reason },
        DefaultProfileChanged { previous, current },
        ContextChanged { changed_signals },
        ClipboardChanged { entry_id, sensitivity, content_type, profile_id },
        ClipboardEntryExpired { entry_id },
        ClipboardScopeSealed { profile_id },
        HotkeyFired { sequence, layer, action },
        LayerChanged { from, to, trigger_app },
        MacroTriggered { macro_id, expansion_preview },
        SecretResolved { secret_ref, ttl_remaining_s },
        SecretExpired { secret_ref },
        SsoSessionExpired { profile_id, provider },
        AppLaunched { app_id, launch_action, profile_id },
        QuerySubmitted { query, result_count, latency_ms },
        DaemonStarted { daemon_id, version, capabilities },
        DaemonStopped { daemon_id, reason },
        KeyRotationPending { daemon_name, new_pubkey, grace_period_s },
        KeyRotationComplete { daemon_name },
        ConfigReloaded { daemon_id, changed_keys },
        PolicyApplied { source, locked_keys },
        SecretGet { profile, key },
        SecretSetResponse { success, denial },
        SecretDelete { profile, key },
        SecretDeleteResponse { success, denial },
        SecretList { profile },
        SecretListResponse { keys, denial },
        SecretOperationAudit { action, profile, key, requester, requester_name, outcome },
        ProfileActivate { target, profile_name },
        ProfileActivateResponse { success },
        ProfileDeactivate { target, profile_name },
        ProfileDeactivateResponse { success },
        ProfileList,
        ProfileListResponse { profiles },
        SetDefaultProfile { profile_name },
        SetDefaultProfileResponse { success },
        StatusRequest,
        StatusResponse { active_profiles, default_profile, daemon_uptimes_ms, locked },
        UnlockResponse { success },
        UnlockRejected { reason },
        LockRequest,
        LockResponse { success },
        SecretsStateRequest,
        SecretsStateResponse { locked, active_profiles },
        WmListWindows,
        WmListWindowsResponse { windows },
        WmActivateWindow { window_id },
        WmActivateWindowResponse { success },
        WmActivateOverlay,
        WmActivateOverlayBackward,
        WmActivateOverlayLauncher,
        WmOverlayShown,
        WmOverlayDismissed,
        LaunchQuery { query, max_results, profile },
        LaunchQueryResponse { results },
        LaunchExecute { entry_id, profile, tags },
        LaunchExecuteResponse { pid, error },
        ClipboardHistory { profile, limit },
        ClipboardHistoryResponse { entries },
        ClipboardClear { profile },
        ClipboardClearResponse { success },
        ClipboardGet { entry_id },
        ClipboardGetResponse { content, content_type },
        InputLayersList,
        InputLayersListResponse { layers },
        InputStatus,
        InputStatusResponse { active_layer, grabbed_devices, remapping_active },
        SnippetList { profile },
        SnippetListResponse { snippets },
        SnippetExpand { profile, trigger },
        SnippetExpandResponse { expanded },
        SnippetAdd { profile, trigger, template },
        SnippetAddResponse { success },
        AgentConnected { agent_id, agent_type, attestations },
        AgentDisconnected { agent_id, reason },
        InstallationCreated { id, org, machine_binding_present },
        ProfileIdMigrated { name, old_id, new_id },
        AuthorizationRequired { request_id, operation, missing_attestations, expires_at },
        AuthorizationGrant { request_id, delegator, scope, ttl_seconds, point_of_use_filter },
        AuthorizationDenied { request_id, reason },
        AuthorizationTimeout { request_id },
        DelegationRevoked { delegation_id, revoker, reason },
        HeartbeatRenewed { delegation_id, renewal_source, next_deadline },
        FederationSessionEstablished { session_id, remote_installation },
        FederationSessionTerminated { session_id, reason },
        PostureEvaluated { secure_boot, disk_encrypted, screen_locked, composite_score },
        AccessDenied { reason },
        Unknown,
    }
}

// ============================================================================
// RPC Support Types
// ============================================================================

/// Summary of a profile for list responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSummary {
    pub id: ProfileId,
    pub name: TrustProfileName,
    /// Whether this profile's vault is currently open and serving secrets.
    pub is_active: bool,
    /// Whether this profile is the default for new unscoped launches.
    pub is_default: bool,
}

/// A single launcher result entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchResult {
    pub entry_id: String,
    pub name: String,
    pub icon: Option<String>,
    pub score: f64,
}

/// A clipboard history entry summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardEntry {
    pub entry_id: ClipboardEntryId,
    pub content_type: String,
    pub sensitivity: SensitivityClass,
    pub profile_id: ProfileId,
    /// Truncated preview (first 80 chars).
    pub preview: String,
    pub timestamp_ms: u64,
}

/// Input layer information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputLayerInfo {
    pub name: String,
    pub is_active: bool,
    pub remap_count: u32,
}

/// Snippet information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnippetInfo {
    pub trigger: String,
    pub template_preview: String,
}

fn default_clipboard_limit() -> u32 {
    20
}

// ============================================================================
// Error Hierarchy
// ============================================================================

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("IPC error: {0}")]
    Ipc(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("profile error: {0}")]
    Profile(String),

    #[error("secrets error: {0}")]
    Secrets(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("platform error: {0}")]
    Platform(String),

    #[error("extension error: {0}")]
    Extension(String),

    #[error("policy locked: {key} is controlled by {policy_source}")]
    PolicyLocked { key: String, policy_source: String },

    #[error("capability denied: {capability} not declared in extension manifest")]
    CapabilityDenied { capability: String },

    #[error("profile isolation: access to {resource} denied by isolation contract")]
    IsolationDenied { resource: String },

    #[error("validation error: {0}")]
    Validation(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

// ============================================================================
// Secret Key Validation
// ============================================================================

/// Validate a secret key name.
///
/// Rejects keys that are empty, contain path traversal patterns, path
/// separators, or exceed 256 characters. Applied at both the CLI trust
/// boundary and in daemon-secrets as defense-in-depth.
///
/// # Errors
///
/// Returns `Error::Validation` if the key is empty, too long, contains
/// path traversal (`..`), or path separators (`/`, `\`).
pub fn validate_secret_key(key: &str) -> Result<()> {
    if key.is_empty() {
        return Err(Error::Validation("secret key must not be empty".into()));
    }
    if key.len() > 256 {
        return Err(Error::Validation(format!(
            "secret key exceeds 256 characters (got {})", key.len()
        )));
    }
    if key.contains("..") {
        return Err(Error::Validation(
            "secret key must not contain '..' (path traversal)".into(),
        ));
    }
    if key.contains('/') || key.contains('\\') {
        return Err(Error::Validation(
            "secret key must not contain path separators ('/' or '\\')".into(),
        ));
    }
    if key.contains('\0') {
        return Err(Error::Validation(
            "secret key must not contain null bytes".into(),
        ));
    }
    Ok(())
}

// ============================================================================
// TrustProfileName — validated, path-safe trust profile identifier
// ============================================================================

/// A validated, path-safe trust profile identifier.
///
/// Invariants (enforced at construction, impossible to violate):
/// - Non-empty, max 64 bytes
/// - ASCII alphanumeric, hyphens, underscores only: `[a-zA-Z0-9][a-zA-Z0-9_-]*`
/// - Not `.` or `..` (path traversal)
/// - No whitespace, no path separators, no null bytes
///
/// Maps 1:1 to a `SQLCipher` vault file: `vaults/{name}.db`
/// Maps 1:1 to a BLAKE3 KDF context: `"pds v2 vault-key {name}"`
/// Maps 1:1 to a frecency DB: `launcher/{name}.frecency.db`
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct TrustProfileName(String);

impl TrustProfileName {
    /// Validate a trust profile name. Returns a human-readable error on failure.
    fn validate(name: &str) -> std::result::Result<(), String> {
        if name.is_empty() {
            return Err("trust profile name must not be empty".into());
        }
        if name.len() > 64 {
            return Err(format!(
                "trust profile name exceeds 64 bytes (got {}): '{name}'",
                name.len()
            ));
        }
        if name == "." || name == ".." {
            return Err(format!("trust profile name '{name}' is a path traversal component"));
        }
        if !name.as_bytes()[0].is_ascii_alphanumeric() {
            return Err(format!(
                "trust profile name must start with alphanumeric, got '{}'",
                name.chars().next().unwrap_or('?')
            ));
        }
        for (i, b) in name.bytes().enumerate() {
            if !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
                return Err(format!(
                    "trust profile name contains invalid byte 0x{b:02x} at position {i}: \
                     must contain only [a-zA-Z0-9_-]"
                ));
            }
        }
        Ok(())
    }
}

impl TryFrom<String> for TrustProfileName {
    type Error = Error;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        Self::validate(&value).map_err(Error::Validation)?;
        Ok(Self(value))
    }
}

impl TryFrom<&str> for TrustProfileName {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        Self::validate(value).map_err(Error::Validation)?;
        Ok(Self(value.to_owned()))
    }
}

impl<'de> Deserialize<'de> for TrustProfileName {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::validate(&s).map_err(serde::de::Error::custom)?;
        Ok(Self(s))
    }
}

impl Deref for TrustProfileName {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for TrustProfileName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TrustProfileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<TrustProfileName> for String {
    fn from(name: TrustProfileName) -> String {
        name.0
    }
}

// ============================================================================
// LaunchProfile — trust profile composition at launch time
// ============================================================================

/// Specifies which trust profiles to stack when launching an application.
///
/// Trust profiles compose: launching with `[corporate-aws, local, azure-client]`
/// means the process gets secrets from all three, with precedence determined
/// by list ordering (last = highest priority).
///
/// Not fully implemented yet — currently used as single `TrustProfileName`
/// via `LaunchProfile::single()`. The struct exists so trust profile stacking
/// is an additive change, not a rewrite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchProfile {
    /// Trust profiles to compose. Ordered by precedence: last = highest priority.
    pub trust_profiles: Vec<TrustProfileName>,
    /// How to handle secret key conflicts across stacked profiles.
    #[serde(default)]
    pub conflict_policy: ConflictPolicy,
}

impl LaunchProfile {
    /// Create a launch profile with a single trust profile (current usage).
    #[must_use]
    pub fn single(name: TrustProfileName) -> Self {
        Self {
            trust_profiles: vec![name],
            conflict_policy: ConflictPolicy::default(),
        }
    }
}

/// How to resolve secret key conflicts when multiple trust profiles are stacked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConflictPolicy {
    /// Abort with actionable error, no secret leakage.
    #[default]
    Strict,
    /// Log warning, higher-precedence (later in list) wins.
    Warn,
    /// Silently use higher-precedence value.
    Last,
}

// ============================================================================
// Window and Geometry Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Window {
    pub id: WindowId,
    pub app_id: AppId,
    pub title: String,
    pub workspace_id: WorkspaceId,
    pub monitor_id: MonitorId,
    pub geometry: Geometry,
    pub is_focused: bool,
    pub is_minimized: bool,
    pub is_fullscreen: bool,
    pub profile_id: ProfileId,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Geometry {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Padding {
    pub top: u32,
    pub right: u32,
    pub bottom: u32,
    pub left: u32,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // -- AppId tests (v1 behavioral spec) --

    #[test]
    fn app_id_last_segment_reverse_dns() {
        let id = AppId::new("com.mitchellh.ghostty");
        assert_eq!(id.last_segment(), "ghostty");
    }

    #[test]
    fn app_id_last_segment_simple() {
        let id = AppId::new("firefox");
        assert_eq!(id.last_segment(), "firefox");
    }

    #[test]
    fn app_id_matches_full() {
        let id = AppId::new("com.mitchellh.ghostty");
        assert!(id.matches("com.mitchellh.ghostty"));
    }

    #[test]
    fn app_id_matches_last_segment() {
        let id = AppId::new("com.mitchellh.ghostty");
        assert!(id.matches("ghostty"));
    }

    #[test]
    fn app_id_matches_case_insensitive() {
        let id = AppId::new("com.mitchellh.Ghostty");
        assert!(id.matches("ghostty"));
    }

    #[test]
    fn app_id_matches_other_reverse_dns() {
        let id = AppId::new("com.mitchellh.ghostty");
        assert!(id.matches("org.example.ghostty"));
    }

    #[test]
    fn app_id_no_match() {
        let id = AppId::new("com.mitchellh.ghostty");
        assert!(!id.matches("firefox"));
    }

    // -- SecretRef debug redaction --

    #[test]
    fn secret_ref_debug_does_not_leak_values() {
        let r = SecretRef::Keyring {
            secret: "work/token".into(),
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("keyring:work/token"));
        // The ref path is safe to log; the resolved VALUE never appears in this type.
    }

    // -- Sensitivity ordering --

    #[test]
    fn sensitivity_ordering() {
        assert!(SensitivityClass::Public < SensitivityClass::Confidential);
        assert!(SensitivityClass::Confidential < SensitivityClass::Secret);
        assert!(SensitivityClass::Secret < SensitivityClass::TopSecret);
    }

    // -- SecurityLevel ordering --

    #[test]
    fn security_level_ordering() {
        assert!(SecurityLevel::Open < SecurityLevel::Internal);
        assert!(SecurityLevel::Internal < SecurityLevel::ProfileScoped);
        assert!(SecurityLevel::ProfileScoped < SecurityLevel::SecretsOnly);
    }

    // -- Serialization round-trip property tests --

    proptest! {
        #[test]
        fn profile_id_roundtrip_postcard(n in any::<u128>()) {
            let id = ProfileId::from_uuid(Uuid::from_u128(n));
            let bytes = postcard::to_allocvec(&id).unwrap();
            let decoded: ProfileId = postcard::from_bytes(&bytes).unwrap();
            prop_assert_eq!(id, decoded);
        }

        #[test]
        fn window_id_roundtrip_json(n in any::<u128>()) {
            let id = WindowId::from_uuid(Uuid::from_u128(n));
            let json = serde_json::to_string(&id).unwrap();
            let decoded: WindowId = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(id, decoded);
        }

        #[test]
        fn app_id_roundtrip_json(s in "[a-z]{1,5}(\\.[a-z]{1,5}){0,3}") {
            let id = AppId::new(s);
            let json = serde_json::to_string(&id).unwrap();
            let decoded: AppId = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(id, decoded);
        }

        #[test]
        fn sensitivity_roundtrip_json(idx in 0u8..4) {
            let class = match idx {
                0 => SensitivityClass::Public,
                1 => SensitivityClass::Confidential,
                2 => SensitivityClass::Secret,
                _ => SensitivityClass::TopSecret,
            };
            let json = serde_json::to_string(&class).unwrap();
            let decoded: SensitivityClass = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(class, decoded);
        }

        #[test]
        fn trust_profile_name_roundtrip_postcard_prop(s in "[a-zA-Z][a-zA-Z0-9_-]{0,63}") {
            let name = TrustProfileName::try_from(s).unwrap();
            let bytes = postcard::to_allocvec(&name).unwrap();
            let decoded: TrustProfileName = postcard::from_bytes(&bytes).unwrap();
            prop_assert_eq!(name, decoded);
        }

        #[test]
        fn geometry_roundtrip_postcard(x in any::<i32>(), y in any::<i32>(), w in any::<u32>(), h in any::<u32>()) {
            let geo = Geometry { x, y, width: w, height: h };
            let bytes = postcard::to_allocvec(&geo).unwrap();
            let decoded: Geometry = postcard::from_bytes(&bytes).unwrap();
            prop_assert_eq!(geo, decoded);
        }
    }

    // -- TrustProfileName validation --

    #[test]
    fn trust_profile_name_valid() {
        for name in ["default", "work", "corporate-aws", "my_profile", "a", "A1-b_2"] {
            assert!(
                TrustProfileName::try_from(name).is_ok(),
                "expected '{name}' to be valid"
            );
        }
    }

    #[test]
    fn trust_profile_name_rejects_empty() {
        assert!(TrustProfileName::try_from("").is_err());
    }

    #[test]
    fn trust_profile_name_rejects_path_traversal() {
        assert!(TrustProfileName::try_from(".").is_err());
        assert!(TrustProfileName::try_from("..").is_err());
        assert!(TrustProfileName::try_from("../../etc/passwd").is_err());
    }

    #[test]
    fn trust_profile_name_rejects_slashes() {
        assert!(TrustProfileName::try_from("foo/bar").is_err());
        assert!(TrustProfileName::try_from("foo\\bar").is_err());
    }

    #[test]
    fn trust_profile_name_rejects_spaces_and_special() {
        assert!(TrustProfileName::try_from("foo bar").is_err());
        assert!(TrustProfileName::try_from("foo\0bar").is_err());
        assert!(TrustProfileName::try_from("-leading").is_err());
        assert!(TrustProfileName::try_from("_leading").is_err());
    }

    #[test]
    fn trust_profile_name_rejects_over_64() {
        let long = "a".repeat(65);
        assert!(TrustProfileName::try_from(long).is_err());
    }

    #[test]
    fn trust_profile_name_roundtrip_json() {
        let name = TrustProfileName::try_from("corporate-aws").unwrap();
        let json = serde_json::to_string(&name).unwrap();
        assert_eq!(json, "\"corporate-aws\"");
        let decoded: TrustProfileName = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, name);
    }

    #[test]
    fn trust_profile_name_roundtrip_postcard() {
        let name = TrustProfileName::try_from("my-profile").unwrap();
        let bytes = postcard::to_allocvec(&name).unwrap();
        let decoded: TrustProfileName = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, name);
    }

    #[test]
    fn trust_profile_name_json_rejects_invalid() {
        let result: std::result::Result<TrustProfileName, _> = serde_json::from_str("\"../../etc\"");
        assert!(result.is_err());
    }

    #[test]
    fn trust_profile_name_deref_to_str() {
        let name = TrustProfileName::try_from("work").unwrap();
        let s: &str = &name;
        assert_eq!(s, "work");
    }

    #[test]
    fn trust_profile_name_display() {
        let name = TrustProfileName::try_from("work").unwrap();
        assert_eq!(format!("{name}"), "work");
    }

    // -- validate_secret_key --

    #[test]
    fn secret_key_valid() {
        assert!(validate_secret_key("api-key").is_ok());
        assert!(validate_secret_key("a").is_ok());
        assert!(validate_secret_key(&"x".repeat(256)).is_ok());
    }

    #[test]
    fn secret_key_rejects_empty() {
        assert!(validate_secret_key("").is_err());
    }

    #[test]
    fn secret_key_rejects_too_long() {
        assert!(validate_secret_key(&"x".repeat(257)).is_err());
    }

    #[test]
    fn secret_key_rejects_path_traversal() {
        assert!(validate_secret_key("..").is_err());
        assert!(validate_secret_key("foo/../bar").is_err());
    }

    #[test]
    fn secret_key_rejects_separators() {
        assert!(validate_secret_key("foo/bar").is_err());
        assert!(validate_secret_key("foo\\bar").is_err());
    }

    #[test]
    fn secret_key_rejects_null_bytes() {
        assert!(validate_secret_key("foo\0bar").is_err());
        assert!(validate_secret_key("\0").is_err());
    }

    // -- ConflictPolicy --

    #[test]
    fn conflict_policy_default_is_strict() {
        assert_eq!(ConflictPolicy::default(), ConflictPolicy::Strict);
    }

    #[test]
    fn conflict_policy_roundtrip_json() {
        for policy in [ConflictPolicy::Strict, ConflictPolicy::Warn, ConflictPolicy::Last] {
            let json = serde_json::to_string(&policy).unwrap();
            let decoded: ConflictPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, policy);
        }
    }

    // -- LaunchProfile --

    #[test]
    fn launch_profile_single() {
        let name = TrustProfileName::try_from("work").unwrap();
        let lp = LaunchProfile::single(name.clone());
        assert_eq!(lp.trust_profiles.len(), 1);
        assert_eq!(lp.trust_profiles[0], name);
        assert_eq!(lp.conflict_policy, ConflictPolicy::Strict);
    }

    // -- SensitiveBytes --

    #[test]
    fn sensitive_bytes_debug_redacts() {
        let sb = SensitiveBytes::new(b"super_secret".to_vec());
        let debug = format!("{sb:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("super_secret"));
        assert!(debug.contains("12 bytes"));
    }

    #[test]
    fn sensitive_bytes_accessors() {
        let sb = SensitiveBytes::new(vec![1, 2, 3]);
        assert_eq!(sb.as_bytes(), &[1, 2, 3]);
        assert_eq!(sb.len(), 3);
        assert!(!sb.is_empty());

        let empty = SensitiveBytes::new(vec![]);
        assert!(empty.is_empty());
    }

    #[test]
    fn sensitive_bytes_from_vec() {
        let sb: SensitiveBytes = vec![0xAA, 0xBB].into();
        assert_eq!(sb.as_bytes(), &[0xAA, 0xBB]);
    }

    // -- EventKind Debug redaction --

    #[test]
    fn event_kind_debug_redacts_secrets() {
        let unlock = EventKind::UnlockRequest { password: SensitiveBytes::new(b"hunter2".to_vec()) };
        let debug = format!("{unlock:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("hunter2"));

        let get_resp = EventKind::SecretGetResponse { key: "api-key".into(), value: SensitiveBytes::new(b"secret123".to_vec()), denial: None };
        let debug = format!("{get_resp:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("secret123"));
        assert!(debug.contains("api-key")); // key name is NOT redacted

        let set = EventKind::SecretSet {
            profile: TrustProfileName::try_from("work").unwrap(),
            key: "db-pass".into(),
            value: SensitiveBytes::new(b"p@ssw0rd".to_vec()),
        };
        let debug = format!("{set:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("p@ssw0rd"));
        assert!(debug.contains("db-pass"));
        assert!(debug.contains("work"));
    }

    // -- EventKind forward compatibility --

    #[test]
    fn event_kind_unknown_variant_deserializes() {
        // Externally-tagged: unknown variant name maps to Unknown via #[serde(other)]
        let json = r#""FutureEventV99""#;
        let event: EventKind = serde_json::from_str(json).unwrap();
        assert!(matches!(event, EventKind::Unknown));
    }

    #[test]
    fn event_kind_known_variant_roundtrips() {
        let event = EventKind::DaemonStarted {
            daemon_id: DaemonId::from_uuid(Uuid::from_u128(42)),
            version: "0.1.0".into(),
            capabilities: vec!["wm".into(), "tiling".into()],
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: EventKind = serde_json::from_str(&json).unwrap();
        // Verify it round-trips to the same variant (not Unknown)
        assert!(matches!(decoded, EventKind::DaemonStarted { .. }));
    }

    // -- AgentId --

    #[test]
    fn agent_id_display_prefix() {
        let id = AgentId::from_uuid(Uuid::from_u128(1));
        let s = format!("{id}");
        assert!(s.starts_with("agent-"), "AgentId display should have 'agent-' prefix, got: {s}");
    }

    proptest! {
        #[test]
        fn agent_id_roundtrip_postcard(n in any::<u128>()) {
            let id = AgentId::from_uuid(Uuid::from_u128(n));
            let bytes = postcard::to_allocvec(&id).unwrap();
            let decoded: AgentId = postcard::from_bytes(&bytes).unwrap();
            prop_assert_eq!(id, decoded);
        }

        #[test]
        fn agent_id_roundtrip_json(n in any::<u128>()) {
            let id = AgentId::from_uuid(Uuid::from_u128(n));
            let json = serde_json::to_string(&id).unwrap();
            let decoded: AgentId = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(id, decoded);
        }
    }

    // -- CryptoConfig enums --

    #[test]
    fn crypto_config_default_is_leading_edge() {
        let cfg = CryptoConfig::default();
        assert_eq!(cfg.kdf, KdfAlgorithm::Argon2id);
        assert_eq!(cfg.hkdf, HkdfAlgorithm::Blake3);
        assert_eq!(cfg.noise_cipher, NoiseCipher::ChaChaPoly);
        assert_eq!(cfg.noise_hash, NoiseHash::Blake2s);
        assert_eq!(cfg.audit_hash, AuditHash::Blake3);
        assert_eq!(cfg.minimum_peer_profile, CryptoProfile::LeadingEdge);
    }

    #[test]
    fn kdf_algorithm_roundtrip_json() {
        for alg in [KdfAlgorithm::Argon2id, KdfAlgorithm::Pbkdf2Sha256] {
            let json = serde_json::to_string(&alg).unwrap();
            let decoded: KdfAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(alg, decoded);
        }
    }

    #[test]
    fn hkdf_algorithm_roundtrip_json() {
        for alg in [HkdfAlgorithm::Blake3, HkdfAlgorithm::HkdfSha256] {
            let json = serde_json::to_string(&alg).unwrap();
            let decoded: HkdfAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(alg, decoded);
        }
    }

    #[test]
    fn noise_cipher_roundtrip_json() {
        for c in [NoiseCipher::ChaChaPoly, NoiseCipher::AesGcm] {
            let json = serde_json::to_string(&c).unwrap();
            let decoded: NoiseCipher = serde_json::from_str(&json).unwrap();
            assert_eq!(c, decoded);
        }
    }

    #[test]
    fn noise_hash_roundtrip_json() {
        for h in [NoiseHash::Blake2s, NoiseHash::Sha256] {
            let json = serde_json::to_string(&h).unwrap();
            let decoded: NoiseHash = serde_json::from_str(&json).unwrap();
            assert_eq!(h, decoded);
        }
    }

    #[test]
    fn audit_hash_roundtrip_json() {
        for h in [AuditHash::Blake3, AuditHash::Sha256] {
            let json = serde_json::to_string(&h).unwrap();
            let decoded: AuditHash = serde_json::from_str(&json).unwrap();
            assert_eq!(h, decoded);
        }
    }

    #[test]
    fn crypto_profile_roundtrip_json() {
        for p in [CryptoProfile::LeadingEdge, CryptoProfile::GovernanceCompatible, CryptoProfile::Custom] {
            let json = serde_json::to_string(&p).unwrap();
            let decoded: CryptoProfile = serde_json::from_str(&json).unwrap();
            assert_eq!(p, decoded);
        }
    }

    #[test]
    fn crypto_config_roundtrip_postcard() {
        let cfg = CryptoConfig::default();
        let bytes = postcard::to_allocvec(&cfg).unwrap();
        let decoded: CryptoConfig = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(cfg, decoded);
    }

    #[test]
    fn kdf_algorithm_kebab_case_serialization() {
        let json = serde_json::to_string(&KdfAlgorithm::Pbkdf2Sha256).unwrap();
        assert_eq!(json, "\"pbkdf2-sha256\"");
        let json = serde_json::to_string(&KdfAlgorithm::Argon2id).unwrap();
        assert_eq!(json, "\"argon2id\"");
    }

    // -- InstallationId --

    #[test]
    fn installation_id_roundtrip_json() {
        let install = InstallationId {
            id: Uuid::from_u128(42),
            org_ns: Some(OrganizationNamespace {
                domain: "braincraft.io".into(),
                namespace: Uuid::from_u128(99),
            }),
            namespace: Uuid::from_u128(123),
            machine_binding: Some(MachineBinding {
                binding_hash: [0xAB; 32],
                binding_type: MachineBindingType::MachineId,
            }),
        };
        let json = serde_json::to_string(&install).unwrap();
        let decoded: InstallationId = serde_json::from_str(&json).unwrap();
        assert_eq!(install, decoded);
    }

    #[test]
    fn installation_id_roundtrip_postcard() {
        let install = InstallationId {
            id: Uuid::from_u128(1),
            org_ns: None,
            namespace: Uuid::from_u128(2),
            machine_binding: None,
        };
        let bytes = postcard::to_allocvec(&install).unwrap();
        let decoded: InstallationId = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(install, decoded);
    }

    #[test]
    fn installation_namespace_determinism() {
        // Same org domain produces same namespace UUID via uuid5.
        let ns1 = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"braincraft.io");
        let ns2 = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"braincraft.io");
        assert_eq!(ns1, ns2);

        // Different domains produce different namespaces.
        let ns3 = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"example.com");
        assert_ne!(ns1, ns3);
    }

    // -- OciReference --

    #[test]
    fn oci_reference_parse_full() {
        let r = OciReference::parse("registry.example.com/principal/scope:1.0.0@sha256:abc123").unwrap();
        assert_eq!(r.registry, "registry.example.com");
        assert_eq!(r.principal, "principal");
        assert_eq!(r.scope, "scope");
        assert_eq!(r.revision, "1.0.0");
        assert_eq!(r.provenance.as_deref(), Some("sha256:abc123"));
    }

    #[test]
    fn oci_reference_parse_without_provenance() {
        let r = OciReference::parse("registry.example.com/org/ext:2.0").unwrap();
        assert_eq!(r.registry, "registry.example.com");
        assert_eq!(r.principal, "org");
        assert_eq!(r.scope, "ext");
        assert_eq!(r.revision, "2.0");
        assert!(r.provenance.is_none());
    }

    #[test]
    fn oci_reference_display_roundtrip() {
        let r = OciReference::parse("reg.io/org/ext:1.0@sha256:def").unwrap();
        let s = r.to_string();
        let r2 = OciReference::parse(&s).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn oci_reference_display_roundtrip_no_provenance() {
        let r = OciReference::parse("reg.io/org/ext:1.0").unwrap();
        let s = r.to_string();
        let r2 = OciReference::parse(&s).unwrap();
        assert_eq!(r, r2);
    }

    #[test]
    fn oci_reference_rejects_empty() {
        assert!(OciReference::parse("").is_err());
    }

    #[test]
    fn oci_reference_rejects_missing_revision() {
        assert!(OciReference::parse("reg.io/org/ext").is_err());
    }

    #[test]
    fn oci_reference_rejects_too_few_segments() {
        assert!(OciReference::parse("reg.io/ext:1.0").is_err());
    }

    #[test]
    fn oci_reference_roundtrip_json() {
        let r = OciReference::parse("reg.io/org/ext:1.0@sha256:abc").unwrap();
        let json = serde_json::to_string(&r).unwrap();
        let decoded: OciReference = serde_json::from_str(&json).unwrap();
        assert_eq!(r, decoded);
    }

    // -- CapabilitySet lattice --

    #[test]
    fn capability_set_empty_is_subset_of_all() {
        assert!(CapabilitySet::empty().is_subset(&CapabilitySet::all()));
    }

    #[test]
    fn capability_set_all_is_superset_of_empty() {
        assert!(CapabilitySet::all().is_superset(&CapabilitySet::empty()));
    }

    #[test]
    fn capability_set_union_identity() {
        let a = CapabilitySet::all();
        let empty = CapabilitySet::empty();
        assert_eq!(a.union(&empty), a);
        assert_eq!(empty.union(&a), a);
    }

    #[test]
    fn capability_set_intersection_identity() {
        let a = CapabilitySet::all();
        let empty = CapabilitySet::empty();
        assert_eq!(a.intersection(&empty), empty);
        assert_eq!(empty.intersection(&a), empty);
    }

    #[test]
    fn capability_set_intersection_self_is_self() {
        let a = CapabilitySet::all();
        assert_eq!(a.intersection(&a), a);
    }

    #[test]
    fn capability_set_roundtrip_json() {
        let cs = CapabilitySet::all();
        let json = serde_json::to_string(&cs).unwrap();
        let decoded: CapabilitySet = serde_json::from_str(&json).unwrap();
        assert_eq!(cs, decoded);
    }

    #[test]
    fn capability_delegate_roundtrip_json() {
        let cap = Capability::Delegate {
            max_depth: 3,
            scope: Box::new(CapabilitySet::empty()),
        };
        let json = serde_json::to_string(&cap).unwrap();
        let decoded: Capability = serde_json::from_str(&json).unwrap();
        assert_eq!(cap, decoded);
    }

    // -- DelegationGrant --

    #[test]
    fn delegation_grant_roundtrip_json() {
        let grant = DelegationGrant {
            delegator: AgentId::from_uuid(Uuid::from_u128(1)),
            scope: CapabilitySet::empty(),
            initial_ttl: Duration::from_secs(3600),
            heartbeat_interval: Duration::from_secs(60),
            nonce: [0xAA; 16],
            point_of_use_filter: None,
            signature: vec![0xBB; 64],
        };
        let json = serde_json::to_string(&grant).unwrap();
        let decoded: DelegationGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(grant, decoded);
    }

    // -- Attestation --

    #[test]
    fn attestation_ucred_roundtrip_json() {
        let att = Attestation::UCred { pid: 1234, uid: 1000, gid: 1000 };
        let json = serde_json::to_string(&att).unwrap();
        let decoded: Attestation = serde_json::from_str(&json).unwrap();
        assert_eq!(att, decoded);
    }

    #[test]
    fn attestation_delegation_roundtrip_json() {
        let att = Attestation::Delegation {
            delegator: AgentId::from_uuid(Uuid::from_u128(5)),
            scope: CapabilitySet::empty(),
            chain_depth: 2,
        };
        let json = serde_json::to_string(&att).unwrap();
        let decoded: Attestation = serde_json::from_str(&json).unwrap();
        assert_eq!(att, decoded);
    }

    #[test]
    fn attestation_type_roundtrip_json() {
        for at in [
            AttestationType::UCred,
            AttestationType::NoiseIK,
            AttestationType::MasterPassword,
            AttestationType::Delegation,
            AttestationType::DeviceAttestation,
        ] {
            let json = serde_json::to_string(&at).unwrap();
            let decoded: AttestationType = serde_json::from_str(&json).unwrap();
            assert_eq!(at, decoded);
        }
    }

    // -- AgentType / AgentIdentity --

    #[test]
    fn agent_type_roundtrip_json() {
        let at = AgentType::AI { model_family: "claude".into() };
        let json = serde_json::to_string(&at).unwrap();
        let decoded: AgentType = serde_json::from_str(&json).unwrap();
        assert_eq!(at, decoded);
    }

    #[test]
    fn agent_identity_roundtrip_json() {
        let identity = AgentIdentity {
            id: AgentId::from_uuid(Uuid::from_u128(10)),
            agent_type: AgentType::Human,
            local_id: LocalAgentId::UnixUid(1000),
            installation: InstallationId {
                id: Uuid::from_u128(1),
                org_ns: None,
                namespace: Uuid::from_u128(2),
                machine_binding: None,
            },
            attestations: vec![Attestation::UCred { pid: 100, uid: 1000, gid: 1000 }],
            session_scope: CapabilitySet::all(),
            delegation_chain: vec![],
        };
        let json = serde_json::to_string(&identity).unwrap();
        let decoded: AgentIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(identity, decoded);
    }

    // -- TrustLevel ordering --

    #[test]
    fn trust_level_ordering() {
        assert!(TrustLevel::None < TrustLevel::Low);
        assert!(TrustLevel::Low < TrustLevel::Medium);
        assert!(TrustLevel::Medium < TrustLevel::High);
        assert!(TrustLevel::High < TrustLevel::Hardware);
    }

    // -- NetworkTrust ordering --

    #[test]
    fn network_trust_ordering() {
        assert!(NetworkTrust::Local < NetworkTrust::Encrypted);
        assert!(NetworkTrust::Encrypted < NetworkTrust::Onion);
        assert!(NetworkTrust::Onion < NetworkTrust::PublicInternet);
    }

    // -- TrustVector --

    #[test]
    fn trust_vector_roundtrip_json() {
        let tv = TrustVector {
            authn_strength: TrustLevel::High,
            authz_freshness: Duration::from_secs(30),
            delegation_depth: 0,
            device_posture: 0.95,
            network_exposure: NetworkTrust::Local,
            agent_type: AgentType::Human,
        };
        let json = serde_json::to_string(&tv).unwrap();
        let decoded: TrustVector = serde_json::from_str(&json).unwrap();
        assert_eq!(tv, decoded);
    }

    // -- ProfileRef --

    #[test]
    fn profile_ref_roundtrip_json() {
        let pr = ProfileRef {
            name: TrustProfileName::try_from("work").unwrap(),
            id: ProfileId::from_uuid(Uuid::from_u128(77)),
            installation: InstallationId {
                id: Uuid::from_u128(1),
                org_ns: None,
                namespace: Uuid::from_u128(2),
                machine_binding: None,
            },
        };
        let json = serde_json::to_string(&pr).unwrap();
        let decoded: ProfileRef = serde_json::from_str(&json).unwrap();
        assert_eq!(pr, decoded);
    }

    // -- CapabilitySet lattice property tests --

    #[test]
    fn capability_set_lattice_properties() {
        let caps_a = CapabilitySet {
            capabilities: [
                Capability::SecretRead { key_pattern: None },
                Capability::SecretWrite { key_pattern: None },
                Capability::ProfileActivate,
            ].into_iter().collect(),
        };
        let caps_b = CapabilitySet {
            capabilities: [
                Capability::SecretWrite { key_pattern: None },
                Capability::Admin,
                Capability::StatusRead,
            ].into_iter().collect(),
        };
        let caps_c = CapabilitySet {
            capabilities: [
                Capability::SecretRead { key_pattern: None },
                Capability::Admin,
                Capability::Lock,
            ].into_iter().collect(),
        };

        // Commutativity of intersection
        assert_eq!(caps_a.intersection(&caps_b), caps_b.intersection(&caps_a));

        // Commutativity of union
        assert_eq!(caps_a.union(&caps_b), caps_b.union(&caps_a));

        // Associativity of intersection
        assert_eq!(
            caps_a.intersection(&caps_b).intersection(&caps_c),
            caps_a.intersection(&caps_b.intersection(&caps_c))
        );

        // Associativity of union
        assert_eq!(
            caps_a.union(&caps_b).union(&caps_c),
            caps_a.union(&caps_b.union(&caps_c))
        );

        // Union is superset of both operands
        let ab = caps_a.union(&caps_b);
        assert!(ab.is_superset(&caps_a));
        assert!(ab.is_superset(&caps_b));

        // Intersection is subset of both operands
        let ab_inter = caps_a.intersection(&caps_b);
        assert!(caps_a.is_superset(&ab_inter));
        assert!(caps_b.is_superset(&ab_inter));

        // Empty is subset of everything
        let empty = CapabilitySet::empty();
        assert!(caps_a.is_superset(&empty));
        assert!(caps_b.is_superset(&empty));
        assert!(caps_c.is_superset(&empty));

        // All is superset of everything
        let all = CapabilitySet::all();
        assert!(all.is_superset(&caps_a));
        assert!(all.is_superset(&caps_b));
        assert!(all.is_superset(&caps_c));

        // Idempotence: union with self is self
        assert_eq!(caps_a.union(&caps_a), caps_a);

        // Idempotence: intersection with self is self
        assert_eq!(caps_a.intersection(&caps_a), caps_a);

        // Absorption: a union (a intersect b) == a
        assert_eq!(caps_a.union(&caps_a.intersection(&caps_b)), caps_a);
    }

    // -- Namespace derivation determinism --

    #[test]
    fn namespace_derivation_determinism() {
        let ns1 = uuid::Uuid::from_bytes([
            0x4c, 0x45, 0xa6, 0x4f, 0xab, 0xcd, 0x59, 0x77,
            0xbc, 0x73, 0x99, 0xd4, 0xc9, 0x3d, 0x66, 0x8b,
        ]);
        let ns2 = uuid::Uuid::from_bytes([0xaa; 16]);

        // Same namespace + same name = same ID across 100 iterations
        let expected = uuid::Uuid::new_v5(&ns1, b"profile:work");
        for _ in 0..100 {
            assert_eq!(uuid::Uuid::new_v5(&ns1, b"profile:work"), expected);
        }

        // Different namespace + same name = different ID
        assert_ne!(
            uuid::Uuid::new_v5(&ns1, b"profile:work"),
            uuid::Uuid::new_v5(&ns2, b"profile:work"),
        );

        // Same namespace + different name = different ID
        assert_ne!(
            uuid::Uuid::new_v5(&ns1, b"profile:work"),
            uuid::Uuid::new_v5(&ns1, b"profile:personal"),
        );
    }

    // -- OciReference fuzz / adversarial input tests --

    #[test]
    fn oci_reference_never_panics_on_adversarial_input() {
        let long_input = "a".repeat(65536);
        let inputs: Vec<&str> = vec![
            "",
            " ",
            "/",
            "//",
            ":",
            "@",
            "a@",
            "@a",
            "a:b@c",
            "registry/principal/scope:rev@prov",
            "\0",
            "\0\0\0",
            &long_input,
            "emoji/\u{1f525}/scope:rev",
            "registry/principal/scope:",
            "registry//scope:rev",
            "///:",
            ":@",
            "a/b/c:d@",
            "a/b/c:d@e@f",
        ];
        for input in &inputs {
            let _ = input.parse::<OciReference>(); // must not panic
        }
    }
}
