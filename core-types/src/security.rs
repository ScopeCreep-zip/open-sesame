use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;
use uuid::Uuid;

use crate::ids::AgentId;
use crate::oci::OciReference;

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
        Self {
            capabilities: BTreeSet::new(),
        }
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
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Set union: all capabilities from both sets.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        Self {
            capabilities: self
                .capabilities
                .union(&other.capabilities)
                .cloned()
                .collect(),
        }
    }

    /// Set intersection: only capabilities present in both sets.
    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        Self {
            capabilities: self
                .capabilities
                .intersection(&other.capabilities)
                .cloned()
                .collect(),
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
    UCred { pid: u32, uid: u32, gid: u32 },
    /// Noise IK static key verified against the clearance registry.
    NoiseIK {
        public_key: [u8; 32],
        registry_generation: u64,
    },
    /// Master password verified against the KDF-derived key.
    MasterPassword { verified_at: u64 },
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
// Agent Identity (merged from identity.rs to avoid circular deps)
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
    /// Computed as `uuid5(PROFILE_NAMESPACE, id.as_bytes())`.
    pub namespace: Uuid,
    /// Optional machine binding for hardware attestation.
    pub machine_binding: Option<MachineBinding>,
    /// X25519 public key for network transport identity (32 bytes).
    /// `None` for installations that have not run the extended init ceremony.
    #[serde(default)]
    pub network_pubkey: Option<Vec<u8>>,
    /// Ed25519 public key for vault log signing and coordinator operations (32 bytes).
    /// `None` for installations that have not run the extended init ceremony.
    #[serde(default)]
    pub signing_pubkey: Option<Vec<u8>>,
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
