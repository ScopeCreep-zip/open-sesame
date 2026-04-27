//! Installation identity configuration types.
//!
//! Stored in `~/.config/pds/installation.toml`, generated once at `sesame init`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Installation identity stored in `installation.toml`.
///
/// Generated once at `sesame init` and never modified unless the user
/// explicitly re-initializes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallationConfig {
    /// Unique installation identifier (UUID v4).
    pub id: Uuid,
    /// Derived namespace for deterministic ID generation.
    pub namespace: Uuid,
    /// Optional organizational namespace for enterprise deployments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<OrgConfig>,
    /// Optional machine binding for hardware attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_binding: Option<MachineBindingConfig>,
    /// ISO 8601 timestamp of installation creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Human-readable display name for this installation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Hex-encoded X25519 public key for network transport identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_pubkey_hex: Option<String>,
    /// Hex-encoded Ed25519 public key for vault log signing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_pubkey_hex: Option<String>,
    /// Whether the init ceremony completed successfully.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceremony_completed: Option<bool>,
}

/// Organizational namespace configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgConfig {
    /// Organization domain (e.g., "braincraft.io").
    pub domain: String,
    /// Deterministic namespace derived from domain.
    pub namespace: Uuid,
}

/// Machine binding configuration (serialized as hex strings in TOML).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineBindingConfig {
    /// Hex-encoded hash of machine identity material.
    pub binding_hash: String,
    /// Binding method: "machine-id" or "tpm-bound".
    pub binding_type: String,
}
