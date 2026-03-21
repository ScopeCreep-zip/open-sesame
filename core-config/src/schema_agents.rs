//! Agent identity, authorization, and extension policy configuration types.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Agent identity and authorization configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentsConfig {
    /// Default agent configuration applied when no specific agent matches.
    pub default: AgentConfig,
    /// Named agent configurations keyed by agent name.
    #[serde(default)]
    pub agents: BTreeMap<String, AgentConfig>,
}

/// Configuration for a single agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// Agent type: "human", "ai", "service", "extension".
    pub agent_type: String,
    /// Default capabilities granted to this agent.
    pub default_capabilities: Vec<String>,
    /// Whether master password verification is required.
    pub require_master_password: bool,
    /// Unix UID constraint (process attestation).
    pub uid: Option<u32>,
    /// AI model family (for `agent_type` = "ai").
    pub model_family: Option<String>,
    /// Maximum delegation chain depth this agent can create.
    pub max_delegation_depth: Option<u8>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_type: "human".into(),
            default_capabilities: vec!["admin".into()],
            require_master_password: true,
            uid: None,
            model_family: None,
            max_delegation_depth: None,
        }
    }
}

/// Extension system configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ExtensionsConfig {
    /// Extension security policy.
    pub policy: ExtensionsPolicyConfig,
}

/// Security policy for extension installation and execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ExtensionsPolicyConfig {
    /// Allowed OCI registries for extension installation.
    pub allowed_registries: Vec<String>,
    /// Blocked namespaces (deny list).
    pub blocked_namespaces: Vec<String>,
    /// Require cryptographic signature on extension manifests.
    pub require_signature: bool,
    /// Trusted signer public keys (hex-encoded).
    pub trusted_signers: Vec<String>,
}
