//! Peripheral daemon configuration types.
//!
//! Config sections for clipboard, input, launcher, and audit — each consumed
//! by exactly one daemon.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Clipboard configuration for a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ClipboardConfig {
    /// Maximum history entries.
    pub max_history: usize,
    /// TTL for sensitive entries (seconds).
    pub sensitive_ttl_s: u64,
    /// Enable sensitivity detection.
    pub detect_sensitive: bool,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self {
            max_history: 1000,
            sensitive_ttl_s: 30,
            detect_sensitive: true,
        }
    }
}

/// Input remapping configuration for a profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct InputConfig {
    /// Key binding layers.
    pub layers: BTreeMap<String, BTreeMap<String, String>>,
}

/// Launcher configuration for a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LauncherConfig {
    /// Maximum results to display.
    pub max_results: usize,
    /// Enable frecency-based ranking.
    pub frecency: bool,
}

impl Default for LauncherConfig {
    fn default() -> Self {
        Self {
            max_results: 20,
            frecency: true,
        }
    }
}

/// Audit log configuration for a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Enable audit logging for this profile.
    pub enabled: bool,
    /// Retention period (days).
    pub retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 90,
        }
    }
}
