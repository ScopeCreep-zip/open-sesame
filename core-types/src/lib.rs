//! Shared types, error types, and event schema for the PDS IPC bus.
//!
//! This crate defines the canonical type system shared across all PDS crates.
//! It has zero platform dependencies and is `no_std`-compatible for hot-path types.
//! Minimal external deps: serde, uuid, thiserror.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
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
    /// Trigger the window switcher overlay.
    WmActivateOverlay,
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
    },
    LaunchExecuteResponse {
        pid: u32,
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
        WmActivateOverlayLauncher,
        WmOverlayShown,
        WmOverlayDismissed,
        LaunchQuery { query, max_results, profile },
        LaunchQueryResponse { results },
        LaunchExecute { entry_id, profile },
        LaunchExecuteResponse { pid },
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
/// Maps 1:1 to a BLAKE3 KDF context: `"pds v1 vault-key {name}"`
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
}
